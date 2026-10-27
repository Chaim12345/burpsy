package web

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/persist"
	"go.uber.org/zap"
)

// ---- project switch vs live capture (burpsy-react-ui-switch-deadlock) -----------------------------
//
// The capture path used to take the stores' own locks first and the project-switch lock second
// (the mirror sinks took projectSwitchMu.RLock while TrafficStore.Put / AddExchange and
// FindingStore.Add held their write lock), while a switch took projectSwitchMu first and the
// stores' locks second (Restore, SegmentLog, SetPersistenceSinks). With capture running, the
// second or third switch never returned and the whole process wedged. This drives the two paths
// against each other the way a live proxy does, and then checks the invariant the lock exists
// for: every project file holds only rows that were captured while it was the open project.

func TestProjectSwitchesUnderConcurrentCaptureCompleteAndNeverMixProjects(t *testing.T) {
	const (
		switches        = 12
		trafficWriters  = 4
		findingsWriters = 2
	)
	dir := t.TempDir()
	first, err := persist.Open(filepath.Join(dir, "p0.db"), zap.NewNop())
	if err != nil {
		t.Fatalf("open the first project: %v", err)
	}
	srv := newTestServer().WithPersist(first)
	// The startup path main.go takes: the capture sinks are installed before any traffic flows.
	InstallCaptureSinks(srv.store, srv.findings, first)
	// A deadlocked run leaves the switch lock held forever; closing the project under it would hang
	// the cleanup and turn the reported failure into the package timeout.
	var wedged atomic.Bool
	t.Cleanup(func() {
		if !wedged.Load() {
			srv.CloseProject()
		}
	})

	stop := make(chan struct{})
	var writers sync.WaitGroup
	var captured, found atomic.Int64
	for w := 0; w < trafficWriters; w++ {
		writers.Add(1)
		go func(w int) {
			defer writers.Done()
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				host := fmt.Sprintf("w%d-%d.test", w, i)
				if _, err := srv.store.Put([]byte("GET / HTTP/1.1\r\nHost: "+host+"\r\n\r\n"), core.DirectionRequest); err != nil {
					t.Errorf("put: %v", err)
					return
				}
				srv.store.AddExchange(&core.Exchange{Host: host, Port: 80, Method: "GET", Path: "/"})
				captured.Add(1)
			}
		}(w)
	}
	for w := 0; w < findingsWriters; w++ {
		writers.Add(1)
		go func(w int) {
			defer writers.Done()
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				// Distinct names, so no two adds merge and every add is one durable row.
				srv.findings.Add(core.NewFinding{Name: fmt.Sprintf("finding-%d-%d", w, i), Severity: core.SeverityInformational})
				found.Add(1)
			}
		}(w)
	}

	// The switches run on their own goroutine so a deadlock is reported as a failure with the
	// goroutine dump rather than as the package-level test timeout ten minutes later.
	done := make(chan []string, 1)
	go func() {
		var failures []string
		for i := 1; i <= switches; i++ {
			// Let some capture land in each project before leaving it.
			for start := captured.Load(); captured.Load() < start+50; {
				runtime.Gosched()
			}
			rec := openProjectSwitch(t, srv, filepath.Join(dir, fmt.Sprintf("p%d.db", i)))
			if rec.Code != http.StatusOK {
				failures = append(failures, fmt.Sprintf("switch %d = %d: %s", i, rec.Code, rec.Body.String()))
			}
		}
		done <- failures
	}()
	select {
	case failures := <-done:
		for _, f := range failures {
			t.Error(f)
		}
	case <-time.After(60 * time.Second):
		buf := make([]byte, 1<<20)
		n := runtime.Stack(buf, true)
		_, _ = os.Stderr.Write(buf[:n])
		wedged.Store(true)
		t.Fatalf("project switches did not complete within 60s under concurrent capture (deadlock); goroutine dump above")
	}
	close(stop)
	writers.Wait()
	if captured.Load() == 0 || found.Load() == 0 {
		t.Fatalf("the writers made no progress (captured %d, findings %d): the test exercised nothing", captured.Load(), found.Load())
	}

	// The project open now must hold exactly what the console holds. Read under the switch lock so
	// the pointer and the stores are one consistent view (the writers have stopped by now anyway).
	projectSwitchMu.Lock()
	live := srv.persist
	memEx := srv.store.Exchanges()
	memFindings := srv.findings.All()
	projectSwitchMu.Unlock()
	if want := filepath.Join(dir, fmt.Sprintf("p%d.db", switches)); !sameFile(live.Path(), want) {
		t.Fatalf("the open project is %s, want %s", live.Path(), want)
	}
	fileEx, err := live.LoadExchanges()
	if err != nil {
		t.Fatalf("load exchanges of the open project: %v", err)
	}
	if len(fileEx) != len(memEx) {
		t.Errorf("the open project's file holds %d exchanges, the console %d", len(fileEx), len(memEx))
	}
	for i := range fileEx {
		if i < len(memEx) && (fileEx[i].ID != memEx[i].ID || fileEx[i].Host != memEx[i].Host) {
			t.Errorf("exchange %d: file has id %d host %s, console has id %d host %s",
				i, fileEx[i].ID, fileEx[i].Host, memEx[i].ID, memEx[i].Host)
			break
		}
	}
	fileFindings, err := live.LoadFindings()
	if err != nil {
		t.Fatalf("load findings of the open project: %v", err)
	}
	if len(fileFindings) != len(memFindings) {
		t.Errorf("the open project's file holds %d findings, the console %d", len(fileFindings), len(memFindings))
	}

	// Every closed project file must be internally consistent: ids are positions within the
	// project they were captured into, so a row written into the wrong project shows up as an id
	// outside 0..n-1 or as a duplicate.
	for i := 0; i < switches; i++ {
		path := filepath.Join(dir, fmt.Sprintf("p%d.db", i))
		p, err := persist.Open(path, zap.NewNop())
		if err != nil {
			t.Fatalf("reopen %s: %v", path, err)
		}
		checkDense(t, path, "message", func() ([]uint64, error) {
			ms, err := p.LoadMessages(nil)
			ids := make([]uint64, len(ms))
			for j, m := range ms {
				ids[j] = uint64(m.ID)
			}
			return ids, err
		})
		checkDense(t, path, "exchange", func() ([]uint64, error) {
			es, err := p.LoadExchanges()
			ids := make([]uint64, len(es))
			for j, e := range es {
				ids[j] = uint64(e.ID)
			}
			return ids, err
		})
		checkDense(t, path, "finding", func() ([]uint64, error) {
			fs, err := p.LoadFindings()
			ids := make([]uint64, len(fs))
			for j, f := range fs {
				ids[j] = f.ID
			}
			return ids, err
		})
		_ = p.Close()
	}
}

// checkDense asserts a project file's ids of one kind are exactly 0..n-1 — what a project that
// only ever received its own captures holds, since every store restarts its ids at zero when a
// fresh project is opened.
func checkDense(t *testing.T, path, kind string, load func() ([]uint64, error)) {
	t.Helper()
	ids, err := load()
	if err != nil {
		t.Fatalf("%s: load %ss: %v", path, kind, err)
	}
	seen := make(map[uint64]bool, len(ids))
	for _, id := range ids {
		if id >= uint64(len(ids)) || seen[id] {
			t.Errorf("%s: %s id %d is not one of 0..%d exactly once — a row from another project", path, kind, id, len(ids)-1)
			return
		}
		seen[id] = true
	}
}
