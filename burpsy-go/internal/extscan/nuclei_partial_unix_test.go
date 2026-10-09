//go:build unix

package extscan

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/procgroup/proctest"
)

// burpsy-react-ui-b2wh: a nuclei run cut short keeps the hits it streamed —
// they are real evidence — and says, in the result and in every row, that it
// did not finish and why. These drive a fake nuclei (a shell script on the
// allowlist) through RunNuclei, so the classification is tested end to end
// through run's process handling, not against a hand-built error.

const fakeRecord1 = `{"template-id":"tpl-one","info":{"name":"One","severity":"high"},"type":"http","host":"127.0.0.1","port":"80","matched-at":"http://127.0.0.1/a"}`
const fakeRecord2 = `{"template-id":"tpl-two","info":{"name":"Two","severity":"low"},"type":"http","host":"127.0.0.1","port":"80","matched-at":"http://127.0.0.1/b"}`

// fakeNuclei writes an executable script that prints the two records and then
// runs tail (a shell fragment), and returns a Config allowlisting it.
func fakeNuclei(t *testing.T, tail string, timeout time.Duration) Config {
	t.Helper()
	script := "#!/bin/sh\nprintf '%s\\n' '" + fakeRecord1 + "'\nprintf '%s\\n' '" + fakeRecord2 + "'\n" + tail + "\n"
	path := filepath.Join(t.TempDir(), "nuclei")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return Config{Tools: map[string]string{ToolNuclei: path}, Timeout: timeout}
}

func fakeTarget(t *testing.T) (ScopeAuthoriser, Target) {
	t.Helper()
	scope := core.NewScopeAllowEverything()
	target, err := Authorise(scope, "http://127.0.0.1/")
	if err != nil {
		t.Fatal(err)
	}
	return scope, target
}

func TestNucleiTimedOutAfterStreamingHitsIsPartialWithItsHits(t *testing.T) {
	cfg := fakeNuclei(t, "exec sleep 30", 500*time.Millisecond)
	scope, target := fakeTarget(t)
	began := time.Now()
	res := RunNuclei(context.Background(), cfg, scope, target, NucleiOptions{})
	if took := time.Since(began); took > 5*time.Second {
		t.Fatalf("RunNuclei took %s for a 500ms timeout", took)
	}
	if res.Outcome != OutcomePartial {
		t.Fatalf("outcome = %v (err %v), want OutcomePartial: a nuclei killed at its timeout must not read as completed", res.Outcome, res.Err)
	}
	if res.Incomplete != IncompleteTimeout {
		t.Errorf("incomplete = %q, want %q", res.Incomplete, IncompleteTimeout)
	}
	if len(res.Hits) != 2 || res.Hits[0].TemplateID != "tpl-one" || res.Hits[1].TemplateID != "tpl-two" {
		t.Errorf("hits = %+v, want the two streamed before the timeout", res.Hits)
	}
	if res.Err == nil || !errors.Is(res.Err, ErrTimedOut) || !strings.Contains(res.Err.Error(), "timed out") {
		t.Errorf("err = %v, want one wrapping ErrTimedOut that says so", res.Err)
	}
	if res.Outcome.Looked() {
		t.Error("a cut-short run reports Looked: that licenses \"nothing else found\"")
	}
	if !res.Outcome.Reported() {
		t.Error("a partial run does not report its results")
	}
	rows := res.Rows()
	if len(rows) != 2 {
		t.Fatalf("rows = %d, want 2: the partial hits are still evidence", len(rows))
	}
	for _, r := range rows {
		if !strings.Contains(r.AdvisoryNote, "did not finish (timed out)") {
			t.Errorf("row %q does not say the run was cut short: %q", r.Name, r.AdvisoryNote)
		}
	}
}

func TestNucleiStoppedAfterStreamingHitsIsPartial(t *testing.T) {
	cfg := fakeNuclei(t, "exec sleep 30", time.Minute)
	scope, target := fakeTarget(t)
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	res := RunNuclei(ctx, cfg, scope, target, NucleiOptions{})
	if res.Outcome != OutcomePartial || res.Incomplete != IncompleteStopped || len(res.Hits) != 2 {
		t.Errorf("outcome %v incomplete %q hits %d (err %v), want partial/stopped/2: the caller's own "+
			"deadline is a stop, not this run's timeout", res.Outcome, res.Incomplete, len(res.Hits), res.Err)
	}
	if !errors.Is(res.Err, ErrStopped) {
		t.Errorf("err = %v, want ErrStopped", res.Err)
	}
}

// A process nuclei started that holds stdout open after nuclei exits makes the
// capture incomplete (procgroup.WaitDelay, PR #339): partial, reason output.
func TestNucleiWhoseOutputWasHeldOpenIsPartial(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	cfg := fakeNuclei(t, "sleep 30 &\necho $! > '"+pidFile+"'\nexit 0", time.Minute)
	scope, target := fakeTarget(t)
	res := RunNuclei(context.Background(), cfg, scope, target, NucleiOptions{})
	// Nothing kills a child left behind by a tool that exited on its own; this
	// test's own leftover is reaped here so it does not outlive the run.
	syscall.Kill(proctest.ChildPID(t, pidFile), syscall.SIGKILL)
	if res.Outcome != OutcomePartial || res.Incomplete != IncompleteOutput || len(res.Hits) != 2 {
		t.Errorf("outcome %v incomplete %q hits %d (err %v), want partial/incomplete output/2",
			res.Outcome, res.Incomplete, len(res.Hits), res.Err)
	}
	if !errors.Is(res.Err, ErrOutputIncomplete) {
		t.Errorf("err = %v, want ErrOutputIncomplete", res.Err)
	}
}

// A record nuclei could not have meant, mid-stream, stops the parse: the hits
// before it are kept, and the run is partial rather than completed.
func TestNucleiWithAnUnparseableRecordMidStreamIsPartial(t *testing.T) {
	cfg := fakeNuclei(t, "printf '%s\\n' '{not json'\nprintf '%s\\n' '"+fakeRecord1+"'", time.Minute)
	scope, target := fakeTarget(t)
	res := RunNuclei(context.Background(), cfg, scope, target, NucleiOptions{})
	if res.Outcome != OutcomePartial || res.Incomplete != IncompleteUnparseable || len(res.Hits) != 2 {
		t.Errorf("outcome %v incomplete %q hits %d (err %v), want partial/unparseable/2",
			res.Outcome, res.Incomplete, len(res.Hits), res.Err)
	}
}

// The capture cap cutting the stream is partial too.
func TestNucleiOverTheOutputCapIsPartial(t *testing.T) {
	cfg := fakeNuclei(t, "exit 0", time.Minute)
	cfg.MaxOutputBytes = len(fakeRecord1) + 1 + 20 // first record whole, second cut mid-record
	scope, target := fakeTarget(t)
	res := RunNuclei(context.Background(), cfg, scope, target, NucleiOptions{})
	if res.Outcome != OutcomePartial || res.Incomplete != IncompleteCapped || !res.Truncated || len(res.Hits) != 1 {
		t.Errorf("outcome %v incomplete %q truncated %v hits %d (err %v), want partial/capped/true/1",
			res.Outcome, res.Incomplete, res.Truncated, len(res.Hits), res.Err)
	}
}

// Controls: a run that finishes is completed with no reason, including one that
// exits non-zero (nuclei does on ordinary conditions), and a timed-out run that
// streamed nothing is a failure, not an empty partial.
func TestNucleiThatFinishesIsComplete(t *testing.T) {
	for _, tail := range []string{"exit 0", "exit 1"} {
		cfg := fakeNuclei(t, tail, time.Minute)
		scope, target := fakeTarget(t)
		res := RunNuclei(context.Background(), cfg, scope, target, NucleiOptions{})
		if res.Outcome != OutcomeCompleted || res.Incomplete != "" || res.Err != nil || len(res.Hits) != 2 {
			t.Errorf("%s: outcome %v incomplete %q err %v hits %d, want completed/\"\"/nil/2",
				tail, res.Outcome, res.Incomplete, res.Err, len(res.Hits))
		}
		for _, r := range res.Rows() {
			if strings.Contains(r.AdvisoryNote, "did not finish") {
				t.Errorf("%s: a finished run's row says it did not finish", tail)
			}
		}
	}
}

func TestNucleiTimedOutWithNothingStreamedIsFailed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nuclei")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexec sleep 30\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := Config{Tools: map[string]string{ToolNuclei: path}, Timeout: 300 * time.Millisecond}
	scope, target := fakeTarget(t)
	res := RunNuclei(context.Background(), cfg, scope, target, NucleiOptions{})
	if res.Outcome != OutcomeFailed || res.Incomplete != "" || !errors.Is(res.Err, ErrTimedOut) {
		t.Errorf("outcome %v incomplete %q err %v, want failed/\"\"/ErrTimedOut", res.Outcome, res.Incomplete, res.Err)
	}
}
