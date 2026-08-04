// Command realstore validates the storage change against the actual product
// code — core.TrafficStore plus internal/persist — rather than a model of it.
//
//	build   ingest a deterministic capture into a real store with a capture
//	        directory and a real SQLite mirror, then report memory and disk.
//	restore in a fresh process, restore that store through persist.Restore and
//	        report what coming back up costs.
//
// The two run as separate processes so restore's RSS is the real cost of a
// restart rather than whatever the ingest left behind.
package main

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/persist"
)

const (
	targetBytes = 400 << 20
	seed        = 20260728
	root        = "/tmp/realstore"
)

func paths() (captureDir, db string) {
	return filepath.Join(root, "capture"), filepath.Join(root, "state.db")
}

type mem struct {
	VmRSS     float64 `json:"vm_rss_mb"`
	VmHWM     float64 `json:"vm_hwm_mb"`
	VmSwap    float64 `json:"vm_swap_mb"`
	HeapAlloc float64 `json:"heap_alloc_mb"`
}

func sampleMem() mem {
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	rss, hwm, swap := -1.0, -1.0, -1.0
	if data, err := os.ReadFile("/proc/self/status"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			switch {
			case strings.HasPrefix(line, "VmRSS:"):
				fmt.Sscanf(line, "VmRSS: %f", &rss)
			case strings.HasPrefix(line, "VmHWM:"):
				fmt.Sscanf(line, "VmHWM: %f", &hwm)
			case strings.HasPrefix(line, "VmSwap:"):
				fmt.Sscanf(line, "VmSwap: %f", &swap)
			}
		}
	}
	return mem{VmRSS: rss / 1024, VmHWM: hwm / 1024, VmSwap: swap / 1024,
		HeapAlloc: float64(ms.HeapAlloc) / (1 << 20)}
}

func dirBytes(dir string) int64 {
	var total int64
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	for _, e := range entries {
		if info, err := e.Info(); err == nil {
			total += info.Size()
		}
	}
	return total
}

func fileBytes(path string) int64 {
	if info, err := os.Stat(path); err == nil {
		return info.Size()
	}
	return 0
}

type result struct {
	Phase        string  `json:"phase"`
	Messages     int     `json:"messages"`
	Exchanges    int     `json:"exchanges"`
	Captured     int64   `json:"captured_bytes"`
	ElapsedMs    float64 `json:"elapsed_ms"`
	CaptureBytes int64   `json:"capture_dir_bytes"`
	DBBytes      int64   `json:"db_bytes"`
	Mem          mem     `json:"mem"`
	DiskBacked   int     `json:"disk_backed_messages"`
	Resident     int     `json:"resident_messages"`
	BodySum      uint64  `json:"body_checksum"`
	BodyBytes    int64   `json:"body_bytes"`
	VerifyIndex  string  `json:"verify_index"`
}

func emit(r result) {
	b, _ := json.Marshal(r)
	fmt.Println(string(b))
}

func genCorpus(yield func(host, method, path string, status int, req, res []byte)) {
	rng := rand.New(rand.NewSource(seed))
	var cumulative int64
	for cumulative < targetBytes {
		method := "GET"
		if rng.Intn(4) == 0 {
			method = "POST"
		}
		host := fmt.Sprintf("svc-%d.test", rng.Intn(200))
		if rng.Intn(3) != 0 {
			host = fmt.Sprintf("svc-%d.prod.test", rng.Intn(200))
		}
		path := "/v1/account/list"
		switch rng.Intn(4) {
		case 0:
			path = fmt.Sprintf("/v1/account/%d", rng.Intn(1000))
		case 1:
			path = "/v1/account/create"
		case 2:
			path = "/assets/static.js"
		case 3:
			path = "/v1/account/export"
		}
		status := 200
		switch rng.Intn(100) {
		case 0, 1, 2, 3, 4, 5, 6, 7, 8, 9:
			status = 500
		case 10, 11, 12, 13, 14:
			status = 404
		}
		size := bodySize(rng)
		reqBody := sized(size/4, rng)
		resBody := sized(size-size/4, rng)
		req := []byte(fmt.Sprintf("%s %s HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\nAccept: */*\r\n\r\n%s",
			method, path, host, len(reqBody), reqBody))
		res := []byte(fmt.Sprintf("HTTP/1.1 %d OK\r\nContent-Length: %d\r\nContent-Type: application/json\r\n\r\n%s",
			status, len(resBody), resBody))
		yield(host, method, path, status, req, res)
		cumulative += int64(len(req) + len(res))
	}
}

func bodySize(rng *rand.Rand) int {
	switch r := rng.Intn(100); {
	case r < 83:
		return 200 + rng.Intn(1300)
	case r < 98:
		return 4000 + rng.Intn(26000)
	default:
		return 100_000 + rng.Intn(400_000)
	}
}

func sized(n int, rng *rand.Rand) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte('a' + rng.Intn(26))
	}
	return b
}

// consume folds every byte of a body, so build and restore can be shown to have
// read the same bytes.
func consume(b []byte) uint64 {
	var sum uint64 = 1469598103934665603
	for _, c := range b {
		sum = (sum ^ uint64(c)) * 1099511628211
	}
	return sum
}

// scanBodies reads the body of every response in the store, which for a
// disk-backed store means faulting those pages in through the mapping.
func scanBodies(store *core.TrafficStore) (int64, uint64) {
	var total int64
	var sum uint64
	for _, ex := range store.Exchanges() {
		if ex.Response == nil {
			continue
		}
		m, err := store.Get(*ex.Response)
		if err != nil {
			panic(err)
		}
		body := m.Body()
		total += int64(len(body))
		sum ^= consume(body)
	}
	return total, sum
}

func census(store *core.TrafficStore) (diskBacked, resident int) {
	msgs, _ := store.Count()
	for i := 0; i < msgs; i++ {
		m, err := store.Get(core.MsgId(i))
		if err != nil {
			panic(err)
		}
		if m.Location().Segment != "" {
			diskBacked++
		} else {
			resident++
		}
	}
	return diskBacked, resident
}

func verdict(err error) string {
	if err == nil {
		return "ok"
	}
	return err.Error()
}

func runBuild() {
	os.RemoveAll(root)
	captureDir, dbPath := paths()
	if err := os.MkdirAll(captureDir, 0o755); err != nil {
		panic(err)
	}

	store, err := core.NewTrafficStoreWithCaptureDir(captureDir, 64<<20)
	if err != nil {
		panic(err)
	}
	p, err := persist.Open(dbPath, zap.NewNop())
	if err != nil {
		panic(err)
	}
	store.SetPersistenceSinks(p.SaveMessage, p.SaveExchange)

	var captured int64
	start := time.Now()
	genCorpus(func(host, method, path string, status int, req, res []byte) {
		reqID, err := store.Put(req, core.DirectionRequest)
		if err != nil {
			panic(err)
		}
		resID, err := store.Put(res, core.DirectionResponse)
		if err != nil {
			panic(err)
		}
		st := uint16(status)
		store.AddExchange(&core.Exchange{
			Request: reqID, Response: &resID, Host: host, Method: method,
			Path: path, Status: &st, ResponseLen: len(res),
		})
		captured += int64(len(req) + len(res))
	})
	elapsed := float64(time.Since(start).Microseconds()) / 1000
	if err := store.Sync(); err != nil {
		panic(err)
	}
	p.Close()

	msgs, exs := store.Count()
	diskBacked, resident := census(store)
	bodyBytes, bodySum := scanBodies(store)
	emit(result{
		Phase: "build", Messages: msgs, Exchanges: exs, Captured: captured,
		ElapsedMs: elapsed, CaptureBytes: dirBytes(captureDir),
		DBBytes:    fileBytes(dbPath) + fileBytes(dbPath+"-wal"),
		Mem:        sampleMem(),
		DiskBacked: diskBacked, Resident: resident,
		BodyBytes: bodyBytes, BodySum: bodySum,
		VerifyIndex: verdict(store.VerifyIndex()),
	})
}

func runRestore() {
	captureDir, dbPath := paths()
	// Cold: the whole point is what a restart costs, not what a warm cache does.
	os.WriteFile("/proc/sys/vm/drop_caches", []byte("3\n"), 0o200)

	start := time.Now()
	store, err := core.NewTrafficStoreWithCaptureDir(captureDir, 64<<20)
	if err != nil {
		panic(err)
	}
	p, err := persist.Open(dbPath, zap.NewNop())
	if err != nil {
		panic(err)
	}
	if err := p.Restore(store, nil, nil, nil, nil, nil, nil); err != nil {
		panic(err)
	}
	elapsed := float64(time.Since(start).Microseconds()) / 1000
	p.Close()

	msgs, exs := store.Count()
	diskBacked, resident := census(store)
	afterIndex := sampleMem()
	bodyBytes, bodySum := scanBodies(store)
	emit(result{
		Phase: "restore", Messages: msgs, Exchanges: exs,
		ElapsedMs: elapsed, CaptureBytes: dirBytes(captureDir),
		DBBytes:    fileBytes(dbPath) + fileBytes(dbPath+"-wal"),
		Mem:        afterIndex,
		DiskBacked: diskBacked, Resident: resident,
		BodyBytes: bodyBytes, BodySum: bodySum,
		VerifyIndex: verdict(store.VerifyIndex()),
	})
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: realstore <build|restore>")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "build":
		runBuild()
	case "restore":
		runRestore()
	default:
		fmt.Fprintln(os.Stderr, "usage: realstore <build|restore>")
		os.Exit(2)
	}
}
