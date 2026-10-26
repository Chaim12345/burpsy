package jsexec

// Adversarial resource harness for the pre-request script runner (burpsy-react-ui-1944 containment research).
// TEST ONLY. It is skipped unless BURPSY_ADV_HARNESS=1, so it never runs in a normal `go test`. Several cases
// are DESIGNED to exhaust memory: run them only through scripts/adv-cgroup-run.sh, which puts each one in a
// hard cgroup memory cap. The URL below is data only; nothing here opens a network connection.

import (
	"os"
	"runtime"
	"testing"
	"time"
)

var advCases = map[string]string{
	"recurse": "function f(n){return f(n+1)+1} f(0)",
	"dbl":     "var s='x'; for(var i=0;i<40;i++){s+=s} s.length",
	"repeat":  "var s='x'.repeat(Math.pow(2,29)); s.length",
	"arr":     "var a=[]; for(var i=0;i<1e9;i++){a.push({k:i})}",
	"join":    "new Array(Math.pow(2,28)).join('abcdefgh').length",
}

func TestAdversarialResourceHarness(t *testing.T) {
	if os.Getenv("BURPSY_ADV_HARNESS") != "1" {
		t.Skip("set BURPSY_ADV_HARNESS=1 (scripts/adv-cgroup-run.sh does) to run the adversarial cases")
	}
	k := os.Getenv("ADV")
	src, ok := advCases[k]
	if !ok {
		t.Fatalf("ADV=%q is not a known case (recurse, dbl, repeat, arr, join): refusing to run a no-op", k)
	}
	t0 := time.Now()
	_, err := RunRequestScript(src, ScriptRequest{Method: "GET", URL: "http://example.invalid/"}, nil, nil)
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	t.Logf("%s err=%v elapsed=%v sys=%dMiB heapalloc=%dMiB", k, err, time.Since(t0), m.Sys>>20, m.HeapAlloc>>20)
}
