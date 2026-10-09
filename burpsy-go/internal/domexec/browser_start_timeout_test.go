package domexec

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The browser's startup bound is Options.Timeout, not chromedp's own 20s for reading the DevTools
// URL. A Chrome that announces itself after 21s, inside a 40s bound, must get past that read; before
// this was fixed it failed at 20s with "websocket url timeout reached" (a loaded CI runner under
// -race, burpsy-react-ui-c3lq). The stand-in announces an address nothing listens on, so the launch
// still fails — at the dial, after the read, which is the point.
func TestTheStartupBoundIsTheOptionsTimeoutNotChromedpsDefault(t *testing.T) {
	if testing.Short() {
		t.Skip("waits 21s for a slow stand-in browser")
	}
	chrome := filepath.Join(t.TempDir(), "chrome")
	script := "#!/bin/sh\nsleep 21\necho 'DevTools listening on ws://127.0.0.1:1/devtools/browser/x' >&2\nsleep 30\n"
	if err := os.WriteFile(chrome, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	b, err := NewBrowser(context.Background(), Options{ChromePath: chrome, Timeout: 40 * time.Second})
	if err == nil {
		b.Close()
		t.Fatal("a stand-in with no DevTools endpoint started")
	}
	if strings.Contains(err.Error(), "websocket url timeout") || time.Since(start) < 21*time.Second {
		t.Fatalf("startup gave up after %s, inside the 40s bound: %v", time.Since(start).Round(time.Second), err)
	}
}
