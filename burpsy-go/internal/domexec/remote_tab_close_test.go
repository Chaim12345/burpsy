package domexec

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/chromedp"
)

// startRemoteChrome launches a headless Chrome with a CDP port, the stand-in for a remote engine, and
// returns its browser websocket URL and its HTTP debugging base.
func startRemoteChrome(t *testing.T) (wsURL, httpBase string) {
	t.Helper()
	var bin string
	for _, name := range []string{"chromium", "google-chrome", "google-chrome-stable", "chrome"} {
		if p, err := exec.LookPath(name); err == nil {
			bin = p
			break
		}
	}
	if bin == "" {
		t.Skip("no Chrome on PATH")
	}
	cmd := exec.Command(bin, "--headless=new", "--no-sandbox", "--disable-gpu", "--remote-debugging-port=0",
		"--user-data-dir="+t.TempDir(), "about:blank")
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Skipf("could not start Chrome: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	re := regexp.MustCompile(`DevTools listening on (ws://[^\s]+)`)
	found := make(chan string, 1)
	go func() {
		sc := bufio.NewScanner(stderr)
		for sc.Scan() {
			if m := re.FindStringSubmatch(sc.Text()); m != nil {
				found <- m[1]
				for sc.Scan() {
				}
				return
			}
		}
	}()
	select {
	case wsURL = <-found:
	case <-time.After(20 * time.Second):
		t.Skip("Chrome did not report a DevTools URL")
	}
	httpBase = "http://" + strings.SplitN(strings.TrimPrefix(wsURL, "ws://"), "/", 2)[0]
	return wsURL, httpBase
}

func pageTargets(t *testing.T, httpBase string) int {
	t.Helper()
	resp, err := http.Get(httpBase + "/json/list")
	if err != nil {
		t.Fatalf("list targets: %v", err)
	}
	defer resp.Body.Close()
	var list []struct {
		Type string `json:"type"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		t.Fatalf("decode targets: %v", err)
	}
	n := 0
	for _, x := range list {
		if x.Type == "page" {
			n++
		}
	}
	return n
}

// A remote-mode tab whose CALLER's context is cancelled (an audit timing out) must still close its
// target on the server. The per-tab connection used to be derived from that same context, so it was
// already gone when the teardown tried to close the target over it, and every timed-out tab leaked.
func TestARemoteTabIsClosedWhenItsCallersContextIsCancelled(t *testing.T) {
	wsURL, httpBase := startRemoteChrome(t)
	b, err := NewBrowser(context.Background(), Options{RemoteURL: wsURL, Timeout: 20 * time.Second})
	if err != nil {
		t.Skipf("remote attach failed: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })
	before := pageTargets(t, httpBase)

	for i := 0; i < 3; i++ {
		ctx, cancelCaller := context.WithCancel(context.Background())
		tab, cancelTab, err := b.newTab(ctx)
		if err != nil {
			t.Fatalf("newTab: %v", err)
		}
		if err := chromedp.Run(tab, chromedp.Navigate("about:blank")); err != nil {
			t.Fatalf("navigate: %v", err)
		}
		if n := pageTargets(t, httpBase); n <= before {
			t.Fatalf("the open tab is not visible as a page target (%d before, %d now), so this test could not see a leak", before, n)
		}
		cancelCaller() // the caller's budget expires; nobody calls cancelTab before it
		defer cancelTab()
	}

	deadline := time.Now().Add(10 * time.Second)
	for {
		after := pageTargets(t, httpBase)
		if after <= before {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d page target(s) before, %d after three tabs whose caller was cancelled: the tabs leaked", before, after)
		}
		time.Sleep(200 * time.Millisecond)
	}
}
