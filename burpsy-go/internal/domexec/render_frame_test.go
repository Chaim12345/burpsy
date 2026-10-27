package domexec

import (
	"bytes"
	"context"
	"testing"
	"time"
)

// The live crawl view's frames (burpsy-react-ui-1l3x). Before captureFrame brought the tab to the
// front, the first render's capture took seconds and every later one hung until the 30 s tab timeout,
// failing the render it rode on — so this asserts on the SECOND and later renders, and on time.
func TestEveryRenderThatAsksForAFrameGetsOneQuickly(t *testing.T) {
	b := newTestBrowser(t)
	u := servePage(t, "<html><body><h1>frame</h1></body></html>")
	for i := 0; i < 3; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		started := time.Now()
		html, out, err := b.renderedDOMWithOptions(ctx, u, RenderOptions{Screenshot: true})
		cancel()
		if err != nil || html == "" {
			t.Fatalf("render %d: %v", i, err)
		}
		if !bytes.HasPrefix(out.Screenshot, []byte{0xff, 0xd8}) {
			t.Fatalf("render %d: no JPEG frame (%d bytes)", i, len(out.Screenshot))
		}
		if took := time.Since(started); took > 8*time.Second {
			t.Fatalf("render %d took %s: the capture is stalling the render", i, took)
		}
	}
	// Not asked, not taken.
	_, out, err := b.renderedDOMWithOptions(context.Background(), u, RenderOptions{})
	if err != nil || out.Screenshot != nil {
		t.Fatalf("a render that did not ask got a frame: %v %d", err, len(out.Screenshot))
	}
}
