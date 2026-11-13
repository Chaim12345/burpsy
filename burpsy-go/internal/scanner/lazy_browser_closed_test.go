package scanner

import (
	"context"
	"testing"
)

// A closed provider must answer an error: (nil, nil) made the caller dereference a nil browser.
func TestLazyBrowserAfterCloseReturnsAnError(t *testing.T) {
	l := &lazyBrowser{started: true} // the state Close leaves behind
	b, err := l.Browser(context.Background())
	if b != nil || err == nil {
		t.Fatalf("Browser() after Close = (%v, %v), want (nil, an error)", b, err)
	}
}
