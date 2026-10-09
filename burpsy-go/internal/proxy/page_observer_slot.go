package proxy

import (
	"sync/atomic"

	"github.com/burpsy-go/burpsy/internal/core"
)

// PageObserverSlot lets a page observer be attached to a proxy that is already serving.
//
// WithPageObserver, like every ProxyConfig hook, must be set before NewServer: relay goroutines read
// the config without a lock, so attaching a hook to a running listener is a data race. The live
// passive crawl's observer is a method on the web server, which main builds long after the proxy
// starts. The slot's Observe is what gets attached before serving; the web server's method is
// installed into it later with Set, through an atomic pointer, so the late install is race-free.
//
// Pages the listener records before Set is called are not observed. That is the window between the
// proxy starting and the web server existing, at boot, before any operator can be driving a browser
// through a listener whose UI is not up yet.
type PageObserverSlot struct {
	fn atomic.Pointer[func(ex *core.Exchange, response []byte)]
}

// Set installs the observer. Safe to call while the proxy serves; a nil fn detaches.
func (p *PageObserverSlot) Set(fn func(ex *core.Exchange, response []byte)) {
	if fn == nil {
		p.fn.Store(nil)
		return
	}
	p.fn.Store(&fn)
}

// Observe forwards to the installed observer, or does nothing when none is installed yet. It is the
// function handed to WithPageObserver.
func (p *PageObserverSlot) Observe(ex *core.Exchange, response []byte) {
	if fn := p.fn.Load(); fn != nil {
		(*fn)(ex, response)
	}
}
