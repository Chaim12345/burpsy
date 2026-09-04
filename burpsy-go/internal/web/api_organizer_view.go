package web

import (
	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/organizer"
)

// ---- Organizer rows, resolved ------------------------------------------------------------------
//
// Burp's Organizer filters by in-scope, status class and MIME type (organiserShowOnlyInScopeCheckbox
// and friends). burpsy's organizer could not, and the reason was not a missing control: an
// organizer.Item is `{id, exchange, title, note, highlight}` and nothing else. None of the three
// things Burp filters on is in it. Adding three dropdowns to the page would have filtered on data
// that was never sent.
//
// So the list endpoint resolves each item against the traffic store and the scope, once, server-side
// — which is also where the scope lives, and scope is not something a browser should be re-deciding.
//
// # The case this shape exists for: an item whose exchange is gone
//
// The traffic store is bounded; the organizer is not. An exchange saved a thousand requests ago can
// be evicted while the operator's note about it survives — that asymmetry is the point of the
// organizer, and it means "what was this exchange's status" has a third answer beyond a number:
// nobody knows any more.
//
// A filter cannot decide about such a row, and the wrong ways to handle that are both worse than the
// problem:
//
//   - Dropping it when a filter is active hides a note the operator deliberately wrote, and hides it
//     precisely when they are looking for something.
//   - Inventing a value — status 0, MIME "", out of scope — makes the row answer a question it
//     cannot, and the operator has no way to tell that answer from a real one.
//
// So Resolved is a field, unresolved rows are exempt from every filter rather than failing it, and
// the console marks them. A row that cannot be judged is shown and labelled, never quietly removed.
//
// # Why Status is a pointer and Mime is not enough on its own
//
// core.Exchange.Status is nil when there is no response yet, and core.Exchange.Mime is "" for BOTH
// "no response" and "a response naming no usable Content-Type" — the store's own doc says consumers
// must not render those identically. HasResponse is what separates them, and it is carried for that
// reason rather than left to be inferred from a zero value.

// organizerItemView is an organizer item plus the fields the console needs to filter it.
type organizerItemView struct {
	organizer.Item

	// Resolved reports that the exchange this item names is still in the traffic store. When false
	// every field below is absent and the row cannot be filtered — see the note above.
	Resolved bool `json:"resolved"`

	Host   string `json:"host,omitempty"`
	Port   uint16 `json:"port,omitempty"`
	Method string `json:"method,omitempty"`
	Path   string `json:"path,omitempty"`

	// Status is nil when the exchange has no response — a request that never came back is not a
	// status of zero.
	Status *uint16 `json:"status,omitempty"`
	// HasResponse is what makes an empty Mime readable: without it, "no response" and "a response
	// that named no usable Content-Type" are the same empty string.
	HasResponse bool `json:"has_response"`
	// Mime is the response media type with parameters stripped, as the store recorded it.
	Mime string `json:"mime,omitempty"`

	// InScope is nil exactly when Resolved is false. A bool with no third state would make an
	// unresolvable row look out of scope, which is a claim about the engagement rather than an
	// admission that the exchange is gone.
	InScope *bool `json:"in_scope,omitempty"`
}

// organizerView resolves every saved item for the list endpoint.
//
// Order is preserved: the organizer is a list the operator built, and re-sorting it here would
// silently override whatever order they added things in.
func (s *Server) organizerView() []organizerItemView {
	items := s.organizer.List()
	// Non-nil so the endpoint serialises `[]` rather than null for an empty organizer: a client
	// distinguishing "no field" from "no items" should not have to.
	out := make([]organizerItemView, 0, len(items))

	for _, item := range items {
		view := organizerItemView{Item: item}

		exchange, err := s.store.GetExchange(core.ExchangeID(item.Exchange))
		if err != nil || exchange == nil {
			// Evicted, or never there. Left unresolved rather than dropped — the note is the thing
			// worth keeping, and the row is the only place it is shown.
			out = append(out, view)
			continue
		}

		view.Resolved = true
		view.Host = exchange.Host
		view.Port = exchange.Port
		view.Method = exchange.Method
		view.Path = exchange.Path
		view.Mime = exchange.Mime
		view.HasResponse = exchange.Response != nil
		if exchange.Status != nil {
			status := *exchange.Status
			view.Status = &status
		}

		// Asked here rather than in the browser: the scope is server state, and a console deciding
		// for itself what is in scope would be a second implementation of the only rule that says
		// what this tool may touch.
		inScope := s.scope.Contains(exchange.Host, exchange.Port, exchange.Path, exchange.TLS)
		view.InScope = &inScope

		out = append(out, view)
	}
	return out
}
