package extension

import (
	"errors"
	"fmt"
	"strconv"
)

// The operator's ordering of the allowlist (burpsy-react-ui-d3gj).
//
// # What order means here, and what it deliberately does not mean
//
// Burp's Extender tab says "Requests and responses pass through the extensions in the order that
// they are listed", and its Up/Down buttons move a plugin within that pipeline. burpsy has no such
// pipeline and this file does not invent one: the closed set of registration kinds in protocol.go
// has no HTTP-handler analogue, a plugin is never given a request on its way to the wire, and
// UnsupportedCapabilities states that a plugin cannot originate or intercept traffic at all. A
// `Host.InvokeAll` that walked every plugin in order would be a pipeline with no caller — a control
// that looks like Burp's and passes through nothing.
//
// What *is* real is that h.ordered is the single sequence every surface that offers a plugin's work
// reads. Host.List serves the rows in it; the console builds the palette group, the context-menu
// group and (once the editor tab strip lands) the tab strip by walking those rows in the order they
// arrive — see internal/web/ui/src/lib/plugin-registrations.ts, whose pluginInvocations is
// documented as "the plugin list's own order". So moving a plugin up moves it ahead of the others
// everywhere its registrations are offered and therefore everywhere they are invoked from. That is
// the honest half of Burp's control, and order_test.go proves it by driving two real plugin
// processes through the served order and reading back which of them ran first.
//
// # Why this is a separate file and touches nothing in host.go
//
// Host.List already takes a copy of h.ordered under h.mu on every call, so permuting the slice is
// the whole change. NewHost's comment that the order is "sorted once here" still describes where
// the order starts: alphabetical, because Config.Plugins is a map and the command line's order is
// lost before the host sees it. An operator who wants a different one now has a way to say so.
//
// # Not persisted
//
// The order lives in this process and is lost on restart, exactly like every other piece of host
// state (which plugin is loaded, what is on its consoles). Burp persists its extension order in the
// project file. Saying that here is the point: a reader who needs it across restarts learns it from
// this comment rather than from a reordering that silently reverts.

// MoveDirection is which way a move goes. A closed set of two, because a move with no direction is
// not a move, and an unrecognised one is refused by name rather than treated as "down".
type MoveDirection string

const (
	MoveUp   MoveDirection = "up"
	MoveDown MoveDirection = "down"
)

var (
	// ErrAlreadyFirst and ErrAlreadyLast are refusals, not no-ops. A move that answered 200 and
	// changed nothing would be a button an operator could press forever while believing the order
	// had changed — the "control that does nothing real" defect this tree treats as a bug. The edge
	// of the list is a fact about the list, so it is reported as one.
	ErrAlreadyFirst = errors.New("plugin is already first in the order, so it cannot move up")
	ErrAlreadyLast  = errors.New("plugin is already last in the order, so it cannot move down")
	// ErrBadDirection names the value it was given, so a caller that sent "top" is told that, and
	// not that its request was generally unreadable.
	ErrBadDirection = errors.New("a move is either up or down")
)

// Move shifts one allowlisted plugin one place in the order and returns the whole list as it now
// stands.
//
// The whole list rather than the moved row: a move changes the position of two plugins, and a
// caller handed only the one it named would have to guess what happened to its neighbour. It is
// also what the console re-renders from.
//
// Order is a property of the allowlist entry and not of the process, so a plugin can be moved
// whether or not it is loaded. Refusing to reorder an unloaded plugin would make the control
// available only in the state where it matters least.
func (h *Host) Move(name string, dir MoveDirection) (ListView, error) {
	if dir != MoveUp && dir != MoveDown {
		return ListView{}, fmt.Errorf("direction %s: %w", strconv.Quote(string(dir)), ErrBadDirection)
	}

	h.mu.Lock()
	if _, ok := h.byName[name]; !ok {
		h.mu.Unlock()
		return ListView{}, fmt.Errorf("%q: %w", name, ErrUnknownPlugin)
	}
	at := -1
	for i, candidate := range h.ordered {
		if candidate == name {
			at = i
			break
		}
	}
	if at < 0 {
		// Unreachable while byName and ordered are built together in NewHost. Kept as a real error
		// rather than a panic or a silent return, because a plugin present in one and absent from
		// the other is a bug in the host and must say so rather than look like a refused move.
		h.mu.Unlock()
		return ListView{}, fmt.Errorf("%q is allowlisted but absent from the order, which is a defect in the host", name)
	}
	swap := at - 1
	if dir == MoveDown {
		swap = at + 1
	}
	if swap < 0 {
		h.mu.Unlock()
		return ListView{}, fmt.Errorf("%q: %w", name, ErrAlreadyFirst)
	}
	if swap >= len(h.ordered) {
		h.mu.Unlock()
		return ListView{}, fmt.Errorf("%q: %w", name, ErrAlreadyLast)
	}
	h.ordered[at], h.ordered[swap] = h.ordered[swap], h.ordered[at]
	h.mu.Unlock()

	return h.List(), nil
}
