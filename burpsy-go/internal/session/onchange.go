package session

// Session movement notification (ui2 Session page live updates): one OnChange hook on the
// Coordinator, mirroring the matchreplace.RuleSet / proxy.TlsPolicy pattern. Rule edits, cookie
// jar movement and the opt-in tracer all feed the same hook; the web server turns it into the
// coarse session change frame the open page follows. The hook runs synchronously where the
// movement happened and is installed once at wiring time; a nil hook costs one atomic load.
//
// Silence discipline, the same "real movement only" rule the proxy components follow: an
// unchanged rule PUT, an offset-0 or edge-clamped move, a removal that removed nothing, and a
// Set-Cookie whose content the jar already holds all stay silent. For the jar, "same content"
// compares every stored attribute, with one deliberate exception: a Set-Cookie that only slides
// a still-valid expiry forward (a rolling Max-Age refresh) is not movement — announcing it
// would page the operator on every response of a keepalive-happy app without the jar table
// saying anything new. An expiry that appears, disappears, or crosses the expired boundary IS
// announced: the cookie became sendable or unsendable, which the jar's send path honours.

import (
	"bytes"
	"encoding/json"
	"sync/atomic"
)

// onChange is the movement hook shared by the Coordinator and, through it, the jar manager.
// Stored as atomic.Value holding func() so the hot absorb path never takes a lock to check.
type onChangeHook struct{ fn atomic.Value }

func (h *onChangeHook) set(fn func()) { h.fn.Store(fn) }
func (h *onChangeHook) note() {
	if fn, ok := h.fn.Load().(func()); ok && fn != nil {
		fn()
	}
}

// OnChange installs the movement hook on the coordinator and, through it, on the cookie jar
// manager it owns, so every session state the Session page renders announces through one
// install. Nil clears it.
func (c *Coordinator) OnChange(fn func()) {
	c.onChange.set(fn)
	c.jarMgr.onChange.set(fn)
}

// noteChange reports session movement to the installed hook, if any.
func (c *Coordinator) noteChange() { c.onChange.note() }

// rulesSemanticallyEqual compares two validated, action-normalised rules by their JSON
// projection: slices keep order (evaluation-relevant), maps encode with sorted keys, and
// pointers are followed by the encoder, so two separately decoded rules with the same meaning
// compare equal while any rendered difference compares unequal.
func rulesSemanticallyEqual(a, b *SessionRule) bool {
	aj, err := json.Marshal(a)
	if err != nil {
		return false
	}
	bj, err := json.Marshal(b)
	if err != nil {
		return false
	}
	return bytes.Equal(aj, bj)
}

// jarCookieMeaningfullyDifferent compares two stored cookies on every stored field, expiry
// included. The Session page renders the expiry verbatim, so any stored slide - even a rolling
// Max-Age refresh that leaves the cookie just as sendable - is a rendered difference the page
// must announce; suppressing it would leave the rendered Expires cell stale. Identical
// resubmissions (same absolute expiry, or none) still stay silent.
func jarCookieMeaningfullyDifferent(old, new jarCookie) bool {
	return old.Value != new.Value || old.Path != new.Path || old.Domain != new.Domain ||
		old.Secure != new.Secure || old.HTTPOnly != new.HTTPOnly || !old.Expires.Equal(new.Expires)
}
