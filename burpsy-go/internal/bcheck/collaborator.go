// Collaborator checks: `generate_collaborator_address()` and the `<type> interactions` conditions
// (burpsy-react-ui-ar8v).
//
// # What Burp documents
//
// The BCheck reference: generate_collaborator_address() "Generates a new Burp Collaborator
// address", and `dns interactions` is "True if Burp Collaborator has received any DNS
// interactions" (likewise `http`, `smtp`, and `any`). A fresh address per call; the conditions ask
// about the interactions those addresses received.
//
// # Why a condition cannot simply be evaluated when it is reached
//
// A target calls back on its own schedule. When the evaluator reaches `if http interactions then`,
// the probe has just gone out and the answer usually has not arrived. Treating "nothing yet" as
// false makes every collaborator check silently clean; blocking the audit until a deadline stalls
// the whole scan on one check. The scanner already owns a scan-lifetime wait for exactly this — the
// pending registry that the built-in out-of-band rows hand their callbacks to — so this file makes
// the evaluator able to use it.
//
// # The mechanism: three-valued conditions, then a recorded replay
//
//  1. Live pass. An interactions atom is true once an interaction has arrived for an address this
//     run minted, and *unknown* otherwise — never false, because absence so far is not evidence.
//     `and`/`or`/`not` combine with Kleene logic, so `{x} contains "y" and http interactions`
//     is false outright when the response rules it out. An `if` whose condition is unknown runs
//     neither branch; the check carries on, so a `run for each` still sends every payload. Every
//     send, tool run and minted address of the run is recorded.
//  2. If any condition was unknown, the run is handed back as a Deferred. Its Resolve re-runs the
//     check from the same starting state against the recording: sends are answered from the
//     recorded responses (byte-for-byte the same request is required), tools likewise, and
//     generate_collaborator_address() returns the same addresses in the same order. Only the
//     interactions can differ, so the replay takes the branches the live pass could not. A replay
//     never sends: a branch that would need a probe the live pass never sent stops it with
//     ActiveReplayDiverged, which the caller keeps as outstanding, not clean.
//
// What this does not do, on purpose: an interactions atom never becomes *false* by waiting. A
// condition that needs the absence of a callback (`not(dns interactions)`) therefore never fires;
// it stays unknown until the caller's deadline and is reported outstanding. That is a miss, never a
// false positive, and the same rule the built-in out-of-band rows follow.
package bcheck

import (
	"errors"
	"fmt"
	"strings"
	"sync"
)

// Collaborator is the interaction server a collaborator check runs against. An interface so the
// evaluator owns no transport and tests can supply one whose callbacks they control.
type Collaborator interface {
	// NewAddress mints a payload host no other call has returned. An error abandons the check as
	// unsupported: a check that cannot plant an address can prove nothing.
	NewAddress() (string, error)
	// Interactions returns the interactions received so far for address. An error is "could not
	// ask", which leaves the condition unknown rather than false.
	Interactions(address string) ([]Interaction, error)
}

// Interaction is one callback the interaction server received for an address this run minted.
type Interaction struct {
	// Protocol is "dns", "http", "smtp" (or another protocol the server speaks, which only `any`
	// matches).
	Protocol string
	// Address is the minted address the callback was for.
	Address string
	// From is who made the callback. For DNS this is the upstream resolver, not the target.
	From string
	// Detail is a short description of the callback for a finding's evidence.
	Detail string
}

// SetCollaborator attaches the interaction server. Without one a check that needs it is refused as
// ActiveUnsupported — never run with empty addresses and read as clean.
func (ctx *Context) SetCollaborator(c Collaborator) {
	ctx.collaborator = c
}

// Deferred returns the runs whose interactions conditions were still unknown when the live pass
// finished — one per insertion point (or one for the whole check). Each must be resolved later or
// reported outstanding; a caller that drops one has turned "no answer yet" into "clean".
func (ctx *Context) Deferred() []*Deferred {
	return ctx.deferred
}

// recordedSend is one probe of a live pass and the response it got.
type recordedSend struct {
	raw  []byte
	resp []byte
}

// recordedTool is one tool run of a live pass.
type recordedTool struct {
	tool string
	args []string
	res  ToolResult
}

// collabUnit is the recording (live pass) or the replay cursor (Resolve) for one run of a
// collaborator check. One per insertion point, shared by every fork within it, so the order of
// sends and mints is the run's own order.
type collabUnit struct {
	replay bool
	sends  []recordedSend
	tools  []recordedTool
	addrs  []string

	sendIx, toolIx, addrIx int

	// unknown is set when an `if` condition could not be decided.
	unknown bool
	// halted is set when a plain `report issue` ended the check. A halted run is over: a condition
	// still unknown behind it can no longer change what the check reports.
	halted bool
	// pollErr is the last error the interaction server returned, kept for the caller's report.
	pollErr error
	// err abandons the run: an address could not be minted, or the replay diverged.
	err error
	// cache memoises one poll per address per pass, so a `run for each` of a hundred iterations
	// reads the interaction log once per address rather than once per condition.
	cache map[string][]Interaction
}

func (u *collabUnit) fail(err error) {
	if u.err == nil {
		u.err = err
	}
}

// replayingSink is the sink a replay context carries. A replay answers every send from the
// recording, so reaching this sink would be a bug — and it must refuse rather than send, because a
// resolver runs outside the audit that authorised and metered the live pass.
type replayingSink struct{}

func (replayingSink) Send(*Target, []byte) ([]byte, error) {
	return nil, errors.New("a deferred collaborator replay never sends")
}

// generateCollaboratorAddress is `generate_collaborator_address()`.
func (ctx *Context) generateCollaboratorAddress(name string) string {
	u := ctx.unit
	if ctx.collaborator == nil || u == nil {
		// Passive evaluation, or a caller that attached no interaction server: the reference
		// cannot be supplied, and is recorded like any other absent binding.
		ctx.recordUnresolved(name)
		return ""
	}
	var addr string
	if u.replay {
		if u.addrIx >= len(u.addrs) {
			u.fail(&ActiveError{Kind: ActiveReplayDiverged,
				Detail: "the replay asked for a collaborator address the live pass never minted"})
			return ""
		}
		addr = u.addrs[u.addrIx]
		u.addrIx++
	} else {
		a, err := ctx.collaborator.NewAddress()
		if err != nil {
			u.fail(&ActiveError{Kind: ActiveUnsupported,
				Detail: "a collaborator address could not be generated: " + err.Error()})
			return ""
		}
		addr = a
		u.addrs = append(u.addrs, a)
	}
	ctx.collabAddrs = append(ctx.collabAddrs, addr)
	return addr
}

// tri is a three-valued truth: a condition about interactions can be not-yet-known.
type tri int8

const (
	triFalse tri = iota
	triTrue
	triUnknown
)

func triOf(b bool) tri {
	if b {
		return triTrue
	}
	return triFalse
}

// interactionsAtom evaluates `<kind> interactions` against the addresses this context minted.
func (ctx *Context) interactionsAtom(kind string) tri {
	if ctx.collaborator == nil || ctx.unit == nil {
		return triUnknown
	}
	if len(ctx.collabAddrs) == 0 {
		// Nothing was planted in this run, so nothing can call back to it.
		return triFalse
	}
	u := ctx.unit
	if u.cache == nil {
		u.cache = make(map[string][]Interaction)
	}
	found := false
	for _, addr := range ctx.collabAddrs {
		got, ok := u.cache[addr]
		if !ok {
			var err error
			got, err = ctx.collaborator.Interactions(addr)
			if err != nil {
				u.pollErr = err
				continue
			}
			u.cache[addr] = got
		}
		for _, in := range got {
			if kind != "any" && !strings.EqualFold(in.Protocol, kind) {
				continue
			}
			found = true
			if !ctx.hasObserved(in) {
				ctx.observed = append(ctx.observed, in)
			}
		}
	}
	if found {
		return triTrue
	}
	return triUnknown
}

func (ctx *Context) hasObserved(in Interaction) bool {
	for _, o := range ctx.observed {
		if o == in {
			return true
		}
	}
	return false
}

// usesCollaboratorAddress reports whether any value in the check calls generate_collaborator_address().
func usesCollaboratorAddress(c *Check) bool {
	for _, d := range c.Defines {
		if valueCallsCollaborator(d.Value) {
			return true
		}
	}
	for _, fe := range c.ForEach {
		for _, v := range fe.Values {
			if valueCallsCollaborator(v) {
				return true
			}
		}
	}
	return stmtsCallCollaborator(c.Statements)
}

func valueCallsCollaborator(v Value) bool {
	return (v.Type == "tpl" || v.Type == "var") &&
		strings.Contains(strings.ToLower(v.StringVal), "generate_collaborator_address(")
}

func stmtsCallCollaborator(stmts []Statement) bool {
	for _, s := range stmts {
		switch t := s.(type) {
		case *DefineStatement:
			if valueCallsCollaborator(t.Value) {
				return true
			}
		case *SendRequestStatement:
			if strings.Contains(strings.ToLower(t.Template), "generate_collaborator_address(") {
				return true
			}
			for _, m := range t.Modifiers {
				for _, v := range m.Values {
					if valueCallsCollaborator(v) {
						return true
					}
				}
			}
		case *SendPayloadStatement:
			if valueCallsCollaborator(t.Value) {
				return true
			}
		case *RunToolStatement:
			if valueCallsCollaborator(t.Tool) {
				return true
			}
			for _, v := range t.Args {
				if valueCallsCollaborator(v) {
					return true
				}
			}
		case *ReportIssueStatement:
			if valueCallsCollaborator(t.IssueName) || valueCallsCollaborator(t.Description) ||
				valueCallsCollaborator(t.Remediation) {
				return true
			}
		case *IfStatement:
			if exprCallsCollaborator(t.Condition) || stmtsCallCollaborator(t.Then) || stmtsCallCollaborator(t.Else) {
				return true
			}
		case *RunForEachStatement:
			for _, v := range t.Values {
				if valueCallsCollaborator(v) {
					return true
				}
			}
			if stmtsCallCollaborator(t.Body) {
				return true
			}
		}
	}
	return false
}

func exprCallsCollaborator(e BoolExpr) bool {
	if valueCallsCollaborator(e.Left) || valueCallsCollaborator(e.Right) {
		return true
	}
	return (e.LHS != nil && exprCallsCollaborator(*e.LHS)) || (e.RHS != nil && exprCallsCollaborator(*e.RHS))
}

// Deferred is one run of a collaborator check whose interactions conditions were still unknown
// when its live pass finished. Resolve answers it later, without sending anything.
type Deferred struct {
	check *Check
	// start is the context the live pass began from: variables, RNG state, insertion point.
	start *Context
	rec   *collabUnit

	mu       sync.Mutex
	reported map[string]int
}

// newDeferred captures a finished live pass. start must be the snapshot taken before the pass ran;
// already holds the findings the live pass reported, so a replay does not report them twice.
func newDeferred(check *Check, start *Context, rec *collabUnit, already []Finding) *Deferred {
	d := &Deferred{check: check, start: start, rec: rec, reported: make(map[string]int)}
	for _, f := range already {
		d.reported[findingKey(f)]++
	}
	return d
}

// Addresses are the collaborator addresses the live pass planted, in mint order.
func (d *Deferred) Addresses() []string { return append([]string(nil), d.rec.addrs...) }

// Probes is how many requests the live pass sent.
func (d *Deferred) Probes() int { return len(d.rec.sends) }

// Param names the insertion point this run attacked, empty outside a `given insertion point` check.
func (d *Deferred) Param() string {
	if d.start.point == nil {
		return ""
	}
	return d.start.point.Name
}

// PollErr is the last error the interaction server returned during the live pass, if any.
func (d *Deferred) PollErr() error { return d.rec.pollErr }

// Resolve replays the run against the interactions that have arrived since. It returns the findings
// the replay reports that were not already reported (by the live pass or an earlier Resolve), and
// settled = true once no condition is unknown any more. An error is a replay that could not be
// completed — the caller keeps the run outstanding rather than calling it clean.
func (d *Deferred) Resolve() (findings []Finding, settled bool, err error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	c := *d.start
	c.Variables = cloneVars(d.start.Variables)
	c.sink = replayingSink{}
	c.collabAddrs = nil
	c.observed = nil
	c.sent, c.tools, c.unresolved = nil, nil, nil
	c.deferred = nil
	c.unit = &collabUnit{replay: true, sends: d.rec.sends, tools: d.rec.tools, addrs: d.rec.addrs}

	all, err := runCheckBody(d.check, &c)
	if err == nil {
		err = c.unit.err
	}
	if err != nil {
		return nil, false, err
	}
	// A finding is new when this replay reports it more times than every earlier pass did. The
	// ledger keeps the most any pass reported, so a finding is never handed back twice.
	counts := make(map[string]int, len(all))
	for _, f := range all {
		k := findingKey(f)
		counts[k]++
		if counts[k] > d.reported[k] {
			findings = append(findings, f)
		}
	}
	for k, n := range counts {
		if n > d.reported[k] {
			d.reported[k] = n
		}
	}
	return findings, !c.unit.unknown || c.unit.halted, nil
}

func findingKey(f Finding) string {
	return fmt.Sprintf("%s\x00%s\x00%s\x00%s\x00%s", f.IssueName, f.Severity, f.Confidence, f.Description, f.Param)
}

func cloneVars(in map[string]Value) map[string]Value {
	out := make(map[string]Value, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// snapshot copies ctx as a run's starting state, before the live pass mutates it.
func (ctx *Context) snapshot() *Context {
	c := *ctx
	c.Variables = cloneVars(ctx.Variables)
	c.sent, c.tools, c.unresolved = nil, nil, nil
	c.collabAddrs, c.observed = nil, nil
	c.deferred = nil
	c.unit = nil
	return &c
}
