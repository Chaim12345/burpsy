package session

import (
	"bufio"
	"bytes"
	"net/textproto"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// Absorbing Set-Cookie from raw response bytes, and reporting who is feeding the jar.
//
// # Why this exists beside HandleResponse
//
// Coordinator.HandleResponse takes `hdrs map[string]string`, which cannot hold a response's
// Set-Cookie headers: a login that sets a session cookie and a CSRF cookie sends two Set-Cookie
// lines, and a map keyed by header name holds one of them. Every caller of HandleResponse builds
// that map itself from an already-parsed response, so the loss is invisible at those call sites and
// was never going to be noticed there. The proxy has the actual response bytes, so it gets a method
// that reads them: every Set-Cookie line, in order, none of them dropped.
//
// # Why the sources are recorded
//
// Before this, nothing on the proxy path absorbed cookies at all, while the Session page's empty
// state told the operator that browsing through the proxy would fill the jar. An empty jar and a jar
// nothing feeds render identically — that is the failure this file is written against — so the
// coordinator now records which surfaces have registered as absorption sources and how many
// responses they actually offered it. "No cookies yet" and "nothing is watching" become two
// different, reportable facts, which is what /api/session/cookies projects.

// AbsorptionSource names a surface that feeds the cookie jar. Registered by the surface itself at
// wiring time, the same shape upstream.Policy.Attach uses, so the report reflects what was actually
// wired rather than what this package hopes was wired.
type AbsorptionSource string

const (
	// SourceProxy is the proxy listener: traffic the operator's own browser drove. On by default in
	// Burp, and unconditional here — see Coordinator.AbsorbResponseCookies.
	SourceProxy AbsorptionSource = "proxy"
	// SourceMacro is a session-handling login macro: the web Session page's runner, the CLI's, the
	// crawler's session gate and project recovery all reach the jar through one, so they report as
	// one source rather than four. The crawler is not listed separately for that reason — its
	// absorption is a macro step, and a "crawler" entry would name a second path that does not exist.
	SourceMacro AbsorptionSource = "macro"
	// SourceRepeater is the Repeater's own send (burpsy-react-ui-sn3j): a response the operator
	// resent by hand. Burp's own monitored-tool list offers Proxy, Intruder, Scanner, Sequencer,
	// Repeater, Extensions; the surfaces burpsy has that hold raw responses are the Repeater, the
	// Intruder's stored exemplars and the scanner's audit reads, named in Burp's vocabulary.
	SourceRepeater AbsorptionSource = "repeater"
	// SourceIntruder is an attack's stored exemplar response (burpsy-react-ui-sn3j). One per result
	// bucket, not one per request — the engine's memory contract — so an attack that lands in four
	// buckets offers the jar four responses, which is the same set of Set-Cookie lines the attack
	// actually saw behave distinctly.
	SourceIntruder AbsorptionSource = "intruder"
	// SourceScanner is the audit engine's own probe responses (burpsy-react-ui-sn3j). An audit reads
	// through sender.Authorised paths that record exchanges; the responses a check sends are the
	// scanner's to observe.
	SourceScanner AbsorptionSource = "scanner"
)

// JarObservation is what the jar can say about itself beyond its contents.
type JarObservation struct {
	// Sources are the surfaces that registered as feeding the jar, sorted. Empty means nothing does,
	// and an empty jar under an empty source list is not "no cookies yet" — it is "no cookies will
	// ever arrive".
	Sources []AbsorptionSource
	// ResponsesObserved is how many responses were offered to the jar for absorption, whether or not
	// any of them carried a Set-Cookie. Zero with a non-empty source list means the source is wired
	// and no traffic has flowed through it yet, which is a third distinct state.
	ResponsesObserved uint64
	// SetCookiesAbsorbed is how many Set-Cookie header lines were fed to a jar. Counted per header
	// line, not per cookie stored: a line that carried no name=value pair is still a line the origin
	// sent, and hiding it would make a jar that stayed empty after a real Set-Cookie look like a jar
	// that was never offered one.
	SetCookiesAbsorbed uint64
}

// absorption is the coordinator's record of who feeds the jar and how much they have offered it.
type absorption struct {
	mu      sync.RWMutex
	sources map[AbsorptionSource]bool

	// monitored is the operator's monitored-tool set (burpsy-react-ui-sn3j): which sources may
	// ABSORB. Registered sources still count as attached; a source switched off here shows in
	// Observation as attached-but-not-monitoring rather than vanishing, because "the Repeater
	// never registered" and "you switched the Repeater off" are different facts an operator
	// debugging an empty jar needs told apart. Defaults to ALL sources, matching Burp's
	// proxy-on-by-default taken to the surface set this port has: a disabled-by-default switch
	// would reproduce the exact state AbsorbResponseCookies exists to end (see its contract
	// note), and an off-by-default entry here would silently un-fill a jar that was filling.
	monitored map[AbsorptionSource]bool

	responses atomic.Uint64
	cookies   atomic.Uint64
}

// monitors answers whether one source may absorb. Unbuilt map = every source may, which is the
// default; an explicitly built map answers membership.
func (a *absorption) monitors(src AbsorptionSource) bool {
	if len(a.monitored) == 0 {
		return true
	}
	return a.monitored[src]
}

func (a *absorption) attach(src AbsorptionSource) {
	if src == "" {
		return
	}
	a.mu.Lock()
	if a.sources == nil {
		a.sources = make(map[AbsorptionSource]bool, 3)
	}
	a.sources[src] = true
	a.mu.Unlock()
}

func (a *absorption) observation() JarObservation {
	a.mu.RLock()
	out := make([]AbsorptionSource, 0, len(a.sources))
	for src := range a.sources {
		out = append(out, src)
	}
	a.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return JarObservation{
		Sources:            out,
		ResponsesObserved:  a.responses.Load(),
		SetCookiesAbsorbed: a.cookies.Load(),
	}
}

// AttachAbsorptionSource records that a surface is feeding this coordinator's cookie jar.
//
// Called by the surface at wiring time rather than asserted here, because this package cannot see
// whether a caller actually holds it. A surface that registers and then never calls
// AbsorbResponseCookies shows as a source with zero responses observed, which is a visible wiring
// bug rather than a silent one.
func (c *Coordinator) AttachAbsorptionSource(src AbsorptionSource) {
	if c == nil {
		return
	}
	c.absorb.attach(src)
}

// Observation reports which surfaces feed the jar and how much traffic they have offered it. See
// JarObservation for why each field is separate from "how many cookies are in the jar".
func (c *Coordinator) Observation() JarObservation {
	if c == nil {
		return JarObservation{}
	}
	return c.absorb.observation()
}

// AbsorbResponseCookies reads every Set-Cookie header from one raw HTTP response and folds it into
// the jar for the given authority. It returns how many Set-Cookie lines it found.
//
// Unconditional: there is no per-tool switch in front of this, and the caller is the switch. Burp
// makes the monitored-tool set configurable with Proxy on by default; this build has one absorbing
// surface, and a disabled-by-default option would reproduce the exact state this method exists to
// end — a jar the UI says the proxy fills and the proxy does not fill. A tools-scope switch is a
// later addition that needs a UI to be honest about, and it must default to on.
//
// A response whose head does not parse is counted as observed and absorbed from zero times. That is
// not a silent drop: the observation counter moves, so a proxy feeding malformed heads shows as
// traffic observed with nothing absorbed rather than as no traffic at all.
// AbsorbResponseCookies reads every Set-Cookie header from one raw HTTP response and folds it into
// the jar for the given authority, attributed to the surface calling it. It returns how many
// Set-Cookie lines it found.
//
// The monitored-tool set (burpsy-react-ui-sn3j) is the switch Burp's settings expose: a source
// the operator switched off has its response COUNTED as observed — the wiring is real either
// way, and Observation must still be able to say "the Repeater is attached and traffic is
// flowing" — but absorbs nothing. That is the same three-state honesty the observation counters
// exist for: attached / attached-and-monitoring / absorbing.
//
// The default is every source monitored (see absorption.monitored), matching the contract note
// this method has carried since it was proxy-only: the switch must not reproduce the
// "a jar the UI says X fills and X does not fill" state it was written to end.
func (c *Coordinator) AbsorbResponseCookies(src AbsorptionSource, host string, port uint16, tls bool, response []byte) int {
	if c == nil {
		return 0
	}
	c.absorb.responses.Add(1)
	if !c.absorb.monitors(src) {
		return 0
	}
	values := setCookieValues(response)
	for _, v := range values {
		c.jarMgr.AbsorbSetCookie(host, port, tls, v)
	}
	if n := len(values); n > 0 {
		c.absorb.cookies.Add(uint64(n))
		return n
	}
	return 0
}

// SetMonitoredSources sets which surfaces may absorb cookies (burpsy-react-ui-sn3j) — Burp's
// "configure the cookie jar to monitor any of the following tools". An empty set is refused
// rather than read as "monitor nothing": un-monitoring every surface is a jar that can only
// stay empty, and a caller who means it can pass a set that names no attached source — but an
// empty slice, the zero value of a missed field on a wire shape, must not silently stop the
// jar filling. Every entry is trimmed; an unknown name is kept: the vocabulary belongs to the
// caller (Burp's list includes Sequencer and Extensions, which this port does not attach), and
// a set naming an unattached source monitors it for the day it attaches — the same
// registered-when-wired rule AttachAbsorptionSource holds.
func (c *Coordinator) SetMonitoredSources(srcs []string) {
	if c == nil {
		return
	}
	c.absorb.mu.Lock()
	defer c.absorb.mu.Unlock()
	if len(srcs) == 0 {
		return
	}
	m := make(map[AbsorptionSource]bool, len(srcs))
	for _, raw := range srcs {
		name := AbsorptionSource(strings.TrimSpace(raw))
		if name != "" {
			m[name] = true
		}
	}
	c.absorb.monitored = m
}

// MonitoredSources reports the monitored-tool set in force: every attached source when the
// default holds, or the configured subset. Sorted, so two reads of one state agree.
func (c *Coordinator) MonitoredSources() []string {
	if c == nil {
		return nil
	}
	c.absorb.mu.RLock()
	defer c.absorb.mu.RUnlock()
	if len(c.absorb.monitored) == 0 {
		out := make([]string, 0, len(c.absorb.sources))
		for src := range c.absorb.sources {
			out = append(out, string(src))
		}
		sort.Strings(out)
		return out
	}
	out := make([]string, 0, len(c.absorb.monitored))
	for src := range c.absorb.monitored {
		out = append(out, string(src))
	}
	sort.Strings(out)
	return out
}

// setCookieValues extracts the Set-Cookie header values from a raw HTTP response, in the order the
// origin sent them.
//
// The head is parsed with textproto rather than net/http.ReadResponse so the body is never touched:
// this runs on the proxy's capture path for every response, and reading (or worse, decompressing) a
// body to find a header would be a per-response cost for nothing. A response with no header
// terminator yields nothing — the headers may be truncated mid-line and a partial Set-Cookie is not
// a cookie.
func setCookieValues(response []byte) []string {
	sep := bytes.Index(response, []byte("\r\n\r\n"))
	if sep < 0 {
		// Bare-LF heads exist on the wire and burpsy's own senders never produce them, but a proxied
		// origin can. Accepting them here is cheaper than losing a real session cookie to framing.
		if sep = bytes.Index(response, []byte("\n\n")); sep < 0 {
			return nil
		}
		sep += 2
	} else {
		sep += 4
	}
	head := response[:sep]
	// textproto wants the status line gone and the block terminated, which head already is.
	nl := bytes.IndexByte(head, '\n')
	if nl < 0 || nl+1 >= len(head) {
		return nil
	}
	r := textproto.NewReader(bufio.NewReader(bytes.NewReader(head[nl+1:])))
	hdr, err := r.ReadMIMEHeader()
	if err != nil && len(hdr) == 0 {
		return nil
	}
	// Values, not Get: a login that sets a session cookie and a CSRF cookie sends two lines, and
	// this is the whole reason the method takes bytes instead of a map.
	return hdr.Values("Set-Cookie")
}
