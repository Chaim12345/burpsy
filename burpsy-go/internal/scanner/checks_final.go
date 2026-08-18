package scanner

// The last sixteen rows. Grouped here because each needs one capability that did not exist
// before, and the groups are small.

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/burpsy-go/burpsy/internal/alpn"
	"github.com/burpsy-go/burpsy/internal/bcheck"
	burpsyhttp2 "github.com/burpsy-go/burpsy/internal/http2"
	"github.com/burpsy-go/burpsy/internal/sender"
	"github.com/burpsy-go/burpsy/internal/session"
)

// ---------------------------------------------------------------------------
// reflected siblings of the stored rows
// ---------------------------------------------------------------------------

// reflectedContextCheck is the reflected counterpart of storedContextCheck: submit a canary
// into each insertion point of *this* request and look for it in *this* response, in the
// context the row is about.
//
// The distinction from the stored rows is the exchange: a value echoed by the same response
// that carried it is reflected, and one surfacing in a later exchange is stored. Sharing the
// context matchers keeps the two families deciding "which row" the same way.
func reflectedContextCheck(row, severity string, inContext func(body, token string) (string, bool)) CheckRunner {
	return func(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
		h, err := NewProbeHarness(ctx, cc, DefaultProbeInsertionKinds)
		if err != nil {
			return nil, err
		}
		points := h.Points()
		if len(points) > MaxInjectionPointsPerCheck {
			points = points[:MaxInjectionPointsPerCheck]
		}
		for _, point := range points {
			token := "bsyrefl" + ArithmeticProofProduct() + strings.ToLower(point.Name)
			// A canary already present in the baseline would make any response look
			// reflective, so the baseline is checked before the probe is judged.
			if indexFold(h.Baseline().Body, token) >= 0 {
				continue
			}
			res, err := h.Send(ctx, point, token)
			if err != nil {
				continue
			}
			evidence, matched := inContext(res.Body, token)
			if !matched {
				continue
			}
			return []*Finding{buildHeaderFinding(cc, row, severity, "firm", evidence,
				fmt.Sprintf("a value submitted in %s %q is reflected here in the context this issue is about",
					point.Kind, point.Name))}, nil
		}
		return nil, nil
	}
}

// contextTransformed matches a canary that came back *altered* — the "suspicious input
// transformation" condition. An unchanged echo is ordinary reflection and belongs to another
// row, so an exact match is explicitly not a finding here.
func contextTransformed(body, token string) (string, bool) {
	if indexFold(body, token) >= 0 {
		return "", false
	}
	// Look for a recognisable mutation of the token: the same prefix with the tail changed,
	// which is what an encoder, a case-folder or an escaper leaves behind.
	if len(token) < 8 {
		return "", false
	}
	prefix := token[:8]
	i := indexFold(body, prefix)
	if i < 0 {
		return "", false
	}
	return excerpt(body, i, len(token)), true
}

// ---------------------------------------------------------------------------
// session-dependent rows
// ---------------------------------------------------------------------------

// WithSessionCoordinator installs the handle the access-control and CSRF rows need. Without it
// both report a missing capability rather than comparing two anonymous requests and calling
// them identical.
func (s *ActiveScanner) WithSessionCoordinator(c *session.Coordinator) *ActiveScanner {
	s.sessions = c
	return s
}

// SessionCoordinator returns the scan's coordinator, or an error when none is configured.
func (cc *CheckContext) SessionCoordinator() (*session.Coordinator, error) {
	if cc == nil || cc.Scanner == nil || cc.Scanner.sessions == nil {
		return nil, fmt.Errorf("session: no session coordinator is configured for this scan")
	}
	return cc.Scanner.sessions, nil
}

func checkBrokenAccessControl(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	coord, err := cc.SessionCoordinator()
	if err != nil {
		return nil, err
	}
	if cc.Exchange == nil {
		return nil, nil
	}
	authed, _ := AuthContextsFrom(coord, cc.Exchange.Host, cc.Exchange.Port, cc.Exchange.TLS)

	h, err := NewProbeHarness(ctx, cc, []string{"header"})
	if err != nil {
		return nil, err
	}
	raw := requestRaw(cc.Scanner, cc.Exchange)
	authedRes, err := h.send(ctx, []byte(withCookieHeader(raw, authed.CookieHeader)))
	if err != nil {
		return nil, err
	}
	anonRes, err := h.send(ctx, []byte(withCookieHeader(raw, "")))
	if err != nil {
		return nil, err
	}

	ev := ClassifyAccessControl(authedRes.Status, anonRes.Status, authedRes.Body, anonRes.Body,
		headerValue(string(anonRes.Raw), "location"), authed.HasCredentials)
	if ev != ACEvidenceIdenticalResponses {
		return nil, nil
	}
	return []*Finding{buildHeaderFinding(cc, "Broken access control", "high", "firm",
		fmt.Sprintf("authenticated HTTP %d and unauthenticated HTTP %d returned the same body",
			authedRes.Status, anonRes.Status),
		"the endpoint serves the same response with and without session credentials, so its access control is not enforced")}, nil
}

// withCookieHeader replaces or removes the Cookie header of a raw request.
func withCookieHeader(raw, cookie string) string {
	head, body, hasBody := strings.Cut(raw, "\r\n\r\n")
	var kept []string
	for _, line := range strings.Split(head, "\r\n") {
		if strings.HasPrefix(strings.ToLower(line), "cookie:") {
			continue
		}
		kept = append(kept, line)
	}
	if cookie != "" {
		kept = append(kept, "Cookie: "+cookie)
	}
	out := strings.Join(kept, "\r\n") + "\r\n\r\n"
	if hasBody {
		out += body
	}
	return out
}

func checkCSRF(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	coord, err := cc.SessionCoordinator()
	if err != nil {
		return nil, err
	}
	if cc.Scanner == nil || cc.Exchange == nil {
		return nil, nil
	}
	// Only a state-changing request is worth testing; a GET carries no CSRF risk by itself.
	if strings.EqualFold(cc.Exchange.Method, "GET") || strings.EqualFold(cc.Exchange.Method, "HEAD") {
		return nil, nil
	}
	authed, _ := AuthContextsFrom(coord, cc.Exchange.Host, cc.Exchange.Port, cc.Exchange.TLS)
	if !authed.HasCredentials {
		// Without a session there is nothing to ride, and comparing two anonymous
		// requests would report every endpoint as vulnerable.
		return nil, nil
	}
	raw := requestRaw(cc.Scanner, cc.Exchange)
	respRaw := responseRaw(cc.Scanner, cc.Exchange)
	tokens := FindAntiCSRFTokens(responseBody(respRaw))

	h, err := NewProbeHarness(ctx, cc, []string{"header"})
	if err != nil {
		return nil, err
	}
	withToken, err := h.send(ctx, []byte(withCookieHeader(raw, authed.CookieHeader)))
	if err != nil {
		return nil, err
	}
	stripped := stripTokenParams(raw, tokens)
	withoutToken, err := h.send(ctx, []byte(withCookieHeader(stripped, authed.CookieHeader)))
	if err != nil {
		return nil, err
	}
	crossOrigin, err := h.send(ctx, []byte(withRefererHeader(
		withCookieHeader(raw, authed.CookieHeader), "https://evil.example.com/")))
	if err != nil {
		return nil, err
	}

	sameSite := strings.Contains(strings.ToLower(respRaw), "samesite=strict") ||
		strings.Contains(strings.ToLower(respRaw), "samesite=lax")

	ev := ClassifyCSRF(
		ProbeOutcome{Succeeded: withToken.Status < 400, Status: withToken.Status},
		ProbeOutcome{Succeeded: withoutToken.Status < 400, Status: withoutToken.Status},
		ProbeOutcome{Succeeded: crossOrigin.Status < 400, Status: crossOrigin.Status},
		sameSite)
	if ev == 0 {
		return nil, nil
	}
	return []*Finding{buildHeaderFinding(cc, "Cross-site request forgery", "medium", "firm",
		fmt.Sprintf("with token HTTP %d, without token HTTP %d, cross-origin Referer HTTP %d",
			withToken.Status, withoutToken.Status, crossOrigin.Status),
		"the state-changing request succeeds without its anti-CSRF token or from a foreign origin")}, nil
}

// stripTokenParams removes the named parameters from a raw request's query and body.
func stripTokenParams(raw string, tokens []string) string {
	out := raw
	for _, name := range tokens {
		for _, sep := range []string{"&", "?"} {
			for {
				i := strings.Index(out, sep+name+"=")
				if i < 0 {
					break
				}
				rest := out[i+1:]
				end := strings.IndexAny(rest, "& \r\n")
				if end < 0 {
					out = out[:i]
					break
				}
				out = out[:i] + sep + rest[end+1:]
			}
		}
	}
	return out
}

func withRefererHeader(raw, referer string) string {
	head, body, hasBody := strings.Cut(raw, "\r\n\r\n")
	var kept []string
	for _, line := range strings.Split(head, "\r\n") {
		if strings.HasPrefix(strings.ToLower(line), "referer:") ||
			strings.HasPrefix(strings.ToLower(line), "origin:") {
			continue
		}
		kept = append(kept, line)
	}
	kept = append(kept, "Referer: "+referer, "Origin: "+strings.TrimSuffix(referer, "/"))
	out := strings.Join(kept, "\r\n") + "\r\n\r\n"
	if hasBody {
		out += body
	}
	return out
}

// ---------------------------------------------------------------------------
// pipelining rows
// ---------------------------------------------------------------------------

// smugglingProbes are the CL.TE and TE.CL framing disagreements. A front end and back end that
// disagree about where a request ends is the whole of request smuggling.
func smugglingProbes(host, path string) [][]byte {
	clte := "POST " + path + " HTTP/1.1\r\nHost: " + host +
		"\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nX"
	tecl := "POST " + path + " HTTP/1.1\r\nHost: " + host +
		"\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nA\r\n0\r\n\r\n"
	follow := "GET " + path + " HTTP/1.1\r\nHost: " + host + "\r\n\r\n"
	return [][]byte{[]byte(clte), []byte(tecl), []byte(follow)}
}

// pipeliningCheck runs the framing probes down one connection and reports a disagreement.
//
// The verdict is deliberately narrow: a probe that provokes a 4xx from the front end proves the
// framing was rejected, which is the safe outcome. What signals smuggling is the *following*
// request on the same connection getting an answer that does not belong to it, which only shows
// up because SendPipelined keeps the connection and returns per-response framing.
func pipeliningCheck(row, detail string) CheckRunner {
	return func(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
		if cc.Scanner == nil || cc.Exchange == nil {
			return nil, nil
		}
		if cc.Scanner.sender == nil {
			return nil, fmt.Errorf("%s: no sender; a framing probe cannot be sent", row)
		}
		exchanges, err := cc.Scanner.sender.SendPipelined(ctx, cc.Exchange.Host, cc.Exchange.Port,
			cc.Exchange.TLS, smugglingProbes(cc.Exchange.Host, cc.Exchange.Path))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", row, err)
		}
		if len(exchanges) < 3 {
			// Fewer responses than requests means the connection closed early. That is a
			// framing signal on its own, but not a confirmed desync.
			return nil, nil
		}
		// The trailing plain GET must come back as its own well-formed response. A 4xx or a
		// body carrying the smuggled marker means the back end read the boundary elsewhere.
		last := exchanges[len(exchanges)-1]
		text := strings.ToLower(string(last.Raw))
		if !strings.Contains(text, " 400 ") && !strings.Contains(text, " 405 ") &&
			!strings.Contains(text, "unrecognized") && !strings.Contains(text, "invalid chunk") {
			return nil, nil
		}
		return []*Finding{buildHeaderFinding(cc, row, "high", "tentative",
			strings.TrimSpace(firstResponseLine(string(last.Raw))),
			detail+" The trailing request on the same connection was answered with a framing error, which means the boundary was read differently by two hops. Confirm by hand before acting on it.")}, nil
	}
}

func firstResponseLine(s string) string {
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		return s[:i]
	}
	return s
}

// ---------------------------------------------------------------------------
// Hidden HTTP/2
// ---------------------------------------------------------------------------

// checkHiddenHTTP2 reports an origin that speaks HTTP/2 without advertising it.
//
// # What the row actually means, and what this check used to do instead
//
// The row is about a *discrepancy*: an origin whose ALPN never offers h2, but which reads HTTP/2
// frames anyway if you simply write them. Such a surface is reached by nothing that negotiates
// politely, so it tends to sit behind less of the hardening the advertised HTTP/1.1 front has.
//
// The previous implementation sent one ordinary probe through the auto-preference sender and fired
// whenever the response text contained "HTTP/2". Since the sender offers h2 by default, that fired
// on essentially every modern HTTPS origin — and worse, it fired on exactly the origins that
// advertise h2 correctly, which is the opposite population. It was a near-universal false positive,
// recorded as a defect rather than papered over with a fixture.
//
// # The two observations, and why they must come from different connections
//
// Baseline: what this authority's ALPN says when h2 *is* offered. ProtocolFor answers that from the
// handshake the scan already paid for. An origin that answers h2 there is advertising h2, so there
// is nothing hidden and the check stops — this is Burp's own gate (Zpfw.Zw skips when its
// per-service h2 ledger already knows the service speaks h2).
//
// Probe: an isolated, non-pooled connection on which HTTP/2 is forced past that http/1.1 ALPN —
// RFC 9113 §3.3 prior knowledge over TLS. Burp does the same thing through
// Zwk0.FORCE_HTTP2_NON_POOLED. Non-pooled is load-bearing: an answer drawn from a connection the
// site had already negotiated would be an answer about that negotiation, not about this origin.
//
// The program is a preface and one empty SETTINGS frame, which is the least a client may say and
// still be speaking HTTP/2. A peer that replies with a parseable HTTP/2 frame read those octets as
// HTTP/2; an HTTP/1.1 server answers a 400 in text, which yields no frame. Nothing is asked about a
// path, so no request is smuggled past the scope gate — SendFrameProgramForcingHTTP2 still runs the
// host-level authorisation.
func checkHiddenHTTP2(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	if cc.Scanner == nil || cc.Exchange == nil || !cc.Exchange.TLS {
		return nil, nil
	}
	if cc.Scanner.sender == nil {
		return nil, fmt.Errorf("Hidden HTTP 2: no sender; the paired probe cannot be sent")
	}

	// Baseline. An error here is the target's, not the check's: an authority whose ALPN cannot be
	// observed cannot be said to be hiding anything, so the row stays silent rather than guessing.
	support, err := cc.Scanner.sender.ProtocolFor(ctx, cc.Exchange.Host, cc.Exchange.Port, true)
	if err != nil {
		return nil, nil
	}
	if support != sender.ProtocolSupportHTTP11 {
		return nil, nil
	}

	program := burpsyhttp2.NewH2FrameProgram(
		burpsyhttp2.NewFrameSpec(burpsyhttp2.TypeSettings, 0, 0, nil),
	)
	res, err := cc.Scanner.probeGate(cc.Exchange).SendFrameProgramForcingHTTP2(ctx, program)
	if err != nil {
		// A refusal or a connection the origin tore down on seeing the preface is the *safe*
		// answer for this row: it did not read our frames.
		return nil, nil
	}
	if res.Negotiated == alpn.H2 {
		// The baseline said http/1.1 and this handshake said h2. Two different answers from one
		// authority is a fact about the authority, not about hidden h2, so the row does not claim
		// one — see the ProtocolFor gate above.
		return nil, nil
	}
	if len(res.ReplyFrames) == 0 {
		return nil, nil
	}

	return []*Finding{buildHeaderFinding(cc, "Hidden HTTP 2", "info", "tentative",
		strings.Join(alpn.EgressOffer(true), ","),
		fmt.Sprintf("this origin's ALPN settled on HTTP/1.1 when h2 was offered, but a separate, non-pooled "+
			"connection on which HTTP/2 was written regardless of that negotiation was answered with %d HTTP/2 "+
			"frame(s); an HTTP/2 surface reachable only by prior knowledge is often less hardened than the "+
			"advertised HTTP/1.1 one in front of it", len(res.ReplyFrames)))}, nil
}

// ---------------------------------------------------------------------------
// provenance rows
// ---------------------------------------------------------------------------

// FindingProvenance is where a finding came from. The four "<x> generated issue" catalog rows
// are not detections: they are the labels Burp attaches when something other than its own
// scanner files a finding. Emitting them means reporting that such a finding exists, which is
// why they read from a ledger rather than probing anything.
type FindingProvenance int

const (
	ProvenanceBCheck FindingProvenance = iota
	ProvenanceTool
	ProvenanceManual
	ProvenanceFilter
)

// provenanceRows maps each source to the catalog row that labels it.
var provenanceRows = map[FindingProvenance]string{
	ProvenanceBCheck: "BCheck generated issue",
	ProvenanceTool:   "Extension generated issue",
	ProvenanceManual: "Manually generated issue",
	ProvenanceFilter: "Bambda generated issue",
}

// ProvenanceLedger counts findings by source. A scan with no BCheck corpus loaded records
// nothing under ProvenanceBCheck, and the row then correctly does not fire.
type ProvenanceLedger struct {
	mu     sync.RWMutex
	counts map[FindingProvenance]int
	names  map[FindingProvenance][]string
}

func NewProvenanceLedger() *ProvenanceLedger {
	return &ProvenanceLedger{
		counts: make(map[FindingProvenance]int),
		names:  make(map[FindingProvenance][]string),
	}
}

// Record notes that a finding named issue came from src.
func (l *ProvenanceLedger) Record(src FindingProvenance, issue string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.counts[src]++
	if len(l.names[src]) < 32 {
		l.names[src] = append(l.names[src], issue)
	}
}

// Count returns how many findings came from src.
func (l *ProvenanceLedger) Count(src FindingProvenance) int {
	if l == nil {
		return 0
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.counts[src]
}

// Issues returns the recorded issue names for src.
func (l *ProvenanceLedger) Issues(src FindingProvenance) []string {
	if l == nil {
		return nil
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	return append([]string{}, l.names[src]...)
}

// WithProvenanceLedger installs the ledger the four provenance rows read.
func (s *ActiveScanner) WithProvenanceLedger(l *ProvenanceLedger) *ActiveScanner {
	s.provenance = l
	return s
}

// RecordProvenance is the hook a finding-producing surface calls.
func (s *ActiveScanner) RecordProvenance(src FindingProvenance, issue string) {
	if s == nil || s.provenance == nil {
		return
	}
	s.provenance.Record(src, issue)
}

// provenanceCheck emits the label row when a finding of that provenance exists.
func provenanceCheck(src FindingProvenance) CheckRunner {
	row := provenanceRows[src]
	return func(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
		if cc == nil || cc.Scanner == nil || cc.Scanner.provenance == nil {
			// No ledger means nothing is tracking finding sources. That is not the same
			// as "no such findings exist", so it is reported rather than assumed clean.
			return nil, fmt.Errorf("%s: no provenance ledger is configured for this scan", row)
		}
		n := cc.Scanner.provenance.Count(src)
		if n == 0 {
			return nil, nil
		}
		issues := cc.Scanner.provenance.Issues(src)
		return []*Finding{buildHeaderFinding(cc, row, "info", "certain",
			strings.Join(issues, ", "),
			fmt.Sprintf("%d finding(s) in this scan were filed by that source rather than by a native check", n))}, nil
	}
}

// ---------------------------------------------------------------------------
// registration
// ---------------------------------------------------------------------------

func finalChecksEnabled(c *ScanConfig) bool { return c != nil && c.CheckExtendedActive }

// FinalCheckDescriptors returns the last sixteen rows.
func FinalCheckDescriptors() []CheckDescriptor {
	out := []CheckDescriptor{
		nativeDescriptor("Suspicious input transformation (reflected)", DispatchScopePerUrl, finalChecksEnabled,
			reflectedContextCheck("Suspicious input transformation (reflected)", "info", contextTransformed)),
		nativeDescriptor("CSS injection (reflected)", DispatchScopePerUrl, finalChecksEnabled,
			reflectedContextCheck("CSS injection (reflected)", "medium", contextInsideTag("style"))),
		nativeDescriptor("Client-side HTTP parameter pollution (reflected)", DispatchScopePerUrl, finalChecksEnabled,
			reflectedContextCheck("Client-side HTTP parameter pollution (reflected)", "low", contextInAttribute("src"))),
		nativeDescriptor("Form action hijacking (reflected)", DispatchScopePerUrl, finalChecksEnabled,
			reflectedContextCheck("Form action hijacking (reflected)", "medium", contextInAttribute("action"))),

		nativeDescriptor("Broken access control", DispatchScopePerUrl, finalChecksEnabled, checkBrokenAccessControl),
		nativeDescriptor("Cross-site request forgery", DispatchScopePerRequest, finalChecksEnabled, checkCSRF),

		nativeDescriptor("HTTP request smuggling", DispatchScopePerHost, finalChecksEnabled,
			pipeliningCheck("HTTP request smuggling", "A CL.TE / TE.CL framing pair was pipelined down one connection.")),
		nativeDescriptor("Client-side desync", DispatchScopePerHost, finalChecksEnabled,
			pipeliningCheck("Client-side desync", "A framing pair was pipelined down one connection to test whether the browser-visible boundary disagrees with the server's.")),

		nativeDescriptor("Hidden HTTP 2", DispatchScopePerHost, finalChecksEnabled, checkHiddenHTTP2),

		nativeDescriptor("External service interaction (SMTP)", DispatchScopePerUrl, oobChecksEnabled,
			oobCheck("External service interaction (SMTP)", "smtp")),

		nativeDescriptor("JWT arbitrary jku header supported", DispatchScopePerRequest, finalChecksEnabled,
			jwtHostedCheck("JWT arbitrary jku header supported", true)),
		nativeDescriptor("JWT arbitrary x5u header supported", DispatchScopePerRequest, finalChecksEnabled,
			jwtHostedCheck("JWT arbitrary x5u header supported", false)),
	}
	for _, src := range []FindingProvenance{ProvenanceBCheck, ProvenanceTool, ProvenanceManual, ProvenanceFilter} {
		out = append(out, nativeDescriptor(provenanceRows[src], DispatchScopePerHost,
			finalChecksEnabled, provenanceCheck(src)))
	}
	return out
}

var _ = bcheck.IpQuery
var _ = time.Second
