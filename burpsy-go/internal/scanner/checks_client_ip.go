package scanner

// Spoofable client-IP headers, tested actively (burpsy-react-ui-0vzb.14).
//
// An application behind a reverse proxy learns the client's address from a header the proxy sets
// (X-Forwarded-For and its relatives). When the application trusts that header on a request the
// proxy did not rewrite — or when there is no proxy at all — the client chooses its own address.
// That matters when the address is an input to a security decision: an "internal only" page that
// admits loopback, or a rate limiter keyed on the address. (PortSwigger Web Security Academy,
// "Authentication vulnerabilities: flawed brute-force protection"; OWASP WSTG-ATHN-03.)
//
// Each header is its own probe, so a finding names the exact header. The headers:
// X-Forwarded-For, X-Real-IP, X-Client-IP, True-Client-IP, CF-Connecting-IP, X-Originating-IP and
// Forwarded (RFC 7239, as "for=<ip>").
//
// # Access-control bypass (burpsy row, CWE-290)
//
// Only for a safe-method request (GET, HEAD, OPTIONS) whose fresh baseline is 401 or 403 — a refused
// state-changing request is never replayed with a bypass that might make it succeed. A finding
// needs, for one header:
//
//   - 127.0.0.1 in the header: 2xx, with a body different from the baseline's;
//   - a random documentation address (203.0.113.0/24) in the same header: not 2xx — so it is the
//     claimed address that opened the door, not the header's presence or a flapping endpoint;
//   - 127.0.0.1 again, after the control: 2xx again.
//
// # Rate-limit bypass (burpsy row, CWE-348)
//
// Only for a safe-method request or a captured login (a password-like field), whose fresh baseline
// is 429. A finding needs, for one header: a fresh documentation address answered with neither 429
// nor 5xx; the unmodified request, sent next, still 429 — the limit has not simply lapsed; and a
// second fresh address again not 429.
//
// # Address reflected (Burp's "Spoofable client IP address", information)
//
// One probe carries every header at once, each with its own random documentation address, plus an
// echo control: a header no proxy sets (X-Burpsy-Echo-Control) with another address. An address is
// counted only as an exact token — in a parsed response header value, or in the body with neither a
// digit nor a dot on either side — and only when the baseline did not carry it. If the echo control
// came back too the application echoes request headers wholesale and nothing is reported. The header
// whose address came back is then sent alone with a fresh address, which must come back the same way.

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"
)

// The burpsy rows this check reports; see BurpsyNativeRows. The reflection finding is Burp's own
// "Spoofable client IP address" row.
const (
	IssueClientIPAccessBypass    = "Access control bypass via spoofed client IP header"
	IssueClientIPRateLimitBypass = "Rate limit bypass via spoofed client IP header"
	spoofableClientIPRow         = "Spoofable client IP address"
	clientIPEchoControlHeader    = "X-Burpsy-Echo-Control"
)

// clientIPProbeHeaders are the headers probed, in order.
var clientIPProbeHeaders = []string{
	"X-Forwarded-For", "X-Real-IP", "X-Client-IP", "True-Client-IP",
	"CF-Connecting-IP", "X-Originating-IP", "Forwarded",
}

// clientIPSpoofEnabled is the check's own switch.
func clientIPSpoofEnabled(c *ScanConfig) bool { return c != nil && c.CheckClientIPSpoofing }

// withClientIPSpoofing adds this check to the runner of the descriptor it rides ("Broken access
// control"). The inner runner keeps its own switches; a proven finding from either half is returned
// even when the other failed.
func withClientIPSpoofing(inner CheckRunner) CheckRunner {
	return func(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
		if cc == nil || cc.Scanner == nil {
			return nil, nil
		}
		innerF, innerErr := inner(ctx, cc)
		var ipF []*Finding
		var ipErr error
		if clientIPSpoofEnabled(cc.Config) {
			ipF, ipErr = checkClientIPSpoofing(ctx, cc)
		}
		out := append(innerF, ipF...)
		switch {
		case len(ipF) > 0:
			return out, nil
		case innerErr != nil:
			return innerF, innerErr
		case ipErr != nil:
			return innerF, ipErr
		}
		return out, nil
	}
}

// clientIPHeaderValue renders an address the way the header carries it.
func clientIPHeaderValue(header, ip string) string {
	if strings.EqualFold(header, "Forwarded") {
		return "for=" + ip
	}
	return ip
}

// docIP returns a random address in 203.0.113.0/24 (RFC 5737) not in avoid.
func docIP(avoid map[string]bool) string {
	for {
		n, _ := rand.Int(rand.Reader, big.NewInt(253))
		ip := fmt.Sprintf("203.0.113.%d", n.Int64()+1)
		if !avoid[ip] {
			avoid[ip] = true
			return ip
		}
	}
}

func is2xx(s int) bool { return s >= 200 && s < 300 }

// ipTokenIn reports whether ip occurs in s as a whole token: neither a digit nor a dot on either side.
func ipTokenIn(s, ip string) bool {
	for i := 0; ; {
		j := strings.Index(s[i:], ip)
		if j < 0 {
			return false
		}
		start, end := i+j, i+j+len(ip)
		before := start == 0 || !isIPChar(s[start-1])
		after := end == len(s) || !isIPChar(s[end])
		if before && after {
			return true
		}
		i = start + 1
	}
}

func isIPChar(b byte) bool { return b == '.' || (b >= '0' && b <= '9') }

// ipReflectedWhere says where ip came back in a raw response: "header <Name>", "body", or "".
func ipReflectedWhere(raw []byte, ip string) string {
	head, body, _ := strings.Cut(string(raw), "\r\n\r\n")
	lines := strings.Split(head, "\r\n")
	for _, l := range lines[1:] {
		name, value, ok := strings.Cut(l, ":")
		if ok && ipTokenIn(value, ip) {
			return "header " + strings.TrimSpace(name)
		}
	}
	if ipTokenIn(body, ip) {
		return "body"
	}
	return ""
}

func isSafeMethod(m string) bool {
	switch strings.ToUpper(m) {
	case "GET", "HEAD", "OPTIONS":
		return true
	}
	return false
}

// clientIPProber is one URL's run.
type clientIPProber struct {
	cc  *CheckContext
	h   *ProbeHarness
	raw string
}

func (p *clientIPProber) with(ctx context.Context, header, value string) (ProbeResponse, error) {
	return p.h.send(ctx, []byte(rawSetHeader(p.raw, header, value)))
}

// checkClientIPSpoofing runs the three tests against one URL.
func checkClientIPSpoofing(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	if cc == nil || cc.Scanner == nil || cc.Exchange == nil {
		return nil, nil
	}
	raw := requestRaw(cc.Scanner, cc.Exchange)
	if raw == "" {
		return nil, nil
	}
	if strings.EqualFold(headerValue(raw, "Upgrade"), "websocket") {
		// A WebSocket handshake is not a page whose access or reflection this check can read.
		return nil, nil
	}
	h, err := NewProbeHarness(ctx, cc, []string{"query"})
	if err != nil {
		return nil, fmt.Errorf("client IP spoofing: %w", err)
	}
	p := &clientIPProber{cc: cc, h: h, raw: raw}
	var out []*Finding
	var firstErr error
	keep := func(f *Finding, err error) {
		if f != nil {
			out = append(out, f)
		}
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	base := h.Baseline()
	method := cc.Exchange.Method
	switch {
	case (base.Status == 401 || base.Status == 403) && isSafeMethod(method):
		keep(p.accessBypass(ctx, base))
	case base.Status == 429 && (isSafeMethod(method) || hasLoginFields(raw)):
		keep(p.rateLimitBypass(ctx))
	}
	keep(p.reflection(ctx, base))
	if len(out) > 0 {
		return out, nil
	}
	if firstErr != nil {
		return nil, fmt.Errorf("client IP spoofing: %w", firstErr)
	}
	return nil, nil
}

func hasLoginFields(raw string) bool {
	_, ok := sessLoginFields(raw)
	return ok
}

func (p *clientIPProber) accessBypass(ctx context.Context, base ProbeResponse) (*Finding, error) {
	avoid := map[string]bool{}
	for _, hdr := range clientIPProbeHeaders {
		loop := clientIPHeaderValue(hdr, "127.0.0.1")
		first, err := p.with(ctx, hdr, loop)
		if err != nil {
			return nil, err
		}
		if !is2xx(first.Status) || strings.TrimSpace(first.Body) == strings.TrimSpace(base.Body) {
			continue
		}
		ctrlIP := docIP(avoid)
		ctrl, err := p.with(ctx, hdr, clientIPHeaderValue(hdr, ctrlIP))
		if err != nil {
			return nil, err
		}
		if is2xx(ctrl.Status) {
			// Any address opens it: the header's presence, not the claimed address, decides — or the
			// endpoint is not refusing at all any more. Neither is this finding.
			continue
		}
		again, err := p.with(ctx, hdr, loop)
		if err != nil {
			return nil, err
		}
		if !is2xx(again.Status) {
			continue
		}
		evidence := fmt.Sprintf("%s: (absent) -> HTTP %d\n%s: %s -> HTTP %d (%d-byte body)\n%s: %s -> HTTP %d\n%s: %s -> HTTP %d again",
			hdr, base.Status, hdr, loop, first.Status, len(first.Body), hdr, clientIPHeaderValue(hdr, ctrlIP),
			ctrl.Status, hdr, loop, again.Status)
		detail := fmt.Sprintf("The request is refused (HTTP %d) as sent, and admitted (HTTP %d, a different page) "+
			"when the %s request header claims the client is 127.0.0.1. The same header claiming %s, a "+
			"documentation address, is refused (HTTP %d), so it is the claimed address that decides; the "+
			"loopback claim was admitted again afterwards. A client chooses this header's value, so any client "+
			"can claim to be local and pass this access control.", base.Status, first.Status, hdr, ctrlIP, ctrl.Status)
		f := buildHeaderFinding(p.cc, IssueClientIPAccessBypass, "high", "firm", evidence, detail)
		f.Param = hdr
		return f, nil
	}
	return nil, nil
}

func (p *clientIPProber) rateLimitBypass(ctx context.Context) (*Finding, error) {
	avoid := map[string]bool{}
	notLimited := func(s int) bool { return s != 0 && s != 429 && s < 500 }
	for _, hdr := range clientIPProbeHeaders {
		ip1 := docIP(avoid)
		first, err := p.with(ctx, hdr, clientIPHeaderValue(hdr, ip1))
		if err != nil {
			return nil, err
		}
		if !notLimited(first.Status) {
			continue
		}
		plain, err := p.h.send(ctx, []byte(p.raw))
		if err != nil {
			return nil, err
		}
		if plain.Status != 429 {
			// The limit lapsed (or never held): the header proved nothing.
			return nil, nil
		}
		ip2 := docIP(avoid)
		second, err := p.with(ctx, hdr, clientIPHeaderValue(hdr, ip2))
		if err != nil {
			return nil, err
		}
		if !notLimited(second.Status) {
			continue
		}
		evidence := fmt.Sprintf("(no %s) -> HTTP 429\n%s: %s -> HTTP %d\n(no %s) -> HTTP %d\n%s: %s -> HTTP %d",
			hdr, hdr, clientIPHeaderValue(hdr, ip1), first.Status, hdr, plain.Status, hdr,
			clientIPHeaderValue(hdr, ip2), second.Status)
		detail := fmt.Sprintf("The request is rate limited (HTTP 429) as sent. With the %s request header "+
			"claiming a fresh address it is answered (HTTP %d), while the unmodified request sent straight "+
			"afterwards is still limited, and a second fresh address is answered again (HTTP %d). The limiter "+
			"keys on a value the client chooses, so a client that rotates the header is never limited.",
			hdr, first.Status, second.Status)
		f := buildHeaderFinding(p.cc, IssueClientIPRateLimitBypass, "medium", "firm", evidence, detail)
		f.Param = hdr
		return f, nil
	}
	return nil, nil
}

func (p *clientIPProber) reflection(ctx context.Context, base ProbeResponse) (*Finding, error) {
	avoid := map[string]bool{}
	ips := make(map[string]string, len(clientIPProbeHeaders))
	req := p.raw
	for _, hdr := range clientIPProbeHeaders {
		ip := docIP(avoid)
		ips[hdr] = ip
		req = rawSetHeader(req, hdr, clientIPHeaderValue(hdr, ip))
	}
	echoIP := docIP(avoid)
	req = rawSetHeader(req, clientIPEchoControlHeader, echoIP)
	resp, err := p.h.send(ctx, []byte(req))
	if err != nil {
		return nil, err
	}
	if ipReflectedWhere(resp.Raw, echoIP) != "" {
		// Request headers are echoed wholesale (a debug page, a reflected request dump).
		return nil, nil
	}
	for _, hdr := range clientIPProbeHeaders {
		ip := ips[hdr]
		if ipReflectedWhere(resp.Raw, ip) == "" || ipReflectedWhere(base.Raw, ip) != "" {
			continue
		}
		fresh := docIP(avoid)
		confirm, err := p.with(ctx, hdr, clientIPHeaderValue(hdr, fresh))
		if err != nil {
			return nil, err
		}
		where := ipReflectedWhere(confirm.Raw, fresh)
		if where == "" {
			continue
		}
		evidence := fmt.Sprintf("%s: %s -> %s in the response's %s (alone, a second probe); "+
			"%s: %s was not echoed", hdr, clientIPHeaderValue(hdr, fresh), fresh, where,
			clientIPEchoControlHeader, echoIP)
		detail := fmt.Sprintf("The address claimed in the %s request header was used by the application "+
			"as the client's address: %s, sent in that header alone, came back as a whole token in the "+
			"response's %s, while the same kind of value in a header no proxy sets was not echoed. "+
			"Review whether this address feeds any security decision (access control, rate limiting, "+
			"audit logging).", hdr, fresh, where)
		f := buildHeaderFinding(p.cc, spoofableClientIPRow, "info", "firm", evidence, detail)
		f.Param = hdr
		return f, nil
	}
	return nil, nil
}
