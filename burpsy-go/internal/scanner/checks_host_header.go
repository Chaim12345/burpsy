package scanner

// Host header injection: the application builds absolute URLs — links, script sources, redirect
// targets — from the Host header (or one of the headers proxies use to override it) without checking
// it against the hosts it actually serves. Reference: PortSwigger Web Security Academy, "HTTP Host
// header attacks" (portswigger.net/web-security/host-header) and its exploitation page, whose probe
// vehicles this check sends: an arbitrary Host, an absolute-form request target with a different
// Host, duplicate Host headers in both orders, a Host whose port carries injected text, and the
// override family (X-Forwarded-Host, X-Host, X-Forwarded-Server, X-HTTP-Host-Override, Forwarded).
//
// # Evidence
//
// A Host value echoed into the page as text proves nothing — every error page that prints "Host:
// x" would qualify. What makes the defect exploitable is the host becoming the AUTHORITY of a URL
// the browser will follow or load (password-reset and cache-poisoning attacks both hinge on it), so
// that is what is required:
//
//   - the canary host is the host of a URL in the probe response, read the way a browser reads it:
//     the Location / Content-Location / Refresh / Link headers resolved with redirectTargetHost, and
//     body URLs that begin at an attribute or string boundary (so "next=//canary" inside another
//     URL's query is not a link to the canary);
//   - the same canary is absent from the baseline response;
//   - a control probe through the same vehicle with a DIFFERENT canary moves with it: the second
//     canary appears as a URL host and the first one does not. A page that happened to retain the
//     first value (a shared cache, a sticky configuration) cannot pass that.
//
// # Safety
//
// Every probe is sent to the exchange's own authorised authority: the scope gate decides on the
// bound host, port and request path, never on the Host header the probe writes, so a canary Host
// cannot redirect traffic anywhere. Canaries are random labels under the reserved .invalid TLD (RFC
// 2606), which no resolver answers, so a front end that does route by Host reaches nothing. Each
// probe also carries a random cache-buster parameter, so a shared cache in front of the target
// stores the probe's response under a key no real user requests. Off by default (check_host_header).
//
// Routing-based SSRF — a front end that forwards the request to whatever host the Host header
// names — cannot be seen in band; it is confirmed by planting the collaborator domain in the Host
// header, which the out-of-band rows do (oobHostVehicles in checks_remaining.go).

import (
	"context"
	"fmt"
	"html"
	"strings"
)

// IssueHostHeaderInjection is burpsy's own row (burpsy_rows.go): Burp's catalogue has no entry for a
// Host header reflected into absolute URLs.
const IssueHostHeaderInjection = "Host header injection"

func hostHeaderEnabled(c *ScanConfig) bool { return c != nil && c.CheckHostHeader }

// hostOverrideHeaders are the headers reverse proxies and frameworks use to carry the original host,
// which an application that trusts them lets a client set directly.
var hostOverrideHeaders = [...]string{
	"X-Forwarded-Host", "X-Host", "X-Forwarded-Server", "X-HTTP-Host-Override", "Forwarded",
}

// hostVehicle is one way of handing the application a host.
type hostVehicle struct {
	name string
	// build returns the probe request: base with the vehicle carrying value.
	build func(base []byte, authority, value string) []byte
	// port marks the vehicle that injects into the port of the real host rather than naming a host.
	port bool
}

var hostVehicles = []hostVehicle{
	{name: "Host header", build: func(base []byte, _, v string) []byte {
		return withHostHeaders(base, v)
	}},
	{name: "absolute-form request target with a different Host header", build: func(base []byte, authority, v string) []byte {
		return withAbsoluteTarget(withHostHeaders(base, v), authority)
	}},
	{name: "duplicate Host header (the original first)", build: func(base []byte, authority, v string) []byte {
		return withHostHeaders(base, authority, v)
	}},
	{name: "duplicate Host header (the injected one first)", build: func(base []byte, authority, v string) []byte {
		return withHostHeaders(base, v, authority)
	}},
	{name: "Host header port", port: true, build: func(base []byte, authority, v string) []byte {
		return withHostHeaders(base, hostnameOf(authority)+":"+v)
	}},
}

// hostCanary is a fresh host no response could contain by chance.
func hostCanary() string { return newProbeCanary("h") + ".invalid" }

// portCanary is a fresh non-numeric "port": the injected text a lax Host parser carries into links.
func portCanary() string { return newProbeCanary("p") }

// checkHostHeaderInjection sends each vehicle with a canary host and reports the vehicles whose
// canary became the host of a URL in the response and moved with a control canary.
func checkHostHeaderInjection(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	h, err := NewProbeHarness(ctx, cc, []string{"query"})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", IssueHostHeaderInjection, err)
	}
	base := h.RequestBytes()
	authority := requestHostHeader(base)
	if authority == "" {
		authority = hostPort(cc.Exchange.Host, cc.Exchange.Port, cc.Exchange.TLS)
	}
	baseURL := exchangeURL(cc.Exchange)
	baseline := h.Baseline()
	// A response with no URL at all has nowhere to put a host: nothing below could be observed.
	if !strings.Contains(string(baseline.Raw), "//") {
		return nil, nil
	}

	send := func(raw []byte) (ProbeResponse, bool) {
		res, err := h.SendRequestHTTP1(ctx, withCacheBuster(raw))
		return res, err == nil
	}
	var confirmed []string
	var evidence []string
	for _, v := range hostVehicles {
		mk := hostCanary
		if v.port {
			mk = portCanary
		}
		first, second := mk(), mk()
		match := func(res ProbeResponse, value string) []string {
			if v.port {
				return hostURLSightings(baseURL, res.Raw, hostnameOf(authority)+":"+value, true)
			}
			return hostURLSightings(baseURL, res.Raw, value, false)
		}
		if len(match(baseline, first)) > 0 || len(match(baseline, second)) > 0 {
			continue
		}
		r1, ok := send(v.build(base, authority, first))
		if !ok {
			continue
		}
		seen := match(r1, first)
		if len(seen) == 0 {
			continue
		}
		r2, ok := send(v.build(base, authority, second))
		if !ok || len(match(r2, second)) == 0 || len(match(r2, first)) > 0 {
			continue
		}
		confirmed = append(confirmed, v.name)
		evidence = append(evidence, v.name+": "+seen[0])
	}

	// The override family goes out in one probe, each header carrying its own canary, so a hit names
	// its header; each hit is then confirmed alone with a fresh canary.
	canaries := map[string]string{}
	pairs := make([][2]string, 0, len(hostOverrideHeaders))
	for _, name := range hostOverrideHeaders {
		c := hostCanary()
		canaries[name] = c
		pairs = append(pairs, [2]string{name, overrideHeaderValue(name, c)})
	}
	if r, ok := send(withHeaderPairs(base, pairs)); ok {
		for _, name := range hostOverrideHeaders {
			seen := hostURLSightings(baseURL, r.Raw, canaries[name], false)
			if len(seen) == 0 || len(hostURLSightings(baseURL, baseline.Raw, canaries[name], false)) > 0 {
				continue
			}
			control := hostCanary()
			r2, ok := send(withHeaderPairs(base, [][2]string{{name, overrideHeaderValue(name, control)}}))
			if !ok || len(hostURLSightings(baseURL, r2.Raw, control, false)) == 0 ||
				len(hostURLSightings(baseURL, r2.Raw, canaries[name], false)) > 0 {
				continue
			}
			confirmed = append(confirmed, name+" header")
			evidence = append(evidence, name+": "+seen[0])
		}
	}
	if len(confirmed) == 0 {
		return nil, nil
	}
	f := buildProbeFinding(cc, IssueHostHeaderInjection, "firm",
		strings.Join(evidence, "; "),
		"a host supplied through the "+strings.Join(confirmed, ", ")+" became the host of an absolute URL in the "+
			"response (a link, script source or redirect target); a control canary through the same vehicle moved "+
			"with it, and neither appeared in the baseline. An attacker who can get a victim's request carry that "+
			"host — through a shared cache, or a password-reset link built from it — points the victim at a host "+
			"of the attacker's choosing.")
	f.Severity = "medium"
	return []*Finding{f}, nil
}

// overrideHeaderValue renders a host in the header's own syntax.
func overrideHeaderValue(name, host string) string {
	if strings.EqualFold(name, "Forwarded") {
		return "host=" + host
	}
	return host
}

// requestHostHeader is the captured request's first Host header value.
func requestHostHeader(raw []byte) string {
	_, headers, _, _ := splitRequest(raw)
	for _, line := range headers {
		if name, value, ok := strings.Cut(line, ":"); ok && strings.EqualFold(strings.TrimSpace(name), "host") {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

// hostnameOf drops the port from an authority, keeping an IPv6 literal's brackets.
func hostnameOf(authority string) string {
	if strings.HasPrefix(authority, "[") {
		if i := strings.IndexByte(authority, ']'); i >= 0 {
			return authority[:i+1]
		}
		return authority
	}
	if i := strings.LastIndexByte(authority, ':'); i >= 0 {
		return authority[:i]
	}
	return authority
}

// withHostHeaders replaces every Host header with one line per value, in order, where the first
// Host header was.
func withHostHeaders(raw []byte, values ...string) []byte {
	line, headers, body, eol := splitRequest(raw)
	out := make([]string, 0, len(headers)+len(values))
	placed := false
	for _, hd := range headers {
		if name, _, ok := strings.Cut(hd, ":"); ok && strings.EqualFold(strings.TrimSpace(name), "host") {
			if !placed {
				for _, v := range values {
					out = append(out, "Host: "+v)
				}
				placed = true
			}
			continue
		}
		out = append(out, hd)
	}
	if !placed {
		hs := make([]string, 0, len(values))
		for _, v := range values {
			hs = append(hs, "Host: "+v)
		}
		out = append(hs, out...)
	}
	return joinRequest(line, out, body, eol)
}

// withHeaderPairs sets each named header, replacing any the request already carries.
func withHeaderPairs(raw []byte, pairs [][2]string) []byte {
	line, headers, body, eol := splitRequest(raw)
	drop := map[string]bool{}
	for _, p := range pairs {
		drop[strings.ToLower(p[0])] = true
	}
	out := make([]string, 0, len(headers)+len(pairs))
	for _, hd := range headers {
		if name, _, ok := strings.Cut(hd, ":"); ok && drop[strings.ToLower(strings.TrimSpace(name))] {
			continue
		}
		out = append(out, hd)
	}
	for _, p := range pairs {
		out = append(out, p[0]+": "+p[1])
	}
	return joinRequest(line, out, body, eol)
}

// withAbsoluteTarget rewrites an origin-form request target to the absolute form naming authority.
func withAbsoluteTarget(raw []byte, authority string) []byte {
	line, headers, body, eol := splitRequest(raw)
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 3 || !strings.HasPrefix(parts[1], "/") {
		return raw
	}
	parts[1] = "http://" + authority + parts[1]
	return joinRequest(strings.Join(parts, " "), headers, body, eol)
}

// withCacheBuster adds a random query parameter, so a cache in front of the target files the probe's
// response under a key no real visitor asks for.
func withCacheBuster(raw []byte) []byte {
	return addQueryPairs(raw, [][2]string{{newProbeCanary("cb"), "1"}})
}

// hostURLSightings returns the places in a raw response where a URL's authority is host (or, with
// authorityText, where a URL's authority is literally that text, for a port that does not parse).
//
// Headers are read from the parsed header block; body URLs only count when they start at a
// boundary — a quote, whitespace, '(' or '>', or the '=' of an unquoted URL attribute or a meta
// refresh — so a URL nested in another URL's query string is not mistaken for a link.
func hostURLSightings(base string, raw []byte, host string, authorityText bool) []string {
	host = strings.ToLower(host)
	if host == "" {
		return nil
	}
	isHit := func(candidate string) bool {
		if authorityText {
			return authorityIs(candidate, host)
		}
		got, ok := redirectTargetHost(base, candidate)
		return ok && got == host
	}
	var out []string
	head, body := splitResponseHead(string(raw))
	for _, hd := range parsedResponseHeaders(head) {
		var candidates []string
		switch strings.ToLower(hd[0]) {
		case "location", "content-location":
			candidates = []string{hd[1]}
		case "refresh":
			if i := strings.Index(strings.ToLower(hd[1]), "url="); i >= 0 {
				candidates = []string{strings.Trim(hd[1][i+4:], `"' `)}
			}
		case "link":
			for _, part := range strings.Split(hd[1], ",") {
				if a, b := strings.IndexByte(part, '<'), strings.IndexByte(part, '>'); a >= 0 && b > a {
					candidates = append(candidates, part[a+1:b])
				}
			}
		}
		for _, c := range candidates {
			if isHit(c) {
				out = append(out, hd[0]+": "+strings.TrimSpace(hd[1]))
			}
		}
	}
	seen := map[string]bool{}
	for _, view := range []string{body, strings.ReplaceAll(body, `\/`, "/"), html.UnescapeString(body)} {
		for _, u := range bodyURLsNaming(view, host) {
			if !seen[u] && isHit(u) {
				seen[u] = true
				out = append(out, "body URL "+u)
			}
		}
	}
	return out
}

// authorityIs reports whether a URL's authority, read as text up to its end, equals want.
func authorityIs(u, want string) bool {
	i := strings.Index(u, "//")
	if i < 0 {
		return false
	}
	rest := u[i+2:]
	end := strings.IndexAny(rest, "/?#\\")
	if end >= 0 {
		rest = rest[:end]
	}
	if at := strings.LastIndexByte(rest, '@'); at >= 0 {
		rest = rest[at+1:]
	}
	return strings.EqualFold(rest, want)
}

// bodyURLsNaming returns the URL-shaped runs of body that contain host right after "//" and begin at
// a boundary.
func bodyURLsNaming(body, host string) []string {
	lower := strings.ToLower(body)
	var out []string
	for from := 0; ; {
		i := strings.Index(lower[from:], host)
		if i < 0 {
			return out
		}
		i += from
		from = i + len(host)
		if i < 2 || lower[i-2:i] != "//" {
			continue
		}
		start := i - 2
		if start > 0 && lower[start-1] == ':' {
			k := start - 1
			for k > 0 && isSchemeByte(lower[k-1]) {
				k--
			}
			if k < start-1 {
				start = k
			}
		}
		if !urlBoundaryBefore(lower, start) {
			continue
		}
		end := from
		for end < len(body) && !strings.ContainsRune("\"'<>` \t\r\n)", rune(body[end])) {
			end++
		}
		out = append(out, body[start:end])
	}
}

func isSchemeByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '+' || c == '-' || c == '.'
}

// urlBoundaryBefore reports whether a URL starting at start begins a value rather than continuing one.
func urlBoundaryBefore(lower string, start int) bool {
	if start == 0 {
		return true
	}
	switch lower[start-1] {
	case '"', '\'', '`', '(', '>', ' ', '\t', '\r', '\n', ',':
		return true
	case '=':
		before := lower[:start-1]
		for _, attr := range [...]string{"url", "href", "src", "action", "formaction", "srcset", "poster", "data"} {
			if strings.HasSuffix(before, attr) {
				return true
			}
		}
	}
	return false
}

// splitResponseHead splits a raw response at the first blank line, CRLF or bare LF.
func splitResponseHead(raw string) (head, body string) {
	i, n := strings.Index(raw, "\r\n\r\n"), 4
	if j := strings.Index(raw, "\n\n"); j >= 0 && (i < 0 || j < i) {
		i, n = j, 2
	}
	if i < 0 {
		return raw, ""
	}
	return raw[:i], raw[i+n:]
}

// parsedResponseHeaders parses a response header block the way an HTTP client does: lines end at LF
// with an optional CR before it (RFC 9112 section 2.2 lets a recipient accept a bare LF, and browsers
// and Go do), the status line is skipped, and a line only counts as a header when it is a token, a
// colon and a value. A bare CR inside a line does not end it, so text after one stays part of the
// value it was written into.
func parsedResponseHeaders(head string) [][2]string {
	lines := strings.Split(head, "\n")
	var out [][2]string
	for i, line := range lines {
		if i == 0 {
			continue
		}
		line = strings.TrimSuffix(line, "\r")
		name, value, ok := strings.Cut(line, ":")
		if !ok || name == "" || !isHeaderToken(name) {
			continue
		}
		out = append(out, [2]string{name, strings.TrimSpace(value)})
	}
	return out
}

// isHeaderToken reports whether s is an RFC 9110 field-name token.
func isHeaderToken(s string) bool {
	for i := range len(s) {
		c := s[i]
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0
		if !ok {
			return false
		}
	}
	return true
}

// linkManipulationWithHostHeader runs the link-manipulation row's own check when its family is on and
// the Host header check when its switch is on, so one descriptor carries both behind separate
// switches.
func linkManipulationWithHostHeader(inner CheckRunner) CheckRunner {
	return func(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
		if cc == nil {
			return nil, nil
		}
		var out []*Finding
		var firstErr error
		if reflectionProbeChecksEnabled(cc.Config) {
			f, err := inner(ctx, cc)
			out, firstErr = append(out, f...), err
		}
		if hostHeaderEnabled(cc.Config) {
			f, err := checkHostHeaderInjection(ctx, cc)
			out = append(out, f...)
			if firstErr == nil {
				firstErr = err
			}
		}
		if len(out) > 0 {
			return out, nil
		}
		return nil, firstErr
	}
}
