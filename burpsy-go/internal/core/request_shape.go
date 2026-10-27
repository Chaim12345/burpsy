package core

import (
	"sort"
	"strings"
)

// volatileParameterNames are the parameter names whose VALUES change on essentially every capture
// of one endpoint without the endpoint's semantics changing: anti-CSRF tokens and nonces
// (burpsy-go W4). Matching is exact and case-insensitive, and the list is deliberately short -
// a name that is only SOMETIMES volatile ("token", "ts", "viewstate") is security-relevant
// content, and masking it would silently stop the re-audit the fingerprint exists to cause.
var volatileParameterNames = map[string]bool{
	"csrf":                       true,
	"csrf_token":                 true,
	"csrftoken":                  true,
	"csrfmiddlewaretoken":        true,
	"_csrf":                      true,
	"xsrf":                       true,
	"xsrf_token":                 true,
	"_xsrf":                      true,
	"nonce":                      true,
	"_nonce":                     true,
	"authenticity_token":         true,
	"__requestverificationtoken": true,
	"_token":                     true,
}

// MaskVolatileParamValues rewrites a name/value string (a query string or a form body), replacing
// the VALUE of every volatile-named parameter with a fixed marker. Names, order, duplicates and
// every non-volatile value stay byte-exact, so a real content change still changes the shape.
// Exported for the audit's per-URL unit key, whose request target carries the same volatile
// query values this package masks in the fingerprint.
func MaskVolatileParamValues(s string) string {
	// A request target carries its path: mask only the query tail, keeping the path byte-exact.
	if i := strings.IndexByte(s, '?'); i >= 0 {
		return s[:i+1] + MaskVolatileParamValues(s[i+1:])
	}
	if s == "" {
		return s
	}
	parts := strings.Split(s, "&")
	masked := false
	for i, p := range parts {
		j := strings.IndexByte(p, '=')
		name := p
		if j >= 0 {
			name = p[:j]
		}
		if volatileParameterNames[strings.ToLower(name)] && j >= 0 {
			parts[i] = p[:j+1] + "\x00volatile\x00"
			masked = true
		}
	}
	if !masked {
		return s
	}
	return strings.Join(parts, "&")
}

// cookieNamesOf returns the sorted names carried by one Cookie header value.
func cookieNamesOf(value string) []string {
	var names []string
	for _, c := range strings.Split(value, ";") {
		if j := strings.IndexByte(c, '='); j >= 0 {
			names = append(names, strings.TrimSpace(c[:j]))
		}
	}
	sort.Strings(names)
	return names
}

// RequestShapeFingerprint is a 64-bit FNV-1a over the request's NORMALIZED shape, computed at the
// same capture seam as RequestFingerprint (burpsy-go W4).
//
// # What it is for
//
// RequestFingerprint keys the audit ledger's URL-keyed scopes on the request's exact bytes, so a
// re-capture whose content changed is re-audited. But any volatile byte - a rotated session
// cookie, a per-request CSRF token - also changes it, and on a tokened app EVERY capture of one
// endpoint minted a new dispatch unit: per-host checks re-ran on every capture, and nothing
// capped it. The shape fingerprint is the same digest with the known-volatile regions masked:
//
//   - the values of the well-known volatile parameter names above, in the query string and in a
//     form-encoded body;
//   - the Cookie header's values (its sorted names stay - a request carrying a DIFFERENT cookie
//     set is a different shape).
//
// Everything else is hashed byte-exact: the method, path, non-volatile parameters and values,
// the other headers, and bodies in formats not parsed here (JSON, XML - volatility inside them
// is what the run's unit-variant cap, not this function, bounds; masking without parsing would
// be guesswork, and guessing wrong silently stops a re-audit).
//
// Zero means "no request bytes", matching RequestFingerprint.
func RequestShapeFingerprint(raw []byte) uint64 {
	if len(raw) == 0 {
		return 0
	}
	head, body := splitHeadBody(raw)

	var b strings.Builder
	// Request line with the query's volatile values masked.
	line := startLine(head)
	fields := strings.Fields(line)
	if len(fields) >= 2 {
		target := fields[1]
		if i := strings.IndexByte(target, '?'); i >= 0 {
			target = target[:i+1] + MaskVolatileParamValues(target[i+1:])
		}
		fields[1] = target
		line = strings.Join(fields, " ")
	}
	b.WriteString(line)
	b.WriteByte('\n')
	// Headers byte-exact, except Cookie, which contributes its sorted names only.
	for i, hline := range strings.Split(string(head), "\n") {
		if i == 0 {
			continue
		}
		hline = strings.TrimRight(hline, "\r")
		colon := strings.IndexByte(hline, ':')
		if colon >= 0 && strings.EqualFold(strings.TrimSpace(hline[:colon]), "cookie") {
			b.WriteString("Cookie: ")
			b.WriteString(strings.Join(cookieNamesOf(hline[colon+1:]), ";"))
			b.WriteByte('\n')
			continue
		}
		b.WriteString(hline)
		b.WriteByte('\n')
	}
	b.WriteString("\n")
	// Body: masked when it is a form we can read, byte-exact otherwise (see the doc above).
	if mediaTypeOf(headerValue(head, "content-type")) == "application/x-www-form-urlencoded" {
		b.WriteString(MaskVolatileParamValues(string(body)))
	} else {
		b.Write(body)
	}
	return RequestFingerprint([]byte(b.String()))
}
