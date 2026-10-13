package scanner

// Two burpsy rows beside the JWT forgery family (jwt_attacks.go), both decided by its differential.
//
// # JWT credential insufficiently protected (CWE-522)
//
// A JWT the server verifies is a bearer credential: whoever holds the string is the user. This row
// reports such a credential carried or stored where it can be read by someone other than the server
// and the user's own browser:
//
//   - in the request URL (CWE-598): browser history, server and proxy logs, the Referer header;
//   - in a cookie set without HttpOnly (CWE-1004): any script on the origin reads it, so one XSS
//     anywhere on the site steals the session;
//   - in a cookie set without Secure (CWE-614): the browser also sends it on a plain-HTTP request to
//     the host, where anyone on the path reads it;
//   - over unencrypted HTTP (CWE-319): the exchange that carried it was itself cleartext.
//
// Each vector is a fact about the captured exchange (its request line, its transport, the Set-Cookie
// that carries the token — in the captured response, or failing that the newest earlier response on
// the same origin that set it). None of them alone makes the string a credential: a JWT-shaped
// tracking id in a non-HttpOnly cookie is nobody's session. So nothing is reported unless the
// forgery family's differential shows the server VERIFIES the token: the original is answered with a
// success, the same token with every signature byte altered is answered differently, the request
// without the token is answered differently, and the original and the altered control are each sent
// again and answer as they did (the second observation). A server that does not check the signature
// at all is "JWT signature not verified"'s finding and is not re-reported here.
//
// # JWT signature truncated at null byte (CWE-347, CWE-158)
//
// A verifier that cuts the signature at a NUL (an encoded %00, or a C-string comparison) accepts a
// token whose signature segment has arbitrary bytes after the real one. Decided only when the
// signature is otherwise checked (the altered-signature control is rejected), and only by a
// differential: the valid token with a random suffix appended is rejected (so the server does not
// simply ignore trailing data), while the valid token with "%00" and a random suffix appended is
// accepted — twice, with two different suffixes. The probe changes nothing but the token's bytes.

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
)

// IssueJWTCredentialExposed is burpsy's row for a verified JWT carried or stored where it can leak.
const IssueJWTCredentialExposed = "JWT credential insufficiently protected"

// IssueJWTNullByteSignature is burpsy's row for a verifier that truncates the signature at a NUL.
const IssueJWTNullByteSignature = "JWT signature truncated at null byte"

// jwtExposureEnabled admits the credential-exposure row (check_jwt_exposure). Off by default: it
// replays the captured request with the token altered and removed.
func jwtExposureEnabled(c *ScanConfig) bool { return c != nil && c.CheckJwtExposure }

// jwtSignatureOrExposure runs the forgery family's signature row and, behind its own switch, the
// credential-exposure row, which rides the same descriptor.
func jwtSignatureOrExposure(sig CheckRunner) CheckRunner {
	return func(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
		if cc == nil {
			return nil, nil
		}
		var out []*Finding
		var firstErr error
		if jwtForgeryEnabled(cc.Config) {
			f, err := sig(ctx, cc)
			out = append(out, f...)
			firstErr = err
		}
		if jwtExposureEnabled(cc.Config) {
			f, err := jwtExposureCheck(ctx, cc)
			out = append(out, f...)
			if firstErr == nil {
				firstErr = err
			}
		}
		return out, firstErr
	}
}

// jwtExposureVector is one way the token is exposed, with the CWE that names it.
type jwtExposureVector struct {
	cwe  int
	what string
}

// jwtExposureCheck reports a JWT credential carried or stored insecurely, once the server is shown to
// verify it.
func jwtExposureCheck(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	if cc == nil || cc.Scanner == nil || cc.Exchange == nil {
		return nil, nil
	}
	original, _, ok := jwtFromExchange(cc)
	if !ok {
		return nil, nil
	}
	// The vectors are facts about traffic already captured: when there is none, nothing is sent.
	vectors := jwtExposureVectors(cc, original)
	if len(vectors) == 0 {
		return nil, nil
	}
	p, ok, err := newJWTProbe(ctx, cc, IssueJWTCredentialExposed)
	if err != nil || !ok {
		return nil, err
	}
	if p.original != original || !p.decidable() || p.garbageAccepted {
		return nil, nil
	}
	// Second observation: the altered-signature control is still refused and the original still
	// answered as it was.
	again, err := p.send(ctx, p.garbageTok)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", IssueJWTCredentialExposed, err)
	}
	if p.base.SameShape(again) {
		return nil, nil
	}
	if ok, err := p.confirm(ctx, ""); err != nil || !ok {
		return nil, err
	}
	parts := make([]string, 0, len(vectors))
	for _, v := range vectors {
		parts = append(parts, fmt.Sprintf("%s (CWE-%d)", v.what, v.cwe))
	}
	return []*Finding{buildHeaderFinding(cc, IssueJWTCredentialExposed, "medium", "firm", original,
		fmt.Sprintf("the server verifies this JWT as a credential — the original was answered HTTP %d, while the same "+
			"token with its signature altered and the request without the token were each answered differently, "+
			"both re-checked — and the credential is %s", p.baseCode, strings.Join(parts, "; ")))}, nil
}

// jwtExposureVectors lists how the captured exchange exposes token.
func jwtExposureVectors(cc *CheckContext, token string) []jwtExposureVector {
	ex := cc.Exchange
	raw := requestRaw(cc.Scanner, ex)
	var out []jwtExposureVector
	line := raw
	if i := strings.IndexAny(line, "\r\n"); i >= 0 {
		line = line[:i]
	}
	if strings.Contains(line, token) {
		out = append(out, jwtExposureVector{598, "carried in the request URL, so it is kept in browser history and " +
			"server and proxy logs and sent onward in the Referer header"})
	}
	if name, attrs, ok := jwtCookieSetting(cc, token); ok {
		if !attrs["httponly"] {
			out = append(out, jwtExposureVector{1004, fmt.Sprintf("set in cookie %q without the HttpOnly attribute, "+
				"so any script running on the origin can read it", name)})
		}
		if !attrs["secure"] {
			out = append(out, jwtExposureVector{614, fmt.Sprintf("set in cookie %q without the Secure attribute, so "+
				"the browser also sends it on plain-HTTP requests to the host", name)})
		}
	}
	if !ex.TLS {
		out = append(out, jwtExposureVector{319, "sent over unencrypted HTTP, where anyone on the network path can " +
			"read and replay it"})
	}
	return out
}

// jwtMaxIssuerScan bounds how many captured exchanges are searched for the response that set the
// token's cookie.
const jwtMaxIssuerScan = 2000

// jwtCookieSetting finds the Set-Cookie that stored token: in the captured response first, else in the
// newest other captured response on the same origin (scheme, host and port), which is the only origin
// whose cookie the browser would send back here. attrs holds the attribute names present, lower-cased.
func jwtCookieSetting(cc *CheckContext, token string) (string, map[string]bool, bool) {
	if name, attrs, ok := jwtCookieIn(setCookieHeaders(cc), token); ok {
		return name, attrs, true
	}
	if cc.Scanner.store == nil {
		return "", nil, false
	}
	ex := cc.Exchange
	all := cc.Scanner.store.Exchanges()
	scanned := 0
	for i := len(all) - 1; i >= 0 && scanned < jwtMaxIssuerScan; i-- {
		e := all[i]
		if e == nil || e.ID == ex.ID || e.Response == nil || e.TLS != ex.TLS || e.Port != ex.Port || !strings.EqualFold(e.Host, ex.Host) {
			continue
		}
		scanned++
		if name, attrs, ok := jwtCookieIn(jwtResponseSetCookies(cc.Scanner, e), token); ok {
			return name, attrs, true
		}
	}
	return "", nil, false
}

// jwtResponseSetCookies is setCookieHeaders for any captured exchange.
func jwtResponseSetCookies(s *ActiveScanner, e *core.Exchange) []string {
	raw := responseRaw(s, e)
	if i := strings.Index(raw, "\r\n\r\n"); i >= 0 {
		raw = raw[:i]
	}
	return headerValues(raw, headerSetCookie)
}

// jwtCookieIn returns the cookie among the Set-Cookie values whose value holds token. A deletion
// (Max-Age <= 0 or an Expires in the past) stores nothing and is skipped.
func jwtCookieIn(setCookies []string, token string) (string, map[string]bool, bool) {
	for _, sc := range setCookies {
		pair := sc
		if i := strings.Index(pair, ";"); i >= 0 {
			pair = pair[:i]
		}
		name, value, ok := strings.Cut(pair, "=")
		if !ok || !strings.Contains(value, token) {
			continue
		}
		list := cookieAttrList(sc)
		if cookieDeletes(list, time.Now()) {
			continue
		}
		attrs := map[string]bool{}
		for _, a := range list {
			attrs[a.name] = true
		}
		return strings.TrimSpace(name), attrs, true
	}
	return "", nil, false
}

// jwtNullByteFinding decides the null-byte truncation row. The caller (jwtSignatureCheck) has a
// decidable probe whose altered-signature control was rejected.
func jwtNullByteFinding(ctx context.Context, cc *CheckContext, p *jwtProbe) *Finding {
	suffix := func() string { return "bsy" + strings.ToLower(newProbeCanary("")) }
	// Control: trailing bytes WITHOUT the NUL must be refused, or the verifier ignores trailing data
	// for some other reason and the NUL proves nothing.
	if ok, err := p.accepted(ctx, p.original+suffix()); err != nil || ok {
		return nil
	}
	first := p.original + "%00" + suffix()
	if ok, err := p.accepted(ctx, first); err != nil || !ok {
		return nil
	}
	second := p.original + "%00" + suffix()
	if ok, err := p.confirm(ctx, second); err != nil || !ok {
		return nil
	}
	return buildHeaderFinding(cc, IssueJWTNullByteSignature, "low", "firm", first,
		fmt.Sprintf("the token with \"%%00\" and random bytes appended to its signature was accepted like the original "+
			"(HTTP %d), twice with two different suffixes, while the same token with random bytes appended and no "+
			"NUL, and the token with its signature altered, were refused: the verifier truncates the signature at "+
			"the NUL, so a signature segment is accepted with arbitrary content after it", p.baseCode))
}
