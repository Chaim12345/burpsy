package scanner

// Access-control bypass by URL interpretation tricks (burpsy-react-ui-0vzb.4, the bead's
// "auth-bypass probes" half).
//
// A reverse proxy (or the application itself) decides access on the request target AS WRITTEN,
// while the router that serves the request decides on the target AFTER normalisation. When the two
// disagree, a refused page is served under a spelling the access check did not recognise
// (PortSwigger Web Security Academy, "Access control vulnerabilities": /%2e/admin, ..;/, trailing
// whitespace; and the X-Original-URL / X-Rewrite-URL override headers a front server strips but a
// back end honours).
//
// The check runs only on a safe-method request whose FRESH baseline is 401 or 403: a refused page
// is the only place a bypass can be read, and a refused state-changing request is never replayed
// with a spelling that might make it succeed. Two techniques, each with its own controls:
//
//   - Path normalisation: /%2e<path>, <path>/., /..;<path>, /./<path>, /<path> with a doubled
//     slash, and trailing %20 / %09 spellings. A variant that answers 2xx with a body different
//     from the refused baseline is a candidate. A random sibling path must NOT be served (a
// wildcard application that answers everything 200 proves nothing), and the variant must
//     answer 2xx with the same body again.
//   - URL-override headers (URLOverrideHeaderNames, recovered from burp.Zw6n): the site root is
//     fetched as the allowed carrier; the header naming the refused path must turn the carrier's
//     answer into a different 2xx page; the same header naming a random path must NOT produce that
//     page; and the probe must reproduce.
//
// Findings ride Burp's "Broken access control" row (its CWE-284 is the class both techniques
// attack) behind the CheckURLAuthBypass switch, off by default like every active burpsy check: the
// probes replay a refused request under spellings meant to defeat its refusal.

import (
	"context"
	"fmt"
	"strings"
)

// urlAuthBypassEnabled is the check's own switch.
func urlAuthBypassEnabled(c *ScanConfig) bool { return c != nil && c.CheckURLAuthBypass }

// withURLAuthBypass adds this check to the runner of the descriptor it rides ("Broken access
// control"). The inner runner keeps its own switches; a proven finding from either half is
// returned even when the other failed.
func withURLAuthBypass(inner CheckRunner) CheckRunner {
	return func(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
		if cc == nil || cc.Scanner == nil {
			return nil, nil
		}
		innerF, innerErr := inner(ctx, cc)
		var ubF []*Finding
		var ubErr error
		if urlAuthBypassEnabled(cc.Config) {
			ubF, ubErr = checkURLAuthBypass(ctx, cc)
		}
		out := append(innerF, ubF...)
		switch {
		case len(ubF) > 0:
			return out, nil
		case innerErr != nil:
			return innerF, innerErr
		case ubErr != nil:
			return innerF, ubErr
		}
		return out, nil
	}
}

// rawSetRequestTarget returns raw with the request line's target replaced. The target is written
// as given: percent-encoded spellings must reach the wire un-re-encoded, which is the point of the
// probes this check sends.
func rawSetRequestTarget(raw, target string) string {
	i := strings.Index(raw, "\r\n")
	if i < 0 {
		return raw
	}
	method, rest, ok1 := strings.Cut(raw[:i], " ")
	_, version, ok2 := strings.Cut(rest, " ")
	if !ok1 || !ok2 {
		return raw
	}
	return method + " " + target + " " + version + raw[i:]
}

// pathNormalisationVariants spells p the ways a router may resolve to p while a literal front-end
// match for p does not fire. p is a leading-slash path with no query.
func pathNormalisationVariants(p string) []string {
	trimmed := strings.TrimPrefix(p, "/")
	return []string{
		"/%2e" + p,      // encoded dot segment: /%2e/admin
		"/%2E" + p,      // uppercase form, for a case-sensitive decoder check
		p + "/.",        // trailing dot segment: /admin/.
		"/..;" + p,      // path-parameter climb: /..;/admin (Tomcat strips ";…" and pops)
		"/./" + trimmed, // explicit dot segment: /./admin
		"//" + trimmed,  // doubled separator: //admin
		p + "%20",       // trailing space: a trim-before-serve, compare-after back end
		p + "%09",       // trailing tab, same class
	}
}

// urlBypassProber is one URL's run.
type urlBypassProber struct {
	cc  *CheckContext
	h   *ProbeHarness
	raw string
}

func (p *urlBypassProber) send(ctx context.Context, raw string) (ProbeResponse, error) {
	return p.h.send(ctx, []byte(raw))
}

// checkURLAuthBypass runs both techniques against one refused URL.
func checkURLAuthBypass(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	if cc == nil || cc.Scanner == nil || cc.Exchange == nil {
		return nil, nil
	}
	if !isSafeMethod(cc.Exchange.Method) {
		return nil, nil
	}
	raw := requestRaw(cc.Scanner, cc.Exchange)
	if raw == "" {
		return nil, nil
	}
	if strings.EqualFold(headerValue(raw, "Upgrade"), "websocket") {
		return nil, nil
	}
	h, err := NewProbeHarness(ctx, cc, []string{"query"})
	if err != nil {
		return nil, fmt.Errorf("URL auth bypass: %w", err)
	}
	base := h.Baseline()
	if base.Status != 401 && base.Status != 403 {
		return nil, nil
	}
	path, _, _ := strings.Cut(cc.Exchange.Path, "?")
	if path == "" || path == "/" {
		return nil, nil
	}
	p := &urlBypassProber{cc: cc, h: h, raw: raw}
	var out []*Finding
	var firstErr error
	for _, run := range []func(context.Context, ProbeResponse, string) (*Finding, error){
		p.pathNormalisation, p.urlOverrideHeader,
	} {
		f, err := run(ctx, base, path)
		if f != nil {
			out = append(out, f)
		}
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if len(out) > 0 {
		return out, nil
	}
	if firstErr != nil {
		return nil, fmt.Errorf("URL auth bypass: %w", firstErr)
	}
	return nil, nil
}

// pathNormalisation tries the encoded/normalised spellings of the refused path.
func (p *urlBypassProber) pathNormalisation(ctx context.Context, base ProbeResponse, path string) (*Finding, error) {
	denied := strings.TrimSpace(base.Body)
	var ctrl *ProbeResponse
	for _, v := range pathNormalisationVariants(path) {
		first, err := p.send(ctx, rawSetRequestTarget(p.raw, v))
		if err != nil {
			return nil, err
		}
		firstBody := strings.TrimSpace(first.Body)
		if !is2xx(first.Status) || firstBody == denied {
			continue
		}
		if ctrl == nil {
			c, err := p.send(ctx, rawSetRequestTarget(p.raw, "/burpsy-"+randomLetters(8)))
			if err != nil {
				return nil, err
			}
			ctrl = &c
			if is2xx(ctrl.Status) {
				// The application answers any path 200: no refusal is keyed on the path, so a
				// variant answering 2xx shows nothing.
				return nil, nil
			}
		}
		again, err := p.send(ctx, rawSetRequestTarget(p.raw, v))
		if err != nil {
			return nil, err
		}
		if !is2xx(again.Status) || strings.TrimSpace(again.Body) != firstBody {
			continue
		}
		evidence := fmt.Sprintf("GET %s -> HTTP %d\nGET %s -> HTTP %d (%d-byte body)\nGET %s -> HTTP %d again",
			path, base.Status, v, first.Status, len(first.Body), v, again.Status)
		detail := fmt.Sprintf("The request for %s is refused (HTTP %d) as sent, but the spelling %s is "+
			"served (HTTP %d, a different page) and served again on repetition. A random sibling path is "+
			"not served, so the application does refuse by path — its access check matches the request "+
			"target as written while its router resolves the normalised spelling, and the two disagree. "+
			"Anyone can fetch this page by asking for it the second way.", path, base.Status, v, first.Status)
		f := buildHeaderFinding(p.cc, "Broken access control", "high", "firm", evidence, detail)
		f.Param = v
		return f, nil
	}
	return nil, nil
}

// urlOverrideHeader replays the refused path through the two recovered URL-override headers on an
// allowed carrier page.
func (p *urlBypassProber) urlOverrideHeader(ctx context.Context, base ProbeResponse, path string) (*Finding, error) {
	carrier, err := p.send(ctx, rawSetRequestTarget(p.raw, "/"))
	if err != nil {
		return nil, err
	}
	if !is2xx(carrier.Status) {
		// No allowed page to carry the header; without the carrier's body there is no telling the
		// bypass page apart from the page every request gets.
		return nil, nil
	}
	carrierBody := strings.TrimSpace(carrier.Body)
	denied := strings.TrimSpace(base.Body)
	for _, hdr := range URLOverrideHeaderNames {
		probe := rawSetHeader(rawSetRequestTarget(p.raw, "/"), hdr, path)
		first, err := p.send(ctx, probe)
		if err != nil {
			return nil, err
		}
		firstBody := strings.TrimSpace(first.Body)
		if !is2xx(first.Status) || firstBody == carrierBody || firstBody == denied {
			continue
		}
		ctrl, err := p.send(ctx, rawSetHeader(rawSetRequestTarget(p.raw, "/"), hdr, "/burpsy-"+randomLetters(8)))
		if err != nil {
			return nil, err
		}
		if ctrl.Status == first.Status && strings.TrimSpace(ctrl.Body) == firstBody {
			// Any path in the header yields that page: the header's presence, not the named path,
			// decides — or the endpoint is not refusing at all any more. Neither is this finding.
			continue
		}
		again, err := p.send(ctx, probe)
		if err != nil {
			return nil, err
		}
		if !is2xx(again.Status) || strings.TrimSpace(again.Body) != firstBody {
			continue
		}
		evidence := fmt.Sprintf("GET %s -> HTTP %d\nGET / with %s: %s -> HTTP %d (%d-byte body, not the / page)\nGET / with %s naming a random path -> HTTP %d\nGET / with %s: %s -> HTTP %d again",
			path, base.Status, hdr, path, first.Status, len(first.Body), hdr, ctrl.Status, hdr, path, again.Status)
		detail := fmt.Sprintf("The request for %s is refused (HTTP %d) as sent, but the site root carries "+
			"the page when the %s request header names %s (HTTP %d, a different page from both the root "+
			"and the refusal). The same header naming a path that does not exist does not produce it, so "+
			"the header maps the named path; the bypass reproduced afterwards. A client chooses this "+
			"header's value, so anyone can fetch the refused page through it.", path, base.Status, hdr, path, first.Status)
		f := buildHeaderFinding(p.cc, "Broken access control", "high", "firm", evidence, detail)
		f.Param = hdr
		return f, nil
	}
	return nil, nil
}
