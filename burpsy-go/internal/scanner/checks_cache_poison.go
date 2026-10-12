package scanner

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/sender"
)

// Web cache poisoning, the Param Miner / Web Cache Vulnerability Scanner technique.
//
// # What is proved, and what is not enough
//
// Poisoning is the claim that a response produced by an input the cache key EXCLUDES was stored and
// served to a request that never carried the input. So the evidence is a pair of requests to one
// cache key:
//
//  1. the poisoned request: the unique cache buster B plus the candidate input carrying a fresh
//     random canary;
//  2. a CLEAN request with the same buster B and nothing else.
//
// The canary coming back in (2) is the proof — (2) never sent it, so it can only have been served
// from what (1) stored. A third request with a different fresh buster B' must NOT carry the canary:
// that is the control separating "the cache stored it under B" from "the application persisted the
// value server-side and echoes it to everyone", which is a different defect and not this row.
//
// A canary reflected in the poisoned response alone is not reported. It shows the input reaches the
// page, not that the cache ignores it — the safe twins in internal/vulnapp reflect exactly that way.
//
// The second evidence class is a cached redirect (the X-Forwarded-Scheme shape): the input turns a
// non-redirect page into a 3xx, the clean replay under B is served that 3xx with the same Location,
// the control under B' is not, and the whole sequence repeats under a second buster before it counts.
// Only 3xx is considered: a cached 4xx/5xx is cache-poisoned denial of service, which this scanner
// does not probe for.
//
// # The buster is verified before anything is poisoned
//
// The buster is what keeps a probe from landing on the cache entry real users are served, so it has
// to be part of the key, and that is checked rather than assumed. A cache that reports its state
// (X-Cache, CF-Cache-Status, Cache-Status, Age, X-Varnish, …) is asked with CLEAN requests only:
// buster b1 twice, then b2. b1's second response a hit and b2's response not a hit means the buster
// is keyed. Both hits means the cache ignores it — that buster is dropped, and the next location is
// tried: a query parameter first, then a path parameter (";name=value", which servlet containers and
// many frameworks route to the same handler while the cache sees a different URI). If the cache
// reports itself but no buster is keyed, nothing is poisoned at all.
//
// A target that reports no cache state cannot be verified that way. There the query-string buster
// is used, because caches key on the full URL unless configured otherwise; the control request
// still refuses any canary that appears under a fresh buster, so an unkeyed buster yields no finding
// rather than a wrong one.

const (
	// cachePoisonBusterName is the buster's parameter name, in either location.
	cachePoisonBusterName = "burpsy_cb"
)

// cacheBusterLocation is where the buster rides.
type cacheBusterLocation uint8

const (
	busterQuery cacheBusterLocation = iota
	busterPathParam
)

func (l cacheBusterLocation) String() string {
	if l == busterPathParam {
		return "path parameter"
	}
	return "query parameter"
}

// applyCacheBuster returns rawPath (path plus optional query) with the buster added at loc.
func applyCacheBuster(rawPath string, loc cacheBusterLocation, value string) string {
	if loc == busterQuery {
		return appendQueryParam(rawPath, cachePoisonBusterName, value)
	}
	path, query, hasQuery := strings.Cut(rawPath, "?")
	if path == "" {
		path = "/"
	}
	path += ";" + cachePoisonBusterName + "=" + value
	if hasQuery {
		return path + "?" + query
	}
	return path
}

// cacheState is what a response says about the cache that served it.
type cacheState uint8

const (
	cacheUnknown cacheState = iota
	cacheMiss
	cacheHit
)

func (c cacheState) String() string {
	switch c {
	case cacheHit:
		return "hit"
	case cacheMiss:
		return "miss"
	}
	return "unknown"
}

// cacheStatusHeaders carry a hit/miss word from a cache vendor.
var cacheStatusHeaders = []string{
	"X-Cache", "X-Cache-Status", "CF-Cache-Status", "X-Proxy-Cache", "X-Cache-Lookup",
	"X-Drupal-Cache", "X-Varnish-Cache", "X-Rack-Cache", "X-LiteSpeed-Cache", "X-Nginx-Cache",
	"X-Cache-Remote", "X-Fastly-Cache", "X-Akamai-Cache", "X-Edge-Cache", "X-Cdn-Cache",
}

// classifyCacheWord reads one vendor status value: "HIT", "TCP_MEM_HIT", "MISS, HIT", "DYNAMIC".
func classifyCacheWord(v string) cacheState {
	words := strings.FieldsFunc(strings.ToLower(v), func(r rune) bool { return r < 'a' || r > 'z' })
	state := cacheUnknown
	for _, w := range words {
		switch w {
		case "hit", "stale", "revalidated", "updating":
			return cacheHit
		case "miss", "expired", "bypass", "dynamic", "pass", "refresh", "none", "uncacheable":
			state = cacheMiss
		}
	}
	return state
}

// observeCacheState classifies a response's cache-state headers. Explicit vendor words win; RFC 9211
// Cache-Status next; then the X-Varnish two-id form; Age > 0 last. Age: 0 says nothing either way.
func observeCacheState(h map[string]string) cacheState {
	state := cacheUnknown
	for _, name := range cacheStatusHeaders {
		if v := headerLookupFold(h, name); v != "" {
			switch classifyCacheWord(v) {
			case cacheHit:
				return cacheHit
			case cacheMiss:
				state = cacheMiss
			}
		}
	}
	if v := headerLookupFold(h, "Cache-Status"); v != "" {
		lv := strings.ToLower(v)
		for _, member := range strings.Split(lv, ",") {
			for _, p := range strings.Split(member, ";") {
				if strings.TrimSpace(p) == "hit" {
					return cacheHit
				}
			}
		}
		if strings.Contains(lv, "fwd=") {
			state = cacheMiss
		}
	}
	if state != cacheUnknown {
		return state
	}
	if v := strings.TrimSpace(headerLookupFold(h, "X-Varnish")); v != "" {
		if len(strings.Fields(v)) >= 2 {
			return cacheHit
		}
		return cacheMiss
	}
	if v := strings.TrimSpace(headerLookupFold(h, "Age")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return cacheHit
		}
	}
	return cacheUnknown
}

// cachePoisonInput is one candidate unkeyed input. build turns the bustered clean path into the
// poisoned request for a canary; needle is what the canary looks like in a response.
type cachePoisonInput struct {
	label  string
	build  func(bustered, canary string) (path string, headers map[string]string, body []byte)
	needle func(canary string) string
}

func plainNeedle(c string) string { return c }

func headerInput(name string, value func(canary string) string) cachePoisonInput {
	return cachePoisonInput{
		label: "header " + name,
		build: func(bustered, canary string) (string, map[string]string, []byte) {
			return bustered, map[string]string{name: value(canary)}, nil
		},
		needle: plainNeedle,
	}
}

// cachePoisonHeaderInputs are request headers front-end caches commonly leave out of the key while
// frameworks and applications read them to build absolute URLs, pick a scheme or route a request.
func cachePoisonHeaderInputs() []cachePoisonInput {
	host := func(c string) string { return c + ".invalid" }
	path := func(c string) string { return "/" + c }
	raw := func(c string) string { return c }
	ins := []cachePoisonInput{
		headerInput("X-Forwarded-Host", host),
		headerInput("X-Host", host),
		headerInput("X-Forwarded-Server", host),
		headerInput("X-HTTP-Host-Override", host),
		headerInput("X-Original-Host", host),
		headerInput("Forwarded", func(c string) string { return "host=" + c + ".invalid" }),
		headerInput("X-Original-URL", path),
		headerInput("X-Rewrite-URL", path),
		headerInput("X-Forwarded-Prefix", path),
		headerInput("X-Forwarded-Scheme", raw),
		headerInput("X-Forwarded-Proto", raw),
	}
	// The port is numeric, so its canary is a port number and its needle the ":port" an absolute URL
	// would carry. The number is derived from the canary so one probe's needle is stable.
	port := cachePoisonInput{
		label: "header X-Forwarded-Port",
		build: func(bustered, canary string) (string, map[string]string, []byte) {
			return bustered, map[string]string{"X-Forwarded-Port": canaryPort(canary)}, nil
		},
		needle: func(c string) string { return ":" + canaryPort(c) },
	}
	return append(ins, port)
}

// canaryPort maps a canary to a stable port in 20000-59999.
func canaryPort(canary string) string {
	var h uint32 = 2166136261
	for i := 0; i < len(canary); i++ {
		h = (h ^ uint32(canary[i])) * 16777619
	}
	return strconv.Itoa(20000 + int(h%40000))
}

// cachePoisonCommonUnkeyedParams are query parameters CDNs routinely strip from the cache key
// (analytics and click identifiers) while the page still sees them.
var cachePoisonCommonUnkeyedParams = []string{"utm_source", "utm_medium", "utm_campaign", "utm_content", "fbclid", "gclid"}

// queryParams splits a raw query into ordered name/value pairs, values still encoded.
type rawParam struct{ name, value string }

func splitRawQuery(q string) []rawParam {
	var out []rawParam
	for _, part := range strings.Split(q, "&") {
		if part == "" {
			continue
		}
		n, v, _ := strings.Cut(part, "=")
		out = append(out, rawParam{n, v})
	}
	return out
}

func joinRawQuery(ps []rawParam) string {
	parts := make([]string, len(ps))
	for i, p := range ps {
		parts[i] = p.name + "=" + p.value
	}
	return strings.Join(parts, "&")
}

// replaceQueryValue sets the value of every occurrence of name in rawPath's query.
func replaceQueryValue(rawPath, name, value string) string {
	path, q, _ := strings.Cut(rawPath, "?")
	ps := splitRawQuery(q)
	for i := range ps {
		if ps[i].name == name {
			ps[i].value = url.QueryEscape(value)
		}
	}
	return path + "?" + joinRawQuery(ps)
}

// cachePoisonQueryInputs: each parameter the request already carries (the cache may key the path
// but not the query, or not that parameter), each commonly-stripped analytics parameter, and the
// "fat GET" form of each carried parameter — the same name in a GET body, which some frameworks
// prefer over the query while every cache ignores the body.
func cachePoisonQueryInputs(method, rawPath string) []cachePoisonInput {
	_, q, _ := strings.Cut(rawPath, "?")
	var ins []cachePoisonInput
	seen := map[string]bool{cachePoisonBusterName: true}
	var carried []string
	for _, p := range splitRawQuery(q) {
		name, err := url.QueryUnescape(p.name)
		if err != nil || seen[p.name] {
			continue
		}
		seen[p.name] = true
		carried = append(carried, p.name)
		pname := p.name
		ins = append(ins, cachePoisonInput{
			label: "query parameter " + name,
			build: func(bustered, canary string) (string, map[string]string, []byte) {
				return replaceQueryValue(bustered, pname, canary), nil, nil
			},
			needle: plainNeedle,
		})
	}
	for _, name := range cachePoisonCommonUnkeyedParams {
		if seen[name] {
			continue
		}
		pname := name
		ins = append(ins, cachePoisonInput{
			label: "query parameter " + name,
			build: func(bustered, canary string) (string, map[string]string, []byte) {
				return appendQueryParam(bustered, pname, canary), nil, nil
			},
			needle: plainNeedle,
		})
	}
	if strings.EqualFold(method, "GET") {
		for _, pname := range carried {
			pname := pname
			name, _ := url.QueryUnescape(pname)
			ins = append(ins, cachePoisonInput{
				label: "GET body parameter " + name + " (fat GET)",
				build: func(bustered, canary string) (string, map[string]string, []byte) {
					return bustered, map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
						[]byte(pname + "=" + url.QueryEscape(canary))
				},
				needle: plainNeedle,
			})
		}
	}
	return ins
}

// responseCarries reports whether needle appears in the response body or any header value.
func responseCarries(r *sender.Response, needle string) bool {
	if r == nil || needle == "" {
		return false
	}
	if strings.Contains(string(r.Body), needle) {
		return true
	}
	for _, v := range r.Headers {
		if strings.Contains(v, needle) {
			return true
		}
	}
	return false
}

// cachePoisonProber holds one URL's run: the exchange, the chosen buster and the clean baseline.
type cachePoisonProber struct {
	s        *ActiveScanner
	ex       *core.Exchange
	loc      cacheBusterLocation
	verified bool
	baseline *sender.Response
	signals  bool // the target reports cache state at all
}

func (p *cachePoisonProber) send(ctx context.Context, path string, headers map[string]string, body []byte) *sender.Response {
	if body != nil {
		return p.s.sendTestRequestBody(ctx, p.ex, p.ex.Method, path, headers, body)
	}
	return p.s.sendTestRequestFull(ctx, p.ex, p.ex.Method, path, headers)
}

func freshBuster() string { return randomToken(12) }

func freshCanary() string { return "bcp" + randomToken(12) }

// selectBuster verifies a keyed buster location with clean requests only. ok=false means the target
// reports a cache but no buster is provably keyed (or it stores nothing): probing would risk the
// real entry, or could not succeed, so the caller sends nothing poisoned.
func (p *cachePoisonProber) selectBuster(ctx context.Context) (ok bool, notes []string) {
	baseStatus := 0
	for _, loc := range []cacheBusterLocation{busterQuery, busterPathParam} {
		b1, b2 := freshBuster(), freshBuster()
		r1 := p.send(ctx, applyCacheBuster(p.ex.Path, loc, b1), nil, nil)
		if r1 == nil {
			notes = append(notes, loc.String()+" buster: no response")
			continue
		}
		if baseStatus == 0 {
			baseStatus = r1.StatusCode
		} else if r1.StatusCode != baseStatus {
			notes = append(notes, fmt.Sprintf("%s buster: changed the status (%d, baseline %d), not the same resource", loc, r1.StatusCode, baseStatus))
			continue
		}
		r2 := p.send(ctx, applyCacheBuster(p.ex.Path, loc, b1), nil, nil)
		r3 := p.send(ctx, applyCacheBuster(p.ex.Path, loc, b2), nil, nil)
		if r2 == nil || r3 == nil {
			notes = append(notes, loc.String()+" buster: no response")
			continue
		}
		o1, o2, o3 := observeCacheState(r1.Headers), observeCacheState(r2.Headers), observeCacheState(r3.Headers)
		if o1 != cacheUnknown || o2 != cacheUnknown || o3 != cacheUnknown {
			p.signals = true
		}
		switch {
		case o2 == cacheHit && o3 != cacheHit:
			p.loc, p.verified, p.baseline = loc, true, r3
			notes = append(notes, fmt.Sprintf("%s buster verified keyed (repeat %s, fresh value %s)", loc, o2, o3))
			return true, notes
		case o2 == cacheHit && o3 == cacheHit:
			notes = append(notes, loc.String()+" buster is not in the cache key (a fresh value was a hit); not used")
		default:
			notes = append(notes, fmt.Sprintf("%s buster: repeat was not served from cache (%s)", loc, o2))
		}
		if p.baseline == nil {
			p.baseline = r1
		}
	}
	if p.signals {
		return false, notes
	}
	// No cache state reported anywhere: unverifiable, so fall back to the query buster (see the
	// file comment) and let the per-probe control request carry the weight.
	p.loc, p.verified = busterQuery, false
	return p.baseline != nil, append(notes, "target reports no cache state; query-parameter buster used unverified")
}

// cachePoisonHit is one proved unkeyed input.
type cachePoisonHit struct {
	input    string
	evidence string
	hitState cacheState
}

// probe runs one input. It returns nil unless the poisoning is proved with the control.
func (p *cachePoisonProber) probe(ctx context.Context, in cachePoisonInput) *cachePoisonHit {
	b := freshBuster()
	canary := freshCanary()
	needle := in.needle(canary)
	clean := applyCacheBuster(p.ex.Path, p.loc, b)
	ppath, ph, pbody := in.build(clean, canary)
	poisoned := p.send(ctx, ppath, ph, pbody)
	if poisoned == nil {
		return nil
	}
	if responseCarries(poisoned, needle) {
		replay := p.send(ctx, clean, nil, nil)
		if !responseCarries(replay, needle) {
			return nil // reflected, but keyed or not stored: not poisoning
		}
		control := p.send(ctx, applyCacheBuster(p.ex.Path, p.loc, freshBuster()), nil, nil)
		if control == nil || responseCarries(control, needle) {
			return nil // persisted server-side, or the buster was not keyed: not this row
		}
		st := observeCacheState(replay.Headers)
		return &cachePoisonHit{
			input:    in.label,
			hitState: st,
			evidence: fmt.Sprintf("poisoned request %s %s carried canary %q via %s; the clean request %s %s "+
				"(same %s buster, no such input) was served it back (cache state: %s); a control request "+
				"with a fresh buster was not", p.ex.Method, ppath, needle, in.label, p.ex.Method, clean, p.loc, st),
		}
	}
	// Cached redirect: only for header inputs, only 3xx, and only against a non-redirect baseline.
	if pbody != nil || len(ph) == 0 || p.baseline == nil || isRedirectStatus(p.baseline.StatusCode) ||
		!isRedirectStatus(poisoned.StatusCode) {
		return nil
	}
	if !p.cachedRedirect(ctx, in, clean, b, poisoned) {
		return nil
	}
	b2 := freshBuster()
	clean2 := applyCacheBuster(p.ex.Path, p.loc, b2)
	pp2, ph2, _ := in.build(clean2, freshCanary())
	poisoned2 := p.send(ctx, pp2, ph2, nil)
	if poisoned2 == nil || !isRedirectStatus(poisoned2.StatusCode) || !p.cachedRedirect(ctx, in, clean2, b2, poisoned2) {
		return nil
	}
	loc := headerLookupFold(poisoned.Headers, "Location")
	return &cachePoisonHit{
		input:    in.label,
		hitState: cacheUnknown,
		evidence: fmt.Sprintf("%s turned a %d response into a %d redirect to %q; a clean request with the same %s "+
			"buster was served that redirect, a fresh-buster control got %d; reproduced under a second buster",
			in.label, p.baseline.StatusCode, poisoned.StatusCode, loc, p.loc, p.baseline.StatusCode),
	}
}

// cachedRedirect: the clean replay under the poisoned buster gets the same redirect, and a control
// under a fresh buster gets the baseline status.
func (p *cachePoisonProber) cachedRedirect(ctx context.Context, in cachePoisonInput, clean, b string, poisoned *sender.Response) bool {
	replay := p.send(ctx, clean, nil, nil)
	if replay == nil || replay.StatusCode != poisoned.StatusCode ||
		headerLookupFold(replay.Headers, "Location") != headerLookupFold(poisoned.Headers, "Location") {
		return false
	}
	control := p.send(ctx, applyCacheBuster(p.ex.Path, p.loc, freshBuster()), nil, nil)
	return control != nil && control.StatusCode == p.baseline.StatusCode
}

// checkWebCachePoisoning is the per-URL entry point.
func checkWebCachePoisoning(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	if cc == nil || cc.Exchange == nil || cc.Scanner == nil || cc.Scanner.sender == nil {
		return nil, nil
	}
	ex := cc.Exchange
	// A shared cache stores GET and HEAD responses; any other method has nothing to poison.
	if m := strings.ToUpper(ex.Method); m != "GET" && m != "HEAD" && m != "" {
		return nil, nil
	}
	p := &cachePoisonProber{s: cc.Scanner, ex: ex}
	ok, notes := p.selectBuster(ctx)
	if !ok {
		return nil, nil
	}
	inputs := append(cachePoisonHeaderInputs(), cachePoisonQueryInputs(ex.Method, ex.Path)...)
	var hits []*cachePoisonHit
	for _, in := range inputs {
		if ctx.Err() != nil {
			break
		}
		if h := p.probe(ctx, in); h != nil {
			hits = append(hits, h)
		}
	}
	if len(hits) == 0 {
		return nil, nil
	}
	confidence := "firm"
	if p.verified && hits[0].hitState == cacheHit {
		confidence = "certain"
	}
	labels := make([]string, len(hits))
	evidence := make([]string, 0, len(hits)+1)
	for i, h := range hits {
		labels[i] = h.input
		evidence = append(evidence, h.evidence)
	}
	evidence = append(evidence, "cache buster: "+strings.Join(notes, "; "))
	return []*Finding{{
		Name:       cachePoisonIssue,
		Severity:   "high",
		Confidence: confidence,
		Description: "Web cache poisoning: a response produced by an input the cache key excludes (" +
			strings.Join(labels, ", ") + ") was stored and served to a request that did not send it.",
		URL:        ex.Path,
		Method:     ex.Method,
		Param:      hits[0].input,
		Evidence:   strings.Join(evidence, "\n"),
		Solution:   remediationFor(cachePoisonIssue),
		ExchangeID: ex.ID,
		Timestamp:  time.Now(),
	}}, nil
}
