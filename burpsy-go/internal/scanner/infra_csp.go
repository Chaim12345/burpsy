package scanner

// CSP directive parsing and posture analysis.
//
// checks_headers.go already has a coarse CSP classifier (analyzeCSPEvidence /
// cspProbe) used for two catalog rows — "not enforced" and "allows
// clickjacking" — that only inspects header presence and a substring search
// for "frame-ancestors". It does not parse directive syntax or reason about
// source-list semantics, so it cannot support the other five CSP rows in the
// catalog (allowlisted script resources, untrusted script/style execution,
// malformed syntax, form hijacking). This file is that real parser. It is
// deliberately independent of analyzeCSPEvidence/cspProbe: neither modifies
// the other, and every exported/unexported name here is prefixed CSPPolicy/
// cspP to avoid colliding with the existing csp*/CSPEvidence* identifiers.
//
// Ground truth for directive names, keywords, and the exact misconfiguration
// wording comes from the decompiled Burp CSP analyser (burp.Zupz, which
// builds and validates the directive table, and burp.Zifp, which holds the
// finding prose) recovered in /root/burp-re/out/strings/map_root.tsv. That
// evidence is what fixes, e.g., the fallback-chain shape and the specific
// "policy allows data: URLs" / "policy allows global wildcard URLs" /
// "form hijacking" wording paraphrased in the doc comments below.

import (
	"fmt"
	"regexp"
	"strings"
)

// CSPDirective is one parsed directive: its (lowercased) name and the raw
// source-expression tokens that followed it, in declaration order.
type CSPDirective struct {
	Name    string
	Sources []string
}

// CSPPolicy is a parsed Content-Security-Policy header value: its directives
// in declaration order, plus every concrete syntax problem noticed while
// parsing. A policy with no problems has an empty (nil) MalformedReasons.
type CSPPolicy struct {
	Directives []CSPDirective

	// MalformedReasons accumulates human-readable syntax problems found while
	// parsing: an unrecognised directive name, a directive repeated after its
	// first (and only enforced) occurrence, a non-boolean directive with no
	// source expressions, or a source expression that is neither a
	// recognised quoted keyword nor a parseable host/scheme source. It is the
	// raw material for the "malformed syntax" catalog row (2098438) and is
	// intentionally prose, not a bitmask: each entry names the offending
	// directive/token so a finding can quote it directly.
	MalformedReasons []string
}

// cspPKnownDirectives lists every directive name defined by CSP2/CSP3 that
// Burp's own analyser recognises (per burp.Zupz's literal table: img-src,
// script-src, script-src-elem/attr, style-src-elem/attr, form-action,
// frame-ancestors, sandbox, trusted-types, require-trusted-types-for,
// navigate-to, and friends). A name outside this set is flagged as an
// "unknown directive" malformed reason rather than silently accepted, since a
// typo'd directive name is exactly the kind of syntax error CSP analysis is
// meant to catch — browsers ignore it too, just without telling anyone.
var cspPKnownDirectives = map[string]bool{
	"default-src":               true,
	"script-src":                true,
	"script-src-elem":           true,
	"script-src-attr":           true,
	"style-src":                 true,
	"style-src-elem":            true,
	"style-src-attr":            true,
	"img-src":                   true,
	"connect-src":               true,
	"font-src":                  true,
	"object-src":                true,
	"media-src":                 true,
	"frame-src":                 true,
	"worker-src":                true,
	"manifest-src":              true,
	"prefetch-src":              true,
	"child-src":                 true,
	"form-action":               true,
	"frame-ancestors":           true,
	"base-uri":                  true,
	"sandbox":                   true,
	"report-uri":                true,
	"report-to":                 true,
	"upgrade-insecure-requests": true,
	"block-all-mixed-content":   true,
	"require-trusted-types-for": true,
	"trusted-types":             true,
	"navigate-to":               true,
	"plugin-types":              true,
}

// cspPBooleanDirectives are directives that are syntactically complete with
// no source expressions at all — "upgrade-insecure-requests;" is the entire,
// valid directive. Every other directive with zero source tokens is flagged
// as an empty-directive malformed reason: for e.g. "script-src;" that is not
// a deliberate lockdown (CSP has 'none' for that), it is almost always a
// truncated or misauthored policy.
var cspPBooleanDirectives = map[string]bool{
	"upgrade-insecure-requests": true,
	"block-all-mixed-content":   true,
}

// cspPKnownKeywordSet is every quoted CSP keyword other than the nonce-/hash-
// source families, which cspPIsNonceOrHash matches by prefix since their
// suffix is caller-chosen.
var cspPKnownKeywordSet = map[string]bool{
	"'self'":                   true,
	"'none'":                   true,
	"'unsafe-inline'":          true,
	"'unsafe-eval'":            true,
	"'unsafe-hashes'":          true,
	"'strict-dynamic'":         true,
	"'report-sample'":          true,
	"'wasm-unsafe-eval'":       true,
	"'unsafe-allow-redirects'": true,
}

const (
	cspPUnsafeInline  = "'unsafe-inline'"
	cspPStrictDynamic = "'strict-dynamic'"
)

// cspPFallbackChain encodes CSP's real directive-inheritance graph for the
// handful of directives these checks care about. Per the spec, a *fetch*
// directive that a policy omits inherits from the next directive up its own
// chain, terminating at default-src: script-src-elem/attr fall back to
// script-src, which falls back to default-src; style-src-elem/attr fall back
// to style-src, which falls back to default-src.
//
// form-action has NO entry here on purpose. form-action is a *navigation*
// directive, not a fetch directive, and the CSP spec explicitly limits the
// default-src fallback to fetch directives only. That is precisely why "CSP
// allows form hijacking" is its own catalog row distinct from a generic
// script/style check: a page can ship an airtight default-src 'self' and
// still let an attacker-injected <form action="https://evil"> exfiltrate a
// password manager's autofilled credentials, because nothing but an explicit
// form-action directive ever restricts form targets.
var cspPFallbackChain = map[string][]string{
	"script-src-elem": {"script-src", "default-src"},
	"script-src-attr": {"script-src", "default-src"},
	"script-src":      {"default-src"},
	"style-src-elem":  {"style-src", "default-src"},
	"style-src-attr":  {"style-src", "default-src"},
	"style-src":       {"default-src"},
}

// cspPSchemeSourceRe matches a bare scheme-source token like "data:",
// "https:", "blob:", or "filesystem:" — a URI scheme name followed by a
// colon and nothing else.
var cspPSchemeSourceRe = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.-]*:$`)

// cspPHostSourceRe matches a CSP host-source expression: an optional
// "scheme://" prefix, a host that may be a bare wildcard ("*"), a
// wildcard-subdomain ("*.example.com"), or a dotted/undotted hostname, an
// optional ":port" or ":*" port wildcard, and an optional path. This mirrors
// the shape of Burp's own host-source pattern recovered from map_root.tsv
// (burp.Zupz: "(((http|ws)s?)://)?\*" for the scheme+wildcard prefix and
// ")(?::\d+|:\*)?(?:/[\w\-._~:/?#@!$&'()*+=]*)?" for the port/path suffix).
var cspPHostSourceRe = regexp.MustCompile(
	`^(?:[a-zA-Z][a-zA-Z0-9+.-]*://)?` +
		`(?:\*|(?:\*\.)?[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)*)` +
		`(?::(?:[0-9]+|\*))?` +
		`(?:/[^\s]*)?$`,
)

// ParseCSP parses a raw Content-Security-Policy header value into a
// CSPPolicy. It splits on ';', treats the first whitespace-separated token of
// each segment as the directive name (lowercased — directive names are
// case-insensitive) and the rest as source expressions, and records a
// MalformedReasons entry for every concrete syntax problem it notices along
// the way.
//
// An empty segment produced by a leading/trailing/doubled ';' (e.g.
// "script-src 'self';;" or ";default-src 'self'") is skipped silently, not
// reported as malformed: browsers do exactly that, and stray semicolons are
// far too common in hand-written policies to treat as a real defect. An
// empty header value parses to a CSPPolicy with no directives and no
// malformed reasons.
func ParseCSP(headerValue string) CSPPolicy {
	var p CSPPolicy
	seen := make(map[string]bool)

	for _, segment := range strings.Split(headerValue, ";") {
		trimmed := strings.TrimSpace(segment)
		if trimmed == "" {
			continue
		}

		fields := strings.Fields(trimmed)
		name := strings.ToLower(fields[0])
		tokens := fields[1:]

		if !cspPKnownDirectives[name] {
			p.MalformedReasons = append(p.MalformedReasons,
				fmt.Sprintf("unknown directive name %q", name))
		}

		if seen[name] {
			// CSP: "If the set of directives already contains a directive
			// whose name is a case-insensitive match, ignore this instance
			// of the directive and skip the rest of these steps." Only the
			// first occurrence is ever enforced, so later duplicates are
			// recorded as a syntax problem and then dropped rather than
			// merged or allowed to overwrite the first.
			p.MalformedReasons = append(p.MalformedReasons,
				fmt.Sprintf("duplicate directive %q (only the first occurrence is enforced)", name))
			continue
		}
		seen[name] = true

		if len(tokens) == 0 && !cspPBooleanDirectives[name] {
			p.MalformedReasons = append(p.MalformedReasons,
				fmt.Sprintf("directive %q has no source expressions", name))
		}

		sources := make([]string, 0, len(tokens))
		for _, tok := range tokens {
			if !cspPIsParseableSource(tok) {
				p.MalformedReasons = append(p.MalformedReasons,
					fmt.Sprintf("directive %q has an unparseable source expression %q", name, tok))
			}
			sources = append(sources, tok)
		}

		p.Directives = append(p.Directives, CSPDirective{Name: name, Sources: sources})
	}

	return p
}

// directive returns the first (and only enforced) occurrence of name in p, or
// ok=false if it was never declared.
func (p CSPPolicy) directive(name string) (CSPDirective, bool) {
	for _, d := range p.Directives {
		if d.Name == name {
			return d, true
		}
	}
	return CSPDirective{}, false
}

// EffectiveSources returns the source expressions that actually govern
// directive, walking CSP's real fallback chain (cspPFallbackChain) when
// directive itself was not declared. It returns nil only when neither
// directive nor anything in its fallback chain is present in the policy at
// all — meaning that resource type is completely unrestricted, which callers
// must treat as maximally permissive, not as "no sources." A directive that
// IS present with zero source tokens (e.g. a bare "script-src;") returns a
// non-nil empty slice instead, which is the opposite: CSP treats an empty
// source list as blocking everything of that type.
func (p CSPPolicy) EffectiveSources(directive string) []string {
	name := strings.ToLower(directive)
	if d, ok := p.directive(name); ok {
		return d.Sources
	}
	for _, fallback := range cspPFallbackChain[name] {
		if d, ok := p.directive(fallback); ok {
			return d.Sources
		}
	}
	return nil
}

// cspPIsNonceOrHash reports whether token is a quoted nonce-source or
// hash-source, e.g. 'nonce-r4nd0m' or 'sha256-abc123...'. Its digest/nonce
// suffix is caller-chosen so it cannot be a fixed-set membership check like
// cspPKnownKeywordSet; it must at least be non-empty.
func cspPIsNonceOrHash(token string) bool {
	lower := strings.ToLower(token)
	if !strings.HasSuffix(lower, "'") {
		return false
	}
	for _, prefix := range []string{"'nonce-", "'sha256-", "'sha384-", "'sha512-"} {
		if strings.HasPrefix(lower, prefix) && len(token) > len(prefix)+1 {
			return true
		}
	}
	return false
}

// cspPIsKeyword reports whether token is any recognised quoted CSP keyword —
// a fixed keyword like 'self' or 'unsafe-inline', or a nonce-/hash-source.
func cspPIsKeyword(token string) bool {
	if len(token) < 2 || !strings.HasPrefix(token, "'") || !strings.HasSuffix(token, "'") {
		return false
	}
	if cspPKnownKeywordSet[strings.ToLower(token)] {
		return true
	}
	return cspPIsNonceOrHash(token)
}

// cspPIsParseableSource reports whether token is syntactically valid as a CSP
// source expression: the bare wildcard "*", a recognised quoted keyword, a
// scheme-source ("https:"), or a host-source ("https://*.example.com:8443/*").
// A token that starts with a quote but matches none of the known keyword
// forms is rejected outright rather than falling through to the host-source
// regex — a mistyped or unterminated quoted keyword is a syntax error, not an
// oddly-shaped hostname.
func cspPIsParseableSource(token string) bool {
	if token == "*" {
		return true
	}
	if cspPIsKeyword(token) {
		return true
	}
	if strings.HasPrefix(token, "'") {
		return false
	}
	if cspPSchemeSourceRe.MatchString(token) {
		return true
	}
	return cspPHostSourceRe.MatchString(token)
}

// cspPContainsStrictDynamic reports whether sources includes 'strict-dynamic'.
func cspPContainsStrictDynamic(sources []string) bool {
	for _, src := range sources {
		if strings.EqualFold(src, cspPStrictDynamic) {
			return true
		}
	}
	return false
}

// cspPAllowsUntrustedExecution is the shared decision table behind
// AllowsUntrustedScript and AllowsUntrustedStyle: given the effective source
// list for script-src or style-src, does it permit inline or arbitrary
// resource execution an attacker could reach via injection?
//
// Two neutralisation rules are the entire point of this function, and
// getting either backwards is the classic CSP-analyser false positive:
//
//  1. A nonce-source or hash-source causes browsers to IGNORE
//     'unsafe-inline' (CSP3 §8.4, "Directives » script-src"). It does NOT
//     neutralise a host/scheme allowlist or a bare "*" — those keep
//     permitting untrusted content regardless of any nonce/hash also
//     present. So 'unsafe-inline' only counts against the policy when no
//     nonce/hash source is also present.
//  2. 'strict-dynamic' tells supporting browsers to disregard the REST of
//     the allowlist entirely (host/scheme sources, 'self', 'unsafe-inline')
//     and trust only nonce/hash-tagged scripts plus whatever those trusted
//     scripts load dynamically. A policy with 'strict-dynamic' plus a host
//     allowlist is not "the allowlist is untrusted" — the allowlist is inert
//     for any browser that honours strict-dynamic. Reporting it as
//     "allows untrusted execution" would be exactly backwards.
func cspPAllowsUntrustedExecution(sources []string) bool {
	if sources == nil {
		// Neither the directive nor its fallback chain is declared at all:
		// nothing restricts this resource type, which is at least as
		// permissive as an explicit 'unsafe-inline'.
		return true
	}

	var (
		hasUnsafeInline  bool
		hasNonceOrHash   bool
		hasStrictDynamic bool
		hasWildcard      bool
		hasUnsafeScheme  bool
	)
	for _, src := range sources {
		lower := strings.ToLower(src)
		switch {
		case lower == cspPUnsafeInline:
			hasUnsafeInline = true
		case lower == cspPStrictDynamic:
			hasStrictDynamic = true
		case src == "*":
			hasWildcard = true
		case cspPIsNonceOrHash(src):
			hasNonceOrHash = true
		case lower == "data:" || lower == "http:":
			// "The policy allows data: URLs which allows arbitrary scripts
			// to be executed" / the http: analogue: an unauthenticated
			// scheme source that lets any origin (or a MITM on plaintext
			// HTTP) serve the resource.
			hasUnsafeScheme = true
		}
	}

	if hasStrictDynamic {
		return false
	}
	if hasUnsafeInline && !hasNonceOrHash {
		return true
	}
	if hasWildcard || hasUnsafeScheme {
		// "The policy allows global wildcard URLs which allows arbitrary
		// scripts/styles to be executed."
		return true
	}
	return false
}

// AllowsUntrustedScript reports whether the policy's effective script-src
// permits untrusted script execution: see cspPAllowsUntrustedExecution for
// the exact decision table, including the nonce/hash and strict-dynamic
// neutralisation rules. This is the primitive behind catalog row 2098436.
func (p CSPPolicy) AllowsUntrustedScript() bool {
	return cspPAllowsUntrustedExecution(p.EffectiveSources("script-src"))
}

// AllowsUntrustedStyle is AllowsUntrustedScript's style-src counterpart,
// behind catalog row 2098437 ("The policy contains unsafe-inline which can
// allow arbitrary styles to be executed" / global-wildcard style equivalent).
func (p CSPPolicy) AllowsUntrustedStyle() bool {
	return cspPAllowsUntrustedExecution(p.EffectiveSources("style-src"))
}

// AllowsFormHijacking reports whether the policy fails to restrict <form
// action> targets: form-action is absent entirely (see EffectiveSources'
// doc comment on why default-src never covers it), or present but permits
// the bare wildcard "*". This is the primitive behind catalog row 2098440.
func (p CSPPolicy) AllowsFormHijacking() bool {
	sources := p.EffectiveSources("form-action")
	if sources == nil {
		return true
	}
	for _, src := range sources {
		if src == "*" {
			return true
		}
	}
	return false
}

// AllowlistedScriptSources returns the non-keyword host/scheme sources in the
// policy's effective script-src — the raw material for catalog row 2098435
// ("allowlisted script resources"), whose finding text warns that any
// allowlisted domain hosting a reflected/DOM-XSS-vulnerable or JSONP endpoint
// can be abused to bypass the policy.
//
// When 'strict-dynamic' is present, the host/scheme allowlist is inert for
// any browser honouring it (see cspPAllowsUntrustedExecution's doc comment),
// so reporting those entries as an exploitable allowlist would be the same
// false positive AllowsUntrustedScript avoids; this returns nil in that case.
func (p CSPPolicy) AllowlistedScriptSources() []string {
	sources := p.EffectiveSources("script-src")
	if len(sources) == 0 {
		return nil
	}
	if cspPContainsStrictDynamic(sources) {
		return nil
	}

	hosts := make([]string, 0, len(sources))
	for _, src := range sources {
		if cspPIsKeyword(src) || src == "*" {
			continue
		}
		hosts = append(hosts, src)
	}
	if len(hosts) == 0 {
		return nil
	}
	return hosts
}
