package scanner

import (
	"reflect"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// ParseCSP: basic shape, whitespace, and malformed syntax accumulation
// ---------------------------------------------------------------------------

func TestParseCSPOfAnEmptyHeaderValueYieldsNoDirectivesAndNoMalformedReasons(t *testing.T) {
	p := ParseCSP("")
	if len(p.Directives) != 0 {
		t.Fatalf("an empty header value must parse to zero directives, got %d", len(p.Directives))
	}
	if len(p.MalformedReasons) != 0 {
		t.Fatalf("an empty header value must not be treated as malformed, got %v", p.MalformedReasons)
	}
}

func TestParseCSPSkipsEmptySegmentsFromLeadingTrailingAndDoubledSemicolonsWithoutFlaggingThemMalformed(t *testing.T) {
	p := ParseCSP(";;default-src 'self';;script-src 'self';;")
	if len(p.MalformedReasons) != 0 {
		t.Fatalf("stray/duplicated semicolons must not themselves be reported as malformed, got %v", p.MalformedReasons)
	}
	if len(p.Directives) != 2 {
		t.Fatalf("stray semicolons must not create phantom directives, want 2 got %d: %+v", len(p.Directives), p.Directives)
	}
}

func TestParseCSPCollapsesRunsOfWhitespaceBetweenSourceExpressions(t *testing.T) {
	p := ParseCSP("script-src  'self'   https://cdn.example.com")
	d, ok := p.directive("script-src")
	if !ok {
		t.Fatal("script-src must be parsed as a directive")
	}
	want := []string{"'self'", "https://cdn.example.com"}
	if !reflect.DeepEqual(d.Sources, want) {
		t.Fatalf("runs of internal whitespace must not produce empty source tokens, got %v want %v", d.Sources, want)
	}
}

func TestParseCSPLowercasesDirectiveNamesSinceTheyAreCaseInsensitive(t *testing.T) {
	p := ParseCSP("Script-Src 'self'")
	if _, ok := p.directive("script-src"); !ok {
		t.Fatal("a mixed-case directive name must still be found under its lowercased form, since CSP directive names are case-insensitive")
	}
}

func TestParseCSPFlagsAnUnknownDirectiveNameAsMalformed(t *testing.T) {
	p := ParseCSP("scirpt-src 'self'")
	found := false
	for _, reason := range p.MalformedReasons {
		if strings.Contains(reason, "unknown directive") && strings.Contains(reason, "scirpt-src") {
			found = true
		}
	}
	if !found {
		t.Fatalf("a misspelled directive name must produce a concrete 'unknown directive' reason naming it, got %v", p.MalformedReasons)
	}
}

func TestParseCSPFlagsADuplicateDirectiveAndKeepsOnlyTheFirstOccurrenceEnforced(t *testing.T) {
	p := ParseCSP("script-src 'self'; script-src *")
	found := false
	for _, reason := range p.MalformedReasons {
		if strings.Contains(reason, "duplicate directive") && strings.Contains(reason, "script-src") {
			found = true
		}
	}
	if !found {
		t.Fatalf("a repeated directive name must produce a concrete 'duplicate directive' reason, got %v", p.MalformedReasons)
	}

	d, ok := p.directive("script-src")
	if !ok {
		t.Fatal("script-src must still be present once, from its first occurrence")
	}
	want := []string{"'self'"}
	if !reflect.DeepEqual(d.Sources, want) {
		t.Fatalf("CSP enforces only the FIRST occurrence of a duplicated directive, not the last or a merge; got %v want %v", d.Sources, want)
	}
}

func TestParseCSPFlagsANonBooleanDirectiveWithNoSourceExpressionsAsMalformed(t *testing.T) {
	p := ParseCSP("script-src; default-src 'self'")
	found := false
	for _, reason := range p.MalformedReasons {
		if strings.Contains(reason, "no source expressions") && strings.Contains(reason, "script-src") {
			found = true
		}
	}
	if !found {
		t.Fatalf("a directive with no source expressions (that isn't a boolean directive) must be flagged malformed, got %v", p.MalformedReasons)
	}
}

func TestParseCSPDoesNotFlagKnownBooleanDirectivesForHavingNoSourceExpressions(t *testing.T) {
	p := ParseCSP("upgrade-insecure-requests; block-all-mixed-content")
	for _, reason := range p.MalformedReasons {
		if strings.Contains(reason, "no source expressions") {
			t.Fatalf("upgrade-insecure-requests/block-all-mixed-content are complete with no source list; got a spurious malformed reason: %q", reason)
		}
	}
}

func TestParseCSPFlagsASourceExpressionThatIsNeitherAKeywordNorAParseableHostSourceAsMalformed(t *testing.T) {
	p := ParseCSP("script-src 'unsafe-inlin")
	found := false
	for _, reason := range p.MalformedReasons {
		if strings.Contains(reason, "unparseable source expression") {
			found = true
		}
	}
	if !found {
		t.Fatalf("an unterminated/misspelled quoted keyword must be rejected as unparseable, not silently accepted as a hostname; got %v", p.MalformedReasons)
	}
}

func TestParseCSPAcceptsQuotedKeywordsIncludingNonceAndHashSourcesAsWellFormed(t *testing.T) {
	p := ParseCSP("script-src 'self' 'none' 'unsafe-inline' 'unsafe-eval' 'strict-dynamic' 'nonce-abc123' 'sha256-deadbeef'")
	if len(p.MalformedReasons) != 0 {
		t.Fatalf("every token here is a recognised quoted keyword or nonce/hash source; got spurious malformed reasons: %v", p.MalformedReasons)
	}
}

func TestParseCSPAcceptsSchemeAndHostSourcesIncludingWildcardSubdomainsPortsAndPaths(t *testing.T) {
	p := ParseCSP("script-src https: https://cdn.example.com https://*.example.com:8443/scripts/*")
	if len(p.MalformedReasons) != 0 {
		t.Fatalf("scheme-sources and well-formed host-sources must not be flagged malformed; got %v", p.MalformedReasons)
	}
}

// ---------------------------------------------------------------------------
// EffectiveSources: the real fallback chain, and form-action's deliberate
// exclusion from it
// ---------------------------------------------------------------------------

func TestEffectiveSourcesReturnsTheDirectiveItselfWhenDeclared(t *testing.T) {
	p := ParseCSP("script-src 'self' https://cdn.example.com")
	got := p.EffectiveSources("script-src")
	want := []string{"'self'", "https://cdn.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("a declared directive must return its own sources verbatim, got %v want %v", got, want)
	}
}

func TestEffectiveSourcesFallsBackThroughScriptSrcElemToScriptSrcToDefaultSrc(t *testing.T) {
	// Only default-src is declared. script-src-elem has no direct entry, so it
	// must walk script-src-elem -> script-src -> default-src and land on
	// default-src's sources — proving the full three-link chain, not just a
	// single hop.
	p := ParseCSP("default-src 'self'")
	got := p.EffectiveSources("script-src-elem")
	want := []string{"'self'"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("script-src-elem must fall back through script-src to default-src when neither of the first two is declared, got %v want %v", got, want)
	}
}

func TestEffectiveSourcesPrefersScriptSrcOverDefaultSrcWhenBothAreDeclared(t *testing.T) {
	// script-src-elem is still undeclared, but script-src IS declared, so the
	// chain must stop at script-src and never reach default-src.
	p := ParseCSP("default-src 'none'; script-src 'self'")
	got := p.EffectiveSources("script-src-elem")
	want := []string{"'self'"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("the nearer link in the fallback chain must win over a farther one, got %v want %v", got, want)
	}
}

func TestEffectiveSourcesReturnsNilWhenNeitherTheDirectiveNorItsFallbackChainIsPresentAtAll(t *testing.T) {
	p := ParseCSP("frame-ancestors 'self'")
	got := p.EffectiveSources("script-src")
	if got != nil {
		t.Fatalf("with no script-src and no default-src declared at all, EffectiveSources must return nil to signal 'unrestricted', got %v", got)
	}
}

func TestEffectiveSourcesDoesNotFallBackFromFormActionToDefaultSrc(t *testing.T) {
	// This is the spec detail that makes form hijacking its own catalog row:
	// form-action is a navigation directive, and CSP's default-src fallback
	// only covers fetch directives. A strict default-src must NOT leak into
	// form-action.
	p := ParseCSP("default-src 'self'")
	got := p.EffectiveSources("form-action")
	if got != nil {
		t.Fatalf("form-action must NOT inherit from default-src; got %v, want nil (no fallback)", got)
	}
}

// ---------------------------------------------------------------------------
// AllowsUntrustedScript / AllowsUntrustedStyle: the nonce/hash and
// strict-dynamic neutralisation rules
// ---------------------------------------------------------------------------

func TestAllowsUntrustedScriptIsTrueForBareUnsafeInlineWithNoNonceOrHash(t *testing.T) {
	p := ParseCSP("script-src 'self' 'unsafe-inline'")
	if !p.AllowsUntrustedScript() {
		t.Fatal("'unsafe-inline' with no nonce/hash present must report untrusted script execution")
	}
}

func TestAllowsUntrustedScriptIsFalseWhenANonceAccompaniesUnsafeInlineBecauseBrowsersIgnoreUnsafeInlineThen(t *testing.T) {
	// The core neutralisation rule under test: per CSP3, a nonce-source (or
	// hash-source) causes supporting browsers to ignore 'unsafe-inline'
	// entirely. A naive analyser that only checks for the substring
	// "unsafe-inline" would wrongly flag this policy as unsafe.
	p := ParseCSP("script-src 'self' 'unsafe-inline' 'nonce-r4nd0m123'")
	if p.AllowsUntrustedScript() {
		t.Fatal("a nonce source alongside 'unsafe-inline' neutralises 'unsafe-inline' in supporting browsers; this must NOT report untrusted script execution")
	}
}

func TestAllowsUntrustedScriptIsFalseWhenAHashAccompaniesUnsafeInlineForTheSameReason(t *testing.T) {
	p := ParseCSP("script-src 'self' 'unsafe-inline' 'sha256-abcdef0123456789'")
	if p.AllowsUntrustedScript() {
		t.Fatal("a hash source alongside 'unsafe-inline' neutralises 'unsafe-inline' just like a nonce does; this must NOT report untrusted script execution")
	}
}

func TestAllowsUntrustedScriptIsFalseWhenStrictDynamicNeutralisesAHostAllowlist(t *testing.T) {
	// The second neutralisation rule: 'strict-dynamic' makes supporting
	// browsers disregard the rest of the allowlist (host/scheme sources,
	// 'self', 'unsafe-inline'). A host allowlist next to 'strict-dynamic' is
	// inert, not exploitable, so this must not be reported as untrusted.
	p := ParseCSP("script-src 'nonce-r4nd0m123' 'strict-dynamic' https://untrusted-cdn.example.com")
	if p.AllowsUntrustedScript() {
		t.Fatal("'strict-dynamic' neutralises the host allowlist for supporting browsers; reporting it as untrusted execution would be the classic CSP-analyser false positive")
	}
}

func TestAllowsUntrustedScriptIsTrueForABareWildcardSource(t *testing.T) {
	p := ParseCSP("script-src *")
	if !p.AllowsUntrustedScript() {
		t.Fatal("a bare '*' script-src allows any host to serve script and must report untrusted script execution")
	}
}

func TestAllowsUntrustedScriptIsTrueForADataSchemeSource(t *testing.T) {
	p := ParseCSP("script-src 'self' data:")
	if !p.AllowsUntrustedScript() {
		t.Fatal("a data: scheme source lets injected markup smuggle an executable script and must report untrusted script execution")
	}
}

func TestAllowsUntrustedScriptIsTrueWhenNeitherScriptSrcNorDefaultSrcIsDeclaredAtAll(t *testing.T) {
	p := ParseCSP("frame-ancestors 'self'")
	if !p.AllowsUntrustedScript() {
		t.Fatal("no script-src and no default-src fallback means nothing restricts script execution at all, which must report untrusted script execution")
	}
}

func TestAllowsUntrustedScriptIsFalseForAStrictAllowlistWithNoUnsafeKeywordsWildcardOrUnsafeScheme(t *testing.T) {
	p := ParseCSP("script-src 'self' https://cdn.example.com")
	if p.AllowsUntrustedScript() {
		t.Fatal("a strict host allowlist with no unsafe-inline/wildcard/unsafe-scheme must not report untrusted script execution")
	}
}

func TestAllowsUntrustedStyleMirrorsAllowsUntrustedScriptForTheStyleSrcDirective(t *testing.T) {
	p := ParseCSP("style-src 'self' 'unsafe-inline'")
	if !p.AllowsUntrustedStyle() {
		t.Fatal("'unsafe-inline' with no nonce/hash in style-src must report untrusted style execution")
	}

	neutralised := ParseCSP("style-src 'self' 'unsafe-inline' 'nonce-abc12345'")
	if neutralised.AllowsUntrustedStyle() {
		t.Fatal("a nonce alongside 'unsafe-inline' in style-src must neutralise it just like it does for script-src")
	}
}

// ---------------------------------------------------------------------------
// AllowsFormHijacking: absence vs. explicit wildcard, and the default-src
// non-fallback proven end to end
// ---------------------------------------------------------------------------

func TestAllowsFormHijackingIsTrueWhenFormActionIsAbsentEvenWithAStrictDefaultSrc(t *testing.T) {
	// Proves EffectiveSources' no-fallback rule end to end: a strict
	// default-src 'self' does nothing to stop form hijacking because
	// form-action never inherits from it.
	p := ParseCSP("default-src 'self'")
	if !p.AllowsFormHijacking() {
		t.Fatal("an absent form-action must report form hijacking even when default-src is strict, since form-action does not fall back to default-src")
	}
}

func TestAllowsFormHijackingIsTrueWhenFormActionExplicitlyPermitsAWildcard(t *testing.T) {
	p := ParseCSP("form-action *")
	if !p.AllowsFormHijacking() {
		t.Fatal("an explicit wildcard form-action must report form hijacking")
	}
}

func TestAllowsFormHijackingIsFalseWhenFormActionRestrictsToSelf(t *testing.T) {
	p := ParseCSP("default-src 'self'; form-action 'self'")
	if p.AllowsFormHijacking() {
		t.Fatal("an explicit, restrictive form-action 'self' must not report form hijacking")
	}
}

// ---------------------------------------------------------------------------
// AllowlistedScriptSources
// ---------------------------------------------------------------------------

func TestAllowlistedScriptSourcesReturnsOnlyTheNonKeywordHostAndSchemeSources(t *testing.T) {
	p := ParseCSP("script-src 'self' 'unsafe-inline' https://cdn.example.com https://other.example.net")
	got := p.AllowlistedScriptSources()
	want := []string{"https://cdn.example.com", "https://other.example.net"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("keywords like 'self'/'unsafe-inline' must be excluded, leaving only the host allowlist, got %v want %v", got, want)
	}
}

func TestAllowlistedScriptSourcesReturnsNilWhenScriptSrcHasNoHostOrSchemeSources(t *testing.T) {
	p := ParseCSP("script-src 'self' 'unsafe-inline'")
	if got := p.AllowlistedScriptSources(); got != nil {
		t.Fatalf("with only keywords and no host/scheme sources there is nothing to allowlist, got %v", got)
	}
}

func TestAllowlistedScriptSourcesReturnsNilWhenStrictDynamicNeutralisesTheHostAllowlist(t *testing.T) {
	p := ParseCSP("script-src 'nonce-abc12345' 'strict-dynamic' https://untrusted-cdn.example.com")
	if got := p.AllowlistedScriptSources(); got != nil {
		t.Fatalf("'strict-dynamic' makes the host allowlist inert; reporting it as an allowlisted-resources finding would be the same false positive AllowsUntrustedScript avoids, got %v", got)
	}
}

func TestAllowlistedScriptSourcesFollowsTheDefaultSrcFallbackWhenScriptSrcIsUndeclared(t *testing.T) {
	p := ParseCSP("default-src https://cdn.example.com")
	got := p.AllowlistedScriptSources()
	want := []string{"https://cdn.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("with no script-src declared, the effective (default-src) allowlist must be reported, got %v want %v", got, want)
	}
}
