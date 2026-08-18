package extscan

import (
	"errors"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

func TestAuthoriseAcceptsAnInScopeTarget(t *testing.T) {
	scope := core.NewScope()
	scope.AddInclude("example.com")

	got, err := Authorise(scope, "https://example.com/app/")
	if err != nil {
		t.Fatalf("Authorise: %v", err)
	}
	if !got.Authorised() {
		t.Error("target did not come back authorised")
	}
	if got.Host != "example.com" || got.Port != 443 || !got.IsTLS {
		t.Errorf("authority = %s:%d tls=%v, want example.com:443 tls=true", got.Host, got.Port, got.IsTLS)
	}
	if got.URL != "https://example.com/app/" {
		t.Errorf("URL = %q, want https://example.com/app/", got.URL)
	}
	if got.HostPort() != "example.com" {
		t.Errorf("HostPort() = %q, want example.com (the default port is not printed)", got.HostPort())
	}
}

func TestAuthoriseRefusesAnOutOfScopeTarget(t *testing.T) {
	scope := core.NewScope()
	scope.AddInclude("example.com")

	_, err := Authorise(scope, "https://not-the-target.example.org/")
	if !errors.Is(err, ErrUnauthorised) {
		t.Fatalf("err = %v, want ErrUnauthorised", err)
	}
}

// The gate that matters most: scope may authorise the base URL while a
// path-scoped exclude carves a hole out of the subtree. An external tool picks
// its own paths and will walk straight into that hole, so the run is refused
// rather than started. Without this the command would be a way to send requests
// the engagement explicitly excluded.
func TestAuthoriseRefusesAPartiallyScopedHost(t *testing.T) {
	scope := core.NewScope()
	scope.AddInclude("example.com")
	scope.Add(core.NewScopeRuleWithPath(core.ScopeExclude, "example.com", "/"))

	_, err := Authorise(scope, "https://example.com/")
	if !errors.Is(err, ErrUnauthorised) {
		t.Fatalf("err = %v, want ErrUnauthorised", err)
	}

	// And the narrower case: the base path is fine, an invented path under it is not.
	scope2 := core.NewScope()
	scope2.AddInclude("example.com")
	scope2.Add(core.NewScopeRuleWithPath(core.ScopeExclude, "example.com", "/app/burpsy"))
	_, subtreeErr := Authorise(scope2, "https://example.com/app/")
	if !errors.Is(subtreeErr, ErrUnauthorised) {
		t.Fatalf("a scope excluding part of the subtree was accepted: err = %v", subtreeErr)
	}
	if !strings.Contains(subtreeErr.Error(), "not every path beneath it") {
		t.Errorf("refusal does not explain itself: %q", subtreeErr)
	}
}

func TestAuthoriseRefusesNonHTTPAndMissingScope(t *testing.T) {
	scope := core.NewScope()
	for _, target := range []string{"", "ftp://example.com/", "https:///nohost", "not a url at all"} {
		if _, err := Authorise(scope, target); !errors.Is(err, ErrUnauthorised) {
			t.Errorf("Authorise(%q) err = %v, want ErrUnauthorised", target, err)
		}
	}
	// A nil scope is a refusal, never a waiver.
	if _, err := Authorise(nil, "https://example.com/"); !errors.Is(err, ErrUnauthorised) {
		t.Errorf("nil scope err = %v, want ErrUnauthorised", err)
	}
}

// A Target that never went through Authorise must not reach a binary. This is
// what makes the gate unavoidable rather than merely conventional.
func TestRunnersRefuseAnUnauthorisedTarget(t *testing.T) {
	cfg := Config{Tools: map[string]string{ToolFFUF: "ffuf", ToolNuclei: "nuclei"}}
	bare := Target{URL: "http://example.com/", Host: "example.com", Port: 80}

	ffuf := RunFFUF(t.Context(), cfg, core.NewScope(), bare, FFUFOptions{Wordlist: "/etc/hostname"})
	if ffuf.Outcome != OutcomeUnauthorised {
		t.Errorf("ffuf outcome = %v, want OutcomeUnauthorised", ffuf.Outcome)
	}
	nuc := RunNuclei(t.Context(), cfg, core.NewScope(), bare, NucleiOptions{})
	if nuc.Outcome != OutcomeUnauthorised {
		t.Errorf("nuclei outcome = %v, want OutcomeUnauthorised", nuc.Outcome)
	}
}

// Delegation is off until the operator switches it on: an empty allowlist
// refuses, and the refusal is OutcomeNotAllowed rather than a clean empty scan.
func TestEmptyAllowlistRefuses(t *testing.T) {
	scope := core.NewScopeAllowEverything()
	target, err := Authorise(scope, "http://127.0.0.1:1/")
	if err != nil {
		t.Fatalf("Authorise: %v", err)
	}

	res := RunNuclei(t.Context(), Config{}, scope, target, NucleiOptions{})
	if res.Outcome != OutcomeNotAllowed {
		t.Errorf("outcome = %v, want OutcomeNotAllowed", res.Outcome)
	}
	if !errors.Is(res.Err, ErrNotAllowed) {
		t.Errorf("err = %v, want ErrNotAllowed", res.Err)
	}
	if res.Outcome.Looked() {
		t.Error("a refused run reported that it looked")
	}
}

// An allowlisted name whose binary is missing is a different outcome from a
// name that was never allowed — a misconfigured path must not read as a policy
// decision.
func TestAllowlistedButMissingBinaryIsUnavailable(t *testing.T) {
	scope := core.NewScopeAllowEverything()
	target, err := Authorise(scope, "http://127.0.0.1:1/")
	if err != nil {
		t.Fatalf("Authorise: %v", err)
	}
	cfg := Config{Tools: map[string]string{ToolNuclei: "/nonexistent/definitely-not-nuclei"}}

	res := RunNuclei(t.Context(), cfg, scope, target, NucleiOptions{})
	if res.Outcome != OutcomeUnavailable {
		t.Errorf("outcome = %v, want OutcomeUnavailable", res.Outcome)
	}
	if !errors.Is(res.Err, ErrUnavailable) {
		t.Errorf("err = %v, want ErrUnavailable", res.Err)
	}
}

func TestFFUFWithoutAWordlistIsNotInvoked(t *testing.T) {
	scope := core.NewScopeAllowEverything()
	target, _ := Authorise(scope, "http://127.0.0.1:1/")
	cfg := Config{Tools: map[string]string{ToolFFUF: "ffuf"}}

	res := RunFFUF(t.Context(), cfg, scope, target, FFUFOptions{})
	if res.Outcome != OutcomeNotInvoked {
		t.Errorf("outcome = %v, want OutcomeNotInvoked", res.Outcome)
	}
	res = RunFFUF(t.Context(), cfg, scope, target, FFUFOptions{Wordlist: "/nonexistent/wordlist.txt"})
	if res.Outcome != OutcomeNotInvoked {
		t.Errorf("unreadable wordlist outcome = %v, want OutcomeNotInvoked", res.Outcome)
	}
}

// The severity mapping is the reason a merged report has one scale and not two.
func TestMapSeverityUsesBurpsysOwnVocabulary(t *testing.T) {
	cases := map[string]core.Severity{
		"critical": core.SeverityCritical,
		"high":     core.SeverityHigh,
		"medium":   core.SeverityMedium,
		"low":      core.SeverityLow,
		"info":     core.SeverityInformational,
		"unknown":  core.SeverityInformational,
		"":         core.SeverityInformational,
		"  HIGH ":  core.SeverityHigh,
	}
	for in, want := range cases {
		if got := MapSeverity(in); got != want {
			t.Errorf("MapSeverity(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestOutcomeLookedOnlyForCompleted(t *testing.T) {
	for _, o := range []Outcome{OutcomeNotInvoked, OutcomeNotAllowed, OutcomeUnauthorised, OutcomeUnavailable, OutcomeFailed} {
		if o.Looked() {
			t.Errorf("%v reported that the tool looked", o)
		}
	}
	if !OutcomeCompleted.Looked() {
		t.Error("OutcomeCompleted did not report that the tool looked")
	}
}

func TestCappedBufferStopsAtTheLimit(t *testing.T) {
	var b cappedBuffer
	b.limit = 10
	n, err := b.Write([]byte("0123456789abcdef"))
	if err != nil || n != 16 {
		t.Fatalf("Write = %d, %v; want the full length reported so the writer does not error", n, err)
	}
	if got := string(b.Bytes()); got != "0123456789" {
		t.Errorf("buffered %q, want the first 10 bytes only", got)
	}
	b.Write([]byte("more"))
	if len(b.Bytes()) != 10 {
		t.Errorf("buffer grew past the cap to %d bytes", len(b.Bytes()))
	}
}
