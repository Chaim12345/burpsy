package scanner

import (
	"net/http"
	"testing"
)

func TestRequestURLOverridesUsesTheRecoveredHeaderSet(t *testing.T) {
	h := http.Header{}
	h.Set("X-Original-URL", "/admin")
	if got := RequestURLOverrides(h); len(got) != 1 || got[0] != "X-Original-URL" {
		t.Fatalf("RequestURLOverrides = %v, want [X-Original-URL]", got)
	}

	h.Set("X-Rewrite-URL", "/admin")
	if got := RequestURLOverrides(h); len(got) != 2 {
		t.Fatalf("RequestURLOverrides = %v, want both recovered headers", got)
	}
}

func TestAnEmptyOverrideHeaderIsNotAnOverride(t *testing.T) {
	h := http.Header{}
	h.Set("X-Original-URL", "")
	if got := RequestURLOverrides(h); len(got) != 0 {
		t.Fatalf("an empty header value was reported as an override: %v", got)
	}
}

func TestMethodOverridesUsesTheRecoveredHeaderSet(t *testing.T) {
	h := http.Header{}
	h.Set("X-HTTP-Method-Override", "DELETE")
	if got := MethodOverrides(h); len(got) != 1 || got[0] != "X-HTTP-Method-Override" {
		t.Fatalf("MethodOverrides = %v, want [X-HTTP-Method-Override]", got)
	}
}

func TestAbsentContentTypeIsDistinctFromASingleOne(t *testing.T) {
	if got := DeclareContentType(http.Header{}); got != ContentTypeAbsent {
		t.Fatalf("empty headers gave %v, want ContentTypeAbsent", got)
	}
	h := http.Header{}
	h.Set("Content-Type", "text/html; charset=utf-8")
	if got := DeclareContentType(h); got != ContentTypeSingle {
		t.Fatalf("one content type gave %v, want ContentTypeSingle", got)
	}
}

func TestRepeatedContentTypeHeadersAreMultiple(t *testing.T) {
	h := http.Header{}
	h.Add("Content-Type", "text/html")
	h.Add("Content-Type", "application/json")
	if got := DeclareContentType(h); got != ContentTypeMultiple {
		t.Fatalf("two Content-Type headers gave %v, want ContentTypeMultiple", got)
	}
}

// A comma-separated list in one header is just as ambiguous to the recipient as two headers.
func TestCommaSeparatedContentTypeIsMultiple(t *testing.T) {
	h := http.Header{}
	h.Set("Content-Type", "text/html, application/json")
	if got := DeclareContentType(h); got != ContentTypeMultiple {
		t.Fatalf("a comma-separated content type gave %v, want ContentTypeMultiple", got)
	}
}

// The row is about a body served without a declaration; an empty body is not the defect.
func TestContentTypeMissingOnBodyNeedsABody(t *testing.T) {
	if ContentTypeMissingOnBody(http.Header{}, 0) {
		t.Error("an empty body with no content type was reported")
	}
	if !ContentTypeMissingOnBody(http.Header{}, 512) {
		t.Error("a body with no content type was not reported")
	}
}

func TestLongRedirectionNeedsBoth3xxAndALargeBody(t *testing.T) {
	if !IsLongRedirectionResponse(302, LongRedirectBodyBytes+1) {
		t.Error("a 302 with an oversized body was not reported")
	}
	if IsLongRedirectionResponse(302, LongRedirectBodyBytes) {
		t.Error("a 302 at exactly the threshold was reported")
	}
	if IsLongRedirectionResponse(200, LongRedirectBodyBytes*10) {
		t.Error("a 200 was reported as a long redirection")
	}
}

// 304 is defined to carry no body, so content there is a different defect entirely.
func TestNotModifiedIsExcludedFromLongRedirection(t *testing.T) {
	if IsLongRedirectionResponse(http.StatusNotModified, LongRedirectBodyBytes*4) {
		t.Error("a 304 was reported as a long redirection response")
	}
}

func TestRefererPolicyThatWithholdsTheQueryStringSuppressesTheFinding(t *testing.T) {
	for _, p := range []string{"no-referrer", "same-origin", "strict-origin-when-cross-origin", "ORIGIN"} {
		if !RefererPolicyWithholdsURL(p) {
			t.Errorf("policy %q was not treated as withholding the URL", p)
		}
	}
	for _, p := range []string{"", "unsafe-url", "no-referrer-when-downgrade"} {
		if RefererPolicyWithholdsURL(p) {
			t.Errorf("policy %q was treated as withholding the URL", p)
		}
	}
}

func TestCrossDomainRefererLeakNeedsAQueryStringToLeak(t *testing.T) {
	body := []byte(`<a href="https://third.test/x">out</a>`)

	leaks, err := CrossDomainRefererLeaks("https://app.test/page?token=abc", "", body)
	if err != nil {
		t.Fatalf("CrossDomainRefererLeaks: %v", err)
	}
	if len(leaks) != 1 || leaks[0].TargetHost != "third.test" {
		t.Fatalf("leaks = %+v, want one leak to third.test", leaks)
	}

	leaks, err = CrossDomainRefererLeaks("https://app.test/page", "", body)
	if err != nil {
		t.Fatalf("CrossDomainRefererLeaks: %v", err)
	}
	if len(leaks) != 0 {
		t.Errorf("a page with no query string reported leaks: %+v", leaks)
	}
}

func TestSameHostAndRelativeLinksDoNotLeak(t *testing.T) {
	body := []byte(`<a href="/local">a</a><a href="https://app.test/other">b</a><a href="mailto:x@y.test">c</a>`)
	leaks, err := CrossDomainRefererLeaks("https://app.test/p?t=1", "", body)
	if err != nil {
		t.Fatalf("CrossDomainRefererLeaks: %v", err)
	}
	if len(leaks) != 0 {
		t.Fatalf("same-host, relative and mailto links reported as leaks: %+v", leaks)
	}
}

func TestRefererLeaksAreDedupedByHost(t *testing.T) {
	body := []byte(`<a href="https://third.test/a">1</a><a href="https://third.test/b">2</a>`)
	leaks, _ := CrossDomainRefererLeaks("https://app.test/p?t=1", "", body)
	if len(leaks) != 1 {
		t.Fatalf("leaks = %+v, want one entry per distinct host", leaks)
	}
}

func TestEffectiveRefererPolicySuppressesLeaks(t *testing.T) {
	body := []byte(`<a href="https://third.test/x">out</a>`)
	leaks, _ := CrossDomainRefererLeaks("https://app.test/p?token=abc", "no-referrer", body)
	if len(leaks) != 0 {
		t.Fatalf("an effective Referrer-Policy did not suppress the finding: %+v", leaks)
	}
}
