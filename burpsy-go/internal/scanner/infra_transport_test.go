package scanner

import (
	"net/http"
	"testing"
)

func TestUnencryptedCommunicationIsJudgedOnScheme(t *testing.T) {
	if !IsUnencryptedCommunication("http://app.test/p") {
		t.Error("an http:// URL was not reported as unencrypted")
	}
	if IsUnencryptedCommunication("https://app.test/p") {
		t.Error("an https:// URL was reported as unencrypted")
	}
}

func TestHSTSMaxAgeZeroIsNotEnforcement(t *testing.T) {
	h := ParseHSTS("max-age=0")
	if !h.Present {
		t.Error("header was not recorded as present")
	}
	if h.Enforced() {
		t.Error("max-age=0 counted as enforcement; it instructs the browser to forget the policy")
	}
}

func TestHSTSWithPositiveMaxAgeIsEnforced(t *testing.T) {
	h := ParseHSTS("max-age=31536000; includeSubDomains; preload")
	if !h.Enforced() {
		t.Fatal("a year-long max-age was not treated as enforcement")
	}
	if h.MaxAge != 31536000 || !h.IncludeSubDomains || !h.Preload {
		t.Errorf("parsed HSTS = %+v", h)
	}
}

func TestHSTSWithoutMaxAgeIsNotEnforced(t *testing.T) {
	if ParseHSTS("includeSubDomains").Enforced() {
		t.Error("a header with no max-age counted as enforcement")
	}
}

func TestStrictTransportSecurityOnlyAppliesOverTLS(t *testing.T) {
	if StrictTransportSecurityNotEnforced(false, http.Header{}) {
		t.Error("a cleartext response was flagged for a missing HSTS header, which it must ignore")
	}
	if !StrictTransportSecurityNotEnforced(true, http.Header{}) {
		t.Error("an https response with no HSTS header was not flagged")
	}
}

func TestStrictTransportSecurityHonoursAValidHeader(t *testing.T) {
	h := http.Header{}
	h.Set("Strict-Transport-Security", "max-age=63072000")
	if StrictTransportSecurityNotEnforced(true, h) {
		t.Error("a valid HSTS header was still reported as not enforced")
	}
}

// no-cache still permits storage; only no-store prevents it. Treating them alike would
// clear a response that remains recoverable from disk.
func TestNoCacheDoesNotPreventStorage(t *testing.T) {
	h := http.Header{}
	h.Set("Cache-Control", "no-cache")
	if !ResponseIsCacheable(h) {
		t.Error("no-cache was treated as preventing storage")
	}
}

func TestNoStorePreventsCaching(t *testing.T) {
	h := http.Header{}
	h.Set("Cache-Control", "private, no-store, max-age=0")
	if ResponseIsCacheable(h) {
		t.Error("no-store did not prevent caching")
	}
}

func TestCacheableHTTPSResponseRequiresTLS(t *testing.T) {
	if CacheableHTTPSResponse(false, http.Header{}) {
		t.Error("a cleartext response was reported as a cacheable HTTPS response")
	}
	if !CacheableHTTPSResponse(true, http.Header{}) {
		t.Error("an https response with no cache directives was not reported")
	}
}

func TestMixedContentSeparatesActiveFromPassive(t *testing.T) {
	body := []byte(`
		<script src="http://cdn.test/a.js"></script>
		<img src="http://cdn.test/a.png">`)
	refs, err := MixedContent("https://app.test/p", true, body)
	if err != nil {
		t.Fatalf("MixedContent: %v", err)
	}
	if len(refs) != 2 {
		t.Fatalf("refs = %+v, want 2", refs)
	}

	// Assert the classification per tag rather than through HasActiveMixedContent: a
	// filtered slice can be empty for the wrong reason, which hides a misclassification.
	wantActive := map[string]bool{"script": true, "img": false}
	for _, r := range refs {
		want, known := wantActive[r.Tag]
		if !known {
			t.Fatalf("unexpected tag %q in %+v", r.Tag, r)
		}
		if r.Active != want {
			t.Errorf("%s Active = %v, want %v; executable and passive subresources are different findings",
				r.Tag, r.Active, want)
		}
		delete(wantActive, r.Tag)
	}
	if len(wantActive) != 0 {
		t.Errorf("no reference produced for %v", wantActive)
	}

	if !HasActiveMixedContent(refs) {
		t.Error("a cleartext script was not classified as active mixed content")
	}
}

func TestHTTPSSubresourcesAreNotMixedContent(t *testing.T) {
	body := []byte(`<script src="https://cdn.test/a.js"></script><script src="/local.js"></script>`)
	refs, err := MixedContent("https://app.test/p", true, body)
	if err != nil {
		t.Fatalf("MixedContent: %v", err)
	}
	if len(refs) != 0 {
		t.Fatalf("https and relative subresources reported as mixed content: %+v", refs)
	}
}

// Mixed content is defined relative to a secure context, so a cleartext page has none.
func TestCleartextPageHasNoMixedContent(t *testing.T) {
	body := []byte(`<script src="http://cdn.test/a.js"></script>`)
	refs, err := MixedContent("http://app.test/p", false, body)
	if err != nil {
		t.Fatalf("MixedContent: %v", err)
	}
	if len(refs) != 0 {
		t.Fatalf("a cleartext page reported mixed content: %+v", refs)
	}
}

func TestMixedContentCoversFormActionsAndStylesheets(t *testing.T) {
	body := []byte(`
		<link rel="stylesheet" href="http://cdn.test/s.css">
		<form action="http://cdn.test/submit"></form>`)
	refs, err := MixedContent("https://app.test/p", true, body)
	if err != nil {
		t.Fatalf("MixedContent: %v", err)
	}
	if len(refs) != 2 || !HasActiveMixedContent(refs) {
		t.Fatalf("refs = %+v, want two active references", refs)
	}
}
