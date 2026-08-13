package scanner

import (
	"testing"
)

func TestWebCachePoisoningEvidenceReflectsInjectedValue(t *testing.T) {
	// A follow-up request that never sent the header yet contains the marker is
	// the poisoning signal.
	ev := analyzeCachePoisoningEvidence("burpsy-poisoned-host.invalid",
		"<html><a href='//burpsy-poisoned-host.invalid/x'>click</a></html>", true)
	if ev&poisonEvidenceReflected == 0 {
		t.Fatal("reflected injection evidence was not recognized")
	}
	if ev&poisonEvidenceCachable == 0 {
		t.Fatal("cacheable evidence was not recognized")
	}
}

func TestWebCachePoisoningEvidenceNoFalsePositiveOnDifferentBody(t *testing.T) {
	ev := analyzeCachePoisoningEvidence("burpsy-poisoned-host.invalid",
		"<html>an ordinary, unpoisoned page</html>", false)
	if ev != 0 {
		t.Fatalf("clean follow-up produced poisoning evidence %#x", ev)
	}
}

func TestWebCachePoisoningEvidenceMarkerAbsentIsNegative(t *testing.T) {
	// Same cacheable status, but the marker is absent: no reflection, so no finding.
	ev := analyzeCachePoisoningEvidence("burpsy-poisoned-host.invalid",
		"<html>content without the marker</html>", true)
	if ev&poisonEvidenceReflected != 0 {
		t.Fatal("reflected bit set without the marker present")
	}
	if ev&poisonEvidenceCachable == 0 {
		t.Fatal("cacheable bit should still be set for a cacheable response")
	}
}

func TestWebCacheDeceptionEvidenceFlagsDynamicUnderStaticKey(t *testing.T) {
	original := "Welcome back, alice — your balance is $12.00"
	decorated := "<html>" + original + "</html>"
	ev := analyzeCacheDeceptionEvidence(original, decorated, 200)
	if ev&deceptionEvidenceDynamicContent == 0 {
		t.Fatal("dynamic content under a static-looking key was not recognized")
	}
	if ev&deceptionEvidenceCacheableStatus == 0 {
		t.Fatal("cacheable status (200) was not recognized")
	}
}

func TestWebCacheDeceptionEvidenceNoFalsePositiveOnDifferentContent(t *testing.T) {
	original := "Welcome back, alice — your balance is $12.00"
	decorated := "<html>404 Not Found</html>"
	ev := analyzeCacheDeceptionEvidence(original, decorated, 404)
	if ev != 0 {
		t.Fatalf("unrelated 404 produced deception evidence %#x", ev)
	}
}

func TestWebCacheDeceptionEvidenceUncacheableStatusIsNegative(t *testing.T) {
	// 401 is a dynamic-looking status but not one a cache would store.
	original := "secret session content"
	decorated := "<html>" + original + "</html>"
	ev := analyzeCacheDeceptionEvidence(original, decorated, 401)
	if ev&deceptionEvidenceCacheableStatus != 0 {
		t.Fatal("401 must not be treated as a cacheable status")
	}
	if ev&deceptionEvidenceDynamicContent == 0 {
		t.Fatal("dynamic content bit should still be set")
	}
}

func TestResponseIsCacheableHonorsNoStore(t *testing.T) {
	if responseIsCacheable(map[string]string{"Cache-Control": "no-store"}) {
		t.Fatal("no-store response must not be cacheable")
	}
	if responseIsCacheable(map[string]string{"Cache-Control": "private"}) {
		t.Fatal("response with an Age header is a caching candidate")
	}
	if !responseIsCacheable(map[string]string{}) {
		t.Fatal("response without explicit uncacheable headers is conservatively cacheable")
	}
}

func TestAppendCacheDeceptionSuffixPreservesQuery(t *testing.T) {
	got := appendCacheDeceptionSuffix("/account/settings?token=abc")
	want := "/account/settings/nonexistent.css?token=abc"
	if got != want {
		t.Fatalf("appendCacheDeceptionSuffix = %q, want %q", got, want)
	}
	got = appendCacheDeceptionSuffix("/account/settings")
	if got != "/account/settings/nonexistent.css" {
		t.Fatalf("appendCacheDeceptionSuffix = %q, want /account/settings/nonexistent.css", got)
	}
}

func TestCacheCheckDeclinedEntriesAreValid(t *testing.T) {
	// This file used to decline "HTTP request smuggling" and "Client-side desync" for want of
	// a pipelining primitive. Both now run on SendPipelined and are registered by
	// FinalCheckDescriptors, so CacheCheckDescriptors declines nothing and the invariant
	// worth asserting is that it declines nothing rather than that it declines those two.
	for _, d := range CacheCheckDescriptors() {
		if d.Implementation == ImplementationDeclined {
			t.Errorf("%q is still declined here; the pipelining rows moved to checks_final.go", d.Name)
		}
		if !d.Runnable() {
			t.Errorf("%q is not runnable", d.Name)
		}
	}
}

func TestCacheCheckDescriptorsReturnsTwoValidDistinctTypes(t *testing.T) {
	descriptors := CacheCheckDescriptors()
	if len(descriptors) != 2 {
		t.Fatalf("CacheCheckDescriptors returned %d descriptors, want 2 (poisoning and deception; the two pipelining rows moved to checks_final.go)", len(descriptors))
	}

	seen := make(map[uint32]struct{}, len(descriptors))
	for _, d := range descriptors {
		if !d.Valid() {
			t.Fatalf("descriptor %q (%d) is not Valid()", d.Name, d.TypeIndex)
		}
		if _, dup := seen[d.TypeIndex]; dup {
			t.Fatalf("duplicate TypeIndex %d across cache descriptors", d.TypeIndex)
		}
		seen[d.TypeIndex] = struct{}{}

		catalog, ok := ByName(d.Name)
		if !ok {
			t.Fatalf("descriptor name %q is absent from catalog", d.Name)
		}
		if catalog.TypeIndex != d.TypeIndex {
			t.Fatalf("descriptor %q TypeIndex %d does not match catalog %d", d.Name, d.TypeIndex, catalog.TypeIndex)
		}
	}

	// The two pipelining rows moved to checks_final.go when SendPipelined gained a driver;
	// this file owns the two cache rows only.
	want := []string{
		"Web cache poisoning",
		"Web cache deception",
	}
	gotNames := make(map[string]bool, len(want))
	for _, d := range descriptors {
		gotNames[d.Name] = true
	}
	for _, name := range want {
		if !gotNames[name] {
			t.Errorf("CacheCheckDescriptors missing claimed name %q", name)
		}
	}
}
