package httputil

import "testing"

func TestRefreshTargetGrammar(t *testing.T) {
	for _, c := range []struct {
		in, want string
		ok       bool
	}{
		{"0; url=/a", "/a", true}, {"5;URL='/b c'", "/b c", true}, {`3, url="/q"`, "/q", true},
		{"1; /bare", "/bare", true}, {"0.5; url = /spaced", "/spaced", true},
		{"10", "", false}, {"url=/x", "", false}, {"0; url=", "", false},
	} {
		if got, ok := RefreshTarget(c.in); got != c.want || ok != c.ok {
			t.Errorf("RefreshTarget(%q) = %q,%v; want %q,%v", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestMetaRefreshTarget(t *testing.T) {
	if got, ok := MetaRefreshTarget([]byte(`<html><head><META HTTP-EQUIV="Refresh" CONTENT="0;URL=/next"></head></html>`)); !ok || got != "/next" {
		t.Errorf("got %q %v", got, ok)
	}
	if _, ok := MetaRefreshTarget([]byte(`<html><head><meta name="refresh" content="0;url=/x"></head></html>`)); ok {
		t.Error("a meta without http-equiv=refresh is not a redirect")
	}
}
