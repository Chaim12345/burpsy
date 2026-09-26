package persist

import (
	"slices"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

func TestCookiesTitleSurviveSaveLoadRoundTrip(t *testing.T) {
	s := newTestStore(t)
	ex := &core.Exchange{
		Request: core.MsgPtr(core.MsgId(1)), Host: "roundtrip.test", Port: 80, Method: "GET", Path: "/",
		Cookies: []string{"sid", "theme"}, Title: "Roundtrip Shop",
	}
	s.SaveExchange(ex)
	loaded, err := s.LoadExchanges()
	if err != nil {
		t.Fatalf("LoadExchanges: %v", err)
	}
	if len(loaded) != 1 {
		t.Fatalf("loaded %d exchanges, want 1", len(loaded))
	}
	if !slices.Equal(loaded[0].Cookies, []string{"sid", "theme"}) {
		t.Errorf("Cookies = %q, want [sid theme]", loaded[0].Cookies)
	}
	if loaded[0].Title != "Roundtrip Shop" {
		t.Errorf("Title = %q, want Roundtrip Shop", loaded[0].Title)
	}
}
