package web

import (
	"net/url"
	"strings"
	"testing"
)

// The engines section renders, and a DOM value the route would refuse is refused at review.
func TestUI2SettingsEnginesRendersAndRefusesABadEngine(t *testing.T) {
	s := newTestServer()
	if body := getUI2(t, s, "/ui2/settings/write/engines").Body.String(); !strings.Contains(body, `id="settings-engines"`) {
		t.Fatalf("engines section did not render: %.200s", body)
	}
	out := postUI2Form(t, s, "/ui2/settings/write/engines/confirm", url.Values{"op": {"dom"}, "engine": {"/bin/sh"}}).Body.String()
	if !strings.Contains(out, "a browser path is not accepted at runtime") {
		t.Fatalf("a non-browser engine was not refused at review: %.300s", out)
	}
}
