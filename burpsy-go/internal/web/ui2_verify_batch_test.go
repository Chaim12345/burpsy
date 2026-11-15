package web

import (
	"strings"
	"testing"
)

// intercept.html must expose the interception state as a data attribute so the Alt+T toggle
// on other pages can read it before deciding whether to disable or navigate.
func TestUI2InterceptStateElement(t *testing.T) {
	for _, tc := range []struct {
		enabled bool
		want    string
	}{
		{true, `data-on="true"`},
		{false, `data-on="false"`},
	} {
		out := string(ui2Exec("intercept.html", map[string]any{"enabled": tc.enabled, "wired": 0, "pending": 0, "in_scope_only": false}))
		if !strings.Contains(out, `id="intercept-state"`) || !strings.Contains(out, tc.want) {
			t.Fatalf("intercept state element missing (%v): %s", tc.enabled, out)
		}
	}
}
