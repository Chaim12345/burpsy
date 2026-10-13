package domexec

import (
	"context"
	"strings"
	"testing"
	"time"
)

// TestRenderFragmentRunsInsertedHandlers pins what an innerHTML insertion executes: resource
// error handlers, a details toggle, and an svg load handler run; a <script> element, escaped
// markup and plain text do not. The escaped and script rows are the negative controls — a
// recorder that fired on them would make every reflection look like execution.
func TestRenderFragmentRunsInsertedHandlers(t *testing.T) {
	b := newTestBrowser(t)
	cases := []struct {
		name, fragment, want string
		fires                bool
	}{
		{"img unquoted onerror", `<img src=zxssa1 onerror=alert(zxssa1Mark) width="4"/>`, "zxssa1Mark", true},
		{"img onerror backtick", "<img src=zxssa2 onerror=alert`zxssa2Mark` width=\"4\"/>", "zxssa2Mark", true},
		{"img quoted breakout onerror", `<img src="zxssa3" onerror="alert('zxssa3Mark')" width="4"/>`, "zxssa3Mark", true},
		{"details toggle", `<div id="comments"><details open ontoggle=alert('zxssa4Mark')></div>`, "zxssa4Mark", true},
		{"handler evaluating an undefined name throws", `<img src=x onerror=zxssa5Mark()>`, "zxssa5Mark is not defined", true},
		{"absolute image is blocked, error fires", `<img src="http://127.0.0.1:1/x.png" onerror="alert('zxssa6Mark')">`, "zxssa6Mark", true},
		{"script element is inert", `<script>alert('zxssb1Mark')</script>`, "zxssb1Mark", false},
		{"escaped markup is inert", `<div>&lt;img src=x onerror=alert('zxssb2Mark')&gt;</div>`, "zxssb2Mark", false},
		{"onfocus on img does not fire", `<img src=zxssb3 autofocus onfocus=alert('zxssb3Mark')>`, "zxssb3Mark", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			calls, err := b.RenderFragment(ctx, tc.fragment, 0)
			if err != nil {
				t.Fatalf("RenderFragment: %v", err)
			}
			got := false
			for _, c := range calls {
				if strings.Contains(c.Args, tc.want) || c.TargetID == tc.want {
					got = true
				}
			}
			if got != tc.fires {
				t.Fatalf("fired=%v, want %v (calls %+v)", got, tc.fires, calls)
			}
		})
	}
}
