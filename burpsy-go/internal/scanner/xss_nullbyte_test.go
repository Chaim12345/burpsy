package scanner

import (
	"github.com/burpsy-go/burpsy/internal/domexec/domexectest"
	"html"
	"strings"
	"testing"
)

// The null-byte variant appends `<NUL><payload>` to the captured value, and is confirmed by the base
// payload's own confirmation: the variant changes what a truncating defence reads, never what counts
// as a breakout.
func TestTheNullBytePayloadIsTheBasePayloadBehindANUL(t *testing.T) {
	bank := xssPayloadsForContexts(classifyXSSContexts(`<img src=owl.jpgzxssabc width="400">`, "zxssabc"))
	if len(bank) == 0 {
		t.Fatal("no payload chosen for an unquoted img src")
	}
	base := bank[0]
	nb := xssNullBytePayload(base)
	if got, want := nb.build("zxssq"), "\x00"+base.build("zxssq"); got != want {
		t.Fatalf("null-byte payload = %q, want %q", got, want)
	}
	if nb.bit != base.bit || nb.confirm == nil {
		t.Fatalf("the variant must keep the base payload's evidence bit and confirmation")
	}
	if !strings.Contains(nb.note, xssNullByteVariantName) {
		t.Fatalf("note %q does not name the variant, so a finding could not say how it was carried", nb.note)
	}
}

// The parse-level half on the two VulnerableApp shapes, with the NUL in the answer: the HTML parser
// turns it into U+FFFD inside the value (img) or drops it from text (comments), and neither may stop
// the confirmation from seeing the injected handler or element - nor make it see one in the escaped
// safe forms.
func TestNullByteBreakoutsAreConfirmedThroughTheNULAndNotInTheEscapedForm(t *testing.T) {
	const seed = "owl.jpg"
	escapeBeforeNUL := func(s string) string {
		i := strings.IndexByte(s, 0)
		if i < 0 {
			return html.EscapeString(s)
		}
		return html.EscapeString(s[:i]) + s[i:]
	}
	img := func(v string) string { return `<img src=` + html.EscapeString(v) + ` width="400" height="300"/>` }
	comment := func(esc func(string) string) func(string) string {
		return func(v string) string { return `<div class="comment">` + esc(v) + `</div>` }
	}
	cases := []struct {
		name   string
		render func(string) string
		want   bool
	}{
		{"img allowlist read up to the NUL", img, true},
		{"comment escaped up to the NUL", comment(escapeBeforeNUL), true},
		{"comment escaped whole", comment(html.EscapeString), false},
	}
	for _, tc := range cases {
		observed := "zxssobserve"
		contexts := classifyXSSContexts(tc.render(seed+"\x00"+observed), observed)
		if len(contexts) == 0 {
			t.Errorf("%s: the observation canary behind the NUL was not placed in any context", tc.name)
			continue
		}
		bank := xssPayloadsForContexts(contexts)
		if len(bank) > maxXSSNullByteProbes {
			bank = bank[:maxXSSNullByteProbes]
		}
		confirmed := false
		for _, base := range bank {
			p := xssNullBytePayload(base)
			canary := newXSSCanary()
			body := tc.render(seed + p.build(canary))
			if p.confirm != nil && p.confirm(body, canary) {
				confirmed = true
				break
			}
		}
		if confirmed != tc.want {
			t.Errorf("%s: confirmed = %v, want %v (contexts %+v)", tc.name, confirmed, tc.want, contexts)
		}
	}
}

// End to end on the text/html gallery: the plain probes cannot reach the allowlisted value, so the
// finding exists only because the null-byte variant carried it, and must say so. Its safe twin
// allowlists the whole value and stays quiet. No browser needed.
func TestTheNullByteVariantFindsTheGalleryAndNotItsSafeTwin(t *testing.T) {
	rt := startRuntimeTarget(t)
	got := rt.findingsFor(t, "/nullbyte/gallery?src=owl.jpg", false)
	f, fired := got[xssReflectedIssue]
	if !fired {
		t.Fatalf("the XSS row did not fire on the null-byte gallery; rows reported: %s",
			strings.Join(rowNames(got), ", "))
	}
	if !strings.Contains(strings.Join(f.DecodingVariants, ","), xssNullByteVariantName) {
		t.Errorf("the finding names variants %v, want %q: only the null-byte variant can pass this "+
			"allowlist, so any other attribution is wrong", f.DecodingVariants, xssNullByteVariantName)
	}
	safe := rt.findingsFor(t, "/safe/nullbyte/gallery?src=owl.jpg", false)
	if f, fired := safe[xssReflectedIssue]; fired {
		t.Errorf("the safe gallery allowlists the whole value, NUL included, yet reported %q: %q",
			xssReflectedIssue, f.Evidence)
	}
}

// The two VulnerableApp shapes as served there - an HTML fragment a page's script inserts - are
// decided by rendering, so they need a browser; the evidence must name the null-byte variant.
func TestTheNullByteFragmentsAreConfirmedInTheBrowser(t *testing.T) {
	rt := startRuntimeTarget(t)
	if !rt.chrome {
		domexectest.Skip(t, "no Chrome on PATH: the fragment rows are untested")
	}
	for _, tc := range []struct{ path, row string }{
		{"/nullbyte/img?src=owl.jpg", xssReflectedIssue},
		{"/nullbyte/comments?comment=hello", xssStoredIssue},
	} {
		got := rt.findingsFor(t, tc.path, true)
		f, fired := got[tc.row]
		if !fired {
			t.Errorf("%s: %q did not fire; rows reported: %s", tc.path, tc.row, strings.Join(rowNames(got), ", "))
			continue
		}
		if !strings.Contains(f.Evidence, xssNullByteVariantName) {
			t.Errorf("%s: evidence %q does not name the null-byte variant", tc.path, f.Evidence)
		}
	}
}
