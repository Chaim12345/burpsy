package extension

import (
	"strings"
	"testing"
)

// NormaliseChord (burpsy-react-ui-wsu4) is the host's half of the hotkey contract: a plugin
// declares its chord in Burp's Settings format, and the host either spells it in the console's
// vocabulary or refuses the registration at load. These tests pin the three properties that
// keep that honest:
//
//  1. Agreement with the console's own validateChord. The UI side (plugin-hotkeys.ts) installs
//     what this accepts, so the two spellings must agree: a chord this accepts and that side
//     refuses would leave a registration that loaded and never fires — the worst outcome here.
//  2. Burp's documented leniency: "Hotkeys are defined in the same format as within Burp's
//     Settings", which allows case, separator and order variation.
//  3. The one-modifier rule, so a bare key cannot fire while the operator types.
func TestNormaliseChordSpellsBurpsFormatInTheConsolesVocabulary(t *testing.T) {
	accepted := []struct{ in, want string }{
		{"Ctrl+Shift+K", "mod+shift+k"},
		{"Ctrl+K", "mod+k"},
		{"Alt+T", "alt+t"},
		{"Ctrl+Alt+R", "mod+alt+r"},
		// The documented format's leniency: case, separators, glued modifiers, any order.
		{"ctrl SHIFT k", "mod+shift+k"},
		{"ctrl-shift-k", "mod+shift+k"},
		{"ctrlshiftk", "mod+shift+k"},
		{"Shift+Ctrl+K", "mod+shift+k"},
		{"Cmd+K", "mod+k"},
		{"Option+T", "alt+t"},
		// A modifier named twice is the same modifier: the format is lenient, and a spelling
		// variation that names one binding must not become a refusal.
		{"Ctrl+Ctrl+K", "mod+k"},
	}
	for _, tc := range accepted {
		if got := NormaliseChord(tc.in); got != tc.want {
			t.Errorf("NormaliseChord(%q) = %q, want %q — the console's installer spells this chord differently and the binding would never fire", tc.in, got, tc.want)
		}
	}
}

func TestNormaliseChordRefusesABindingThatWouldNeverFire(t *testing.T) {
	refused := []string{
		"",           // nothing to install
		"K",          // a bare key fires while the operator types
		"Ctrl",       // a modifier alone is not a shortcut
		"Ctrl+Shift", // still no key
		"Meta+K",     // mod is already the platform's primary modifier; meta would never fire
		"Super+K",    // same
		"Windows+K",  // same
		"Ctrl+F5",    // function keys belong to the browser and the OS
		"Ctrl+F12",   // same
		"Ctrl+shift", // the key cannot itself be a modifier
	}
	for _, in := range refused {
		if got := NormaliseChord(in); got != "" {
			t.Errorf("NormaliseChord(%q) = %q, want the empty refusal — this console cannot install it and a silent non-firing binding is worse than none", in, got)
		}
	}
}

// The load-time refusal: a hotkey with no chord, or one this console cannot spell, is refused
// and counted like any other unusable registration — never accepted as an inert row, which in
// the UI is indistinguishable from a working one.
func TestAHotkeyRegistrationWithoutASpellableChordIsRefusedAtLoad(t *testing.T) {
	h := testHost(t, "bad-hotkeys")
	if _, err := h.Load("probe"); err != nil {
		t.Fatalf("Load: %v", err)
	}
	view := h.List().Extensions[0]
	if len(view.Registrations) != 1 || view.RegistrationsRefused != 2 {
		t.Fatalf("registrations = %d accepted, %d refused; want 1 and 2 — the hotkey without a chord and the one asking for meta must both be counted, and the plain menu action must survive",
			len(view.Registrations), view.RegistrationsRefused)
	}
	if view.Registrations[0].ID != "survives" {
		t.Errorf("the accepted registration is %q, want the unrelated menu action", view.Registrations[0].ID)
	}
	console := consoleText(t, h, "probe", StreamError)
	for _, want := range []string{
		`"no-chord" is a hotkey with no chord`,
		`"meta-chord" asks for "Meta+K"`,
	} {
		if !strings.Contains(console, want) {
			t.Errorf("the error console is missing %q; it said:\n%s", want, console)
		}
	}
}
