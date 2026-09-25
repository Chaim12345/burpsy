package proxy

import (
	"strings"
	"testing"
)

// Enabling interception makes the proxy offer only http/1.1 upstream, because the hold queue holds
// whole HTTP/1-shaped messages (alpn.go's AlpnOffer). That is a real fidelity cost — an h2-first
// target is silently moved off the protocol the client's browser negotiated — and the only thing
// that made it invisible was that every intercepted row recorded ProtocolHTTP1 unconditionally, so
// a downgraded row and a genuine HTTP/1.1 row were identical (burpsy-react-ui-y0l2).
//
// These tests pin the two halves of the repair: the offer still narrows, and the narrowing is now
// stated on the rows it affected.

func TestTheOfferStillNarrowsUnderInterception(t *testing.T) {
	clientOffer := []string{"h2", "http/1.1"}

	if got := AlpnOffer(clientOffer, true); len(got) != 1 || got[0] != alpnHTTP11 {
		t.Errorf("interception offer = %v, want [%s]: the hold queue is HTTP/1-shaped, so h2 must not be offered", got, alpnHTTP11)
	}
	if got := AlpnOffer(clientOffer, false); len(got) != 2 {
		t.Errorf("passthrough offer = %v, want both: a tunnel the proxy does not read may carry anything the client asked for", got)
	}
}

func TestADowngradedTunnelSaysSoAndAnUnaffectedOneDoesNot(t *testing.T) {
	cases := []struct {
		name    string
		offer   []string
		carried string
		want    string
	}{
		{
			name:    "an h2 client carried over http/1.1 is a downgrade",
			offer:   []string{"h2", "http/1.1"},
			carried: alpnHTTP11,
			want:    "client offered HTTP/2; interception carried this over HTTP/1.1",
		},
		{
			name:    "an http/1.1-only client is not",
			offer:   []string{"http/1.1"},
			carried: alpnHTTP11,
			want:    "",
		},
		{
			name:    "a client that offered nothing is not",
			offer:   nil,
			carried: alpnHTTP11,
			want:    "",
		},
		{
			name:    "a tunnel that actually carried h2 is not a downgrade",
			offer:   []string{"h2", "http/1.1"},
			carried: alpnH2,
			want:    "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := DowngradeNote(tc.offer, tc.carried); got != tc.want {
				t.Errorf("DowngradeNote(%v, %q) = %q, want %q", tc.offer, tc.carried, got, tc.want)
			}
		})
	}
}

// The note must be recognisable to the UI, which matches its opening clause. This pins the two
// halves of one string across a process boundary: internal/web/ui/src/lib/api.ts's
// isProtocolDowngrade tests notes.startsWith("client offered HTTP/2;").
func TestTheDowngradeNoteOpensWithTheClauseTheUIMatches(t *testing.T) {
	note := DowngradeNote([]string{"h2", "http/1.1"}, alpnHTTP11)
	if !strings.HasPrefix(note, "client offered HTTP/2;") {
		t.Errorf("note = %q; the UI detects a downgraded row by this prefix, so changing the wording "+
			"silently hides every badge in history", note)
	}
}

func TestTheDowngradeNoteJoinsRatherThanOverwritesAnExistingNote(t *testing.T) {
	held := "held and edited by the operator"
	got := withDowngradeNote(&held, "client offered HTTP/2; interception carried this over HTTP/1.1")
	if got == nil {
		t.Fatal("the note is nil; the row lost both facts")
	}
	if !strings.Contains(*got, "HTTP/2") || !strings.Contains(*got, held) {
		t.Errorf("note = %q; it must carry the downgrade AND the row's own note", *got)
	}
	if !strings.HasPrefix(*got, "client offered HTTP/2;") {
		t.Errorf("note = %q; the downgrade clause must come first so the UI prefix still matches", *got)
	}
}

func TestNoNoteIsAddedWhenNothingWasDowngraded(t *testing.T) {
	if got := withDowngradeNote(nil, ""); got != nil {
		t.Errorf("withDowngradeNote(nil, \"\") = %q, want nil: an ordinary row must not gain a note", *got)
	}
	existing := "something else"
	got := withDowngradeNote(&existing, "")
	if got == nil || *got != existing {
		t.Errorf("withDowngradeNote(existing, \"\") = %v, want the existing note untouched", got)
	}
}

// A downgraded tunnel whose row the operator also edited carries two facts, and the join is the
// only thing that keeps both. The end-to-end test cannot reach this shape — editing needs a held
// message, which is a separate fixture — so the merge is pinned here against the real helper.
func TestADowngradedAndEditedRowKeepsBothFacts(t *testing.T) {
	edited := "request held and edited by the operator"
	got := withDowngradeNote(&edited, "client offered HTTP/2; interception carried this over HTTP/1.1")
	if got == nil {
		t.Fatal("note is nil; the row lost both the downgrade and the edit")
	}
	if *got != "client offered HTTP/2; interception carried this over HTTP/1.1; "+edited {
		t.Errorf("note = %q; overwriting the row's own note loses the operator's edit, and burying "+
			"the downgrade under it hides the badge the UI keys on", *got)
	}
}
