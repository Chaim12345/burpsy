package web

import (
	"testing"

	"github.com/burpsy-go/burpsy/internal/oob"
)

// The collapsed flag folds one lookup's resolver fan-out into a single event, but only within one
// payload: the same resolver calling back for two different payloads is two events (vfqy).
func TestCollaboratorCollapseIsScopedToThePayload(t *testing.T) {
	minted := []mintedPayload{
		{Address: "bsyaaa.oast.example", Marker: "bsyaaa"},
		{Address: "bsybbb.oast.example", Marker: "bsybbb"},
	}
	lookup := func(name string) oob.Interaction {
		return oob.Interaction{Protocol: "dns", QType: "A", RemoteAddress: "198.51.100.7", RawRequest: "query " + name}
	}
	all := []oob.Interaction{
		lookup("bsyaaa.oast.example"),
		lookup("BSYaaa.oast.example"), // the same payload again, DNS-0x20 cased: a repeat
		lookup("bsybbb.oast.example"), // a different payload, identical on (protocol, qtype, client)
		lookup("bsybbb.oast.example"), // a repeat of that one
		lookup("unrelated.example"),   // attributed to no payload
		lookup("other.example"),       // nor this: unattributed rows still collapse among themselves
	}

	rows := collaboratorRows(all, minted)
	want := []struct {
		payload   string
		collapsed bool
	}{
		{"bsyaaa.oast.example", false},
		{"bsyaaa.oast.example", true},
		{"bsybbb.oast.example", false},
		{"bsybbb.oast.example", true},
		{"", false},
		{"", true},
	}
	if len(rows) != len(want) {
		t.Fatalf("got %d rows, want %d", len(rows), len(want))
	}
	for i, w := range want {
		if rows[i].ID != i || rows[i].Payload != w.payload || rows[i].Collapsed != w.collapsed {
			t.Errorf("row %d = {id %d, payload %q, collapsed %v}, want {id %d, payload %q, collapsed %v}",
				i, rows[i].ID, rows[i].Payload, rows[i].Collapsed, i, w.payload, w.collapsed)
		}
	}

	counts := countsOf(all, minted)
	if counts.Total != 6 || counts.Distinct != 3 {
		t.Errorf("counts = total %d distinct %d, want total 6 distinct 3", counts.Total, counts.Distinct)
	}
}
