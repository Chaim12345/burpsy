package scanner

import (
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

// burpsy-react-ui-87fq: the queue row carries a URL-level verdict. A reached-and-ran item is
// AUDITABLE; one whose probes only failed below HTTP is NETWORK_ERROR; a budget-refused item has no
// URL verdict (its State says why).
func TestAuditItemURLDisposition(t *testing.T) {
	cases := []struct {
		name string
		out  AuditOutcome
		want string
	}{
		{"ran", AuditOutcome{State: ItemStateAudited, Ran: 3}, "AUDITABLE"},
		{"ran even with some send failures", AuditOutcome{State: ItemStateAudited, Ran: 1, SendFailures: 2}, "AUDITABLE"},
		{"only send failures", AuditOutcome{State: ItemStateAudited, SendFailures: 4}, "NETWORK_ERROR"},
		{"refused before dispatch", AuditOutcome{State: ItemStateBounded}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			l := NewAuditItemLedger(16)
			id := core.ExchangeID(1)
			l.Enqueue(id, 3)
			l.Resolve(id, &core.Exchange{Host: "h", Path: "/p"}, c.out, AuditConfig{}, "")
			rows := l.Items(10)
			if len(rows) != 1 {
				t.Fatalf("rows = %d", len(rows))
			}
			if rows[0].URLDisposition != c.want {
				t.Errorf("URLDisposition = %q, want %q", rows[0].URLDisposition, c.want)
			}
		})
	}
}
