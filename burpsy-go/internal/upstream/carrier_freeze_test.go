package upstream

import "testing"

// Freeze and Identity back the sender's dial identity (burpsy-react-ui-o388-predial-vs-dial):
// every edit that changes what the carrier does to some connection must change the identity, an
// identical rewrite must not, and a frozen copy must not see later edits.
func TestCarrierIdentityMovesWithEveryBehaviouralEdit(t *testing.T) {
	c := NewCarrier()
	if got := c.Identity(); got != "" {
		t.Fatalf("an unconfigured carrier's identity = %q, want empty (same as no carrier)", got)
	}
	if got := (*Carrier)(nil).Identity(); got != "" {
		t.Fatalf("a nil carrier's identity = %q, want empty", got)
	}
	set := func(raw string, bypass []string, remote bool) string {
		t.Helper()
		if err := c.SetSocks(raw, bypass, remote); err != nil {
			t.Fatal(err)
		}
		return c.Identity()
	}
	seen := map[string]string{}
	for name, id := range map[string]string{
		"hop":         set("socks5://127.0.0.1:1080", nil, false),
		"other hop":   set("socks5://127.0.0.1:1081", nil, false),
		"credentials": set("socks5://u:p@127.0.0.1:1081", nil, false),
		"password":    set("socks5://u:q@127.0.0.1:1081", nil, false),
		"remote dns":  set("socks5://u:q@127.0.0.1:1081", nil, true),
		"bypass":      set("socks5://u:q@127.0.0.1:1081", []string{"a.test"}, true),
		"bypass 2":    set("socks5://u:q@127.0.0.1:1081", []string{"a.test", "b.test"}, true),
	} {
		if id == "" {
			t.Errorf("%s: a configured carrier has the empty identity", name)
		}
		if prev, dup := seen[id]; dup {
			t.Errorf("%s and %s share one identity: an edit between them would retire nothing", name, prev)
		}
		seen[id] = name
	}
	before := c.Identity()
	if after := set("socks5://u:q@127.0.0.1:1081", []string{"a.test", "b.test"}, true); after != before {
		t.Error("an identical rewrite changed the identity: every save would cost every pooled connection")
	}
}

func TestAFrozenCarrierDoesNotSeeLaterEdits(t *testing.T) {
	c := NewCarrier()
	if err := c.SetSocks("socks5://127.0.0.1:1080", []string{"a.test"}, true); err != nil {
		t.Fatal(err)
	}
	frozen, id := c.Freeze()
	if id != c.Identity() {
		t.Fatal("Freeze's identity disagrees with the holder's at the same instant")
	}
	if err := c.SetSocks("", nil, false); err != nil {
		t.Fatal(err)
	}
	if proxy, bypass, remote, ok := frozen.Configured(); !ok || proxy == "" || len(bypass) != 1 || !remote {
		t.Errorf("the frozen copy moved with the holder: %q %v %v %v", proxy, bypass, remote, ok)
	}
	if frozen.Identity() != id {
		t.Error("the frozen copy's identity moved after a holder edit")
	}
	if f, id := (*Carrier)(nil).Freeze(); f != nil || id != "" {
		t.Error("a nil carrier must freeze to nil and the empty identity")
	}
}
