package netauth

import "testing"

// ReplaceWith is what a project switch calls (burpsy-react-ui-oava). It must leave the store holding
// exactly the incoming rules and nothing it learned under the outgoing ones, and it must do it in
// place, because the sender and the proxy hold this pointer.
func TestReplaceWithSwapsTheRulesAndForgetsWhatTheOldOnesLearned(t *testing.T) {
	live := NewCredentials()
	live.Add(mustCredential(t, "a.example", SchemeBasic, "alice", testPassword, ""))
	live.SetPromptOnFailure(true)
	live.mu.Lock()
	live.challenges["a.example"] = &digestState{}
	live.ntlm["a.example"] = &ntlmSession{}
	live.recordFailureLocked("a.example", `Basic realm="a"`, "rejected")
	live.mu.Unlock()
	if len(live.Failures()) != 1 {
		t.Fatal("positive control: the failure was not recorded, so the reset below proves nothing")
	}

	incoming := NewCredentials()
	incoming.Add(mustCredential(t, "b.example", SchemeDigest, "bob", "b-pass", "b"))
	live.ReplaceWith(incoming)

	if _, ok := live.Match("a.example"); ok {
		t.Error("the outgoing rule still matches after the replace")
	}
	if rule, ok := live.Match("b.example"); !ok || rule.Username != "bob" {
		t.Errorf("the incoming rule is not live: %+v %v", rule, ok)
	}
	if live.PromptOnFailure() {
		t.Error("the outgoing prompt setting survived; the incoming store never turned it on")
	}
	if n := len(live.Failures()); n != 0 {
		t.Errorf("%d failures recorded under the outgoing rules survived", n)
	}
	live.mu.RLock()
	learned := len(live.challenges) + len(live.ntlm)
	live.mu.RUnlock()
	if learned != 0 {
		t.Errorf("%d cached Digest/NTLM handshake states survived the replace", learned)
	}
	// The source is read, not shared: a later edit to it must not reach the live store.
	incoming.Add(mustCredential(t, "c.example", SchemeBasic, "carol", "c", ""))
	if live.Len() != 1 {
		t.Errorf("the live store aliases the source's slice: %d rules after editing the source", live.Len())
	}

	live.ReplaceWith(nil)
	if live.Len() != 0 {
		t.Errorf("replacing with nil left %d rules", live.Len())
	}
}

func TestClientCertsReplaceWithSwapsTheBindingsInPlace(t *testing.T) {
	live := NewClientCerts()
	live.Add(ClientCert{Host: "a.example", Path: "/a.p12"})
	incoming := NewClientCerts()
	incoming.Add(ClientCert{Host: "b.example", Path: "/b.p12"})

	live.ReplaceWith(incoming)
	views := live.View()
	if len(views) != 1 || views[0].Host != "b.example" {
		t.Fatalf("after the replace the bindings are %+v, want only b.example", views)
	}
	incoming.Add(ClientCert{Host: "c.example"})
	if live.Len() != 1 {
		t.Errorf("the live store aliases the source's slice: %d bindings", live.Len())
	}
	live.ReplaceWith(nil)
	if live.Len() != 0 {
		t.Errorf("replacing with nil left %d bindings", live.Len())
	}
}
