package intruder

import (
	"errors"
	"strings"
	"testing"
)

// fakeBridge records calls and answers from a table, so a test can see exactly what the
// chain asked the plugin for and control what it answered.
type fakeBridge struct {
	calls []fakeCall
	out   []byte
	skip  bool
	err   error
}

type fakeCall struct {
	plugin, regID string
	payload, base string
}

func (f *fakeBridge) ProcessPayload(plugin, registration string, payload, base []byte) ([]byte, bool, error) {
	f.calls = append(f.calls, fakeCall{plugin, registration, string(payload), string(base)})
	return f.out, f.skip, f.err
}

func TestPluginRuleRewritesThroughTheBridge(t *testing.T) {
	bridge := &fakeBridge{out: []byte("signed")}
	chain, err := NewChainWith([]RuleSpec{
		{Rule: "add_prefix", Text: "pre-"},
		{Rule: "plugin", Plugin: &PluginRuleRef{Plugin: "signer", Registration: "reg-1"}},
	}, bridge)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	res := chain.Apply([]byte("body"))
	if res.Dropped || string(res.Keep) != "signed" {
		t.Fatalf("got %+v", res)
	}
	// The plugin saw the payload AFTER the earlier rule and the ORIGINAL as the base value,
	// the Burp processPayload(payload, baseValue) contract.
	if len(bridge.calls) != 1 || bridge.calls[0].payload != "pre-body" || bridge.calls[0].base != "body" {
		t.Fatalf("bridge calls = %+v", bridge.calls)
	}
	if bridge.calls[0].plugin != "signer" || bridge.calls[0].regID != "reg-1" {
		t.Fatalf("bridge addressed = %+v", bridge.calls[0])
	}
}

func TestPluginRuleSkipAndErrorDropWithReasons(t *testing.T) {
	for _, tc := range []struct {
		name   string
		bridge *fakeBridge
		want   string
	}{
		{"skip", &fakeBridge{skip: true}, "skipped"},
		{"error", &fakeBridge{err: errors.New("boom")}, "boom"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			chain, err := NewChainWith([]RuleSpec{
				{Rule: "plugin", Plugin: &PluginRuleRef{Plugin: "signer", Registration: "reg-1"}},
			}, tc.bridge)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			res := chain.Apply([]byte("body"))
			if !res.Dropped || !strings.Contains(res.Reason, tc.want) || !strings.Contains(res.Reason, "signer") {
				t.Fatalf("got %+v", res)
			}
		})
	}
}

func TestPluginRuleRefusesWithoutBridgeOrAddress(t *testing.T) {
	if _, err := NewChain([]RuleSpec{{Rule: "plugin", Plugin: &PluginRuleRef{Plugin: "signer", Registration: "reg-1"}}}); err == nil {
		t.Fatal("NewChain compiled a plugin rule with no bridge")
	}
	if _, err := NewChainWith([]RuleSpec{{Rule: "plugin"}}, &fakeBridge{}); err == nil {
		t.Fatal("compiled a plugin rule with no address")
	}
	if _, err := NewChainWith([]RuleSpec{{Rule: "plugin", Plugin: &PluginRuleRef{Plugin: "signer"}}}, &fakeBridge{}); err == nil {
		t.Fatal("compiled a plugin rule with no registration")
	}
}

func TestPluginPayloadSourceRefusesDirectResolve(t *testing.T) {
	if _, err := (&PayloadSource{Type: "plugin", Plugin: &PluginSource{Plugin: "gen", Registration: "reg-9"}}).Resolve(10); err == nil ||
		!strings.Contains(err.Error(), "not materialized") {
		t.Fatalf("Resolve = %v", err)
	}
	if _, err := (&PayloadSource{Type: "plugin"}).Resolve(10); err == nil {
		t.Fatal("Resolve answered a plugin source with no address")
	}
}
