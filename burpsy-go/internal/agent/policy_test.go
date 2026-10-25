package agent

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestFloorCannotBeRelaxed(t *testing.T) {
	for _, r := range []Risk{RiskScope, RiskAttack, RiskCredential, RiskDestructive, RiskExecute} {
		for _, mode := range []Mode{ModeManual, ModeSmart, ModeAutonomous} {
			p := Policy{Mode: mode, Tools: map[string]ToolSetting{"t": SettingAct}}
			if v := p.Decide("t", r); v.Action != ActionAsk {
				t.Errorf("mode %s risk %s with per-tool Act: got %s, want ask (floor)", mode, r, v.Action)
			}
		}
	}
}

func TestUnknownRiskIsFloor(t *testing.T) {
	p := Policy{Mode: ModeAutonomous, Tools: map[string]ToolSetting{"t": SettingAct}}
	if v := p.Decide("t", Risk("brand-new")); v.Action != ActionAsk {
		t.Fatalf("an unrecognised risk class must ask, got %s", v.Action)
	}
	if v := p.Decide("t", Risk("")); v.Action != ActionAsk {
		t.Fatalf("an empty risk class must ask, got %s", v.Action)
	}
}

func TestModes(t *testing.T) {
	cases := []struct {
		mode Mode
		risk Risk
		want Action
	}{
		{ModeManual, RiskRead, ActionAllow},
		{ModeManual, RiskLocal, ActionAsk},
		{ModeManual, RiskEgress, ActionAsk},
		{ModeSmart, RiskRead, ActionAllow},
		{ModeSmart, RiskLocal, ActionAllow},
		{ModeSmart, RiskEgress, ActionAsk},
		{ModeAutonomous, RiskEgress, ActionAllow},
		{ModeAutonomous, RiskLocal, ActionAllow},
		{ModeAutonomous, RiskAttack, ActionAsk},
		{"", RiskLocal, ActionAllow}, // zero Mode is Smart
		{"", RiskEgress, ActionAsk},
	}
	for _, c := range cases {
		if got := (Policy{Mode: c.mode}).Decide("t", c.risk).Action; got != c.want {
			t.Errorf("mode %q risk %s: got %s want %s", c.mode, c.risk, got, c.want)
		}
	}
}

func TestPerToolOnlyTightensBelowFloorAndActRelaxesAbove(t *testing.T) {
	p := Policy{Mode: ModeSmart, Tools: map[string]ToolSetting{"ask-me": SettingAsk, "act": SettingAct, "off": SettingDisabled}}
	if p.Decide("ask-me", RiskRead).Action != ActionAsk {
		t.Error("per-tool Ask must tighten a read tool")
	}
	if p.Decide("act", RiskEgress).Action != ActionAllow {
		t.Error("per-tool Act (always approve) must relax a non-floor egress tool under Smart")
	}
	if p.Decide("act", RiskEgress).Action == ActionDeny {
		t.Error("unexpected deny")
	}
	if v := p.Decide("off", RiskRead); v.Action != ActionDeny || v.Reason == "" {
		t.Errorf("Disabled must deny with a reason, got %+v", v)
	}
	if v := p.Decide("off", RiskAttack); v.Action != ActionDeny {
		t.Error("Disabled beats the floor: a disabled attack tool is refused, not asked")
	}
	if p.Visible("off") || !p.Visible("act") {
		t.Error("Visible must hide only disabled tools")
	}
}

func TestRelaxingManualWithActIsAllowedAboveFloor(t *testing.T) {
	p := Policy{Mode: ModeManual, Tools: map[string]ToolSetting{"x": SettingAct}}
	if p.Decide("x", RiskLocal).Action != ActionAllow {
		t.Error("Act on a non-floor tool is the always-approve setting and applies in Manual mode")
	}
}

func TestPolicyJSONAndValidate(t *testing.T) {
	var p Policy
	if err := json.Unmarshal([]byte(`{"mode":"manual","tools":{"a":"ask","b":"disabled"}}`), &p); err != nil {
		t.Fatal(err)
	}
	if p.Mode != ModeManual || p.Tools["b"] != SettingDisabled {
		t.Fatalf("decoded %+v", p)
	}
	out, _ := json.Marshal(Policy{})
	if !strings.Contains(string(out), `"mode":"smart"`) || !strings.Contains(string(out), `"tools":{}`) {
		t.Fatalf("zero policy must marshal to explicit smart mode and empty tools, got %s", out)
	}
	for _, bad := range []string{`{"mode":"yolo"}`, `{"tools":{"a":"maybe"}}`, `{"mode":"smart","extra":1}`} {
		var q Policy
		if err := json.Unmarshal([]byte(bad), &q); err == nil {
			t.Errorf("%s must be refused", bad)
		}
	}
}

func TestTightenedBy(t *testing.T) {
	parent := Policy{Mode: ModeManual, Tools: map[string]ToolSetting{"a": SettingDisabled, "b": SettingAsk}}
	child := Policy{Mode: ModeAutonomous, Tools: map[string]ToolSetting{"a": SettingAct, "b": SettingAct, "c": SettingAct}}
	got := child.TightenedBy(parent)
	if got.Mode != ModeManual {
		t.Errorf("mode %s, want manual", got.Mode)
	}
	if got.Tools["a"] != SettingDisabled || got.Tools["b"] != SettingAsk || got.Tools["c"] != SettingAct {
		t.Errorf("tools %+v", got.Tools)
	}
}
