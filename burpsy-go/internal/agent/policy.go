package agent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
)

// Risk is a route's risk class. The values mirror the console's riskClass strings
// (internal/web/route_manifest.go); they are restated here because this package must not import the
// console. A value this package does not know is treated as part of the floor.
type Risk string

const (
	RiskRead        Risk = "read"
	RiskLocal       Risk = "local-write"
	RiskEgress      Risk = "egress"
	RiskAttack      Risk = "attack"
	RiskScope       Risk = "scope"
	RiskCredential  Risk = "credential"
	RiskDestructive Risk = "destructive"
	RiskAsset       Risk = "asset"
	RiskExecute     Risk = "execute"
)

// InFloor reports whether a call of this class always needs a human, whatever the mode or the
// per-tool setting. It is the console's needsConfirmation set plus execute (a script class must be
// in the floor) plus every class this package does not recognise, so a new class fails closed.
func InFloor(r Risk) bool {
	switch r {
	case RiskRead, RiskLocal, RiskEgress, RiskAsset:
		return false
	default:
		return true
	}
}

// Mode is the autonomy mode.
type Mode string

const (
	// ModeManual asks before every call that is not a read.
	ModeManual Mode = "manual"
	// ModeSmart asks for the floor and for egress (traffic to the target); the default.
	ModeSmart Mode = "smart"
	// ModeAutonomous asks only for the floor.
	ModeAutonomous Mode = "autonomous"
)

// ToolSetting is the per-tool override.
type ToolSetting string

const (
	// SettingAsk makes the tool ask even where the mode would not.
	SettingAsk ToolSetting = "ask"
	// SettingAct ("always approve") lets the tool run without asking where the mode would ask, but never
	// below the floor.
	SettingAct ToolSetting = "act"
	// SettingDisabled removes the tool: hidden from listings, refused on call.
	SettingDisabled ToolSetting = "disabled"
)

// Action is what the policy says to do with one call.
type Action string

const (
	ActionAllow Action = "allow"
	ActionAsk   Action = "ask"
	ActionDeny  Action = "deny"
)

// Verdict is Decide's answer. Reason is always set for ask and deny.
type Verdict struct {
	Action Action `json:"action"`
	Reason string `json:"reason,omitempty"`
}

// Policy is the per-project agent policy: an autonomy mode and per-tool Ask/Act/Disabled. It only
// tightens below the floor: no mode and no per-tool setting can make a floor class run unattended.
// The zero value is Smart mode with no overrides.
type Policy struct {
	Mode  Mode                   `json:"mode"`
	Tools map[string]ToolSetting `json:"tools"`
}

func (p Policy) mode() Mode {
	if p.Mode == "" {
		return ModeSmart
	}
	return p.Mode
}

// Visible reports whether a tool should be listed to the agent.
func (p Policy) Visible(tool string) bool { return p.Tools[tool] != SettingDisabled }

// Decide answers for one call of tool, whose route has risk class r.
func (p Policy) Decide(tool string, r Risk) Verdict {
	set := p.Tools[tool]
	if set == SettingDisabled {
		return Verdict{ActionDeny, fmt.Sprintf("tool %s is disabled by the project's agent policy", tool)}
	}
	if InFloor(r) {
		return Verdict{ActionAsk, fmt.Sprintf("%s is %s: a human must approve it in every mode", tool, orUnknown(r))}
	}
	if set == SettingAsk {
		return Verdict{ActionAsk, fmt.Sprintf("tool %s is set to Ask", tool)}
	}
	if set == SettingAct {
		return Verdict{Action: ActionAllow}
	}
	switch p.mode() {
	case ModeManual:
		if r != RiskRead && r != RiskAsset {
			return Verdict{ActionAsk, "Manual mode asks before every call that is not a read"}
		}
	case ModeSmart:
		if r == RiskEgress {
			return Verdict{ActionAsk, "Smart mode asks before traffic is sent to the target"}
		}
	}
	return Verdict{Action: ActionAllow}
}

func orUnknown(r Risk) string {
	if r == "" {
		return "of unknown risk"
	}
	return "risk class " + string(r)
}

func modeRank(m Mode) int {
	switch m {
	case ModeManual:
		return 0
	case ModeAutonomous:
		return 2
	default:
		return 1
	}
}

// TightenedBy returns p constrained by parent: the stricter mode, every tool the parent disabled
// stays disabled, and a parent Ask is not relaxed. A sub-task's policy is built this way, so a child
// can never be looser than the run that spawned it.
func (p Policy) TightenedBy(parent Policy) Policy {
	out := Policy{Mode: p.mode(), Tools: map[string]ToolSetting{}}
	if modeRank(parent.mode()) < modeRank(out.Mode) {
		out.Mode = parent.mode()
	}
	for k, v := range p.Tools {
		out.Tools[k] = v
	}
	for k, v := range parent.Tools {
		cur := out.Tools[k]
		switch {
		case v == SettingDisabled:
			out.Tools[k] = SettingDisabled
		case v == SettingAsk && cur != SettingDisabled:
			out.Tools[k] = SettingAsk
		}
	}
	// An always-approve the parent does not itself hold is dropped: a child may not be more
	// permissive than the run that spawned it, and falls back to the (stricter) mode.
	for k, v := range out.Tools {
		if v == SettingAct && parent.Tools[k] != SettingAct {
			delete(out.Tools, k)
		}
	}
	return out
}

// Validate refuses a mode or setting this package does not define.
func (p Policy) Validate() error {
	switch p.Mode {
	case "", ModeManual, ModeSmart, ModeAutonomous:
	default:
		return fmt.Errorf("agent policy: unknown mode %q (want manual, smart or autonomous)", p.Mode)
	}
	names := make([]string, 0, len(p.Tools))
	for k := range p.Tools {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		switch p.Tools[k] {
		case SettingAsk, SettingAct, SettingDisabled:
		default:
			return fmt.Errorf("agent policy: tool %q has unknown setting %q (want ask, act or disabled)", k, p.Tools[k])
		}
	}
	return nil
}

// MarshalJSON writes the effective policy: an explicit mode and a non-null tools object.
func (p Policy) MarshalJSON() ([]byte, error) {
	tools := p.Tools
	if tools == nil {
		tools = map[string]ToolSetting{}
	}
	return json.Marshal(struct {
		Mode  Mode                   `json:"mode"`
		Tools map[string]ToolSetting `json:"tools"`
	}{p.mode(), tools})
}

// UnmarshalJSON refuses unknown fields and invalid values.
func (p *Policy) UnmarshalJSON(b []byte) error {
	var raw struct {
		Mode  Mode                   `json:"mode"`
		Tools map[string]ToolSetting `json:"tools"`
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&raw); err != nil {
		return fmt.Errorf("agent policy: %w", err)
	}
	q := Policy{Mode: raw.Mode, Tools: raw.Tools}
	if err := q.Validate(); err != nil {
		return err
	}
	*p = q
	return nil
}
