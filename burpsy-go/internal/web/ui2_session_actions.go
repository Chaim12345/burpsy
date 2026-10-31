package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/burpsy-go/burpsy/internal/session"
)

// Only fields this bounded editor understands may be authored. An action with any
// other stored field is label-only, even when its kind is otherwise supported.
func ui2SessionActionEditable(a *session.Action) bool {
	if a == nil || !ui2SessionRulePageKind(a.Kind) {
		return false
	}
	allowed := map[string]bool{"kind": true, "enabled": true, "stop": true}
	switch a.Kind {
	case session.ActionSetCookie, session.ActionSetHeader:
		allowed["name"], allowed["value"] = true, true
	case session.ActionSetParam:
		allowed["name"], allowed["value"], allowed["in"] = true, true, true
	case session.ActionReplace:
		allowed["match"], allowed["replacement"], allowed["regex"] = true, true, true
	case session.ActionRunScript:
		allowed["script"] = true
	}
	b, _ := json.Marshal(a)
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(b, &fields)
	for k := range fields {
		if !allowed[k] {
			return false
		}
	}
	return true
}

func ui2SessionActionRows(rule *session.SessionRule) []map[string]any {
	rows := make([]map[string]any, 0, len(rule.Actions))
	for i, a := range rule.Actions {
		row := map[string]any{"index": i, "position": i + 1, "up": i > 0, "down": i+1 < len(rule.Actions), "removable": len(rule.Actions) > 1, "editable": ui2SessionActionEditable(a)}
		if a != nil {
			row["label"], row["kind"], row["name"], row["in"], row["regex"] = session.ActionKindLabel(a.Kind), session.ActionKindName(a.Kind), a.Name, a.In, a.Regex
			row["enabled"], row["stop"] = a.Enabled, a.Stop
		} else {
			row["label"] = "Missing action (console repair required)"
		}
		rows = append(rows, row)
	}
	return rows
}

func ui2SessionSecretEdit(r *http.Request, field, old string, clear bool) (string, error) {
	mode := r.PostFormValue(field + "_mode")
	value := r.PostFormValue(field)
	switch mode {
	case "keep":
		if value != "" {
			return "", fmt.Errorf("%s: choose replace before entering a new value", field)
		}
		return old, nil
	case "replace":
		if value == redactedValue || strings.Contains(value, redactedValue) {
			return "", fmt.Errorf("%s: the redaction marker is not a replacement value", field)
		}
		if value == "" {
			return "", fmt.Errorf("%s: use clear for an empty value", field)
		}
		return value, nil
	case "clear":
		if !clear {
			return "", fmt.Errorf("%s cannot be cleared", field)
		}
		if value != "" {
			return "", fmt.Errorf("%s: clear must not carry a replacement", field)
		}
		return "", nil
	default:
		return "", fmt.Errorf("%s: choose keep, replace or an allowed clear", field)
	}
}

func ui2SessionMutateActions(rule *session.SessionRule, r *http.Request) (string, error) {
	op := r.PostFormValue("rule_op")
	if op == "action_append" {
		for k := range r.PostForm {
			if strings.HasSuffix(k, "_mode") || k == "action_enabled" || k == "action_stop" {
				return "", fmt.Errorf("%s is not available for a new action", k)
			}
		}
		kind, err := session.ParseActionKind(r.PostFormValue("action"))
		if err != nil || !ui2SessionRulePageKind(kind) {
			return "", fmt.Errorf("choose one of the seven page action kinds")
		}
		fields, err := ui2SessionRulePageAction(kind, r)
		if err != nil {
			return "", err
		}
		for _, v := range fields {
			if text, ok := v.(string); ok && strings.Contains(text, redactedValue) {
				return "", fmt.Errorf("the redaction marker is not an action value")
			}
		}
		b, _ := json.Marshal(fields)
		var dto sessionActionDto
		_ = json.Unmarshal(b, &dto)
		a, err := actionsToModel([]sessionActionDto{dto})
		if err != nil {
			return "", err
		}
		rule.Actions = append(rule.Actions, a[0])
		return "Append " + session.ActionKindLabel(kind) + " as the last action (enabled, stop off)", nil
	}
	i, err := strconv.Atoi(r.PostFormValue("action_index"))
	if err != nil || i < 0 || i >= len(rule.Actions) {
		return "", fmt.Errorf("that action position no longer exists")
	}
	a := rule.Actions[i]
	label := "missing action"
	if a != nil {
		label = session.ActionKindLabel(a.Kind)
	}
	note := fmt.Sprintf("Action %d (%s): ", i+1, label)
	switch op {
	case "action_enable", "action_disable", "action_stop_on", "action_stop_off":
		if !ui2SessionActionEditable(a) {
			return "", fmt.Errorf("this action is label-only: edit its switches in the console")
		}
		allowed := map[string]bool{"rule_op": true, "rule_id": true, "form_base": true, "action_index": true}
		for k, values := range r.PostForm {
			if !allowed[k] || len(values) != 1 {
				return "", fmt.Errorf("%s is not a single permitted switch field", k)
			}
		}
		target := op == "action_enable" || op == "action_stop_on"
		current := a.Enabled
		field := "enabled"
		if op == "action_stop_on" || op == "action_stop_off" {
			current = a.Stop
			field = "stop"
		}
		if current == target {
			return "", fmt.Errorf("action %d %s is already %t - nothing to review", i+1, field, current)
		}
		if op == "action_enable" || op == "action_disable" {
			a.Enabled = target
		} else {
			a.Stop = target
		}
		effect := fmt.Sprintf("%schange only %s from %t to %t. ", note, field, current, target)
		if op == "action_enable" || op == "action_disable" {
			if target {
				effect += "If execution reaches this action, it will run: " + ui2SessionActionEffects(map[string]any{"actions": []any{map[string]any{"kind": session.ActionKindName(a.Kind), "name": a.Name, "label": label}}}) + ". "
			} else {
				effect += "This action will be skipped. "
			}
		}
		if a.Stop || ((op == "action_stop_on" || op == "action_stop_off") && !target) {
			if !a.Enabled {
				effect += "Its stop flag is inert while this action is disabled. "
			} else if a.Stop {
				effect += "If execution reaches this enabled action, its stop flag prevents later actions after it runs, even if it changes nothing. Earlier stops, prompt decline or script outcomes can prevent reaching it. "
			} else {
				effect += "This action no longer stops later actions itself; earlier stops or action outcomes can still prevent them from running. "
			}
		} else if (op == "action_enable" || op == "action_disable") && !target && current {
			effect += "Later actions may still run if execution reaches them. "
		}
		if (op == "action_enable" || op == "action_disable") && !target && a.Stop {
			effect += "Disabling it removes its own stop barrier; later actions may become reachable, but are not guaranteed to run. "
		}
		if i == len(rule.Actions)-1 {
			effect += "There are no later actions today; this stored stop setting also applies to actions appended later. "
		}
		enabledCount := 0
		for _, item := range rule.Actions {
			if item != nil && item.Enabled {
				enabledCount++
			}
		}
		if enabledCount == 0 {
			effect += "The rule will run no actions: every action is disabled. "
		}
		return effect, nil
	case "action_up":
		if i == 0 {
			return "", fmt.Errorf("the first action cannot move up")
		}
		rule.Actions[i-1], rule.Actions[i] = rule.Actions[i], rule.Actions[i-1]
		return note + "move up one position; execution order changes", nil
	case "action_down":
		if i+1 == len(rule.Actions) {
			return "", fmt.Errorf("the last action cannot move down")
		}
		rule.Actions[i+1], rule.Actions[i] = rule.Actions[i], rule.Actions[i+1]
		return note + "move down one position; execution order changes", nil
	case "action_remove":
		if len(rule.Actions) <= 1 {
			return "", fmt.Errorf("cannot remove the last action: the engine would materialize its default flow")
		}
		rule.Actions = append(rule.Actions[:i], rule.Actions[i+1:]...)
		return note + "remove the whole action, including any conditional branches; it will no longer run", nil
	case "action_edit":
		if !ui2SessionActionEditable(a) {
			return "", fmt.Errorf("this action is label-only: edit its fields in the console")
		}
		allowed := map[string]bool{}
		switch a.Kind {
		case session.ActionSetCookie, session.ActionSetHeader:
			for _, k := range []string{"action_name", "action_value", "action_value_mode"} {
				allowed[k] = true
			}
		case session.ActionSetParam:
			for _, k := range []string{"action_name", "action_value", "action_value_mode", "action_in"} {
				allowed[k] = true
			}
		case session.ActionReplace:
			for _, k := range []string{"action_match", "action_match_mode", "action_replacement", "action_replacement_mode", "action_regex"} {
				allowed[k] = true
			}
		case session.ActionRunScript:
			allowed["action_script"], allowed["action_script_mode"] = true, true
		}
		for k := range r.PostForm {
			if strings.HasPrefix(k, "action_") && k != "action_index" && !allowed[k] {
				return "", fmt.Errorf("%s does not belong to this action editor", k)
			}
		}
		var err error
		switch a.Kind {
		case session.ActionSetCookie, session.ActionSetHeader, session.ActionSetParam:
			a.Name = strings.TrimSpace(r.PostFormValue("action_name"))
			a.Value, err = ui2SessionSecretEdit(r, "action_value", a.Value, true)
			if a.Kind == session.ActionSetParam {
				a.In = r.PostFormValue("action_in")
			}
		case session.ActionReplace:
			a.Match, err = ui2SessionSecretEdit(r, "action_match", a.Match, false)
			if err == nil {
				a.Replacement, err = ui2SessionSecretEdit(r, "action_replacement", a.Replacement, true)
			}
			a.Regex = r.PostFormValue("action_regex") == "1"
		case session.ActionRunScript:
			a.Script, err = ui2SessionSecretEdit(r, "action_script", a.Script, false)
		default:
			return "", fmt.Errorf("this fieldless action has no editable fields")
		}
		if err != nil {
			return "", err
		}
		return note + "edit supported fields; enabled and stop remain unchanged", nil
	}
	return "", fmt.Errorf("unknown action operation")
}
