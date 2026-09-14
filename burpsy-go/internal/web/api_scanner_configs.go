// SCAN-03's operator-facing surface: the shipped scan configurations, listed, and an audit that can be
// run under one by name.
//
// scanner.BuiltInConfigs, BuiltInConfig.Apply and BuiltInConfigByName were ported and tested and then
// reachable from nothing — no route, no flag, no way for an operator to pick one. A preset table with
// no selector satisfies "the code exists" and not "operator can load Burp's built-in scan
// configurations", which is what the requirement says.
//
// # Why the listing is generated
//
// Every field in the response comes from scanner.BuiltInConfig.Keys(), which reads the same table
// BuiltInConfig.Apply overlays from. A hand-written list here would be a second copy of what the
// presets change: it would render perfectly while omitting a key added to the engine, and nothing would
// notice. The one thing this file is allowed to know is how to spell an AuditConfig in JSON.
//
// # Why the resolved configuration comes back on the audit
//
// An endpoint that accepts a name and returns the same body either way cannot be distinguished from one
// that ignores the name. The audit response therefore carries the configuration it actually ran under,
// so a caller — and the test — can see the overlay in the reply rather than trusting that it happened.
// An unknown name is a 400 naming the known ones, never a silent fall back to the default: running a
// different configuration than the operator asked for is worse than refusing.
package web

import (
	"encoding/json"
	"net/http"

	"github.com/burpsy-go/burpsy/internal/scanner"
)

// auditConfigView is one AuditConfig as JSON.
//
// MaxRequests is a pointer because OptUint32 distinguishes "uncapped" from "capped at zero", and those
// are opposite instructions — null and 0 keep them apart where a plain number could not. The
// issues_reported gates follow the same rule: null inherits the base switch set, true and false are
// the overlay's explicit answer.
type auditConfigView struct {
	TimeBudgetMs                          int64   `json:"time_budget_ms"`
	MaxRequests                           *uint32 `json:"max_requests"`
	ConsecutiveCheckFailuresToAbandonUnit uint32  `json:"consecutive_check_failures_to_abandon_unit"`
	ConsecutiveUnitFailuresToFailItem     uint32  `json:"consecutive_unit_failures_to_fail_item"`
	PauseSessionAfterFailedItems          uint32  `json:"pause_session_after_failed_items"`
	PauseSessionAtFailedItemPercentage    uint8   `json:"pause_session_at_failed_item_percentage"`
	PassiveChecks                         *bool   `json:"passive_checks"`
	LightActiveChecks                     *bool   `json:"light_active_checks"`
	MediumActiveChecks                    *bool   `json:"medium_active_checks"`
	IntrusiveActiveChecks                 *bool   `json:"intrusive_active_checks"`
	JavaScriptAnalysis                    *bool   `json:"javascript_analysis"`
	StoreQueueItems                       *bool   `json:"store_queue_items"`
	// InsertionKinds is the point class list the run enumerates when the configuration carries an
	// explicit one; null means the engine default (the four core classes).
	InsertionKinds []string `json:"insertion_kinds"`
}

// optBoolPtr maps an OptUint32 bool onto a JSON pointer: unset becomes null.
func optBoolPtr(v scanner.OptUint32) *bool {
	if !v.Set {
		return nil
	}
	b := v.Value != 0
	return &b
}

func newAuditConfigView(cfg scanner.AuditConfig) auditConfigView {
	v := auditConfigView{
		TimeBudgetMs:                          cfg.TimeBudget.Milliseconds(),
		ConsecutiveCheckFailuresToAbandonUnit: cfg.ConsecutiveCheckFailuresToAbandonUnit,
		ConsecutiveUnitFailuresToFailItem:     cfg.ConsecutiveUnitFailuresToFailItem,
		PauseSessionAfterFailedItems:          cfg.PauseSessionAfterFailedItems,
		PauseSessionAtFailedItemPercentage:    cfg.PauseSessionAtFailedItemPercentage,
		PassiveChecks:                         optBoolPtr(cfg.PassiveChecks),
		LightActiveChecks:                     optBoolPtr(cfg.LightActiveChecks),
		MediumActiveChecks:                    optBoolPtr(cfg.MediumActiveChecks),
		IntrusiveActiveChecks:                 optBoolPtr(cfg.IntrusiveActiveChecks),
		JavaScriptAnalysis:                    optBoolPtr(cfg.JavaScriptAnalysis),
		StoreQueueItems:                       optBoolPtr(cfg.StoreQueueItems),
	}
	if cfg.MaxRequests.Set {
		n := cfg.MaxRequests.Value
		v.MaxRequests = &n
	}
	if len(cfg.InsertionKinds) > 0 {
		v.InsertionKinds = cfg.InsertionKinds
	}
	return v
}

// builtInConfigView is one shipped configuration: its name, every key it can carry with whether it sets
// it, and the AuditConfig that results from overlaying it on the server's current default.
//
// Resolved is included because the keys alone do not answer the question an operator is asking. "sets
// maximum_audit_time_minutes to 15" and "this run will stop after 900000 ms" are the same fact, and only
// the second one can be compared against what another configuration would do.
type builtInConfigView struct {
	Name     string                     `json:"name"`
	Keys     []scanner.BuiltInConfigKey `json:"keys"`
	Resolved auditConfigView            `json:"resolved"`
}

// handleScannerConfigs serves GET /api/scanner/configs: the shipped configurations an audit can be run
// under, and the default it runs under when none is named.
func (s *Server) handleScannerConfigs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	base := s.auditBaseConfig()
	configs := make([]builtInConfigView, 0, len(scanner.BuiltInConfigs))
	for _, c := range scanner.BuiltInConfigs {
		configs = append(configs, builtInConfigView{
			Name:     c.Name,
			Keys:     c.Keys(),
			Resolved: newAuditConfigView(c.Apply(base)),
		})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"configs": configs,
		// The default is what an audit with no `config` runs under, so a caller can see what a preset
		// actually changes rather than reading absolute numbers with nothing to compare them to.
		"default": newAuditConfigView(base),
		// Burp ships 29 configurations; six of them set a key this engine implements, and both
		// numbers are reported rather than left to be inferred from the length of the list, because
		// "6 configurations" reads as Burp having six. The reason names what is honoured instead of
		// implying the rest does nothing: every key Burp's own 29 shipped configurations set has a
		// row in the engine's table, so a key it cannot apply is reported by name with its reason.
		"shipped_by_burp":   scanner.BurpShippedConfigCount,
		"implemented_here":  len(scanner.BuiltInConfigs),
		"omitted_reason":    "those configurations mostly set crawl tuning, per-issue selection and JavaScript-analysis keys, which this engine has no equivalent of; every key they set is listed with applies=false and a reason, and honouring key counts are pinned by internal/scanner's own tests",
		"how_to_run_under":  "POST /api/audit/{exchange_id} or /api/scanner/audit with {\"config\": \"<name>\"}",
		"applies_to_server": "the CLI flag -scan-config sets the default above for every audit this server runs",
	})
}

// auditBaseConfig is the configuration an audit runs under when no preset is named — the scanner's own,
// which honours a -scan-config default set at startup.
func (s *Server) auditBaseConfig() scanner.AuditConfig {
	if s.scanner == nil {
		return scanner.DefaultAuditConfig()
	}
	return s.scanner.AuditConfig()
}

// resolveAuditConfig turns an optional preset name into the configuration to audit under, plus the
// preset's own name for the reply.
//
// An empty name is the default and is not an error. An unknown name is an error carrying the known
// names: silently auditing under the default would run a configuration the operator did not ask for and
// report success, which is the same class of lie as a skipped check reporting as a pass.
//
// The returned report names every key the preset sets that this engine could not apply — the
// not-silent half of honouring a shipped configuration. The caller echoes it beside the resolved
// configuration.
func (s *Server) resolveAuditConfig(name string) (scanner.AuditConfig, string, []string, error) {
	base := s.auditBaseConfig()
	if name == "" {
		return base, "", nil, nil
	}
	preset, ok := scanner.BuiltInConfigByName(name)
	if !ok {
		return base, "", nil, &unknownConfigError{Name: name, Known: scanner.BuiltInConfigNames()}
	}
	applied, unapplied := preset.ApplyWithReport(base)
	return applied, preset.Name, unapplied, nil
}

// unknownConfigError names the configuration that was asked for and every one that exists, because
// these names contain spaces and hyphens and a typo is the likely cause.
type unknownConfigError struct {
	Name  string
	Known []string
}

func (e *unknownConfigError) Error() string {
	msg := "no built-in scan configuration is named " + e.Name + "; the available ones are:"
	for _, k := range e.Known {
		msg += "\n  " + k
	}
	return msg
}
