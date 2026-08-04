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
// are opposite instructions — null and 0 keep them apart where a plain number could not.
type auditConfigView struct {
	TimeBudgetMs                          int64   `json:"time_budget_ms"`
	MaxRequests                           *uint32 `json:"max_requests"`
	ConsecutiveCheckFailuresToAbandonUnit uint32  `json:"consecutive_check_failures_to_abandon_unit"`
	ConsecutiveUnitFailuresToFailItem     uint32  `json:"consecutive_unit_failures_to_fail_item"`
	PauseSessionAfterFailedItems          uint32  `json:"pause_session_after_failed_items"`
	PauseSessionAtFailedItemPercentage    uint8   `json:"pause_session_at_failed_item_percentage"`
}

func newAuditConfigView(cfg scanner.AuditConfig) auditConfigView {
	v := auditConfigView{
		TimeBudgetMs:                          cfg.TimeBudget.Milliseconds(),
		ConsecutiveCheckFailuresToAbandonUnit: cfg.ConsecutiveCheckFailuresToAbandonUnit,
		ConsecutiveUnitFailuresToFailItem:     cfg.ConsecutiveUnitFailuresToFailItem,
		PauseSessionAfterFailedItems:          cfg.PauseSessionAfterFailedItems,
		PauseSessionAtFailedItemPercentage:    cfg.PauseSessionAtFailedItemPercentage,
	}
	if cfg.MaxRequests.Set {
		n := cfg.MaxRequests.Value
		v.MaxRequests = &n
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
		// Burp ships 29; six of them set a key this engine implements. Reported rather than left to be
		// inferred from the length of the list, because "6 configurations" reads as Burp having six.
		"shipped_by_burp":   scanner.BurpShippedConfigCount,
		"implemented_here":  len(scanner.BuiltInConfigs),
		"omitted_reason":    "the other configurations set only crawl, insertion-point, parameter-relocation and JavaScript-analysis keys, which this engine does not have; they are omitted rather than offered as knobs that would do nothing",
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
func (s *Server) resolveAuditConfig(name string) (scanner.AuditConfig, string, error) {
	base := s.auditBaseConfig()
	if name == "" {
		return base, "", nil
	}
	preset, ok := scanner.BuiltInConfigByName(name)
	if !ok {
		return base, "", &unknownConfigError{Name: name, Known: scanner.BuiltInConfigNames()}
	}
	return preset.Apply(base), preset.Name, nil
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
