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
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/burpsy-go/burpsy/internal/scanner"
	"go.uber.org/zap"
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
	// MaxInsertionPointsPerRequest is Burp's max_insertion_points_per_base_request: how many
	// insertion points one base request may yield before the rest are dropped and reported. A
	// pointer for the same reason MaxRequests is one — null inherits Burp's shipped default of 30,
	// and zero is refused rather than meaningful, so a plain number could not tell "the operator did
	// not set this" from a value they chose.
	MaxInsertionPointsPerRequest *uint32 `json:"max_insertion_points_per_request"`
	// NestedInsertionPoints is Burp's use_nested_insertion_points: null inherits the default (on),
	// false stops the enumerator expanding JSON/base64/XML inside a parameter value.
	NestedInsertionPoints *bool `json:"nested_insertion_points"`
	// AutoBackoffMs is the per-step delay after the target answers a probe 429/503
	// (fkl8): null inherits the engine default (2s), 0 disables the backoff (a real
	// choice — an operator who knows the limiter's cadence may prefer the request
	// budget eat the 429s), a positive number is the wait in milliseconds.
	AutoBackoffMs *uint32 `json:"auto_backoff_ms"`
	// SkipAllTestsForParameters is Burp's scanner.ignored_insertion_points
	// skip_all_tests_for_parameters: parameter names an operator exempted from testing
	// entirely (v9cg). Absent/null means no exemptions; an empty array is accepted as "the
	// operator cleared the list" — unlike the numeric keys there is no zero-value ambiguity,
	// because absent and empty mean the same thing for a list.
	SkipAllTestsForParameters []string `json:"skip_all_tests_for_parameters"`
	// SkipServerSideInjectionForParameters is Burp's skip_server_side_injection_for_parameters
	// (burpsy-react-ui-gmdk): parameter names the server-side injection checks do not probe while
	// every other check still does. Written like the skip-all list — absent leaves it alone, [] clears
	// it — and always read back as an array, [] when empty.
	SkipServerSideInjectionForParameters []string `json:"skip_server_side_injection_for_parameters"`
	// The deny half of Burp's per-issue selection and what it could not act on (saq3.1, 2hze).
	// An imported configuration fills them, and since burpsy-react-ui-saq3.3.1 the first two are
	// also written through the library's settings block (see applyTo); the declines are a derived
	// report and never accepted as input. Each is always an array, [] when empty, so a console never
	// reads an absent list as "nothing removed".
	DisabledIssueTypes       []uint32                       `json:"disabled_issue_types"`
	DisabledDetectionMethods []scanner.IssueDetectionMethod `json:"disabled_detection_methods"`
	DeclinedDetectionMethods scanner.MethodDeclines         `json:"declined_detection_methods"`
	// LightAuditKinds is the DERIVED per-kind set the light-audit tier is gated on
	// (burpsy-react-ui-02qi). Reported rather than set: the eight quick_scan_* keys are the operator's
	// control, and this is what they resolved to, so a console can show "your light audit covers
	// everything except body parameters" without re-deriving it from eight booleans.
	//
	// A deny list, because that is the polarity those keys have. An empty list means every kind is in
	// the light pass, which is the behaviour before the keys existed — NOT "no kind is", which is
	// what an allow-list reading would say.
	LightAuditKindsExcluded []string `json:"light_audit_kinds_excluded,omitempty"`
	// IssueTypes is Burp's per-issue selection (scanner/issues_reported/selected_issues): the
	// catalogue type indexes a run dispatches, and an EMPTY list means no restriction. Absent and
	// empty mean the same thing here, as they do for the skip list -- a list has no zero-value
	// ambiguity, so there is nothing to tell apart.
	IssueTypes []uint32 `json:"issue_types"`
	// FollowUpPasses is Burp's number_of_follow_up_passes: how many extra passes a failed item is
	// re-dispatched. Null inherits the shipped default of 1, and 0 is a real choice -- an operator
	// who would rather account a failed item's coverage as lost than retry against a target that is
	// refusing -- so it is a pointer for the same reason MaxRequests is one.
	FollowUpPasses *uint32 `json:"number_of_follow_up_passes"`
	// PerHostThrottleMs is Burp's resource-pool throttle_interval_millis: the minimum
	// interval between probes to the same host. Null means no per-host throttle.
	PerHostThrottleMs *uint32 `json:"per_host_throttle_ms"`
	// PerHostThrottleRandom enables Burp's throttle_random_enabled: jitter the per-host
	// interval by up to 50% so a fixed cadence is not fingerprintable.
	//
	// Always written on the read side (true or false, never null) and a pointer only for the write
	// side (burpsy-react-ui-saq3.3.1): as a plain bool, a settings block that did not mention it
	// decoded to false and applyTo stored that, so the first partial save — one that only edited the
	// issue selection — silently switched a saved configuration's jitter off.
	PerHostThrottleRandom *bool `json:"per_host_throttle_random"`
	// PerHostMaxInFlight is Burp's resource-pool concurrent_request_limit: the ceiling on
	// probes in flight to ONE host at a time. Null means no per-host cap.
	PerHostMaxInFlight *uint32 `json:"per_host_max_in_flight"`
	// The per-run project-option overrides (burpsy-react-ui-o2p3), reported as the run carries them.
	// Null is "not overridden" — the engagement's own setting applies — which is a different answer
	// from false or 0, so each is a pointer. Timeouts are whole seconds, as Burp writes them.
	FollowRedirections *bool   `json:"follow_redirections"`
	ConnectTimeoutS    *uint32 `json:"connect_timeout_s"`
	NormalTimeoutS     *uint32 `json:"normal_timeout_s"`
	// The javascript_analysis keys (burpsy-react-ui-9mti). Null is unset: both techniques on, no
	// per-item limit. The limits are whole seconds, 0 meaning no limit.
	JavaScriptStaticAnalysis  *bool   `json:"javascript_static_analysis"`
	JavaScriptDynamicAnalysis *bool   `json:"javascript_dynamic_analysis"`
	MaxStaticTimePerItemS     *uint32 `json:"max_static_time_per_item_s"`
	MaxDynamicTimePerItemS    *uint32 `json:"max_dynamic_time_per_item_s"`
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
	if cfg.MaxInsertionPointsPerRequest.Set {
		n := cfg.MaxInsertionPointsPerRequest.Value
		v.MaxInsertionPointsPerRequest = &n
	}
	v.NestedInsertionPoints = optBoolPtr(cfg.NestedInsertionPoints)
	if cfg.AutoBackoffMs.Set {
		n := cfg.AutoBackoffMs.Value
		v.AutoBackoffMs = &n
	}
	// The skip list is carried, not defaulted: an absent field reads back absent, and a list
	// the operator set reads back in the order they set it (the enumerator's matching is
	// case-insensitive, so round-tripping preserves spelling rather than normalising it away).
	if len(cfg.SkipAllTestsForParameters) > 0 {
		v.SkipAllTestsForParameters = cfg.SkipAllTestsForParameters
	}
	if len(cfg.IssueTypes) > 0 {
		v.IssueTypes = cfg.IssueTypes
	}
	v.SkipServerSideInjectionForParameters = append([]string{}, cfg.SkipServerSideInjectionForParameters...)
	v.DisabledIssueTypes = append([]uint32{}, cfg.DisabledIssueTypes...)
	v.DisabledDetectionMethods = append([]scanner.IssueDetectionMethod{}, cfg.DisabledDetectionMethods...)
	v.DeclinedDetectionMethods = append(scanner.MethodDeclines{}, cfg.DeclinedDetectionMethods...)
	if excluded := cfg.LightAuditKinds.ExcludedKinds(); len(excluded) > 0 {
		v.LightAuditKindsExcluded = excluded
	}
	if cfg.FollowUpPasses.Set {
		n := cfg.FollowUpPasses.Value
		v.FollowUpPasses = &n
	}
	if cfg.PerHostThrottleMs.Set {
		n := cfg.PerHostThrottleMs.Value
		v.PerHostThrottleMs = &n
	}
	jitter := cfg.PerHostThrottleRandom
	v.PerHostThrottleRandom = &jitter
	if cfg.PerHostMaxInFlight.Set {
		n := cfg.PerHostMaxInFlight.Value
		v.PerHostMaxInFlight = &n
	}
	v.FollowRedirections = optBoolPtr(cfg.FollowRedirects)
	if cfg.ConnectTimeout.Set {
		n := cfg.ConnectTimeout.Value
		v.ConnectTimeoutS = &n
	}
	if cfg.NormalTimeout.Set {
		n := cfg.NormalTimeout.Value
		v.NormalTimeoutS = &n
	}
	v.JavaScriptStaticAnalysis = optBoolPtr(cfg.JavaScriptStaticAnalysis)
	v.JavaScriptDynamicAnalysis = optBoolPtr(cfg.JavaScriptDynamicAnalysis)
	if cfg.MaxStaticTimePerItem.Set {
		n := cfg.MaxStaticTimePerItem.Value
		v.MaxStaticTimePerItemS = &n
	}
	if cfg.MaxDynamicTimePerItem.Set {
		n := cfg.MaxDynamicTimePerItem.Value
		v.MaxDynamicTimePerItemS = &n
	}
	return v
}

// applyTo overlays the fields this view SETS onto cfg, leaving every null alone.
//
// Partial by design. The write endpoint takes a settings block on top of a base — the server's
// current configuration, or whatever `from` resolved to — so an operator changing one ceiling does
// not have to restate a whole configuration, and cannot silently reset the rest of it to this
// struct's zero values by omitting them. Decoding the body straight into a scanner.AuditConfig
// would have done exactly that: a save that sent only a ceiling would have stored a configuration
// with a zero time budget and every breaker disabled, under the operator's name.
//
// Writable here: the two misc_insertion_point_options keys, the operator's parameter skip list (v9cg)
// and its server-side-injection sibling (gmdk), the per-issue allow list and its deny half — disabled
// types and per-type disabled detection methods (saq3.3.1) — among the fields applyTo reads below.
// The rest of the view is still read-only.
func (v auditConfigView) applyTo(cfg scanner.AuditConfig) (scanner.AuditConfig, error) {
	if v.MaxInsertionPointsPerRequest != nil {
		n := *v.MaxInsertionPointsPerRequest
		// Zero enumerates nothing, so the run would probe nothing and still report a completed
		// audit. Refused by name rather than clamped, matching ParseBurpConfig's own refusal — an
		// impossible setting must not become a different, possible one the operator did not choose.
		if n == 0 {
			return cfg, errors.New("max_insertion_points_per_request must be at least 1: a ceiling of zero " +
				"enumerates no insertion points, so an audit under it would probe nothing and still report as complete")
		}
		cfg.MaxInsertionPointsPerRequest = scanner.SomeUint32(n)
	}
	if v.NestedInsertionPoints != nil {
		cfg.NestedInsertionPoints = scanner.SomeUint32(b2u32(*v.NestedInsertionPoints))
	}
	if v.AutoBackoffMs != nil {
		cfg.AutoBackoffMs = scanner.SomeUint32(*v.AutoBackoffMs)
	}
	// The skip list overlays when the request carried the field at all. Decoding the body
	// into the view leaves the field nil when the key was absent and a non-nil slice when it
	// was present — even as [] — so clearing the list ("skip nothing") is expressible as
	// an explicit empty array and distinguishable from not touching it. Each name is
	// trimmed; an empty name is refused rather than dropped, because a name that silently
	// vanishes from the list is a parameter that silently goes back to being tested.
	// An explicitly empty list means the operator cleared the selection, and absent means the field
	// was not sent -- the two are told apart by nil rather than by length, which is why this is a
	// pointer-to-slice shape rather than a plain one. "No selection" and "nothing selected" are
	// different requests and a run must not be told they are the same.
	if v.IssueTypes != nil {
		// Zero is refused: type index 0 is not a catalogue entry, and a selection containing it
		// matches nothing -- a list that reads as a restriction and admits no check at all is an
		// operator auditing nothing while believing they scoped the run.
		for _, t := range v.IssueTypes {
			if t == 0 {
				return cfg, errors.New("issue_types: 0 is not a catalogue issue type, so a selection " +
					"containing it would match no check at all — the run would audit nothing while the " +
					"configuration read as a restriction")
			}
			// Any other index outside the catalogue is refused for the same reason (saq3.3.1): an
			// import drops such an entry into the declines and never into this list, so a write must
			// not be able to put one here either.
			if _, ok := scanner.ByTypeIndex(t); !ok {
				return cfg, fmt.Errorf("issue_types: 0x%08x is not an issue type in the catalogue, so selecting it "+
					"would select no check", t)
			}
		}
		cfg.IssueTypes = append([]uint32(nil), v.IssueTypes...)
	}
	// The deny half (burpsy-react-ui-saq3.3.1), written like the allow list: nil leaves the base
	// alone, [] clears it. Validated against the same two tables the import resolves against — the
	// catalogue for a type, and Burp's per-type method set for a method, because Burp resolves a
	// method name INSIDE its type ("Time delays" is a SQL injection method and not a reflected XSS
	// one). An entry that names nothing is refused by name rather than stored: a deny entry that
	// matches no check reads as "I turned this off" while turning nothing off.
	denyTouched := false
	if v.DisabledIssueTypes != nil {
		types := make([]uint32, 0, len(v.DisabledIssueTypes))
		for _, t := range v.DisabledIssueTypes {
			if _, ok := scanner.ByTypeIndex(t); !ok {
				return cfg, fmt.Errorf("disabled_issue_types: 0x%08x is not an issue type in the catalogue", t)
			}
			types = append(types, t)
		}
		cfg.DisabledIssueTypes = types
		denyTouched = true
	}
	if v.DisabledDetectionMethods != nil {
		methods := make([]scanner.IssueDetectionMethod, 0, len(v.DisabledDetectionMethods))
		for _, m := range v.DisabledDetectionMethods {
			def, ok := scanner.ByTypeIndex(m.TypeIndex)
			if !ok {
				return cfg, fmt.Errorf("disabled_detection_methods: 0x%08x is not an issue type in the catalogue", m.TypeIndex)
			}
			if !scanner.BurpDefinesDetectionMethod(m.TypeIndex, m.Method) {
				defined := scanner.BurpDetectionMethods(m.TypeIndex)
				if len(defined) == 0 {
					return cfg, fmt.Errorf("disabled_detection_methods: %s (0x%08x) has no detection methods — it is "+
						"selected by type alone, so disable the type instead", def.Name, m.TypeIndex)
				}
				return cfg, fmt.Errorf("disabled_detection_methods: %s is not a detection method of %s (0x%08x); "+
					"its methods are %s", strconv.Quote(m.Method), def.Name, m.TypeIndex, strings.Join(defined, ", "))
			}
			methods = append(methods, m)
		}
		cfg.DisabledDetectionMethods = methods
		denyTouched = true
	}
	if denyTouched {
		cfg.DeclinedDetectionMethods = pruneCoveredDeclines(cfg)
	}
	if v.FollowUpPasses != nil {
		cfg.FollowUpPasses = scanner.SomeUint32(*v.FollowUpPasses)
	}
	if v.PerHostThrottleMs != nil {
		cfg.PerHostThrottleMs = scanner.SomeUint32(*v.PerHostThrottleMs)
	}
	if v.PerHostThrottleRandom != nil {
		cfg.PerHostThrottleRandom = *v.PerHostThrottleRandom
	}
	if v.PerHostMaxInFlight != nil {
		cfg.PerHostMaxInFlight = scanner.SomeUint32(*v.PerHostMaxInFlight)
	}
	if v.SkipAllTestsForParameters != nil {
		names := make([]string, 0, len(v.SkipAllTestsForParameters))
		for _, raw := range v.SkipAllTestsForParameters {
			name := strings.TrimSpace(raw)
			if name == "" {
				return cfg, errors.New("skip_all_tests_for_parameters: every entry needs a parameter name")
			}
			names = append(names, name)
		}
		cfg.SkipAllTestsForParameters = names
	}
	// The server-side list follows the skip-all list's rules exactly (gmdk): present overlays, [] clears,
	// an empty name is refused rather than dropped.
	if v.SkipServerSideInjectionForParameters != nil {
		names := make([]string, 0, len(v.SkipServerSideInjectionForParameters))
		for _, raw := range v.SkipServerSideInjectionForParameters {
			name := strings.TrimSpace(raw)
			if name == "" {
				return cfg, errors.New("skip_server_side_injection_for_parameters: every entry needs a parameter name")
			}
			names = append(names, name)
		}
		cfg.SkipServerSideInjectionForParameters = names
	}
	return cfg, nil
}

// pruneCoveredDeclines drops the declines a written deny list has made untrue.
//
// An imported selection records "enabled, but burpsy's check cannot do it" for a method only while
// the method and its type are both enabled (applyIssueSelection), and the audit re-records those rows
// on every item the check runs on (audit_engine.go). Once the operator disables that method or its
// type, the row would go on telling every item the method was skipped for want of an implementation
// when it is now skipped because they turned it off — so it goes. Only that kind is touched: a decline
// with no method (a type the catalogue does not know) or with a name Burp does not define for the
// type stays true whatever the deny list says, and is kept.
//
// Nothing is ADDED for a method the write re-enables. An import accounts only for the methods its
// file names, and the console shows, for every Burp method of every type, whether burpsy implements
// it — so that answer is visible without a decline row.
func pruneCoveredDeclines(cfg scanner.AuditConfig) scanner.MethodDeclines {
	if len(cfg.DeclinedDetectionMethods) == 0 {
		return cfg.DeclinedDetectionMethods
	}
	disabledType := make(map[uint32]bool, len(cfg.DisabledIssueTypes))
	for _, t := range cfg.DisabledIssueTypes {
		disabledType[t] = true
	}
	disabledMethod := make(map[scanner.IssueDetectionMethod]bool, len(cfg.DisabledDetectionMethods))
	for _, m := range cfg.DisabledDetectionMethods {
		disabledMethod[m] = true
	}
	kept := make(scanner.MethodDeclines, 0, len(cfg.DeclinedDetectionMethods))
	for _, d := range cfg.DeclinedDetectionMethods {
		enabledButUnimplemented := d.Method != "" && scanner.BurpDefinesDetectionMethod(d.TypeIndex, d.Method)
		if enabledButUnimplemented && (disabledType[d.TypeIndex] ||
			disabledMethod[scanner.IssueDetectionMethod{TypeIndex: d.TypeIndex, Method: d.Method}]) {
			continue
		}
		kept = append(kept, d)
	}
	return kept
}

// b2u32 is the bool spelling OptUint32 stores.
func b2u32(b bool) uint32 {
	if b {
		return 1
	}
	return 0
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
	// Shipped marks the read-only configurations Burp bundles apart from the operator's own saved
	// ones. A shipped configuration cannot be overwritten, renamed or deleted — the CRUD verbs refuse
	// it by name — and the console disables those controls on its row rather than offering a button
	// that would only ever answer 409. Both lists ride one array so the launch picker reads one place.
	Shipped bool `json:"shipped"`
	// Damaged marks a saved configuration whose stored document cannot be parsed. It is listed
	// rather than hidden — an operator who saved one must not have it vanish — but it carries no
	// resolved settings and the picker will not offer it, because running an audit under "whatever
	// the default happens to be" while calling it by the operator's name is the one outcome worse
	// than saying the row is broken.
	Damaged bool `json:"damaged,omitempty"`
}

// handleScannerConfigs serves GET /api/scanner/configs: the shipped configurations an audit can be run
// under, and the default it runs under when none is named.
func (s *Server) handleScannerConfigs(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
	case http.MethodPost, http.MethodPut, http.MethodDelete:
		s.scannerConfigLibraryWrite(w, r)
		return
	default:
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
			Shipped:  true,
		})
	}
	// The operator's own saved configurations, in the SAME list as the shipped ones and marked
	// shipped:false. One array rather than two, because the launch picker asks "what can this audit
	// run under?" and that question has one answer — a caller forced to merge two lists is a caller
	// that will one day merge them differently from this one.
	for _, saved := range s.savedScanConfigs() {
		configs = append(configs, saved)
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
		"omitted_reason":    "those configurations are not transcribed as presets here; they mostly set crawl tuning and JavaScript-analysis keys. Loading one as a file (-scan-config /path/to/file.json) applies what this engine honours, including per-issue selection, and names every key it cannot apply; the honoured key counts are pinned by internal/scanner's own tests",
		"how_to_run_under":  "POST /api/audit/{exchange_id} or /api/scanner/audit with {\"config\": \"<name>\"}",
		"applies_to_server": "the CLI flag -scan-config sets the default above for every audit this server runs",
	})
}

// auditBaseConfig is the configuration an audit runs under when no preset is named — the scanner's own,
// which honours a -scan-config default set at startup.
func (s *Server) auditBaseConfig() scanner.AuditConfig {
	if s.wiredScanner() == nil {
		return scanner.DefaultAuditConfig()
	}
	return s.wiredScanner().AuditConfig()
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
		// Not a shipped preset — it may be one the operator saved (burpsy-react-ui-uxcs). Resolved
		// here rather than at the call sites so that every path that can run an audit under a name
		// resolves that name the same way, and so the name this returns is the one the run records.
		if cfg, found := s.savedScanConfig(name); found {
			// No unapplied-key report: a saved configuration IS a resolved AuditConfig, not an
			// overlay of keys, so there is no key that failed to apply — see the library's comment.
			return cfg, name, nil, nil
		}
		return base, "", nil, &unknownConfigError{Name: name, Known: s.knownConfigNames()}
	}
	applied, unapplied := preset.ApplyWithReport(base)
	return applied, preset.Name, unapplied, nil
}

// savedScanConfig resolves one of the operator's own configurations by name. A stored document that
// cannot be parsed reports NOT FOUND rather than the default: running an audit under settings the
// operator never chose, while the run record names their configuration, is the failure this whole
// library is written to avoid.
func (s *Server) savedScanConfig(name string) (scanner.AuditConfig, bool) {
	if s.persist == nil {
		return scanner.AuditConfig{}, false
	}
	doc, found, err := s.persist.LoadScanConfigLibrary(name)
	if err != nil || !found {
		return scanner.AuditConfig{}, false
	}
	return decodeSavedScanConfig(doc)
}

// knownConfigNames is every name an audit can be run under — shipped and saved — so an unknown-name
// refusal lists what actually exists rather than only half of it.
func (s *Server) knownConfigNames() []string {
	names := scanner.BuiltInConfigNames()
	if s.persist == nil {
		return names
	}
	entries, err := s.persist.LoadScanConfigLibraries()
	if err != nil {
		return names
	}
	for _, e := range entries {
		names = append(names, e.Name)
	}
	return names
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

// ---- The configuration library (burpsy-react-ui-uxcs) --------------------------------------------
//
// Burp's Settings tree carries a "Configuration library" of named scan configurations the operator
// saves, clones and edits. burpsy had only the shipped presets, rendered read-only, so a tuning an
// operator arrived at for one engagement could not be kept.
//
// A saved configuration is stored as the RESOLVED scanner.AuditConfig, one JSON document per name —
// not as a diff against a preset. A diff would mean a saved configuration silently changed meaning
// whenever the preset it was derived from changed, which is the drift the scope library refuses for
// the same reason: what was saved is what must come back.
//
// The shipped presets are never stored here. They live in scanner.BuiltInConfigs and are read-only,
// which is what makes a shipped name unshadowable — the writes below refuse one by name, so a saved
// configuration can never quietly take over a name an audit already resolves to something else.

// savedScanConfigs reads the operator's own configurations for the GET list. A store that cannot be
// read yields nothing rather than failing the whole listing: the shipped presets are still the
// truthful answer to "what can this audit run under?", and an empty library is not an error.
func (s *Server) savedScanConfigs() []builtInConfigView {
	if s.persist == nil {
		return nil
	}
	entries, err := s.persist.LoadScanConfigLibraries()
	if err != nil {
		s.logger.Warn("scan configuration library could not be read", zap.Error(err))
		return nil
	}
	out := make([]builtInConfigView, 0, len(entries))
	for _, e := range entries {
		cfg, ok := decodeSavedScanConfig(e.Doc)
		if !ok {
			// A document that cannot be parsed is listed as damaged rather than dropped or silently
			// resolved to the default. Dropping it would leave the operator looking for a
			// configuration they saved; resolving it to the default would run an audit under
			// settings they never chose, under a name that says otherwise.
			out = append(out, builtInConfigView{Name: e.Name, Keys: []scanner.BuiltInConfigKey{}, Shipped: false, Damaged: true})
			continue
		}
		// Keys is [] rather than nil: a saved configuration is a resolved config, not an overlay of
		// preset keys, and a null here crashed the console's library table, which read .length off it
		// (found by the saq3.3.1 live drive: the Settings page went blank the moment one was saved).
		out = append(out, builtInConfigView{
			Name:     e.Name,
			Keys:     []scanner.BuiltInConfigKey{},
			Resolved: newAuditConfigView(cfg),
			Shipped:  false,
		})
	}
	return out
}

// decodeSavedScanConfig parses a stored document back into a configuration.
func decodeSavedScanConfig(doc string) (scanner.AuditConfig, bool) {
	var cfg scanner.AuditConfig
	if err := json.Unmarshal([]byte(doc), &cfg); err != nil {
		return scanner.AuditConfig{}, false
	}
	return cfg, true
}

// scanConfigWriteReq is the write surface: save (or overwrite) under a name, clone an existing
// configuration under a new one, rename, and delete.
type scanConfigWriteReq struct {
	// Action is "save", "clone", "rename" or "delete". Anything else is refused naming the value,
	// rather than falling through to a default that would act on the operator's data.
	Action string `json:"action"`
	Name   string `json:"name"`
	// From is the configuration a clone or rename starts from. For a clone it may be a SHIPPED
	// preset — that is the ordinary way to start from Burp's own tuning and adjust it.
	From string `json:"from"`
	// Settings is the operator's own values, overlaid on whatever the save or clone started from.
	//
	// Without it the library could only ever snapshot the configuration the server was already
	// running under: "save" stored auditBaseConfig() and "clone" stored what `from` resolved to, so
	// an operator could name a configuration and could not change anything in it. A library of
	// copies is not a library. Null leaves the base exactly as it was, which is what every existing
	// caller sends.
	Settings *auditConfigView `json:"settings,omitempty"`
}

// scannerConfigLibraryWrite serves POST/PUT/DELETE /api/scanner/configs.
func (s *Server) scannerConfigLibraryWrite(w http.ResponseWriter, r *http.Request) {
	var req scanConfigWriteReq
	if err := requestJSON(w, r, nil).Decode(&req); err != nil {
		http.Error(w, "body must be JSON with an action and a name", http.StatusBadRequest)
		return
	}
	if s.persist == nil {
		http.Error(w, "no database is attached, so a saved scan configuration would not survive this "+
			"process; start burpsy with -db to use the configuration library", http.StatusServiceUnavailable)
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		http.Error(w, "a configuration must be named", http.StatusBadRequest)
		return
	}
	// A shipped name is refused for every write. Allowing one would give two different answers to
	// the same name depending on which list a reader consulted, and an audit resolves names.
	if _, shipped := scanner.BuiltInConfigByName(req.Name); shipped {
		http.Error(w, fmt.Sprintf(
			"%s is a configuration burpsy ships, which is read-only: clone it under another name and edit that",
			strconv.Quote(req.Name)), http.StatusConflict)
		return
	}

	switch req.Action {
	case "save", "clone":
		// The configuration being stored: for a clone, whatever `from` resolves to (shipped or
		// saved); for a plain save, the configuration the server is currently running audits under.
		cfg := s.auditBaseConfig()
		if req.From != "" {
			resolved, _, _, err := s.resolveAuditConfig(req.From)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			cfg = resolved
		}
		if req.Settings != nil {
			overlaid, err := req.Settings.applyTo(cfg)
			if err != nil {
				// Refused before anything is written. A configuration saved under the operator's
				// name that does not carry what they wrote is worse than a rejected save.
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			cfg = overlaid
		}
		doc, err := json.Marshal(cfg)
		if err != nil {
			http.Error(w, "the configuration could not be encoded: "+err.Error(), http.StatusInternalServerError)
			return
		}
		replaced, err := s.persist.SaveScanConfigLibrary(req.Name, string(doc))
		if err != nil {
			http.Error(w, "the configuration could not be saved: "+err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"saved": req.Name, "replaced": replaced})

	case "rename":
		from := strings.TrimSpace(req.From)
		if from == "" {
			http.Error(w, "rename needs the configuration to rename in `from`", http.StatusBadRequest)
			return
		}
		if _, shipped := scanner.BuiltInConfigByName(from); shipped {
			http.Error(w, fmt.Sprintf(
				"%s is a configuration burpsy ships and cannot be renamed: clone it under the name you want",
				strconv.Quote(from)), http.StatusConflict)
			return
		}
		doc, found, err := s.persist.LoadScanConfigLibrary(from)
		if err != nil {
			http.Error(w, "the configuration could not be read: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if !found {
			http.Error(w, fmt.Sprintf("no saved configuration is named %s", strconv.Quote(from)), http.StatusNotFound)
			return
		}
		if _, err := s.persist.SaveScanConfigLibrary(req.Name, doc); err != nil {
			http.Error(w, "the configuration could not be saved under its new name: "+err.Error(), http.StatusInternalServerError)
			return
		}
		// Deleted only after the new name is durably written: a rename that lost the configuration
		// between the two steps would be worse than one that briefly left both.
		if _, err := s.persist.DeleteScanConfigLibrary(from); err != nil {
			http.Error(w, "the configuration was copied to its new name but the old one could not be removed: "+err.Error(),
				http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"renamed": from, "to": req.Name})

	case "delete":
		deleted, err := s.persist.DeleteScanConfigLibrary(req.Name)
		if err != nil {
			http.Error(w, "the configuration could not be deleted: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if !deleted {
			http.Error(w, fmt.Sprintf("no saved configuration is named %s", strconv.Quote(req.Name)), http.StatusNotFound)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"deleted": req.Name})

	default:
		http.Error(w, fmt.Sprintf(
			"action %s is not one of save, clone, rename or delete", strconv.Quote(req.Action)), http.StatusBadRequest)
	}
}
