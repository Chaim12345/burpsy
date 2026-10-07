package scanner

// Burp's per-issue selection: `scanner/issues_reported/{select_individual_issues,
// scan_only_selected_issues, selected_issues}`, read the way Burp reads it.
//
// # The semantics, and why the list is NOT a whitelist by default
//
// Everything below is read from Burp Suite 2026.7.1 (build 51467) under
// /root/burp-re/out/clean/jdt_src/burp/:
//
//   - Mode (Zmzw.java:80-87). An issue type is decided by the scan-type flags
//     (scan_type_passive, scan_type_*_active, scan_type_javascript_analysis — Zx9y.java:24-58)
//     UNLESS select_individual_issues or scan_only_selected_issues is set; then the scan-type
//     flags are not consulted at all and the per-type bitmask alone decides (Zx9y.java:20-22).
//   - The bitmask (Zx9y.java:122-158, Zwnn.java:13-25). Per issue type, bit 0 is "issue disabled"
//     and bit N is "detection method with permanentIndex N disabled". A type with no entry reads 0
//     — ENABLED — except when scan_only_selected_issues is set and the list is non-empty, where an
//     absent type reads 1 (disabled). So without scan_only_selected_issues the list is a set of
//     per-issue OVERRIDES and `enabled: false` removes a type; with it the list is a whitelist.
//   - Loading replaces state (Zx9y.java:186-191, :283-299): the map is cleared before the list is
//     read, then every entry sets its type bit and each named method's bit.
//   - Method names are resolved WITHIN the type's own method set (Zwx_.java:43-61): "Time delays"
//     is TIME_BASED for SQL injection and REQUEST_SMUGGLING_NORMAL for request smuggling. A name
//     the type does not define trips an assertion and is ignored.
//   - A check is enabled when ANY of the (type, method) pairs it registers is enabled, or when it
//     registers types only (Zwy6.java:36-75, the per-pair predicate at :170-184).
//
// That is why "Audit checks - all except time-based detection methods.json" — select_individual_issues
// true, NO scan_only_selected_issues, nine entries — means "everything, minus five issue types and
// minus the Time delays method of four more", and why reading its list as AuditConfig.IssueTypes
// (a whitelist) would have silently narrowed a full audit to nine checks.

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// Burp's detection-method display names (Zwx_.java, constructor table recovered in
// /root/burp-re/out/deobf_merged/burp/Zwx_.java:216-240). They are what a configuration file
// spells, so they are what this engine matches on.
const (
	MethodStringEcho                 = "String echo"
	MethodErrorMessages              = "Error messages"
	MethodTimeDelays                 = "Time delays"
	MethodBooleanConditions          = "Boolean conditions"
	MethodOracleSpecific             = "Oracle specific"
	MethodMySQLSpecific              = "MySQL specific"
	MethodSQLServerSpecific          = "SQL Server specific"
	MethodPostgreSQLSpecific         = "PostgreSQL specific"
	MethodPassiveChecks              = "Passive checks"
	MethodActiveChecks               = "Active checks"
	MethodClientSide                 = "Client-side"
	MethodServerSideTemplateBreakout = "Server-side template breakout"
	MethodFileRetrieval              = "File retrieval"
	MethodResponseDiffing            = "Response diffing"
	MethodJavaScriptStatic           = "Javascript static analysis"
	MethodJavaScriptDynamic          = "Javascript dynamic analysis"
	MethodInBand                     = "In-band"
	MethodCollaborator               = "Burp Collaborator"
	MethodInfiltrator                = "Burp Infiltrator"
	MethodBackEndSocketPoisoning     = "Back-end socket poisoning"
)

// BCheckGeneratedTypeIndex and ExtensionGeneratedTypeIndex are the catalogue rows Burp files a
// BCheck's and an extension's findings under. A loaded corpus check IS a BCheck, so it is selected
// and deselected as this type — "Audit checks - BChecks only.json" whitelists exactly 0x09000000.
const (
	BCheckGeneratedTypeIndex    uint32 = 0x09000000
	ExtensionGeneratedTypeIndex uint32 = 0x08000000
)

// burpIssueDetectionMethods is the per-issue-type detection-method set Burp defines, transcribed
// from the Zcot enum constructors (/root/burp-re/out/deobf_merged/burp/Zcot.java:555-1195, the
// fifth constructor argument). A type absent here defines no method: Burp selects it by type alone,
// and a configuration naming a method for it is ignored (Zwx_.java:43-61).
var burpIssueDetectionMethods = map[uint32][]string{
	0x00100100: {MethodStringEcho, MethodTimeDelays, MethodCollaborator, MethodInfiltrator},                                                                                                                           // OS_COMMAND_INJECTION
	0x00100200: {MethodErrorMessages, MethodBooleanConditions, MethodTimeDelays, MethodCollaborator, MethodSQLServerSpecific, MethodMySQLSpecific, MethodOracleSpecific, MethodPostgreSQLSpecific, MethodInfiltrator}, // SQL_INJECTION
	0x00100210: {MethodErrorMessages, MethodBooleanConditions, MethodTimeDelays, MethodCollaborator, MethodSQLServerSpecific, MethodMySQLSpecific, MethodOracleSpecific, MethodPostgreSQLSpecific},                    // SQL_INJECTION_2ND_ORDER
	0x00100300: {MethodFileRetrieval, MethodInfiltrator},                                                                                                                                                              // FILE_PATH_TRAVERSAL
	0x00100400: {MethodFileRetrieval, MethodCollaborator},                                                                                                                                                             // XML_EXTERNAL_ENTITY_INJECTION
	0x00100500: {MethodBooleanConditions, MethodInfiltrator},                                                                                                                                                          // LDAP_INJECTION
	0x00100600: {MethodErrorMessages, MethodBooleanConditions, MethodInfiltrator},                                                                                                                                     // XPATH_INJECTION
	0x00100700: {MethodErrorMessages, MethodCollaborator, MethodInfiltrator},                                                                                                                                          // XML_INJECTION
	0x00100850: {MethodResponseDiffing, MethodInBand},                                                                                                                                                                 // BROKEN_ACCESS_CONTROL
	0x00100c00: {MethodStringEcho, MethodTimeDelays, MethodCollaborator},                                                                                                                                              // PHP_CODE_INJECTION
	0x00101080: {MethodStringEcho, MethodCollaborator},                                                                                                                                                                // SERVER_SIDE_TEMPLATE_ENGINE_INJECTION
	0x00101100: {MethodStringEcho, MethodCollaborator},                                                                                                                                                                // SSI_INJECTION
	0x00200100: {MethodInBand, MethodCollaborator},                                                                                                                                                                    // XSS_STORED
	0x00200140: {MethodTimeDelays, MethodBackEndSocketPoisoning},                                                                                                                                                      // REQUEST_SMUGGLING
	0x00200300: {MethodClientSide, MethodServerSideTemplateBreakout},                                                                                                                                                  // XSS_REFLECTED
	0x00200310: {MethodJavaScriptDynamic, MethodJavaScriptStatic},                                                                                                                                                     // XSS_DOM_BASED
	0x00200311: {MethodJavaScriptDynamic, MethodJavaScriptStatic},                                                                                                                                                     // XSS_REFLECTED_DOM_BASED
	0x00200312: {MethodJavaScriptDynamic, MethodJavaScriptStatic},                                                                                                                                                     // XSS_STORED_DOM_BASED
	0x00200316: {MethodJavaScriptDynamic, MethodJavaScriptStatic},                                                                                                                                                     // CLIENT_SIDE_PROTOTYPE_POLLUTION
	0x00200320: {MethodJavaScriptDynamic, MethodJavaScriptStatic},                                                                                                                                                     // JAVASCRIPT_INJECTION_DOM_BASED
	0x00200321: {MethodJavaScriptDynamic, MethodJavaScriptStatic},                                                                                                                                                     // JAVASCRIPT_INJECTION_REFLECTED_DOM_BASED
	0x00200322: {MethodJavaScriptDynamic, MethodJavaScriptStatic},                                                                                                                                                     // JAVASCRIPT_INJECTION_STORED_DOM_BASED
	0x00200330: {MethodJavaScriptDynamic, MethodJavaScriptStatic},                                                                                                                                                     // CLIENT_SIDE_SQL_INJECTION_DOM_BASED
	0x00200331: {MethodJavaScriptDynamic, MethodJavaScriptStatic},                                                                                                                                                     // CLIENT_SIDE_SQL_INJECTION_REFLECTED_DOM_BASED
	0x00200332: {MethodJavaScriptDynamic, MethodJavaScriptStatic},                                                                                                                                                     // CLIENT_SIDE_SQL_INJECTION_STORED_DOM_BASED
	0x00200340: {MethodJavaScriptDynamic, MethodJavaScriptStatic},                                                                                                                                                     // WEBSOCKET_URL_POISONING_DOM_BASED
	0x00200341: {MethodJavaScriptDynamic, MethodJavaScriptStatic},                                                                                                                                                     // WEBSOCKET_URL_POISONING_REFLECTED_DOM_BASED
	0x00200342: {MethodJavaScriptDynamic, MethodJavaScriptStatic},                                                                                                                                                     // WEBSOCKET_URL_POISONING_STORED_DOM_BASED
	0x00200350: {MethodJavaScriptDynamic, MethodJavaScriptStatic},                                                                                                                                                     // LOCAL_FILE_PATH_MANIPULATION_DOM_BASED
	0x00200351: {MethodJavaScriptDynamic, MethodJavaScriptStatic},                                                                                                                                                     // LOCAL_FILE_PATH_MANIPULATION_REFLECTED_DOM_BASED
	0x00200352: {MethodJavaScriptDynamic, MethodJavaScriptStatic},                                                                                                                                                     // LOCAL_FILE_PATH_MANIPULATION_STORED_DOM_BASED
	0x00200360: {MethodJavaScriptDynamic, MethodJavaScriptStatic},                                                                                                                                                     // CLIENT_SIDE_XPATH_INJECTION_DOM_BASED
	0x00200361: {MethodJavaScriptDynamic, MethodJavaScriptStatic},                                                                                                                                                     // CLIENT_SIDE_XPATH_INJECTION_REFLECTED_DOM_BASED
	0x00200362: {MethodJavaScriptDynamic, MethodJavaScriptStatic},                                                                                                                                                     // CLIENT_SIDE_XPATH_INJECTION_STORED_DOM_BASED
	0x00200370: {MethodJavaScriptDynamic, MethodJavaScriptStatic},                                                                                                                                                     // CLIENT_SIDE_JSON_INJECTION_DOM_BASED
	0x00200371: {MethodJavaScriptDynamic, MethodJavaScriptStatic},                                                                                                                                                     // CLIENT_SIDE_JSON_INJECTION_REFLECTED_DOM_BASED
	0x00200372: {MethodJavaScriptDynamic, MethodJavaScriptStatic},                                                                                                                                                     // CLIENT_SIDE_JSON_INJECTION_STORED_DOM_BASED
	0x00300200: {MethodCollaborator, MethodInfiltrator},                                                                                                                                                               // EXTERNAL_SERVICE_INTERACTION_DNS
	0x00300210: {MethodCollaborator, MethodInfiltrator},                                                                                                                                                               // EXTERNAL_SERVICE_INTERACTION_HTTP
	0x00400110: {MethodResponseDiffing, MethodCollaborator},                                                                                                                                                           // SPOOFABLE_CLIENT_IP
	0x00500110: {MethodJavaScriptDynamic, MethodJavaScriptStatic},                                                                                                                                                     // OPEN_REDIRECTION_DOM_BASED
	0x00500111: {MethodJavaScriptDynamic, MethodJavaScriptStatic},                                                                                                                                                     // OPEN_REDIRECTION_REFLECTED_DOM_BASED
	0x00500112: {MethodJavaScriptDynamic, MethodJavaScriptStatic},                                                                                                                                                     // OPEN_REDIRECTION_STORED_DOM_BASED
	0x00500b00: {MethodJavaScriptDynamic, MethodJavaScriptStatic},                                                                                                                                                     // COOKIE_MANIPULATION_DOM_BASED
	0x00500b01: {MethodJavaScriptDynamic, MethodJavaScriptStatic},                                                                                                                                                     // COOKIE_MANIPULATION_REFLECTED_DOM_BASED
	0x00500b02: {MethodJavaScriptDynamic, MethodJavaScriptStatic},                                                                                                                                                     // COOKIE_MANIPULATION_STORED_DOM_BASED
	0x00500c00: {MethodJavaScriptDynamic, MethodJavaScriptStatic},                                                                                                                                                     // AJAX_REQUEST_HEADER_MANIPULATION_DOM_BASED
	0x00500c01: {MethodJavaScriptDynamic, MethodJavaScriptStatic},                                                                                                                                                     // AJAX_REQUEST_HEADER_REFLECTED_MANIPULATION_DOM_BASED
	0x00500c02: {MethodJavaScriptDynamic, MethodJavaScriptStatic},                                                                                                                                                     // AJAX_REQUEST_HEADER_STORED_MANIPULATION_DOM_BASED
	0x00500d00: {MethodJavaScriptDynamic, MethodJavaScriptStatic},                                                                                                                                                     // DENIAL_OF_SERVICE_DOM_BASED
	0x00500d01: {MethodJavaScriptDynamic, MethodJavaScriptStatic},                                                                                                                                                     // DENIAL_OF_SERVICE_REFLECTED_DOM_BASED
	0x00500d02: {MethodJavaScriptDynamic, MethodJavaScriptStatic},                                                                                                                                                     // DENIAL_OF_SERVICE_STORED_DOM_BASED
	0x00500e00: {MethodJavaScriptDynamic, MethodJavaScriptStatic},                                                                                                                                                     // HTML5_WEB_MESSAGE_MANIPULATION_DOM_BASED
	0x00500e01: {MethodJavaScriptDynamic, MethodJavaScriptStatic},                                                                                                                                                     // HTML5_WEB_MESSAGE_MANIPULATION_REFLECTED_DOM_BASED
	0x00500e02: {MethodJavaScriptDynamic, MethodJavaScriptStatic},                                                                                                                                                     // HTML5_WEB_MESSAGE_MANIPULATION_STORED_DOM_BASED
	0x00500f00: {MethodJavaScriptDynamic, MethodJavaScriptStatic},                                                                                                                                                     // HTML5_STORAGE_MANIPULATION_DOM_BASED
	0x00500f01: {MethodJavaScriptDynamic, MethodJavaScriptStatic},                                                                                                                                                     // HTML5_STORAGE_MANIPULATION_REFLECTED_DOM_BASED
	0x00500f02: {MethodJavaScriptDynamic, MethodJavaScriptStatic},                                                                                                                                                     // HTML5_STORAGE_MANIPULATION_STORED_DOM_BASED
	0x00501000: {MethodJavaScriptDynamic, MethodJavaScriptStatic},                                                                                                                                                     // LINK_MANIPULATION_DOM_BASED
	0x00501001: {MethodJavaScriptDynamic, MethodJavaScriptStatic},                                                                                                                                                     // LINK_MANIPULATION_REFLECTED_DOM_BASED
	0x00501002: {MethodJavaScriptDynamic, MethodJavaScriptStatic},                                                                                                                                                     // LINK_MANIPULATION_STORED_DOM_BASED
	0x00501100: {MethodJavaScriptDynamic, MethodJavaScriptStatic},                                                                                                                                                     // DOCUMENT_DOMAIN_MANIPULATION_DOM_BASED
	0x00501101: {MethodJavaScriptDynamic, MethodJavaScriptStatic},                                                                                                                                                     // DOCUMENT_DOMAIN_MANIPULATION_REFLECTED_DOM_BASED
	0x00501102: {MethodJavaScriptDynamic, MethodJavaScriptStatic},                                                                                                                                                     // DOCUMENT_DOMAIN_MANIPULATION_STORED_DOM_BASED
	0x00501200: {MethodJavaScriptDynamic, MethodJavaScriptStatic},                                                                                                                                                     // DOM_DATA_MANIPULATION_DOM_BASED
	0x00501201: {MethodJavaScriptDynamic, MethodJavaScriptStatic},                                                                                                                                                     // DOM_DATA_MANIPULATION_REFLECTED_DOM_BASED
	0x00501202: {MethodJavaScriptDynamic, MethodJavaScriptStatic},                                                                                                                                                     // DOM_DATA_MANIPULATION_STORED_DOM_BASED
	0x08000000: {MethodPassiveChecks, MethodActiveChecks},                                                                                                                                                             // EXTENSION_GENERATED
	0x09000000: {MethodPassiveChecks, MethodActiveChecks},                                                                                                                                                             // BCHECK_GENERATED
	0x09008000: {MethodPassiveChecks, MethodActiveChecks, MethodCollaborator},                                                                                                                                         // BAMBDA_GENERATED
}

// BurpDetectionMethods returns the detection methods Burp defines for one issue type, in Burp's
// declaration order. Nil means the type is selected by type alone.
func BurpDetectionMethods(typeIndex uint32) []string {
	return append([]string(nil), burpIssueDetectionMethods[typeIndex]...)
}

// burpDefinesMethod reports whether Burp resolves name for this type (Zwx_.Zm is a per-type lookup).
func burpDefinesMethod(typeIndex uint32, name string) bool {
	for _, m := range burpIssueDetectionMethods[typeIndex] {
		if m == name {
			return true
		}
	}
	return false
}

// DetectionMethodSetting is one `detection_methods[]` entry of a selected issue, as the file spells it.
type DetectionMethodSetting struct {
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
}

// SelectedIssue is one `scanner/issues_reported/selected_issues[]` entry.
type SelectedIssue struct {
	TypeIndex        uint32                   `json:"type_index"`
	Enabled          bool                     `json:"enabled"`
	DetectionMethods []DetectionMethodSetting `json:"detection_methods"`
}

// IssueDetectionMethod names one detection method of one issue type. Methods are keyed by type
// because Burp resolves a method name inside its type: the same "Time delays" is a different method
// for SQL injection than for request smuggling.
type IssueDetectionMethod struct {
	TypeIndex uint32 `json:"type_index"`
	Method    string `json:"method"`
}

// MethodDecline is one detection method (or, with Method empty, one issue type) a configuration
// named that this engine did not act on, with the reason. It is the honest-counting record for the
// selection: a method the file enabled that burpsy cannot run, a method name Burp itself would have
// ignored, or a method a run withheld because the configuration disabled it.
type MethodDecline struct {
	TypeIndex uint32 `json:"type_index"`
	Issue     string `json:"issue"`
	Method    string `json:"method"`
	Reason    string `json:"reason"`
	// ProbesWithheld counts the probe requests a run did NOT send because this method was disabled.
	// Zero on a configuration-level record, where nothing has been dispatched yet.
	ProbesWithheld int `json:"probes_withheld"`
}

// MethodDeclines marshals as [] when empty, never null: a console reading "no declines" from a null
// would be reading the absence of a list as a clean one.
type MethodDeclines []MethodDecline

// MarshalJSON keeps an empty list an empty list.
func (m MethodDeclines) MarshalJSON() ([]byte, error) {
	if m == nil {
		return []byte("[]"), nil
	}
	return json.Marshal([]MethodDecline(m))
}

// parseSelectedIssues decodes Burp's `selected_issues` array. type_index is a string Burp writes as
// "0x00100200" and reads with Integer.decode (Zx9y.java:284), so hex, octal and decimal spellings are
// all accepted; a bare JSON number is accepted too, for a hand-written file.
func parseSelectedIssues(raw json.RawMessage) ([]SelectedIssue, error) {
	var entries []struct {
		TypeIndex        json.RawMessage `json:"type_index"`
		Enabled          *bool           `json:"enabled"`
		DetectionMethods []struct {
			Name    string `json:"name"`
			Enabled *bool  `json:"enabled"`
		} `json:"detection_methods"`
	}
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, fmt.Errorf("expected a list of {type_index, enabled, detection_methods}: %w", err)
	}
	out := make([]SelectedIssue, 0, len(entries))
	for i, e := range entries {
		t, err := parseTypeIndex(e.TypeIndex)
		if err != nil {
			return nil, fmt.Errorf("entry %d: type_index: %w", i, err)
		}
		// Burp reads `enabled` with a required getter (Zx9y.java:285); a missing one is a malformed
		// file, and guessing either value would select or drop an issue nobody chose.
		if e.Enabled == nil {
			return nil, fmt.Errorf("entry %d (0x%08x): enabled is missing", i, t)
		}
		sel := SelectedIssue{TypeIndex: t, Enabled: *e.Enabled, DetectionMethods: []DetectionMethodSetting{}}
		for j, m := range e.DetectionMethods {
			if m.Enabled == nil {
				return nil, fmt.Errorf("entry %d (0x%08x): detection_methods[%d] %q: enabled is missing", i, t, j, m.Name)
			}
			sel.DetectionMethods = append(sel.DetectionMethods, DetectionMethodSetting{Name: m.Name, Enabled: *m.Enabled})
		}
		out = append(out, sel)
	}
	return out, nil
}

// parseTypeIndex reads one type_index spelling.
func parseTypeIndex(raw json.RawMessage) (uint32, error) {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		n, perr := strconv.ParseUint(strings.TrimSpace(s), 0, 32)
		if perr != nil {
			return 0, fmt.Errorf("%q is not an issue type index", s)
		}
		return uint32(n), nil
	}
	n, err := burpConfigUint(raw)
	if err != nil {
		return 0, err
	}
	return n, nil
}

// selectionMode reports whether this configuration decides issues per type rather than by scan
// type (Zmzw.java:86). Unset reads false, Burp's default for both flags.
func (c BuiltInConfig) selectionMode() bool {
	return (c.SelectIndividualIssues.Set && c.SelectIndividualIssues.Value != 0) ||
		(c.ScanOnlySelectedIssues.Set && c.ScanOnlySelectedIssues.Value != 0)
}

// touchesSelection reports whether the source named any of the three selection keys.
func (c BuiltInConfig) touchesSelection() bool {
	return c.SelectIndividualIssues.Set || c.ScanOnlySelectedIssues.Set || c.SelectedIssuesSet
}

// applyIssueSelection overlays the three selection keys onto a run configuration and accounts for
// selected_issues in the report. Called from applyWithAccounting after the row walk, because in
// selection mode it has to undo what the scan_type_* rows wrote: Burp does not consult them then.
func (c BuiltInConfig) applyIssueSelection(a *AuditConfig, rep *configApplyReport, named bool) {
	const key = "selected_issues"
	if !c.touchesSelection() {
		if named {
			rep.Unapplied = append(rep.Unapplied, key)
		}
		return
	}
	// Loading replaces state (Zx9y.java:186-191): a base configuration's selection does not survive a
	// file that speaks about selection, in either mode.
	a.IssueTypes = nil
	a.DisabledIssueTypes = nil
	a.DisabledDetectionMethods = nil
	a.DeclinedDetectionMethods = nil

	if !c.selectionMode() {
		if !c.SelectedIssuesSet {
			return
		}
		// Scan-type mode: Burp stores the list and never consults it (Zmzw.java:86). An empty list is
		// therefore fully honoured; a non-empty one did nothing, and the operator is told so rather
		// than left to discover that the issues they listed still ran.
		if len(c.SelectedIssues) > 0 {
			rep.Unapplied = append(rep.Unapplied, key)
			return
		}
		rep.Applied = append(rep.Applied, key)
		return
	}

	// Selection mode: the scan-type flags are not consulted (Zmzw.java:86), so the tiers the row walk
	// applied are taken back. Every shipped selection-mode configuration sets all five true, which is
	// why this is invisible on Burp's own files and still has to be right for an operator's.
	a.PassiveChecks = OptUint32{}
	a.LightActiveChecks = OptUint32{}
	a.MediumActiveChecks = OptUint32{}
	a.IntrusiveActiveChecks = OptUint32{}
	a.JavaScriptAnalysis = OptUint32{}

	whitelist := c.ScanOnlySelectedIssues.Set && c.ScanOnlySelectedIssues.Value != 0
	var declined MethodDeclines
	for _, e := range c.SelectedIssues {
		def, ok := ByTypeIndex(e.TypeIndex)
		if !ok {
			declined = append(declined, MethodDecline{TypeIndex: e.TypeIndex,
				Reason: "not an issue type in Burp's catalogue, so this entry selects nothing"})
			continue
		}
		// Under scan_only_selected_issues an absent type is disabled (Zwnn.java:20), so every listed
		// type is in the whitelist and a listed-but-disabled one is ALSO denied: the intersection is
		// exactly the enabled entries, and a list whose every entry is disabled admits nothing — which
		// an empty whitelist could not say, since empty means "no restriction".
		if whitelist {
			a.IssueTypes = append(a.IssueTypes, e.TypeIndex)
		}
		if !e.Enabled {
			a.DisabledIssueTypes = append(a.DisabledIssueTypes, e.TypeIndex)
		}
		for _, m := range e.DetectionMethods {
			if !burpDefinesMethod(e.TypeIndex, m.Name) {
				declined = append(declined, MethodDecline{TypeIndex: e.TypeIndex, Issue: def.Name, Method: m.Name,
					Reason: "Burp defines no detection method of this name for this issue type, so Burp itself ignores it (Zwx_.Zm)"})
				continue
			}
			if !m.Enabled {
				a.DisabledDetectionMethods = append(a.DisabledDetectionMethods,
					IssueDetectionMethod{TypeIndex: e.TypeIndex, Method: m.Name})
			}
		}
	}
	a.DeclinedDetectionMethods = declined
	rep.Applied = append(rep.Applied, key)
}

// issueTypeDisabled reports whether the run's selection removed this type.
func (cfg AuditConfig) issueTypeDisabled(typeIndex uint32) bool {
	for _, t := range cfg.DisabledIssueTypes {
		if t == typeIndex {
			return true
		}
	}
	return false
}

// filterBySelection is the second stage of Burp's two-stage dispatch (Zwy6.java:36-75): the
// whitelist when scan_only_selected_issues put one in force, then the per-type overrides.
func filterBySelection(checks []activeCheck, cfg AuditConfig) []activeCheck {
	checks = filterByIssueTypes(checks, cfg.IssueTypes)
	if len(cfg.DisabledIssueTypes) == 0 {
		return checks
	}
	out := make([]activeCheck, 0, len(checks))
	for _, c := range checks {
		if c.typeIndex != 0 && cfg.issueTypeDisabled(c.typeIndex) {
			continue
		}
		out = append(out, c)
	}
	return out
}
