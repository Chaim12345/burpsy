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
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
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

// burpsyDetectionMethods is what burpsy's OWN check for each type actually does, spelled in Burp's
// method vocabulary. It is the half the selection is enforced against: a check is withheld when a
// method it declares here is disabled for its type, and a method the configuration enables that is
// not listed here is declined by name, because burpsy will not run it.
//
// Every entry was read from the check it describes, not inferred from the row name:
//   - SQL injection's check sends three probe banks, each with its own method gate at the probe
//     (saq3.2.1): the error bank (ProbeErrorSignatures, "Error messages"), the boolean
//     differential (ProbeBoolean, "Boolean conditions") and the timing probes (ProbeTimingUnder,
//     "Time delays"; PostgreSQL pg_sleep and SQL Server waitfor — the two dialect banks
//     recoverable from the decompile — additionally under their dialect's own method). MySQL and
//     Oracle timing remain declined by name: their payload banks are inside ZKM string decoders
//     this tree does not run. Collaborator-based SQLi is likewise not implemented. The check
//     itself is withheld only when every declared method is disabled, per Zwy6's rule above.
//   - OS command, PHP, SSI and server-side template injection prove execution by an echoed marker
//     or arithmetic result (ProbeEvaluation): Burp's "String echo".
//   - Path traversal and XXE read a known file's content back in band: "File retrieval".
//   - LDAP compares an always-true and a negated filter (ProbeBoolean). Its error-signature probe is
//     not a Burp method of the LDAP type, so it carries no method of its own.
//   - XPath and XML injection read parser error signatures: "Error messages".
//   - Broken access control compares two sessions' responses: "Response diffing".
//   - Stored XSS re-reads a planted canary in a later response: "In-band".
//   - Request smuggling pipelines a CL.TE / TE.CL pair down one connection and reads the response
//     that follows — Burp's socket-poisoning method, not its timing one.
//   - Reflected XSS confirms a client-side markup or script breakout: "Client-side".
//   - The DOM rows run in the instrumented browser (domexec); the static DOM pass runs on the
//     passive path, outside these descriptors: "Javascript dynamic analysis".
//   - External service interaction plants an interactsh domain: Burp's "Burp Collaborator".
//   - A loaded corpus check is a BCheck's active half: "Active checks".
var burpsyDetectionMethods = map[uint32][]string{
	0x00100100:               {MethodStringEcho},                                                                                                  // OS command injection
	0x00100200:               {MethodErrorMessages, MethodBooleanConditions, MethodTimeDelays, MethodPostgreSQLSpecific, MethodSQLServerSpecific}, // SQL injection
	0x00100300:               {MethodFileRetrieval},                                                                                               // File path traversal
	0x00100400:               {MethodFileRetrieval},                                                                                               // XML external entity injection
	0x00100500:               {MethodBooleanConditions},                                                                                           // LDAP injection
	0x00100600:               {MethodErrorMessages},                                                                                               // XPath injection
	0x00100700:               {MethodErrorMessages},                                                                                               // XML injection
	0x00100850:               {MethodResponseDiffing},                                                                                             // Broken access control
	0x00100c00:               {MethodStringEcho},                                                                                                  // PHP code injection
	0x00101080:               {MethodStringEcho},                                                                                                  // Server-side template injection
	0x00101100:               {MethodStringEcho},                                                                                                  // SSI injection
	0x00200100:               {MethodInBand},                                                                                                      // Cross-site scripting (stored)
	0x00200140:               {MethodBackEndSocketPoisoning},                                                                                      // HTTP request smuggling
	0x00200300:               {MethodClientSide},                                                                                                  // Cross-site scripting (reflected)
	0x00300200:               {MethodCollaborator},                                                                                                // External service interaction (DNS)
	0x00300210:               {MethodCollaborator},                                                                                                // External service interaction (HTTP)
	BCheckGeneratedTypeIndex: {MethodActiveChecks},
}

// burpsyMethodlessTypes are the types Burp defines methods for whose burpsy check uses none of
// them, each with the reason. Such a check is selected by type alone; every method a configuration
// enables for it is declined.
var burpsyMethodlessTypes = map[uint32]string{
	0x00100210:                  "burpsy's second-order SQL injection row decides on a planted canary's later sighting, which is none of Burp's SQL injection methods",
	0x00400110:                  "burpsy's spoofable-client-IP row reads the captured request's headers passively and sends nothing",
	ExtensionGeneratedTypeIndex: "a provenance label for findings an extension filed; burpsy has no extension mechanism and the row reads a ledger, never a target",
	0x09008000:                  "a provenance label for findings a Bambda filed; the row reads a ledger, never a target",
}

func init() {
	// Every DOM-based type Burp defines (static and dynamic analysis) is driven by the instrumented
	// browser here. Filled from Burp's own table rather than typed out, so a DOM row cannot be missed.
	for t, methods := range burpIssueDetectionMethods {
		if len(methods) == 2 && methods[0] == MethodJavaScriptDynamic && methods[1] == MethodJavaScriptStatic {
			burpsyDetectionMethods[t] = []string{MethodJavaScriptDynamic}
		}
	}
}

// infiltratorDeclineReason is why "Burp Infiltrator" never runs here, whatever the configuration says.
const infiltratorDeclineReason = "Burp Infiltrator instruments the target application with an agent that " +
	"reports which server-side APIs a payload reached; burpsy has no such agent, so this method never runs here"

// methodDeclineReason explains an enabled method burpsy's check for the type does not implement.
func methodDeclineReason(def IssueDefinition, method string) string {
	if method == MethodInfiltrator {
		return infiltratorDeclineReason
	}
	if why, ok := burpsyMethodlessTypes[def.TypeIndex]; ok {
		return why
	}
	have := burpsyDetectionMethods[def.TypeIndex]
	if len(have) == 0 {
		return fmt.Sprintf("burpsy's %s check implements none of Burp's detection methods for this type", def.Name)
	}
	return fmt.Sprintf("burpsy's %s check does not implement %q detection (it detects by %s), so this enabled method never runs here",
		def.Name, method, strings.Join(have, ", "))
}

// burpsyImplements reports whether burpsy's check for the type uses the method.
func burpsyImplements(typeIndex uint32, method string) bool {
	for _, m := range burpsyDetectionMethods[typeIndex] {
		if m == method {
			return true
		}
	}
	return false
}

// disabledMethodsFor is the set of methods the run disabled for one type. Nil when none are.
func (cfg AuditConfig) disabledMethodsFor(typeIndex uint32) map[string]bool {
	var out map[string]bool
	for _, m := range cfg.DisabledDetectionMethods {
		if m.TypeIndex != typeIndex {
			continue
		}
		if out == nil {
			out = map[string]bool{}
		}
		out[m.Method] = true
	}
	return out
}

// methodDisabledReason is the decline reason a run records when it withholds a disabled method.
const methodDisabledReason = "disabled for this issue type by the scan configuration (selected_issues detection_methods)"

// MethodDeclineLedger accumulates one audit item's detection-method declines. Records merge on
// (type, method, reason), summing the probes withheld, so a check whose four payloads were all
// withheld reads as one decline of four requests rather than four rows. Safe for concurrent use.
type MethodDeclineLedger struct {
	mu   sync.Mutex
	rows MethodDeclines
}

// NewMethodDeclineLedger returns an empty ledger.
func NewMethodDeclineLedger() *MethodDeclineLedger { return &MethodDeclineLedger{} }

// Record adds one decline, merging with an existing row for the same (type, method, reason).
func (l *MethodDeclineLedger) Record(d MethodDecline) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for i := range l.rows {
		r := &l.rows[i]
		if r.TypeIndex == d.TypeIndex && r.Method == d.Method && r.Reason == d.Reason {
			r.ProbesWithheld += d.ProbesWithheld
			return
		}
	}
	l.rows = append(l.rows, d)
}

// List returns a copy of the declines, never nil.
func (l *MethodDeclineLedger) List() MethodDeclines {
	out := MethodDeclines{}
	if l == nil {
		return out
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return append(out, l.rows...)
}

// methodDeclinesKeyCtx carries an audit item's ledger to the checks it dispatches.
type methodDeclinesKeyCtx struct{}

func withMethodDeclines(ctx context.Context, l *MethodDeclineLedger) context.Context {
	return context.WithValue(ctx, methodDeclinesKeyCtx{}, l)
}

func methodDeclinesFrom(ctx context.Context) *MethodDeclineLedger {
	if ctx == nil {
		return nil
	}
	l, _ := ctx.Value(methodDeclinesKeyCtx{}).(*MethodDeclineLedger)
	return l
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
				continue
			}
			// Enabled, and the type itself runs: if burpsy's check cannot do it, say so by name —
			// "Burp Infiltrator" above all, which has no counterpart here at all.
			if e.Enabled && !burpsyImplements(e.TypeIndex, m.Name) {
				declined = append(declined, MethodDecline{TypeIndex: e.TypeIndex, Issue: def.Name, Method: m.Name,
					Reason: methodDeclineReason(def, m.Name)})
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
//
// Then the method rule, which is Burp's own (Zwy6.java:36-75, the per-pair predicate at
// :170-184): a check is kept while ANY (type, method) pair it registers is enabled, and withheld
// only when EVERY declared method is disabled. Burpsy first withheld on any single disabled
// method, which was only unchanged while every check declared one method; with the SQL-injection
// type's five implemented methods on one check (saq3.2.1), any-single would withhold the error
// probes an operator left on. The granularity for the disabled pair is the probe gate
// (ProbeHarness.withhold): a disabled method's probes are not sent and are counted in the item's
// methods_declined, which is where Burp's own multi-method checks gate too.
func filterBySelection(checks []activeCheck, cfg AuditConfig) []activeCheck {
	checks = filterByIssueTypes(checks, cfg.IssueTypes)
	if len(cfg.DisabledIssueTypes) == 0 && len(cfg.DisabledDetectionMethods) == 0 {
		return checks
	}
	out := make([]activeCheck, 0, len(checks))
	for _, c := range checks {
		if c.typeIndex != 0 && cfg.issueTypeDisabled(c.typeIndex) {
			continue
		}
		// A check that registers types only (no methods) is selected by type alone (Zwy6), so the
		// two states — no declaration, and an empty DISABLED declaration — both read as untouched.
		if disabled := cfg.disabledMethodsFor(c.typeIndex); disabled != nil && len(c.methods) > 0 &&
			everyDisabled(c.methods, disabled) {
			continue
		}
		out = append(out, c)
	}
	return out
}

// everyDisabled reports whether nothing enabled is left: the check's registered set intersects
// the disabled set over every name, so a check whose methods are all disabled has no enabled
// (type, method) pair and is withheld whole (Zwy6).
func everyDisabled(methods []string, disabled map[string]bool) bool {
	for _, m := range methods {
		if !disabled[m] {
			return false
		}
	}
	return true
}
