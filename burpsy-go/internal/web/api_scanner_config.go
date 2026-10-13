package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/burpsy-go/burpsy/internal/scanner"
	"go.uber.org/zap"
)

// ---- Runtime scan configuration ----------------------------------------------------------------
//
// Every audit family switch and performance knob, readable and editable while the process runs.
// PUT is a partial patch: only keys present in the body change, unknown keys are refused by name,
// and the response carries the whole confirmed state so a client never has to merge. Each edit is
// persisted, because a policy that dies with the process was never really a policy.

type scannerConfigView struct {
	MaxConcurrency int `json:"max_concurrency"`
	TimeoutMs      int `json:"timeout_ms"`
	ProbeTimeoutMs int `json:"probe_timeout_ms"`

	CheckSqli               bool `json:"check_sqli"`
	CheckXss                bool `json:"check_xss"`
	CheckPathTraversal      bool `json:"check_path_traversal"`
	CheckSSRF               bool `json:"check_ssrf"`
	CheckXXE                bool `json:"check_xxe"`
	CheckJwtWeak            bool `json:"check_jwt_weak"`
	CheckJSVulns            bool `json:"check_js_vulns"`
	CheckHeaders            bool `json:"check_headers"`
	CheckCachePoisoning     bool `json:"check_cache_poisoning"`
	CheckCorpus             bool `json:"check_corpus"`
	CheckExtendedCoverage   bool `json:"check_extended_coverage"`
	CheckReflectionProbes   bool `json:"check_reflection_probes"`
	CheckHostDiscovery      bool `json:"check_host_discovery"`
	CheckResponseDependence bool `json:"check_response_dependence"`
	CheckPassivePosture     bool `json:"check_passive_posture"`
	CheckPassiveAnalysis    bool `json:"check_passive_analysis"`
	CheckActiveInjection    bool `json:"check_active_injection"`
	CheckDOM                bool `json:"check_dom"`
	CheckXSSBrowserConfirm  bool `json:"check_xss_browser_confirm"`
	CheckSSRFInBand         bool `json:"check_ssrf_in_band"`
	CheckExtendedActive     bool `json:"check_extended_active"`
	CheckOutOfBand          bool `json:"check_out_of_band"`
	CheckStored             bool `json:"check_stored"`
	CheckFileUpload         bool `json:"check_file_upload"`
	CheckJwtForgery         bool `json:"check_jwt_forgery"`
	CheckIDOR               bool `json:"check_idor"`
	// The login rate-limit and username-enumeration rows (scanner/checks_auth_logic.go), each off by
	// default, and the rate-limit check's burst size (0 = the scanner's default).
	CheckLoginRateLimit      bool `json:"check_login_rate_limit"`
	CheckUsernameEnumeration bool `json:"check_username_enumeration"`
	LoginRateLimitAttempts   int  `json:"login_rate_limit_attempts"`
	CheckSqliHeavyQuery      bool `json:"check_sqli_heavy_query"`
	CheckSqliOrBoolean       bool `json:"check_sqli_or_boolean"`
	CheckPasswordReset       bool `json:"check_password_reset"`
	// The password-reset checks' operator inputs: the test accounts they may act on, and the test
	// inbox URL ("{identity}" is replaced by the query-escaped identity).
	ResetTestIdentities    []string `json:"reset_test_identities"`
	ResetMailboxURL        string   `json:"reset_mailbox_url"`
	CheckSessionManagement bool     `json:"check_session_management"`
	// The timing-only HTTP request smuggling check (scanner/checks_smuggling.go), off by default.
	CheckRequestSmuggling bool `json:"check_request_smuggling"`
	// The Host header check (scanner/checks_host_header.go), off by default.
	CheckHostHeader bool `json:"check_host_header"`
	// The GraphQL hardening rows (scanner/checks_graphql_hardening.go), off by default.
	CheckGraphQLHardening bool `json:"check_graphql_hardening"`

	// The insecure-deserialization row (scanner/checks_deserialization.go), off by default.
	CheckInsecureDeserialization bool `json:"check_insecure_deserialization"`
	// The NoSQL injection check (scanner/checks_nosqli.go), off by default.
	CheckNoSQLInjection bool `json:"check_nosql_injection"`
	// The cross-site WebSocket hijacking check (scanner/checks_ws_hijack.go), off by default.
	CheckWebSocketHijacking bool `json:"check_websocket_hijacking"`
	// The spoofable client-IP header check (scanner/checks_client_ip.go), off by default.
	CheckClientIPSpoofing bool `json:"check_client_ip_spoofing"`
	// The server-side parameter pollution check (scanner/checks_sspp.go), off by default.
	CheckServerSideParamPollution bool `json:"check_server_side_parameter_pollution"`

	// The cookie prefix / SameSite rows (scanner/checks_cookie_attrs.go) and the subdomain-takeover row
	// (scanner/checks_takeover.go), both passive and off by default.
	CheckCookieAttributes  bool `json:"check_cookie_attributes"`
	CheckSubdomainTakeover bool `json:"check_subdomain_takeover"`
}

func scannerConfigFrom(c scanner.ScanConfig) scannerConfigView {
	return scannerConfigView{
		MaxConcurrency: c.MaxConcurrency,
		TimeoutMs:      int(c.Timeout / time.Millisecond),
		ProbeTimeoutMs: int(c.ProbeTimeout / time.Millisecond),

		CheckSqli:               c.CheckSqli,
		CheckXss:                c.CheckXss,
		CheckPathTraversal:      c.CheckPathTraversal,
		CheckSSRF:               c.CheckSSRF,
		CheckXXE:                c.CheckXXE,
		CheckJwtWeak:            c.CheckJwtWeak,
		CheckJSVulns:            c.CheckJSVulns,
		CheckHeaders:            c.CheckHeaders,
		CheckCachePoisoning:     c.CheckCachePoisoning,
		CheckCorpus:             c.CheckCorpus,
		CheckExtendedCoverage:   c.CheckExtendedCoverage,
		CheckReflectionProbes:   c.CheckReflectionProbes,
		CheckHostDiscovery:      c.CheckHostDiscovery,
		CheckResponseDependence: c.CheckResponseDependence,
		CheckPassivePosture:     c.CheckPassivePosture,
		CheckPassiveAnalysis:    c.CheckPassiveAnalysis,
		CheckActiveInjection:    c.CheckActiveInjection,
		CheckDOM:                c.CheckDOM,
		CheckXSSBrowserConfirm:  c.CheckXSSBrowserConfirm,
		CheckSSRFInBand:         c.CheckSSRFInBand,
		CheckExtendedActive:     c.CheckExtendedActive,
		CheckOutOfBand:          c.CheckOutOfBand,
		CheckStored:             c.CheckStored,
		CheckFileUpload:         c.CheckFileUpload,
		CheckJwtForgery:         c.CheckJwtForgery,
		CheckIDOR:               c.CheckIDOR,

		CheckLoginRateLimit:      c.CheckLoginRateLimit,
		CheckUsernameEnumeration: c.CheckUsernameEnumeration,
		CheckGraphQLHardening:    c.CheckGraphQLHardening,
		LoginRateLimitAttempts:   c.LoginRateLimitAttempts,
		CheckSqliHeavyQuery:      c.CheckSqliHeavyQuery,
		CheckSqliOrBoolean:       c.CheckSqliOrBoolean,
		CheckPasswordReset:       c.CheckPasswordReset,
		ResetTestIdentities:      append([]string{}, c.ResetTestIdentities...),
		ResetMailboxURL:          c.ResetMailboxURL,
		CheckSessionManagement:   c.CheckSessionManagement,
		CheckRequestSmuggling:    c.CheckRequestSmuggling,
		CheckHostHeader:          c.CheckHostHeader,

		CheckInsecureDeserialization:  c.CheckInsecureDeserialization,
		CheckNoSQLInjection:           c.CheckNoSQLInjection,
		CheckWebSocketHijacking:       c.CheckWebSocketHijacking,
		CheckClientIPSpoofing:         c.CheckClientIPSpoofing,
		CheckServerSideParamPollution: c.CheckServerSideParamPollution,

		CheckCookieAttributes:  c.CheckCookieAttributes,
		CheckSubdomainTakeover: c.CheckSubdomainTakeover,
	}
}

// boolKeys and intKeys are the whole writable surface, named in one place: a family that gains a
// switch joins this map or it does not exist on the wire, which keeps the endpoint's honesty
// mechanical rather than a matter of remembering to update a doc.
var scannerConfigBoolKeys = map[string]func(v *scannerConfigView) *bool{
	"check_sqli":                 func(v *scannerConfigView) *bool { return &v.CheckSqli },
	"check_xss":                  func(v *scannerConfigView) *bool { return &v.CheckXss },
	"check_path_traversal":       func(v *scannerConfigView) *bool { return &v.CheckPathTraversal },
	"check_ssrf":                 func(v *scannerConfigView) *bool { return &v.CheckSSRF },
	"check_xxe":                  func(v *scannerConfigView) *bool { return &v.CheckXXE },
	"check_jwt_weak":             func(v *scannerConfigView) *bool { return &v.CheckJwtWeak },
	"check_js_vulns":             func(v *scannerConfigView) *bool { return &v.CheckJSVulns },
	"check_headers":              func(v *scannerConfigView) *bool { return &v.CheckHeaders },
	"check_cache_poisoning":      func(v *scannerConfigView) *bool { return &v.CheckCachePoisoning },
	"check_corpus":               func(v *scannerConfigView) *bool { return &v.CheckCorpus },
	"check_dom":                  func(v *scannerConfigView) *bool { return &v.CheckDOM },
	"check_xss_browser_confirm":  func(v *scannerConfigView) *bool { return &v.CheckXSSBrowserConfirm },
	"check_ssrf_in_band":         func(v *scannerConfigView) *bool { return &v.CheckSSRFInBand },
	"check_extended_coverage":    func(v *scannerConfigView) *bool { return &v.CheckExtendedCoverage },
	"check_reflection_probes":    func(v *scannerConfigView) *bool { return &v.CheckReflectionProbes },
	"check_host_discovery":       func(v *scannerConfigView) *bool { return &v.CheckHostDiscovery },
	"check_response_dependence":  func(v *scannerConfigView) *bool { return &v.CheckResponseDependence },
	"check_passive_posture":      func(v *scannerConfigView) *bool { return &v.CheckPassivePosture },
	"check_passive_analysis":     func(v *scannerConfigView) *bool { return &v.CheckPassiveAnalysis },
	"check_active_injection":     func(v *scannerConfigView) *bool { return &v.CheckActiveInjection },
	"check_extended_active":      func(v *scannerConfigView) *bool { return &v.CheckExtendedActive },
	"check_out_of_band":          func(v *scannerConfigView) *bool { return &v.CheckOutOfBand },
	"check_stored":               func(v *scannerConfigView) *bool { return &v.CheckStored },
	"check_file_upload":          func(v *scannerConfigView) *bool { return &v.CheckFileUpload },
	"check_jwt_forgery":          func(v *scannerConfigView) *bool { return &v.CheckJwtForgery },
	"check_idor":                 func(v *scannerConfigView) *bool { return &v.CheckIDOR },
	"check_login_rate_limit":     func(v *scannerConfigView) *bool { return &v.CheckLoginRateLimit },
	"check_username_enumeration": func(v *scannerConfigView) *bool { return &v.CheckUsernameEnumeration },
	"check_graphql_hardening":    func(v *scannerConfigView) *bool { return &v.CheckGraphQLHardening },
	"check_sqli_heavy_query":     func(v *scannerConfigView) *bool { return &v.CheckSqliHeavyQuery },
	"check_sqli_or_boolean":      func(v *scannerConfigView) *bool { return &v.CheckSqliOrBoolean },
	"check_password_reset":       func(v *scannerConfigView) *bool { return &v.CheckPasswordReset },
	"check_session_management":   func(v *scannerConfigView) *bool { return &v.CheckSessionManagement },
	"check_request_smuggling":    func(v *scannerConfigView) *bool { return &v.CheckRequestSmuggling },
	"check_host_header":          func(v *scannerConfigView) *bool { return &v.CheckHostHeader },

	"check_insecure_deserialization":        func(v *scannerConfigView) *bool { return &v.CheckInsecureDeserialization },
	"check_nosql_injection":                 func(v *scannerConfigView) *bool { return &v.CheckNoSQLInjection },
	"check_websocket_hijacking":             func(v *scannerConfigView) *bool { return &v.CheckWebSocketHijacking },
	"check_client_ip_spoofing":              func(v *scannerConfigView) *bool { return &v.CheckClientIPSpoofing },
	"check_server_side_parameter_pollution": func(v *scannerConfigView) *bool { return &v.CheckServerSideParamPollution },
	"check_cookie_attributes":               func(v *scannerConfigView) *bool { return &v.CheckCookieAttributes },
	"check_subdomain_takeover":              func(v *scannerConfigView) *bool { return &v.CheckSubdomainTakeover },
}

var scannerConfigIntMSKeys = map[string]func(v *scannerConfigView) *int{
	"timeout_ms":       func(v *scannerConfigView) *int { return &v.TimeoutMs },
	"probe_timeout_ms": func(v *scannerConfigView) *int { return &v.ProbeTimeoutMs },
}

func (s *Server) handleScannerConfig(w http.ResponseWriter, r *http.Request) {
	// Method first: a verb this route does not implement must answer 405 even in a process with no
	// scanner, because "wrong method" and "no scanner" are different facts and the 405 contract is
	// what the manifest test holds the route to.
	switch r.Method {
	case http.MethodGet:
		if s.wiredScanner() == nil {
			http.Error(w, "No scanner is configured in this process", http.StatusServiceUnavailable)
			return
		}
		writeJSON(w, http.StatusOK, scannerConfigFrom(s.wiredScanner().ConfigSnapshot()))
	case http.MethodPut:
		s.applyScannerConfigPatch(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) applyScannerConfigPatch(w http.ResponseWriter, r *http.Request) {
	var patch map[string]json.RawMessage
	if err := requestJSON(w, r, nil).Decode(&patch); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	// After the decode so the schema sweep reaches it (burpsy-react-ui-3zw0); a malformed body is a
	// 400 whatever this process carries.
	if s.wiredScanner() == nil {
		http.Error(w, "No scanner is configured in this process", http.StatusServiceUnavailable)
		return
	}

	view := scannerConfigFrom(s.wiredScanner().ConfigSnapshot())
	for key, raw := range patch {
		if get := scannerConfigBoolKeys[key]; get != nil {
			var b bool
			if err := json.Unmarshal(raw, &b); err != nil {
				http.Error(w, fmt.Sprintf("key %q wants true or false", key), http.StatusBadRequest)
				return
			}
			*get(&view) = b
			continue
		}
		if get := scannerConfigIntMSKeys[key]; get != nil {
			var n int
			if err := json.Unmarshal(raw, &n); err != nil || n < 0 {
				http.Error(w, fmt.Sprintf("key %q wants a non-negative number of milliseconds", key), http.StatusBadRequest)
				return
			}
			*get(&view) = n
			continue
		}
		if key == "login_rate_limit_attempts" {
			// 0 restores the scanner's default; anything else must be a burst the check will actually
			// send, so an out-of-range value is refused rather than silently clamped.
			var n int
			if err := json.Unmarshal(raw, &n); err != nil || (n != 0 && (n < scanner.MinLoginRateLimitAttempts || n > scanner.MaxLoginRateLimitAttempts)) {
				http.Error(w, fmt.Sprintf("key %q wants 0 (the default, %d) or an integer from %d to %d", key,
					scanner.DefaultLoginRateLimitAttempts, scanner.MinLoginRateLimitAttempts, scanner.MaxLoginRateLimitAttempts), http.StatusBadRequest)
				return
			}
			view.LoginRateLimitAttempts = n
			continue
		}
		if key == "reset_test_identities" {
			var ids []string
			if err := json.Unmarshal(raw, &ids); err != nil {
				http.Error(w, fmt.Sprintf("key %q wants a list of strings", key), http.StatusBadRequest)
				return
			}
			clean := []string{}
			for _, id := range ids {
				if id = strings.TrimSpace(id); id != "" {
					clean = append(clean, id)
				}
			}
			view.ResetTestIdentities = clean
			continue
		}
		if key == "reset_mailbox_url" {
			var u string
			if err := json.Unmarshal(raw, &u); err != nil {
				http.Error(w, fmt.Sprintf("key %q wants a string", key), http.StatusBadRequest)
				return
			}
			if u = strings.TrimSpace(u); u != "" {
				pu, err := url.Parse(strings.ReplaceAll(u, "{identity}", "x"))
				if err != nil || (pu.Scheme != "http" && pu.Scheme != "https") || pu.Host == "" {
					http.Error(w, fmt.Sprintf("key %q wants an absolute http(s) URL", key), http.StatusBadRequest)
					return
				}
			}
			view.ResetMailboxURL = u
			continue
		}
		if key == "max_concurrency" {
			var n int
			if err := json.Unmarshal(raw, &n); err != nil || n < 1 {
				http.Error(w, fmt.Sprintf("key %q wants an integer of at least 1", key), http.StatusBadRequest)
				return
			}
			view.MaxConcurrency = n
			continue
		}
		http.Error(w, fmt.Sprintf("unknown scan configuration key %q", key), http.StatusBadRequest)
		return
	}

	confirmed := s.wiredScanner().UpdateScanConfig(func(c *scanner.ScanConfig) {
		c.MaxConcurrency = view.MaxConcurrency
		c.Timeout = time.Duration(view.TimeoutMs) * time.Millisecond
		c.ProbeTimeout = time.Duration(view.ProbeTimeoutMs) * time.Millisecond
		c.CheckSqli = view.CheckSqli
		c.CheckXss = view.CheckXss
		c.CheckPathTraversal = view.CheckPathTraversal
		c.CheckSSRF = view.CheckSSRF
		c.CheckXXE = view.CheckXXE
		c.CheckJwtWeak = view.CheckJwtWeak
		c.CheckJSVulns = view.CheckJSVulns
		c.CheckHeaders = view.CheckHeaders
		c.CheckCachePoisoning = view.CheckCachePoisoning
		c.CheckCorpus = view.CheckCorpus
		c.CheckExtendedCoverage = view.CheckExtendedCoverage
		c.CheckReflectionProbes = view.CheckReflectionProbes
		c.CheckHostDiscovery = view.CheckHostDiscovery
		c.CheckResponseDependence = view.CheckResponseDependence
		c.CheckPassivePosture = view.CheckPassivePosture
		c.CheckPassiveAnalysis = view.CheckPassiveAnalysis
		c.CheckActiveInjection = view.CheckActiveInjection
		c.CheckDOM = view.CheckDOM
		c.CheckXSSBrowserConfirm = view.CheckXSSBrowserConfirm
		c.CheckSSRFInBand = view.CheckSSRFInBand
		c.CheckExtendedActive = view.CheckExtendedActive
		c.CheckOutOfBand = view.CheckOutOfBand
		c.CheckStored = view.CheckStored
		c.CheckFileUpload = view.CheckFileUpload
		c.CheckJwtForgery = view.CheckJwtForgery
		c.CheckIDOR = view.CheckIDOR
		c.CheckLoginRateLimit = view.CheckLoginRateLimit
		c.CheckUsernameEnumeration = view.CheckUsernameEnumeration
		c.CheckGraphQLHardening = view.CheckGraphQLHardening
		c.LoginRateLimitAttempts = view.LoginRateLimitAttempts
		c.CheckSqliHeavyQuery = view.CheckSqliHeavyQuery
		c.CheckSqliOrBoolean = view.CheckSqliOrBoolean
		c.CheckPasswordReset = view.CheckPasswordReset
		c.ResetTestIdentities = append([]string(nil), view.ResetTestIdentities...)
		c.ResetMailboxURL = view.ResetMailboxURL
		c.CheckSessionManagement = view.CheckSessionManagement
		c.CheckRequestSmuggling = view.CheckRequestSmuggling
		c.CheckHostHeader = view.CheckHostHeader
		c.CheckInsecureDeserialization = view.CheckInsecureDeserialization
		c.CheckNoSQLInjection = view.CheckNoSQLInjection
		c.CheckWebSocketHijacking = view.CheckWebSocketHijacking
		c.CheckClientIPSpoofing = view.CheckClientIPSpoofing
		c.CheckServerSideParamPollution = view.CheckServerSideParamPollution
		c.CheckCookieAttributes = view.CheckCookieAttributes
		c.CheckSubdomainTakeover = view.CheckSubdomainTakeover
	})
	if s.persist != nil {
		if err := s.persist.SaveScanConfig(confirmed); err != nil {
			// The live scanner already has the edit; persistence failing is reported and still
			// answers 200, because the operator's immediate intent took effect.
			s.logger.Warn("scan config persist failed", zap.Error(err))
		}
	}
	writeJSON(w, http.StatusOK, scannerConfigFrom(confirmed))
}
