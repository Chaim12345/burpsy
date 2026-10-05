package scanner

// Pluggable response analyzers, modelled on PSFuzz's post-request module pipeline: each module
// inspects one captured response independently of the others and of the check registry, and returns
// whatever it found. A module that finds nothing returns a nil slice — the same "nil is a clean
// result, not a refusal" convention CheckRunner uses (check_contract.go) — so a caller can tell
// "looked, found nothing" from a module that panicked or was skipped.
//
// These are deliberately not CheckDescriptors: a ResponseModule has no catalog issue to resolve by
// name, no invasiveness tier (it sends nothing, it only reads a response the audit engine already
// captured), and no insertion point. Wiring a module into a scan is a matter of calling
// RunResponseModules once per captured response body/header pair; nothing here dials out.

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/burpsy-go/burpsy/internal/core"
)

// ResponseFinding is one observation a ResponseModule makes about a single response. It is a
// smaller, sibling shape to Finding (scanner.go): a module has no exchange, no catalog issue name to
// resolve remediation from, and no insertion point — only a response it read.
type ResponseFinding struct {
	// Module is the producing module's Name(), so a caller aggregating findings from several
	// modules can still tell them apart.
	Module string
	// Name is a short, human-readable finding title, matching the catalog's naming style
	// ("AWS access key ID exposed") without requiring a catalog entry to exist.
	Name string
	// Severity is one of Burp's own scale: "high", "medium", "low", "info".
	Severity string
	// Confidence is one of Burp's own scale: "certain", "firm", "tentative".
	Confidence string
	// Detail is a one-line human-readable elaboration.
	Detail string
	// Evidence is the (possibly redacted) matched text that justifies the finding.
	Evidence string
}

// ResponseModule analyzes one captured response and reports what it found. Analyze must not
// mutate response or headers, and must not perform network or storage I/O — a module is a pure
// classifier over bytes it is handed, mirroring the analyze*Evidence functions in
// checks_headers.go and checks_cache.go.
type ResponseModule interface {
	// Name identifies the module in aggregated output.
	Name() string
	// Analyze inspects one response body and its headers (canonical lowercase header name ->
	// single joined value, matching how the rest of this package's readers use headers) and
	// returns every finding it produced. A nil/empty return means a clean result.
	Analyze(response []byte, headers map[string]string) []ResponseFinding
}

// DefaultResponseModules returns the standard module set in a stable order: secrets first (the
// highest-severity findings), then auth posture, then fingerprinting (lowest severity, informational
// only). New modules append here rather than reordering the existing three, so a caller that keeps
// only the first N findings does not silently lose a module's coverage after an unrelated change.
func DefaultResponseModules() []ResponseModule {
	return []ResponseModule{
		&SecretsModule{},
		&AuthModule{},
		&FingerprintModule{},
	}
}

// RunResponseModules runs every module in modules against one response and concatenates their
// findings in module order. A nil entry in modules is skipped rather than panicking, so a caller
// building its module list from a partially-populated config cannot crash the scan on a nil slot.
func RunResponseModules(modules []ResponseModule, response []byte, headers map[string]string) []ResponseFinding {
	var out []ResponseFinding
	for _, m := range modules {
		if m == nil {
			continue
		}
		out = append(out, m.Analyze(response, headers)...)
	}
	return out
}

// ---------------------------------------------------------------------------
// Secrets module
// ---------------------------------------------------------------------------

// SecretsModule detects credential material leaked into a response body: AWS access/secret keys,
// JWTs, generic API keys, and GCP/Azure cloud credentials. It addresses the generic
// secret/credential detection gap tracked as burpsy-react-ui-8j0d.
type SecretsModule struct{}

func (m *SecretsModule) Name() string { return "secrets" }

var (
	// awsAccessKeyIDRe matches an AWS access key ID. The AKIA/ASIA/etc. prefixes are the
	// documented AWS key-class markers; 16 trailing base32-ish characters is the fixed shape.
	awsAccessKeyIDRe = regexp.MustCompile(`\b(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b`)
	// awsSecretKeyRe matches a labelled AWS secret access key: a 40-character base64-alphabet
	// value assigned to a key/variable whose name mentions "secret" and "key" (or "access" and
	// "key"), which is how these leak in dumped config files and .env content.
	awsSecretKeyRe = regexp.MustCompile(`(?i)aws[a-z_]*secret[a-z_]*key[a-z_]*["']?\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})["']?`)
	// jwtRe matches a three-part JWT. "eyJ" is the base64 encoding of `{"` — every JWT header
	// starts with it because every JWT header is a JSON object.
	jwtRe = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\b`)
	// genericAPIKeyRe matches a labelled generic API key: a variable/JSON-key whose name is some
	// spelling of "api key" or "apikey", assigned a token-shaped value.
	genericAPIKeyRe = regexp.MustCompile(`(?i)api[_-]?key["']?\s*[:=]\s*["']([A-Za-z0-9_\-]{16,64})["']`)
	// gcpServiceAccountRe matches the distinctive shape of a GCP service-account JSON key file:
	// the "type": "service_account" field is present in every such file and in essentially
	// nothing else.
	gcpServiceAccountRe = regexp.MustCompile(`"type"\s*:\s*"service_account"`)
	// azureStorageConnStringRe matches an Azure Storage connection string, which carries its
	// account key in cleartext as a labelled field.
	azureStorageConnStringRe = regexp.MustCompile(`(?i)DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{20,}`)
)

func (m *SecretsModule) Analyze(response []byte, _ map[string]string) []ResponseFinding {
	body := string(response)
	var out []ResponseFinding

	if matches := awsAccessKeyIDRe.FindAllString(body, -1); len(matches) > 0 {
		out = append(out, ResponseFinding{
			Module:     m.Name(),
			Name:       "AWS access key ID exposed",
			Severity:   "high",
			Confidence: "firm",
			Detail:     fmt.Sprintf("%d AWS access key ID(s) found in the response body", len(matches)),
			// Not redacted, and deliberately so — an AWS access key ID is a public identifier (it
			// appears in IAM listings and CloudTrail), so echoing it costs nothing and the operator
			// needs it to know WHICH key leaked. The secret half on the branch below is a different
			// matter and IS redacted. Stating the asymmetry here rather than leaving one branch
			// unreconciled: a reader checking whether this file honours its own "never reproduce the
			// whole secret" rule needs to see that it does in both directions, not infer it.
			Evidence: matches[0],
		})
	}

	if match := awsSecretKeyRe.FindStringSubmatch(body); match != nil {
		out = append(out, ResponseFinding{
			Module:     m.Name(),
			Name:       "AWS secret access key exposed",
			Severity:   "high",
			Confidence: "tentative",
			Detail:     "a labelled AWS secret access key was found in the response body",
			Evidence:   redactSecret(match[1]),
		})
	}

	if matches := jwtRe.FindAllString(body, -1); len(matches) > 0 {
		out = append(out, ResponseFinding{
			Module:     m.Name(),
			Name:       "JSON Web Token exposed",
			Severity:   "medium",
			Confidence: "firm",
			Detail:     fmt.Sprintf("%d JWT(s) found in the response body", len(matches)),
			Evidence:   redactSecret(matches[0]),
		})
	}

	if match := genericAPIKeyRe.FindStringSubmatch(body); match != nil {
		out = append(out, ResponseFinding{
			Module:     m.Name(),
			Name:       "API key exposed",
			Severity:   "medium",
			Confidence: "tentative",
			Detail:     "a labelled API key was found in the response body",
			Evidence:   redactSecret(match[1]),
		})
	}

	if gcpServiceAccountRe.MatchString(body) {
		out = append(out, ResponseFinding{
			Module:     m.Name(),
			Name:       "GCP service account key exposed",
			Severity:   "high",
			Confidence: "firm",
			Detail:     "a GCP service account JSON key (\"type\": \"service_account\") was found in the response body",
			Evidence:   `"type": "service_account"`,
		})
	}

	if match := azureStorageConnStringRe.FindString(body); match != "" {
		out = append(out, ResponseFinding{
			Module:     m.Name(),
			Name:       "Azure storage account key exposed",
			Severity:   "high",
			Confidence: "firm",
			Detail:     "an Azure Storage connection string carrying an AccountKey was found in the response body",
			Evidence:   redactSecret(match),
		})
	}

	return out
}

// redactSecret keeps a short prefix/suffix and blanks the middle, so evidence in a finding proves a
// match happened without reproducing the whole secret in logs or reports.
func redactSecret(s string) string {
	const keep = 4
	if len(s) <= keep*2 {
		return "[redacted]"
	}
	return s[:keep] + "..." + s[len(s)-keep:]
}

// ---------------------------------------------------------------------------
// Auth module
// ---------------------------------------------------------------------------

// AuthModule detects authentication-related response posture: HTML login forms, 401/403 status,
// redirect-to-login responses, and session cookies being set.
type AuthModule struct{}

func (m *AuthModule) Name() string { return "auth" }

var (
	// loginFormRe matches an HTML <form>...</form> that contains a password input, without
	// requiring the password input to be the form's only field or its last one.
	loginFormRe = regexp.MustCompile(`(?is)<form\b[^>]*>.*?<input\b[^>]*\btype\s*=\s*["']?password["']?.*?</form>`)
	// redirectToLoginRe matches a Location header value that names a login/sign-in path.
	redirectToLoginRe = regexp.MustCompile(`(?i)(login|log-in|signin|sign-in)`)
	// sessionCookieRe matches the common session-cookie names frameworks assign: JSESSIONID
	// (Java), PHPSESSID (PHP), ASP.NET_SessionId (ASP.NET), connect.sid (Express), and any cookie
	// whose name literally contains "session" or is the bare "sid".
	sessionCookieRe = regexp.MustCompile(`(?i)\b(jsessionid|phpsessid|asp\.net_sessionid|connect\.sid|[a-z_]*session[a-z_]*id|sid)\s*=`)
)

func (m *AuthModule) Analyze(response []byte, headers map[string]string) []ResponseFinding {
	body := string(response)
	var out []ResponseFinding

	if loginFormRe.MatchString(body) {
		out = append(out, ResponseFinding{
			Module:     m.Name(),
			Name:       "Login form detected",
			Severity:   "info",
			Confidence: "firm",
			Detail:     "an HTML form containing a password input field was found in the response body",
			Evidence:   "<form> ... <input type=\"password\"> ... </form>",
		})
	}

	switch code := responseStatusCode(response, headers); code {
	case 401:
		out = append(out, ResponseFinding{
			Module:     m.Name(),
			Name:       "Authentication required",
			Severity:   "info",
			Confidence: "certain",
			Detail:     "the response status was 401 Unauthorized",
			Evidence:   "HTTP 401",
		})
	case 403:
		out = append(out, ResponseFinding{
			Module:     m.Name(),
			Name:       "Access forbidden",
			Severity:   "info",
			Confidence: "certain",
			Detail:     "the response status was 403 Forbidden",
			Evidence:   "HTTP 403",
		})
	}

	if loc := headerLookupFold(headers, "location"); loc != "" && redirectToLoginRe.MatchString(loc) {
		out = append(out, ResponseFinding{
			Module:     m.Name(),
			Name:       "Redirect to login page",
			Severity:   "info",
			Confidence: "firm",
			Detail:     "the response redirected to a path that names a login/sign-in page",
			Evidence:   fmt.Sprintf("Location: %s", loc),
		})
	}

	if cookie := headerLookupFold(headers, headerSetCookie); cookie != "" && sessionCookieRe.MatchString(cookie) {
		name, _ := splitCookie(cookie)
		out = append(out, ResponseFinding{
			Module:     m.Name(),
			Name:       "Session cookie observed",
			Severity:   "info",
			Confidence: "firm",
			Detail:     "the response set a cookie whose name matches a common session-cookie pattern",
			Evidence:   fmt.Sprintf("Set-Cookie: %s=...", name),
		})
	}

	return out
}

// responseStatusCode resolves the response status code from either a "status" header entry
// (however the caller chose to surface it — the raw bytes reader in this package never assigns one
// under that key, so a caller populating headers from a higher-level Response type can still pass
// it through) or the HTTP status line at the top of the raw response bytes. Returns 0 when neither
// source parses, which the switch above simply does not match — a module must not claim 401/403 it
// could not actually confirm.
func responseStatusCode(response []byte, headers map[string]string) int {
	if v := headerLookupFold(headers, "status"); v != "" {
		if code, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			return code
		}
	}
	line := string(response)
	if i := strings.IndexAny(line, "\r\n"); i >= 0 {
		line = line[:i]
	}
	fields := strings.Fields(line)
	if len(fields) >= 2 && strings.HasPrefix(fields[0], "HTTP/") {
		if code, err := strconv.Atoi(fields[1]); err == nil {
			return code
		}
	}
	return 0
}

// ---------------------------------------------------------------------------
// Fingerprint module
// ---------------------------------------------------------------------------

// FingerprintModule identifies web servers, frameworks, CMSes, and languages from response headers
// and body. It is a thin wrapper around Fingerprint (infra_fingerprint.go), which already carries
// the full Wappalyzer signature corpus — reusing it here means this module recognises whatever that
// corpus recognises (nginx/Apache/IIS, Express/Django/Rails, WordPress/Drupal, PHP/Python/Node.js,
// and everything else Wappalyzer ships) instead of a hand-rolled subset that goes stale.
type FingerprintModule struct{}

func (m *FingerprintModule) Name() string { return "fingerprint" }

func (m *FingerprintModule) Analyze(response []byte, headers map[string]string) []ResponseFinding {
	// Fingerprint takes net/http-shaped headers (name -> all values); this module's headers map
	// is name -> single joined value, so each entry becomes a one-element slice.
	hdrs := make(map[string][]string, len(headers))
	for k, v := range headers {
		hdrs[k] = []string{v}
	}

	techs, err := Fingerprint(hdrs, response)
	if err != nil || len(techs) == 0 {
		return nil
	}

	out := make([]ResponseFinding, 0, len(techs))
	for _, t := range techs {
		detail := t.String()
		if !t.HasVersion() {
			detail = t.Name + " (version unknown)"
		}
		out = append(out, ResponseFinding{
			Module:     m.Name(),
			Name:       "Technology detected: " + t.Name,
			Severity:   "info",
			Confidence: "firm",
			Detail:     detail,
			Evidence:   strings.Join(t.Categories, ", "),
		})
	}
	return out
}

// moduleFindings runs the configured response modules over one captured exchange's response and
// translates what they report into the package's Finding shape, so a module's output is indexed,
// stored and surfaced by exactly the path every other finding takes.
//
// The translation exists because a ResponseFinding is deliberately the SMALLER shape: no catalog
// issue name to resolve remediation from, no insertion point, no exchange. Appending one directly
// to a []Finding would compile and produce a row carrying no exchange — unreachable from history,
// un-deduplicated, and invisible to every view that joins findings to exchanges. The module's
// Detail becomes Description and its Evidence is carried as-is, which matters: that is the field
// redactSecret writes the redacted excerpt into, and a translation that dropped it would throw
// away the one piece of evidence an operator needs.
//
// The response body is read back out of the store rather than carried in memory, because the whole
// package works from an indexed exchange (see ScanExchange) and holding a copy of every response
// body for the length of a scan is exactly the cost model this codebase refuses. An exchange with
// no readable response yields no module findings and no error: a module that cannot read its input
// has looked at nothing, which is not a finding.
func moduleFindings(store *core.TrafficStore, ex *core.Exchange, modules []ResponseModule) []*Finding {
	if store == nil || ex == nil || ex.Response == nil || len(modules) == 0 {
		return nil
	}
	msg, err := store.Get(*ex.Response)
	if err != nil {
		return nil
	}
	headers := make(map[string]string)
	for _, name := range []string{"Server", "X-Powered-By", "Content-Type", "Location", "Set-Cookie"} {
		if v := msg.Header(name); len(v) > 0 {
			headers[name] = string(v)
		}
	}
	raw := RunResponseModules(modules, msg.Body(), headers)
	if len(raw) == 0 {
		return nil
	}
	out := make([]*Finding, 0, len(raw))
	for _, f := range raw {
		// Evidence rides its own field, which core grew for exactly this (burpsy-react-ui-cx31). It
		// used to be concatenated into Description as a workaround for core having nowhere to put
		// it, which meant every stored module finding carried the excerpt twice — once in its own
		// place and once glued to the prose. That duplication was visible in the data and is gone.
		out = append(out, &Finding{
			Name:        f.Name,
			Severity:    f.Severity,
			Confidence:  f.Confidence,
			Description: f.Detail,
			Evidence:    f.Evidence,
			ExchangeID:  ex.ID,
		})
	}
	return out
}
