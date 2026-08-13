package scanner

// infra_coverage.go is the machine-readable map from an infrastructure primitive to the
// catalog issues whose decline reason that primitive answers. It exists so
// docs/SCANNER-INFRA.md cannot drift from the code: TestInfraPrimitiveMappingIsExhaustive
// resolves every issue name here against the shipped catalog, and
// TestNoDeclineReasonCitesAnAvailablePrimitive fails if a declined row still claims a
// capability listed here as built.
//
// # What "unblocks" means, and what it does not
//
// A row appears here only when a primitive in this repository directly supplies the
// capability that row's DeclineReason names as missing. It does NOT mean the check is
// implemented: every issue named here is still an explicitly declined row, still counted
// as declined, and still absent from any scan result. The distinction is the point —
// "we now have the machinery" and "we now detect this" are different claims, and
// conflating them is exactly the dishonest counting this project forbids.
//
// # Why some obviously-related rows are deliberately absent
//
// The primitive briefs targeted a wider row set than shipped. Rows are omitted here when
// no exported function actually provides their discriminator, even though a sibling row in
// the same family is covered:
//
//   - "Cacheable HTTPS response", "Unencrypted communications", "Strict transport security
//     not enforced", "Mixed content", "Hidden HTTP 2": these share the TLS row's old
//     reason text, but their gaps are response-header and subresource analysis, which
//     internal/tlsprobe does not perform — it analyses the handshake and certificate.
//
// Listing those would make the guard test demand a reason rewrite that would then be a
// lie. They stay declined with their original reasons until a primitive genuinely covers
// them.
type InfraPrimitive struct {
	// Name is the primitive's stable identifier, also used as the section anchor in
	// docs/SCANNER-INFRA.md.
	Name string
	// File is where the primitive lives, relative to the module root.
	File string
	// StaleReasonPhrases are the substrings a DeclineReason can no longer honestly
	// contain now that this primitive exists. The guard test searches every declined
	// row for these.
	StaleReasonPhrases []string
	// UnblockedIssues are catalog issue Names (resolved against ByName) whose decline
	// reason this primitive answers, and which are STILL declined.
	UnblockedIssues []string
	// WiredIssues are rows this primitive's machinery now actually detects — they have a
	// native evaluator and are no longer declined. Kept separate from UnblockedIssues so
	// the accounting cannot blur "we have the machinery" into "we detect this".
	WiredIssues []string
}

// InfraPrimitives is the complete inventory. Adding a primitive means adding a row here;
// the tests then force the doc and the decline reasons to agree with it.
var InfraPrimitives = []InfraPrimitive{
	{
		Name:               "csp-parser",
		File:               "internal/scanner/infra_csp.go",
		StaleReasonPhrases: []string{"burpsy has no native CSP evaluator"},
		UnblockedIssues:    nil,
		WiredIssues: []string{
			"Content security policy: allowlisted script resources",
			"Content security policy: allows untrusted script execution",
			"Content security policy: allows untrusted style execution",
			"Content security policy: malformed syntax",
			"Content security policy: allows form hijacking",
		},
	},
	{
		Name:               "crossdomain-policy-parser",
		File:               "internal/scanner/infra_crossdomain.go",
		StaleReasonPhrases: []string{"burpsy has no native cross-domain-policy analyzer"},
		UnblockedIssues:    nil,
		WiredIssues: []string{
			"Flash cross-domain policy",
			"Silverlight cross-domain policy",
		},
	},
	{
		Name:               "viewstate-decoder",
		File:               "internal/scanner/infra_viewstate.go",
		StaleReasonPhrases: []string{"burpsy has no native ViewState evaluator"},
		UnblockedIssues:    nil,
		WiredIssues: []string{
			"ASP.NET ViewState without MAC enabled",
		},
	},
	{
		Name:               "serialized-object-recogniser",
		File:               "internal/scanner/infra_viewstate.go",
		StaleReasonPhrases: []string{"burpsy has no native serialized-object evaluator"},
		UnblockedIssues:    nil,
		WiredIssues: []string{
			"Serialized object in HTTP message",
		},
	},
	{
		Name:               "cookie-security-analyser",
		File:               "internal/scanner/infra_passive.go",
		StaleReasonPhrases: []string{"Passive cookie / header security analysis"},
		UnblockedIssues:    nil,
		WiredIssues: []string{
			"TLS cookie without secure flag set",
			"Cookie scoped to parent domain",
			"Cookie without HttpOnly flag set",
			"Session token in URL",
		},
	},
	{
		Name: "header-attribute-analyser",
		File: "internal/scanner/infra_passive.go",
		// Deliberately NOT claiming the whole "Passive response / header attribute
		// analysis" phrase: several rows carrying it have no detector here (see the
		// file comment), so claiming the phrase would force a dishonest rewrite of
		// those rows.
		StaleReasonPhrases: nil,
		UnblockedIssues:    nil,
		WiredIssues: []string{
			"Spoofable client IP address",
			"Cross-domain script include",
			"Frameable response (potential Clickjacking)",
			"Browser cross-site scripting filter disabled",
			"Base64-encoded data in parameter",
			"HTML does not specify charset",
			"HTML uses unrecognized charset",
			"Content type incorrectly stated",
		},
	},
	{
		Name:               "disclosure-pattern-bank",
		File:               "internal/scanner/infra_passive.go",
		StaleReasonPhrases: []string{"Passive information-disclosure scan for this indicator is not implemented"},
		UnblockedIssues:    nil,
		WiredIssues: []string{
			"Database connection string disclosed",
			"Source code disclosure",
			"Directory listing",
			"Email addresses disclosed",
			"Private IP addresses disclosed",
			"Social security numbers disclosed",
			"Credit card numbers disclosed",
			"Private key disclosed",
			"Json Web Key Set disclosed",
		},
	},
	{
		Name:               "smtp-mail-header-evaluator",
		File:               "internal/scanner/infra_smtp.go",
		StaleReasonPhrases: []string{"burpsy has no native mail-header evaluator"},
		UnblockedIssues:    nil,
		WiredIssues:        []string{"SMTP header injection"},
	},
	{
		Name:               "jwt-forgery",
		File:               "internal/scanner/infra_jwt.go",
		StaleReasonPhrases: []string{"burpsy has no native JWT-forgery evaluator"},
		UnblockedIssues:    nil,
		WiredIssues: []string{
			"JWT signature not verified",
			"JWT none algorithm supported",
			"JWT self-signed JWK header supported",
			"JWT private key disclosed",
			"JWT arbitrary jku header supported",
			"JWT arbitrary x5u header supported",
		},
	},
	{
		Name:               "graphql-engine",
		File:               "internal/scanner/infra_graphql.go",
		StaleReasonPhrases: []string{"burpsy has no native GraphQL evaluator"},
		UnblockedIssues:    nil,
		WiredIssues: []string{
			"GraphQL endpoint found",
			"GraphQL introspection enabled",
			"GraphQL suggestions enabled",
			"GraphQL content type not validated",
		},
	},
	{
		Name: "xml-xxe-payloads",
		File: "internal/scanner/infra_xml.go",
		StaleReasonPhrases: []string{
			"burpsy has no native XML entity-expansion evaluator",
			"requires an XML parser and controlled external-entity resolver",
		},
		UnblockedIssues: nil,
		WiredIssues: []string{
			"XML entity expansion",
			"XML external entity injection",
		},
	},
	{
		Name: "http-pipelining",
		File: "internal/sender/pipeline.go",
		StaleReasonPhrases: []string{
			"sender has no keep-alive/pipelining primitive",
			"on a reused connection",
		},
		UnblockedIssues: nil,
		WiredIssues: []string{
			"HTTP request smuggling",
			"Client-side desync",
		},
	},
	{
		Name: "auth-differential",
		File: "internal/scanner/infra_authdiff.go",
		StaleReasonPhrases: []string{
			"no native access-control evaluator exists",
			"burpsy performs no session-aware request forgery",
		},
		UnblockedIssues: nil,
		WiredIssues: []string{
			"Broken access control",
			"Cross-site request forgery",
		},
	},
	{
		Name: "oob-interaction-channel",
		File: "internal/oob/client.go",
		StaleReasonPhrases: []string{
			"that burpsy does not implement",
			"no safe outbound interaction primitive is configured",
		},
		UnblockedIssues: nil,
		WiredIssues: []string{
			"External service interaction (DNS)",
			"External service interaction (HTTP)",
			"Out-of-band resource load (HTTP)",
			"External service interaction (SMTP)",
		},
	},
	{
		Name:               "dom-execution-harness",
		File:               "internal/domexec/browser.go",
		StaleReasonPhrases: []string{"requires a headless browser / JavaScript execution engine"},
		UnblockedIssues:    nil,
		WiredIssues: []string{
			"Ajax request header manipulation (DOM-based)",
			"Ajax request header manipulation (reflected DOM-based)",
			"Cookie manipulation (DOM-based)",
			"Cookie manipulation (reflected DOM-based)",
			"DOM data manipulation (DOM-based)",
			"DOM data manipulation (reflected DOM-based)",
			"Document domain manipulation (DOM-based)",
			"Document domain manipulation (reflected DOM-based)",
			"HTML5 storage manipulation (DOM-based)",
			"HTML5 storage manipulation (reflected DOM-based)",
			"HTML5 web message manipulation (DOM-based)",
			"HTML5 web message manipulation (reflected DOM-based)",
			"Open redirection (DOM-based)",
			"Open redirection (reflected DOM-based)",
			"WebSocket URL poisoning (DOM-based)",
			"WebSocket URL poisoning (reflected DOM-based)",
			"CSS injection (reflected)",
			"Client-side HTTP parameter pollution (reflected)",
			"Client-side JSON injection (DOM-based)",
			"Client-side JSON injection (reflected DOM-based)",
			"Client-side SQL injection (DOM-based)",
			"Client-side SQL injection (reflected DOM-based)",
			"Client-side XPath injection (DOM-based)",
			"Client-side XPath injection (reflected DOM-based)",
			"Denial of service (DOM-based)",
			"Denial of service (reflected DOM-based)",
			"Form action hijacking (reflected)",
			"Link manipulation (DOM-based)",
			"Link manipulation (reflected DOM-based)",
			"Local file path manipulation (DOM-based)",
			"Local file path manipulation (reflected DOM-based)",
			"Path-relative style sheet import",
		},
	},
	{
		Name: "js-execution-tier",
		File: "internal/jsexec/jsexec.go",
		// No stale phrase of its own: the prototype-pollution row's reason cites the
		// browser blocker, which the dom-execution-harness entry already retires. Listing
		// the same phrase twice would make the guard test's message ambiguous about which
		// primitive answered it.
		StaleReasonPhrases: nil,
		UnblockedIssues:    nil,
		WiredIssues:        []string{"Client-side prototype pollution"},
	},
	{
		Name: "stored-canary-ledger",
		File: "internal/scanner/infra_stored.go",
		StaleReasonPhrases: []string{
			"burpsy has no stored-exchange thread",
			"which burpsy does not thread",
			"requires a stored-exchange second-order dispatch path, which this audit engine does not yet resolve",
			"requires both a stored-exchange second-order dispatch path and a browser/DOM execution engine, neither of which this port has",
		},
		UnblockedIssues: nil,
		WiredIssues: []string{
			"Cross-site scripting (stored DOM-based)",
			"JavaScript injection (stored DOM-based)",
			"WebSocket URL poisoning (stored DOM-based)",
			"Open redirection (stored DOM-based)",
			"Cookie manipulation (stored DOM-based)",
			"Ajax request header manipulation (stored DOM-based)",
			"HTML5 web message manipulation (stored DOM-based)",
			"HTML5 storage manipulation (stored DOM-based)",
			"Document domain manipulation (stored DOM-based)",
			"DOM data manipulation (stored DOM-based)",
			"Password returned in later response",
			"Input returned in response (stored)",
			"Suspicious input transformation (stored)",
			"Open redirection (stored)",
			"Cross-site scripting (stored)",
			"SQL injection (second order)",
			"Client-side SQL injection (stored DOM-based)",
			"Local file path manipulation (stored DOM-based)",
			"Client-side XPath injection (stored DOM-based)",
			"Client-side JSON injection (stored DOM-based)",
			"Denial of service (stored DOM-based)",
			"Link manipulation (stored DOM-based)",
			"Link manipulation (stored)",
			"CSS injection (stored)",
			"Client-side HTTP parameter pollution (stored)",
			"Form action hijacking (stored)",
		},
	},
	{
		Name: "tlsx-probe",
		File: "internal/tlsprobe/tlsprobe.go",
		// No stale phrase: the reason text this primitive would retire was shared with
		// four rows answered by transport-posture-analyser and with "Hidden HTTP 2",
		// which needs a paired ALPN/prior-knowledge probe. This primitive analyses the
		// handshake and certificate only, so the phrase belongs to that entry instead.
		StaleReasonPhrases: nil,
		UnblockedIssues:    nil,
		WiredIssues:        []string{"TLS certificate"},
	},
	{
		Name: "transport-posture-analyser",
		File: "internal/scanner/infra_transport.go",
		StaleReasonPhrases: []string{
			"Host-wide transport / TLS security analysis (this indicator) is not implemented as a native evaluator in burpsy.",
		},
		UnblockedIssues: nil,
		WiredIssues: []string{
			"Unencrypted communications",
			"Strict transport security not enforced",
			"Cacheable HTTPS response",
			"Mixed content",
		},
	},
	{
		Name: "response-shape-analyser",
		File: "internal/scanner/infra_response.go",
		StaleReasonPhrases: []string{
			"Passive response / header attribute analysis (this indicator) is not implemented as a native evaluator in burpsy.",
		},
		UnblockedIssues: nil,
		WiredIssues: []string{
			"Long redirection response",
			"Request URL override",
			"Cross-domain Referer leakage",
			"Multiple content types specified",
			"Content type is not specified",
		},
	},
	{
		// Two files, one primitive: the recovered payload banks are useless without the
		// differential classifier, and the classifier proves nothing without the banks.
		// infra_injection_evidence.go ships alongside the file named here.
		Name: "injection-evaluator-logic",
		File: "internal/scanner/infra_injection_payloads.go",
		StaleReasonPhrases: []string{
			"Active injection check requires sending crafted payloads and observing error / response / behavioral differences; burpsy has no native evaluator for this injection class.",
		},
		UnblockedIssues: nil,
		WiredIssues: []string{
			"LDAP injection",
			"XPath injection",
			"XML injection",
			"File path manipulation",
			"Server-side template injection",
			"Expression Language injection",
			"PHP code injection",
			"Perl code injection",
			"Ruby code injection",
			"Python code injection",
			"Server-side JavaScript code injection",
		},
	},
	{
		Name: "form-field-analyser",
		File: "internal/scanner/infra_forms.go",
		StaleReasonPhrases: []string{
			"Passive password-handling check (this indicator) is not implemented as a native evaluator in burpsy.",
		},
		UnblockedIssues: nil,
		WiredIssues: []string{
			"Cleartext submission of password",
			"Password submitted using GET method",
			"Password returned in URL query string",
			"Password field with autocomplete enabled",
			"Password value set in cookie",
			"Cross-domain POST",
		},
	},
	{
		Name: "shell-breakout-classifier",
		File: "internal/scanner/infra_cmdinject.go",
		// No stale phrase: the OS command injection row shares its reason text verbatim
		// with ten other injection classes this primitive says nothing about, so listing
		// that phrase would demand rewrites that would then be false.
		StaleReasonPhrases: nil,
		UnblockedIssues:    nil,
		WiredIssues:        []string{"OS command injection"},
	},
	{
		Name: "technology-fingerprint",
		File: "internal/scanner/infra_fingerprint.go",
		StaleReasonPhrases: []string{
			"burpsy performs no React / Next.js dependency-version fingerprinting.",
		},
		UnblockedIssues: nil,
		WiredIssues:     []string{"React Server Components remote code execution (React2Shell)"},
	},
}

// InfraUnblockedIssueCount is the number of distinct catalog issues the built primitives
// answer the decline reason for. It is reported separately from any runnable count
// precisely so nobody reads it as coverage.
func InfraUnblockedIssueCount() int {
	seen := make(map[string]struct{})
	for _, p := range InfraPrimitives {
		for _, name := range p.UnblockedIssues {
			seen[name] = struct{}{}
		}
	}
	return len(seen)
}

// InfraWiredIssueCount is the number of distinct catalog issues a primitive's machinery now
// actually detects. This is the only number here that means coverage; InfraUnblockedIssueCount
// deliberately does not.
func InfraWiredIssueCount() int {
	seen := make(map[string]struct{})
	for _, p := range InfraPrimitives {
		for _, name := range p.WiredIssues {
			seen[name] = struct{}{}
		}
	}
	return len(seen)
}
