package scanner

// burpsy's own issue rows: classes a burpsy check reports that Burp's catalogue has no entry for.
//
// They are not catalogue rows. catalog_data.go is Burp's transcribed catalogue and stays exactly 183
// entries, and the registry admits one descriptor per Burp type, so a burpsy row is reported by a
// check that rides an existing Burp descriptor (Rides) behind its own switch. Each row's advisory —
// description, remediation, CWE — is a burpsy-authored definition in internal/advisory/native, which
// is what attaches the CWE to the finding; burpsy_rows_test.go keeps the two in step.

// BurpsyRow is one burpsy-only issue row.
type BurpsyRow struct {
	// Name is the finding name the check reports and the native advisory definition's name.
	Name string
	// TypeIndex is the native advisory definition's index (0xb5xxxxxx), never a Burp index.
	TypeIndex uint32
	// CWE is the row's primary classification.
	CWE uint32
	// Rides is the Burp catalogue descriptor the reporting check is dispatched under.
	Rides string
	// Why records why Burp's catalogue has no row for this class.
	Why string
}

// BurpsyNativeRows lists burpsy's own rows.
func BurpsyNativeRows() []BurpsyRow {
	return []BurpsyRow{{
		Name:      idorIssue,
		TypeIndex: 0xb5000100,
		CWE:       639,
		Rides:     "Broken access control",
		Why: "Burp's catalogue has no insecure-direct-object-reference row: Burp leaves object-level " +
			"authorization to the Autorize and AuthMatrix extensions, whose issues carry the generic " +
			"extension-generated type. Its 'Broken access control' row (CWE-284) is the ancestor class.",
	}, {
		Name:      IssueLoginRateLimitMissing,
		TypeIndex: 0xb5000200,
		CWE:       307,
		Rides:     "Broken access control",
		Why: "Burp's catalogue has no row for missing login rate limiting: Burp finds it by hand or with an " +
			"extension or BCheck, filed under the generic extension-generated type. It rides 'Broken access " +
			"control' because that row's CWE-284 is the pillar CWE-307 descends from (307 < 1390 < 287 < 284) " +
			"and it is the only active Burp row about authentication or authorization.",
	}, {
		Name:      IssueUsernameEnumeration,
		TypeIndex: 0xb5000300,
		CWE:       204,
		Rides:     "Broken access control",
		Why: "Burp's catalogue has no username-enumeration row (its only CWE-204 row, 'Password returned in " +
			"later response', is a passive disclosure). It rides 'Broken access control' with the rate-limit " +
			"row because both are failed-login probes of an authentication endpoint and no Burp row closer " +
			"to authentication is active.",
	}, {
		Name:      pwrTokenInResponse,
		TypeIndex: 0xb5000800,
		CWE:       640,
		Rides:     "SMTP header injection",
		Why:       pwrRowWhy("a reset token in the reset request's own response"),
	}, {
		Name:      pwrPredictable,
		TypeIndex: 0xb5000810,
		CWE:       330,
		Rides:     "SMTP header injection",
		Why:       pwrRowWhy("a reset token predicted from a model and then issued"),
	}, {
		Name:      pwrLowEntropy,
		TypeIndex: 0xb5000820,
		CWE:       331,
		Rides:     "SMTP header injection",
		Why:       pwrRowWhy("a reset token with a keyspace small enough to brute-force online"),
	}, {
		Name:      pwrReusable,
		TypeIndex: 0xb5000830,
		CWE:       640,
		Rides:     "SMTP header injection",
		Why:       pwrRowWhy("a reset token that succeeds twice"),
	}, {
		Name:      pwrNoExpiry,
		TypeIndex: 0xb5000840,
		CWE:       613,
		Rides:     "SMTP header injection",
		Why:       pwrRowWhy("a self-contained (JWT) reset token without an exp claim"),
	}, {
		Name:      pwrInsecureLink,
		TypeIndex: 0xb5000850,
		CWE:       319,
		Rides:     "SMTP header injection",
		Why:       pwrRowWhy("a reset link with an http:// scheme"),
	}, {
		Name:      pwrReferer,
		TypeIndex: 0xb5000860,
		CWE:       200,
		Rides:     "SMTP header injection",
		Why: "Burp's 'Cross-domain Referer leakage' row (CWE-200) is the passive URL heuristic over pages " +
			"in the site map; the reset page is reached only through the mailed link, so it is never in the " +
			"map, and the row does not observe what the browser sends. This row is that leak for the reset " +
			"token specifically, observed in the browser (or computed from the page's effective policy).",
	}, {
		Name:      pwrPoisoning,
		TypeIndex: 0xb5000870,
		CWE:       640,
		Rides:     "SMTP header injection",
		Why:       pwrRowWhy("a reset link built from an attacker-supplied Host or forwarding header"),
	}, {
		Name:      sessionFixationIssue,
		TypeIndex: 0xb5000400,
		CWE:       384,
		Rides:     "Broken access control",
		Why: "Burp's scanner has no session-fixation check or row; testing it is a manual step. Its " +
			"'Session token in URL' row lists CWE-384 only as a consequence of a token in a URL.",
	}, {
		Name:      predictableSessionIssue,
		TypeIndex: 0xb5000500,
		CWE:       330,
		Rides:     "Broken access control",
		Why: "Burp analyses token randomness in Sequencer, a manual tool whose results are not scanner " +
			"issues; its catalogue has no row for a predictable session token.",
	}, {
		Name:      logoutInvalidationIssue,
		TypeIndex: 0xb5000600,
		CWE:       613,
		Rides:     "Broken access control",
		Why: "Burp's catalogue has no row for a session that survives logout (CWE-613); it is found by " +
			"hand or by an extension.",
	}, {
		Name:      IssueHostHeaderInjection,
		TypeIndex: 0xb5001000,
		CWE:       20,
		Rides:     "Link manipulation (reflected)",
		Why: "Burp's catalogue has no Host header row: Burp's scanner treats the Host header as one more " +
			"insertion point and files what it finds there under the row the payload proves (link " +
			"manipulation, open redirection, cache poisoning, external service interaction), and the Academy " +
			"documents the attack class without a catalogue entry. It rides 'Link manipulation (reflected)' " +
			"because a Host that becomes a link's host is link manipulation through the HOST insertion point " +
			"(the relabelling Zb_5 does), and shares that row's CWE-20.",
	}, {
		Name:      IssueGraphQLBatching,
		TypeIndex: 0xb5001800,
		CWE:       799,
		Rides:     "GraphQL endpoint found",
		Why: "Burp's catalogue has four GraphQL rows (endpoint found, introspection, suggestions, content type " +
			"not validated) and none for batching; Burp leaves it to manual testing with Repeater and to " +
			"extensions such as InQL. It rides 'GraphQL endpoint found' because it is probed only on an " +
			"endpoint that row's probe has shown to execute GraphQL, once per URL.",
	}, {
		Name:      IssueGraphQLDepth,
		TypeIndex: 0xb5001810,
		CWE:       770,
		Rides:     "GraphQL endpoint found",
		Why: "Burp's catalogue has no GraphQL depth or complexity row. It rides 'GraphQL endpoint found' with " +
			"the batching row, for the same reason.",
	}, {
		Name:      IssueGraphQLDebug,
		TypeIndex: 0xb5001820,
		CWE:       209,
		Rides:     "GraphQL endpoint found",
		Why: "Burp's catalogue has no row for GraphQL debug output: its error-message rows are passive and " +
			"read responses the proxy already saw, while this one provokes a GraphQL error and reads the " +
			"envelope's errors and extensions. It rides 'GraphQL endpoint found' with the other GraphQL rows.",
	}, {
		Name:      IssueInsecureDeserialization,
		TypeIndex: 0xb5001400,
		CWE:       502,
		Rides:     "React Server Components remote code execution (React2Shell)",
		Why: "Burp's catalogue has only a passive deserialization row ('Serialized object in HTTP message', " +
			"which reports a blob that looks serialized, not that the server deserializes it); active " +
			"deserialization testing is left to extensions (Java Deserialization Scanner, Freddy), filed " +
			"under the generic extension-generated type. It rides React2Shell, the only active Burp row " +
			"classified CWE-502.",
	}, {
		Name:      nosqliIssue,
		TypeIndex: 0xb5002000,
		CWE:       943,
		Rides:     "Server-side JavaScript code injection",
		Why: "Burp's catalogue has no NoSQL injection row: Burp's scanner does not probe MongoDB operators, " +
			"and NoSQL findings come from extensions, filed under the generic extension-generated type. It " +
			"rides 'Server-side JavaScript code injection' because the $where form of the flaw is " +
			"server-side JavaScript evaluated by the database, and that row probes the same parameters.",
	}, {
		Name:      IssueWebSocketHijacking,
		TypeIndex: 0xb5002400,
		CWE:       1385,
		Rides:     "Cross-site request forgery",
		Why: "Burp's catalogue has no WebSocket hijacking row: Burp's scanner audits WebSocket messages as " +
			"insertion points and leaves the handshake's Origin check to manual testing (the Academy topic). " +
			"It rides 'Cross-site request forgery' because the attack is a cross-site forgery of the " +
			"handshake, and CWE-1385 is that row's CWE-352 specialised to WebSockets.",
	}, {
		Name:      IssueClientIPAccessBypass,
		TypeIndex: 0xb5002410,
		CWE:       290,
		Rides:     "Broken access control",
		Why: "Burp's only client-IP row, 'Spoofable client IP address', is informational: it shows the " +
			"header is read, not that a decision depends on it. A refused page served on a loopback claim " +
			"is an access-control failure, so it rides 'Broken access control' (CWE-290 descends from " +
			"CWE-284 through CWE-287).",
	}, {
		Name:      IssueClientIPRateLimitBypass,
		TypeIndex: 0xb5002420,
		CWE:       348,
		Rides:     "Broken access control",
		Why: "Burp's catalogue has no rate-limit row at all, and its 'Spoofable client IP address' row is " +
			"informational. It rides 'Broken access control' with the client-IP access bypass, which the " +
			"same probes test.",
	}, {
		Name:      IssueCookiePrefixViolated,
		TypeIndex: 0xb5002800,
		CWE:       693,
		Rides:     "Cookie scoped to parent domain",
		Why: "Burp's catalogue has no row for cookie name prefixes: its cookie rows read the Secure, " +
			"HttpOnly and Domain attributes one at a time and never the __Host-/__Secure- contract that ties " +
			"them to the name. It rides 'Cookie scoped to parent domain', a passive per-request reading of " +
			"the same Set-Cookie headers.",
	}, {
		Name:      IssueSessionCookieSameSite,
		TypeIndex: 0xb5002810,
		CWE:       1275,
		Rides:     "Cookie scoped to parent domain",
		Why: "Burp's catalogue has no SameSite row: SameSite enters only as one of the defences its " +
			"'Cross-site request forgery' check weighs. It rides 'Cookie scoped to parent domain' with the " +
			"prefix row.",
	}, {
		Name:      IssueSubdomainTakeover,
		TypeIndex: 0xb5002820,
		CWE:       672,
		Rides:     "Strict transport security not enforced",
		Why: "Burp's catalogue has no subdomain-takeover row and its scanner makes no DNS lookups of its " +
			"own; takeover is found with external tools (subjack, can-i-take-over-xyz). It rides 'Strict " +
			"transport security not enforced', a passive per-host row, because it is a property of the " +
			"hostname checked once per host.",
	}, {
		Name:      IssueSSPPQuery,
		TypeIndex: 0xb5002c00,
		CWE:       235,
		Rides:     "Client-side HTTP parameter pollution (reflected)",
		Why:       ssppRowWhy("a delimiter that becomes structure in an internal query string"),
	}, {
		Name:      IssueSSPPPath,
		TypeIndex: 0xb5002c10,
		CWE:       74,
		Rides:     "Client-side HTTP parameter pollution (reflected)",
		Why:       ssppRowWhy("a value that walks or ends an internal REST path"),
	}, {
		Name:      IssueSSPPJSON,
		TypeIndex: 0xb5002c20,
		CWE:       74,
		Rides:     "Client-side HTTP parameter pollution (reflected)",
		Why:       ssppRowWhy("a value that adds a member to an internal JSON document"),
	}, {
		Name:      IssueLLMPromptInjection,
		TypeIndex: 0xb5003000,
		CWE:       1427,
		Rides:     "Server-side template injection",
		Why: "Burp's catalogue has no LLM row: PortSwigger documents prompt injection as an Academy topic " +
			"(Web LLM attacks) tested by hand, and Burp's scanner sends no instruction to a model. It rides " +
			"'Server-side template injection' because both are instructions in user input executed by a " +
			"server-side interpreter, proven the same way: by a value computed from operands only the " +
			"instruction names.",
	}, {
		Name:      IssueWeakHashOfInput,
		TypeIndex: 0xb5003800,
		CWE:       328,
		Rides:     "Suspicious input transformation (reflected)",
		Why:       weakCryptoRowWhy("an unsalted MD4, MD5, SHA-1, NTLM, LM or MySQL 4.1 digest of the input"),
	}, {
		Name:      IssueWeakPasswordHash,
		TypeIndex: 0xb5003810,
		CWE:       916,
		Rides:     "Suspicious input transformation (reflected)",
		Why:       weakCryptoRowWhy("a password hashed with a fast unsalted hash or a low-cost bcrypt"),
	}, {
		Name:      IssueECBEncryptionOfInput,
		TypeIndex: 0xb5003820,
		CWE:       327,
		Rides:     "Suspicious input transformation (reflected)",
		Why:       weakCryptoRowWhy("ECB encryption of the input, shown by repeated ciphertext blocks"),
	}, {
		Name:      IssuePlaintextPasswordStore,
		TypeIndex: 0xb5003830,
		CWE:       256,
		Rides:     "Suspicious input transformation (reflected)",
		Why:       weakCryptoRowWhy("a password returned verbatim from the server's record"),
	}}
}

// weakCryptoRowWhy is the shared reason for the weak-cryptography rows (checks_weakcrypto.go).
func weakCryptoRowWhy(what string) string {
	return "Burp's catalogue has no row for " + what + ": its only hash-related output is passive " +
		"(a string shaped like a hash), and Burp's scanner never computes a digest of what it sent. It rides " +
		"'Suspicious input transformation (reflected)' because the finding is a transformation of the input " +
		"proven by computing it, which is that row's own method."
}

// ssppRowWhy is the shared reason for the server-side parameter pollution rows (checks_sspp.go).
func ssppRowWhy(what string) string {
	return "Burp's catalogue has no server-side parameter pollution row: its parameter-pollution rows are " +
		"client-side (links and forms the response renders), and the server-side class is an Academy topic " +
		"tested by hand. This row is " + what + ". It rides 'Client-side HTTP parameter pollution " +
		"(reflected)', the same class (CAPEC-460) on the request the server makes instead of the page it renders."
}

// pwrRowWhy is the shared reason for the password-reset rows (checks_pwreset.go).
func pwrRowWhy(what string) string {
	return "Burp's catalogue has no password-reset rows: Burp's scanner never reads the reset message, " +
		"so it cannot see " + what + ". The check rides 'SMTP header injection', the other row aimed " +
		"at mail-sending endpoints."
}
