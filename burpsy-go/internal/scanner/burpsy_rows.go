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
	}}
}

// pwrRowWhy is the shared reason for the password-reset rows (checks_pwreset.go).
func pwrRowWhy(what string) string {
	return "Burp's catalogue has no password-reset rows: Burp's scanner never reads the reset message, " +
		"so it cannot see " + what + ". The check rides 'SMTP header injection', the other row aimed " +
		"at mail-sending endpoints."
}
