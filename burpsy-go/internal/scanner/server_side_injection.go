package scanner

// skip_server_side_injection_for_parameters (burpsy-react-ui-gmdk): which checks are "server-side
// injection", read from Burp rather than guessed from row names.
//
// Burp Suite 2026.7.1 (build 51467), out/clean/jdt_src/burp:
//
//   - The predicate is Zgx0.Zr(config): the insertion point's parameter is on the
//     skip_server_side_injection_for_parameters list (Ziqf.java:51-54 → Ze9d.Ze → Zs4k.java:198-200,
//     which reads the first list Zwh1.java:9-13 loads).
//   - The SQL-and-XPath runner consults it in its own body, unconditionally: Zppj.java:166 returns
//     before any probe when the point is listed. So SQL injection, its second-order form and XPath
//     injection are ALWAYS exempted.
//   - Every other consumer consults it inside the per-point applicability method Zuit.Zh(), and Zh()
//     is read only when skip_ineffective_checks is on: Zfhb.java:81-82 is
//     `(!config.Zip() || check.Zh())`, Zip() being that key (Zhd_.java:38). Those checks are
//     exempted only while the effectiveness gate is on — which is Burp's default. They are: OS command
//     (Zx8l.java:119-140), the XSS-and-template check (Zi6p.java:128-130 — reflected and stored XSS,
//     server-side template and Expression Language injection), code injection (Zsn3.java:74-76),
//     server-side JavaScript (Zg_v.java:46-48), suspicious input transformation (Zeo6.java:34-36),
//     XML external entities and entity expansion (Zf5e.java:34-36, Zin9.java:34-36), path traversal
//     and manipulation (Zp3a via Zibp.java:46-58), out-of-band resource load and external service
//     interaction (Zxfo.java:50-61 via Zibp.java:24-44), XML injection (Zp7s.java:37-46), LDAP
//     (Zwkf.java:37-48), SMTP header injection (Zgcg.java:31-63), the JWT checks (Zu4y.java:28) and
//     SSI injection (Zexx.java:36-66).
//   - Not consulted at all: open redirection (Zuag), HTTP header injection (Zwi), reflected input
//     retrieval (Zr02), client-side template injection (Zrmh), link manipulation (Zb_5), web cache
//     (Zgux), file upload (Zb42), and BCheck/Bambda/extension checks.
//
// Note what that means for reflected XSS: Burp DOES skip it for a listed parameter, while the
// effectiveness gate is on. "Server-side injection" in Burp's sense is the checks whose probes are
// interpreted on the server, and the XSS breakout check shares its probe set with template
// injection.

// ServerSideInjectionClass is whether, and when, a check honours skip_server_side_injection_for_parameters.
type ServerSideInjectionClass uint8

const (
	// NotServerSideInjection: the check probes a listed parameter as usual.
	NotServerSideInjection ServerSideInjectionClass = iota
	// ServerSideInjectionAlways: the check never probes a listed parameter (Zppj.java:166).
	ServerSideInjectionAlways
	// ServerSideInjectionWhenSkipIneffective: the check skips a listed parameter only while
	// skip_ineffective_checks is on, because Burp asks it through Zuit.Zh() (Zfhb.java:81-82).
	ServerSideInjectionWhenSkipIneffective
)

// serverSideInjectionByType classifies the catalogue rows Burp's server-side-injection checks report.
// The four interpreted-language rows other than PHP (Perl, Ruby, Python, unidentified) are PROBABLE:
// they have no detection method of their own in Zcot, and the code-injection check (Zsn3) whose Zh()
// is cited above is the one that owns PHP; their runner was not located, so they take the class of
// the family they belong to rather than none.
var serverSideInjectionByType = map[uint32]ServerSideInjectionClass{
	0x00100200: ServerSideInjectionAlways, // SQL injection
	0x00100210: ServerSideInjectionAlways, // SQL injection (second order)
	0x00100600: ServerSideInjectionAlways, // XPath injection

	0x00100100: ServerSideInjectionWhenSkipIneffective, // OS command injection
	0x00200300: ServerSideInjectionWhenSkipIneffective, // Cross-site scripting (reflected)
	0x00200100: ServerSideInjectionWhenSkipIneffective, // Cross-site scripting (stored)
	0x00101080: ServerSideInjectionWhenSkipIneffective, // Server-side template injection
	0x00100f20: ServerSideInjectionWhenSkipIneffective, // Expression Language injection
	0x00100c00: ServerSideInjectionWhenSkipIneffective, // PHP code injection
	0x00100e00: ServerSideInjectionWhenSkipIneffective, // Perl code injection (PROBABLE)
	0x00100f00: ServerSideInjectionWhenSkipIneffective, // Ruby code injection (PROBABLE)
	0x00100f10: ServerSideInjectionWhenSkipIneffective, // Python code injection (PROBABLE)
	0x00101000: ServerSideInjectionWhenSkipIneffective, // Unidentified code injection (PROBABLE)
	0x00100d00: ServerSideInjectionWhenSkipIneffective, // Server-side JavaScript code injection
	0x00400d00: ServerSideInjectionWhenSkipIneffective, // Suspicious input transformation (reflected)
	0x00100400: ServerSideInjectionWhenSkipIneffective, // XML external entity injection
	0x00400700: ServerSideInjectionWhenSkipIneffective, // XML entity expansion
	0x00100300: ServerSideInjectionWhenSkipIneffective, // File path traversal
	0x00100b00: ServerSideInjectionWhenSkipIneffective, // File path manipulation
	0x00100a00: ServerSideInjectionWhenSkipIneffective, // Out-of-band resource load (HTTP)
	0x00300200: ServerSideInjectionWhenSkipIneffective, // External service interaction (DNS)
	0x00300210: ServerSideInjectionWhenSkipIneffective, // External service interaction (HTTP)
	0x00100700: ServerSideInjectionWhenSkipIneffective, // XML injection
	0x00100500: ServerSideInjectionWhenSkipIneffective, // LDAP injection
	0x00200800: ServerSideInjectionWhenSkipIneffective, // SMTP header injection
	0x00200900: ServerSideInjectionWhenSkipIneffective, // JWT signature not verified
	0x00200901: ServerSideInjectionWhenSkipIneffective, // JWT none algorithm supported
	0x00200902: ServerSideInjectionWhenSkipIneffective, // JWT self-signed JWK header supported
	0x00101100: ServerSideInjectionWhenSkipIneffective, // SSI injection
}

// skipsServerSideParams reports whether a check of this class exempts listed parameters in a run
// whose skip_ineffective_checks resolved to skipIneffective.
func (c ServerSideInjectionClass) skipsServerSideParams(skipIneffective bool) bool {
	switch c {
	case ServerSideInjectionAlways:
		return true
	case ServerSideInjectionWhenSkipIneffective:
		return skipIneffective
	}
	return false
}

// skipIneffectiveResolved is skip_ineffective_checks with its default applied: unset is on.
func (cfg AuditConfig) skipIneffectiveResolved() bool {
	if cfg.SkipIneffectiveChecks.Set {
		return cfg.SkipIneffectiveChecks.Value != 0
	}
	return true
}
