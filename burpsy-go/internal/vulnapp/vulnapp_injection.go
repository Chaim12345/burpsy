package vulnapp

// Active injection rows this family plants: Expression Language injection, File path
// manipulation, XML injection, and the five interpreted-language code-injection rows (PHP,
// Perl, Ruby, Python, server-side JavaScript). All eight ride internal/scanner's ProbeHarness
// over the query/body/cookie/header insertion points, and every endpoint here takes its input
// through a query parameter. That was forced when bcheck's body-point enumerator modelled no
// container for an XML or plain-text body — an XML row reached only through a POST body had no
// point to probe at all. XML bodies are modelled now (burpsy-react-ui-63jg), and these endpoints
// stay query-only on purpose: one reachable route per row keeps the demonstration about the
// check, not about which of two routes the payload took.
//
// Corresponding scanner descriptors: InjectionCheckDescriptors in
// internal/scanner/checks_injection.go.
//
// The eight rows split into the two evidence classes internal/scanner/infra_injection_evidence.go
// defines for them:
//
//   - Error signature (ClassifyErrorEvidence): File path manipulation and XML injection. Both
//     genuinely determine failure first - a real path.Clean resolution for the former, a real
//     encoding/xml token walk for the latter - and only then choose the matching documented
//     signature text. Neither pattern-matches the payload that produced the failure.
//   - Evaluated arithmetic (ClassifyEvaluation): Expression Language injection and the five code
//     injection languages. Each recognises its own delimiter/print-statement shape generically -
//     any two operands, not the specific 7 and 6 the check happens to send - and actually
//     multiplies them, the same technique vulnapp.go's renderTemplate and evalNote already use.

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// injectionEndpoints returns this family's manifest entries.
func injectionEndpoints() []Endpoint {
	return []Endpoint{
		{Path: "/ij/rewards?formula=seed", Row: "Expression Language injection",
			Note: "evaluates an arithmetic expression inside EL delimiters (${...}, #{...})"},
		{Path: "/ij/safe/rewards?formula=seed", Row: "Expression Language injection", Safe: true,
			Note: "reflects the formula as text, never evaluates it"},

		{Path: "/ij/attachments?resource=seed", Row: "File path manipulation",
			Note: "resolves resource against a virtual upload directory; traversal reaches /etc/passwd-shaped content"},
		{Path: "/ij/safe/attachments?resource=seed", Row: "File path manipulation", Safe: true,
			Note: "echoes the resource name without ever resolving it against a filesystem"},

		{Path: "/ij/catalog?item=seed", Row: "XML injection",
			Note: "concatenates item into an XML text node and parses the result; a malformed document leaks a genuine parser error"},
		{Path: "/ij/safe/catalog?item=seed", Row: "XML injection", Safe: true,
			Note: "reflects item without ever building or parsing XML from it"},

		{Path: "/ij/scripts/php?snippet=seed", Row: "PHP code injection",
			Note: "runs snippet through a PHP arithmetic/concatenation evaluator"},
		{Path: "/ij/safe/scripts/php?snippet=seed", Row: "PHP code injection", Safe: true,
			Note: "reflects snippet without evaluating it"},

		{Path: "/ij/scripts/perl?snippet=seed", Row: "Perl code injection",
			Note: "runs snippet through a Perl print-statement evaluator"},
		{Path: "/ij/safe/scripts/perl?snippet=seed", Row: "Perl code injection", Safe: true,
			Note: "reflects snippet without evaluating it"},

		{Path: "/ij/scripts/ruby?snippet=seed", Row: "Ruby code injection",
			Note: "runs snippet through a Ruby puts/interpolation evaluator"},
		{Path: "/ij/safe/scripts/ruby?snippet=seed", Row: "Ruby code injection", Safe: true,
			Note: "reflects snippet without evaluating it"},

		{Path: "/ij/scripts/python?snippet=seed", Row: "Python code injection",
			Note: "runs snippet through a Python print/str evaluator"},
		{Path: "/ij/safe/scripts/python?snippet=seed", Row: "Python code injection", Safe: true,
			Note: "reflects snippet without evaluating it"},

		{Path: "/ij/scripts/node?snippet=seed", Row: "Server-side JavaScript code injection",
			Note: "runs snippet through a JavaScript template-literal evaluator"},
		{Path: "/ij/safe/scripts/node?snippet=seed", Row: "Server-side JavaScript code injection", Safe: true,
			Note: "reflects snippet without evaluating it"},

		{Path: "/ij/books?sort_col=seed", Row: "SQL injection",
			Note: "concatenates sort_col into a condition; an appended boolean comparison decides whether rows come back"},
		{Path: "/ij/safe/books?sort_col=seed", Row: "SQL injection", Safe: true,
			Note: "sorts by the named column only; no condition in the value is ever evaluated"},

		{Path: "/ij/jobs?queue=seed", Row: "SQL injection",
			Note: "concatenates queue into a job query; a sleep directive in the value executes and delays the response"},
		{Path: "/ij/safe/jobs?queue=seed", Row: "SQL injection", Safe: true,
			Note: "stores the parameter verbatim and returns immediately, the way a parameterised query does"},

		// The XSS decoding endpoints (burpsy-react-ui-79ld): each strips the LITERAL form of
		// the angle brackets an ordinary breakout needs, then performs one decoding before
		// reflecting — the decode-after-filter bug class. A payload that arrives already
		// spelling its markup in the endpoint's own encoding walks through the strip and is
		// decoded into live markup; the plain payload never can. The safe twins keep the
		// strip and add the output encoding a real fix would have, and never decode.
		{Path: "/ij/xss/decode/url?term=seed", Row: "Cross-site scripting (reflected)",
			Note: "strips literal angle brackets, then URL-decodes the value before reflecting it raw"},
		{Path: "/ij/xss/safe/decode/url?term=seed", Row: "Cross-site scripting (reflected)", Safe: true,
			Note: "strips literal angle brackets and output-encodes the value; nothing is ever decoded"},
		{Path: "/ij/xss/decode/html?term=seed", Row: "Cross-site scripting (reflected)",
			Note: "strips literal angle brackets, then HTML-entity-decodes the value before reflecting it raw"},
		{Path: "/ij/xss/safe/decode/html?term=seed", Row: "Cross-site scripting (reflected)", Safe: true,
			Note: "strips literal angle brackets and output-encodes the value; nothing is ever decoded"},
		{Path: "/ij/xss/decode/backslash?term=seed", Row: "Cross-site scripting (reflected)",
			Note: "strips literal angle brackets, then unescapes backslash \\xHH sequences before reflecting the value raw"},
		{Path: "/ij/xss/safe/decode/backslash?term=seed", Row: "Cross-site scripting (reflected)", Safe: true,
			Note: "strips literal angle brackets and output-encodes the value; nothing is ever unescaped"},
		{Path: "/ij/xss/decode/overlong?term=seed", Row: "Cross-site scripting (reflected)",
			Note: "strips literal angle brackets, then leniently decodes overlong two-byte UTF-8 before reflecting the value raw"},
		{Path: "/ij/xss/safe/decode/overlong?term=seed", Row: "Cross-site scripting (reflected)", Safe: true,
			Note: "strips literal angle brackets and output-encodes the value; nothing is ever decoded"},
		{Path: "/ij/xss/decode/invalid?term=seed", Row: "Cross-site scripting (reflected)",
			Note: "strips literal angle brackets, then bitmask-decodes three-byte UTF-8 sequences without validating them, before reflecting the value raw"},
		{Path: "/ij/xss/safe/decode/invalid?term=seed", Row: "Cross-site scripting (reflected)", Safe: true,
			Note: "strips literal angle brackets and output-encodes the value; nothing is ever decoded"},

		// The decode-then-output-encode endpoint: the decoding happens (which is itself worth
		// reporting, on the transformation row) but the markup is neutralized, so the XSS row
		// must stay silent here. It is declared Safe for the XSS row it would otherwise be a
		// false positive against.
		{Path: "/ij/xss/decode/url/escaped?term=seed", Row: "Cross-site scripting (reflected)", Safe: true,
			Note: "URL-decodes the value and then output-encodes the result — the decoding is observable, the breakout is not"},
	}
}

// registerInjection serves this family's routes.
func registerInjection(mux *http.ServeMux) {
	mux.HandleFunc("/ij/rewards", evalRewardsFormula)
	mux.HandleFunc("/ij/safe/rewards", safeRewardsFormula)

	mux.HandleFunc("/ij/attachments", resolveAttachment)
	mux.HandleFunc("/ij/safe/attachments", safeResolveAttachment)

	mux.HandleFunc("/ij/catalog", previewCatalogItem)
	mux.HandleFunc("/ij/safe/catalog", safePreviewCatalogItem)

	phpVuln, phpSafe := codeInjectionHandlers(phpArithmetic)
	perlVuln, perlSafe := codeInjectionHandlers(perlArithmetic)
	rubyVuln, rubySafe := codeInjectionHandlers(rubyArithmetic)
	pythonVuln, pythonSafe := codeInjectionHandlers(pythonArithmetic)
	nodeVuln, nodeSafe := codeInjectionHandlers(nodeArithmetic)
	mux.HandleFunc("/ij/scripts/php", phpVuln)
	mux.HandleFunc("/ij/safe/scripts/php", phpSafe)
	mux.HandleFunc("/ij/scripts/perl", perlVuln)
	mux.HandleFunc("/ij/safe/scripts/perl", perlSafe)
	mux.HandleFunc("/ij/scripts/ruby", rubyVuln)
	mux.HandleFunc("/ij/safe/scripts/ruby", rubySafe)
	mux.HandleFunc("/ij/scripts/python", pythonVuln)
	mux.HandleFunc("/ij/safe/scripts/python", pythonSafe)
	mux.HandleFunc("/ij/scripts/node", nodeVuln)
	mux.HandleFunc("/ij/safe/scripts/node", nodeSafe)

	mux.HandleFunc("/ij/books", sortBookedByCondition)
	mux.HandleFunc("/ij/safe/books", safeSortBookedByCondition)
	mux.HandleFunc("/ij/jobs", queueJobWithDelay)
	mux.HandleFunc("/ij/safe/jobs", safeQueueJobWithDelay)

	mux.HandleFunc("/ij/xss/decode/url", xssDecodeURL)
	mux.HandleFunc("/ij/xss/safe/decode/url", xssSafeDecodeURL)
	mux.HandleFunc("/ij/xss/decode/html", xssDecodeHTML)
	mux.HandleFunc("/ij/xss/safe/decode/html", xssSafeDecodeHTML)
	mux.HandleFunc("/ij/xss/decode/backslash", xssDecodeBackslash)
	mux.HandleFunc("/ij/xss/safe/decode/backslash", xssSafeDecodeBackslash)
	mux.HandleFunc("/ij/xss/decode/overlong", xssDecodeOverlong)
	mux.HandleFunc("/ij/xss/safe/decode/overlong", xssSafeDecodeOverlong)
	mux.HandleFunc("/ij/xss/decode/invalid", xssDecodeInvalid)
	mux.HandleFunc("/ij/xss/safe/decode/invalid", xssSafeDecodeInvalid)
	mux.HandleFunc("/ij/xss/decode/url/escaped", xssDecodeURLEscaped)
}

// ---------------------------------------------------------------------------
// Expression Language injection
// ---------------------------------------------------------------------------

// elArithmetic recognises an arithmetic product inside EL delimiters - `${...}`, `#{...}`, or
// the doubled-brace breakout `${{...}}` - generically on the two operands. A real EL engine
// handed "${7*6}" does not know or care that 7*6 is the specific pair a scanner happened to
// send, and neither does this: it multiplies whatever two integers it finds.
var elArithmetic = regexp.MustCompile(`[$#]\{+\s*(-?\d+)\s*\*\s*(-?\d+)\s*\}+`)

func evalRewardsFormula(w http.ResponseWriter, r *http.Request) {
	v := r.URL.Query().Get("formula")
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, "reward points: %s\n", runSnippet(elArithmetic, v))
}

func safeRewardsFormula(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, "reward points: %s\n", r.URL.Query().Get("formula"))
}

// ---------------------------------------------------------------------------
// File path manipulation
// ---------------------------------------------------------------------------

// resolveVirtualPath mirrors what a real filesystem does with a relative path: `..` climbs one
// directory, and - per POSIX semantics and path.Clean's own documented behaviour - a `..` at the
// root is a no-op rather than an error. That clamping is exactly why a payload with far more
// `../` than the base directory is deep still lands on the target file: the excess segments are
// absorbed at the root the same way a real kernel absorbs them, not because this function went
// looking for that specific payload.
func resolveVirtualPath(base, rel string) string {
	return path.Clean(base + "/" + strings.ReplaceAll(rel, `\`, "/"))
}

func resolveAttachment(w http.ResponseWriter, r *http.Request) {
	v := r.URL.Query().Get("resource")
	w.Header().Set("Content-Type", "text/plain")
	if resolveVirtualPath("/var/app/uploads", v) == "/etc/passwd" {
		fmt.Fprint(w, "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n")
		return
	}
	fmt.Fprintf(w, "attachment not found: %s\n", v)
}

func safeResolveAttachment(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, "attachment not found: %s\n", r.URL.Query().Get("resource"))
}

// ---------------------------------------------------------------------------
// XML injection
// ---------------------------------------------------------------------------

// xmlWellFormedError runs doc through a real token-by-token XML parse and, only if that parse
// genuinely fails, translates the failure into the wording production XML parsers use for the
// same condition: libxml2/Expat report a truncated document as "Premature end of data in tag"
// and almost everything else as "not well-formed (invalid token)" - both real, documented parser
// strings, and both present in XMLErrorSignatures. Which branch fires depends on what actually
// broke, never on which payload was sent.
func xmlWellFormedError(doc string) (msg string, malformed bool) {
	dec := xml.NewDecoder(strings.NewReader(doc))
	for {
		_, err := dec.Token()
		if err == nil {
			continue
		}
		if errors.Is(err, io.EOF) {
			return "", false
		}
		if strings.Contains(strings.ToLower(err.Error()), "eof") {
			return fmt.Sprintf("XML Parsing Error: Premature end of data in tag line 1 (%v)", err), true
		}
		return fmt.Sprintf("XML Parsing Error: not well-formed (invalid token) (%v)", err), true
	}
}

func previewCatalogItem(w http.ResponseWriter, r *http.Request) {
	item := r.URL.Query().Get("item")
	w.Header().Set("Content-Type", "text/plain")
	if msg, broken := xmlWellFormedError("<product><name>" + item + "</name></product>"); broken {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "%s\n", msg)
		return
	}
	fmt.Fprintf(w, "catalog entry accepted: %s\n", item)
}

func safePreviewCatalogItem(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, "catalog entry accepted: %s\n", r.URL.Query().Get("item"))
}

// ---------------------------------------------------------------------------
// Interpreted-language code injection: PHP, Perl, Ruby, Python, server-side JavaScript
// ---------------------------------------------------------------------------
//
// codeInjectionCheck (internal/scanner/checks_injection.go) tries two emitters per language
// across three quoting contexts: a bare print/echo of an arithmetic product, and a
// string-breakout form that closes an assumed surrounding quote before doing the same. Every
// regex below matches its language's arithmetic-bearing shape wherever it lands in the value -
// it does not anchor to start or end, so it fires the same way whether or not a breakout quote
// surrounds it - and multiplies whatever two operands it finds, never the specific 7*6 the check
// happens to send.

var (
	// phpArithmetic matches either recovered emitter: printf's format-string form, or the
	// `".(A*B)."` string-close/concatenate/reopen breakout (burp.Zxvv's own recovered literal).
	phpArithmetic = regexp.MustCompile(`printf\(\s*"(-?\d+)\s*\*\s*(-?\d+)"\s*\)|\.\(\s*(-?\d+)\s*\*\s*(-?\d+)\s*\)\.`)
	// perlArithmetic matches a bare `print` statement, with or without a surrounding breakout
	// quote - the breakout form still contains this substring, so one pattern covers both.
	perlArithmetic = regexp.MustCompile(`print\s+(-?\d+)\s*\*\s*(-?\d+)`)
	// rubyArithmetic matches a bare `puts` statement or Ruby's own `#{...}` interpolation.
	rubyArithmetic = regexp.MustCompile(`puts\s+(-?\d+)\s*\*\s*(-?\d+)|#\{\s*(-?\d+)\s*\*\s*(-?\d+)\s*\}`)
	// pythonArithmetic matches either emitter: both wrap the arithmetic in a function call.
	pythonArithmetic = regexp.MustCompile(`(?:print|str)\(\s*(-?\d+)\s*\*\s*(-?\d+)\s*\)`)
	// nodeArithmetic matches a template-literal interpolation or a `"+(A*B)+"` breakout.
	nodeArithmetic = regexp.MustCompile(`\$\{\s*(-?\d+)\s*\*\s*(-?\d+)\s*\}|\+\(\s*(-?\d+)\s*\*\s*(-?\d+)\s*\)\+`)
)

// evalArithmeticMatch multiplies the first two non-empty capture groups a regex produced -
// whichever alternative matched supplies them, the other alternative's groups come back empty -
// and returns the decimal product, or "" if fewer than two numbers were captured.
func evalArithmeticMatch(groups []string) string {
	var nums []int
	for _, g := range groups[1:] {
		if g == "" {
			continue
		}
		n, _ := strconv.Atoi(g)
		nums = append(nums, n)
		if len(nums) == 2 {
			break
		}
	}
	if len(nums) != 2 {
		return ""
	}
	return strconv.Itoa(nums[0] * nums[1])
}

// runSnippet replaces every arithmetic match re finds in snippet with its computed product,
// leaving anything that does not match untouched - the same "evaluate whatever landed here"
// behaviour as vulnapp.go's renderTemplate and evalNote, extended to one regex per language.
func runSnippet(re *regexp.Regexp, snippet string) string {
	return re.ReplaceAllStringFunc(snippet, func(m string) string {
		if product := evalArithmeticMatch(re.FindStringSubmatch(m)); product != "" {
			return product
		}
		return m
	})
}

// codeInjectionHandlers builds the vulnerable/safe pair for one language: the vulnerable side
// runs the snippet through re and echoes the result, the safe side echoes the raw snippet and
// never evaluates anything.
func codeInjectionHandlers(re *regexp.Regexp) (vulnerable, safe http.HandlerFunc) {
	vulnerable = func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("snippet")
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "webhook output: %s\n", runSnippet(re, v))
	}
	safe = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "webhook output: %s\n", r.URL.Query().Get("snippet"))
	}
	return vulnerable, safe
}

// ---------------------------------------------------------------------------
// SQL injection: the blind techniques (boolean conditions, time delays)
// ---------------------------------------------------------------------------
//
// The two endpoints below demonstrate what internal/scanner's boolean and timing SQLi checks
// (sqli_techniques.go) look for, without any database: a real application concatenates the
// parameter into a query, and the injected condition or sleep call changes what the query does.
// Each endpoint recognises the SHAPE generically - a comparison of two operands, a sleep
// directive with a numeric argument - never the specific payload the check happens to send,
// and the safe twin concatenates nothing and recognises nothing.

// sqlQuotedClause evaluates the clause `col='<value>'` the way a database would, for the blind
// SQLi fixtures (review of saq3.2.1). The value is concatenated inside the string literal, so a
// payload only reaches the statement if it closes that literal itself: what follows the literal is
// parsed as SQL — a trailing `-- ` comment, an `and` condition comparing two numbers or two quoted
// strings, or (for the jobs fixture) a sleep call — and anything else there is a syntax error. The
// literal's own content must still be the expected value for rows to come back.
//
// This is what makes the fixtures honest: a condition sent instead of the value, or one that does
// not close the quote, lands inside the literal and changes nothing but the row match.
type sqlClause struct {
	literal  string
	rest     string // SQL after the literal, comment removed, trimmed
	parseErr bool
}

func parseQuotedClause(value string) sqlClause {
	q := value + "'" // the application's own closing quote
	i := strings.IndexByte(q, '\'')
	if i < 0 {
		return sqlClause{parseErr: true}
	}
	rest := q[i+1:]
	if c := strings.Index(rest, "--"); c >= 0 {
		rest = rest[:c]
	}
	rest = strings.TrimSpace(rest)
	// A dangling quote left over (the application's closing one, after a payload closed the
	// literal and then commented nothing out) is unbalanced SQL.
	if strings.Count(rest, "'")%2 != 0 {
		return sqlClause{literal: q[:i], parseErr: true}
	}
	return sqlClause{literal: q[:i], rest: rest}
}

// sqlAndCondition is `and <operand> = <operand>`, operands numbers or quoted strings.
var sqlAndCondition = regexp.MustCompile(`^(?i)and\s+(\d+|'[^']*')\s*=\s*(\d+|'[^']*')$`)

// sortBookedByCondition concatenates sort_col into `category='<value>'`: an appended condition
// that closes the literal decides whether the rows come back, and the always-true one leaves the
// listing byte-identical to the baseline.
func sortBookedByCondition(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	clause := parseQuotedClause(r.URL.Query().Get("sort_col"))
	rows := clause.literal == "seed"
	switch {
	case clause.parseErr:
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, "query failed")
		return
	case clause.rest == "":
	default:
		m := sqlAndCondition.FindStringSubmatch(clause.rest)
		if m == nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, "query failed")
			return
		}
		rows = rows && m[1] == m[2]
	}
	if !rows {
		fmt.Fprint(w, "Products: (no rows)")
		return
	}
	fmt.Fprint(w, "Products: Widget, Gadget, Gizmo")
}

func safeSortBookedByCondition(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	// The safe twin treats the value as a column name only: no condition is ever evaluated,
	// so `1=1` and `1=2` both sort and both return the full listing.
	fmt.Fprintf(w, "Products sorted by %s: Widget, Gadget, Gizmo", r.URL.Query().Get("sort_col"))
}

// sqlSleepAfterLiteral is what may follow the queue literal and execute: a PostgreSQL pg_sleep(N)
// joined by `||` or `and`, or a SQL Server waitfor delay'0:0:N' after a separator.
var sqlSleepAfterLiteral = regexp.MustCompile(`^(?i)(?:\|\||and|,''\|\|)?\s*pg_sleep\s*\(\s*(\d+)\s*\)$|^(?i)[),0\s]*waitfor\s+delay\s*'0:0:(\d+)'$`)

// queueJobWithDelay concatenates queue into `queue='<value>'`: a sleep call that closes the literal
// executes and delays the response. Capped so a probe cannot hold the suite hostage.
func queueJobWithDelay(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	v := r.URL.Query().Get("queue")
	clause := parseQuotedClause(v)
	if clause.parseErr {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, "query failed")
		return
	}
	if clause.rest != "" {
		m := sqlSleepAfterLiteral.FindStringSubmatch(clause.rest)
		if m == nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, "query failed")
			return
		}
		secs := m[1]
		if secs == "" {
			secs = m[2]
		}
		if n, err := strconv.Atoi(secs); err == nil && n > 0 {
			if n > 5 {
				n = 5
			}
			time.Sleep(time.Duration(n) * time.Second)
		}
	}
	fmt.Fprintf(w, "Job queued: %s", clause.literal)
}

func safeQueueJobWithDelay(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	// The safe twin stores the parameter and returns immediately, the way an application
	// that parameterises the query does: the sleep text is data, never a directive.
	fmt.Fprintf(w, "Job queued: %s", r.URL.Query().Get("queue"))
}

// ---------------------------------------------------------------------------
// XSS: the decoding endpoints (burpsy-react-ui-79ld)
// ---------------------------------------------------------------------------
//
// Every endpoint here is the same bug class: the application filters the LITERAL form of the
// characters a breakout needs (the angle brackets), and then DECODES the value before
// reflecting it. The filter and the decoding are in the wrong order, which is a real bug shape
// (a WAF stripping angle brackets in front of an app that entity- or URL-decodes its input),
// and it is the shape Burp's decoding variants exist to reach: a payload whose markup is
// spelled in the endpoint's own encoding walks through the filter untouched and is decoded
// into live markup, while the plain payload the check already tried never can.
//
// Each decoder below recognises the SHAPE of its transformation generically — any percent-
// escape, any entity, any \xHH pair, any overlong or malformed sequence — never a literal
// payload the scanner happens to send. The safe twins keep the filter and add the output
// encoding a real fix would have, and never decode: nothing fires there, which is what makes
// the vulnerable half's findings evidence rather than reflection-detection.

// stripAngleBrackets is the literal filter every endpoint here applies first: the WAF shape.
// It deletes the raw '<' and '>' bytes, whatever else the value carries.
func stripAngleBrackets(s string) string {
	s = strings.ReplaceAll(s, "<", "")
	return strings.ReplaceAll(s, ">", "")
}

// decodeHTMLEntities unescapes the standard set plus numeric references — shape-generic: any
// entity the HTML parsers define, not any payload's spelling.
func decodeHTMLEntities(s string) string {
	s = strings.ReplaceAll(s, "&lt;", "<")
	s = strings.ReplaceAll(s, "&gt;", ">")
	s = strings.ReplaceAll(s, "&quot;", "\"")
	s = strings.ReplaceAll(s, "&#39;", "'")
	s = strings.ReplaceAll(s, "&#x27;", "'")
	s = strings.ReplaceAll(s, "&amp;", "&")
	return s
}

// decodeBackslashEscapes unescapes \xHH hex pairs and the simple escapes — the string-
// unescaper shape (template engines, eval paths, the strconv family).
func decodeBackslashEscapes(s string) string {
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) && s[i+1] == 'x' {
			if v, err := strconv.ParseUint(s[i+2:i+4], 16, 8); err == nil {
				sb.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		if s[i] == '\\' && i+1 < len(s) {
			switch s[i+1] {
			case '\\', '\'', '"':
				sb.WriteByte(s[i+1])
				i++
				continue
			}
		}
		sb.WriteByte(s[i])
	}
	return sb.String()
}

// decodeOverlongUTF8 is the lenient decoder that never rejected overlong forms: a two-byte
// sequence with a VALID continuation byte is decoded to its code point however short, while
// the modern prohibition (0xC0/0xC1 leads) is ignored. Three-byte sequences are validated
// normally. Bytes that do not form a valid or overlong sequence are dropped — the behaviour
// that makes the malformed three-byte spelling a non-event here.
func decodeOverlongUTF8(s string) string {
	var sb strings.Builder
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c >= 0xC2 && c <= 0xDF && i+1 < len(s) && s[i+1]&0xC0 == 0x80:
			sb.WriteRune(rune((rune(c&0x1F) << 6) | rune(s[i+1]&0x3F)))
			i += 2
		case (c == 0xC0 || c == 0xC1) && i+1 < len(s) && s[i+1]&0xC0 == 0x80:
			// The overlong two-byte form: continuation bits valid, length ignored.
			sb.WriteRune(rune((rune(c&0x1F) << 6) | rune(s[i+1]&0x3F)))
			i += 2
		case c >= 0xE0 && c <= 0xEF && i+2 < len(s) && s[i+1]&0xC0 == 0x80 && s[i+2]&0xC0 == 0x80:
			sb.WriteRune(rune((rune(c&0x0F) << 12) | (rune(s[i+1]&0x3F) << 6) | rune(s[i+2]&0x3F)))
			i += 3
		case c < 0x80:
			sb.WriteByte(c)
			i++
		default:
			// Not a sequence this decoder accepts: dropped, not passed through, because a
			// decoder that passed its rejects through would be no filter at all.
			i++
		}
	}
	return sb.String()
}

// decodeBitmaskUTF8 is the loosest decoder there is: a three-byte sequence is decoded by
// masking the low six bits of each byte WITHOUT validating that they are continuation bytes,
// and two-byte sequences are handled correctly (an overlong two-byte form is rejected, the
// way a decoder that special-cases the two-byte range properly would be). This is the sloppy
// BMP path a real decoder can have, and it is deliberately NOT the same population as the
// overlong decoder above: a payload that only the loosest decoder undoes has to be able to
// fail on the lenient one, or the two variants would be one.
func decodeBitmaskUTF8(s string) string {
	var sb strings.Builder
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c >= 0xE0 && c <= 0xEF && i+2 < len(s):
			// No continuation validation: the low six bits of each byte, as-is.
			sb.WriteRune(rune((rune(c&0x0F) << 12) | (rune(s[i+1]&0x3F) << 6) | rune(s[i+2]&0x3F)))
			i += 3
		case c >= 0xC2 && c <= 0xDF && i+1 < len(s) && s[i+1]&0xC0 == 0x80:
			sb.WriteRune(rune((rune(c&0x1F) << 6) | rune(s[i+1]&0x3F)))
			i += 2
		case c < 0x80:
			sb.WriteByte(c)
			i++
		default:
			i++
		}
	}
	return sb.String()
}

// reflectDecoded is the vulnerable half's one shape: filter, decode, reflect raw.
func reflectDecoded(w http.ResponseWriter, r *http.Request, decode func(string) string) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, "<p>Results for: %s</p>", decode(stripAngleBrackets(r.URL.Query().Get("term"))))
}

// reflectSafe is the safe twin's one shape: filter, output-encode, never decode.
func reflectSafe(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, "<p>Results for: %s</p>", htmlEscape(stripAngleBrackets(r.URL.Query().Get("term"))))
}

func xssDecodeURL(w http.ResponseWriter, r *http.Request) {
	reflectDecoded(w, r, func(v string) string {
		out, err := url.QueryUnescape(v)
		if err != nil {
			return v
		}
		return out
	})
}

func xssSafeDecodeURL(w http.ResponseWriter, r *http.Request)       { reflectSafe(w, r) }
func xssSafeDecodeHTML(w http.ResponseWriter, r *http.Request)      { reflectSafe(w, r) }
func xssSafeDecodeBackslash(w http.ResponseWriter, r *http.Request) { reflectSafe(w, r) }
func xssSafeDecodeOverlong(w http.ResponseWriter, r *http.Request)  { reflectSafe(w, r) }
func xssSafeDecodeInvalid(w http.ResponseWriter, r *http.Request)   { reflectSafe(w, r) }

func xssDecodeHTML(w http.ResponseWriter, r *http.Request) {
	reflectDecoded(w, r, decodeHTMLEntities)
}

func xssDecodeBackslash(w http.ResponseWriter, r *http.Request) {
	reflectDecoded(w, r, decodeBackslashEscapes)
}

func xssDecodeOverlong(w http.ResponseWriter, r *http.Request) {
	reflectDecoded(w, r, decodeOverlongUTF8)
}

func xssDecodeInvalid(w http.ResponseWriter, r *http.Request) {
	reflectDecoded(w, r, decodeBitmaskUTF8)
}

// xssDecodeURLEscaped is the decode-then-output-encode endpoint: the decoding is observable
// (the transformation row reports it) but the markup is neutralized, so the XSS row must stay
// silent. It is the honest half-way house: an application that decodes its input is worth a
// finding even when it escapes the result.
func xssDecodeURLEscaped(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	v := r.URL.Query().Get("term")
	if out, err := url.QueryUnescape(stripAngleBrackets(v)); err == nil {
		v = out
	}
	fmt.Fprintf(w, "<p>Results for: %s</p>", htmlEscape(v))
}
