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
	"path"
	"regexp"
	"strconv"
	"strings"
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
