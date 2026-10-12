package scanner

// The wired injection evaluators against real local servers: one deliberately vulnerable
// handler per family, plus a safe handler that reflects input without acting on it. The safe
// case is the one that matters — an evaluator that fires on a reflecting server is a false
// positive generator, and reflection is what most endpoints do.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/burpsy-go/burpsy/internal/bcheck"
)

// injectionFixture wires a CheckContext against a live handler with one query parameter.
func injectionFixture(t *testing.T, handler http.HandlerFunc) *CheckContext {
	t.Helper()
	return harnessAgainst(t, handler, "/probe?input=seed")
}

// echoServer reflects the parameter verbatim and evaluates nothing. Every evaluator must stay
// quiet against it.
func echoServer(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "<html><body>you searched for %s</body></html>", r.URL.Query().Get("input"))
}

func runCheck(t *testing.T, fn CheckRunner, cc *CheckContext) []*Finding {
	t.Helper()
	got, err := fn(context.Background(), cc)
	if err != nil {
		t.Fatalf("check returned error: %v", err)
	}
	return got
}

// requireUndecided asserts the honest middle verdict: no finding, and the check saying so
// because its evidence could not be judged rather than because the endpoint looked clean.
// Asserting a nil error here would forbid the distinction this scanner exists to draw.
func requireUndecided(t *testing.T, fn CheckRunner, cc *CheckContext) {
	t.Helper()
	got, err := fn(context.Background(), cc)
	if len(got) != 0 {
		t.Fatalf("got %d findings, want 0 - nothing here was provable", len(got))
	}
	if !errors.Is(err, errCheckInconclusive) {
		t.Fatalf("err = %v, want the inconclusive sentinel: silence on an endpoint that cannot be "+
			"judged must be reported as undecided, never as clean", err)
	}
}

func requireInjectionFinding(t *testing.T, got []*Finding, wantName string) *Finding {
	t.Helper()
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	if got[0].Name != wantName {
		t.Fatalf("name = %q, want %q", got[0].Name, wantName)
	}
	if got[0].Param == "" {
		t.Errorf("finding does not name the parameter it was found in: %+v", got[0])
	}
	if !strings.Contains(got[0].Description, "insertion point") {
		t.Errorf("description should carry the coverage line: %q", got[0].Description)
	}
	return got[0]
}

// ---------- XPath ----------

func TestXPathInjectionFiresOnAnXPathErrorAndNotOnReflection(t *testing.T) {
	vuln := injectionFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.ContainsAny(r.URL.Query().Get("input"), `'"`) {
			fmt.Fprint(w, "javax.xml.xpath.XPathExpressionException: bad expression")
			return
		}
		fmt.Fprint(w, "results")
	})
	f := requireInjectionFinding(t, runCheck(t, checkXPathInjection, vuln), "XPath injection")
	if f.Confidence != "firm" {
		t.Errorf("confidence = %q, want firm for an error-signature verdict", f.Confidence)
	}

	safe := injectionFixture(t, echoServer)
	if got := runCheck(t, checkXPathInjection, safe); len(got) != 0 {
		t.Fatalf("got %d findings against a reflecting server, want 0", len(got))
	}
}

// An endpoint that always emits an XPath error proves nothing. The baseline already carries the
// discriminator, so the verdict is undecided - reporting it as clean would be a false negative.
func TestXPathInjectionReportsUndecidedOnAnAlwaysErroringEndpoint(t *testing.T) {
	cc := injectionFixture(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "System.Xml.XPath error, always")
	})
	requireUndecided(t, checkXPathInjection, cc)
}

// ---------- LDAP ----------

func TestLDAPInjectionFiresOnABooleanDifferential(t *testing.T) {
	cc := injectionFixture(t, func(w http.ResponseWriter, r *http.Request) {
		in := r.URL.Query().Get("input")
		switch {
		case strings.HasPrefix(in, "!("):
			fmt.Fprint(w, "no entries found")
		default:
			fmt.Fprint(w, "entries: alice bob")
		}
	})
	f := requireInjectionFinding(t, runCheck(t, checkLDAPInjection, cc), "LDAP injection")
	if f.Confidence != "tentative" {
		t.Errorf("confidence = %q, want tentative for a boolean differential", f.Confidence)
	}
}

func TestLDAPInjectionFiresOnADirectoryError(t *testing.T) {
	cc := injectionFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("input"), "(") {
			fmt.Fprint(w, "javax.naming.directory.InvalidSearchFilterException")
			return
		}
		fmt.Fprint(w, "entries: alice bob")
	})
	requireInjectionFinding(t, runCheck(t, checkLDAPInjection, cc), "LDAP injection")
}

func TestLDAPInjectionReportsUndecidedOnReflection(t *testing.T) {
	cc := injectionFixture(t, echoServer)
	requireUndecided(t, checkLDAPInjection, cc)
}

// ---------- file path manipulation ----------

func TestFilePathManipulationFiresOnRealFileContent(t *testing.T) {
	cc := injectionFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("input"), "etc/passwd") {
			fmt.Fprint(w, "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:")
			return
		}
		fmt.Fprint(w, "file not found")
	})
	requireInjectionFinding(t, runCheck(t, checkFilePathManipulation, cc), "File path manipulation")
}

// The row needs file *content*. A server that merely echoes the traversal string back has not
// read anything, and reporting it would be a false positive on any reflecting endpoint.
func TestFilePathManipulationStaysQuietWhenOnlyThePayloadIsReflected(t *testing.T) {
	cc := injectionFixture(t, echoServer)
	if got := runCheck(t, checkFilePathManipulation, cc); len(got) != 0 {
		t.Fatalf("got %d findings from a reflected traversal string, want 0", len(got))
	}
}

// ---------- OS command ----------

// shellArith is a POSIX `$((a*b))` arithmetic expansion; arithProduct is any bare `a*b`.
var (
	shellArith   = regexp.MustCompile(`\$\(\(\s*(\d+)\s*\*\s*(\d+)\s*\)\)`)
	arithProduct = regexp.MustCompile(`(\d+)\s*\*\s*(\d+)`)
)

func multiply(m []string) string {
	a, _ := strconv.Atoi(m[1])
	b, _ := strconv.Atoi(m[2])
	return strconv.Itoa(a * b)
}

// simulatedShell is what `sh -c "ping " + input` prints: arithmetic expansion first, then the
// argument of any echo that follows a separator. It evaluates whatever operands arrive, so no
// particular payload is privileged.
func simulatedShell(in string) (string, bool) {
	in = shellArith.ReplaceAllStringFunc(in, func(m string) string { return multiply(shellArith.FindStringSubmatch(m)) })
	i := strings.IndexAny(in, ";&|\n")
	if i < 0 {
		return "", false
	}
	rest := strings.TrimSpace(in[i+1:])
	if !strings.HasPrefix(rest, "echo ") {
		return "", false
	}
	return strings.Trim(strings.Fields(rest)[1], ";&|"), true
}

func TestOSCommandInjectionFiresWhenTheShellEchoesTheMarker(t *testing.T) {
	cc := injectionFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if out, ran := simulatedShell(r.URL.Query().Get("input")); ran {
			fmt.Fprintf(w, "PING output\n%s\n", out)
			return
		}
		fmt.Fprint(w, "PING output for a host")
	})
	f := requireInjectionFinding(t, runCheck(t, checkOSCommandInjection, cc), "OS command injection")
	if f.Confidence != "certain" {
		t.Errorf("confidence = %q, want certain for an evaluated payload", f.Confidence)
	}
	if !strings.Contains(f.Description, "reproduced with an independent second challenge") {
		t.Errorf("a finding must rest on two independent challenges: %q", f.Description)
	}
}

// The tightened form of the old critical case: the server reflects the whole payload. The proof is
// computed by the shell and never spelled in the payload, so a reflection is now decisively clean —
// no finding and no undecided verdict either.
func TestOSCommandInjectionStaysCleanWhenThePayloadIsMerelyReflected(t *testing.T) {
	cc := injectionFixture(t, echoServer)
	if got := runCheck(t, checkOSCommandInjection, cc); len(got) != 0 {
		t.Fatalf("got %d findings against a reflecting server, want 0", len(got))
	}
}

// reflectionFixtures are endpoints that run nothing but give the payload back TRANSFORMED, which
// is what defeated the old echo subtraction on OWASP VulnerableApp (j1mk.34): each of these was
// reported as OS command injection at certain confidence.
func reflectionFixtures() map[string]http.HandlerFunc {
	var mu sync.Mutex
	var stored []string
	return map[string]http.HandlerFunc{
		// A JSON API: the newline in "\necho X\n" comes back as the two characters `\n`.
		"json-escaped": func(w http.ResponseWriter, r *http.Request) {
			b, _ := json.Marshal(map[string]string{"content": r.URL.Query().Get("input")})
			w.Write(b)
		},
		// H2's syntax error: quotes doubled, newlines written as \000a, a [*] cursor inserted.
		"sql-error": func(w http.ResponseWriter, r *http.Request) {
			in := r.URL.Query().Get("input")
			if in == "seed" {
				fmt.Fprint(w, `{"isCarPresent": true}`)
				return
			}
			q := strings.NewReplacer(`"`, `""`, "\n", `\000a`).Replace(in)
			fmt.Fprintf(w, `Syntax error in SQL statement "select * from cars where id=[*]%s"; [42000-214]`, q)
		},
		// A stored comment list: every earlier probe is rendered back alongside the current one,
		// so a payload sent later never covers the marker an earlier one planted.
		"stored": func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			defer mu.Unlock()
			if in := r.URL.Query().Get("input"); in != "seed" {
				stored = append(stored, in)
			}
			fmt.Fprintf(w, "<ul><li>%s</li></ul>", strings.Join(stored, "</li><li>"))
		},
		// Partial HTML escaping: only the double quote is escaped.
		"half-escaped": func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "<p>Banner: %s</p>", strings.ReplaceAll(r.URL.Query().Get("input"), `"`, "&quot;"))
		},
	}
}

func TestEvaluationChecksStayCleanOnTransformedAndStoredReflections(t *testing.T) {
	checks := map[string]CheckRunner{
		"OS command": checkOSCommandInjection,
		"template":   checkServerSideTemplateInjection,
		"EL":         checkExpressionLanguageInjection,
		"python":     codeInjectionCheck("Python code injection", "python", "high"),
		"php":        codeInjectionCheck("PHP code injection", "php", "high"),
		"perl":       codeInjectionCheck("Perl code injection", "perl", "high"),
		"ruby":       codeInjectionCheck("Ruby code injection", "ruby", "high"),
		"javascript": codeInjectionCheck("Server-side JavaScript code injection", "javascript", "high"),
	}
	for fixture, handler := range reflectionFixtures() {
		for name, fn := range checks {
			t.Run(fixture+"/"+name, func(t *testing.T) {
				got, err := fn(context.Background(), injectionFixture(t, handler))
				if len(got) != 0 {
					t.Fatalf("got %d finding(s) on an endpoint that only reflects its input: %s", len(got), got[0].Description)
				}
				if err != nil && !errors.Is(err, errCheckInconclusive) {
					t.Fatalf("unexpected error: %v", err)
				}
			})
		}
	}
}

// ---------- interpreted languages ----------

// evaluatingServer computes every a*b product in the input and prints only the results: an
// interpreter, without an echo.
func evaluatingServer(w http.ResponseWriter, r *http.Request) {
	ms := arithProduct.FindAllStringSubmatch(r.URL.Query().Get("input"), -1)
	if len(ms) == 0 {
		fmt.Fprint(w, "computed: nothing")
		return
	}
	var outs []string
	for _, m := range ms {
		outs = append(outs, multiply(m))
	}
	fmt.Fprint(w, "computed: "+strings.Join(outs, ","))
}

func TestCodeInjectionFiresOnAnEvaluatingServerPerLanguage(t *testing.T) {
	for _, tc := range []struct{ row, lang string }{
		{"PHP code injection", "php"},
		{"Perl code injection", "perl"},
		{"Ruby code injection", "ruby"},
		{"Python code injection", "python"},
		{"Server-side JavaScript code injection", "javascript"},
	} {
		t.Run(tc.lang, func(t *testing.T) {
			cc := injectionFixture(t, evaluatingServer)
			f := requireInjectionFinding(t, runCheck(t, codeInjectionCheck(tc.row, tc.lang, "high"), cc), tc.row)
			if !strings.Contains(f.Description, "context") {
				t.Errorf("finding should name the quoting context: %q", f.Description)
			}
		})
	}
}

func TestCodeInjectionStaysQuietOnReflection(t *testing.T) {
	cc := injectionFixture(t, echoServer)
	for _, lang := range []string{"php", "perl", "ruby", "python", "javascript"} {
		got := runCheck(t, codeInjectionCheck("PHP code injection", lang, "high"), cc)
		if len(got) != 0 {
			t.Errorf("%s: got %d findings against a reflecting server, want 0", lang, len(got))
		}
	}
}

// The recovered 7*6 made "42" the proof, and "42" turns up on its own: in an error code, a random
// token, a row count. A page that shows "42" only when the input is not the baseline value — an
// error page, here — was reported as code injection by every language. With drawn operands the
// page proves nothing and says nothing.
func TestCodeInjectionIgnoresAFortyTwoTheEndpointPrintsOnItsOwn(t *testing.T) {
	cc := injectionFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("input") == "seed" {
			fmt.Fprint(w, "ok")
			return
		}
		fmt.Fprint(w, "error [42000-214], token 4242")
	})
	for _, lang := range []string{"php", "perl", "ruby", "python", "javascript"} {
		got, err := codeInjectionCheck("PHP code injection", lang, "high")(context.Background(), cc)
		if len(got) != 0 || err != nil {
			t.Errorf("%s: got %d finding(s), err %v; want clean", lang, len(got), err)
		}
	}
	for name, fn := range map[string]CheckRunner{"template": checkServerSideTemplateInjection, "el": checkExpressionLanguageInjection} {
		if got, err := fn(context.Background(), cc); len(got) != 0 || err != nil {
			t.Errorf("%s: got %d finding(s), err %v; want clean", name, len(got), err)
		}
	}
}

// ---------- template and expression language ----------

func TestTemplateInjectionFiresOnAnEvaluatingTemplateEngine(t *testing.T) {
	tmpl := regexp.MustCompile(`(?:\$\{|\{\{|#\{|<%=)\s*(\d+)\*(\d+)\s*(?:\}\}|\}|%>)`)
	cc := injectionFixture(t, func(w http.ResponseWriter, r *http.Request) {
		in := r.URL.Query().Get("input")
		fmt.Fprint(w, "rendered: "+tmpl.ReplaceAllStringFunc(in, func(m string) string { return multiply(tmpl.FindStringSubmatch(m)) }))
	})
	requireInjectionFinding(t, runCheck(t, checkServerSideTemplateInjection, cc), "Server-side template injection")
}

func TestExpressionLanguageInjectionFiresOnAnEvaluatingEL(t *testing.T) {
	el := regexp.MustCompile(`^\$\{(\d+)\*(\d+)\}$`)
	cc := injectionFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if m := el.FindStringSubmatch(r.URL.Query().Get("input")); m != nil {
			fmt.Fprint(w, "value: "+multiply(m))
			return
		}
		fmt.Fprint(w, "value: none")
	})
	requireInjectionFinding(t, runCheck(t, checkExpressionLanguageInjection, cc), "Expression Language injection")
}

func TestTemplateAndELStayQuietOnReflection(t *testing.T) {
	cc := injectionFixture(t, echoServer)
	for name, fn := range map[string]CheckRunner{
		"template": checkServerSideTemplateInjection,
		"el":       checkExpressionLanguageInjection,
	} {
		if got := runCheck(t, fn, cc); len(got) != 0 {
			t.Errorf("%s: got %d findings against a reflecting server, want 0", name, len(got))
		}
	}
}

// ---------- capability and wiring invariants ----------

// No sender means the check could not look. That must surface as an error so the audit engine
// counts a refusal, not as nil findings that read as a clean result.
func TestInjectionChecksReportAnErrorWhenTheyCannotProbe(t *testing.T) {
	cc := postureFixture(t, "GET /?input=1 HTTP/1.1\r\nHost: app.test\r\n\r\n", htmlResponse("ok"), false)
	for _, d := range InjectionCheckDescriptors() {
		if _, err := d.Run(context.Background(), cc); err == nil {
			t.Errorf("%q returned no error with no sender configured; a caller would read that as clean", d.Name)
		}
	}
}

func TestEveryInjectionDescriptorIsRunnableAndGated(t *testing.T) {
	descs := InjectionCheckDescriptors()
	if len(descs) != 12 {
		t.Fatalf("got %d descriptors, want 12", len(descs))
	}
	seen := map[uint32]string{}
	for _, d := range descs {
		if !d.Runnable() || !d.Valid() {
			t.Errorf("%q is not a valid runnable descriptor", d.Name)
		}
		if d.Enabled == nil || d.Enabled(&ScanConfig{}) {
			t.Errorf("%q is admitted with the flag off", d.Name)
		}
		if !d.Enabled(&ScanConfig{CheckActiveInjection: true}) {
			t.Errorf("%q is not admitted with CheckActiveInjection set", d.Name)
		}
		if prev, dup := seen[d.TypeIndex]; dup {
			t.Errorf("TypeIndex %d claimed by both %q and %q", d.TypeIndex, prev, d.Name)
		}
		seen[d.TypeIndex] = d.Name
	}
}

// The point cap must show up as reduced coverage rather than as a silently short scan.
func TestInjectionPointCapIsReportedNotHidden(t *testing.T) {
	var params []string
	for i := range MaxInjectionPointsPerCheck + 4 {
		params = append(params, fmt.Sprintf("p%d=v%d", i, i))
	}
	cc := harnessAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "nothing interesting")
	}, "/many?"+strings.Join(params, "&"))

	h, err := NewProbeHarness(context.Background(), cc, []string{"query"})
	if err != nil {
		t.Fatalf("NewProbeHarness: %v", err)
	}
	// The fixture builds MaxInjectionPointsPerCheck+4 query parameters, so falling short here
	// means enumeration dropped points — a bug to surface, never a reason to skip the cap test.
	if len(h.Points()) <= MaxInjectionPointsPerCheck {
		t.Fatalf("enumerated %d points from %d query parameters, want more than the cap %d; the cap cannot be exercised and enumeration is losing points",
			len(h.Points()), MaxInjectionPointsPerCheck+4, MaxInjectionPointsPerCheck)
	}
	res, err := runInjection(context.Background(), cc, "test", []string{"query"},
		func(h *ProbeHarness, p bcheck.InsertionPoint) []InjectionProbe {
			return h.ProbeErrorSignatures(context.Background(), p, []string{"'"}, SQLErrorSignatures)
		})
	if err != nil {
		t.Fatalf("runInjection: %v", err)
	}
	if res.coverage.PointsTested != MaxInjectionPointsPerCheck {
		t.Fatalf("PointsTested = %d, want the cap %d", res.coverage.PointsTested, MaxInjectionPointsPerCheck)
	}
}

func TestInjectionParamFromDetailExtractsTheName(t *testing.T) {
	if got := injectionParamFromDetail(`query "input": introduced ORA-`); got != "input" {
		t.Fatalf("got %q, want input", got)
	}
	if got := injectionParamFromDetail("no quotes here"); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}
