package scanner

// The wired injection evaluators against real local servers: one deliberately vulnerable
// handler per family, plus a safe handler that reflects input without acting on it. The safe
// case is the one that matters — an evaluator that fires on a reflecting server is a false
// positive generator, and reflection is what most endpoints do.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
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

func TestOSCommandInjectionFiresWhenTheShellEchoesTheMarker(t *testing.T) {
	cc := injectionFixture(t, func(w http.ResponseWriter, r *http.Request) {
		in := r.URL.Query().Get("input")
		// Crude shell simulation: anything after a metacharacter "runs".
		if i := strings.IndexAny(in, ";&|\n"); i >= 0 {
			rest := in[i+1:]
			if strings.HasPrefix(strings.TrimSpace(rest), "echo ") {
				word := strings.Fields(strings.TrimSpace(rest))[1]
				fmt.Fprintf(w, "PING output\n%s\n", strings.Trim(word, ";&|"))
				return
			}
		}
		fmt.Fprint(w, "PING output for a host")
	})
	f := requireInjectionFinding(t, runCheck(t, checkOSCommandInjection, cc), "OS command injection")
	if f.Confidence != "certain" {
		t.Errorf("confidence = %q, want certain for an evaluated payload", f.Confidence)
	}
}

// The critical false-positive case: the server reflects the whole payload, so the marker is
// present in the response without any command having run.
func TestOSCommandInjectionReportsUndecidedWhenThePayloadIsMerelyReflected(t *testing.T) {
	cc := injectionFixture(t, echoServer)
	requireUndecided(t, checkOSCommandInjection, cc)
}

// ---------- interpreted languages ----------

func TestCodeInjectionFiresOnAnEvaluatingServerPerLanguage(t *testing.T) {
	for _, tc := range []struct{ row, lang string }{
		{"PHP code injection", "php"},
		{"Perl code injection", "perl"},
		{"Ruby code injection", "ruby"},
		{"Python code injection", "python"},
		{"Server-side JavaScript code injection", "javascript"},
	} {
		t.Run(tc.lang, func(t *testing.T) {
			cc := injectionFixture(t, func(w http.ResponseWriter, r *http.Request) {
				// Evaluates the arithmetic without echoing the payload.
				if strings.Contains(r.URL.Query().Get("input"), "7*6") {
					fmt.Fprint(w, "computed: 42")
					return
				}
				fmt.Fprint(w, "computed: nothing")
			})
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

// A page that already contains "42" must not make every payload look evaluated. It also cannot be
// called clean: the product was there before any probe, so nothing about the probe is knowable.
func TestCodeInjectionReportsUndecidedWhenTheBaselineAlreadyContainsTheProduct(t *testing.T) {
	cc := injectionFixture(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "the answer is 42, always")
	})
	requireUndecided(t, codeInjectionCheck("PHP code injection", "php", "high"), cc)
}

// ---------- template and expression language ----------

func TestTemplateInjectionFiresOnAnEvaluatingTemplateEngine(t *testing.T) {
	cc := injectionFixture(t, func(w http.ResponseWriter, r *http.Request) {
		in := r.URL.Query().Get("input")
		for _, open := range []string{"${", "{{", "#{", "<%="} {
			if strings.Contains(in, open+"7*6") || strings.Contains(in, open+" 7*6") {
				fmt.Fprint(w, "rendered: 42")
				return
			}
		}
		fmt.Fprint(w, "rendered: "+in)
	})
	requireInjectionFinding(t, runCheck(t, checkServerSideTemplateInjection, cc), "Server-side template injection")
}

func TestExpressionLanguageInjectionFiresOnAnEvaluatingEL(t *testing.T) {
	cc := injectionFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("input"), "${7*6}") {
			fmt.Fprint(w, "value: 42")
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
	res, err := runInjection(context.Background(), cc, []string{"query"},
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
