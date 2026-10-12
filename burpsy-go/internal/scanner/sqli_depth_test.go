package scanner

// burpsy-react-ui-v0ei.2 (sqlmap's error bank) and v0ei.4 (boolean detection on dynamic pages),
// end to end through an AuditSession against vulnapp, with the safe twins and the guards' negative
// controls.

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/vulnapp"
)

// sqliDepthEngineDBMS is the DBMS each simulated engine's error must be attributed to.
var sqliDepthEngineDBMS = map[string]string{
	"sqlite":     "SQLite",
	"h2":         "H2",
	"clickhouse": "ClickHouse",
	"snowflake":  "Snowflake",
	"hsqldb":     "HSQLDB",
	"firebird":   "Firebird",
}

func auditSQLi(t *testing.T, path string, cfg *ScanConfig) []*Finding {
	t.Helper()
	scan, id := blindSQLiTarget(t, path)
	if cfg != nil {
		scan.WithConfig(cfg)
	}
	_, findings := scan.AuditSession(context.Background(), []core.ExchangeID{id}, AuditConfig{})
	return sqliFindingsNamed(findings, sqlInjectionIssue)
}

func vulnappGet(t *testing.T, srv *httptest.Server, path, param, value string) string {
	t.Helper()
	resp, err := srv.Client().Get(srv.URL + path + "?" + param + "=" + url.QueryEscape(value))
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

// Each engine's own error is new to the substring bank, is caught by sqlmap's, names its DBMS, and
// follows the evidence rule: present for the broken literal, absent for the repaired one.
func TestSqlmapBankClassifiesEachEnginesErrorAndItsRepairedControl(t *testing.T) {
	srv := httptest.NewServer(vulnapp.Handler())
	defer srv.Close()
	if len(vulnapp.DBErrorEngines()) != len(sqliDepthEngineDBMS) {
		t.Fatalf("vulnapp simulates %v; this test names %d engines", vulnapp.DBErrorEngines(), len(sqliDepthEngineDBMS))
	}
	for _, engine := range vulnapp.DBErrorEngines() {
		path := "/ij/dberr/" + engine + "/accounts"
		base := vulnappGet(t, srv, path, "owner", "seed")
		broken := vulnappGet(t, srv, path, "owner", "seed'")
		repaired := vulnappGet(t, srv, path, "owner", "seed''")
		if sub := ClassifyErrorEvidence(base, broken, SQLErrorSignatures); sub.Evidence == InjectionEvidenceErrorSignature {
			t.Errorf("%s: the substring bank already matches %v, so this engine is not newly covered", engine, sub.Matched)
		}
		got := ClassifySQLError(base, broken)
		if got.Evidence != InjectionEvidenceErrorSignature {
			t.Errorf("%s: broken literal: evidence = %v, want an error signature; body %q", engine, got.Evidence, broken)
			continue
		}
		want := sqliDepthEngineDBMS[engine]
		if len(got.DBMS) == 0 || !strings.HasPrefix(got.DBMS[0], want) {
			t.Errorf("%s: DBMS = %v, want %s", engine, got.DBMS, want)
		}
		for _, d := range got.DBMS {
			if !strings.HasPrefix(d, want) {
				t.Errorf("%s: the error was also attributed to %s", engine, d)
			}
		}
		if rep := ClassifySQLError(base, repaired); rep.Evidence != InjectionEvidenceNone {
			t.Errorf("%s: repaired literal: evidence = %v (%v), want none", engine, rep.Evidence, rep.Matched)
		}
	}
}

// The audit finds each engine's endpoint through the error technique and the finding names the DBMS.
func TestTheErrorTechniqueFindsEachNewEngineAndNamesItsDBMS(t *testing.T) {
	for _, engine := range vulnapp.DBErrorEngines() {
		engine := engine
		t.Run(engine, func(t *testing.T) {
			t.Parallel()
			got := auditSQLi(t, "/ij/dberr/"+engine+"/accounts?owner=seed", nil)
			if len(got) == 0 {
				t.Fatalf("no %q finding on the %s error endpoint", sqlInjectionIssue, engine)
			}
			d := got[0].Description
			if !strings.Contains(d, InjectionEvidenceErrorSignature.String()) {
				t.Errorf("finding is not error-signature evidence: %s", d)
			}
			if !strings.Contains(d, "identifies the DBMS as "+sqliDepthEngineDBMS[engine]) {
				t.Errorf("finding does not name the DBMS %s: %s", sqliDepthEngineDBMS[engine], d)
			}
		})
	}
}

// The safe twin: a quoted value introduces a page full of SQL vocabulary that is not a database
// error, and nothing is reported.
func TestTheSQLKeywordHelpPageIsNotADatabaseError(t *testing.T) {
	if got := auditSQLi(t, "/ij/safe/dberr/accounts?owner=seed", nil); len(got) != 0 {
		t.Fatalf("the safe twin reported %d finding(s): %+v", len(got), got[0])
	}
}

// sqlmap's patterns obey the shell attribution rule: a match on a shell's own diagnostic line is the
// shell's, and the same text on any other line is still a database error.
func TestSqlmapMatchesOnAShellDiagnosticLineDoNotCount(t *testing.T) {
	const msg = "Syntax error: Encountered \"<EOF>\" at line 1, column 9."
	if sub := ClassifyErrorEvidence("ok", msg, SQLErrorSignatures); sub.Evidence == InjectionEvidenceErrorSignature {
		t.Fatalf("the substring bank matches %v; pick a message only sqlmap's bank knows", sub.Matched)
	}
	shell := ClassifySQLError("ok", "sh: 1: "+msg)
	if shell.Evidence != InjectionEvidenceNone || len(shell.Foreign) == 0 {
		t.Errorf("on a shell diagnostic line: evidence = %v, foreign = %v; want none, attributed to the shell", shell.Evidence, shell.Foreign)
	}
	db := ClassifySQLError("ok", "<pre>"+msg+"</pre>")
	if db.Evidence != InjectionEvidenceErrorSignature || len(db.DBMS) == 0 || db.DBMS[0] != "Apache Derby" {
		t.Errorf("relayed by an application: evidence = %v, DBMS = %v; want an Apache Derby error", db.Evidence, db.DBMS)
	}
}

// The dynamic page really is dynamic: two fetches of the same request differ under the exact
// comparison, so a boolean finding on it is something only the dynamic-content removal can produce.
func TestTheDynamicCatalogDiffersOnEveryFetch(t *testing.T) {
	srv := httptest.NewServer(vulnapp.Handler())
	defer srv.Close()
	for _, path := range []string{"/ij/dyn/catalog", "/ij/safe/dyn/catalog"} {
		a := vulnappGet(t, srv, path, "category", "seed")
		b := vulnappGet(t, srv, path, "category", "seed")
		if NewResponseFingerprint(200, a).SameShape(NewResponseFingerprint(200, b)) {
			t.Errorf("%s served the same page twice; it does not exercise dynamic content", path)
		}
		cmp := newBooleanComparator(200, a, 200, b)
		if !cmp.exact || len(cmp.regions) == 0 {
			t.Errorf("%s: dynamic regions not learned (exact=%v, regions=%d)", path, cmp.exact, len(cmp.regions))
		}
	}
}

// The boolean technique finds the condition on the dynamic page, and stays quiet on its bound twin.
func TestTheBooleanTechniqueFindsInjectionOnADynamicPage(t *testing.T) {
	got := auditSQLi(t, "/ij/dyn/catalog?category=seed", nil)
	if len(got) == 0 {
		t.Fatal("no finding on the boolean-injectable dynamic page")
	}
	if !strings.Contains(got[0].Description, InjectionEvidenceBooleanDifferential.String()) {
		t.Errorf("finding is not a boolean differential: %s", got[0].Description)
	}
	if safe := auditSQLi(t, "/ij/safe/dyn/catalog?category=seed", nil); len(safe) != 0 {
		t.Fatalf("the dynamic safe twin reported %d finding(s): %s", len(safe), safe[0].Description)
	}
}

// The widening `or` shapes find a lookup whose baseline matched nothing, only when the run admits
// them, and never on the bound twin.
func TestTheOrShapesAreGatedAndFindAWideningLookup(t *testing.T) {
	on := &ScanConfig{MaxConcurrency: 1, Timeout: time.Minute, CheckSqli: true, CheckSqliOrBoolean: true}
	if got := auditSQLi(t, "/ij/dyn/members?handle=nobody", nil); len(got) != 0 {
		t.Fatalf("with check_sqli_or_boolean off the lookup was reported: an `or` probe was sent: %s", got[0].Description)
	}
	got := auditSQLi(t, "/ij/dyn/members?handle=nobody", on)
	if len(got) == 0 {
		t.Fatal("with check_sqli_or_boolean on, the widening lookup was not found")
	}
	if !strings.Contains(got[0].Description, "widened") {
		t.Errorf("finding does not come from a widening shape: %s", got[0].Description)
	}
	if safe := auditSQLi(t, "/ij/safe/dyn/members?handle=nobody", on); len(safe) != 0 {
		t.Fatalf("the bound twin reported %d finding(s): %s", len(safe), safe[0].Description)
	}
}

// A page that reacts to the literal text of the documented false condition (a denylist matching
// `1=2`), not to its truth, passes the same-pair repeat every time. The fresh-operand pair is what
// tells it apart: `4821=7302` is false and the page does not react.
func TestAPageReactingToTheConditionsSpellingIsNotInjection(t *testing.T) {
	deny := regexp.MustCompile(`1\W{0,3}=\W{0,3}2`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		if deny.MatchString(r.URL.Query().Get("q")) {
			_, _ = io.WriteString(w, "Request blocked by policy.")
			return
		}
		_, _ = io.WriteString(w, "Results: Widget, Gadget, Gizmo")
	}))
	defer srv.Close()
	scan, id := seededExchange(t, srv, "/search?q=seed")
	_, findings := scan.AuditSession(context.Background(), []core.ExchangeID{id}, AuditConfig{})
	if got := sqliFindingsNamed(findings, sqlInjectionIssue); len(got) != 0 {
		t.Fatalf("a denylist on the text `1=2` was reported as SQL injection: %s", got[0].Description)
	}
}

// Comparator units: a timestamp that rolls over a minute after the baselines were taken is still
// dynamic content; a removed row is still a difference; an unanchored page is too unstable to judge.
func TestTheBooleanComparatorRemovesLearnedDynamicContentOnly(t *testing.T) {
	page := func(ts, token string, rows string) string {
		return `<html><head><meta name="csrf" content="` + token + `"></head><body><p>Rendered at ` + ts +
			` by the catalogue service</p><ul>` + rows + `</ul><p>Thank you for shopping with us today.</p></body></html>`
	}
	full := "<li>Widget</li><li>Gadget</li><li>Gizmo</li>"
	cmp := newBooleanComparator(200, page("2026-10-12T12:34:56.111Z", "aa11", full), 200, page("2026-10-12T12:34:56.999Z", "bb22", full))
	if !cmp.exact {
		t.Fatalf("baselines not identical after removal: regions %d, stability %.3f", len(cmp.regions), cmp.stability)
	}
	later := cmp.page(200, page("2026-10-12T12:35:01.5Z", "cc33", full), "")
	if !cmp.sameAsBase(later) {
		t.Error("a later timestamp (minute rolled over) and token made the page differ")
	}
	fewer := cmp.page(200, page("2026-10-12T12:35:02.5Z", "dd44", "<li>Widget</li>"), "")
	if cmp.sameAsBase(fewer) {
		t.Error("two removed rows were absorbed as dynamic content")
	}
	echoBase := newBooleanComparator(200, page("x", "1", full)+"You searched for seed", 200, page("x", "1", full)+"You searched for seed")
	if !echoBase.sameAsBase(echoBase.page(200, page("x", "1", full)+"You searched for seed&#39; and &#39;1&#39;=&#39;1", "' and '1'='1")) {
		t.Error("an HTML-escaped reflection of the payload made the page differ")
	}

	// An anchor that recurs on the page must not carry the removal across the content: here the
	// dynamic reference's leading anchor ("<div>Ref") recurs right before the rows, and its trailing
	// anchor ("</div>") only after them.
	refPage := func(ref, rows string) string {
		return "<div>Ref " + ref + "</div><div>Ref <ul>" + rows + "</ul></div>"
	}
	refCmp := newBooleanComparator(200, refPage("r1", full), 200, refPage("r2", full))
	if refCmp.sameAsBase(refCmp.page(200, refPage("r3", "<li>Widget</li>"), "")) {
		t.Error("a recurring anchor let the dynamic-region removal swallow the rows")
	}

	unstable := newBooleanComparator(200, "alpha beta gamma delta", 200, "one two three four five six")
	if unstable.stable() {
		t.Errorf("two unrelated pages were judged stable (%.2f)", unstable.stability)
	}
}

// A script engine's own SyntaxError is not a database error: MongoDB's $where relays SpiderMonkey's
// "unterminated string literal" inside a MongoServerError, and Python and V8 word theirs the same
// way. The banked SQL signature on that line is the script engine's. A driver's namespaced class
// (`PG::SyntaxError`) and the same wording on any other line still count.
func TestAScriptEnginesSyntaxErrorIsNotSQLEvidence(t *testing.T) {
	const base = `{"products":[]}`
	for _, body := range []string{
		`{"error":"MongoServerError: Executor error during find command :: caused by :: SyntaxError: unterminated string literal"}`,
		"Uncaught SyntaxError: unterminated string literal",
		`  File "<string>", line 1` + "\n" + `SyntaxError: unterminated string literal (detected at line 1)`,
	} {
		got := ClassifySQLError(base, body)
		if got.Evidence == InjectionEvidenceErrorSignature {
			t.Errorf("script engine error counted as SQL evidence (%v): %s", got.Matched, body)
		}
		if len(got.Foreign) == 0 {
			t.Errorf("script engine error was not attributed to its interpreter: %s", body)
		}
	}
	for _, body := range []string{
		`PG::SyntaxError: ERROR:  unterminated quoted string at or near "'"`,
		`query failed: unterminated string literal at position 31`,
		// Synthetic: a namespaced driver class immediately ahead of the wording is the driver's.
		`Db::SyntaxError: unterminated quoted string at or near "'"`,
	} {
		if got := ClassifySQLError(base, body); got.Evidence != InjectionEvidenceErrorSignature {
			t.Errorf("a database error was attributed away (%v, foreign %v): %s", got.Evidence, got.Foreign, body)
		}
	}
}
