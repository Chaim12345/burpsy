package scanner

// burpsy-react-ui-v0ei.5 (UNION-based and stacked-query SQL injection) and v0ei.3 (out-of-band SQL
// injection), end to end against vulnapp's simulated engines, with the safe twins and the guards'
// negative controls.

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/vulnapp"
)

// The H2-like endpoint renders only the first row, so the marker reaches the page only in the
// value-replacing form; ORDER BY finds the three columns, the id column rejects a string, and the
// fingerprint names H2.
func TestUnionFindsColumnCountReflectedColumnAndDBMSOnAFirstRowPage(t *testing.T) {
	got := auditSQLi(t, "/ij/union/cars?id=1", nil)
	if len(got) == 0 {
		t.Fatal("no SQL injection finding on the UNION-injectable cars endpoint")
	}
	d := got[0].Description
	t.Logf("%s (%s): %s", got[0].Evidence, got[0].Confidence, d)
	for _, want := range []string{"UNION-based", "numeric context", "replacing the value", "3 column(s) (count from the ORDER BY binary search)", "column 2", "DBMS: H2"} {
		if !strings.Contains(d, want) {
			t.Errorf("description lacks %q: %s", want, d)
		}
	}
	if got[0].Confidence != "certain" {
		t.Errorf("confidence = %q, want certain: a computed marker is evaluation, not inference", got[0].Confidence)
	}
}

// The SQLite-like endpoint has `||` only and a string context; its fingerprint is SQLite's.
func TestUnionFindsAStringContextWithPipeConcatenation(t *testing.T) {
	got := auditSQLi(t, "/ij/union/staff?name=alice", nil)
	if len(got) == 0 {
		t.Fatal("no SQL injection finding on the UNION-injectable staff endpoint")
	}
	d := got[0].Description
	t.Logf("%s (%s): %s", got[0].Evidence, got[0].Confidence, d)
	for _, want := range []string{"UNION-based", "single-quoted string context", "2 column(s)", "||-concatenated", "DBMS: SQLite"} {
		if !strings.Contains(d, want) {
			t.Errorf("description lacks %q: %s", want, d)
		}
	}
}

// Where ORDER BY never reaches the statement, the column count comes from the UNION SELECT NULL
// fallback, which runs on a point another technique (here the boolean differential) has proven.
// Negative control: with the fallback disabled in checkSQLInjectionCore, this fails.
func TestUnionFallsBackToNullColumnsWhereOrderByIsFiltered(t *testing.T) {
	got := auditSQLi(t, "/ij/union/cars-noorder?id=1", nil)
	if len(got) == 0 {
		t.Fatal("no SQL injection finding on the ORDER BY-filtered cars endpoint")
	}
	d := got[0].Description
	t.Logf("%s (%s): %s", got[0].Evidence, got[0].Confidence, d)
	for _, want := range []string{"UNION-based", "3 column(s) (count from the UNION SELECT NULL count)", "column 2", "DBMS: H2"} {
		if !strings.Contains(d, want) {
			t.Errorf("description lacks %q: %s", want, d)
		}
	}
}

// The bound twin echoes what it was given and evaluates nothing.
func TestUnionStaysQuietOnTheBoundTwin(t *testing.T) {
	if got := auditSQLi(t, "/ij/safe/union/cars?id=1", nil); len(got) != 0 {
		t.Fatalf("the bound twin reported %d finding(s): %s", len(got), got[0].Description)
	}
}

// The look-alike: injectable (its MySQL error proves that), but the page never shows a row; it
// echoes the term with every `'||'` deleted, which turns `'bsyu'||'x'` into the marker. The second,
// product-carrying expression is what keeps that echo from being reported as UNION-based.
// Negative control: with the confirmation removed from markerSearch, this test fails.
func TestAMarkerLookAlikeEchoIsNotReportedAsUnion(t *testing.T) {
	got := auditSQLi(t, "/ij/sqli/union-echo?q=seed", nil)
	if len(got) == 0 {
		t.Fatal("the injectable look-alike was not reported at all: its error should prove SQL injection")
	}
	t.Logf("(%s): %s", got[0].Confidence, got[0].Description)
	if d := got[0].Description; strings.Contains(d, "UNION-based") || got[0].Confidence == "certain" {
		t.Fatalf("an echo that deletes `'||'` was reported as a UNION evaluation (%s): %s", got[0].Confidence, d)
	}
}

// The look-alike's first sighting really happens, so the test above exercises the confirmation and
// not the ORDER BY gate.
func TestTheLookAlikeEchoDoesProduceTheFirstMarker(t *testing.T) {
	srv := httptest.NewServer(vulnapp.Handler())
	defer srv.Close()
	body := vulnappGet(t, srv, "/ij/sqli/union-echo", "q", "x' UNION ALL SELECT 'bsyu'||'q1w2',NULL-- ")
	if !strings.Contains(body, "bsyuq1w2") {
		t.Fatalf("the look-alike no longer produces the joined marker, so the guard is untested: %s", body)
	}
	body = vulnappGet(t, srv, "/ij/sqli/union-echo", "q", "x' ORDER BY 1-- ")
	if strings.Contains(body, "error in your SQL syntax") {
		t.Fatalf("ORDER BY 1 errors on the look-alike, so the marker search never runs there: %s", body)
	}
}

func stackedConfig() *ScanConfig {
	return &ScanConfig{MaxConcurrency: 1, Timeout: 2 * time.Minute, CheckSqli: true, CheckSqliStacked: true}
}

// A stacked sleep annotates the finding of a multi-statement endpoint, and only with the switch on.
func TestStackedQueriesAnnotateAProvenFinding(t *testing.T) {
	if testing.Short() {
		t.Skip("timing: several multi-second sleeps")
	}
	got := auditSQLi(t, "/ij/stacked/mysql/items?id=7", stackedConfig())
	if len(got) == 0 {
		t.Fatal("no finding on the multi-statement endpoint")
	}
	d := got[0].Description
	if !strings.Contains(d, "Stacked queries supported") || !strings.Contains(d, "MySQL/MariaDB") {
		t.Errorf("description does not report stacked queries for MySQL: %s", d)
	}
	off := auditSQLi(t, "/ij/stacked/mysql/items?id=7", nil)
	if len(off) == 0 {
		t.Fatal("no finding with the stacked switch off")
	}
	if strings.Contains(off[0].Description, "Stacked queries") {
		t.Errorf("with check_sqli_stacked off the stacked probe ran: %s", off[0].Description)
	}
}

// The single-statement twin is injectable, but a stacked statement is a syntax error there: the
// finding stands and says stacked queries were not shown.
func TestStackedQueriesAreNotClaimedWhereTheDriverRejectsThem(t *testing.T) {
	got := auditSQLi(t, "/ij/stacked/single/items?id=7", stackedConfig())
	if len(got) == 0 {
		t.Fatal("no finding on the single-statement endpoint")
	}
	if d := got[0].Description; strings.Contains(d, "Stacked queries supported") || !strings.Contains(d, "Stacked queries: not shown") {
		t.Errorf("description = %s; want stacked queries reported as not shown", d)
	}
}

// ---------------------------------------------------------------------------
// out of band (v0ei.3)
// ---------------------------------------------------------------------------

func oobSQLAudit(t *testing.T, path, domain string, cfg AuditConfig, scanCfg *ScanConfig) ([]*Finding, AuditOutcome, []*Finding, ScanCompletion) {
	t.Helper()
	scan, id := blindSQLiTarget(t, path)
	if scanCfg == nil {
		scanCfg = &ScanConfig{MaxConcurrency: 1, Timeout: 2 * time.Minute, CheckSqli: true,
			CheckExtendedActive: true, CheckOutOfBand: true, PendingDeadline: 1500 * time.Millisecond}
	}
	scan.WithConfig(scanCfg).WithOOBProvider(&vulnappOOBProvider{ch: &vulnappCollaborator{domain: domain}})
	outcome, findings := scan.AuditWithin(context.Background(), id, cfg)
	deferred, completion := scan.FinishScan(context.Background(), cfg)
	return sqliFindingsNamed(findings, sqlInjectionIssue), outcome, sqliFindingsNamed(deferred, sqlInjectionIssue), completion
}

func sqliOnly() AuditConfig {
	cfg := DefaultAuditConfig()
	cfg.IssueTypes = []uint32{0x00100200}
	return cfg
}

// SQL Server's xp_dirtree and Oracle's UTL_INADDR / HTTPURITYPE reach the collaborator from blind
// endpoints no in-band technique can see; the finding names the family that made the lookup.
func TestOutOfBandSQLiIsFoundByTheLookupItsOwnIDCarries(t *testing.T) {
	for _, tc := range []struct{ path, domain, dbms, primitive string }{
		{"/oob/sqli/mssql?id=7", "collab-sqo-mssql.test", "Microsoft SQL Server", "xp_dirtree"},
		{"/oob/sqli/oracle?name=seed", "collab-sqo-oracle.test", "Oracle", "UTL_INADDR"},
	} {
		inBand, outcome, deferred, _ := oobSQLAudit(t, tc.path, tc.domain, sqliOnly(), nil)
		if len(inBand) != 0 {
			t.Fatalf("%s: an in-band technique reported the blind fixture: %s", tc.path, inBand[0].Description)
		}
		if outcome.Unmeasurable == 0 {
			t.Errorf("%s: the audit counted the planted check %+v; want it undecided while it awaits a callback", tc.path, outcome)
		}
		if len(deferred) != 1 {
			t.Fatalf("%s: deferred SQL injection findings = %d, want 1", tc.path, len(deferred))
		}
		f := deferred[0]
		t.Logf("%s: %s", tc.path, f.Description)
		if f.Confidence != "certain" || !strings.Contains(f.Description, tc.dbms) || !strings.Contains(f.Description, tc.primitive) ||
			!strings.Contains(f.Description, tc.domain) {
			t.Errorf("%s: finding %s/%s: %s", tc.path, f.Severity, f.Confidence, f.Description)
		}
		if f.Param == "" {
			t.Errorf("%s: the finding names no parameter", tc.path)
		}
	}
}

// The bound twin is planted and never calls back: no finding, and the claim ends outstanding, not
// clean.
func TestOutOfBandSQLiBoundTwinEndsOutstanding(t *testing.T) {
	_, _, deferred, completion := oobSQLAudit(t, "/safe/oob/sqli/bound?id=7", "collab-sqo-bound.test", sqliOnly(), nil)
	if len(deferred) != 0 {
		t.Fatalf("the bound twin produced %d finding(s): %s", len(deferred), deferred[0].Description)
	}
	found := false
	for _, o := range completion.Outstanding {
		if o.Row == sqlInjectionIssue && strings.Contains(o.What, "collab-sqo-bound.test") {
			found = true
		}
	}
	if !found {
		t.Errorf("no outstanding SQL injection claim naming the collaborator domain: %+v", completion.Outstanding)
	}
}

// The resolver looks up every host-shaped token, so it calls back for the payloads too — and for the
// plain-text control. The control is what keeps that from being reported as SQL injection.
// Negative control: with the control check removed from the resolver in sqli_oob.go, this fails.
func TestOutOfBandSQLiIsNotClaimedForATargetThatResolvesAnyHost(t *testing.T) {
	_, _, deferred, completion := oobSQLAudit(t, "/safe/oob/sqli/resolver?q=seed", "collab-sqo-resolver.test", sqliOnly(), nil)
	if len(deferred) != 0 {
		t.Fatalf("a host resolver was reported as SQL injection: %s", deferred[0].Description)
	}
	for _, o := range completion.Outstanding {
		if o.Row == sqlInjectionIssue {
			t.Errorf("the resolver's claim is still outstanding; the control interaction should have settled it: %+v", o)
		}
	}
	// The resolver did look the payload hosts up: the guard, not silence, decided.
	hit := false
	for _, c := range vulnapp.OutboundContacts() {
		if strings.HasPrefix(c.Host, "bsysqo") && strings.HasSuffix(c.Host, ".collab-sqo-resolver.test") {
			hit = true
		}
	}
	if !hit {
		t.Fatal("the resolver never looked a payload host up, so the control guard was not exercised")
	}
}

// The families are gated: off without CheckOutOfBand, and withheld (and counted) when Burp
// Collaborator is disabled for the SQL-injection type.
func TestOutOfBandSQLiIsGated(t *testing.T) {
	off := &ScanConfig{MaxConcurrency: 1, Timeout: 2 * time.Minute, CheckSqli: true, CheckExtendedActive: true,
		PendingDeadline: 500 * time.Millisecond}
	_, _, deferred, completion := oobSQLAudit(t, "/oob/sqli/mssql?id=7", "collab-sqo-off.test", sqliOnly(), off)
	if len(deferred) != 0 || len(completion.Outstanding) != 0 {
		t.Fatalf("with check_out_of_band off, out-of-band payloads were planted: %d finding(s), %d outstanding", len(deferred), len(completion.Outstanding))
	}
	cfg := sqliOnly()
	cfg.DisabledDetectionMethods = []IssueDetectionMethod{{TypeIndex: 0x00100200, Method: MethodCollaborator}}
	_, outcome, deferred, completion := oobSQLAudit(t, "/oob/sqli/mssql?id=7", "collab-sqo-withheld.test", cfg, nil)
	if len(deferred) != 0 || len(completion.Outstanding) != 0 {
		t.Fatalf("with Burp Collaborator disabled, out-of-band payloads were planted")
	}
	declined := false
	for _, d := range outcome.MethodsDeclined {
		if d.Method == MethodCollaborator && d.ProbesWithheld > 0 {
			declined = true
		}
	}
	if !declined {
		t.Errorf("methods_declined = %+v; want the withheld Collaborator probes counted", outcome.MethodsDeclined)
	}
}
