package scanner

// burpsy-react-ui-saq3.2.1 end to end: the blind SQL-injection techniques (boolean conditions,
// time delays) find their vulnapp endpoints through a real AuditSession, each family's probes
// are withheld when its detection method is disabled, and the safe twins report nothing.
//
// The boolean and timing payloads themselves are pinned separately by the harness-level tests in
// detection_methods_test.go (which drive ProbeBoolean/ProbeTimingUnder through the gate); what
// only an AuditSession can prove is that the checks are DISPATCHED, reach the endpoint over the
// sender, and that a finding comes back named for the SQL-injection row.
import (
	"context"
	"io"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/sender"
	"github.com/burpsy-go/burpsy/internal/vulnapp"
	"go.uber.org/zap"
)

// blindSQLiTarget serves vulnapp and seeds one exchange for the given path, returning a scanner
// whose SQLi family is on and nothing else that could muddie the assertion.
func blindSQLiTarget(t *testing.T, path string) (*ActiveScanner, core.ExchangeID) {
	t.Helper()
	srv := httptest.NewServer(vulnapp.Handler())
	t.Cleanup(srv.Close)

	host, portStr, ok := strings.Cut(strings.TrimPrefix(srv.URL, "http://"), ":")
	if !ok {
		t.Fatalf("cannot split %q", srv.URL)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		t.Fatalf("port: %v", err)
	}

	res, err := srv.Client().Get(srv.URL + path)
	if err != nil {
		t.Fatalf("seed %s: %v", path, err)
	}
	raw0, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	_ = res.Body.Close()

	store := core.NewTrafficStore()
	raw := "GET " + path + " HTTP/1.1\r\nHost: " + host + "\r\n\r\n"
	reqID, err := store.Put([]byte(raw), core.DirectionRequest)
	if err != nil {
		t.Fatalf("put request: %v", err)
	}
	respRaw := "HTTP/1.1 200 OK\r\nContent-Length: " + strconv.Itoa(len(raw0)) + "\r\n\r\n" + string(raw0)
	respID, err := store.Put([]byte(respRaw), core.DirectionResponse)
	if err != nil {
		t.Fatalf("put response: %v", err)
	}
	ex := &core.Exchange{
		Request: core.MsgPtr(reqID), Response: &respID,
		Host: host, Port: uint16(port), TLS: false, Method: "GET", Path: path,
	}
	store.AddExchange(ex)

	scan := NewActiveScanner(store, zap.NewNop()).
		WithSender(sender.NewSender(sender.DefaultSenderConfig())).
		WithConfig(&ScanConfig{MaxConcurrency: 1, Timeout: time.Minute, CheckSqli: true})
	return scan, ex.ID
}

func sqliFindingsNamed(findings []*Finding, name string) []*Finding {
	var out []*Finding
	for _, f := range findings {
		if f.Name == name {
			out = append(out, f)
		}
	}
	return out
}

// The boolean-conditions technique finds the condition-evaluating endpoint: an always-true
// appended condition leaves the listing as the baseline had it and an always-false one empties
// it, which is a differential no error signature could have produced (the endpoint never errors).
func TestTheBooleanTechniqueFindsBlindSQLiThroughAnAuditSession(t *testing.T) {
	scan, id := blindSQLiTarget(t, "/ij/books?sort_col=seed")
	_, findings := scan.AuditSession(context.Background(), []core.ExchangeID{id}, AuditConfig{})
	if got := sqliFindingsNamed(findings, sqlInjectionIssue); len(got) == 0 {
		t.Fatalf("no %q finding on the boolean-blind endpoint; findings = %+v", sqlInjectionIssue, findings)
	}
}

// ...and the same endpoint's safe twin, which never evaluates a condition, reports nothing: the
// both-halves-differ shape reads as inconclusive, not as evidence.
func TestTheBooleanTechniqueReportsNothingOnTheSafeTwin(t *testing.T) {
	scan, id := blindSQLiTarget(t, "/ij/safe/books?sort_col=seed")
	_, findings := scan.AuditSession(context.Background(), []core.ExchangeID{id}, AuditConfig{})
	if got := sqliFindingsNamed(findings, sqlInjectionIssue); len(got) != 0 {
		t.Fatalf("the safe twin reported %d %q finding(s): %+v", len(got), sqlInjectionIssue, got)
	}
}

// The time-delays technique finds the sleep-executing endpoint: a pg_sleep directive in the
// value delays the response by the seconds it asked for, and the classifier reads the delay
// against the baseline. The run is bounded by the endpoint's own 5-second cap.
func TestTheTimingTechniqueFindsBlindSQLiThroughAnAuditSession(t *testing.T) {
	if testing.Short() {
		t.Skip("the timing endpoint really sleeps; -short skips the wall-clock cost")
	}
	scan, id := blindSQLiTarget(t, "/ij/jobs?queue=seed")
	start := time.Now()
	_, findings := scan.AuditSession(context.Background(), []core.ExchangeID{id}, AuditConfig{})
	if got := sqliFindingsNamed(findings, sqlInjectionIssue); len(got) == 0 {
		t.Fatalf("no %q finding on the timing-blind endpoint after %s; findings = %+v",
			sqlInjectionIssue, time.Since(start), findings)
	}
}

// ...and the safe twin, which stores the parameter and never executes it, reports nothing and
// does not stall.
func TestTheTimingTechniqueReportsNothingOnTheSafeTwin(t *testing.T) {
	scan, id := blindSQLiTarget(t, "/ij/safe/jobs?queue=seed")
	start := time.Now()
	_, findings := scan.AuditSession(context.Background(), []core.ExchangeID{id}, AuditConfig{})
	if took := time.Since(start); took > 3*time.Second {
		t.Fatalf("the safe twin took %s; it must not execute any sleep directive", took)
	}
	if got := sqliFindingsNamed(findings, sqlInjectionIssue); len(got) != 0 {
		t.Fatalf("the safe twin reported %d %q finding(s): %+v", len(got), sqlInjectionIssue, got)
	}
}

// Each family declines when its method is disabled: "Boolean conditions" off withholds the
// boolean check's probes from the boolean-blind endpoint, and the endpoint — which produces no
// error and no delay — reports nothing at all, because no other technique can see it.
func TestTheBlindFamiliesDeclineWhenTheirMethodsAreDisabled(t *testing.T) {
	boolOff := AuditConfig{DisabledDetectionMethods: []IssueDetectionMethod{
		{TypeIndex: sqlInjectionType, Method: MethodBooleanConditions},
	}}
	scan, id := blindSQLiTarget(t, "/ij/books?sort_col=seed")
	_, findings := scan.AuditSession(context.Background(), []core.ExchangeID{id}, boolOff)
	if got := sqliFindingsNamed(findings, sqlInjectionIssue); len(got) != 0 {
		t.Fatalf("with Boolean conditions disabled, the boolean-only endpoint reported %d finding(s): %+v",
			len(got), got)
	}

	timeOff := AuditConfig{DisabledDetectionMethods: []IssueDetectionMethod{
		{TypeIndex: sqlInjectionType, Method: MethodTimeDelays},
	}}
	scan2, id2 := blindSQLiTarget(t, "/ij/jobs?queue=seed")
	_, findings2 := scan2.AuditSession(context.Background(), []core.ExchangeID{id2}, timeOff)
	if got := sqliFindingsNamed(findings2, sqlInjectionIssue); len(got) != 0 {
		t.Fatalf("with Time delays disabled, the timing-only endpoint reported %d finding(s): %+v",
			len(got), got)
	}
}

// The dialect gate: a PostgreSQL probe is withheld when PostgreSQL specific is disabled even
// with Time delays on, and the decline names the method that stopped it.
func TestADialectMethodWithholdsOnlyItsOwnDialectsProbes(t *testing.T) {
	h, cc, target := harnessFor(t, MethodPostgreSQLSpecific)
	point := h.Points()[0]
	before := target.total()
	pg := h.ProbeTimingUnder(context.Background(), point, "||pg_sleep(5)--", InjectionTimingDelay,
		[]string{MethodTimeDelays, MethodPostgreSQLSpecific})
	if !pg.Withheld {
		t.Fatal("a pg_sleep probe was sent with PostgreSQL specific disabled")
	}
	mssql := h.ProbeTimingUnder(context.Background(), point, " waitfor delay'0:0:5'--", InjectionTimingDelay,
		[]string{MethodTimeDelays, MethodSQLServerSpecific})
	if mssql.Withheld {
		t.Fatal("PostgreSQL specific's switch withheld SQL Server's waitfor probe")
	}
	if sent := target.total() - before; sent != 1 {
		t.Fatalf("the target received %d request(s), want exactly the waitfor probe", sent)
	}
	declines := cc.MethodDeclines.List()
	if len(declines) != 1 || declines[0].Method != MethodPostgreSQLSpecific {
		t.Fatalf("declines = %+v, want one PostgreSQL specific record", declines)
	}
}

// The payload BANKS are pinned exactly (saq3.2.1): the context breaks are recovered Burp
// literals, and a bank that drifted would splice probes into the wrong place silently — the
// vulnapp recognizers are deliberately shape-generic, so only an exact-text assertion can
// catch a swapped break list.
func TestTheBlindTechniquePayloadsAreTheRecoveredForms(t *testing.T) {
	bools := sqlBooleanPayloads()
	// The bare pair: no break, no terminator.
	if bools[0][0] != "1=1" || bools[0][1] != "1=2" {
		t.Errorf("bare pair = %q / %q, want 1=1 / 1=2", bools[0][0], bools[0][1])
	}
	// The comment-terminated pairs close the application's own quote after the terminator.
	for _, ctx := range [][2]string{{" and ", "-- "}, {")and ", "-- "}, {"))and ", "-- "}} {
		found := false
		for _, pair := range bools {
			if pair[0] == ctx[0]+"1=1"+ctx[1]+"'" && pair[1] == ctx[0]+"1=2"+ctx[1]+"'" {
				found = true
			}
		}
		if !found {
			t.Errorf("no boolean pair for break %q: the comment-terminated form must carry the closing quote", ctx[0])
		}
	}
	// The concatenation and argument forms carry no quote.
	wantConcat := [2]string{"||1=1||", "||1=2||"}
	wantArg := [2]string{",1=1", ",1=2"}
	sawConcat, sawArg := false, false
	for _, pair := range bools {
		if pair == wantConcat {
			sawConcat = true
		}
		if pair == wantArg {
			sawArg = true
		}
	}
	if !sawConcat || !sawArg {
		t.Errorf("concat/argument boolean pairs missing: concat=%v arg=%v", sawConcat, sawArg)
	}

	// The timing bank: every recovered break, both dialects, quoted and unquoted.
	timing := sqlTimingPayloads(5 * time.Second)
	// PostgreSQL forms carry pg_sleep(5); SQL Server forms carry waitfor delay'0:0:5'.
	var pg, mssql int
	for _, tp := range timing {
		switch {
		case strings.Contains(tp.payload, "pg_sleep(5)--") && strings.Contains(tp.payload, "waitfor"):
			t.Errorf("payload %q mixes both dialects", tp.payload)
		case strings.Contains(tp.payload, "pg_sleep(5)--"):
			pg++
			for _, m := range tp.methods {
				if m == MethodPostgreSQLSpecific || m == MethodTimeDelays {
					continue
				}
				t.Errorf("pg payload %q gated by unexpected method %q", tp.payload, m)
			}
		case strings.Contains(tp.payload, "waitfor delay'0:0:5'--"):
			mssql++
			for _, m := range tp.methods {
				if m == MethodSQLServerSpecific || m == MethodTimeDelays {
					continue
				}
				t.Errorf("mssql payload %q gated by unexpected method %q", tp.payload, m)
			}
		default:
			t.Errorf("payload %q is neither dialect's recovered form", tp.payload)
		}
	}
	// 3 PostgreSQL breaks x 2 forms + 5 SQL Server breaks x 2 forms.
	if pg != 6 || mssql != 10 {
		t.Errorf("timing payload counts: pg=%d (want 6), mssql=%d (want 10)", pg, mssql)
	}
	// Every break is actually ahead of its dialect's sleep call, spelled exactly as recovered
	// (Zxpy for pg_sleep, Zuyg for waitfor): the whole break prepends the sleep text.
	var joined strings.Builder
	for _, tp := range timing {
		joined.WriteString(tp.payload)
		joined.WriteByte('\n')
	}
	all := joined.String()
	for _, want := range []string{
		"||pg_sleep(5)--", "'||pg_sleep(5)--",
		" AND pg_sleep(5)--", "' AND pg_sleep(5)--",
		",''||pg_sleep(5)--", "',\x27\x27||pg_sleep(5)--",
		" waitfor delay'0:0:5'--", "' waitfor delay'0:0:5'--",
		")waitfor delay'0:0:5'--", "')waitfor delay'0:0:5'--",
		",0)waitfor delay'0:0:5'--", ",0,0)waitfor delay'0:0:5'--", ",0,0,0)waitfor delay'0:0:5'--",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("timing bank is missing the recovered form %q", want)
		}
	}
}
