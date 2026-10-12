package scanner

// burpsy-react-ui-v0ei.1: time-based blind SQL injection per dialect. The evidence rule is pinned on
// synthetic measurements (each guard with a case that only that guard rejects); the families are
// driven end to end through an AuditSession against vulnapp's per-dialect simulations, each of which
// answers identically whatever happened so only the delay can decide; and the safe twins — a
// constantly slow endpoint and a job runner that sleeps on any sleep spelling — report nothing.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
)

const ms = time.Millisecond

// sleepCase and heavyCase are measurements that pass every leg of the rule.
func sleepCase() delayMeasurement {
	return delayMeasurement{baseline: 100 * ms, controls: []time.Duration{120 * ms, 110 * ms},
		lo: []time.Duration{2110 * ms}, hi: []time.Duration{5100 * ms, 5120 * ms}, loValue: 2, hiValue: 5, seconds: true}
}

func heavyCase() delayMeasurement {
	return delayMeasurement{baseline: 100 * ms, controls: []time.Duration{110 * ms, 105 * ms},
		lo: []time.Duration{1600 * ms, 1650 * ms}, hi: []time.Duration{3150 * ms}, loValue: 15_000_000, hiValue: 30_000_000}
}

func TestTheDelayScalingRuleConfirmsAScaledRepeatedDelay(t *testing.T) {
	for name, m := range map[string]delayMeasurement{"sleep": sleepCase(), "heavy": heavyCase()} {
		if ev, why := confirmDelayScaling(m); ev != InjectionEvidenceTiming {
			t.Errorf("%s: a clean scaled delay was not confirmed: %s (%s)", name, ev, why)
		}
	}
}

// Every leg of the rule rejects a case the others would accept. Each case is a negative control for
// one guard: with that guard removed from confirmDelayScaling, exactly that case confirms.
func TestTheDelayScalingRuleRejectsEachMissingLeg(t *testing.T) {
	cases := map[string]func() delayMeasurement{
		// A zero-delay control as slow as the low delay: the endpoint is slow now.
		"slow control": func() delayMeasurement {
			m := heavyCase()
			m.controls = []time.Duration{110 * ms, 700 * ms}
			m.lo = []time.Duration{3600 * ms, 3650 * ms}
			m.hi = []time.Duration{7150 * ms}
			return m
		},
		// No scaling: the low and high values took the same time (a tarpit or a fixed throttle).
		"flat": func() delayMeasurement {
			m := heavyCase()
			m.hi = []time.Duration{1700 * ms}
			return m
		},
		// The high value is slower, but by far more than the value ratio: not tracking the work.
		"overshoot": func() delayMeasurement {
			m := heavyCase()
			m.hi = []time.Duration{9000 * ms}
			return m
		},
		// Baseline and controls spread wide: the delay does not clear three times the jitter.
		"jitter": func() delayMeasurement {
			m := heavyCase()
			m.baseline = 100 * ms
			m.controls = []time.Duration{480 * ms, 120 * ms}
			return m
		},
		// The repeat of the low value disagrees with its first reading.
		"repeat disagrees": func() delayMeasurement {
			m := heavyCase()
			m.lo = []time.Duration{900 * ms, 2600 * ms}
			return m
		},
		// A sleep family must show the seconds it asked for, not merely scale.
		"sleep short of its delay": func() delayMeasurement {
			m := sleepCase()
			m.lo = []time.Duration{900 * ms}
			m.hi = []time.Duration{2100 * ms, 2150 * ms}
			return m
		},
		// No repeat at all.
		"no repeat": func() delayMeasurement {
			m := heavyCase()
			m.lo = m.lo[:1]
			return m
		},
	}
	for name, mk := range cases {
		if ev, why := confirmDelayScaling(mk()); ev == InjectionEvidenceTiming {
			t.Errorf("%s: confirmed (%s)", name, why)
		}
	}
}

// The banks: every new family in every quoting context, its methods, its foreign control spelled
// in another engine, and a heavy family's control never zero.
func TestTheDialectDelayBankCoversEveryContextAndEngine(t *testing.T) {
	bank := sqlDialectDelayPayloads(5 * time.Second)
	byDBMS := map[string]map[string]bool{}
	for _, tp := range bank {
		if byDBMS[tp.dbms+"/"+tp.primitive] == nil {
			byDBMS[tp.dbms+"/"+tp.primitive] = map[string]bool{}
		}
		byDBMS[tp.dbms+"/"+tp.primitive][tp.context] = true
		if !strings.Contains(tp.payload, "0<=") && tp.context != "ORDER BY" {
			t.Errorf("%s/%s %s: payload %q does not compare the delay expression", tp.dbms, tp.primitive, tp.context, tp.payload)
		}
		foreign := tp.foreign(5)
		if strings.HasPrefix(tp.dbms, "MySQL") {
			if !strings.Contains(foreign, "pg_sleep(5)") {
				t.Errorf("%s foreign control %q is not PostgreSQL's", tp.dbms, foreign)
			}
		} else if !strings.Contains(foreign, "SLEEP(5)") {
			t.Errorf("%s foreign control %q is not MySQL's", tp.dbms, foreign)
		}
		if tp.heavy {
			if tp.probeSize <= 0 || !strings.Contains(tp.payload, itoa64(tp.probeSize)) {
				t.Errorf("%s heavy payload %q does not carry its work bound %d", tp.dbms, tp.payload, tp.probeSize)
			}
		}
		for _, m := range tp.methods {
			switch {
			case m == MethodTimeDelays:
			case m == MethodMySQLSpecific && strings.HasPrefix(tp.dbms, "MySQL"):
			case m == MethodOracleSpecific && tp.dbms == "Oracle":
			default:
				t.Errorf("%s payload gated by unexpected method %q", tp.dbms, m)
			}
		}
	}
	for _, want := range []string{"MySQL/MariaDB/SLEEP", "MySQL/MariaDB/BENCHMARK", "Oracle/DBMS_PIPE.RECEIVE_MESSAGE",
		"Oracle/ALL_OBJECTS heavy query", "SQLite/RANDOMBLOB recursive heavy query", "IBM DB2/SYSIBM heavy query",
		"H2/SYSTEM_RANGE heavy query", "HSQLDB/SYSTEM_COLUMNS heavy query"} {
		got := byDBMS[want]
		for _, c := range sqlDelayContexts {
			if !got[c.name] {
				t.Errorf("%s has no %s form", want, c.name)
			}
		}
	}
}

func itoa64(n int64) string {
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// auditDialect audits one vulnapp endpoint with the SQL family on and the heavy-query switch as
// given, returning the SQL-injection findings.
func auditDialect(t *testing.T, path string, heavy bool, disabled ...string) []*Finding {
	t.Helper()
	scan, id := blindSQLiTarget(t, path)
	scan.WithConfig(&ScanConfig{MaxConcurrency: 1, Timeout: 3 * time.Minute, CheckSqli: true, CheckSqliHeavyQuery: heavy})
	cfg := AuditConfig{}
	for _, m := range disabled {
		cfg.DisabledDetectionMethods = append(cfg.DisabledDetectionMethods, IssueDetectionMethod{TypeIndex: sqlInjectionType, Method: m})
	}
	_, findings := scan.AuditSession(context.Background(), []core.ExchangeID{id}, cfg)
	return sqliFindingsNamed(findings, sqlInjectionIssue)
}

var allDBMSNames = []string{"PostgreSQL", "Microsoft SQL Server", "MySQL/MariaDB", "Oracle", "SQLite", "IBM DB2", "H2", "HSQLDB"}

// Each dialect's endpoint is found by its own family, and the finding names that DBMS and no other.
// The endpoints answer identically for rows, no rows and a syntax error, so neither the error bank
// nor the boolean differential can be what found them.
func TestEachDialectsTimingFamilyFindsItsEndpointAndNamesItsDBMS(t *testing.T) {
	if testing.Short() {
		t.Skip("the dialect endpoints really sleep")
	}
	for _, c := range []struct {
		path, dbms, primitive string
		heavy                 bool
	}{
		{"/ij/dialect/mysql/orders?id=7", "MySQL/MariaDB", "SLEEP", false},
		{"/ij/dialect/mysql-filtered/orders?id=7", "MySQL/MariaDB", "BENCHMARK", true},
		{"/ij/dialect/oracle/staff?name=seed", "Oracle", "DBMS_PIPE.RECEIVE_MESSAGE", false},
		{"/ij/dialect/sqlite/notes?id=7", "SQLite", "RANDOMBLOB", true},
		{"/ij/dialect/db2/ledger?sort=amount", "IBM DB2", "SYSIBM", true},
		{"/ij/dialect/h2/cars?id=1", "H2", "SYSTEM_RANGE", true},
		{"/ij/dialect/hsqldb/parts?code=seed", "HSQLDB", "SYSTEM_COLUMNS", true},
		{"/ij/jobs?queue=seed", "PostgreSQL", "pg_sleep", false},
	} {
		c := c
		t.Run(c.dbms+"/"+c.primitive, func(t *testing.T) {
			t.Parallel()
			got := auditDialect(t, c.path, c.heavy)
			if len(got) != 1 {
				t.Fatalf("%s: %d SQL injection finding(s), want 1: %+v", c.path, len(got), got)
			}
			desc := got[0].Description
			t.Logf("%s: %s", c.path, desc)
			if !strings.Contains(desc, "DBMS "+c.dbms+": its own "+c.primitive) {
				t.Errorf("%s: the finding does not attribute the delay to %s's %s: %s", c.path, c.dbms, c.primitive, desc)
			}
			for _, other := range allDBMSNames {
				if other != c.dbms && strings.Contains(desc, "DBMS "+other) {
					t.Errorf("%s: the finding names %s too: %s", c.path, other, desc)
				}
			}
		})
	}
}

// The heavy families are an opt-in: with check_sqli_heavy_query off, an engine that only a heavy
// query can reach is not found, and the method gate withholds MySQL's SLEEP when MySQL specific is off.
func TestHeavyQueryFamiliesAndDialectMethodsAreGated(t *testing.T) {
	if testing.Short() {
		t.Skip("the dialect endpoints really sleep")
	}
	t.Run("heavy off", func(t *testing.T) {
		t.Parallel()
		if got := auditDialect(t, "/ij/dialect/h2/cars?id=1", false); len(got) != 0 {
			t.Fatalf("the H2 endpoint was reported with heavy queries off: %+v", got)
		}
	})
	t.Run("MySQL specific off", func(t *testing.T) {
		t.Parallel()
		if got := auditDialect(t, "/ij/dialect/mysql/orders?id=7", true, MethodMySQLSpecific); len(got) != 0 {
			t.Fatalf("the MySQL endpoint was reported with MySQL specific disabled: %+v", got)
		}
	})
}

// The safe twins: a constant slow pace is not a delay, and a delay that follows ANY dialect's sleep
// spelling is not attributable to a database (the foreign-dialect control).
func TestTheDialectSafeTwinsReportNothing(t *testing.T) {
	if testing.Short() {
		t.Skip("the safe twins really sleep")
	}
	for _, path := range []string{"/ij/safe/dialect/slow?id=7", "/ij/safe/dialect/jobs?step=seed"} {
		path := path
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			if got := auditDialect(t, path, true); len(got) != 0 {
				t.Fatalf("%s reported %d SQL injection finding(s): %+v", path, len(got), got[0].Description)
			}
		})
	}
}
