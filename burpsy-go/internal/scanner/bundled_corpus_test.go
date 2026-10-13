package scanner

// The bundled BCheck corpus (internal/bcheck/bundled) against the whole vulnapp target, with only
// check_corpus on (burpsy-react-ui-0vzb.21).
//
// Community BChecks vary in quality, and the manifest's enabled set is a claim that each one stays
// quiet where nothing it tests for exists. This file is what makes the claim checkable: every
// enabled check audits every seeded endpoint through the real engine, and every finding is judged
// against what vulnapp declares there. A finding on a safe twin, or on an endpoint whose declared
// row the check does not test for, is a false positive, and the enabled set must have none.
//
// The other direction is pinned too. Every check the manifest excludes as a false positive is run
// the same way and must still misfire — so the exclusion reasons stay true, and a re-enabled one
// fails the precision test (TestABundledCheckExcludedAsAFalsePositiveStillMisfires is that
// negative control, run on every check in the category rather than one).

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/bcheck"
	"github.com/burpsy-go/burpsy/internal/bcheck/bundled"
	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/sender"
	"github.com/burpsy-go/burpsy/internal/vulnapp"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

// codeEvaluationRows are the vulnapp rows whose endpoints evaluate input as code or a template:
// what a computed-arithmetic probe (`{a*b}` coming back as the product) legitimately reports.
var codeEvaluationRows = []string{
	"Server-side template injection", "Unidentified code injection", "Expression Language injection",
	"Server-side JavaScript code injection", "PHP code injection", "Perl code injection",
	"Python code injection", "Ruby code injection", "SSI injection",
}

// bundledCheckMatches is the precision oracle: the vulnapp rows each bundled check legitimately
// reports. A check with no entry tests for nothing vulnapp plants, so any finding it makes is a
// false positive. Per-host checks are judged against every row the firing host serves, since a
// per-host finding is about the host rather than the exchange it was attached to.
var bundledCheckMatches = map[string][]string{
	"examples/suspicious-input-transformation.bcheck":              codeEvaluationRows,
	"vulnerability-classes/injection/template-injection.bcheck":    codeEvaluationRows,
	"vulnerability-classes/injection/SSTI-Razor.bcheck":            codeEvaluationRows,
	"other/exposed-swagger-ui.bcheck":                              {"OpenAPI definition found (active scan check)", "OpenAPI definition found (passive scan check)"},
	"other/GraphQL/graphql-introspection-enabled.bcheck":           {"GraphQL introspection enabled"},
	"other/GraphQL/grapple-get-method.bcheck":                      {"GraphQL endpoint found", "GraphQL endpoint discovered"},
	"other/tokens/jwt-none-algorithm.bcheck":                       {"JWT none algorithm supported", "JWT signature not verified"},
	"other/Openredirect/mass48-openredirect.bcheck":                {"Open redirection (reflected)"},
	"other/email/email-splitting-attack.bcheck":                    {"SMTP header injection"},
	"examples/blind-ssrf.bcheck":                                   {"Out-of-band resource load (HTTP)"},
	"other/Blind-SSRF-By-Collaborator.bcheck":                      {"Out-of-band resource load (HTTP)"},
	"vulnerability-classes/injection/SSRFInjection.bcheck":         {"Out-of-band resource load (HTTP)"},
	"vulnerability-classes/injection/ExtendedSSRFInjection.bcheck": {"Out-of-band resource load (HTTP)"},
}

// bundledFiring is one finding a bundled check made in the sweep, judged.
type bundledFiring struct {
	check, path, row    string
	safe, falsePositive bool
}

func (f bundledFiring) String() string {
	twin := ""
	if f.safe {
		twin = " (safe twin)"
	}
	return fmt.Sprintf("%s fired at %s [declared %q%s]", f.check, f.path, f.row, twin)
}

// bundledCheckRun is one check's sweep: its judged findings, what it sent, and the references and
// refusals the engine logged for it.
type bundledCheckRun struct {
	source     string
	firings    []bundledFiring
	sent       uint32
	paused     bool
	took       time.Duration
	unresolved []string
	refused    []string
}

func (r bundledCheckRun) falsePositives() []bundledFiring {
	var out []bundledFiring
	for _, f := range r.firings {
		if f.falsePositive {
			out = append(out, f)
		}
	}
	return out
}

// bundledSweepSkip names the endpoints the sweep leaves out, each with its reason.
var bundledSweepSkip = map[string]string{
	// A login tarpit: every failed login past the third, process-wide, waits up to 2.4s longer.
	// The insertion-point checks send dozens of payloads into its two fields, so one check spent
	// three minutes there and ran out its session budget — the sweep measured the fixture's
	// throttle, not the corpus, and slowed every other test sharing the target. It declares a
	// rate-limit row, which no bundled check tests for.
	"/auth/slow/login": "rate-limit tarpit",
}

var (
	bundledSweepMu   sync.Mutex
	bundledSweepMemo = map[string]bundledCheckRun{}
)

// bundledSweepSender carries a User-Agent, as the shipped sender does: five corpus checks put
// {user_agent} in a raw request, and runtimeSender's empty one would read as an interpreter gap.
func bundledSweepSender() *sender.Sender {
	cfg := sender.DefaultSenderConfig()
	cfg.TLSVerify = false
	cfg.Timeout = 10 * time.Second
	return sender.NewSender(cfg)
}

// sweepBundled audits every seeded vulnapp endpoint with each named bundled check alone, through
// the real engine with only check_corpus on, and judges every finding. Memoised per check for the
// test binary: the precision test and its negative control share the runs.
func sweepBundled(t *testing.T, m *bundled.Manifest, sources []string) []bundledCheckRun {
	t.Helper()
	rt := startRuntimeTarget(t)
	ids := make([]core.ExchangeID, 0, len(rt.exchanges))
	pathOf := map[core.ExchangeID]string{}
	for p, id := range rt.exchanges {
		pathOf[id] = p
		if bundledSweepSkip[p] != "" {
			continue
		}
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	endpoint := map[string]vulnapp.Endpoint{}
	for _, e := range vulnapp.Vulnerabilities() {
		endpoint[e.Path] = e
	}
	// The cleartext server and its TLS twin serve one handler, so they are one application; each
	// listener is its own.
	app := func(ex *core.Exchange) string {
		if (ex.Host == rt.host && ex.Port == rt.port) || (ex.Host == rt.tlsHost && ex.Port == rt.tlsPort) {
			return "vulnapp"
		}
		return fmt.Sprintf("%s:%d", ex.Host, ex.Port)
	}
	appRows := map[string]map[string]bool{}
	for p, id := range rt.exchanges {
		ex, err := rt.store.GetExchange(id)
		if err != nil {
			t.Fatalf("seeded %s is missing: %v", p, err)
		}
		e := endpoint[p]
		if e.Row == "" || e.Safe {
			continue
		}
		a := app(ex)
		if appRows[a] == nil {
			appRows[a] = map[string]bool{}
		}
		appRows[a][e.Row] = true
	}

	// The control: with no corpus check at all, a check_corpus-only session must find nothing, or
	// the attribution below would charge some other check's finding to a bundled one.
	bundledSweepMu.Lock()
	_, controlled := bundledSweepMemo[""]
	bundledSweepMu.Unlock()
	if !controlled {
		sc := NewActiveScanner(rt.store, zap.NewNop()).WithSender(bundledSweepSender()).
			WithConfig(&ScanConfig{CheckCorpus: true, MaxConcurrency: 8, Timeout: 2 * time.Minute})
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		_, findings := sc.AuditSession(ctx, ids, sc.AuditConfig())
		cancel()
		if len(findings) != 0 {
			t.Fatalf("a check_corpus-only session with no corpus found %d issues (first: %s); findings cannot be attributed to bundled checks", len(findings), findings[0].Name)
		}
		bundledSweepMu.Lock()
		bundledSweepMemo[""] = bundledCheckRun{}
		bundledSweepMu.Unlock()
	}

	runs := make([]bundledCheckRun, len(sources))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for i, src := range sources {
		bundledSweepMu.Lock()
		memo, ok := bundledSweepMemo[src]
		bundledSweepMu.Unlock()
		if ok {
			runs[i] = memo
			continue
		}
		check, err := m.Check(src)
		if err != nil {
			t.Fatal(err)
		}
		wg.Add(1)
		go func(i int, src string, check *bcheck.Check) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			obs, logs := observer.New(zapcore.WarnLevel)
			sc := NewActiveScanner(rt.store, zap.New(obs)).
				WithSender(bundledSweepSender()).
				WithConfig(&ScanConfig{CheckCorpus: true, MaxConcurrency: 8, Timeout: 2 * time.Minute, PendingDeadline: time.Second}).
				WithBundledCorpus([]*bcheck.Check{check}).
				WithOOBProvider(&vulnappOOBProvider{ch: &vulnappCollaborator{domain: "bundled-sweep.test"}})
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			start := time.Now()
			out, findings := sc.AuditSession(ctx, ids, sc.AuditConfig())
			expired := ctx.Err() != nil
			cancel()
			run := bundledCheckRun{source: src, sent: out.RequestsSent, paused: out.Paused || out.TimedOut || expired, took: time.Since(start)}
			for _, e := range logs.All() {
				fields := e.ContextMap()
				switch e.Message {
				case "active bcheck referenced paths it could not supply":
					run.unresolved = append(run.unresolved, fmt.Sprint(fields["unresolved"]))
				case "active bcheck unsupported":
					run.refused = append(run.refused, fmt.Sprint(fields["reason"]))
				}
			}
			allowed := map[string]bool{}
			for _, r := range bundledCheckMatches[src] {
				allowed[r] = true
			}
			perHost := strings.EqualFold(strings.TrimSpace(check.Given), "host")
			for _, f := range findings {
				if f == nil {
					continue
				}
				p := pathOf[f.ExchangeID]
				e := endpoint[p]
				fr := bundledFiring{check: src, path: p, row: e.Row, safe: e.Safe}
				if perHost {
					ex, err := rt.store.GetExchange(f.ExchangeID)
					fr.falsePositive = true
					if err == nil {
						for r := range allowed {
							if appRows[app(ex)][r] {
								fr.falsePositive = false
							}
						}
					}
				} else {
					fr.falsePositive = e.Safe || !allowed[e.Row]
				}
				run.firings = append(run.firings, fr)
			}
			runs[i] = run
			bundledSweepMu.Lock()
			bundledSweepMemo[src] = run
			bundledSweepMu.Unlock()
		}(i, src, check)
	}
	wg.Wait()
	return runs
}

func bundledSources(m *bundled.Manifest, keep func(bundled.Entry) bool) []string {
	var out []string
	for _, e := range m.Entries {
		if keep(e) {
			out = append(out, e.SourcePath)
		}
	}
	return out
}

func bundledManifest(t *testing.T) *bundled.Manifest {
	t.Helper()
	m, err := bundled.LoadManifest()
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// Every enabled bundled check runs against the whole target with every reference resolved, and
// none of them reports anything vulnapp does not declare for it.
func TestTheBundledCorpusMakesNoFalsePositivesOnVulnapp(t *testing.T) {
	m := bundledManifest(t)
	enabled := bundledSources(m, func(e bundled.Entry) bool { return e.Enabled })
	if len(enabled) == 0 {
		t.Fatal("the manifest enables no check")
	}
	runs := sweepBundled(t, m, enabled)
	var sent uint32
	fps, tps := 0, 0
	for _, r := range runs {
		sent += r.sent
		if r.paused {
			t.Errorf("%s: the session paused or ran out of time, so part of the target was never audited", r.source)
		}
		// The manifest says runs=true for every enabled check: a reference the engine could not
		// supply means the check compared against nothing, which is an interpreter gap, not a pass.
		if len(r.unresolved) > 0 {
			t.Errorf("%s: references this interpreter could not supply: %v", r.source, r.unresolved)
		}
		if len(r.refused) > 0 {
			t.Errorf("%s: the evaluator refused it: %v", r.source, r.refused)
		}
		for _, f := range r.firings {
			if f.falsePositive {
				fps++
				t.Errorf("false positive: %s", f)
			} else {
				tps++
				t.Logf("matches a declared row: %s", f)
			}
		}
	}
	if sent == 0 {
		t.Fatal("the sweep sent no probe; every assertion above was vacuous")
	}
	slow := append([]bundledCheckRun(nil), runs...)
	sort.Slice(slow, func(i, j int) bool { return slow[i].took > slow[j].took })
	for _, r := range slow[:min(5, len(slow))] {
		t.Logf("slowest: %s took %s for %d probes", r.source, r.took.Round(time.Millisecond), r.sent)
	}
	t.Logf("%d enabled bundled checks, %d probes, %d findings matching a declared row, %d false positives",
		len(runs), sent, tps, fps)
}

// The negative control, over the whole category: every check the manifest excludes as a false
// positive still misfires on vulnapp. Re-enabling any one of them would therefore fail the test
// above — and if one stops misfiring (an upstream fix, an interpreter change), this says so, and
// its exclusion reason is no longer true.
func TestABundledCheckExcludedAsAFalsePositiveStillMisfires(t *testing.T) {
	m := bundledManifest(t)
	excluded := bundledSources(m, func(e bundled.Entry) bool {
		return e.Exclusion != nil && e.Exclusion.Category == bundled.CategoryFalsePositive
	})
	if len(excluded) == 0 {
		t.Fatal("no check is excluded as a false positive; the control is vacuous")
	}
	for _, r := range sweepBundled(t, m, excluded) {
		fp := r.falsePositives()
		if len(fp) == 0 {
			t.Errorf("%s is excluded as a false positive but made none in this sweep (%d findings, %d probes); re-review it", r.source, len(r.firings), r.sent)
			continue
		}
		t.Logf("%s: %d false positives, e.g. %s", r.source, len(fp), fp[0])
	}
}

// The bundled set is available and not enabled: attaching it leaves check_corpus off, so a default
// audit dispatches none of it until the operator turns the switch on.
func TestTheBundledCorpusIsOffUntilCheckCorpusIsOn(t *testing.T) {
	checks, err := bundled.Checks()
	if err != nil {
		t.Fatal(err)
	}
	store := core.NewTrafficStore()
	sc := NewActiveScanner(store, zap.NewNop()).WithBundledCorpus(checks)
	if sc.ConfigSnapshot().CheckCorpus {
		t.Fatal("attaching the bundled corpus turned check_corpus on")
	}
	countCorpus := func() int {
		n := 0
		for _, c := range sc.enabledChecks() {
			if c.typeIndex == BCheckGeneratedTypeIndex {
				n++
			}
		}
		return n
	}
	if n := countCorpus(); n != 0 {
		t.Fatalf("with check_corpus off, %d bundled checks are in the dispatch set", n)
	}
	cfg := sc.ConfigSnapshot()
	cfg.CheckCorpus = true
	sc.WithConfig(&cfg)
	if n := countCorpus(); n == 0 {
		t.Fatal("with check_corpus on, no bundled check is in the dispatch set")
	}
	// A loaded check of the same name replaces the bundled one rather than running beside it.
	sc.WithCorpusChecks([]*bcheck.Check{checks[0]})
	seen := map[string]int{}
	sc.mu.RLock()
	for _, c := range sc.dispatchCorpusLocked() {
		seen[c.Name]++
	}
	sc.mu.RUnlock()
	if seen[checks[0].Name] != 1 {
		t.Fatalf("%q is dispatched %d times with the same check loaded and bundled", checks[0].Name, seen[checks[0].Name])
	}
}
