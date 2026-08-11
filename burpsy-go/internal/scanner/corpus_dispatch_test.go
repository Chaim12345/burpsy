// End-to-end tests for the corpus-driven active checks: a loaded BCheck's active checks
// (`given host/path/request`, and the insertion-point set) dispatched by the audit engine
// alongside the built-in table.
//
// These are the tests that make DispatchScopePerInsertionPoint *reachable* mean something:
// before the corpus wiring, `given insertion point` checks were counted at load and then
// dropped. Each test here drives a real audit over a real store and a real target, so a
// regression that stopped the corpus from dispatching would fail with a request count of
// zero rather than with a silent clean bill of health.
package scanner

import (
	"context"
	"testing"

	"github.com/burpsy-go/burpsy/internal/bcheck"
	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/sender"
	"go.uber.org/zap"
)

// corpusCheck parses one active check body with the mandatory metadata block, mirroring the
// bcheck package's own test helper.
func corpusCheck(t *testing.T, body string) *bcheck.Check {
	t.Helper()
	c, err := bcheck.Parse("metadata:\n  language: v2-beta\n  name: \"t\"\n" + body)
	if err != nil {
		t.Fatalf("corpus check did not parse: %v", err)
	}
	return c
}

func Test_an_insertion_point_corpus_check_dispatches_through_the_audit_engine(t *testing.T) {
	store := core.NewTrafficStore()
	port := reflectingTarget(t)
	// The seeded request carries one query parameter named xss, so a `given query insertion
	// point` check has exactly one point to probe — and reflectingTarget echoes ?xss= back, so
	// the payload lands in a body the check can see.
	id := seedAuditExchange(t, store, "127.0.0.1", port, "/search?xss=1", "<html>seed</html>")

	// WithConfig first (all built-in switches off), then WithCorpusChecks so its CheckCorpus switch
	// lands on a config whose only enabled check is the corpus one.
	scan := NewActiveScanner(store, zap.NewNop()).
		WithSender(sender.NewSender(sender.DefaultSenderConfig())).
		WithConfig(&ScanConfig{MaxConcurrency: 1}).
		WithCorpusChecks([]*bcheck.Check{corpusCheck(t, `given query insertion point then
  send payload:
    appending: "VULN"
  if "VULN" in {latest.response.body} then
    report issue:
      severity: high
      confidence: certain
      detail: "reflected"
  end if
`)})

	outcome, findings := scan.AuditWithin(context.Background(), id, DefaultAuditConfig())

	if got := scan.ActiveCheckCount(); got != 1 {
		t.Errorf("enabled checks = %d, want just the one corpus check", got)
	}
	if outcome.State != ItemStateAudited {
		t.Errorf("state = %s, want audited", outcome.State.Label())
	}
	// The check ran, and it ran through the real sender: one point, one probe.
	if outcome.Ran != 1 {
		t.Errorf("ran = %d, want 1", outcome.Ran)
	}
	if outcome.RequestsSent != 1 {
		t.Errorf("requests sent = %d, want 1 probe to the single insertion point", outcome.RequestsSent)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1: the probe's reflection must surface as a finding", len(findings))
	}
	if findings[0].Name == "" {
		t.Error("the corpus finding must carry the check's issue name")
	}
	if outcome.FindingsDropped != 0 {
		t.Errorf("findings dropped = %d, want 0: the probe response was real", outcome.FindingsDropped)
	}
}

func Test_a_corpus_check_switched_off_by_config_is_not_admitted(t *testing.T) {
	store := core.NewTrafficStore()
	target := newCountingProbeTarget(t)
	id := seedAuditExchange(t, store, target.host, target.port, "/search?a=1", "<html>seed</html>")

	// WithCorpusChecks turns CheckCorpus on; WithConfig overriding it off is the honest opt-out —
	// an operator who explicitly asks for the built-ins alone must get exactly that.
	scan := NewActiveScanner(store, zap.NewNop()).
		WithSender(sender.NewSender(sender.DefaultSenderConfig())).
		WithCorpusChecks([]*bcheck.Check{corpusCheck(t, `given query insertion point then
  send payload:
    appending: "VULN"
  if "VULN" in {latest.response.body} then
    report issue:
      severity: high
      confidence: certain
  end if
`)}).
		WithConfig(&ScanConfig{MaxConcurrency: 1})

	outcome, findings := scan.AuditWithin(context.Background(), id, DefaultAuditConfig())

	if got := scan.ActiveCheckCount(); got != 0 {
		t.Errorf("enabled checks = %d, want 0 with the corpus switch off", got)
	}
	if outcome.Considered() != 0 {
		t.Errorf("considered = %d, want 0", outcome.Considered())
	}
	if got := target.total(); got != 0 {
		t.Errorf("target saw %d request(s), want 0", got)
	}
	if len(findings) != 0 {
		t.Errorf("findings = %d, want 0", len(findings))
	}
}

func Test_auditing_the_same_capture_twice_dispatches_the_insertion_point_check_once(t *testing.T) {
	// The insertion-point unit keys on the captured request itself (origin#id), because two
	// captures of one URL can carry different parameter values — a session token, say — so each
	// capture's point set deserves its own enumeration. What must collapse is *re-auditing the
	// same capture* in one session, which is identical work twice.
	store := core.NewTrafficStore()
	first := seedAuditExchange(t, store, "h.test", 80, "/search?a=1", "<html>one</html>")
	// No sender: the check still dispatches offline (its probe cannot leave, so it counts as a
	// send failure rather than a clean miss), and the ledger's refusal is what is under test.
	scan := NewActiveScanner(store, zap.NewNop()).
		WithConfig(&ScanConfig{MaxConcurrency: 1}).
		WithCorpusChecks([]*bcheck.Check{corpusCheck(t, `given query insertion point then
  send payload:
    appending: "VULN"
  if "VULN" in {latest.response.body} then
    report issue:
      severity: high
      confidence: certain
  end if
`)})

	session, _ := scan.AuditSession(context.Background(), []core.ExchangeID{first, first}, DefaultAuditConfig())

	if len(session.Items) != 2 {
		t.Fatalf("items = %d, want 2", len(session.Items))
	}
	// First admission: the check dispatches (and fails its probe for want of a sender, which is
	// a send failure — never a clean miss). The repeat: refused as already covered.
	if got := session.Items[0].Outcome.Considered(); got != 1 {
		t.Errorf("first admission considered = %d, want 1", got)
	}
	if got := session.Items[1].Outcome.AlreadyCovered; got != 1 {
		t.Errorf("repeat already-covered = %d, want 1: one capture's point set is one unit", got)
	}
	if session.DispatchUnits != 1 {
		t.Errorf("dispatch units = %d, want 1", session.DispatchUnits)
	}
}

func Test_a_given_host_corpus_check_dispatches_once_across_a_session(t *testing.T) {
	// The per-host corpus checks must use the same coarse unit as the built-in per-host ones, so
	// a session over many captures of one host dispatches them once. This is the admission bound
	// applied to the corpus, not a new behaviour.
	store := core.NewTrafficStore()
	first := seedAuditExchange(t, store, "h.test", 80, "/one", "<html>one</html>")
	second := seedAuditExchange(t, store, "h.test", 80, "/two", "<html>two</html>")
	scan := NewActiveScanner(store, zap.NewNop()).
		WithConfig(&ScanConfig{MaxConcurrency: 1}).
		WithCorpusChecks([]*bcheck.Check{corpusCheck(t, `given host then
  if {response.status_code} is "200" then
    report issue:
      severity: low
      confidence: certain
  end if
`)})

	session, _ := scan.AuditSession(context.Background(), []core.ExchangeID{first, second}, DefaultAuditConfig())

	if got := session.Items[0].Outcome.Ran; got != 1 {
		t.Errorf("first capture ran = %d, want 1", got)
	}
	if got := session.Items[1].Outcome.AlreadyCovered; got != 1 {
		t.Errorf("second capture already-covered = %d, want 1: the host answer cannot change", got)
	}
	if session.DispatchUnits != 1 {
		t.Errorf("dispatch units = %d, want 1", session.DispatchUnits)
	}
}
