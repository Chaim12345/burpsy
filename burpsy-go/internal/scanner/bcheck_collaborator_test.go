package scanner

// Integration tests for BCheck collaborator checks through the audit dispatch
// (burpsy-react-ui-ar8v): a corpus check, the real audit engine, the real sender and scope gate,
// vulnapp's out-of-band fixture, and an in-process interaction server that reads what the fixture
// "contacted" the way a real one reads its own log.

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/bcheck"
	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/oob"
	"github.com/burpsy-go/burpsy/internal/sender"
	"github.com/burpsy-go/burpsy/internal/vulnapp"
	"go.uber.org/zap"
)

// vulnappCollaborator is an interaction server for vulnapp's /oob fixtures: an interaction exists
// when the fixture recorded a contact with a host under this server's domain.
//
// held models delivery latency. The fixture records its contact synchronously, inside the probe's
// own request, but a real interaction server hands a callback to its poller seconds later; while
// held, nothing has been delivered yet.
type vulnappCollaborator struct {
	domain string
	mu     sync.Mutex
	reads  int
	held   bool
}

func (v *vulnappCollaborator) release() {
	v.mu.Lock()
	v.held = false
	v.mu.Unlock()
}

func (v *vulnappCollaborator) Domain() string { return v.domain }

func (v *vulnappCollaborator) InteractionsFor(marker string) ([]oob.Interaction, error) {
	v.mu.Lock()
	v.reads++
	held := v.held
	v.mu.Unlock()
	if held {
		return nil, nil
	}
	var out []oob.Interaction
	for _, c := range vulnapp.OutboundContacts() {
		if !strings.HasSuffix(c.Host, "."+v.domain) {
			continue
		}
		raw := "GET / HTTP/1.1\r\nHost: " + c.Host + "\r\n\r\n"
		qtype := ""
		if c.Protocol == "dns" {
			raw = ";; QUESTION SECTION:\n;" + c.Host + ".\tIN\t A"
			qtype = "A"
		}
		in := oob.Interaction{Protocol: c.Protocol, FullID: c.Host, QType: qtype, RawRequest: raw, RemoteAddress: "127.0.0.1"}
		if marker == "" || strings.Contains(strings.ToLower(raw), strings.ToLower(marker)) {
			out = append(out, in)
		}
	}
	return out, nil
}

type vulnappOOBProvider struct{ ch *vulnappCollaborator }

func (p *vulnappOOBProvider) Channel(context.Context) (OOBChannel, error) { return p.ch, nil }
func (p *vulnappOOBProvider) Close() error                                { return nil }
func (p *vulnappOOBProvider) Registration() OOBRegistration {
	return OOBRegistration{Attempted: true, Open: true, Domain: p.ch.domain}
}

// oobTarget serves vulnapp and seeds the two /oob fixtures as captured GETs with an empty url
// parameter, so an appended collaborator address is the whole value — what the fixture fetches.
func oobTarget(t *testing.T) (*core.TrafficStore, map[string]core.ExchangeID, *countingHandler) {
	t.Helper()
	counter := &countingHandler{inner: vulnapp.Handler()}
	srv := httptest.NewServer(counter)
	t.Cleanup(srv.Close)
	host, portStr, ok := strings.Cut(strings.TrimPrefix(srv.URL, "http://"), ":")
	if !ok {
		t.Fatalf("cannot split %q", srv.URL)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		t.Fatalf("port: %v", err)
	}
	store := core.NewTrafficStore()
	ids := map[string]core.ExchangeID{}
	for _, path := range []string{"/oob/fetch?url=", "/safe/oob/fetch?url="} {
		res, err := srv.Client().Get(srv.URL + path)
		if err != nil {
			t.Fatalf("seed %s: %v", path, err)
		}
		body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
		_ = res.Body.Close()
		reqID, err := store.Put([]byte("GET "+path+" HTTP/1.1\r\nHost: "+host+"\r\n\r\n"), core.DirectionRequest)
		if err != nil {
			t.Fatal(err)
		}
		respID, err := store.Put([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: "+
			strconv.Itoa(len(body))+"\r\n\r\n"+string(body)), core.DirectionResponse)
		if err != nil {
			t.Fatal(err)
		}
		ex := &core.Exchange{Request: core.MsgPtr(reqID), Response: &respID, Host: host, Port: uint16(port),
			Method: "GET", Path: path}
		store.AddExchange(ex)
		ids[path] = ex.ID
	}
	counter.reset()
	return store, ids, counter
}

// countingHandler counts the requests that reach the target, so a test can prove what left.
type countingHandler struct {
	inner http.Handler
	mu    sync.Mutex
	n     int
}

func (c *countingHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	c.n++
	c.mu.Unlock()
	c.inner.ServeHTTP(w, r)
}

func (c *countingHandler) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}

func (c *countingHandler) reset() {
	c.mu.Lock()
	c.n = 0
	c.mu.Unlock()
}

// ssrfCheck is PortSwigger's corpus SSRFInjection.bcheck as transcribed in
// docs/BCHECK-RESEARCH.md (fixture F4), and pinned verbatim in the bcheck package's tests.
const ssrfCheck = "metadata:\n" +
	"    language: v1-beta\n" +
	"    name: \"SSRF in each insetpoint\"\n" +
	"    description: \"Insert an Collaborator address into each parameter to detect SSRF\"\n" +
	"    author: \"xelkomy\"\n" +
	"\n" +
	"define:\n" +
	"    ssrfaddress=`{generate_collaborator_address()}`\n" +
	"\n" +
	"# we will automatically insert into nested insertion points\n" +
	"given insertion point then\n" +
	"    send payload:\n" +
	"        appending: {ssrfaddress}\n" +
	"\t\t\n" +
	"\tif http interactions then\n" +
	"        report issue:\n" +
	"            severity: high\n" +
	"            confidence: firm\n" +
	"            detail: \"SSRF Discovery by BCheck\"\n" +
	"            remediation: \"Implement SSRF remediation measures.\"\n" +
	"    end if\n"

func collabScanner(t *testing.T, store *core.TrafficStore, provider OOBProvider) *ActiveScanner {
	t.Helper()
	c, err := bcheck.Parse(ssrfCheck)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	scan := NewActiveScanner(store, zap.NewNop()).
		WithSender(sender.NewSender(sender.DefaultSenderConfig())).
		WithConfig(&ScanConfig{MaxConcurrency: 1, Timeout: time.Minute, PendingDeadline: 3 * time.Second}).
		WithCorpusChecks([]*bcheck.Check{c})
	if provider != nil {
		scan.WithOOBProvider(provider)
	}
	return scan
}

// A callback delivered while the check is still running settles it in the audit itself.
func TestACollaboratorBCheckReportsACallbackAlreadyDeliveredInTheAudit(t *testing.T) {
	store, ids, counter := oobTarget(t)
	scan := collabScanner(t, store, &vulnappOOBProvider{ch: &vulnappCollaborator{domain: "collab-ar8v-live.test"}})

	outcome, findings := scan.AuditWithin(context.Background(), ids["/oob/fetch?url="], DefaultAuditConfig())
	if outcome.RequestsSent != 1 || counter.count() != 1 {
		t.Fatalf("requests sent = %d, target saw %d; want 1", outcome.RequestsSent, counter.count())
	}
	if len(findings) != 1 || findings[0].Param != "url" || !strings.Contains(findings[0].Evidence, "HTTP interaction") {
		t.Fatalf("findings = %+v, want one at parameter url with the HTTP interaction as evidence", findings)
	}
	if scan.PendingCount() != 0 {
		t.Errorf("pending = %d, want 0: nothing was left unknown", scan.PendingCount())
	}
}

// The vulnerable endpoint, callback delivered late: the audit sends one probe carrying a fresh
// collaborator address, does not block on the callback, counts the check undecided (never clean),
// and the deferred phase reports the finding with the interaction as its evidence.
func TestACollaboratorBCheckFindsTheSSRFThroughTheAuditAndItsDeferredPhase(t *testing.T) {
	store, ids, counter := oobTarget(t)
	ch := &vulnappCollaborator{domain: "collab-ar8v.test", held: true}
	scan := collabScanner(t, store, &vulnappOOBProvider{ch: ch})

	outcome, findings := scan.AuditWithin(context.Background(), ids["/oob/fetch?url="], DefaultAuditConfig())
	if outcome.Error != "" {
		t.Fatalf("audit failed: %s", outcome.Error)
	}
	if outcome.RequestsSent != 1 || counter.count() != 1 {
		t.Fatalf("requests sent = %d, target saw %d; want one probe through the sender to the one insertion point",
			outcome.RequestsSent, counter.count())
	}
	if outcome.Ran != 1 || outcome.Unmeasurable != 1 || outcome.Skipped != 0 {
		t.Errorf("ran %d / unmeasurable %d / skipped %d; want 1 / 1 / 0: planted and awaiting is undecided, not clean",
			outcome.Ran, outcome.Unmeasurable, outcome.Skipped)
	}
	if len(findings) != 0 {
		t.Errorf("the audit itself reported %d finding(s); the callback belongs to the deferred phase", len(findings))
	}
	if scan.PendingCount() != 1 {
		t.Fatalf("pending claims = %d, want 1", scan.PendingCount())
	}

	ch.release() // the interaction server delivers the callback the fixture recorded
	deferred, completion := scan.FinishScan(context.Background(), DefaultAuditConfig())
	if len(deferred) != 1 {
		t.Fatalf("deferred findings = %d, want 1 (pending: %s)", len(deferred), completion.Pending)
	}
	f := deferred[0]
	if f.Name == "" || f.Param != "url" || f.Severity != "high" || f.Confidence != "firm" {
		t.Errorf("finding = %q param %q %s/%s; want the check's issue at parameter url, high/firm",
			f.Name, f.Param, f.Severity, f.Confidence)
	}
	if !strings.Contains(f.Evidence, "HTTP interaction") || !strings.Contains(f.Evidence, "collab-ar8v.test") {
		t.Errorf("evidence = %q, want the HTTP interaction with its collaborator address", f.Evidence)
	}
	if f.ExchangeID != ids["/oob/fetch?url="] {
		t.Errorf("finding is attributed to exchange %d, want the audited one", f.ExchangeID)
	}
	if len(completion.Outstanding) != 0 {
		t.Errorf("outstanding = %d after the callback settled the claim", len(completion.Outstanding))
	}
	if counter.count() != 1 {
		t.Errorf("the target saw %d requests in all; the deferred replay must send nothing", counter.count())
	}
}

// The safe twin: the same probe goes out, no callback ever arrives, and the claim ends outstanding
// — not a finding, and not clean either.
func TestTheSafeTwinYieldsNoFindingAndAnOutstandingClaim(t *testing.T) {
	store, ids, counter := oobTarget(t)
	ch := &vulnappCollaborator{domain: "collab-ar8v-safe.test"}
	scan := collabScanner(t, store, &vulnappOOBProvider{ch: ch})
	scan.WithConfig(&ScanConfig{MaxConcurrency: 1, Timeout: time.Minute, PendingDeadline: 1500 * time.Millisecond, CheckCorpus: true})

	outcome, _ := scan.AuditWithin(context.Background(), ids["/safe/oob/fetch?url="], DefaultAuditConfig())
	if outcome.RequestsSent != 1 || counter.count() != 1 {
		t.Fatalf("requests sent = %d, target saw %d; want 1 probe, or the twin proves nothing",
			outcome.RequestsSent, counter.count())
	}
	if outcome.Unmeasurable != 1 {
		t.Errorf("unmeasurable = %d, want 1", outcome.Unmeasurable)
	}
	deferred, completion := scan.FinishScan(context.Background(), DefaultAuditConfig())
	if len(deferred) != 0 {
		t.Fatalf("the safe twin produced %d finding(s): a false positive", len(deferred))
	}
	if len(completion.Outstanding) != 1 || !strings.HasPrefix(completion.Outstanding[0].Row, "BCheck: ") {
		t.Fatalf("outstanding = %d, want the one BCheck claim: no callback is not evidence of no SSRF",
			len(completion.Outstanding))
	}
	if !strings.Contains(completion.Outstanding[0].What, "collab-ar8v-safe.test") {
		t.Errorf("outstanding claim %q does not name the address it planted", completion.Outstanding[0].What)
	}
	if !strings.Contains(completion.Pending, "outstanding") {
		t.Errorf("pending summary %q does not report the unanswered claim", completion.Pending)
	}
	ch.mu.Lock()
	reads := ch.reads
	ch.mu.Unlock()
	if reads < 2 {
		t.Errorf("the channel was read %d time(s); the outstanding verdict must come from polling it", reads)
	}
}

// "Don't use Collaborator": no provider. The check is dispatched and refused with the reason —
// counted Skipped, nothing sent, nothing deferred — never run with an empty address and read clean.
func TestWithoutACollaboratorTheCorpusCheckIsReportedNotRun(t *testing.T) {
	store, ids, counter := oobTarget(t)
	scan := collabScanner(t, store, nil)

	outcome, findings := scan.AuditWithin(context.Background(), ids["/oob/fetch?url="], DefaultAuditConfig())
	if outcome.Skipped != 1 || outcome.Ran != 0 {
		t.Errorf("skipped %d / ran %d, want 1 / 0", outcome.Skipped, outcome.Ran)
	}
	if outcome.RequestsSent != 0 || counter.count() != 0 {
		t.Errorf("sent %d / target saw %d, want nothing: a probe without an address proves nothing",
			outcome.RequestsSent, counter.count())
	}
	if len(findings) != 0 || scan.PendingCount() != 0 {
		t.Errorf("findings %d / pending %d, want 0 / 0", len(findings), scan.PendingCount())
	}

	// The same reason reaches a console test run (kbu1).
	ex, err := store.GetExchange(ids["/oob/fetch?url="])
	if err != nil {
		t.Fatal(err)
	}
	c, _ := bcheck.Parse(ssrfCheck)
	trial := scan.TrialCorpusCheck(context.Background(), ex, c)
	if !strings.Contains(trial.Unsupported, "collaborator") || !strings.Contains(trial.Unsupported, "not run") {
		t.Errorf("trial reason = %q, want it to say the check was not run for want of a collaborator", trial.Unsupported)
	}
}

// The probe still passes the scope gate. The audited exchange is in scope; the check's probe names
// a path the scope excludes, so the gate refuses it: nothing reaches the target, the check counts
// as a send failure rather than clean, and no claim is registered for an address no target was
// sent.
func TestACollaboratorProbeOutsideScopeIsRefused(t *testing.T) {
	store, ids, counter := oobTarget(t)
	ex, err := store.GetExchange(ids["/oob/fetch?url="])
	if err != nil {
		t.Fatal(err)
	}
	scope := core.NewScope()
	scope.AddInclude(ex.Host)
	scope.Add(core.NewScopeRuleWithPath(core.ScopeExclude, ex.Host, "/admin"))
	c, err := bcheck.Parse("metadata:\n  language: v2-beta\n  name: \"oob admin\"\n" +
		"define:\n  a = `{generate_collaborator_address()}`\n" +
		"given request then\n  send request:\n    path: `/admin/fetch?url=http://{a}/`\n" +
		"  if http interactions then\n    report issue:\n      severity: high\n      confidence: firm\n  end if\n")
	if err != nil {
		t.Fatal(err)
	}
	scan := NewActiveScanner(store, zap.NewNop()).
		WithSender(sender.NewSender(sender.DefaultSenderConfig())).
		WithConfig(&ScanConfig{MaxConcurrency: 1, Timeout: time.Minute, PendingDeadline: time.Second}).
		WithCorpusChecks([]*bcheck.Check{c}).
		WithOOBProvider(&vulnappOOBProvider{ch: &vulnappCollaborator{domain: "collab-ar8v-scope.test"}}).
		WithScope(scope)

	outcome, findings := scan.AuditWithin(context.Background(), ids["/oob/fetch?url="], DefaultAuditConfig())
	if outcome.Error != "" {
		t.Fatalf("the audited exchange itself was refused (%s); the probe's gate is what is under test", outcome.Error)
	}
	if outcome.RequestsRefused != 1 || outcome.SendFailures != 1 {
		t.Errorf("refused %d / send failures %d, want 1 / 1", outcome.RequestsRefused, outcome.SendFailures)
	}
	if counter.count() != 0 {
		t.Errorf("the out-of-scope path saw %d request(s)", counter.count())
	}
	if len(findings) != 0 || scan.PendingCount() != 0 {
		t.Errorf("findings %d / pending %d, want 0 / 0", len(findings), scan.PendingCount())
	}
}
