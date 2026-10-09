package web

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/dash"
	"github.com/burpsy-go/burpsy/internal/query"
	"github.com/burpsy-go/burpsy/internal/scanner"
	"go.uber.org/zap"
)

// ---- Live active audit ------------------------------------------------------------------------
//
// Mirrors crates/web/src/routes/liveaudit.rs: a switch plus two counters, owned by the web
// server (which holds the scanner) and flipped by the UI. The sweep itself is a background
// loop, bounded the way the Rust one is: walk newly-completed in-scope exchanges in id order
// (append-only store, so position is the id), hand a batch to the active scanner, and record
// what happened. An exchange whose response has not landed simply waits for a later tick.

// LiveAuditTrafficSource is Burp's scope source choice (Zhwl :1606-1607), for the live
// sweep (burpsy-react-ui-zk35): which captured traffic the sweep admits.
type LiveAuditTrafficSource string

const (
	// LiveAuditSourceProxy is Burp's "Proxy": only traffic the operator's own client sent
	// through the proxy. The default, because a sweep that also audits the crawler's and
	// the scanner's own requests would audit its own probe traffic — the feedback loop Burp's
	// "Proxy" choice exists to prevent.
	LiveAuditSourceProxy LiveAuditTrafficSource = "proxy"
	// LiveAuditSourceEverything is Burp's "Everything": every in-scope captured exchange
	// regardless of which tool produced it. An operator crawling a target with the live
	// sweep on wants the crawler's discoveries audited as they land, and says so here.
	LiveAuditSourceEverything LiveAuditTrafficSource = "everything"
)

// liveAuditSourceDefault is the inherited choice when the operator never set one.
const liveAuditSourceDefault = LiveAuditSourceProxy

// LiveAuditState is the operator-visible state of the live sweep: whether it is enabled and
// how many exchanges/findings the sweep has accumulated so far.
//
// `skipped` and `stalledAt` exist because `swept` alone cannot distinguish a sweep that has
// audited everything from a sweep whose cursor stopped moving. The sweep walks ids in order and
// waits at an exchange whose response has not landed — correct for a proxied request still in
// flight, and indistinguishable, from `swept` alone, from a cursor that will never move again. See
// liveAuditTick for why one such exchange used to end coverage permanently.
type LiveAuditState struct {
	enabled  atomic.Bool
	swept    atomic.Uint64
	findings atomic.Uint64
	// skipped counts exchanges the cursor advanced past without auditing, because their response
	// never landed. Never folded into swept: an exchange nobody looked at is not an exchange that
	// came back clean.
	skipped atomic.Uint64
	// stalledAt is the id the cursor is currently waiting on, +1 so that zero means "not waiting"
	// (id 0 is a real exchange id in a position-is-the-id store). Read only for the operator view.
	stalledAt atomic.Uint64
	// reached and recorded are where the cursor has walked to and how many exchanges the store held
	// when it got there. Their difference is Behind(): the sweep's backlog.
	//
	// This is the arithmetic that makes the pane honest under a crawl. The sweep admits at most 200
	// exchanges every liveAuditSweepInterval — about 66 a second at the shipped interval — and a
	// crawler outpaces that without trying. `swept` then keeps climbing while the gap between it and
	// the capture grows, so the pane whose job is to demonstrate DASH-03 would be the one reporting a
	// count with no idea how much it was behind.
	reached  atomic.Uint64
	recorded atomic.Uint64
	// behindSince is when the current backlog began, as unix nanoseconds; 0 while the sweep is caught
	// up. Behind() alone cannot tell a sweep twenty seconds behind a burst from one that has been
	// behind since the crawl started — both show the same number — so the pane needs the age to say
	// which, and "caught up" is the only state whose age is not a duration (burpsy-react-ui-iosv).
	behindSince atomic.Int64
	// batchLimit is the admission bound the last tick ran with. Recorded so the catch-up is legible: a
	// sweep admitting 10,000 exchanges a tick is doing something the baseline 200 does not explain, and
	// without this the pane would show a burst with nothing saying it was deliberate.
	batchLimit atomic.Uint64
	// seenMu guards seen: the cross-run request-content ledger (apfh). The sweep's AuditLedger
	// lives on the run and dies with it — a restarted sweep or process re-audited every
	// exchange it had already covered. This ledger lives on the state and on disk, keyed by
	// (host, request fingerprint): a re-seen exchange with content already audited is counted
	// as REQUEST_TO_AUDIT_DEDUPLICATED (Burp's Zeze.java:17 disposition) instead of becoming
	// audit work again. The 6n4d pairing is exact: the fingerprint makes changed content a
	// NEW key there; here identical content is the OLD key, so one gate admits the changed
	// and the other refuses the same.
	seenMu sync.Mutex
	// seen holds "host#fp" -> true. Bounded like the dispatch ledger: past seenCap it is
	// dropped and rebuilt, counted, reported, and recorded as an event — the honest trade,
	// not a silent cap (see seenCap).
	seen map[string]bool
	// seenCap bounds the seen ledger. Twenty thousand distinct request contents is more
	// than any single engagement's in-scope surface; past it the ledger resets and
	// already-audited content re-audits once more, visibly.
	seenCap int
	// liveSeen holds every distinct in-scope URL the sweep has admitted, in first-seen order —
	// the live passive crawl's seed set (burpsy-react-ui-tqug). Wire-observed: the URL a
	// captured exchange actually fetched, not a link parsed out of a body. This set is what
	// a "crawl from live capture" seeds from, so a page a user browses is not only audited
	// but becomes a crawl origin; the count of distinct URLs is the honest metric the pane
	// reports. The same collector is where browser-rendered links (nx7b) will land — one
	// mechanism, two producers — so wire and DOM sources cannot disagree about what was
	// seen.
	liveSeenMu sync.Mutex
	liveSeen   []string
	liveSeenOf map[string]bool

	// seenAddedSinceSave counts new ledger keys since the last persist; the sweep saves in
	// small batches rather than per-exchange, so a trickling capture does not become a
	// write-per-request on disk.
	seenAddedSinceSave atomic.Int64
	// seenLedgerResets counts how many times the seen ledger was dropped at its cap. On the
	// state, not a package global: a counter that outlives its state leaks across -count runs
	// and across servers in one process, and the pane would report resets another sweep made.
	seenLedgerResets atomic.Uint64
	// deduplicated counts exchanges the sweep refused as already-audited content — the
	// disposition rows, not a caveat: a sweep that skipped 50 re-seen captures is 50 rows of
	// "we already audited this exact request", and the pane says so.
	deduplicated atomic.Uint64
	// pendingRetry holds the id the sweep gave up waiting on, for one bounded re-enqueue when
	// its response eventually lands (iyqg: a skip must not be a death sentence — a proxied
	// request whose response finally arrives after the sweep moved on is auditable, and
	// dropping it permanently because the response was thirty-one seconds late is a coverage
	// loss the pane would never mention). One slot, not a set: the cursor is a position, and a
	// stall is a single id at a time; anything more is a backlog system, which the Behind()
	// counter already reports honestly.
	pendingRetry atomic.Uint64
	// hostSessions counts per-host AuditSessions the sweep has run (6urp) — the honest
	// pacing metric: a multi-host tick runs one session PER HOST, and the operator can see
	// the batch was split rather than one global sequential run.
	hostSessions atomic.Uint64
	// reWalkMu guards the reset re-walk accounting below (m9e0).
	reWalkMu sync.Mutex
	// reWalkWidth is the admitted-pair count the dead ledger held at the last reset —
	// the width of the re-dispatch the fresh ledger will perform. 0 = no re-walk in progress.
	reWalkWidth int
	// reWalkAdmittedAt is how many pairs the fresh ledger has admitted since the reset.
	reWalkAdmittedAt int
	// reAdmittedTotal accumulates re-admitted pairs across all resets.
	reAdmittedTotal int
	// passiveFindings counts findings the live PASSIVE pass raised (v7fo) — the posture and
	// analysis rows that read the captured exchange and send nothing. Counted separately
	// from the active audit's findings because they are different claims: "found on
	// capture" and "found by sending probes" deserve their own numbers on the pane, and
	// folding them would make a passive-heavy sweep read as an active one.
	passiveFindings atomic.Uint64
	// retried counts exchanges audited on their second chance. Distinct from swept — a pane
	// that folded it in would read "audited 401" for a run that gave up on 1 and took it back,
	// and the second-chance arithmetic (gave up on N, took back M) is the honest sentence.
	retried atomic.Uint64
	// retryMu guards retryCursor's identity across the sweep goroutine and an operator's
	// RetryStalled call: a rewind that races a tick must land the cursor at the id, not at
	// wherever the tick's read moved it in between.
	retryMu sync.Mutex
	// retryCursor is the liveAuditRun whose cursor RetryStalled rewinds. Set at loop start.
	retryCursor *liveAuditCursor
	// collapsed counts checks the shared ledger refused because an identical (dispatch unit, check)
	// had already run. Not a caveat — this work ran, see SessionOutcome.AlreadyCovered — but reported,
	// because it is the whole reason the sweep shares a ledger across ticks and the only way to see
	// the saving is happening.
	collapsed atomic.Uint64
	// ledgerResets counts how many times the shared ledger was dropped at its unit cap. Each reset
	// means checks that had already been collapsed will re-dispatch once more, so a nonzero count is
	// something the operator should be able to see rather than infer from a request rate.
	ledgerResets atomic.Uint64

	// queryMu guards the DSL-03 filter below. A mutex rather than an atomic because the expression
	// and the source text it was parsed from must never be read apart: the view reports the text and
	// the sweep evaluates the expression, and a pane showing one query while another filters traffic
	// is worse than no filter at all.
	queryMu  sync.RWMutex
	query    *query.Expr
	querySrc string

	// trafficSource is the per-source gate (zk35): which tool's traffic the sweep admits.
	// Guarded by the same queryMu as the DSL filter: the view reports the choice text and
	// the sweep reads it per exchange, and a pane showing one source while another filters
	// traffic is the same lie a split query read would be.
	trafficSource LiveAuditTrafficSource
	// configName and poolName are the live task's own scan configuration and resource pool
	// (burpsy-react-ui-chct); "" is the process-wide AuditConfig and the global pace. Guarded by queryMu.
	configName, poolName string
	// refusedSource counts in-scope exchanges the sweep skipped because of the source gate.
	// Counted per source like the other refuses: a sweep that declined 40 crawler captures
	// is 40 rows of "the operator chose Proxy", and the pane says so rather than reading
	// them as swept.
	refusedSource atomic.Uint64
}

// TrafficSource returns the sweep's source choice, the default when never set.
func (la *LiveAuditState) TrafficSource() LiveAuditTrafficSource {
	la.queryMu.RLock()
	defer la.queryMu.RUnlock()
	if la.trafficSource == "" {
		return liveAuditSourceDefault
	}
	return la.trafficSource
}

// SetTrafficSource installs the operator's choice. An unknown value is refused rather than
// read as "everything": a typo in the wire shape must not silently widen the gate.
// SetRunSettings records the live task's scan configuration and resource pool by name (chct). The
// caller has already resolved both, so a name stored here is one that resolves.
func (la *LiveAuditState) SetRunSettings(config, pool *string) {
	la.queryMu.Lock()
	defer la.queryMu.Unlock()
	if config != nil {
		la.configName = *config
	}
	if pool != nil {
		la.poolName = *pool
	}
}

// RunSettings returns the live task's scan configuration and resource pool names.
func (la *LiveAuditState) RunSettings() (config, pool string) {
	la.queryMu.Lock()
	defer la.queryMu.Unlock()
	return la.configName, la.poolName
}

func (la *LiveAuditState) SetTrafficSource(src LiveAuditTrafficSource) error {
	switch src {
	case LiveAuditSourceProxy, LiveAuditSourceEverything:
	default:
		return fmt.Errorf("unknown live-audit traffic source %q: want %q or %q",
			src, LiveAuditSourceProxy, LiveAuditSourceEverything)
	}
	la.queryMu.Lock()
	la.trafficSource = src
	la.queryMu.Unlock()
	return nil
}

// RefusedSource reports how many in-scope exchanges the source gate skipped.
func (la *LiveAuditState) RefusedSource() uint64 { return la.refusedSource.Load() }

// NoteLiveURL records one URL the sweep admitted (tqug). Returns true when the URL was new
// to the set. The URL is normalized to scheme://host:port/path (query dropped, default
// ports spelled off): a crawl seed is an origin to walk, not an exact request to replay, the
// query the user typed carries parameters the crawler would re-submit verbatim, and a URL
// spelled two ways would re-walk one origin. Normalization lives HERE rather than in the
// producer so every producer — the sweep today, the browser enrichment (nx7b) later —
// shares one spelling and the dedup holds across them.
func (la *LiveAuditState) NoteLiveURL(u string) bool {
	u = normalizeLiveSeedURL(u)
	if u == "" {
		return false
	}
	la.liveSeenMu.Lock()
	defer la.liveSeenMu.Unlock()
	if la.liveSeenOf == nil {
		la.liveSeenOf = make(map[string]bool)
	}
	if la.liveSeenOf[u] {
		return false
	}
	la.liveSeenOf[u] = true
	la.liveSeen = append(la.liveSeen, u)
	return true
}

// normalizeLiveSeedURL strips the query and spells off default ports. An unparseable URL is
// returned as-is: inventing a spelling for a URL this cannot parse would seed the crawl
// with a string nobody observed.
func normalizeLiveSeedURL(u string) string {
	parsed, err := url.Parse(strings.TrimSpace(u))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return strings.TrimSpace(u)
	}
	host := parsed.Hostname()
	port := parsed.Port()
	switch {
	case port == "", parsed.Scheme == "https" && port == "443", parsed.Scheme == "http" && port == "80":
		return parsed.Scheme + "://" + host + parsed.Path
	default:
		return parsed.Scheme + "://" + host + ":" + port + parsed.Path
	}
}

// LiveSeenURLs returns the distinct in-scope URLs the sweep has admitted, in first-seen
// order, and takes them: a crawl seeded from the set consumes the observation (Burp's live
// passive crawl does not re-feed the same origin twice), and a later crawl that finds
// nothing new says so rather than silently reusing an old harvest. The second return is
// how many URLs were taken.
func (la *LiveAuditState) TakeLiveSeenURLs() ([]string, int) {
	la.liveSeenMu.Lock()
	defer la.liveSeenMu.Unlock()
	out := append([]string(nil), la.liveSeen...)
	la.liveSeen = nil
	la.liveSeenOf = make(map[string]bool)
	return out, len(out)
}

// LiveSeenCount reports how many distinct URLs are held without taking them.
func (la *LiveAuditState) LiveSeenCount() int {
	la.liveSeenMu.Lock()
	defer la.liveSeenMu.Unlock()
	return len(la.liveSeen)
}

// NewLiveAuditState creates a disabled live audit state.
func NewLiveAuditState() *LiveAuditState {
	return &LiveAuditState{}
}

// IsEnabled reports whether the sweep loop should run.
func (la *LiveAuditState) IsEnabled() bool { return la.enabled.Load() }

// SetEnabled flips the switch.
func (la *LiveAuditState) SetEnabled(on bool) { la.enabled.Store(on) }

// Record accumulates the outcome of one sweep tick.
func (la *LiveAuditState) Record(swept, findings uint64) {
	la.swept.Add(swept)
	la.findings.Add(findings)
}

// Swept returns the total exchanges handed to the scanner.
func (la *LiveAuditState) Swept() uint64 { return la.swept.Load() }

// FindingCount returns the total findings the sweep produced.
func (la *LiveAuditState) FindingCount() uint64 { return la.findings.Load() }

// Skipped returns how many exchanges the cursor advanced past unaudited because their response
// never landed. Reported alongside Swept rather than added to it — DASH-03's rule, applied to the
// pane that exists to demonstrate it.
func (la *LiveAuditState) Skipped() uint64 { return la.skipped.Load() }

// StalledAt returns the exchange id the cursor is waiting on and whether it is waiting at all. A
// sweep waiting on an in-flight response is normal; a sweep waiting on the same id for many ticks
// is the shape of lost coverage, which is why the id is exposed rather than merely counted.
func (la *LiveAuditState) StalledAt() (uint64, bool) {
	v := la.stalledAt.Load()
	if v == 0 {
		return 0, false
	}
	return v - 1, true
}

// recordSkipped accounts for one exchange the cursor gave up waiting on, and files the id
// for its one bounded retry: when the response lands later, the sweep audits it once more
// rather than leaving the skip as a terminal verdict.
func (la *LiveAuditState) recordSkipped(n uint64, retryID core.ExchangeID) {
	la.skipped.Add(n)
	// +1 so 0 means "no retry pending" — id 0 is a real exchange in a position-is-the-id store.
	la.pendingRetry.Store(uint64(retryID) + 1)
}

// Retried reports how many exchanges the sweep audited on their second chance.
func (la *LiveAuditState) Retried() uint64 { return la.retried.Load() }

// recordPassive counts passive findings raised by the live passive pass (v7fo).
func (la *LiveAuditState) recordPassive(n uint64) { la.passiveFindings.Add(n) }

// PassiveFindings reports how many findings the live passive pass has raised.
func (la *LiveAuditState) PassiveFindings() uint64 { return la.passiveFindings.Load() }

// recordHostSessions notes the per-host session count one tick ran (6urp).
func (la *LiveAuditState) recordHostSessions(n uint64) { la.hostSessions.Add(n) }

// HostSessions reports the total per-host sessions the sweep has run.
func (la *LiveAuditState) HostSessions() uint64 { return la.hostSessions.Load() }

// seenKey is the cross-run dedup key: the host the request went to and the request-content
// fingerprint. Not the URL: the sweep's own audit ledger already keys by scope+content
// (6n4d), and this ledger's question is coarser — "has THIS exact content at THIS host been
// audited by any sweep before?" — because it is what survives restarts.
func seenKey(ex *core.Exchange) string {
	return ex.Host + "#" + fmt.Sprintf("%x", ex.RequestFP)
}

// admitSeen consults the cross-run ledger for one exchange. Returns true when the content is
// new (and records it); false when it was already audited — the REQUEST_TO_AUDIT_DEDUPLICATED
// disposition. A zero fingerprint (hand-built or restored exchanges, exchanges minted before
// the capture seam computed one) always admits: refusing content the ledger cannot identify
// would dedup on "unknown", which is a silent coverage hole.
func (la *LiveAuditState) admitSeen(ex *core.Exchange) bool {
	if ex == nil || ex.RequestFP == 0 {
		return true
	}
	la.seenMu.Lock()
	defer la.seenMu.Unlock()
	key := seenKey(ex)
	if la.seen == nil {
		la.seen = make(map[string]bool)
	}
	if la.seen[key] {
		return false
	}
	la.seen[key] = true
	la.seenAddedSinceSave.Add(1)
	return true
}

// SeenCount reports distinct request contents the ledger holds.
func (la *LiveAuditState) SeenCount() int {
	la.seenMu.Lock()
	defer la.seenMu.Unlock()
	return len(la.seen)
}

// seenLedgerCap returns the cap in force, defaulting to 20000.
func (la *LiveAuditState) seenLedgerCap() int {
	if la.seenCap > 0 {
		return la.seenCap
	}
	return 20000
}

// maybeResetSeen drops the seen ledger when it has outgrown its cap, returning true when a
// reset happened. The caller reports it: a reset means already-audited content re-audits once
// more, and that trade is visible, counted, and evented — never a silent cap.
func (la *LiveAuditState) maybeResetSeen() bool {
	la.seenMu.Lock()
	defer la.seenMu.Unlock()
	if len(la.seen) <= la.seenLedgerCap() {
		return false
	}
	la.seen = make(map[string]bool)
	la.seenLedgerResets.Add(1)
	return true
}

// Deduplicated reports how many re-seen exchanges were counted as
// REQUEST_TO_AUDIT_DEDUPLICATED instead of audit work.
func (la *LiveAuditState) Deduplicated() uint64 { return la.deduplicated.Load() }

// SeenLedgerResets reports how many times the seen ledger was dropped at its cap.
func (la *LiveAuditState) SeenLedgerResets() uint64 { return la.seenLedgerResets.Load() }

// PersistSeen stores the seen ledger's keys for a restart, and LoadSeen restores them. The
// list is bounded by the cap, and the format is one key per line: the ledger is a set, and a
// set in a settings value does not want a second encoding ceremony.
func (la *LiveAuditState) PersistSeen() []byte {
	la.seenMu.Lock()
	defer la.seenMu.Unlock()
	out := make([]string, 0, len(la.seen))
	for k := range la.seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return []byte(strings.Join(out, "\n"))
}

func (la *LiveAuditState) LoadSeen(blob []byte) {
	la.seenMu.Lock()
	defer la.seenMu.Unlock()
	la.seen = make(map[string]bool)
	for _, line := range strings.Split(string(blob), "\n") {
		if line != "" {
			la.seen[line] = true
		}
	}
}

// pendingRetryID returns the filed retry id, or none.
func (la *LiveAuditState) pendingRetryID() (core.ExchangeID, bool) {
	v := la.pendingRetry.Load()
	if v == 0 {
		return 0, false
	}
	return core.ExchangeID(v - 1), true
}

// takePendingRetry clears the slot and returns the id if the response has landed: the sweep
// calls this once per tick, and a landed response turns the pending skip into one more
// exchange to audit. Cleared whether or not it landed — the retry is once, and a second
// give-up must not be fileable forever.
func (la *LiveAuditState) takePendingRetry(store *core.TrafficStore) (core.ExchangeID, bool) {
	id, ok := la.pendingRetryID()
	if !ok {
		return 0, false
	}
	la.pendingRetry.Store(0)
	if store == nil {
		return 0, false
	}
	ex, err := store.GetExchange(id)
	if err != nil || ex.Response == nil {
		return id, false
	}
	return id, true
}

// attachRun hands the sweep's cursor to the state so RetryStalled can rewind it.
func (la *LiveAuditState) attachRun(cursor *liveAuditCursor) {
	la.retryMu.Lock()
	la.retryCursor = cursor
	la.retryMu.Unlock()
}

// RetryStalled rewinds the cursor to the stalled exchange so the next tick waits on it again
// with a fresh stall budget. An operator action (iyqg): the pane's only remedies were waiting
// ten ticks or disabling the sweep, and neither tells the operator whether the exchange that
// stalled is auditable at all. Answers whether a rewind happened — false means "not currently
// stalled" or "no sweep running", both of which the pane renders as the button standing down.
func (la *LiveAuditState) RetryStalled() bool {
	id, waiting := la.StalledAt()
	if !waiting {
		return false
	}
	la.retryMu.Lock()
	defer la.retryMu.Unlock()
	cursor := la.retryCursor
	if cursor == nil {
		return false
	}
	// Rewind under the same lock the tick's cursor operations are serialized by: a tick that
	// advanced past the id between the StalledAt read and here would make the rewind land the
	// cursor ahead of the stall, silently. Note the stall budget is NOT reset: the exchange
	// has already waited its ten ticks once, and an operator retry that silently restarted
	// the full budget would be a second, invisible thirty-second wait for the same answer.
	cursor.at = core.ExchangeID(id)
	cursor.stalls = liveAuditStallTicks
	return true
}

// Behind reports how many recorded exchanges the cursor has not reached yet — the sweep's backlog.
//
// Saturating rather than signed: `recorded` and `reached` are written by the same goroutine but read
// by handlers, so a reader can catch them mid-update and see reached briefly ahead. Zero is the right
// answer for that instant; a negative backlog is not an answer at all.
func (la *LiveAuditState) Behind() uint64 {
	recorded, reached := la.recorded.Load(), la.reached.Load()
	if reached >= recorded {
		return 0
	}
	return recorded - reached
}

// BehindFor reports how long the current backlog has existed, or zero when the sweep is caught up.
//
// The age is anchored to the moment the backlog appeared and NOT restarted by every tick that finds it
// still there: a sweep that has been behind for ten minutes is behind by ten minutes, and a number that
// reset on each tick would make the worst case look like the newest one. Zero is the caught-up state —
// a duration of zero, not an absent answer — which is why every reader treats it as a value.
func (la *LiveAuditState) BehindFor() time.Duration {
	since := la.behindSince.Load()
	if since == 0 {
		return 0
	}
	return time.Since(time.Unix(0, since))
}

// BatchLimit reports the admission bound the last tick ran with, or zero before any tick has run.
//
// Zero is honest here in a way Behind's zero is not: a bound nobody has applied yet is not a bound of
// zero, it is the absence of a measurement, and the pane renders the two differently.
func (la *LiveAuditState) BatchLimit() uint64 { return la.batchLimit.Load() }

// recordBatchLimit stores the bound a tick ran with, for the pane.
func (la *LiveAuditState) recordBatchLimit(n int) { la.batchLimit.Store(uint64(n)) }

// Collapsed reports checks the shared ledger refused as already covered. See the field doc: reported,
// never a caveat.
func (la *LiveAuditState) Collapsed() uint64 { return la.collapsed.Load() }

// LedgerResets reports how many times the shared ledger was dropped at its unit cap.
func (la *LiveAuditState) LedgerResets() uint64 { return la.ledgerResets.Load() }

// recordPosition stores where the cursor reached and how much had been recorded when it got there, and
// maintains the backlog's age anchor: the first tick that finds work outstanding stamps the time, every
// later tick that still finds work outstanding leaves the stamp alone, and a tick that reaches
// everything clears it. Anchoring here rather than in the tick keeps the age correct for every caller of
// the position accounting, which is what makes it a property of the state and not of one code path.
func (la *LiveAuditState) recordPosition(reached, recorded uint64) {
	la.reached.Store(reached)
	la.recorded.Store(recorded)
	if reached >= recorded {
		la.behindSince.Store(0)
		return
	}
	// Only the tick that FINDS the backlog stamps it: a compare-and-swap from zero, so a later tick
	// cannot restart the clock on a backlog that is already dated.
	la.behindSince.CompareAndSwap(0, time.Now().UnixNano())
}

func (la *LiveAuditState) recordCollapsed(n uint64) { la.collapsed.Add(n) }
func (la *LiveAuditState) recordLedgerReset()       { la.ledgerResets.Add(1) }

// The reset re-walk's honest accounting (m9e0): after a ledger reset, the collapsed pairs
// re-dispatch. reWalkWidth is the dead ledger's admitted count AT THE RESET — the cost,
// stated once; reAdmittedTotal accumulates what the fresh ledger has actually admitted.
// Together with ledgerResets, the pane shows the event, its width, and the payment — not
// one figure hiding an unbounded cost. Zero width means "no re-walk in progress".
func (la *LiveAuditState) beginResetReWalk(width int) {
	la.reWalkMu.Lock()
	la.reWalkWidth = width
	la.reWalkAdmittedAt = 0
	la.reWalkMu.Unlock()
}

// recordReAdmission notes the fresh ledger admitting one pair after a reset. Returns true
// when the re-walk just completed — the caller reports it.
func (la *LiveAuditState) recordReAdmission() (done bool) {
	la.reWalkMu.Lock()
	defer la.reWalkMu.Unlock()
	if la.reWalkWidth == 0 {
		return false // no re-walk in progress
	}
	la.reWalkAdmittedAt++
	la.reAdmittedTotal++
	if la.reWalkAdmittedAt >= la.reWalkWidth {
		la.reWalkWidth = 0
		return true
	}
	return false
}

// ResetReWalk reports the in-progress re-walk's remaining width and the total re-admitted
// across resets. Zero width with a nonzero admitted is a completed re-walk.
func (la *LiveAuditState) ResetReWalk() (remaining, admitted int) {
	la.reWalkMu.Lock()
	defer la.reWalkMu.Unlock()
	if la.reWalkWidth == 0 {
		return 0, la.reAdmittedTotal
	}
	return la.reWalkWidth - la.reWalkAdmittedAt, la.reAdmittedTotal
}

// SetQuery installs the live-audit scope query (DSL-03), or clears it when src is empty.
//
// The full grammar is accepted with no field restriction, which is the difference between this gate
// and the crawler's. The crawler decides *before* the fetch, so `status`, `mime` and `body` have no
// obtainable value and it refuses any query naming them (see internal/query/fields.go). Live audit
// decides *after* the response is stored, so all five fields are real answers and every query the
// parser accepts can be evaluated honestly here.
//
// A parse error is returned and nothing is installed: the previous filter — including "no filter" —
// stays in force. Installing a partially-understood query would silently change which traffic is
// audited, which is the one thing an operator setting a filter must be able to rely on.
func (la *LiveAuditState) SetQuery(src string) error {
	if src == "" {
		la.queryMu.Lock()
		la.query, la.querySrc = nil, ""
		la.queryMu.Unlock()
		return nil
	}
	expr, err := query.Parse(src)
	if err != nil {
		return err
	}
	la.queryMu.Lock()
	la.query, la.querySrc = expr, src
	la.queryMu.Unlock()
	return nil
}

// Query returns the installed filter and the source text it was parsed from, together — see queryMu.
func (la *LiveAuditState) Query() (*query.Expr, string) {
	la.queryMu.RLock()
	defer la.queryMu.RUnlock()
	return la.query, la.querySrc
}

// noteStall records which id the cursor is waiting on, or clears it when the cursor is moving.
func (la *LiveAuditState) noteStall(id uint64, waiting bool) {
	if !waiting {
		la.stalledAt.Store(0)
		return
	}
	la.stalledAt.Store(id + 1)
}

// liveAuditView mirrors dashboard.ts's LiveAuditResp.
//
// Skipped and StalledAt are carried next to Swept rather than folded into it: "audited 400" and
// "audited 400, gave up on 3, currently waiting on 404" are different claims about coverage, and
// only the second one is honest when it is true. This is DASH-03's rule applied to the pane whose
// job is to demonstrate it.
type liveAuditView struct {
	Wired    bool   `json:"wired"`
	Enabled  bool   `json:"enabled"`
	Hint     string `json:"hint,omitempty"`
	Swept    uint64 `json:"swept,omitempty"`
	Findings uint64 `json:"findings,omitempty"`
	Skipped  uint64 `json:"skipped,omitempty"`
	// Behind is recorded-but-not-yet-reached exchanges: the sweep's backlog. Not omitempty, unlike the
	// counters above — a zero backlog is the single most useful thing this field ever says ("the sweep
	// is caught up"), and omitting it would make caught-up indistinguishable from an older build that
	// did not report a backlog at all.
	Behind uint64 `json:"behind"`
	// BehindForMs is how long that backlog has existed, in whole milliseconds, and BatchLimit is the
	// admission bound the last tick ran with (burpsy-react-ui-iosv). Neither is omitempty: a zero age is
	// the caught-up answer and a zero bound is "no tick has run yet", and omitting either would make
	// those states indistinguishable from a build that does not report them at all — the same rule
	// Behind's own field doc states.
	BehindForMs int64  `json:"behind_for_ms"`
	BatchLimit  uint64 `json:"batch_limit"`
	// Collapsed is checks the shared ledger refused as already covered, and LedgerResets is how many
	// times that ledger was dropped at its unit cap. Reported, never folded into a caveat: this work
	// ran. See LiveAuditState's field docs.
	Collapsed    uint64 `json:"collapsed"`
	LedgerResets uint64 `json:"ledger_resets"`
	// Query is the DSL-03 filter as the operator wrote it, empty for none.
	Query string `json:"query,omitempty"`
	// Config and Pool are the live task's own scan configuration and resource pool (chct); empty is
	// the server default configuration and the global pace.
	Config string `json:"config"`
	Pool   string `json:"pool"`
	// StalledAt is the exchange id the cursor is waiting on, omitted when it is moving.
	StalledAt *uint64 `json:"stalled_at,omitempty"`
	// RefusedSource is in-scope exchanges the source gate skipped (zk35): the sweep's own
	// count of "in scope, but not the tool you chose". Reported beside Skipped because
	// both are floors on coverage, each naming its own reason.
	RefusedSource uint64 `json:"refused_source"`
	// LiveSeenHeld is the count of distinct in-scope URLs the sweep holds for a live crawl
	// to seed from (tqug), not yet consumed. The pane offers "Crawl from live capture" on
	// it; after a crawl takes the set this returns to zero — a held count that never moved
	// would be a set nothing read.
	LiveSeenHeld int `json:"live_seen_held"`
	// PassiveFindings counts findings the live PASSIVE pass has raised (v7fo) — the posture
	// and analysis rows that read the captured exchange and send nothing. Reported beside
	// the active Findings number because "found on capture" and "found by sending probes"
	// are different claims, and folding them would make a passive-heavy sweep read as an
	// active one.
	PassiveFindings uint64 `json:"passive_findings"`
	// ResetReWalkRemaining is how many pairs the in-progress ledger-reset re-walk has left
	// to re-dispatch (m9e0). Zero = no re-walk in progress (none began, or it completed).
	// Reported beside LedgerResets because the reset count alone hides the cost: three
	// resets at width zero are three non-events, and one reset at width 18,000 is a
	// scheduled re-dispatch the pane owes the operator a number for.
	ResetReWalkRemaining int `json:"reset_re_walk_remaining"`
	// ResetReAdmitted accumulates the pairs re-admitted across all resets — the payment
	// made, so a completed re-walk's cost stays visible after "remaining" reads zero.
	ResetReAdmitted int `json:"reset_re_admitted"`
	// TrafficSource is the operator's choice in force (zk35), rendered as the word the
	// pane shows: "proxy" or "everything". Always present — an unset choice is a real
	// answer (the default), not an absence.
	TrafficSource string `json:"traffic_source"`
	// Retried is exchanges the sweep audited on their second chance (iyqg): skipped when their
	// response was late, taken back when it landed. Reported beside Skipped because "gave up
	// on 3" and "gave up on 3, took 1 back" are different coverage claims.
	Retried uint64 `json:"retried"`
	// Deduplicated is re-seen exchanges counted as REQUEST_TO_AUDIT_DEDUPLICATED (apfh):
	// content a sweep already audited, refused as work and recorded as a row. Reported
	// beside Collapsed — the two are the same saving at different scopes (Collapsed is
	// per-run (unit, check) pairs; Deduplicated is whole requests across runs).
	Deduplicated uint64 `json:"deduplicated"`
	// SeenLedgerResets is how many times the cross-run seen ledger was dropped at its cap —
	// the same honest trade the dispatch ledger's resets make: bounded memory, one visible
	// re-audit of already-covered content.
	SeenLedgerResets uint64 `json:"seen_ledger_resets"`
}

// liveAuditUnwired reports a 200 with wired:false rather than a 404, matching the other
// feature surfaces so an unwired process does not look like a typo in the route.
func liveAuditUnwired() liveAuditView {
	return liveAuditView{
		Wired:   false,
		Enabled: false,
		Hint:    "live active audit needs a loaded check set; start with --bchecks",
	}
}

func (s *Server) liveAuditStatus() liveAuditView {
	if s.liveAudit == nil {
		return liveAuditUnwired()
	}
	_, querySrc := s.liveAudit.Query()
	v := liveAuditView{
		Wired:    true,
		Enabled:  s.liveAudit.IsEnabled(),
		Swept:    s.liveAudit.Swept(),
		Findings: s.liveAudit.FindingCount(),
		Skipped:  s.liveAudit.Skipped(),
		Behind:   s.liveAudit.Behind(),
		// Milliseconds on the wire because that is the pane's unit: the age is a duration an operator
		// reads, and a nanosecond field would be a precision nobody asked for in a JSON payload.
		BehindForMs:  s.liveAudit.BehindFor().Milliseconds(),
		BatchLimit:   s.liveAudit.BatchLimit(),
		Collapsed:    s.liveAudit.Collapsed(),
		LedgerResets: s.liveAudit.LedgerResets(),
		Query:        querySrc,
	}
	v.Config, v.Pool = s.liveAudit.RunSettings()
	if id, waiting := s.liveAudit.StalledAt(); waiting {
		v.StalledAt = &id
	}
	v.Retried = s.liveAudit.Retried()
	v.Deduplicated = s.liveAudit.Deduplicated()
	v.SeenLedgerResets = s.liveAudit.SeenLedgerResets()
	v.RefusedSource = s.liveAudit.RefusedSource()
	v.TrafficSource = string(s.liveAudit.TrafficSource())
	v.LiveSeenHeld = s.liveAudit.LiveSeenCount()
	v.PassiveFindings = s.liveAudit.PassiveFindings()
	v.ResetReWalkRemaining, v.ResetReAdmitted = s.liveAudit.ResetReWalk()
	return v
}

// exchangeSeedURL renders one exchange as a live-crawl seed origin: scheme, authority, path.
// Port spelled only when non-default, so the set's entries look like what an operator would
// have typed.
func exchangeSeedURL(ex *core.Exchange) string {
	if ex == nil {
		return ""
	}
	scheme := "http"
	if ex.TLS {
		scheme = "https"
	}
	switch {
	case ex.TLS && ex.Port == 443:
		return fmt.Sprintf("%s://%s%s", scheme, ex.Host, pathOf(ex.Path))
	case !ex.TLS && (ex.Port == 80 || ex.Port == 0):
		return fmt.Sprintf("%s://%s%s", scheme, ex.Host, pathOf(ex.Path))
	default:
		return fmt.Sprintf("%s://%s:%d%s", scheme, ex.Host, ex.Port, pathOf(ex.Path))
	}
}

// pathOf strips the query from a request target; a target with no path reads "/".
func pathOf(target string) string {
	p := target
	if i := strings.IndexByte(p, '?'); i >= 0 {
		p = p[:i]
	}
	if p == "" || p[0] != '/' {
		if len(p) > 0 && p[0] != '/' {
			return "/" + p
		}
		return "/"
	}
	return p
}

// auditedExchangeQuery adapts a stored, completed exchange to query.Queryable for the live-audit gate
// (DSL-03).
//
// Distinct from filteredExchangeQuery, which serves the history filter and deliberately reports Mime
// as absent and Body as the *request* body. Live audit runs after the response is stored, so all five
// fields have real answers, and reporting two of them absent here would make `mime = "text/html"`
// false for every exchange and `not mime = "text/html"` true for every one — the silent-wrong-answer
// this package's Fields() machinery exists to prevent, arrived at from the other direction.
//
// Mime and Body read the response through the store on demand, and cache it: the sweep evaluates one
// query per exchange and a query naming both fields would otherwise resolve the message twice. A query
// naming neither never resolves it at all, which is why this is lazy rather than eager — the common
// case is a host or status filter that touches no bytes.
type auditedExchangeQuery struct {
	store *core.TrafficStore
	ex    *core.Exchange
	// resolved is the memo flag; resp is nil either because there is no response or because reading it
	// failed. Both mean the same thing to a comparison: absent, never a wrong value.
	resolved bool
	resp     *core.StoredMessage
}

// TaskID answers from the audited exchange's own attribution: an audit row is a real captured
// row and knows which run produced it — (id, true), with 0 meaning what it always meant.
func (q *auditedExchangeQuery) TaskID() (uint64, bool) { return q.ex.TaskID, true }

func (q *auditedExchangeQuery) Host() string   { return q.ex.Host }
func (q *auditedExchangeQuery) Method() string { return q.ex.Method }
func (q *auditedExchangeQuery) Path() string   { return q.ex.Path }
func (q *auditedExchangeQuery) Status() int {
	if q.ex.Status == nil {
		return 0
	}
	return int(*q.ex.Status)
}

func (q *auditedExchangeQuery) response() *core.StoredMessage {
	if q.resolved {
		return q.resp
	}
	q.resolved = true
	if q.ex.Response == nil {
		return nil
	}
	if msg, err := q.store.Get(*q.ex.Response); err == nil {
		q.resp = msg
	}
	return q.resp
}

// Mime is the response Content-Type with any parameters stripped, so `mime = "text/html"` matches
// `text/html; charset=utf-8` — the form servers actually send.
//
// The stored value first, because since core.Exchange carries Mime this is the same answer without
// resolving the response at all. The fallback is not dead code: a row restored from a database
// written before the mime column existed has an empty Mime and real response bytes, and reading the
// header is strictly better than reporting "absent" for a response whose type is right there. Both
// paths go through core.MimeFromContentType so the two cannot reduce the value differently — the
// local strip-and-trim that used to live here also did not fold case, which made this row's `mime`
// comparison disagree with the History column beside it on a server sending `text/HTML`.
func (q *auditedExchangeQuery) Mime() string {
	if q.ex.Mime != "" {
		return q.ex.Mime
	}
	msg := q.response()
	if msg == nil {
		return ""
	}
	return core.MimeFromContentType(string(msg.Header("Content-Type")))
}

func (q *auditedExchangeQuery) Body() []byte {
	msg := q.response()
	if msg == nil {
		return nil
	}
	return msg.Body()
}

// Annotation answers from the index row. See filteredExchangeQuery.Annotation for why known is true.
func (q *auditedExchangeQuery) Annotation() (string, string, bool) {
	comment := ""
	if q.ex.Notes != nil {
		comment = *q.ex.Notes
	}
	return q.ex.Highlight, comment, true
}

// Header reads the response head through the same memoised resolution Mime and Body use, so a query
// naming a header and a body resolves the message once rather than twice.
func (q *auditedExchangeQuery) Header(name string) ([]string, bool) {
	msg := q.response()
	if msg == nil {
		return nil, false
	}
	raw, present := msg.HeaderValues(name)
	if !present {
		return nil, false
	}
	out := make([]string, 0, len(raw))
	for _, value := range raw {
		out = append(out, string(value))
	}
	return out, true
}

// ResponseLen and DurationUs both read the index row rather than the message, so neither forces the
// lazy response resolution above. Same absence rules as filteredExchangeQuery: presence comes from
// Response and from Measured, never from the value being non-zero.
func (q *auditedExchangeQuery) ResponseLen() (int64, bool) {
	if q.ex.Response == nil {
		return 0, false
	}
	return int64(q.ex.ResponseLen), true
}

func (q *auditedExchangeQuery) DurationUs() (int64, bool) {
	if !q.ex.Duration.Measured {
		return 0, false
	}
	return int64(q.ex.Duration.Us), true
}

// liveAuditAdmits is the sweep's whole admission decision for one exchange: the engagement scope, then
// the operator's query.
//
// Scope first and always. The query narrows what the operator wants audited; it can never widen it
// past the engagement, so an exchange out of scope is refused before the query is even parsed against
// it.
func (s *Server) liveAuditAdmits(ex *core.Exchange) bool {
	if !s.scope.Contains(ex.Host, ex.Port, ex.Path, ex.TLS) {
		return false
	}
	// The per-source gate (zk35), after scope and before the query: the same order Burp's
	// own scope dialog reads (source choice, then in-scope test, then the rest). "Proxy"
	// admits only SourceProxy captures — the sweep must not audit the crawler's or its own
	// probe traffic unless the operator chose Everything. Refused HERE is a counted
	// refusal, not a silent gap: the cursor advances either way (the position is the
	// store), and the pane reports the gate's own count.
	if s.liveAudit.TrafficSource() == LiveAuditSourceProxy && ex.Source != core.SourceProxy {
		s.liveAudit.refusedSource.Add(1)
		return false
	}
	// An exchange with no response is refused before the query is consulted, and this is not merely
	// defensive. It is what makes the full grammar safe here.
	//
	// The premise of accepting `mime` and `body` at all is that live audit runs after the response is
	// stored, so those fields have real values. For an exchange with no response they do not, and the
	// query package's absent-field rule then bites in the direction internal/query/fields.go warns
	// about: `mime = "text/html"` is correctly false, and `not mime = "text/html"` is *true* — so a
	// negated filter would admit exactly the exchanges that cannot be audited at all.
	//
	// The sweep's walk already stops at such an exchange, so today nothing reaches here with one. That
	// makes this an invariant held by one caller, which is the kind that stops being true when a second
	// caller appears. Held locally instead.
	if ex.Response == nil {
		return false
	}
	expr, _ := s.liveAudit.Query()
	if expr == nil {
		return true
	}
	return expr.Match(&auditedExchangeQuery{store: s.store, ex: ex})
}

// liveAuditSweepInterval is how often the loop looks for newly-completed exchanges.
//
// Three seconds is a compromise the operator feels in both directions: long enough that an idle
// process is not walking the store continuously, short enough that a click on the toggle produces
// visible findings while the operator is still looking at the tab.
const liveAuditSweepInterval = 3 * time.Second

// liveAuditBatchSize is the sweep's BASELINE admission: how many exchanges one tick takes when there is
// no backlog to work off.
//
// Named because it is the floor of the sweep's throughput — 200 every liveAuditSweepInterval is about
// 66 exchanges a second, which a crawler outpaces without trying. Reporting that number beside the
// backlog (Behind) says how far behind the sweep is; it does not reduce it, and a pane whose job is to
// demonstrate DASH-03 was the one showing a gap that only ever widened (burpsy-react-ui-iosv). The
// tick's admission therefore scales with the backlog it faces, up to the cap below.
const liveAuditBatchSize = 200

// liveAuditCatchUpBatchMax bounds how much one catch-up tick may admit.
//
// A backlog is worked off in bursts, but not in one unbounded burst: the batch becomes an audit run, and
// a run is the unit the engine bounds (its own time budget and request cap), so admitting a hundred
// thousand exchanges in a single tick would hand the scanner a run it can only abandon part-way — the
// queue would look clear and the work would not have happened. Ten thousand is the ceiling that keeps a
// catch-up honest under the engine's existing bounds: at the shipped interval it is a burst, not a
// second sweep, and everything above it is still visible as Behind.
const liveAuditCatchUpBatchMax = 10000

// liveAuditTickBatch is the admission bound for a tick facing `behind` unreached exchanges.
//
// The shape is deliberately piecewise-linear rather than a formula: below the baseline the baseline
// applies (a sweep with nothing behind it must not admit one exchange per tick because the arithmetic
// says so), between the baseline and the cap the backlog itself is admitted (one tick clears a backlog
// one burst can hold — this is the case the bead exists for), and past the cap the cap applies. A
// function rather than an inline expression because the three regimes are the contract, and they are
// pinned by TestLiveAuditTickBatchScalesWithTheBacklogAndStopsAtTheCap.
func liveAuditTickBatch(behind uint64) int {
	if behind < liveAuditBatchSize {
		return liveAuditBatchSize
	}
	if behind > liveAuditCatchUpBatchMax {
		return liveAuditCatchUpBatchMax
	}
	return int(behind)
}

// auditOutcomeSeverity grades a finished bulk audit for the event log. A run the breaker paused or the
// budget bounded is a warning: for the live sweep the next tick starts again against a target that has
// already stopped answering, and for a crawl-and-audit's audit phase the run is over having looked at
// less than it was given. Either way an operator scanning the log must be able to see that without
// reading every line's counts.
//
// Named for what it grades rather than for its first caller (it was liveAuditSeverity), because the
// crawl-and-audit phase asks the same question of the same type — and a second caller reaching for a
// function named after the first one is how two severity rules start to drift.
func auditOutcomeSeverity(outcome *scanner.SessionOutcome) dash.Severity {
	if outcome == nil {
		return dash.SeverityInfo
	}
	if outcome.Paused || outcome.TimedOut || outcome.FailedItems > 0 {
		return dash.SeverityWarn
	}
	return dash.SeverityInfo
}

// liveAuditTarget names the batch for the task list. The first exchange's host stands for the sweep
// because a batch is walked in id order from one high-water mark, so it is overwhelmingly one host's
// traffic; the count is appended so a batch spanning several is not misread as one.
func liveAuditTarget(store *core.TrafficStore, ids []core.ExchangeID) string {
	if len(ids) == 0 {
		return "no exchanges"
	}
	// Every distinct host in the batch, in first-seen order, capped for the label's length:
	// a multi-host sweep is not the first host's run, and a label that says otherwise is a
	// claim the numbers do not back (6urp).
	seen := map[string]bool{}
	var hosts []string
	for _, id := range ids {
		ex, err := store.GetExchange(id)
		if err != nil {
			continue
		}
		if !seen[ex.Host] {
			seen[ex.Host] = true
			hosts = append(hosts, ex.Host)
			if len(hosts) >= 3 {
				break
			}
		}
	}
	if len(hosts) == 0 {
		return fmt.Sprintf("%d exchange(s)", len(ids))
	}
	label := strings.Join(hosts, ", ")
	if seenCount := len(seen); seenCount > len(hosts) {
		label = fmt.Sprintf("%s + %d more host(s)", label, seenCount-len(hosts))
	}
	return fmt.Sprintf("%s (%d exchange(s))", label, len(ids))
}

// StartLiveAuditSweep launches the background sweep loop. It walks newly-completed
// in-scope exchanges in id order and hands batches to the active scanner while enabled.
// The caller owns the context; when it is cancelled the loop stops at the next tick.
func (s *Server) StartLiveAuditSweep(ctx context.Context) {
	s.startLiveAuditSweep(ctx, liveAuditSweepInterval)
}

// startLiveAuditSweep is StartLiveAuditSweep with the interval exposed, so a test can pin the
// opt-in (CRAWL-06) against a real target inside a test's patience rather than waiting whole
// multiples of the shipped interval to observe that nothing was sent.
// LoadLiveSeenLedger restores the cross-run seen ledger from disk (apfh). The sweep's
// own state is created lazily, so this materialises it first — a restore that needed the
// sweep to have started would load after the first tick had already re-audited content.
func (s *Server) LoadLiveSeenLedger(blob []byte) {
	if s.liveAudit == nil {
		s.liveAudit = NewLiveAuditState()
	}
	s.liveAudit.LoadSeen(blob)
}

func (s *Server) startLiveAuditSweep(ctx context.Context, every time.Duration) {
	if s.liveAudit == nil {
		s.liveAudit = NewLiveAuditState()
	}
	go s.liveAuditLoop(ctx, every)
}

func (s *Server) liveAuditLoop(ctx context.Context, every time.Duration) {
	run := liveAuditRun{}
	// The operator's RetryStalled needs the live cursor; hand it over the moment it exists.
	s.liveAudit.attachRun(&run.cursor)
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// The switch is read here, before anything else happens — before the store is walked,
			// before a batch is built, and long before the scanner is reached. CRAWL-06 is that
			// nothing is audited until the operator opts in, and the cheapest way to be sure of that
			// is for the disabled path to do nothing at all.
			if !s.liveAudit.IsEnabled() {
				continue
			}
			s.liveAuditTick(ctx, &run)
		}
	}
}

// liveAuditRun is everything one sweep loop carries between ticks.
//
// The ledger is here, rather than being rebuilt inside each AuditSession call, because the sweep is the
// one audit caller that repeats forever. See AuditConfig.Ledger: a per-run ledger makes every
// host-scoped and path-scoped check re-dispatch every liveAuditSweepInterval for the life of the
// process, which is invisible against trickling proxy traffic and a request storm against a crawl.
//
// Everything else about a run stays per-tick. The time budget, the request budget and both failure
// breakers are properties of one batch, and carrying those across ticks would let one slow minute
// bound the sweep permanently — the same wedge the cursor's stall counter exists to prevent, arrived
// at through the budget instead.
type liveAuditRun struct {
	cursor liveAuditCursor
	ledger *scanner.AuditLedger
}

// liveAuditLedgerUnitCap bounds the shared ledger by dispatch units — hosts and paths.
//
// Twenty thousand units is a few megabytes of keys and bitsets, and comfortably more paths than any
// single engagement's in-scope surface. Past it the ledger is dropped and rebuilt rather than grown
// without limit, because a ledger that grows with the site is the one piece of audit state that does,
// and an unbounded one turns a long crawl into a memory leak.
//
// A reset is not free and is not silent: the checks it had collapsed will each re-dispatch once more,
// so the reset is counted, reported in the view, and recorded as an event. That is the honest trade —
// a bounded, visible re-dispatch instead of either unbounded memory or a silent cap.
const liveAuditLedgerUnitCap = 20_000

// auditLedger returns the ledger for this tick, rebuilding it when it has outgrown its unit cap.
func (r *liveAuditRun) auditLedger(state *LiveAuditState, events *dash.EventLog, logger *zap.Logger) *scanner.AuditLedger {
	if r.ledger == nil {
		r.ledger = scanner.NewAuditLedger()
		return r.ledger
	}
	if units := r.ledger.Units(); units > liveAuditLedgerUnitCap {
		// The reset's cost, stated (m9e0): the dead ledger's admitted-pair count is the
		// width of the re-walk the fresh ledger will perform — every one of those pairs
		// dispatches once more. Recorded BEFORE the drop, reported beside the reset
		// count, and the re-admission is measured against it so the pane shows the cost
		// and the payment, not a single "resets" figure hiding both.
		width := r.ledger.Admitted()
		r.ledger = scanner.NewAuditLedger()
		state.recordLedgerReset()
		state.beginResetReWalk(width)
		events.Record(dash.EventLedgerReset, dash.SeverityWarn, fmt.Sprintf(
			"the live sweep's admission ledger passed its cap of %d dispatch units (%d) and was reset; already-covered checks will dispatch once more",
			liveAuditLedgerUnitCap, units))
		if logger != nil {
			logger.Warn("live audit admission ledger reset at its unit cap",
				zap.Int("units", units),
				zap.Int("cap", liveAuditLedgerUnitCap))
		}
	}
	return r.ledger
}

// liveAuditCursor is the sweep's position, plus how long it has been stuck there.
//
// The stall count is the whole point. The sweep must wait at an exchange whose response has not
// landed, because ids are handed out when a request is captured and a later id can complete first —
// auditing past a gap would skip the request still in flight. But "wait" and "wait forever" are
// different behaviours, and before this counter existed only the first was implemented: one
// exchange that never got a response ended live-audit coverage for the life of the process, while
// Swept() went on reporting the number it had reached. A silent permanent coverage loss is the
// exact failure this codebase's style exists to prevent, so the wait is now bounded and what it
// gave up on is counted.
type liveAuditCursor struct {
	at core.ExchangeID
	// stalls counts consecutive ticks that made no progress from `at`.
	stalls int
}

// liveAuditStallTicks is how many consecutive no-progress ticks the sweep tolerates before it
// advances past the exchange it is waiting on.
//
// Ten ticks at the shipped three-second interval is thirty seconds — comfortably longer than any
// response the proxy is still streaming, and short enough that an operator watching the pane sees
// the number move again rather than concluding the feature is broken. The exchange it gives up on
// is counted as skipped, never as swept.
const liveAuditStallTicks = 10

// liveAuditTick collects one bounded batch of newly-completed in-scope exchanges and hands
// them to the scanner, recording the outcome. Sequential and bounded rather than
// exhaustive: an exchange whose response has not landed waits for a later tick, and
// everything after it waits with it.
func (s *Server) liveAuditTick(ctx context.Context, run *liveAuditRun) {
	cursor := &run.cursor
	_, total := s.store.Count()
	// The admission bound for THIS tick, from the backlog it faces right now (burpsy-react-ui-iosv): a
	// sweep facing a backlog admits it in one burst up to the catch-up cap, and one with nothing behind
	// it admits the baseline. Computed from the store's count and the cursor rather than from Behind(),
	// which is only updated by a tick that has already run — so on the FIRST tick Behind() is still zero
	// and a bound read from it would make every sweep start at the baseline no matter how far behind the
	// capture already was. Recorded so the pane can say which bound produced the count it is showing.
	behind := uint64(0)
	if uint64(cursor.at) < uint64(total) {
		behind = uint64(total) - uint64(cursor.at)
	}
	batch := liveAuditTickBatch(behind)
	s.liveAudit.recordBatchLimit(batch)
	ids := make([]core.ExchangeID, 0, batch)
	// The skip's second chance (iyqg): if a response landed after the sweep gave up on its
	// exchange, the id goes into this tick's batch ahead of the walk. Admitted by the same
	// in-scope gate as everything else — a retry that bypassed scope would re-open an
	// exemption the operator set deliberately. Counted as retried, never folded into swept:
	// the pane reports "gave up on N, took back M", and folding M into swept would read as if
	// the skip never happened.
	var retriedThisTick int
	if id, landed := s.liveAudit.takePendingRetry(s.store); landed {
		if ex, err := s.store.GetExchange(id); err == nil && s.liveAuditAdmits(ex) {
			ids = append(ids, id)
			retriedThisTick++
		}
	}
	// The seen ledger's bound (apfh): checked once per tick, before new admissions. A reset
	// re-audits already-covered content once more — visibly, counted, evented.
	if s.liveAudit.maybeResetSeen() {
		s.events.Record(dash.EventLedgerReset, dash.SeverityWarn, fmt.Sprintf(
			"the live sweep's cross-run seen ledger passed its cap and was reset; re-seen request content will audit once more"))
	}

	next := cursor.at
	// waitingOn is the id the walk stopped at because its response had not landed. Distinct from
	// "ran out of exchanges": only the former is something the cursor can get permanently stuck on.
	var waitingOn core.ExchangeID
	waiting := false
	for uint64(next) < uint64(total) && len(ids) < batch {
		ex, err := s.store.GetExchange(next)
		if err != nil {
			break
		}
		if ex.Response == nil {
			waitingOn, waiting = next, true
			break
		}
		if s.liveAuditAdmits(ex) {
			// The live passive crawl's seed set (tqug): the URL this admitted exchange
			// actually fetched joins the live-seen set — wire-observed, not body-parsed. The
			// scope gate has already passed (liveAuditAdmits), so every URL here is one the
			// engagement authorised; the crawler's own New re-checks scope when a crawl
			// consumes the set, so an operator tightening scope between capture and crawl
			// cannot be handed a stale origin.
			s.liveAudit.NoteLiveURL(exchangeSeedURL(ex))
			// The cross-run dedup (apfh): content this sweep lineage has already audited is
			// counted as REQUEST_TO_AUDIT_DEDUPLICATED — a disposition row, not work. The
			// fingerprint is 6n4d's, so changed content admits (that ledger's job) and only
			// identical re-seen content dedups here. The id advances either way: the cursor's
			// position is the store, and a dedup row is still a row the sweep has accounted for.
			if !s.liveAudit.admitSeen(ex) {
				s.liveAudit.deduplicated.Add(1)
			} else {
				ids = append(ids, next)
			}
		}
		next++
	}
	// Recorded before any early return, so the backlog is current even on a tick that does no work —
	// a sweep parked behind a stalled exchange while a crawl races ahead is exactly when an operator
	// needs to see how far behind it is.
	s.liveAudit.recordPosition(uint64(next), uint64(total))

	// A retry consumed at the top of this tick counts as work regardless of walk progress: a
	// tick whose only batch is one taken-back exchange is a tick with work, and sending it to
	// the stall accounting (or returning with it uncounted) would lose the second chance the
	// skip was owed (iyqg).
	if next == cursor.at && len(ids) == 0 {
		// No progress. If we are parked on a response that never landed, give it a bounded number of
		// ticks and then step over it, counting it as skipped — an exchange nobody audited is not an
		// exchange that came back clean. Without this the sweep waits here forever.
		if waiting {
			cursor.stalls++
			s.liveAudit.noteStall(uint64(waitingOn), true)
			if cursor.stalls >= liveAuditStallTicks {
				s.logger.Warn("live audit advancing past an exchange whose response never landed",
					zap.Uint64("exchange", uint64(waitingOn)),
					zap.Int("ticks_waited", cursor.stalls))
				s.events.Record(dash.EventLiveAuditSkipped, dash.SeverityWarn, fmt.Sprintf(
					"exchange %d never recorded a response after %d sweeps; the live audit advanced past it unaudited",
					waitingOn, cursor.stalls))
				cursor.at = waitingOn + 1
				cursor.stalls = 0
				s.liveAudit.recordSkipped(1, waitingOn)
				s.liveAudit.noteStall(0, false)
			} else if cursor.stalls == 1 {
				// Once, on the tick the wait begins, rather than every tick it continues: a stall that
				// resolves normally is unremarkable and should not fill the log.
				s.events.Record(dash.EventLiveAuditStalled, dash.SeverityInfo, fmt.Sprintf(
					"the live audit is waiting for exchange %d's response before it can go further", waitingOn))
			}
		}
		return
	}

	cursor.at = next
	cursor.stalls = 0
	s.liveAudit.noteStall(uint64(waitingOn), waiting)
	// Persist the seen ledger in small batches (apfh): a restart restores it, so
	// REQUEST_TO_AUDIT_DEDUPLICATED survives restarts. Sixteen keys to a save bounds disk
	// writes while keeping the restore window narrow; zero keys means the tick admitted
	// nothing new and touches nothing.
	if s.persist != nil && s.liveAudit.seenAddedSinceSave.Load() >= 16 {
		if err := s.persist.SaveLiveSeenLedger(s.liveAudit.PersistSeen()); err != nil {
			if s.logger != nil {
				s.logger.Warn("could not persist the live sweep's seen ledger", zap.Error(err))
			}
			// The counter still clears: an unwritable save must not retry the same batch on
			// every tick forever, and the in-memory ledger keeps working regardless.
		}
		s.liveAudit.seenAddedSinceSave.Store(0)
	}
	if len(ids) == 0 {
		return
	}

	if retriedThisTick > 0 {
		s.liveAudit.retried.Add(uint64(retriedThisTick))
		s.events.Record(dash.EventLiveAuditSkipped, dash.SeverityInfo, fmt.Sprintf(
			"exchange the sweep had given up on got its response; auditing it now (retry)"))
	}
	if s.scanner == nil {
		s.logger.Warn("live audit enabled but no active scanner wired")
		return
	}
	// Registered per sweep-with-work rather than per tick: a tick that found nothing new returned
	// above, and a registry filling with empty three-second ticks would bury the runs that matter.
	// The target names EVERY host in the batch (6urp): a first-host-only label described a
	// multi-host sweep as one host's run, which was a claim the numbers did not back.
	task := s.tasks.Start(dash.KindLiveAudit, liveAuditTarget(s.store, ids), uint64(len(ids)))
	start := time.Now()
	// AuditSession rather than AuditMultiple: this is the highest-volume audit path in the process, so
	// it is where the engine's bounding pays for itself — a sweep over 200 captures of one host
	// dispatches each per-URL check once and refuses the rest as already covered. The session outcome
	// is the only place that saving is visible, and a sweep that reported "200 exchanges, 3 findings"
	// while quietly admitting a fraction of the work would be the exact claim the engine exists to
	// prevent.
	// The live passive audit (burpsy-react-ui-v7fo): Burp's Zcvb — passive checks run on
	// live traffic as it lands, not only inside an audit session. The passive rows read the
	// captured exchange and send nothing, so they run over every admitted id BEFORE the
	// active half: a posture finding (a cleartext password form, a missing HSTS) surfaces
	// the moment the traffic is captured. Counted separately (passiveFindings); the
	// active session's own passive rows then merge into the same stored findings by
	// identity — confirmed, not duplicated.
	//
	// The configuration is read ONCE, here, and both halves run under it (burpsy-react-ui-saq3.3.2).
	// It used to be read after the passive loop and handed to the active half only, so a deselected
	// passive issue type — or scan_type_passive false — stopped in the session and kept firing on
	// every captured exchange one loop earlier.
	cfg := s.scanner.AuditConfig()
	// The live task's own scan configuration and pool (chct), resolved per tick so a change applies
	// from the next batch, and resolved here — before the passive half — so both halves run under the
	// task's configuration, not only the active one. A name that stopped resolving (a pool deleted
	// since) falls back to the default with an event, rather than stopping the sweep.
	if cfgName, poolName := s.liveAudit.RunSettings(); cfgName != "" || poolName != "" {
		if cfgName != "" {
			if named, _, _, err := s.resolveAuditConfig(cfgName); err == nil {
				cfg = named
			} else {
				s.events.Record(dash.EventLiveAuditScoped, dash.SeverityWarn, "the live audit's scan configuration no longer resolves; this batch runs the default: "+err.Error())
			}
		}
		if poolName != "" {
			if pctx, err := s.auditContext(ctx, poolName); err == nil {
				ctx = pctx
			} else {
				s.events.Record(dash.EventLiveAuditScoped, dash.SeverityWarn, "the live audit's resource pool no longer resolves; this batch runs at the global pace: "+err.Error())
			}
		}
	}
	passiveFindings := 0
	if s.scanner != nil {
		for _, id := range ids {
			ex, err := s.store.GetExchange(id)
			if err != nil || ex == nil {
				continue
			}
			for _, f := range s.scanner.RunPassiveChecks(ctx, ex, cfg) {
				if f == nil {
					continue
				}
				// core.NewFinding is the one door the store's merge knows: a finding added
				// here is the same finding a later audit session's passive row would raise,
				// so the store's dedup by identity is what keeps the count single.
				s.findings.Add(core.NewFinding{
					Name:        f.Name,
					Severity:    core.ParseSeverity(f.Severity),
					Confidence:  core.ParseConfidence(f.Confidence),
					Description: f.Description,
					Remediation: f.Solution,
					Param:       f.Param,
					Target: core.FindingTarget{
						Host: ex.Host, Port: ex.Port, TLS: ex.TLS, Path: ex.Path,
					},
					TaskID: ex.TaskID,
					// One occurrence citing the captured exchange: the merge key the
					// audit session's own passive row will agree with, which is what
					// keeps this finding single in the store.
					Occurrences: []core.Occurrence{{
						ExchangeID: ex.ID, Request: ex.Request, Response: ex.Response,
					}},
				})
				passiveFindings++
			}
		}
	}
	s.liveAudit.recordPassive(uint64(passiveFindings))

	// The ledger is the one part of the config that outlives this tick — see liveAuditRun.
	cfg.Ledger = run.auditLedger(s.liveAudit, s.events, s.logger)
	// The sweep is the highest-volume producer of audit items, so it is the one that makes the queue
	// worth having: this is where "swept 400" becomes 400 rows an operator can ask which of them the
	// budget bounded. The queue's own cap (scanner.DefaultAuditItemCap) is what keeps a sweep that
	// runs for hours from growing it without limit, and the endpoint reports the evictions.
	cfg.Items = s.auditItems
	// The reset re-walk's measurement point (m9e0): the ledger's admitted count before the
	// session; after it, the delta while a re-walk is in progress is pairs the fresh ledger
	// re-admitted — the payment, tick by tick, against the width the reset stated.
	ledgerAdmittedBefore := run.ledger.Admitted()
	// Per-host pacing (6urp): the tick's ids group by authority and each group runs as its
	// OWN AuditSession, concurrently under a bound — so one slow host paces only itself.
	outcome, findings := s.auditGroupedByHost(ctx, ids, cfg)
	s.liveAudit.recordCollapsed(uint64(outcome.AlreadyCovered()))
	if reAdmitted := run.ledger.Admitted() - ledgerAdmittedBefore; reAdmitted > 0 {
		for range reAdmitted {
			if done := s.liveAudit.recordReAdmission(); done {
				s.events.Record(dash.EventLedgerReset, dash.SeverityInfo, fmt.Sprintf(
					"the live sweep finished re-dispatching the checks the ledger reset had collapsed; steady-state admission resumed"))
				break
			}
		}
	}
	task.Advance(uint64(len(ids)))
	// The engine's own outcome, projected onto the dashboard's four buckets: a sweep the failure
	// breaker paused or the budget bounded finishes here with a non-complete result, so the
	// dashboard shows it as a run that stopped looking rather than as a clean one.
	task.FinishWithNote(outcome.Breakdown(), outcome.Summary())
	for _, f := range findings {
		s.findings.Add(s.activeFinding(f, task.ID()))
	}
	s.liveAudit.Record(uint64(len(ids)), uint64(len(findings)))
	// This used to be a toollog row: Record(ToolScanner, host, port, tls, "LIVE", "/audit", 0, ...) —
	// a *request* row for something that is not a request, with an invented method and an invented
	// path, so that a sweep completing could travel down a pipe shaped for sent requests. The probes
	// the sweep actually sends belong in toollog and are logged by the sender that sends them; the
	// sweep finishing is an event. See internal/dash/events.go on why the two logs are separate.
	//
	// Recorded per sweep-with-work, matching the task registration above, so the event log and the task
	// table describe the same set of runs.
	s.events.RecordFor(task.ID(), dash.EventLiveAuditBounded, auditOutcomeSeverity(outcome), fmt.Sprintf(
		"live sweep of %s: %s", liveAuditTarget(s.store, ids), outcome.Summary()))
	s.logger.Debug("live audit sweep",
		zap.Int("exchanges", len(ids)),
		zap.Int("findings", len(findings)),
		zap.String("engine", outcome.Summary()),
		zap.Duration("took", time.Since(start)))
	// A sweep the failure breaker stopped is not a sweep that found nothing, and it is worth more than
	// a debug line: the next tick will start again against a target that has already stopped answering.
	if outcome.Paused || outcome.TimedOut {
		s.logger.Warn("live audit sweep was bounded before it finished",
			zap.Int("exchanges", len(ids)),
			zap.Int("checks_not_admitted", outcome.NotAdmitted()),
			zap.Bool("paused", outcome.Paused),
			zap.Bool("timed_out", outcome.TimedOut))
	}
}

// liveAuditHostSessions bounds how many per-host sessions one tick runs at once (6urp).
// Four, not the engine's MaxConcurrency: each session already runs its own workers under
// that figure, so the true in-flight ceiling is this bound × the engine's, and an operator
// pacing per host wants the host count small. Named because it is half of the tick's
// real concurrency ceiling and nothing reported it.
const liveAuditHostSessions = 4

// auditGroupedByHost runs the tick's ids as one AuditSession PER HOST, concurrently under
// liveAuditHostSessions (6urp). Burp's live-audit queue is per-host (Zeuc :255,
// parallel_crawl_and_audit :8768-8769): pacing is a per-queue property, and a global
// sequential batch lets one slow host wedge every host behind it.
//
// The returned outcome is the FOLD of every host session — the same SessionOutcome shape
// the single call produced, aggregated so the task row, the event and the pane keep one
// set of numbers per tick (items summed, the worst state kept, Paused/TimedOut ORed)
// rather than per-host rows the operator would have to add. A single-host batch makes
// exactly one call and returns its outcome verbatim — no folding artefacts in the common
// case.
func (s *Server) auditGroupedByHost(ctx context.Context, ids []core.ExchangeID, cfg scanner.AuditConfig) (*scanner.SessionOutcome, []*scanner.Finding) {
	// Group in first-seen order so the fold's item order matches the batch's walk order.
	// The key is the AUTHORITY (host:port_tls), not the hostname: two local test origins on
	// different ports are two targets, and one hostname behind a port-based vhost array is
	// exactly the case where per-host pacing must not collapse them.
	byHost := make(map[string][]core.ExchangeID)
	var order []string
	authorityOf := func(ex *core.Exchange) string {
		auth := fmt.Sprintf("%s:%d", ex.Host, ex.Port)
		if ex.TLS {
			return auth + "/tls"
		}
		return auth
	}
	for _, id := range ids {
		ex, err := s.store.GetExchange(id)
		if err != nil {
			continue
		}
		auth := authorityOf(ex)
		if _, ok := byHost[auth]; !ok {
			order = append(order, auth)
		}
		byHost[auth] = append(byHost[auth], id)
	}
	if len(order) <= 1 {
		// The single-host batch: the old one call, verbatim — no fold, no new concurrency.
		s.liveAudit.recordHostSessions(1)
		return oneSession(s, ctx, ids, cfg)
	}
	s.liveAudit.recordHostSessions(uint64(len(order)))
	type result struct {
		outcome  *scanner.SessionOutcome
		findings []*scanner.Finding
	}
	results := make([]result, len(order))
	sem := make(chan struct{}, liveAuditHostSessions)
	var wg sync.WaitGroup
	for i, host := range order {
		wg.Add(1)
		go func(i int, host string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			o, f := oneSession(s, ctx, byHost[host], cfg)
			results[i] = result{o, f}
		}(i, host)
	}
	wg.Wait()

	fold := &scanner.SessionOutcome{}
	var findings []*scanner.Finding
	for _, r := range results {
		if r.outcome == nil {
			continue
		}
		fold.Items = append(fold.Items, r.outcome.Items...)
		findings = append(findings, r.findings...)
		fold.DispatchUnits += r.outcome.DispatchUnits
		fold.RequestsSent += r.outcome.RequestsSent
		fold.FailedItems += r.outcome.FailedItems
		if r.outcome.Paused {
			fold.Paused = true
		}
		if r.outcome.TimedOut {
			fold.TimedOut = true
		}
	}
	return fold, findings
}

// oneSession is the single AuditSession call the sweep has always made, isolated so the
// per-host path and the single-host path share one spelling.
func oneSession(s *Server, ctx context.Context, ids []core.ExchangeID, cfg scanner.AuditConfig) (*scanner.SessionOutcome, []*scanner.Finding) {
	return s.scanner.AuditSession(ctx, ids, cfg)
}
