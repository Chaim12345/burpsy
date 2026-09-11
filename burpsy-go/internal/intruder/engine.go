package intruder

// Running an attack: bounded concurrency, and a summary instead of a pile of bodies. Ported from
// burpsy-intruder::engine.
//
// # What an operator actually gets back
//
// A cluster bomb produces 100,000 responses. Handing back 100,000 response bodies is useless
// twice over — nobody reads them, and holding them is the exact memory failure this project
// exists to avoid. What distinguishes an interesting response from the other 99,999 is almost
// always the triple (status, length, did the payload come back), so that triple is the key, and
// the report is a bucket per distinct triple with a count.
//
// Two consequences fall out of that:
//
//   - Results hold ordinals, not payloads. AttackPlan derives request i from i, so a bucket
//     recording first_ordinal can regenerate the exact payload combination that produced it.
//   - Only one response per bucket is stored. Recording all 100k into the traffic store would
//     reintroduce the same problem one layer down, so the recorder fires for the *first* response
//     in each bucket. Resident bytes scale with distinct behaviours, not with requests sent.
//
// Reflection is the fixed case of what Burp exposes as configurable grep-match. Here it is one
// question, asked of every attack: did this payload come back?
//
// # Grep-match and grep-extract, and why they stayed out of the key
//
// Grep adds the configurable version: an operator regex tested against each response, and a
// second one whose first capture group is pulled out. They are computed per response and reported
// per attempt — but the bucket key is still (status, length, reflected), because a grep result is
// a *question the operator asked*, not a property of how the target behaved. Keying on it would
// silently double the bucket count for every attack that turned a pattern on.
//
// # Concurrency
//
// Every send passes through the RateLimiter. The driver loop takes a permit *before* it splices
// the request, so the number of spliced request copies alive at once is max_in_flight, not the
// length of the plan.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"regexp"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
)

// MAX_EXTRACT is the longest grep-extract this will report.
//
// A capture group can match a whole response body, and a report is not a place to put 200 KB of
// it once per attempt. Burp bounds the same thing (its grep-extract has a maximum capture
// length, default 100 characters); this is more generous and still bounded. A capture longer
// than this is cut — the field's doc says so, so a truncated value is never presented as a whole
// one.
const MAX_EXTRACT = 256

// Sent is what one send produced. Status comes from the sender because the sender already parsed
// it.
type Sent struct {
	Raw      []byte
	Duration time.Duration
	Status   *int
}

// SendFn sends raw request bytes and returns the response.
type SendFn func(raw []byte) (Sent, error)

// RecordFn stores a response and returns its message id. Called once per distinct result bucket.
type RecordFn func(raw []byte) uint64

// Guard decides whether a spliced request may be sent. See Attack.Guard.
type Guard func(raw []byte) error

// Grep is grep-match and grep-extract: two optional regexes, applied to every response.
type Grep struct {
	// MatchRe answers "does the response match?" as a boolean per attempt.
	MatchRe *regexp.Regexp
	// ExtractRe pulls out the first capture group of the first match, or the whole match when
	// the pattern has no groups — which is what an operator who wrote a pattern with no
	// parentheses means.
	ExtractRe *regexp.Regexp
}

// IsEmpty reports whether neither pattern was configured.
func (g *Grep) IsEmpty() bool { return g.MatchRe == nil && g.ExtractRe == nil }

// AutoPause is Burp's auto-pause (configure-attack/settings.html): pause the attack when a
// chosen expression appears in — or goes missing from — a response. It is a predicate over
// the same bytes Grep.run reads, evaluated in the same place, and its action is the Control
// the attack already carries: nothing about pausing is new, only the trigger.
//
// # Appears vs missing
//
// Appears pauses when ANY expression matches — Burp's two list modes are "pause if an
// expression in the list appears" and "pause if an expression in the list is missing", and
// the missing mode is the complement over the same list: pause when NO expression matches.
// One predicate each way over one list; two independent knobs would be two ways to describe
// the same four states, three of them contradictory.
//
// # When it fires
//
// On the FIRST qualifying response — the lockout page or the success indicator is the event,
// and the requests after it are the damage. Burp re-arms on resume so an operator can step
// past a hit; ReArm does that here, and the report records how many times it fired (an
// attack paused three times reads differently from one paused once, even with the same
// final counts).
type AutoPause struct {
	// Expressions are the patterns tested against every response. Compile them once —
	// running uncompiled strings through regexp.MustCompile per response is exactly the
	// per-send work this package refuses to do (see the process.go placement note).
	MatchRe []*regexp.Regexp
	// Missing inverts the predicate: pause when NO expression in the list matches.
	Missing bool
	// CaseSensitive disables the case-folding that simple-string matching would otherwise
	// use. For compiled regexes the flag is embedded by the caller ( (?i) or not), because
	// Go's regexp has no per-call case option — so this field is honest only for the
	// string path, and the constructor is where the distinction lives.
	CaseSensitive bool
}

// NewAutoPause compiles the expression list. simple=true treats every entry as a literal
// string (quoted with regexp.QuoteMeta), case-folded unless caseSensitive; simple=false
// treats each entry as a regex compiled as-is — case-sensitivity then belongs to the
// pattern itself, the way Go's regexp works, and the flag is ignored rather than guessed
// at. Entries that do not compile are an error: an auto-pause that never fires because one
// of its expressions failed to compile is a control that lies by omission.
func NewAutoPause(expressions []string, simple, missing, caseSensitive bool) (*AutoPause, error) {
	if len(expressions) == 0 {
		return nil, nil // configured off; nil is the "not configured" the attack checks
	}
	ap := &AutoPause{Missing: missing, CaseSensitive: caseSensitive}
	for _, expr := range expressions {
		pattern := expr
		if simple {
			pattern = regexp.QuoteMeta(expr)
			if !caseSensitive {
				pattern = "(?i)" + pattern
			}
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("auto-pause expression %q does not compile: %w", expr, err)
		}
		ap.MatchRe = append(ap.MatchRe, re)
	}
	return ap, nil
}

// triggered evaluates one response. true means the pause condition is met: any expression
// matched (appears mode) or none did (missing mode). Not configured is never triggered.
func (ap *AutoPause) triggered(raw []byte) bool {
	if ap == nil || len(ap.MatchRe) == 0 {
		return false
	}
	any := false
	for _, re := range ap.MatchRe {
		if re.Match(raw) {
			any = true
			break
		}
	}
	if ap.Missing {
		return !any
	}
	return any
}

// ReArm clears the pause trigger so the attack can run again — Burp re-arms on resume, and
// pausing on the same response forever would make resume a no-op for an attack that stopped
// on a page that stays in every further response (a lockout banner does exactly that).
func (ap *AutoPause) ReArm() {
	if ap == nil {
		return
	}
	// The predicate itself carries no latch — triggered() is stateless over the list — so
	// re-arming is not a state reset but the attack's own resume: Control.Resume is the
	// re-arm, and this method exists to keep the name Burp uses in the flow. The fired
	// count lives on the Attack (atomic) so the report can read it after ReArm.
}

// run applies both patterns over one response.
func (g *Grep) run(raw []byte) (*bool, *string) {
	var matched *bool
	if g.MatchRe != nil {
		m := g.MatchRe.Match(raw)
		matched = &m
	}
	var extracted *string
	if g.ExtractRe != nil {
		if v, ok := g.extract(raw); ok {
			extracted = &v
		}
	}
	return matched, extracted
}

// extract pulls the first capture group, or the whole match when there is no group. It reports
// false when there was no match, or when group 1 existed but did not participate in the match —
// which is a real "nothing extracted".
func (g *Grep) extract(raw []byte) (string, bool) {
	sub := g.ExtractRe.FindSubmatch(raw)
	if sub == nil {
		return "", false
	}
	var m []byte
	if g.ExtractRe.NumSubexp() > 0 {
		if len(sub) < 2 || sub[1] == nil {
			return "", false
		}
		m = sub[1]
	} else {
		m = sub[0]
	}
	if len(m) > MAX_EXTRACT {
		m = m[:MAX_EXTRACT]
	}
	return string(m), true
}

// Attack holds everything an attack needs that is not "how do I reach the network".
type Attack struct {
	// Base is the request every attempt starts from. Never mutated; each attempt splices a copy.
	Base []byte
	// Points are the selected positions, in the order the plan's point indices refer to.
	Points []InsertionPoint
	// Sets are the payload sets, in the order the plan's set indices refer to.
	Sets []PayloadSet
	Plan *AttackPlan
	// setBytes is Sets re-encoded as bytes, so the per-request splice does not allocate.
	setBytes [][][]byte
	// Limits bound how hard the attack may hit the target.
	Limits RateLimit
	// DetailLimit is how many per-request rows to keep. Beyond this only bucket counts survive.
	DetailLimit int
	// MaxBuckets is how many distinct result buckets to keep before giving up on further
	// distinctions.
	MaxBuckets int
	// RecordRequest decides whether the exact outbound bytes for a detail-row attempt are handed
	// to RequestFn before the send. It is nil-safe so every existing caller keeps its no-storage
	// behaviour; the web caller enables it for the bounded attempt table, not for every attack.
	RecordRequest bool
	// RequestFn stores one exact outbound request and returns its message id. The engine calls
	// it only when RecordRequest is set and the attempt is below DetailLimit, so recording
	// stays tied to the rows an operator can act on rather than multiplying the 100k-request
	// memory profile the report is designed to avoid.
	RequestFn func(raw []byte) uint64
	// SuiteGate blocks while the dashboard's suite-wide pause is set, checked between enumerations
	// alongside the attack's own Control. Two pauses rather than one because they answer different
	// questions — "hold this attack" and "hold everything" — and an operator who pressed the second
	// must not have to find the first. Nil is every caller that is not the web layer
	// (burpsy-react-ui-cijs).
	SuiteGate func(context.Context)
	// Guard refuses a spliced request before it goes out. Err(reason) means do not send.
	//
	// The engine has no concept of engagement scope and should not grow one — but it is the only
	// place that sees the request a payload actually produced. A caller checked the *target* the
	// operator named; a payload spliced into a path position can move the request somewhere else
	// entirely. So the caller supplies the predicate and the engine guarantees nothing bypasses
	// it. Refusals are counted as errors, never dropped silently.
	Guard Guard
	// Grep holds the operator's regexes tested against each response. Empty by default and free
	// when empty.
	Grep Grep
	// AutoPause is Burp's auto-pause predicate, evaluated on every response in the same
	// place Grep runs. Nil is unconfigured: the attack runs to its bound. See AutoPause.
	AutoPause *AutoPause
	// autoPaused counts trigger events. Atomic: doSend's send goroutines write it while the
	// collector reads it for the report.
	autoPaused atomic.Int64
	// Control is the pause/resume/stop handle, consulted by the driver loop before each plan
	// position. Nil is the uncontrolled attack: it runs to completion, which is what every caller
	// got before Control existed. See internal/intruder/control.go.
	Control *Control
}

// NewAttack builds an attack with defaults sized for a UI: enough rows to render a small attack,
// enough buckets that a real target's response variety fits without truncation.
func NewAttack(base []byte, points []InsertionPoint, sets []PayloadSet, plan *AttackPlan) *Attack {
	setBytes := make([][][]byte, len(sets))
	for i, s := range sets {
		setBytes[i] = make([][]byte, len(s.Items))
		for j, it := range s.Items {
			setBytes[i][j] = []byte(it)
		}
	}
	return &Attack{
		Base:        base,
		Points:      points,
		Sets:        sets,
		setBytes:    setBytes,
		Plan:        plan,
		Limits:      DefaultRateLimit(),
		DetailLimit: 500,
		MaxBuckets:  2_000,
	}
}

// WithLimits attaches the operator's bounds.
func (a *Attack) WithLimits(l RateLimit) *Attack {
	a.Limits = l
	return a
}

// WithGuard attaches the predicate every spliced request must satisfy before it is sent.
func (a *Attack) WithGuard(g Guard) *Attack {
	a.Guard = g
	return a
}

// WithGrep attaches the operator's grep-match and grep-extract patterns.
func (a *Attack) WithGrep(g Grep) *Attack {
	a.Grep = g
	return a
}

// WithAutoPause attaches the auto-pause predicate. Nil is unconfigured.
func (a *Attack) WithAutoPause(ap *AutoPause) *Attack {
	a.AutoPause = ap
	return a
}

// AutoPauseFired reports the trigger count for the report. Atomic because the driver goroutine
// fires the pause while the collector reads the count — the same split-brain the sent/failed
// counters already navigate.
func (a *Attack) AutoPauseFired() int {
	if a == nil {
		return 0
	}
	return int(a.autoPaused.Load())
}

// WithControl attaches the pause/resume/stop handle. Without one the attack cannot be halted, which
// is the state every web-launched attack was in.
func (a *Attack) WithControl(c *Control) *Attack {
	a.Control = c
	return a
}

// ResultBucket is a set of responses that behaved the same, counted once.
type ResultBucket struct {
	Status       *int `json:"status"`
	ResponseLen  int  `json:"response_len"`
	Reflected    bool `json:"reflected"`
	Count        int  `json:"count"`
	FirstOrdinal int  `json:"first_ordinal"`
	// ExampleRequestID and ExampleResponseID name the one stored exchange kept for this bucket —
	// the bytes of FirstOrdinal's send and the response it produced. One per bucket, not one per
	// request: a 100k-request attack that lands in four buckets stores four exchanges.
	ExampleRequestID  *uint64 `json:"example_request_id"`
	ExampleResponseID *uint64 `json:"example_response_id"`
	GrepMatches       int     `json:"grep_matches"`
	GrepExtract       *string `json:"grep_extract"`
}

// ErrorBucket is a set of sends that never produced a response, grouped by message.
type ErrorBucket struct {
	Error        string `json:"error"`
	Count        int    `json:"count"`
	FirstOrdinal *int   `json:"first_ordinal"`
}

// Attempt is one request's outcome. It carries no bytes: ordinal regenerates the payloads through
// the plan.
//
// RequestID names the exact outbound bytes for this attempt when the caller stored them. It is nil
// for guard refusals, send failures, detail rows past DetailLimit and callers that did not opt into
// recording.
//
// ResponseID is set only on the attempt that opened its bucket — the exemplar the engine stored.
// A later attempt in the same bucket is deliberately nil rather than pointed at that exemplar:
// bucketing matches on status, length and reflection, which is not a claim that two bodies are
// equal, and handing a row someone else's response would make the results table lie.
type Attempt struct {
	Ordinal     int     `json:"ordinal"`
	Status      *int    `json:"status"`
	ResponseLen int     `json:"response_len"`
	DurationMS  int64   `json:"duration_ms"`
	Reflected   bool    `json:"reflected"`
	RequestID   *uint64 `json:"request_id"`
	ResponseID  *uint64 `json:"response_id"`
	Error       *string `json:"error"`
	GrepMatched *bool   `json:"grep_matched"`
	GrepExtract *string `json:"grep_extract"`
	// TimeOfDay is when this attempt was dispatched — or, for a guard refusal, when it was refused.
	// Burp's results table carries it as its own column ("the time of day the request was made";
	// viewing-results.html), and an attack that runs for an hour needs it to line up a row with
	// whatever else was happening against the target at that moment. Set unconditionally, so it is
	// never the zero time even for a row that never reached the network.
	TimeOfDay time.Time `json:"time_of_day"`
	// Cookies are the names Set-Cookie carried in this attempt's response — Burp: "any cookies
	// received in the response". Names only, never values: an attack report is a document that gets
	// pasted into tickets, and a session token belongs in the stored response (ResponseID above), not
	// in a summary row — the same restraint intruderSessionCookies (internal/web) already holds to.
	// Empty, never nil: see newCollector's nil-slice note, which is the same wire contract applied to
	// a field inside each row rather than to the top-level slices.
	Cookies []string `json:"cookies"`
	// Timeout is true when Error above is specifically the per-request deadline expiring, rather than
	// any other failure (connection refused, TLS failure, a guard refusal). Burp lists Timeout as a
	// column distinct from Error for exactly this reason: a target that stalls on every Nth payload is
	// a pattern worth seeing at a glance, and folding it into free-text error strings buries it behind
	// having to read every row.
	Timeout bool `json:"timeout"`
}

// AttackReport is the answer to "what happened".
type AttackReport struct {
	Kind              AttackKind `json:"kind"`
	Combinations      uint64     `json:"combinations"`
	CombinationsExact bool       `json:"combinations_exact"`
	MaxRequests       int        `json:"max_requests"`
	Truncated         bool       `json:"truncated"`
	Planned           int        `json:"planned"`
	// Status is how the attack ended: "completed" for the plan exhausted, "stopped" for halted early
	// (see StopReason), and "paused" only on a report a caller built from a still-live attack.
	//
	// It exists because Planned/Sent cannot say it. An attack stopped at request 12 of 200,000 and an
	// attack whose target refused 199,988 requests both report sent=12 — and the second is a finding
	// about the target while the first is a fact about the operator's own button. Without this the
	// report reads as a complete answer over the whole payload set.
	Status AttackStatus `json:"status"`
	// StopReason is why the attack ended early, empty when it did not.
	StopReason string `json:"stop_reason,omitempty"`
	// Enumerated is how many plan positions the driver actually reached. For a completed attack this
	// equals Planned; for a stopped one it is the honest denominator — the count the results describe
	// a prefix of. Sent + Failed can be smaller still, because a stop lets in-flight sends land.
	Enumerated          int            `json:"enumerated"`
	Sent                int            `json:"sent"`
	Failed              int            `json:"failed"`
	ElapsedMS           int64          `json:"elapsed_ms"`
	Buckets             []ResultBucket `json:"buckets"`
	BucketsTruncated    bool           `json:"buckets_truncated"`
	Unbucketed          int            `json:"unbucketed"`
	Errors              []ErrorBucket  `json:"errors"`
	Attempts            []Attempt      `json:"attempts"`
	DetailLimit         int            `json:"detail_limit"`
	GrepMatched         int            `json:"grep_matched"`
	Pool                *string        `json:"pool"`
	AutoThrottleEngaged int            `json:"auto_throttle_engaged"`
	// AutoPaused is how many times the auto-pause condition fired (burpsy-react-ui-8f2).
	// Zero with a stopped status and an auto-pause configured means the operator stopped it
	// themselves; non-zero says the predicate did it — the report's own account of who
	// pressed the button.
	AutoPaused int `json:"auto_paused"`
}

// bucketKey is the distinct-behaviour triple. hasStatus distinguishes "no response" from a
// literal HTTP/0.9 0 status.
type bucketKey struct {
	status    int
	hasStatus bool
	length    int
	reflected bool
}

// hit is one successful response, fully described except for its payloads. It carries the exact
// request bytes only while they are needed to attach their stored id to this attempt's report row;
// the collector does not retain them after absorb returns.
type hit struct {
	status      *int
	length      int
	durationMS  int64
	reflected   bool
	grepMatched *bool
	grepExtract *string
	raw         []byte
	request     []byte
	// cookies are the Set-Cookie names this response carried, computed once here (doSend) so the
	// collector never needs the raw bytes to answer Attempt.Cookies. Always non-nil.
	cookies []string
}

// outcome is one attempt's result as the collector sees it. Guard refusals and send failures
// arrive as err; everything else as hit.
type outcome struct {
	ordinal int
	hit     *hit
	err     error
	// sentAt is when this ordinal was dispatched or refused. See Attempt.TimeOfDay.
	sentAt time.Time
}

// collector reduces a stream of outcomes into the report. Buckets are keyed by behaviour, not
// accumulated: the count lives here and the exemplar is stored once, through the recorder.
type collector struct {
	record       RecordFn
	request      func([]byte) uint64
	recordDetail bool
	index        map[bucketKey]int
	buckets      []ResultBucket
	errorIndex   map[string]int
	errors       []ErrorBucket
	attempts     []Attempt
	detailLimit  int
	maxBuckets   int
	sent         int
	failed       int
	unbucketed   int
	grepMatched  int
}

func newCollector(a *Attack, record RecordFn) *collector {
	mb := a.MaxBuckets
	if mb < 1 {
		mb = 1
	}
	// The three row slices start empty rather than nil, and that is a wire-format decision, not a
	// preallocation. A nil slice marshals to JSON `null`, and types.tools.ts declares these as
	// `ResultBucket[]` / `ErrorBucket[]` / `Attempt[]` — not nullable — so a report from a clean
	// attack was handing the browser a `null` where it had promised an array. `report.errors.length`
	// in AttackResult threw on it, which meant the Results tab rendered the ErrorBoundary for every
	// attack whose sends all succeeded (burpsy-react-ui-9pxd). Nothing in Go noticed, because a nil
	// slice and an empty one range and len identically.
	return &collector{
		record:       record,
		request:      a.RequestFn,
		recordDetail: a.RecordRequest && a.RequestFn != nil,
		index:        map[bucketKey]int{},
		buckets:      []ResultBucket{},
		errorIndex:   map[string]int{},
		errors:       []ErrorBucket{},
		attempts:     []Attempt{},
		detailLimit:  a.DetailLimit,
		maxBuckets:   mb,
	}
}

// absorb folds one outcome into the running summary.
func (c *collector) absorb(o outcome) {
	if o.err != nil {
		c.failed++
		if o.ordinal < c.detailLimit {
			e := o.err.Error()
			c.attempts = append(c.attempts, Attempt{
				// Cookies is []string{}, not nil: a failed send never reached a response, but the
				// field's wire contract (types.tools.ts declares Attempt.cookies non-nullable) does
				// not get an exception for that — see the nil-slice note on newCollector.
				Ordinal: o.ordinal, Error: &e, TimeOfDay: o.sentAt, Timeout: isTimeout(o.err),
				Cookies: []string{},
			})
		}
		c.noteError(o.ordinal, o.err.Error())
		return
	}
	h := o.hit
	c.sent++
	if h.grepMatched != nil && *h.grepMatched {
		c.grepMatched++
	}
	key := bucketKey{status: derefInt(h.status), hasStatus: h.status != nil, length: h.length, reflected: h.reflected}
	_, seen := c.index[key]
	newBucket := !seen && len(c.buckets) < c.maxBuckets
	detailRow := o.ordinal < c.detailLimit
	// One store per outcome, shared by the bucket exemplar and the detail row. Both want the same
	// bytes, and storing them twice would put two ids on the same send — the operator would open
	// the bucket's request and the attempt's request and be shown two copies with no way to tell
	// they are one request.
	var requestID *uint64
	if c.recordDetail && (newBucket || detailRow) {
		id := c.request(h.request)
		requestID = &id
	}
	var responseID *uint64
	if seen {
		i := c.index[key]
		c.buckets[i].Count++
		if h.grepMatched != nil && *h.grepMatched {
			c.buckets[i].GrepMatches++
		}
	} else if newBucket {
		if c.record != nil {
			id := c.record(h.raw)
			responseID = &id
		}
		c.index[key] = len(c.buckets)
		gm := 0
		if h.grepMatched != nil && *h.grepMatched {
			gm = 1
		}
		c.buckets = append(c.buckets, ResultBucket{
			Status: h.status, ResponseLen: h.length, Reflected: h.reflected, Count: 1,
			FirstOrdinal: o.ordinal, ExampleRequestID: requestID, ExampleResponseID: responseID,
			GrepMatches: gm, GrepExtract: h.grepExtract,
		})
	} else {
		c.unbucketed++
	}
	if detailRow {
		c.attempts = append(c.attempts, Attempt{
			Ordinal: o.ordinal, Status: h.status, ResponseLen: h.length, DurationMS: h.durationMS,
			Reflected: h.reflected, RequestID: requestID, ResponseID: responseID,
			GrepMatched: h.grepMatched, GrepExtract: h.grepExtract,
			TimeOfDay: o.sentAt, Cookies: h.cookies,
		})
	}
}

// noteError grows the error groups. Distinct messages beyond maxBuckets stop being tracked —
// their sends are still counted in failed.
func (c *collector) noteError(ordinal int, message string) {
	if i, ok := c.errorIndex[message]; ok {
		c.errors[i].Count++
		return
	}
	if len(c.errors) < c.maxBuckets {
		first := ordinal
		c.errorIndex[message] = len(c.errors)
		c.errors = append(c.errors, ErrorBucket{Error: message, Count: 1, FirstOrdinal: &first})
	}
}

// finish closes out the summary. Sorted so the smallest, strangest buckets surface first: the
// count of an attack's success mode is usually a wall, and the interesting rows are the ones
// with a count of one at the top.
func (c *collector) finish(a *Attack, limiter *RateLimiter, elapsed time.Duration, enumerated int) *AttackReport {
	sort.SliceStable(c.buckets, func(i, j int) bool {
		if c.buckets[i].Count != c.buckets[j].Count {
			return c.buckets[i].Count < c.buckets[j].Count
		}
		return c.buckets[i].FirstOrdinal < c.buckets[j].FirstOrdinal
	})
	sort.SliceStable(c.errors, func(i, j int) bool {
		if c.errors[i].Count != c.errors[j].Count {
			return c.errors[i].Count < c.errors[j].Count
		}
		oi := math.MaxInt
		oj := math.MaxInt
		if c.errors[i].FirstOrdinal != nil {
			oi = *c.errors[i].FirstOrdinal
		}
		if c.errors[j].FirstOrdinal != nil {
			oj = *c.errors[j].FirstOrdinal
		}
		return oi < oj
	})
	sort.SliceStable(c.attempts, func(i, j int) bool {
		return c.attempts[i].Ordinal < c.attempts[j].Ordinal
	})
	var pool *string
	if p := limiter.PoolName(); p != "" {
		pool = &p
	}
	return &AttackReport{
		Kind: a.Plan.Kind(), Combinations: a.Plan.Combinations(),
		CombinationsExact: a.Plan.CombinationsExact(), MaxRequests: a.Plan.MaxRequests(),
		Truncated: a.Plan.Truncated(), Planned: a.Plan.Len(),
		Sent: c.sent, Failed: c.failed,
		ElapsedMS: elapsed.Milliseconds(),
		Buckets:   c.buckets, BucketsTruncated: c.unbucketed > 0, Unbucketed: c.unbucketed,
		Errors: c.errors, Attempts: c.attempts,
		DetailLimit: c.detailLimit, GrepMatched: c.grepMatched,
		Pool: pool, AutoThrottleEngaged: limiter.AutoThrottleEngaged(),
		AutoPaused: a.AutoPauseFired(),
		Status:     reportStatus(a.Control), StopReason: a.Control.StopReason(),
		Enumerated: enumerated,
	}
}

// Run executes an attack. send carries the requests; record stores one exemplar per distinct
// bucket. When the attack opts into bounded request recording, RequestFn stores the exact
// outbound bytes for each detail-row attempt and the attempt names them. Returns the summary —
// the report is honest about every phase: planned is what the plan enumerated, sent is what
// produced a response, failed is what errored or was refused, and the truncated flags say where
// the limits cut.
func Run(a *Attack, send SendFn, record RecordFn) *AttackReport {
	started := time.Now()
	limiter := NewRateLimiter(&a.Limits)
	col := newCollector(a, record)

	results := make(chan outcome, 64)
	// enumerated is how many plan positions the loop actually reached. A stopped attack's report must
	// not present its planned count as the denominator of what happened — see AttackReport.Enumerated.
	enumerated := 0
	go func() {
		defer close(results)
		var wg sync.WaitGroup
		var asg Assignment
		for i := 0; i < a.Plan.Len(); i++ {
			// Before the plan is read and before a permit is taken: a paused attack must hold no
			// permit (it would throttle nothing and block a resume's first send) and must not have
			// spliced a request it is not going to send. Stop breaks out here rather than letting the
			// remaining ordinals become send errors — 199,988 errors for requests the target never
			// received is a report about a target that was never asked.
			if !a.Control.gate() {
				break
			}
			// Same placement as the attack's own pause, and for the same reason: a hold here has
			// not spliced a request it is not going to send, and holds no rate-limiter permit.
			if a.SuiteGate != nil {
				a.SuiteGate(context.Background())
			}
			if !a.Plan.Fill(i, &asg) {
				break
			}
			enumerated++
			places := make([]ApplyPlace, 0, len(asg.Slots))
			payloads := make([][]byte, 0, len(asg.Slots))
			for _, s := range asg.Slots {
				if s.Point < 0 || s.Point >= len(a.Points) ||
					s.Set < 0 || s.Set >= len(a.setBytes) ||
					s.Payload < 0 || s.Payload >= len(a.setBytes[s.Set]) {
					continue
				}
				payload := a.setBytes[s.Set][s.Payload]
				places = append(places, ApplyPlace{Point: &a.Points[s.Point], Payload: payload})
				payloads = append(payloads, payload)
			}

			permit := limiter.Acquire()
			req := ApplyAll(a.Base, places)
			if a.Guard != nil {
				if err := a.Guard(req); err != nil {
					permit.Release()
					results <- outcome{ordinal: i, err: err, sentAt: time.Now()}
					continue
				}
			}
			wg.Add(1)
			go func(ordinal int, raw []byte, payloads [][]byte, permit *Permit) {
				defer wg.Done()
				defer permit.Release()
				// Captured here, not before the permit or the guard: this is the closest point to the
				// actual send that every ordinal passes through, so it is what Attempt.TimeOfDay means
				// by "the time of day the request was made" — a rate-limiter wait or a guard refusal
				// must not be counted as part of it.
				sentAt := time.Now()
				defer func() {
					if r := recover(); r != nil {
						results <- outcome{ordinal: ordinal, err: fmt.Errorf("send task failed: %v", r), sentAt: sentAt}
					}
				}()
				h, err := doSend(a, limiter, send, raw, payloads)
				if h != nil {
					h.request = raw
				}
				results <- outcome{ordinal: ordinal, hit: h, err: err, sentAt: sentAt}
			}(i, req, payloads, permit)
		}
		wg.Wait()
	}()

	for o := range results {
		col.absorb(o)
		// Feed the live progress view: settled sends and failures, the same totals the
		// report will carry, so a control-route poll cannot disagree with it.
		a.Control.note(o.err == nil)
	}
	// After the drain, so an attack whose last in-flight sends were still landing when the plan ran
	// out is completed only once they are collected. complete() leaves a stopped attack stopped.
	a.Control.complete()
	// Read after the range loop: the driver goroutine's writes to enumerated happen-before the
	// channel close, which happens-before the loop's exit.
	return col.finish(a, limiter, time.Since(started), enumerated)
}

// doSend runs one request: send, observe the limiter, ask the reflection and grep questions.
func doSend(a *Attack, limiter *RateLimiter, send SendFn, raw []byte, payloads [][]byte) (*hit, error) {
	sent, err := send(raw)
	if err != nil {
		return nil, err
	}
	limiter.Observe(sent.Status)
	reflected := false
	for _, p := range payloads {
		if containsBytes(sent.Raw, p) {
			reflected = true
			break
		}
	}
	grepMatched, grepExtract := a.Grep.run(sent.Raw)
	// Auto-pause, evaluated on the same bytes grep just read (burpsy-react-ui-8f2). The
	// response already went out — the target has it — so this is not a guard, it is a halt
	// AFTER an observation: the current attempt is collected whole, and the driver's next
	// gate() call holds the rest. A triggered pause re-arms immediately, so a resume runs
	// rather than re-pausing on the same page; the fired count is what the report carries.
	if a.AutoPause.triggered(sent.Raw) {
		a.Control.Pause()
		// ReArm clears the predicate's matched state for the next resume — but the fired
		// count must survive it, so it lives on the attack, not the predicate.
		a.autoPaused.Add(1)
		a.AutoPause.ReArm()
	}
	// core.CookieNames is the same capture-path function the HTTP history table's Cookies column
	// reads (internal/core/capture_fields.go) — reused rather than re-parsed here so there is one
	// definition of "what counts as a cookie name" for a raw response, not two that could disagree.
	// It returns nil for "no Set-Cookie", which Attempt.Cookies' wire contract does not allow.
	cookies := core.CookieNames(sent.Raw)
	if cookies == nil {
		cookies = []string{}
	}
	return &hit{
		status: sent.Status, length: len(sent.Raw), durationMS: sent.Duration.Milliseconds(),
		reflected: reflected, grepMatched: grepMatched, grepExtract: grepExtract,
		raw: sent.Raw, cookies: cookies,
	}, nil
}

// isTimeout reports whether err is the per-request deadline expiring, as distinct from any other
// send failure (connection refused, TLS failure, a guard refusal). See Attempt.Timeout for why that
// distinction is its own column rather than text inside Error.
//
// Checked three ways because a timeout reaches this package wrapped differently depending on the
// path a send took: internal/sender/cancel.go's explainCancellation re-wraps a socket deadline as
// context.DeadlineExceeded when the caller's own context expired — the ordinary case here, since
// api_tools.go gives every send a per-request context.WithTimeout — a bare deadline can still
// surface as the stdlib's os.ErrDeadlineExceeded sentinel, and a streamed send (sender/pipeline.go,
// sender/h2program.go) reports a net.Error whose Timeout() is the only signal either way carries.
// A caller asking "was this a timeout" should not have to know which path a particular send took.
func isTimeout(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

// containsBytes is bytes.Contains with the "empty needle always matches" trap removed. A zero-
// length payload is not a reflection and must never make every response look reflective.
func containsBytes(hay, needle []byte) bool {
	if len(needle) == 0 || len(hay) < len(needle) {
		return false
	}
	return bytes.Contains(hay, needle)
}

func derefInt(p *int) int {
	if p == nil {
		return 0
	}
	return *p
}
