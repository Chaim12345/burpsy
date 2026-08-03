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
	"fmt"
	"math"
	"regexp"
	"sort"
	"sync"
	"time"
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

// ResultBucket is a set of responses that behaved the same, counted once.
type ResultBucket struct {
	Status            *int    `json:"status"`
	ResponseLen       int     `json:"response_len"`
	Reflected         bool    `json:"reflected"`
	Count             int     `json:"count"`
	FirstOrdinal      int     `json:"first_ordinal"`
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
type Attempt struct {
	Ordinal     int     `json:"ordinal"`
	Status      *int    `json:"status"`
	ResponseLen int     `json:"response_len"`
	DurationMS  int64   `json:"duration_ms"`
	Reflected   bool    `json:"reflected"`
	ResponseID  *uint64 `json:"response_id"`
	Error       *string `json:"error"`
	GrepMatched *bool   `json:"grep_matched"`
	GrepExtract *string `json:"grep_extract"`
}

// AttackReport is the answer to "what happened".
type AttackReport struct {
	Kind                AttackKind     `json:"kind"`
	Combinations        uint64         `json:"combinations"`
	CombinationsExact   bool           `json:"combinations_exact"`
	MaxRequests         int            `json:"max_requests"`
	Truncated           bool           `json:"truncated"`
	Planned             int            `json:"planned"`
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
}

// bucketKey is the distinct-behaviour triple. hasStatus distinguishes "no response" from a
// literal HTTP/0.9 0 status.
type bucketKey struct {
	status    int
	hasStatus bool
	length    int
	reflected bool
}

// hit is one successful response, fully described except for its payloads.
type hit struct {
	status      *int
	length      int
	durationMS  int64
	reflected   bool
	grepMatched *bool
	grepExtract *string
	raw         []byte
}

// outcome is one attempt's result as the collector sees it. Guard refusals and send failures
// arrive as err; everything else as hit.
type outcome struct {
	ordinal int
	hit     *hit
	err     error
}

// collector reduces a stream of outcomes into the report. Buckets are keyed by behaviour, not
// accumulated: the count lives here and the exemplar is stored once, through the recorder.
type collector struct {
	record      RecordFn
	index       map[bucketKey]int
	buckets     []ResultBucket
	errorIndex  map[string]int
	errors      []ErrorBucket
	attempts    []Attempt
	detailLimit int
	maxBuckets  int
	sent        int
	failed      int
	unbucketed  int
	grepMatched int
}

func newCollector(a *Attack, record RecordFn) *collector {
	mb := a.MaxBuckets
	if mb < 1 {
		mb = 1
	}
	return &collector{
		record: record, index: map[bucketKey]int{},
		errorIndex:  map[string]int{},
		detailLimit: a.DetailLimit, maxBuckets: mb,
	}
}

// absorb folds one outcome into the running summary.
func (c *collector) absorb(o outcome) {
	if o.err != nil {
		c.failed++
		if o.ordinal < c.detailLimit {
			e := o.err.Error()
			c.attempts = append(c.attempts, Attempt{
				Ordinal: o.ordinal, Error: &e,
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
	var responseID *uint64
	if i, ok := c.index[key]; ok {
		c.buckets[i].Count++
		if h.grepMatched != nil && *h.grepMatched {
			c.buckets[i].GrepMatches++
		}
	} else if len(c.buckets) < c.maxBuckets {
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
			FirstOrdinal: o.ordinal, ExampleResponseID: responseID,
			GrepMatches: gm, GrepExtract: h.grepExtract,
		})
	} else {
		c.unbucketed++
	}
	if o.ordinal < c.detailLimit {
		c.attempts = append(c.attempts, Attempt{
			Ordinal: o.ordinal, Status: h.status, ResponseLen: h.length, DurationMS: h.durationMS,
			Reflected: h.reflected, ResponseID: responseID,
			GrepMatched: h.grepMatched, GrepExtract: h.grepExtract,
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
func (c *collector) finish(a *Attack, limiter *RateLimiter, elapsed time.Duration) *AttackReport {
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
	}
}

// Run executes an attack. send carries the requests; record stores one exemplar per distinct
// bucket. Returns the summary — the report is honest about every phase: planned is what the plan
// enumerated, sent is what produced a response, failed is what errored or was refused, and the
// truncated flags say where the limits cut.
func Run(a *Attack, send SendFn, record RecordFn) *AttackReport {
	started := time.Now()
	limiter := NewRateLimiter(&a.Limits)
	col := newCollector(a, record)

	results := make(chan outcome, 64)
	go func() {
		defer close(results)
		var wg sync.WaitGroup
		var asg Assignment
		for i := 0; i < a.Plan.Len(); i++ {
			if !a.Plan.Fill(i, &asg) {
				break
			}
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
					results <- outcome{ordinal: i, err: err}
					continue
				}
			}
			wg.Add(1)
			go func(ordinal int, raw []byte, payloads [][]byte, permit *Permit) {
				defer wg.Done()
				defer permit.Release()
				defer func() {
					if r := recover(); r != nil {
						results <- outcome{ordinal: ordinal, err: fmt.Errorf("send task failed: %v", r)}
					}
				}()
				h, err := doSend(a, limiter, send, raw, payloads)
				results <- outcome{ordinal: ordinal, hit: h, err: err}
			}(i, req, payloads, permit)
		}
		wg.Wait()
	}()

	for o := range results {
		col.absorb(o)
	}
	return col.finish(a, limiter, time.Since(started))
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
	return &hit{
		status: sent.Status, length: len(sent.Raw), durationMS: sent.Duration.Milliseconds(),
		reflected: reflected, grepMatched: grepMatched, grepExtract: grepExtract,
		raw: sent.Raw,
	}, nil
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
