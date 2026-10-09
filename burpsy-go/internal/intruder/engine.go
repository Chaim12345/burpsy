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
	"slices"
	"sort"
	"strings"
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

// Grep is grep-match and grep-extract, applied to every response.
type Grep struct {
	// MatchRe answers "does the response match?" as a boolean per attempt.
	MatchRe *regexp.Regexp
	// ExtractRe pulls out the first capture group of the first match, or the whole match when
	// the pattern has no groups — which is what an operator who wrote a pattern with no
	// parentheses means.
	ExtractRe *regexp.Regexp
	// MatchList is Burp's full Grep - Match form (irt): a LIST of expressions, each counting
	// its occurrences in the response — "Burp adds a results column for each expression in the
	// list. This records the number of times the expression is found in the response."
	// Recovered from the decompiled original: Zru_ holds the panel (matchgrep.dogrep's
	// Simple string/Regex radio, matchgrep.casesensitive, matchgrep.excludeheaders) and the
	// matchgrep.item0..N persisted list of default error strings. Nil when unconfigured.
	MatchList *MatchList
}

// MatchList is the compiled Grep - Match expression list (irt).
type MatchList struct {
	// Items are the compiled expressions, in list order — the order the results columns go in.
	Items []*regexp.Regexp
	// Labels are the expressions as the operator typed them, for the results-table headers.
	Labels []string
	// ExcludeHeaders trims the search to the response body: Burp's "Exclude HTTP headers"
	// checkbox. The header/body split is the first \r\n\r\n in the message; a response with
	// no split is searched whole, because there is no header block to exclude.
	ExcludeHeaders bool
	// maxMatchesPerItem bounds one expression's count on one response, so a pathological
	// response (an attacker-supplied body that repeats the token a million times) cannot turn
	// per-response counting into a per-response allocation. The cap is far above every count a
	// real response produces, and the count is capped, not the search.
	maxMatchesPerItem int
}

// NewMatchList compiles the expression list. simple=true treats every entry as a literal string
// (quoted), case-folded unless caseSensitive — Burp's Match type radio and Case sensitive match
// checkbox; simple=false compiles each entry as a regex, where case is the pattern's own
// business. Patterns that do not compile are refused with the item's index and text, not
// dropped: a column that silently counts nothing is a lie.
func NewMatchList(items []string, simple, caseSensitive, excludeHeaders bool) (*MatchList, error) {
	ml := &MatchList{
		ExcludeHeaders:    excludeHeaders,
		maxMatchesPerItem: 10_000,
	}
	for i, expr := range items {
		if strings.TrimSpace(expr) == "" {
			continue // an empty line in the list is no expression, matching Burp's **empty** row
		}
		pattern := expr
		if simple {
			pattern = regexp.QuoteMeta(expr)
			if !caseSensitive {
				pattern = "(?i)" + pattern
			}
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("grep match item %d (%q) does not compile: %w", i+1, expr, err)
		}
		ml.Items = append(ml.Items, re)
		ml.Labels = append(ml.Labels, expr)
	}
	return ml, nil
}

// labelsOrEmpty is the operator's expressions as typed, for the report's column headers. Nil
// when no list — the report distinguishes "no list" (omitempty drops the field) from a list
// whose items all failed... which cannot happen, because NewMatchList refuses items that do not
// compile and skips empties.
func (ml *MatchList) labelsOrEmpty() []string {
	if ml == nil {
		return nil
	}
	return ml.Labels
}

// counts applies every expression to one response. Always one count per item, never nil: the
// wire rows carry a parallel array and a missing slot would shift every column after it.
//
// The nil check is FIRST, before any field access — a nil receiver's field dereference panics,
// and every ordinary attack (no list configured) holds a nil MatchList. Caught by the full
// suite: every attack's sends were "failing" through the plan loop's recover, which is exactly
// the kind of bug a package-scoped build+vet misses because it compiles fine.
func (ml *MatchList) counts(raw []byte) []int {
	if ml == nil || len(ml.Items) == 0 {
		return []int{}
	}
	out := make([]int, len(ml.Items))
	if ml.ExcludeHeaders {
		// The first double CRLF is the header/body boundary. Everything from there on is body.
		if i := bytes.Index(raw, []byte("\r\n\r\n")); i >= 0 {
			raw = raw[i+4:]
		}
	}
	for i, re := range ml.Items {
		if re == nil {
			continue
		}
		out[i] = len(re.FindAllIndex(raw, ml.maxMatchesPerItem))
	}
	return out
}

// IsEmpty reports whether no grep was configured at all.
func (g *Grep) IsEmpty() bool { return g.MatchRe == nil && g.ExtractRe == nil && g.MatchList == nil }

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

// RecursiveGrep is Burp's Recursive grep payload type (ztuu): the payload for request N+1 is
// extracted from the response to request N. Ported from the decompiled original — Zm2n holds the
// initial payload (ZLI), the previous payload (ZLj), the current one (ZL1) and the stop-on-
// duplicate flag (ZLp); Zccc.Zt stops when the current payload is null (the extraction matched
// nothing) or when stop-duplicate fires with current == previous; Zsvp.Zx forces the resource
// pool to max concurrent 1 whenever the attack uses this source, because the chain is only
// meaningful in send order — request 2's payload is derived from request 1's response.
type RecursiveGrep struct {
	// Re extracts the next payload from the previous response. Same convention as Grep.extract:
	// first capture group, or the whole match when the pattern has no group; capped at
	// MAX_EXTRACT.
	Re *regexp.Regexp
	// StopDuplicate stops the attack when the extracted payload equals the one just sent —
	// Burp: "This normally indicates that the exercise is complete."
	StopDuplicate bool
}

// extract applies Re to one response. ok=false is the chain's natural end: nothing matched, so
// there is no next payload. This is Grep.extract's contract on a different field, not a copy of
// it — the recursive driver feeds the result back as a payload, so an empty group hit is a real
// "no payload" rather than a "keep the old one".
func (rg *RecursiveGrep) extract(raw []byte) (string, bool) {
	if rg == nil || rg.Re == nil {
		return "", false
	}
	sub := rg.Re.FindSubmatch(raw)
	if sub == nil {
		return "", false
	}
	m := sub[0]
	if rg.Re.NumSubexp() > 0 {
		if len(sub) < 2 || sub[1] == nil {
			return "", false
		}
		m = sub[1]
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
	// GrepPayloads is Burp's Grep - Payloads (7qc3): whether and how each response is searched for
	// the payloads that produced it. NewAttack sets LegacyGrepPayloads. See grep_payloads.go.
	GrepPayloads GrepPayloads
	// setPreBytes is the pre-URL-encoding form of each set that has one, built by prepareReflection
	// only when pre-encoded matching will read it; nil otherwise.
	setPreBytes [][][]byte
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
	// StoreResponses is Burp's "Store responses" attack-results setting (burpsy-react-ui-nqww): whether
	// the recorder is asked to store each bucket's exemplar response. True by NewAttack, Burp's default
	// (Zrua reads storeresponses as anything but "false"). False trades the stored bodies for memory and
	// disk: every response is still read, bucketed and grepped, and the session jar still learns from it
	// (Observe), but no response id is handed out. "Store requests" is RecordRequest above.
	StoreResponses bool
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
	// Recursive is the recursive-grep driver config (ztuu). Non-nil switches Run to the serial
	// chain driver: the plan is not consulted, because the payloads are response-derived and
	// therefore unknown at plan time. See RecursiveGrep.
	Recursive *RecursiveGrep
	// Retries is Burp's "Number of retries on network failure" (n39): how many times a failed
	// send is retried before its error becomes the attempt's outcome. Zero disables; the web
	// layer defaults it to Burp's own 3 (Zrur: requireNonNullElse(numretries, "3")). A retry
	// is a network-failure answer, not a new attempt — the request the target already failed
	// to answer is sent again, and the report counts retries separately (Retries field on
	// AttackReport) so a hole-filling retry is never hidden inside sent/failed.
	Retries int
	// RetryDelay is Burp's "Pause before retry" (n39): how long to wait between retries.
	// Burp's default is 2000ms (Zrur: "2000" beside pausebeforeretry) and its validation bound
	// is 0..600000 (Zb33: "Pause before retry must be between 0 and 600000").
	RetryDelay time.Duration
	// retriesUsed counts retry sends across the attack. Atomic: the drivers' send paths write
	// it while the collector reads the total for the report.
	retriesUsed atomic.Int64
	// Baseline is Burp's "Make unmodified baseline request" (v34): issue the template request
	// with every payload position at its base value, in addition to the configured attack
	// requests — "The request shows as item 0 in the results table. This is useful to provide
	// a base response against which to compare the attack responses" (settings.html, Attack
	// results). The decompiled original renders that row's position as -1 with the label
	// "Baseline request (no payloads)" (Zrpq), so the ordinal shift is one and the sentinel is
	// the position field's -1 — the same shape here: ordinal 0 is the baseline, plan ordinal i
	// becomes result ordinal i+1.
	Baseline bool
	// autoPaused counts trigger events. Atomic: doSend's send goroutines write it while the
	// collector reads it for the report.
	autoPaused atomic.Int64
	// Control is the pause/resume/stop handle, consulted by the driver loop before each plan
	// position. Nil is the uncontrolled attack: it runs to completion, which is what every caller
	// got before Control existed. See internal/intruder/control.go.
	Control *Control
	// SetConnectionClose is Burp's "Set Connection header" attack setting (burpsy-react-ui-fmxv):
	// "Add or update the Connection header with the value close." Applied to every request this
	// attack sends — the spliced ones, the baseline, and each link of a recursive chain — after
	// the payloads are in place, because insertion points are byte offsets and a header added
	// ahead of them would move every span that follows. False leaves the template's own Connection
	// header, whatever it says, exactly as the operator wrote it. See connection.go.
	SetConnectionClose bool
	// StorePayloads is Burp's "Store full payloads" attack setting (burpsy-react-ui-fmxv): "Store
	// the full payload values for each result. This consumes additional memory but may be required
	// to perform certain actions at runtime."
	//
	// What it costs here is worth stating plainly, because memory frugality is this project's
	// reason to exist. The payload SETS are materialised either way — the splice reads them, so
	// they exist for the length of the attack no matter what this says, and neither setting can
	// change that. What this buys is a per-result copy: Attempt.Payloads, one []string per kept
	// attempt row, holding the same string values the sets already hold. Go strings are immutable
	// and shared, so the bytes are not copied; the cost is the slice header plus one 16-byte string
	// header per payload per row, bounded by DetailLimit. For the default 500-row limit and a
	// two-position cluster bomb that is on the order of 28 KB, and it is paid only when asked for.
	//
	// What it buys is a report that can name its own payloads. Without it an Attempt row carries an
	// ordinal, and recovering the payload behind that ordinal means holding the plan AND the
	// resolved sets and replaying the plan's arithmetic — which is fine inside the handler that
	// just ran the attack and impossible for anything handed the report afterwards.
	StorePayloads bool
	// Capture is Burp's results capture filter (ip2b): which items are captured as result rows and stored
	// messages. Nil captures everything. A discarded item is still counted — Sent/Failed, its error
	// group, its bucket — and in AttackReport.Discarded; it just leaves no row and no stored bytes.
	// See capture.go.
	Capture *CaptureFilter
	// Observe is shown the response that opens each new result bucket, whether or not it is captured or
	// stored — the web layer's session cookie jar learns Set-Cookie lines here (one per distinct
	// behaviour, the same restraint the exemplar store holds to). Separate from the recorder so that
	// discarding or not storing a response never silently stops the jar learning from the attack.
	Observe func(raw []byte)
	// Evasion is the optional WAF-evasion composition (burpsy-react-ui-tfqk): User-Agent rotation,
	// jitter, and header-order randomisation applied around every send this attack makes. Nil —
	// the default — leaves the attack byte-for-byte and timing-for-timing what it was.
	//
	// Held as a configured value rather than applied by the caller so the setting travels WITH the
	// attack: a surface that builds an Attack and hands it to Run cannot forget to wrap, and a
	// recursive chain's later links get the same evasion as the first without re-wrapping at each
	// hop. Run performs the wrap exactly once, around the SendFn it was given.
	//
	// It composes with Limits rather than replacing them: the jitter waits INSIDE the wrapped send,
	// so the RateLimiter's own reserve/acquire still runs and the two delays add. See evasion.go
	// for why collapsing them into one wait would give up one of the two guarantees.
	Evasion *WAFEvasion
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
		Base:     base,
		Points:   points,
		Sets:     sets,
		setBytes: setBytes,
		Plan:     plan,
		// The reflection check every attack ran before Grep - Payloads had settings (7qc3).
		GrepPayloads: LegacyGrepPayloads(),
		// Burp's default, and what every attack did before the switch existed (nqww).
		StoreResponses: true,
		Limits:         DefaultRateLimit(),
		DetailLimit:    500,
		MaxBuckets:     2_000,
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

// egress shapes the bytes that will actually go on the wire, after the payloads are spliced and
// before the guard reads them.
//
// Before the guard, deliberately: the guard is the scope chokepoint, and its contract is that it
// sees "the request a payload actually produced". Showing it one request and sending another would
// make that contract false for the sake of one header.
//
// After the splice, equally deliberately: insertion points are byte offsets into the base request,
// so a header added ahead of them would move every span that follows.
//
// The returned slice is the caller's input untouched when no setting applies, so an attack that
// configures none of these allocates nothing per request.
func (a *Attack) egress(raw []byte) []byte {
	if a == nil || !a.SetConnectionClose {
		return raw
	}
	return setConnectionClose(raw)
}

// storedPayloads is the per-attempt payload record, or nil when the attack did not ask for one.
// nil rather than an empty slice, because Attempt.Payloads is omitempty and the absence is what
// says "this attack did not store payload values" — see Attempt.Payloads.
func (a *Attack) storedPayloads(payloads [][]byte) []string {
	if a == nil || !a.StorePayloads || len(payloads) == 0 {
		return nil
	}
	out := make([]string, len(payloads))
	for i, p := range payloads {
		out[i] = string(p)
	}
	return out
}

// WithSetConnectionClose attaches Burp's "Set Connection header" setting. See
// Attack.SetConnectionClose.
func (a *Attack) WithSetConnectionClose(b bool) *Attack {
	a.SetConnectionClose = b
	return a
}

// collaboratorPayloads picks the Collaborator addresses out of one ordinal's slots, nil when none
// of its sets is a Collaborator set.
func (a *Attack) collaboratorPayloads(slots []Slot) []string {
	var out []string
	for _, sl := range slots {
		if sl.Set < 0 || sl.Set >= len(a.Sets) || a.Sets[sl.Set].Kind != "collaborator" ||
			sl.Payload < 0 || sl.Payload >= len(a.setBytes[sl.Set]) {
			continue
		}
		v := string(a.setBytes[sl.Set][sl.Payload])
		if !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	return out
}

// WithStorePayloads attaches Burp's "Store full payloads" setting. See Attack.StorePayloads for
// what it costs and what it buys.
func (a *Attack) WithStorePayloads(b bool) *Attack {
	a.StorePayloads = b
	return a
}

// WithRecursive attaches the recursive-grep driver. Nil is an ordinary attack.
func (a *Attack) WithRecursive(rg *RecursiveGrep) *Attack {
	a.Recursive = rg
	return a
}

// WithBaseline attaches Burp's "Make unmodified baseline request" (v34).
func (a *Attack) WithBaseline(b bool) *Attack {
	a.Baseline = b
	return a
}

// WithRetries attaches Burp's error-handling knobs (n39): retries per failed send, and the
// pause between them. retries < 0 or delay < 0 are clamped to zero here rather than refused —
// the web layer validates the operator's numbers against Burp's own bounds; the engine just
// refuses to sleep a negative time.
func (a *Attack) WithRetries(retries int, delay time.Duration) *Attack {
	if retries < 0 {
		retries = 0
	}
	if delay < 0 {
		delay = 0
	}
	a.Retries = retries
	a.RetryDelay = delay
	return a
}

// RetriesUsed reports how many retry sends the attack made, for the report. The count is the
// honest half of the feature: an attack that retried its way to success reads differently from
// one that never stumbled, and a summary that hides retries would make a flaky target look
// clean.
func (a *Attack) RetriesUsed() int {
	if a == nil {
		return 0
	}
	return int(a.retriesUsed.Load())
}

// retryWait sleeps the pause before a retry, in slices that notice a stop — checked after
// EVERY slice, not once at the end, because the stop lands mid-sleep and the whole point of
// slicing is to cut the wait short: a plain time.Sleep(delay) would hold a stopped attack's
// send goroutine for the whole pause, and a 600-second sleep per dead connection is how an
// operator learns the stop button lied. Returns false when the control was stopped mid-wait.
//
// The gate is also asked BEFORE the loop, and that check is not redundant. A zero pause is
// inside Burp's own 0..600000 bound and is what a caller who wants immediate retries passes;
// with it set the loop body never runs, so the checks inside it never happen and a stopped
// attack would go on retrying — one request per retry, after the operator had halted it. "Stop
// means stop" must not depend on a delay being non-zero. (The gate also blocks while the
// attack is paused, which is the same answer one step earlier: hold the retries too.)
func (a *Attack) retryWait(ctx context.Context) bool {
	if !a.Control.gate() {
		return false
	}
	remaining := a.RetryDelay
	const slice = 25 * time.Millisecond
	for remaining > 0 {
		step := slice
		if remaining < step {
			step = remaining
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(step):
		}
		remaining -= step
		if !a.Control.gate() {
			return false
		}
	}
	return true
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
	// ReflectedCountTotals is Grep - Payloads' per-set occurrence count summed over this bucket's
	// responses (7qc3), one slot per payload set — the bucket-table counterpart of an attempt's
	// ReflectedCounts, as GrepMatchTotals is of GrepMatchCounts. Empty when Grep - Payloads is off.
	ReflectedCountTotals []int `json:"reflected_count_totals"`
	// ExampleRequestID and ExampleResponseID name the one stored exchange kept for this bucket —
	// the bytes of FirstOrdinal's send and the response it produced. One per bucket, not one per
	// request: a 100k-request attack that lands in four buckets stores four exchanges.
	//
	// With a capture filter (ip2b) the response that opened the bucket may have been discarded; the
	// bucket then takes its exemplar from the first CAPTURED response in it, and ExampleOrdinal names
	// that ordinal. Both ids are null, and ExampleOrdinal too, while no response in the bucket was
	// captured and stored.
	ExampleRequestID  *uint64 `json:"example_request_id"`
	ExampleResponseID *uint64 `json:"example_response_id"`
	ExampleOrdinal    *int    `json:"example_ordinal"`
	GrepMatches       int     `json:"grep_matches"`
	GrepExtract       *string `json:"grep_extract"`
	// GrepMatchTotals is the match list's occurrence count summed over this bucket's
	// responses (irt): one slot per expression, in list order — the same shape an attempt row
	// carries, summed. Empty when no list was configured.
	GrepMatchTotals []int `json:"grep_match_totals"`
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
	Ordinal     int   `json:"ordinal"`
	Status      *int  `json:"status"`
	ResponseLen int   `json:"response_len"`
	DurationMS  int64 `json:"duration_ms"`
	Reflected   bool  `json:"reflected"`
	// ReflectedCounts is Grep - Payloads' column per payload set (7qc3): "the number of times the
	// payload is found in the response … If more than one payload set is used, a separate column is
	// added for each payload set." One slot per set, in set order; the baseline row has zeros. Empty
	// (never null) when Grep - Payloads is off, and for an attempt that produced no response.
	ReflectedCounts []int   `json:"reflected_counts"`
	RequestID       *uint64 `json:"request_id"`
	ResponseID      *uint64 `json:"response_id"`
	Error           *string `json:"error"`
	GrepMatched     *bool   `json:"grep_matched"`
	GrepExtract     *string `json:"grep_extract"`
	// GrepMatchCounts is the Grep - Match list's per-expression occurrence count for this
	// response (irt), parallel to the attack's expression list. Empty (not nil) when no list
	// was configured, so the wire shape never varies (the nil-slice note on newCollector).
	GrepMatchCounts []int `json:"grep_match_counts"`
	// TimeOfDay is when this attempt was dispatched — or, for a guard refusal, when it was refused.
	// Burp's results table carries it as its own column ("the time of day the request was made";
	// viewing-results.html), and an attack that runs for an hour needs it to line up a row with
	// whatever else was happening against the target at that moment. Set unconditionally, so it is
	// never the zero time even for a row that never reached the network.
	TimeOfDay time.Time `json:"time_of_day"`
	// Payloads are the payload values spliced into this attempt's insertion points, in position
	// order — Burp's "Store full payloads" (burpsy-react-ui-fmxv). Present only when the attack
	// asked for them (Attack.StorePayloads); ABSENT from the JSON otherwise, never an empty array.
	//
	// That distinction is the whole point. An empty array would read as "this attempt had no
	// payloads", which is a real state — the baseline row (v34) is exactly that. An absent field
	// reads as "this attack did not store payload values", which is a different fact about the
	// report rather than about the request. A reader that cannot tell them apart would label the
	// baseline and every row of a frugal attack the same way.
	Payloads []string `json:"payloads,omitempty"`
	// CollaboratorPayloads are the Collaborator addresses this attempt sent (nib6), whatever
	// StorePayloads says: they are what ties a later out-of-band interaction back to this row —
	// Burp's "Interactions" results column. Absent when the attack had no Collaborator payload set.
	CollaboratorPayloads []string `json:"collaborator_payloads,omitempty"`
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
	// AnomalyRank is this row's place in the attack's anomaly ranking (pglp, anomaly.go): 1 is the
	// most unusual response; equal scores share a rank. Zero when the attack had fewer than two
	// detail rows to compare.
	AnomalyRank int `json:"anomaly_rank"`
}

// AttackReport is the answer to "what happened".
type AttackReport struct {
	// VariantAttributes are the response attributes that varied across the attack's detail rows
	// (Burp's variantAttributes, pglp); the anomaly ranking scores only these. Never null.
	VariantAttributes []string   `json:"variant_attributes"`
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
	// ChainPayloads is the recursive-grep chain's payload per ordinal, set only by the chain
	// driver (ztuu). Plan arithmetic cannot answer "what payload produced ordinal 3" for a
	// response-derived chain — the payloads exist only because the responses did — so the
	// driver records them as it goes and the wire view reads this instead of payloadsAt.
	// Empty (not nil) for every plan-driven attack, so the wire shape never varies.
	ChainPayloads []string `json:"chain_payloads"`
	// GrepMatchLabels are the Grep - Match expressions as the operator typed them (irt), in
	// list order — the results-table headers for the per-expression count columns. Present
	// only when a list ran; nil otherwise, so the browser can tell "no list" from "empty list".
	GrepMatchLabels []string `json:"grep_match_labels,omitempty"`
	// RetriesUsed is how many retry sends the attack made (n39) — Burp's error-handling count,
	// surfaced because an attack that retried its way to a full result set is a different fact
	// about the target than one that never stumbled. Zero unless the attack configured retries.
	RetriesUsed int `json:"retries_used"`
	// Baseline is true when the attack issued the unmodified template request as item 0 (v34):
	// every ordinal in Attempts/Buckets is one higher than the plan's arithmetic, and ordinal
	// 0's row is "Baseline request (no payloads)" — the base response the attack responses hang
	// against. The wire view reads this to shift payloadsAt's plan arithmetic.
	Baseline bool `json:"baseline"`
	// Discarded is how many items the capture filter dropped (ip2b): counted in Sent or Failed, in their
	// error group or bucket, and in nothing else — no row, no stored request or response. Zero with no
	// filter. Captured items plus Discarded is Sent plus Failed.
	Discarded int `json:"discarded"`
	// CaptureFilter is the capture filter the attack ran with, or null when it captured everything.
	CaptureFilter *CaptureFilterSpec `json:"capture_filter"`
	// RequestsStored and ResponsesStored say whether this attack stored the exact requests and the
	// exemplar responses at all (nqww: Burp's "Store requests" / "Store responses"). A null id on a row is
	// then read through them: not stored because the attack was told not to, rather than because nothing
	// came back — the two mean different things about the target.
	RequestsStored  bool `json:"requests_stored"`
	ResponsesStored bool `json:"responses_stored"`
	// GrepPayloads is the Grep - Payloads configuration this attack ran with (7qc3) — always present,
	// so the report says whether reflected and its count columns were asked at all, and how, rather
	// than leaving a reader to infer it from an all-false column.
	GrepPayloads GrepPayloads `json:"grep_payloads"`
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
	status     *int
	length     int
	durationMS int64
	reflected  bool
	// reflectedCounts is Grep - Payloads' per-set count (7qc3); [] when it is off.
	reflectedCounts []int
	grepMatched     *bool
	grepExtract     *string
	// grepCounts is the match list's per-expression occurrence count (irt), one slot per
	// item, in list order. Nil when no list was configured.
	grepCounts []int
	raw        []byte
	request    []byte
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
	// payloads are this ordinal's payload values, carried only when the attack asked to store
	// them (Attack.StorePayloads) and nil otherwise, so an attack that did not ask allocates
	// nothing per outcome. Set on refusals and guard failures too: the payload a container would
	// not hold is exactly the one an operator needs named. See Attempt.Payloads.
	payloads []string
	// collab are the Collaborator addresses this ordinal carried (nib6). See
	// Attempt.CollaboratorPayloads.
	collab []string
}

// collector reduces a stream of outcomes into the report. Buckets are keyed by behaviour, not
// accumulated: the count lives here and the exemplar is stored once, through the recorder.
type collector struct {
	// attrs are each detail row's response attributes, by ordinal, for the anomaly ranking.
	attrs        map[int]map[string]string
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
	// capture is the attack's capture filter (nil captures everything); discarded counts what it
	// dropped and captured what it kept. With a filter, the DetailLimit row budget is spent on the
	// first captured items rather than on the first ordinals — see detailRow.
	capture   *CaptureFilter
	discarded int
	captured  int
	// observe is Attack.Observe; pendingExemplar marks buckets whose opening response was not stored
	// (discarded by the capture filter), so the first captured response in them becomes the exemplar.
	observe         func([]byte)
	pendingExemplar map[int]bool
	// storeResponses is Attack.StoreResponses with a recorder present (nqww).
	storeResponses bool
	// chain is the recursive driver's payload-per-ordinal record (ztuu); nil for every
	// plan-driven attack, which is how finish() knows to leave ChainPayloads empty.
	chain []string
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
		record:          record,
		request:         a.RequestFn,
		recordDetail:    a.RecordRequest && a.RequestFn != nil,
		index:           map[bucketKey]int{},
		buckets:         []ResultBucket{},
		errorIndex:      map[string]int{},
		errors:          []ErrorBucket{},
		attempts:        []Attempt{},
		attrs:           map[int]map[string]string{},
		detailLimit:     a.DetailLimit,
		maxBuckets:      mb,
		capture:         a.Capture,
		observe:         a.Observe,
		pendingExemplar: map[int]bool{},
		storeResponses:  a.StoreResponses && record != nil,
	}
}

// detailRow decides whether a captured item gets a results row. Without a capture filter the row
// budget is the first DetailLimit ordinals, as it always was. With one it is the first DetailLimit
// CAPTURED items: the filter is how an operator spends the row budget on the items that matter, and
// spending it on ordinals the filter then discards would leave a filtered 50,000-request attack with a
// handful of rows from its first 500 requests. The cost is order: concurrent sends complete out of
// order, so which captured items fill the last rows can vary between runs; at max_in_flight 1 it does
// not. finish() sorts the rows by ordinal either way. Called after c.captured counted this item.
func (c *collector) detailRow(ordinal int) bool {
	if c.capture == nil {
		return ordinal < c.detailLimit
	}
	return c.captured <= c.detailLimit
}

// chainOrEmpty is the wire-shape guard for ChainPayloads: never nil, so the JSON is [] and not
// null — the same contract the row slices already hold (newCollector's nil-slice note).
func (c *collector) chainOrEmpty() []string {
	if c.chain == nil {
		return []string{}
	}
	return c.chain
}

// absorb folds one outcome into the running summary.
func (c *collector) absorb(o outcome) {
	if o.err != nil {
		c.failed++
		// No response to judge: only "discard items without responses" and a positive search term can
		// drop it (capture.go).
		if !c.capture.captures(nil, nil) {
			c.discarded++
			c.noteError(o.ordinal, o.err.Error())
			return
		}
		c.captured++
		if c.detailRow(o.ordinal) {
			e := o.err.Error()
			outcome := "error"
			if isTimeout(o.err) {
				outcome = "timeout"
			}
			c.attrs[o.ordinal] = map[string]string{"outcome": outcome}
			c.attempts = append(c.attempts, Attempt{
				// Cookies is []string{}, not nil: a failed send never reached a response, but the
				// field's wire contract (types.tools.ts declares Attempt.cookies non-nullable) does
				// not get an exception for that — see the nil-slice note on newCollector. The
				// match-count array holds to the same contract: [] for a send that never produced
				// a response, not null (irt).
				Ordinal: o.ordinal, Error: &e, TimeOfDay: o.sentAt, Timeout: isTimeout(o.err),
				Cookies: []string{}, GrepMatchCounts: []int{}, ReflectedCounts: []int{}, Payloads: o.payloads,
				CollaboratorPayloads: o.collab,
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
	bucketIndex, seen := c.index[key]
	newBucket := !seen && len(c.buckets) < c.maxBuckets
	// The capture filter (ip2b) decides whether this item leaves a row and stored bytes. It never
	// decides whether it is counted: sent, the bucket's count and its totals include it either way.
	keep := c.capture.captures(h.raw, h.status)
	if keep {
		c.captured++
	} else {
		c.discarded++
	}
	if newBucket && c.observe != nil {
		c.observe(h.raw)
	}
	// The exemplar: the bucket's opening response when it is captured, or — when that one was
	// discarded — the first captured response that lands in the bucket afterwards.
	exemplar := keep && (newBucket || (seen && c.pendingExemplar[bucketIndex]))
	detailRow := keep && c.detailRow(o.ordinal)
	// One store per outcome, shared by the bucket exemplar and the detail row. Both want the same
	// bytes, and storing them twice would put two ids on the same send — the operator would open
	// the bucket's request and the attempt's request and be shown two copies with no way to tell
	// they are one request.
	var requestID *uint64
	if c.recordDetail && (exemplar || detailRow) {
		id := c.request(h.request)
		requestID = &id
	}
	var responseID *uint64
	if exemplar && c.storeResponses {
		id := c.record(h.raw)
		responseID = &id
	}
	if seen {
		i := bucketIndex
		if exemplar {
			ordinal := o.ordinal
			c.buckets[i].ExampleRequestID, c.buckets[i].ExampleResponseID, c.buckets[i].ExampleOrdinal = requestID, responseID, &ordinal
			delete(c.pendingExemplar, i)
		}
		c.buckets[i].Count++
		if h.grepMatched != nil && *h.grepMatched {
			c.buckets[i].GrepMatches++
		}
		// Slot-wise sum: the bucket's totals describe every response it holds, so the list's
		// per-expression columns can sort the bucket table the way Burp's do.
		for j, v := range h.grepCounts {
			if j < len(c.buckets[i].GrepMatchTotals) {
				c.buckets[i].GrepMatchTotals[j] += v
			}
		}
		for j, v := range h.reflectedCounts {
			if j < len(c.buckets[i].ReflectedCountTotals) {
				c.buckets[i].ReflectedCountTotals[j] += v
			}
		}
	} else if newBucket {
		var exampleOrdinal *int
		if exemplar && (requestID != nil || responseID != nil) {
			ordinal := o.ordinal
			exampleOrdinal = &ordinal
		}
		if !keep {
			c.pendingExemplar[len(c.buckets)] = true
		}
		c.index[key] = len(c.buckets)
		gm := 0
		if h.grepMatched != nil && *h.grepMatched {
			gm = 1
		}
		c.buckets = append(c.buckets, ResultBucket{
			Status: h.status, ResponseLen: h.length, Reflected: h.reflected, Count: 1,
			FirstOrdinal: o.ordinal, ExampleRequestID: requestID, ExampleResponseID: responseID,
			ExampleOrdinal: exampleOrdinal,
			GrepMatches:    gm, GrepExtract: h.grepExtract,
			GrepMatchTotals: emptyCounts(h.grepCounts),
			// A copy: the bucket's totals grow with every later response, and the opening attempt's
			// row keeps its own counts.
			ReflectedCountTotals: append([]int{}, h.reflectedCounts...),
		})
	} else {
		c.unbucketed++
	}
	if detailRow {
		c.attrs[o.ordinal] = responseAttributes(h.raw, h.status, h.length, h.cookies)
		c.attempts = append(c.attempts, Attempt{
			Ordinal: o.ordinal, Status: h.status, ResponseLen: h.length, DurationMS: h.durationMS,
			Reflected: h.reflected, RequestID: requestID, ResponseID: responseID,
			GrepMatched: h.grepMatched, GrepExtract: h.grepExtract,
			GrepMatchCounts: emptyCounts(h.grepCounts),
			ReflectedCounts: emptyCounts(h.reflectedCounts),
			TimeOfDay:       o.sentAt, Cookies: h.cookies, Payloads: o.payloads,
			CollaboratorPayloads: o.collab,
		})
	}
}

// errPayloadRefused is the error an attempt carries when its payload could not be written into
// its insertion point at all. It names the container's own reason (escapePayload, which is
// bcheck's WireValue) rather than a generic message, so the report says WHY the attempt could not
// be represented — the scanner already reports the identical refusal for the identical payload at
// the identical point, and the two consumers must not describe it differently.
func errPayloadRefused(refusals []string) error {
	return fmt.Errorf("payload could not be placed in its insertion point: %s", strings.Join(refusals, "; "))
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
	variant := rankAnomalies(c.attempts, c.attrs)
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
		Errors: c.errors, Attempts: c.attempts, VariantAttributes: variant,
		DetailLimit: c.detailLimit, GrepMatched: c.grepMatched,
		Pool: pool, AutoThrottleEngaged: limiter.AutoThrottleEngaged(),
		AutoPaused: a.AutoPauseFired(),
		Status:     reportStatus(a.Control), StopReason: a.Control.StopReason(),
		Enumerated: enumerated,
		// Empty for every plan-driven attack (nil chain), set for the recursive driver — see
		// AttackReport.ChainPayloads.
		ChainPayloads: c.chainOrEmpty(),
		// Labels only when a list ran; the omitempty tag keeps "no list" and "empty list"
		// distinguishable, matching the Attempt counts' always-array contract where absence
		// would shift columns.
		GrepMatchLabels: a.Grep.MatchList.labelsOrEmpty(),
		RetriesUsed:     a.RetriesUsed(),
		Baseline:        a.Baseline,
		GrepPayloads:    a.GrepPayloads,
		Discarded:       c.discarded,
		CaptureFilter:   captureSpec(a.Capture),
		RequestsStored:  c.recordDetail,
		ResponsesStored: c.storeResponses,
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
	// The retry pause (n39) waits in slices that notice a stop — through Control, which is the
	// cancellation surface every web-launched attack already wires (StopOnContext). A bare
	// Background here is what the driver's SuiteGate call already uses; Control is what makes
	// it stoppable.
	ctx := context.Background()
	// The WAF-evasion wrap (burpsy-react-ui-tfqk), applied ONCE here and before the recursive
	// branch below, so every send this attack makes — the fanned-out plan, a recursive chain's
	// every link, and the retries inside doSend — goes through the same wrapped function. Wrapping
	// at each call site instead would be four places to forget, and a chain whose second link lost
	// the operator's evasion is the kind of silent half-application this project treats as a defect.
	//
	// Nil Evasion returns the caller's SendFn unchanged, so an attack that configured none is
	// byte-for-byte and timing-for-timing what it was.
	send = a.Evasion.wrapOrIdentity(send)
	a.prepareReflection()
	limiter := NewRateLimiter(&a.Limits)
	col := newCollector(a, record)

	// The recursive chain (ztuu) is a different shape of attack, not a mode of the plan: the
	// payloads do not exist until the responses do, so there is nothing to enumerate up front
	// and nothing to fan out — request 2 is built from request 1's response, so concurrency
	// could only reorder a chain whose meaning depends on its order.
	if a.Recursive != nil {
		return runRecursive(a, send, limiter, col)
	}

	results := make(chan outcome, 64)
	// enumerated is how many plan positions the loop actually reached. A stopped attack's report must
	// not present its planned count as the denominator of what happened — see AttackReport.Enumerated.
	enumerated := 0
	go func() {
		defer close(results)
		var wg sync.WaitGroup
		var asg Assignment
		// The baseline (v34) is ordinal 0 and every plan ordinal shifts by one: Burp shows it
		// as item 0 ("Baseline request (no payloads)", position -1 in Zrpq), and the results
		// table's whole point is that the attack responses hang after something to compare
		// against. Sent through the same doSend, so its response is bucketed, grepped, and
		// recorded exactly like an attack row — a baseline the pipeline treated specially
		// would not be comparable with the rows it exists to be compared against.
		if a.Baseline {
			if a.Control.gate() {
				if a.SuiteGate != nil {
					a.SuiteGate(context.Background())
				}
				// The baseline is "the template request with all payload positions set to their
				// base values" — the request the attack rows are compared against. It therefore
				// carries the same egress settings every attack row does: a baseline sent without
				// Connection: close while every attack row has it would make the one row that
				// exists to be comparable the one row that is not.
				baseReq := a.egress(a.Base)
				permit := limiter.Acquire()
				if a.Guard != nil {
					if err := a.Guard(baseReq); err != nil {
						permit.Release()
						results <- outcome{ordinal: 0, err: err, sentAt: time.Now()}
					} else {
						wg.Add(1)
						go func() {
							defer wg.Done()
							defer permit.Release()
							sentAt := time.Now()
							h, err := doSend(a, limiter, send, baseReq, nil, ctx)
							if h != nil {
								h.request = baseReq
							}
							results <- outcome{ordinal: 0, hit: h, err: err, sentAt: sentAt}
						}()
					}
				} else {
					wg.Add(1)
					go func() {
						defer wg.Done()
						defer permit.Release()
						sentAt := time.Now()
						h, err := doSend(a, limiter, send, baseReq, nil, ctx)
						if h != nil {
							h.request = baseReq
						}
						results <- outcome{ordinal: 0, hit: h, err: err, sentAt: sentAt}
					}()
				}
			}
		}
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
			// gateForSend, not limiter.Acquire: the gate above ran before this ordinal queued for
			// an in-flight slot, and a pause raised WHILE it queued — which is every auto-pause,
			// since the predicate reads the response of the send that frees the slot — was
			// invisible to it. Re-asking with the permit in hand is what makes a halt halt the
			// next request rather than the one after it (burpsy-react-ui-xqwe). nil is stopped.
			//
			// Above enumerated++, so a stop here does not put a position the attack never sent
			// into the report's denominator: Enumerated is what the loop reached, and this
			// ordinal was abandoned before it reached anything.
			permit := gateForSend(a.Control, limiter)
			if permit == nil {
				break
			}
			enumerated++
			places := make([]ApplyPlace, 0, len(asg.Slots))
			payloads := make([][]byte, 0, len(asg.Slots))
			probes := make([]reflectProbe, 0, len(asg.Slots))
			for _, s := range asg.Slots {
				if s.Point < 0 || s.Point >= len(a.Points) ||
					s.Set < 0 || s.Set >= len(a.setBytes) ||
					s.Payload < 0 || s.Payload >= len(a.setBytes[s.Set]) {
					continue
				}
				payload := a.setBytes[s.Set][s.Payload]
				places = append(places, ApplyPlace{Point: &a.Points[s.Point], Payload: payload})
				payloads = append(payloads, payload)
				probes = append(probes, a.probe(s.Set, s.Payload))
			}

			// applyAllChecked, not ApplyAll: a payload its container cannot hold is dropped from
			// the splice, and the request built from what remains is the BASE request for a
			// single-position attack. Sending that would put an unmodified request in the report
			// among the real sends, indistinguishable from a payload that was actually tried
			// (burpsy-react-ui-194b). The attempt is recorded with the enumerator's own reason and
			// never sent, which is the same shape the guard refusal below already takes.
			req, refusals := applyAllChecked(a.Base, places)
			// Stored once per ordinal and shared by every outcome this ordinal can produce — the
			// send, the refusal and the guard failure — so a report that names payloads names them
			// on the rows where the operator most needs them. nil when the attack did not ask.
			stored := a.storedPayloads(payloads)
			collab := a.collaboratorPayloads(asg.Slots)
			if len(refusals) > 0 {
				permit.Release()
				results <- outcome{ordinal: baselineShift(a) + i, err: errPayloadRefused(refusals), sentAt: time.Now(), payloads: stored, collab: collab}
				continue
			}
			req = a.egress(req)
			if a.Guard != nil {
				if err := a.Guard(req); err != nil {
					permit.Release()
					results <- outcome{ordinal: baselineShift(a) + i, err: err, sentAt: time.Now(), payloads: stored, collab: collab}
					continue
				}
			}
			wg.Add(1)
			go func(ordinal int, raw []byte, probes []reflectProbe, stored []string, permit *Permit) {
				defer wg.Done()
				defer permit.Release()
				// Captured here, not before the permit or the guard: this is the closest point to the
				// actual send that every ordinal passes through, so it is what Attempt.TimeOfDay means
				// by "the time of day the request was made" — a rate-limiter wait or a guard refusal
				// must not be counted as part of it.
				sentAt := time.Now()
				defer func() {
					if r := recover(); r != nil {
						results <- outcome{ordinal: ordinal, err: fmt.Errorf("send task failed: %v", r), sentAt: sentAt, payloads: stored, collab: collab}
					}
				}()
				h, err := doSend(a, limiter, send, raw, probes, ctx)
				if h != nil {
					h.request = raw
				}
				results <- outcome{ordinal: ordinal, hit: h, err: err, sentAt: sentAt, payloads: stored, collab: collab}
			}(baselineShift(a)+i, req, probes, stored, permit)
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

// runRecursive drives Burp's Recursive grep chain (ztuu): send the current payload, extract the
// next from the response, repeat. Ported from Zccc.Zt's stop conditions — current payload nil
// (the extraction matched nothing) or stop-duplicate with current == previous — and the driver
// is serial by construction, the same constraint Burp imposes (its resource pool is forced to
// max concurrent 1 for these attacks; Zsvp.Zx).
//
// Every attempt flows through the same collector, recorder, guard, limiter and control gates
// the plan-driven loop uses, so a chain's rows, buckets, exemplars and dashboard progress are
// indistinguishable from any other attack's — the operator's pause and stop work mid-chain.
func runRecursive(a *Attack, send SendFn, limiter *RateLimiter, col *collector) *AttackReport {
	started := time.Now()
	ctx := context.Background()
	// The initial payload is the first set's first item: Resolve put it there (payload.go), so
	// the wire contract's "payload_sets" and the chain agree on where the chain starts.
	if len(a.Sets) == 0 || len(a.setBytes) == 0 || len(a.setBytes[0]) == 0 {
		// Nothing to start from. Reported as an empty, completed attack rather than an error:
		// the caller validated the source shape before attaching the driver, and the honest
		// answer to "what did the chain do" with no initial payload is "nothing".
		return col.finish(a, limiter, time.Since(started), 0)
	}
	current := a.setBytes[0][0]
	ordinal := 0
	// Chained is the honest denominator: unlike a plan, the chain's length is not known until it
	// ends, so every field the report derives from "enumerated" counts what actually ran.
	chained := 0
	// chainPayloads is the per-ordinal record the wire view needs (ztuu): plan arithmetic
	// cannot name a response-derived payload, so the driver writes each one down as it goes.
	chainPayloads := []string{}
	for {
		if !a.Control.gate() {
			break
		}
		if a.SuiteGate != nil {
			a.SuiteGate(context.Background())
		}
		if ordinal >= a.Plan.maxRequests {
			break
		}
		chained++
		chainPayloads = append(chainPayloads, string(current))
		places := make([]ApplyPlace, 0, len(a.Points))
		payloads := make([][]byte, 0, len(a.Points))
		for i := range a.Points {
			places = append(places, ApplyPlace{Point: &a.Points[i], Payload: current})
			payloads = append(payloads, current)
		}
		permit := limiter.Acquire()
		// See the plan loop: a refused payload must be recorded, not sent as the base request.
		req, refusals := applyAllChecked(a.Base, places)
		// The chain already records its payloads per ordinal unconditionally (ChainPayloads) —
		// plan arithmetic cannot name a response-derived payload, so the driver has no choice.
		// Attempt.Payloads is still filled when asked, so a row means the same thing whichever
		// driver produced it and a reader does not need to know which one did.
		stored := a.storedPayloads(payloads)
		if len(refusals) > 0 {
			permit.Release()
			col.absorb(outcome{ordinal: ordinal, err: errPayloadRefused(refusals), sentAt: time.Now(), payloads: stored})
			a.Control.note(false)
			// Nothing was sent, so there is no response to extract the chain's next payload from —
			// the same reason the guard refusal below stops rather than retrying the same bytes.
			break
		}
		req = a.egress(req)
		if a.Guard != nil {
			if err := a.Guard(req); err != nil {
				permit.Release()
				col.absorb(outcome{ordinal: ordinal, err: err, sentAt: time.Now(), payloads: stored})
				// The live progress view is fed here too, not only on the success path: this
				// outcome is a settled failure and the report will count it, and control.go's
				// contract is that a poll cannot disagree with the report. Leaving it out made a
				// chain that died on a guard refusal report failed=1 while the view said 0.
				a.Control.note(false)
				// A refused request produced no response to extract from: the chain's next
				// payload is unknowable, and continuing with the same one would resend bytes
				// the guard just refused. Stop, the refusal is already counted.
				break
			}
		}
		sentAt := time.Now()
		// The chain's one payload set: response-derived, never URL-encoded, so both forms are the bytes
		// that were sent.
		h, err := doSend(a, limiter, send, req, []reflectProbe{{set: 0, sent: current, pre: current}}, ctx)
		// Released immediately after the send, matching the plan loop's defer-permit in its
		// goroutine (which releases the moment doSend returns): the serial driver holds one
		// permit across exactly one request, and holding it across the extraction would
		// deadlock the chain at max_in_flight=1 — the very limit this driver runs under.
		permit.Release()
		if err != nil {
			col.absorb(outcome{ordinal: ordinal, err: err, sentAt: sentAt, payloads: stored})
			// Same as the guard refusal above: a counted failure is a settled failure.
			a.Control.note(false)
			// Same reasoning as the guard refusal: no response, no extraction, no chain. The
			// error is counted; a retry loop that re-derived payloads would be a different
			// feature (Burp's retry settings, n39).
			break
		}
		h.request = req
		col.absorb(outcome{ordinal: ordinal, hit: h, sentAt: sentAt, payloads: stored})
		a.Control.note(true)

		next, ok := a.Recursive.extract(h.raw)
		if !ok {
			// Zccc's first stop: the extraction matched nothing. The chain is complete, not
			// failed — "the exercise is complete" is Burp's own reading of an extraction that
			// stops matching.
			break
		}
		if a.Recursive.StopDuplicate && string(next) == string(current) {
			// Zccc's second stop: stop-if-duplicate. The comparison is next against the payload
			// just sent — Zccc compares its newly-derived payload (var3, from ZL1) with the one
			// before it (var4, ZLj) — i.e. "the same payload is derived twice in succession",
			// not "any payload ever seen".
			break
		}
		current = []byte(next)
		ordinal++
	}
	a.Control.complete()
	col.chain = chainPayloads
	return col.finish(a, limiter, time.Since(started), chained)
}

// baselineShift is the ordinal offset the baseline request (v34) introduces: 1 when the attack
// sends one, 0 otherwise. A function of the attack, not a captured variable, so the plan loop
// and the wire view (payloadsAt's ordinal) agree on the shift without sharing state.
func baselineShift(a *Attack) int {
	if a.Baseline {
		return 1
	}
	return 0
}

// doSend runs one request: send (retrying network failures per Burp's error-handling settings,
// n39), observe the limiter, ask the reflection and grep questions.
//
// The retry lives here and nowhere else because this is the one function every request passes
// through — the plan loop's goroutines and the recursive chain's serial driver both land here —
// so a retry cannot be forgotten on one path and double-counted on another. A retried request
// is still ONE attempt: the Attempt row and the buckets describe what the target finally
// answered, and the retry count rides the report separately.
//
// A send error whose context is already done is not a failure to retry — it is the attack (or
// the operator) giving up — so ctx.Err() short-circuits before the loop.
func doSend(a *Attack, limiter *RateLimiter, send SendFn, raw []byte, probes []reflectProbe, ctx context.Context) (*hit, error) {
	sent, err := send(raw)
	for attempt := 0; err != nil && attempt < a.Retries && ctx.Err() == nil; attempt++ {
		if !a.retryWait(ctx) {
			break // stopped mid-pause: the give-up wins over the retry
		}
		a.retriesUsed.Add(1)
		sent, err = send(raw)
	}
	if err != nil {
		return nil, err
	}
	limiter.Observe(sent.Status)
	// Grep - Payloads (7qc3), with the attack's settings; the legacy settings ask exactly the old
	// question — any payload, as sent, case-sensitive, anywhere in the response.
	reflected, reflectedCounts := a.reflection(sent.Raw, probes)
	grepMatched, grepExtract := a.Grep.run(sent.Raw)
	grepCounts := a.Grep.MatchList.counts(sent.Raw)
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
		reflected: reflected, reflectedCounts: reflectedCounts, grepMatched: grepMatched, grepExtract: grepExtract,
		grepCounts: grepCounts, raw: sent.Raw, cookies: cookies,
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

// emptyCounts is the never-nil wire guard for the per-expression count arrays: no list
// configured means [] on the wire, not null (the same contract newCollector's nil-slice note
// holds the row slices to).
func emptyCounts(counts []int) []int {
	if counts == nil {
		return []int{}
	}
	return counts
}

func derefInt(p *int) int {
	if p == nil {
		return 0
	}
	return *p
}
