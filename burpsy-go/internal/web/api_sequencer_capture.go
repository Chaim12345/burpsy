package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/burpsy-go/burpsy/internal/dash"
	"github.com/burpsy-go/burpsy/internal/sender"
	"github.com/burpsy-go/burpsy/internal/sequencer"
	"github.com/burpsy-go/burpsy/internal/toollog"
)

// Sequencer capture (HONEST-02).
//
// # What was here before
//
// Three routes that described a capture phase which did not exist. GET
// /api/sequencer/capture/{id} answered `{"total": 0, "tokens": []}` — a shape indistinguishable from
// a real capture that had genuinely collected nothing — from a captureTokens() helper whose entire
// body was `return nil`. POST /api/sequencer/capture/stop answered `{"stopped": true}` for a loop
// that had never been started, on any verb. There was no route to start one at all.
//
// That is the defect class AGENTS.md names: code that makes a partial result look complete. An
// operator reading "0 tokens" concluded the application's session tokens were unreadable, when the
// truth was that nothing had ever asked for one. The UI knew, and carried a warning notice
// explaining that the endpoints were decorative — a design that documents its own dishonesty rather
// than removing it.
//
// # What is here now
//
// A real loop. It sends the operator's request N times through a sender.AuthorisedSender bound to the
// engagement scope — so the scope decision is made on the bytes, per send, not on a host-level
// pre-filter — extracts one token per response from a location the operator declares, and
// accumulates them into a
// sequencer.TokenList that /api/sequencer/analyse can then analyse. Progress rides on a dash task, so
// a capture in flight is visible on the dashboard rather than only in the tab that started it.
//
// Three things it deliberately does not do:
//
//   - It does not guess where the token is. Burp asks the operator to select it, because a heuristic
//     that picks the wrong cookie produces a confident entropy verdict about the wrong string, which
//     is worse than no verdict. An unparseable location is a 400.
//   - It does not report a token it did not extract. A response with no token at the declared
//     location increments a miss count with the reason, and the miss count is on the wire — an
//     analysis over 40 tokens from 200 requests is a different claim than one over 200.
//   - It does not pretend to have stopped something. /stop reports how many captures it actually
//     signalled, which is zero when none was running.

// tokenLocation says where in a response the token lives. The operator declares it; nothing here
// infers it.
type tokenLocation struct {
	// Kind is "cookie", "header", "form_field" or "body_regex".
	Kind string `json:"kind"`
	// Name is the cookie or header name, for those two kinds. Matched case-insensitively, because
	// header names are case-insensitive on the wire and Set-Cookie names in practice are not typed
	// consistently by operators either.
	Name string `json:"name,omitempty"`
	// Pattern is an RE2 regexp for body_regex. The token is capture group 1 when the pattern has one,
	// and the whole match otherwise — so `csrf"\s*:\s*"([^"]+)"` works without further ceremony.
	Pattern string `json:"pattern,omitempty"`

	re *regexp.Regexp
}

// formFieldRe matches the value-bearing form controls a token travels in: input, select and
// textarea, self-closing or not. The value attribute is captured when quoted — the only shape
// that survives HTML's quoting rules — and the attribute run before '>' is captured so the
// name can be matched case-insensitively without rebuilding the tag.
var formFieldRe = regexp.MustCompile(`(?i)<(?:input|select|textarea)((?:[^>"']|"[^"]*"|'[^']*')*)value\s*=\s*("([^"]*)"|'([^']*)')`)

// Describe is the location as one operator-facing line, for the task target and the capture note.
func (loc tokenLocation) Describe() string {
	switch strings.ToLower(loc.Kind) {
	case "cookie":
		return "cookie " + loc.Name
	case "header":
		return "header " + loc.Name
	case "form_field":
		return "form field " + loc.Name
	case "body_regex":
		return "body /" + loc.Pattern + "/"
	}
	return "unknown location"
}

// compile validates the location and prepares it for use, returning why it is unusable rather than
// falling back to a default. Defaulting here would mean analysing whichever string a guess landed on.
func (loc *tokenLocation) compile() error {
	loc.Kind = strings.ToLower(strings.TrimSpace(loc.Kind))
	loc.Name = strings.TrimSpace(loc.Name)
	switch loc.Kind {
	case "cookie", "header", "form_field":
		if loc.Name == "" {
			return fmt.Errorf("a %s location needs the %s name to read the token from", loc.Kind, loc.Kind)
		}
		return nil
	case "body_regex":
		if strings.TrimSpace(loc.Pattern) == "" {
			return fmt.Errorf("a body_regex location needs a pattern")
		}
		re, err := regexp.Compile(loc.Pattern)
		if err != nil {
			return fmt.Errorf("pattern does not compile: %w", err)
		}
		loc.re = re
		return nil
	case "":
		return fmt.Errorf(`no token location given: pass {"kind":"cookie","name":"SESSIONID"}, ` +
			`{"kind":"header","name":"X-Token"}, {"kind":"form_field","name":"csrf_token"} ` +
			`or {"kind":"body_regex","pattern":"..."}`)
	default:
		return fmt.Errorf("unknown token location kind %q: want cookie, header, form_field or body_regex", loc.Kind)
	}
}

// extract pulls the token out of one response, or explains why it could not.
//
// The error is kept because it is reported: a capture that misses is a capture whose sample is
// smaller than the operator asked for, and the reason is the difference between "the app stopped
// setting the cookie after 30 requests" and "the name is misspelled".
func (loc tokenLocation) extract(response []byte) (string, error) {
	head, body := splitHeadBody(response)
	switch loc.Kind {
	case "cookie":
		for _, value := range headerValues(head, "Set-Cookie") {
			pair, _, _ := strings.Cut(value, ";")
			name, token, ok := strings.Cut(pair, "=")
			if ok && strings.EqualFold(strings.TrimSpace(name), loc.Name) {
				if token = strings.TrimSpace(token); token != "" {
					return token, nil
				}
				return "", fmt.Errorf("cookie %s was set to an empty value", loc.Name)
			}
		}
		return "", fmt.Errorf("no Set-Cookie for %s in this response", loc.Name)
	case "header":
		for _, value := range headerValues(head, loc.Name) {
			if value = strings.TrimSpace(value); value != "" {
				return value, nil
			}
		}
		return "", fmt.Errorf("no %s header in this response", loc.Name)
	case "form_field":
		// Burp's "Form field" location (6t8): the value of an input/select/textarea by name —
		// the shape anti-CSRF and per-page tokens travel in. Parsed, not regexed, so the
		// operator picks a name off a list instead of writing HTML-aware patterns; matched
		// case-insensitively because HTML attribute names are case-insensitive and authors are
		// not consistent about it.
		name := strings.ToLower(loc.Name)
		for _, m := range formFieldRe.FindAllSubmatch(body, -1) {
			// m[1] = attributes between the tag name and '>'; the value landed in group 3
			// (double-quoted) or group 4 (single-quoted), whichever matched. Name matching is
			// case-insensitive over the attribute run because HTML attribute names are
			// case-insensitive and authors are not consistent about quoting either.
			attrs := strings.ToLower(string(m[1]))
			if !strings.Contains(attrs, `name="`+name+`"`) && !strings.Contains(attrs, "name='"+name+"'") {
				continue
			}
			value := strings.TrimSpace(string(m[3]))
			if value == "" {
				value = strings.TrimSpace(string(m[4]))
			}
			if value == "" {
				return "", fmt.Errorf("form field %s has an empty value in this response", loc.Name)
			}
			return value, nil
		}
		return "", fmt.Errorf("no form field named %s in this response", loc.Name)
	case "body_regex":
		m := loc.re.FindSubmatch(body)
		if m == nil {
			return "", fmt.Errorf("pattern did not match the response body")
		}
		// Group 1 when the pattern has one — the usual shape for pulling a token out of surrounding
		// markup — and the whole match otherwise.
		token := m[0]
		if len(m) > 1 {
			token = m[1]
		}
		if len(token) == 0 {
			return "", fmt.Errorf("pattern matched an empty string")
		}
		return string(token), nil
	}
	return "", fmt.Errorf("unknown token location kind %q", loc.Kind)
}

// splitHeadBody divides a raw response at the header terminator, tolerating bare-LF line endings.
// A response with no terminator at all is all head and no body, which is what a truncated response
// actually is.
func splitHeadBody(raw []byte) (head, body []byte) {
	if i := strings.Index(string(raw), "\r\n\r\n"); i >= 0 {
		return raw[:i], raw[i+4:]
	}
	if i := strings.Index(string(raw), "\n\n"); i >= 0 {
		return raw[:i], raw[i+2:]
	}
	return raw, nil
}

// headerValues returns every value for a header name, case-insensitively. Every value, not the first:
// Set-Cookie legitimately repeats, and taking only one would read the wrong cookie on any application
// that sets more than one.
func headerValues(head []byte, name string) []string {
	var out []string
	lines := strings.Split(strings.ReplaceAll(string(head), "\r\n", "\n"), "\n")
	for _, line := range lines[min(1, len(lines)):] { // skip the status line
		key, value, ok := strings.Cut(line, ":")
		if ok && strings.EqualFold(strings.TrimSpace(key), name) {
			out = append(out, strings.TrimSpace(value))
		}
	}
	return out
}

// captureMiss is one response that carried no token, kept with its reason.
type captureMiss struct {
	Attempt int    `json:"attempt"`
	Reason  string `json:"reason"`
}

// sequencerCapture is one run of the loop.
type sequencerCapture struct {
	mu sync.Mutex

	id       uint64
	taskID   uint64
	target   string
	location tokenLocation

	requested int
	// lengthDeviates is Burp's length-deviation filter: 0 disables it, N drops tokens whose
	// length differs from the running average by more than N. The average is over tokens this
	// capture already accepted, which is exactly the reference the operator means — the normal
	// token this location produces.
	lengthDeviates int
	// tokenCount/tokenLenSum maintain the running average the filter compares against, both
	// written on the worker that accepted the token under c.mu.
	tokenCount  int
	tokenLenSum int
	attempts    int
	tokens      *sequencer.TokenList
	// misses is bounded: a capture of 5000 requests against a misspelled cookie name would otherwise
	// accumulate 5000 identical strings. The count is exact; the examples are a sample, and say so.
	misses    []captureMiss
	missCount int
	running   bool
	// pauseRequested is what the API writes; pausedAtGate is what the loop reports once it has
	// actually stopped between sends. The split is the honest part of the feature: a pause lands
	// between sends, so the one send already on the wire when the request arrives still records —
	// and until the loop reaches the gate, the capture is NOT paused, whatever the request said.
	// Reporting the request flag would let the view claim a state the loop is not in, and a
	// sample that grows "while paused" is exactly the lie this project does not ship.
	// (burpsy-react-ui-5kx)
	pauseRequested bool
	pausedAtGate   bool
	// claimed is the send-claim counter for the worker pool (burpsy-react-ui-9t1): a promise
	// to send, distinct from attempts (a settled send). CAS-advanced so two workers cannot
	// hold the same ordinal; the sequential loop's `attempt() < requested` check was safe
	// only because one goroutine ran it.
	claimed    atomic.Int64
	startedMs  int64
	endedMs    int64
	stopReason string
}

// maxRecordedMisses bounds the miss examples kept per capture. The count is never truncated.
const maxRecordedMisses = 20

// maxConsecutiveMisses is the give-up threshold shared by every capture worker: per worker the
// streak is local, and a location that never matches drives each of them to it at the same rate,
// so the guard's stop lands in the same order of magnitude of requests the sequential loop's did.
const maxConsecutiveMisses = 25

// captureView is the wire shape of a capture.
//
// Every field exists because its absence made two different situations look the same. `Requested`
// against `Total` is what turns "40 tokens" into "40 of the 200 asked for". `Running` distinguishes a
// capture still filling from one that finished. `StopReason` names why a short capture is short.
type captureView struct {
	ID        uint64 `json:"id"`
	TaskID    uint64 `json:"task_id"`
	Target    string `json:"target"`
	Location  string `json:"location"`
	Capturing bool   `json:"capturing"`
	// Paused is only meaningful while Capturing is true: a finished capture is not paused,
	// whatever the field's historical value, and the UI must not offer Resume on one.
	Paused    bool     `json:"paused"`
	Requested int      `json:"requested"`
	Attempts  int      `json:"attempts"`
	Total     int      `json:"total"`
	Tokens    []string `json:"tokens"`
	// Misses is how many responses carried no token at the declared location, with up to
	// maxRecordedMisses examples. A non-zero count is the difference between a small sample and a
	// wrong location, and the reasons are what tell those apart.
	Misses          int           `json:"misses"`
	MissExamples    []captureMiss `json:"miss_examples,omitempty"`
	MissesTruncated bool          `json:"misses_truncated"`
	StartedMs       int64         `json:"started_ms"`
	EndedMs         int64         `json:"ended_ms,omitempty"`
	StopReason      string        `json:"stop_reason,omitempty"`
}

func (c *sequencerCapture) view() captureView {
	c.mu.Lock()
	defer c.mu.Unlock()
	tokens := c.tokens.Tokens()
	return captureView{
		ID:              c.id,
		TaskID:          c.taskID,
		Target:          c.target,
		Location:        c.location.Describe(),
		Capturing:       c.running,
		Paused:          c.running && c.pausedAtGate,
		Requested:       c.requested,
		Attempts:        c.attempts,
		Total:           len(tokens),
		Tokens:          tokens,
		Misses:          c.missCount,
		MissExamples:    c.misses,
		MissesTruncated: c.missCount > len(c.misses),
		StartedMs:       c.startedMs,
		EndedMs:         c.endedMs,
		StopReason:      c.stopReason,
	}
}

// sequencerCaptures holds every capture this process has run. Bounded, because a capture holds its
// tokens and an unbounded map of them is a leak an operator cannot see.
type sequencerCaptures struct {
	mu     sync.Mutex
	byID   map[uint64]*sequencerCapture
	order  []uint64
	nextID uint64
}

// maxRetainedCaptures is how many finished captures are kept. Small on purpose: a capture's whole
// output is meant to be handed straight to /api/sequencer/analyse, and 8 covers comparing a few runs
// without holding tens of thousands of tokens for a session.
const maxRetainedCaptures = 8

func newSequencerCaptures() *sequencerCaptures {
	return &sequencerCaptures{byID: make(map[uint64]*sequencerCapture)}
}

func (set *sequencerCaptures) add(c *sequencerCapture) {
	set.mu.Lock()
	defer set.mu.Unlock()
	set.nextID++
	c.id = set.nextID
	set.byID[c.id] = c
	set.order = append(set.order, c.id)
	// Evict the oldest *finished* capture, never a running one — the same rule dash.Registry applies
	// to tasks, and for the same reason: dropping a live run answers "what is capturing?" with silence.
	for len(set.order) > maxRetainedCaptures {
		evicted := -1
		for i, id := range set.order {
			held := set.byID[id]
			held.mu.Lock()
			idle := !held.running
			held.mu.Unlock()
			if idle {
				evicted = i
				break
			}
		}
		if evicted < 0 {
			break // everything is running; overshoot honestly rather than drop a live capture
		}
		delete(set.byID, set.order[evicted])
		set.order = append(set.order[:evicted], set.order[evicted+1:]...)
	}
}

func (set *sequencerCaptures) get(id uint64) *sequencerCapture {
	set.mu.Lock()
	defer set.mu.Unlock()
	return set.byID[id]
}

// running returns every capture still filling, oldest first.
func (set *sequencerCaptures) running() []*sequencerCapture {
	set.mu.Lock()
	held := make([]*sequencerCapture, 0, len(set.order))
	for _, id := range set.order {
		held = append(held, set.byID[id])
	}
	set.mu.Unlock()
	var out []*sequencerCapture
	for _, c := range held {
		c.mu.Lock()
		live := c.running
		c.mu.Unlock()
		if live {
			out = append(out, c)
		}
	}
	return out
}

// captureSet returns the server's capture set, creating it on first use. Lazy rather than in
// NewServer so a server that never captures never allocates one, matching how `scanner` is built.
func (s *Server) captureSet() *sequencerCaptures {
	s.captureOnce.Do(func() { s.captures = newSequencerCaptures() })
	return s.captures
}

// ---- routes ------------------------------------------------------------------------------------

type sequencerCaptureReq struct {
	Target   string        `json:"target"`
	Protocol string        `json:"protocol"`
	Request  string        `json:"request"`
	Count    int           `json:"count"`
	Location tokenLocation `json:"location"`
	// DelayMs paces the loop. Sequencer captures are the one tool that deliberately hammers a single
	// endpoint, and an operator who needs to stay under a rate limit has no other way to ask.
	DelayMs int `json:"delay_ms"`
	// LengthDeviates is Burp's "Ignore token whose length deviates by X characters"
	// (settings/tools/sequencer.html): when set with Enable, tokens whose length differs from
	// the running average by more than X are dropped from the sample and counted as gated.
	// Useful when the application occasionally returns a different item where the token lives —
	// an error page where the session id was.
	LengthDeviates struct {
		Enable bool `json:"enable"`
		Chars  int  `json:"chars"`
	} `json:"length_deviates"`
	// Threads is Burp's "Number of threads" (settings/tools/sequencer.html): the maximum number of
	// concurrent requests the capture makes. 1 (or absent) is the historical sequential capture —
	// the honest default, because concurrency changes what the capture measures: a token that
	// arrives per request is unaffected, but per-request wall-clock pacing (delay) becomes a lower
	// bound shared across the pool, and an endpoint that serialises logins server-side will show a
	// capture that looks slower without producing worse tokens. The operator opts into that.
	Threads int `json:"threads"`
}

// maxCaptureCount bounds one capture at Burp's own maximum: 20,000 is what the FIPS 140-2
// statistical battery takes a formally compliant sample of, and the page presents FIPS
// results — a live capture that could not reach the compliant size would make that claim
// unreachable no matter how long the operator let it run. The default stays far below at
// 100; the bound is a ceiling on what can be ASKED for, so a typo in the count field still
// cannot commit the tool to a million requests against an engagement target
// (burpsy-react-ui-vhs0).
const maxCaptureCount = 20000

// defaultCaptureCount is what an unspecified count means. 100 matches Burp's default sample size and
// is enough for FIPS bit-level tests to report at all.
const defaultCaptureCount = 100

// maxCaptureThreads bounds the concurrency pool. Burp's own default is a handful; a pool wider than
// the bound would out-race the view's polling and the miss-streak guard's meaning (25 misses is a
// wrong location at 1 thread and a rounding error at 500). 32 keeps a capture from opening more
// sockets than the store can absorb.
const maxCaptureThreads = 32

// handleSequencerCaptureStart serves POST /api/sequencer/capture, beginning a real capture.
func (s *Server) handleSequencerCaptureStart(w http.ResponseWriter, r *http.Request) {
	var req sequencerCaptureReq
	if err := requestJSON(w, r, nil).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	host, port, tls, err := targetParts(req.Target)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if strings.EqualFold(req.Protocol, "https") {
		tls = true
	} else if strings.EqualFold(req.Protocol, "http") {
		tls = false
	}
	if strings.TrimSpace(req.Request) == "" {
		http.Error(w, "Empty request: a capture needs the request whose response carries the token", http.StatusBadRequest)
		return
	}
	if err := req.Location.compile(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	threads := req.Threads
	if threads <= 0 {
		threads = 1
	}
	if threads > maxCaptureThreads {
		http.Error(w, fmt.Sprintf("threads is capped at %d; a pool that wide out-races the miss-streak guard's meaning", maxCaptureThreads), http.StatusBadRequest)
		return
	}
	count := req.Count
	if count <= 0 {
		count = defaultCaptureCount
	}
	if count > maxCaptureCount {
		http.Error(w, fmt.Sprintf("count %d exceeds the %d-request bound on one capture", count, maxCaptureCount),
			http.StatusBadRequest)
		return
	}
	if req.DelayMs < 0 {
		http.Error(w, "delay_ms cannot be negative", http.StatusBadRequest)
		return
	}
	lengthDeviates := 0
	if req.LengthDeviates.Enable {
		// 0 enabled would drop nothing but still cost the average check per token; requiring a
		// real bound keeps the setting meaning what it says.
		if req.LengthDeviates.Chars < 1 || req.LengthDeviates.Chars > 1000 {
			http.Error(w, "length_deviates.chars must be between 1 and 1000 when enabled", http.StatusBadRequest)
			return
		}
		lengthDeviates = req.LengthDeviates.Chars
	}
	// Same host-level gate as Repeater and Intruder, and for the same reason: a capture is the most
	// request-hungry thing in the tool, so a scope the operator set to constrain outbound traffic
	// must not be bypassable by starting one.
	if !s.scope.MayContainHost(host, port, tls) {
		http.Error(w, "refused: "+s.scope.Explain(host, port, "/", tls), http.StatusForbidden)
		return
	}
	if s.sender == nil {
		// Reported rather than 500'd, the house pattern for an unwired dependency.
		http.Error(w, "no authorised sender is wired, so no request can be sent", http.StatusServiceUnavailable)
		return
	}

	capture := &sequencerCapture{
		target:         req.Target,
		location:       req.Location,
		requested:      count,
		lengthDeviates: lengthDeviates,
		tokens:         sequencer.NewTokenList(),
		running:        true,
		startedMs:      time.Now().UnixMilli(),
	}
	s.captureSet().add(capture)

	task := s.tasks.Start(dash.KindSequencerCapture,
		fmt.Sprintf("%s → %s", req.Target, req.Location.Describe()), uint64(count))
	capture.taskID = task.ID()

	// Not r.Context(): the capture outlives the request that started it, and a context cancelled when
	// this handler returns would stop the loop on the first iteration. context.Background() derived
	// through the task handle is what makes it cancellable by /stop instead.
	// One authorising sender for the whole capture, the intruder's pattern rather than the repeater's.
	// The repeater takes the weaker host-level-only path because the operator edits the request between
	// every send and is present for each one; a capture sends unattended, hundreds of times, so the
	// scope decision belongs on the bytes — AuthorisedSender.authorityOf re-derives the authority from
	// the request line, which is the check a host-level pre-filter cannot make.
	auth := sender.NewAuthorisedSender(s.scope, s.sender, host, port, tls)
	ctx, cancel := task.WithCancel(context.Background())
	// The capture loop calls GateCheck between sends, so this row's own Pause reaches it (g0ba).
	ctx = task.Pausable(ctx)
	go func() {
		defer cancel()
		s.runCapture(ctx, capture, task, auth, host, port, tls, []byte(req.Request),
			time.Duration(req.DelayMs)*time.Millisecond, threads)
	}()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(capture.view())
}

// runCapture is the loop. It sends the same request `requested` times, extracting one token per
// response, and stops early on cancellation.
func (s *Server) runCapture(ctx context.Context, capture *sequencerCapture, task *dash.Handle,
	auth *sender.AuthorisedSender, host string, port uint16, tls bool, request []byte, delay time.Duration, threads int) {

	// consecutiveMisses gives up on a location that is never going to match rather than sending the
	// operator's full count into a wall. The threshold is generous, because an application that sets
	// its cookie only on some responses is a real and interesting case — the point is to stop a
	// misspelled cookie name from costing 5000 requests, not to second-guess a sparse token.
	// maxConsecutiveMisses is a package const (below) so the pool's noteMiss shares it.

	// claimIssues hands out the next attempt ordinal, or false when the capture has sent enough.
	// Atomic claim rather than a channel of ordinals: the pool size is bounded (maxCaptureThreads)
	// and the claim is the loop's only shared decision.
	claim := func() (int, bool) {
		for {
			n := capture.sentCount()
			if n >= capture.requested {
				return 0, false
			}
			if capture.claimNext(n) {
				return n + 1, true
			}
		}
	}

	var wg sync.WaitGroup
	giveUp := make(chan string, 1) // first worker to hit the miss ceiling reports it; capacity 1, rest dropped
	for w := 0; w < threads; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			consecutive := int32(0)
			for {
				// An issuance from another worker's give-up ends this worker cleanly: the capture
				// is finished already, and its finish() is idempotent.
				select {
				case <-ctx.Done():
					// The closer classifies cancellation after the pool drains: several workers
					// see it at once, and exactly one Stop must land.
					return
				case reason := <-giveUp:
					capture.finish(reason)
					task.Stop(capture.breakdown(), capture.reason())
					return
				default:
				}

				if _, ok := claim(); !ok {
					return // the count is satisfied; the closer below finishes the capture
				}

				// Both pauses gate between sends, never inside one: the response in flight is
				// always recorded whole. Same placement as the single-threaded loop this pool
				// replaced — one gate for the capture's own switch and the dashboard's.
				capture.waitWhilePaused(ctx)
				s.tasks.GateCheck(ctx)

				sent, err := auth.Send(ctx, request)
				response, elapsed := sent.Raw, sent.Duration
				attempt := capture.recordAttempt()
				if err != nil {
					// A transport failure is a miss with a reason, not a token. Logged through the tool log
					// so the request appears in Logger like every other egress this process performs.
					// nil rather than len(sent.Raw): on a transport failure there is no response, and the zero
					// bytes sitting in Raw are the absence of one, not a measurement of one.
					s.toolLog.Record(toollog.ToolSequencer, host, port, tls, "CAPTURE", "", 0, nil,
						uint64(elapsed.Milliseconds()), err.Error(), nil)
					capture.miss(attempt, "send failed: "+err.Error())
					if capture.noteMiss(&consecutive) {
						// This worker made the give-up decision, so it stops claiming work now: continuing
						// would send on, since the reason may sit in the channel until another worker's
						// select reaches it — and that overshoot was scheduling-dependent, not bounded
						// (burpsy-react-ui-zqrm, finding 3). The reason is handed on through the channel;
						// the worker that receives it (or the closer, below) does the one finish+Stop.
						select {
						case giveUp <- fmt.Sprintf("gave up after %d consecutive failures; last: %s", maxConsecutiveMisses, err.Error()):
						default:
						}
						return
					}
					continue
				}
				statusCode := 0
				if sent.Status != nil {
					statusCode = *sent.Status
				}
				s.toolLog.Record(toollog.ToolSequencer, host, port, tls, "CAPTURE", "", statusCode,
					toollog.Bytes(len(response)), uint64(elapsed.Milliseconds()), "", nil)

				token, err := capture.location.extract(response)
				if err != nil {
					capture.miss(attempt, err.Error())
					if capture.noteMiss(&consecutive) {
						// Same give-up discipline as the send-failure branch: post the reason, stop here.
						select {
						case giveUp <- fmt.Sprintf("gave up after %d consecutive responses with no token at %s: %s",
							maxConsecutiveMisses, capture.location.Describe(), err.Error()):
						default:
						}
						return
					}
					continue
				}
				// A hit resets the worker's own streak; the global guard reads the workers' last
				// states through noteMiss's accounting, so one lucky hit per worker is honoured.
				atomic.StoreInt32(&consecutive, 0)
				// Burp's length-deviation filter (burpsy-react-ui-rcs): a token whose length is
				// far from the average is the application occasionally returning a different item
				// where the token normally lives. Dropped from the sample and counted as gated —
				// it happened, it just is not a token — and the streak resets like a hit, because
				// for the location it IS a hit: the location worked, the value is the outlier.
				if limit := capture.lengthDeviates; limit > 0 {
					if avg := capture.tokenAverage(); avg >= 0 && absDiff(len(token), avg) > limit {
						capture.miss(attempt, fmt.Sprintf(
							"token dropped: length %d deviates from the %d-token average of %d by more than %d",
							len(token), capture.tokenCount, avg, limit))
						task.Advance(1)
						continue
					}
				}
				capture.acceptToken(token)
				task.Advance(1)

				if delay > 0 {
					select {
					case <-ctx.Done():
						// Checked here too, so a paced capture answers a stop within one delay rather than
						// sleeping through it.
					case <-time.After(delay):
					}
				}
			}
		}()
	}
	wg.Wait()
	// The end-of-capture bookkeeping must distinguish three endings: the count satisfied
	// (done), a give-up (already Stopped by the reporting worker), and cancellation (stopped
	// — a cancelled capture is not a completed one, and the dashboard must not read it as
	// such). The old sequential loop called task.Stop inline on cancellation; with a pool,
	// several workers see ctx.Done at once, so the closer owns the classification.
	// A give-up reason may still be buffered: the tripper posts and returns without finishing,
	// so the closer — not a racing worker's select — owns the finish+Stop. Drained before the
	// cancellation branch, so an operator stop and a give-up landing together report the give-up:
	// it says what the capture actually died of, and the miss streak that tripped it predates the
	// operator's button.
	select {
	case reason := <-giveUp:
		capture.finish(reason)
		task.Stop(capture.breakdown(), capture.reason())
		return
	default:
	}
	if ctx.Err() != nil {
		capture.finish("stopped by the operator after " + strconv.Itoa(capture.attempt()) + " of " +
			strconv.Itoa(capture.requested) + " requests")
		task.Stop(capture.breakdown(), capture.reason())
		return
	}
	capture.finish("")
	task.FinishWithNote(capture.breakdown(), capture.reason())
}

// sentCount reads the claim counter. Claims and attempts are deliberately separate: a claim is a
// promise to send, an attempt is a settled send. The pool claims under an atomic CAS so two workers
// cannot hold the same ordinal — the sequential loop's `attempt() < requested` check was safe only
// because one goroutine ran it.
func (c *sequencerCapture) sentCount() int {
	return int(c.claimed.Load())
}

// claimNext CAS-advances the claim counter from n. Returns false when another worker won the race,
// and the caller re-reads — the loser spins back into claim, which re-checks the bound itself.
func (c *sequencerCapture) claimNext(n int) bool {
	return c.claimed.CompareAndSwap(int64(n), int64(n+1))
}

// noteMiss advances a worker's miss streak against the global guard. The streak is per-worker
// (each worker's own consecutive failures in a row) and the ceiling trips when ANY worker's local
// run reaches it — under a pool, a location that never matches drives every worker to the ceiling
// at the same rate, so the guard's stop arrives in the same order of magnitude of requests as the
// sequential loop's did. Returns true when this call tripped it; the caller reports the give-up.
func (c *sequencerCapture) noteMiss(consecutive *int32) bool {
	return atomic.AddInt32(consecutive, 1) >= maxConsecutiveMisses
}

// waitWhilePaused blocks while the capture's own pause is set, answering cancellation each tick.
// Extracted from the loop body: with a pool, every worker runs it, and a helper beats six copies
// of one select.
func (c *sequencerCapture) waitWhilePaused(ctx context.Context) {
	if !c.isPaused() {
		return
	}
	c.gatePause(true)
	defer c.gatePause(false)
	for c.isPaused() {
		select {
		case <-ctx.Done():
			return
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// attempt and recordAttempt keep the loop's counter behind the same mutex the view reads it through.
func (c *sequencerCapture) attempt() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.attempts
}

func (c *sequencerCapture) recordAttempt() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.attempts++
	return c.attempts
}

// tokenAverage is the mean token length over the sample accepted so far, or -1 when nothing
// has been accepted: the first token has nothing to deviate from, so it can never be filtered.
// The sum is maintained on the capture loop's own thread (single writer per token accept),
// read here under the same mutex the view uses.
func (c *sequencerCapture) tokenAverage() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.tokenCount == 0 {
		return -1
	}
	return c.tokenLenSum / c.tokenCount
}

func absDiff(a, b int) int {
	if a > b {
		return a - b
	}
	return b - a
}

// acceptToken records one token into the sample and advances the running length average the
// deviation filter compares against. Under c.mu because tokenAverage reads it from any worker.
func (c *sequencerCapture) acceptToken(token string) {
	c.mu.Lock()
	c.tokens.Collect(token)
	c.tokenCount++
	c.tokenLenSum += len(token)
	c.mu.Unlock()
}

func (c *sequencerCapture) miss(attempt int, reason string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.missCount++
	if len(c.misses) < maxRecordedMisses {
		c.misses = append(c.misses, captureMiss{Attempt: attempt, Reason: reason})
	}
}

// setPaused flips the pause gate. Reports whether the capture was in a state where the request
// could apply: pausing a finished capture is a 409, not a silent success, because the UI offering
// Resume on a dead capture is worse than the error.
func (c *sequencerCapture) setPaused(paused bool) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.running {
		return false
	}
	c.pauseRequested = paused
	return true
}

// isPaused reports whether the loop should hold at the gate: the request flag, read under the
// same mutex everything else uses.
func (c *sequencerCapture) isPaused() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.pauseRequested
}

// gatePause records that the loop has reached the gate and is holding (or has resumed and is
// going again). Called by the loop, so the wire's paused flag tracks the loop, not the handler.
func (c *sequencerCapture) gatePause(held bool) {
	c.mu.Lock()
	c.pausedAtGate = held
	c.mu.Unlock()
}

func (c *sequencerCapture) finish(reason string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.running = false
	c.endedMs = time.Now().UnixMilli()
	if reason != "" {
		c.stopReason = reason
	}
}

func (c *sequencerCapture) reason() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stopReason
}

// breakdown reports the capture in the four buckets the dashboard folds. Tokens collected are found;
// responses that carried none are gated, because the request happened and produced no sample — which
// is a caveat on the count, not an error and not a success.
func (c *sequencerCapture) breakdown() dash.Breakdown {
	c.mu.Lock()
	defer c.mu.Unlock()
	collected := c.tokens.Count()
	// Skipped is the requests never sent: a capture stopped at 40 of 200 has 160 units of work with
	// no verdict, and folding them anywhere else would let a short capture read as a complete one.
	var unsent uint64
	if c.requested > c.attempts {
		unsent = uint64(c.requested - c.attempts)
	}
	return dash.Breakdown{
		Found:   uint64(collected),
		Gated:   uint64(c.missCount),
		Skipped: unsent,
	}
}

// handleSequencerCapture serves GET /api/sequencer/capture/{id} and POST /api/sequencer/capture/stop.
func (s *Server) handleSequencerCapture(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/sequencer/capture/"), "/")
	// The guard is per-sub-path because the two sub-paths are different kinds of operation, and one
	// guard for both would have to be the looser of the two. Stopping a capture changes state, so it
	// is POST; reading a token list does not, so it is GET. Unguarded, `GET .../stop` answered
	// {"stopped":true} — a state change reported for a request that could not have caused one.
	switch {
	case (path == "stop" || path == "pause" || path == "resume") && r.Method != http.MethodPost,
		path != "stop" && path != "pause" && path != "resume" && r.Method != http.MethodGet:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")

	if path == "stop" {
		s.stopCaptures(w)
		return
	}
	if path == "pause" || path == "resume" {
		// The most recent live capture is the one the UI is looking at; pausing by explicit id
		// would need a picker this page does not have, and Burp's pause button operates on the
		// capture in front of the operator too.
		live := s.captureSet().running()
		if len(live) == 0 {
			http.Error(w, "no capture is running, so nothing to "+path, http.StatusConflict)
			return
		}
		target := live[len(live)-1]
		want := path == "pause"
		if !target.setPaused(want) {
			http.Error(w, "the capture finished before the request landed", http.StatusConflict)
			return
		}
		views := make([]captureView, 0, len(live))
		for _, c := range live {
			views = append(views, c.view())
		}
		json.NewEncoder(w).Encode(map[string]any{
			"captured": views,
			"note":     "capture " + strconv.FormatUint(target.id, 10) + " " + path + "d",
		})
		return
	}
	if path == "" {
		// The index: every capture this process has run, so a UI that lost its capture id can find it
		// again instead of being told there is nothing.
		set := s.captureSet()
		set.mu.Lock()
		ids := append([]uint64(nil), set.order...)
		set.mu.Unlock()
		views := make([]captureView, 0, len(ids))
		for _, id := range ids {
			if c := set.get(id); c != nil {
				views = append(views, c.view())
			}
		}
		json.NewEncoder(w).Encode(map[string]any{"captures": views, "retained": maxRetainedCaptures})
		return
	}
	id, err := strconv.ParseUint(path, 10, 64)
	if err != nil {
		http.Error(w, "Invalid capture id", http.StatusBadRequest)
		return
	}
	capture := s.captureSet().get(id)
	if capture == nil {
		// 404 and a reason, rather than an empty capture. `{"total": 0, "tokens": []}` for an id that
		// never existed was the original defect: it reads as a capture that found nothing.
		http.Error(w, fmt.Sprintf("no capture %d: it was never started, or it aged out of the last %d",
			id, maxRetainedCaptures), http.StatusNotFound)
		return
	}
	json.NewEncoder(w).Encode(capture.view())
}

// stopCaptureResp answers /stop with what actually happened.
type stopCaptureResp struct {
	// Stopped is whether anything was signalled. False with an empty Captures list is the honest
	// answer to "stop" when nothing was running; the route used to answer true unconditionally.
	Stopped   bool          `json:"stopped"`
	Signalled int           `json:"signalled"`
	Captures  []captureView `json:"captures"`
	Note      string        `json:"note"`
}

func (s *Server) stopCaptures(w http.ResponseWriter) {
	live := s.captureSet().running()
	if len(live) == 0 {
		json.NewEncoder(w).Encode(stopCaptureResp{
			Stopped:  false,
			Captures: []captureView{},
			Note:     "no capture was running, so nothing was stopped",
		})
		return
	}
	// Cancelled through the task registry rather than by touching the capture: the loop owns its own
	// state transition, and a stop that marked the capture stopped from out here would have to invent
	// the sample count it ended on.
	signalled := s.tasks.CancelKind(dash.KindSequencerCapture)
	// Give the loop a moment to notice, so the reply carries the sample it ended with rather than the
	// one it had a tick earlier. Bounded and short: this is a courtesy, not a synchronisation point,
	// and the capture's own view is authoritative either way.
	deadline := time.Now().Add(250 * time.Millisecond)
	for time.Now().Before(deadline) {
		if len(s.captureSet().running()) == 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	views := make([]captureView, 0, len(live))
	for _, c := range live {
		views = append(views, c.view())
	}
	note := fmt.Sprintf("signalled %d running capture(s)", signalled)
	if signalled == 0 {
		// A capture was running but registered no cancel function — only reachable if the registry is
		// unwired, in which case the loop cannot be stopped and saying so beats claiming otherwise.
		note = "a capture is running but is not cancellable (no task registry is wired), so it was not stopped"
	}
	json.NewEncoder(w).Encode(stopCaptureResp{
		Stopped:   signalled > 0,
		Signalled: signalled,
		Captures:  views,
		Note:      note,
	})
}

// captureTokens is the accumulator the analyse route reads when no explicit token list is posted: the
// tokens of the most recent capture. It used to be `return nil` with a comment describing an
// accumulator that did not exist.
func (s *Server) captureTokens() []string {
	set := s.captureSet()
	set.mu.Lock()
	var newest uint64
	if len(set.order) > 0 {
		newest = set.order[len(set.order)-1]
	}
	set.mu.Unlock()
	if newest == 0 {
		return nil
	}
	if c := set.get(newest); c != nil {
		return c.tokens.Tokens()
	}
	return nil
}
