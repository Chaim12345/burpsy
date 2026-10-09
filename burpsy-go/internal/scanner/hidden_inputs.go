package scanner

// Hidden-input guessing: Burp's Param Miner workflow and its "Secret input" issues
// (burpsy-react-ui-wlz8).
//
// Burp's own documentation of the workflow (desktop/testing-workflow/analyzing/hidden-inputs):
// "Param Miner uses a built-in wordlist ... to guess at potential hidden inputs. It then sends a
// request containing each input, followed by another request with this input omitted. If the
// responses differ, this suggests that the tested header, cookie, or parameter is supported by the
// website." In Burp that is a BApp extension an operator runs from a right-click; here it is built
// in, and it is equally on-demand: nothing in the audit engine dispatches it, because it sends a few
// hundred requests per exchange that no check in an ordinary audit asked for.
//
// # The method, and why each step exists
//
//  1. Baseline, twice. The two must fingerprint identically or the run stops with "the response
//     varies on its own": a page that differs between two identical requests cannot attribute a
//     difference to a name, and guessing on it would report the page's own noise as inputs.
//  2. A control batch of nonsense names per kind. If that already changes the response, the
//     application reacts to ANY added input of this kind — it echoes the URL, or rejects unknown
//     parameters — and a change cannot be attributed to a name either. That kind stops, with the
//     reason, and its names are counted as gated rather than as tested.
//  3. Names in batches. A batch whose response differs is bisected down to single names.
//  4. Every single name is CONFIRMED before it is reported: with it (a fresh value) the response
//     differs, without it the response is the baseline, with it again it differs again. A name that
//     fails any of the three is counted as unconfirmed, not reported.
//
// Every value the guesser sends is a random token sharing a per-run tag, and every fingerprint
// strips those tokens before comparing. That is what keeps a page that merely ECHOES what it was
// sent (a canonical-URL tag, a "you searched for" line) from reading as one that reads it. A value
// that comes back in the response is separate evidence, used only when the control's values did
// not come back — otherwise echoing is the page's general behaviour, not this name's.
//
// # Every probe leaves through probeGate
//
// The same AuthorisedSender every audit probe uses, bound to the exchange's own authority, so the
// engagement scope is checked against the rendered bytes of every single guess. A refusal stops the
// run: a guesser that kept going after the scope said no would be counting refusals as "tested".

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/url"
	"regexp"
	"strings"

	"github.com/burpsy-go/burpsy/internal/core"
)

// HiddenInputKind is one of the three places Param Miner guesses: Burp's "Guess GET parameters",
// "Guess cookie parameters" and "Guess headers".
type HiddenInputKind string

const (
	HiddenInputQuery  HiddenInputKind = "query"
	HiddenInputCookie HiddenInputKind = "cookie"
	HiddenInputHeader HiddenInputKind = "header"
)

// HiddenInputKinds is every kind, in the order a run guesses them — Burp's "Guess everything!".
var HiddenInputKinds = []HiddenInputKind{HiddenInputQuery, HiddenInputCookie, HiddenInputHeader}

// IssueName is the "Secret input" issue a confirmed input of this kind is filed under.
func (k HiddenInputKind) IssueName() string {
	switch k {
	case HiddenInputQuery:
		return "Secret input: query parameter"
	case HiddenInputCookie:
		return "Secret input: cookie"
	case HiddenInputHeader:
		return "Secret input: header"
	}
	return ""
}

// ParseHiddenInputKind accepts a kind name, refusing anything it does not know rather than
// guessing nothing for it.
func ParseHiddenInputKind(s string) (HiddenInputKind, error) {
	switch k := HiddenInputKind(strings.ToLower(strings.TrimSpace(s))); k {
	case HiddenInputQuery, HiddenInputCookie, HiddenInputHeader:
		return k, nil
	}
	return "", fmt.Errorf("unknown hidden-input kind %q: expected query, cookie or header", s)
}

// HiddenInputWordlist is the built-in name list for one kind. The slice is a copy.
func HiddenInputWordlist(k HiddenInputKind) []string {
	switch k {
	case HiddenInputQuery:
		return append([]string(nil), hiddenQueryWordlist...)
	case HiddenInputCookie:
		return append([]string(nil), hiddenCookieWordlist...)
	case HiddenInputHeader:
		return append([]string(nil), hiddenHeaderWordlist...)
	}
	return nil
}

// DefaultHiddenInputBudget bounds the requests one run may send, baselines included. A full
// three-kind run of the built-in lists needs a few dozen when nothing is found; the rest is headroom
// for bisection and confirmation on a target with many hidden inputs.
const DefaultHiddenInputBudget = 500

// hiddenInputBatch is how many names one request carries, per kind. Headers are smaller: each one
// is a line, servers cap header count and size, and a 431 would read as a difference.
var hiddenInputBatch = map[HiddenInputKind]int{
	HiddenInputQuery:  40,
	HiddenInputCookie: 30,
	HiddenInputHeader: 20,
}

// HiddenInputCacheBusterParam is the query parameter every request carries, with a fresh random
// value each time, unless the operator turns it off. See HiddenInputOptions.NoCacheBuster.
const HiddenInputCacheBusterParam = "burpsycb"

// HiddenInputOptions configures one run.
type HiddenInputOptions struct {
	// Kinds are the kinds to guess, in order. Empty is refused by the caller, never read as "all".
	Kinds []HiddenInputKind
	// MaxRequests bounds the run; 0 means DefaultHiddenInputBudget.
	MaxRequests int
	// NoCacheBuster turns off the per-request cache-buster query parameter. On by default because
	// a header or cookie guess goes to the same URL as the real page: behind a shared cache, an
	// unkeyed header such as X-Forwarded-Host with a random value could be stored and served to the
	// application's real users. A fresh random parameter keys every guess to a cache entry nobody
	// else requests. An application that rejects unknown query parameters would answer every
	// request with its rejection, which is why it can be switched off.
	NoCacheBuster bool
	// Wordlists overrides the built-in list for a kind. For tests; the route does not expose it.
	Wordlists map[HiddenInputKind][]string
	// Progress is called after every request with the count sent so far. Optional.
	Progress func(sent int)
}

// HiddenInput is one confirmed hidden input.
type HiddenInput struct {
	Kind HiddenInputKind `json:"kind"`
	Name string          `json:"name"`
	// Issue is the "Secret input" row it is filed under.
	Issue string `json:"issue"`
	// Confidence is "firm" when both confirming sends changed the response the same way, and
	// "tentative" when both changed it but differently from each other (the change depends on
	// the value, or on something else as well).
	Confidence string `json:"confidence"`
	// Reflected is true when the evidence is the value coming back in the response rather than the
	// response changing shape.
	Reflected bool `json:"reflected"`
	// Evidence states the observed difference in one line.
	Evidence string `json:"evidence"`
}

// HiddenKindResult accounts for every name of one kind. The four counts partition Candidates:
// Candidates == Present + Settled + Unresolved + Untested, which a test asserts, so no name can
// leave the run without being counted somewhere.
type HiddenKindResult struct {
	Kind HiddenInputKind `json:"kind"`
	// State is "done", "stopped" (this kind could not be guessed, see Reason), "budget" (the request
	// budget ran out part way) or "not-run" (the run ended before this kind started).
	State  string `json:"state"`
	Reason string `json:"reason,omitempty"`
	// Candidates is the wordlist size for this kind.
	Candidates int `json:"candidates"`
	// Present are names the captured request already carries. Guessing them is meaningless.
	Present int `json:"present"`
	// Settled are names that were sent and got a verdict: no difference, confirmed, or unconfirmed.
	Settled int `json:"settled"`
	// Unresolved are names in a batch that changed the response where bisection could not isolate a
	// single name — the change needed several names together, or did not reproduce.
	Unresolved int `json:"unresolved"`
	// Untested are names never sent: the kind stopped, the budget ran out, or the run was stopped.
	Untested int `json:"untested"`
	// Unconfirmed are single names that changed the response once but failed confirmation.
	Unconfirmed []string `json:"unconfirmed"`
	// Found is this kind's confirmed inputs.
	Found []HiddenInput `json:"found"`
}

// HiddenInputResult is one run's outcome.
type HiddenInputResult struct {
	ExchangeID core.ExchangeID `json:"exchange_id"`
	// State: "done", "unstable" (the baseline varies on its own; nothing was guessed), "budget"
	// (MaxRequests ran out), "stopped" (the context was cancelled), "failed" (a request failed or
	// was refused, see Reason).
	State   string             `json:"state"`
	Reason  string             `json:"reason,omitempty"`
	Sent    int                `json:"requests_sent"`
	Budget  int                `json:"request_budget"`
	Kinds   []HiddenKindResult `json:"kinds"`
	Inputs  []HiddenInput      `json:"inputs"`
	Summary string             `json:"summary"`
}

// Untested sums names never sent across kinds.
func (r HiddenInputResult) Untested() int {
	n := 0
	for _, k := range r.Kinds {
		n += k.Untested
	}
	return n
}

var (
	errHiddenBudget  = errors.New("the request budget is spent")
	errHiddenRefused = errors.New("refused")
)

// CanSendProbes reports whether this scanner has a network sender. Without one, a guess run could
// not send anything, and a route should refuse up front rather than register a task that fails.
func (s *ActiveScanner) CanSendProbes() bool { return s != nil && s.sender != nil }

// GuessHiddenInputs runs the guesser against one captured exchange. It never returns a nil slice
// in the result, so the marshalled form is always `[]` for an empty list.
func (s *ActiveScanner) GuessHiddenInputs(ctx context.Context, id core.ExchangeID, opts HiddenInputOptions) HiddenInputResult {
	budget := opts.MaxRequests
	if budget <= 0 {
		budget = DefaultHiddenInputBudget
	}
	res := HiddenInputResult{ExchangeID: id, Budget: budget, Kinds: []HiddenKindResult{}, Inputs: []HiddenInput{}}
	for _, k := range opts.Kinds {
		words := opts.Wordlists[k]
		if words == nil {
			words = HiddenInputWordlist(k)
		}
		res.Kinds = append(res.Kinds, HiddenKindResult{Kind: k, State: "not-run", Candidates: len(words),
			Untested: len(words), Unconfirmed: []string{}, Found: []HiddenInput{}})
	}
	fail := func(state, reason string) HiddenInputResult {
		res.State, res.Reason = state, reason
		res.Summary = hiddenSummary(res)
		return res
	}
	if !s.CanSendProbes() {
		return fail("failed", "no sender is attached, so no request could be sent")
	}
	ex, err := s.store.GetExchange(id)
	if err != nil {
		return fail("failed", fmt.Sprintf("exchange %d is not in the store: %v", id, err))
	}
	raw := []byte(requestRaw(s, ex))
	if len(raw) == 0 {
		return fail("failed", "the exchange carries no request bytes to guess against")
	}

	g := &guesser{s: s, ex: ex, base: raw, budget: budget, opts: opts, tag: randomToken(5)}
	g.tokenRE = regexp.MustCompile(regexp.QuoteMeta(g.tag) + `[a-z0-9]{7}`)
	finish := func(err error) HiddenInputResult {
		res.Sent = g.sent
		switch {
		case err == nil:
			res.State = "done"
		case errors.Is(err, errHiddenBudget):
			res.State = "budget"
			res.Reason = fmt.Sprintf("the request budget (%d) ran out before every name was tested", budget)
		case ctx.Err() != nil:
			res.State = "stopped"
			res.Reason = "stopped by the operator before every name was tested"
		default:
			res.State = "failed"
			res.Reason = err.Error()
		}
		for _, k := range res.Kinds {
			res.Inputs = append(res.Inputs, k.Found...)
		}
		res.Summary = hiddenSummary(res)
		return res
	}

	// 1. The baseline, twice.
	b1, err := g.send(ctx, g.base, nil)
	if err != nil {
		return finish(err)
	}
	b2, err := g.send(ctx, g.base, nil)
	if err != nil {
		return finish(err)
	}
	if !b1.fp.same(b2.fp) {
		res.Sent = g.sent
		return fail("unstable", "the response varies on its own: two identical baseline requests "+
			"gave different responses ("+b1.fp.diff(b2.fp)+"), so a difference could not be "+
			"attributed to a guessed name. Nothing was guessed.")
	}
	g.baseline = b1.fp

	for i := range res.Kinds {
		kr := &res.Kinds[i]
		words := opts.Wordlists[kr.Kind]
		if words == nil {
			words = HiddenInputWordlist(kr.Kind)
		}
		if err := g.guessKind(ctx, kr, words); err != nil {
			return finish(err)
		}
	}
	return finish(nil)
}

// guesser holds one run's state.
type guesser struct {
	s        *ActiveScanner
	ex       *core.Exchange
	base     []byte
	budget   int
	sent     int
	opts     HiddenInputOptions
	tag      string
	tokenRE  *regexp.Regexp
	baseline guessFingerprint
}

// guessResponse is one probe's fingerprint plus the raw body, kept for the reflection test.
type guessResponse struct {
	fp   guessFingerprint
	body string
}

// guessFingerprint is what "the response differs" means here: status, content type, redirect
// target and whitespace-normalised body, every run token stripped. Location is in it because a
// hidden input that only redirects elsewhere is still a hidden input, and status-plus-body alone
// (ResponseFingerprint.SameShape) would miss it.
type guessFingerprint struct {
	Status      int
	ContentType string
	Location    string
	Body        string
}

func (f guessFingerprint) same(o guessFingerprint) bool { return f == o }

// diff names what differs, for a reason or an evidence line.
func (f guessFingerprint) diff(o guessFingerprint) string {
	var parts []string
	if f.Status != o.Status {
		parts = append(parts, fmt.Sprintf("status %d vs %d", f.Status, o.Status))
	}
	if f.ContentType != o.ContentType {
		parts = append(parts, fmt.Sprintf("content type %q vs %q", f.ContentType, o.ContentType))
	}
	if f.Location != o.Location {
		parts = append(parts, fmt.Sprintf("Location %q vs %q", f.Location, o.Location))
	}
	if f.Body != o.Body {
		parts = append(parts, fmt.Sprintf("body differs, %d vs %d bytes after normalisation", len(f.Body), len(o.Body)))
	}
	if len(parts) == 0 {
		return "no difference"
	}
	return strings.Join(parts, "; ")
}

// value mints one random value carrying the run tag, so the fingerprint can strip it.
func (g *guesser) value() string { return g.tag + randomToken(7) }

// send renders the base request with pairs added for kind (nil pairs: the base request itself), adds
// the cache buster, and sends it through probeGate. The budget is checked BEFORE the send, so it is
// a hard bound on requests that left, not a count of requests that came back.
func (g *guesser) send(ctx context.Context, raw []byte, add func([]byte) []byte) (guessResponse, error) {
	if err := ctx.Err(); err != nil {
		return guessResponse{}, err
	}
	if g.sent >= g.budget {
		return guessResponse{}, errHiddenBudget
	}
	req := raw
	if add != nil {
		req = add(req)
	}
	if !g.opts.NoCacheBuster {
		req = addQueryPairs(req, [][2]string{{HiddenInputCacheBusterParam, g.value()}})
	}
	gate := g.s.probeGate(ctx, g.ex)
	if gate == nil {
		return guessResponse{}, errors.New("no authorised sender")
	}
	g.sent++
	if g.opts.Progress != nil {
		g.opts.Progress(g.sent)
	}
	refusedBefore := gate.Refused()
	res, err := gate.Send(ctx, req)
	if gate.Refused() > refusedBefore {
		return guessResponse{}, fmt.Errorf("%w: a guess was outside the engagement scope (%v); the run stopped "+
			"rather than count a refused request as tested", errHiddenRefused, err)
	}
	if err != nil {
		if ctx.Err() != nil {
			return guessResponse{}, ctx.Err()
		}
		return guessResponse{}, fmt.Errorf("a request failed, so the run stopped rather than read a failure "+
			"as a difference: %w", err)
	}
	readable, _ := readableResponse(res.Raw)
	head, body, _ := splitHeadAndBody(readable)
	status := 0
	if res.Status != nil {
		status = *res.Status
	}
	if status == 0 {
		status = responseStatus(string(readable))
	}
	strip := func(s string) string { return g.tokenRE.ReplaceAllString(s, "") }
	return guessResponse{
		fp: guessFingerprint{
			Status:      status,
			ContentType: strings.ToLower(firstHeader(head, "Content-Type")),
			Location:    strip(firstHeader(head, "Location")),
			Body:        strings.Join(strings.Fields(strip(string(body))), " "),
		},
		body: string(body),
	}, nil
}

// sendWith sends the base request with the named inputs of kind k, one fresh value each, and
// returns the values it used.
func (g *guesser) sendWith(ctx context.Context, k HiddenInputKind, names []string) (guessResponse, map[string]string, error) {
	pairs := make([][2]string, len(names))
	values := make(map[string]string, len(names))
	for i, n := range names {
		v := g.value()
		pairs[i] = [2]string{n, v}
		values[n] = v
	}
	resp, err := g.send(ctx, g.base, func(raw []byte) []byte { return addInputs(raw, k, pairs) })
	return resp, values, err
}

// guessKind runs the control, the batches, bisection and confirmation for one kind, keeping kr's
// partition exact on every path out — including an error part way.
func (g *guesser) guessKind(ctx context.Context, kr *HiddenKindResult, words []string) error {
	present := presentInputs(g.base, kr.Kind)
	var names []string
	seen := map[string]bool{}
	for _, w := range words {
		key := w
		if kr.Kind == HiddenInputHeader {
			key = strings.ToLower(w)
		}
		switch {
		case present[key]:
			kr.Present++
		case seen[key] || (kr.Kind == HiddenInputHeader && hiddenHeaderDenylist[key]):
			// A duplicate or a denylisted header is never sent; it is counted as present-equivalent
			// (nothing to guess) so the partition stays exact.
			kr.Present++
		default:
			names = append(names, w)
		}
		seen[key] = true
	}
	kr.Untested = len(names)
	kr.State = "done"
	if len(names) == 0 {
		return nil
	}
	batch := hiddenInputBatch[kr.Kind]

	stop := func(err error) error {
		if errors.Is(err, errHiddenBudget) {
			kr.State = "budget"
			kr.Reason = "the request budget ran out; untested names were never sent"
		} else {
			kr.State = "stopped"
			kr.Reason = err.Error()
		}
		return err
	}

	// 2. The control: as many nonsense names as a batch carries. Retried once, so a single noisy
	// response does not cost the whole kind.
	control := make([]string, min(batch, len(names)))
	for i := range control {
		control[i] = "z" + randomToken(9)
		if kr.Kind == HiddenInputHeader {
			control[i] = "X-" + control[i]
		}
	}
	var controlEchoes bool
	for attempt := 0; ; attempt++ {
		resp, values, err := g.sendWith(ctx, kr.Kind, control)
		if err != nil {
			return stop(err)
		}
		controlEchoes = controlEchoes || reflectsAny(resp.body, values)
		if resp.fp.same(g.baseline) {
			break
		}
		if attempt == 1 {
			kr.State = "stopped"
			kr.Reason = fmt.Sprintf("the response changes when any %s is added — a control of %d random "+
				"names changed it twice (%s) — so a change could not be attributed to a name. The page "+
				"probably echoes or rejects unknown input; nothing of this kind was guessed.",
				kindNoun(kr.Kind), len(control), resp.fp.diff(g.baseline))
			return nil
		}
	}

	// 3. Batches, bisection, confirmation.
	for start := 0; start < len(names); start += batch {
		chunk := names[start:min(start+batch, len(names))]
		var out chunkOutcome
		err := g.guessChunk(ctx, kr.Kind, chunk, controlEchoes, &out)
		kr.Found = append(kr.Found, out.found...)
		kr.Unconfirmed = append(kr.Unconfirmed, out.unconfirmed...)
		kr.Unresolved += out.unresolved
		kr.Untested -= out.unresolved
		if err != nil {
			// Part of the chunk has verdicts; the rest was never decided and stays untested.
			n := len(out.found) + len(out.unconfirmed)
			kr.Settled += n
			kr.Untested -= n
			return stop(err)
		}
		settled := len(chunk) - out.unresolved
		kr.Settled += settled
		kr.Untested -= settled
	}
	return nil
}

// chunkOutcome is what one batch decided. found, unconfirmed and the unresolved names are disjoint;
// every other name in the batch got the verdict "no difference".
type chunkOutcome struct {
	found       []HiddenInput
	unconfirmed []string
	unresolved  int
}

// guessChunk sends one batch and, when it changes the response or reflects a value, isolates and
// confirms the names responsible.
func (g *guesser) guessChunk(ctx context.Context, k HiddenInputKind, chunk []string, controlEchoes bool, out *chunkOutcome) error {
	resp, values, err := g.sendWith(ctx, k, chunk)
	if err != nil {
		return err
	}
	reflected := map[string]bool{}
	if !controlEchoes {
		for _, n := range chunk {
			if strings.Contains(resp.body, values[n]) {
				reflected[n] = true
			}
		}
	}
	isCandidate := map[string]bool{}
	if !resp.fp.same(g.baseline) {
		leaves, unresolved, err := g.bisect(ctx, k, chunk)
		if err != nil {
			return err
		}
		out.unresolved = len(unresolved)
		for _, n := range unresolved {
			// An unresolved name is still tested for reflection below, but its count stays with
			// Unresolved: a reflection verdict alone would otherwise count it twice.
			delete(reflected, n)
		}
		for _, n := range leaves {
			isCandidate[n] = true
			found, err := g.confirm(ctx, k, n)
			if err != nil {
				return err
			}
			if found != nil {
				out.found = append(out.found, *found)
				delete(reflected, n)
			} else if !reflected[n] {
				out.unconfirmed = append(out.unconfirmed, n)
			}
		}
	}
	for _, n := range chunk {
		if !reflected[n] {
			continue
		}
		found, err := g.confirmReflection(ctx, k, n)
		if err != nil {
			return err
		}
		if found != nil {
			out.found = append(out.found, *found)
		} else if isCandidate[n] {
			out.unconfirmed = append(out.unconfirmed, n)
		}
	}
	return nil
}

// bisect isolates which names in a differing set change the response. It returns the single names
// that differed alone (to be confirmed) and the names that sat in a set that differed while neither
// of its halves did — a change that needs several names together, or that did not reproduce.
func (g *guesser) bisect(ctx context.Context, k HiddenInputKind, names []string) (leaves, unresolved []string, err error) {
	if len(names) == 1 {
		return names, nil, nil
	}
	mid := len(names) / 2
	anyDiffered := false
	for _, half := range [][]string{names[:mid], names[mid:]} {
		resp, _, err := g.sendWith(ctx, k, half)
		if err != nil {
			return nil, nil, err
		}
		if resp.fp.same(g.baseline) {
			continue
		}
		anyDiffered = true
		subLeaves, subUnresolved, err := g.bisect(ctx, k, half)
		if err != nil {
			return nil, nil, err
		}
		leaves = append(leaves, subLeaves...)
		unresolved = append(unresolved, subUnresolved...)
	}
	if !anyDiffered {
		return nil, names, nil
	}
	return leaves, unresolved, nil
}

// confirm repeats a single-name difference: with a fresh value it differs, without the name the
// baseline comes back, with another fresh value it differs again. Nil means not confirmed.
func (g *guesser) confirm(ctx context.Context, k HiddenInputKind, name string) (*HiddenInput, error) {
	with1, _, err := g.sendWith(ctx, k, []string{name})
	if err != nil {
		return nil, err
	}
	if with1.fp.same(g.baseline) {
		return nil, nil
	}
	without, err := g.send(ctx, g.base, nil)
	if err != nil {
		return nil, err
	}
	if !without.fp.same(g.baseline) {
		return nil, nil
	}
	with2, _, err := g.sendWith(ctx, k, []string{name})
	if err != nil {
		return nil, err
	}
	if with2.fp.same(g.baseline) {
		return nil, nil
	}
	confidence := "firm"
	if !with1.fp.same(with2.fp) {
		confidence = "tentative"
	}
	return &HiddenInput{
		Kind: k, Name: name, Issue: k.IssueName(), Confidence: confidence,
		Evidence: fmt.Sprintf("with %s %q the response differs from the baseline (%s); without it the "+
			"baseline returns; a second send with a different value differs again", kindNoun(k), name,
			with1.fp.diff(g.baseline)),
	}, nil
}

// confirmReflection repeats a reflection: the name alone, twice, each time with a fresh value that
// must come back. Only reached when the control's values did not come back, so echoing is not the
// page's general behaviour.
func (g *guesser) confirmReflection(ctx context.Context, k HiddenInputKind, name string) (*HiddenInput, error) {
	for range 2 {
		resp, values, err := g.sendWith(ctx, k, []string{name})
		if err != nil {
			return nil, err
		}
		if !strings.Contains(resp.body, values[name]) {
			return nil, nil
		}
	}
	return &HiddenInput{
		Kind: k, Name: name, Issue: k.IssueName(), Confidence: "firm", Reflected: true,
		Evidence: fmt.Sprintf("the value sent in %s %q is reflected in the response, on two sends with "+
			"different values, while the values of %s names that do not exist are not", kindNoun(k), name,
			kindNoun(k)),
	}, nil
}

func kindNoun(k HiddenInputKind) string {
	switch k {
	case HiddenInputQuery:
		return "query parameter"
	case HiddenInputCookie:
		return "cookie"
	case HiddenInputHeader:
		return "header"
	}
	return string(k)
}

func reflectsAny(body string, values map[string]string) bool {
	for _, v := range values {
		if strings.Contains(body, v) {
			return true
		}
	}
	return false
}

func randomToken(n int) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[rand.IntN(len(alphabet))]
	}
	return string(b)
}

// hiddenSummary states the run in one line, with what it did not cover.
func hiddenSummary(r HiddenInputResult) string {
	var b strings.Builder
	switch r.State {
	case "unstable", "failed":
		fmt.Fprintf(&b, "%s: %s", r.State, r.Reason)
		return b.String()
	}
	fmt.Fprintf(&b, "%d hidden input(s) confirmed in %d request(s)", len(r.Inputs), r.Sent)
	for _, k := range r.Kinds {
		fmt.Fprintf(&b, "; %s: %s, %d of %d name(s) settled", k.Kind, k.State, k.Settled, k.Candidates)
		if k.Present > 0 {
			fmt.Fprintf(&b, ", %d already in the request", k.Present)
		}
		if k.Unresolved > 0 {
			fmt.Fprintf(&b, ", %d unresolved", k.Unresolved)
		}
		if n := len(k.Unconfirmed); n > 0 {
			fmt.Fprintf(&b, ", %d unconfirmed", n)
		}
		if k.Untested > 0 {
			fmt.Fprintf(&b, ", %d never sent", k.Untested)
		}
		if k.State == "stopped" && k.Reason != "" {
			fmt.Fprintf(&b, " (%s)", strings.TrimSuffix(k.Reason, "."))
		}
	}
	if r.Reason != "" {
		fmt.Fprintf(&b, ". %s", r.Reason)
	}
	b.WriteString(". A name the wordlist does not contain was never guessed, so an absence here is an " +
		"absence of guesses, not of inputs.")
	return b.String()
}

// ---- Request rewriting ----------------------------------------------------------------------------

// addInputs adds name/value pairs of kind k to a raw request.
func addInputs(raw []byte, k HiddenInputKind, pairs [][2]string) []byte {
	switch k {
	case HiddenInputQuery:
		return addQueryPairs(raw, pairs)
	case HiddenInputCookie:
		return addCookiePairs(raw, pairs)
	case HiddenInputHeader:
		return addHeaderLines(raw, pairs)
	}
	return raw
}

// splitRequest splits a raw request into its request line, its header lines and its body, keeping
// the line ending it used so the rewrite does not change the framing.
func splitRequest(raw []byte) (line string, headers []string, body []byte, eol string) {
	s := string(raw)
	eol = "\r\n"
	sep := strings.Index(s, "\r\n\r\n")
	sepLen := 4
	if sep < 0 {
		if i := strings.Index(s, "\n\n"); i >= 0 {
			eol, sep, sepLen = "\n", i, 2
		}
	}
	head := s
	if sep >= 0 {
		head, body = s[:sep], raw[sep+sepLen:]
	}
	lines := strings.Split(head, eol)
	return lines[0], lines[1:], body, eol
}

func joinRequest(line string, headers []string, body []byte, eol string) []byte {
	var b strings.Builder
	b.WriteString(line)
	for _, h := range headers {
		b.WriteString(eol)
		b.WriteString(h)
	}
	b.WriteString(eol)
	b.WriteString(eol)
	b.Write(body)
	return []byte(b.String())
}

// addQueryPairs appends pairs to the request target's query string.
func addQueryPairs(raw []byte, pairs [][2]string) []byte {
	line, headers, body, eol := splitRequest(raw)
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 2 {
		return raw
	}
	target := parts[1]
	frag := ""
	if i := strings.IndexByte(target, '#'); i >= 0 {
		target, frag = target[:i], target[i:]
	}
	var q strings.Builder
	for _, p := range pairs {
		if q.Len() > 0 {
			q.WriteByte('&')
		}
		q.WriteString(url.QueryEscape(p[0]))
		q.WriteByte('=')
		q.WriteString(url.QueryEscape(p[1]))
	}
	switch {
	case !strings.Contains(target, "?"):
		target += "?" + q.String()
	case strings.HasSuffix(target, "?") || strings.HasSuffix(target, "&"):
		target += q.String()
	default:
		target += "&" + q.String()
	}
	parts[1] = target + frag
	return joinRequest(strings.Join(parts, " "), headers, body, eol)
}

// addCookiePairs extends the request's Cookie header, or adds one.
func addCookiePairs(raw []byte, pairs [][2]string) []byte {
	line, headers, body, eol := splitRequest(raw)
	var add strings.Builder
	for i, p := range pairs {
		if i > 0 {
			add.WriteString("; ")
		}
		add.WriteString(p[0] + "=" + p[1])
	}
	for i, h := range headers {
		k, v, ok := strings.Cut(h, ":")
		if ok && strings.EqualFold(strings.TrimSpace(k), "cookie") {
			v = strings.TrimSpace(v)
			if v != "" && !strings.HasSuffix(v, ";") {
				v += "; "
			} else if v != "" {
				v += " "
			}
			headers[i] = k + ": " + v + add.String()
			return joinRequest(line, headers, body, eol)
		}
	}
	headers = append(headers, "Cookie: "+add.String())
	return joinRequest(line, headers, body, eol)
}

// addHeaderLines appends header lines. A denylisted name is never written, whatever the caller
// passed: the wordlist test is the first line of defence and this is the last.
func addHeaderLines(raw []byte, pairs [][2]string) []byte {
	line, headers, body, eol := splitRequest(raw)
	for _, p := range pairs {
		if hiddenHeaderDenylist[strings.ToLower(p[0])] {
			continue
		}
		headers = append(headers, p[0]+": "+p[1])
	}
	return joinRequest(line, headers, body, eol)
}

// presentInputs returns the names of kind k the request already carries. Header names are
// lower-cased; query and cookie names are case-sensitive, as servers read them.
func presentInputs(raw []byte, k HiddenInputKind) map[string]bool {
	out := map[string]bool{}
	line, headers, _, _ := splitRequest(raw)
	switch k {
	case HiddenInputQuery:
		parts := strings.SplitN(line, " ", 3)
		if len(parts) < 2 {
			return out
		}
		_, query, _ := strings.Cut(parts[1], "?")
		query, _, _ = strings.Cut(query, "#")
		for _, kv := range strings.Split(query, "&") {
			name, _, _ := strings.Cut(kv, "=")
			if n, err := url.QueryUnescape(name); err == nil && n != "" {
				out[n] = true
			}
		}
	case HiddenInputCookie:
		for _, h := range headers {
			key, v, ok := strings.Cut(h, ":")
			if !ok || !strings.EqualFold(strings.TrimSpace(key), "cookie") {
				continue
			}
			for _, c := range strings.Split(v, ";") {
				name, _, _ := strings.Cut(strings.TrimSpace(c), "=")
				if name != "" {
					out[name] = true
				}
			}
		}
	case HiddenInputHeader:
		for _, h := range headers {
			if key, _, ok := strings.Cut(h, ":"); ok {
				out[strings.ToLower(strings.TrimSpace(key))] = true
			}
		}
	}
	return out
}
