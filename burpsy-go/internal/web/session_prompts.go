package web

import (
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ---- the console's "prompt for browser recovery" surface ------------------------------------------
//
// internal/session defines the seam (session.SessionPrompter) and refuses to own the prompt UI,
// because the UI sits above the coordinator in the dependency direction: the proxy consults
// session rules on every request, and dragging the console's React tree into that package would
// put a browser on the request path of the proxy's own import graph. This file is the adapter,
// the same place every other "wire the seam to the real component" decision is made.
//
// # What the prompt is
//
// Burp opens a browser window on the failing response so the operator can log in by hand. burpsy
// has no window it can open — the console is a page the operator opens themselves — so the prompt
// is a modal on that page, and the task that hit the action blocks here until the operator
// answers. The session the operator establishes reaches the retried request the same way Burp's
// does: through the proxy, into the cookie jar, out on the Cookie header.
//
// # Why the registry is keyed by id
//
// The blocked caller waits on a channel, but the answer arrives at a different endpoint — the
// modal's button — possibly minutes later and on a different connection. A map keyed by prompt id
// is the only shape that joins the two, which is the same reason intercept.Engine holds its held
// messages by id rather than by connection.

// browserRecoveryPromptTimeout bounds how long a task stays suspended waiting for the operator.
//
// Generous on purpose: recovering a session means walking to a keyboard and logging in by hand,
// and a short timeout would turn the prompt into a timeout error wearing a recovery's clothes. It
// exists so an abandoned prompt — the operator closed the tab, or walked away — costs a bounded
// wait and an honest trace entry rather than a goroutine parked for the life of the process.
const browserRecoveryPromptTimeout = 30 * time.Minute

// sessionPromptResolution is the operator's answer to one pending prompt.
type sessionPromptResolution struct {
	recovered bool
	err       error
}

// sessionPrompt is one pending browser-recovery prompt: the question the blocked task asked, and
// the channel the answer arrives on.
type sessionPrompt struct {
	id         uint64
	ruleName   string
	requestURL string
	createdAt  time.Time
	answered   chan sessionPromptResolution
}

// sessionPrompts is the registry of pending prompts. The lock is a 1-buffered channel rather than
// a sync.Mutex, matching intercept.Engine: every critical section here is a map operation, and a
// channel lock makes the lock's scope visible at the call site rather than in a defer someone
// later adds a call under.
type sessionPrompts struct {
	mu     chan struct{}
	byID   map[uint64]*sessionPrompt
	nextID uint64
}

func newSessionPrompts() *sessionPrompts {
	return &sessionPrompts{mu: make(chan struct{}, 1), byID: make(map[uint64]*sessionPrompt)}
}

func (r *sessionPrompts) lock()   { r.mu <- struct{}{} }
func (r *sessionPrompts) unlock() { <-r.mu }

// register adds a pending prompt and returns it.
func (r *sessionPrompts) register(ruleName, requestURL string) *sessionPrompt {
	r.lock()
	defer r.unlock()
	r.nextID++
	p := &sessionPrompt{
		id:         r.nextID,
		ruleName:   ruleName,
		requestURL: requestURL,
		createdAt:  time.Now(),
		answered:   make(chan sessionPromptResolution, 1),
	}
	r.byID[p.id] = p
	return p
}

// pending snapshots the pending prompts, oldest first: the console shows them in the order the
// tasks were suspended, so the operator can tell which request is waiting.
func (r *sessionPrompts) pending() []sessionPromptDto {
	r.lock()
	defer r.unlock()
	out := make([]sessionPromptDto, 0, len(r.byID))
	for _, p := range r.byID {
		out = append(out, sessionPromptDto{
			ID: p.id, RuleName: p.ruleName, RequestURL: p.requestURL, CreatedAt: p.createdAt,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// resolve answers a pending prompt exactly once. A second resolve — the operator's click arriving
// twice, or landing after a timeout — is ignored so the blocked task cannot act on a stale answer.
// Returns false when no prompt with that id is pending.
func (r *sessionPrompts) resolve(id uint64, recovered bool) bool {
	r.lock()
	p, ok := r.byID[id]
	if ok {
		delete(r.byID, id)
	}
	r.unlock()
	if !ok {
		return false
	}
	// Buffered, and the waiter has either taken the value or timed out and left — either way the
	// send cannot block, so it is safe outside the lock.
	p.answered <- sessionPromptResolution{recovered: recovered}
	return true
}

// expire removes a prompt that timed out, so the console's modal closes. A resolve that already
// removed it — the operator answered first — is a no-op.
func (r *sessionPrompts) expire(id uint64) {
	r.lock()
	delete(r.byID, id)
	r.unlock()
}

// sessionPrompter adapts the console to session.SessionPrompter.
type sessionPrompter struct {
	s *Server
}

// PromptForBrowserRecovery suspends the calling task until the operator answers the modal.
//
// The notify is what makes the modal appear: the console refetches the pending list on a "session"
// event, and the prompt is in it by the time the refetch lands. The wait is unbounded on the
// operator's side and bounded by browserRecoveryPromptTimeout on the task's side — see the
// constant for why the bound exists and why it is generous.
func (p sessionPrompter) PromptForBrowserRecovery(ruleName string, requestURL string) (bool, error) {
	prompt := p.s.prompts.register(ruleName, requestURL)
	p.s.live.notify(changeSession)
	select {
	case r := <-prompt.answered:
		return r.recovered, r.err
	case <-time.After(browserRecoveryPromptTimeout):
		p.expireAndAnnounce(prompt.id)
		return false, fmt.Errorf("no answer from the operator after %s", browserRecoveryPromptTimeout)
	}
}

// expireAndAnnounce removes a prompt whose wait timed out and announces the removal, so a live
// console's pending count returns to none instead of reading stale until some unrelated change
// refetches it - the same frame a resolve sends.
func (p sessionPrompter) expireAndAnnounce(id uint64) {
	p.s.prompts.expire(id)
	p.s.live.notify(changeSession)
}

// ---- wire shapes -----------------------------------------------------------------------------------

// sessionPromptDto is one pending browser-recovery prompt, as the console renders it.
type sessionPromptDto struct {
	ID         uint64    `json:"id"`
	RuleName   string    `json:"rule_name"`
	RequestURL string    `json:"request_url"`
	CreatedAt  time.Time `json:"created_at"`
}

// sessionPromptsResp is the pending-prompt list.
type sessionPromptsResp struct {
	// Never omitempty: an empty list and an absent field are the same JSON to a client, and "no
	// prompt is pending" is precisely the fact a client must not confuse with "the server is too
	// old to say".
	Prompts []sessionPromptDto `json:"prompts"`
}

// sessionPromptResolveReq is the operator's answer to a pending prompt.
type sessionPromptResolveReq struct {
	Recovered bool `json:"recovered"`
}

// sessionPromptResolveResp confirms a resolution.
type sessionPromptResolveResp struct {
	Resolved  bool `json:"resolved"`
	Recovered bool `json:"recovered"`
}

// ---- handlers --------------------------------------------------------------------------------------

// handleSessionPrompts is GET /api/session/prompts — the pending browser-recovery prompts.
func (s *Server) handleSessionPrompts(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, sessionPromptsResp{Prompts: s.prompts.pending()})
}

// handleSessionPromptResolve is POST /api/session/prompts/{id}/resolve — the operator's answer.
func (s *Server) handleSessionPromptResolve(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/api/session/prompts/")
	idStr = strings.TrimSuffix(idStr, "/resolve")
	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		http.Error(w, "Invalid prompt id", http.StatusBadRequest)
		return
	}
	var req sessionPromptResolveReq
	if err := requestJSON(w, r, nil).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if !s.prompts.resolve(id, req.Recovered) {
		// A duplicate or late resolution — the prompt timed out, or was already answered — is a
		// 404 rather than a 500: the click landed on a prompt that was no longer pending, which is
		// a stale modal, not a broken one.
		http.Error(w, "No such pending prompt", http.StatusNotFound)
		return
	}
	// The notify is what dismisses the modal: the console refetches the pending list and the
	// prompt is gone from it.
	s.live.notify(changeSession)
	writeJSON(w, http.StatusOK, sessionPromptResolveResp{Resolved: true, Recovered: req.Recovered})
}
