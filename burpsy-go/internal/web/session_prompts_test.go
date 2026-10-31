package web

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/session"
	"go.uber.org/zap"
)

// These pin the console's "prompt for browser recovery" surface (burpsy-react-ui-dq1g): the
// registry that joins a blocked task to the operator's answer, the endpoints the modal calls, and
// the wire shape the palette is built from. The session package's own tests pin the action kind
// and the walk; these pin the half that lives in this layer.

// ---- the registry ----------------------------------------------------------------------------------

// TestThePromptRegistryResolvesAPendingPromptExactlyOnce is the registry's contract: a prompt is
// pending until it is resolved, the resolution is delivered once, and a duplicate or late resolve
// is ignored rather than acting on a stale answer.
func TestThePromptRegistryResolvesAPendingPromptExactlyOnce(t *testing.T) {
	r := newSessionPrompts()

	p := r.register("ask the operator", "https://example.com/act")
	if p.id != 1 {
		t.Fatalf("first prompt id = %d, want 1 — ids count from one so a client can address a prompt "+
			"it was just shown", p.id)
	}
	if got := r.pending(); len(got) != 1 || got[0].RuleName != "ask the operator" {
		t.Fatalf("pending() = %+v, want the one registered prompt", got)
	}
	if got := r.pending()[0].RequestURL; got != "https://example.com/act" {
		t.Errorf("RequestURL = %q, want the URL of the request that is suspended", got)
	}

	// A prompt registered after the first gets the next id, and the list is oldest-first so the
	// console shows them in the order the tasks were suspended.
	q := r.register("second rule", "https://example.com/other")
	if q.id != 2 {
		t.Fatalf("second prompt id = %d, want 2", q.id)
	}
	if got := r.pending(); len(got) != 2 || got[0].ID != 1 || got[1].ID != 2 {
		t.Fatalf("pending() = %+v, want both prompts oldest-first", got)
	}

	if !r.resolve(p.id, true) {
		t.Fatal("resolve returned false for a pending prompt — the blocked task would hang")
	}
	if got := r.pending(); len(got) != 1 || got[0].ID != 2 {
		t.Fatalf("pending() = %+v after resolving the first, want only the second", got)
	}
	// A second resolve of the same prompt is ignored: the operator's click cannot be delivered
	// twice, and a click landing after a timeout must not reach a task that has moved on.
	if r.resolve(p.id, true) {
		t.Error("a duplicate resolve was accepted; the blocked task could act on a stale answer")
	}
	// An unknown id is refused rather than panic'd on.
	if r.resolve(999, true) {
		t.Error("resolving an unknown prompt id was accepted")
	}
}

// TestThePromptRegistryExpiresATimedOutPrompt is the bound on the wait: a prompt nobody answers
// is removed from the pending list, so the console's modal closes and the list does not grow one
// entry per abandoned prompt for the life of the process.
func TestThePromptRegistryExpiresATimedOutPrompt(t *testing.T) {
	r := newSessionPrompts()
	p := r.register("walked away", "https://example.com/act")

	r.expire(p.id)
	if got := r.pending(); len(got) != 0 {
		t.Fatalf("pending() = %+v after expiry, want empty — a timed-out prompt must not stay on "+
			"the console forever", got)
	}
	// The operator's late answer finds nothing to resolve, which is the honest outcome: the task
	// already gave up waiting.
	if r.resolve(p.id, true) {
		t.Error("a resolve landing after the prompt expired was accepted")
	}
}

// ---- the seam, over HTTP ----------------------------------------------------------------------------

// TestABrowserRecoveryPromptSuspendsTheTaskUntilTheOperatorResolvesIt is the whole feature at the
// web layer: the seam blocks until the operator answers, the pending list is what the console
// renders, and the resolve is what dismisses it.
func TestABrowserRecoveryPromptSuspendsTheTaskUntilTheOperatorResolvesIt(t *testing.T) {
	srv := newTestServer().WithSessionCoordinator(session.NewCoordinator(zap.NewNop()))
	// The adapter is stateless beyond its server handle, so a test constructs the same instance
	// WithSessionCoordinator wired into the coordinator — the session package's own tests pin the
	// walk that calls it; these pin the web layer around it.
	prompter := sessionPrompter{s: srv}

	type answer struct {
		recovered bool
		err       error
	}
	done := make(chan answer, 1)
	go func() {
		recovered, err := prompter.PromptForBrowserRecovery("ask the operator", "https://example.com/act")
		done <- answer{recovered: recovered, err: err}
	}()

	// The prompt is pending, and the task is still suspended: the seam must not return before
	// the operator answers.
	select {
	case <-done:
		t.Fatal("PromptForBrowserRecovery returned before the operator answered — the task was " +
			"not suspended while the prompt was pending")
	case <-time.After(100 * time.Millisecond):
	}

	rec := get(t, srv, "/api/session/prompts")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/session/prompts answered %d, want 200 — body: %s", rec.Code, rec.Body.String())
	}
	var list sessionPromptsResp
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode pending list: %v", err)
	}
	if len(list.Prompts) != 1 {
		t.Fatalf("pending list has %d entries, want 1 — the console renders this list as the modal",
			len(list.Prompts))
	}
	prompt := list.Prompts[0]
	if prompt.RuleName != "ask the operator" || prompt.RequestURL != "https://example.com/act" {
		t.Errorf("pending prompt = %+v, want the rule name and URL the task asked about", prompt)
	}
	if prompt.CreatedAt.IsZero() {
		t.Error("the pending prompt carries no creation time, so the console cannot say how long " +
			"the task has been suspended")
	}

	// The operator confirms the session is recovered.
	resolveRec := postJSON(t, srv, "/api/session/prompts/1/resolve",
		sessionPromptResolveReq{Recovered: true})
	if resolveRec.Code != http.StatusOK {
		t.Fatalf("POST resolve answered %d, want 200 — body: %s", resolveRec.Code, resolveRec.Body.String())
	}

	select {
	case a := <-done:
		if a.err != nil || !a.recovered {
			t.Fatalf("the seam returned (%v, %v), want (true, nil) — the operator confirmed the "+
				"session was recovered", a.recovered, a.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the seam did not return after the resolve — the suspended task never resumed")
	}

	// The modal's list is empty again, which is what dismisses the console's modal.
	list = sessionPromptsResp{}
	rec = get(t, srv, "/api/session/prompts")
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode pending list after resolve: %v", err)
	}
	if len(list.Prompts) != 0 {
		t.Errorf("pending list = %+v after the resolve, want empty", list.Prompts)
	}
}

// TestResolvingAnUnknownPromptIsRefused pins the failure mode the modal's error path reads: a
// prompt id that is not pending — unknown, already resolved, or expired — is a 404 naming that,
// not a 500 that would read as a broken console.
func TestResolvingAnUnknownPromptIsRefused(t *testing.T) {
	srv := newTestServer()

	rec := postJSON(t, srv, "/api/session/prompts/1/resolve", sessionPromptResolveReq{Recovered: true})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("POST resolve for an unknown prompt answered %d, want 404 — body: %s",
			rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "No such pending prompt") {
		t.Errorf("the 404 does not say what is wrong: %s", rec.Body.String())
	}

	// A malformed id is a 400, not a 404: "not a number" and "no such prompt" are different
	// things for an operator to read.
	rec = postJSON(t, srv, "/api/session/prompts/not-a-number/resolve", sessionPromptResolveReq{Recovered: true})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST resolve with a non-numeric id answered %d, want 400 — body: %s",
			rec.Code, rec.Body.String())
	}
}

// TestAPromptForBrowserRecoveryAnnouncesItselfOnTheEventStream pins the notify that makes the
// modal appear without a poll: a prompt becoming pending announces the "session" kind, and so
// does its resolution — the two events that open and dismiss the modal.
func TestAPromptForBrowserRecoveryAnnouncesItselfOnTheEventStream(t *testing.T) {
	srv := newTestServer().WithSessionCoordinator(session.NewCoordinator(zap.NewNop()))
	sub, unsubscribe := srv.live.subscribe()
	defer unsubscribe()

	// The seam notifies when the prompt becomes pending.
	go func() {
		_, _ = sessionPrompter{s: srv}.PromptForBrowserRecovery("ask the operator", "https://example.com/act")
	}()

	deadline := time.After(5 * time.Second)
	announced := false
	for !announced {
		select {
		case <-sub.signal:
			for _, frame := range srv.live.take(sub) {
				if frame.Kind == "session" {
					announced = true
				}
			}
		case <-deadline:
			t.Fatal("no \"session\" event frame arrived after a prompt became pending — the " +
				"console's modal would never appear without a poll")
		}
	}

	// The resolve notifies too, which is what dismisses the modal — through the endpoint, which is
	// the only path an operator's click can take.
	resolveRec := postJSON(t, srv, "/api/session/prompts/1/resolve", sessionPromptResolveReq{Recovered: true})
	if resolveRec.Code != http.StatusOK {
		t.Fatalf("POST resolve answered %d, want 200 — body: %s", resolveRec.Code, resolveRec.Body.String())
	}
	announced = false
	for !announced {
		select {
		case <-sub.signal:
			for _, frame := range srv.live.take(sub) {
				if frame.Kind == "session" {
					announced = true
				}
			}
		case <-deadline:
			t.Fatal("no \"session\" event frame arrived after the prompt was resolved — the " +
				"console's modal would never dismiss")
		}
	}
}

// ---- the wire shapes the palette is built from -------------------------------------------------------

// TestTheActionPaletteOffersThePromptForBrowserRecovery pins the palette entry the editor's
// "Add an action" dropdown renders: the wire name the server accepts and Burp's own label, so the
// editor offers the action under the documentation's wording rather than this port's enum name.
func TestTheActionPaletteOffersThePromptForBrowserRecovery(t *testing.T) {
	srv := newTestServer()

	rec := get(t, srv, "/api/session/rules")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/session/rules answered %d, want 200", rec.Code)
	}
	var body struct {
		ActionKinds []sessionActionKindDto `json:"action_kinds"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode rules response: %v", err)
	}
	var found *sessionActionKindDto
	for i := range body.ActionKinds {
		if body.ActionKinds[i].Kind == "prompt_for_browser_recovery" {
			found = &body.ActionKinds[i]
		}
	}
	if found == nil {
		t.Fatalf("the action palette does not offer prompt_for_browser_recovery; it offers %s",
			kindList(body.ActionKinds))
	}
	if found.Label != "Prompt the user for in-browser session recovery" {
		t.Errorf("the palette label is %q, want Burp's own words", found.Label)
	}
}

// kindList renders the palette for a failure message.
func kindList(kinds []sessionActionKindDto) string {
	out := make([]string, 0, len(kinds))
	for _, k := range kinds {
		out = append(out, k.Kind)
	}
	return strings.Join(out, ", ")
}

// TestTheDeclinedActionsWireFieldIsGone pins the other half of the palette contract: with Burp's
// ninth action implemented, there is no declined list any more, and the wire no longer carries the
// field — an action absent from the palette is now simply one this port does not have.
func TestTheDeclinedActionsWireFieldIsGone(t *testing.T) {
	srv := newTestServer()

	rec := get(t, srv, "/api/session/rules")
	var body map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode rules response: %v", err)
	}
	if _, present := body["declined_actions"]; present {
		t.Error("the rules response still carries declined_actions; with every Burp action " +
			"implemented the field has no job, and a client reading it would wait for an entry " +
			"that will never come")
	}
}

// TestAnExpiredBrowserRecoveryPromptAnnouncesItsRemoval pins the timeout half of the prompt
// lifecycle: a prompt the operator never answered must leave the pending list AND announce the
// "session" frame, or a live console keeps reading "1 pending" until some unrelated change
// refetches it. The wait itself is pinned against the seam; this drives the expire-and-announce
// helper directly so the test does not wait out the generous operator bound.
func TestAnExpiredBrowserRecoveryPromptAnnouncesItsRemoval(t *testing.T) {
	srv := newTestServer().WithSessionCoordinator(session.NewCoordinator(zap.NewNop()))
	sub, unsubscribe := srv.live.subscribe()
	defer unsubscribe()

	prompt := srv.prompts.register("ask the operator", "https://example.com/act")
	sessionPrompter{s: srv}.expireAndAnnounce(prompt.id)

	rec := get(t, srv, "/api/session/prompts")
	var list sessionPromptsResp
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode pending list: %v", err)
	}
	if len(list.Prompts) != 0 {
		t.Fatalf("pending list has %d entries after expiry, want 0", len(list.Prompts))
	}

	deadline := time.After(5 * time.Second)
	for {
		select {
		case <-sub.signal:
			for _, frame := range srv.live.take(sub) {
				if frame.Kind == "session" {
					return
				}
			}
		case <-deadline:
			t.Fatal("no \"session\" event frame arrived after a prompt expired — a live console " +
				"would keep reading the stale pending count")
		}
	}
}
