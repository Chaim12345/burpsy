package web

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// TestUI2IntruderConfirmMintsToken drives the two-step launch: POST /ui2/intruder/confirm
// must return a confirm fragment carrying a real token (minted through the gate), not a
// cross-site refusal.
func TestUI2IntruderConfirmMintsToken(t *testing.T) {
	s := newTestServer()
	seedUI2Exchange(t, s, "GET /p?a=1 HTTP/1.1\r\nHost: p.test\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n.")
	form := "msg_id=1&payloads=admin%0Aroot&all_points=on"
	req := httptest.NewRequest(http.MethodPost, "/ui2/intruder/confirm", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("confirm = %d: %s", rec.Code, rec.Body.String()[:ui2Min(200, rec.Body.Len())])
	}
	body := rec.Body.String()
	if strings.Contains(body, "did not come from burpsy") {
		t.Fatalf("mint went through the cross-site gate and was refused: %s", body[:ui2Min(200, len(body))])
	}
	if !strings.Contains(body, `name="token" value="`) {
		t.Errorf("confirm fragment carries no token: %s", body[:ui2Min(300, len(body))])
	}
	if !strings.Contains(body, "Confirm and launch attack") {
		t.Errorf("confirm fragment missing the confirm button")
	}
	if !strings.Contains(body, "/api/intruder/run") {
		t.Errorf("preview does not name the gated call")
	}
	// "All points" must resolve to explicit indexes: /api/intruder/run refuses all:true alone
	// ("no insertion point selected"), so the confirmed call must carry the discovered indexes.
	if !strings.Contains(body, `name="point" value="`) {
		t.Errorf("confirm fragment carries no resolved insertion points: %s", body[:ui2Min(400, len(body))])
	}
	// all_points must ALSO ride along: it selects the discovery config at run time, and the
	// gate binds the token to the exact minted body, so the rebuilt body needs every key.
	if !strings.Contains(body, `name="all_points" value="on"`) {
		t.Errorf("confirm fragment dropped all_points: the rebuilt body would miss the discovery config and the token match")
	}
}

// TestUI2IntruderConfirmWithoutPointsSaysSo: a base message the points discovery cannot resolve
// must not mint a token for a launch the run API would refuse — the confirm step says why.
func TestUI2IntruderConfirmWithoutPointsSaysSo(t *testing.T) {
	s := newTestServer()
	seedUI2Exchange(t, s, "GET /p?a=1 HTTP/1.1\r\nHost: p.test\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n.")
	form := "msg_id=999&payloads=admin&all_points=on"
	req := httptest.NewRequest(http.MethodPost, "/ui2/intruder/confirm", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("confirm = %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `role="alert"`) {
		t.Errorf("expected the discovery error rendered as an alert: %s", body[:ui2Min(300, len(body))])
	}
	if strings.Contains(body, `name="token" value="`) {
		t.Errorf("a token was minted for a launch that cannot run")
	}
}

// TestUI2SequencerAnalyseRendersReport posts a small token list and expects the report.
func TestUI2SequencerAnalyseRendersReport(t *testing.T) {
	s := newTestServer()
	tokens := "aaa\naab\naba\nabb\nbaa\nbab\nbba\nbbb"
	form := "tokens=" + strings.ReplaceAll(tokens, "\n", "%0A") + "&encoding=raw"
	req := httptest.NewRequest(http.MethodPost, "/ui2/sequencer/analyse", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("analyse = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Report") {
		t.Errorf("no report rendered: %s", rec.Body.String()[:ui2Min(300, rec.Body.Len())])
	}
}

// TestUI2CollaboratorMintConfirmStep: the payload route is riskEgress, which the confirmation
// gate does not cover, so there is no token-mint endpoint for it — the two-step confirm is
// ui2-local. The first POST shows the exact call; only confirmed=1 dispatches.
func TestUI2CollaboratorMintConfirmStep(t *testing.T) {
	s := newTestServer()
	req := httptest.NewRequest(http.MethodPost, "/ui2/collaborator/mint", strings.NewReader("count=1"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("mint page = %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Confirm mint") {
		t.Errorf("first POST did not render the confirm step: %s", body[:ui2Min(300, len(body))])
	}
	if !strings.Contains(body, "POST /api/collaborator/payload") {
		t.Errorf("confirm step does not name the exact call: %s", body[:ui2Min(300, len(body))])
	}
	if !strings.Contains(body, `name="mint_id"`) {
		t.Errorf("confirm form does not carry the server-held mint id: %s", body[:ui2Min(300, len(body))])
	}
	if strings.Contains(body, `name="token"`) {
		t.Errorf("confirm step still asks the gate for a token — that endpoint 404s for riskEgress")
	}

	// The confirm POST spends the held call; with no interaction server configured the
	// handler answers with the API's error rendered, not a broken page.
	mintID := extractHiddenInput(t, body, "mint_id")
	req2 := httptest.NewRequest(http.MethodPost, "/ui2/collaborator/mint", strings.NewReader("mint_id="+mintID))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec2 := httptest.NewRecorder()
	s.mux.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("confirmed mint page = %d", rec2.Code)
	}
	if strings.Contains(rec2.Body.String(), "Confirm mint") {
		t.Errorf("confirmed POST rendered the confirm step again instead of dispatching")
	}
}

func TestUI2IntruderPagesAreRegistered(t *testing.T) {
	s := newTestServer()
	for _, p := range []string{"/ui2/intruder", "/ui2/sequencer", "/ui2/collaborator"} {
		if rec := getUI2(t, s, p); rec.Code != http.StatusOK {
			t.Errorf("GET %s = %d", p, rec.Code)
		}
	}
}

// TestUI2IntruderConfirmedDispatchSpendsItsOwnToken drives the full two-step chain: the body the
// confirm step mints the token for must be byte-identical to the body the run step rebuilds from
// the fragment's fields, or the gate refuses the confirmed dispatch with 428 (a regression caught
// by browser UAT: the minted body carried "all": true, the rebuilt one did not).
func TestUI2IntruderConfirmedDispatchSpendsItsOwnToken(t *testing.T) {
	s := newTestServer()
	// A loopback victim the attack can reach: against p.test every send fails on DNS, and a
	// failed send stores no request (Attempt.RequestID is nil), which would leave the results
	// dataset legitimately empty — untestable. The victim also proves the dispatch left the
	// process: its 200 lands on the results rows.
	victim := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("victim-ok"))
	}))
	t.Cleanup(victim.Close)
	vhost := strings.TrimPrefix(victim.URL, "http://")
	s.scope.AddInclude("127.0.0.1")
	msgID := seedUI2ExchangeMsgID(t, s, "GET /p?a=1 HTTP/1.1\r\nHost: "+vhost+"\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nvictim-ok")
	msgIDStr := strconv.FormatUint(msgID, 10)

	// Step 1: the confirm form (all points, LF-delimited payloads as the browser posts them).
	form := "msg_id=" + msgIDStr + "&payloads=admin%0Aroot&all_points=on"
	req := httptest.NewRequest(http.MethodPost, "/ui2/intruder/confirm", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("confirm = %d", rec.Code)
	}
	frag := rec.Body.String()
	token := extractHiddenInput(t, frag, "token")

	// Step 2: rebuild the run POST from exactly the fields the fragment carries.
	runForm := "token=" + token + "&msg_id=" + extractHiddenInput(t, frag, "msg_id") +
		"&target=" + extractHiddenInput(t, frag, "target") +
		"&payload_placement=" + extractHiddenInput(t, frag, "payload_placement")
	for _, pt := range extractHiddenInputs(frag, "point") {
		runForm += "&point=" + pt
	}
	// The browser posts every hidden input back; all_points carries the discovery config.
	for _, ap := range extractHiddenInputs(frag, "all_points") {
		runForm += "&all_points=" + ap
	}
	payloads := extractTextarea(t, frag, "payloads")
	runForm += "&payloads=" + urlQueryEscape(payloads)
	req2 := httptest.NewRequest(http.MethodPost, "/ui2/intruder/run", strings.NewReader(runForm))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec2 := httptest.NewRecorder()
	s.mux.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("run = %d", rec2.Code)
	}
	body := rec2.Body.String()
	if strings.Contains(body, "confirmation required") || strings.Contains(body, "428") {
		t.Fatalf("confirmed dispatch refused its own token: %s", body[:ui2Min(300, len(body))])
	}
	if strings.Contains(body, "out of range") {
		t.Fatalf("resolved points rejected at run time (discovery config mismatch): %s", body[:ui2Min(300, len(body))])
	}
	// The run answers when the attack is over and its registry entry is already gone, so the
	// page must hand the operator the finished attack's results link here — or the results of
	// the attack they just confirmed are unreachable from this console.
	i := strings.Index(body, `href="/ui2/intruder/`)
	if i < 0 || !strings.Contains(body[i:], `/results"`) {
		t.Fatalf("finished attack's results not linked: %s", body[:ui2Min(300, len(body))])
	}
	rest := body[i+len(`href="/ui2/intruder/`):]
	path := "/ui2/intruder/" + rest[:strings.Index(rest, `"`)]
	rec3 := httptest.NewRecorder()
	s.mux.ServeHTTP(rec3, httptest.NewRequest(http.MethodGet, path, nil))
	if rec3.Code != http.StatusOK {
		t.Fatalf("results page %s = %d", path, rec3.Code)
	}
	// The attack's sends — payloads spliced into the query string — are the page's rows. An
	// empty table here was the pre-recordIntruderExchanges state: real attack, no results.
	if rows := rec3.Body.String(); !strings.Contains(rows, "a=admin") || !strings.Contains(rows, "a=root") {
		t.Fatalf("results page does not list the attack's sent requests: %s", rows[:ui2Min(300, len(rows))])
	}
}

func extractHiddenInput(t *testing.T, html, name string) string {
	t.Helper()
	vals := extractHiddenInputs(html, name)
	if len(vals) != 1 {
		t.Fatalf("fragment carries %d %q inputs, want 1", len(vals), name)
	}
	return vals[0]
}

func extractHiddenInputs(html, name string) []string {
	var out []string
	marker := `name="` + name + `" value="`
	for rest := html; ; {
		i := strings.Index(rest, marker)
		if i < 0 {
			return out
		}
		rest = rest[i+len(marker):]
		j := strings.Index(rest, `"`)
		out = append(out, rest[:j])
		rest = rest[j:]
	}
}

func extractTextarea(t *testing.T, html, name string) string {
	t.Helper()
	marker := `<textarea name="` + name + `"`
	i := strings.Index(html, marker)
	if i < 0 {
		t.Fatalf("no %q textarea in fragment", name)
	}
	rest := html[i+len(marker):]
	j := strings.Index(rest, ">")
	k := strings.Index(rest, "</textarea>")
	if j < 0 || k < 0 || k < j {
		t.Fatalf("malformed %q textarea in fragment", name)
	}
	return rest[j+1 : k]
}

// TestUI2IntruderConfirmRefusesAnEmptySelection: "all points" unchecked with no point[] selected
// means NOTHING is selected. Resolving every point anyway (the old `|| len(points) == 0`
// fallback) turned an operator narrowing an attack into the widest one possible without a word.
func TestUI2IntruderConfirmRefusesAnEmptySelection(t *testing.T) {
	s := newTestServer()
	msgID := seedUI2ExchangeMsgID(t, s, "GET /p?a=1 HTTP/1.1\r\nHost: p.test\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n.")

	form := "msg_id=" + strconv.FormatUint(msgID, 10) + "&payloads=admin"
	req := httptest.NewRequest(http.MethodPost, "/ui2/intruder/confirm", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	frag := rec.Body.String()
	if !strings.Contains(frag, "no insertion points selected") {
		t.Fatalf("an empty selection was not refused: %s", frag[:ui2Min(300, len(frag))])
	}
	if strings.Contains(frag, `name="token"`) {
		t.Fatal("a token was minted for a call with no selection")
	}
}

// TestUI2IntruderRunWithoutSelectionSpendsNothing: the same refusal at the run step, before the
// token is spent — a hand-built POST cannot route around the confirm step's refusal.
func TestUI2IntruderRunWithoutSelectionSpendsNothing(t *testing.T) {
	s := newTestServer()
	msgID := seedUI2ExchangeMsgID(t, s, "GET /p?a=1 HTTP/1.1\r\nHost: p.test\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n.")

	form := "token=deadbeef&msg_id=" + strconv.FormatUint(msgID, 10) + "&payloads=admin"
	req := httptest.NewRequest(http.MethodPost, "/ui2/intruder/run", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	body := rec.Body.String()
	if !strings.Contains(body, "no insertion points selected") {
		t.Fatalf("run without a selection not refused: %s", body[:ui2Min(300, len(body))])
	}
	if strings.Contains(body, "confirmation required") {
		t.Fatal("the call reached the confirmation gate without a selection")
	}
}

// TestUI2CollaboratorConfirmSpendsTheHeldCall: the confirm form carries only the mint id; the
// dispatched body is the one the server held when the preview rendered. A count edited between
// preview and confirm cannot change what runs, and the id is single-use.
func TestUI2CollaboratorConfirmSpendsTheHeldCall(t *testing.T) {
	s := newTestServer()

	form := "count=2"
	req := httptest.NewRequest(http.MethodPost, "/ui2/collaborator/mint", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	frag := rec.Body.String()
	// html/template escapes the preview's quotes (&#34;) in the raw fragment.
	if !strings.Contains(frag, `&#34;count&#34;:2`) {
		t.Fatalf("preview does not show the call: %s", frag[:ui2Min(300, len(frag))])
	}
	id := extractHiddenInput(t, frag, "mint_id")
	v, ok := s.ui2Mints.Load(id)
	mint, isMint := v.(ui2PendingMint)
	if !ok || !isMint || string(mint.body) != `{"count":2}` {
		got, _ := v.(ui2PendingMint)
		t.Fatalf("held call: present=%v body=%q, want the previewed {\"count\":2}", ok, got.body)
	}

	// Confirm, with the form's count tampered: it is not even parsed on this path.
	form2 := "mint_id=" + id + "&count=20"
	req2 := httptest.NewRequest(http.MethodPost, "/ui2/collaborator/mint", strings.NewReader(form2))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec2 := httptest.NewRecorder()
	s.mux.ServeHTTP(rec2, req2)
	body2 := rec2.Body.String()
	// The API's own refusal (no channel configured) proves the held call was dispatched.
	if !strings.Contains(body2, "no out-of-band interaction channel is configured") {
		t.Fatalf("the held call was not dispatched: %s", body2[:ui2Min(300, len(body2))])
	}

	// Single-use: the same id cannot confirm twice.
	req3 := httptest.NewRequest(http.MethodPost, "/ui2/collaborator/mint", strings.NewReader(form2))
	req3.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec3 := httptest.NewRecorder()
	s.mux.ServeHTTP(rec3, req3)
	if !strings.Contains(rec3.Body.String(), "unknown or has expired") {
		t.Fatalf("a spent mint id confirmed again: %s", rec3.Body.String()[:ui2Min(300, rec3.Body.Len())])
	}
}

// TestUI2CollaboratorConfirmWithUnknownMintRefuses: an id the server never held (or already
// spent) refuses without dispatching anything.
func TestUI2CollaboratorConfirmWithUnknownMintRefuses(t *testing.T) {
	s := newTestServer()
	form := "mint_id=deadbeef&count=1"
	req := httptest.NewRequest(http.MethodPost, "/ui2/collaborator/mint", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	body := rec.Body.String()
	if !strings.Contains(body, "unknown or has expired") {
		t.Fatalf("an unknown mint id was not refused: %s", body[:ui2Min(300, len(body))])
	}
	if strings.Contains(body, "no out-of-band interaction channel") {
		t.Fatal("an unknown mint id dispatched a call")
	}
}

// seedUI2ExchangeMsgID seeds one exchange and returns the REQUEST's message id — the id the
// intruder forms take as msg_id. Seeding stores request then response as messages 0 and 1, so
// a hardcoded msg_id=1 quietly attacks the response bytes: the points discovery splices
// payloads into the status line and the attack sends garbage like "HTTP/1.1 admin OK".
func seedUI2ExchangeMsgID(t *testing.T, s *Server, request, response string) uint64 {
	t.Helper()
	exID := seedUI2Exchange(t, s, request, response)
	ex, err := s.store.GetExchange(exID)
	if err != nil || ex.Request == nil {
		t.Fatalf("seeded exchange %d has no request: %v", exID, err)
	}
	return uint64(*ex.Request)
}

// TestUI2IntruderPostedPointsAreTheConfirmedSet: when the confirm fragment posts a selection
// back, those indexes are what the operator confirmed — the server must not re-resolve the
// discovered set and silently widen it (the inputs are live, not decoration).
func TestUI2IntruderPostedPointsAreTheConfirmedSet(t *testing.T) {
	s := newTestServer()
	msgID := seedUI2ExchangeMsgID(t, s, "GET /p?a=1&b=2 HTTP/1.1\r\nHost: p.test\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n.")

	// all-points config, but only point 1 of the two selected.
	form := "msg_id=" + strconv.FormatUint(msgID, 10) + "&payloads=admin&all_points=on&point=1"
	req := httptest.NewRequest(http.MethodPost, "/ui2/intruder/confirm", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	frag := rec.Body.String()
	if !strings.Contains(frag, "&#34;points&#34;: [\n    1\n  ]") {
		t.Fatalf("the posted selection was not honored: %s", frag[:ui2Min(400, len(frag))])
	}
	// Exactly one point input rides back to the run step.
	if got := len(extractHiddenInputs(frag, "point")); got != 1 {
		t.Fatalf("confirm fragment carries %d point inputs, want the confirmed 1", got)
	}
}

// TestUI2ConfirmFragmentsRenderUnarmedAndArmable pins the readiness guard behind
// burpsy-react-ui settle-race: htmx 2.x binds swapped-in content after the swap, so a
// click in that window used to submit the confirm form NATIVELY — a GET to the page URL
// that silently dropped the launch and put the minted token and payloads in the URL
// (history, logs). The fragments now render the destructive submit disabled and
// data-arm-on-load, and app.js arms it only from the button's own htmx:load, which fires
// after the hx-post form is bound; the forms also declare method="post" so even a native
// submit fails explicitly (405 on the GET-only page route) without a URL leak.
func TestUI2ConfirmFragmentsRenderUnarmedAndArmable(t *testing.T) {
	s := newTestServer()
	seedUI2Exchange(t, s, "GET /p?a=1 HTTP/1.1\r\nHost: p.test\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n.")

	// Intruder confirm fragment.
	req := httptest.NewRequest(http.MethodPost, "/ui2/intruder/confirm", strings.NewReader("msg_id=1&payloads=admin%0Aroot&all_points=on"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("intruder confirm = %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `disabled data-arm-on-load`) {
		t.Errorf("launch button is not rendered disabled+armable: %s", body[:ui2Min(400, len(body))])
	}
	if !strings.Contains(body, `hx-post="/ui2/intruder/run" method="post"`) {
		t.Errorf("launch form lost the safe native fallback (method=post): %s", body[:ui2Min(400, len(body))])
	}

	// Collaborator confirm form.
	req = httptest.NewRequest(http.MethodPost, "/ui2/collaborator/mint", strings.NewReader("count=1"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("collaborator mint = %d", rec.Code)
	}
	body = rec.Body.String()
	if !strings.Contains(body, `disabled data-arm-on-load`) {
		t.Errorf("confirm-mint button is not rendered disabled+armable: %s", body[:ui2Min(400, len(body))])
	}
	if !strings.Contains(body, `hx-post="/ui2/collaborator/mint" method="post"`) {
		t.Errorf("confirm-mint form lost the safe native fallback (method=post): %s", body[:ui2Min(400, len(body))])
	}

	// The arming script ships in app.js and keys on htmx:load armed on DESCENDANTS:
	// htmx fires htmx:load per top-level swapped node right after binding that whole
	// subtree, and never on the button itself; afterSettle/afterSwap of another in-flight
	// swap can interleave before this fragment's binding (both shapes were observed in
	// the browser test's event probe). Pin the working wiring so a refactor cannot
	// reintroduce either failure.
	appJS, err := ui2FS.ReadFile("ui2/app.js")
	if err != nil {
		t.Fatalf("reading app.js: %v", err)
	}
	js := string(appJS)
	if !strings.Contains(js, "htmx:load") || !strings.Contains(js, "querySelectorAll('[data-arm-on-load][disabled]')") {
		t.Errorf("app.js must arm data-arm-on-load controls inside an element whose htmx:load fired")
	}
	if strings.Contains(js, "htmx:afterSettle") {
		t.Errorf("arming from afterSettle is the interleaving race this guard exists to remove")
	}

	// The native fallback the guard relies on: a native POST of either form lands on the
	// GET-only page route and is refused explicitly, never a silent re-render or launch.
	for _, p := range []string{"/ui2/intruder", "/ui2/collaborator"} {
		req := httptest.NewRequest(http.MethodPost, p, strings.NewReader("token=x&mint_id=x&payloads=admin"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		s.mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("native POST %s = %d, want 405 (explicit refusal, no silent GET re-render)", p, rec.Code)
		}
	}
}

// TestUI2CollaboratorInteractionsRenderRows: the interactions table ranged
// .interactions.interactions — the counts object, not the rows — so a real recorded
// interaction rendered as empty cells (caught by UAT against a stub channel: the poll
// API showed total 1 while the page showed a blank row). The table now ranges
// .interactions.rows and renders the recorded id, type, client and time.
func TestUI2CollaboratorInteractionsRenderRows(t *testing.T) {
	model := map[string]any{
		"status": map[string]any{"configured": true, "hint": "h", "domain": "d.oast.local"},
		"interactions": map[string]any{
			"total": 1, "distinct": 1,
			"rows": []any{map[string]any{
				"interaction_id": "abc123", "type": "dns", "q_type": "A",
				"client_ip": "127.0.0.1", "at_ms": float64(1793400325000),
			}},
		},
	}
	out := string(ui2Exec("collaborator.html", model))
	if !strings.Contains(out, "abc123") || !strings.Contains(out, "dns A") || !strings.Contains(out, "127.0.0.1") {
		t.Errorf("interaction row does not render its fields: %s", out[:ui2Min(500, len(out))])
	}
	if strings.Contains(out, "<td></td>") {
		t.Errorf("interaction row rendered empty cells: %s", out[:ui2Min(500, len(out))])
	}
	if strings.Contains(out, "No interactions recorded.") {
		t.Errorf("empty-state shown alongside a real row")
	}
	if !strings.Contains(out, "2026-") {
		t.Errorf("at_ms did not render as a wall-clock time: %s", out[:ui2Min(500, len(out))])
	}
}

// TestUI2CollaboratorMintResultIsStructured pins the post-mint display: the operator gets
// the minted addresses (copyable), the domain and the marker — never the raw API response
// blob, whose config and log noise buried the one thing they needed and could leak details
// into a screen share. Addresses render through html/template, so a hostile address cannot
// break out of the copy attribute.
func TestUI2CollaboratorMintResultIsStructured(t *testing.T) {
	model := map[string]any{
		"status":       map[string]any{"configured": true, "hint": "h", "domain": "d.oast.local"},
		"interactions": map[string]any{"total": 0, "rows": []any{}},
		"minted": map[string]any{
			"addresses": []string{"mk1.d.oast.local", "mk2.d.oast.local"},
			"domain":    "d.oast.local",
			"marker":    "mk",
		},
	}
	out := string(ui2Exec("collaborator.html", model))
	for _, want := range []string{"mk1.d.oast.local", "mk2.d.oast.local", `data-copy="mk1.d.oast.local"`, "Copy", "d.oast.local", "Minted 2 payload(s)"} {
		if !strings.Contains(out, want) {
			t.Errorf("structured mint result missing %q: %s", want, out[:ui2Min(600, len(out))])
		}
	}
	if strings.Contains(out, "marker_note") || strings.Contains(out, `{"address"`) {
		t.Errorf("raw API blob leaked into the mint result display")
	}

	// A hostile address stays inert in both the text and the copy attribute.
	model["minted"] = map[string]any{"addresses": []string{`x"><script>alert(1)</script>`}, "domain": "d", "marker": "m"}
	out = string(ui2Exec("collaborator.html", model))
	if strings.Contains(out, "<script>alert(1)</script>") {
		t.Errorf("hostile minted address rendered unescaped")
	}

	// The failure path is a clean alert line, not a dump.
	out = string(ui2Exec("collaborator.html", map[string]any{
		"status":       map[string]any{"configured": false, "hint": "h"},
		"interactions": map[string]any{"total": 0, "rows": []any{}},
		"mint_error":   "no out-of-band interaction channel is configured",
	}))
	if !strings.Contains(out, `role="alert"`) || !strings.Contains(out, "no out-of-band interaction channel is configured") {
		t.Errorf("mint failure does not render as a clean alert: %s", out[:ui2Min(400, len(out))])
	}
}

// TestUI2CollaboratorMintRefusalIsReadable: a refused mint renders the refusal as readable
// text (the API's error sentence and hint), never the raw JSON error body — browser UAT
// caught the unconfigured-channel refusal rendering as one escaped-JSON line.
func TestUI2CollaboratorMintRefusalIsReadable(t *testing.T) {
	s := newTestServer()
	req := httptest.NewRequest(http.MethodPost, "/ui2/collaborator/mint", strings.NewReader("count=1"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	id := extractHiddenInput(t, rec.Body.String(), "mint_id")

	req2 := httptest.NewRequest(http.MethodPost, "/ui2/collaborator/mint", strings.NewReader("mint_id="+id))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec2 := httptest.NewRecorder()
	s.mux.ServeHTTP(rec2, req2)
	body := rec2.Body.String()
	if !strings.Contains(body, "no out-of-band interaction channel is configured") {
		t.Fatalf("refusal text missing: %s", body[:ui2Min(300, len(body))])
	}
	if !strings.Contains(body, "no interaction server is configured") {
		t.Errorf("configured-state hint missing from the refusal: %s", body[:ui2Min(300, len(body))])
	}
	for _, raw := range []string{`&#34;error&#34;:`, `{"error":`, `003c`, `&#34;status&#34;:`} {
		if strings.Contains(body, raw) {
			t.Errorf("refusal still renders raw JSON (%q present): %s", raw, body[:ui2Min(300, len(body))])
		}
	}
}
