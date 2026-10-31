package web

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ---- confirm-gate helper for ui2 mutating forms ---------------------------------------------
//
// Mutating /api routes sit behind the one-time confirmation gate (issue #374's note). A ui2
// form cannot mint-and-spend invisibly, so the flow is deliberate and visible:
//  1. POST /ui2/<page>/confirm  -> server mints a token for the exact internal call and
//     renders a confirmation fragment naming the call.
//  2. Operator clicks "Confirm and run" -> POST /ui2/<page>/run with the token -> server
//     dispatches the internal call WITH X-Burpsy-Confirm: token and renders the result.
//
// ui2MintConfirm mints a confirmation for one internal call and returns the token + preview.
func (s *Server) ui2MintConfirm(apiPattern, method, url string, body []byte) (token string, preview string, errText string) {
	call := map[string]any{"method": method, "url": url}
	if body != nil {
		if isUTF8Bytes(body) {
			call["body"] = string(body)
		} else {
			call["body_base64"] = base64.StdEncoding.EncodeToString(body)
		}
	}
	payload, _ := ui2Marshal(call)
	mintURL := strings.TrimRight(apiPattern, "/") + "/confirm"
	req := newReq(http.MethodPost, mintURL)
	req.Header.Set("Content-Type", "application/json")
	req.Body = ioNopCloser(strings.NewReader(string(payload)))
	rec := newRecorder()
	// The mint endpoints live on confirmMux (a separate mux the guarded chain consults first);
	// dispatch the internal mint straight to it — an in-process call needs no origin headers.
	s.confirmMux.ServeHTTP(rec, req)
	var minted struct {
		Token string `json:"token"`
		Call  struct {
			Method string `json:"method"`
			URL    string `json:"url"`
			Body   string `json:"body"`
		} `json:"call"`
	}
	if err := ui2DecodeJSON(rec.Body.Bytes(), &minted); err != nil {
		return "", "", "bad mint response: " + err.Error()
	}
	preview = fmt.Sprintf("%s %s", minted.Call.Method, minted.Call.URL)
	if minted.Call.Body != "" {
		preview += " — body " + truncateForDisplay(minted.Call.Body, 200)
	}
	return minted.Token, preview, ""
}

// ui2DispatchConfirmed runs one internal call with a confirmation token attached.
func (s *Server) ui2DispatchConfirmed(method, path string, payload any, token string) (any, string) {
	var body ioReadCloser
	if payload != nil {
		b, _ := ui2Marshal(payload)
		body = ioNopCloser(strings.NewReader(string(b)))
	}
	req := newReq(method, path)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
		req.Body = body
	}
	if token != "" {
		req.Header.Set(ConfirmHeader, token)
	}
	// The dispatch must pass both gates, so go through s.guarded with the console's own
	// Host/Origin — the same headers the operator's browser sends.
	req.Host = "127.0.0.1"
	req.Header.Set("Origin", "http://127.0.0.1")
	rec := newRecorder()
	s.guarded.ServeHTTP(rec, req)
	if rec.Code == http.StatusPreconditionRequired {
		return nil, "confirmation required (428) — mint one first"
	}
	if rec.Code != http.StatusOK && rec.Code != http.StatusAccepted {
		return nil, strings.TrimSpace(rec.Body.String())
	}
	var result any
	if err := ui2DecodeJSON(rec.Body.Bytes(), &result); err != nil {
		return nil, "unreadable response: " + err.Error()
	}
	return result, ""
}

func isUTF8Bytes(b []byte) bool { return string(b) == string(strings.ToValidUTF8(string(b), "")) }

func truncateForDisplay(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// ---- Intruder --------------------------------------------------------------------------------

// handleUI2Intruder serves GET /ui2/intruder: running attacks + launch form (points from the
// selected history exchange), and the run/confirm/run chain for launching an attack.
func (s *Server) handleUI2Intruder(w http.ResponseWriter, r *http.Request) {
	model := map[string]any{}
	attacks, _ := s.ui2APIResult(http.MethodGet, "/api/intruder/attacks", nil)
	model["attacks"] = attacks
	wordlists, _ := s.ui2APIResult(http.MethodGet, "/api/wordlists", nil)
	model["wordlists"] = wordlists
	// Latest proxy exchange as the default base request for the launch form.
	model["base_exchange"], model["base_msgid"], model["base_request"] = ui2LatestExchange(s)
	ui2Fragment(w, r, "burpsy /ui2/ — Intruder", "intruder", ui2Exec("intruder.html", model))
}

// ui2LatestExchange returns the newest non-tool exchange id, the id of its stored request
// message (the id /api/intruder/* takes as msg_id), and the raw request text.
func ui2LatestExchange(s *Server) (exchID, msgID uint64, raw string) {
	exs := s.store.Exchanges()
	for i := len(exs) - 1; i >= 0; i-- {
		ex := exs[i]
		switch ex.Source {
		case "repeater", "intruder", "scanner":
			continue
		}
		if ex.Request != nil {
			if msg, err := s.store.Get(*ex.Request); err == nil {
				return uint64(ex.ID), uint64(*ex.Request), string(msg.Raw())
			}
		}
	}
	return 0, 0, ""
}

// handleUI2IntruderPoints serves POST /ui2/intruder/points: enumerate insertion points of the
// given exchange (a read API) and render them as checkboxes.
func (s *Server) handleUI2IntruderPoints(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	msgID := r.PostFormValue("msg_id")
	all := r.PostFormValue("all") == "on" || r.PostFormValue("all") == "true"
	points, errText := s.ui2APIResult(http.MethodPost, "/api/intruder/points",
		map[string]any{"msg_id": ui2Atoi(msgID), "all": all})
	model := map[string]any{"points": points, "error": errText, "msg_id": msgID}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(ui2Exec("intruder_points.html", model)))
}

// handleUI2IntruderConfirm serves POST /ui2/intruder/confirm: builds the /api/intruder/run
// payload from the form, mints a confirmation for that exact call, and renders the confirm UI.
func (s *Server) handleUI2IntruderConfirm(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	run, selErr := s.ui2IntruderRunPayload(r)
	// No usable selection (nothing discovered, discovery refused, or the operator unchecked
	// "all points" without picking any): /api/intruder/run would refuse the launch, so say so
	// on the confirm step instead of minting a token for a call that cannot succeed.
	if selErr != "" {
		model := map[string]any{
			"error": selErr,
			"run":   run, "form": r.PostForm,
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(ui2Exec("intruder_confirm.html", model)))
		return
	}
	payload, _ := ui2Marshal(run)
	token, preview, errText := s.ui2MintConfirm("/api/intruder/run", http.MethodPost, "/api/intruder/run", payload)
	model := map[string]any{
		"token": token, "preview": preview, "error": errText,
		"run": run, "form": r.PostForm,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(ui2Exec("intruder_confirm.html", model)))
}

// handleUI2IntruderRun serves POST /ui2/intruder/run: spends the token on the real call.
func (s *Server) handleUI2IntruderRun(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	token := r.PostFormValue("token")
	run, selErr := s.ui2IntruderRunPayload(r)
	attacks, _ := s.ui2APIResult(http.MethodGet, "/api/intruder/attacks", nil)
	wordlists, _ := s.ui2APIResult(http.MethodGet, "/api/wordlists", nil)
	model := map[string]any{"attacks": attacks, "wordlists": wordlists}
	if selErr != "" {
		// No dispatch at all without a real selection — spending the confirmation on a body
		// the operator never reviewed is the failure this branch exists to prevent.
		model["error"] = selErr
	} else {
		result, errText := s.ui2DispatchConfirmed(http.MethodPost, "/api/intruder/run", run, token)
		model["result"] = result
		model["error"] = errText
		// /api/intruder/run answers when the attack is over, and its registry entry is gone by
		// then — without this link the just-finished attack's results are unreachable from here.
		if m, ok := result.(map[string]any); ok {
			if id, ok := m["task_id"].(float64); ok && id > 0 {
				model["launched_task"] = uint64(id)
			}
		}
	}
	// Re-seed the launch form: without the base request the re-rendered form goes blank.
	model["base_exchange"], model["base_msgid"], model["base_request"] = ui2LatestExchange(s)
	ui2Fragment(w, r, "burpsy /ui2/ — Intruder", "intruder", ui2Exec("intruder.html", model))
}

// handleUI2IntruderControl serves POST /ui2/intruder/{id}/{action}: pause/resume/stop one attack.
func (s *Server) handleUI2IntruderControl(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	action := r.PathValue("action")
	if action != "pause" && action != "resume" && action != "stop" {
		http.Error(w, "unknown attack action", http.StatusBadRequest)
		return
	}
	path := "/api/intruder/attacks/" + id + "/" + action
	_, errText := s.ui2APIResult(http.MethodPost, path, map[string]any{})
	attacks, _ := s.ui2APIResult(http.MethodGet, "/api/intruder/attacks", nil)
	wordlists, _ := s.ui2APIResult(http.MethodGet, "/api/wordlists", nil)
	model := map[string]any{"attacks": attacks, "wordlists": wordlists, "error": errText, "action": action, "id": id}
	model["base_exchange"], model["base_msgid"], model["base_request"] = ui2LatestExchange(s)
	ui2Fragment(w, r, "burpsy /ui2/ — Intruder", "intruder", ui2Exec("intruder.html", model))
}

// handleUI2IntruderResults serves GET /ui2/intruder/{id}/results: the attack's sent requests
// via the datasets table view.
func (s *Server) handleUI2IntruderResults(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	// The label says newest first, so ask for it (the dataset default is ascending ids), and
	// forward the page offset: without it every page request returned the same first 200 rows.
	q := "limit=200&sort_by=id&sort_order=desc"
	if off := r.URL.Query().Get("offset"); off != "" {
		q += "&offset=" + url.QueryEscape(off)
	}
	res, errText := s.ui2APIResult(http.MethodGet, "/api/datasets/intruder/"+id+"?"+q, nil)
	model := map[string]any{"task": id, "results": res, "error": errText}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if r.Header.Get("HX-Request") == "true" {
		_, _ = w.Write([]byte(ui2Exec("intruder_results.html", model)))
		return
	}
	ui2RenderPage(w, "burpsy /ui2/ — Attack "+id, "intruder", ui2Exec("intruder_results.html", model))
}

// ui2IntruderRunPayload builds the /api/intruder/run body from the launch form.
func (s *Server) ui2IntruderRunPayload(r *http.Request) (map[string]any, string) {
	run := map[string]any{
		"msg_id": ui2Atoi(r.PostFormValue("msg_id")),
		"target": r.PostFormValue("target"),
		"mode":   "sniper",
	}
	if r.PostFormValue("target") == "" {
		if _, _, raw := ui2LatestExchange(s); raw != "" {
			run["target"] = ui2HostFromRequest(raw)
		}
	}
	// Payloads: one per line from the textarea.
	var payloads []string
	for _, line := range strings.Split(r.PostFormValue("payloads"), "\n") {
		if p := strings.TrimRight(line, "\r"); p != "" {
			payloads = append(payloads, p)
		}
	}
	if len(payloads) > 0 {
		run["payloads"] = payloads
	}
	// Points: checkbox list points[].
	var points []int
	for _, v := range r.PostForm["point"] {
		if n, err := strconv.Atoi(v); err == nil {
			points = append(points, n)
		}
	}
	if r.PostFormValue("all_points") == "on" {
		// "all" selects the discovery CONFIG at run time (intruderPointConfig(true, ...) — the
		// same config the points listing used); it does not select the points: selectPoints
		// refuses a run without an explicit selection ("no insertion point selected"). So the
		// payload needs both: all:true to keep the discovery config, and the selection as
		// explicit indexes.
		run["all"] = true
		if len(points) > 0 {
			// The confirm fragment posts the minted selection back: those indexes ARE the
			// confirmed set — the operator was shown exactly these, and the gate's digest
			// binds the token to them. Re-resolving here would make the posted inputs inert
			// and let a changed message silently widen the confirmed attack.
			run["points"] = points
		} else {
			// A hand-built post without the fragment's fields: resolve the selection the way
			// the confirm step would have.
			n, errText := s.ui2DiscoveredPointCount(r)
			if errText != "" {
				return run, errText
			}
			if n == 0 {
				// /api/intruder/run would refuse this launch with "no insertion point selected";
				// say so on the form instead of minting a token for a call that cannot succeed.
				return run, "no insertion points discovered on message " + r.PostFormValue("msg_id") +
					" — pick a request whose parameters, cookies or body can carry payloads"
			}
			idx := make([]int, n)
			for i := range idx {
				idx[i] = i
			}
			run["points"] = idx
		}
	} else if len(points) > 0 {
		run["points"] = points
	} else {
		// An unchecked "all points" with no explicit indexes selected nothing. Resolving every
		// point anyway — the previous behaviour — turned "I want to choose" into the widest
		// possible attack without a word; refuse and name the ways to make a selection.
		return run, `no insertion points selected: check "all points" or select at least one point`
	}
	if r.PostFormValue("payload_placement") != "" {
		run["payload_placement"] = r.PostFormValue("payload_placement")
	}
	return run, ""
}

// ui2DiscoveredPointCount counts the insertion points /api/intruder/points discovers for the
// form's message; the error text is the API's own (unknown message, bad placement) when it
// refused, and "" when it answered — 0 then genuinely means nothing to inject into.
func (s *Server) ui2DiscoveredPointCount(r *http.Request) (int, string) {
	disc, errText := s.ui2APIResult(http.MethodPost, "/api/intruder/points", map[string]any{
		"msg_id":            ui2Atoi(r.PostFormValue("msg_id")),
		"all":               true,
		"payload_placement": r.PostFormValue("payload_placement"),
	})
	if errText != "" {
		return 0, errText
	}
	list, ok := disc.([]any)
	if !ok {
		return 0, "point discovery answered in a shape the page does not understand"
	}
	return len(list), ""
}

func ui2Atoi(s string) uint64 {
	n, _ := strconv.ParseUint(s, 10, 64)
	return n
}

// ---- Sequencer -------------------------------------------------------------------------------

// handleUI2Sequencer serves GET /ui2/sequencer: captures list + analyse form.
func (s *Server) handleUI2Sequencer(w http.ResponseWriter, r *http.Request) {
	ui2Fragment(w, r, "burpsy /ui2/ — Sequencer", "sequencer", ui2Exec("sequencer.html", s.ui2SequencerModel()))
}

// ui2SequencerModel is the page model every Sequencer handler re-renders with: the capture
// list and analysis settings, whether any capture is running (drives the control buttons),
// and the latest proxy exchange as the start form's prefilled request.
func (s *Server) ui2SequencerModel() map[string]any {
	caps, _ := s.ui2APIResult(http.MethodGet, "/api/sequencer/capture/", nil)
	settings, _ := s.ui2APIResult(http.MethodGet, "/api/sequencer/settings", nil)
	model := map[string]any{"captures": caps, "settings": settings}
	anyRunning := false
	if m, ok := caps.(map[string]any); ok {
		if list, ok := m["captures"].([]any); ok {
			for _, c := range list {
				if cm, ok := c.(map[string]any); ok {
					if b, ok := cm["capturing"].(bool); ok && b {
						anyRunning = true
					}
				}
			}
		}
	}
	model["any_running"] = anyRunning
	_, _, raw := ui2LatestExchange(s)
	model["base_request"] = raw
	return model
}

// ui2SequencerCapturePayload builds the /api/sequencer/capture body from the start form.
// Zero-value count/delay/threads are left for the API's own defaults and validation to
// report, so the reviewed body is exactly what the operator typed.
func ui2SequencerCapturePayload(r *http.Request) map[string]any {
	loc := map[string]any{"kind": r.PostFormValue("kind")}
	if n := r.PostFormValue("name"); n != "" {
		loc["name"] = n
	}
	if p := r.PostFormValue("pattern"); p != "" {
		loc["pattern"] = p
	}
	return map[string]any{
		"target":   r.PostFormValue("target"),
		"protocol": r.PostFormValue("protocol"),
		// The textarea round-trips line endings as lone LF; the head must be CRLF on the
		// wire or many servers never answer (the repeater's ui2RestoreHeaderNewlines).
		"request":  ui2RestoreHeaderNewlines(r.PostFormValue("request")),
		"count":    int(ui2Atoi(r.PostFormValue("count"))),
		"delay_ms": int(ui2Atoi(r.PostFormValue("delay_ms"))),
		"threads":  int(ui2Atoi(r.PostFormValue("threads"))),
		"location": loc,
	}
}

// handleUI2SequencerCapture serves POST /ui2/sequencer/capture/{action}. "confirm" mints the
// one-time review for the exact start call (/api/sequencer/capture is riskAttack - the gate
// must see the same body the operator reviewed); "run" spends it; pause/resume/stop drive a
// running capture through the API's own control verbs, which are riskRead because stopping
// work cannot attack anything.
func (s *Server) handleUI2SequencerCapture(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	switch r.PathValue("action") {
	case "confirm":
		payload := ui2SequencerCapturePayload(r)
		body, _ := ui2Marshal(payload)
		token, preview, errText := s.ui2MintConfirm("/api/sequencer/capture", http.MethodPost, "/api/sequencer/capture", body)
		model := map[string]any{
			"token": token, "preview": preview, "error": errText,
			// The one-line preview is truncated for display; a confirmation gate has to
			// show the WHOLE exact body it binds, so the sheet carries it in full.
			"full_body": string(body),
			"target":    r.PostFormValue("target"), "protocol": r.PostFormValue("protocol"),
			"count": r.PostFormValue("count"), "delay_ms": r.PostFormValue("delay_ms"),
			"threads": r.PostFormValue("threads"), "kind": r.PostFormValue("kind"),
			"name": r.PostFormValue("name"), "pattern": r.PostFormValue("pattern"),
			"request": r.PostFormValue("request"),
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(ui2Exec("sequencer_confirm.html", model)))
	case "run":
		// No dispatch at all without a token: spending a confirmation on a body the operator
		// never reviewed is the failure this branch exists to prevent.
		var errText string
		if r.PostFormValue("token") == "" {
			errText = "no confirmation token: review the capture first"
		} else {
			_, errText = s.ui2DispatchConfirmed(http.MethodPost, "/api/sequencer/capture", ui2SequencerCapturePayload(r), r.PostFormValue("token"))
		}
		// The model is built after the dispatch, not before: the operator just started a
		// capture and the response is the first place they look for its row.
		model := s.ui2SequencerModel()
		model["error"] = errText
		ui2Fragment(w, r, "burpsy /ui2/ — Sequencer", "sequencer", ui2Exec("sequencer.html", model))
	case "pause", "resume", "stop":
		_, errText := s.ui2APIResult(http.MethodPost, "/api/sequencer/capture/"+r.PathValue("action"), map[string]any{})
		model := s.ui2SequencerModel()
		model["error"] = errText
		ui2Fragment(w, r, "burpsy /ui2/ — Sequencer", "sequencer", ui2Exec("sequencer.html", model))
	default:
		http.Error(w, "unknown capture action", http.StatusBadRequest)
	}
}

// handleUI2SequencerAnalyse serves POST /ui2/sequencer/analyse (paste mode, riskRead — no
// confirmation needed) rendering the report.
func (s *Server) handleUI2SequencerAnalyse(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	var tokens []string
	for _, line := range strings.Split(r.PostFormValue("tokens"), "\n") {
		if t := strings.TrimSpace(line); t != "" {
			tokens = append(tokens, t)
		}
	}
	body := map[string]any{"tokens": tokens, "encoding": r.PostFormValue("encoding")}
	rep, errText := s.ui2APIResult(http.MethodPost, "/api/sequencer/analyse", body)
	caps, _ := s.ui2APIResult(http.MethodGet, "/api/sequencer/capture/", nil)
	var report string
	if errText == "" {
		report = ui2RenderSequencerReport(rep)
	}
	model := map[string]any{"captures": caps, "report": report, "error": errText,
		"tokens": r.PostFormValue("tokens"), "encoding": r.PostFormValue("encoding")}
	ui2Fragment(w, r, "burpsy /ui2/ — Sequencer", "sequencer", ui2Exec("sequencer.html", model))
}

// ---- Collaborator ----------------------------------------------------------------------------

// handleUI2Collaborator serves GET /ui2/collaborator: channel status, minted payloads,
// recorded interactions.
func (s *Server) handleUI2Collaborator(w http.ResponseWriter, r *http.Request) {
	status, _ := s.ui2APIResult(http.MethodGet, "/api/collaborator/status", nil)
	inter, _ := s.ui2APIResult(http.MethodGet, "/api/collaborator/interactions", nil)
	model := map[string]any{"status": status, "interactions": inter}
	ui2Fragment(w, r, "burpsy /ui2/ — Collaborator", "collaborator", ui2Exec("collaborator.html", model))
}

// ui2MintTTL is how long a previewed collaborator mint stays confirmable. Same trade as the
// confirmation gate's ConfirmTTL: long enough to read and click, short enough that a stale
// confirm step refuses instead of minting something the operator stopped looking at.
const ui2MintTTL = 60 * time.Second

// ui2PendingMint is one previewed collaborator mint, held server-side until its confirm step
// spends it. The confirm form carries only the id: the dispatched body is the reviewed one held
// here, never re-read form fields, so a count edited between preview and confirm cannot change
// what runs (a hidden preview field alone would be client-editable and bind nothing).
type ui2PendingMint struct {
	body    []byte
	expires time.Time
}

// handleUI2CollaboratorMint serves POST /ui2/collaborator/mint: mint one payload. The route is
// riskEgress, which the confirmation gate does not cover, so no /api/collaborator/payload/confirm
// mint endpoint exists: the two-step confirm here is ui2-local. The first POST holds the exact
// call server-side and renders it for review; the second (mint_id) spends that held call.
func (s *Server) handleUI2CollaboratorMint(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	status, _ := s.ui2APIResult(http.MethodGet, "/api/collaborator/status", nil)
	inter, _ := s.ui2APIResult(http.MethodGet, "/api/collaborator/interactions", nil)
	if id := r.PostFormValue("mint_id"); id != "" {
		// Confirm step: single-use, and only while fresh. LoadAndDelete spends the id even when
		// the entry turns out stale, so an expired id cannot be retried into a live one.
		v, ok := s.ui2Mints.LoadAndDelete(id)
		mint, isMint := v.(ui2PendingMint)
		if !ok || !isMint || time.Now().After(mint.expires) {
			model := map[string]any{"status": status, "interactions": inter,
				"error": "that confirmation is unknown or has expired — review the call and confirm again"}
			ui2Fragment(w, r, "burpsy /ui2/ — Collaborator", "collaborator", ui2Exec("collaborator.html", model))
			return
		}
		var body map[string]any
		if err := ui2DecodeJSON(mint.body, &body); err != nil {
			model := map[string]any{"status": status, "interactions": inter,
				"error": "the held call is unreadable — review and confirm again"}
			ui2Fragment(w, r, "burpsy /ui2/ — Collaborator", "collaborator", ui2Exec("collaborator.html", model))
			return
		}
		result, errText := s.ui2APIResult(http.MethodPost, "/api/collaborator/payload", body)
		model := map[string]any{"status": status, "interactions": inter, "mint_error": ui2APIErrorText(errText)}
		// Structured result, not the raw response blob: the operator needs the minted
		// addresses, the domain they belong to and the correlating marker — copyable —
		// not a JSON dump that buries them next to config and log noise.
		if errText == "" {
			if m, ok := result.(map[string]any); ok {
				addrs := []string{}
				if arr, ok := m["addresses"].([]any); ok {
					for _, a := range arr {
						if addr, ok := a.(string); ok && addr != "" {
							addrs = append(addrs, addr)
						}
					}
				}
				if len(addrs) == 0 {
					if addr, ok := m["address"].(string); ok && addr != "" {
						addrs = append(addrs, addr)
					}
				}
				domain, _ := m["domain"].(string)
				marker, _ := m["marker"].(string)
				if len(addrs) > 0 {
					model["minted"] = map[string]any{"addresses": addrs, "domain": domain, "marker": marker}
					model["mint_error"] = ""
				} else {
					model["mint_error"] = "the payload API returned no address — check the channel status below"
				}
			}
		}
		ui2Fragment(w, r, "burpsy /ui2/ — Collaborator", "collaborator", ui2Exec("collaborator.html", model))
		return
	}
	// Preview step: hold the exact call server-side and render it for review.
	count := 1
	if n, err := strconv.Atoi(r.PostFormValue("count")); err == nil && n > 0 && n <= 20 {
		count = n
	}
	payload, _ := ui2Marshal(map[string]any{"count": count})
	id, err := randomHex(16)
	if err != nil {
		model := map[string]any{"status": status, "interactions": inter, "error": "mint id: " + err.Error()}
		ui2Fragment(w, r, "burpsy /ui2/ — Collaborator", "collaborator", ui2Exec("collaborator.html", model))
		return
	}
	// Sweep expired entries while here; the map stays as small as the number of open tabs.
	now := time.Now()
	s.ui2Mints.Range(func(k, v any) bool {
		if m, ok := v.(ui2PendingMint); ok && now.After(m.expires) {
			s.ui2Mints.Delete(k)
		}
		return true
	})
	s.ui2Mints.Store(id, ui2PendingMint{body: payload, expires: now.Add(ui2MintTTL)})
	model := map[string]any{"status": status, "interactions": inter,
		"confirm_pending": true, "confirm_preview": "POST /api/collaborator/payload\n" + string(payload),
		"mint_id": id, "count": count}
	ui2Fragment(w, r, "burpsy /ui2/ — Collaborator", "collaborator", ui2Exec("collaborator.html", model))
}

// ui2RenderSequencerReport renders the sequencer analysis JSON as a readable report —
// grade, verdict, entropy figures, per-test outcomes, warnings — never a Go map dump.
// Every partial-analysis fact the API reports (FIPS blocks untested, per-position not
// computed, significance defaulted, warnings) is carried through, not smoothed over.
func ui2RenderSequencerReport(rep any) string {
	m, ok := rep.(map[string]any)
	if !ok {
		return ""
	}
	num := func(v any) float64 {
		f, _ := v.(float64)
		return f
	}
	sub := func(mm map[string]any, k string) map[string]any {
		v, _ := mm[k].(map[string]any)
		return v
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "Grade: %s\n", strOf(m["grade"]))
	if v := strOf(m["verdict"]); v != "" {
		fmt.Fprintf(&sb, "Verdict: %s\n", v)
	}
	// Provenance: what the sample went through before any figure was computed.
	// An operator reading a number must know whether the tokens were re-encoded,
	// decoded, or padded first — a figure over transformed input read as a
	// figure over the pasted text is a wrong conclusion with a citation.
	if enc := strOf(m["encoding"]); enc != "" {
		line := "Encoding: " + enc
		if d, _ := m["encoding_detected"].(bool); d {
			line += " (detected from the sample, not chosen by the operator)"
		}
		sb.WriteString(line + "\n")
	}
	if b, _ := m["base64_decoded"].(bool); b {
		sb.WriteString("Base64: tokens were base64-decoded to their underlying bytes before analysis - every figure below describes the decoded bytes, not the base64 text\n")
	}
	if p := sub(m, "padding"); p != nil {
		switch strOf(p["mode"]) {
		case "start", "end":
			fmt.Fprintf(&sb, "Padding: %v token(s) padded at %s with %s (%v byte(s) added; original token lengths %v..%v)\n",
				p["tokens_padded"], strOf(p["mode"]), strOf(p["pad_byte_label"]), p["pad_bytes_added"], p["orig_min_len"], p["orig_max_len"])
		default:
			sb.WriteString("Padding: none - short tokens are excluded from the positions they do not reach rather than padded with invented characters\n")
		}
	}
	if ee := sub(m, "effective_entropy"); ee != nil {
		chosen := sub(ee, "chosen")
		if c, _ := chosen["computed"].(bool); c {
			line := fmt.Sprintf("Effective entropy: %v bit(s) at %v%% significance",
				chosen["bits"], ee["significance_percent"])
			if d, _ := ee["significance_defaulted"].(bool); d {
				line += " (significance defaulted, not chosen)"
			}
			sb.WriteString(line + "\n")
		} else {
			// Computed false means Bits is null: printing the figure line
			// anyway rendered "Effective entropy: <nil>" on samples too small
			// to support an answer. Name the miss and give the engine's reason.
			line := "Effective entropy: not computed on this sample"
			if r := strOf(chosen["reason"]); r != "" {
				line += " - " + r
			}
			sb.WriteString(line + "\n")
		}
	}
	if ws, _ := m["warnings"].([]any); len(ws) > 0 {
		sb.WriteString("Warnings:\n")
		for _, w := range ws {
			fmt.Fprintf(&sb, "- %s\n", strOf(w))
		}
	}
	if c := sub(m, "characters"); c != nil {
		fmt.Fprintf(&sb, "Characters: %v tokens, lengths %v..%v, alphabet %v, %.2f bits/char, %.2f bits total",
			num(c["tokens"]), num(c["min_len"]), num(c["max_len"]), num(c["alphabet_size"]),
			num(c["entropy_bits_per_char"]), num(c["total_entropy_bits"]))
		if a, _ := c["assumes_positional_independence"].(bool); a {
			sb.WriteString(" (positional independence assumed)")
		}
		sb.WriteByte('\n')
	}
	if es := sub(m, "extra_stats"); es != nil {
		fmt.Fprintf(&sb, "Extra stats: chi-square %v, serial correlation %.4f, Monte Carlo pi %v (deviation %.4f), repeated tokens %v\n",
			es["chi_square"], num(es["serial_correlation"]), es["monte_carlo_pi"], num(es["monte_carlo_deviation"]), es["repeated_tokens"])
	}
	if b := sub(m, "bits"); b != nil {
		fmt.Fprintf(&sb, "Bits: %v supplied, bit entropy %.4f, longest run %v\n",
			num(b["bits"]), num(b["bit_entropy"]), num(b["longest_run"]))
	}
	if f := sub(m, "fips"); f != nil {
		fmt.Fprintf(&sb, "FIPS 140-2: %v of %v supplied bits tested (%v-bit blocks, %v complete) - untested bits are not failed bits\n",
			num(f["bits_tested"]), num(f["bits_supplied"]), num(f["block_bits"]), num(f["blocks_tested"]))
	}
	if fp := sub(m, "fips_positions"); fp != nil {
		if c, _ := fp["computed"].(bool); !c {
			fmt.Fprintf(&sb, "Per-position significance: not computed - %s\n", strOf(fp["reason"]))
		}
	}
	if adv := sub(m, "advanced"); adv != nil {
		fmt.Fprintf(&sb, "Extended tests: %s (grade affected: %v)\n", strOf(adv["summary"]), adv["affects_grade"])
		for _, t := range adv["tests"].([]any) {
			tm, _ := t.(map[string]any)
			if tm == nil {
				continue
			}
			name := strOf(tm["name"])
			if tested, _ := tm["tested"].(bool); !tested {
				fmt.Fprintf(&sb, "  - %s: not testable on this sample - %s\n", name, strOf(tm["reason"]))
			} else if passed, _ := tm["passed"].(bool); passed {
				fmt.Fprintf(&sb, "  - %s: PASS (observed %v, threshold %v)\n", name, tm["observed"], tm["threshold"])
			} else {
				fmt.Fprintf(&sb, "  - %s: FAIL (observed %v, flagged %v of %v examined, threshold %v)\n",
					name, tm["observed"], tm["flagged"], tm["examined"], tm["threshold"])
			}
		}
	}
	return sb.String()
}
