package web

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"strings"
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
	model["base_exchange"], model["base_request"] = ui2LatestExchange(s)
	ui2Fragment(w, r, "burpsy /ui2/ — Intruder", "intruder", ui2Exec("intruder.html", model))
}

// ui2LatestExchange returns the newest non-tool exchange id and its raw request text.
func ui2LatestExchange(s *Server) (id uint64, raw string) {
	exs := s.store.Exchanges()
	for i := len(exs) - 1; i >= 0; i-- {
		ex := exs[i]
		switch ex.Source {
		case "repeater", "intruder", "scanner":
			continue
		}
		if ex.Request != nil {
			if msg, err := s.store.Get(*ex.Request); err == nil {
				return uint64(ex.ID), string(msg.Raw())
			}
		}
	}
	return 0, ""
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
	run := s.ui2IntruderRunPayload(r)
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
	run := s.ui2IntruderRunPayload(r)
	result, errText := s.ui2DispatchConfirmed(http.MethodPost, "/api/intruder/run", run, token)
	attacks, _ := s.ui2APIResult(http.MethodGet, "/api/intruder/attacks", nil)
	model := map[string]any{"attacks": attacks, "result": result, "error": errText}
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
	model := map[string]any{"attacks": attacks, "error": errText, "action": action, "id": id}
	ui2Fragment(w, r, "burpsy /ui2/ — Intruder", "intruder", ui2Exec("intruder.html", model))
}

// handleUI2IntruderResults serves GET /ui2/intruder/{id}/results: the attack's sent requests
// via the datasets table view.
func (s *Server) handleUI2IntruderResults(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	res, errText := s.ui2APIResult(http.MethodGet, "/api/datasets/intruder/"+id+"?limit=200", nil)
	model := map[string]any{"task": id, "results": res, "error": errText}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if r.Header.Get("HX-Request") == "true" {
		_, _ = w.Write([]byte(ui2Exec("intruder_results.html", model)))
		return
	}
	ui2RenderPage(w, "burpsy /ui2/ — Attack "+id, "intruder", ui2Exec("intruder_results.html", model))
}

// ui2IntruderRunPayload builds the /api/intruder/run body from the launch form.
func (s *Server) ui2IntruderRunPayload(r *http.Request) map[string]any {
	run := map[string]any{
		"msg_id": ui2Atoi(r.PostFormValue("msg_id")),
		"target": r.PostFormValue("target"),
		"mode":   "sniper",
	}
	if r.PostFormValue("target") == "" {
		if _, raw := ui2LatestExchange(s); raw != "" {
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
		run["all"] = true
	} else if len(points) > 0 {
		run["points"] = points
	} else {
		run["all"] = true // default: all discovered points
	}
	if r.PostFormValue("payload_placement") != "" {
		run["payload_placement"] = r.PostFormValue("payload_placement")
	}
	return run
}

func ui2Atoi(s string) uint64 {
	n, _ := strconv.ParseUint(s, 10, 64)
	return n
}

// ---- Sequencer -------------------------------------------------------------------------------

// handleUI2Sequencer serves GET /ui2/sequencer: captures list + analyse form.
func (s *Server) handleUI2Sequencer(w http.ResponseWriter, r *http.Request) {
	caps, _ := s.ui2APIResult(http.MethodGet, "/api/sequencer/capture/", nil)
	settings, _ := s.ui2APIResult(http.MethodGet, "/api/sequencer/settings", nil)
	model := map[string]any{"captures": caps, "settings": settings}
	ui2Fragment(w, r, "burpsy /ui2/ — Sequencer", "sequencer", ui2Exec("sequencer.html", model))
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
	model := map[string]any{"captures": caps, "report": rep, "error": errText,
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

// handleUI2CollaboratorMint serves POST /ui2/collaborator/mint: mint one payload (riskEgress —
// confirm first via the same two-step pattern). The confirm step is a GET form; the run POST
// carries the token.
func (s *Server) handleUI2CollaboratorMint(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	token := r.PostFormValue("token")
	count := 1
	if n, err := strconv.Atoi(r.PostFormValue("count")); err == nil && n > 0 && n <= 20 {
		count = n
	}
	body := map[string]any{"count": count}
	payload, _ := ui2Marshal(body)
	if token == "" {
		tok, preview, errText := s.ui2MintConfirm("/api/collaborator/payload", http.MethodPost, "/api/collaborator/payload", payload)
		status, _ := s.ui2APIResult(http.MethodGet, "/api/collaborator/status", nil)
		inter, _ := s.ui2APIResult(http.MethodGet, "/api/collaborator/interactions", nil)
		model := map[string]any{"status": status, "interactions": inter,
			"confirm_token": tok, "confirm_preview": preview, "confirm_error": errText, "count": count}
		ui2Fragment(w, r, "burpsy /ui2/ — Collaborator", "collaborator", ui2Exec("collaborator.html", model))
		return
	}
	result, errText := s.ui2DispatchConfirmed(http.MethodPost, "/api/collaborator/payload", body, token)
	status, _ := s.ui2APIResult(http.MethodGet, "/api/collaborator/status", nil)
	inter, _ := s.ui2APIResult(http.MethodGet, "/api/collaborator/interactions", nil)
	model := map[string]any{"status": status, "interactions": inter, "result": result, "error": errText}
	ui2Fragment(w, r, "burpsy /ui2/ — Collaborator", "collaborator", ui2Exec("collaborator.html", model))
}
