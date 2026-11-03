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
	token, preview, full, errText := s.ui2MintConfirmBody(apiPattern, method, url, body)
	if full != "" {
		preview += " — body " + truncateForDisplay(full, 200)
	}
	return token, preview, errText
}

// ui2MintConfirmBody is ui2MintConfirm without the display truncation: the call line and the
// minted body in full, for a review sheet that must show everything the token binds.
func (s *Server) ui2MintConfirmBody(apiPattern, method, url string, body []byte) (token, callLine, fullBody, errText string) {
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
		return "", "", "", "bad mint response: " + err.Error()
	}
	return minted.Token, fmt.Sprintf("%s %s", minted.Call.Method, minted.Call.URL), minted.Call.Body, ""
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

// handleUI2Intruder serves GET /ui2/intruder: running attacks + the launch form. The base
// request defaults to the newest proxy capture; ?msg_id= picks another stored request.
func (s *Server) handleUI2Intruder(w http.ResponseWriter, r *http.Request) {
	form := url.Values{}
	if v := r.URL.Query().Get("msg_id"); v != "" {
		if _, err := strconv.ParseUint(v, 10, 64); err == nil {
			form.Set("msg_id", v)
		}
	}
	ui2Fragment(w, r, "burpsy /ui2/ — Intruder", "intruder", ui2Exec("intruder.html", s.ui2IntruderPageModel(form)))
}

// ui2IntruderPageModel is the Intruder page model: the attack list and the launch form,
// re-filled from form (empty on a fresh page).
func (s *Server) ui2IntruderPageModel(form url.Values) map[string]any {
	attacks, _ := s.ui2APIResult(http.MethodGet, "/api/intruder/attacks", nil)
	defMsg := ""
	if _, id, raw := ui2LatestExchange(s); raw != "" {
		defMsg = strconv.FormatUint(id, 10)
	}
	return map[string]any{"attacks": attacks, "launch": s.ui2IntruderFormModel(form, defMsg)}
}

// ui2LatestExchange returns the newest non-tool exchange id, the id of its stored request
// message (the id /api/intruder/* takes as msg_id), and the raw request text. Intruder uses it
// only to pick the form's default base request: an attack's target comes from the request it
// names (ui2IntruderBaseTarget), never from whatever was captured last.
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

// handleUI2IntruderPoints serves POST /ui2/intruder/points: the positions section, re-rendered
// after Find positions / Auto § / Clear § (op). Discovery is the read API /api/intruder/points.
func (s *Server) handleUI2IntruderPoints(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	op := r.PostFormValue("op")
	if op != "auto" && op != "clear" {
		op = "find"
	}
	model := s.ui2IntruderPositionsModel(r.PostForm, op)
	ui2Fragment(w, r, "burpsy /ui2/ — Intruder", "intruder", ui2Exec("intruder_attack_positions.html", model))
}

// handleUI2IntruderConfirm serves POST /ui2/intruder/confirm: builds the /api/intruder/run
// payload from the form, mints a confirmation for that exact call, and renders the review sheet
// with the whole bound body.
func (s *Server) handleUI2IntruderConfirm(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	run, selErr := s.ui2IntruderRunPayload(r)
	// No usable selection (nothing discovered, discovery refused, or the operator unchecked
	// "all points" without picking any): /api/intruder/run would refuse the launch, so say so
	// on the confirm step instead of minting a token for a call that cannot succeed.
	if selErr != "" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(ui2Exec("intruder_attack_confirm.html", map[string]any{"error": selErr})))
		return
	}
	payload, _ := ui2Marshal(run)
	token, callLine, fullBody, errText := s.ui2MintConfirmBody("/api/intruder/run", http.MethodPost, "/api/intruder/run", payload)
	if fullBody == "" {
		fullBody = string(payload)
	}
	model := map[string]any{
		"token": token, "call": callLine, "error": errText,
		// The sheet binds the whole body, so it shows the whole body — never the 200-byte
		// one-line preview the other confirm steps use.
		"full_body":    fullBody,
		"run":          run,
		"mode_label":   ui2OptLabel(ui2IntruderModes, run["mode"]),
		"point_labels": s.ui2IntruderPointLabels(run),
		"echo":         ui2ConfirmEcho(r.PostForm, run),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(ui2Exec("intruder_attack_confirm.html", model)))
}

func ui2OptLabel(opts []ui2Opt, v any) string {
	for _, o := range opts {
		if o.Value == v {
			return o.Label
		}
	}
	return fmt.Sprint(v)
}

// ui2IntruderPointLabels names every position the run body selects: discovered points by their
// discovery label, manual spans by the bytes they cover.
func (s *Server) ui2IntruderPointLabels(run map[string]any) []string {
	var out []string
	if pts, ok := run["points"].([]int); ok && len(pts) > 0 {
		all, _ := run["all"].(bool)
		placement, _ := run["payload_placement"].(string)
		disc, _ := s.ui2APIResult(http.MethodPost, "/api/intruder/points", map[string]any{
			"msg_id": run["msg_id"], "all": all, "payload_placement": placement,
		})
		list, _ := disc.([]any)
		for _, p := range pts {
			label := fmt.Sprintf("#%d", p)
			if p >= 0 && p < len(list) {
				if m, ok := list[p].(map[string]any); ok {
					label += fmt.Sprintf(" %v %v = %v", m["kind"], m["label"], m["current"])
				}
			}
			out = append(out, label)
		}
	}
	if spans, ok := run["manual_points"].([]map[string]int); ok {
		msgID, _ := run["msg_id"].(uint64)
		raw, _, _ := s.ui2IntruderBase(msgID)
		for _, sp := range spans {
			text := ""
			if sp["start"] >= 0 && sp["end"] <= len(raw) && sp["start"] <= sp["end"] {
				text = string(raw[sp["start"]:sp["end"]])
			}
			out = append(out, fmt.Sprintf("§ bytes %d–%d = %s", sp["start"], sp["end"], text))
		}
	}
	return out
}

// handleUI2IntruderRun serves POST /ui2/intruder/run: rebuilds the body from the reviewed form
// with the same function the confirm step used, and spends the token on it.
func (s *Server) handleUI2IntruderRun(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	token := r.PostFormValue("token")
	run, errText := s.ui2IntruderRunPayload(r)
	var launched uint64
	switch {
	case errText != "":
		// No dispatch at all without a valid body — spending the confirmation on a body the
		// operator never reviewed is the failure this branch exists to prevent.
	case token == "":
		errText = "no confirmation token: review the attack first"
	default:
		var result any
		result, errText = s.ui2DispatchConfirmed(http.MethodPost, "/api/intruder/run", run, token)
		// /api/intruder/run answers when the attack is over, and its registry entry is gone by
		// then — without this link the just-finished attack's results are unreachable from here.
		if m, ok := result.(map[string]any); ok {
			if id, ok := m["task_id"].(float64); ok && id > 0 {
				launched = uint64(id)
			}
		}
	}
	model := s.ui2IntruderPageModel(r.PostForm)
	model["error"] = errText
	if launched > 0 {
		model["launched_task"] = launched
	}
	ui2Fragment(w, r, "burpsy /ui2/ — Intruder", "intruder", ui2Exec("intruder.html", model))
}

// ui2IntruderAttackID parses the {id} path segment as an attack id.
func ui2IntruderAttackID(r *http.Request) (string, bool) {
	id, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
	return strconv.FormatUint(id, 10), err == nil
}

// handleUI2IntruderControl serves POST /ui2/intruder/{id}/{action}: pause/resume/stop one attack.
func (s *Server) handleUI2IntruderControl(w http.ResponseWriter, r *http.Request) {
	id, ok := ui2IntruderAttackID(r)
	if !ok {
		http.Error(w, "attack id must be a number", http.StatusBadRequest)
		return
	}
	action := r.PathValue("action")
	if action != "pause" && action != "resume" && action != "stop" {
		http.Error(w, "unknown attack action", http.StatusBadRequest)
		return
	}
	_, errText := s.ui2APIResult(http.MethodPost, "/api/intruder/attacks/"+id+"/"+action, map[string]any{})
	model := s.ui2IntruderPageModel(url.Values{})
	model["error"] = errText
	ui2Fragment(w, r, "burpsy /ui2/ — Intruder", "intruder", ui2Exec("intruder.html", model))
}

// handleUI2IntruderResults serves GET /ui2/intruder/{id}/results: the attack's sent requests
// via the datasets table view.
func (s *Server) handleUI2IntruderResults(w http.ResponseWriter, r *http.Request) {
	id, ok := ui2IntruderAttackID(r)
	if !ok {
		http.Error(w, "attack id must be a number", http.StatusBadRequest)
		return
	}
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

// ui2IntruderRunPayload builds the /api/intruder/run body from the launch form. The confirm step
// and the run step both call it, so the body the token was minted for is rebuilt byte-for-byte.
func (s *Server) ui2IntruderRunPayload(r *http.Request) (map[string]any, string) {
	form := r.PostForm
	msgID := ui2Atoi(form.Get("msg_id"))
	run := map[string]any{"msg_id": msgID, "target": strings.TrimSpace(form.Get("target"))}
	if run["target"] == "" {
		// The default target is the base request's own Host — the request this attack
		// replays — recomputed the same way at confirm and at run.
		run["target"] = s.ui2IntruderBaseTarget(msgID)
	}
	if errText := ui2IntruderAddLaunchFields(form, run); errText != "" {
		return run, errText
	}
	// Positions marked by hand: § pairs in the operator's copy of the base request.
	var manual []map[string]int
	if marked := form.Get("marked"); strings.Contains(marked, "§") {
		if mf := form.Get("marked_for"); mf != "" && mf != form.Get("msg_id") {
			return run, "the § markers were placed on message " + mf + ", not on the base request " +
				form.Get("msg_id") + " — find positions again before marking"
		}
		raw, _, ok := s.ui2IntruderBase(msgID)
		if !ok {
			return run, "no stored message " + form.Get("msg_id")
		}
		spans, errText := ui2MarkedSpans(raw, marked)
		if errText != "" {
			return run, errText
		}
		manual = spans
		run["manual_points"] = manual
	}
	// Points: checkbox list point[].
	var points []int
	for _, v := range form["point"] {
		if n, err := strconv.Atoi(v); err == nil {
			points = append(points, n)
		}
	}
	all := form.Get("all_points") == "on"
	if all {
		// "all" selects the discovery CONFIG at run time (intruderPointConfig(true, ...) — the
		// same config the points listing used); it does not select the points: selectPoints
		// refuses a run without an explicit selection. So the payload carries both.
		run["all"] = true
	}
	switch {
	case len(points) > 0:
		// Posted indexes ARE the confirmed set: the review sheet showed exactly these and the
		// gate's digest binds the token to them. Re-resolving here would let a changed message
		// silently widen the confirmed attack.
		run["points"] = points
	case all && form.Get("points_listed") == "":
		// Every candidate, never listed: resolve the selection the way discovery sees it.
		n, errText := s.ui2DiscoveredPointCount(r)
		if errText != "" {
			return run, errText
		}
		if n == 0 && len(manual) == 0 {
			return run, "no insertion points discovered on message " + form.Get("msg_id") +
				" — pick a request whose parameters, cookies or body can carry payloads, or mark positions with §"
		}
		if n > 0 {
			idx := make([]int, n)
			for i := range idx {
				idx[i] = i
			}
			run["points"] = idx
		}
	case len(manual) == 0:
		// Nothing checked and nothing marked selects nothing. Resolving every point anyway
		// turned "I want to choose" into the widest possible attack without a word.
		return run, `no insertion points selected: check "all points", select at least one point, or mark positions with §`
	}
	if v := form.Get("payload_placement"); v != "" {
		run["payload_placement"] = v
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

// ui2ParseCount parses an operator-entered form count. An unparseable value or one past
// the ceiling is refused with the field named, never silently clamped into a body the
// review gate would then mint as if the operator had asked for it. The ceiling keeps the
// uint64->int conversion wrap-free (G115); an empty field means "absent" and the API's
// own validation decides what 0 means there.
func ui2ParseCount(field, s string) (int, string) {
	const ceiling = 1 << 20
	if s == "" {
		return 0, ""
	}
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, field + " must be a whole number"
	}
	if n > ceiling {
		return 0, fmt.Sprintf("%s must be at most %d", field, ceiling)
	}
	return int(n), ""
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
func ui2SequencerCapturePayload(r *http.Request) (map[string]any, string) {
	count, errText := ui2ParseCount("count", r.PostFormValue("count"))
	delay, err := ui2ParseCount("delay_ms", r.PostFormValue("delay_ms"))
	if errText == "" {
		errText = err
	}
	threads, err := ui2ParseCount("threads", r.PostFormValue("threads"))
	if errText == "" {
		errText = err
	}
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
		"count":    count,
		"delay_ms": delay,
		"threads":  threads,
		"location": loc,
	}, errText
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
		payload, errText := ui2SequencerCapturePayload(r)
		if errText != "" {
			model := s.ui2SequencerModel()
			model["error"] = errText
			ui2Fragment(w, r, "burpsy /ui2/ — Sequencer", "sequencer", ui2Exec("sequencer.html", model))
			return
		}
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
		payload, valErr := ui2SequencerCapturePayload(r)
		switch {
		case valErr != "":
			errText = valErr
		case r.PostFormValue("token") == "":
			errText = "no confirmation token: review the capture first"
		default:
			_, errText = s.ui2DispatchConfirmed(http.MethodPost, "/api/sequencer/capture", payload, r.PostFormValue("token"))
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
