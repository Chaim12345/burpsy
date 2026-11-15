package web

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
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
	// "Send to Intruder" from an exchange's menu arrives as a seed: it picks the base request.
	notice, seed, ok := s.ui2SeedFor(r, "Intruder", false)
	if ok {
		form.Set("msg_id", strconv.FormatUint(seed.MsgID, 10))
	}
	ui2Fragment(w, r, "burpsy /ui2/ — Intruder", "intruder", notice+ui2Exec("intruder.html", s.ui2IntruderPageModel(form)))
}

// ui2IntruderPageModel is the Intruder page model: the attack list and the launch form,
// re-filled from form (empty on a fresh page).
func (s *Server) ui2IntruderPageModel(form url.Values) map[string]any {
	attacks, _ := s.ui2APIResult(http.MethodGet, "/api/intruder/attacks", nil)
	defMsg := ""
	if _, id, raw := ui2LatestExchange(s); raw != "" {
		defMsg = strconv.FormatUint(id, 10)
	}
	launch := s.ui2IntruderFormModel(form, defMsg)
	launch["settings"] = s.ui2IntruderSettingsForPage(form)
	return map[string]any{"attacks": attacks, "launch": launch}
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
		s.ui2IntruderKeepReport(run, result)
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
	if errText := ui2IntruderApplySettings(run, r.PostForm); errText != "" {
		return run, errText
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

// ---- Collaborator ----------------------------------------------------------------------------
