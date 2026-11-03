package web

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/burpsy-go/burpsy/internal/session"
)

// ---- Session tools: reviewed /api/session/* calls ---------------------------------------------
//
// Test/analyze macro, apply extractions, update macro, move, log-in-again probe, cookie jar
// writes, the tracer switch and prompt resolution all post here. review builds the exact call(s);
// when the target route needs confirmation (needsConfirmation(routeRiskFor(path))) it mints one
// gate token per call, holds calls and tokens server-side and renders a redacted review sheet; the
// run form carries only the review id and a one-time nonce. A route that needs no confirmation
// (the tracer, riskLocal) is dispatched at once - review is the operator's own click there.

const ui2SessionCallCap = 8

type ui2SessionHeldCall struct {
	method, url string
	body        []byte
	token       string
	gated       bool
}

type ui2SessionCallReview struct {
	kind    string
	calls   []ui2SessionHeldCall
	nonce   string
	banner  bool
	ruleID  int64
	expires time.Time
}

type ui2SessionCallOut struct {
	code int
	body []byte
}

// handleUI2SessionCall serves POST /ui2/session/call/{action}: review | run.
func (s *Server) handleUI2SessionCall(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	switch r.PathValue("action") {
	case "review":
		s.ui2SessionCallReview(w, r)
	case "run":
		s.ui2SessionCallRun(w, r)
	default:
		http.Error(w, "unknown session tool action", http.StatusBadRequest)
	}
}

func (s *Server) ui2SessionCallFail(w http.ResponseWriter, r *http.Request, banner bool, msg string) {
	if banner {
		s.ui2SessionPromptsRender(w, r, "", msg)
		return
	}
	ui2Fragment(w, r, "burpsy /ui2/ — Session", "session", ui2Exec("session_confirm.html", map[string]any{"error": msg}))
}

func ui2SessionRuleIDOf(r *http.Request) (int64, error) {
	id, err := strconv.ParseInt(r.PostFormValue("rule_id"), 10, 64)
	if err != nil || id <= 0 {
		return 0, fmt.Errorf("that rule id is not valid")
	}
	return id, nil
}

// ui2SessionCallBuild turns the tool form into the exact calls, with the review's own words.
func (s *Server) ui2SessionCallBuild(r *http.Request) (review ui2SessionCallReview, summary, consequence string, err error) {
	kind := r.PostFormValue("call")
	review.kind = kind
	add := func(method, path string, payload any) {
		var body []byte
		if payload != nil {
			body, _ = json.Marshal(payload)
		}
		review.calls = append(review.calls, ui2SessionHeldCall{method: method, url: path, body: body})
	}
	rulePath := func(id int64, suffix string) string {
		return "/api/session/rules/" + strconv.FormatInt(id, 10) + suffix
	}
	ruleName := func(id int64) string {
		if s.sessionCoordinator != nil {
			if rule := s.sessionCoordinator.Rule(session.RuleID(id)); rule != nil {
				return rule.Name
			}
		}
		return ""
	}
	switch kind {
	case "test", "analyze", "update_macro", "apply_extractions", "move_up", "move_down":
		id, e := ui2SessionRuleIDOf(r)
		if e != nil {
			return review, "", "", e
		}
		name := ruleName(id)
		if name == "" {
			return review, "", "", fmt.Errorf("that rule no longer exists")
		}
		review.ruleID = id
		switch kind {
		case "test":
			add(http.MethodPost, rulePath(id, "/test"), nil)
			summary = fmt.Sprintf("Test the macro of rule %q (id %d): a dry run of its steps.", name, id)
			consequence = "The macro's login requests are SENT to the target with their stored credentials. Nothing is saved to the rule; cookies the responses set reach the session jar."
		case "analyze":
			add(http.MethodPost, rulePath(id, "/analyze"), nil)
			summary = fmt.Sprintf("Re-analyze the macro of rule %q (id %d) and suggest extractions.", name, id)
			consequence = "The macro is dry-run (its login requests are SENT to the target) and the responses are read for parameter relationships. Nothing is written to the rule."
		case "update_macro":
			add(http.MethodPost, rulePath(id, "/update-macro"), nil)
			summary = fmt.Sprintf("Update the macro of rule %q (id %d) from its last observed run.", name, id)
			consequence = "The rule's stored steps are REPLACED with what its most recent login run actually sent. Open editors on this rule will refuse to save afterwards."
		case "apply_extractions":
			names := r.PostForm["name"]
			if len(names) == 0 {
				return review, "", "", fmt.Errorf("tick at least one suggested extraction to apply")
			}
			add(http.MethodPost, rulePath(id, "/apply-extractions"), map[string]any{"names": names})
			summary = fmt.Sprintf("Add %d suggested extraction(s) to rule %q (id %d): %s.", len(names), name, id, strings.Join(names, ", "))
			consequence = "The server re-runs the analysis (the macro's login requests are SENT again) and adds only suggestions still current."
		default:
			offset := -1
			if kind == "move_down" {
				offset = 1
			}
			add(http.MethodPost, rulePath(id, "/move"), map[string]any{"offset": offset})
			summary = fmt.Sprintf("Move rule %q (id %d) %s one place in the rule order.", name, id, strings.TrimPrefix(kind, "move_"))
			consequence = "The first enabled rule whose scope covers a request handles it, so the order decides which login runs."
		}
	case "login":
		method := strings.ToUpper(strings.TrimSpace(r.PostFormValue("method")))
		if method == "" {
			method = http.MethodGet
		}
		target := strings.TrimSpace(r.PostFormValue("url"))
		if target == "" {
			return review, "", "", fmt.Errorf("the log-in probe needs a URL")
		}
		hdrs, e := ui2SessionHeaderLines(r.PostFormValue("headers"))
		if e != nil {
			return review, "", "", e
		}
		pairs := [][2]string{}
		for _, n := range ui2SessionSortedHeaders(hdrs) {
			pairs = append(pairs, [2]string{n, hdrs[n]})
		}
		add(http.MethodPost, "/api/session/login", map[string]any{"probe": map[string]any{
			"method": method, "url": target, "headers": pairs, "body": r.PostFormValue("body")}})
		summary = fmt.Sprintf("Run the log-in-again probe: %s %s.", method, ui2SessionRuleSanitizeURL(target))
		consequence = "The probe is SENT to the target. If the matching rule finds the session invalid, its macro (login requests with stored credentials) runs and the probe is retried."
	case "cookie_set", "cookie_remove":
		host := strings.TrimSpace(r.PostFormValue("host"))
		name := strings.TrimSpace(r.PostFormValue("name"))
		port, e := strconv.ParseUint(r.PostFormValue("port"), 10, 16)
		if host == "" || name == "" || e != nil {
			return review, "", "", fmt.Errorf("that cookie row is not valid - refresh the page")
		}
		tls := r.PostFormValue("tls") == "true"
		payload := map[string]any{"action": strings.TrimPrefix(kind, "cookie_"), "host": host, "port": port, "tls": tls, "name": name}
		where := net.JoinHostPort(host, strconv.FormatUint(port, 10))
		if kind == "cookie_set" {
			value := r.PostFormValue("value")
			if value == "" || strings.Contains(value, redactedValue) {
				return review, "", "", fmt.Errorf("enter the new cookie value (the stored value is never shown)")
			}
			payload["value"] = value
			summary = fmt.Sprintf("Set cookie %q on %s to the value you entered.", name, where)
			consequence = "The jar sends the new value with every matching request from now on."
		} else {
			summary = fmt.Sprintf("Remove cookie %q from the jar for %s.", name, where)
			consequence = "Requests to that authority no longer carry it until a response sets it again."
		}
		add(http.MethodPost, "/api/session/cookies", payload)
	case "cookie_empty":
		var jar struct {
			Cookies []sessionHostCookies `json:"cookies"`
		}
		rec := newRecorder()
		s.mux.ServeHTTP(rec, newReq(http.MethodGet, "/api/session/cookies"))
		_ = json.Unmarshal(rec.Body.Bytes(), &jar)
		for _, a := range jar.Cookies {
			host := a.Host
			if h, _, e := net.SplitHostPort(a.Host); e == nil {
				host = h
			}
			add(http.MethodPost, "/api/session/cookies", map[string]any{"action": "clear", "host": host, "port": a.Port, "tls": a.TLS})
		}
		if len(review.calls) == 0 {
			return review, "", "", fmt.Errorf("the jar is already empty")
		}
		summary = fmt.Sprintf("Empty the cookie jar: clear all %d authorit(ies) it holds.", len(review.calls))
		consequence = "Every stored session cookie is dropped; requests go out without them until responses set them again."
	case "trace_on", "trace_off":
		add(http.MethodPost, "/api/session/trace/enable", map[string]any{"enabled": kind == "trace_on"})
		summary = "Turn the session-handling tracer " + strings.TrimPrefix(kind, "trace_") + "."
	case "prompt_resolve":
		review.banner = true
		id, e := strconv.ParseUint(r.PostFormValue("prompt_id"), 10, 64)
		if e != nil {
			return review, "", "", fmt.Errorf("that prompt id is not valid")
		}
		recovered := r.PostFormValue("recovered") == "true"
		add(http.MethodPost, "/api/session/prompts/"+strconv.FormatUint(id, 10)+"/resolve", map[string]any{"recovered": recovered})
		if recovered {
			summary = fmt.Sprintf("Answer prompt %d: I recovered the session in my browser.", id)
			consequence = "The waiting crawl or audit continues, and the engine replays the stored login itself (credentials go back on the wire)."
		} else {
			summary = fmt.Sprintf("Answer prompt %d: I could not recover the session.", id)
			consequence = "The waiting crawl or audit gives up on that request."
		}
	default:
		return review, "", "", fmt.Errorf("unknown session tool")
	}
	for i := range review.calls {
		_, risk, ok := routeRiskFor(strings.SplitN(review.calls[i].url, "?", 2)[0])
		review.calls[i].gated = !ok || needsConfirmation(risk)
	}
	return review, summary, consequence, nil
}

// ui2SessionCallProjection renders the held calls for the review sheet with credential values
// withheld (the rule redactor, plus a cookie write's generic "value" member).
func ui2SessionCallProjection(calls []ui2SessionHeldCall) string {
	parts := make([]string, 0, len(calls))
	for _, c := range calls {
		out := c.method + " " + c.url
		if len(c.body) > 0 {
			var v any
			if json.Unmarshal(c.body, &v) == nil {
				ui2SessionRuleRedact(v)
				if m, ok := v.(map[string]any); ok {
					if val, ok := m["value"].(string); ok && val != "" {
						m["value"] = redactedValue
					}
				}
				if pretty, err := json.MarshalIndent(v, "", "  "); err == nil {
					out += "\n" + string(pretty)
				}
			}
		}
		parts = append(parts, out)
	}
	return strings.Join(parts, "\n\n")
}

func (s *Server) ui2SessionCallReview(w http.ResponseWriter, r *http.Request) {
	review, summary, consequence, err := s.ui2SessionCallBuild(r)
	if err != nil {
		s.ui2SessionCallFail(w, r, review.banner, err.Error())
		return
	}
	gated := false
	for _, c := range review.calls {
		gated = gated || c.gated
	}
	if !gated {
		outs := make([]ui2SessionCallOut, 0, len(review.calls))
		for _, c := range review.calls {
			outs = append(outs, s.ui2SessionDispatch(c, false))
		}
		s.ui2SessionCallResult(w, r, review, outs)
		return
	}
	if s.sessionCoordinator == nil {
		s.ui2SessionCallFail(w, r, review.banner, "no session coordinator is wired on this server")
		return
	}
	for i := range review.calls {
		c := &review.calls[i]
		pattern, _, _ := routeRiskFor(strings.SplitN(c.url, "?", 2)[0])
		token, _, errText := s.ui2MintConfirm(pattern, c.method, c.url, c.body)
		if errText != "" {
			s.ui2SessionCallFail(w, r, review.banner, errText)
			return
		}
		c.token = token
	}
	nonce, err := randomHex(16)
	id, err2 := randomHex(16)
	if err != nil || err2 != nil {
		s.ui2SessionCallFail(w, r, review.banner, "review id could not be generated")
		return
	}
	now := time.Now()
	count := 0
	s.ui2SessionCalls.Range(func(k, v any) bool {
		if e, ok := v.(ui2SessionCallReview); ok && now.After(e.expires) {
			s.ui2SessionCalls.Delete(k)
			return true
		}
		count++
		return true
	})
	if count >= ui2SessionCallCap {
		s.ui2SessionCallFail(w, r, review.banner, "too many reviews are open at once - confirm or let some expire, then try again")
		return
	}
	review.nonce, review.expires = nonce, now.Add(ConfirmTTL)
	s.ui2SessionCalls.Store(id, review)
	ui2Fragment(w, r, "burpsy /ui2/ — Session", "session", ui2Exec("session_call_confirm.html", map[string]any{
		"review_id": id, "nonce": nonce, "summary": summary, "consequence": consequence,
		"preview": ui2SessionCallProjection(review.calls), "banner": review.banner,
	}))
}

// ui2SessionDispatch runs one held call: through the guarded chain with its token when gated,
// straight to the mux otherwise.
func (s *Server) ui2SessionDispatch(c ui2SessionHeldCall, gated bool) ui2SessionCallOut {
	req := newReq(c.method, c.url)
	if c.body != nil {
		req.Header.Set("Content-Type", "application/json")
		req.Body = ioNopCloser(strings.NewReader(string(c.body)))
	}
	rec := newRecorder()
	if gated {
		req.Header.Set(ConfirmHeader, c.token)
		req.Host = "127.0.0.1"
		req.Header.Set("Origin", "http://127.0.0.1")
		s.guarded.ServeHTTP(rec, req)
	} else {
		s.mux.ServeHTTP(rec, req)
	}
	return ui2SessionCallOut{code: rec.Code, body: rec.Body.Bytes()}
}

func (s *Server) ui2SessionCallRun(w http.ResponseWriter, r *http.Request) {
	v, ok := s.ui2SessionCalls.LoadAndDelete(r.PostFormValue("review_id"))
	review, isReview := v.(ui2SessionCallReview)
	banner := r.PostFormValue("banner") == "1"
	if !ok || !isReview {
		s.ui2SessionCallFail(w, r, banner, "that review is unknown or was already used - review it again")
		return
	}
	if time.Now().After(review.expires) {
		s.ui2SessionCallFail(w, r, review.banner, "that review expired with the confirmation window - review it again")
		return
	}
	if subtle.ConstantTimeCompare([]byte(review.nonce), []byte(r.PostFormValue("nonce"))) != 1 {
		s.ui2SessionCallFail(w, r, review.banner, "that review does not match this confirmation - review it again")
		return
	}
	outs := make([]ui2SessionCallOut, 0, len(review.calls))
	for _, c := range review.calls {
		outs = append(outs, s.ui2SessionDispatch(c, c.gated))
	}
	s.ui2SessionCallResult(w, r, review, outs)
}

// ui2SessionCallResult renders what the API answered, by tool. Values a response carries that
// can be credentials (extracted tokens, set cookies, probe bodies) are withheld.
func (s *Server) ui2SessionCallResult(w http.ResponseWriter, r *http.Request, review ui2SessionCallReview, outs []ui2SessionCallOut) {
	for _, o := range outs {
		if o.code >= 300 {
			msg := ui2APIErrorText(strings.TrimSpace(string(o.body)))
			if o.code == http.StatusPreconditionRequired {
				msg = "confirmation required (428) - the review and the dispatch disagree; review again"
			}
			s.ui2SessionCallFail(w, r, review.banner, "the session API refused: "+truncateForDisplay(msg, 300))
			return
		}
	}
	var out map[string]any
	if len(outs) > 0 {
		_ = json.Unmarshal(outs[0].body, &out)
	}
	if review.banner {
		s.ui2SessionPromptsRender(w, r, "prompt answered", "")
		return
	}
	note := ""
	result := map[string]any{"kind": review.kind, "rule_id": review.ruleID}
	switch review.kind {
	case "test", "analyze":
		result["report"] = ui2SessionTestView(out)
		if review.kind == "analyze" {
			result["suggestions"] = ui2SessionSuggestionsView(out)
		}
		note = "macro " + review.kind + " finished"
	case "apply_extractions":
		applied, _ := out["applied"].([]any)
		note = fmt.Sprintf("applied %d extraction(s) to the rule", len(applied))
	case "update_macro":
		steps, _ := out["steps"].([]any)
		note = fmt.Sprintf("macro updated: the rule now stores %d step(s) from its last run", len(steps))
	case "move_up", "move_down":
		note = fmt.Sprintf("rule moved to position %v", out["position"])
	case "login":
		result["login"] = ui2SessionLoginView(out)
		note = "log-in probe finished"
	case "cookie_set":
		note = "cookie updated"
	case "cookie_remove":
		note = "cookie removed"
		if removed, ok := out["removed"].(bool); ok && !removed {
			note = "the cookie was not in the jar"
		}
	case "cookie_empty":
		note = "cookie jar emptied"
	case "trace_on":
		note = "tracer on - it adds work to every request a rule handles; turn it off when you are done"
	case "trace_off":
		note = "tracer off; what it recorded is kept below"
	}
	model := s.ui2SessionView(note)
	model["result"] = result
	ui2Fragment(w, r, "burpsy /ui2/ — Session", "session", ui2Exec("session.html", model))
}

func ui2SessionTestView(out map[string]any) map[string]any {
	view := map[string]any{"status": out["status"]}
	steps, _ := out["steps"].([]any)
	rows := []map[string]any{}
	for _, st := range steps {
		m, _ := st.(map[string]any)
		if m == nil {
			continue
		}
		row := map[string]any{"index": m["index"], "skipped": m["skipped"]}
		if sent, ok := m["sent"].(map[string]any); ok {
			row["method"] = sent["method"]
			if u, ok := sent["url"].(string); ok {
				row["url"] = ui2SessionRuleSanitizeURL(u)
			}
		}
		if resp, ok := m["response"].(map[string]any); ok {
			row["response_status"] = resp["status"]
		}
		names := []string{}
		if sc, ok := m["set_cookies"].([]any); ok {
			for _, c := range sc {
				if line, ok := c.(string); ok {
					name, _, _ := strings.Cut(line, "=")
					names = append(names, strings.TrimSpace(name))
				}
			}
		}
		row["set_cookies"] = strings.Join(names, ", ")
		exs := []map[string]any{}
		if list, ok := m["extractions"].([]any); ok {
			for _, e := range list {
				if em, ok := e.(map[string]any); ok {
					val, _ := em["value"].(string)
					exs = append(exs, map[string]any{"name": em["name"], "outcome": em["outcome"], "detail": em["detail"], "value_len": len(val)})
				}
			}
		}
		row["extractions"] = exs
		rows = append(rows, row)
	}
	view["steps"] = rows
	return view
}

func ui2SessionSuggestionsView(out map[string]any) []map[string]any {
	rows := []map[string]any{}
	list, _ := out["suggestions"].([]any)
	for _, sg := range list {
		m, _ := sg.(map[string]any)
		if m == nil {
			continue
		}
		step := 0
		if f, ok := m["step"].(float64); ok {
			step = int(f) + 1
		}
		val, _ := m["value"].(string)
		rows = append(rows, map[string]any{"name": m["name"], "source": m["source"], "from": m["from"], "header": m["header"], "step": step, "value_len": len(val)})
	}
	return rows
}

func ui2SessionLoginView(out map[string]any) map[string]any {
	view := map[string]any{}
	for _, k := range []string{"outcome", "rule", "rule_id", "login_attempts", "validity", "hint", "attempt", "step_index"} {
		if v, ok := out[k]; ok {
			view[k] = v
		}
	}
	if e, ok := out["error"].(string); ok {
		view["error"] = truncateForDisplay(e, 300)
	}
	if resp, ok := out["response"].(map[string]any); ok {
		body, _ := resp["body"].(string)
		view["response_status"], view["response_len"] = resp["status"], len(body)
	}
	actions := []map[string]any{}
	if list, ok := out["actions"].([]any); ok {
		for _, a := range list {
			if m, ok := a.(map[string]any); ok {
				kind, _ := m["kind"].(string)
				detail, _ := m["detail"].(string)
				actions = append(actions, map[string]any{"label": m["label"], "skipped": m["skipped"], "changed": m["changed"],
					"detail": ui2SessionTraceDetail(kind, detail)})
			}
		}
	}
	view["actions"] = actions
	return view
}

// ui2SessionTraceDetail withholds the value an action detail spells out ("set cookie n=v",
// "set header n: v", "set parameter n=v in the query").
func ui2SessionTraceDetail(kind, detail string) string {
	switch kind {
	case "set_cookie", "set_param":
		if name, rest, ok := strings.Cut(detail, "="); ok {
			tail := ""
			if k := strings.LastIndex(rest, " in the "); k >= 0 && kind == "set_param" {
				tail = rest[k:]
			}
			return name + "=" + redactedValue + tail
		}
	case "set_header":
		if name, _, ok := strings.Cut(detail, ": "); ok {
			return name + ": " + redactedValue
		}
	}
	return detail
}

// ---- prompt banner --------------------------------------------------------------------------

// handleUI2SessionPrompts serves GET /ui2/session/prompts: the pending-prompt banner every ui2
// page loads into #session-prompts. Empty when nothing is pending.
func (s *Server) handleUI2SessionPrompts(w http.ResponseWriter, r *http.Request) {
	s.ui2SessionPromptsRender(w, r, "", "")
}

func (s *Server) ui2SessionPromptsRender(w http.ResponseWriter, r *http.Request, note, errText string) {
	rows := []map[string]any{}
	if s.prompts != nil {
		for _, p := range s.prompts.pending() {
			rows = append(rows, map[string]any{"id": p.ID, "rule": p.RuleName, "url": ui2SessionRuleSanitizeURL(p.RequestURL), "at": p.CreatedAt.Format("15:04:05")})
		}
	}
	ui2Fragment(w, r, "burpsy /ui2/ — Session prompts", "session", ui2Exec("session_prompts.html", map[string]any{
		"prompts": rows, "note": note, "error": errText,
	}))
}

// ui2SessionViewRedact strips credential values from the Session page model before any template
// sees it: cookie values become a length, trace action details lose the value they spell out,
// prompt URLs and rule step URLs are sanitized. It also adds the jar rows' bare host (the write
// API takes host, port, tls) and each rule row's move flags.
func ui2SessionViewRedact(model map[string]any) {
	if jar, ok := model["cookies"].(map[string]any); ok {
		auths, _ := jar["cookies"].([]any)
		for _, a := range auths {
			auth, ok := a.(map[string]any)
			if !ok {
				continue
			}
			authority, _ := auth["host"].(string)
			auth["hostname"] = authority
			if h, _, err := net.SplitHostPort(authority); err == nil {
				auth["hostname"] = h
			}
			if f, ok := auth["port"].(float64); ok {
				auth["port"] = strconv.FormatFloat(f, 'f', 0, 64)
			}
			pairs, _ := auth["cookies"].([]any)
			for _, p := range pairs {
				if pair, ok := p.(map[string]any); ok {
					val, _ := pair["value"].(string)
					delete(pair, "value")
					pair["value_len"] = len(val)
				}
			}
		}
	}
	if tr, ok := model["trace"].(map[string]any); ok {
		entries, _ := tr["entries"].([]any)
		for _, e := range entries {
			entry, ok := e.(map[string]any)
			if !ok {
				continue
			}
			actions, _ := entry["actions"].([]any)
			for _, a := range actions {
				if am, ok := a.(map[string]any); ok {
					kind, _ := am["kind"].(string)
					detail, _ := am["detail"].(string)
					am["detail"] = ui2SessionTraceDetail(kind, detail)
				}
			}
		}
	}
	if pr, ok := model["prompts"].(map[string]any); ok {
		list, _ := pr["prompts"].([]any)
		for _, p := range list {
			if pm, ok := p.(map[string]any); ok {
				if u, ok := pm["request_url"].(string); ok {
					pm["request_url"] = ui2SessionRuleSanitizeURL(u)
				}
			}
		}
	}
	if rv, ok := model["rules"].(map[string]any); ok {
		rows, _ := rv["rules"].([]any)
		for i, row := range rows {
			if rule, ok := row.(map[string]any); ok {
				rule["move_up"], rule["move_down"] = i > 0, i+1 < len(rows)
			}
		}
	}
}
