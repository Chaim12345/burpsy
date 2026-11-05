package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/burpsy-go/burpsy/internal/core"
)

// ---- Engagement tools: CSRF PoC, hidden inputs, Clickbandit -----------------------------------
//
// The CSRF PoC is attacker-shaped HTML built from captured bytes, so the console only ever shows it
// as escaped text; "test in browser" opens the PoC host's one-shot URL (its own origin, never this
// one) and the download is an attachment under a sandbox CSP.

var ui2CSRFTechniques = []string{"auto", "form", "multipart", "plain", "xhr"}

// ui2CSRFParams reads id/technique/auto_submit; the API path is built only from a parsed integer
// and allowlisted values.
func ui2CSRFParams(get func(string) string) (id uint64, technique string, autoSubmit bool, err error) {
	id, err = strconv.ParseUint(strings.TrimSpace(get("id")), 10, 64)
	if err != nil {
		return 0, "", false, fmt.Errorf("enter the exchange id (a whole number from HTTP history)")
	}
	technique = get("technique")
	if technique == "" {
		technique = "auto"
	}
	ok := false
	for _, t := range ui2CSRFTechniques {
		ok = ok || t == technique
	}
	if !ok {
		return 0, "", false, fmt.Errorf("unknown technique %q", technique)
	}
	autoSubmit = get("auto_submit") != "false"
	return id, technique, autoSubmit, nil
}

func ui2CSRFAPIPath(id uint64, technique string, autoSubmit, testURL bool) string {
	q := url.Values{"technique": {technique}, "auto_submit": {strconv.FormatBool(autoSubmit)}}
	if testURL {
		q.Set("test_url", "true")
	}
	return "/api/exchange/" + strconv.FormatUint(id, 10) + "/csrf?" + q.Encode()
}

func (s *Server) ui2CSRFModel(get func(string) string, testURL bool) map[string]any {
	model := map[string]any{"techniques": ui2CSRFTechniques, "technique": "auto", "auto_submit": true}
	if strings.TrimSpace(get("id")) == "" {
		return model
	}
	model["id"] = get("id")
	id, technique, autoSubmit, err := ui2CSRFParams(get)
	if err != nil {
		model["error"] = err.Error()
		return model
	}
	model["id"], model["technique"], model["auto_submit"] = id, technique, autoSubmit
	res, errText := s.ui2APIResult(http.MethodGet, ui2CSRFAPIPath(id, technique, autoSubmit, testURL), nil)
	if errText != "" {
		model["error"] = ui2APIErrorText(errText)
		return model
	}
	model["poc"] = res
	model["download"] = fmt.Sprintf("/ui2/engagement/csrf/%d/download?%s", id,
		url.Values{"technique": {technique}, "auto_submit": {strconv.FormatBool(autoSubmit)}}.Encode())
	return model
}

// handleUI2EngagementCSRF serves GET /ui2/engagement/csrf[?id=&technique=&auto_submit=].
func (s *Server) handleUI2EngagementCSRF(w http.ResponseWriter, r *http.Request) {
	model := s.ui2CSRFModel(r.URL.Query().Get, false)
	ui2Fragment(w, r, "burpsy /ui2/ — CSRF PoC", "csrf", ui2Exec("engagement_csrf.html", model))
}

// handleUI2EngagementCSRFTest serves POST /ui2/engagement/csrf/test: regenerates the PoC and mints
// a one-shot URL on the PoC host (state on the server, hence POST).
func (s *Server) handleUI2EngagementCSRFTest(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	model := s.ui2CSRFModel(r.PostFormValue, true)
	ui2Fragment(w, r, "burpsy /ui2/ — CSRF PoC", "csrf", ui2Exec("engagement_csrf.html", model))
}

// handleUI2EngagementCSRFDownload serves GET /ui2/engagement/csrf/{id}/download: the PoC as an
// attachment. The sandbox CSP keeps it inert even if a browser were to render it in place.
func (s *Server) handleUI2EngagementCSRFDownload(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	get := func(k string) string {
		if k == "id" {
			return r.PathValue("id")
		}
		return q.Get(k)
	}
	id, technique, autoSubmit, err := ui2CSRFParams(get)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	res, errText := s.ui2APIResult(http.MethodGet, ui2CSRFAPIPath(id, technique, autoSubmit, false), nil)
	if errText != "" {
		http.Error(w, ui2APIErrorText(errText), http.StatusNotFound)
		return
	}
	m, _ := res.(map[string]any)
	poc, _ := m["html"].(string)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="csrf-poc-%d.html"`, id))
	w.Header().Set("Content-Security-Policy", "sandbox")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	// #nosec G705 -- served as an attachment under a sandbox CSP, never rendered in this origin.
	_, _ = w.Write([]byte(poc))
}

// ---- Hidden inputs ---------------------------------------------------------------------------

var ui2HiddenInputKinds = []string{"query", "cookie", "header"}

// ui2HiddenInputsBody builds the POST /api/hidden-inputs body from the form; confirm and run both
// call it so the run sends exactly what the token binds.
func ui2HiddenInputsBody(r *http.Request) (hiddenInputStartReq, error) {
	id, err := strconv.ParseUint(strings.TrimSpace(r.PostFormValue("exchange_id")), 10, 64)
	if err != nil {
		return hiddenInputStartReq{}, fmt.Errorf("enter the exchange id (a whole number from HTTP history)")
	}
	var kinds []string
	for _, k := range ui2HiddenInputKinds {
		for _, v := range r.PostForm["kinds"] {
			if v == k {
				kinds = append(kinds, k)
				break
			}
		}
	}
	if len(kinds) == 0 {
		return hiddenInputStartReq{}, fmt.Errorf("pick at least one input kind to guess")
	}
	budget := 0
	if raw := strings.TrimSpace(r.PostFormValue("max_requests")); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > maxHiddenInputBudget {
			return hiddenInputStartReq{}, fmt.Errorf("the request budget must be 1-%d", maxHiddenInputBudget)
		}
		budget = n
	}
	exID := core.ExchangeID(id)
	cb := r.PostFormValue("cache_buster") == "on"
	return hiddenInputStartReq{ExchangeID: &exID, Kinds: kinds, MaxRequests: budget, CacheBuster: &cb}, nil
}

func (s *Server) ui2HiddenInputsModel(task string) map[string]any {
	model := map[string]any{"kinds": ui2HiddenInputKinds}
	list, errText := s.ui2APIResult(http.MethodGet, "/api/hidden-inputs", nil)
	m, _ := list.(map[string]any)
	wordlist, _ := m["wordlist"].(map[string]any)
	if wordlist == nil {
		wordlist = map[string]any{}
	}
	model["runs"], model["wordlist"], model["default_budget"], model["list_error"] = m["runs"], wordlist, m["default_budget"], errText
	if task != "" {
		model["run"] = s.ui2HiddenInputRun(task)
	}
	return model
}

// ui2HiddenInputRun loads one run for the live panel; a bad id renders as a note, not a 500.
func (s *Server) ui2HiddenInputRun(task string) map[string]any {
	id, err := strconv.ParseUint(task, 10, 64)
	if err != nil {
		return map[string]any{"error": "task must be a whole number"}
	}
	res, errText := s.ui2APIResult(http.MethodGet, "/api/hidden-inputs?task="+strconv.FormatUint(id, 10), nil)
	if errText != "" {
		return map[string]any{"error": ui2APIErrorText(errText), "task": id}
	}
	m, _ := res.(map[string]any)
	if m == nil {
		m = map[string]any{}
	}
	m["task"] = id
	return m
}

// handleUI2EngagementHiddenInputs serves GET /ui2/engagement/hidden-inputs[?task=N[&frag=run]].
func (s *Server) handleUI2EngagementHiddenInputs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("frag") == "run" && q.Get("task") != "" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(ui2Exec("engagement_hidden_inputs_run.html", s.ui2HiddenInputRun(q.Get("task")))))
		return
	}
	model := s.ui2HiddenInputsModel(q.Get("task"))
	model["exchange_id"] = q.Get("id")
	ui2Fragment(w, r, "burpsy /ui2/ — Hidden inputs", "hidden-inputs", ui2Exec("engagement_hidden_inputs.html", model))
}

// handleUI2EngagementHiddenInputsAction serves POST /ui2/engagement/hidden-inputs/{confirm|run}.
func (s *Server) handleUI2EngagementHiddenInputsAction(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	action := r.PathValue("action")
	if action != "confirm" && action != "run" {
		http.Error(w, "unknown hidden-inputs action", http.StatusBadRequest)
		return
	}
	render := func(name string, model map[string]any) {
		ui2Fragment(w, r, "burpsy /ui2/ — Hidden inputs", "hidden-inputs", ui2Exec(name, model))
	}
	body, err := ui2HiddenInputsBody(r)
	if err != nil {
		render("engagement_hidden_inputs_confirm.html", map[string]any{"error": err.Error()})
		return
	}
	if action == "run" {
		res, errText := s.ui2DispatchConfirmed(http.MethodPost, "/api/hidden-inputs", body, r.PostFormValue("token"))
		task := ""
		if m, ok := res.(map[string]any); ok {
			if n, ok := m["task_id"].(float64); ok {
				task = strconv.FormatUint(uint64(n), 10)
			}
		}
		model := s.ui2HiddenInputsModel(task)
		model["exchange_id"] = strconv.FormatUint(uint64(*body.ExchangeID), 10)
		if errText != "" {
			model["error"] = ui2APIErrorText(errText)
		}
		render("engagement_hidden_inputs.html", model)
		return
	}
	payload, _ := json.Marshal(body)
	ex, exErr := s.store.GetExchange(*body.ExchangeID)
	if exErr != nil {
		render("engagement_hidden_inputs_confirm.html", map[string]any{"error": fmt.Sprintf("no exchange %d", *body.ExchangeID)})
		return
	}
	token, _, errText := s.ui2MintConfirm("/api/hidden-inputs", http.MethodPost, "/api/hidden-inputs", payload)
	if errText != "" {
		render("engagement_hidden_inputs_confirm.html", map[string]any{"error": errText})
		return
	}
	budget := "the default budget"
	if body.MaxRequests > 0 {
		budget = strconv.Itoa(body.MaxRequests) + " requests"
	}
	render("engagement_hidden_inputs_confirm.html", map[string]any{
		"summary": fmt.Sprintf("Guess hidden %s against exchange %d (%s %s%s): up to %s sent to that target, cache buster %s.",
			strings.Join(body.Kinds, ", "), *body.ExchangeID, ex.Method, ex.Host, ex.Path, budget, ui2OnOff(*body.CacheBuster)),
		"preview":      "POST /api/hidden-inputs\n" + string(payload),
		"token":        token,
		"exchange_id":  uint64(*body.ExchangeID),
		"kinds":        body.Kinds,
		"max_requests": r.PostFormValue("max_requests"),
		"cache_buster": *body.CacheBuster,
	})
}

// ---- Clickbandit -----------------------------------------------------------------------------

// handleUI2EngagementClickbandit serves GET /ui2/engagement/clickbandit: the script as copyable text.
func (s *Server) handleUI2EngagementClickbandit(w http.ResponseWriter, r *http.Request) {
	rec := newRecorder()
	s.mux.ServeHTTP(rec, newReq(http.MethodGet, "/api/engagement/clickbandit.js"))
	model := map[string]any{"script": rec.Body.String()}
	if rec.Code != http.StatusOK {
		model = map[string]any{"error": strings.TrimSpace(rec.Body.String())}
	}
	ui2Fragment(w, r, "burpsy /ui2/ — Clickbandit", "clickbandit", ui2Exec("engagement_clickbandit.html", model))
}
