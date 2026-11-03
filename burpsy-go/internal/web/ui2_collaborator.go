package web

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ---- Collaborator ----------------------------------------------------------------------------
//
// The page reads /api/collaborator/status, /interactions and /api/blindxss in process and renders
// them; every write is a POST. Three API calls change something outside this page and go through
// a held review (ui2Mints): the payload mint and the health check (riskEgress: they contact the
// interaction server) and the server set/unset (riskScope: it chooses that third party). The
// review holds the exact method, path and body; when the route is gated (needsConfirmation) it
// also mints a gate token bound to those bytes, so the run step dispatches the held bytes through
// the gate verbatim. Poll (riskRead) and the blind-XSS mint (riskLocal, sends nothing) run
// directly. Read state, highlights and comments are this browser's notes (app.js, localStorage).

const ui2CollabTitle = "burpsy /ui2/ — Collaborator"

// ui2MintTTL is how long a previewed collaborator call stays confirmable. Same trade as the
// confirmation gate's ConfirmTTL: long enough to read and click, short enough that a stale
// confirm step refuses instead of running something the operator stopped looking at.
const ui2MintTTL = 60 * time.Second

// ui2MintCap bounds ui2Mints like the other review maps: a full map refuses and says so.
const ui2MintCap = 8

// ui2PendingMint is one previewed collaborator call, held server-side until its confirm step
// spends it. The confirm form carries only the id (plus the gate token for a gated route): the
// dispatched body is the reviewed one held here, never re-read form fields.
type ui2PendingMint struct {
	kind    string // "mint" | "health" | "server"
	method  string
	path    string
	body    []byte
	token   string // gate token when the route needs confirmation, else empty
	expires time.Time
}

// ui2CollabMinted is the structured result of a payload mint.
type ui2CollabMinted struct {
	Addresses []string
	Domain    string
	Marker    string
}

// ui2CollabRow is one interaction row as the table renders it.
type ui2CollabRow struct {
	collaboratorInteractionRow
	TypeUpper string
	Time      string
}

// ui2BXRow is one blind-XSS payload row.
type ui2BXRow struct {
	Token       string
	TokenShort  string
	ScriptURL   string
	ScriptTag   string
	Outstanding bool
	Hits        int
	LastHit     string
}

// ui2CollabTime renders epoch millis as the console's wall-clock format.
func ui2CollabTime(ms int64) string {
	if ms <= 0 {
		return ""
	}
	return time.UnixMilli(ms).Format("2006-01-02 15:04:05")
}

// ui2CollabModel is the whole Collaborator page.
type ui2CollabModel struct {
	Status    collaboratorStatus
	StatusErr string
	LastRead  string // "never", the read time, or the read's error

	Rows      []ui2CollabRow
	RowsTotal int
	Protocols []string
	Protocol  string
	Q         string
	InterErr  string
	Counts    *collaboratorCounts

	BX       blindxssStateView
	BXRows   []ui2BXRow
	BXErr    string
	BXMinted *mintedBlindXSSPayload
	BXCaveat string

	// Outcome lines: Error is a refusal the operator must read, Done is the landed fact.
	Error string
	Done  string

	// Payload mint review / result.
	ConfirmPending bool
	ConfirmPreview string
	MintID         string
	Count          int
	Minted         *ui2CollabMinted
	MintError      string

	// Health check review / result.
	HealthPending bool
	HealthPreview string
	HealthID      string
	Health        *collaboratorHealthReport
	HealthError   string

	// Server set/unset review.
	ServerReview *ui2CollabServerReview
	ServerInput  string
	ClientInput  string
}

// ui2CollabServerReview is the review sheet for one set/unset call.
type ui2CollabServerReview struct {
	ID      string
	Token   string
	Gated   bool
	Unset   bool
	Preview string // the FULL bound call: method, path and body
	Domain  string
	Orphans int
}

// ui2CollabCall runs one in-process API call. Any 2xx decodes into out; anything else comes back
// as the API's readable refusal. (ui2APIResult insists on 200, and /api/blindxss/payload is 201.)
func (s *Server) ui2CollabCall(method, path string, body []byte, out any) string {
	req := newReq(method, path)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
		req.Body = ioNopCloser(strings.NewReader(string(body)))
	}
	rec := newRecorder()
	s.mux.ServeHTTP(rec, req)
	return ui2CollabOutcome(rec, out)
}

func ui2CollabOutcome(rec *recorderAlias, out any) string {
	if rec.Code < 200 || rec.Code > 299 {
		return ui2CollabRefusal(rec.Body.String())
	}
	if out != nil {
		if err := json.Unmarshal(rec.Body.Bytes(), out); err != nil {
			return "unreadable response: " + err.Error()
		}
	}
	return ""
}

// ui2CollabRefusal renders an API refusal: the error sentence plus its hint or detail, never the
// raw JSON. A plain-text body comes back trimmed.
func ui2CollabRefusal(body string) string {
	body = strings.TrimSpace(body)
	var m map[string]any
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		return body
	}
	msg, _ := m["error"].(string)
	if msg == "" {
		return body
	}
	for _, k := range []string{"hint", "detail"} {
		if extra, _ := m[k].(string); extra != "" {
			msg += " — " + extra
		}
	}
	return msg
}

// ui2CollabPage loads every model the page renders. Filters come from the query (GET) or the
// form (POST re-render), so a write keeps the operator's filter.
func (s *Server) ui2CollabPage(r *http.Request) *ui2CollabModel {
	m := &ui2CollabModel{Count: 1}
	m.Protocol = strings.ToLower(strings.TrimSpace(r.FormValue("protocol")))
	m.Q = strings.TrimSpace(r.FormValue("q"))
	m.StatusErr = s.ui2CollabCall(http.MethodGet, "/api/collaborator/status", nil, &m.Status)
	switch lr := m.Status.LastRead; {
	case lr == nil:
		m.LastRead = "never"
	case lr.OK:
		m.LastRead = ui2CollabTime(lr.AtMs)
	default:
		m.LastRead = "failed: " + lr.Error
	}
	var inter struct {
		Rows         []collaboratorInteractionRow `json:"rows"`
		Interactions *collaboratorCounts          `json:"interactions"`
	}
	m.InterErr = s.ui2CollabCall(http.MethodGet, "/api/collaborator/interactions", nil, &inter)
	m.Counts = inter.Interactions
	m.RowsTotal = len(inter.Rows)
	seen := map[string]bool{}
	needle := strings.ToLower(m.Q)
	for _, row := range inter.Rows {
		t := strings.ToLower(row.Type)
		if !seen[t] {
			seen[t] = true
			m.Protocols = append(m.Protocols, t)
		}
		if m.Protocol != "" && m.Protocol != "all" && t != m.Protocol {
			continue
		}
		if needle != "" {
			hay := strings.ToLower(fmt.Sprintf("%d %s %s %s %s %s", row.ID, row.InteractionID, row.Type, row.QType, row.ClientIP, row.Payload))
			if !strings.Contains(hay, needle) {
				continue
			}
		}
		m.Rows = append(m.Rows, ui2CollabRow{collaboratorInteractionRow: row, TypeUpper: strings.ToUpper(row.Type), Time: ui2CollabTime(row.AtMs)})
	}
	sort.Strings(m.Protocols)
	m.BXErr = s.ui2CollabCall(http.MethodGet, "/api/blindxss", nil, &m.BX)
	for _, p := range m.BX.Payloads {
		row := ui2BXRow{Token: p.Token, TokenShort: p.Token, ScriptURL: p.ScriptURL, ScriptTag: p.ScriptTag,
			Outstanding: p.Outstanding, Hits: len(p.Hits), LastHit: "—"}
		if len(row.TokenShort) > 12 {
			row.TokenShort = row.TokenShort[:12]
		}
		if n := len(p.Hits); n > 0 {
			row.LastHit = p.Hits[n-1].ReceivedAt.Local().Format("2006-01-02 15:04:05")
		}
		m.BXRows = append(m.BXRows, row)
	}
	return m
}

func (s *Server) ui2CollabRender(w http.ResponseWriter, r *http.Request, m *ui2CollabModel) {
	// A filter change targets the interactions block alone, so the search box keeps its focus.
	if r.Header.Get("HX-Target") == "collab-interactions" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(ui2Exec("collaborator_interactions.html", m)))
		return
	}
	ui2Fragment(w, r, ui2CollabTitle, "collaborator", ui2Exec("collaborator_page.html", m))
}

// handleUI2Collaborator serves GET /ui2/collaborator: the channel, its metrics, the interactions
// (filtered by ?protocol= and ?q=) and the blind-XSS callbacks.
func (s *Server) handleUI2Collaborator(w http.ResponseWriter, r *http.Request) {
	s.ui2CollabRender(w, r, s.ui2CollabPage(r))
}

// ui2CollabHold holds one reviewed call in ui2Mints. Gating is derived from the route's risk
// class: a gated route gets a gate token bound to the exact bytes. Expired entries are swept
// first, and a map still holding ui2MintCap entries refuses rather than growing.
func (s *Server) ui2CollabHold(kind, method, path string, body []byte) (id, token, errText string) {
	if _, risk, ok := routeRiskFor(path); ok && needsConfirmation(risk) {
		call, _ := json.Marshal(map[string]any{"method": method, "url": path, "body": string(body)})
		req := newReq(http.MethodPost, strings.TrimRight(path, "/")+"/confirm")
		req.Header.Set("Content-Type", "application/json")
		req.Body = ioNopCloser(strings.NewReader(string(call)))
		rec := newRecorder()
		s.confirmMux.ServeHTTP(rec, req)
		var minted struct {
			Token string `json:"token"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &minted); err != nil || minted.Token == "" {
			return "", "", "the confirmation gate refused to mint a review — try again"
		}
		token = minted.Token
	}
	now := time.Now()
	count := 0
	s.ui2Mints.Range(func(k, v any) bool {
		if m, ok := v.(ui2PendingMint); !ok || now.After(m.expires) {
			s.ui2Mints.Delete(k)
		} else {
			count++
		}
		return true
	})
	if count >= ui2MintCap {
		return "", "", "too many reviews are open at once — confirm or let some expire, then try again"
	}
	id, err := randomHex(16)
	if err != nil {
		return "", "", "review id: " + err.Error()
	}
	s.ui2Mints.Store(id, ui2PendingMint{kind: kind, method: method, path: path, body: body, token: token, expires: now.Add(ui2MintTTL)})
	return id, token, ""
}

// ui2CollabSpend spends one held call: single-use (LoadAndDelete spends even a stale or
// mismatched id), only while fresh, only for its own kind, and with the gate token the review
// rendered. The held bytes are dispatched verbatim — through the gate when a token is held.
func (s *Server) ui2CollabSpend(kind, id, token string, out any) string {
	v, ok := s.ui2Mints.LoadAndDelete(id)
	held, isHeld := v.(ui2PendingMint)
	if !ok || !isHeld || held.kind != kind || time.Now().After(held.expires) {
		return "that confirmation is unknown or has expired — review the call and confirm again"
	}
	if subtle.ConstantTimeCompare([]byte(held.token), []byte(token)) != 1 {
		return "that review does not match this confirmation — review the call and confirm again"
	}
	req := newReq(held.method, held.path)
	req.Header.Set("Content-Type", "application/json")
	req.Body = ioNopCloser(strings.NewReader(string(held.body)))
	rec := newRecorder()
	if held.token != "" {
		req.Header.Set(ConfirmHeader, held.token)
		req.Host = "127.0.0.1"
		req.Header.Set("Origin", "http://127.0.0.1")
		s.guarded.ServeHTTP(rec, req)
		if rec.Code == http.StatusPreconditionRequired {
			return "confirmation required (428) — the review and the dispatch disagree; review again"
		}
	} else {
		s.mux.ServeHTTP(rec, req)
	}
	return ui2CollabOutcome(rec, out)
}

// handleUI2CollaboratorMint serves POST /ui2/collaborator/mint: the first POST (count) holds the
// exact /api/collaborator/payload call and renders it for review; the second (mint_id) spends it.
func (s *Server) handleUI2CollaboratorMint(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	if id := r.PostFormValue("mint_id"); id != "" {
		var result struct {
			Address   string   `json:"address"`
			Addresses []string `json:"addresses"`
			Domain    string   `json:"domain"`
			Marker    string   `json:"marker"`
		}
		errText := s.ui2CollabSpend("mint", id, "", &result)
		m := s.ui2CollabPage(r)
		switch {
		case strings.HasPrefix(errText, "that confirmation"):
			m.Error = errText
		case errText != "":
			m.MintError = errText
		default:
			addrs := []string{}
			for _, a := range result.Addresses {
				if a != "" {
					addrs = append(addrs, a)
				}
			}
			if len(addrs) == 0 && result.Address != "" {
				addrs = append(addrs, result.Address)
			}
			if len(addrs) == 0 {
				m.MintError = "the payload API returned no address — check the channel status below"
			} else {
				m.Minted = &ui2CollabMinted{Addresses: addrs, Domain: result.Domain, Marker: result.Marker}
			}
		}
		s.ui2CollabRender(w, r, m)
		return
	}
	count := 1
	if n, err := strconv.Atoi(r.PostFormValue("count")); err == nil && n > 0 && n <= 20 {
		count = n
	}
	payload, _ := json.Marshal(map[string]any{"count": count})
	m := s.ui2CollabPage(r)
	m.Count = count
	id, _, errText := s.ui2CollabHold("mint", http.MethodPost, "/api/collaborator/payload", payload)
	if errText != "" {
		m.Error = errText
	} else {
		m.ConfirmPending, m.MintID = true, id
		m.ConfirmPreview = "POST /api/collaborator/payload\n" + string(payload)
	}
	s.ui2CollabRender(w, r, m)
}

// handleUI2CollaboratorHealth serves POST /ui2/collaborator/health: the first POST holds the
// health-check call (it registers a channel if needed and sends DNS/HTTP/HTTPS/SMTP traffic to
// the interaction server) and renders it for review; the second (review_id) runs it.
func (s *Server) handleUI2CollaboratorHealth(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	if id := r.PostFormValue("review_id"); id != "" {
		var report collaboratorHealthReport
		errText := s.ui2CollabSpend("health", id, "", &report)
		m := s.ui2CollabPage(r)
		if errText != "" {
			m.HealthError = errText
		} else {
			m.Health = &report
		}
		s.ui2CollabRender(w, r, m)
		return
	}
	m := s.ui2CollabPage(r)
	body := []byte("{}")
	id, _, errText := s.ui2CollabHold("health", http.MethodPost, "/api/collaborator/health", body)
	if errText != "" {
		m.HealthError = errText
	} else {
		m.HealthPending, m.HealthID = true, id
		m.HealthPreview = "POST /api/collaborator/health\n" + string(body)
	}
	s.ui2CollabRender(w, r, m)
}

// handleUI2CollaboratorServer serves POST /ui2/collaborator/server/{action}: confirm validates
// the form (op=set with server/client_path, or op=unset with discard), holds the exact call and
// renders the review; run spends it.
func (s *Server) handleUI2CollaboratorServer(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	switch r.PathValue("action") {
	case "confirm":
		s.ui2CollabServerConfirm(w, r)
	case "run":
		s.ui2CollabServerRun(w, r)
	default:
		http.Error(w, "unknown collaborator server action", http.StatusBadRequest)
	}
}

func (s *Server) ui2CollabServerConfirm(w http.ResponseWriter, r *http.Request) {
	m := s.ui2CollabPage(r)
	m.ServerInput = strings.TrimSpace(r.PostFormValue("server"))
	m.ClientInput = strings.TrimSpace(r.PostFormValue("client_path"))
	var method string
	var body []byte
	review := &ui2CollabServerReview{Domain: m.Status.Domain, Orphans: len(m.Status.Payloads)}
	switch r.PostFormValue("op") {
	case "set":
		if m.ServerInput == "" {
			m.Error = `give an interaction server URL, or the word "public" for interactsh's own public pool`
			s.ui2CollabRender(w, r, m)
			return
		}
		method = http.MethodPost
		req := map[string]any{"server": m.ServerInput}
		if m.ClientInput != "" {
			req["client_path"] = m.ClientInput
		}
		body, _ = json.Marshal(req)
	case "unset":
		method = http.MethodDelete
		review.Unset = true
		body, _ = json.Marshal(map[string]any{"discard_open_channel": r.PostFormValue("discard") != ""})
	default:
		m.Error = "unknown server operation"
		s.ui2CollabRender(w, r, m)
		return
	}
	id, token, errText := s.ui2CollabHold("server", method, "/api/collaborator/server", body)
	if errText != "" {
		m.Error = errText
		s.ui2CollabRender(w, r, m)
		return
	}
	review.ID, review.Token, review.Gated = id, token, token != ""
	review.Preview = method + " /api/collaborator/server\n" + string(body)
	m.ServerReview = review
	s.ui2CollabRender(w, r, m)
}

func (s *Server) ui2CollabServerRun(w http.ResponseWriter, r *http.Request) {
	var result struct {
		// POST answers the fresh status; DELETE answers {status, orphaned_payloads, ...}.
		DefaultPool      bool   `json:"default_pool"`
		Server           string `json:"server"`
		State            string `json:"state"`
		OrphanedPayloads *int   `json:"orphaned_payloads"`
		ClosedDomain     string `json:"closed_domain"`
		CloseError       string `json:"close_error"`
	}
	errText := s.ui2CollabSpend("server", r.PostFormValue("review_id"), r.PostFormValue("token"), &result)
	m := s.ui2CollabPage(r)
	switch {
	case errText != "":
		m.Error = errText
	case result.OrphanedPayloads != nil:
		m.Done = "Collaborator is off. Out-of-band checks will refuse until a server is set."
		if *result.OrphanedPayloads > 0 {
			m.Done = fmt.Sprintf("Collaborator is off. %d payload address(es) on %s are no longer polled.", *result.OrphanedPayloads, result.ClosedDomain)
		}
		if result.CloseError != "" {
			m.Done += " The client's shutdown reported: " + result.CloseError
		}
	case result.DefaultPool:
		m.Done = "Configured: interactsh public pool. Generate a payload to register a channel — configured is not reachable."
	default:
		m.Done = "Configured: " + result.Server + ". Generate a payload to register a channel — configured is not reachable."
	}
	s.ui2CollabRender(w, r, m)
}

// handleUI2CollaboratorPoll serves POST /ui2/collaborator/poll: re-read the interaction log now
// (riskRead — nothing leaves the process) and re-render.
func (s *Server) handleUI2CollaboratorPoll(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	var st collaboratorStatus
	errText := s.ui2CollabCall(http.MethodPost, "/api/collaborator/poll", nil, &st)
	m := s.ui2CollabPage(r)
	switch {
	case errText != "":
		m.Error = errText
	case st.Interactions == nil:
		m.Done = "Polled: no channel is open, so there is nothing to read yet."
	case st.LastRead != nil && !st.LastRead.OK:
		m.Error = "Polled, but the interaction log could not be read: " + st.LastRead.Error
	default:
		m.Done = fmt.Sprintf("Polled: %d interaction(s) recorded.", st.Interactions.Total)
	}
	s.ui2CollabRender(w, r, m)
}

// handleUI2CollaboratorBlindXSS serves POST /ui2/collaborator/blindxss: mint one blind-XSS script
// tag. riskLocal — the listener starts answering for a token and nothing is sent — so it runs
// directly; the minted tag renders with a copy button.
func (s *Server) handleUI2CollaboratorBlindXSS(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	var minted struct {
		Payload mintedBlindXSSPayload `json:"payload"`
		Caveat  string                `json:"caveat"`
	}
	errText := s.ui2CollabCall(http.MethodPost, "/api/blindxss/payload", []byte("{}"), &minted)
	m := s.ui2CollabPage(r)
	if errText != "" {
		m.Error = "Blind-XSS mint refused: " + errText
	} else {
		m.BXMinted = &minted.Payload
		m.BXCaveat = minted.Caveat
	}
	s.ui2CollabRender(w, r, m)
}

// ui2CollabDetail is the model for one interaction's detail pane.
type ui2CollabDetail struct {
	collaboratorInteractionDetail
	TypeUpper string
	Time      string
	Error     string
}

// handleUI2CollaboratorInteraction serves GET /ui2/collaborator/interaction/{id}: one
// interaction's correlation id, client IP and what it means, time, and its raw bytes (escaped —
// they are attacker-controlled). Highlight and comment are local (app.js).
func (s *Server) handleUI2CollaboratorInteraction(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil || id < 0 {
		http.Error(w, "Invalid interaction id", http.StatusBadRequest)
		return
	}
	var d ui2CollabDetail
	d.Error = s.ui2CollabCall(http.MethodGet, "/api/collaborator/interaction/"+strconv.Itoa(id), nil, &d.collaboratorInteractionDetail)
	if d.Error == "" {
		d.TypeUpper = strings.ToUpper(d.Type)
		d.Time = ui2CollabTime(d.AtMs)
	} else {
		d.ID = id
	}
	ui2Fragment(w, r, ui2CollabTitle, "collaborator", ui2Exec("collaborator_detail.html", d))
}
