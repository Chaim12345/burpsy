package web

// ui2 DOM auditor (Burp's DOM Invader in burpsy's shape): the canary watch switch and canary,
// the opt-in prototype-pollution probe plan and its scan, and the flows the browser extension
// reported. Every write goes through the held-call review in ui2_discovery.go.

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/burpsy-go/burpsy/internal/dominvader"
)

const ui2DomTitle = "burpsy /ui2/ — DOM auditor"

type ui2DomModel struct {
	domInvaderView
	Hits     []*dominvader.Hit // newest first
	Props    string
	Error    string
	Note     string
	Done     string
	Scan     *dominvader.ScanResult
	ScanDone bool
}

func (s *Server) ui2DomModel() ui2DomModel {
	var m ui2DomModel
	rec := newRecorder()
	s.mux.ServeHTTP(rec, newReq(http.MethodGet, "/api/dominvader"))
	if rec.Code != http.StatusOK {
		m.Error = strings.TrimSpace(rec.Body.String())
		return m
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &m.domInvaderView); err != nil {
		m.Error = "unreadable DOM auditor state: " + err.Error()
		return m
	}
	for i := len(m.domInvaderView.Hits) - 1; i >= 0; i-- {
		m.Hits = append(m.Hits, m.domInvaderView.Hits[i])
	}
	m.Props = strings.Join(m.Pollution.Properties, ",")
	return m
}

// handleUI2DomInvader serves GET /ui2/dominvader.
func (s *Server) handleUI2DomInvader(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ui2Fragment(w, r, ui2DomTitle, "dominvader", ui2Exec("dominvader.html", s.ui2DomModel()))
}

// ui2DomPollutionForm builds the probe plan from the form; validation is the domain's own.
func ui2DomPollutionForm(r *http.Request) (dominvader.PollutionConfig, string) {
	p := dominvader.PollutionConfig{
		Enabled:    r.PostFormValue("pollution_enabled") != "",
		Target:     strings.TrimSpace(r.PostFormValue("target")),
		Query:      r.PostFormValue("query") != "",
		Hash:       r.PostFormValue("hash") != "",
		JSON:       r.PostFormValue("json") != "",
		Nested:     r.PostFormValue("nested") != "",
		Properties: []string{},
	}
	for _, prop := range strings.Split(r.PostFormValue("properties"), ",") {
		if prop = strings.TrimSpace(prop); prop != "" {
			p.Properties = append(p.Properties, prop)
		}
	}
	if err := p.Validate(); err != nil {
		return p, err.Error()
	}
	return p, ""
}

// handleUI2DomInvaderReview serves POST /ui2/dominvader/review: op=settings (enabled, canary,
// optional randomize), plan (the pollution probe plan), scan or clear. Holds the exact call
// and renders it; nothing changes yet.
func (s *Server) handleUI2DomInvaderReview(w http.ResponseWriter, r *http.Request) {
	sheet := ui2ReviewSheet{RunURL: "/ui2/dominvader/run", Target: "#dom", Back: "/ui2/dominvader"}
	if msg := ui2FormOnly(r); msg != "" {
		if msg == "method not allowed" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		sheet.Error = msg
		ui2RenderReview(w, r, ui2DomTitle, "dominvader", sheet)
		return
	}
	fail := func(msg string) {
		sheet.Error = msg
		ui2RenderReview(w, r, ui2DomTitle, "dominvader", sheet)
	}
	op := r.PostFormValue("op")
	method, path := http.MethodPut, "/api/dominvader"
	var body []byte
	switch op {
	case "settings":
		canary := strings.TrimSpace(r.PostFormValue("canary"))
		if r.PostFormValue("randomize") != "" {
			hex, err := randomHex(6)
			if err != nil {
				fail("random canary: " + err.Error())
				return
			}
			canary = "burpsyDI" + hex
		}
		if canary == "" {
			fail("a canary cannot be empty")
			return
		}
		enabled := r.PostFormValue("enabled") != ""
		body, _ = json.Marshal(map[string]any{"canary": canary, "enabled": enabled})
		sheet.What = "Save the DOM auditor settings."
		sheet.Effect = "Changes burpsy's own auditor state; nothing is sent. The canary and switch apply when the browser is next opened or relaunched."
	case "plan":
		p, errText := ui2DomPollutionForm(r)
		if errText != "" {
			fail(errText)
			return
		}
		body, _ = json.Marshal(map[string]any{"pollution": p})
		sheet.What = "Save the prototype-pollution probe plan."
		sheet.Effect = "Stores the plan; nothing is sent until a scan runs it. An enabled plan's target must be inside the engagement scope."
	case "scan":
		method, path = http.MethodPost, "/api/dominvader/scan"
		sheet.What = "Run the saved probe plan."
		sheet.Effect = "Loads the plan's target in an isolated browser context with each probe - real requests to the target, same-origin and scope-checked on every one. Takes up to two minutes."
	case "clear":
		method, path = http.MethodDelete, "/api/dominvader/hits"
		sheet.What = "Clear every reported flow."
		sheet.Effect = "Deletes the reported flows from burpsy's auditor list; this cannot be undone."
	default:
		fail("unknown review action")
		return
	}
	call, id, errText := s.ui2HoldCall("dominvader", op, method, path, body)
	if errText != "" {
		fail(errText)
		return
	}
	sheet.Method, sheet.Path, sheet.Body, sheet.Gated = call.method, call.path, string(call.body), call.gated
	sheet.ReviewID, sheet.Token = id, call.token
	ui2RenderReview(w, r, ui2DomTitle, "dominvader", sheet)
}

// handleUI2DomInvaderRun serves POST /ui2/dominvader/run: spends the held call and re-renders
// the page with the outcome (and the scan's result for op=scan).
func (s *Server) handleUI2DomInvaderRun(w http.ResponseWriter, r *http.Request) {
	if msg := ui2FormOnly(r); msg == "method not allowed" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	call, errText := s.ui2SpendCall("dominvader", r)
	var out []byte
	if errText == "" {
		out, errText = s.ui2DispatchHeldCall(call)
	}
	m := s.ui2DomModel()
	if errText != "" {
		m.Note = "Not run: " + errText
	} else {
		switch call.op {
		case "settings":
			m.Done = "Settings saved — open or relaunch the browser to watch for the canary."
		case "plan":
			m.Done = "Probe plan saved."
		case "clear":
			m.Done = "Reported flows cleared."
		case "scan":
			var res dominvader.ScanResult
			if err := json.Unmarshal(out, &res); err != nil {
				m.Note = "unreadable scan result: " + err.Error()
			} else {
				m.Scan, m.ScanDone = &res, true
				m.Done = "Probe plan ran."
			}
		}
	}
	ui2Fragment(w, r, ui2DomTitle, "dominvader", ui2Exec("dominvader.html", m))
}
