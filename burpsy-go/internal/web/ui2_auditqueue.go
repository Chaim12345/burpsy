package web

// ui2 Audit queue (unit 11): Burp's audit-items table over GET /api/scanner/audit-items, the
// selected item's base request/response, and its two actions - cancel and audit again - through
// the review engine in ui2_issues.go (both are on the riskAttack /api/scanner/audit-items/
// subtree, so both mint a gate token and rebuild from the sheet's fields).

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
)

// ui2AQItem is the subset of scanner.AuditItem the page renders, decoded from the API's JSON.
type ui2AQItem struct {
	ExchangeID       uint64   `json:"exchange_id"`
	Seq              uint64   `json:"seq"`
	Method           string   `json:"method"`
	Host             string   `json:"host"`
	Port             int      `json:"port"`
	TLS              bool     `json:"tls"`
	Path             string   `json:"path"`
	State            string   `json:"state"`
	URLDisposition   string   `json:"url_disposition"`
	StatusLabel      string   `json:"status_label"`
	BurpStatus       string   `json:"burp_status"`
	Note             string   `json:"note"`
	Attempts         int      `json:"attempts"`
	StepsPlanned     int      `json:"steps_planned"`
	StepsDone        int      `json:"steps_done"`
	PointKinds       []string `json:"point_kinds"`
	PointsEnumerated int      `json:"points_enumerated"`
	PointsSkipped    int      `json:"points_skipped"`
	PointsPlaces     int      `json:"points_declined_places"`
	Points           []struct {
		Kind   string `json:"kind"`
		Name   string `json:"name"`
		Status string `json:"status"`
		Detail string `json:"detail"`
	} `json:"points"`
	QueuedUnixMs  int64 `json:"queued_unix_ms"`
	UpdatedUnixMs int64 `json:"updated_unix_ms"`
}

// URL is the item's request line target, the SPA's rendering (default ports omitted).
func (it ui2AQItem) URL() string {
	scheme := "http"
	def := 80
	if it.TLS {
		scheme, def = "https", 443
	}
	u := scheme + "://" + it.Host
	if it.Port != 0 && it.Port != def {
		u += ":" + strconv.Itoa(it.Port)
	}
	return u + it.Path
}

// Progress is "done/planned steps (n%)", or "not planned".
func (it ui2AQItem) Progress() string {
	if it.StepsPlanned == 0 {
		return "not planned"
	}
	return strconv.Itoa(it.StepsDone) + "/" + strconv.Itoa(it.StepsPlanned) + " steps (" +
		strconv.Itoa(it.StepsDone*100/it.StepsPlanned) + "%)"
}

// Timing is "queued → updated", the queue time alone when the row has not moved, "" when unknown.
func (it ui2AQItem) Timing() string {
	if it.QueuedUnixMs == 0 {
		return ""
	}
	at := func(ms int64) string { return time.UnixMilli(ms).Format("15:04:05") }
	if it.UpdatedUnixMs != 0 && it.UpdatedUnixMs != it.QueuedUnixMs {
		return at(it.QueuedUnixMs) + " → " + at(it.UpdatedUnixMs)
	}
	return at(it.QueuedUnixMs)
}

// Label is the status the row shows.
func (it ui2AQItem) Label() string {
	if it.StatusLabel != "" {
		return it.StatusLabel
	}
	return it.State
}

type ui2AQView struct {
	Items     []ui2AQItem `json:"items"`
	Returned  int         `json:"returned"`
	Truncated bool        `json:"truncated"`
	Queue     struct {
		Retained int `json:"retained"`
	} `json:"queue"`
	Totals struct {
		ItemsPending        int `json:"items_pending"`
		ItemsAuditing       int `json:"items_auditing"`
		ItemsCompletedAudit int `json:"items_completed_audit"`
		ItemsBounded        int `json:"items_bounded"`
		ItemsFailed         int `json:"items_failed"`
		ItemsOutOfScope     int `json:"items_out_of_scope"`
	} `json:"totals"`
	Hint   string `json:"hint"`
	Parity struct {
		Declared    int `json:"burp_statuses_declared"`
		Modelled    int `json:"burp_statuses_modelled"`
		NotModelled []struct {
			Status string `json:"status"`
			Label  string `json:"label"`
		} `json:"burp_statuses_not_modelled"`
	} `json:"parity"`
}

type ui2AQModel struct {
	View  ui2AQView
	Error string
}

// ui2AuditQueueRead reads the queue through the JSON API, the shape the SPA renders.
func (s *Server) ui2AuditQueueRead() (ui2AQView, string) {
	var v ui2AQView
	rec := newRecorder()
	s.mux.ServeHTTP(rec, newReq(http.MethodGet, "/api/scanner/audit-items"))
	if rec.Code != http.StatusOK {
		return v, ui2APIErrorText(rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		return v, "unreadable audit queue: " + err.Error()
	}
	return v, ""
}

// handleUI2AuditQueue serves GET /ui2/auditqueue: the full page (metrics, queue table, the
// selected-item pane) or, for htmx, the #rows fragment alone so a live refresh never touches the
// selected item or an open review sheet.
func (s *Server) handleUI2AuditQueue(w http.ResponseWriter, r *http.Request) {
	v, errText := s.ui2AuditQueueRead()
	rows := ui2Exec("auditqueue_rows.html", ui2AQModel{View: v, Error: errText})
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(rows))
		return
	}
	ui2RenderPage(w, "burpsy /ui2/ — Audit queue", "auditqueue", ui2Exec("auditqueue.html", rows))
}

type ui2AQDetail struct {
	Item     ui2AQItem
	Found    bool
	ID       uint64
	Request  string
	Response string
	ReqPane  ui2PaneView
	RespPane ui2PaneView
	HasEx    bool
}

// handleUI2AuditQueueItem serves GET /ui2/auditqueue/item/{id}: one queue row's state, its
// insertion points, the base request/response it was decided about, and its actions.
func (s *Server) handleUI2AuditQueueItem(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "Invalid exchange ID", http.StatusBadRequest)
		return
	}
	v, errText := s.ui2AuditQueueRead()
	if errText != "" {
		http.Error(w, errText, http.StatusServiceUnavailable)
		return
	}
	m := ui2AQDetail{ID: id}
	for _, it := range v.Items {
		if it.ExchangeID == id {
			m.Item, m.Found = it, true
			break
		}
	}
	if !m.Found {
		http.Error(w, "no audit queue item for that exchange", http.StatusNotFound)
		return
	}
	if ex, err := s.store.GetExchange(core.ExchangeID(id)); err == nil {
		m.HasEx = true
		if raw := requestMessageForExchange(s.store, ex); raw != nil {
			m.Request = string(raw)
		}
		if ex.Response != nil {
			if msg, err := s.store.Get(*ex.Response); err == nil {
				m.Response = string(msg.Raw())
			}
		}
		m.ReqPane = renderMessagePane(m.Request, true, true)
		m.RespPane = renderMessagePane(m.Response, false, true)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(ui2Exec("auditqueue_detail.html", m)))
}

// ui2AuditQueueCall builds the exact call for one queue action; both review steps use it.
func ui2AuditQueueCall(op, idStr string) (ui2Call, string) {
	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		return ui2Call{}, "an exchange id is required"
	}
	path := "/api/scanner/audit-items/" + strconv.FormatUint(id, 10)
	label := "exchange #" + strconv.FormatUint(id, 10)
	switch op {
	case "cancel":
		return ui2Call{
			Method: http.MethodPost, Path: path + "/cancel", Payload: map[string]any{},
			Title:        "Cancel the queued audit of " + label,
			Consequences: []string{"Only this item stops, before dispatch. Nothing is sent to the target."},
		}, ""
	case "again":
		return ui2Call{
			Method: http.MethodPost, Path: path + "/again", Payload: map[string]any{},
			Title: "Audit " + label + " again",
			Consequences: []string{
				"A fresh active audit runs under the server's default configuration: real probes are sent to the target.",
				"Work already covered by an earlier item is not skipped - that is the point of auditing again.",
			},
		}, ""
	}
	return ui2Call{}, "unknown audit queue action"
}

// handleUI2AuditQueueAction serves POST /ui2/auditqueue/action/{step}: confirm renders the
// review sheet into the selected-item pane, run spends it.
func (s *Server) handleUI2AuditQueueAction(w http.ResponseWriter, r *http.Request) {
	render := func(m ui2ReviewModel) {
		body := ui2Exec("issues_review.html", m)
		if r.Header.Get("HX-Request") == "true" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(body))
			return
		}
		v, errText := s.ui2AuditQueueRead()
		rows := ui2Exec("auditqueue_rows.html", ui2AQModel{View: v, Error: errText})
		ui2RenderPage(w, "burpsy /ui2/ — Audit queue", "auditqueue", rows+body)
	}
	_ = r.ParseForm()
	cancel := "/ui2/auditqueue/item/" + strconv.FormatUint(func() uint64 {
		n, _ := strconv.ParseUint(r.PostFormValue("id"), 10, 64)
		return n
	}(), 10)
	switch r.PathValue("step") {
	case "confirm":
		op, idStr := r.PostFormValue("op"), r.PostFormValue("id")
		call, errText := ui2AuditQueueCall(op, idStr)
		if errText != "" {
			render(ui2ReviewModel{Error: errText})
			return
		}
		var fields []ui2Field
		if _, gated := ui2CallGate(call.Path); gated {
			fields = []ui2Field{{"op", op}, {"id", idStr}}
		}
		m := s.ui2PrepareReview("auditqueue", call, fields)
		m.RunURL, m.Target, m.Swap = "/ui2/auditqueue/action/run", "#aq-detail", "innerHTML"
		m.CancelURL, m.CancelTarget = cancel, "#aq-detail"
		render(m)
	case "run":
		call, result, errText := s.ui2RunReviewed(r, "auditqueue", []string{"op", "id"}, func(r *http.Request) (ui2Call, string) {
			return ui2AuditQueueCall(r.PostFormValue("op"), r.PostFormValue("id"))
		})
		m := ui2ReviewModel{Error: errText}
		if errText == "" {
			w.Header().Set("HX-Trigger", "ui2-auditqueue-changed")
			m.Done = "Done: " + call.Title + "."
			if res, ok := result.(map[string]any); ok {
				if reason, _ := res["reason"].(string); reason != "" {
					m.Done += " " + reason
				}
			}
		}
		if call.Path != "" {
			m.CancelURL, m.CancelTarget = cancel, "#aq-detail"
		}
		render(m)
	default:
		http.Error(w, "unknown audit queue step", http.StatusNotFound)
	}
}
