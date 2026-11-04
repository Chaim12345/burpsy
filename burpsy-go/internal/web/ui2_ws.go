package web

import (
	"encoding/hex"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// ---- WebSockets history ----------------------------------------------------------------------
//
// The /ui2/ws page: relayed connections, a server-filtered frame table, one frame's payload and one
// connection's upgrade handshake. Read-only; every model comes from the /api/ws/* and
// /api/exchange|message JSON routes. Frame payloads are attacker-controlled and render through
// html/template only.

// ui2WSParams is the view state the page round-trips through its filter form and URL.
type ui2WSParams struct {
	Exchange  string // the selected connection's handshake exchange id, "" for every connection
	Direction string
	Opcode    string
	Payload   string
	Frame     uint64 // the frame whose view is open, 0 for none
}

func parseUI2WSParams(v url.Values) ui2WSParams {
	p := ui2WSParams{
		Direction: v.Get("direction"),
		Opcode:    v.Get("opcode"),
		Payload:   v.Get("payload"),
	}
	if n, err := strconv.ParseUint(v.Get("exchange"), 10, 64); err == nil {
		p.Exchange = strconv.FormatUint(n, 10)
	}
	if n, err := strconv.ParseUint(v.Get("frame"), 10, 64); err == nil {
		p.Frame = n
	}
	return p
}

// historyQuery is the /api/ws/history query for this view; the API validates direction/opcode.
func (p ui2WSParams) historyQuery() string {
	q := url.Values{}
	q.Set("limit", "300")
	for k, v := range map[string]string{"exchange": p.Exchange, "direction": p.Direction, "opcode": p.Opcode, "payload": p.Payload} {
		if v != "" {
			q.Set(k, v)
		}
	}
	return q.Encode()
}

type ui2WSConn struct {
	wsConnectionView
	Selected bool
	Age      string
}

type ui2WSRow struct {
	wsRowView
	Age    string
	Sent   bool
	Opened bool
}

type ui2WSPageModel struct {
	P           ui2WSParams
	Connections []ui2WSConn
	Rows        []ui2WSRow
	Frames      int
	Sent        int
	Received    int
	Total       int
	Error       string
	HasFilter   bool
	Selected    *ui2WSConn
	FrameView   *ui2WSPageFrame
}

// handleUI2WS serves GET /ui2/ws: metrics, connections, the filtered frame table and, with
// ?frame=N, that frame's view.
func (s *Server) handleUI2WS(w http.ResponseWriter, r *http.Request) {
	p := parseUI2WSParams(r.URL.Query())
	ui2Fragment(w, r, "burpsy /ui2/ — WebSockets", "ws", ui2Exec("ws_page.html", s.ui2WSView(p)))
}

func (s *Server) ui2WSView(p ui2WSParams) ui2WSPageModel {
	m := ui2WSPageModel{P: p, HasFilter: p.Direction != "" || p.Opcode != "" || p.Payload != ""}
	var conns []wsConnectionView
	if errText := s.ui2APIGet("/api/ws/connections", &conns); errText != "" {
		m.Error = errText
	}
	for _, c := range conns {
		m.Frames += c.Messages
		m.Sent += c.Sent
		m.Received += c.Received
		row := ui2WSConn{wsConnectionView: c, Selected: p.Exchange != "" && strconv.FormatUint(uint64(c.Exchange), 10) == p.Exchange, Age: ui2Age(c.LastMs)}
		m.Connections = append(m.Connections, row)
		if row.Selected {
			sel := row
			m.Selected = &sel
		}
	}
	var hist wsHistoryResp
	if errText := s.ui2APIGet("/api/ws/history?"+p.historyQuery(), &hist); errText != "" {
		m.Error = errText
	}
	m.Total = hist.Total
	for _, row := range hist.Rows {
		m.Rows = append(m.Rows, ui2WSRow{wsRowView: row, Age: ui2Age(row.AtMs), Sent: row.Direction == "client_to_server", Opened: p.Frame != 0 && row.ID == p.Frame})
	}
	if p.Frame != 0 {
		m.FrameView = s.ui2WSFrameFor(p.Frame)
	}
	return m
}

// ui2WSPageFrame is one frame's view: the row, its payload (text, or hex for a non-text opcode), the
// decoded close status, and the links that act on it.
type ui2WSPageFrame struct {
	ID          uint64
	Error       string
	Msg         wsMessageResp
	IsText      bool
	Payload     string
	Summary     string
	At          string
	HistoryHref string
}

func (s *Server) ui2WSFrameFor(id uint64) *ui2WSPageFrame {
	f := &ui2WSPageFrame{ID: id}
	if errText := s.ui2APIGet("/api/ws/message/"+strconv.FormatUint(id, 10), &f.Msg); errText != "" {
		f.Error = errText
		return f
	}
	f.IsText = f.Msg.Opcode == "text"
	f.Payload = f.Msg.Hex
	if f.IsText {
		f.Payload = f.Msg.Text
	}
	at := time.UnixMilli(int64(f.Msg.AtMs))
	f.At = at.Format("2006-01-02 15:04:05") + " (" + ui2Age(f.Msg.AtMs) + " ago)"
	f.Summary = "#" + strconv.FormatUint(f.Msg.ID, 10) + " " + f.Msg.Direction + " " + f.Msg.Opcode + " " +
		strconv.Itoa(f.Msg.Len) + "B " + at.UTC().Format("2006-01-02T15:04:05.000Z")
	var ex struct {
		Host string `json:"host"`
		Path string `json:"path"`
	}
	if s.ui2APIGet("/api/exchange/"+strconv.FormatUint(uint64(f.Msg.Exchange), 10), &ex) == "" && ex.Host != "" {
		f.HistoryHref = ui2HistoryQueryHref("host = " + ui2QueryQuote(ex.Host) + " AND path = " + ui2QueryQuote(ex.Path))
	}
	return f
}

// handleUI2WSFrame serves GET /ui2/ws/frame/{id}: the frame view fragment (a plain navigation gets
// the page with the frame open), or with ?download=1 the payload bytes as a file.
func (s *Server) handleUI2WSFrame(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "Invalid frame id", http.StatusBadRequest)
		return
	}
	if r.URL.Query().Get("download") == "1" {
		var msg wsMessageResp
		if errText := s.ui2APIGet("/api/ws/message/"+strconv.FormatUint(id, 10), &msg); errText != "" {
			http.Error(w, errText, http.StatusNotFound)
			return
		}
		raw, err := hex.DecodeString(msg.Hex)
		if err != nil {
			http.Error(w, "unreadable payload", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Disposition", `attachment; filename="ws-message-`+strconv.FormatUint(id, 10)+`.bin"`)
		_, _ = w.Write(raw)
		return
	}
	if r.Header.Get("HX-Request") != "true" {
		p := parseUI2WSParams(r.URL.Query())
		p.Frame = id
		ui2RenderPage(w, "burpsy /ui2/ — WebSockets", "ws", ui2Exec("ws_page.html", s.ui2WSView(p)))
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(ui2Exec("ws_frame.html", s.ui2WSFrameFor(id))))
}

// handleUI2WSHandshake serves GET /ui2/ws/handshake/{id}: the upgrade request/response that opened
// one connection, rendered like any stored exchange.
func (s *Server) handleUI2WSHandshake(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "Invalid exchange id", http.StatusBadRequest)
		return
	}
	pretty := r.URL.Query().Get("view") != "raw"
	body := ui2Exec("ws_handshake.html", map[string]any{"panes": s.ui2ExchangePanesFor(id, pretty, pretty), "pretty": pretty, "id": id})
	if r.Header.Get("HX-Request") != "true" {
		ui2RenderPage(w, "burpsy /ui2/ — WebSocket handshake", "ws", body)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(body))
}
