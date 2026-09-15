package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/burpsy-go/burpsy/internal/core"
)

// ---- WebSocket capture surface -----------------------------------------------------------------

// The shapes below mirror wshistory.ts exactly: an HTTP row is a request/response pair keyed by an
// exchange, while a WebSocket row is a single one-way message keyed by the connection it belongs to.
// The two surfaces are therefore separate, and the connection is the join between them: every message
// names the Exchange whose 101 opened it.

// Rows are index data only — direction, opcode, length, timestamp — and never a payload, so listing
// a socket that has carried a hundred thousand messages touches no message bytes. The payload is
// fetched only when a specific message is opened.

// wsRowView mirrors wshistory.ts's RowView.
type wsRowView struct {
	ID        uint64          `json:"id"`
	Exchange  core.ExchangeID `json:"exchange"`
	Payload   uint64          `json:"payload"`
	Direction string          `json:"direction"` // "client_to_server" | "server_to_client"
	Opcode    string          `json:"opcode"`
	Len       int             `json:"len"`
	Dropped   uint64          `json:"dropped"`
	Truncated bool            `json:"truncated"`
	Fragments uint32          `json:"fragments"`
	AtMs      uint64          `json:"at_ms"`
	Note      string          `json:"note,omitempty"`
	// Edited is Burp's "Edited" column for a WebSocket message: the operator's own hold changed this
	// message before it was relayed. No omitempty — "edited":false is a stated fact the console renders
	// as an empty column, and an absent key would make "not edited" indistinguishable from an older row
	// that predates the field.
	Edited bool `json:"edited"`
}

// wsHistoryResp mirrors wshistory.ts's HistoryResp.
type wsHistoryResp struct {
	Total int         `json:"total"`
	Rows  []wsRowView `json:"rows"`
}

// wsCloseView mirrors wshistory.ts's CloseView.
type wsCloseView struct {
	Code   uint16 `json:"code"`
	Reason string `json:"reason"`
}

// wsMessageResp mirrors wshistory.ts's MessageResp: the row flattened, plus the payload rendered
// both ways. Embedding puts the row's fields at the top level, exactly as the UI reads them.
type wsMessageResp struct {
	wsRowView
	Text  string       `json:"text"`
	Hex   string       `json:"hex"`
	Close *wsCloseView `json:"close,omitempty"`
}

// wsConnectionView mirrors wshistory.ts's ConnectionView.
type wsConnectionView struct {
	Exchange core.ExchangeID `json:"exchange"`
	Host     string          `json:"host"`
	Port     uint16          `json:"port"`
	TLS      bool            `json:"tls"`
	Path     string          `json:"path"`
	Messages int             `json:"messages"`
	Sent     int             `json:"sent"`
	Received int             `json:"received"`
	LastMs   uint64          `json:"last_ms"`
}

// wsMaxLimit caps a history page. Matches /api/history's cap: the browser is what falls over first.
const wsMaxLimit = 2000

func wsRowFromMessage(m *core.WsMessage) wsRowView {
	direction := "server_to_client"
	if m.FromClient {
		direction = "client_to_server"
	}
	return wsRowView{
		ID:        uint64(m.ID),
		Exchange:  m.Exchange,
		Payload:   uint64(m.Payload),
		Direction: direction,
		Opcode:    m.Opcode.Name(),
		Len:       m.Len,
		Dropped:   m.Dropped,
		Truncated: m.Dropped > 0,
		Fragments: m.Fragments,
		AtMs:      m.AtMs,
		Note:      m.Note,
		Edited:    m.UserEdited,
	}
}

// handleWSConnections serves GET /api/ws/connections -> ConnectionView[], newest activity first.
// A fold over the index rather than a second stored structure: two copies of "which connections
// exist" could disagree, one derived view cannot, and the fold is over fixed-size rows.
func (s *Server) handleWSConnections(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	conns := s.store.WsConnections()
	views := make([]wsConnectionView, 0, len(conns))
	for _, c := range conns {
		views = append(views, wsConnectionView{
			Exchange: c.Exchange,
			Host:     c.Host,
			Port:     c.Port,
			TLS:      c.TLS,
			Path:     c.Path,
			Messages: c.Messages,
			Sent:     c.Sent,
			Received: c.Received,
			LastMs:   c.LastMs,
		})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(views)
}

// handleWSHistory serves GET /api/ws/history[?offset=N&limit=N[&exchange=N][&direction=…]
// [&opcode=…][&payload=…]] -> HistoryResp.
// Newest-first page. `total` is the whole index's size, not the page's, so the UI can page without
// asking separately; filtering by connection narrows the rows but not the total.
//
// # Why direction/opcode/payload filter on the server while the UI filter box feels client-side
//
// A frame's payload bytes are not on the row — by design, so listing a socket that has carried a
// hundred thousand messages touches no payload bytes (see the WsMessage comment in core). A
// client-side payload filter would run over rows that do not carry the payload, so it could only
// match against whatever the UI happened to have fetched — the selected frame — and would hide
// everything else for a reason the data cannot support. Filtering here reads each candidate's
// payload exactly once through the same WsPayload handle the detail view uses, and the rows the
// operator sees are the rows that actually matched.
func (s *Server) handleWSHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	offset := 0
	if raw := r.URL.Query().Get("offset"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			offset = n
		}
	}
	limit := 300
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > wsMaxLimit {
		limit = wsMaxLimit
	}

	// An `exchange` that will not parse is refused rather than ignored. The parse error used to be
	// discarded, and the nil-check below then fell through to the unfiltered index — so
	// `?exchange=abc` answered with every message on the server while the caller believed it was
	// looking at one connection. A filter that silently does not filter is worse than no filter: the
	// rows are real, so nothing about the response looks wrong.
	//
	// The fallback itself is kept for the no-filter case, but it is now reached only when `exchange`
	// was absent — a connection that genuinely holds no messages answers with an empty page, not with
	// the whole index.
	var messages []*core.WsMessage
	if raw := r.URL.Query().Get("exchange"); raw != "" {
		ex, err := strconv.ParseUint(raw, 10, 64)
		if err != nil {
			http.Error(w, fmt.Sprintf("exchange must be a whole number, got %q", raw), http.StatusBadRequest)
			return
		}
		messages = s.store.WsMessagesFor(core.ExchangeID(ex), offset, limit)
		if messages == nil {
			messages = []*core.WsMessage{}
		}
	} else {
		messages = s.store.WsMessages(offset, limit)
	}

	// The frame filter (burpsy-react-ui-5k4). direction and opcode are exact matches over the
	// row's own fields; payload is a case-insensitive substring over the stored bytes, the same
	// comparison the detail view renders as text. An unknown direction/opcode value is refused
	// rather than ignored: a filter parameter that silently does not filter would answer with
	// every frame while the operator believes they are looking at a narrowed list — the same
	// refusal rule the `exchange` parameter above already follows.
	dirFilter := r.URL.Query().Get("direction")
	if dirFilter != "" && dirFilter != "client_to_server" && dirFilter != "server_to_client" {
		http.Error(w, fmt.Sprintf("direction must be client_to_server or server_to_client, got %q", dirFilter), http.StatusBadRequest)
		return
	}
	opcodeFilter := r.URL.Query().Get("opcode")
	if opcodeFilter != "" && opcodeFilter != "text" && opcodeFilter != "binary" && opcodeFilter != "ping" && opcodeFilter != "pong" && opcodeFilter != "close" {
		http.Error(w, fmt.Sprintf("opcode must be one of text, binary, ping, pong, close, got %q", opcodeFilter), http.StatusBadRequest)
		return
	}
	payloadFilter := strings.ToLower(r.URL.Query().Get("payload"))

	rows := make([]wsRowView, 0, len(messages))
	for _, m := range messages {
		if dirFilter != "" {
			want := dirFilter == "client_to_server"
			if m.FromClient != want {
				continue
			}
		}
		if opcodeFilter != "" && m.Opcode.Name() != opcodeFilter {
			continue
		}
		if payloadFilter != "" {
			payload, err := s.store.WsPayload(m.Payload)
			if err != nil {
				// A payload that cannot be read cannot be shown to have matched. The row is
				// skipped rather than passed: passing it would claim the substring matched bytes
				// nobody read.
				continue
			}
			if !strings.Contains(strings.ToLower(string(payload)), payloadFilter) {
				continue
			}
		}
		rows = append(rows, wsRowFromMessage(m))
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(wsHistoryResp{Total: s.store.WsCount(), Rows: rows})
}

// handleWSMessage serves GET /api/ws/message/{id} -> MessageResp, rendering one message's payload
// both as lossy text and as lowercase hex. A close frame's status code is decoded as a number —
// showing its two bytes as characters would render mojibake instead of 1000.
func (s *Server) handleWSMessage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id, err := strconv.ParseUint(strings.TrimPrefix(r.URL.Path, "/api/ws/message/"), 10, 64)
	if err != nil {
		http.Error(w, "Invalid message ID", http.StatusBadRequest)
		return
	}
	m, err := s.store.WsMessage(core.MsgId(id))
	if err != nil {
		http.Error(w, fmt.Sprintf("no ws message %d", id), http.StatusNotFound)
		return
	}
	payload, err := s.store.WsPayload(m.Payload)
	if err != nil {
		// The index says this payload exists and the store disagrees. Reported rather than shown as
		// an empty message, which would be indistinguishable from a genuinely empty frame.
		http.Error(w, fmt.Sprintf("ws message %d points at payload %d which the store cannot resolve", id, m.Payload), http.StatusInternalServerError)
		return
	}

	var closeView *wsCloseView
	if m.Opcode == core.WsOpcodeClose {
		if code, reason, ok := core.WsCloseStatus(payload); ok {
			closeView = &wsCloseView{Code: code, Reason: reason}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(wsMessageResp{
		wsRowView: wsRowFromMessage(m),
		Text:      string(payload),
		Hex:       hexString(payload),
		Close:     closeView,
	})
}

func hexString(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = digits[c>>4]
		out[i*2+1] = digits[c&0x0f]
	}
	return string(out)
}
