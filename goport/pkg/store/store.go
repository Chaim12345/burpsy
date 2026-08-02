package store

import (
	"bytes"
	"fmt"
	"strings"
	"sync"
)

// MsgID is a unique identifier for a stored message.
type MsgID uint64

// Direction defines whether the message is a request or a response.
type Direction string

const (
	Request  Direction = "Request"
	Response Direction = "Response"
)

// Span is a slice offset and length representation.
type Span struct {
	Offset int `json:"offset"`
	Len    int `json:"len"`
}

func NewSpan(offset, length int) Span {
	return Span{Offset: offset, Len: length}
}

func (s Span) End() int {
	return s.Offset + s.Len
}

// HeaderSpan represents the spans of a header name and value.
type HeaderSpan struct {
	Name  Span `json:"name"`
	Value Span `json:"value"`
}

// MessageShape holds parsing spans into raw message bytes.
type MessageShape struct {
	Direction   Direction    `json:"direction"`
	FirstToken  Span         `json:"first_token"`  // Method or version
	SecondToken Span         `json:"second_token"` // Path or status code
	ThirdToken  Span         `json:"third_token"`  // Version or reason
	Headers     []HeaderSpan `json:"headers"`
	Body        Span         `json:"body"`
}

// StoredMessage bundles the raw bytes with the parsed shape spans.
type StoredMessage struct {
	ID    MsgID        `json:"id"`
	Raw   []byte       `json:"raw"`
	Shape MessageShape `json:"shape"`
}

func (m *StoredMessage) Slice(s Span) []byte {
	if s.End() > len(m.Raw) {
		return nil
	}
	return m.Raw[s.Offset:s.End()]
}

func (m *StoredMessage) Text(s Span) string {
	slice := m.Slice(s)
	if slice == nil {
		return ""
	}
	return string(slice)
}

func (m *StoredMessage) Header(name string) []byte {
	want := []byte(strings.ToLower(name))
	for _, h := range m.Shape.Headers {
		n := m.Slice(h.Name)
		if bytes.Equal(bytes.ToLower(n), want) {
			return m.Slice(h.Value)
		}
	}
	return nil
}

func (m *StoredMessage) Body() []byte {
	return m.Slice(m.Shape.Body)
}

// Protocol identifies HTTP version.
type Protocol string

const (
	Http1 Protocol = "Http1"
	Http2 Protocol = "Http2"
)

// ChildRef points to a child resource like a websocket frame or HTTP/2 frame.
type ChildRef struct {
	Type string `json:"type"` // "WsFrame" or "H2Frame"
	Msg  MsgID  `json:"msg"`
}

// Exchange represents a logged request-response flow.
type Exchange struct {
	ID          uint64     `json:"id"`
	Request     MsgID      `json:"request"`
	Response    *MsgID     `json:"response"`
	Host        string     `json:"host"`
	Port        uint16     `json:"port"`
	TLS         bool       `json:"tls"`
	Method      string     `json:"method"`
	Path        string     `json:"path"`
	Status      *uint16    `json:"status"`
	ResponseLen int        `json:"response_len"`
	StartedMs   uint64     `json:"started_ms"`
	DurationMs  uint64     `json:"duration_ms"`
	Notes       *string    `json:"notes"`
	Related     []ChildRef `json:"related"`
	Protocol    Protocol   `json:"protocol"`
}

// WsMessage represents a captured WebSocket frame message.
type WsMessage struct {
	ID        uint64 `json:"id"`
	Exchange  uint64 `json:"exchange"`
	Direction string `json:"direction"` // "client" or "server"
	Opcode    uint8  `json:"opcode"`
	Payload   MsgID  `json:"payload"`
	Length    int    `json:"length"`
	TimeMs    uint64 `json:"time_ms"`
}

// TrafficStore manages the messages and exchanges thread-safely.
type TrafficStore struct {
	mu        sync.RWMutex
	messages  []StoredMessage
	exchanges []Exchange
	ws        []WsMessage
	bytes     int
}

func NewTrafficStore() *TrafficStore {
	return &TrafficStore{
		messages:  make([]StoredMessage, 0),
		exchanges: make([]Exchange, 0),
		ws:        make([]WsMessage, 0),
	}
}

func (ts *TrafficStore) Put(raw []byte, dir Direction) MsgID {
	shape := Parse(raw, dir)
	ts.mu.Lock()
	defer ts.mu.Unlock()

	id := MsgID(len(ts.messages))
	msg := StoredMessage{
		ID:    id,
		Raw:   raw,
		Shape: shape,
	}
	ts.messages = append(ts.messages, msg)
	ts.bytes += len(raw)
	return id
}

func (ts *TrafficStore) Get(id MsgID) (*StoredMessage, bool) {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	if int(id) >= len(ts.messages) {
		return nil, false
	}
	msg := ts.messages[id]
	return &msg, true
}

func (ts *TrafficStore) AddExchange(ex Exchange) uint64 {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	id := uint64(len(ts.exchanges))
	ex.ID = id
	ts.exchanges = append(ts.exchanges, ex)
	return id
}

func (ts *TrafficStore) SetResponse(exchangeID uint64, resp MsgID, status uint16, length int, durationMs uint64) {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	if int(exchangeID) < len(ts.exchanges) {
		ts.exchanges[exchangeID].Response = &resp
		ts.exchanges[exchangeID].Status = &status
		ts.exchanges[exchangeID].ResponseLen = length
		ts.exchanges[exchangeID].DurationMs = durationMs
	}
}

func (ts *TrafficStore) Exchanges(offset, limit int) []Exchange {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	n := len(ts.exchanges)
	if offset >= n {
		return nil
	}
	end := offset + limit
	if end > n {
		end = n
	}
	out := make([]Exchange, 0, end-offset)
	for i := n - 1 - offset; i >= n-end; i-- {
		out = append(out, ts.exchanges[i])
	}
	return out
}

func (ts *TrafficStore) Exchange(id uint64) (Exchange, bool) {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	if int(id) >= len(ts.exchanges) {
		return Exchange{}, false
	}
	return ts.exchanges[id], true
}

func (ts *TrafficStore) AddWsMessage(m WsMessage) uint64 {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	id := uint64(len(ts.ws))
	m.ID = id
	ts.ws = append(ts.ws, m)
	return id
}

func (ts *TrafficStore) WsMessages(offset, limit int) []WsMessage {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	n := len(ts.ws)
	if offset >= n {
		return nil
	}
	end := offset + limit
	if end > n {
		end = n
	}
	out := make([]WsMessage, 0, end-offset)
	for i := n - 1 - offset; i >= n-end; i-- {
		out = append(out, ts.ws[i])
	}
	return out
}

func (ts *TrafficStore) WsMessagesFor(exchangeID uint64, offset, limit int) []WsMessage {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	var filtered []WsMessage
	for _, m := range ts.ws {
		if m.Exchange == exchangeID {
			filtered = append(filtered, m)
		}
	}

	n := len(filtered)
	if offset >= n {
		return nil
	}
	end := offset + limit
	if end > n {
		end = n
	}

	out := make([]WsMessage, 0, end-offset)
	for i := n - 1 - offset; i >= n-end; i-- {
		out = append(out, filtered[i])
	}
	return out
}

func (ts *TrafficStore) WsMessage(id uint64) (WsMessage, bool) {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	if int(id) >= len(ts.ws) {
		return WsMessage{}, false
	}
	return ts.ws[id], true
}

func (ts *TrafficStore) WsCount() int {
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	return len(ts.ws)
}

func (ts *TrafficStore) Counts() (int, int, int) {
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	return len(ts.exchanges), len(ts.messages), ts.bytes
}

// Parse extracts Spans from raw HTTP payload bytes.
func Parse(raw []byte, dir Direction) MessageShape {
	headEnd, bodyStart := findHeaderEnd(raw)
	lineEnd := findLineEnd(raw, 0)
	if lineEnd > headEnd {
		lineEnd = headEnd
	}

	first, second, third := split3(raw, 0, lineEnd)

	var headers []HeaderSpan
	pos := nextLineStart(raw, lineEnd)
	for pos < headEnd {
		eol := findLineEnd(raw, pos)
		if eol > headEnd {
			eol = headEnd
		}
		if eol <= pos {
			break
		}

		colon := bytes.IndexByte(raw[pos:eol], ':')
		if colon != -1 {
			nameSpan := Span{Offset: pos, Len: colon}
			vs := pos + colon + 1
			for vs < eol && (raw[vs] == ' ' || raw[vs] == '\t') {
				vs++
			}
			headers = append(headers, HeaderSpan{
				Name:  nameSpan,
				Value: Span{Offset: vs, Len: eol - vs},
			})
		}
		pos = nextLineStart(raw, eol)
	}

	bodyLen := len(raw) - bodyStart
	if bodyLen < 0 {
		bodyLen = 0
	}

	return MessageShape{
		Direction:   dir,
		FirstToken:  first,
		SecondToken: second,
		ThirdToken:  third,
		Headers:     headers,
		Body:        Span{Offset: bodyStart, Len: bodyLen},
	}
}

func findHeaderEnd(raw []byte) (int, int) {
	if i := bytes.Index(raw, []byte("\r\n\r\n")); i != -1 {
		return i, i + 4
	}
	if i := bytes.Index(raw, []byte("\n\n")); i != -1 {
		return i, i + 2
	}
	return len(raw), len(raw)
}

func findLineEnd(raw []byte, from int) int {
	for i := from; i < len(raw); i++ {
		if raw[i] == '\r' && i+1 < len(raw) && raw[i+1] == '\n' {
			return i
		}
		if raw[i] == '\n' {
			return i
		}
	}
	return len(raw)
}

func nextLineStart(raw []byte, eol int) int {
	if eol < len(raw) && raw[eol] == '\r' && eol+1 < len(raw) && raw[eol+1] == '\n' {
		return eol + 2
	}
	if eol < len(raw) && raw[eol] == '\n' {
		return eol + 1
	}
	return eol
}

func split3(raw []byte, start, end int) (Span, Span, Span) {
	if start >= len(raw) || end > len(raw) || start >= end {
		return Span{}, Span{}, Span{}
	}
	seg := raw[start:end]
	s1 := bytes.IndexByte(seg, ' ')
	if s1 == -1 {
		return Span{Offset: start, Len: len(seg)}, Span{}, Span{}
	}

	rest := seg[s1+1:]
	s2 := bytes.IndexByte(rest, ' ')
	if s2 == -1 {
		return Span{Offset: start, Len: s1},
			Span{Offset: start + s1 + 1, Len: len(rest)},
			Span{Offset: end, Len: 0}
	}

	return Span{Offset: start, Len: s1},
		Span{Offset: start + s1 + 1, Len: s2},
		Span{Offset: start + s1 + 1 + s2 + 1, Len: len(rest) - (s2 + 1)}
}

func parseValue(v string) string {
	v = strings.TrimSpace(v)
	if strings.HasPrefix(v, `"`) && strings.HasSuffix(v, `"`) {
		v = v[1 : len(v)-1]
		v = strings.ReplaceAll(v, `\"`, `"`)
	} else if strings.HasPrefix(v, `'`) && strings.HasSuffix(v, `'`) {
		v = v[1 : len(v)-1]
		v = strings.ReplaceAll(v, `\'`, `'`)
	}
	return v
}

// MatchesQuery implements basic typed filtering over exchanges: DSL-01.
// Supports query like: host == "x.test", status == 200, method == "POST", mime == "application/json", body ~ "admin".
func (ts *TrafficStore) MatchesQuery(ex *Exchange, query string) (bool, error) {
	query = strings.TrimSpace(query)
	if query == "" {
		return true, nil
	}

	var field, op, valStr string
	var opIdx int

	operators := []string{"==", "!=", "~", "<", ">"}
	for _, operator := range operators {
		idx := strings.Index(query, operator)
		if idx != -1 {
			field = strings.TrimSpace(query[:idx])
			op = operator
			opIdx = idx
			break
		}
	}

	if op == "" {
		return false, fmt.Errorf("no valid operator found in query: %s", query)
	}

	valStr = parseValue(query[opIdx+len(op):])
	field = strings.ToLower(field)

	switch field {
	case "host":
		hostLower := strings.ToLower(ex.Host)
		valLower := strings.ToLower(valStr)
		if op == "==" {
			return hostLower == valLower, nil
		} else if op == "!=" {
			return hostLower != valLower, nil
		} else if op == "~" {
			return strings.Contains(hostLower, valLower), nil
		}
	case "status":
		if ex.Status == nil {
			return false, nil
		}
		var sVal uint16
		_, err := fmt.Sscanf(valStr, "%d", &sVal)
		if err != nil {
			return false, fmt.Errorf("invalid status value: %s", valStr)
		}
		status := *ex.Status
		switch op {
		case "==":
			return status == sVal, nil
		case "!=":
			return status != sVal, nil
		case "<":
			return status < sVal, nil
		case ">":
			return status > sVal, nil
		}
	case "method":
		mUpper := strings.ToUpper(ex.Method)
		vUpper := strings.ToUpper(valStr)
		if op == "==" {
			return mUpper == vUpper, nil
		} else if op == "!=" {
			return mUpper != vUpper, nil
		} else if op == "~" {
			return strings.Contains(mUpper, vUpper), nil
		}
	case "mime":
		if ex.Response == nil {
			return false, nil
		}
		resp, ok := ts.Get(*ex.Response)
		if !ok {
			return false, nil
		}
		mime := string(resp.Header("content-type"))
		mimeLower := strings.ToLower(mime)
		valLower := strings.ToLower(valStr)
		if op == "==" {
			return strings.Contains(mimeLower, valLower), nil
		} else if op == "~" {
			return strings.Contains(mimeLower, valLower), nil
		}
	case "body":
		req, ok1 := ts.Get(ex.Request)
		var bodyReq, bodyResp []byte
		if ok1 {
			bodyReq = req.Body()
		}
		if ex.Response != nil {
			if resp, ok2 := ts.Get(*ex.Response); ok2 {
				bodyResp = resp.Body()
			}
		}
		needle := []byte(strings.ToLower(valStr))
		if op == "~" {
			containsReq := bytes.Contains(bytes.ToLower(bodyReq), needle)
			containsResp := bytes.Contains(bytes.ToLower(bodyResp), needle)
			return containsReq || containsResp, nil
		}
	}

	return false, nil
}
