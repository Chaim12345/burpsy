package web

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/crawler"
)

// ui2 Repeater tools beside the HTTP editor: the WebSocket Repeater (/ui2/repeater/ws), the
// HTTP/2 kettle header-list editor (/ui2/repeater/h2) and the GraphQL tools
// (/ui2/repeater/graphql). Every model comes from the JSON API through the mux; nothing here
// re-derives what those routes decide. The sends (ws-send, ws-attach, repeater/send) are
// riskEgress, ungated, the same class as the HTTP Repeater's own send. The one store write,
// /api/graphql/sitemap (riskLocal), goes through a server-held review: confirm holds the exact
// body, run spends it once.

const ui2RepeaterTitle = "burpsy /ui2/ — Repeater"

// ui2RWAPI calls one internal JSON route and decodes the answer into out. The error string is
// the API's refusal made readable, "" on success.
func (s *Server) ui2RWAPI(method, path string, payload, out any) string {
	res, errText := s.ui2APIResult(method, path, payload)
	if errText != "" {
		return ui2APIErrorText(errText)
	}
	if out == nil {
		return ""
	}
	b, _ := json.Marshal(res)
	if err := json.Unmarshal(b, out); err != nil {
		return "unreadable response: " + err.Error()
	}
	return ""
}

// ui2RWStoredRequest returns an exchange's request text and the exchange, or "" when it has none.
func (s *Server) ui2RWStoredRequest(id core.ExchangeID) (string, *core.Exchange) {
	ex, err := s.store.GetExchange(id)
	if err != nil || ex.Request == nil {
		return "", nil
	}
	msg, err := s.store.Get(*ex.Request)
	if err != nil {
		return "", nil
	}
	return string(msg.Raw()), ex
}

// ui2RWSeedRequest resolves ?exchange=N, else the newest captured request. ok is false when
// ?exchange names nothing (the caller says so rather than silently showing another request).
func (s *Server) ui2RWSeedRequest(r *http.Request) (raw string, ex *core.Exchange, note string) {
	if v := r.URL.Query().Get("exchange"); v != "" {
		id, err := strconv.ParseUint(v, 10, 63)
		if err != nil {
			return "", nil, "exchange must be a whole number"
		}
		raw, ex = s.ui2RWStoredRequest(core.ExchangeID(id))
		if ex == nil {
			return "", nil, fmt.Sprintf("exchange %d has no stored request", id)
		}
		return raw, ex, ""
	}
	exID, _, latest := ui2LatestExchange(s)
	if latest == "" {
		return "", nil, ""
	}
	_, ex = s.ui2RWStoredRequest(core.ExchangeID(exID))
	return latest, ex, ""
}

func ui2RWTarget(ex *core.Exchange) string {
	if ex == nil || ex.Host == "" {
		return ""
	}
	scheme := "http://"
	if ex.TLS {
		scheme = "https://"
	}
	host := ex.Host
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}
	return scheme + host + ":" + strconv.Itoa(int(ex.Port))
}

// ---- WebSocket Repeater ----------------------------------------------------------------------

// ui2WSForm is the WebSocket editor's state, round-tripped through the form.
type ui2WSForm struct {
	Mode          string // new | clone | attach
	Target        string // ws://host:port for a new connection
	Path          string
	Socket        string // the WebSocket ID (handshake exchange) clone/attach act on
	Direction     string // server | client
	Opcode        string // text | binary
	Payload       string
	Handshake     string
	EditHandshake bool
}

type ui2WSFrame struct {
	wsRowView
	Preview string
}

type ui2WSModel struct {
	Form        ui2WSForm
	Connections []wsConnectionView
	Conn        *wsConnectionView // the connection Socket names, when the store knows it
	Frames      []ui2WSFrame
	Frame       *wsMessageResp // the frame loaded into the editor
	Note        string
	Error       string
	Sent        *repeaterWsSendResp
	Attached    *repeaterWsAttachResp
}

func ui2WSFormFrom(v url.Values) ui2WSForm {
	f := ui2WSForm{
		Mode:          v.Get("mode"),
		Target:        strings.TrimSpace(v.Get("target")),
		Path:          strings.TrimSpace(v.Get("path")),
		Socket:        strings.TrimSpace(v.Get("socket")),
		Direction:     v.Get("direction"),
		Opcode:        v.Get("opcode"),
		Payload:       v.Get("payload"),
		Handshake:     v.Get("handshake"),
		EditHandshake: v.Get("edit_handshake") == "on",
	}
	if f.Direction != "client" {
		f.Direction = "server"
	}
	if f.Opcode != "binary" {
		f.Opcode = "text"
	}
	return f
}

func ui2WSSocketID(f ui2WSForm) (uint64, bool, string) {
	if f.Socket == "" {
		return 0, false, ""
	}
	id, err := strconv.ParseUint(f.Socket, 10, 63)
	if err != nil {
		return 0, false, "socket must be a WebSocket ID (a whole number)"
	}
	return id, true, ""
}

// ui2WSModelFor reads connections, the selected connection's frames and (optionally) a frame.
func (s *Server) ui2WSModelFor(f ui2WSForm, frameID string) ui2WSModel {
	m := ui2WSModel{Form: f, Connections: []wsConnectionView{}}
	if e := s.ui2RWAPI(http.MethodGet, "/api/ws/connections", nil, &m.Connections); e != "" {
		m.Error = "connections unavailable: " + e
	}
	if frameID != "" {
		id, err := strconv.ParseUint(frameID, 10, 63)
		if err != nil {
			m.Error = "frame must be a whole number"
		} else {
			var msg wsMessageResp
			if e := s.ui2RWAPI(http.MethodGet, "/api/ws/message/"+strconv.FormatUint(id, 10), nil, &msg); e != "" {
				m.Error = e
			} else {
				m.Frame = &msg
				if m.Form.Socket == "" {
					m.Form.Socket = strconv.FormatUint(uint64(msg.Exchange), 10)
				}
				if m.Form.Payload == "" {
					m.Form.Payload = msg.Text
				}
				if msg.Opcode == "binary" {
					m.Form.Opcode = "binary"
				}
			}
		}
	}
	socket, has, bad := ui2WSSocketID(m.Form)
	if bad != "" {
		m.Error = bad
		m.Form.Socket = ""
	}
	if has {
		for i := range m.Connections {
			if uint64(m.Connections[i].Exchange) == socket {
				m.Conn = &m.Connections[i]
			}
		}
		var hist wsHistoryResp
		if e := s.ui2RWAPI(http.MethodGet, "/api/ws/history?limit=50&exchange="+strconv.FormatUint(socket, 10), nil, &hist); e == "" {
			for i, row := range hist.Rows {
				fr := ui2WSFrame{wsRowView: row}
				if i < 20 {
					var msg wsMessageResp
					if s.ui2RWAPI(http.MethodGet, "/api/ws/message/"+strconv.FormatUint(row.ID, 10), nil, &msg) == "" {
						fr.Preview = msg.Text
						if len(fr.Preview) > 200 {
							fr.Preview = strings.ToValidUTF8(fr.Preview[:200], "") + "…"
						}
					}
				}
				m.Frames = append(m.Frames, fr)
			}
		}
	}
	switch m.Form.Mode {
	case "new", "clone", "attach":
	default:
		// Burp's default for a connection opened from history: attach while the proxy holds it,
		// clone once it has closed, new when no connection is named.
		switch {
		case !has:
			m.Form.Mode = "new"
		case m.Conn != nil && m.Conn.Live:
			m.Form.Mode = "attach"
		default:
			m.Form.Mode = "clone"
		}
	}
	if m.Form.Target == "" && m.Conn != nil {
		scheme := "ws://"
		if m.Conn.TLS {
			scheme = "wss://"
		}
		host := m.Conn.Host
		if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
			host = "[" + host + "]"
		}
		m.Form.Target = scheme + host + ":" + strconv.Itoa(int(m.Conn.Port))
		if m.Form.Path == "" {
			m.Form.Path = m.Conn.Path
		}
	}
	return m
}

// handleUI2RepeaterWS serves GET /ui2/repeater/ws: the WebSocket editor, seeded from ?frame=N
// (a WebSockets history frame) or ?exchange=N (a connection). ?preview=1 loads the handshake
// a send would dial with into the negotiation-request editor; it reads and dials nothing.
func (s *Server) handleUI2RepeaterWS(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := ui2WSFormFrom(q)
	if f.Socket == "" {
		f.Socket = strings.TrimSpace(q.Get("exchange"))
	}
	m := s.ui2WSModelFor(f, q.Get("frame"))
	if q.Get("preview") == "1" && m.Error == "" {
		pq := url.Values{}
		if m.Form.Mode != "new" && m.Form.Socket != "" {
			pq.Set("socket", m.Form.Socket)
		} else {
			pq.Set("target", m.Form.Target)
			if m.Form.Path != "" {
				pq.Set("path", m.Form.Path)
			}
		}
		var prev repeaterWsHandshakePreviewResp
		if e := s.ui2RWAPI(http.MethodGet, "/api/repeater/ws-handshake-preview?"+pq.Encode(), nil, &prev); e != "" {
			m.Error = "handshake preview: " + e
		} else {
			m.Form.Handshake, m.Form.EditHandshake = prev.Handshake, true
			m.Note = "Handshake loaded (" + prev.Source + "): edit it, and the send dials with these bytes."
		}
	}
	ui2Fragment(w, r, ui2RepeaterTitle, "repeater-ws", ui2Exec("repeater_ws_page.html", m))
}

// handleUI2RepeaterWSSend serves POST /ui2/repeater/ws/send: one frame on a new or cloned
// connection (/api/repeater/ws-send) or into a live one (/api/repeater/ws-attach).
func (s *Server) handleUI2RepeaterWSSend(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	f := ui2WSFormFrom(r.PostForm)
	socket, has, bad := ui2WSSocketID(f)
	var sent repeaterWsSendResp
	var attached repeaterWsAttachResp
	errText := bad
	if errText == "" {
		toClient := f.Direction == "client"
		switch {
		case f.Mode == "attach" && has:
			errText = s.ui2RWAPI(http.MethodPost, "/api/repeater/ws-attach",
				repeaterWsAttachReq{Socket: &socket, Opcode: f.Opcode, Payload: f.Payload, ToClient: toClient}, &attached)
		case f.Mode == "clone" && has:
			req := repeaterWsSendReq{Socket: &socket, Opcode: f.Opcode, Payload: f.Payload, ToClient: toClient}
			if f.EditHandshake {
				req.Handshake = &f.Handshake
			} else {
				req.Clone = true
			}
			errText = s.ui2RWAPI(http.MethodPost, "/api/repeater/ws-send", req, &sent)
		case f.Mode == "new":
			req := repeaterWsSendReq{Target: f.Target, Path: f.Path, Opcode: f.Opcode, Payload: f.Payload, ToClient: toClient}
			if f.EditHandshake {
				req.Handshake = &f.Handshake
			}
			errText = s.ui2RWAPI(http.MethodPost, "/api/repeater/ws-send", req, &sent)
		default:
			errText = "clone and attach need a connection: open the editor from WebSockets history or name a WebSocket ID"
		}
	}
	m := s.ui2WSModelFor(f, "")
	if errText != "" {
		m.Error = errText
	} else if f.Mode == "attach" {
		m.Attached = &attached
	} else {
		m.Sent = &sent
	}
	ui2Fragment(w, r, ui2RepeaterTitle, "repeater-ws", ui2Exec("repeater_ws_page.html", m))
}

// ---- HTTP/2 kettle header-list editor --------------------------------------------------------

// ui2H2Row is one header-list field as the editor shows it: name and value in escape notation
// (\r \n \t \\ \xHH), so bytes HTTP/1 text cannot carry stay visible and editable.
type ui2H2Row struct{ Name, Value string }

type ui2H2Model struct {
	Exchange  *core.ExchangeID
	Target    string
	TLS       bool
	Rows      []ui2H2Row
	Body      string
	Answer    *h2KettleResp
	Rendering string
	Result    *repeaterSendResp
	Note      string
	Error     string
}

func ui2H2Escape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		r, n := utf8.DecodeRuneInString(s[i:])
		c := s[i]
		switch {
		case c == '\\':
			b.WriteString(`\\`)
		case c == '\r':
			b.WriteString(`\r`)
		case c == '\n':
			b.WriteString(`\n`)
		case c == '\t':
			b.WriteString(`\t`)
		case r == utf8.RuneError && n <= 1, c < 0x20, c == 0x7f:
			fmt.Fprintf(&b, `\x%02x`, c)
			n = 1
		default:
			b.WriteString(s[i : i+n])
		}
		i += n
	}
	return b.String()
}

func ui2H2Unescape(s string) (string, error) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			b.WriteByte(s[i])
			continue
		}
		if i+1 >= len(s) {
			return "", fmt.Errorf("a trailing backslash escapes nothing (write \\\\ for a backslash)")
		}
		i++
		switch s[i] {
		case '\\':
			b.WriteByte('\\')
		case 'r':
			b.WriteByte('\r')
		case 'n':
			b.WriteByte('\n')
		case 't':
			b.WriteByte('\t')
		case 'x':
			if i+2 >= len(s) {
				return "", fmt.Errorf(`\x needs two hex digits`)
			}
			v, err := strconv.ParseUint(s[i+1:i+3], 16, 8)
			if err != nil {
				return "", fmt.Errorf(`\x needs two hex digits, got %q`, s[i+1:i+3])
			}
			b.WriteByte(byte(v))
			i += 2
		default:
			return "", fmt.Errorf(`unknown escape \%c (use \r \n \t \\ or \xHH)`, s[i])
		}
	}
	return b.String(), nil
}

// ui2H2Seed turns an HTTP/1-shaped request into the field list a kettling edit starts from:
// pseudo-headers first (:authority from the first Host), then every other header, lowercased.
func ui2H2Seed(raw string, tls bool) ([]ui2H2Row, string) {
	norm := strings.ReplaceAll(raw, "\r\n", "\n")
	head, body, _ := strings.Cut(norm, "\n\n")
	lines := strings.Split(head, "\n")
	method, target := "GET", "/"
	if parts := strings.Fields(lines[0]); len(parts) >= 2 {
		method, target = parts[0], parts[1]
	}
	scheme := "http"
	if tls {
		scheme = "https"
	}
	rows := []ui2H2Row{{":method", method}, {":scheme", scheme}, {":authority", ""}, {":path", target}}
	hostSeen := false
	for _, line := range lines[1:] {
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		name, value = strings.ToLower(strings.TrimSpace(name)), strings.TrimSpace(value)
		if name == "host" && !hostSeen {
			rows[2].Value, hostSeen = value, true
			continue
		}
		rows = append(rows, ui2H2Row{name, value})
	}
	if !hostSeen {
		rows = append(rows[:2], rows[3:]...)
	}
	for i := range rows {
		rows[i].Name, rows[i].Value = ui2H2Escape(rows[i].Name), ui2H2Escape(rows[i].Value)
	}
	return rows, strings.ReplaceAll(body, "\n", "\r\n")
}

// ui2H2Parse reads the editor form: repeated name/value pairs in order, blank rows dropped.
func ui2H2Parse(r *http.Request) (ui2H2Model, []h2FieldView, string) {
	m := ui2H2Model{
		Target: strings.TrimSpace(r.PostFormValue("target")),
		TLS:    r.PostFormValue("tls") == "on",
		Body:   r.PostFormValue("body"),
	}
	if v := r.PostFormValue("exchange"); v != "" {
		if id, err := strconv.ParseUint(v, 10, 63); err == nil {
			ex := core.ExchangeID(id)
			m.Exchange = &ex
		}
	}
	names, values := r.PostForm["name"], r.PostForm["value"]
	if len(names) != len(values) {
		return m, nil, "every header row needs a name and a value field"
	}
	var fields []h2FieldView
	for i := range names {
		if names[i] == "" && values[i] == "" {
			continue
		}
		m.Rows = append(m.Rows, ui2H2Row{names[i], values[i]})
		name, err := ui2H2Unescape(names[i])
		if err != nil {
			return m, nil, fmt.Sprintf("row %d name: %v", i+1, err)
		}
		value, err := ui2H2Unescape(values[i])
		if err != nil {
			return m, nil, fmt.Sprintf("row %d value: %v", i+1, err)
		}
		if name == "" {
			return m, nil, fmt.Sprintf("row %d has a value but no name", i+1)
		}
		// The list travels to the API as JSON text, which would silently replace these bytes.
		if !utf8.ValidString(name) || !utf8.ValidString(value) {
			return m, nil, fmt.Sprintf("row %d is not valid UTF-8 after unescaping; the header list API carries text", i+1)
		}
		fields = append(fields, h2FieldView{Name: name, Value: value})
	}
	if len(fields) == 0 {
		return m, nil, "the header list is empty; a kettled request needs at least its pseudo-headers"
	}
	return m, fields, ""
}

func ui2H2Render(w http.ResponseWriter, r *http.Request, m ui2H2Model) {
	// Three blank rows to add fields into.
	m.Rows = append(m.Rows, ui2H2Row{}, ui2H2Row{}, ui2H2Row{})
	ui2Fragment(w, r, ui2RepeaterTitle, "repeater-h2", ui2Exec("repeater_h2_page.html", m))
}

// handleUI2RepeaterH2 serves GET /ui2/repeater/h2[?exchange=N]: the header list of a stored
// request (default: the newest captured one) as an editable HTTP/2 field list.
func (s *Server) handleUI2RepeaterH2(w http.ResponseWriter, r *http.Request) {
	raw, ex, note := s.ui2RWSeedRequest(r)
	m := ui2H2Model{Error: note, TLS: true}
	if ex != nil {
		id := ex.ID
		m.Exchange, m.Target, m.TLS = &id, ui2RWTarget(ex), ex.TLS
	}
	if raw != "" {
		m.Rows, m.Body = ui2H2Seed(raw, m.TLS)
	} else if note == "" {
		m.Note = "No captured request: write the header list by hand."
		m.Rows = []ui2H2Row{{":method", "GET"}, {":scheme", "https"}, {":authority", ""}, {":path", "/"}}
	}
	ui2H2Render(w, r, m)
}

// handleUI2RepeaterH2Preview serves POST /ui2/repeater/h2/preview: asks /api/http2/kettle whether
// the list is kettled and whether a send would be refused, and shows the HTTP/1 rendering. Sends nothing.
func (s *Server) handleUI2RepeaterH2Preview(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	m, fields, errText := ui2H2Parse(r)
	if errText == "" {
		var ans h2KettleResp
		if errText = s.ui2RWAPI(http.MethodPost, "/api/http2/kettle", h2KettleReq{Fields: fields, TLS: m.TLS}, &ans); errText == "" {
			m.Answer = &ans
			if hf, err := validKettledFields("fields", fields); err == nil {
				m.Rendering = string(kettledRendering(hf, []byte(m.Body)))
			}
		}
	}
	m.Error = errText
	ui2H2Render(w, r, m)
}

// handleUI2RepeaterH2Send serves POST /ui2/repeater/h2/send: the list goes out as written through
// /api/repeater/send's kettled path (h2_headers), with the body from the editor.
func (s *Server) handleUI2RepeaterH2Send(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	m, fields, errText := ui2H2Parse(r)
	if errText == "" && m.Target == "" {
		errText = "give a target (host:port) to send to"
	}
	if errText == "" {
		hf, err := validKettledFields("h2_headers", fields)
		if err != nil {
			errText = err.Error()
		} else {
			protocol := "http"
			if m.TLS {
				protocol = "https"
			}
			var res repeaterSendResp
			errText = s.ui2RWAPI(http.MethodPost, "/api/repeater/send", map[string]any{
				"target": m.Target, "protocol": protocol, "from_exchange": m.Exchange,
				"request": string(kettledRendering(hf, []byte(m.Body))), "h2_headers": fields,
			}, &res)
			if errText == "" {
				m.Result = &res
			}
		}
	}
	m.Error = errText
	ui2H2Render(w, r, m)
}

// ---- GraphQL tools ---------------------------------------------------------------------------

// The two documents Burp's "Set introspection query" / "Set legacy introspection query" write.
const ui2GQLIntrospection = "query IntrospectionQuery {\n    __schema {\n        queryType {\n            name\n        }\n        mutationType {\n            name\n        }\n        subscriptionType {\n            name\n        }\n        types {\n            ...FullType\n        }\n        directives {\n            name\n            description\n            locations\n            args {\n                ...InputValue\n            }\n        }\n    }\n}\n\nfragment FullType on __Type {\n    kind\n    name\n    description\n    fields(includeDeprecated: true) {\n        name\n        description\n        args {\n            ...InputValue\n        }\n        type {\n            ...TypeRef\n        }\n        isDeprecated\n        deprecationReason\n    }\n    inputFields {\n        ...InputValue\n    }\n    interfaces {\n        ...TypeRef\n    }\n    enumValues(includeDeprecated: true) {\n        name\n        description\n        isDeprecated\n        deprecationReason\n    }\n    possibleTypes {\n        ...TypeRef\n    }\n}\n\nfragment InputValue on __InputValue {\n    name\n    description\n    type {\n        ...TypeRef\n    }\n    defaultValue\n}\n\nfragment TypeRef on __Type {\n    kind\n    name\n    ofType {\n        kind\n        name\n        ofType {\n            kind\n            name\n            ofType {\n                kind\n                name\n            }\n        }\n    }\n}"

const ui2GQLLegacyIntrospection = "query IntrospectionQuery {\n    __schema {\n        queryType {\n            name\n        }\n        mutationType {\n            name\n        }\n        types {\n            ...FullType\n        }\n        directives {\n            name\n            description\n            args {\n                ...InputValue\n            }\n            onOperation\n            onFragment\n            onField\n        }\n    }\n}\n\nfragment FullType on __Type {\n    kind\n    name\n    description\n    fields(includeDeprecated: true) {\n        name\n        description\n        args {\n            ...InputValue\n        }\n        type {\n            ...TypeRef\n        }\n        isDeprecated\n        deprecationReason\n    }\n    inputFields {\n        ...InputValue\n    }\n    interfaces {\n        ...TypeRef\n    }\n    enumValues(includeDeprecated: true) {\n        name\n        description\n        isDeprecated\n        deprecationReason\n    }\n    possibleTypes {\n        ...TypeRef\n    }\n}\n\nfragment InputValue on __InputValue {\n    name\n    description\n    type {\n        ...TypeRef\n    }\n    defaultValue\n}\n\nfragment TypeRef on __Type {\n    kind\n    name\n    ofType {\n        kind\n        name\n        ofType {\n            kind\n            name\n            ofType {\n                kind\n                name\n            }\n        }\n    }\n}"

type ui2GQLModel struct {
	Exchange    *core.ExchangeID
	HasResponse bool
	Target      string
	Request     string
	Index       int
	Operations  int
	Query       string
	Source      string
	Validation  *repeaterGraphQLValidateResp
	Result      *repeaterSendResp
	Note        string
	Error       string
	Sitemap     ui2GQLSitemapModel
}

// ui2GQLCurrentQuery decodes the index'th operation's query out of the request's carrier, for
// the query editor. It reads the same spans /api/repeater/graphql-query rewrites.
func ui2GQLCurrentQuery(raw string, index int) (query string, count int) {
	spans := findGraphQLQuerySpans(raw)
	if index < 0 || index >= len(spans) {
		return "", len(spans)
	}
	sp := spans[index]
	content := raw[sp.start:sp.end]
	if sp.source == "params" {
		if q, err := url.PathUnescape(content); err == nil {
			return q, len(spans)
		}
		return content, len(spans)
	}
	var q string
	if json.Unmarshal([]byte(`"`+content+`"`), &q) == nil {
		return q, len(spans)
	}
	return content, len(spans)
}

func (s *Server) ui2GQLFill(m *ui2GQLModel, keepQuery bool) {
	q, n := ui2GQLCurrentQuery(m.Request, m.Index)
	m.Operations = n
	if !keepQuery {
		m.Query = q
	}
	if m.Exchange != nil {
		if ex, err := s.store.GetExchange(*m.Exchange); err == nil {
			m.HasResponse = ex.Request != nil && ex.Response != nil
		}
		m.Sitemap.Exchange = *m.Exchange
		m.Sitemap.Ready = m.HasResponse
	}
}

func ui2GQLForm(r *http.Request) ui2GQLModel {
	m := ui2GQLModel{
		Request: r.PostFormValue("request"),
		Query:   r.PostFormValue("query"),
		Target:  strings.TrimSpace(r.PostFormValue("target")),
	}
	if n, err := strconv.Atoi(r.PostFormValue("index")); err == nil && n >= 0 {
		m.Index = n
	}
	if v := r.PostFormValue("exchange"); v != "" {
		if id, err := strconv.ParseUint(v, 10, 63); err == nil {
			ex := core.ExchangeID(id)
			m.Exchange = &ex
		}
	}
	return m
}

func ui2GQLRender(w http.ResponseWriter, r *http.Request, m ui2GQLModel) {
	ui2Fragment(w, r, ui2RepeaterTitle, "repeater-gql", ui2Exec("repeater_gql_page.html", m))
}

// handleUI2RepeaterGraphQL serves GET /ui2/repeater/graphql[?exchange=N&index=I]: a stored
// request (default: the newest captured one) with its GraphQL query in an editor.
func (s *Server) handleUI2RepeaterGraphQL(w http.ResponseWriter, r *http.Request) {
	raw, ex, note := s.ui2RWSeedRequest(r)
	m := ui2GQLModel{Request: raw, Error: note}
	if n, err := strconv.Atoi(r.URL.Query().Get("index")); err == nil && n >= 0 {
		m.Index = n
	}
	if ex != nil {
		id := ex.ID
		m.Exchange, m.Target = &id, ui2RWTarget(ex)
	}
	s.ui2GQLFill(&m, false)
	ui2GQLRender(w, r, m)
}

// handleUI2RepeaterGraphQLValidate serves POST /ui2/repeater/graphql/validate: the query editor's
// document through /api/repeater/graphql-validate. Reads only.
func (s *Server) handleUI2RepeaterGraphQLValidate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	m := ui2GQLForm(r)
	var v repeaterGraphQLValidateResp
	if m.Error = s.ui2RWAPI(http.MethodPost, "/api/repeater/graphql-validate", repeaterGraphQLValidateReq{Query: m.Query}, &v); m.Error == "" {
		m.Validation = &v
	}
	s.ui2GQLFill(&m, true)
	ui2GQLRender(w, r, m)
}

// handleUI2RepeaterGraphQLQuery serves POST /ui2/repeater/graphql/query: writes the editor's
// query (or an introspection document, preset=introspection|legacy) into the request's carrier
// through /api/repeater/graphql-query. Text surgery on the draft; nothing is sent or stored.
func (s *Server) handleUI2RepeaterGraphQLQuery(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	m := ui2GQLForm(r)
	switch r.PostFormValue("preset") {
	case "":
	case "introspection":
		m.Query = ui2GQLIntrospection
	case "legacy":
		m.Query = ui2GQLLegacyIntrospection
	default:
		m.Error = "unknown preset"
	}
	if m.Error == "" {
		var res repeaterGraphQLQueryResp
		if m.Error = s.ui2RWAPI(http.MethodPost, "/api/repeater/graphql-query",
			repeaterGraphQLQueryReq{Request: m.Request, Index: m.Index, Query: m.Query}, &res); m.Error == "" {
			m.Request, m.Source = res.Request, res.Source
			m.Note = "Query written into the request's " + res.Source + " carrier; nothing was sent."
		}
	}
	s.ui2GQLFill(&m, m.Error != "")
	ui2GQLRender(w, r, m)
}

// handleUI2RepeaterGraphQLSend serves POST /ui2/repeater/graphql/send: the request through
// /api/repeater/send (riskEgress, the HTTP Repeater's own send). The page then names the new
// exchange, so its answer can be saved to the site map.
func (s *Server) handleUI2RepeaterGraphQLSend(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	m := ui2GQLForm(r)
	target := m.Target
	if target == "" {
		target = ui2HostFromRequest(m.Request)
	}
	if target == "" {
		m.Error = "no target: the request carries no Host header and no target was given"
	} else {
		var res repeaterSendResp
		if m.Error = s.ui2RWAPI(http.MethodPost, "/api/repeater/send",
			map[string]any{"target": target, "request": m.Request, "from_exchange": m.Exchange}, &res); m.Error == "" {
			m.Result = &res
			id := res.ExchangeID
			m.Exchange = &id
		}
	}
	s.ui2GQLFill(&m, true)
	ui2GQLRender(w, r, m)
}

// ---- GraphQL save-to-site-map: server-held review --------------------------------------------

type ui2GQLSitemapModel struct {
	Exchange  core.ExchangeID
	Ready     bool
	ReviewID  string
	Token     string
	Endpoint  string
	Placement string
	Ops       []ui2GQLOpView
	Truncated bool
	Limit     int
	Done      *graphqlSitemapResp
	Error     string
}

type ui2GQLOpView struct{ Kind, Field, Name string }

type ui2GQLSitemapReview struct {
	srv     *Server
	body    []byte // the exact /api/graphql/sitemap body run dispatches
	token   string // review handle, or the confirmation gate's token when gated
	gated   bool
	expires time.Time
}

// ui2GQLSitemapReviews holds open reviews by id; each is bound to its Server and spent once.
var ui2GQLSitemapReviews sync.Map

const ui2GQLSitemapReviewCap = 8

func ui2GQLSitemapRender(w http.ResponseWriter, r *http.Request, m ui2GQLSitemapModel) {
	ui2Fragment(w, r, ui2RepeaterTitle, "repeater-gql", ui2Exec("repeater_gql_sitemap.html", m))
}

// handleUI2RepeaterGraphQLSitemapConfirm serves POST /ui2/repeater/graphql/sitemap-confirm: reads
// the exchange's introspection answer, lists the operations the save would write, and holds the
// exact call for one spend. Nothing is stored here.
func (s *Server) handleUI2RepeaterGraphQLSitemapConfirm(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	var m ui2GQLSitemapModel
	id, err := strconv.ParseUint(r.PostFormValue("exchange"), 10, 63)
	if err != nil {
		m.Error = "exchange must be a whole number naming the exchange whose response is the introspection answer"
		ui2GQLSitemapRender(w, r, m)
		return
	}
	m.Exchange = core.ExchangeID(id)
	ex, err := s.store.GetExchange(m.Exchange)
	if err != nil || ex.Request == nil || ex.Response == nil {
		m.Error = fmt.Sprintf("exchange %d has no request and response pair - send the introspection query first", id)
		ui2GQLSitemapRender(w, r, m)
		return
	}
	respMsg, err := s.store.Get(*ex.Response)
	if err != nil {
		m.Error = "the exchange's response is not in the store"
		ui2GQLSitemapRender(w, r, m)
		return
	}
	schema, reason := introspectionSchemaFrom(respMsg.Raw())
	if schema == nil {
		m.Error = reason
		ui2GQLSitemapRender(w, r, m)
		return
	}
	ops, truncated := schema.Operations(crawler.MaxGraphQLOperations)
	for _, op := range ops {
		m.Ops = append(m.Ops, ui2GQLOpView{op.Kind, op.Field, op.Name})
	}
	m.Truncated, m.Limit, m.Ready = truncated, crawler.MaxGraphQLOperations, true
	m.Endpoint = ex.Host + ex.Path
	if reqMsg, err := s.store.Get(*ex.Request); err == nil {
		m.Placement = graphqlPlacementOf(reqMsg.Raw())
	}

	now := time.Now()
	open := 0
	ui2GQLSitemapReviews.Range(func(k, v any) bool {
		if e := v.(ui2GQLSitemapReview); now.After(e.expires) {
			ui2GQLSitemapReviews.Delete(k)
		} else if e.srv == s {
			open++
		}
		return true
	})
	if open >= ui2GQLSitemapReviewCap {
		m.Error = "too many save reviews are open; wait for them to expire"
		ui2GQLSitemapRender(w, r, m)
		return
	}
	body, _ := json.Marshal(graphqlSitemapReq{ExchangeID: &m.Exchange})
	rev := ui2GQLSitemapReview{srv: s, body: body, expires: now.Add(ConfirmTTL)}
	if _, risk, _ := routeRiskFor("/api/graphql/sitemap"); needsConfirmation(risk) {
		tok, _, e := s.ui2MintConfirm("/api/graphql/sitemap", http.MethodPost, "/api/graphql/sitemap", body)
		if e != "" || tok == "" {
			m.Error = "could not mint a confirmation: " + e
			ui2GQLSitemapRender(w, r, m)
			return
		}
		rev.token, rev.gated = tok, true
	} else if rev.token, err = randomHex(16); err != nil {
		m.Error = "could not create a review"
		ui2GQLSitemapRender(w, r, m)
		return
	}
	rid, err := randomHex(16)
	if err != nil {
		m.Error = "could not create a review id"
		ui2GQLSitemapRender(w, r, m)
		return
	}
	ui2GQLSitemapReviews.Store(rid, rev)
	m.ReviewID, m.Token = rid, rev.token
	ui2GQLSitemapRender(w, r, m)
}

// handleUI2RepeaterGraphQLSitemapRun serves POST /ui2/repeater/graphql/sitemap-run: spends the
// held review once and dispatches its exact body to /api/graphql/sitemap.
func (s *Server) handleUI2RepeaterGraphQLSitemapRun(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	var m ui2GQLSitemapModel
	v, ok := ui2GQLSitemapReviews.LoadAndDelete(r.PostFormValue("review_id"))
	if !ok {
		m.Error = "review unknown or already used - review again"
		ui2GQLSitemapRender(w, r, m)
		return
	}
	rev := v.(ui2GQLSitemapReview)
	if rev.srv != s || time.Now().After(rev.expires) ||
		subtle.ConstantTimeCompare([]byte(rev.token), []byte(r.PostFormValue("token"))) != 1 {
		m.Error = "review expired or confirmation does not match - review again"
		ui2GQLSitemapRender(w, r, m)
		return
	}
	var req graphqlSitemapReq
	_ = json.Unmarshal(rev.body, &req)
	if req.ExchangeID != nil {
		m.Exchange = *req.ExchangeID
	}
	var payload json.RawMessage = rev.body
	var res graphqlSitemapResp
	if rev.gated {
		out, e := s.ui2DispatchConfirmed(http.MethodPost, "/api/graphql/sitemap", payload, rev.token)
		if e == "" {
			b, _ := json.Marshal(out)
			_ = json.Unmarshal(b, &res)
		}
		m.Error = ui2APIErrorText(e)
	} else {
		m.Error = s.ui2RWAPI(http.MethodPost, "/api/graphql/sitemap", payload, &res)
	}
	if m.Error == "" {
		m.Done = &res
	}
	ui2GQLSitemapRender(w, r, m)
}
