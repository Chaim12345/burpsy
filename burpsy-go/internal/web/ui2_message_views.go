package web

// The ui2 message editor views: the read-only views the SPA's HttpEditor offers over one
// recorded exchange (ui/src/ui/editor.tsx), server-rendered and selected by query parameter so
// every view is bookmarkable. Raw and Pretty stay renderMessagePane's (ui2_highlight.go); this
// file adds Hex, Render, JWT, GraphQL and Protobuf, the Inspector panel and the display options
// (charset, non-printing characters, hiding uninteresting headers).
//
// Every view is a READING aid: nothing here writes the store. Every byte reaches the page through
// html/template escaping; the one exception to "rendered as text" is the Render view, which
// serves the response body from its own route under a CSP sandbox inside a sandbox="" iframe, so
// captured markup never runs in the console origin.

import (
	"bytes"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/grpcproto"
	"github.com/burpsy-go/burpsy/internal/httputil"
	"github.com/burpsy-go/burpsy/internal/tools"
	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/formatter"
	"github.com/vektah/gqlparser/v2/parser"
	"golang.org/x/text/encoding/htmlindex"
)

// ---- view state (the query string) ----------------------------------------------------------

var (
	ui2ReqViews  = []string{"pretty", "raw", "hex", "jwt", "graphql", "protobuf"}
	ui2RespViews = []string{"pretty", "raw", "hex", "render", "jwt", "protobuf"}
)

// ui2MsgViewLabels names each view's tab.
var ui2MsgViewLabels = map[string]string{
	"pretty": "Pretty", "raw": "Raw", "hex": "Hex", "render": "Render",
	"jwt": "JWT", "graphql": "GraphQL", "protobuf": "Protobuf",
}

// ui2Charsets is the charset selector's allowlist: "" is UTF-8 (the default reading) and "auto"
// takes the Content-Type charset parameter. Anything else in the query is ignored.
var ui2Charsets = []struct{ Value, Label string }{
	{"", "UTF-8"},
	{"auto", "From Content-Type"},
	{"windows-1252", "windows-1252 / Latin-1"},
	{"iso-8859-2", "ISO-8859-2"},
	{"windows-1251", "windows-1251"},
	{"koi8-r", "KOI8-R"},
	{"utf-16le", "UTF-16LE"},
	{"utf-16be", "UTF-16BE"},
	{"shift_jis", "Shift_JIS"},
	{"euc-jp", "EUC-JP"},
	{"euc-kr", "EUC-KR"},
	{"gbk", "GBK"},
	{"gb18030", "GB18030"},
	{"big5", "Big5"},
}

// ui2MsgState is the message views' URL state. Every link and form in the panes is built from
// it, so switching one view keeps every other choice.
type ui2MsgState struct {
	ID        uint64
	Base      string // the page the state belongs to, e.g. /ui2/history/5
	ViewReq   string
	ViewResp  string
	HexReq    int
	HexResp   int
	Charset   string
	NonPrint  bool
	Hide      bool
	Inspector bool
}

func ui2PickView(v string, allowed []string) string {
	for _, a := range allowed {
		if v == a {
			return v
		}
	}
	return "pretty"
}

func parseUI2MsgState(base string, id uint64, q url.Values) ui2MsgState {
	st := ui2MsgState{
		ID: id, Base: base,
		ViewReq:   ui2PickView(q.Get("view_req"), ui2ReqViews),
		ViewResp:  ui2PickView(q.Get("view_resp"), ui2RespViews),
		NonPrint:  q.Get("nonprint") == "1",
		Hide:      q.Get("hide") == "1",
		Inspector: q.Get("inspector") == "1",
	}
	if n, err := strconv.Atoi(q.Get("hex_req")); err == nil && n > 0 {
		st.HexReq = n
	}
	if n, err := strconv.Atoi(q.Get("hex_resp")); err == nil && n > 0 {
		st.HexResp = n
	}
	cs := strings.ToLower(strings.TrimSpace(q.Get("charset")))
	for _, c := range ui2Charsets {
		if c.Value == cs {
			st.Charset = cs
		}
	}
	return st
}

func (st ui2MsgState) values() url.Values {
	v := url.Values{}
	v.Set("view_req", st.ViewReq)
	v.Set("view_resp", st.ViewResp)
	if st.HexReq > 0 {
		v.Set("hex_req", strconv.Itoa(st.HexReq))
	}
	if st.HexResp > 0 {
		v.Set("hex_resp", strconv.Itoa(st.HexResp))
	}
	if st.Charset != "" {
		v.Set("charset", st.Charset)
	}
	if st.NonPrint {
		v.Set("nonprint", "1")
	}
	if st.Hide {
		v.Set("hide", "1")
	}
	if st.Inspector {
		v.Set("inspector", "1")
	}
	return v
}

// Href is this state's URL with one parameter replaced ("" removes it).
func (st ui2MsgState) Href(key, val string) string {
	v := st.values()
	if val == "" {
		v.Del(key)
	} else {
		v.Set(key, val)
	}
	return st.Base + "?" + v.Encode()
}

// Query is the full state as a query string, for POST URLs that re-render the same panes.
func (st ui2MsgState) Query() string { return st.values().Encode() }

// ---- parsed message --------------------------------------------------------------------------

// ui2KV is one name/value row (header, parameter, cookie, attribute).
type ui2KV struct {
	Name  string
	Value string
	Note  string
}

type ui2ParsedMsg struct {
	StartLine string
	Headers   []ui2KV
	Body      string
}

func ui2ParseMsg(raw string) ui2ParsedMsg {
	head, _, body := splitHTTPMessage(raw)
	lines := strings.Split(head, "\n")
	p := ui2ParsedMsg{Body: body}
	for i, line := range lines {
		line = strings.TrimSuffix(line, "\r")
		if i == 0 {
			p.StartLine = line
			continue
		}
		if j := strings.IndexByte(line, ':'); j > 0 {
			p.Headers = append(p.Headers, ui2KV{Name: strings.TrimSpace(line[:j]), Value: strings.TrimSpace(line[j+1:])})
		}
	}
	return p
}

func (p ui2ParsedMsg) header(name string) string {
	for _, h := range p.Headers {
		if strings.EqualFold(h.Name, name) {
			return h.Value
		}
	}
	return ""
}

// target is the request-target of a request line ("" for a response).
func (p ui2ParsedMsg) target() string {
	parts := strings.Fields(p.StartLine)
	if len(parts) >= 2 && !strings.HasPrefix(parts[0], "HTTP/") {
		return parts[1]
	}
	return ""
}

// ui2Pairs splits a&b=c form/query text in order, percent-decoding names and values; a value
// that does not decode is kept as written.
func ui2Pairs(s string) []ui2KV {
	var out []ui2KV
	for _, pair := range strings.Split(s, "&") {
		if pair == "" {
			continue
		}
		name, value, _ := strings.Cut(pair, "=")
		if n, err := url.QueryUnescape(name); err == nil {
			name = n
		}
		if v, err := url.QueryUnescape(value); err == nil {
			value = v
		}
		out = append(out, ui2KV{Name: name, Value: value})
	}
	return out
}

func (p ui2ParsedMsg) queryParams() []ui2KV {
	t := p.target()
	if i := strings.IndexByte(t, '?'); i >= 0 {
		return ui2Pairs(t[i+1:])
	}
	return nil
}

// cookies reads Cookie headers on a request and Set-Cookie on a response (attributes as Note).
func (p ui2ParsedMsg) cookies(isRequest bool) []ui2KV {
	var out []ui2KV
	for _, h := range p.Headers {
		switch {
		case isRequest && strings.EqualFold(h.Name, "Cookie"):
			for _, c := range strings.Split(h.Value, ";") {
				if c = strings.TrimSpace(c); c != "" {
					n, v, _ := strings.Cut(c, "=")
					out = append(out, ui2KV{Name: n, Value: v})
				}
			}
		case !isRequest && strings.EqualFold(h.Name, "Set-Cookie"):
			first, attrs, _ := strings.Cut(h.Value, ";")
			n, v, _ := strings.Cut(strings.TrimSpace(first), "=")
			out = append(out, ui2KV{Name: n, Value: v, Note: strings.TrimSpace(attrs)})
		}
	}
	return out
}

// bodyParams splits urlencoded, multipart and JSON-object bodies into top-level parameters; any
// other body is named as not split, never shown as a body without parameters.
func (p ui2ParsedMsg) bodyParams() ([]ui2KV, string) {
	if strings.TrimSpace(p.Body) == "" {
		return nil, ""
	}
	ct := p.header("Content-Type")
	mt, params, _ := mime.ParseMediaType(ct)
	trimmed := strings.TrimSpace(p.Body)
	switch {
	case mt == "application/x-www-form-urlencoded":
		return ui2Pairs(trimmed), ""
	case strings.HasPrefix(mt, "multipart/"):
		return ui2MultipartParams(p.Body, params["boundary"])
	case strings.Contains(mt, "json") || (mt == "" && strings.HasPrefix(trimmed, "{")):
		return ui2JSONTopLevel(trimmed)
	}
	if mt == "" {
		return nil, "the body carries no Content-Type, so it was not split into parameters; its bytes are on the Raw view"
	}
	return nil, "the " + mt + " body was not split into parameters (urlencoded, multipart and JSON objects are); its bytes are on the Raw view"
}

func ui2MultipartParams(body, boundary string) ([]ui2KV, string) {
	if boundary == "" {
		return nil, "multipart body without a boundary parameter; not split"
	}
	mr := multipart.NewReader(strings.NewReader(body), boundary)
	var out []ui2KV
	for i := 0; i < 200; i++ {
		part, err := mr.NextPart()
		if err == io.EOF {
			return out, ""
		}
		if err != nil {
			return out, "the multipart body stopped parsing: " + err.Error()
		}
		data, _ := io.ReadAll(io.LimitReader(part, 64<<10))
		kv := ui2KV{Name: part.FormName()}
		if fn := part.FileName(); fn != "" {
			kv.Note = fmt.Sprintf("file %q, %s", fn, part.Header.Get("Content-Type"))
			kv.Value = fmt.Sprintf("(%d bytes)", len(data))
		} else {
			kv.Value = string(data)
		}
		out = append(out, kv)
	}
	return out, "more than 200 parts; the rest are not listed"
}

// ui2JSONTopLevel lists a JSON object's top-level keys in document order; string values are
// shown unquoted, everything else as compact JSON.
func ui2JSONTopLevel(body string) ([]ui2KV, string) {
	dec := json.NewDecoder(strings.NewReader(body))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return nil, "the JSON body is not an object, so it has no top-level parameters"
	}
	var out []ui2KV
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return out, "the JSON body stopped parsing: " + err.Error()
		}
		key, _ := kt.(string)
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return out, "the JSON body stopped parsing: " + err.Error()
		}
		var s string
		if json.Unmarshal(raw, &s) == nil {
			out = append(out, ui2KV{Name: key, Value: s})
			continue
		}
		var buf bytes.Buffer
		if json.Compact(&buf, raw) == nil {
			out = append(out, ui2KV{Name: key, Value: buf.String()})
		} else {
			out = append(out, ui2KV{Name: key, Value: string(raw)})
		}
	}
	return out, ""
}

// ---- Hex -----------------------------------------------------------------------------------

const (
	ui2HexRowBytes  = 16
	ui2HexPageBytes = 4096
)

type ui2HexRow struct{ Offset, Hex, ASCII string }

type ui2HexView struct {
	Rows               []ui2HexRow
	Page, Pages, Total int
	From, To           int
	PrevHref, NextHref string
}

// ui2BuildHex renders one page of offset/hex/ASCII rows over the exact recorded bytes.
func ui2BuildHex(raw []byte, page int, href func(int) string) *ui2HexView {
	pages := (len(raw) + ui2HexPageBytes - 1) / ui2HexPageBytes
	if pages == 0 {
		pages = 1
	}
	if page >= pages {
		page = pages - 1
	}
	from := page * ui2HexPageBytes
	to := min(from+ui2HexPageBytes, len(raw))
	v := &ui2HexView{Page: page + 1, Pages: pages, Total: len(raw), From: from, To: to}
	for off := from; off < to; off += ui2HexRowBytes {
		end := min(off+ui2HexRowBytes, to)
		var hx, asc strings.Builder
		for i := off; i < off+ui2HexRowBytes; i++ {
			if i == off+8 {
				hx.WriteByte(' ')
			}
			if i < end {
				fmt.Fprintf(&hx, "%02x ", raw[i])
				if c := raw[i]; c >= 0x20 && c < 0x7f {
					asc.WriteByte(c)
				} else {
					asc.WriteByte('.')
				}
			} else {
				hx.WriteString("   ")
			}
		}
		v.Rows = append(v.Rows, ui2HexRow{Offset: fmt.Sprintf("%08x", off), Hex: strings.TrimRight(hx.String(), " "), ASCII: asc.String()})
	}
	if page > 0 {
		v.PrevHref = href(page - 1)
	}
	if page+1 < pages {
		v.NextHref = href(page + 1)
	}
	return v
}

// ---- JWT -----------------------------------------------------------------------------------

var ui2JWTCandidate = regexp.MustCompile(`[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*`)

// ui2JWTBodyScanLimit: a token lives in a header, cookie or small body; past this the view says
// the body was not scanned in full rather than reporting "no tokens".
const ui2JWTBodyScanLimit = 128 << 10

type ui2JWTTime struct{ Claim, Value, When string }

type ui2JWT struct {
	Token       string
	Alg         string
	Header      string
	Payload     string
	PayloadNote string
	Signature   string
	Locations   []string
	Times       []ui2JWTTime
}

type ui2JWTView struct {
	Tokens    []*ui2JWT
	Truncated bool
}

// ui2DecodeJWTSegment base64url-decodes one segment (tools.Base64Decode, the Decoder's own
// tolerant reading) and pretty-prints it when it is JSON.
func ui2DecodeJWTSegment(part string) (text string, obj map[string]any, isJSON bool) {
	b := tools.Base64Decode([]byte(part), true)
	var v any
	if json.Unmarshal(b, &v) == nil {
		out, _ := json.MarshalIndent(v, "", "  ")
		m, _ := v.(map[string]any)
		return string(out), m, true
	}
	return strings.ToValidUTF8(string(b), "�"), nil, false
}

// ui2FindJWTs finds every compact JWT in a message: header values, decoded query and cookie
// values, and the first ui2JWTBodyScanLimit bytes of the body. A candidate counts only when
// its header decodes to a JSON object with a string alg — three dotted words are not a token.
func ui2FindJWTs(p ui2ParsedMsg, isRequest bool) *ui2JWTView {
	view := &ui2JWTView{}
	found := map[string]*ui2JWT{}
	scan := func(text, where string) {
		if !strings.Contains(text, ".") {
			return
		}
		for _, c := range ui2JWTCandidate.FindAllString(text, 50) {
			if t, ok := found[c]; ok {
				if !containsString(t.Locations, where) {
					t.Locations = append(t.Locations, where)
				}
				continue
			}
			parts := strings.Split(c, ".")
			hdr, hm, ok := ui2DecodeJWTSegment(parts[0])
			alg, _ := hm["alg"].(string)
			if !ok || alg == "" {
				continue
			}
			payload, pm, pok := ui2DecodeJWTSegment(parts[1])
			t := &ui2JWT{Token: c, Alg: alg, Header: hdr, Payload: payload, Signature: parts[2], Locations: []string{where}}
			if !pok {
				t.PayloadNote = "the payload is not JSON; shown as decoded text"
			}
			for _, claim := range []string{"iat", "nbf", "exp"} {
				if f, ok := pm[claim].(float64); ok {
					t.Times = append(t.Times, ui2JWTTime{Claim: claim, Value: strconv.FormatFloat(f, 'f', -1, 64),
						When: time.Unix(int64(f), 0).UTC().Format(time.RFC3339)})
				}
			}
			found[c] = t
			view.Tokens = append(view.Tokens, t)
		}
	}
	for _, h := range p.Headers {
		scan(h.Value, h.Name+" header")
	}
	for _, q := range p.queryParams() {
		scan(q.Value, "query parameter "+q.Name)
	}
	for _, c := range p.cookies(isRequest) {
		if v, err := url.QueryUnescape(c.Value); err == nil {
			scan(v, "cookie "+c.Name)
		}
	}
	body := p.Body
	if len(body) > ui2JWTBodyScanLimit {
		body = body[:ui2JWTBodyScanLimit]
		view.Truncated = true
	}
	scan(body, "body")
	return view
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// ---- GraphQL -------------------------------------------------------------------------------

const ui2GraphQLBodyLimit = 512 << 10

type ui2GQLOp struct {
	OperationName string
	Query         string
	Pretty        bool
	Variables     string
	VariablesErr  string
	Extensions    string
	Valid         bool
	Errors        []string
	ValidateErr   string
}

type ui2GraphQLView struct {
	Source string
	Ops    []ui2GQLOp
}

// ui2GQLText renders variables/extensions: indented JSON, or the string as sent plus why it is
// not JSON (some clients send variables as a JSON string).
func ui2GQLText(v any) (text, errText string) {
	if v == nil {
		return "", ""
	}
	if s, ok := v.(string); ok {
		var inner any
		if err := json.Unmarshal([]byte(s), &inner); err != nil {
			return s, "a string that is not JSON: " + err.Error()
		}
		v = inner
	}
	b, _ := json.MarshalIndent(v, "", "  ")
	return string(b), ""
}

func ui2GQLOpFrom(m map[string]any) (ui2GQLOp, bool) {
	q, ok := m["query"].(string)
	if !ok || !httputil.LooksLikeGraphQLDocument(q) {
		return ui2GQLOp{}, false
	}
	op := ui2GQLOp{Query: q}
	op.OperationName, _ = m["operationName"].(string)
	op.Variables, op.VariablesErr = ui2GQLText(m["variables"])
	op.Extensions, _ = ui2GQLText(m["extensions"])
	return op, true
}

// ui2DetectGraphQL is the SPA's detectGraphQL (lib/message-views.ts) carrier order: the URL's
// query parameter, then a JSON body (one or a batch), a urlencoded body, an application/graphql
// body. The shape test (httputil.LooksLikeGraphQLDocument), not the parameter name, decides.
func ui2DetectGraphQL(p ui2ParsedMsg) *ui2GraphQLView {
	ct := strings.ToLower(p.header("Content-Type"))
	t := p.target()
	if i := strings.IndexByte(t, '?'); i >= 0 {
		for _, pair := range strings.Split(t[i+1:], "&") {
			if !strings.HasPrefix(pair, "query=") {
				continue
			}
			q := httputil.GraphQLPercentDecode(strings.TrimPrefix(pair, "query="))
			if httputil.LooksLikeGraphQLDocument(q) {
				op := ui2GQLOp{Query: q}
				for _, kv := range ui2Pairs(t[i+1:]) {
					switch kv.Name {
					case "variables":
						op.Variables, op.VariablesErr = ui2GQLText(kv.Value)
					case "operationName":
						op.OperationName = kv.Value
					}
				}
				return &ui2GraphQLView{Source: "query string", Ops: []ui2GQLOp{op}}
			}
			break
		}
	}
	body := p.Body
	if len(body) <= ui2GraphQLBodyLimit && strings.Contains(body, "query") {
		if strings.Contains(ct, "x-www-form-urlencoded") {
			m := map[string]any{}
			for _, kv := range ui2Pairs(strings.TrimSpace(body)) {
				if _, seen := m[kv.Name]; !seen {
					m[kv.Name] = kv.Value
				}
			}
			if op, ok := ui2GQLOpFrom(m); ok {
				return &ui2GraphQLView{Source: "urlencoded body", Ops: []ui2GQLOp{op}}
			}
		} else {
			var decoded any
			if json.Unmarshal([]byte(body), &decoded) == nil {
				switch d := decoded.(type) {
				case []any:
					var ops []ui2GQLOp
					for _, e := range d {
						if m, ok := e.(map[string]any); ok {
							if op, ok := ui2GQLOpFrom(m); ok {
								ops = append(ops, op)
							}
						}
					}
					if len(ops) > 0 {
						return &ui2GraphQLView{Source: fmt.Sprintf("batched JSON body (%d operations)", len(ops)), Ops: ops}
					}
				case map[string]any:
					if op, ok := ui2GQLOpFrom(d); ok {
						return &ui2GraphQLView{Source: "JSON body", Ops: []ui2GQLOp{op}}
					}
				}
			}
		}
	}
	if strings.Contains(ct, "application/graphql") && !strings.Contains(ct, "json") && httputil.LooksLikeGraphQLDocument(body) {
		return &ui2GraphQLView{Source: "application/graphql body", Ops: []ui2GQLOp{{Query: body}}}
	}
	return nil
}

// ui2GraphQLValidateCap bounds the validate calls one batched request can cause.
const ui2GraphQLValidateCap = 20

// ui2CompleteGraphQL validates each operation through POST /api/repeater/graphql-validate (a
// riskRead parse that sends nothing) and pretty-prints the ones that parse.
func (s *Server) ui2CompleteGraphQL(v *ui2GraphQLView) {
	for i := range v.Ops {
		op := &v.Ops[i]
		if i >= ui2GraphQLValidateCap {
			op.ValidateErr = fmt.Sprintf("not validated: only the first %d operations are", ui2GraphQLValidateCap)
			continue
		}
		var res struct {
			OK     bool `json:"ok"`
			Errors []struct {
				Message string `json:"message"`
				Line    int    `json:"line"`
				Column  int    `json:"column"`
			} `json:"errors"`
		}
		if errText := s.ui2MsgAPI(http.MethodPost, "/api/repeater/graphql-validate", map[string]string{"query": op.Query}, &res); errText != "" {
			op.ValidateErr = ui2APIErrorText(errText)
			continue
		}
		op.Valid = res.OK
		for _, e := range res.Errors {
			if e.Line > 0 {
				op.Errors = append(op.Errors, fmt.Sprintf("%d:%d %s", e.Line, e.Column, e.Message))
			} else {
				op.Errors = append(op.Errors, e.Message)
			}
		}
		if res.OK {
			if doc, err := parser.ParseQueryWithTokenLimit(&ast.Source{Input: op.Query}, graphQLRepeaterTokenLimit); err == nil {
				var buf bytes.Buffer
				formatter.NewFormatter(&buf, formatter.WithIndent("  ")).FormatQueryDocument(doc)
				if pretty := strings.TrimSpace(buf.String()); pretty != "" {
					op.Query, op.Pretty = pretty, true
				}
			}
		}
	}
}

// ---- Protobuf ------------------------------------------------------------------------------

var ui2ProtobufCT = regexp.MustCompile(`application/(grpc|(x-)?protobuf|vnd\.google\.protobuf)`)

type ui2PbField struct {
	Number   int
	Name     string
	Type     string
	Wire     string
	Value    string
	Children []ui2PbField
}

type ui2PbFrame struct {
	Compressed bool
	Trailer    bool
	Text       string
	Error      string
	Fields     []ui2PbField
}

type ui2ProtobufView struct {
	GRPC         bool
	Frames       []ui2PbFrame
	Error        string
	Note         string
	Message      string
	Messages     []string
	SchemaSource string
	SchemaFiles  []string
	// Reflect form defaults: the exchange's own authority.
	ReflectTarget string
	ReflectTLS    bool
	RPCPath       string
}

var ui2WireNames = map[int]string{0: "varint", 1: "i64", 2: "len", 5: "i32"}

func ui2PbFields(fs []grpcproto.Field, depth int) []ui2PbField {
	out := make([]ui2PbField, 0, len(fs))
	for _, f := range fs {
		pf := ui2PbField{Number: f.Number, Name: f.Name, Type: f.Type, Wire: ui2WireNames[f.WireType]}
		switch {
		case len(f.Packed) > 0:
			pf.Value = "[" + strings.Join(f.Packed, ", ") + "]"
		case f.EnumName != "":
			pf.Value = f.EnumName + " (" + f.Varint + ")"
		case f.WireType == 0:
			pf.Value = f.Varint
		case f.WireType == 1:
			pf.Value = f.I64
		case f.WireType == 5:
			pf.Value = strconv.FormatUint(uint64(f.I32), 10)
		case f.LenKind == grpcproto.LenString:
			pf.Value = strconv.Quote(f.String)
		case f.LenKind == grpcproto.LenBytes:
			pf.Value = "bytes " + f.BytesHex
		case f.LenKind == grpcproto.LenMessage:
			pf.Value = "message"
		}
		if len(f.Message) > 0 && depth < 64 {
			pf.Children = ui2PbFields(f.Message, depth+1)
		}
		out = append(out, pf)
	}
	return out
}

func ui2PbViewFrom(resp protoDecodeResponse) *ui2ProtobufView {
	v := &ui2ProtobufView{GRPC: resp.GRPC, Message: resp.Message, Messages: resp.Messages,
		SchemaSource: resp.SchemaSource, SchemaFiles: resp.SchemaFiles}
	for _, f := range resp.Frames {
		v.Frames = append(v.Frames, ui2PbFrame{Compressed: f.Compressed, Trailer: f.Trailer, Text: f.Text, Error: f.Error, Fields: ui2PbFields(f.Fields, 0)})
	}
	return v
}

// ui2MessageBody returns the application bytes of a message: chunk framing removed and a
// supported Content-Encoding decoded. note says what could not be unwrapped.
func ui2MessageBody(raw []byte) (body []byte, ct string, note string) {
	head, b := splitHeadBody(raw)
	ct = firstHeaderValue(head, "Content-Type")
	if strings.Contains(strings.ToLower(firstHeaderValue(head, "Transfer-Encoding")), "chunked") {
		un, ok := dechunkForView(b)
		if !ok {
			return b, ct, "the chunk framing did not parse; showing the body as recorded"
		}
		b = un
	}
	if enc := firstHeaderValue(head, "Content-Encoding"); enc != "" && !strings.EqualFold(enc, "identity") {
		if !httputil.Unpackable(enc) {
			return b, ct, "no decoder for Content-Encoding " + strconv.Quote(enc) + "; showing the encoded body"
		}
		d, err := httputil.DecodeBody(enc, b)
		if err != nil {
			return b, ct, "the " + enc + " body did not decode: " + err.Error()
		}
		b = d
	}
	return b, ct, ""
}

// ui2ProtobufDecode decodes a message body through POST /api/protobuf/decode (riskLocal, a pure
// transform). proto/message are the optional operator schema.
func (s *Server) ui2ProtobufDecode(raw string, isRequest bool, rpcPath, proto, message string) *ui2ProtobufView {
	body, ct, note := ui2MessageBody([]byte(raw))
	grpc := strings.Contains(strings.ToLower(ct), "application/grpc")
	payload := map[string]any{"body_base64": base64.StdEncoding.EncodeToString(body), "grpc": grpc}
	if strings.TrimSpace(proto) != "" {
		payload["proto"] = proto
		payload["message"] = message
		if grpc {
			payload["rpc_path"] = rpcPath
			payload["direction"] = map[bool]string{true: "request", false: "response"}[isRequest]
		}
	}
	var resp protoDecodeResponse
	if errText := s.ui2MsgAPI(http.MethodPost, "/api/protobuf/decode", payload, &resp); errText != "" {
		return &ui2ProtobufView{GRPC: grpc, Error: ui2APIErrorText(errText), Note: note}
	}
	v := ui2PbViewFrom(resp)
	v.Note = note
	return v
}

// ---- display options -----------------------------------------------------------------------

// ui2DecodeCharset reinterprets a body under the chosen charset. ok=false leaves the body as is
// and note says why.
func ui2DecodeCharset(label, contentType string, body string) (string, string, bool) {
	if label == "auto" {
		_, params, _ := mime.ParseMediaType(contentType)
		label = strings.ToLower(params["charset"])
		if label == "" {
			return body, "no charset parameter in Content-Type; the body is read as UTF-8", false
		}
	}
	enc, err := htmlindex.Get(label)
	if err != nil {
		return body, fmt.Sprintf("%q is not a charset this build decodes; the body is read as UTF-8", label), false
	}
	out, err := enc.NewDecoder().String(body)
	if err != nil {
		return body, "the body did not decode as " + label + ": " + err.Error(), false
	}
	name, _ := htmlindex.Name(enc)
	return out, "body decoded as " + name + " (display only; Hex shows the recorded bytes)", true
}

// ui2HideHeaders drops the named header lines from a message's head, keeping every other byte.
func ui2HideHeaders(raw string, names map[string]bool) (string, int) {
	head, sep, body := splitHTTPMessage(raw)
	lines := strings.Split(head, "\n")
	kept := lines[:1]
	hidden := 0
	for _, line := range lines[1:] {
		if j := strings.IndexByte(line, ':'); j > 0 && names[strings.ToLower(strings.TrimSpace(line[:j]))] {
			hidden++
			continue
		}
		kept = append(kept, line)
	}
	return strings.Join(kept, "\n") + sep + body, hidden
}

// ui2ShowNonPrinting makes control characters visible as Unicode control pictures. It runs on
// already-escaped pane HTML: control bytes only ever occur in text content there (the markup the
// highlighter writes is printable ASCII), and the glyphs it inserts are not markup.
func ui2ShowNonPrinting(h template.HTML) template.HTML {
	s := string(h)
	var b strings.Builder
	b.Grow(len(s) + len(s)/8)
	for len(s) > 0 {
		r, size := utf8.DecodeRuneInString(s)
		switch {
		case r == utf8.RuneError && size == 1:
			b.WriteString("�")
		case r == '\n':
			b.WriteString("␊\n")
		case r < 0x20:
			b.WriteRune(0x2400 + r)
		case r == 0x7f:
			b.WriteRune('␡')
		default:
			b.WriteString(s[:size])
		}
		s = s[size:]
	}
	return template.HTML(b.String()) //nolint:gosec // input is escaped pane HTML; only printable glyphs are added
}

// ---- panes ---------------------------------------------------------------------------------

type ui2MsgTab struct {
	View, Label, Href string
	Active            bool
}

type ui2MsgPane struct {
	Side     string // "req" | "resp"
	Label    string
	View     string
	Empty    bool
	Tabs     []ui2MsgTab
	Notes    []string
	Text     *ui2PaneView
	Hex      *ui2HexView
	Render   string // the sandboxed render route, when View is render
	JWT      *ui2JWTView
	GraphQL  *ui2GraphQLView
	Protobuf *ui2ProtobufView
	// SchemaPost and ReflectPost are the Protobuf view's form actions, state query included.
	SchemaPost  string
	ReflectPost string
}

type ui2InspectorSection struct {
	Title string
	Rows  []ui2KV
	Note  string
}

type ui2MsgViews struct {
	State     ui2MsgState
	Target    string
	Req       ui2MsgPane
	Resp      ui2MsgPane
	Charsets  []struct{ Value, Label string }
	Inspector []ui2InspectorSection
}

// ui2PbOverlay is a protobuf decode computed by a POST (schema or reflection) for one side.
type ui2PbOverlay struct {
	Side string
	View *ui2ProtobufView
}

func ui2RenderableResponse(p ui2ParsedMsg) bool {
	mt, _, _ := mime.ParseMediaType(p.header("Content-Type"))
	switch {
	case mt == "text/html", mt == "application/xhtml+xml", ui2RenderImageTypes[mt]:
		return true
	case mt == "":
		return strings.HasPrefix(strings.TrimSpace(p.Body), "<")
	}
	return false
}

// ui2RenderImageTypes are the image types the Render route serves as images. SVG is not among
// them: it is markup, and the route serves it as text.
var ui2RenderImageTypes = map[string]bool{
	"image/png": true, "image/jpeg": true, "image/gif": true, "image/webp": true,
	"image/bmp": true, "image/x-icon": true, "image/vnd.microsoft.icon": true, "image/avif": true,
}

// ui2BuildMessageViews computes both panes and the Inspector for one exchange.
func (s *Server) ui2BuildMessageViews(d ui2Detail, st ui2MsgState, exTLS bool, overlay *ui2PbOverlay) ui2MsgViews {
	mv := ui2MsgViews{State: st, Target: "#detail", Charsets: ui2Charsets}
	var hidden map[string]map[string]bool
	if st.Hide {
		var lists uninterestingHeadersResponse
		hidden = map[string]map[string]bool{"req": {}, "resp": {}}
		if errText := s.ui2MsgAPI(http.MethodGet, "/api/headers/uninteresting", nil, &lists); errText == "" {
			for _, n := range lists.Request {
				hidden["req"][strings.ToLower(n)] = true
			}
			for _, n := range lists.Response {
				hidden["resp"][strings.ToLower(n)] = true
			}
		}
	}
	reqParsed := ui2ParseMsg(d.Request)
	rpcPath := reqParsed.target()
	if i := strings.IndexByte(rpcPath, '?'); i >= 0 {
		rpcPath = rpcPath[:i]
	}
	build := func(side, label, raw, view string, page int, allowed []string) ui2MsgPane {
		isReq := side == "req"
		pane := ui2MsgPane{Side: side, Label: label, Empty: raw == "",
			SchemaPost:  fmt.Sprintf("/ui2/message/protobuf/%d/schema?%s", st.ID, st.Query()),
			ReflectPost: fmt.Sprintf("/ui2/message/protobuf/%d/reflect-review?%s", st.ID, st.Query())}
		if pane.Empty {
			return pane
		}
		p := ui2ParsedMsg{}
		if isReq {
			p = reqParsed
		} else {
			p = ui2ParseMsg(raw)
		}
		jwts := ui2FindJWTs(p, isReq)
		var gql *ui2GraphQLView
		if isReq {
			gql = ui2DetectGraphQL(p)
		}
		avail := map[string]bool{"pretty": true, "raw": true, "hex": true,
			"render":   !isReq && ui2RenderableResponse(p),
			"jwt":      len(jwts.Tokens) > 0,
			"graphql":  gql != nil,
			"protobuf": ui2ProtobufCT.MatchString(strings.ToLower(p.header("Content-Type"))),
		}
		if overlay != nil && overlay.Side == side {
			view = "protobuf"
		}
		if !avail[view] {
			pane.Notes = append(pane.Notes, "the "+ui2MsgViewLabels[view]+" view does not apply to this message; showing Pretty")
			view = "pretty"
		}
		pane.View = view
		key := "view_" + side
		for _, v := range allowed {
			if avail[v] {
				pane.Tabs = append(pane.Tabs, ui2MsgTab{View: v, Label: ui2MsgViewLabels[v], Href: st.Href(key, v), Active: v == view})
			}
		}
		switch view {
		case "pretty", "raw":
			text := raw
			if st.Hide {
				var n int
				text, n = ui2HideHeaders(text, hidden[side])
				if n > 0 {
					pane.Notes = append(pane.Notes, fmt.Sprintf("%d uninteresting header(s) hidden", n))
				}
			}
			if st.Charset != "" {
				head, sep, body := splitHTTPMessage(text)
				if body != "" {
					decoded, note, _ := ui2DecodeCharset(st.Charset, p.header("Content-Type"), body)
					text = head + sep + decoded
					pane.Notes = append(pane.Notes, note)
				}
			}
			tv := renderMessagePane(text, isReq, view == "pretty")
			if st.NonPrint {
				tv.Highlighted = ui2ShowNonPrinting(tv.Highlighted)
			}
			pane.Text = &tv
		case "hex":
			pane.Hex = ui2BuildHex([]byte(raw), page, func(n int) string {
				return st.Href("hex_"+side, strconv.Itoa(n))
			})
		case "render":
			pane.Render = fmt.Sprintf("/ui2/message/render/%d", st.ID)
		case "jwt":
			pane.JWT = jwts
		case "graphql":
			s.ui2CompleteGraphQL(gql)
			pane.GraphQL = gql
		case "protobuf":
			if overlay != nil && overlay.Side == side {
				pane.Protobuf = overlay.View
			} else {
				pane.Protobuf = s.ui2ProtobufDecode(raw, isReq, rpcPath, "", "")
			}
			pane.Protobuf.ReflectTarget = net.JoinHostPort(d.Host, strconv.Itoa(int(d.Port)))
			pane.Protobuf.ReflectTLS = exTLS
			pane.Protobuf.RPCPath = rpcPath
		}
		return pane
	}
	mv.Req = build("req", "Request", d.Request, st.ViewReq, st.HexReq, ui2ReqViews)
	mv.Resp = build("resp", "Response", d.Response, st.ViewResp, st.HexResp, ui2RespViews)
	if st.Inspector {
		mv.Inspector = ui2Inspect(d.Request, d.Response)
	}
	return mv
}

// ui2Inspect builds the Inspector sections: attributes, query/body params, cookies, headers.
func ui2Inspect(reqRaw, respRaw string) []ui2InspectorSection {
	var out []ui2InspectorSection
	if reqRaw != "" {
		p := ui2ParseMsg(reqRaw)
		parts := strings.Fields(p.StartLine)
		attrs := []ui2KV{}
		if len(parts) >= 2 {
			path, query, _ := strings.Cut(parts[1], "?")
			attrs = append(attrs, ui2KV{Name: "Method", Value: parts[0]}, ui2KV{Name: "Path", Value: path})
			if query != "" {
				attrs = append(attrs, ui2KV{Name: "Query string", Value: query})
			}
		}
		if len(parts) >= 3 {
			attrs = append(attrs, ui2KV{Name: "Protocol", Value: parts[2]})
		}
		attrs = append(attrs, ui2KV{Name: "Request length", Value: strconv.Itoa(len(reqRaw))},
			ui2KV{Name: "Request body length", Value: strconv.Itoa(len(p.Body))})
		out = append(out, ui2InspectorSection{Title: "Request attributes", Rows: attrs})
		out = append(out, ui2InspectorSection{Title: "Request query parameters", Rows: p.queryParams()})
		bp, note := p.bodyParams()
		out = append(out, ui2InspectorSection{Title: "Request body parameters", Rows: bp, Note: note})
		out = append(out, ui2InspectorSection{Title: "Request cookies", Rows: p.cookies(true)})
		out = append(out, ui2InspectorSection{Title: "Request headers", Rows: p.Headers})
	}
	if respRaw != "" {
		p := ui2ParseMsg(respRaw)
		parts := strings.SplitN(p.StartLine, " ", 3)
		attrs := []ui2KV{}
		if len(parts) >= 1 {
			attrs = append(attrs, ui2KV{Name: "Protocol", Value: parts[0]})
		}
		if len(parts) >= 2 {
			attrs = append(attrs, ui2KV{Name: "Status code", Value: parts[1]})
		}
		if len(parts) >= 3 {
			attrs = append(attrs, ui2KV{Name: "Reason", Value: parts[2]})
		}
		attrs = append(attrs, ui2KV{Name: "Response length", Value: strconv.Itoa(len(respRaw))},
			ui2KV{Name: "Response body length", Value: strconv.Itoa(len(p.Body))})
		out = append(out, ui2InspectorSection{Title: "Response attributes", Rows: attrs})
		out = append(out, ui2InspectorSection{Title: "Response cookies", Rows: p.cookies(false)})
		out = append(out, ui2InspectorSection{Title: "Response headers", Rows: p.Headers})
	}
	return out
}

// ---- routes --------------------------------------------------------------------------------

// ui2LoadDetail reads one exchange's header facts and message bytes.
func (s *Server) ui2LoadDetail(id uint64) (ui2Detail, bool, int, string) {
	ex, err := s.store.GetExchange(core.ExchangeID(id))
	if err != nil {
		return ui2Detail{}, false, http.StatusNotFound, "Exchange not found"
	}
	v := exchangeView(ex)
	d := ui2Detail{
		ID: uint64(v.ID), Method: v.Method, Host: v.Host, Port: v.Port, Path: v.Path,
		Status: ui2StatusString(v.Status), Mime: v.Mime, ResponseLen: v.ResponseLen,
		DurationMs: v.DurationMs,
	}
	if v.Request != nil {
		if msg, err := s.store.Get(core.MsgId(*v.Request)); err == nil {
			d.Request = string(msg.Raw())
		}
	}
	if d.Request == "" {
		// Restored-project case: resolve through the store's request index, never a guessed id.
		if raw := requestMessageForExchange(s.store, ex); raw != nil {
			d.Request = string(raw)
		}
	}
	if v.Response != nil {
		if msg, err := s.store.Get(core.MsgId(*v.Response)); err == nil {
			d.Response = string(msg.Raw())
		}
	}
	return d, ex.TLS, 0, ""
}

// ui2RenderDetail renders history_detail.html for one exchange with the given view state.
func (s *Server) ui2RenderDetail(w http.ResponseWriter, r *http.Request, id uint64, overlay *ui2PbOverlay) {
	d, tls, code, msg := s.ui2LoadDetail(id)
	if code != 0 {
		http.Error(w, msg, code)
		return
	}
	st := parseUI2MsgState(fmt.Sprintf("/ui2/history/%d", id), id, r.URL.Query())
	d.Views = s.ui2BuildMessageViews(d, st, tls, overlay)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := ui2Templates.ExecuteTemplate(w, "history_detail.html", d); err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}

// ui2RenderCSP is the Render route's policy: a CSP sandbox without allow-scripts (no script, no
// same-origin, no forms, no top navigation) and no fetches beyond inline style and data: images,
// so a rendered page can neither run nor phone home. frame-ancestors keeps it to the console.
const ui2RenderCSP = "sandbox; default-src 'none'; img-src data:; style-src 'unsafe-inline'; font-src data:; frame-ancestors 'self'"

// handleUI2MessageRender serves GET /ui2/message/render/{id}: the response body for the Render
// view's sandbox="" iframe. HTML is served as HTML and listed image types as themselves; anything
// else as text/plain. The CSP sandbox holds even when the URL is opened directly.
func (s *Server) handleUI2MessageRender(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "Invalid exchange ID", http.StatusBadRequest)
		return
	}
	d, _, code, msg := s.ui2LoadDetail(id)
	if code != 0 {
		http.Error(w, msg, code)
		return
	}
	if d.Response == "" {
		http.Error(w, "No response recorded for this exchange", http.StatusNotFound)
		return
	}
	body, ct, _ := ui2MessageBody([]byte(d.Response))
	mt, params, _ := mime.ParseMediaType(ct)
	serveType := "text/plain; charset=utf-8"
	switch {
	case mt == "text/html" || mt == "application/xhtml+xml" || (mt == "" && bytes.HasPrefix(bytes.TrimSpace(body), []byte("<"))):
		charset := "utf-8"
		if enc, err := htmlindex.Get(params["charset"]); err == nil {
			if name, err := htmlindex.Name(enc); err == nil {
				charset = name
			}
		}
		serveType = "text/html; charset=" + charset
	case ui2RenderImageTypes[mt]:
		serveType = mt
	}
	h := w.Header()
	h.Set("Content-Type", serveType)
	h.Set("Content-Security-Policy", ui2RenderCSP)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cache-Control", "no-store")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	// #nosec G705 -- captured bytes served under a CSP sandbox with no script source, nosniff,
	// and framed only by a sandbox="" iframe: they cannot execute in the console origin.
	_, _ = w.Write(body)
}

// ui2ReflectReviewCap bounds the held reflection reviews (same cap as the other review maps).
const ui2ReflectReviewCap = 8

type ui2ReflectReview struct {
	token   string
	id      uint64
	side    string
	payload map[string]any
	expires time.Time
}

// handleUI2MessageProtobuf serves POST /ui2/message/protobuf/{id}/{action}:
//   - schema: decode one side with an operator .proto (pasted or uploaded) — a local transform;
//   - reflect-review: hold the gRPC reflection call (riskEgress: one request to the target) and
//     render it for review;
//   - reflect-run: spend the held call (single use, token compared in constant time) and render
//     the decode it returns.
//
// Each re-renders the history detail with the state carried in the post URL's query.
func (s *Server) handleUI2MessageProtobuf(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "Invalid exchange ID", http.StatusBadRequest)
		return
	}
	if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/") {
		_ = r.ParseMultipartForm(8 << 20)
	} else {
		_ = r.ParseForm()
	}
	side := r.PostFormValue("side")
	if side != "req" && side != "resp" && r.PathValue("action") != "reflect-run" {
		http.Error(w, "side must be req or resp", http.StatusBadRequest)
		return
	}
	d, tls, code, msg := s.ui2LoadDetail(id)
	if code != 0 {
		http.Error(w, msg, code)
		return
	}
	raw := d.Request
	if side == "resp" {
		raw = d.Response
	}
	rpcPath := ui2ParseMsg(d.Request).target()
	if i := strings.IndexByte(rpcPath, '?'); i >= 0 {
		rpcPath = rpcPath[:i]
	}
	switch r.PathValue("action") {
	case "schema":
		proto := r.PostFormValue("proto")
		if f, _, err := r.FormFile("proto_file"); err == nil {
			b, _ := io.ReadAll(io.LimitReader(f, 4<<20))
			_ = f.Close()
			if len(b) > 0 {
				proto = string(b)
			}
		}
		if strings.TrimSpace(proto) == "" {
			s.ui2RenderDetail(w, r, id, &ui2PbOverlay{Side: side, View: &ui2ProtobufView{Error: "no .proto was given; paste one or choose a file"}})
			return
		}
		v := s.ui2ProtobufDecode(raw, side == "req", rpcPath, proto, strings.TrimSpace(r.PostFormValue("message")))
		s.ui2RenderDetail(w, r, id, &ui2PbOverlay{Side: side, View: v})
	case "reflect-review":
		s.ui2ReflectReview(w, r, id, side, raw, tls)
	case "reflect-run":
		s.ui2ReflectRun(w, r, id)
	default:
		http.Error(w, "unknown protobuf action", http.StatusBadRequest)
	}
}

func (s *Server) ui2ReflectReview(w http.ResponseWriter, r *http.Request, id uint64, side, raw string, exTLS bool) {
	st := parseUI2MsgState(fmt.Sprintf("/ui2/history/%d", id), id, r.URL.Query())
	model := map[string]any{"ID": id, "Side": side, "BackHref": st.Base + "?" + st.Query(),
		"RunHref": fmt.Sprintf("/ui2/message/protobuf/%d/reflect-run?%s", id, st.Query())}
	fail := func(m string) {
		model["Error"] = m
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = ui2Templates.ExecuteTemplate(w, "message_reflect_review.html", model)
	}
	target := strings.TrimSpace(r.PostFormValue("target"))
	service := strings.TrimSpace(r.PostFormValue("service"))
	useTLS := r.PostFormValue("tls") == "1"
	if target == "" || service == "" {
		fail("a target (host:port) and a fully-qualified service name are both required")
		return
	}
	body, ct, _ := ui2MessageBody([]byte(raw))
	payload := map[string]any{
		"body_base64": base64.StdEncoding.EncodeToString(body),
		"grpc":        strings.Contains(strings.ToLower(ct), "application/grpc"),
		"reflect":     map[string]any{"target": target, "service": service, "tls": useTLS},
		"message":     strings.TrimSpace(r.PostFormValue("message")),
	}
	reviewID, err1 := randomHex(16)
	token, err2 := randomHex(16)
	if err1 != nil || err2 != nil {
		fail("could not create a review id")
		return
	}
	now := time.Now()
	count := 0
	s.ui2ReflectReviews.Range(func(k, v any) bool {
		if e, ok := v.(ui2ReflectReview); ok && now.After(e.expires) {
			s.ui2ReflectReviews.Delete(k)
		} else {
			count++
		}
		return true
	})
	if count >= ui2ReflectReviewCap {
		fail("too many reflection reviews are open at once - confirm or let some expire, then try again")
		return
	}
	s.ui2ReflectReviews.Store(reviewID, ui2ReflectReview{token: token, id: id, side: side, payload: payload, expires: now.Add(ConfirmTTL)})
	model["ReviewID"] = reviewID
	model["Token"] = token
	model["Target"] = target
	model["Service"] = service
	model["TLS"] = useTLS
	model["Message"] = payload["message"]
	model["BodyLen"] = len(body)
	model["ExchangeTLS"] = exTLS
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = ui2Templates.ExecuteTemplate(w, "message_reflect_review.html", model)
}

func (s *Server) ui2ReflectRun(w http.ResponseWriter, r *http.Request, id uint64) {
	v, ok := s.ui2ReflectReviews.LoadAndDelete(r.PostFormValue("review_id"))
	rev, isRev := v.(ui2ReflectReview)
	if !ok || !isRev || time.Now().After(rev.expires) || rev.id != id ||
		subtle.ConstantTimeCompare([]byte(rev.token), []byte(r.PostFormValue("token"))) != 1 {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		st := parseUI2MsgState(fmt.Sprintf("/ui2/history/%d", id), id, r.URL.Query())
		_ = ui2Templates.ExecuteTemplate(w, "message_reflect_review.html", map[string]any{"ID": id, "BackHref": st.Base + "?" + st.Query(),
			"Error": "that review is unknown, already used or expired - review the reflection call again"})
		return
	}
	var resp protoDecodeResponse
	view := &ui2ProtobufView{}
	if errText := s.ui2MsgAPI(http.MethodPost, "/api/protobuf/reflect-decode", rev.payload, &resp); errText != "" {
		view.Error = ui2APIErrorText(errText)
	} else {
		view = ui2PbViewFrom(resp)
	}
	s.ui2RenderDetail(w, r, id, &ui2PbOverlay{Side: rev.side, View: view})
}

// ui2MsgAPI calls one internal JSON route in process and decodes a 200 answer into out; any
// other answer comes back as its error text.
func (s *Server) ui2MsgAPI(method, path string, payload any, out any) string {
	req := newReq(method, path)
	if payload != nil {
		b, _ := json.Marshal(payload)
		req.Header.Set("Content-Type", "application/json")
		req.Body = ioNopCloser(strings.NewReader(string(b)))
	}
	rec := newRecorder()
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		return strings.TrimSpace(rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), out); err != nil {
		return "unreadable response: " + err.Error()
	}
	return ""
}
