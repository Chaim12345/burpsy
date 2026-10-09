package web

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/httputil"
	"github.com/burpsy-go/burpsy/internal/mcpscan"
	"github.com/burpsy-go/burpsy/internal/sender"
	"github.com/burpsy-go/burpsy/internal/toollog"
)

// ---- MCP-target scanning (burpsy-react-ui-wflj) --------------------------------------------------
//
// burpsy as the client testing a Model Context Protocol server — the inverse of exposing burpsy over
// MCP. POST /api/mcpscan names a Streamable-HTTP MCP endpoint; the handler performs the handshake,
// enumerates tools, resources and prompts, calls only the tools the operator named, and runs the
// MCP-specific checks, filing findings in the existing store. The protocol and checks live in
// internal/mcpscan; this file binds that package's Transport to sender.AuthorisedSender, so every
// JSON-RPC message is authorised against the scope on the exact bytes written, and every message is
// recorded as an exchange and a tool-log row — "what did you send to my server" has an answer.
//
// riskAttack in the manifest: it connects to the target and, when asked, invokes its tools, so the
// confirmation gate stands in front of it. The traffic is nonetheless bounded and stated in the
// response: initialize and its notification, at most mcpscan's page bound per list, at most
// mcpscan.MaxProbes tool calls, the three-message unauthenticated repeat when a credential was given,
// and the session DELETE — under one overall deadline.

// mcpScanDeadline bounds one scan end to end.
const mcpScanDeadline = 2 * time.Minute

// maxMCPProbeNames bounds the probe_tools list a caller may send. Names past mcpscan.MaxProbes are
// reported as skipped; this only stops a request body from being an unbounded list.
const maxMCPProbeNames = 200

type mcpScanReq struct {
	Endpoint string `json:"endpoint" desc:"the MCP server's Streamable-HTTP endpoint, an absolute http(s) URL such as https://host/mcp; must be in scope"`
	// AuthHeader is one header line sent on every message, e.g. "Authorization: Bearer …". Kept out of
	// the response and the stored findings; it is in the stored exchanges, as any request header is.
	AuthHeader string `json:"auth_header,omitempty" desc:"optional single header line carrying the credential, e.g. 'Authorization: Bearer <token>'; when set, the handshake is also repeated without it to test enforcement"`
	// ProbeTools are tools to call with empty arguments. Empty means none: a tool's effect is
	// whatever its author made it, so no tool is invoked unless the operator names it.
	ProbeTools []string `json:"probe_tools,omitempty" desc:"tool names to call once each with empty arguments, at most 20 are called; omitted means no tool is invoked"`
}

type mcpScanResponse struct {
	Endpoint        string                `json:"endpoint"`
	Server          mcpscan.ServerInfo    `json:"server"`
	ProtocolVersion string                `json:"protocol_version"`
	Tools           []mcpToolView         `json:"tools"`
	Resources       []mcpscan.Resource    `json:"resources"`
	Prompts         []mcpscan.Prompt      `json:"prompts"`
	Lists           []mcpscan.ListOutcome `json:"lists"`
	// Complete is false when any list failed, failed part-way or stopped at a bound — the case where
	// an empty or short inventory must not be read as the server's whole surface.
	Complete      bool                `json:"complete"`
	Probes        []mcpscan.Probe     `json:"probes"`
	ProbeSkipped  []mcpscan.ProbeSkip `json:"probe_skipped"`
	Authenticated bool                `json:"authenticated"`
	// AuthCheck is omitted when no credential was given: the scan itself was the unauthenticated view.
	AuthCheck *mcpscan.AuthCheck `json:"auth_check,omitempty"`
	// Sent and Refused count JSON-RPC messages that went out and that the scope gate stopped.
	Sent        int64             `json:"requests_sent"`
	Refused     int64             `json:"requests_refused"`
	ExchangeIDs []core.ExchangeID `json:"exchange_ids"`
	Findings    []mcpFindingView  `json:"findings"`
	// NotCovered says what this scan does not test, so an empty findings list is not read as "safe".
	NotCovered []string `json:"not_covered"`
}

type mcpToolView struct {
	Name        string                   `json:"name"`
	Description string                   `json:"description"`
	Annotations *mcpscan.ToolAnnotations `json:"annotations,omitempty"`
}

type mcpFindingView struct {
	ID          uint64 `json:"id"`
	Name        string `json:"name"`
	Severity    string `json:"severity"`
	Confidence  string `json:"confidence"`
	Subject     string `json:"subject,omitempty"`
	Description string `json:"description"`
	Evidence    string `json:"evidence,omitempty"`
}

var mcpNotCovered = []string{
	"stdio MCP servers and the deprecated HTTP+SSE transport (2024-11-05) are not spoken",
	"OAuth authorization flows are not performed; a credential is a single header the operator supplies",
	"tools are not driven with crafted arguments: a named tool is called once with empty arguments",
	"resources are listed but not read, and prompts are listed but not fetched",
	"server-initiated requests (sampling, elicitation, roots) arriving on a response stream are ignored",
}

// handleMCPScan serves POST /api/mcpscan.
func (s *Server) handleMCPScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req mcpScanReq
	if err := requestJSON(w, r, http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		http.Error(w, `the body must be {"endpoint":"https://host/mcp","auth_header"?:"Authorization: Bearer ...","probe_tools"?:["name"]}`, http.StatusBadRequest)
		return
	}
	endpoint, err := url.Parse(strings.TrimSpace(req.Endpoint))
	if err != nil || (endpoint.Scheme != "http" && endpoint.Scheme != "https") || endpoint.Hostname() == "" || endpoint.User != nil {
		http.Error(w, "endpoint must be an absolute http(s) URL with a host and no userinfo", http.StatusBadRequest)
		return
	}
	if p := endpoint.Port(); p != "" {
		if n, perr := strconv.ParseUint(p, 10, 16); perr != nil || n == 0 {
			http.Error(w, "endpoint port must be 1-65535", http.StatusBadRequest)
			return
		}
	}
	authLine, err := validateMCPAuthHeader(req.AuthHeader)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if len(req.ProbeTools) > maxMCPProbeNames {
		http.Error(w, fmt.Sprintf("probe_tools may name at most %d tools (at most %d are called)", maxMCPProbeNames, mcpscan.MaxProbes), http.StatusBadRequest)
		return
	}
	for _, name := range req.ProbeTools {
		if name == "" || len(name) > 256 {
			http.Error(w, "every probe_tools entry must be a non-empty tool name of at most 256 bytes", http.StatusBadRequest)
			return
		}
	}
	if s.sender == nil {
		http.Error(w, "no sender is configured, so no MCP server can be reached", http.StatusServiceUnavailable)
		return
	}
	if s.scope == nil {
		// Fail closed: with no scope there is nothing to authorise a message against.
		http.Error(w, "no engagement scope is configured, so nothing may be sent", http.StatusServiceUnavailable)
		return
	}
	host, port, tls := endpointParts(endpoint)
	// An early, explained refusal. The authoritative gate is the AuthorisedSender each message goes
	// through, which re-reads the bytes actually written.
	if !s.scope.MayContainHost(host, port, tls) {
		http.Error(w, "the MCP endpoint is not in the engagement scope, so nothing was sent: "+s.scope.Explain(host, port, endpoint.RequestURI(), tls), http.StatusForbidden)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), mcpScanDeadline)
	defer cancel()

	auth := sender.NewAuthorisedSender(s.scope, s.sender, host, port, tls)
	primary := s.newMCPTransport(auth, endpoint, authLine)
	en, err := mcpscan.NewClient(primary, authLine != "").Enumerate(ctx)
	if err != nil {
		primary.close(ctx)
		status := http.StatusBadGateway
		if auth.Refused() > 0 {
			status = http.StatusForbidden
		}
		http.Error(w, "could not enumerate the MCP server, so nothing was scanned: "+err.Error()+mcpInitHint(err), status)
		return
	}
	mcpscan.NewClient(primary, authLine != "").Probe(ctx, en, req.ProbeTools)
	primary.close(ctx)

	exchanges := append([]core.ExchangeID{}, primary.exchanges...)
	if authLine != "" {
		bare := s.newMCPTransport(auth, endpoint, "")
		check := mcpscan.CheckAuthEnforced(ctx, bare)
		bare.close(ctx)
		en.AuthCheck = &check
		exchanges = append(exchanges, bare.exchanges...)
	}

	resp := mcpScanResponse{
		Endpoint:        endpoint.String(),
		Server:          en.Server,
		ProtocolVersion: en.ProtocolVersion,
		Tools:           []mcpToolView{},
		Resources:       nonNil(en.Resources),
		Prompts:         nonNil(en.Prompts),
		Lists:           en.Lists,
		Probes:          nonNil(en.Probes),
		ProbeSkipped:    nonNil(en.ProbeSkipped),
		Authenticated:   en.Authenticated,
		AuthCheck:       en.AuthCheck,
		Sent:            auth.Sent(),
		Refused:         auth.Refused(),
		ExchangeIDs:     exchanges,
		Findings:        []mcpFindingView{},
		NotCovered:      mcpNotCovered,
	}
	resp.Complete = true
	for _, lo := range en.Lists {
		if (lo.State != mcpscan.ListOK && lo.State != mcpscan.ListNotAdvertised) || lo.Truncated {
			resp.Complete = false
		}
	}
	for _, t := range en.Tools {
		resp.Tools = append(resp.Tools, mcpToolView{Name: t.Name, Description: t.Description, Annotations: t.Annotations})
	}

	target := core.FindingTarget{Host: host, Port: port, TLS: tls, Path: endpoint.RequestURI()}
	var occurrences []core.Occurrence
	if len(exchanges) > 0 {
		// The initialize exchange: the one every finding about this server rests on.
		if ex, gerr := s.store.GetExchange(exchanges[0]); gerr == nil {
			occurrences = []core.Occurrence{{ExchangeID: ex.ID, Request: ex.Request, Response: ex.Response}}
		}
	}
	for _, f := range mcpscan.Checks(en) {
		id := s.findings.Add(core.NewFinding{
			Name:        f.Name,
			Severity:    core.ParseSeverity(f.Severity),
			Confidence:  core.ParseConfidence(f.Confidence),
			Description: f.Description,
			Evidence:    f.Evidence,
			Occurrences: occurrences,
			Target:      target,
			// Keyed on the endpoint and the subject, so a re-scan updates a row rather than filing a
			// second copy, and two tools with the same finding stay two rows.
			MergeKey: "mcp\x00" + endpoint.String() + "\x00" + f.Subject,
		})
		resp.Findings = append(resp.Findings, mcpFindingView{
			ID: id, Name: f.Name, Severity: f.Severity, Confidence: f.Confidence,
			Subject: f.Subject, Description: f.Description, Evidence: f.Evidence,
		})
	}
	if len(resp.Findings) > 0 {
		s.live.notify(changeIssues)
	}
	writeJSON(w, http.StatusOK, resp)
}

func nonNil[T any](xs []T) []T {
	if xs == nil {
		return []T{}
	}
	return xs
}

// mcpInitHint adds what an initialize failure most likely means.
func mcpInitHint(err error) string {
	switch mcpscan.StatusOf(err) {
	case 401, 403:
		return " — the server requires authentication; supply auth_header"
	case 404, 405:
		return " — the endpoint does not accept MCP over POST; it may be the wrong path, or a server speaking the deprecated HTTP+SSE transport, which this scanner does not support"
	}
	return ""
}

// validateMCPAuthHeader accepts one "Name: value" header line and returns it trimmed. A line break, a
// framing header or a Host header would let the credential field rewrite the request around it, so
// those are refused rather than sanitised.
func validateMCPAuthHeader(line string) (string, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return "", nil
	}
	if strings.ContainsAny(line, "\r\n\x00") {
		return "", errors.New("auth_header must be a single header line")
	}
	name, value, ok := strings.Cut(line, ":")
	name = strings.TrimSpace(name)
	if !ok || name == "" || strings.TrimSpace(value) == "" {
		return "", errors.New(`auth_header must be "Name: value", e.g. "Authorization: Bearer <token>"`)
	}
	for _, c := range name {
		if c <= ' ' || c >= 0x7f || strings.ContainsRune(`"(),/:;<=>?@[\]{}`, c) {
			return "", errors.New("auth_header's name is not a valid header name")
		}
	}
	switch strings.ToLower(name) {
	case "host", "content-length", "transfer-encoding", "connection", "content-type", "accept", "mcp-session-id", "mcp-protocol-version":
		return "", fmt.Errorf("auth_header may not set %s; the scanner owns that header", name)
	}
	return name + ": " + strings.TrimSpace(value), nil
}

// mcpHTTPTransport is mcpscan.Transport over the Streamable-HTTP transport, through one
// AuthorisedSender. It is used from one goroutine at a time, so it holds its session state unlocked.
type mcpHTTPTransport struct {
	s          *Server
	auth       *sender.AuthorisedSender
	host       string
	port       uint16
	tls        bool
	path       string
	hostHeader string
	authLine   string

	nextID          int
	sessionID       string
	protocolVersion string
	exchanges       []core.ExchangeID
}

func (s *Server) newMCPTransport(auth *sender.AuthorisedSender, endpoint *url.URL, authLine string) *mcpHTTPTransport {
	host, port, tls := endpointParts(endpoint)
	hostHeader := endpoint.Host
	if endpoint.Port() == "" {
		hostHeader = endpoint.Hostname()
		if strings.Contains(hostHeader, ":") {
			hostHeader = "[" + hostHeader + "]"
		}
	}
	return &mcpHTTPTransport{s: s, auth: auth, host: host, port: port, tls: tls,
		path: endpoint.RequestURI(), hostHeader: hostHeader, authLine: authLine}
}

func (t *mcpHTTPTransport) Call(ctx context.Context, method string, params any) (json.RawMessage, error) {
	t.nextID++
	id := t.nextID
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
	if err != nil {
		return nil, err
	}
	head, respBody, err := t.send(ctx, http.MethodPost, body, method)
	if err != nil {
		return nil, err
	}
	result, err := parseJSONRPCResult(head, respBody, id)
	if err != nil {
		return nil, err
	}
	if method == "initialize" {
		// The session the server assigned, echoed on every later message. Accepted only as the
		// visible-ASCII token the specification defines: it goes back into a header line.
		if sid := firstHeader(head, "Mcp-Session-Id"); sid != "" && len(sid) <= 1024 && visibleASCII(sid) {
			t.sessionID = sid
		}
		var ir struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		if json.Unmarshal(result, &ir) == nil && len(ir.ProtocolVersion) <= 64 && visibleASCII(ir.ProtocolVersion) {
			t.protocolVersion = ir.ProtocolVersion
		}
	}
	return result, nil
}

func (t *mcpHTTPTransport) Notify(ctx context.Context, method string, params any) error {
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "method": method, "params": params})
	if err != nil {
		return err
	}
	_, _, err = t.send(ctx, http.MethodPost, body, method)
	return err
}

// close ends the server-side session, when one was assigned. Best effort: a 405 is a server that does
// not let clients end sessions, which the specification allows.
func (t *mcpHTTPTransport) close(ctx context.Context) {
	if t.sessionID == "" {
		return
	}
	_, _, _ = t.send(ctx, http.MethodDelete, nil, "session close")
	t.sessionID = ""
}

// send authorises and writes one message, records it, and returns the response head and the body with
// chunk framing removed. A non-2xx status is an *mcpscan.HTTPStatusError.
func (t *mcpHTTPTransport) send(ctx context.Context, verb string, body []byte, label string) (head, respBody []byte, err error) {
	raw := t.render(verb, body)
	started := time.Now()
	res, err := t.auth.Send(ctx, raw)
	if err != nil {
		return nil, nil, err
	}
	t.record(raw, res, started, label)
	head, respBody = splitHeadBody(res.Raw)
	if strings.Contains(strings.ToLower(firstHeader(head, "Transfer-Encoding")), "chunked") {
		if plain, ok := httputil.Dechunk(respBody); ok {
			respBody = plain
		}
	}
	status := authzStatus(res.Raw)
	if status < 200 || status >= 300 {
		return head, respBody, &mcpscan.HTTPStatusError{Status: status, Authenticate: firstHeader(head, "WWW-Authenticate")}
	}
	return head, respBody, nil
}

func (t *mcpHTTPTransport) render(verb string, body []byte) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\n", verb, t.path)
	fmt.Fprintf(&b, "Host: %s\r\n", t.hostHeader)
	if body != nil {
		b.WriteString("Content-Type: application/json\r\n")
		// Both, because a Streamable-HTTP server may answer with a JSON body or an SSE stream.
		b.WriteString("Accept: application/json, text/event-stream\r\n")
	}
	if t.sessionID != "" {
		b.WriteString("Mcp-Session-Id: " + t.sessionID + "\r\n")
	}
	if t.protocolVersion != "" {
		b.WriteString("MCP-Protocol-Version: " + t.protocolVersion + "\r\n")
	}
	if t.authLine != "" {
		b.WriteString(t.authLine + "\r\n")
	}
	fmt.Fprintf(&b, "Content-Length: %d\r\n", len(body))
	b.WriteString("Connection: close\r\n\r\n")
	b.Write(body)
	return b.Bytes()
}

// record stores one message as an exchange and a tool-log row, source scanner, like any probe.
func (t *mcpHTTPTransport) record(raw []byte, res sender.AuthorisedResult, started time.Time, label string) {
	s := t.s
	if s.store == nil {
		return
	}
	reqID, err := s.store.Put(raw, core.DirectionRequest)
	if err != nil {
		return
	}
	respID, err := s.store.Put(res.Raw, core.DirectionResponse)
	if err != nil {
		return
	}
	note := "MCP scan: " + label
	ex := &core.Exchange{
		Host:        t.host,
		Port:        t.port,
		TLS:         t.tls,
		Method:      firstLineMethod(string(raw)),
		Path:        firstLinePath(string(raw)),
		Status:      parseResponseStatus(res.Raw),
		ResponseLen: len(res.Raw),
		Mime:        core.MimeEssence(res.Raw),
		StartedMs:   uint64(started.UnixMilli()),
		Duration:    core.MeasuredDuration(res.Duration),
		Request:     core.MsgPtr(reqID),
		Response:    &respID,
		Source:      core.SourceScanner,
		Notes:       &note,
	}
	s.store.AddExchange(ex)
	t.exchanges = append(t.exchanges, ex.ID)
	if s.toolLog != nil {
		s.toolLog.Record(toollog.ToolScanner, t.host, t.port, t.tls, ex.Method, ex.Path, intOrZero(ex.Status),
			toollog.Bytes(len(res.Raw)), ex.Duration.Millis(), note, &ex.ID)
	}
}

// parseJSONRPCResult pulls the result for request id out of a JSON body or an SSE stream. In a stream
// the server may send notifications or its own requests before the response, so the event whose id
// matches is the answer; the others are skipped.
func parseJSONRPCResult(head, body []byte, id int) (json.RawMessage, error) {
	ct := strings.ToLower(firstHeader(head, "Content-Type"))
	var candidates [][]byte
	if strings.HasPrefix(ct, "text/event-stream") {
		candidates = sseData(body)
		if len(candidates) == 0 {
			return nil, errors.New("the server answered with an event stream that carried no data")
		}
	} else {
		candidates = [][]byte{bytes.TrimSpace(body)}
	}
	for _, c := range candidates {
		var env struct {
			ID     json.RawMessage `json:"id"`
			Result json.RawMessage `json:"result"`
			Error  *struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.Unmarshal(c, &env); err != nil {
			if len(candidates) == 1 {
				return nil, fmt.Errorf("the server's reply is not JSON-RPC: %w", err)
			}
			continue
		}
		if string(bytes.TrimSpace(env.ID)) != strconv.Itoa(id) {
			continue
		}
		if env.Error != nil {
			return nil, &mcpscan.RPCError{Code: env.Error.Code, Message: env.Error.Message}
		}
		if env.Result == nil {
			return nil, errors.New("the server's reply has neither result nor error")
		}
		return env.Result, nil
	}
	return nil, fmt.Errorf("the server's reply carried no response to request %d", id)
}

// sseData returns each event's data (multi-line data joined by "\n"), per the EventSource format.
func sseData(body []byte) [][]byte {
	var out [][]byte
	var cur []string
	flush := func() {
		if len(cur) > 0 {
			out = append(out, []byte(strings.Join(cur, "\n")))
			cur = nil
		}
	}
	for _, line := range strings.Split(strings.ReplaceAll(string(body), "\r\n", "\n"), "\n") {
		switch {
		case line == "":
			flush()
		case strings.HasPrefix(line, "data:"):
			cur = append(cur, strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
		}
	}
	flush()
	return out
}

func firstHeader(head []byte, name string) string {
	if vs := headerValues(head, name); len(vs) > 0 {
		return vs[0]
	}
	return ""
}

func visibleASCII(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// endpointParts splits a parsed endpoint URL into the host/port/tls the sender takes.
func endpointParts(u *url.URL) (host string, port uint16, tls bool) {
	host = u.Hostname()
	tls = strings.EqualFold(u.Scheme, "https")
	if p := u.Port(); p != "" {
		if n, err := strconv.ParseUint(p, 10, 16); err == nil {
			port = uint16(n)
		}
	}
	if port == 0 {
		if tls {
			port = 443
		} else {
			port = 80
		}
	}
	return host, port, tls
}
