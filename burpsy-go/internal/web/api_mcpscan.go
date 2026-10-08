package web

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/mcpscan"
	"github.com/burpsy-go/burpsy/internal/sender"
)

// ---- MCP-target scanning (burpsy-react-ui-wflj) --------------------------------------------------
//
// burpsy as the client attacking a Model Context Protocol server (the inverse of exposing burpsy over
// MCP): point it at a server's HTTP endpoint, and it performs the handshake, enumerates every tool,
// resource and prompt, probes each tool with a representative call, and runs the MCP-specific checks,
// filing findings in the existing store. The protocol and the checks live in internal/mcpscan; this
// file binds that package's Transport seam to burpsy's authorised sender and scope, so every JSON-RPC
// call is subject to the same scope chokepoint every other outbound request is.
//
// riskAttack: it connects out to the target and invokes its tools — unbounded traffic to the
// engagement target, the definition of the class.

// mcpTransport binds mcpscan.Transport to the authorised sender: each JSON-RPC call becomes a POST to
// the endpoint, authorised against scope (the real gate re-reads the bytes going out) and sent on a
// fresh connection. A non-2xx HTTP status or a JSON-RPC error object is returned as an error, which
// the client treats as "this call failed" — fatal for initialize, survivable for a list.
func (s *Server) mcpTransport(endpoint *url.URL, authHeader string) mcpscan.Transport {
	host, port, tls := endpointParts(endpoint)
	path := endpoint.RequestURI()
	id := 0
	return func(ctx context.Context, method string, params any) (json.RawMessage, error) {
		id++
		envelope := map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params}
		body, err := json.Marshal(envelope)
		if err != nil {
			return nil, err
		}
		raw := buildMCPRequest(host, port, path, authHeader, body)
		if aerr := s.scope.AuthoriseRaw(host, port, tls, raw); aerr != nil {
			return nil, fmt.Errorf("refused by scope: %w", aerr)
		}
		respBytes, _, serr := s.sender.SendRawOutcome(ctx, host, port, tls, raw, sender.ProtocolPreferenceAuto)
		if serr != nil {
			return nil, serr
		}
		return parseJSONRPCResponse(respBytes)
	}
}

// buildMCPRequest renders the raw POST for one JSON-RPC call. Connection: close because each call is
// its own send; the scanner is not a session.
func buildMCPRequest(host string, port uint16, path, authHeader string, body []byte) []byte {
	if path == "" {
		path = "/"
	}
	hostHeader := host
	if !(port == 80 || port == 443) {
		hostHeader = host + ":" + strconv.Itoa(int(port))
	}
	var b strings.Builder
	fmt.Fprintf(&b, "POST %s HTTP/1.1\r\n", path)
	fmt.Fprintf(&b, "Host: %s\r\n", hostHeader)
	b.WriteString("Content-Type: application/json\r\n")
	// Both accepts, because the Streamable-HTTP transport may answer either a JSON body or an SSE
	// stream; parseJSONRPCResponse handles both.
	b.WriteString("Accept: application/json, text/event-stream\r\n")
	if strings.TrimSpace(authHeader) != "" {
		b.WriteString(strings.TrimSpace(authHeader) + "\r\n")
	}
	fmt.Fprintf(&b, "Content-Length: %d\r\n", len(body))
	b.WriteString("Connection: close\r\n\r\n")
	b.Write(body)
	return []byte(b.String())
}

// parseJSONRPCResponse pulls the JSON-RPC result from a raw HTTP response, handling both a plain JSON
// body and an SSE stream (a `data:` line carrying the JSON). A JSON-RPC error object, or a non-2xx
// status, is returned as a Go error.
func parseJSONRPCResponse(respBytes []byte) (json.RawMessage, error) {
	head, body := splitHeadBody(respBytes)
	if status := authzStatus(append(append([]byte(nil), head...), body...)); status != 0 && (status < 200 || status >= 300) {
		return nil, fmt.Errorf("the server answered HTTP %d", status)
	}
	payload := extractSSEData(body)
	var env struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(payload, &env); err != nil {
		return nil, fmt.Errorf("the server's reply is not JSON-RPC: %w", err)
	}
	if env.Error != nil {
		return nil, fmt.Errorf("JSON-RPC error %d: %s", env.Error.Code, env.Error.Message)
	}
	return env.Result, nil
}

// extractSSEData returns the JSON an SSE body carries on its first `data:` line, or the body unchanged
// when it is not SSE. A Streamable-HTTP server answers a single JSON-RPC response as one SSE event.
func extractSSEData(body []byte) []byte {
	text := strings.TrimSpace(string(body))
	if !strings.HasPrefix(text, "event:") && !strings.HasPrefix(text, "data:") {
		return body
	}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "data:") {
			return []byte(strings.TrimSpace(strings.TrimPrefix(line, "data:")))
		}
	}
	return body
}

// endpointParts splits a parsed endpoint URL into the host/port/tls the sender takes.
func endpointParts(u *url.URL) (host string, port uint16, tls bool) {
	host = u.Hostname()
	tls = strings.EqualFold(u.Scheme, "https")
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err == nil {
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

type mcpScanResponse struct {
	Server struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"server"`
	Tools     int                `json:"tools"`
	Resources int                `json:"resources"`
	Prompts   int                `json:"prompts"`
	Probed    int                `json:"probed"`
	Findings  []mcpFindingView   `json:"findings"`
	ToolNames []string           `json:"tool_names"`
}

type mcpFindingView struct {
	Name        string `json:"name"`
	Severity    string `json:"severity"`
	Confidence  string `json:"confidence"`
	Subject     string `json:"subject,omitempty"`
	Description string `json:"description"`
	ID          uint64 `json:"id"`
}

// handleMCPScan serves POST /api/mcpscan. riskAttack.
func (s *Server) handleMCPScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.sender == nil {
		http.Error(w, "no sender is configured, so no MCP server can be reached", http.StatusServiceUnavailable)
		return
	}
	var body struct {
		Endpoint   string `json:"endpoint"`
		AuthHeader string `json:"auth_header"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body); err != nil {
		http.Error(w, `the body must be {"endpoint":"https://host/mcp","auth_header"?:"Authorization: Bearer ..."}`, http.StatusBadRequest)
		return
	}
	endpoint, err := url.Parse(strings.TrimSpace(body.Endpoint))
	if err != nil || (endpoint.Scheme != "http" && endpoint.Scheme != "https") || endpoint.Host == "" {
		http.Error(w, "endpoint must be an absolute http(s) URL", http.StatusBadRequest)
		return
	}
	host, port, tls := endpointParts(endpoint)
	if !s.scope.MayContainHost(host, port, tls) {
		http.Error(w, "the MCP endpoint is not in the engagement scope: "+s.scope.Explain(host, port, endpoint.RequestURI(), tls), http.StatusForbidden)
		return
	}

	client := mcpscan.NewClient(s.mcpTransport(endpoint, body.AuthHeader), strings.TrimSpace(body.AuthHeader) != "")
	en, err := client.Enumerate(r.Context())
	if err != nil {
		http.Error(w, "could not enumerate the MCP server: "+err.Error(), http.StatusBadGateway)
		return
	}
	client.Probe(r.Context(), en)

	resp := mcpScanResponse{Tools: len(en.Tools), Resources: len(en.Resources), Prompts: len(en.Prompts), Probed: len(en.Probes)}
	resp.Server.Name = en.Server.Name
	resp.Server.Version = en.Server.Version
	for _, t := range en.Tools {
		resp.ToolNames = append(resp.ToolNames, t.Name)
	}

	target := core.FindingTarget{Host: host, Port: port, TLS: tls, Path: endpoint.RequestURI()}
	for _, f := range mcpscan.Checks(en) {
		id := s.findings.Add(core.NewFinding{
			Name:        f.Name,
			Severity:    core.ParseSeverity(f.Severity),
			Confidence:  core.ParseConfidence(f.Confidence),
			Description: f.Description,
			Target:      target,
			// A merge key keyed on the server and the subject so a re-scan updates the row rather than
			// filing a second copy — the same reason the secrets module keys on the secret.
			MergeKey: "mcp:" + target.Origin() + ":" + f.Name + ":" + f.Subject,
		})
		resp.Findings = append(resp.Findings, mcpFindingView{
			Name: f.Name, Severity: f.Severity, Confidence: f.Confidence, Subject: f.Subject, Description: f.Description, ID: id,
		})
	}
	writeJSON(w, http.StatusOK, resp)
}
