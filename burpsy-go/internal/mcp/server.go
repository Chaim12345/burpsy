package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/dash"
	"github.com/burpsy-go/burpsy/internal/scanner"
	"github.com/burpsy-go/burpsy/internal/sender"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"go.uber.org/zap"
)

// Server is an MCP server that exposes burpsy's capabilities over stdio.
type Server struct {
	store          *core.TrafficStore
	scope          *core.Scope
	findings       *core.FindingStore
	sender         *sender.Sender
	scanner        *scanner.ActiveScanner
	passiveScanner *scanner.PassiveScanner
	tasks          *dash.Registry
	events         *dash.EventLog
	logger         *zap.Logger
	mcp            *server.MCPServer
}

// NewServer creates an MCP server backed by live burpsy state.
func NewServer(store *core.TrafficStore, scope *core.Scope, findings *core.FindingStore, snd *sender.Sender, scan *scanner.ActiveScanner, passive *scanner.PassiveScanner, tasks *dash.Registry, events *dash.EventLog, logger *zap.Logger) *Server {
	s := &Server{
		store:          store,
		scope:          scope,
		findings:       findings,
		sender:         snd,
		scanner:        scan,
		passiveScanner: passive,
		tasks:          tasks,
		events:         events,
		logger:         logger,
		mcp: server.NewMCPServer(
			"burpsy",
			"0.1.0",
			server.WithInstructions("You are driving burpsy, an HTTP security testing proxy. Use these tools to capture traffic, scan for vulnerabilities, and report findings. Always check scope before sending requests to a target. The proxy captures traffic passively — route targets through it to populate history, then scan."),
		),
	}
	s.registerTools()
	return s
}

// ServeStdio blocks, serving the MCP protocol on stdin/stdout until stdin closes.
func (s *Server) ServeStdio(ctx context.Context) error {
	done := make(chan error, 1)
	go func() {
		done <- server.ServeStdio(s.mcp)
	}()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Result helpers

func result(data map[string]any) (*mcp.CallToolResult, error) {
	b, err := json.Marshal(data)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("marshal error: %v", err)), nil
	}
	return mcp.NewToolResultText(string(b)), nil
}

func errResult(msg string, args ...any) (*mcp.CallToolResult, error) {
	return mcp.NewToolResultError(fmt.Sprintf(msg, args...)), nil
}

func exchangeView(ex *core.Exchange) map[string]any {
	view := map[string]any{
		"id":           ex.ID,
		"host":         ex.Host,
		"port":         ex.Port,
		"tls":          ex.TLS,
		"method":       ex.Method,
		"path":         ex.Path,
		"status":       ex.Status,
		"response_len": ex.ResponseLen,
		"started_ms":   ex.StartedMs,
		"duration_ms":  ex.Duration.Millis(),
		"protocol":     protocolToken(ex.Protocol),
	}
	if ex.Response != nil {
		view["response"] = uint64(*ex.Response)
	}
	if ex.Request != 0 {
		view["request"] = uint64(ex.Request)
	}
	if ex.Notes != nil {
		view["notes"] = *ex.Notes
	}
	return view
}

func findingView(f *core.Finding) map[string]any {
	return map[string]any{
		"id":          f.ID,
		"name":        f.Name,
		"severity":    f.Severity.String(),
		"confidence":  f.Confidence.String(),
		"description": f.Description,
		"remediation": f.Remediation,
	}
}

func protocolToken(p core.Protocol) string {
	if p == core.ProtocolHTTP2 {
		return "Http2"
	}
	return "Http1"
}

func parseID(v any) (uint64, error) {
	switch n := v.(type) {
	case float64:
		return uint64(n), nil
	case int:
		return uint64(n), nil
	case int64:
		return uint64(n), nil
	case json.Number:
		i, err := n.Int64()
		return uint64(i), err
	case string:
		return strconv.ParseUint(n, 10, 64)
	default:
		return 0, fmt.Errorf("expected numeric id, got %T", v)
	}
}

// getArgs returns the tool arguments map from a CallToolRequest.
func getArgs(req mcp.CallToolRequest) map[string]any {
	if m, ok := req.Params.Arguments.(map[string]any); ok {
		return m
	}
	return map[string]any{}
}


