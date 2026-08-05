package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/dash"
	"github.com/burpsy-go/burpsy/internal/scanner"
	"github.com/burpsy-go/burpsy/internal/sender"
	"github.com/burpsy-go/burpsy/internal/tools"
	mcpgo "github.com/mark3labs/mcp-go/mcp"
	"go.uber.org/zap"
)

// newTestServer creates an MCP server backed by empty state for handler tests.
func newTestServer(t *testing.T) *Server {
	t.Helper()
	store := core.NewTrafficStore()
	scope := core.NewScope()
	findings := core.NewFindingStore()
	snd := sender.NewSender(sender.DefaultSenderConfig())
	scan := scanner.NewActiveScanner(store, zap.NewNop()).
		WithSender(sender.NewSender(sender.DefaultSenderConfig())).
		WithScope(scope).
		WithAuditConfig(scanner.DefaultAuditConfig())
	passive := scanner.NewPassiveScanner(store, zap.NewNop())
	tasks := dash.NewRegistry()
	events := dash.NewEventLog()
	tasks.WithEvents(events)
	return NewServer(store, scope, findings, snd, scan, passive, tasks, events, zap.NewNop())
}

func TestListHistoryIsEmptyOnFreshServer(t *testing.T) {
	s := newTestServer(t)
	res, err := s.hListHistory(context.Background(), mcpgo.CallToolRequest{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.Content) == 0 {
		t.Fatal("expected at least one content block")
	}
	// Result should be valid JSON with total: 0
	text := res.Content[0].(mcpgo.TextContent).Text
	var data map[string]any
	if err := json.Unmarshal([]byte(text), &data); err != nil {
		t.Fatalf("result is not valid JSON: %v", err)
	}
	if total, ok := data["total"].(float64); !ok || total != 0 {
		t.Fatalf("expected total=0, got %v", data["total"])
	}
}

func TestGetScopeReturnsEmptyByDefault(t *testing.T) {
	s := newTestServer(t)
	res, err := s.hGetScope(context.Background(), mcpgo.CallToolRequest{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	text := res.Content[0].(mcpgo.TextContent).Text
	var data map[string]any
	if err := json.Unmarshal([]byte(text), &data); err != nil {
		t.Fatalf("not valid JSON: %v", err)
	}
	if empty, ok := data["empty"].(bool); !ok || !empty {
		t.Fatalf("expected empty=true on fresh scope, got %v", data["empty"])
	}
	rules, ok := data["rules"].([]any)
	if !ok || len(rules) != 0 {
		t.Fatalf("expected 0 rules, got %v", data["rules"])
	}
}

func TestModifyScopeAddInclude(t *testing.T) {
	s := newTestServer(t)
	_, err := s.hModifyScope(context.Background(), mcpgo.CallToolRequest{
		Params: mcpgo.CallToolParams{Arguments: map[string]any{"action": "include", "pattern": "*.example.com"}},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	res, _ := s.hGetScope(context.Background(), mcpgo.CallToolRequest{})
	text := res.Content[0].(mcpgo.TextContent).Text
	var data map[string]any
	json.Unmarshal([]byte(text), &data)
	rules, ok := data["rules"].([]any)
	if !ok || len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %v", data["rules"])
	}
}

func TestModifyScopeClear(t *testing.T) {
	s := newTestServer(t)
	s.scope.AddInclude("*.example.com")
	s.hModifyScope(context.Background(), mcpgo.CallToolRequest{
		Params: mcpgo.CallToolParams{Arguments: map[string]any{"action": "clear"}},
	})
	res, _ := s.hGetScope(context.Background(), mcpgo.CallToolRequest{})
	text := res.Content[0].(mcpgo.TextContent).Text
	var data map[string]any
	json.Unmarshal([]byte(text), &data)
	if empty, ok := data["empty"].(bool); !ok || !empty {
		t.Fatalf("expected empty=true after clear, got %v", data["empty"])
	}
}

func TestListIssuesIsEmptyOnFreshServer(t *testing.T) {
	s := newTestServer(t)
	res, err := s.hListIssues(context.Background(), mcpgo.CallToolRequest{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	text := res.Content[0].(mcpgo.TextContent).Text
	var data map[string]any
	json.Unmarshal([]byte(text), &data)
	if total, ok := data["total"].(float64); !ok || total != 0 {
		t.Fatalf("expected total=0, got %v", data["total"])
	}
}

func TestListScanConfigsReturnsImplemented(t *testing.T) {
	s := newTestServer(t)
	res, err := s.hListScanConfigs(context.Background(), mcpgo.CallToolRequest{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	text := res.Content[0].(mcpgo.TextContent).Text
	var data map[string]any
	json.Unmarshal([]byte(text), &data)
	cfgs, ok := data["configs"].([]any)
	if !ok || len(cfgs) == 0 {
		t.Fatalf("expected non-empty configs, got %v", data["configs"])
	}
	if implemented, ok := data["implemented_here"].(float64); !ok || implemented != float64(len(scanner.BuiltInConfigs)) {
		t.Fatalf("expected implemented_here=%d, got %v", len(scanner.BuiltInConfigs), data["implemented_here"])
	}
}

func TestTransformDecodeBase64(t *testing.T) {
	s := newTestServer(t)
	input := "aGVsbG8=" // "hello"
	res, err := s.hTransform(context.Background(), mcpgo.CallToolRequest{
		Params: mcpgo.CallToolParams{Arguments: map[string]any{"operation": "decode", "input": input, "encoding": "base64"}},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	text := res.Content[0].(mcpgo.TextContent).Text
	var data map[string]any
	json.Unmarshal([]byte(text), &data)
	if out, ok := data["output"].(string); !ok || out != "hello" {
		t.Fatalf("expected output=hello, got %v", data["output"])
	}
}

func TestTransformHashSHA256(t *testing.T) {
	s := newTestServer(t)
	res, err := s.hTransform(context.Background(), mcpgo.CallToolRequest{
		Params: mcpgo.CallToolParams{Arguments: map[string]any{"operation": "hash", "input": "hello", "algorithm": "sha256"}},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	text := res.Content[0].(mcpgo.TextContent).Text
	var data map[string]any
	json.Unmarshal([]byte(text), &data)
	expected := tools.NewHasher().SHA256("hello")
	if out, ok := data["output"].(string); !ok || out != expected {
		t.Fatalf("expected %s, got %v", expected, data["output"])
	}
}

func TestTransformCompareIdentical(t *testing.T) {
	s := newTestServer(t)
	res, err := s.hTransform(context.Background(), mcpgo.CallToolRequest{
		Params: mcpgo.CallToolParams{Arguments: map[string]any{"operation": "compare", "a": "hello", "b": "hello"}},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	text := res.Content[0].(mcpgo.TextContent).Text
	var data map[string]any
	json.Unmarshal([]byte(text), &data)
	if identical, ok := data["identical"].(bool); !ok || !identical {
		t.Fatalf("expected identical=true, got %v", data["identical"])
	}
}

func TestTransformCompareDifferent(t *testing.T) {
	s := newTestServer(t)
	res, err := s.hTransform(context.Background(), mcpgo.CallToolRequest{
		Params: mcpgo.CallToolParams{Arguments: map[string]any{"operation": "compare", "a": "hello", "b": "world"}},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	text := res.Content[0].(mcpgo.TextContent).Text
	var data map[string]any
	json.Unmarshal([]byte(text), &data)
	if identical, ok := data["identical"].(bool); !ok || identical {
		t.Fatalf("expected identical=false, got %v", data["identical"])
	}
}

func TestTransformUnknownOperation(t *testing.T) {
	s := newTestServer(t)
	res, err := s.hTransform(context.Background(), mcpgo.CallToolRequest{
		Params: mcpgo.CallToolParams{Arguments: map[string]any{"operation": "frobnicate"}},
	})
	if err != nil {
		t.Fatalf("handler should not error, should return tool error: %v", err)
	}
	if !res.IsError {
		t.Fatal("expected IsError=true for unknown operation")
	}
}

func TestSendRequestRefusedOutOfScope(t *testing.T) {
	s := newTestServer(t)
	s.scope.AddInclude("*.example.com")
	res, err := s.hSendRequest(context.Background(), mcpgo.CallToolRequest{
		Params: mcpgo.CallToolParams{Arguments: map[string]any{
			"target":  "evil.com:80",
			"request": "GET / HTTP/1.1\r\nHost: evil.com\r\n\r\n",
		}},
	})
	if err != nil {
		t.Fatalf("handler should not error: %v", err)
	}
	if !res.IsError {
		t.Fatal("expected IsError=true for out-of-scope target")
	}
	text := res.Content[0].(mcpgo.TextContent).Text
	if !strings.Contains(text, "refused") && !strings.Contains(text, "out of scope") {
		t.Fatalf("expected refusal message, got: %s", text)
	}
}

func TestExportReportJSON(t *testing.T) {
	s := newTestServer(t)
	s.findings.Add(core.NewFinding{
		Name: "test finding", Severity: core.SeverityHigh, Confidence: core.ConfidenceCertain,
		Description: "test", Remediation: "fix it",
	})
	res, err := s.hExportReport(context.Background(), mcpgo.CallToolRequest{
		Params: mcpgo.CallToolParams{Arguments: map[string]any{"format": "json"}},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	text := res.Content[0].(mcpgo.TextContent).Text
	var data map[string]any
	json.Unmarshal([]byte(text), &data)
	if total, ok := data["total"].(float64); !ok || total != 1 {
		t.Fatalf("expected total=1, got %v", data["total"])
	}
}

func TestExportReportHTML(t *testing.T) {
	s := newTestServer(t)
	res, err := s.hExportReport(context.Background(), mcpgo.CallToolRequest{
		Params: mcpgo.CallToolParams{Arguments: map[string]any{"format": "html"}},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	text := res.Content[0].(mcpgo.TextContent).Text
	var data map[string]any
	json.Unmarshal([]byte(text), &data)
	content, ok := data["content"].(string)
	if !ok || !strings.Contains(content, "<html>") {
		t.Fatalf("expected HTML content, got %v", data["content"])
	}
}

func TestGetStatsZeroOnFreshServer(t *testing.T) {
	s := newTestServer(t)
	res, err := s.hGetStats(context.Background(), mcpgo.CallToolRequest{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	text := res.Content[0].(mcpgo.TextContent).Text
	var data map[string]any
	json.Unmarshal([]byte(text), &data)
	if ex, ok := data["exchanges"].(float64); !ok || ex != 0 {
		t.Fatalf("expected exchanges=0, got %v", data["exchanges"])
	}
}

func TestGetExchangeNotFound(t *testing.T) {
	s := newTestServer(t)
	res, err := s.hGetExchange(context.Background(), mcpgo.CallToolRequest{
		Params: mcpgo.CallToolParams{Arguments: map[string]any{"id": 999}},
	})
	if err != nil {
		t.Fatalf("handler should not error: %v", err)
	}
	if !res.IsError {
		t.Fatal("expected IsError=true for missing exchange")
	}
}

func TestParseTarget(t *testing.T) {
	tests := []struct {
		target   string
		wantHost string
		wantPort uint16
		wantTLS  bool
	}{
		{"example.com", "example.com", 80, false},
		{"example.com:443", "example.com", 443, true},
		{"example.com:8080", "example.com", 8080, false},
		{"https://example.com", "example.com", 443, true},
		{"http://example.com:8080", "example.com", 8080, false},
	}
	for _, tt := range tests {
		host, port, tls, err := parseTarget(tt.target)
		if err != nil {
			t.Errorf("parseTarget(%q) error: %v", tt.target, err)
			continue
		}
		if host != tt.wantHost || port != tt.wantPort || tls != tt.wantTLS {
			t.Errorf("parseTarget(%q) = (%s, %d, %v), want (%s, %d, %v)",
				tt.target, host, port, tls, tt.wantHost, tt.wantPort, tt.wantTLS)
		}
	}
}

func TestParseID(t *testing.T) {
	tests := []struct {
		input any
		want  uint64
	}{
		{float64(42), 42},
		{int(7), 7},
		{int64(99), 99},
		{"123", 123},
	}
	for _, tt := range tests {
		got, err := parseID(tt.input)
		if err != nil {
			t.Errorf("parseID(%v) error: %v", tt.input, err)
			continue
		}
		if got != tt.want {
			t.Errorf("parseID(%v) = %d, want %d", tt.input, got, tt.want)
		}
	}
}
