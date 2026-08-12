package mcp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/dash"
	"github.com/burpsy-go/burpsy/internal/intruder"
	"github.com/burpsy-go/burpsy/internal/scanner"
	"github.com/burpsy-go/burpsy/internal/sender"
	"github.com/burpsy-go/burpsy/internal/tools"
	burpsyhttp2 "github.com/burpsy-go/burpsy/internal/http2"
	"github.com/mark3labs/mcp-go/mcp"
)

// ---- Proxy & History -------------------------------------------------------------------------

func (s *Server) hListHistory(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := getArgs(req)
	limit := 100
	if l, ok := args["limit"].(float64); ok && l > 0 {
		limit = int(l)
		if limit > 1000 {
			limit = 1000
		}
	}
	exchanges := s.store.Exchanges()
	out := make([]map[string]any, 0, limit)
	count := 0
	for i := len(exchanges) - 1; i >= 0 && count < limit; i-- {
		out = append(out, exchangeView(exchanges[i]))
		count++
	}
	return result(map[string]any{"exchanges": out, "total": len(exchanges), "returned": len(out)})
}

func (s *Server) hGetExchange(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := getArgs(req)
	id, err := parseID(args["id"])
	if err != nil {
		return errResult("invalid exchange id: %v", err)
	}
	ex, err := s.store.GetExchange(id)
	if err != nil {
		return errResult("exchange not found: %v", err)
	}
	return result(exchangeView(ex))
}

func (s *Server) hGetMessage(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := getArgs(req)
	id, err := parseID(args["id"])
	if err != nil {
		return errResult("invalid message id: %v", err)
	}
	msg, err := s.store.Get(core.MsgId(id))
	if err != nil {
		return errResult("message not found: %v", err)
	}
	span := core.Span{Offset: 0, Len: msg.Len()}
	return result(map[string]any{
		"id":   uint64(msg.ID),
		"len":  msg.Len(),
		"text": msg.Text(span),
	})
}

func (s *Server) hGetStats(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	messages, exchanges := s.store.Count()
	return result(map[string]any{
		"exchanges":   exchanges,
		"messages":    messages,
		"stored_bytes": s.store.Bytes(),
	})
}

// ---- Scope -----------------------------------------------------------------------------------

func (s *Server) hGetScope(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	rules := s.scope.Rules()
	view := make([]map[string]any, 0, len(rules))
	for _, r := range rules {
		kind := "Include"
		if r.Kind == core.ScopeExclude {
			kind = "Exclude"
		}
		view = append(view, map[string]any{"kind": kind, "pattern": r.Pattern})
	}
	return result(map[string]any{
		"allow_all": s.scope.AllowAll(),
		"empty":     s.scope.Empty(),
		"rules":     view,
	})
}

func (s *Server) hModifyScope(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := getArgs(req)
	action, _ := args["action"].(string)
	pattern, _ := args["pattern"].(string)
	switch action {
	case "include":
		if pattern == "" {
			return errResult("'pattern' is required for include")
		}
		s.scope.AddInclude(pattern)
	case "exclude":
		if pattern == "" {
			return errResult("'pattern' is required for exclude")
		}
		s.scope.AddExclude(pattern)
	case "remove":
		if pattern == "" {
			return errResult("'pattern' is required for remove")
		}
		s.scope.Remove(core.ScopeInclude, pattern)
		s.scope.Remove(core.ScopeExclude, pattern)
	case "clear":
		s.scope.Clear()
	default:
		return errResult("unknown action %q (use include, exclude, remove, or clear)", action)
	}
	return result(map[string]any{"status": "ok", "action": action, "pattern": pattern})
}

// ---- Scanner ---------------------------------------------------------------------------------

func (s *Server) hListIssues(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	findings := s.findings.All()
	out := make([]map[string]any, 0, len(findings))
	for _, f := range findings {
		out = append(out, findingView(f))
	}
	return result(map[string]any{"findings": out, "total": len(out)})
}

func (s *Server) hRunAudit(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := getArgs(req)
	id, err := parseID(args["id"])
	if err != nil {
		return errResult("invalid exchange id: %v", err)
	}
	cfg := scanner.DefaultAuditConfig()
	if c, ok := args["config"].(string); ok && c != "" {
		preset, found := scanner.BuiltInConfigByName(c)
		if !found {
			return errResult("no built-in scan configuration named %q (use list_scan_configs)", c)
		}
		cfg = preset.Apply(cfg)
	}
	task := s.tasks.Start(dash.KindAudit, "audit:"+strconv.FormatUint(id, 10), uint64(s.scanner.ActiveCheckCount()))
	outcome, findings := s.scanner.AuditWithin(ctx, id, cfg)
	task.Finish(dash.Breakdown{Found: uint64(outcome.Findings), Skipped: uint64(outcome.Skipped), Errored: uint64(outcome.SendFailures), Gated: uint64(outcome.NotRun)})
	res := map[string]any{
		"exchange_id":     id,
		"state":           outcome.State,
		"ran":             outcome.Ran,
		"findings_count":  outcome.Findings,
		"skipped":         outcome.Skipped,
		"send_failures":   outcome.SendFailures,
		"not_run":         outcome.NotRun,
		"timed_out":       outcome.TimedOut,
		"requests_sent":   outcome.RequestsSent,
		"requests_refused": outcome.RequestsRefused,
	}
	fms := make([]map[string]any, 0, len(findings))
	for _, f := range findings {
		fms = append(fms, map[string]any{
			"name": f.Name, "severity": f.Severity, "confidence": f.Confidence,
			"description": f.Description, "solution": f.Solution,
		})
		s.findings.Add(core.NewFinding{
			Name:        f.Name,
			Severity:    core.ParseSeverity(f.Severity),
			Confidence:  core.ParseConfidence(f.Confidence),
			Description: f.Description,
			Remediation: f.Solution,
		})
	}
	res["findings"] = fms
	return result(res)
}

func (s *Server) hGetCoverage(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if s.passiveScanner == nil {
		return result(map[string]any{"enabled": false, "hint": "passive scanning not enabled (start with --bchecks DIR)"})
	}
	r := s.passiveScanner.Report()
	return result(map[string]any{
		"enabled": true,
		"loaded":  s.passiveScanner.Loaded(),
		"summary": r.Summary(),
		"errors":  len(r.Errors),
	})
}

func (s *Server) hListScanConfigs(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	cfgs := make([]map[string]any, 0, len(scanner.BuiltInConfigs))
	for _, c := range scanner.BuiltInConfigs {
		keys := make([]map[string]any, 0, len(c.Keys()))
		for _, k := range c.Keys() {
			keys = append(keys, map[string]any{"name": k.Name, "set": k.Set, "value": k.Value, "what": k.What})
		}
		cfgs = append(cfgs, map[string]any{"name": c.Name, "keys": keys})
	}
	return result(map[string]any{"configs": cfgs, "shipped_by_burp": scanner.BurpShippedConfigCount, "implemented_here": len(scanner.BuiltInConfigs)})
}

// ---- Repeater -------------------------------------------------------------------------------

func (s *Server) hSendRequest(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := getArgs(req)
	target, _ := args["target"].(string)
	rawReq, _ := args["request"].(string)
	protocol, _ := args["protocol"].(string)
	if target == "" || rawReq == "" {
		return errResult("both 'target' (host:port) and 'request' (raw HTTP bytes) are required")
	}
	host, port, tls, err := parseTarget(target)
	if err != nil {
		return errResult("invalid target %q: %v", target, err)
	}
	if strings.EqualFold(protocol, "https") {
		tls = true
	} else if strings.EqualFold(protocol, "http") {
		tls = false
	}
	if !s.scope.MayContainHost(host, port, tls) {
		return errResult("refused: target is out of scope (%s)", s.scope.Explain(host, port, "/", tls))
	}
	auth := sender.NewAuthorisedSender(s.scope, s.sender, host, port, tls)
	res, err := auth.Send(ctx, []byte(rawReq))
	if err != nil {
		return errResult("request failed: %v", err)
	}
	status := 0
	if res.Status != nil {
		status = *res.Status
	}
	return result(map[string]any{
		"status":    status,
		"body":      string(res.Raw),
		"protocol":  res.Outcome.Negotiated,
		"duration":  res.Duration.Milliseconds(),
		"outcome":   res.Outcome,
	})
}

// ---- Intruder -------------------------------------------------------------------------------

func (s *Server) hRunAttack(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := getArgs(req)
	msgID, err := parseID(args["msg_id"])
	if err != nil {
		return errResult("invalid msg_id: %v", err)
	}
	target, _ := args["target"].(string)
	mode, _ := args["mode"].(string)
	if mode == "" {
		mode = "sniper"
	}
	payloadsRaw, _ := args["payloads"].([]any)
	payloads := make([]string, 0, len(payloadsRaw))
	for _, p := range payloadsRaw {
		payloads = append(payloads, fmt.Sprintf("%v", p))
	}
	msg, err := s.store.Get(core.MsgId(msgID))
	if err != nil {
		return errResult("base message not found: %v", err)
	}
	host, port, tls, err := parseTarget(target)
	if err != nil {
		return errResult("invalid target: %v", err)
	}
	auth := sender.NewAuthorisedSender(s.scope, s.sender, host, port, tls)
	sendFn := func(ctx context.Context, h string, p uint16, t bool, raw []byte) ([]byte, error) {
		res, err := auth.Send(ctx, raw)
		if err != nil {
			return nil, err
		}
		return res.Raw, nil
	}
	attack := intruder.NewIntruder(s.logger).WithSend(sendFn)
	resultCh, err := attack.Run(ctx, msg.Text(core.Span{Offset: 0, Len: msg.Len()}), host, port, tls, payloads, nil)
	if err != nil {
		return errResult("attack failed to start: %v", err)
	}
	var attempts []map[string]any
	for r := range resultCh {
		errStr := ""
		if r.Error != nil {
			errStr = r.Error.Error()
		}
		attempts = append(attempts, map[string]any{
			"payload": r.Payload,
			"status":  r.StatusCode,
			"length":  r.Length,
			"words":   r.Words,
			"lines":   r.Lines,
			"time_ms": r.Time.Milliseconds(),
			"error":   errStr,
		})
	}
	return result(map[string]any{"mode": mode, "attempts": attempts, "total": len(attempts)})
}

// ---- HTTP/2 --------------------------------------------------------------------------------

func (s *Server) hSendH2Program(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := getArgs(req)
	host, _ := args["host"].(string)
	portF, _ := args["port"].(float64)
	tls, _ := args["tls"].(bool)
	framesRaw, _ := args["frames"].([]any)
	if host == "" {
		return errResult("'host' is required")
	}
	if portF == 0 {
		if tls {
			portF = 443
		} else {
			portF = 80
		}
	}
	var specs []burpsyhttp2.FrameSpec
	for _, f := range framesRaw {
		m, ok := f.(map[string]any)
		if !ok {
			continue
		}
		var spec burpsyhttp2.FrameSpec
		if t, ok := m["type"].(float64); ok {
			spec.Type = uint8(t)
		}
		if flags, ok := m["flags"].(float64); ok {
			spec.Flags = uint8(flags)
		}
		if sid, ok := m["stream_id"].(float64); ok {
			spec.StreamID = uint32(sid)
		}
		if payload, ok := m["payload"].(string); ok {
			if decoded, err := base64.StdEncoding.DecodeString(payload); err == nil {
				spec.Payload = decoded
			} else {
				spec.Payload = []byte(payload)
			}
		}
		specs = append(specs, spec)
	}
	program := burpsyhttp2.NewH2FrameProgram(specs...)
	auth := sender.NewAuthorisedSender(s.scope, s.sender, host, uint16(portF), tls)
	res, err := auth.SendFrameProgram(ctx, program)
	if err != nil {
		return errResult("h2 program refused: %v", err)
	}
	return result(map[string]any{
		"sent":       len(res.Sent) > 0,
		"violations": len(res.Violations),
		"response":   string(res.Response),
		"verdict":    res.Authorisation.Verdict.String(),
	})
}

func (s *Server) hGetProtocols(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	r := s.sender.Protocols()
	return result(map[string]any{
		"sent_as_http2":        r.SentAsHTTP2,
		"sent_as_http1":        r.SentAsHTTP1,
		"downgrades":           r.Downgrades,
		"rewrites":             r.Rewrites,
		"discovery_handshakes": r.DiscoveryHandshakes,
		"cache_hits":           r.CacheHits,
		"authorities":          r.Authorities,
	})
}

// ---- Transform ------------------------------------------------------------------------------

func (s *Server) hTransform(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := getArgs(req)
	operation, _ := args["operation"].(string)
	switch operation {
	case "decode":
		input, _ := args["input"].(string)
		enc, _ := args["encoding"].(string)
		if enc == "" {
			enc = "auto"
		}
		if enc == "auto" {
			enc = "url"
		}
		layer, ok := tools.ParseLayer(enc)
		if !ok {
			return errResult("unknown encoding %q", enc)
		}
		out, truncated, err := tools.Decode(layer, []byte(input))
		if err != nil {
			return errResult("decode failed: %v", err)
		}
		return result(map[string]any{"output": string(out), "encoding": enc, "truncated": truncated})
	case "encode":
		input, _ := args["input"].(string)
		enc, _ := args["encoding"].(string)
		layer, ok := tools.ParseLayer(enc)
		if !ok {
			return errResult("unknown encoding %q", enc)
		}
		out, err := tools.Encode(layer, []byte(input))
		if err != nil {
			return errResult("encode failed: %v", err)
		}
		return result(map[string]any{"output": string(out), "encoding": enc})
	case "hash":
		input, _ := args["input"].(string)
		algo, _ := args["algorithm"].(string)
		if algo == "" {
			algo = "sha256"
		}
		h := tools.NewHasher()
		var out string
		switch algo {
		case "md5":
			out = h.MD5(input)
		case "sha1":
			out = h.SHA1(input)
		case "sha256":
			out = h.SHA256(input)
		case "sha512":
			out = h.SHA512(input)
		default:
			return errResult("unknown hash algorithm %q", algo)
		}
		return result(map[string]any{"output": out, "algorithm": algo})
	case "compare":
		a, _ := args["a"].(string)
		b, _ := args["b"].(string)
		diff := tools.DiffWithBudget([]byte(a), []byte(b), tools.GranularityByte, 1000)
		return result(map[string]any{
			"identical": diff.IsIdentical(),
			"changes":   diff.Changes(),
			"ops":       diff.Ops,
		})
	default:
		return errResult("unknown operation %q (use decode, encode, hash, or compare)", operation)
	}
}

// ---- Reports --------------------------------------------------------------------------------

func (s *Server) hExportReport(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := getArgs(req)
	format, _ := args["format"].(string)
	findings := s.findings.All()
	switch format {
	case "json":
		data := make([]map[string]any, 0, len(findings))
		for _, f := range findings {
			data = append(data, findingView(f))
		}
		return result(map[string]any{"format": "json", "findings": data, "total": len(data)})
	case "html":
		var sb strings.Builder
		sb.WriteString("<html><head><title>burpsy findings</title></head><body>\n")
		sb.WriteString(fmt.Sprintf("<h1>burpsy security findings (%d)</h1>\n<ul>\n", len(findings)))
		for _, f := range findings {
			sb.WriteString(fmt.Sprintf("<li><strong>%s</strong> [%s/%s] %s — <em>%s</em></li>\n",
				f.Name, f.Severity, f.Confidence, f.Description, f.Remediation))
		}
		sb.WriteString("</ul>\n</body></html>")
		return result(map[string]any{"format": "html", "content": sb.String()})
	case "sarif":
		return result(map[string]any{"format": "sarif", "findings": len(findings), "note": "Full SARIF export via web API /api/report/sarif"})
	default:
		return errResult("unknown format %q (use html, json, or sarif)", format)
	}
}

// ---- Dashboard ------------------------------------------------------------------------------

func (s *Server) hGetDashboard(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	_, exchanges := s.store.Count()
	return result(map[string]any{
		"tasks":         s.tasks.Snapshot(),
		"tasks_running": s.tasks.Running(),
		"tasks_dropped": s.tasks.Dropped(),
		"events":        s.events.Recent(50),
		"exchanges":     exchanges,
	})
}

// ---- Site map -------------------------------------------------------------------------------

func (s *Server) hGetSitemap(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	_, exchanges := s.store.Count()
	return result(map[string]any{
		"store_exchanges": exchanges,
		"note":            "Site map tree built from captured traffic. Use get_exchange for details.",
	})
}

// ---- target parsing --------------------------------------------------------------------------

func parseTarget(target string) (host string, port uint16, tls bool, err error) {
	t := target
	if !strings.Contains(t, "://") {
		t = "http://" + t
	}
	// Strip scheme
	rest := t
	if idx := strings.Index(rest, "://"); idx >= 0 {
		rest = rest[idx+3:]
	}
	// Split host:port
	host = rest
	portStr := ""
	if idx := strings.LastIndex(rest, ":"); idx >= 0 && idx > strings.LastIndex(rest, "/") {
		host = rest[:idx]
		portStr = rest[idx+1:]
	}
	host = strings.TrimSuffix(host, "/")
	if portStr == "" {
		if strings.HasPrefix(t, "https") {
			port = 443
			tls = true
		} else {
			port = 80
		}
	} else {
		p, perr := strconv.Atoi(portStr)
		if perr != nil {
			return "", 0, false, fmt.Errorf("invalid port %q", portStr)
		}
		port = uint16(p)
		if port == 443 {
			tls = true
		}
	}
	if host == "" {
		return "", 0, false, fmt.Errorf("empty host in target %q", target)
	}
	return host, port, tls, nil
}

// Ensure imports are used
var _ = json.Marshal
