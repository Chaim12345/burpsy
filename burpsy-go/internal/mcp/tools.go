package mcp

import (
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// registerTools adds every burpsy tool to the MCP server.
func (s *Server) registerTools() {
	tools := []struct {
		name string
		desc string
		opts []mcp.ToolOption
		h    server.ToolHandlerFunc
	}{
		{
			"list_history",
			"List captured HTTP traffic exchanges, newest first. Use to see what traffic has been proxied through burpsy. Optional 'limit' caps results (default 100, max 1000). Optional 'query' filters using burpsy-query DSL (e.g., 'host = example.com AND status >= 400').",
			[]mcp.ToolOption{
				mcp.WithNumber("limit", mcp.Description("Max results to return (default 100)")),
				mcp.WithString("query", mcp.Description("burpsy-query filter")),
			},
			s.hListHistory,
		},
		{
			"get_exchange",
			"Get full details of one captured exchange by its ID. Use after list_history to inspect a specific request.",
			[]mcp.ToolOption{
				mcp.WithNumber("id", mcp.Description("Exchange ID"), mcp.Required()),
			},
			s.hGetExchange,
		},
		{
			"get_message",
			"Get the raw stored request or response message by its message ID.",
			[]mcp.ToolOption{
				mcp.WithNumber("id", mcp.Description("Message ID"), mcp.Required()),
			},
			s.hGetMessage,
		},
		{
			"get_stats",
			"Get capture store statistics: total exchanges, messages, and stored bytes.",
			nil,
			s.hGetStats,
		},
		{
			"get_scope",
			"Get current engagement scope rules (include/exclude patterns) and whether the scope is empty (allow-all).",
			nil,
			s.hGetScope,
		},
		{
			"modify_scope",
			"Add, remove, or clear scope rules. Action: include, exclude, remove, clear. Pattern is a host glob like '*.example.com'.",
			[]mcp.ToolOption{
				mcp.WithString("action", mcp.Description("include, exclude, remove, or clear"), mcp.Required()),
				mcp.WithString("pattern", mcp.Description("Host glob pattern (e.g., '*.example.com')")),
			},
			s.hModifyScope,
		},
		{
			"list_issues",
			"List all findings discovered so far with severity and confidence. Includes passive and active audit results.",
			nil,
			s.hListIssues,
		},
		{
			"run_audit",
			"Run an active vulnerability scan on one captured exchange by ID. Sends real requests — scope is enforced. Returns findings and a breakdown. Optional 'config' names a built-in scan configuration.",
			[]mcp.ToolOption{
				mcp.WithNumber("id", mcp.Description("Exchange ID to audit"), mcp.Required()),
				mcp.WithString("config", mcp.Description("Built-in scan config name (optional)")),
			},
			s.hRunAudit,
		},
		{
			"get_coverage",
			"Get passive check runtime coverage: which checks loaded, which ran, which were skipped and why.",
			nil,
			s.hGetCoverage,
		},
		{
			"list_scan_configs",
			"List built-in scan configurations that burpsy implements. Use to find config names for run_audit.",
			nil,
			s.hListScanConfigs,
		},
		{
			"send_request",
			"Send a raw HTTP request to a target and capture the response. 'target' is host:port, 'request' is raw HTTP bytes. 'protocol' is 'http' or 'https'. Scope-enforced. Returns status, headers, body, duration.",
			[]mcp.ToolOption{
				mcp.WithString("target", mcp.Description("Target host:port"), mcp.Required()),
				mcp.WithString("request", mcp.Description("Raw HTTP request bytes"), mcp.Required()),
				mcp.WithString("protocol", mcp.Description("'http' or 'https' (optional)")),
			},
			s.hSendRequest,
		},
		{
			"run_attack",
			"Run an intruder attack against a target using a captured request as a template. 'msg_id' is the base request, 'mode' is sniper/battering_ram/pitchfork/cluster_bomb, 'payloads' is a list of strings.",
			[]mcp.ToolOption{
				mcp.WithNumber("msg_id", mcp.Description("Message ID of base request"), mcp.Required()),
				mcp.WithString("target", mcp.Description("Target host:port"), mcp.Required()),
				mcp.WithString("mode", mcp.Description("sniper, battering_ram, pitchfork, cluster_bomb"), mcp.Required()),
				mcp.WithArray("payloads", mcp.Description("Payload list"), mcp.WithStringItems()),
			},
			s.hRunAttack,
		},
		{
			"send_h2_program",
			"Authorise and send a deliberately malformed HTTP/2 frame program for request-smuggling research. Returns audit violations and target response.",
			[]mcp.ToolOption{
				mcp.WithString("host", mcp.Description("Target host"), mcp.Required()),
				mcp.WithNumber("port", mcp.Description("Target port")),
				mcp.WithBoolean("tls", mcp.Description("Use TLS")),
				mcp.WithArray("frames", mcp.Description("Frame list (type, flags, stream_id, payload_b64)")),
			},
			s.hSendH2Program,
		},
		{
			"get_protocols",
			"Report what protocol (HTTP/1.1 or HTTP/2) carried each tool's sends, and why any downgrades happened.",
			nil,
			s.hGetProtocols,
		},
		{
			"transform",
			"Decode, encode, hash, or compare data. Operation: decode, encode, hash, compare. Encodings: url, html, base64, hex, jwt. Hash algorithms: md5, sha1, sha256, sha512. Compare takes two inputs 'a' and 'b'.",
			[]mcp.ToolOption{
				mcp.WithString("operation", mcp.Description("decode, encode, hash, or compare"), mcp.Required()),
				mcp.WithString("input", mcp.Description("Input data (for decode/encode/hash)")),
				mcp.WithString("encoding", mcp.Description("url, html, base64, hex, jwt")),
				mcp.WithString("algorithm", mcp.Description("md5, sha1, sha256, sha512")),
				mcp.WithString("a", mcp.Description("First input (for compare)")),
				mcp.WithString("b", mcp.Description("Second input (for compare)")),
			},
			s.hTransform,
		},
		{
			"export_report",
			"Export findings as a report. Format: html, json, or sarif.",
			[]mcp.ToolOption{
				mcp.WithString("format", mcp.Description("html, json, or sarif"), mcp.Required()),
			},
			s.hExportReport,
		},
		{
			"get_dashboard",
			"Get the full dashboard state: running tasks, activity log, event log, and summary counts.",
			nil,
			s.hGetDashboard,
		},
		{
			"get_sitemap",
			"Get the aggregated site map built from captured traffic. Optional 'host' or 'path' filters.",
			[]mcp.ToolOption{
				mcp.WithString("host", mcp.Description("Filter by host")),
				mcp.WithString("path", mcp.Description("Filter by path prefix")),
			},
			s.hGetSitemap,
		},
	}

	for _, t := range tools {
		opts := append([]mcp.ToolOption{mcp.WithDescription(t.desc)}, t.opts...)
		s.mcp.AddTool(mcp.NewTool(t.name, opts...), t.h)
	}
}
