// Package mcpscan tests a Model Context Protocol server as a target (burpsy-react-ui-wflj): it
// performs the MCP handshake, enumerates every tool, resource and prompt the server exposes, probes
// each tool with a representative call, and runs the MCP-specific checks — the surface that barely
// existed a year ago and that an AI agent's MCP servers now present to anyone who can reach them.
//
// This package is the protocol and the checks; it is free of burpsy's sender and scope the way the
// session package is, through a Transport seam the web layer binds to the authorised sender. Only the
// Streamable-HTTP transport is modelled here (a networked endpoint that answers JSON-RPC over POST) —
// a stdio MCP server is a local subprocess, not a network target, and is out of this scanner's scope.
//
// The classification vocabulary deliberately echoes burpsy's own route risk classes: a target
// server's tools are read the same way burpsy reads its own routes — what can this call do, and what
// does it expose — because that framing is exactly what an MCP target audit needs.
package mcpscan

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// protocolVersion is the MCP revision this client announces. A server that speaks a different one
// still answers initialize (the field is advisory), so this is the version burpsy was written to, not
// a gate.
const protocolVersion = "2025-06-18"

// Tool, Resource and Prompt are the three enumerable surfaces an MCP server exposes.
type Tool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
}

type Resource struct {
	URI         string `json:"uri"`
	Name        string `json:"name"`
	Description string `json:"description"`
	MimeType    string `json:"mimeType"`
}

type Prompt struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// ServerInfo is what initialize reports about the server.
type ServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Enumeration is everything a scan read off a server.
type Enumeration struct {
	Server    ServerInfo
	Tools     []Tool
	Resources []Resource
	Prompts   []Prompt
	// Probes records each representative tools/call the scan made and whether the server reported an
	// error, so a finding about a reachable tool can point at the call that reached it.
	Probes []Probe
	// Authenticated is whether the transport carried any credential. A server enumerated without one
	// is exposed unauthenticated, which is a finding in itself.
	Authenticated bool
}

// Probe is one representative tool call and its outcome.
type Probe struct {
	Tool    string
	IsError bool
	// Excerpt is a bounded slice of the response content, so a finding shows what came back without
	// copying a whole document.
	Excerpt string
}

// Transport sends one JSON-RPC request to the server and returns the raw `result` (or an error for a
// transport failure or a JSON-RPC error object). The web layer binds this to the authorised sender; a
// test binds it to an in-process server. method is the JSON-RPC method, params its params object.
type Transport func(ctx context.Context, method string, params any) (json.RawMessage, error)

// Client speaks MCP over a Transport.
type Client struct {
	t             Transport
	authenticated bool
}

// NewClient wraps a transport. authenticated says whether that transport carries a credential, which
// the enumeration records so an unauthenticated-exposure check can fire.
func NewClient(t Transport, authenticated bool) *Client {
	return &Client{t: t, authenticated: authenticated}
}

// Enumerate runs the handshake and lists every surface. A server that refuses initialize is a hard
// error (there is nothing to scan); a server that refuses one of the list calls is not — a server may
// expose tools but no prompts — so those failures leave the slice empty and the scan goes on.
func (c *Client) Enumerate(ctx context.Context) (*Enumeration, error) {
	en := &Enumeration{Authenticated: c.authenticated}

	initRes, err := c.t(ctx, "initialize", map[string]any{
		"protocolVersion": protocolVersion,
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "burpsy", "version": "scan"},
	})
	if err != nil {
		return nil, fmt.Errorf("MCP initialize failed: %w", err)
	}
	var initParsed struct {
		ServerInfo ServerInfo `json:"serverInfo"`
	}
	_ = json.Unmarshal(initRes, &initParsed)
	en.Server = initParsed.ServerInfo

	if res, err := c.t(ctx, "tools/list", map[string]any{}); err == nil {
		var parsed struct {
			Tools []Tool `json:"tools"`
		}
		if json.Unmarshal(res, &parsed) == nil {
			en.Tools = parsed.Tools
		}
	}
	if res, err := c.t(ctx, "resources/list", map[string]any{}); err == nil {
		var parsed struct {
			Resources []Resource `json:"resources"`
		}
		if json.Unmarshal(res, &parsed) == nil {
			en.Resources = parsed.Resources
		}
	}
	if res, err := c.t(ctx, "prompts/list", map[string]any{}); err == nil {
		var parsed struct {
			Prompts []Prompt `json:"prompts"`
		}
		if json.Unmarshal(res, &parsed) == nil {
			en.Prompts = parsed.Prompts
		}
	}
	return en, nil
}

// maxProbes bounds how many tools a scan will call, so pointing burpsy at a server with hundreds of
// tools is not itself a flood. The most-interesting tools (by the dangerous-capability heuristic) are
// probed first.
const maxProbes = 20

// Probe sends a representative tools/call to each tool, in dangerous-first order, up to maxProbes. The
// arguments are an empty object: the goal is to see whether the tool is reachable and what it says
// back (an error naming an internal host, a reflected argument), not to drive it with real input —
// that would be sending attacker-chosen data to a tool whose effect the scanner cannot predict.
func (c *Client) Probe(ctx context.Context, en *Enumeration) {
	order := make([]Tool, len(en.Tools))
	copy(order, en.Tools)
	// Dangerous-capability tools first, so the bound spends its budget where a finding is likeliest.
	sortByDanger(order)
	n := 0
	for _, tool := range order {
		if n >= maxProbes {
			break
		}
		n++
		res, err := c.t(ctx, "tools/call", map[string]any{"name": tool.Name, "arguments": map[string]any{}})
		p := Probe{Tool: tool.Name}
		if err != nil {
			p.IsError = true
			p.Excerpt = excerpt(err.Error())
		} else {
			var parsed struct {
				IsError bool              `json:"isError"`
				Content []json.RawMessage `json:"content"`
			}
			_ = json.Unmarshal(res, &parsed)
			p.IsError = parsed.IsError
			if len(parsed.Content) > 0 {
				p.Excerpt = excerpt(string(parsed.Content[0]))
			} else {
				p.Excerpt = excerpt(string(res))
			}
		}
		en.Probes = append(en.Probes, p)
	}
}

func excerpt(s string) string {
	const max = 200
	s = strings.TrimSpace(s)
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}
