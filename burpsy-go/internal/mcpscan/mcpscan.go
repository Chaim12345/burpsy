// Package mcpscan tests a Model Context Protocol server as a target (burpsy-react-ui-wflj): it performs
// the MCP handshake, enumerates every tool, resource and prompt the server exposes, optionally calls
// the tools the operator names, and runs the MCP-specific checks over what came back.
//
// This package is the protocol and the checks. It is free of burpsy's sender and scope through the
// Transport seam, which the web layer binds to sender.AuthorisedSender so every JSON-RPC message is
// authorised against the engagement scope on the bytes actually written. Only the Streamable-HTTP
// transport is modelled (a networked endpoint answering JSON-RPC over POST). A stdio MCP server is a
// local subprocess rather than a network target, and the deprecated HTTP+SSE transport (2024-11-05) is
// not spoken; both are out of this scanner's reach and the web layer says so rather than reporting an
// empty server.
//
// # What it will and will not send
//
// Enumeration is read-only by the protocol's own definition: initialize, the initialized
// notification, and the three list methods (paginated, bounded by maxListPages and maxListItems).
// tools/call is NOT read-only — a tool's effect is whatever its author made it, and nothing the
// server says about a tool (including its readOnlyHint annotation, which the MCP specification itself
// calls untrusted) makes it safe to invoke blind. So no tool is called unless the operator names it,
// and at most maxProbes are called per scan. Every bound that stopped the scan short is reported on
// the Enumeration rather than leaving a short list to read as a complete one.
package mcpscan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

// ProtocolVersion is the MCP revision this client announces. A server may answer with another one;
// the negotiated version is recorded on the Enumeration and the web transport echoes it in the
// MCP-Protocol-Version header the 2025-06-18 revision requires on every later request.
const ProtocolVersion = "2025-06-18"

// Bounds. Each one that binds is reported (ListOutcome.Truncated, ProbeSkip), never silent.
const (
	// maxListPages bounds how many pages of one list method a scan follows.
	maxListPages = 10
	// maxListItems bounds how many items of one kind a scan keeps.
	maxListItems = 1000
	// MaxProbes bounds how many tools one scan may call.
	MaxProbes = 20
	// excerptRunes bounds a probe excerpt.
	excerptRunes = 200
)

// Transport carries JSON-RPC messages to the server.
type Transport interface {
	// Call sends one request and returns its `result`, or an error for a transport failure, a non-2xx
	// HTTP status (as *HTTPStatusError) or a JSON-RPC error object (as *RPCError).
	Call(ctx context.Context, method string, params any) (json.RawMessage, error)
	// Notify sends one notification, which has no id and expects no result.
	Notify(ctx context.Context, method string, params any) error
}

// HTTPStatusError is a non-2xx HTTP answer to a JSON-RPC message.
type HTTPStatusError struct {
	Status int
	// Authenticate is the WWW-Authenticate header, when the server sent one.
	Authenticate string
}

func (e *HTTPStatusError) Error() string {
	if e.Authenticate != "" {
		return fmt.Sprintf("the server answered HTTP %d (WWW-Authenticate: %s)", e.Status, e.Authenticate)
	}
	return fmt.Sprintf("the server answered HTTP %d", e.Status)
}

// RPCError is a JSON-RPC error object.
type RPCError struct {
	Code    int
	Message string
}

func (e *RPCError) Error() string { return fmt.Sprintf("JSON-RPC error %d: %s", e.Code, e.Message) }

// StatusOf returns the HTTP status an error carries, 0 when it carries none.
func StatusOf(err error) int {
	var he *HTTPStatusError
	if errors.As(err, &he) {
		return he.Status
	}
	return 0
}

// Tool, Resource and Prompt are the three enumerable surfaces an MCP server exposes.
type Tool struct {
	Name        string           `json:"name"`
	Title       string           `json:"title,omitempty"`
	Description string           `json:"description"`
	InputSchema json.RawMessage  `json:"inputSchema,omitempty"`
	Annotations *ToolAnnotations `json:"annotations,omitempty"`
}

// ToolAnnotations are the server's own hints about a tool. Recorded for the operator; never used to
// decide whether calling the tool is safe, because the server is the party being tested.
type ToolAnnotations struct {
	ReadOnlyHint    *bool `json:"readOnlyHint,omitempty"`
	DestructiveHint *bool `json:"destructiveHint,omitempty"`
	IdempotentHint  *bool `json:"idempotentHint,omitempty"`
	OpenWorldHint   *bool `json:"openWorldHint,omitempty"`
}

type Resource struct {
	URI         string `json:"uri"`
	Name        string `json:"name"`
	Description string `json:"description"`
	MimeType    string `json:"mimeType,omitempty"`
}

type Prompt struct {
	Name        string           `json:"name"`
	Description string           `json:"description"`
	Arguments   []PromptArgument `json:"arguments,omitempty"`
}

type PromptArgument struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Required    bool   `json:"required,omitempty"`
}

// ServerInfo is what initialize reports about the server.
type ServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// List states.
const (
	ListOK            = "ok"
	ListPartial       = "partial"        // some pages arrived, then a page failed
	ListFailed        = "failed"         // the first page failed
	ListNotAdvertised = "not_advertised" // the server's capabilities omit this surface; not requested
)

// ListOutcome is what happened to one list method. Kept per method because "the server has no
// prompts" and "prompts/list failed" are different facts that an empty slice cannot tell apart.
type ListOutcome struct {
	Method    string `json:"method"`
	State     string `json:"state"`
	Pages     int    `json:"pages"`
	Items     int    `json:"items"`
	Truncated bool   `json:"truncated,omitempty"`
	Error     string `json:"error,omitempty"`
	Note      string `json:"note,omitempty"`
}

// Enumeration is everything a scan read off a server.
type Enumeration struct {
	Server          ServerInfo
	ProtocolVersion string
	// Instructions is initialize's free-text `instructions`, which a client feeds to its model.
	Instructions string
	Tools        []Tool
	Resources    []Resource
	Prompts      []Prompt
	Lists        []ListOutcome
	Probes       []Probe
	ProbeSkipped []ProbeSkip
	// Authenticated is whether the scan's transport carried an operator-supplied credential.
	Authenticated bool
	// AuthCheck is the result of repeating the handshake without that credential; nil when the scan
	// carried none (it then IS the unauthenticated view) or the check was not run.
	AuthCheck *AuthCheck
}

// Probe is one operator-requested tools/call and its outcome.
type Probe struct {
	Tool string `json:"tool"`
	// Outcome: "ok" (a result), "tool_error" (a result with isError), "call_failed" (no result).
	Outcome string `json:"outcome"`
	Excerpt string `json:"excerpt,omitempty"`
}

// ProbeSkip is a tool the operator asked to call that was not called, and why.
type ProbeSkip struct {
	Tool   string `json:"tool"`
	Reason string `json:"reason"`
}

// Client speaks MCP over a Transport.
type Client struct {
	t             Transport
	authenticated bool
}

// NewClient wraps a transport. authenticated says whether that transport carries a credential.
func NewClient(t Transport, authenticated bool) *Client {
	return &Client{t: t, authenticated: authenticated}
}

type initResult struct {
	ProtocolVersion string                     `json:"protocolVersion"`
	ServerInfo      ServerInfo                 `json:"serverInfo"`
	Capabilities    map[string]json.RawMessage `json:"capabilities"`
	Instructions    string                     `json:"instructions"`
}

// handshake runs initialize and the initialized notification.
func handshake(ctx context.Context, t Transport) (initResult, error) {
	var ir initResult
	res, err := t.Call(ctx, "initialize", map[string]any{
		"protocolVersion": ProtocolVersion,
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "burpsy", "version": "mcpscan"},
	})
	if err != nil {
		return ir, err
	}
	if err := json.Unmarshal(res, &ir); err != nil {
		return ir, fmt.Errorf("the initialize result is not an MCP InitializeResult: %w", err)
	}
	// A notification failure is not fatal: some servers answer it with a status this client does not
	// expect, and the lists that follow say whether the session is usable.
	_ = t.Notify(ctx, "notifications/initialized", map[string]any{})
	return ir, nil
}

// Enumerate runs the handshake and lists every advertised surface. A server that refuses initialize
// is a hard error (there is nothing to scan); a list that fails is recorded in Lists and the scan goes
// on, because a server may serve tools and fail prompts.
func (c *Client) Enumerate(ctx context.Context) (*Enumeration, error) {
	ir, err := handshake(ctx, c.t)
	if err != nil {
		return nil, fmt.Errorf("MCP initialize failed: %w", err)
	}
	en := &Enumeration{
		Authenticated:   c.authenticated,
		Server:          ir.ServerInfo,
		ProtocolVersion: ir.ProtocolVersion,
		Instructions:    ir.Instructions,
	}
	advertised := func(capability string) bool {
		// A server that sent no capabilities object at all is asked anyway: the omission says
		// nothing, and the list call is read-only.
		if ir.Capabilities == nil {
			return true
		}
		_, ok := ir.Capabilities[capability]
		return ok
	}
	en.Lists = append(en.Lists,
		listAll(ctx, c.t, advertised("tools"), "tools/list", "tools", &en.Tools),
		listAll(ctx, c.t, advertised("resources"), "resources/list", "resources", &en.Resources),
		listAll(ctx, c.t, advertised("prompts"), "prompts/list", "prompts", &en.Prompts),
	)
	return en, nil
}

// listAll follows one list method's cursor, bounded, into out.
func listAll[T any](ctx context.Context, t Transport, advertised bool, method, key string, out *[]T) ListOutcome {
	lo := ListOutcome{Method: method, State: ListOK}
	if !advertised {
		lo.State = ListNotAdvertised
		lo.Note = "the server's initialize capabilities do not include this surface, so it was not requested"
		return lo
	}
	fail := func(err error) {
		if lo.Pages == 0 {
			lo.State = ListFailed
		} else {
			lo.State = ListPartial
		}
		lo.Error = err.Error()
	}
	cursor := ""
	seen := map[string]bool{}
	for {
		if lo.Pages >= maxListPages {
			lo.Truncated = true
			lo.Note = fmt.Sprintf("stopped after %d pages; the server offered more", maxListPages)
			break
		}
		params := map[string]any{}
		if cursor != "" {
			params["cursor"] = cursor
		}
		res, err := t.Call(ctx, method, params)
		if err != nil {
			fail(err)
			break
		}
		var page map[string]json.RawMessage
		if err := json.Unmarshal(res, &page); err != nil {
			fail(fmt.Errorf("the result is not a JSON object: %w", err))
			break
		}
		raw, ok := page[key]
		if !ok {
			fail(fmt.Errorf("the result has no %q member", key))
			break
		}
		var items []T
		if err := json.Unmarshal(raw, &items); err != nil {
			fail(fmt.Errorf("the %q member is malformed: %w", key, err))
			break
		}
		lo.Pages++
		for _, it := range items {
			if len(*out) >= maxListItems {
				lo.Truncated = true
				lo.Note = fmt.Sprintf("stopped at %d items", maxListItems)
				lo.Items = len(*out)
				return lo
			}
			*out = append(*out, it)
		}
		var next string
		if v, ok := page["nextCursor"]; ok {
			_ = json.Unmarshal(v, &next)
		}
		if next == "" {
			break
		}
		if seen[next] {
			lo.Truncated = true
			lo.Note = "the server repeated a pagination cursor, so listing stopped there"
			break
		}
		seen[next] = true
		cursor = next
	}
	lo.Items = len(*out)
	return lo
}

// Probe calls each tool the operator named, in the order named, with an empty arguments object, up to
// MaxProbes. A name the enumeration did not list, a repeat, and anything past the bound are recorded
// in ProbeSkipped rather than sent. The empty arguments are deliberate: the point is what the tool
// says back when reached (an error naming an internal host, a stack trace), not driving it with input
// whose effect the scanner cannot predict.
func (c *Client) Probe(ctx context.Context, en *Enumeration, names []string) {
	known := make(map[string]bool, len(en.Tools))
	for _, t := range en.Tools {
		known[t.Name] = true
	}
	done := map[string]bool{}
	for _, name := range names {
		switch {
		case done[name]:
			continue
		case !known[name]:
			en.ProbeSkipped = append(en.ProbeSkipped, ProbeSkip{Tool: name, Reason: "not in the server's enumerated tool list"})
			done[name] = true
			continue
		case len(en.Probes) >= MaxProbes:
			en.ProbeSkipped = append(en.ProbeSkipped, ProbeSkip{Tool: name, Reason: fmt.Sprintf("over the per-scan bound of %d tool calls", MaxProbes)})
			done[name] = true
			continue
		}
		done[name] = true
		res, err := c.t.Call(ctx, "tools/call", map[string]any{"name": name, "arguments": map[string]any{}})
		p := Probe{Tool: name, Outcome: "ok"}
		if err != nil {
			p.Outcome = "call_failed"
			p.Excerpt = excerpt(err.Error())
		} else {
			var parsed struct {
				IsError bool `json:"isError"`
				Content []struct {
					Type string `json:"type"`
					Text string `json:"text"`
				} `json:"content"`
			}
			_ = json.Unmarshal(res, &parsed)
			if parsed.IsError {
				p.Outcome = "tool_error"
			}
			var texts []string
			for _, item := range parsed.Content {
				if item.Type == "text" && item.Text != "" {
					texts = append(texts, item.Text)
				}
			}
			if len(texts) > 0 {
				p.Excerpt = excerpt(strings.Join(texts, "\n"))
			} else {
				p.Excerpt = excerpt(string(res))
			}
		}
		en.Probes = append(en.Probes, p)
	}
}

// Auth-check states.
const (
	AuthEnforced     = "enforced"
	AuthNotEnforced  = "not_enforced"
	AuthInconclusive = "inconclusive"
)

// AuthCheck is the outcome of repeating the handshake and the first tools/list page without the
// operator's credential.
type AuthCheck struct {
	State       string `json:"state"`
	Detail      string `json:"detail"`
	ToolsListed int    `json:"tools_listed,omitempty"`
}

// CheckAuthEnforced repeats initialize and the first tools/list page over a transport that carries no
// credential. Only a 401 or 403 counts as enforcement; any other failure is inconclusive, because a
// timeout says nothing about whether the server would have refused.
func CheckAuthEnforced(ctx context.Context, t Transport) AuthCheck {
	if _, err := handshake(ctx, t); err != nil {
		if s := StatusOf(err); s == 401 || s == 403 {
			return AuthCheck{State: AuthEnforced, Detail: "initialize without the credential was refused: " + err.Error()}
		}
		return AuthCheck{State: AuthInconclusive, Detail: "initialize without the credential failed for a reason other than authentication: " + err.Error()}
	}
	res, err := t.Call(ctx, "tools/list", map[string]any{})
	if err != nil {
		if s := StatusOf(err); s == 401 || s == 403 {
			return AuthCheck{State: AuthEnforced, Detail: "the handshake succeeded without the credential, but tools/list was refused: " + err.Error()}
		}
		return AuthCheck{State: AuthInconclusive, Detail: "tools/list without the credential failed for a reason other than authentication: " + err.Error()}
	}
	var parsed struct {
		Tools []json.RawMessage `json:"tools"`
	}
	if err := json.Unmarshal(res, &parsed); err != nil {
		return AuthCheck{State: AuthInconclusive, Detail: "tools/list without the credential returned something that is not a tool list"}
	}
	return AuthCheck{State: AuthNotEnforced, ToolsListed: len(parsed.Tools),
		Detail: fmt.Sprintf("without the credential the server completed the handshake and listed %d tool(s) on the first page", len(parsed.Tools))}
}

// excerpt bounds s to excerptRunes runes without splitting a UTF-8 sequence.
func excerpt(s string) string {
	s = strings.TrimSpace(s)
	if utf8.RuneCountInString(s) <= excerptRunes {
		return s
	}
	r := []rune(s)
	return string(r[:excerptRunes]) + "…"
}
