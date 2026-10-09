package mcp

// Skills as MCP prompts (burpsy-react-ui-ulsy).
//
// The console's skill library (burpsy -skills DIR, GET /api/skills) is published as MCP prompts:
// prompts/list offers every skill that is available and not disabled for the project, and prompts/get
// renders one, prefixed with a banner naming the tools the skill calls — so the model, and the operator
// reading the transcript, see what the technique will reach for before it runs. A skill naming a tool
// this surface does not publish says so in the banner rather than pointing at nothing.
//
// The transport reads nothing from disk; every answer comes from the console. A console that cannot be
// reached is a JSON-RPC error, never an empty list — "no skills" and "could not ask" are different
// answers.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

type promptsCapability struct {
	ListChanged bool `json:"listChanged"`
}

type skillListing struct {
	Configured bool `json:"configured"`
	Skills     []struct {
		Name        string   `json:"name"`
		Description string   `json:"description"`
		Tools       []string `json:"tools"`
		Arguments   []struct {
			Name        string `json:"name"`
			Description string `json:"description"`
			Required    bool   `json:"required"`
		} `json:"arguments"`
		Available bool `json:"available"`
		Disabled  bool `json:"disabled"`
	} `json:"skills"`
}

// banner names the tools a skill calls, flagging any this surface does not publish.
func (s *Server) banner(name, description string, tools []string) string {
	named := make([]string, 0, len(tools))
	for _, t := range tools {
		if _, ok := s.byName[t]; ok {
			named = append(named, t)
		} else {
			named = append(named, t+" (not a tool on this surface)")
		}
	}
	calls := "no tools named"
	if len(named) > 0 {
		calls = strings.Join(named, ", ")
	}
	return fmt.Sprintf("[burpsy skill %s] %s\nTools this skill calls: %s\n", name, description, calls)
}

func (s *Server) listPrompts(ctx context.Context, req request) response {
	var lib skillListing
	if err := s.getJSON(ctx, "/api/skills", &lib); err != nil {
		return s.fail(req, codeInternalError, "could not read the skill library from the console at %s: %v", s.baseURL, err)
	}
	prompts := []map[string]any{}
	for _, sk := range lib.Skills {
		if !sk.Available || sk.Disabled {
			continue
		}
		args := []map[string]any{}
		for _, a := range sk.Arguments {
			args = append(args, map[string]any{"name": a.Name, "description": a.Description, "required": a.Required})
		}
		prompts = append(prompts, map[string]any{
			"name":        sk.Name,
			"description": strings.TrimSpace(s.banner(sk.Name, sk.Description, sk.Tools)),
			"arguments":   args,
		})
	}
	return s.ok(req, map[string]any{"prompts": prompts})
}

func (s *Server) getPrompt(ctx context.Context, req request) response {
	var p struct {
		Name      string            `json:"name"`
		Arguments map[string]string `json:"arguments"`
	}
	if r := s.parseParams(req, &p); r != nil {
		return *r
	}
	if strings.TrimSpace(p.Name) == "" {
		return s.fail(req, codeInvalidParams, "prompts/get requires a name")
	}
	q := url.Values{}
	for k, v := range p.Arguments {
		q.Set(k, v)
	}
	target := s.baseURL + "/api/skills/" + url.PathEscape(p.Name)
	if len(q) > 0 {
		target += "?" + q.Encode()
	}
	hreq, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return s.fail(req, codeInternalError, "%v", err)
	}
	resp, err := s.http.Do(hreq)
	if err != nil {
		return s.fail(req, codeInternalError, "could not reach the burpsy console at %s: %v", s.baseURL, err)
	}
	defer resp.Body.Close()
	raw, _, err := readCapped(resp.Body, maxResultBytes)
	if err != nil {
		return s.fail(req, codeInternalError, "%v", err)
	}
	if resp.StatusCode != http.StatusOK {
		// Unknown, disabled, unavailable or a bad argument: the console's own words.
		return s.fail(req, codeInvalidParams, "skill %s: HTTP %d: %s", p.Name, resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var sk struct {
		Name        string   `json:"name"`
		Description string   `json:"description"`
		Tools       []string `json:"tools"`
		Prompt      string   `json:"prompt"`
	}
	if err := json.Unmarshal(raw, &sk); err != nil {
		return s.fail(req, codeInternalError, "the console's skill answer did not parse: %v", err)
	}
	return s.ok(req, map[string]any{
		"description": sk.Description,
		"messages": []map[string]any{{
			"role":    "user",
			"content": map[string]any{"type": "text", "text": s.banner(sk.Name, sk.Description, sk.Tools) + "\n" + sk.Prompt},
		}},
	})
}
