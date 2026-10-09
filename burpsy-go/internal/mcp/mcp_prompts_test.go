package mcp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/skills"
	"github.com/burpsy-go/burpsy/internal/web"
)

// burpsy-react-ui-ulsy: the skill library as MCP prompts, through stdio against a real console.

func skillsConsole(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range map[string]string{
		"a.json": `{"name":"jwt-none","description":"Try alg=none on a captured JWT","tools":["history","send","nope_tool"],"arguments":[{"name":"exchange_id","description":"the exchange","required":true}],"prompt":"Read exchange {{exchange_id}} with history, then resend it with alg none using send."}`,
		"b.json": `{"name":"scripted","description":"Needs a runtime","prompt":"x","script":"run.js"}`,
		"c.json": `{"name":"recon","description":"Map the site","tools":["sitemap"],"prompt":"Walk the site map."}`,
	} {
		os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600)
	}
	lib, err := skills.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	srv := web.NewServer(core.NewTrafficStore(), core.NewScope()).WithSkills(lib)
	ts := httptest.NewServer(srv.MCPGuarded())
	t.Cleanup(ts.Close)
	return ts.URL
}

func TestSkillsArePublishedAsPrompts(t *testing.T) {
	base := skillsConsole(t)
	replies := askGrouped(t, base,
		rpcRequest(t, 1, "initialize", map[string]any{}),
		rpcRequest(t, 2, "prompts/list", nil),
		rpcRequest(t, 3, "prompts/get", map[string]any{"name": "jwt-none", "arguments": map[string]string{"exchange_id": "12"}}),
		rpcRequest(t, 4, "prompts/get", map[string]any{"name": "jwt-none"}),
		rpcRequest(t, 5, "prompts/get", map[string]any{"name": "scripted"}),
	)
	byID := map[string]rpcReply{}
	for _, r := range replies {
		byID[string(r.ID)] = r
	}
	if !strings.Contains(string(byID["1"].Result), `"prompts":{"listChanged":false}`) {
		t.Fatalf("initialize does not advertise prompts: %s", byID["1"].Result)
	}
	var list struct {
		Prompts []struct {
			Name        string `json:"name"`
			Description string `json:"description"`
			Arguments   []struct {
				Name     string `json:"name"`
				Required bool   `json:"required"`
			} `json:"arguments"`
		} `json:"prompts"`
	}
	json.Unmarshal(byID["2"].Result, &list)
	if len(list.Prompts) != 2 || list.Prompts[0].Name != "jwt-none" || list.Prompts[1].Name != "recon" {
		t.Fatalf("prompts/list: %s", byID["2"].Result)
	}
	if !strings.Contains(list.Prompts[0].Description, "Tools this skill calls: history, send, nope_tool (not a tool on this surface)") {
		t.Fatalf("the banner does not name the tools: %q", list.Prompts[0].Description)
	}
	if len(list.Prompts[0].Arguments) != 1 || !list.Prompts[0].Arguments[0].Required {
		t.Fatalf("arguments: %+v", list.Prompts[0].Arguments)
	}
	var got struct {
		Messages []struct {
			Role    string `json:"role"`
			Content struct {
				Type, Text string
			} `json:"content"`
		} `json:"messages"`
	}
	json.Unmarshal(byID["3"].Result, &got)
	if len(got.Messages) != 1 || got.Messages[0].Role != "user" ||
		!strings.HasPrefix(got.Messages[0].Content.Text, "[burpsy skill jwt-none]") ||
		!strings.HasSuffix(got.Messages[0].Content.Text, "Read exchange 12 with history, then resend it with alg none using send.") {
		t.Fatalf("prompts/get: %s", byID["3"].Result)
	}
	if byID["4"].Error == nil || !strings.Contains(byID["4"].Error.Message, "exchange_id") {
		t.Fatalf("a missing required argument rendered: %+v", byID["4"])
	}
	if byID["5"].Error == nil || !strings.Contains(byID["5"].Error.Message, "unavailable") {
		t.Fatalf("an unavailable skill rendered: %+v", byID["5"])
	}
}

func TestADisabledSkillIsAbsentFromPrompts(t *testing.T) {
	base := skillsConsole(t)
	req, _ := http.NewRequest(http.MethodPut, base+"/api/skills/disabled", strings.NewReader(`{"disabled":["recon"]}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("disable: %v %v", err, resp)
	}
	resp.Body.Close()
	replies := askGrouped(t, base, rpcRequest(t, 1, "prompts/list", nil), rpcRequest(t, 2, "prompts/get", map[string]any{"name": "recon"}))
	if strings.Contains(string(replies[0].Result), `"recon"`) {
		t.Fatalf("a disabled skill is still listed: %s", replies[0].Result)
	}
	if replies[1].Error == nil || !strings.Contains(replies[1].Error.Message, "disabled") {
		t.Fatalf("a disabled skill rendered: %+v", replies[1])
	}
	// No library: an empty array, not null.
	_, plain := newConsole(t)
	replies = askGrouped(t, plain, rpcRequest(t, 1, "prompts/list", nil))
	if string(replies[0].Result) != `{"prompts":[]}` {
		t.Fatalf("no library: %s", replies[0].Result)
	}
}

func TestAnUnreachableConsoleIsAnErrorNotAnEmptyPromptList(t *testing.T) {
	replies := askGrouped(t, "http://127.0.0.1:1", rpcRequest(t, 1, "prompts/list", nil))
	if replies[0].Error == nil || replies[0].Result != nil {
		t.Fatalf("an unreachable console answered prompts/list: %s", replies[0].Result)
	}
}
