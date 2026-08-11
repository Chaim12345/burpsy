package bcheck

import (
	"strings"
	"testing"
)

// mockToolRunner records the tool runs it was asked to perform and replays a
// canned result, so the evaluator is testable without spawning processes.
type mockToolRunner struct {
	runs    []mockToolRun
	replies []ToolResult
	err     error
}

type mockToolRun struct {
	tool string
	args []string
}

func (m *mockToolRunner) Run(tool string, args []string) (ToolResult, error) {
	m.runs = append(m.runs, mockToolRun{tool: tool, args: args})
	if m.err != nil {
		return ToolResult{}, m.err
	}
	if len(m.replies) == 0 {
		return ToolResult{}, nil
	}
	r := m.replies[0]
	m.replies = m.replies[1:]
	return r, nil
}

// A `run tool` statement parses its name, binding and args structurally, so a
// check that passes `{base.request.url}` to sqlmap can be counted and run.
func TestRunToolParsesNameBindingAndArgs(t *testing.T) {
	c, err := Parse(`metadata:
  language: v1-beta
  name: "sqlmap probe"

given request then
  run tool sqlmap called sqlmap_run:
    args: "-u", {base.request.url}, "--batch"
`)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(c.Statements) != 1 {
		t.Fatalf("got %d statements, want 1", len(c.Statements))
	}
	rt, ok := c.Statements[0].(*RunToolStatement)
	if !ok {
		t.Fatalf("statement is %T, want *RunToolStatement", c.Statements[0])
	}
	if rt.Tool.StringVal != "sqlmap" {
		t.Errorf("tool = %q, want sqlmap", rt.Tool.StringVal)
	}
	if rt.StoreAs != "sqlmap_run" {
		t.Errorf("StoreAs = %q, want sqlmap_run", rt.StoreAs)
	}
	if len(rt.Args) != 3 {
		t.Fatalf("got %d args, want 3", len(rt.Args))
	}
	if rt.Args[1].Type != "var" || rt.Args[1].StringVal != "base.request.url" {
		t.Errorf("arg 1 = %+v, want {base.request.url} var", rt.Args[1])
	}
}

// A tool check is never passive — it executes an external process — and needs
// a tool runner to run at all.
func TestRunToolCheckIsNotPassiveAndNeedsTool(t *testing.T) {
	c, err := Parse(`given response then
  run tool jwt_tool called j:
    args: "-t", "{base.request.url}"
`)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if c.IsPassive() {
		t.Error("a check carrying `run tool` must not be classified passive")
	}
	if !c.NeedsTool() {
		t.Error("NeedsTool() = false for a check with a run tool statement")
	}
}

// A tool run inside an if branch still marks the check NeedsTool — the load
// classification must see through control flow.
func TestNeedsToolSeesThroughIfBlocks(t *testing.T) {
	c, err := Parse(`given request then
  if {base.response.status_code} is "200" then
    run tool sqlmap called probe:
      args: "-u", "{base.request.url}"
  end if
`)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !c.NeedsTool() {
		t.Error("NeedsTool() = false; the run tool statement hides inside an if block")
	}
}

// The evaluator binds a tool's stdout, stderr and exit code under the `called`
// name, and a condition on `{probe.stdout}` decides the verdict. Args resolve
// through the context like any value.
func TestRunToolBindsResultAndDrivesVerdict(t *testing.T) {
	runner := &mockToolRunner{replies: []ToolResult{{
		Stdout:   "target appears to be vulnerable",
		Stderr:   "",
		ExitCode: 0,
	}}}
	ctx := NewContext()
	ctx.Response = []byte(ok200("hello"))
	ctx.Host = "app.test"
	ctx.Path = "/search?q=cat"
	ctx.TLS = false
	ctx.SetToolRunner(runner)
	req := []byte("GET /search?q=cat HTTP/1.1\r\nHost: app.test\r\n\r\n")
	ctx.Request = req

	c, err := Parse(`given request then
  run tool sqlmap called probe:
    args: "-u", {base.request.url}
  if {probe.exit_code} is "0" and {probe.stdout} contains "vulnerable" then
    report issue:
      name: "SQL injection (tool)"
      severity: "high"
      confidence: "firm"
      detail: ` + "`tool output: {probe.stdout}`" + `
  end if
`)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	found, err := RunActive(c, ctx, &mockSink{}, &Target{Host: "app.test", Port: 80})
	if err != nil {
		t.Fatalf("RunActive: %v", err)
	}
	if len(found) != 1 {
		t.Fatalf("got %d findings, want 1", len(found))
	}
	if !strings.Contains(found[0].Description, "tool output: target appears to be vulnerable") {
		t.Errorf("detail = %q, want the resolved stdout interpolated", found[0].Description)
	}
	if len(runner.runs) != 1 {
		t.Fatalf("tool ran %d times, want 1", len(runner.runs))
	}
	if runner.runs[0].tool != "sqlmap" {
		t.Errorf("tool name = %q, want sqlmap", runner.runs[0].tool)
	}
	if len(runner.runs[0].args) != 2 || runner.runs[0].args[1] != "http://app.test/search?q=cat" {
		t.Errorf("args = %v, want [\"-u\" \"http://app.test/search?q=cat\"]", runner.runs[0].args)
	}
}

// A non-zero exit code is data, not a verdict: the check decides via
// `{<name>.exit_code}`. A tool that finds nothing exits non-zero and the
// check reports nothing — the run itself is not an error.
func TestRunToolNonZeroExitIsDataNotError(t *testing.T) {
	runner := &mockToolRunner{replies: []ToolResult{{Stdout: "", Stderr: "no injection", ExitCode: 1}}}
	ctx := NewContext()
	ctx.Response = []byte(ok200("hello"))
	ctx.Host = "app.test"
	ctx.SetToolRunner(runner)

	c, err := Parse(`given request then
  run tool sqlmap called probe:
    args: "-u", "{base.request.url}"
  if {probe.exit_code} is "0" then
    report issue:
      name: "SQL injection (tool)"
      severity: "high"
      confidence: "firm"
  end if
`)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	found, err := RunActive(c, ctx, &mockSink{}, &Target{Host: "app.test", Port: 80})
	if err != nil {
		t.Fatalf("RunActive: %v", err)
	}
	if len(found) != 0 {
		t.Fatalf("got %d findings for a non-zero exit, want 0 (the check's condition decided)", len(found))
	}
	if len(runner.runs) != 1 {
		t.Fatalf("tool ran %d times, want 1", len(runner.runs))
	}
}

// A whole check that needs a tool is refused before anything runs when no
// runner is configured — the same refusal as a check that needs a Collaborator.
func TestRunActiveRefusesToolCheckWithoutRunner(t *testing.T) {
	c, err := Parse(`given request then
  run tool sqlmap called probe:
    args: "-u", "{base.request.url}"
`)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	ctx := NewContext()
	ctx.Response = []byte(ok200("hello"))
	_, err = RunActive(c, ctx, &mockSink{}, &Target{Host: "app.test", Port: 80})
	ae, ok := err.(*ActiveError)
	if !ok {
		t.Fatalf("error is %T (%v), want *ActiveError", err, err)
	}
	if ae.Kind != ActiveUnsupported {
		t.Errorf("kind = %v, want ActiveUnsupported", ae.Kind)
	}
}

// A runner refusal — the tool is not on the allowlist — abandons the check
// rather than letting it judge from nothing.
func TestRunToolRunnerRefusalAbandonsCheck(t *testing.T) {
	runner := &mockToolRunner{err: &errToolRefused{name: "sqlmap"}}
	ctx := NewContext()
	ctx.Response = []byte(ok200("hello"))
	ctx.SetToolRunner(runner)

	c, err := Parse(`given request then
  run tool sqlmap called probe:
    args: "-u", "{base.request.url}"
`)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	_, err = RunActive(c, ctx, &mockSink{}, &Target{Host: "app.test", Port: 80})
	ae, ok := err.(*ActiveError)
	if !ok {
		t.Fatalf("error is %T (%v), want *ActiveError", err, err)
	}
	if ae.Kind != ActiveUnsupported {
		t.Errorf("kind = %v, want ActiveUnsupported", ae.Kind)
	}
	if !strings.Contains(ae.Error(), "sqlmap") {
		t.Errorf("error %q does not name the refused tool", ae.Error())
	}
}

// errToolRefused mimics the scanner runner's allowlist refusal.
type errToolRefused struct{ name string }

func (e *errToolRefused) Error() string {
	return "tool " + e.name + " is not in the configured allowlist"
}
