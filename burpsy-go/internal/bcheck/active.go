// The active evaluator: `send request` (M2) and `given insertion point` / `send payload` (M3).
//
// This is the Go counterpart of `run_active` / `dispatch` / `build_request` in
// crates/bcheck/src/eval.rs, built on the same statement evaluator the passive
// path uses — the two share runCheckBody, executeBlock and evalBoolExpr, so a
// statement's meaning cannot diverge between them.
//
// # What a send is
//
// Every send goes through the caller's Sink, bound to one Target: the scanned
// exchange's own authority. The check chooses the bytes; it never chooses the
// connection. That is the evaluator's half of the egress chokepoint — a raw
// `send request` whose text names a different Host still travels to the
// exchange the scan started from.
//
// # Semantics that are easy to get backwards
//
//   - `base` and `latest` are different messages after a send. `latest.*` is the
//     most recent send, and every send updates it — named or not, `send request`
//     or `send payload`. Before the first send they are the same exchange.
//   - Every send is built from `base.request`, never from the previous send.
//     Modifiers within one `send request` accumulate; sends do not. This is what
//     makes `PathSuffix_WAF_Proxy.bcheck`'s control probe a control.
//   - `send payload` always starts from the base request too, so a second
//     `send payload` in one check is base+payload, not payload+payload.
//   - A failed send abandons the check. Continuing would leave `{check.response}`
//     absent and invite exactly the false positive the absence rules prevent.
//   - A `given insertion point` check runs once per point, each with its own
//     `latest`, its own named bindings and its own `insertion_point_base_value`,
//     so a finding is attributable to one parameter — the entire reason the
//     construct exists.
package bcheck

import (
	"context"
	"strings"

	"github.com/burpsy-go/burpsy/internal/core"
)

// ModOp is how a `send request` modifier applies: replacing the component or
// appending to it.
type ModOp int

const (
	// ModReplace overwrites the component.
	ModReplace ModOp = iota
	// ModAppend extends the component (`appending path`, `appending queries`,
	// `appending body`).
	ModAppend
	// ModRemove deletes the component (`removing headers: "Origin"`, `removing body`) — movb.
	ModRemove
)

// RequestModifier is one `send request` clause. Target names the component
// (`method`, `path`, `query_string`, `queries`, `headers`, `body`) and Values
// holds its resolved arguments — one value for most targets, one per clause
// for `queries`, and flat [name, value, name, value, …] pairs for `headers`.
type RequestModifier struct {
	Target string
	Op     ModOp
	Values []Value
}

// Target is where a check's sends go: the scanned exchange's own authority.
// The check chooses the bytes; it never chooses the connection.
type Target struct {
	Host string
	Port uint16
	TLS  bool
}

// Sink performs the outbound half of `send request` and `send payload`. An
// interface rather than a concrete client so the evaluator is testable without
// a network, and so the caller owns connection reuse, timeouts, rate limiting
// and its scope gate — the caller can meter every send and refuse bytes it was
// not authorised to write.
type Sink interface {
	// Send writes raw request bytes to the bound target, returning the raw
	// response bytes. Err abandons the check: a check that cannot see its own
	// probe's response cannot judge.
	Send(target *Target, raw []byte) ([]byte, error)
}

// ToolRunner performs the outbound half of `run tool`: it resolves the named
// tool through the caller's allowlist and executes it with the resolved args.
// An interface rather than a concrete exec so the evaluator is testable
// without spawning processes, and so the caller owns the allowlist, the
// timeout and the refusal — a `run tool` statement names a tool, never a
// binary, exactly as a send names bytes, never a connection.
type ToolRunner interface {
	// Run executes tool with args and returns its captured output. An unknown
	// tool, a launch failure or a timeout is an error, which abandons the
	// check: a check that cannot see its tool's output cannot judge. A
	// non-zero exit code is *not* an error — it is data the check compares
	// against via `{<name>.exit_code}`.
	//
	// ctx is the caller's audit context: a tool must die when the audit that
	// spawned it is cancelled, not run on to its own timeout. The runner may
	// also bound the run itself.
	Run(ctx context.Context, tool string, args []string) (ToolResult, error)
}

// ToolResult is what one `run tool` produced: the captured stdout and stderr,
// and the exit code (0 when the tool ran to completion with success).
type ToolResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

// Bound is one request/response pair a check can reference: `base`, `latest`,
// or a named send.
type Bound struct {
	request  *core.RequestEdit
	response *messageFields
}

// field resolves `<side>.<rest…>` within this binding. ok is false when the
// binding cannot supply that side at all.
func (b *Bound) field(side string, rest []string) (string, bool) {
	if b == nil {
		return "", false
	}
	// `<x>.response.url` describes the URL that was requested, which lives on
	// the request — matching Rust's Bound::get.
	if len(rest) > 0 && rest[0] == "url" {
		if b.request == nil {
			return "", false
		}
		return boundURLField(b.request, rest[1:]), true
	}
	switch side {
	case "response":
		if b.response == nil {
			return "", false
		}
		return boundResponseField(b.response, rest)
	case "request":
		if b.request == nil {
			return "", false
		}
		return boundRequestField(b.request, rest)
	}
	return "", false
}

// boundResponseField resolves `<binding>.response.<rest…>` against a sent
// response.
func boundResponseField(f *messageFields, rest []string) (string, bool) {
	if len(rest) == 0 {
		return f.raw, true
	}
	switch rest[0] {
	case "body":
		return f.body, true
	case "status_code":
		return f.second, true
	case "headers":
		if len(rest) > 1 {
			return f.byName[strings.ToLower(rest[1])], true
		}
		return f.headers, true
	case "http_version":
		return firstField(f.first), true
	}
	return "", false
}

// boundRequestField resolves `<binding>.request.<rest…>` against a sent
// request.
func boundRequestField(r *core.RequestEdit, rest []string) (string, bool) {
	if len(rest) == 0 {
		return string(r.ToRaw()), true
	}
	switch rest[0] {
	case "body":
		return string(r.Body), true
	case "method":
		return r.Method, true
	case "headers":
		if len(rest) > 1 {
			return r.Header(rest[1]), true
		}
		var sb strings.Builder
		for i, h := range r.Headers {
			if i > 0 {
				sb.WriteString("\r\n")
			}
			sb.WriteString(h[0])
			sb.WriteString(": ")
			sb.WriteString(h[1])
		}
		return sb.String(), true
	case "query_string":
		return r.Query, true
	case "path":
		return r.Path, true
	case "http_version":
		return r.Version, true
	}
	return "", false
}

// boundURLField resolves `<binding>.(request|response).url.<rest…>` for a sent
// request. With no rest it is the full URL; with a field it is that component.
func boundURLField(r *core.RequestEdit, rest []string) string {
	if len(rest) == 0 {
		return r.URL()
	}
	switch rest[0] {
	case "host":
		u := r.URL()
		if i := strings.Index(u, "://"); i >= 0 {
			after := u[i+3:]
			for _, cut := range []byte{':', '/'} {
				if j := strings.IndexByte(after, cut); j >= 0 {
					return after[:j]
				}
			}
			return after
		}
		return ""
	case "path":
		return r.Path
	case "file":
		return r.File()
	case "query", "query_string":
		return r.Query
	case "port":
		if h := r.Header("host"); h != "" {
			if i := strings.LastIndexByte(h, ':'); i >= 0 {
				return h[i+1:]
			}
		}
		return ""
	}
	return ""
}

// boundSend is one recorded send: the name it was bound to ("" for an unnamed
// send, which only `latest` addresses) and the pair itself.
type boundSend struct {
	name  string
	bound Bound
}

// boundTool is one recorded tool run, addressable by its `called` name.
type boundTool struct {
	name     string
	stdout   string
	stderr   string
	exitCode int
}

// ActiveErrKind distinguishes why an active run produced no verdict.
type ActiveErrKind int

const (
	// ActiveUnsupported means the evaluator cannot run the check at all — an
	// interaction server it needs, or an insertion-point enumeration declined in
	// full. Nothing proved, nothing sent.
	ActiveUnsupported ActiveErrKind = iota
	// ActiveSendFailed means a probe could not be sent or read, so the check
	// abandoned.
	ActiveSendFailed
	// ActiveNeedsPoint means `send payload` ran outside a `given insertion
	// point` check, so there is nowhere to put the payload.
	ActiveNeedsPoint
)

// ActiveError is why an active run produced no verdict. Distinct from a
// verdict: no finding, and no clean bill of health either.
type ActiveError struct {
	Kind     ActiveErrKind
	Detail   string
	Declined []string
}

func (e *ActiveError) Error() string {
	switch e.Kind {
	case ActiveUnsupported:
		if len(e.Declined) > 0 {
			return "unsupported: " + strings.Join(e.Declined, "; ")
		}
		if e.Detail != "" {
			return "unsupported: " + e.Detail
		}
		return "unsupported"
	case ActiveSendFailed:
		return "send failed: " + e.Detail
	case ActiveNeedsPoint:
		return "send payload needs an insertion point: " + e.Detail
	}
	return "unknown active error"
}

// RunActive runs a check that may send requests. sink is the chokepoint every
// send passes through and target is the one authority they may reach.
//
// The scan point (`given host` / `request` / `path`) decides *how often* the
// caller invokes this — once per host, per request, per path — not how the body
// evaluates, so it is the caller's business. `given insertion point` is the
// exception, because its iteration is over data only this module can see: the
// points of the base request. It is expanded here, once per point, and each
// point gets its own `latest`, its own named bindings and its own
// `insertion_point_base_value`.
func RunActive(check *Check, ctx *Context, sink Sink, target *Target) ([]Finding, error) {
	if check.NeedsCollaborator() {
		return nil, &ActiveError{Kind: ActiveUnsupported, Detail: "needs a collaborator interaction server"}
	}
	// A check that invokes an external tool cannot run without the caller's
	// allowlist runner. Refused up front, like the collaborator case: nothing
	// proved, nothing executed. The scanner's corpusActiveChecks already gates
	// on a configured runner, so this guard covers the direct callers.
	if check.NeedsTool() && ctx.toolRunner == nil {
		return nil, &ActiveError{Kind: ActiveUnsupported, Detail: "needs a configured tool runner"}
	}
	ctx.sink = sink
	ctx.target = target

	if check.Given != "insertion point" {
		return runCheckBody(check, ctx)
	}
	if len(ctx.Request) == 0 {
		return nil, &ActiveError{Kind: ActiveSendFailed, Detail: "no base request to enumerate insertion points in"}
	}
	opts := EnumerateOptions{Max: DefaultMaxInsertionPoints}
	if ctx.EnumerateOptions != nil {
		opts = *ctx.EnumerateOptions
	}
	points, declined := EnumerateWith(ctx.Request, check.InsertionKinds, opts)
	// A request can have somewhere to inject that the enumerator refuses to
	// splice into — a plain-text or non-UTF-8 body, or a multipart body whose
	// framing cannot be read. When that is the *only* place the check asked for,
	// the enumeration comes back empty but not clean: surfacing the decline as
	// Unsupported makes the caller count it as skipped rather than "tested,
	// found nothing".
	if len(points) == 0 && len(declined) > 0 {
		descs := make([]string, len(declined))
		for i, d := range declined {
			descs[i] = d.Describe()
		}
		return nil, &ActiveError{Kind: ActiveUnsupported, Detail: "insertion points declined", Declined: descs}
	}
	// When real points exist alongside a decline, the check runs them — a mixed
	// request is not fully declined — but the decline itself must not vanish.
	if len(declined) > 0 {
		for _, d := range declined {
			ctx.declined = append(ctx.declined, d.Describe())
		}
	}
	// An empty point list with no declines is not an error: a bare `GET /` has
	// nowhere to inject, and the check simply has nothing to do here.
	var findings []Finding
	for _, p := range points {
		it := ctx.forPoint(p)
		fs, err := runCheckBody(check, it)
		// Fold diagnostics and RNG state back, including on the error path.
		ctx.rng = it.rng
		ctx.mergeUnresolved(it)
		if err != nil {
			return nil, err
		}
		findings = append(findings, fs...)
	}
	return findings, nil
}

// forPoint returns a copy of the context aimed at one insertion point.
//
// `insertion_point_base_value` goes into the variable map rather than being
// resolved specially, because that is where Burp puts it — which means
// `define:` and `run for each:` values can read it, not only the check body.
// The send list starts empty so point B never sees point A's `{check.response}`.
func (ctx *Context) forPoint(p InsertionPoint) *Context {
	c := *ctx
	c.Variables = make(map[string]Value, len(ctx.Variables)+1)
	for k, v := range ctx.Variables {
		c.Variables[k] = v
	}
	c.Variables["insertion_point_base_value"] = Value{Type: "str", StringVal: p.BaseValue}
	c.point = &p
	c.sent = nil
	c.tools = nil
	c.unresolved = nil
	return &c
}

// sendRequest builds and dispatches one `send request` statement.
func (ctx *Context) sendRequest(s *SendRequestStatement) error {
	req, err := ctx.buildRequest(s)
	if err != nil {
		return err
	}
	return ctx.dispatch(s.StoreAs, req)
}

// runTool resolves a `run tool` statement's name and args, executes them
// through the caller's runner, and binds the result under the `called` name.
// The runner owns the allowlist; the evaluator owns nothing but the binding.
func (ctx *Context) runTool(s *RunToolStatement) error {
	if ctx.toolRunner == nil {
		return &ActiveError{Kind: ActiveUnsupported, Detail: "run tool needs a configured tool runner"}
	}
	tool := ctx.resolveValue(s.Tool)
	args := make([]string, 0, len(s.Args))
	for _, a := range s.Args {
		args = append(args, ctx.resolveValue(a))
	}
	res, err := ctx.toolRunner.Run(ctx.toolCtx, tool, args)
	if err != nil {
		return &ActiveError{Kind: ActiveUnsupported, Detail: err.Error()}
	}
	ctx.tools = append(ctx.tools, boundTool{
		name:     s.StoreAs,
		stdout:   res.Stdout,
		stderr:   res.Stderr,
		exitCode: res.ExitCode,
	})
	return nil
}

// sendPayload splices the payload into the current insertion point of the base
// request and dispatches the result — `send payload`'s whole reason for being.
func (ctx *Context) sendPayload(s *SendPayloadStatement) error {
	if ctx.point == nil {
		return &ActiveError{Kind: ActiveNeedsPoint, Detail: "there is no insertion point to place a payload in"}
	}
	if len(ctx.Request) == 0 {
		return &ActiveError{Kind: ActiveSendFailed, Detail: "no base request to place a payload in"}
	}
	payload := ctx.resolveValue(s.Value)
	newRaw, err := ctx.point.Apply(ctx.Request, payload, s.Appending)
	if err != nil {
		return &ActiveError{Kind: ActiveSendFailed, Detail: "applying payload: " + err.Error()}
	}
	req, err := core.ParseRequestEdit(newRaw)
	if err != nil {
		return &ActiveError{Kind: ActiveSendFailed, Detail: "payload request: " + err.Error()}
	}
	return ctx.dispatch(s.StoreAs, req)
}

// buildRequest renders the bytes a `send request` should issue.
//
// Each send starts a fresh accumulator seeded from `base.request`; modifiers
// then apply in source order within that one block. Seeding from the *previous*
// send instead is the tempting reading and it is wrong: a control probe that
// inherits the candidate's suffix is no longer a control.
func (ctx *Context) buildRequest(s *SendRequestStatement) (*core.RequestEdit, error) {
	if s.Template != "" {
		raw := ctx.interpolate(s.Template)
		req, err := core.ParseRequestEdit([]byte(raw))
		if err != nil {
			return nil, &ActiveError{Kind: ActiveSendFailed, Detail: "raw request: " + err.Error()}
		}
		return req, nil
	}
	base := ctx.baseRequest()
	if base == nil {
		return nil, &ActiveError{Kind: ActiveSendFailed, Detail: "no base request to modify"}
	}
	req := cloneRequestEdit(base)
	for _, m := range s.Modifiers {
		applyModifier(req, m, ctx)
	}
	return req, nil
}

// cloneRequestEdit deep-copies a request edit: the cached base request must
// never be mutated by a modifier that a later statement still reads.
func cloneRequestEdit(e *core.RequestEdit) *core.RequestEdit {
	c := *e
	c.Headers = make([][2]string, len(e.Headers))
	copy(c.Headers, e.Headers)
	c.Body = append([]byte(nil), e.Body...)
	return &c
}

// applyModifier applies one `send request` clause to a request, resolving its
// values against the context. Unknown targets are left alone rather than
// refused, matching the parser's structural tolerance of v2-beta extensions.
func applyModifier(r *core.RequestEdit, m RequestModifier, ctx *Context) {
	txt := func(v Value) string { return ctx.resolveValue(v) }
	if m.Op == ModRemove {
		// Burp's reference (movb): headers and queries name what to remove; the rest remove the
		// component outright. `removing path` "removes all path parameters" — the path becomes "/"
		// and the query stays; `removing queries` drops each named parameter, name and value.
		switch m.Target {
		case "headers", "header":
			for _, v := range m.Values {
				r.RemoveHeader(txt(v))
			}
		case "queries", "query":
			for _, v := range m.Values {
				r.RemoveQuery(txt(v))
			}
		case "query_string":
			r.Query = ""
		case "path":
			r.Path = "/"
		case "method":
			r.Method = ""
		case "body":
			r.Body = nil
		}
		return
	}
	switch m.Target {
	case "method":
		if len(m.Values) > 0 {
			r.Method = txt(m.Values[0])
		}
	case "path":
		if len(m.Values) == 0 {
			return
		}
		v := txt(m.Values[0])
		if m.Op == ModReplace {
			// Replacing the path leaves the query string in place — `path` and
			// `query_string` are separate modifier targets — unless the
			// replacement carries its own query.
			if i := strings.IndexByte(v, '?'); i >= 0 {
				r.Path, r.Query = v[:i], v[i+1:]
			} else {
				r.Path = v
			}
		} else {
			r.Path = joinPath(r.Path, v)
		}
	case "query_string":
		if len(m.Values) > 0 {
			v := strings.TrimPrefix(txt(m.Values[0]), "?")
			if m.Op == ModAppend {
				// "Appends the specified query string to the existing query" — it used to replace it.
				r.AddQuery(v)
			} else {
				r.Query = v
			}
		}
	case "queries":
		for _, v := range m.Values {
			if m.Op == ModReplace {
				// "Replaces the value of the specified query parameter(s) … If there are no queries
				// with the specified name then a new query is appended" — it used to always append.
				r.SetQuery(txt(v))
			} else {
				r.AddQuery(txt(v))
			}
		}
	case "headers":
		for i := 0; i+1 < len(m.Values); i += 2 {
			n := txt(m.Values[i])
			v := txt(m.Values[i+1])
			// An empty value marks the whole-line form: `"X-Foo: bar"`.
			if v == "" {
				if j := strings.IndexByte(n, ':'); j >= 0 {
					n, v = strings.TrimSpace(n[:j]), strings.TrimSpace(n[j+1:])
				}
			}
			if n == "" {
				continue
			}
			if m.Op == ModReplace {
				r.SetHeader(n, v)
			} else {
				r.AddHeader(n, v)
			}
		}
	case "body":
		if len(m.Values) == 0 {
			return
		}
		v := txt(m.Values[0])
		if m.Op == ModReplace {
			r.Body = []byte(v)
		} else {
			r.Body = append(r.Body, v...)
		}
	}
}

// joinPath appends a path segment with exactly one slash between the two —
// corpus values are written both with and without a leading slash.
func joinPath(p, v string) string {
	switch {
	case strings.HasSuffix(p, "/") && strings.HasPrefix(v, "/"):
		return p + v[1:]
	case !strings.HasSuffix(p, "/") && !strings.HasPrefix(v, "/"):
		return p + "/" + v
	default:
		return p + v
	}
}

// dispatch sends a built request and binds the result. Shared by `send request`
// and `send payload` because everything after "which bytes go out" — parsing,
// binding `latest`, abandoning on failure — is identical.
func (ctx *Context) dispatch(storeAs string, req *core.RequestEdit) error {
	raw := req.ToRaw()
	resp, err := ctx.sink.Send(ctx.target, raw)
	if err != nil {
		return &ActiveError{Kind: ActiveSendFailed, Detail: err.Error()}
	}
	ctx.sent = append(ctx.sent, boundSend{
		name:  storeAs,
		bound: Bound{request: req, response: parseMessage(resp)},
	})
	return nil
}
