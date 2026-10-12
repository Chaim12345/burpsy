package scanner

// GraphQL hardening (burpsy-react-ui-0vzb.13): three burpsy rows Burp's catalogue has no entry for,
// probed on an endpoint that has first proved it executes GraphQL.
//
//   - "GraphQL query batching enabled": several operations in one HTTP request, the shape that
//     lets one request carry many password or one-time-code guesses past a per-request rate limit.
//     Two mechanisms, as graphql-cop tests them: an array of operations in one JSON body, and many
//     aliases of one field in one operation.
//   - "GraphQL query depth not limited": a nested query of depth ten along a self-referential path
//     of the schema, executed without a depth-limit error.
//   - "GraphQL debug information disclosed": stack frames in an error response, or the resolver
//     trace of Apollo's tracing extension.
//
// # Evidence: every claim names a value only this probe could have caused
//
// A GraphQL answer is keyed by the alias the query chose, so each probe asks under fresh random
// aliases and a claim is made only when the answer carries those aliases back as data. A fixed
// response, a cached page or an echo of the request cannot do that: an echo returns the query
// text, not a data object keyed by names that appear nowhere else. The existence probe that
// gates everything below is the same idea once more: `query{<alias>:__typename}` must come back
// as data.<alias>, a string, or the endpoint is not GraphQL and nothing else is sent.
//
// # Bounded, and safe by construction
//
// Every probe selects only __typename, except the depth probe, which selects object fields along
// one path and fans out at most one item per level (a list field is followed only when it takes a
// first/limit-style argument, which is set to 1). No mutation resolver ever runs: none of these
// probes is a mutation. The sizes are fixed: ten batched operations, one hundred aliases, depth
// ten. A server that limits batching, aliases or depth below those numbers is reported as
// limiting them; one that limits them above is reported as not limiting them, which is what the
// row says and why its evidence states the number that was accepted.

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/burpsy-go/burpsy/pkg/graphqlmap"
)

// The burpsy row names (burpsy_rows.go).
const (
	IssueGraphQLBatching = "GraphQL query batching enabled"
	IssueGraphQLDepth    = "GraphQL query depth not limited"
	IssueGraphQLDebug    = "GraphQL debug information disclosed"
)

const (
	// graphQLBatchSize is how many operations the array-batching probe sends in one request.
	graphQLBatchSize = 10
	// graphQLAliasCount is how many aliases the alias-overloading probe sends in one operation.
	// One hundred rather than ten: ten aliases of one field is ordinary GraphQL that every alias
	// limiter in common use (graphql-armor's default is 15) admits, so ten would report hardened
	// servers. graphql-cop sends 101 for the same reason.
	graphQLAliasCount = 100
	// graphQLDepthProbe is the nesting depth of the depth probe, in object fields.
	graphQLDepthProbe = 10
)

func graphQLHardeningEnabled(c *ScanConfig) bool { return c != nil && c.CheckGraphQLHardening }

// graphQLEndpointWithHardening composes the hardening probes onto the "GraphQL endpoint found"
// descriptor, which already runs once per URL. The inner Burp row runs exactly as before when its
// own family switch is on; the hardening probes run behind their own switch.
func graphQLEndpointWithHardening(inner CheckRunner) CheckRunner {
	return func(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
		if cc == nil {
			return nil, nil
		}
		var out []*Finding
		var firstErr error
		if remainingChecksEnabled(cc.Config) {
			out, firstErr = inner(ctx, cc)
		}
		if graphQLHardeningEnabled(cc.Config) {
			f, err := checkGraphQLHardening(ctx, cc)
			out = append(out, f...)
			if err != nil && firstErr == nil {
				firstErr = err
			}
		}
		if len(out) > 0 {
			return out, nil
		}
		return nil, firstErr
	}
}

// graphQLNonce is a fresh alias: a GraphQL name no schema and no cached answer can already hold.
func graphQLNonce() string { return "bsy" + randHex(10) }

// graphQLDataField returns data.<key> of an envelope, and whether the key is present.
func graphQLDataField(data json.RawMessage, key string) (json.RawMessage, bool) {
	var m map[string]json.RawMessage
	if len(data) == 0 || json.Unmarshal(data, &m) != nil {
		return nil, false
	}
	v, ok := m[key]
	return v, ok
}

// graphQLAliasTyped reports whether data.<alias> is a non-empty string: the answer to
// `<alias>:__typename`.
func graphQLAliasTyped(res *graphqlmap.Response, alias string) bool {
	if res == nil {
		return false
	}
	v, ok := graphQLDataField(res.Data, alias)
	if !ok {
		return false
	}
	var s string
	return json.Unmarshal(v, &s) == nil && s != ""
}

// checkGraphQLHardening runs the three probes on an endpoint proved to execute GraphQL.
func checkGraphQLHardening(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	if cc.Scanner == nil || cc.Exchange == nil {
		return nil, nil
	}
	if err := cc.RequireEgress(); err != nil {
		return nil, fmt.Errorf("GraphQL hardening: %w", err)
	}
	client := newGraphQLClient(cc)
	alias := graphQLNonce()
	base, err := client.Execute(ctx, "query{"+alias+":__typename}")
	if err != nil {
		return nil, fmt.Errorf("GraphQL hardening: existence probe: %w", err)
	}
	if !graphQLAliasTyped(base, alias) {
		// Not a GraphQL endpoint (or not one this client can talk to): nothing to harden.
		return nil, nil
	}
	var out []*Finding
	var firstErr error
	for _, probe := range []func(context.Context, *CheckContext, *graphqlmap.Client, *graphqlmap.Response) (*Finding, error){
		graphQLDebugProbe, graphQLBatchingProbe, graphQLDepthProbeRun,
	} {
		f, err := probe(ctx, cc, client, base)
		if f != nil {
			out = append(out, f)
		}
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if len(out) > 0 {
		return out, nil
	}
	return nil, firstErr
}

// ---------------------------------------------------------------------------
// Batching
// ---------------------------------------------------------------------------

func graphQLBatchingProbe(ctx context.Context, cc *CheckContext, client *graphqlmap.Client, _ *graphqlmap.Response) (*Finding, error) {
	var proofs []string

	// Array batching: N operations, each under its own alias, in one JSON array.
	aliases := make([]string, graphQLBatchSize)
	ops := make([]map[string]string, graphQLBatchSize)
	for i := range aliases {
		aliases[i] = graphQLNonce()
		ops[i] = map[string]string{"query": "query{" + aliases[i] + ":__typename}"}
	}
	body, _ := json.Marshal(ops)
	res, err := (&scannerTransport{cc: cc}).Do(ctx, graphqlmap.Request{
		Method: "POST", URL: exchangeURL(cc.Exchange), Encoding: graphqlmap.EncodingJSON,
		Headers: map[string]string{"Content-Type": "application/json"}, Body: body,
	})
	var sendErr error
	if err != nil {
		sendErr = fmt.Errorf("GraphQL batching: array probe: %w", err)
	} else if n := graphQLBatchAnswered(res.Body, aliases); n == graphQLBatchSize {
		proofs = append(proofs, fmt.Sprintf("array batching: %d operations in one request, each answered under its own alias", n))
	}

	// Alias overloading: one operation selecting __typename under many aliases.
	prefix := graphQLNonce()
	var q strings.Builder
	q.WriteString("query{")
	for i := 0; i < graphQLAliasCount; i++ {
		fmt.Fprintf(&q, "%s_%d:__typename ", prefix, i)
	}
	q.WriteString("}")
	ares, err := client.Execute(ctx, q.String())
	if err != nil {
		if sendErr == nil {
			sendErr = fmt.Errorf("GraphQL batching: alias probe: %w", err)
		}
	} else if !ares.HasErrors() {
		answered := 0
		for i := 0; i < graphQLAliasCount; i++ {
			if graphQLAliasTyped(ares, fmt.Sprintf("%s_%d", prefix, i)) {
				answered++
			}
		}
		if answered == graphQLAliasCount {
			proofs = append(proofs, fmt.Sprintf("alias overloading: %d aliases in one operation, all answered", answered))
		}
	}

	if len(proofs) == 0 {
		return nil, sendErr
	}
	severity := "info"
	if strings.HasPrefix(proofs[0], "array") {
		// Array batching multiplies whole operations, mutations included; alias overloading on
		// its own is the weaker form.
		severity = "low"
	}
	return buildHeaderFinding(cc, IssueGraphQLBatching, severity, "certain", strings.Join(proofs, "; "),
		"the endpoint executes many GraphQL operations or aliased fields in a single HTTP request, so a "+
			"limit counted per request (login attempts, one-time codes, API quotas) can be multiplied by "+
			"batching guesses into one request"), nil
}

// graphQLBatchAnswered counts the array elements whose data carries the alias sent at that
// position. A server that does not batch answers one error envelope (or a 400), which counts 0.
func graphQLBatchAnswered(body []byte, aliases []string) int {
	var arr []struct {
		Data   json.RawMessage `json:"data"`
		Errors []any           `json:"errors"`
	}
	if json.Unmarshal([]byte(strings.TrimSpace(string(body))), &arr) != nil || len(arr) != len(aliases) {
		return 0
	}
	n := 0
	for i, el := range arr {
		if len(el.Errors) > 0 {
			continue
		}
		if graphQLAliasTyped(&graphqlmap.Response{Data: el.Data}, aliases[i]) {
			n++
		}
	}
	return n
}

// ---------------------------------------------------------------------------
// Depth
// ---------------------------------------------------------------------------

// graphQLLimitArgs are the argument names that, by near-universal convention, bound how many items
// a list field returns. A list field is followed by the depth probe only through one of them, set
// to 1, so the probe never fans out.
var graphQLLimitArgs = map[string]bool{
	"first": true, "last": true, "limit": true, "take": true, "top": true, "size": true,
	"count": true, "pagesize": true, "perpage": true, "page_size": true, "per_page": true, "max": true,
}

// graphQLEdge is one step of the depth probe's path: a field to select, rendered with any argument
// it needs, and the object type it leads to.
type graphQLEdge struct {
	render string
	to     string
}

// graphQLEdges returns the fields of a type the depth probe may follow: an object (or interface)
// result, no required argument, and a list result only through a limit-style argument.
func graphQLEdges(t *graphqlmap.Type, kinds map[string]string) []graphQLEdge {
	var out []graphQLEdge
	for _, f := range t.Fields {
		if f.Type == nil || strings.HasPrefix(f.Name, "__") {
			continue
		}
		to := f.Type.Named()
		if k := kinds[to]; k != "OBJECT" && k != "INTERFACE" {
			continue
		}
		required := false
		limitArg := ""
		for _, a := range f.Args {
			if a.Type != nil && a.Type.Kind == "NON_NULL" && a.DefaultValue == nil {
				required = true
			}
			if a.Type != nil && a.Type.Named() == "Int" && graphQLLimitArgs[strings.ToLower(a.Name)] && limitArg == "" {
				limitArg = a.Name
			}
		}
		if required {
			continue
		}
		isList := false
		for cur := f.Type; cur != nil; cur = cur.OfType {
			isList = isList || cur.Kind == "LIST"
		}
		render := f.Name
		if isList {
			if limitArg == "" {
				continue
			}
			render = fmt.Sprintf("%s(%s:1)", f.Name, limitArg)
		}
		out = append(out, graphQLEdge{render: render, to: to})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].render < out[j].render })
	return out
}

// graphQLDepthPath finds a path of depth fields from the query root that never fans out: the
// shortest route to a type on a cycle, then that cycle repeated. ok is false when the schema has
// no such cycle reachable from the root, which is the common, legitimately bounded case.
func graphQLDepthPath(s *graphqlmap.Schema, depth int) ([]string, bool) {
	root := s.QueryType
	if root == "" {
		root = "Query"
	}
	byName := map[string]*graphqlmap.Type{}
	kinds := map[string]string{}
	for i := range s.Types {
		byName[s.Types[i].Name] = &s.Types[i]
		kinds[s.Types[i].Name] = s.Types[i].Kind
	}
	edges := func(name string) []graphQLEdge {
		if t := byName[name]; t != nil {
			return graphQLEdges(t, kinds)
		}
		return nil
	}
	// shortest returns the shortest edge path from one type to another (len 0 when from == to and
	// cycle is false).
	shortest := func(from, to string, cycle bool) ([]graphQLEdge, bool) {
		type node struct {
			name string
			path []graphQLEdge
		}
		seen := map[string]bool{}
		queue := []node{{name: from}}
		if !cycle {
			seen[from] = true
			if from == to {
				return nil, true
			}
		}
		for len(queue) > 0 {
			n := queue[0]
			queue = queue[1:]
			for _, e := range edges(n.name) {
				p := append(append([]graphQLEdge{}, n.path...), e)
				if e.to == to {
					return p, true
				}
				if !seen[e.to] {
					seen[e.to] = true
					queue = append(queue, node{name: e.to, path: p})
				}
			}
		}
		return nil, false
	}
	// Every type reachable from the root, nearest first, is a candidate entry into a cycle.
	reach := []string{root}
	seen := map[string]bool{root: true}
	for i := 0; i < len(reach); i++ {
		for _, e := range edges(reach[i]) {
			if !seen[e.to] {
				seen[e.to] = true
				reach = append(reach, e.to)
			}
		}
	}
	// reach is in breadth-first order, so the first type with a cycle is the nearest entry. The
	// root itself qualifies (Query.viewer: Query), with an empty prefix.
	for _, u := range reach {
		prefix, ok := shortest(root, u, false)
		if !ok {
			continue
		}
		cyc, ok := shortest(u, u, true)
		if !ok || len(cyc) == 0 {
			continue
		}
		var path []string
		for _, e := range prefix {
			path = append(path, e.render)
		}
		for len(path) < depth {
			for _, e := range cyc {
				path = append(path, e.render)
			}
		}
		return path[:depth], true
	}
	return nil, false
}

func graphQLDepthProbeRun(ctx context.Context, cc *CheckContext, client *graphqlmap.Client, _ *graphqlmap.Response) (*Finding, error) {
	schema, err := client.Introspect(ctx)
	if err != nil || schema == nil {
		// No schema, no way to build a query that nests without guessing field names. That is
		// undecided rather than limited, and it is not reported either way.
		return nil, nil
	}
	path, ok := graphQLDepthPath(schema, graphQLDepthProbe)
	if !ok {
		return nil, nil
	}
	alias := graphQLNonce()
	var q strings.Builder
	q.WriteString("query{" + alias + ":")
	for i, f := range path {
		if i > 0 {
			q.WriteString("{")
		}
		q.WriteString(f)
	}
	q.WriteString("{__typename}")
	q.WriteString(strings.Repeat("}", len(path)-1))
	q.WriteString("}")
	res, err := client.Execute(ctx, q.String())
	if err != nil {
		return nil, fmt.Errorf("GraphQL depth probe: %w", err)
	}
	if res.HasErrors() {
		// A depth or complexity limit answers with an error before execution; any error at all
		// keeps this from being a claim.
		return nil, nil
	}
	if _, present := graphQLDataField(res.Data, alias); !present {
		return nil, nil
	}
	return buildHeaderFinding(cc, IssueGraphQLDepth, "low", "firm",
		fmt.Sprintf("a query nested %d object fields deep (%s ...) executed with no error", len(path), strings.Join(path[:min(4, len(path))], " > ")),
		"the endpoint executes deeply nested queries along a self-referential path of its schema without a "+
			"depth or complexity limit; nesting such a path further multiplies the work one request costs "+
			"the server"), nil
}

// ---------------------------------------------------------------------------
// Debug information
// ---------------------------------------------------------------------------

// graphQLStackFrame matches one stack frame line in the formats the common GraphQL servers' debug
// modes emit: JavaScript (`at fn (/app/x.js:12:3)`), Java (`at a.b.C.m(C.java:12)`), .NET
// (`at A.B() in /src/x.cs:line 12`), Python (`File "/app/x.py", line 12, in fn`), Ruby
// (`/app/x.rb:12:in 'fn'`), PHP (`#0 /app/x.php(12): fn()`) and Go (`/app/x.go:12 +0x1d`).
var graphQLStackFrame = regexp.MustCompile(
	`^\s*at (.+ \()?\S+\.(js|mjs|cjs|ts|jsx|tsx):\d+:\d+\)?\s*$` +
		`|^\s*at [\w$.<>]+\([\w$]+\.(java|kt|scala):\d+\)` +
		`|^\s*at .+ in .+:line \d+` +
		`|^\s*File ".+", line \d+` +
		`|\S+\.rb:\d+:in ` +
		`|^#\d+ \S+\.php\(\d+\)` +
		`|^\s*\S+\.go:\d+( \+0x[0-9a-f]+)?\s*$`)

func graphQLDebugProbe(ctx context.Context, cc *CheckContext, client *graphqlmap.Client, base *graphqlmap.Response) (*Finding, error) {
	// Apollo's tracing extension rides on the successful answer already in hand.
	if trace := graphQLTracing(base.Body); trace != "" {
		return buildHeaderFinding(cc, IssueGraphQLDebug, "info", "certain", trace,
			"the endpoint returns the tracing extension with every answer: resolver paths and their "+
				"timings, which map the schema and time each resolver for an attacker"), nil
	}
	alias := graphQLNonce()
	var firstErr error
	for _, q := range []string{
		"query{" + alias + ":__typename",                     // a syntax error: the closing brace is missing
		"query{" + alias + ":" + graphQLNonce() + "Missing}", // a validation error: no such field
	} {
		res, err := client.Execute(ctx, q)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("GraphQL debug probe: %w", err)
			}
			continue
		}
		if where, frames := graphQLStackFrames(res.Body); len(frames) >= 2 {
			return buildHeaderFinding(cc, IssueGraphQLDebug, "low", "firm",
				fmt.Sprintf("%s: %s | %s", where, frames[0], frames[1]),
				"the endpoint answers a malformed query with a server stack trace: source paths, function "+
					"names and library versions of the code behind the GraphQL server"), nil
		}
	}
	return nil, firstErr
}

// graphQLStackFrames walks a GraphQL error envelope's errors and extensions for stack frames,
// returning the JSON path of the first string that held any and the distinct frames found.
func graphQLStackFrames(body []byte) (string, []string) {
	var env map[string]any
	if json.Unmarshal(body, &env) != nil {
		return "", nil
	}
	var where string
	var frames []string
	seen := map[string]bool{}
	var walk func(v any, path string)
	walk = func(v any, path string) {
		switch x := v.(type) {
		case string:
			for _, line := range strings.Split(x, "\n") {
				line = strings.TrimRight(line, "\r")
				if graphQLStackFrame.MatchString(line) && !seen[strings.TrimSpace(line)] {
					seen[strings.TrimSpace(line)] = true
					frames = append(frames, strings.TrimSpace(line))
					if where == "" {
						where = path
					}
				}
			}
		case []any:
			for i, el := range x {
				walk(el, fmt.Sprintf("%s[%d]", path, i))
			}
		case map[string]any:
			keys := make([]string, 0, len(x))
			for k := range x {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				walk(x[k], path+"."+k)
			}
		}
	}
	for _, k := range []string{"errors", "extensions"} {
		if v, ok := env[k]; ok {
			walk(v, k)
		}
	}
	return where, frames
}

// graphQLTracing describes the Apollo tracing extension when an answer carries one with resolver
// timings, "" otherwise.
func graphQLTracing(body []byte) string {
	var env struct {
		Extensions struct {
			Tracing struct {
				Version   any `json:"version"`
				Duration  any `json:"duration"`
				Execution struct {
					Resolvers []json.RawMessage `json:"resolvers"`
				} `json:"execution"`
			} `json:"tracing"`
		} `json:"extensions"`
	}
	if json.Unmarshal(body, &env) != nil {
		return ""
	}
	t := env.Extensions.Tracing
	if t.Version == nil || t.Duration == nil || t.Execution.Resolvers == nil {
		return ""
	}
	return fmt.Sprintf("extensions.tracing (version %v): %d resolver timing(s) in a __typename answer", t.Version, len(t.Execution.Resolvers))
}
