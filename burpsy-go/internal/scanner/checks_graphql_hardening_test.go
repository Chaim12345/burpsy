package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/vulnapp"
	"github.com/burpsy-go/burpsy/pkg/graphqlmap"
	"go.uber.org/zap"
)

// The GraphQL rows (burpsy-react-ui-0vzb.13) against the vulnapp /gql family, with only the
// GraphQL switches and the SQL row on, plus unit tests of each evidence rule on bodies a
// misbehaving server could send.

var (
	gqlTargetOnce sync.Once
	gqlTargetRT   *runtimeTarget
	gqlMemoMu     sync.Mutex
	gqlMemo       = map[string][]*Finding{}
)

func gqlTarget(t *testing.T) *runtimeTarget {
	t.Helper()
	gqlTargetOnce.Do(func() {
		srv := httptest.NewServer(vulnapp.Handler())
		host, portStr, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
		var port uint16
		fmt.Sscanf(portStr, "%d", &port)
		rt := &runtimeTarget{srv: srv, host: host, port: port, store: core.NewTrafficStore(), exchanges: map[string]core.ExchangeID{}}
		client := &http.Client{Timeout: 10 * time.Second}
		for _, e := range vulnapp.Vulnerabilities() {
			if strings.HasPrefix(e.Path, "/gql/") || strings.HasPrefix(e.Path, "/rm/") && strings.Contains(e.Path, "graphql") {
				if _, seen := rt.exchanges[e.Path]; !seen {
					rt.seed(t, client, e)
				}
			}
		}
		gqlTargetRT = rt
	})
	if gqlTargetRT == nil {
		t.Fatal("GraphQL target did not start")
	}
	return gqlTargetRT
}

func gqlAudit(t *testing.T, path string, cfg *ScanConfig) []*Finding {
	t.Helper()
	rt := gqlTarget(t)
	key := path + fmt.Sprintf("|%v|%v|%v", cfg.CheckGraphQLHardening, cfg.CheckSqli, cfg.CheckExtendedActive)
	gqlMemoMu.Lock()
	if got, ok := gqlMemo[key]; ok {
		gqlMemoMu.Unlock()
		return got
	}
	gqlMemoMu.Unlock()
	id, ok := rt.exchanges[path]
	if !ok {
		t.Fatalf("%s was never seeded", path)
	}
	scan := NewActiveScanner(rt.store, zap.NewNop()).WithSender(runtimeSender()).WithConfig(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	outcome, fs := scan.AuditWithin(ctx, id, scan.AuditConfig())
	if outcome.Error != "" {
		t.Fatalf("audit of %s failed: %s", path, outcome.Error)
	}
	gqlMemoMu.Lock()
	gqlMemo[key] = fs
	gqlMemoMu.Unlock()
	return fs
}

func gqlFinding(fs []*Finding, name string) *Finding {
	for _, f := range fs {
		if f != nil && f.Name == name {
			return f
		}
	}
	return nil
}

func gqlHardeningOnly() *ScanConfig {
	return &ScanConfig{MaxConcurrency: 2, Timeout: 2 * time.Minute, CheckGraphQLHardening: true}
}

// Each hardening row fires on /gql/api with the evidence its rule names, and stays quiet on the
// hardened twin.
func TestGraphQLHardeningRowsOnTheVulnerableServerAndItsTwin(t *testing.T) {
	vuln := gqlAudit(t, "/gql/api", gqlHardeningOnly())
	for name, want := range map[string]string{
		IssueGraphQLBatching: "array batching: 10 operations",
		IssueGraphQLDepth:    "nested 10 object fields deep (category > parent > parent > parent",
		IssueGraphQLDebug:    "errors[0].extensions.exception.stacktrace",
	} {
		f := gqlFinding(vuln, name)
		if f == nil {
			t.Errorf("%q not reported on /gql/api", name)
			continue
		}
		if !strings.Contains(f.Evidence, want) {
			t.Errorf("%q evidence = %q, want it to contain %q", name, f.Evidence, want)
		}
	}
	if f := gqlFinding(vuln, IssueGraphQLBatching); f != nil && (!strings.Contains(f.Evidence, "alias overloading: 100 aliases") || f.Severity != "low") {
		t.Errorf("batching finding = %s %q, want low and both mechanisms", f.Severity, f.Evidence)
	}
	safe := gqlAudit(t, "/gql/safe/api", gqlHardeningOnly())
	for _, name := range []string{IssueGraphQLBatching, IssueGraphQLDepth, IssueGraphQLDebug} {
		if f := gqlFinding(safe, name); f != nil {
			t.Errorf("%q reported on the hardened twin: %q", name, f.Evidence)
		}
	}
	// The switch is the gate: with it off, nothing GraphQL-specific is probed or reported.
	off := gqlAudit(t, "/gql/api", &ScanConfig{MaxConcurrency: 2, Timeout: time.Minute, CheckSqli: false})
	for _, name := range []string{IssueGraphQLBatching, IssueGraphQLDepth, IssueGraphQLDebug} {
		if gqlFinding(off, name) != nil {
			t.Errorf("%q reported with check_graphql_hardening off", name)
		}
	}
}

// SQL injection through a GraphQL argument: the SQL row reaches book(title:) only through the
// nested GraphQL insertion point, and the finding names that argument.
func TestSQLInjectionThroughAGraphQLArgument(t *testing.T) {
	cfg := &ScanConfig{MaxConcurrency: 2, Timeout: 2 * time.Minute, CheckSqli: true}
	f := gqlFinding(gqlAudit(t, "/gql/api", cfg), "SQL injection")
	if f == nil {
		t.Fatal("book(title:) concatenates its argument into SQL but the SQL row was not reported on /gql/api")
	}
	if !strings.Contains(f.Param, "graphql:title") {
		t.Errorf("SQL finding param = %q, want the GraphQL argument point query[graphql:title]", f.Param)
	}
	if g := gqlFinding(gqlAudit(t, "/gql/safe/api", cfg), "SQL injection"); g != nil {
		t.Errorf("SQL row reported on the bound-value twin: %s %q", g.Param, g.Evidence)
	}
}

// ---------------------------------------------------------------------------
// Evidence rules on hostile bodies
// ---------------------------------------------------------------------------

// A batch answer counts only when each element carries the alias sent at its position. A server
// that answers every element with the same fixed body (a cache, an echo, a canned response) does
// not batch anything, and neither does one that answers the right count in the wrong order.
func TestGraphQLBatchAnsweredNeedsEachAliasInPlace(t *testing.T) {
	aliases := []string{"bsyA", "bsyB", "bsyC"}
	ok := `[{"data":{"bsyA":"Query"}},{"data":{"bsyB":"Query"}},{"data":{"bsyC":"Query"}}]`
	if n := graphQLBatchAnswered([]byte(ok), aliases); n != 3 {
		t.Fatalf("a real batch answer counted %d, want 3", n)
	}
	for _, body := range []string{
		`[{"data":{"__typename":"Query"}},{"data":{"__typename":"Query"}},{"data":{"__typename":"Query"}}]`,
		`[{"data":{"bsyB":"Query"}},{"data":{"bsyA":"Query"}},{"data":{"bsyC":"Query"}}]`,
		`{"data":{"bsyA":"Query"}}`,
		`[{"data":{"bsyA":"Query"}},{"errors":[{"message":"batching disabled"}]},{"data":{"bsyC":"Query"}}]`,
	} {
		if n := graphQLBatchAnswered([]byte(body), aliases); n == 3 {
			t.Errorf("%s counted as a full batch", body)
		}
	}
}

// Stack frames are recognised in each server family's format, only inside errors/extensions, and
// a lone location line or a frame-looking message is not a trace.
func TestGraphQLStackFramesRecogniseTracesNotLocations(t *testing.T) {
	for name, body := range map[string]string{
		"apollo": `{"errors":[{"message":"x","extensions":{"exception":{"stacktrace":["GraphQLError: x","    at syntaxError (/app/node_modules/graphql/error/syntaxError.js:15:10)","    at Parser.parseDocument (/app/node_modules/graphql/language/parser.js:121:11)"]}}}]}`,
		"python": `{"errors":[{"message":"x","extensions":{"exception":{"stack":["  File \"/app/views.py\", line 12, in resolve\n    raise X\n","  File \"/usr/lib/graphql/execute.py\", line 40, in run\n"]}}}]}`,
		"java":   `{"errors":[{"message":"x","extensions":{"trace":"java.lang.NullPointerException\n\tat com.acme.Resolver.book(Resolver.java:42)\n\tat graphql.execution.ExecutionStrategy.fetch(ExecutionStrategy.java:280)"}}]}`,
		"dotnet": `{"errors":[{"message":"x","extensions":{"stackTrace":"   at Acme.Query.Book() in /src/Query.cs:line 12\n   at HotChocolate.Execute() in /src/Exec.cs:line 88"}}]}`,
		"ruby":   `{"errors":[{"message":"x","extensions":{"backtrace":["/app/graph/types/query.rb:12:in 'book'","/gems/graphql/execute.rb:40:in 'call'"]}}]}`,
	} {
		if _, frames := graphQLStackFrames([]byte(body)); len(frames) < 2 {
			t.Errorf("%s trace not recognised: %v", name, frames)
		}
	}
	for name, body := range map[string]string{
		"location only": `{"errors":[{"message":"Syntax Error: Expected Name, found <EOF>.","locations":[{"line":1,"column":12}]}]}`,
		"at-position":   `{"errors":[{"message":"Unexpected token\nat 1:12\nat 2:3"}]}`,
		"one frame":     `{"errors":[{"message":"x","extensions":{"stacktrace":["    at f (/app/x.js:1:2)"]}}]}`,
		"in data":       `{"data":{"log":"    at f (/app/x.js:1:2)\n    at g (/app/y.js:3:4)"}}`,
	} {
		if _, frames := graphQLStackFrames([]byte(body)); len(frames) >= 2 {
			t.Errorf("%s read as a stack trace: %v", name, frames)
		}
	}
}

func TestGraphQLTracingNeedsResolverTimings(t *testing.T) {
	on := `{"data":{"a":"Query"},"extensions":{"tracing":{"version":1,"startTime":"t","endTime":"t","duration":1200,"execution":{"resolvers":[{"path":["a"],"duration":5}]}}}}`
	if graphQLTracing([]byte(on)) == "" {
		t.Fatal("Apollo tracing not recognised")
	}
	for _, body := range []string{
		`{"data":{"a":"Query"}}`,
		`{"data":{"a":"Query"},"extensions":{"tracing":"enabled"}}`,
		`{"data":{"a":"Query"},"extensions":{"cost":{"requested":1}}}`,
	} {
		if graphQLTracing([]byte(body)) != "" {
			t.Errorf("%s read as tracing", body)
		}
	}
}

func gqlSchema(t *testing.T, types string) *graphqlmap.Schema {
	t.Helper()
	s, err := graphqlmap.ParseSchema(json.RawMessage(`{"__schema":{"queryType":{"name":"Query"},"types":` + types + `}}`))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// The depth path follows the nearest cycle and never fans out: a list field only through a
// limit-style argument set to 1, never a field with a required argument.
func TestGraphQLDepthPathNeverFansOut(t *testing.T) {
	obj := func(n string) string { return `{"kind":"OBJECT","name":"` + n + `","ofType":null}` }
	list := func(n string) string { return `{"kind":"LIST","name":null,"ofType":` + obj(n) + `}` }
	nn := `{"kind":"NON_NULL","name":null,"ofType":{"kind":"SCALAR","name":"ID","ofType":null}}`
	intT := `{"kind":"SCALAR","name":"Int","ofType":null}`

	// User.friends is a list with first:, User.manager needs a required id, so the path is
	// me > friends(first:1) > friends(first:1) ...
	s := gqlSchema(t, `[
		{"kind":"OBJECT","name":"Query","fields":[{"name":"me","args":[],"type":`+obj("User")+`}]},
		{"kind":"OBJECT","name":"User","fields":[
			{"name":"friends","args":[{"name":"first","type":`+intT+`,"defaultValue":null}],"type":`+list("User")+`},
			{"name":"manager","args":[{"name":"id","type":`+nn+`,"defaultValue":null}],"type":`+obj("User")+`}]}]`)
	path, ok := graphQLDepthPath(s, 5)
	if !ok || strings.Join(path, ">") != "me>friends(first:1)>friends(first:1)>friends(first:1)>friends(first:1)" {
		t.Fatalf("path = %v %v", path, ok)
	}

	// A cycle only through an unbounded list, or only through a required argument, is no path.
	for _, types := range []string{
		`[{"kind":"OBJECT","name":"Query","fields":[{"name":"me","args":[],"type":` + obj("User") + `}]},
		  {"kind":"OBJECT","name":"User","fields":[{"name":"friends","args":[],"type":` + list("User") + `}]}]`,
		`[{"kind":"OBJECT","name":"Query","fields":[{"name":"me","args":[],"type":` + obj("User") + `}]},
		  {"kind":"OBJECT","name":"User","fields":[{"name":"manager","args":[{"name":"id","type":` + nn + `,"defaultValue":null}],"type":` + obj("User") + `}]}]`,
		`[{"kind":"OBJECT","name":"Query","fields":[{"name":"me","args":[],"type":` + obj("User") + `}]},
		  {"kind":"OBJECT","name":"User","fields":[{"name":"name","args":[],"type":{"kind":"SCALAR","name":"String","ofType":null}}]}]`,
	} {
		if path, ok := graphQLDepthPath(gqlSchema(t, types), 5); ok {
			t.Errorf("schema without a bounded cycle gave path %v", path)
		}
	}
}

// The suggestion row does not count a name the probe itself sent: a server echoing the query into
// a "Did you mean" sentence suggests nothing, while a real near-miss suggestion is reported.
func TestGraphQLSuggestionProbeNamesAreNotEvidence(t *testing.T) {
	for name, c := range map[string]struct {
		msg  string
		want bool
	}{
		"echo": {`Cannot query field \"usr\" on type \"Query\". Did you mean \"usr\" or \"nod\"?`, false},
		"real": {`Cannot query field \"usr\" on type \"Query\". Did you mean \"user\" or \"users\"?`, true},
	} {
		msg := c.msg
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"errors":[{"message":"%s"}]}`, msg)
		}))
		f, err := checkGraphQLSuggestions(context.Background(), gqlContextFor(t, srv, nil))
		srv.Close()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if (len(f) > 0) != c.want {
			t.Errorf("%s: findings = %v, want %v", name, f, c.want)
		}
		if c.want && len(f) > 0 && f[0].Evidence != "user, users" {
			t.Errorf("%s: evidence = %q", name, f[0].Evidence)
		}
	}
}

// The probes ask as the captured client: cookies and Authorization come along, framing and
// conditional headers do not, and a cross-site probe carries the cookie alone.
func TestGraphQLProbesCarryTheCapturedSession(t *testing.T) {
	var mu sync.Mutex
	var seen []http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Header.Clone())
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"errors":[{"message":"not authorised"}]}`)
	}))
	defer srv.Close()
	cc := gqlContextFor(t, srv, map[string]string{"Cookie": "sid=s3cr3t", "Authorization": "Bearer tok", "If-None-Match": `"x"`, "Apollo-Require-Preflight": "true"})
	mu.Lock()
	seen = nil
	mu.Unlock()
	if _, err := newGraphQLClient(cc).Execute(context.Background(), "query{__typename}"); err != nil {
		t.Fatal(err)
	}
	if _, err := newCrossSiteGraphQLClient(cc, graphqlmap.WithEncoding(graphqlmap.EncodingForm)).Execute(context.Background(), "query{__typename}"); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 2 {
		t.Fatalf("saw %d probes, want 2", len(seen))
	}
	same, cross := seen[0], seen[1]
	if same.Get("Cookie") != "sid=s3cr3t" || same.Get("Authorization") != "Bearer tok" || same.Get("Apollo-Require-Preflight") != "true" {
		t.Errorf("same-origin probe lost the session: %v", same)
	}
	if same.Get("If-None-Match") != "" || same.Get("Content-Type") != "application/json" {
		t.Errorf("same-origin probe kept a conditional header or the wrong body type: %v", same)
	}
	if cross.Get("Cookie") != "sid=s3cr3t" || cross.Get("Authorization") != "" || cross.Get("Apollo-Require-Preflight") != "" {
		t.Errorf("cross-site probe carried more than the cookie: %v", cross)
	}
}

// gqlContextFor captures one JSON POST to srv's /graphql (with the given request headers) and
// returns a check context for it, with the hardening and Burp GraphQL switches on.
func gqlContextFor(t *testing.T, srv *httptest.Server, headers map[string]string) *CheckContext {
	t.Helper()
	host, portStr, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	var port uint16
	fmt.Sscanf(portStr, "%d", &port)
	rt := &runtimeTarget{srv: srv, host: host, port: port, store: core.NewTrafficStore(), exchanges: map[string]core.ExchangeID{}}
	rt.seed(t, srv.Client(), vulnapp.Endpoint{Path: "/graphql", Method: "POST", Body: `{"query":"{a}"}`, ContentType: "application/json",
		RequestHeaders: headers})
	cfg := &ScanConfig{MaxConcurrency: 1, Timeout: time.Minute, CheckExtendedActive: true, CheckGraphQLHardening: true}
	scan := NewActiveScanner(rt.store, zap.NewNop()).WithSender(runtimeSender()).WithConfig(cfg)
	ex, err := rt.store.GetExchange(rt.exchanges["/graphql"])
	if err != nil {
		t.Fatal(err)
	}
	return &CheckContext{Scanner: scan, Exchange: ex, Config: cfg}
}

// A server that answers every request with the same GraphQL-shaped body - a static file, a cached
// answer, a stub - executes nothing. The alias guard keeps every row that rests on "it answered"
// from firing: the CSRF content-type row and the whole hardening family.
func TestGraphQLRowsIgnoreAFixedGraphQLShapedBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"data":{"__typename":"Query"}}`)
	}))
	defer srv.Close()
	cc := gqlContextFor(t, srv, nil)
	if f, err := checkGraphQLContentType(context.Background(), cc); len(f) != 0 || err != nil {
		t.Errorf("content-type row on a fixed body: %v %v", f, err)
	}
	if f, err := checkGraphQLHardening(context.Background(), cc); len(f) != 0 || err != nil {
		t.Errorf("hardening rows on a fixed body: %v %v", f, err)
	}
}

// fakeGraphQL answers through a TransportFunc: introspection with a self-referential schema,
// everything else through answer, which sees the query text.
func fakeGraphQL(answer func(query string) string) *graphqlmap.Client {
	schema := `{"data":{"__schema":{"queryType":{"name":"Query"},"types":[
		{"kind":"OBJECT","name":"Query","fields":[{"name":"node","args":[],"type":{"kind":"OBJECT","name":"Node","ofType":null}}]},
		{"kind":"OBJECT","name":"Node","fields":[{"name":"parent","args":[],"type":{"kind":"OBJECT","name":"Node","ofType":null}}]}]}}}`
	return graphqlmap.New("http://t/graphql", graphqlmap.TransportFunc(func(_ context.Context, req graphqlmap.Request) (*graphqlmap.Response, error) {
		var body struct {
			Query string `json:"query"`
		}
		_ = json.Unmarshal(req.Body, &body)
		if strings.Contains(body.Query, "__schema") {
			return &graphqlmap.Response{Status: 200, Body: []byte(schema)}, nil
		}
		return &graphqlmap.Response{Status: 200, Body: []byte(answer(body.Query))}, nil
	}))
}

// gqlAliasOf is the alias a probe chose: the name before the first colon after the first brace.
func gqlAliasOf(q string) string {
	q = q[strings.Index(q, "{")+1:]
	return q[:strings.Index(q, ":")]
}

func fakeCC() *CheckContext {
	return &CheckContext{Exchange: &core.Exchange{Host: "t", Port: 80, Method: "POST", Path: "/graphql"}}
}

// The depth row needs an answer under the probe's alias AND no error: a depth limiter that still
// returns partial data with its error is a limit, and data without the alias is not an answer.
func TestGraphQLDepthNeedsAnErrorFreeAnswerUnderTheAlias(t *testing.T) {
	cases := map[string]struct {
		answer func(q string) string
		want   bool
	}{
		"executed": {func(q string) string { return `{"data":{"` + gqlAliasOf(q) + `":{"parent":null}}}` }, true},
		"limited with partial data": {func(q string) string {
			return `{"data":{"` + gqlAliasOf(q) + `":null},"errors":[{"message":"Query depth 11 exceeds the maximum of 8"}]}`
		}, false},
		"no alias": {func(string) string { return `{"data":{"node":{"parent":null}}}` }, false},
	}
	for name, c := range cases {
		f, err := graphQLDepthProbeRun(context.Background(), fakeCC(), fakeGraphQL(c.answer), nil)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if (f != nil) != c.want {
			t.Errorf("%s: finding = %v, want %v", name, f != nil, c.want)
		}
	}
}

// The debug row needs two stack frames from the probe's own error answer; a lone frame or a
// message with positions is not a trace.
func TestGraphQLDebugNeedsTwoFrames(t *testing.T) {
	base := &graphqlmap.Response{Body: []byte(`{"data":{"a":"Query"}}`)}
	for name, c := range map[string]struct {
		body string
		want bool
	}{
		"trace":     {`{"errors":[{"message":"x","extensions":{"stacktrace":["    at a (/app/a.js:1:2)","    at b (/app/b.js:3:4)"]}}]}`, true},
		"one frame": {`{"errors":[{"message":"x","extensions":{"stacktrace":["    at a (/app/a.js:1:2)"]}}]}`, false},
		"positions": {`{"errors":[{"message":"Syntax Error","locations":[{"line":1,"column":30}]}]}`, false},
	} {
		body := c.body
		f, _ := graphQLDebugProbe(context.Background(), fakeCC(), fakeGraphQL(func(string) string { return body }), base)
		if (f != nil) != c.want {
			t.Errorf("%s: finding = %v, want %v", name, f != nil, c.want)
		}
	}
}
