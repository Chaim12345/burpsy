package web

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

// burpsy-react-ui-tyso: a named configuration's five crawler/customization discovery switches —
// parse_api_definitions, parse_soap_wsdls, perform_graphql_introspection,
// guess_hidden_graphql_endpoints and application_uses_fragments_for_routing — reach the crawl an
// operator starts through POST /api/crawl. The parser reported them applied (so the start reply did
// not name them as unapplied) and the crawler implements every one, but crawlConfig never set them,
// so a configuration turning them on crawled with all five off. The same defect PR #337 fixed for the
// form threshold (crawl_form_threshold_route_test.go), five times over.
//
// Every assertion is on what the TARGET saw — the requests that reached the wire — or on the run's
// own report, never on the Config literal: a field set on a literal the crawl never reads would pass
// a literal check, which is the shape of the defect itself.

// switchSite is one origin whose handler records every request it receives, so "the crawl sent X" is
// an observation by the target rather than an inference from a count.
type switchSite struct {
	srv  *httptest.Server
	mu   sync.Mutex
	seen []string // "METHOD /path" and, for an introspection query, a " introspection" suffix
}

func newSwitchSite(t *testing.T, routes map[string]func(w http.ResponseWriter, r *http.Request)) *switchSite {
	t.Helper()
	site := &switchSite{}
	site.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		entry := r.Method + " " + r.URL.Path
		if strings.Contains(string(body), "__schema") {
			entry += " introspection"
		}
		site.mu.Lock()
		site.seen = append(site.seen, entry)
		site.mu.Unlock()
		if h, ok := routes[r.URL.Path]; ok {
			h(w, r)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(site.srv.Close)
	return site
}

// count is how many recorded requests equal entry exactly.
func (s *switchSite) count(entry string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, e := range s.seen {
		if e == entry {
			n++
		}
	}
	return n
}

func (s *switchSite) log() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.seen...)
}

func serve(contentType, body string) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", contentType)
		_, _ = w.Write([]byte(body))
	}
}

// switchRun is one crawl started through the route: its start reply's unapplied list and the report
// fields these switches move, read off the same GET /api/crawl the console polls.
type switchRun struct {
	run       crawlRunResp
	unapplied []string
	report    struct {
		APIDocumentsRead      int `json:"api_documents_read"`
		APIEndpointsFound     int `json:"api_endpoints_found"`
		GraphQLEndpointsFound int `json:"graphql_endpoints_found"`
	}
}

func startSwitchCrawl(t *testing.T, s *Server, seed, config string, maxRequests int) switchRun {
	t.Helper()
	body := map[string]any{"seeds": []string{seed}, "max_requests": maxRequests, "max_depth": 5}
	if config != "" {
		body["config"] = config
	}
	rec := postJSON(t, s, "/api/crawl", body)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("POST /api/crawl: %d %s", rec.Code, rec.Body.String())
	}
	var start struct {
		TaskID    uint64   `json:"task_id"`
		Unapplied []string `json:"config_unapplied_keys"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &start); err != nil {
		t.Fatalf("decode start: %v", err)
	}
	var out switchRun
	out.unapplied = start.Unapplied
	out.run = waitForCrawl(t, s, start.TaskID)
	if out.run.State != "done" || out.run.Report == nil {
		t.Fatalf("crawl state %q (%s), report %v", out.run.State, out.run.Error, out.run.Report != nil)
	}
	got := get(t, s, "/api/crawl?task="+strconv.FormatUint(start.TaskID, 10))
	var full struct {
		Report json.RawMessage `json:"report"`
	}
	if err := json.Unmarshal(got.Body.Bytes(), &full); err != nil {
		t.Fatalf("decode run: %v", err)
	}
	if err := json.Unmarshal(full.Report, &out.report); err != nil {
		t.Fatalf("decode report: %v", err)
	}
	return out
}

// saveSwitchConfig saves a named configuration carrying one customization key at value on.
func saveSwitchConfig(t *testing.T, s *Server, name, key string, on bool) {
	t.Helper()
	doc := `{"crawler":{"customization":{"` + key + `":` + strconv.FormatBool(on) + `}}}`
	if _, err := s.persist.SaveScanConfigLibrary(name, doc); err != nil {
		t.Fatalf("save configuration %q: %v", name, err)
	}
}

// assertApplied fails if the start reply listed key as unapplied: the engine honours it, so naming it
// would be false — and, now that it is wired, NOT naming it is a claim the crawl below has to prove.
func assertApplied(t *testing.T, r switchRun, key string) {
	t.Helper()
	for _, k := range r.unapplied {
		if strings.Contains(k, key) {
			t.Errorf("the start reply lists %q as unapplied; the crawler implements %s", k, key)
		}
	}
}

// excludePath adds an engagement-scope exclusion for one path prefix on the test host, so a request the
// switch causes can be shown to stop at the scope gate rather than reach the target.
func excludePath(t *testing.T, s *Server, host, prefix string) {
	t.Helper()
	p := prefix
	rule, err := core.NewScopeRuleFrom(core.ScopeExclude, host, &p, nil, nil)
	if err != nil {
		t.Fatalf("exclude rule: %v", err)
	}
	s.scope.Add(rule)
}

// switchCase is the three crawls every switch gets: no configuration (today's operator default), a
// configuration naming the key false (must match the default — wiring a key in may only change
// behaviour when a configuration turns it on), and one naming it true.
func runSwitchCases(t *testing.T, s *Server, key string, seed func() string, observed func() int) (off, named, on int, onRun switchRun) {
	t.Helper()
	saveSwitchConfig(t, s, key+" off", key, false)
	saveSwitchConfig(t, s, key+" on", key, true)

	before := observed()
	startSwitchCrawl(t, s, seed(), "", 200)
	off = observed() - before

	before = observed()
	r := startSwitchCrawl(t, s, seed(), key+" off", 200)
	named = observed() - before
	assertApplied(t, r, key)

	before = observed()
	onRun = startSwitchCrawl(t, s, seed(), key+" on", 200)
	on = observed() - before
	assertApplied(t, onRun, key)
	return off, named, on, onRun
}

const openAPIDoc = `{"openapi":"3.0.0","info":{"title":"t","version":"1"},"paths":{
  "/api/widgets":{"get":{"operationId":"listWidgets"}},
  "/api/private":{"get":{"operationId":"listPrivate"}}}}`

func TestParseAPIDefinitionsFromANamedConfigReachesTheCrawl(t *testing.T) {
	const key = "parse_api_definitions"
	s, _ := newTestServerWithDB(t)
	site := newSwitchSite(t, map[string]func(http.ResponseWriter, *http.Request){
		"/":             serve("text/html", `<html><body><a href="/openapi.json">api</a></body></html>`),
		"/openapi.json": serve("application/json", openAPIDoc),
		"/api/widgets":  serve("application/json", `{"widgets":[]}`),
		"/api/private":  serve("application/json", `{"private":[]}`),
	})
	u, _ := url.Parse(site.srv.URL)
	s.scope.AddInclude(u.Hostname())
	// The definition's second operation is outside the engagement scope: turning the reader on must
	// widen what the crawl LEARNS, never what it is allowed to send.
	excludePath(t, s, u.Hostname(), "/api/private")

	off, named, on, onRun := runSwitchCases(t, s, key,
		func() string { return site.srv.URL + "/" },
		func() int { return site.count("GET /api/widgets") })

	if off != 0 || named != 0 {
		t.Errorf("GET /api/widgets sent %d times with no configuration and %d under %s=false; the "+
			"definition must not be read unless a configuration turns it on", off, named, key)
	}
	if on != 1 {
		t.Errorf("GET /api/widgets sent %d times under %s=true, want 1: the reply did not list the key "+
			"as unapplied, so it claimed a reader that never reached the crawler; target saw %v", on, key, site.log())
	}
	if onRun.report.APIDocumentsRead != 1 {
		t.Errorf("api_documents_read = %d under %s=true, want 1", onRun.report.APIDocumentsRead, key)
	}
	if n := site.count("GET /api/private"); n != 0 {
		t.Errorf("an out-of-scope operation the definition declared reached the target %d times", n)
	}
	if onRun.run.skipCount("api-location-out-of-scope")+onRun.run.skipCount("out-of-scope") == 0 {
		t.Errorf("the out-of-scope operation was dropped with no recorded reason; skips %+v", onRun.run.Report.Skips.Counts)
	}
}

const switchWSDL = `<?xml version="1.0"?>
<wsdl:definitions xmlns:wsdl="http://schemas.xmlsoap.org/wsdl/" xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/">
  <wsdl:binding name="B">
    <wsdl:operation name="GetUser"><soap:operation soapAction="urn:GetUser"/></wsdl:operation>
    <wsdl:operation name="ListUsers"><soap:operation soapAction="urn:ListUsers"/></wsdl:operation>
  </wsdl:binding>
</wsdl:definitions>`

// A WSDL's operations are counted, not fetched: the reader does not invent a service path (see
// crawler.apiEndpointPath), so this switch sends no new traffic and the observable difference is the
// report. The WSDL itself is fetched either way, as an ordinary linked document.
func TestParseSOAPWSDLsFromANamedConfigReachesTheCrawl(t *testing.T) {
	const key = "parse_soap_wsdls"
	s, _ := newTestServerWithDB(t)
	site := newSwitchSite(t, map[string]func(http.ResponseWriter, *http.Request){
		"/":        serve("text/html", `<html><body><a href="/service">wsdl</a></body></html>`),
		"/service": serve("application/wsdl+xml", switchWSDL),
	})
	u, _ := url.Parse(site.srv.URL)
	s.scope.AddInclude(u.Hostname())

	saveSwitchConfig(t, s, "wsdl off", key, false)
	saveSwitchConfig(t, s, "wsdl on", key, true)
	for _, tc := range []struct {
		config string
		want   int
	}{{"", 0}, {"wsdl off", 0}, {"wsdl on", 1}} {
		r := startSwitchCrawl(t, s, site.srv.URL+"/", tc.config, 200)
		if tc.config != "" {
			assertApplied(t, r, key)
		}
		if r.report.APIDocumentsRead != tc.want {
			t.Errorf("config %q: api_documents_read = %d, want %d; target saw %v",
				tc.config, r.report.APIDocumentsRead, tc.want, site.log())
		}
		wantOps := 0
		if tc.want == 1 {
			wantOps = 2
		}
		if r.report.APIEndpointsFound != wantOps {
			t.Errorf("config %q: api_endpoints_found = %d, want %d", tc.config, r.report.APIEndpointsFound, wantOps)
		}
	}
	// The WSDL reader adds a count, never traffic: the document is fetched once per crawl, as an
	// ordinary linked document, whatever the switch says.
	if n := site.count("GET /service"); n != 3 {
		t.Errorf("GET /service sent %d times across three crawls, want 3; target saw %v", n, site.log())
	}
	for _, e := range site.log() {
		if strings.HasPrefix(e, "POST ") {
			t.Errorf("the WSDL switch caused a POST %q", e)
		}
	}
}

const switchIntrospectionAnswer = `{"data":{"__schema":{"queryType":{"name":"Query"},"types":[
  {"name":"Query","kind":"OBJECT","fields":[{"name":"user","args":[{"name":"id"}]}]},
  {"name":"String","kind":"SCALAR","fields":null}]}}}`

// graphqlEndpoint answers a GET with a GraphQL error envelope — what makes the crawl recognise it as
// an endpoint — and an introspection POST with a schema.
func graphqlEndpoint(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method == http.MethodPost {
		_, _ = w.Write([]byte(switchIntrospectionAnswer))
		return
	}
	_, _ = w.Write([]byte(`{"errors":[{"message":"must provide a query"}]}`))
}

func TestPerformGraphQLIntrospectionFromANamedConfigReachesTheCrawl(t *testing.T) {
	const key = "perform_graphql_introspection"
	s, _ := newTestServerWithDB(t)
	site := newSwitchSite(t, map[string]func(http.ResponseWriter, *http.Request){
		"/":        serve("text/html", `<html><body><a href="/graphql">gql</a></body></html>`),
		"/graphql": graphqlEndpoint,
	})
	u, _ := url.Parse(site.srv.URL)
	s.scope.AddInclude(u.Hostname())

	off, named, on, onRun := runSwitchCases(t, s, key,
		func() string { return site.srv.URL + "/" },
		func() int { return site.count("POST /graphql introspection") })

	if off != 0 || named != 0 {
		t.Errorf("an introspection query was sent %d times with no configuration and %d under %s=false; "+
			"the crawl must not POST of its own initiative unless a configuration asks", off, named, key)
	}
	if on != 1 {
		t.Errorf("introspection sent %d times under %s=true, want 1; target saw %v", on, key, site.log())
	}
	if onRun.report.GraphQLEndpointsFound == 0 {
		t.Errorf("graphql_endpoints_found = 0 under %s=true; the answer declared an operation", key)
	}

	// The request bound holds for the introspection query: with the budget spent on the endpoint's own
	// GET, the query is not sent and the reason is recorded rather than the bound silently exceeded.
	before := site.count("POST /graphql introspection")
	r := startSwitchCrawl(t, s, site.srv.URL+"/graphql", key+" on", 1)
	if n := site.count("POST /graphql introspection") - before; n != 0 {
		t.Errorf("an introspection query was sent %d times past a spent max_requests=1", n)
	}
	if r.run.skipCount("graphql-not-probed") == 0 {
		t.Errorf("the budget-refused introspection recorded no graphql-not-probed skip; skips %+v", r.run.Report.Skips.Counts)
	}
}

func TestGuessHiddenGraphQLEndpointsFromANamedConfigReachesTheCrawl(t *testing.T) {
	const key = "guess_hidden_graphql_endpoints"
	s, _ := newTestServerWithDB(t)
	// No page links any GraphQL path: every probe the target sees is a guess.
	site := newSwitchSite(t, map[string]func(http.ResponseWriter, *http.Request){
		"/": serve("text/html", `<html><body><p>nothing linked</p></body></html>`),
	})
	u, _ := url.Parse(site.srv.URL)
	s.scope.AddInclude(u.Hostname())
	// One of the four guessed paths is excluded from the engagement scope: the guess must stop at the
	// scope gate there and still probe the other three.
	excludePath(t, s, u.Hostname(), "/gql")

	probes := func() int {
		return site.count("POST /graphql introspection") + site.count("POST /api/graphql introspection") +
			site.count("POST /query introspection")
	}
	off, named, on, onRun := runSwitchCases(t, s, key, func() string { return site.srv.URL + "/" }, probes)

	if off != 0 || named != 0 {
		t.Errorf("hidden-GraphQL probes sent %d times with no configuration and %d under %s=false; Burp "+
			"ships this off and so must an operator crawl that did not ask", off, named, key)
	}
	if on != 3 {
		t.Errorf("hidden-GraphQL probes sent %d times under %s=true, want the 3 in-scope guesses; target saw %v",
			on, key, site.log())
	}
	if n := site.count("POST /gql introspection"); n != 0 {
		t.Errorf("a guessed path excluded from scope reached the target %d times", n)
	}
	if onRun.run.skipCount("send-refused")+onRun.run.skipCount("out-of-scope") == 0 {
		t.Errorf("the out-of-scope guess was dropped with no recorded reason; skips %+v", onRun.run.Report.Skips.Counts)
	}

	// The request bound holds for the guesses: the seed spends max_requests=1, so no probe is sent.
	before := probes() + site.count("POST /gql introspection")
	r := startSwitchCrawl(t, s, site.srv.URL+"/", key+" on", 1)
	if n := probes() + site.count("POST /gql introspection") - before; n != 0 {
		t.Errorf("%d hidden-GraphQL probes were sent past a spent max_requests=1", n)
	}
	if r.run.skipCount("graphql-not-probed") == 0 {
		t.Errorf("the budget-refused guesses recorded no graphql-not-probed skip; skips %+v", r.run.Report.Skips.Counts)
	}
}

// The forcing half of fragment routing: `#orders` has none of Burp's routing characters, so the
// automatic rule (always on) treats it as an in-page anchor and the page is one location. Forced, each
// fragment is a route and the document is fetched once per route — the fragment itself never sent.
func TestApplicationUsesFragmentsForRoutingFromANamedConfigReachesTheCrawl(t *testing.T) {
	const key = "application_uses_fragments_for_routing"
	s, _ := newTestServerWithDB(t)
	site := newSwitchSite(t, map[string]func(http.ResponseWriter, *http.Request){
		"/": serve("text/html", `<html><body><a href="#orders">orders</a><a href="#settings">settings</a></body></html>`),
	})
	u, _ := url.Parse(site.srv.URL)
	s.scope.AddInclude(u.Hostname())

	off, named, on, _ := runSwitchCases(t, s, key,
		func() string { return site.srv.URL + "/" },
		func() int { return site.count("GET /") })

	if off != 1 || named != 1 {
		t.Errorf("GET / sent %d times with no configuration and %d under %s=false, want 1 each: an "+
			"anchor-shaped fragment is not a route unless a configuration forces it", off, named, key)
	}
	if on != 3 {
		t.Errorf("GET / sent %d times under %s=true, want 3 (the page plus one per forced route); target saw %v",
			on, key, site.log())
	}
}

// The reporting half: with all five set in one configuration, none of them is listed as unapplied —
// each is proven applied by its own test above — while a key this engine genuinely cannot honour,
// set in the same file, still is. A reply that dropped the honest entry along with the false ones
// would read as "everything applied".
func TestTheFiveDiscoverySwitchesAreNotListedUnappliedButAnUnhonouredKeyStillIs(t *testing.T) {
	s, _ := newTestServerWithDB(t)
	site := newSwitchSite(t, map[string]func(http.ResponseWriter, *http.Request){
		"/": serve("text/html", `<html><body>x</body></html>`),
	})
	u, _ := url.Parse(site.srv.URL)
	s.scope.AddInclude(u.Hostname())
	if _, err := s.persist.SaveScanConfigLibrary("all five", `{"crawler":{"customization":{
	  "parse_api_definitions":true,"parse_soap_wsdls":true,"perform_graphql_introspection":true,
	  "guess_hidden_graphql_endpoints":true,"application_uses_fragments_for_routing":true,
	  "allow_all_clickables":true}}}`); err != nil {
		t.Fatalf("save configuration: %v", err)
	}
	r := startSwitchCrawl(t, s, site.srv.URL+"/", "all five", 200)
	for _, key := range []string{"parse_api_definitions", "parse_soap_wsdls", "perform_graphql_introspection",
		"guess_hidden_graphql_endpoints", "application_uses_fragments_for_routing"} {
		assertApplied(t, r, key)
	}
	found := false
	for _, k := range r.unapplied {
		if k == "customization/allow_all_clickables" {
			found = true
		}
	}
	if !found {
		t.Errorf("config_unapplied_keys = %v, want it to name customization/allow_all_clickables, which "+
			"this engine has no field for", r.unapplied)
	}
}
