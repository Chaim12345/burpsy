package web

// ---- API-only scan -------------------------------------------------------------------------------
//
// Burp's fourth scan kind (Zhw0 in the 2026.7.1 teardown: the New-scan dialog's "API-only scan") is
// the one whose seed is not a URL. The operator hands over an API *definition* and the scan sends the
// endpoints the document describes, instead of discovering endpoints by crawling.
//
// The document-reading half is internal/apidoc. This file is the launch surface, and it is deliberately
// thin: everything that makes a burpsy scan a burpsy scan — the scope chokepoint every request is
// re-authorised through, the rate limiters, the capture-and-passive-scan path, the dashboard task row,
// the bounded-run event — comes from the crawl engine, which runs here in seeds-only mode
// (crawler.Config.SeedsOnly). A definition sweep therefore cannot send a request a crawl could not
// send, cannot appear in history where a crawl would not appear, and cannot be audited by a different
// auditer than a crawl's audit half. The one thing this file adds is the document.
//
// # What it will not do quietly
//
//   - A document that cannot be read is a 400 naming what it actually is (an AsyncAPI file, a Postman
//     collection, a Swagger 1.x document), never a run that reports "0 endpoints" — see apidoc.Parse.
//   - A document with no `servers` and no `base_url` supplied is a 400 asking for one, rather than a
//     scan against a guessed host.
//   - A base URL whose host cannot be in scope under any rule is a 400 before the task is registered,
//     because the alternative is a twelve-endpoint sweep that is twelve refusals and a report the
//     operator has to read to find that out.
//   - A definition worth more endpoints than the run's request budget defaults to the document's own
//     count, not to a cap: a scan whose promise is "these N endpoints" and which quietly sent 500 of
//     3000 would be the exact over-claim this project treats as a defect.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/burpsy-go/burpsy/internal/apidoc"
	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/crawler"
	"github.com/burpsy-go/burpsy/internal/dash"
	"github.com/burpsy-go/burpsy/internal/intruder"
	"github.com/burpsy-go/burpsy/internal/scanner"
)

// runKindAPIScan is the kind recorded on a retained run for a definition-driven sweep. It shares
// crawls' run registry with the two crawl kinds — one place answers "what scan was that", and a
// definition sweep is a scan like any other — and is distinguished by this value in the run record and
// by dash.KindAPIScan on the task row.
const runKindAPIScan = "api-scan"

// apiScanOperation is one endpoint as the run record reports it: enough for an operator to check "did
// it send the endpoints I expected" without the record carrying every parameter value back.
type apiScanOperation struct {
	Method   string `json:"method"`
	Template string `json:"template"`
	Path     string `json:"path"`
}

// apiScanSummary describes the definition a run was built from.
//
// The two value counts are the honest-reporting half of the feature and the reason a definition sweep
// can be trusted or distrusted on sight. A definition that supplies examples for every parameter
// drives a scan of the API as its authors documented it; one that supplies none drives a scan of
// placeholders this build invented. Both are legitimate, and they are not the same result — so the
// reply says which, in numbers and in a sentence, rather than presenting both as "12 endpoints sent".
type apiScanSummary struct {
	Format      string   `json:"format"`
	Title       string   `json:"title,omitempty"`
	Version     string   `json:"version,omitempty"`
	SpecVersion string   `json:"spec_version"`
	Servers     []string `json:"servers,omitempty"`
	// BaseURL is the URL the paths were resolved against: the caller's override, or the document's
	// first server. Recorded because the document's own `servers` may hold several, and a report that
	// named only the document would not say which host this run actually dialled.
	BaseURL string `json:"base_url"`
	// Operations is every endpoint the run was built to send, in the order it was built (which is
	// apidoc's sorted order, not the document's — see apidoc.Parse).
	Operations []apiScanOperation `json:"operations"`
	// DeclaredValues counts every parameter value the run carried, invented or not, and
	// PlaceholderValues the subset this build made up. PlaceholderNote is the same fact as a sentence,
	// so a UI that shows one line does not have to do the arithmetic to be readable.
	DeclaredValues    int    `json:"declared_values"`
	PlaceholderValues int    `json:"placeholder_values"`
	PlaceholderNote   string `json:"placeholder_note"`
}

// apiScanReq is the POST body.
type apiScanReq struct {
	// LoginPagePattern is the login-page recogniser, exactly as on a crawl (burpsy-react-ui-nc9s).
	// Carried on both request types because both launch the same engine in a different mode, and a
	// session rule that keeps a crawl alive should keep an API scan alive for the same reason.
	LoginPagePattern string `json:"login_page_pattern,omitempty"`
	// Definition is the document itself, as text. JSON or YAML; see apidoc. Required.
	Definition string `json:"definition"`
	// BaseURL overrides the document's own `servers`. Required when the document declares none, and
	// accepted when it declares some, because an operator testing a staging copy of a documented API
	// should not have to edit the file to point at it.
	BaseURL string `json:"base_url"`
	// Audit is whether to run the active scan over the endpoints once they have been fetched. A
	// pointer so that "not sent" and "sent false" are different requests: an API-only *scan* audits by
	// default (that is what Burp's kind does), and a bare endpoint sweep is the operator asking for the
	// other thing explicitly.
	Audit *bool `json:"audit"`
	// DryRun reads the document and answers with what a run *would* send, starting nothing. It is what
	// makes the wizard's API step possible: the operator sees the endpoint count and how many values
	// this build would have to invent before committing to a sweep, rather than discovering both in a
	// report afterwards. Same parse, same resolution, same refusals — the only thing skipped is the
	// task.
	DryRun bool `json:"dry_run"`
	// MaxRequests caps the sweep below the definition's own endpoint count. Zero means no cap of its
	// own: the run's budget is the number of operations, so a definition sweep sends what the document
	// describes.
	MaxRequests int `json:"max_requests"`
	// Pool names a saved resource pool, or RequestsPerSecond states the rate inline — never both. The
	// two rules and their reasons are resolveRunRate's.
	Pool              string  `json:"pool"`
	RequestsPerSecond float64 `json:"requests_per_second"`
	// UserAgent and Headers are the crawl engine's: an API scan of an authenticated API needs the same
	// credential headers a crawl does.
	UserAgent string            `json:"user_agent"`
	Headers   map[string]string `json:"headers"`
}

// handleAPIScan serves POST /api/apiscan. There is no GET: a run started here is retained in the same
// registry the crawls are (crawlRuns), so GET /api/crawl?task=N answers for it — including the
// definition summary on the run record. Two read doors onto one registry would be two chances for them
// to disagree about what a run was.
func (s *Server) handleAPIScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req apiScanReq
	if err := requestJSON(w, r, http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}
	if req.DryRun {
		// 200, not 202: nothing was accepted, because nothing was started. A check that answered 202
		// with a task id would be a dry run that leaves a task row behind.
		summary, err := s.checkAPIScan(req)
		if err != nil {
			http.Error(w, err.Error(), crawlStartStatus(err))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"dry_run": true, "definition": summary})
		return
	}
	taskID, summary, err := s.startAPIScan(req)
	if err != nil {
		http.Error(w, err.Error(), crawlStartStatus(err))
		return
	}
	run, ok := s.crawls.get(taskID)
	state, kind := "", runKindAPIScan
	if ok {
		state = run.State
		kind = run.Kind
	}
	audit := true
	if req.Audit != nil {
		audit = *req.Audit
	}
	writeJSON(w, http.StatusAccepted, map[string]any{
		"task_id": taskID,
		"state":   state,
		"kind":    kind,
		// Echoed for the same reason /api/crawl echoes its kind: a reply that looked the same whether
		// the audit half was accepted could not be told apart from one that accepted the sweep alone.
		"audit":      audit,
		"definition": summary,
	})
}

// startAPIScan parses a definition, resolves it into concrete requests, registers the task and starts
// the sweep. It returns the task id and the summary that goes on both the reply and the run record.
//
// Synchronous through the parse and the resolution, and asynchronous only from the first request
// onwards. That split is deliberate: a document that cannot be read is a mistake the operator can fix
// in the dialog, so it is a 400 with the parser's own words; a sweep of three hundred endpoints is
// work, so it is a 202 and a task. Anything in between would be a request held open for the length of
// a scan without ever having been a scan.
func (s *Server) startAPIScan(req apiScanReq) (uint64, *apiScanSummary, error) {
	requests, summary, base, err := s.prepareAPIScan(req)
	if err != nil {
		return 0, nil, err
	}

	poolLimit, err := s.resolveRunRate(req.Pool, req.RequestsPerSecond)
	if err != nil {
		return 0, nil, err
	}

	limits := crawler.DefaultLimits()
	// The definition's own count is the budget, so a sweep sends what the document describes. Capped
	// below only when the operator says so, and never raised above the count: there is nothing to send
	// past the last endpoint.
	if req.MaxRequests > 0 && req.MaxRequests < len(requests) {
		limits.MaxRequests = req.MaxRequests
	} else {
		limits.MaxRequests = len(requests)
	}
	// MaxDepth is left at the engine's default and is inert here: every seeds-only item is depth 0, and
	// nothing is ever discovered to deepen the frontier. Named because a reader comparing this config to
	// the crawl's will look for it.

	c, err := crawler.New(s.apiScanConfig(req, requests, limits, poolLimit))
	if err != nil {
		return 0, nil, err
	}
	c.WithSuiteGate(s.tasks.GateCheck)

	audit := true
	if req.Audit != nil {
		audit = *req.Audit
	}
	target := apiScanTarget(summary, base, len(requests))
	task := s.tasks.Start(dash.KindAPIScan, target, uint64(limits.MaxRequests))
	// The effective bounds, for the same reason a crawl records them (qzzy): an operator asking what
	// stopped an API sweep needs an answer that exists before the run finishes.
	s.crawls.start(task.ID(), seedURLs(requests), runKindAPIScan, limits)
	s.crawls.setDefinition(task.ID(), summary)
	c.WithTaskID(task.ID())

	// Detached from the request context for the same reason a crawl is: the sweep outlives the HTTP
	// call that started it. The bounds that stop it are the engine's own — MaxRequests here, plus the
	// request budget and the duration limit reported in the Report either way.
	go func() {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		rep := c.Run(ctx)
		s.crawls.finish(task.ID(), &rep, nil)
		task.SetNote(apiScanNote(&rep, summary))
		task.Advance(uint64(rep.Fetched))
		if audit {
			// Before Finish, for the reason the crawl's audit half is: the audit's own task id is
			// handed to the findings it produces, and the sweep's row stays open while it runs, so the
			// two rows read as one scan's two halves — which is what the operator launched.
			s.auditFetchedExchanges(ctx, &rep, "API scan of "+base.Host)
		}
		task.Finish(dash.Breakdown{})
		// changeHistory covers the exchanges the sweep just produced and every traffic-derived count;
		// changeIssues covers the passive findings from the same fetches. Both, because an API sweep
		// moves both at once exactly as a crawl does.
		s.live.notify(changeHistory)
		s.live.notify(changeIssues)
		s.live.notify(changeDashboard)
	}()

	return task.ID(), summary, nil
}

// checkAPIScan answers what a run would send, and starts nothing. See apiScanReq.DryRun.
//
// It shares prepareAPIScan with startAPIScan rather than re-parsing, which is the property that makes
// the wizard's preview trustworthy: the count the operator approves in the dialog and the count the run
// sends come from one parse, so a document the preview accepted cannot be refused a second later — the
// failure mode a separate "validate" path always eventually grows.
func (s *Server) checkAPIScan(req apiScanReq) (*apiScanSummary, error) {
	_, summary, _, err := s.prepareAPIScan(req)
	return summary, err
}

// prepareAPIScan is the whole read of a definition, shared by the dry run and the launch: parse it,
// decide the host, refuse a host no scope rule can reach, and resolve every operation into the request
// that will be sent.
func (s *Server) prepareAPIScan(req apiScanReq) ([]crawler.SeedRequest, *apiScanSummary, *url.URL, error) {
	source := strings.TrimSpace(req.Definition)
	if source == "" {
		return nil, nil, nil, errors.New("no API definition was given: paste or upload the document (OpenAPI 3.x and Swagger 2.0, JSON or YAML)")
	}
	doc, err := apidoc.Parse([]byte(source))
	if err != nil {
		return nil, nil, nil, err
	}
	base, err := resolveBaseURL(doc, req.BaseURL)
	if err != nil {
		return nil, nil, nil, err
	}
	// The pre-filter, not the authoriser: MayContainHost answers "could this host be in scope at all",
	// so a document pointing somewhere no rule reaches is refused before a task row exists. It is a
	// stricter question than Contains — it ignores path- and protocol-scoped rules that leave the host
	// partly reachable — which is what keeps this from refusing a run whose endpoints are in scope. The
	// real gate still runs on every request: AuthorisedSender re-reads the bytes actually going out, so
	// this check buys a better error message and nothing else. That is the whole intent, and it is why
	// it is a refusal here rather than a refusal count in a report nobody reads until afterwards.
	if !s.scope.MayContainHost(base.Hostname(), scopePort(base), strings.EqualFold(base.Scheme, "https")) {
		return nil, nil, nil, fmt.Errorf(
			"the definition's base URL %s is out of scope, so every one of its %d endpoint(s) would be refused at the scope chokepoint. %s",
			base, len(doc.Operations),
			s.scope.Explain(base.Hostname(), scopePort(base), "/", strings.EqualFold(base.Scheme, "https")))
	}
	requests, operations, err := resolveOperations(doc, base)
	if err != nil {
		return nil, nil, nil, err
	}
	summary := &apiScanSummary{
		Format:            string(doc.Format),
		Title:             doc.Title,
		Version:           doc.Version,
		SpecVersion:       doc.SpecVersion,
		Servers:           doc.Servers,
		BaseURL:           base.String(),
		Operations:        operations,
		DeclaredValues:    doc.DeclaredValues(),
		PlaceholderValues: doc.PlaceholderValues(),
		PlaceholderNote:   placeholderNote(doc.DeclaredValues(), doc.PlaceholderValues()),
	}
	return requests, summary, base, nil
}

// resolveBaseURL decides which host the document's paths are resolved against: the caller's override
// first, then the document's own first server.
//
// A document that declares neither is refused rather than scanned against a guess. A relative server
// URL (`/api/v1`, legal in OpenAPI) is refused with the same message, because the host it is relative
// *to* is where the document was published — and this build reads documents that were pasted, so it
// has no such host. Removing the guess is the point: a scan that dialled a host nobody named would be
// sending an engagement's traffic somewhere the operator never authorised, and the scope gate would
// answer "out of scope" only if they were lucky enough to have one configured.
func resolveBaseURL(doc *apidoc.Document, override string) (*url.URL, error) {
	raw := strings.TrimSpace(override)
	if raw == "" && len(doc.Servers) > 0 {
		raw = doc.Servers[0]
	}
	if raw == "" {
		return nil, fmt.Errorf(
			"the definition declares no `servers` (or `host`/`basePath`), so it does not say which host its "+
				"%d path(s) are on. Give the base URL to scan, for example https://api.example.com",
			len(doc.Operations))
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("base URL %q is not a URL: %w", raw, err)
	}
	if !strings.EqualFold(u.Scheme, "http") && !strings.EqualFold(u.Scheme, "https") {
		return nil, fmt.Errorf("base URL %q has scheme %q; an API scan can only send http or https, and a relative server URL needs the host it is relative to", raw, u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("base URL %q has no host", raw)
	}
	u.Fragment, u.RawFragment = "", ""
	return u, nil
}

// resolveOperations turns every described operation into the request the engine will send, and returns
// the compact list the run record reports.
//
// It refuses rather than drops, and that is the one judgement in here worth stating. Two operations
// declaring the same header name with different values cannot both be sent on one request, and the
// three ways to resolve that are: silently keep one (a scan that sent something other than the
// document), send the request twice, once per header set (a scan that sent more than the document,
// and the same endpoint counting twice), or refuse the document and name the header. The third is
// right for the reason a scan of a *definition* exists at all: the operator's question is "does my API
// behave under its own contract", and an answer computed from a contract this build silently rewrote
// is not an answer to that question.
func resolveOperations(doc *apidoc.Document, base *url.URL) ([]crawler.SeedRequest, []apiScanOperation, error) {
	requests := make([]crawler.SeedRequest, 0, len(doc.Operations))
	operations := make([]apiScanOperation, 0, len(doc.Operations))
	root := strings.TrimRight(base.String(), "/")
	for _, op := range doc.Operations {
		path := op.Path
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		headers := make(map[string]string, len(op.Header))
		for _, h := range op.Header {
			if existing, seen := headers[h.Name]; seen && existing != h.Value {
				return nil, nil, fmt.Errorf(
					"%s %s declares the header %q twice with different values (%q and %q); one request cannot carry both, and this build will not choose one for you",
					op.Method, op.Template, h.Name, existing, h.Value)
			}
			headers[h.Name] = h.Value
		}
		requests = append(requests, crawler.SeedRequest{
			Method:      op.Method,
			URL:         root + path,
			Headers:     headers,
			Body:        op.Body,
			ContentType: op.ContentType,
		})
		operations = append(operations, apiScanOperation{Method: op.Method, Template: op.Template, Path: path})
	}
	return requests, operations, nil
}

// seedURLs is the request URLs, for the retained run's Seeds field — the same field a crawl fills, so
// "what did this scan point at" has one answer in one place for both kinds.
func seedURLs(requests []crawler.SeedRequest) []string {
	out := make([]string, 0, len(requests))
	for _, req := range requests {
		out = append(out, req.URL)
	}
	return out
}

// apiScanTarget names the run for its task row: the document's title where it has one, the base host
// otherwise, always with the endpoint count. The count is part of the name rather than only of the
// total because a definition's size is the first thing an operator wants to check against their
// expectation — "Petstore (12 endpoints)" either matches the document they pasted or it does not, and
// they can tell before the sweep finishes.
func apiScanTarget(summary *apiScanSummary, base *url.URL, endpoints int) string {
	name := strings.TrimSpace(summary.Title)
	if name == "" {
		return fmt.Sprintf("%s (%d endpoint(s))", base.Host, endpoints)
	}
	if v := strings.TrimSpace(summary.Version); v != "" {
		name += " " + v
	}
	return fmt.Sprintf("%s (%d endpoint(s))", name, endpoints)
}

// apiScanNote is the task row's closing sentence. It states the two numbers that decide how the run
// should be read — how much of it was driven by the document, and whether it reached the end of its own
// endpoint list — rather than the engine's generic fetch/refuse/fail triple alone.
func apiScanNote(rep *crawler.Report, summary *apiScanSummary) string {
	note := fmt.Sprintf("%d fetched, %d refused, %d failed; %s",
		rep.Fetched, rep.Refused, rep.Failed, summary.PlaceholderNote)
	if remaining := rep.Limits.FrontierRemaining; remaining > 0 {
		note += fmt.Sprintf("; %d endpoint(s) were never sent", remaining)
	}
	return note
}

// placeholderNote renders the value provenance as one sentence.
//
// "0 of 12 parameter values were invented" and "12 of 12 … were invented" are the same endpoint count
// and different scans, so this sentence is the difference between a report an operator can act on and
// one that needs the definition reopened to interpret. The distinction is carried in prose rather than
// only as two integers because a UI showing the endpoint count alone would present both scans
// identically.
//
// Every arm names the three places it is talking about — path, query string and headers — because a
// synthesised request *body* is counted by neither number (see apidoc's PlaceholderValues). A sentence
// that said "all parameter values came from the document" while the body was this build's own
// invention would be true of the two integers and false of the request.
func placeholderNote(declared, placeholders int) string {
	if declared == 0 {
		return "the definition declares no path, query or header parameters, so each request was sent as its path and, where the document describes one, its body alone"
	}
	if placeholders == 0 {
		return fmt.Sprintf("all %d path, query and header value(s) came from the definition's own examples, defaults or enums", declared)
	}
	if placeholders == declared {
		return fmt.Sprintf(
			"all %d path, query and header value(s) were invented by this build: the definition supplies no example, default or enum for any of them, so the values are recognisable placeholders rather than data",
			declared)
	}
	return fmt.Sprintf(
		"%d of the %d path, query and header value(s) were invented by this build, because the definition supplies no example, default or enum for them",
		placeholders, declared)
}

// scopePort reads a URL's port with the scheme's default filled in, which is the form core.Scope's
// rules are matched against. A rule written as `https://api.example.com` has port 443, not 0, so
// asking the scope about port 0 would answer about a host nobody named.
func scopePort(u *url.URL) uint16 {
	if p := u.Port(); p != "" {
		if n, err := strconv.ParseUint(p, 10, 16); err == nil {
			return uint16(n)
		}
	}
	if strings.EqualFold(u.Scheme, "https") {
		return 443
	}
	return 80
}

// apiScanConfig is the crawler configuration an API scan runs under, extracted for the same reason as
// crawlConfig (burpsy-react-ui-nc9s): a field missing from a struct literal nobody inspects is
// invisible, and this literal was missing the re-login seam exactly as the crawl's was.
//
// Both modes go through the same coordinator, so a session rule that keeps a crawl alive keeps an
// API scan alive — and there is one place that knows how a re-login happens rather than two that
// can disagree.
func (s *Server) apiScanConfig(req apiScanReq, requests []crawler.SeedRequest, limits crawler.Limits, poolLimit *intruder.RateLimit) crawler.Config {
	return crawler.Config{
		SeedsOnly:    true,
		SeedRequests: requests,
		Scope:        s.scope,
		Sender:       s.sender,
		// SourceCrawl, deliberately, and not a source of its own. `Source` answers "which surface
		// produced this exchange", and the honest answer is the crawler: this *is* the crawl engine, in
		// the mode where the frontier is given rather than discovered. A source of its own would also
		// have to be taught to every surface that enumerates sources — the capture histogram, the
		// suite-search tool filter, HTTP history's exclusions — and a half-taught enum value is a
		// traffic class that quietly disappears from a view. Which of the two crawler modes produced a
		// row is answered where it belongs: by the run record's kind and Definition, and by the task
		// row's kind.
		Capture: scanner.Capture{
			Store:    s.store,
			Scanner:  s.passiveScanner,
			Findings: s.findings,
			Logger:   s.logger,
			Source:   core.SourceCrawl,
		},
		Limits:            limits,
		RequestsPerSecond: req.RequestsPerSecond,
		Pool:              poolLimit,
		UserAgent:         req.UserAgent,
		Headers:           req.Headers,
		Logger:            s.logger,
		// The re-login seam, for the same reason the crawl config has it (burpsy-react-ui-nc9s): an
		// API scan walks exactly the routes a crawl would, and a session that dies partway through
		// leaves it enumerating authenticated endpoints from the login redirect onwards. Both crawl
		// modes go through the same coordinator, so there is one place that knows how a re-login
		// happens rather than two that can disagree.
		SessionCoordinator: s.crawlSessionCoordinator(),
		LoginPagePattern:   req.LoginPagePattern,
	}
}
