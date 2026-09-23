package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/scanner"
	"go.uber.org/zap"
)

// ---- Passively scan a branch (burpsy-react-ui-p09) ---------------------------------------------
//
// The scanning itself is internal/scanner's, tested there. What is tested here is the accounting,
// because that is where this endpoint can lie: a sweep that reports a finding count without saying
// how much of the branch the count covers is unreconcilable against anything an operator can see.
//
// The invariant every test below leans on:
//
//	scanned + skipped_out_of_scope + skipped_no_response + filtered == matched
//
// and the scope decision it encodes — the sweep filters by the CURRENT scope, which may be narrower
// than the one those bytes were captured under, and says how many it refused for that reason rather
// than skipping them silently.

// passiveBranchServer is organizerTestServer with a passive scanner attached, since the handler
// refuses without one — correctly, because a sweep with no scanner would answer 200 with zero
// findings, which reads as a clean branch.
//
// scanner.NewPassiveScanner loads no BCheck corpus, so Loaded() is 0 and the built-in checks
// (security headers, information disclosure) are what run. That is the right shape for these tests:
// what is under test is the accounting, and a corpus would make the finding counts depend on which
// checks happen to fire.
func passiveBranchServer(t *testing.T) *Server {
	t.Helper()
	s := organizerTestServer(t)
	return s.WithPassiveScanner(scanner.NewPassiveScanner(s.store, zap.NewNop())).
		WithFindings(core.NewFindingStore())
}

func passiveBranch(t *testing.T, s *Server, body string) passiveBranchResp {
	t.Helper()
	rec := httptest.NewRecorder()
	s.handlePassiveBranch(rec, httptest.NewRequest(http.MethodPost, "/api/scanner/passive-branch",
		strings.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("POST passive-branch = %d, body %q", rec.Code, rec.Body.String())
	}
	var out passiveBranchResp
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v — %q", err, rec.Body.String())
	}
	return out
}

// assertPartition is the property that makes the report readable as coverage.
func assertPartition(t *testing.T, r passiveBranchResp) {
	t.Helper()
	sum := r.Scanned + r.SkippedOutOfScope + r.SkippedNoResponse + r.Filtered
	if sum != r.Matched {
		t.Errorf("the counts do not partition: scanned %d + out-of-scope %d + no-response %d = %d, "+
			"but %d matched the branch. An operator cannot answer 'what happened to the other ones', "+
			"which is the whole point of reporting them separately",
			r.Scanned, r.SkippedOutOfScope, r.SkippedNoResponse, sum, r.Matched)
	}
}

func TestPassiveBranchScansOnlyTheBranch(t *testing.T) {
	s := passiveBranchServer(t)
	captureExchange(t, s, "target.test", "/app/one", 200, "text/html")
	captureExchange(t, s, "target.test", "/app/two", 200, "text/html")
	captureExchange(t, s, "target.test", "/other", 200, "text/html")
	captureExchange(t, s, "elsewhere.test", "/app/three", 200, "text/html")

	r := passiveBranch(t, s, `{"host":"target.test","path_prefix":"/app"}`)
	assertPartition(t, r)

	if r.Matched != 2 {
		t.Errorf("matched %d, want the 2 under /app on target.test — /other and the other host are "+
			"outside the branch", r.Matched)
	}
}

// A host node means the whole host, which is Burp's "scan this branch" pointed at the root.
func TestAnEmptyPathPrefixMeansTheWholeHost(t *testing.T) {
	s := passiveBranchServer(t)
	captureExchange(t, s, "target.test", "/a", 200, "text/html")
	captureExchange(t, s, "target.test", "/b/c", 200, "text/html")
	captureExchange(t, s, "elsewhere.test", "/a", 200, "text/html")

	r := passiveBranch(t, s, `{"host":"target.test"}`)
	assertPartition(t, r)
	if r.Matched != 2 {
		t.Errorf("matched %d, want both paths on the host", r.Matched)
	}
}

// THE SCOPE DECISION. These bytes were captured, possibly under a wider scope; the sweep refuses them
// under the current one and says how many, because silently skipping would make scanned
// unreconcilable against matched.
func TestExchangesRefusedByTheCurrentScopeAreCountedNotHidden(t *testing.T) {
	s := passiveBranchServer(t)
	// Captured first, while everything was in scope.
	captureExchange(t, s, "target.test", "/in", 200, "text/html")
	captureExchange(t, s, "target.test", "/also-in", 200, "text/html")
	// Then the scope narrows to a different host entirely.
	s.scope.AddInclude("somewhere-else.test")

	r := passiveBranch(t, s, `{"host":"target.test"}`)
	assertPartition(t, r)

	if r.Matched != 2 {
		t.Fatalf("matched %d, want 2 — narrowing the scope must not change what is IN the branch", r.Matched)
	}
	if r.Scanned != 0 {
		t.Errorf("scanned %d, want 0: the current scope excludes this host", r.Scanned)
	}
	if r.SkippedOutOfScope != 2 {
		t.Errorf("skipped_out_of_scope %d, want 2 — an operator who cannot see this number cannot "+
			"explain why a branch of 2 produced 0 scans", r.SkippedOutOfScope)
	}
	if !strings.Contains(r.Summary, "scope") {
		t.Errorf("summary = %q; it must say the scope refused them, or the zero looks like a clean "+
			"branch", r.Summary)
	}
}

// A request with no response is its own bucket: not a failure, not a clean result.
func TestAnExchangeWithNoResponseIsItsOwnBucket(t *testing.T) {
	s := passiveBranchServer(t)
	captureExchange(t, s, "target.test", "/done", 200, "text/html")
	captureRequestOnly(t, s, "target.test", "/pending")

	r := passiveBranch(t, s, `{"host":"target.test"}`)
	assertPartition(t, r)

	if r.Matched != 2 {
		t.Fatalf("matched %d, want 2", r.Matched)
	}
	if r.SkippedNoResponse != 1 {
		t.Errorf("skipped_no_response %d, want 1 — a passive check reads a response, and a request "+
			"still in flight is neither scanned nor a clean result", r.SkippedNoResponse)
	}
}

// An empty branch says so, and says what it does NOT mean.
func TestAnEmptyBranchSaysNothingAboutTheBranch(t *testing.T) {
	s := passiveBranchServer(t)
	r := passiveBranch(t, s, `{"host":"never-seen.test"}`)
	assertPartition(t, r)

	if r.Matched != 0 || r.Scanned != 0 {
		t.Fatalf("matched %d scanned %d, want both 0", r.Matched, r.Scanned)
	}
	if !strings.Contains(r.Summary, "says nothing about the branch") {
		t.Errorf("summary = %q; an empty branch must state that burpsy has not seen it rather than "+
			"reading as a clean result", r.Summary)
	}
}

// No checks loaded is not a clean branch, and the summary must not let it read as one.
func TestNoChecksLoadedIsNotACleanBranch(t *testing.T) {
	s := passiveBranchServer(t)
	captureExchange(t, s, "target.test", "/a", 200, "text/html")

	r := passiveBranch(t, s, `{"host":"target.test"}`)
	if r.Loaded != 0 {
		t.Skipf("this server has %d checks loaded; the no-checks case is covered elsewhere", r.Loaded)
	}
	if !strings.Contains(r.Summary, "not") || !strings.Contains(r.Summary, "clean branch") {
		t.Errorf("summary = %q; with no checks loaded the sweep could not have found anything, and "+
			"that must not render like a branch that came back clean", r.Summary)
	}
}

// A host is required. Defaulting to the whole store would silently do what the live audit does.
func TestPassiveBranchRefusesAnEmptyHost(t *testing.T) {
	s := organizerTestServer(t)
	rec := httptest.NewRecorder()
	s.handlePassiveBranch(rec, httptest.NewRequest(http.MethodPost, "/api/scanner/passive-branch",
		strings.NewReader(`{"host":"  "}`)))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status %d for an empty host, want 400 — a sweep with no host is the whole store, "+
			"which is not what scanning a branch means", rec.Code)
	}
}

// Host matching folds case, because DNS names do; path matching does not, per RFC 3986 and matching
// the query DSL's `path` field rather than inventing a second rule.
func TestBranchMatchingFoldsHostCaseButNotPathCase(t *testing.T) {
	req := passiveBranchReq{Host: "Target.TEST", PathPrefix: "/App"}
	ex := &core.Exchange{Host: "target.test", Port: 443, Path: "/App/x"}
	if !branchContains(ex, req) {
		t.Error("host matching must fold case")
	}
	lower := &core.Exchange{Host: "target.test", Port: 443, Path: "/app/x"}
	if branchContains(lower, req) {
		t.Error("path matching folded case; /App and /app are different resources per RFC 3986, and " +
			"the query DSL's path field already makes that call")
	}
}

// Port zero means every port, because a site-map branch is an authority and an operator pointing at
// a host means both 80 and 443.
func TestPortZeroMeansEveryPort(t *testing.T) {
	req := passiveBranchReq{Host: "target.test"}
	for _, port := range []uint16{80, 443, 8080} {
		if !branchContains(&core.Exchange{Host: "target.test", Port: port, Path: "/x"}, req) {
			t.Errorf("port %d excluded by a request that named no port", port)
		}
	}
	only443 := passiveBranchReq{Host: "target.test", Port: 443}
	if branchContains(&core.Exchange{Host: "target.test", Port: 80, Path: "/x"}, only443) {
		t.Error("a request naming port 443 matched port 80")
	}
}

// ---- the pre-scan filter (burpsy-react-ui-a13) ---------------------------------------------
//
// Burp's scan wizard offers to remove duplicate items, items with no parameters, and items with
// given extensions before the scan starts, each with a live count of what it removes. burpsy's
// ACTIVE scan is a crawl from seeds — there is no item set to filter, and a crawl discovers unique
// URLs by construction, so "remove duplicates" has nothing to remove. The passive branch sweep IS an
// item set (every captured exchange under a host/path), it is where an operator spends a budget,
// and it is the surface whose counts the operator already reads. So the filters landed here,
// expressed in this package's own filter grammar rather than as a second predicate language.

func TestThePreScanFilterRemovesWhatItNamesAndSaysHowMany(t *testing.T) {
	s := passiveBranchServer(t)
	captureExchange(t, s, "target.test", "/app/page", 200, "text/html")
	captureExchange(t, s, "target.test", "/static/app.js", 200, "application/javascript")
	captureExchange(t, s, "target.test", "/static/logo.png", 200, "image/png")
	captureExchange(t, s, "target.test", "/app/api?id=1", 200, "text/html")

	// Burp's shipped extension list, as a query over the grammar. The grammar gives extension =, !=
	// and ~ only — no `in` — so a set of extensions is a disjunction of `=`, which is the same filter
	// the wizard writes, and the server refusing a bad operator is the grammar's own guarantee.
	r := passiveBranch(t, s, `{"host":"target.test","exclude":"not (extension = \"js\" or extension = \"png\")"}`)
	assertPartition(t, r)

	if r.Filtered != 2 {
		t.Errorf("filtered %d, want the 2 static assets removed — the filter is the reason an "+
			"operator aimed a bounded sweep at the pages instead", r.Filtered)
	}
	if r.Scanned != 2 {
		t.Errorf("scanned %d, want the 2 pages that survived the filter", r.Scanned)
	}
	if r.Exclude == "" {
		t.Error("the response does not echo the filter it applied, so a caller cannot state which rule shaped this sweep")
	}
}

func TestAnEmptyPreScanFilterScansExactlyWhatItDidBefore(t *testing.T) {
	s := passiveBranchServer(t)
	captureExchange(t, s, "target.test", "/one", 200, "text/html")
	captureExchange(t, s, "target.test", "/two", 200, "text/html")

	r := passiveBranch(t, s, `{"host":"target.test","exclude":""}`)
	assertPartition(t, r)
	if r.Filtered != 0 || r.Scanned != 2 {
		t.Errorf("an absent filter changed the sweep: filtered %d, scanned %d — every caller that "+
			"predates the field must be unaffected by it", r.Filtered, r.Scanned)
	}
}

func TestAMalformedPreScanFilterIsRefusedRatherThanIgnored(t *testing.T) {
	s := passiveBranchServer(t)
	captureExchange(t, s, "target.test", "/one", 200, "text/html")

	rec := httptest.NewRecorder()
	s.handlePassiveBranch(rec, httptest.NewRequest(http.MethodPost, "/api/scanner/passive-branch",
		strings.NewReader(`{"host":"target.test","exclude":"extension in"}`)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST with a malformed filter = %d, want 400: a filter the server cannot parse must "+
			"not be answered with a sweep that silently ignored it", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "pre-scan filter") {
		t.Errorf("the refusal does not say which field was wrong: %q", rec.Body.String())
	}
}

func TestThePreScanFilterRunsBeforeTheSweepsOwnGates(t *testing.T) {
	s := passiveBranchServer(t)
	// No response, so the no-response bucket would claim it — unless the filter has already
	// removed it. Counting it in both would break the partition and double-count the operator's
	// budget decision.
	id := captureExchange(t, s, "target.test", "/pending", 200, "text/html")
	ex, err := s.store.GetExchange(core.ExchangeID(id))
	if err != nil {
		t.Fatalf("get exchange: %v", err)
	}
	ex.Response = nil

	r := passiveBranch(t, s, `{"host":"target.test","exclude":"path = \"/pending\""}`)
	assertPartition(t, r)
	if r.Filtered != 1 {
		t.Errorf("filtered %d, want the response-less exchange removed by the filter", r.Filtered)
	}
	if r.SkippedNoResponse != 0 {
		t.Errorf("skipped_no_response %d, want 0: the filter is the operator's decision and runs "+
			"first, so this exchange is filtered, not skipped", r.SkippedNoResponse)
	}
}
