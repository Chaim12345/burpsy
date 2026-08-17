package vulnapp

// host discovery rows.
//
// One file per check family, holding that family's vulnerable endpoints, their safe counterparts and
// the routes serving both. The manifest entries returned here are appended to Vulnerabilities() by
// familyEndpoints in vulnapp.go; the routes are registered by familyRegistrars.
//
// The contract every entry has to meet:
//
//   - Row must match a catalog row name in internal/scanner exactly. The runtime test resolves every
//     Row against the shipped registry before auditing anything, so a typo fails loudly rather than
//     exempting the endpoint from its own assertion.
//   - A vulnerable endpoint needs a safe twin: same Row, Safe: true, reflecting or echoing the same
//     input WITHOUT the defect. That twin is what catches a detector firing on reflection alone.
//     Where no such thing can exist, say why in SafeTwinNotApplicable rather than omitting it.
//   - Handlers must be the real mechanism, not a payload matcher. An endpoint that pattern-matches
//     the payloads it expects grades the check against the fixture author's guesses and passes
//     whether or not the detector works.
//
// Corresponding scanner descriptors: HostDiscoveryCheckDescriptors.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
)

// Per-host rows share one SafeTwinNotApplicable reason: each check is DispatchScopePerHost and probes
// a fixed, well-known host path, so on the single host the harness serves a "safe" twin that
// withheld the file would also remove the vulnerable behaviour — no same-host counterpart can exist
// without deleting the very thing the row is about.
const perHostNoSafeTwin = "the check is DispatchScopePerHost and fetches a fixed well-known host " +
	"path (e.g. /robots.txt), so a same-host twin that withheld the file would also disable the " +
	"vulnerable twin on the one host the harness serves; no same-host safe counterpart can exist"

// discoveryEndpoints returns this family's manifest entries.
//
// All five rows are DispatchScopePerHost. The checks ignore the seeded exchange's own path and fetch
// fixed host-relative paths, so every entry below only needs to exist so the harness seeds an
// exchange on this host; the check does the real probing. TRACE uses "/?probe=trace" rather than "/"
// because "/" is already the crawlable home support route and two entries with the same Path would
// collide in the harness's per-path exchange map.
func discoveryEndpoints() []Endpoint {
	return []Endpoint{
		{
			Path: "/robots.txt",
			Row:  "Robots.txt file",
			Note: "serves a real robots.txt (User-agent:/Disallow:) at the exact path checkRobotsTxtFile fetches",
			// checkRobotsTxtFile fetches /robots.txt and requires a User-agent:/Disallow: directive.
			SafeTwinNotApplicable: perHostNoSafeTwin,
		},
		{
			Path: "/swagger.json",
			Row:  "OpenAPI definition found (active scan check)",
			Note: "serves an OpenAPI/Swagger document body naming itself at one of the paths checkOpenAPIDefinitionFound probes",
			// checkOpenAPIDefinitionFound probes a fixed list of candidate paths; /swagger.json is one
			// of them and the body contains the literal "swagger" keyword the check keys on.
			SafeTwinNotApplicable: perHostNoSafeTwin,
		},
		{
			Path:        "/graphql",
			Method:      "POST",
			Body:        `{"query":"query{__typename}"}`,
			ContentType: "application/json; charset=utf-8",
			Row:         "GraphQL endpoint discovered",
			Note:        "mounts a GraphQL endpoint answering query{__typename} with a data.__typename response",
			// checkGraphQLEndpointDiscovered POSTs its own query{__typename} and expects data.__typename.
			SafeTwinNotApplicable: perHostNoSafeTwin,
		},
		{
			Path: "/burpsy-put-probe/seed.txt",
			Row:  "HTTP PUT method is enabled",
			Note: "serves a PUT-to-create subtree that persists the body and returns it verbatim on GET",
			// checkHTTPPutEnabled PUTs a canary to /burpsy-put-probe/<canary>.txt and GETs it back; the
			// differential (PUT 2xx + GET serves the body) is what the check confirms.
			SafeTwinNotApplicable: perHostNoSafeTwin,
		},
		{
			Path: "/?probe=trace",
			Row:  "HTTP TRACE method is enabled",
			Note: "TRACE to / is echoed by the home handler; checkHTTPTraceEnabled sends TRACE to / itself",
			// checkHTTPTraceEnabled sends TRACE to "/" (hardcoded) and looks for its canary echoed back.
			SafeTwinNotApplicable: perHostNoSafeTwin,
		},
	}
}

// putProbeStore persists PUT bodies in memory, keyed by the full request path, so the subsequent GET
// the check makes returns exactly what was written. A real filesystem is not used: this is a test
// target, and writing files from a scan probe would be a side effect the tool has no business causing.
type putProbeStore struct {
	mu sync.Mutex
	m  map[string][]byte
}

// registerDiscovery serves this family's routes.
//
// The four well-known paths are served outside the /dc/ prefix on purpose: each is hardcoded by its
// check (checkRobotsTxtFile -> /robots.txt, checkOpenAPIDefinitionFound -> one of a fixed candidate
// list, checkGraphQLEndpointDiscovered -> /graphql, checkHTTPPutEnabled -> /burpsy-put-probe/<canary>),
// so a prefix is impossible. TRACE needs no handler here — its echo lives in the home handler because
// the check targets "/", which home already owns.
func registerDiscovery(mux *http.ServeMux) {
	// /robots.txt — checkRobotsTxtFile fetches this exact path and requires a real directive line.
	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "User-agent: *\nDisallow: /admin\n")
	})

	// /swagger.json — one of the candidate paths checkOpenAPIDefinitionFound probes; the body names
	// itself as a Swagger document, which is the only evidence the check accepts (a bare 200 is not).
	mux.HandleFunc("/swagger.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"swagger":"2.0","info":{"title":"Demo API","version":"1.0"},"paths":{}}`)
	})

	// /graphql — checkGraphQLEndpointDiscovered POSTs `query{__typename}` and confirms a data.__typename
	// answer. The handler answers every POST that way; it models a real GraphQL endpoint, not a matcher.
	mux.HandleFunc("/graphql", func(w http.ResponseWriter, r *http.Request) {
		// Parses the query rather than answering every POST with the evidence.
		//
		// The first version returned {"data":{"__typename":"Query"}} unconditionally, without
		// reading the body - which is a static file at /graphql wearing GraphQL's evidence. It would
		// have satisfied the check for an empty body, a malformed one, or no query at all, so the row
		// demonstrated only that the check can substring-match a constant: it could not catch a
		// regression where the check stopped sending the query, sent it to the wrong path, or sent it
		// with the wrong content type.
		w.Header().Set("Content-Type", "application/json")
		var req struct {
			Query string `json:"query"`
		}
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
		if err := json.Unmarshal(body, &req); err != nil || strings.TrimSpace(req.Query) == "" {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"errors":[{"message":"no GraphQL query provided"}]}`)
			return
		}
		if !strings.Contains(req.Query, "__typename") {
			fmt.Fprint(w, `{"errors":[{"message":"Cannot query field on type Query"}]}`)
			return
		}
		fmt.Fprint(w, `{"data":{"__typename":"Query"}}`)
	})

	// /burpsy-put-probe/ — checkHTTPPutEnabled PUTs a canary to /burpsy-put-probe/<canary>.txt and then
	// GETs the same path. This subtree stores the PUT body and serves it back, which is the differential
	// the check uses to tell "PUT created a retrievable file" from "PUT was ignored with a 2xx". The
	// canary lives in its own path segment on purpose: a single random filename is unroutable by
	// ServeMux (no mid-segment wildcard, and a root catch-all would shadow siblings), whereas a subtree
	// match is.
	store := &putProbeStore{m: make(map[string][]byte)}
	mux.HandleFunc("/burpsy-put-probe/", func(w http.ResponseWriter, r *http.Request) {
		key := r.URL.Path
		switch r.Method {
		case http.MethodPut:
			body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
			if err != nil {
				http.Error(w, "read failed", http.StatusBadRequest)
				return
			}
			store.mu.Lock()
			store.m[key] = body
			store.mu.Unlock()
			w.WriteHeader(http.StatusCreated)
		default:
			store.mu.Lock()
			body, ok := store.m[key]
			store.mu.Unlock()
			if !ok {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "text/plain")
			w.Write(body)
		}
	})
}
