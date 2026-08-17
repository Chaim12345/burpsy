package vulnapp

// GraphQL, JWT forgery, cross-domain policy files, file upload and OpenAPI discovery,
// React2Shell version fingerprinting, the base CORS row, and the SQL-statement-in-parameter
// heuristic. ("SMTP header injection" was dropped after landing here - see the note below.)
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
// Corresponding scanner descriptors: RemainingCheckDescriptors.
//
// Four of this family's rows are deliberately NOT fixtured here, so the gap is legible rather than
// looking like an oversight: "External service interaction (DNS)", "External service interaction
// (HTTP)", "Out-of-band resource load (HTTP)" and "TLS certificate" are all gated behind
// ScanConfig.CheckOutOfBand (oobChecksEnabled = remainingChecksEnabled && CheckOutOfBand), which the
// runtime harness never enables. The first three need a live interactsh collaborator; "TLS
// certificate" needs the tlsx subprocess. Neither is something a fixture inside this Go test binary
// can honestly satisfy, so they are reported as undemonstrable rather than given an endpoint that
// could never be reached by the check that is supposed to prove it.
//
// A fifth row, "SMTP header injection", was built and then removed: checkSMTPHeaderInjection
// (checks_remaining.go) enumerates DefaultProbeInsertionKinds, which includes "header", and every
// exchange this harness seeds carries an Origin header (runtime_coverage_test.go's rt.seed). A
// safe endpoint that never echoes its own input anywhere still had the row fire, because
// ClassifyMailHeaderResponse (infra_smtp.go) falls through to MailInjectionStatusOrBodyDivergence
// - its own doc comment calls this "a weak signal only... plenty of unrelated causes... produce
// the same observation" - and checkSMTPHeaderInjection reports a finding on ANY non-
// MailInjectionNone result, including that one and MailInjectionReflectedVerbatim, which infra_smtp.go
// separately documents as "evidence AGAINST injection, not for it". No fixture-side response body
// can distinguish itself from this once a header-kind insertion point exists at all, so no safe
// twin could be built and demonstrating the row honestly was not possible in the time available.
// Reported to the coordinator as a check defect rather than fixed here.
//
// /graphql at the host root is discovery family's row ("GraphQL endpoint discovered", a different
// row from this family's four); this family's GraphQL endpoints live entirely under /rm/ to avoid
// the collision.

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
)

// remainingEndpoints returns this family's manifest entries.
func remainingEndpoints() []Endpoint {
	return []Endpoint{
		// --- Cross-origin resource sharing (the base, informational row) ---
		{Path: "/rm/catalog", Row: "Cross-origin resource sharing",
			Note: "echoes any Origin straight into Access-Control-Allow-Origin"},
		{Path: "/rm/safe/catalog", Row: "Cross-origin resource sharing", Safe: true,
			Note: "no Access-Control-Allow-Origin header at all"},

		// --- File upload functionality ---
		{Path: "/rm/upload", Row: "File upload functionality",
			Note: "a real multipart form with a file input"},
		{Path: "/rm/safe/upload", Row: "File upload functionality", Safe: true,
			Note: "a form with no file input"},

		// --- Cross-domain policy files: fixed, host-root paths crossDomainPolicyCheck
		// hardcodes (checks_remaining.go), so no /rm/ prefix is possible - see
		// registerRemaining. Approved by the coordinator as a prefix exception, same
		// reasoning already established for discovery family's /robots.txt et al.
		{Path: "/crossdomain.xml", Row: "Flash cross-domain policy",
			Note: "allow-access-from domain=\"*\" trusts every origin",
			// crossDomainPolicyCheck("Flash cross-domain policy", "/crossdomain.xml", ...)
			// fetches this exact host-root path regardless of which exchange triggered it.
			SafeTwinNotApplicable: perHostNoSafeTwin},
		{Path: "/clientaccesspolicy.xml", Row: "Silverlight cross-domain policy",
			Note: "domain uri=\"*\" trusts every origin",
			// crossDomainPolicyCheck("Silverlight cross-domain policy", "/clientaccesspolicy.xml", ...)
			// fetches this exact host-root path regardless of which exchange triggered it.
			SafeTwinNotApplicable: perHostNoSafeTwin},

		// --- GraphQL: one real vulnerable server, two distinct safe twins (see the
		// GraphQL section below for why two are needed rather than one). ---
		{Path: "/rm/graphql", Method: "POST", Body: rmGraphQLSeedBody, ContentType: rmGraphQLContentType,
			Row:  "GraphQL endpoint found",
			Note: "answers a GraphQL query with a data/errors envelope"},
		{Path: "/rm/safe/graphql-absent", Row: "GraphQL endpoint found", Safe: true,
			Note: "an ordinary REST JSON response with no data/errors member"},

		{Path: "/rm/graphql", Method: "POST", Body: rmGraphQLSeedBody, ContentType: rmGraphQLContentType,
			Row:  "GraphQL introspection enabled",
			Note: "answers the full introspection document"},
		{Path: "/rm/safe/graphql", Method: "POST", Body: rmGraphQLSeedBody, ContentType: rmGraphQLContentType,
			Row: "GraphQL introspection enabled", Safe: true,
			Note: "a working GraphQL server that refuses __schema"},

		{Path: "/rm/graphql", Method: "POST", Body: rmGraphQLSeedBody, ContentType: rmGraphQLContentType,
			Row:  "GraphQL suggestions enabled",
			Note: "an unknown field's error names the closest real field"},
		{Path: "/rm/safe/graphql", Method: "POST", Body: rmGraphQLSeedBody, ContentType: rmGraphQLContentType,
			Row: "GraphQL suggestions enabled", Safe: true,
			Note: "an unknown field gets a generic refusal, no hint"},

		{Path: "/rm/graphql", Method: "POST", Body: rmGraphQLSeedBody, ContentType: rmGraphQLContentType,
			Row:  "GraphQL content type not validated",
			Note: "also answers form-encoded and GET-encoded queries"},
		{Path: "/rm/safe/graphql", Method: "POST", Body: rmGraphQLSeedBody, ContentType: rmGraphQLContentType,
			Row: "GraphQL content type not validated", Safe: true,
			Note: "rejects every encoding but JSON POST"},

		// --- JWT forgery: one real signed token, two verifiers of differing rigour. ---
		{Path: "/rm/jwt", RequestHeaders: map[string]string{"Authorization": "Bearer " + rmJWTToken},
			Row:  "JWT signature not verified",
			Note: "decodes claims without ever checking the signature segment"},
		{Path: "/rm/safe/jwt", RequestHeaders: map[string]string{"Authorization": "Bearer " + rmJWTToken},
			Row: "JWT signature not verified", Safe: true,
			Note: "verifies the HMAC-SHA256 signature against the server secret"},

		{Path: "/rm/jwt", RequestHeaders: map[string]string{"Authorization": "Bearer " + rmJWTToken},
			Row:  "JWT none algorithm supported",
			Note: "accepts alg:none (any casing) with an empty signature"},
		{Path: "/rm/safe/jwt", RequestHeaders: map[string]string{"Authorization": "Bearer " + rmJWTToken},
			Row: "JWT none algorithm supported", Safe: true,
			Note: "rejects any alg other than HS256"},

		{Path: "/rm/jwt", RequestHeaders: map[string]string{"Authorization": "Bearer " + rmJWTToken},
			Row:  "JWT self-signed JWK header supported",
			Note: "accepts a token carrying its own jwk header"},
		{Path: "/rm/safe/jwt", RequestHeaders: map[string]string{"Authorization": "Bearer " + rmJWTToken},
			Row: "JWT self-signed JWK header supported", Safe: true,
			Note: "never consults the token's own jwk header"},

		{Path: "/rm/jwks.json", Row: "JWT private key disclosed",
			Note: "the JWKS also publishes d/p/q - a real RSA private key, not placeholder strings"},
		{Path: "/rm/safe/jwks.json", Row: "JWT private key disclosed", Safe: true,
			Note: "the same key's public n/e only"},

		// --- OpenAPI definition found (passive scan check) ---
		{Path: "/rm/api-docs", Row: "OpenAPI definition found (passive scan check)",
			Note: "a response body carrying both an openapi/swagger key and a paths key"},
		{Path: "/rm/safe/api-docs", Row: "OpenAPI definition found (passive scan check)", Safe: true,
			Note: "an ordinary JSON response with neither marker"},

		// --- React Server Components RCE (React2Shell): version fingerprinting ---
		{Path: "/rm/react2shell", Row: "React Server Components remote code execution (React2Shell)",
			Note: "a script src naming a React build inside the affected range (19.1.0)"},
		{Path: "/rm/safe/react2shell", Row: "React Server Components remote code execution (React2Shell)", Safe: true,
			Note: "a script src naming the patched 19.2.1 build"},

		// --- SQL statement in request parameter (checkSQLStatementInParameter is passive
		// over the captured request text; the seeded value is what matters here).
		//
		// bcheck.InsertionPoint.BaseValue is documented as "the value as it appears on the
		// wire, still encoded" (internal/bcheck/insertion.go) - a query-string value can
		// never carry the literal spaces sqlKeywordsInParameter's keywords need, since any
		// real client percent/plus-encodes them. A JSON body value has no such problem:
		// JSON strings carry ordinary spaces unescaped, so the raw bytes bcheck slices out
		// are exactly the submitted text.
		{Path: "/rm/reports", Method: "POST", ContentType: "application/json",
			Body: `{"filter":"select * from orders where status = 'shipped'"}`,
			Row:  "SQL statement in request parameter",
			Note: "the filter value itself carries a raw SQL-shaped fragment"},
		{Path: "/rm/safe/reports", Method: "POST", ContentType: "application/json",
			Body: `{"filter":"status='shipped'"}`,
			Row:  "SQL statement in request parameter", Safe: true,
			Note: "an ordinary filter value with no SQL keywords"},
	}
}

// registerRemaining serves this family's routes.
func registerRemaining(mux *http.ServeMux) {
	mux.HandleFunc("/rm/catalog", rmCatalog)
	mux.HandleFunc("/rm/safe/catalog", rmSafeCatalog)

	mux.HandleFunc("/rm/upload", rmUpload)
	mux.HandleFunc("/rm/safe/upload", rmSafeUpload)

	// Fixed, host-root paths crossDomainPolicyCheck hardcodes - no /rm/ prefix is possible.
	mux.HandleFunc("/crossdomain.xml", rmCrossdomainXML)
	mux.HandleFunc("/clientaccesspolicy.xml", rmClientAccessPolicyXML)

	mux.HandleFunc("/rm/graphql", rmGraphQL)
	mux.HandleFunc("/rm/safe/graphql-absent", rmSafeGraphQLAbsent)
	mux.HandleFunc("/rm/safe/graphql", rmSafeGraphQL)

	mux.HandleFunc("/rm/jwt", rmJWT)
	mux.HandleFunc("/rm/safe/jwt", rmSafeJWT)
	mux.HandleFunc("/rm/jwks.json", rmJWKS)
	mux.HandleFunc("/rm/safe/jwks.json", rmSafeJWKS)

	mux.HandleFunc("/rm/api-docs", rmAPIDocs)
	mux.HandleFunc("/rm/safe/api-docs", rmSafeAPIDocs)

	mux.HandleFunc("/rm/react2shell", rmReact2Shell)
	mux.HandleFunc("/rm/safe/react2shell", rmSafeReact2Shell)

	mux.HandleFunc("/rm/reports", rmReports)
	mux.HandleFunc("/rm/safe/reports", rmReports)
}

// ---------------------------------------------------------------------------
// Cross-origin resource sharing (the base, informational row)
// ---------------------------------------------------------------------------

// rmCatalog answers with whatever Origin the caller sent, echoed straight into
// Access-Control-Allow-Origin - a permissive-by-default JSON API. The base CORS row flags any
// exposed policy regardless of the value, so an echoed Origin is as real a trigger as a
// literal wildcard.
func rmCatalog(w http.ResponseWriter, r *http.Request) {
	if origin := r.Header.Get("Origin"); origin != "" {
		w.Header().Set("Access-Control-Allow-Origin", origin)
	}
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{"catalog":"public"}`)
}

// rmSafeCatalog exposes the identical catalog data with no cross-origin policy at all.
func rmSafeCatalog(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{"catalog":"public"}`)
}

// ---------------------------------------------------------------------------
// File upload functionality
// ---------------------------------------------------------------------------

// rmUpload serves a real upload form and, on POST, genuinely parses the multipart body and
// reads the file's bytes. The bytes are discarded rather than written anywhere - no
// filesystem access, matching this package's own no-real-damage rule (see vulnapp.go's file
// header) - but the multipart parsing and file read are real.
func rmUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		if err := r.ParseMultipartForm(1 << 20); err != nil {
			http.Error(w, "bad upload", http.StatusBadRequest)
			return
		}
		file, header, err := r.FormFile("avatar")
		if err != nil {
			http.Error(w, "missing file field", http.StatusBadRequest)
			return
		}
		defer func() { _ = file.Close() }()
		n, _ := io.Copy(io.Discard, file)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, "<html><body>received %s, %d bytes</body></html>", htmlEscape(header.Filename), n)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, `<html><body>
<form method="post" action="/rm/upload" enctype="multipart/form-data">
<input type="file" name="avatar">
<input type="submit" value="Upload avatar">
</form>
</body></html>`)
}

// rmSafeUpload has a form, so a detector keying on "some form exists" is caught, but no file
// field, so there is nothing to upload.
func rmSafeUpload(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, `<html><body>
<form method="post" action="/rm/safe/upload">
<input type="text" name="displayName">
<input type="submit" value="Save">
</form>
</body></html>`)
}

// ---------------------------------------------------------------------------
// Cross-domain policy files (host-wide, fixed absolute paths)
// ---------------------------------------------------------------------------

// rmCrossdomainXML answers /crossdomain.xml - crossDomainPolicyCheck's hardcoded fetch target
// for "Flash cross-domain policy" - with the real Adobe crossdomain.xml schema, trusting every
// origin, rather than a payload-shaped stand-in.
func rmCrossdomainXML(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/xml")
	fmt.Fprint(w, `<?xml version="1.0"?>
<cross-domain-policy>
	<allow-access-from domain="*"/>
</cross-domain-policy>`)
}

// rmClientAccessPolicyXML answers /clientaccesspolicy.xml - crossDomainPolicyCheck's hardcoded
// fetch target for "Silverlight cross-domain policy" - with the real Microsoft schema,
// granting every origin access.
func rmClientAccessPolicyXML(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/xml")
	fmt.Fprint(w, `<?xml version="1.0" encoding="utf-8"?>
<access-policy>
	<cross-domain-access>
		<policy>
			<allow-from>
				<domain uri="*"/>
			</allow-from>
		</policy>
	</cross-domain-access>
</access-policy>`)
}

// ---------------------------------------------------------------------------
// GraphQL
// ---------------------------------------------------------------------------
//
// /rm/graphql is a small but real GraphQL server: it parses whatever encoding the query
// arrived in (a JSON body, a form body, or a GET query string - the three shapes
// pkg/graphqlmap.Client can send), recognises __schema anywhere in the document as an
// introspection request and answers with a genuine schema, and validates an unknown top-level
// field against that same schema rather than against any one test's literal payload.
//
// Two different safe twins are needed, not one, because "safe" means something different for
// different rows here:
//   - /rm/safe/graphql-absent is not a GraphQL endpoint at all. The safe twin for "GraphQL
//     endpoint found" has to NOT answer like GraphQL, which a hardened GraphQL server can't be
//     - it still answers query{__typename} with a real data envelope.
//   - /rm/safe/graphql IS a real, working GraphQL server: introspection refused, an unknown
//     field given a generic refusal with no field-name hint, and only JSON POST accepted.
//     "introspection enabled" / "suggestions enabled" / "content type not validated" can only
//     be meaningfully disproved by a server that genuinely answers GraphQL everywhere except
//     the one thing each row is specifically about.

const rmGraphQLSeedBody = `{"query":"query{__typename}"}`
const rmGraphQLContentType = "application/json; charset=utf-8"

// rmGraphQLFields is the tiny real schema both GraphQL servers below validate field names
// against - not a list of the checks' own test payloads, so an arbitrary unknown field name
// (not only the one graphqlmap.SuggestionProbe happens to send) is refused the same way.
var rmGraphQLFields = []string{"products", "product"}

// rmParseGraphQLQuery extracts the "query" value from a request under whichever of the three
// wire encodings pkg/graphqlmap.Client can produce (see that package's Client.encode): a JSON
// body, a form-urlencoded body, or a GET ?query= parameter. Recognising all three generically
// is the point of "GraphQL content type not validated" - a server that only understood one
// encoding could never demonstrate the row either way.
func rmParseGraphQLQuery(r *http.Request) (string, bool) {
	if q := r.URL.Query().Get("query"); q != "" {
		return q, true
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	ct := r.Header.Get("Content-Type")
	switch {
	case strings.Contains(ct, "application/json"):
		var payload struct {
			Query string `json:"query"`
		}
		if err := json.Unmarshal(body, &payload); err == nil && payload.Query != "" {
			return payload.Query, true
		}
	case strings.Contains(ct, "application/x-www-form-urlencoded"):
		if vals, err := url.ParseQuery(string(body)); err == nil {
			if q := vals.Get("query"); q != "" {
				return q, true
			}
		}
	}
	return "", false
}

// rmGraphQLTopFieldRe finds the field name immediately inside a query's outermost brace, e.g.
// "query{__typename}" or "query{bsyNoSuchField}". Introspection documents are recognised
// separately, by the literal "__schema" they contain regardless of where it falls: the legacy
// introspection document's first brace belongs to a fragment definition, not to the query
// itself, so this regex alone would miss it.
var rmGraphQLTopFieldRe = regexp.MustCompile(`\{\s*([A-Za-z_][A-Za-z0-9_]*)`)

func rmGraphQLTopField(query string) string {
	m := rmGraphQLTopFieldRe.FindStringSubmatch(query)
	if len(m) != 2 {
		return ""
	}
	return m[1]
}

// rmGraphQLNearestField picks the schema field closest to name by edit distance - a small,
// genuine "did you mean" implementation rather than one hardcoded suggestion string, so it
// answers sensibly for any unrecognised field name, not only the specific one a given probe
// happens to send.
func rmGraphQLNearestField(name string) string {
	best, bestDist := rmGraphQLFields[0], -1
	for _, f := range rmGraphQLFields {
		d := rmLevenshtein(strings.ToLower(name), f)
		if bestDist == -1 || d < bestDist {
			best, bestDist = f, d
		}
	}
	return best
}

func rmLevenshtein(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	prev := make([]int, len(rb)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(ra); i++ {
		cur := make([]int, len(rb)+1)
		cur[0] = i
		for j := 1; j <= len(rb); j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev = cur
	}
	return prev[len(rb)]
}

// rmGraphQLResolve renders {"data":{field:...}} for __typename or one of rmGraphQLFields.
// Callers must only pass a field already known to be one of those.
func rmGraphQLResolve(w http.ResponseWriter, field string) {
	switch field {
	case "__typename":
		fmt.Fprint(w, `{"data":{"__typename":"Query"}}`)
	case "products":
		fmt.Fprint(w, `{"data":{"products":[{"id":"1","name":"Espresso Machine","price":129.99}]}}`)
	case "product":
		fmt.Fprint(w, `{"data":{"product":{"id":"1","name":"Espresso Machine","price":129.99}}}`)
	}
}

// rmGraphQLIntrospectionDoc is a genuine, if small, introspected schema: two real object types
// with real fields and one real String/ID-typed argument, built from Go structs and marshalled
// rather than a hand-typed JSON blob, so its shape can't silently drift from what
// pkg/graphqlmap.ParseSchema expects to decode.
func rmGraphQLIntrospectionDoc() []byte {
	type typeRef struct {
		Kind   string   `json:"kind"`
		Name   string   `json:"name"`
		OfType *typeRef `json:"ofType"`
	}
	type arg struct {
		Name string   `json:"name"`
		Type *typeRef `json:"type"`
	}
	type field struct {
		Name string   `json:"name"`
		Args []arg    `json:"args"`
		Type *typeRef `json:"type"`
	}
	type gqlType struct {
		Kind   string  `json:"kind"`
		Name   string  `json:"name"`
		Fields []field `json:"fields"`
	}
	doc := map[string]any{
		"data": map[string]any{
			"__schema": map[string]any{
				"queryType": map[string]string{"name": "Query"},
				"types": []gqlType{
					{Kind: "OBJECT", Name: "Query", Fields: []field{
						{Name: "products", Args: []arg{}, Type: &typeRef{Kind: "LIST", OfType: &typeRef{Kind: "OBJECT", Name: "Product"}}},
						{Name: "product", Args: []arg{{Name: "id", Type: &typeRef{Kind: "SCALAR", Name: "ID"}}}, Type: &typeRef{Kind: "OBJECT", Name: "Product"}},
					}},
					{Kind: "OBJECT", Name: "Product", Fields: []field{
						{Name: "id", Args: []arg{}, Type: &typeRef{Kind: "SCALAR", Name: "ID"}},
						{Name: "name", Args: []arg{}, Type: &typeRef{Kind: "SCALAR", Name: "String"}},
						{Name: "price", Args: []arg{}, Type: &typeRef{Kind: "SCALAR", Name: "Float"}},
					}},
				},
			},
		},
	}
	enc, _ := json.Marshal(doc)
	return enc
}

// rmGraphQL is the vulnerable endpoint: every encoding is accepted, introspection is answered
// in full, and an unknown field's error names a real close match - "GraphQL introspection
// enabled", "GraphQL suggestions enabled" and "GraphQL content type not validated", plus
// "GraphQL endpoint found" simply by being a genuinely working GraphQL server.
func rmGraphQL(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	query, ok := rmParseGraphQLQuery(r)
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"errors":[{"message":"no query was supplied"}]}`)
		return
	}
	if strings.Contains(query, "__schema") {
		w.Write(rmGraphQLIntrospectionDoc())
		return
	}
	field := rmGraphQLTopField(query)
	if field == "__typename" || slices.Contains(rmGraphQLFields, field) {
		rmGraphQLResolve(w, field)
		return
	}
	suggestion := rmGraphQLNearestField(field)
	fmt.Fprintf(w, `{"errors":[{"message":%q}]}`,
		fmt.Sprintf(`Cannot query field "%s" on type "Query". Did you mean "%s"?`, field, suggestion))
}

// rmSafeGraphQLAbsent is the safe twin for "GraphQL endpoint found" only: an ordinary
// REST-shaped JSON response with no top-level data/errors member, so it cannot be mistaken
// for a GraphQL answer under any encoding.
func rmSafeGraphQLAbsent(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{"status":"ok","service":"burpsy-catalog-api"}`)
}

// rmSafeGraphQL is the safe twin for "GraphQL introspection enabled", "GraphQL suggestions
// enabled" and "GraphQL content type not validated": a real, working GraphQL server (so those
// three checks have something genuine to probe) with all three specific defects fixed -
// introspection refused, an unknown field given no hint, and every encoding but JSON POST
// rejected outright.
func rmSafeGraphQL(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost || !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		w.WriteHeader(http.StatusUnsupportedMediaType)
		fmt.Fprint(w, `{"error":"unsupported content type"}`)
		return
	}
	query, ok := rmParseGraphQLQuery(r)
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"errors":[{"message":"no query was supplied"}]}`)
		return
	}
	if strings.Contains(query, "__schema") {
		fmt.Fprint(w, `{"errors":[{"message":"introspection is disabled"}]}`)
		return
	}
	field := rmGraphQLTopField(query)
	if field == "__typename" || slices.Contains(rmGraphQLFields, field) {
		rmGraphQLResolve(w, field)
		return
	}
	fmt.Fprint(w, `{"errors":[{"message":"the requested field does not exist"}]}`)
}

// ---------------------------------------------------------------------------
// JWT forgery
// ---------------------------------------------------------------------------

// rmJWTSecret is the server-side HMAC secret a properly configured verifier keeps to itself.
// Fixed rather than randomised: nothing here needs it to be unguessable, only for the
// vulnerable and safe endpoints to agree on what "the real signature" is.
var rmJWTSecret = []byte("burpsy-demo-only-hs256-secret")

func rmB64URL(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func rmB64URLDecode(s string) ([]byte, bool) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	return b, err == nil
}

// rmMintJWT builds a genuine HS256-signed JWT: real base64url segments and a real
// HMAC-SHA256 signature over them, not a string that merely looks like one.
func rmMintJWT(claims map[string]any) string {
	header, _ := json.Marshal(map[string]any{"alg": "HS256", "typ": "JWT"})
	payload, _ := json.Marshal(claims)
	signingInput := rmB64URL(header) + "." + rmB64URL(payload)
	mac := hmac.New(sha256.New, rmJWTSecret)
	mac.Write([]byte(signingInput))
	return signingInput + "." + rmB64URL(mac.Sum(nil))
}

// rmJWTToken is the one real, correctly-signed token both /rm/jwt and /rm/safe/jwt are seeded
// with. The two endpoints differ only in how thoroughly they check it.
var rmJWTToken = rmMintJWT(map[string]any{"sub": "alice"})

func rmBearerToken(r *http.Request) (string, bool) {
	const prefix = "Bearer "
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, prefix) {
		return "", false
	}
	return strings.TrimSpace(strings.TrimPrefix(auth, prefix)), true
}

func rmJWTClaims(tok string) (sub string, ok bool) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return "", false
	}
	payload, ok := rmB64URLDecode(parts[1])
	if !ok {
		return "", false
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", false
	}
	sub, _ = claims["sub"].(string)
	return sub, sub != ""
}

// rmJWT is the defect: it trusts a bearer token's claims without ever checking parts[0] (the
// claimed algorithm) or parts[2] (the signature). A "none"-algorithm forgery or a token
// carrying its own self-signed "jwk" header both leave the payload segment untouched, which is
// all this handler reads - so both are honoured exactly like a genuinely signed token.
func rmJWT(w http.ResponseWriter, r *http.Request) {
	tok, ok := rmBearerToken(r)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "no bearer token")
		return
	}
	sub, ok := rmJWTClaims(tok)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "unrecognised token")
		return
	}
	fmt.Fprintf(w, "Welcome, %s", sub)
}

// rmSafeJWT genuinely verifies the HMAC-SHA256 signature against the server's own secret, and
// pins the algorithm to HS256, before trusting anything the token claims - so a token whose
// header was rewritten to "none" or to carry its own key is rejected before its payload is
// ever read, regardless of what that payload says.
func rmSafeJWT(w http.ResponseWriter, r *http.Request) {
	tok, ok := rmBearerToken(r)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "no bearer token")
		return
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "malformed token")
		return
	}
	var header struct {
		Alg string `json:"alg"`
	}
	if headerJSON, ok := rmB64URLDecode(parts[0]); ok {
		_ = json.Unmarshal(headerJSON, &header)
	}
	if !strings.EqualFold(header.Alg, "HS256") {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "unsupported algorithm")
		return
	}
	sig, sigOK := rmB64URLDecode(parts[2])
	mac := hmac.New(sha256.New, rmJWTSecret)
	mac.Write([]byte(parts[0] + "." + parts[1]))
	if !sigOK || !hmac.Equal(sig, mac.Sum(nil)) {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "signature mismatch")
		return
	}
	sub, ok := rmJWTClaims(tok)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "unrecognised token")
		return
	}
	fmt.Fprintf(w, "Welcome, %s", sub)
}

// ---------------------------------------------------------------------------
// JWT private key disclosed
// ---------------------------------------------------------------------------

// rmJWKSKey is a real RSA-2048 keypair, generated once. Its public half is what a JWKS
// endpoint should publish; the vulnerable endpoint below additionally, mistakenly, publishes
// the private half too.
var rmJWKSKey = rmMustGenerateJWKSKey()

func rmMustGenerateJWKSKey() *rsa.PrivateKey {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic("vulnapp: generating demo JWKS key: " + err.Error())
	}
	return priv
}

func rmPublicJWK(priv *rsa.PrivateKey) map[string]any {
	return map[string]any{
		"kty": "RSA", "kid": "burpsy-signing-key", "use": "sig",
		"n": rmB64URL(priv.PublicKey.N.Bytes()),
		"e": rmB64URL(big.NewInt(int64(priv.PublicKey.E)).Bytes()),
	}
}

// rmJWKS answers with a JWKS that also discloses the private exponent and prime factors -
// mathematically real ones, from rmJWKSKey, not placeholder strings - which is what
// ScanForPrivateKeyInJWKS actually verifies (p*q == n) rather than merely detecting a JSON
// field named "d".
func rmJWKS(w http.ResponseWriter, r *http.Request) {
	jwk := rmPublicJWK(rmJWKSKey)
	jwk["d"] = rmB64URL(rmJWKSKey.D.Bytes())
	jwk["p"] = rmB64URL(rmJWKSKey.Primes[0].Bytes())
	jwk["q"] = rmB64URL(rmJWKSKey.Primes[1].Bytes())
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{jwk}})
}

// rmSafeJWKS answers with the same key's public half only.
func rmSafeJWKS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{rmPublicJWK(rmJWKSKey)}})
}

// ---------------------------------------------------------------------------
// React Server Components RCE (React2Shell) - version fingerprinting
// ---------------------------------------------------------------------------

// rmReact2Shell serves a page whose script tag names a React build inside the affected range
// (react2ShellAffected: >=19.0.0 <19.2.1, checks_remaining.go) using the exact filename shape
// Wappalyzer's own React signature looks for
// (scriptSrc: `react(?:-with-addons)?[.-](\d+(?:\.\d+)+)[^/]*\.js;version:\1`) - a real
// signature match, not a header this fixture invented to be recognised.
func rmReact2Shell(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, `<!DOCTYPE html><html><head>
<script src="/static/js/react-19.1.0.production.min.js"></script>
</head><body><div id="root"></div></body></html>`)
}

// rmSafeReact2Shell names a patched version - 19.2.1, the affected range's own exclusive upper
// bound - in the same real signature shape.
func rmSafeReact2Shell(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, `<!DOCTYPE html><html><head>
<script src="/static/js/react-19.2.1.production.min.js"></script>
</head><body><div id="root"></div></body></html>`)
}

// ---------------------------------------------------------------------------
// OpenAPI definition found (passive scan check)
// ---------------------------------------------------------------------------

func rmAPIDocs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{"openapi":"3.0.3","info":{"title":"Burpsy Catalog API","version":"1.0.0"},"paths":{"/products":{"get":{"summary":"list products"}}}}`)
}

func rmSafeAPIDocs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{"status":"ok","service":"burpsy-catalog-api"}`)
}

// ---------------------------------------------------------------------------
// SQL statement in request parameter
// ---------------------------------------------------------------------------
//
// checkSQLStatementInParameter is passive over the captured request text alone - it never
// sends a probe - so what decides the row is the SEEDED parameter value in remainingEndpoints,
// not this handler's response. The handler is still a genuine, if small, feature: a reporting
// export whose "filter" parameter is documented as a raw WHERE-clause-shaped fragment, applied
// against an in-memory ledger with a real (if minimal) evaluator - the same
// client-chooses-the-query design the row warns about, mirroring the small real interpreters
// vulnapp.go's own evalFilterSequence/ldapLookup use for their client-supplied query languages.

var rmReportRows = []map[string]string{
	{"region": "west", "status": "shipped"},
	{"region": "east", "status": "pending"},
}

var rmFilterClauseRe = regexp.MustCompile(`(?i)^\s*([a-z_]+)\s*(=|!=)\s*'([^']*)'\s*$`)

// rmFilterMatches evaluates filter as zero or more "column='value'" clauses joined by " and ".
// A clause that doesn't parse in that shape - as a raw SQL statement never will - matches
// nothing, rather than everything.
func rmFilterMatches(filter string, row map[string]string) bool {
	if strings.TrimSpace(filter) == "" {
		return true
	}
	for _, clause := range strings.Split(filter, " and ") {
		m := rmFilterClauseRe.FindStringSubmatch(clause)
		if m == nil {
			return false
		}
		col, op, val := strings.ToLower(m[1]), m[2], m[3]
		got, ok := row[col]
		if !ok {
			return false
		}
		eq := strings.EqualFold(got, val)
		if (op == "=" && !eq) || (op == "!=" && eq) {
			return false
		}
	}
	return true
}

// rmReports reads filter from the query string when present, else from a JSON POST body -
// both are genuine ways a real reporting endpoint would accept the parameter, and reading
// either means the same handler serves both the query-string and the JSON-body manifest
// entries above.
func rmReports(w http.ResponseWriter, r *http.Request) {
	filter := r.URL.Query().Get("filter")
	if filter == "" && r.Method == http.MethodPost {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
		var payload struct {
			Filter string `json:"filter"`
		}
		_ = json.Unmarshal(body, &payload)
		filter = payload.Filter
	}
	var out []map[string]string
	for _, row := range rmReportRows {
		if rmFilterMatches(filter, row) {
			out = append(out, row)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}
