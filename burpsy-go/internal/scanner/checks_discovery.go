// checks_discovery.go ports five host-wide catalog issues from real recovered Java probe lists
// (or, for the two HTTP-method checks, well-established RFC-defined confirmation behavior once
// arbitrary-method probing became available): OpenAPI/Swagger definition found (burp.Zh0b),
// robots.txt file (the non-TLS half of burp.Zut6 — see check_registry_declined.go's remaining
// note on the TLS half), GraphQL endpoint discovered (burp.Zmzj), HTTP PUT method is enabled, and
// HTTP TRACE method is enabled. All five probe a fixed, host-relative path (or small set of
// paths) once per host with no insertion-point mutation, which is exactly what their Java `Zf8g`
// family prefix (APH_*, "active per-host") means.
package scanner

import (
	"context"
	"strconv"
	"strings"
)

func hostDiscoveryChecksEnabled(c *ScanConfig) bool { return c != nil && c.CheckHostDiscovery }

// ---------------------------------------------------------------------------
// OpenAPI/Swagger definition found — burp.Zh0b
// ---------------------------------------------------------------------------

const openAPIDefinitionIssue = "OpenAPI definition found (active scan check)"

// openAPIDefinitionPaths are burp.Zh0b's own literal candidate paths, recovered verbatim from
// out/strings/map_root.tsv (23 distinct strings; order here is alphabetised, not the original
// probe order, which was not recoverable from static string evidence alone).
var openAPIDefinitionPaths = [...]string{
	"/api-docs/swagger-ui-init.js",
	"/api/api-docs",
	"/api/swagger.json",
	"/api/v1/api-docs",
	"/api/v1/swagger.json",
	"/api/v1/swagger.yaml",
	"/api/v2/api-docs",
	"/api/v2/swagger.json",
	"/api/v2/swagger.yaml",
	"/openapi",
	"/openapi.json",
	"/openapi.yaml",
	"/swagger",
	"/swagger.json",
	"/swagger.yaml",
	"/swagger/docs/v1",
	"/swagger/docs/v2",
	"/swagger/docs/v3",
	"/swagger/v1/swagger.json",
	"/v1/swagger.json",
	"/v1/swagger.yaml",
	"/v2/swagger.json",
	"/v2/swagger.yaml",
}

// checkOpenAPIDefinitionFound fetches each candidate path once and confirms on the first 200
// response whose body names itself as an OpenAPI/Swagger document — a definition file always
// contains one of these two spec keywords regardless of JSON or YAML encoding, so requiring the
// keyword (rather than just a 200 status) avoids false positives on hosts that return 200 for
// every path.
func checkOpenAPIDefinitionFound(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	exchange := cc.Exchange
	for _, path := range openAPIDefinitionPaths {
		resp := cc.Scanner.sendTestRequestFull(ctx, exchange, path, nil)
		if resp == nil || resp.StatusCode != 200 {
			continue
		}
		body := string(resp.Body)
		lower := strings.ToLower(body)
		if strings.Contains(lower, "swagger") || strings.Contains(lower, "openapi") {
			return []*Finding{buildProbeFinding(cc, openAPIDefinitionIssue, "firm",
				path+" returned HTTP 200 with a body naming itself as an OpenAPI/Swagger document",
				"a publicly accessible API definition was found at "+path)}, nil
		}
	}
	return nil, nil
}

// ---------------------------------------------------------------------------
// Robots.txt file — the non-TLS half of burp.Zut6
// ---------------------------------------------------------------------------

const robotsTxtIssue = "Robots.txt file"

// checkRobotsTxtFile fetches /robots.txt (the literal path recovered from burp.Zut6) and confirms
// on a 200 response containing a real robots.txt directive — User-agent: or Disallow: — rather
// than merely a 200 status, since some hosts serve a 200 catch-all page for any path.
func checkRobotsTxtFile(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	exchange := cc.Exchange
	resp := cc.Scanner.sendTestRequestFull(ctx, exchange, "/robots.txt", nil)
	if resp == nil || resp.StatusCode != 200 {
		return nil, nil
	}
	body := string(resp.Body)
	lower := strings.ToLower(body)
	if !strings.Contains(lower, "user-agent:") && !strings.Contains(lower, "disallow:") {
		return nil, nil
	}
	detail := firstDirectiveLine(body)
	return []*Finding{buildProbeFinding(cc, robotsTxtIssue, "certain",
		"/robots.txt returned HTTP 200 with a robots.txt directive: "+detail,
		"the site publishes a robots.txt file that may enumerate restricted or private paths")}, nil
}

// firstDirectiveLine returns the first non-empty, non-comment line of a robots.txt body, for a
// compact evidence string.
func firstDirectiveLine(body string) string {
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		return line
	}
	return ""
}

// ---------------------------------------------------------------------------
// GraphQL endpoint discovered — burp.Zmzj
// ---------------------------------------------------------------------------

const graphQLEndpointIssue = "GraphQL endpoint discovered"

// graphQLIntrospectionQuery and graphQLContentType are burp.Zmzj's own literal probe body and
// header value, recovered verbatim from out/strings/map_root.tsv.
const (
	graphQLIntrospectionQuery = `query{__typename}`
	graphQLContentType        = "application/json; charset=utf-8"
)

// graphQLCandidatePaths are the standard, publicly documented GraphQL endpoint conventions
// (graphql.org / Apollo / GraphQL Yoga default mount points). burp.Zmzj's own path list was not
// recoverable as a literal string array; these are industry-standard, not Burp-specific.
var graphQLCandidatePaths = [...]string{"/graphql", "/graphql/", "/api/graphql", "/v1/graphql"}

// checkGraphQLEndpointDiscovered POSTs Zmzj's own recovered introspection-lite query to each
// candidate path and confirms when the response is valid JSON naming the query back — a GraphQL
// endpoint responds to `{"query":"query{__typename}"}` with a `data.__typename` field; anything
// else (a REST 404 page, a static file) will not.
func checkGraphQLEndpointDiscovered(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	exchange := cc.Exchange
	body := []byte(`{"query":"` + graphQLIntrospectionQuery + `"}`)
	for _, path := range graphQLCandidatePaths {
		resp := cc.Scanner.sendTestRequestBody(ctx, exchange, "POST", path,
			map[string]string{"Content-Type": graphQLContentType}, body)
		if resp == nil || resp.StatusCode != 200 {
			continue
		}
		respBody := strings.ToLower(string(resp.Body))
		if strings.Contains(respBody, "__typename") && strings.Contains(respBody, `"data"`) {
			return []*Finding{buildProbeFinding(cc, graphQLEndpointIssue, "firm",
				"POST "+path+" with query{__typename} returned a data.__typename response",
				"a GraphQL endpoint was found at "+path)}, nil
		}
	}
	return nil, nil
}

// ---------------------------------------------------------------------------
// HTTP PUT method is enabled
// ---------------------------------------------------------------------------

const httpPutEnabledIssue = "HTTP PUT method is enabled"

// checkHTTPPutEnabled PUTs a canary body to a synthetic, never-before-requested path and then GETs
// that same path back. A server that actually implements PUT-to-create will serve the canary back
// verbatim; a server that merely returns 2xx for a PUT it ignored (or 404/405/501 for one it
// rejected) will not, so requiring the GET-back match is what turns "PUT didn't error" into
// "PUT actually wrote a retrievable file" — the same differential-confirmation shape as
// checkBackupFile.
func checkHTTPPutEnabled(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	exchange := cc.Exchange
	canary := newProbeCanary("brpu")
	path := "/burpsy-put-probe-" + canary + ".txt"
	putResp := cc.Scanner.sendTestRequestBody(ctx, exchange, "PUT", path, nil, []byte(canary))
	if putResp == nil || putResp.StatusCode < 200 || putResp.StatusCode >= 300 {
		return nil, nil
	}
	getResp := cc.Scanner.sendTestRequestFull(ctx, exchange, path, nil)
	if getResp == nil || getResp.StatusCode != 200 || !strings.Contains(string(getResp.Body), canary) {
		return nil, nil
	}
	return []*Finding{buildProbeFinding(cc, httpPutEnabledIssue, "certain",
		"PUT "+path+" returned "+strconv.Itoa(putResp.StatusCode)+", and a subsequent GET of the same path served back the PUT body verbatim",
		"the server accepts PUT requests and persists arbitrary content at an attacker-chosen path")}, nil
}

// ---------------------------------------------------------------------------
// HTTP TRACE method is enabled
// ---------------------------------------------------------------------------

const httpTraceEnabledIssue = "HTTP TRACE method is enabled"

const traceCanaryHeader = "X-Burpsy-Trace-Canary"

// checkHTTPTraceEnabled sends a TRACE request carrying a canary header. RFC 7231 defines TRACE as
// echoing the exact request back as the response body, so a canary header value appearing in the
// response body — never a response header, TRACE has no headers of its own worth checking — is
// direct evidence the server implements TRACE rather than rejecting it with 405/501.
func checkHTTPTraceEnabled(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	exchange := cc.Exchange
	canary := newProbeCanary("brpt")
	resp := cc.Scanner.sendTestRequestBody(ctx, exchange, "TRACE", "/", map[string]string{traceCanaryHeader: canary}, nil)
	if resp == nil || resp.StatusCode != 200 {
		return nil, nil
	}
	if !strings.Contains(string(resp.Body), canary) {
		return nil, nil
	}
	return []*Finding{buildProbeFinding(cc, httpTraceEnabledIssue, "certain",
		"a TRACE request carrying header "+traceCanaryHeader+": "+canary+" was echoed back verbatim in the response body",
		"the server implements the HTTP TRACE method, which echoes the raw request back and may disclose internal headers appended by upstream proxies")}, nil
}

// ---------------------------------------------------------------------------

// HostDiscoveryCheckDescriptors returns the five host-wide native checks this file owns.
func HostDiscoveryCheckDescriptors() []CheckDescriptor {
	return []CheckDescriptor{
		nativeDescriptor(openAPIDefinitionIssue, DispatchScopePerHost, hostDiscoveryChecksEnabled, checkOpenAPIDefinitionFound),
		nativeDescriptor(robotsTxtIssue, DispatchScopePerHost, hostDiscoveryChecksEnabled, checkRobotsTxtFile),
		nativeDescriptor(graphQLEndpointIssue, DispatchScopePerHost, hostDiscoveryChecksEnabled, checkGraphQLEndpointDiscovered),
		nativeDescriptor(httpPutEnabledIssue, DispatchScopePerHost, hostDiscoveryChecksEnabled, checkHTTPPutEnabled),
		nativeDescriptor(httpTraceEnabledIssue, DispatchScopePerHost, hostDiscoveryChecksEnabled, checkHTTPTraceEnabled),
	}
}
