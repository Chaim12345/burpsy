package web

// ---- API scan: Upload from URL, with Add Auth (burpsy-react-ui-fu4l) -----------------------------
//
// Burp's API-only scan can fetch the definition from a URL, with an authentication method for that
// fetch (Basic, Bearer or OAuth2). burpsy's New scan card accepted a pasted or uploaded document only,
// so a definition served behind authentication had to be downloaded by hand first. This endpoint is the
// fetch; the dialog puts what it returns in the same definition box an upload fills, and the dry run
// reads it from there exactly as it reads an uploaded file.
//
// # What it sends, and the gates on it
//
// One GET, through sender.AuthorisedSender — the scope chokepoint every request-originating surface
// uses — so the bytes about to be written are authorised against the scope before the dial and an
// out-of-scope definition URL is never contacted. OAuth2 client credentials adds one POST to the token
// endpoint, through its own AuthorisedSender, gated the same way: a token URL out of scope is refused
// before the definition URL is touched. Redirects are not followed (a 3xx is reported with where it
// pointed), because following one would be a second request to an authority nobody authorised.
//
// # Bounds
//
//   - Time: the whole fetch, token included, runs under apiScanFetchTimeout.
//   - Size: the definition is refused above apiScanFetchMaxBytes, decoded. That cap is chosen to fit
//     back through /api/apiscan's own request-body cap once JSON-escaped. The transport's own read is
//     bounded by the sender's response cap (httputil.MaxResponseBodyBytes), which is what bounds memory
//     before this check runs; a content-encoded body is inflated through httputil.DecodeBody's cap.
//
// # Credentials
//
// Never logged, never persisted, never echoed. The fetch is NOT recorded in proxy history: the request
// carries the operator's credential, and history is persisted to the project file. The tool log gets
// one row per request with the path and no query string (a query is where an API key in a URL lives).
// A credential embedded in the URL itself (user:pass@host) is refused with a pointer to Add Auth, since
// a URL is what gets logged. A token endpoint's answer is never quoted back in an error.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/burpsy-go/burpsy/internal/apidoc"
	"github.com/burpsy-go/burpsy/internal/httputil"
	"github.com/burpsy-go/burpsy/internal/sender"
	"github.com/burpsy-go/burpsy/internal/toollog"
)

// apiScanFetchMaxBytes caps a fetched definition. /api/apiscan reads at most maxRequestBodyBytes of
// JSON, and escaping can roughly double a document, so half of it is what can still be launched.
const apiScanFetchMaxBytes = maxRequestBodyBytes / 2

// apiScanFetchTimeout bounds the whole fetch, the token request included.
var apiScanFetchTimeout = 30 * time.Second

// apiScanTokenMaxBytes caps a token endpoint's answer: a token response is a small JSON object.
const apiScanTokenMaxBytes = 1 << 20

// apiScanFetchReq is the POST body of /api/apiscan/fetch.
type apiScanFetchReq struct {
	// URL is the definition's absolute http(s) URL.
	URL string `json:"url"`
	// Auth is the method used for this fetch only ("Add auth" beside "Upload from URL"). It is not
	// the scan's own authentication, which the review step sets separately.
	Auth *apiScanFetchAuth `json:"auth,omitempty"`
}

// apiScanFetchAuth is Basic, Bearer or OAuth2 client credentials.
type apiScanFetchAuth struct {
	Type     string `json:"type"` // none | basic | bearer | oauth2_client_credentials
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	Token    string `json:"token,omitempty"`
	// TokenURL, ClientID, ClientSecret and Scope are OAuth2 client credentials (RFC 6749 §4.4).
	TokenURL     string `json:"token_url,omitempty"`
	ClientID     string `json:"client_id,omitempty"`
	ClientSecret string `json:"client_secret,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// apiScanFetchResp is the reply: the document, and what it was recognised as.
type apiScanFetchResp struct {
	Definition string `json:"definition"`
	// Format is what the bytes were recognised as: openapi-3, swagger-2, postman-2 (apidoc's own names),
	// wsdl, or unknown.
	Format string `json:"format"`
	// Scannable says whether this build's API scan reads that format. False for WSDL and for anything
	// unrecognised; Note then says why, in the parser's words where it has them.
	Scannable bool   `json:"scannable"`
	Note      string `json:"note,omitempty"`
	// URL is the URL fetched, as given (credentials cannot be in it — they are refused).
	URL         string `json:"url"`
	Status      int    `json:"status"`
	ContentType string `json:"content_type,omitempty"`
	Bytes       int    `json:"bytes"`
	// TokenFetched is true when an OAuth2 token was obtained for this fetch. The token itself is
	// never returned.
	TokenFetched bool `json:"token_fetched,omitempty"`
}

// apiScanFetchError carries the status the handler should answer with.
type apiScanFetchError struct {
	code int
	msg  string
}

func (e *apiScanFetchError) Error() string { return e.msg }

func fetchErr(code int, format string, args ...any) error {
	return &apiScanFetchError{code: code, msg: fmt.Sprintf(format, args...)}
}

// handleAPIScanFetch serves POST /api/apiscan/fetch.
func (s *Server) handleAPIScanFetch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req apiScanFetchReq
	if err := requestJSON(w, r, http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), apiScanFetchTimeout)
	defer cancel()
	resp, err := s.fetchAPIDefinition(ctx, req)
	if err != nil {
		code := http.StatusBadGateway
		var fe *apiScanFetchError
		if errors.As(err, &fe) {
			code = fe.code
		} else if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			code = http.StatusGatewayTimeout
			err = fmt.Errorf("the fetch did not finish within %s: %v", apiScanFetchTimeout, err)
		}
		http.Error(w, err.Error(), code)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// fetchTarget is a parsed, dialable http(s) URL.
type fetchTarget struct {
	host       string
	port       uint16
	tls        bool
	requestURI string
	authority  string
	path       string // for the tool log: no query
}

// parseFetchURL validates a definition or token URL and splits it into what the sender needs.
func parseFetchURL(what, raw string) (fetchTarget, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return fetchTarget{}, fetchErr(http.StatusBadRequest, "the %s %q is not an absolute URL", what, raw)
	}
	if u.User != nil {
		// Not quoted back: the URL holds the credential this refusal is about.
		return fetchTarget{}, fetchErr(http.StatusBadRequest,
			"the %s carries credentials in it (user:password@host); give them under Add auth instead, so they are not part of a URL that gets logged", what)
	}
	var t fetchTarget
	switch strings.ToLower(u.Scheme) {
	case "https":
		t.tls, t.port = true, 443
	case "http":
		t.port = 80
	default:
		return fetchTarget{}, fetchErr(http.StatusBadRequest, "the %s must be http or https, not %q", what, u.Scheme)
	}
	t.host = u.Hostname()
	if p := u.Port(); p != "" {
		n, perr := strconv.ParseUint(p, 10, 16)
		if perr != nil || n == 0 {
			return fetchTarget{}, fetchErr(http.StatusBadRequest, "the %s names an unusable port %q", what, p)
		}
		t.port = uint16(n)
	}
	t.authority = u.Host
	t.requestURI = u.RequestURI()
	t.path = u.EscapedPath()
	if t.path == "" {
		t.path = "/"
	}
	return t, nil
}

// headerSafe refuses a value that would break out of its header line.
func headerSafe(what, v string) error {
	if strings.ContainsAny(v, "\r\n") {
		return fetchErr(http.StatusBadRequest, "the %s contains a line break, which would inject a header", what)
	}
	return nil
}

// fetchAPIDefinition performs the fetch: optional token, then the definition GET, then the sniff.
func (s *Server) fetchAPIDefinition(ctx context.Context, req apiScanFetchReq) (*apiScanFetchResp, error) {
	if s.sender == nil {
		return nil, fetchErr(http.StatusServiceUnavailable, "no sender is attached to this console, so nothing can be fetched")
	}
	target, err := parseFetchURL("definition URL", req.URL)
	if err != nil {
		return nil, err
	}
	// The host gate first, before any credential work: a definition URL that can never be in scope is
	// refused without even asking a token endpoint for a token to send it.
	if !s.scope.MayContainHost(target.host, target.port, target.tls) {
		return nil, fetchErr(http.StatusForbidden, "refused: %s", s.scope.Explain(target.host, target.port, target.path, target.tls))
	}

	authorization := ""
	tokenFetched := false
	auth := req.Auth
	if auth == nil {
		auth = &apiScanFetchAuth{Type: "none"}
	}
	switch auth.Type {
	case "", "none":
	case "basic":
		if auth.Username == "" {
			return nil, fetchErr(http.StatusBadRequest, "basic authentication needs a username")
		}
		if strings.Contains(auth.Username, ":") {
			return nil, fetchErr(http.StatusBadRequest, "a basic-authentication username cannot contain a colon (RFC 7617 §2)")
		}
		authorization = "Basic " + base64.StdEncoding.EncodeToString([]byte(auth.Username+":"+auth.Password))
	case "bearer":
		if auth.Token == "" {
			return nil, fetchErr(http.StatusBadRequest, "bearer authentication needs a token")
		}
		if err := headerSafe("bearer token", auth.Token); err != nil {
			return nil, err
		}
		authorization = "Bearer " + auth.Token
	case "oauth2_client_credentials":
		token, terr := s.fetchClientCredentialsToken(ctx, auth)
		if terr != nil {
			return nil, terr
		}
		authorization = "Bearer " + token
		tokenFetched = true
	default:
		return nil, fetchErr(http.StatusBadRequest, "unknown authentication type %q: expected none, basic, bearer or oauth2_client_credentials", auth.Type)
	}

	var raw strings.Builder
	fmt.Fprintf(&raw, "GET %s HTTP/1.1\r\n", target.requestURI)
	fmt.Fprintf(&raw, "Host: %s\r\n", target.authority)
	raw.WriteString("Accept: application/json, application/yaml, text/yaml, application/xml, text/xml, */*;q=0.5\r\n")
	raw.WriteString("User-Agent: burpsy-apiscan\r\n")
	if authorization != "" {
		fmt.Fprintf(&raw, "Authorization: %s\r\n", authorization)
	}
	raw.WriteString("Connection: close\r\n\r\n")

	status, head, body, err := s.fetchSend(ctx, target, []byte(raw.String()), "GET")
	if err != nil {
		return nil, err
	}
	if status >= 300 && status < 400 {
		loc := head.Get("Location")
		return nil, fetchErr(http.StatusBadGateway,
			"the definition URL answered %d and pointed at %q; redirects are not followed, so fetch that URL instead (it is checked against scope like any other)", status, loc)
	}
	if status < 200 || status >= 300 {
		hint := ""
		if status == http.StatusUnauthorized || status == http.StatusForbidden {
			hint = " — check the authentication method under Add auth"
		}
		return nil, fetchErr(http.StatusBadGateway, "the definition URL answered %d %s%s", status, http.StatusText(status), hint)
	}

	format, scannable, note := sniffDefinition(body)
	return &apiScanFetchResp{
		Definition:   string(body),
		Format:       format,
		Scannable:    scannable,
		Note:         note,
		URL:          strings.TrimSpace(req.URL),
		Status:       status,
		ContentType:  head.Get("Content-Type"),
		Bytes:        len(body),
		TokenFetched: tokenFetched,
	}, nil
}

// fetchSend sends raw through the authorised sender bound to target and returns the status, headers
// and decoded body, bounded. One tool-log row per request, without query or credentials.
func (s *Server) fetchSend(ctx context.Context, target fetchTarget, raw []byte, method string) (int, http.Header, []byte, error) {
	authorised := sender.NewAuthorisedSender(s.scope, s.sender, target.host, target.port, target.tls)
	started := time.Now()
	result, err := authorised.Send(ctx, raw)
	if err != nil {
		if authorised.Refused() > 0 {
			// The scope gate stopped it before the dial: nothing was sent, so nothing is logged as sent.
			return 0, nil, nil, fetchErr(http.StatusForbidden, "refused: %v", err)
		}
		s.toolLog.Record(toollog.ToolScanner, target.host, target.port, target.tls, method, target.path, 0, nil,
			uint64(time.Since(started).Milliseconds()), "API definition fetch failed", nil)
		return 0, nil, nil, err
	}
	resp, perr := http.ReadResponse(bufio.NewReader(bytes.NewReader(result.Raw)), nil)
	if perr != nil {
		return 0, nil, nil, fetchErr(http.StatusBadGateway, "the response could not be read as HTTP: %v", perr)
	}
	defer resp.Body.Close()
	body, rerr := io.ReadAll(io.LimitReader(resp.Body, apiScanFetchMaxBytes+1))
	if rerr != nil {
		return 0, nil, nil, fetchErr(http.StatusBadGateway, "the response body could not be read: %v", rerr)
	}
	if enc := strings.TrimSpace(resp.Header.Get("Content-Encoding")); enc != "" && !strings.EqualFold(enc, "identity") {
		decoded, derr := httputil.DecodeBody(enc, body)
		if derr != nil {
			return 0, nil, nil, fetchErr(http.StatusBadGateway, "the response is %s-encoded and could not be decoded: %v", enc, derr)
		}
		body = decoded
	}
	n := len(body)
	s.toolLog.Record(toollog.ToolScanner, target.host, target.port, target.tls, method, target.path, resp.StatusCode, &n,
		uint64(time.Since(started).Milliseconds()), "API definition fetch", nil)
	if len(body) > apiScanFetchMaxBytes {
		return 0, nil, nil, fetchErr(http.StatusUnprocessableEntity,
			"the response is larger than the %d-byte limit for a fetched definition; download it and load the file instead", apiScanFetchMaxBytes)
	}
	return resp.StatusCode, resp.Header, body, nil
}

// fetchClientCredentialsToken runs the OAuth2 client-credentials grant (RFC 6749 §4.4), with the
// client authenticating by HTTP Basic (§2.3.1). Only the access token comes back; nothing the endpoint
// said is quoted in an error, because its answer may hold the very token or secret being protected.
func (s *Server) fetchClientCredentialsToken(ctx context.Context, auth *apiScanFetchAuth) (string, error) {
	if auth.TokenURL == "" || auth.ClientID == "" {
		return "", fetchErr(http.StatusBadRequest, "OAuth2 client credentials needs a token URL and a client ID")
	}
	target, err := parseFetchURL("token URL", auth.TokenURL)
	if err != nil {
		return "", err
	}
	if !s.scope.MayContainHost(target.host, target.port, target.tls) {
		return "", fetchErr(http.StatusForbidden, "refused: the token URL is out of scope: %s",
			s.scope.Explain(target.host, target.port, target.path, target.tls))
	}
	form := url.Values{"grant_type": {"client_credentials"}}
	if auth.Scope != "" {
		form.Set("scope", auth.Scope)
	}
	body := form.Encode()
	// RFC 6749 §2.3.1: client id and secret are form-urlencoded before being joined for Basic.
	basic := base64.StdEncoding.EncodeToString([]byte(url.QueryEscape(auth.ClientID) + ":" + url.QueryEscape(auth.ClientSecret)))
	var raw strings.Builder
	fmt.Fprintf(&raw, "POST %s HTTP/1.1\r\n", target.requestURI)
	fmt.Fprintf(&raw, "Host: %s\r\n", target.authority)
	fmt.Fprintf(&raw, "Authorization: Basic %s\r\n", basic)
	raw.WriteString("Content-Type: application/x-www-form-urlencoded\r\n")
	raw.WriteString("Accept: application/json\r\n")
	raw.WriteString("User-Agent: burpsy-apiscan\r\n")
	fmt.Fprintf(&raw, "Content-Length: %d\r\n", len(body))
	raw.WriteString("Connection: close\r\n\r\n")
	raw.WriteString(body)

	status, _, respBody, err := s.fetchSend(ctx, target, []byte(raw.String()), "POST")
	if err != nil {
		return "", err
	}
	if status < 200 || status >= 300 {
		return "", fetchErr(http.StatusBadGateway, "the token endpoint answered %d %s; no token was obtained, so the definition was not requested", status, http.StatusText(status))
	}
	if len(respBody) > apiScanTokenMaxBytes {
		return "", fetchErr(http.StatusBadGateway, "the token endpoint's answer is larger than a token response can be")
	}
	var tok struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
	}
	if err := json.Unmarshal(respBody, &tok); err != nil || tok.AccessToken == "" {
		return "", fetchErr(http.StatusBadGateway, "the token endpoint answered %d without a JSON access_token; the definition was not requested", status)
	}
	if tok.TokenType != "" && !strings.EqualFold(tok.TokenType, "bearer") {
		return "", fetchErr(http.StatusBadGateway, "the token endpoint issued a %q token; only bearer tokens can be sent", tok.TokenType)
	}
	if err := headerSafe("issued access token", tok.AccessToken); err != nil {
		return "", err
	}
	return tok.AccessToken, nil
}

// sniffDefinition says what a fetched document is and whether the API scan can read it. The scan's own
// parser is the judge for the formats it reads, so "scannable" means apidoc.Parse accepted it here.
func sniffDefinition(body []byte) (format string, scannable bool, note string) {
	trimmed := bytes.TrimLeft(bytes.TrimPrefix(body, []byte("\xef\xbb\xbf")), " \t\r\n")
	if len(trimmed) == 0 {
		return "unknown", false, "the URL answered with an empty body"
	}
	if trimmed[0] == '<' {
		head := trimmed
		if len(head) > 4096 {
			head = head[:4096]
		}
		lower := bytes.ToLower(head)
		if bytes.Contains(lower, []byte("schemas.xmlsoap.org/wsdl")) || bytes.Contains(lower, []byte("www.w3.org/ns/wsdl")) ||
			bytes.Contains(lower, []byte("<wsdl:definitions")) || bytes.Contains(lower, []byte("<wsdl:description")) {
			return "wsdl", false, "this is a WSDL (SOAP) service description; this build's API scan reads OpenAPI 3.x, Swagger 2.0 and Postman collections, not WSDL"
		}
		if bytes.Contains(lower, []byte("<html")) || bytes.Contains(lower, []byte("<!doctype html")) {
			return "unknown", false, "the URL answered with an HTML page, not a definition — often a login page or the API's documentation viewer rather than its raw document"
		}
		return "unknown", false, "the URL answered with an XML document that is not a WSDL, and no XML format is an API definition this build reads"
	}
	doc, err := apidoc.Parse(body)
	if err != nil {
		return "unknown", false, err.Error()
	}
	return string(doc.Format), true, ""
}
