package web

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

// Binding a confirmation to the resolved call (burpsy-react-ui-e0yq).
//
// # What was wrong
//
// A confirmation used to be minted for a route and spent on any request to that route. The approver
// — a human answering the console's dialog, or a host asking its human before letting an agent call
// burpsy_confirm — signed a route NAME, with no view of the request the token would authorise, and
// nothing compared what was approved with what ran. "Confirm POST /api/crawl" read the same whether
// the crawl was of the in-scope staging host or of every seed the agent could think of, and
// "confirm POST /api/proxy/ca/export" the same for the public certificate and the private key.
//
// Burp's own agent surface draws the line where this file now draws it: a tool publishes a preview
// of the RESOLVED request (ToolDescriptor's burp://preview/<tool>{?args}), and that resolved request
// is what the approver is given (McpBurpTool: "resolved request … is provided to the Judge").
//
// # The binding
//
// A mint describes one concrete call — method, URL (path and query), body — and the token is bound to
// a digest of that call in canonical form (callBinding). The gate computes the same digest from the
// request it is about to let through and refuses, burning the token, on any difference. So a token
// minted for call A cannot authorise call B on the same route: not a different body, not a different
// subtree path, not a different query, not a different verb.
//
// Canonical, not byte-exact, in exactly two places, and both only where the handler cannot tell the
// difference either:
//   - a JSON body is compared as its re-encoded value (object keys sorted, insignificant whitespace
//     gone, numbers kept as their literal spelling). An MCP host is free to re-serialise the
//     arguments it holds between the confirm call and the real one; a byte comparison would refuse
//     a call that is, to every handler here, the same call.
//   - a query string is compared as its parsed-then-re-encoded form, for the same reason (the MCP
//     transport builds it from a map).
//
// Anything that does not parse is compared as its raw bytes, so canonicalisation can only ever
// equate two spellings that decode to the same value — never two that decode differently.
//
// # What is not bound
//
// Headers. The gated routes read their input from the path, the query and the body; Content-Type is
// not consulted by any of them for meaning (requestJSON decodes JSON whatever it is labelled). A
// route that starts reading a header for meaning has to be added here, or its header is a channel
// around the approval.

// maxConfirmDescriptionBytes caps a mint's description. The description carries the call's body as a
// JSON string, and the whole request is already under the server's own maxRequestBodyBytes in
// production (ListenAndServe), so this is the same bound stated where it is applied.
const maxConfirmDescriptionBytes = maxRequestBodyBytes

// maxPreviewBodyBytes is how much of a body the preview shows. The digest covers all of it; the
// preview is for a human to read, and a 16 MiB dialog is not read.
const maxPreviewBodyBytes = 4096

// confirmCall is what a mint request carries: the call the token will authorise, as it will be sent.
type confirmCall struct {
	// Method is the verb of the call, e.g. "POST". A safe verb is refused: the gate never asks for a
	// confirmation of one, so a token for it could only be a token for something else.
	Method string `json:"method"`
	// URL is the call's path, with its query string if it has one: "/api/audit/12?x=1". Relative to
	// the console — a scheme or host is refused, the token authorises a call to THIS server.
	URL string `json:"url"`
	// Body is the call's exact body as text. Omitted (or null) means the call has no body.
	Body *string `json:"body,omitempty"`
	// BodyBase64 is the body as standard base64, for a body that is not valid UTF-8 and so cannot be
	// carried in a JSON string. At most one of Body and BodyBase64.
	BodyBase64 *string `json:"body_base64,omitempty"`
}

// callBinding is the resolved identity of one call: what a token is bound to and what the gate
// recomputes from the request it is about to admit.
type callBinding struct {
	method string
	path   string
	query  string
	// body is the canonical form (canonicalBody) — kept only as long as the mint handler needs it for
	// the preview; the store keeps the digest.
	body    []byte
	rawLen  int
	bodySum [32]byte
}

// digest is the value a token is bound to. Each field is length-prefixed, so no choice of path,
// query or body can shift a boundary and collide with a different call.
func (b callBinding) digest() string {
	h := sha256.New()
	for _, part := range []string{"burpsy-confirm-v1", b.method, b.path, b.query, hex.EncodeToString(b.bodySum[:])} {
		fmt.Fprintf(h, "%d:%s\n", len(part), part)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// newCallBinding builds the binding from a call's parts. Both the mint and the gate come through
// here, which is what makes "the same call" one definition rather than two.
func newCallBinding(method, path, rawQuery string, body []byte) callBinding {
	canon := canonicalBody(body)
	return callBinding{
		method:  strings.ToUpper(method),
		path:    path,
		query:   canonicalQuery(rawQuery),
		body:    canon,
		rawLen:  len(body),
		bodySum: sha256.Sum256(canon),
	}
}

// canonicalBody is the form a body is compared in. A JSON value is re-encoded (sorted keys, no
// insignificant whitespace, numbers as spelled); anything else — including invalid UTF-8, which the
// JSON decoder would silently replace, and so equate with other bytes — is itself.
func canonicalBody(raw []byte) []byte {
	if len(raw) == 0 || !utf8.Valid(raw) || !json.Valid(raw) {
		return raw
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return raw
	}
	out, err := json.Marshal(v)
	if err != nil {
		return raw
	}
	return out
}

// canonicalQuery is a query string in sorted, re-encoded form, or the raw string when it does not
// parse (so two unparseable queries are equal only when they are identical).
func canonicalQuery(raw string) string {
	if raw == "" {
		return ""
	}
	v, err := url.ParseQuery(raw)
	if err != nil {
		return raw
	}
	return v.Encode()
}

// resolve checks a mint's description against the pattern the mint was addressed to and returns
// the binding. It refuses rather than guessing: a description the gate could never match would
// mint a token that authorises nothing, and the caller would learn that only at the 428.
func (c confirmCall) resolve(pattern string) (callBinding, error) {
	method := strings.ToUpper(strings.TrimSpace(c.Method))
	if method == "" {
		return callBinding{}, errors.New(`"method" is required: the verb of the call this confirmation is for`)
	}
	if !methodMutates(method) {
		return callBinding{}, fmt.Errorf("%s is not gated — a read needs no confirmation, so there is nothing to mint", method)
	}
	if strings.TrimSpace(c.URL) == "" {
		return callBinding{}, errors.New(`"url" is required: the path (and query) of the call this confirmation is for`)
	}
	u, err := url.ParseRequestURI(c.URL)
	if err != nil {
		return callBinding{}, fmt.Errorf(`"url" %q is not a request path: %v`, c.URL, err)
	}
	if u.Scheme != "" || u.Host != "" || u.User != nil {
		return callBinding{}, fmt.Errorf(`"url" %q names a scheme or host; give the path on this console, e.g. %q`, c.URL, pattern)
	}
	if u.Fragment != "" {
		return callBinding{}, fmt.Errorf(`"url" %q carries a fragment, which is never sent`, c.URL)
	}
	// A mint endpoint is answered by the mint mux before the gate resolves risk, so a call to one is
	// never spent against: a token for it would authorise nothing, and saying so beats a 428 later.
	if minted := confirmPatternFor(u.Path); minted != u.Path {
		if _, risk, ok := routeRiskFor(minted); ok && needsConfirmation(risk) {
			return callBinding{}, fmt.Errorf(`"url" %q is a confirmation endpoint, not a call`, c.URL)
		}
	}
	target, _, ok := routeRiskFor(u.Path)
	if !ok || confirmRouteKey(target) != confirmRouteKey(pattern) {
		got := "no route"
		if ok {
			got = target
		}
		return callBinding{}, fmt.Errorf(`"url" %q resolves to %s, but this endpoint mints for %s: mint at the call's own route`, c.URL, got, pattern)
	}
	var body []byte
	switch {
	case c.Body != nil && c.BodyBase64 != nil:
		return callBinding{}, errors.New(`give the body once: "body" or "body_base64", not both`)
	case c.Body != nil:
		body = []byte(*c.Body)
	case c.BodyBase64 != nil:
		if body, err = base64.StdEncoding.DecodeString(*c.BodyBase64); err != nil {
			return callBinding{}, fmt.Errorf(`"body_base64" is not standard base64: %v`, err)
		}
	}
	return newCallBinding(method, u.Path, u.RawQuery, body), nil
}

// bindingOfRequest is the binding of the request the gate is about to admit, and the body it read
// to compute it (to be restored onto the request). A body over the server's request cap is an
// error: the gate never admits a call it could not compare in full.
func bindingOfRequest(r *http.Request) (callBinding, []byte, error) {
	var body []byte
	if r.Body != nil && r.Body != http.NoBody {
		var err error
		body, err = io.ReadAll(io.LimitReader(r.Body, maxRequestBodyBytes+1))
		if err != nil {
			return callBinding{}, nil, err
		}
		if len(body) > maxRequestBodyBytes {
			return callBinding{}, nil, fmt.Errorf("the body is over %d bytes", maxRequestBodyBytes)
		}
	}
	return newCallBinding(r.Method, r.URL.Path, r.URL.RawQuery, body), body, nil
}

// burn removes a token without spending it, for a presented token whose call could not be read.
func (c *confirmStore) burn(token string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.tokens, token)
}

// confirmPreview is what the approver is shown: the call as the gate will compare it.
type confirmPreview struct {
	Method string `json:"method"`
	// URL is the path plus the canonical query — the form that is bound, so two spellings of one
	// query preview identically and the preview is never a summary the binding disagrees with.
	URL string `json:"url"`
	// BodyBytes is the size of the body as described; BodySHA256 is the hash of its canonical form,
	// which is the value in the binding.
	BodyBytes  int    `json:"body_bytes"`
	BodySHA256 string `json:"body_sha256"`
	// BodyKind says how Body renders: "none", "json", "text" or "binary" (a binary body is not shown,
	// only sized and hashed).
	BodyKind string `json:"body_kind"`
	// Body is the canonical body for display: pretty-printed JSON with secret-named members
	// redacted, or text. Truncated at maxPreviewBodyBytes, which BodyTruncated reports.
	Body          string `json:"body,omitempty"`
	BodyTruncated bool   `json:"body_truncated,omitempty"`
	// Redacted lists the JSON members whose values the preview withheld. The digest covers them; the
	// preview does not echo a password into a dialog, an MCP transcript or a log.
	Redacted []string `json:"redacted,omitempty"`
}

// secretMember matches the JSON member names a preview withholds the value of.
var secretMember = regexp.MustCompile(`(?i)(pass(word|phrase)?|secret|token|api[_-]?key|private[_-]?key|credential|cookie|authorization)`)

// preview renders the binding for a human.
func (b callBinding) preview() confirmPreview {
	p := confirmPreview{
		Method:     b.method,
		URL:        b.path,
		BodyBytes:  b.rawLen,
		BodySHA256: hex.EncodeToString(b.bodySum[:]),
		BodyKind:   "none",
	}
	if b.query != "" {
		p.URL += "?" + b.query
	}
	if len(b.body) == 0 {
		return p
	}
	var text string
	switch {
	case !utf8.Valid(b.body):
		p.BodyKind = "binary"
		return p
	case json.Valid(b.body):
		p.BodyKind = "json"
		dec := json.NewDecoder(bytes.NewReader(b.body))
		dec.UseNumber()
		var v any
		if err := dec.Decode(&v); err == nil {
			redacted := map[string]bool{}
			v = redactSecrets(v, redacted)
			if out, err := json.MarshalIndent(v, "", "  "); err == nil {
				text = string(out)
			}
			for k := range redacted {
				p.Redacted = append(p.Redacted, k)
			}
			sort.Strings(p.Redacted)
		}
		if text == "" {
			text = string(b.body)
		}
	default:
		p.BodyKind = "text"
		text = string(b.body)
	}
	if len(text) > maxPreviewBodyBytes {
		cut := maxPreviewBodyBytes
		for cut > 0 && !utf8.RuneStart(text[cut]) {
			cut--
		}
		text, p.BodyTruncated = text[:cut], true
	}
	p.Body = text
	return p
}

// redactSecrets replaces the value of every secret-named member, at any depth, with a marker, and
// records the member names it withheld.
func redactSecrets(v any, seen map[string]bool) any {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			if secretMember.MatchString(k) {
				if s, ok := val.(string); ok && s == "" {
					continue // an empty value withholds nothing, and showing it is informative
				}
				t[k] = "«redacted»"
				seen[k] = true
				continue
			}
			t[k] = redactSecrets(val, seen)
		}
		return t
	case []any:
		for i := range t {
			t[i] = redactSecrets(t[i], seen)
		}
		return t
	default:
		return v
	}
}
