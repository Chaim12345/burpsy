package web

// Repeater's GraphQL query editing and validation (burpsy-react-ui-4xqt.3), Burp's GraphQL
// request view grown up: the typed view stops being read-only. Validation is SYNTAX-ONLY:
// the same pinned gqlparser and token limit as the scanner's ingest gate, without the gate's
// 64KiB document cap and union-of-decodings, so a document that passes here can still be one
// the ingest gate declines. Editing replaces ONE operation's query inside its carrier
// surgically: every other byte of the request - variables, operation name, extensions,
// formatting, header order - reaches the draft unchanged, because the edit is the query and
// nothing else. The carrier codecs are httputil's, semantically the scanner's: the encoded
// form differs only where the JSON grammar does (U+2028/U+2029 and invalid UTF-8, which
// Go's encoder escapes and the scanner's byte-level decode does not) - the same document,
// not the same bytes.

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/gqlerror"
	"github.com/vektah/gqlparser/v2/parser"

	"github.com/burpsy-go/burpsy/internal/httputil"
)

// graphQLRepeaterTokenLimit bounds the parser's work on one document, the same bound the
// scanner's ingest gate sets (graphQLIngestTokenLimit): one gqlparser, one limit, one answer.
const graphQLRepeaterTokenLimit = 1 << 18

// repeaterGraphQLValidateReq is the POST body of /api/repeater/graphql-validate.
type repeaterGraphQLValidateReq struct {
	// Query is the GraphQL document to parse. It is the whole body: nothing here is
	// operator-private, and the route sends nothing anywhere.
	Query string `json:"query"`
}

type repeaterGraphQLError struct {
	Message string `json:"message"`
	Line    int    `json:"line,omitempty"`
	Column  int    `json:"column,omitempty"`
}

type repeaterGraphQLValidateResp struct {
	OK     bool                   `json:"ok"`
	Errors []repeaterGraphQLError `json:"errors"`
}

func (s *Server) handleRepeaterGraphQLValidate(w http.ResponseWriter, r *http.Request) {
	var req repeaterGraphQLValidateReq
	if err := requestJSON(w, r, nil).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	_, err := parser.ParseQueryWithTokenLimit(&ast.Source{Input: req.Query}, graphQLRepeaterTokenLimit)
	resp := repeaterGraphQLValidateResp{OK: err == nil, Errors: []repeaterGraphQLError{}}
	if err != nil {
		var gerr *gqlerror.Error
		var lerr gqlerror.List
		switch {
		case errors.As(err, &gerr):
			resp.Errors = append(resp.Errors, graphQLErrorOf(gerr))
		case errors.As(err, &lerr):
			for _, e := range lerr {
				resp.Errors = append(resp.Errors, graphQLErrorOf(e))
			}
		default:
			resp.Errors = append(resp.Errors, repeaterGraphQLError{Message: err.Error()})
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

func graphQLErrorOf(e *gqlerror.Error) repeaterGraphQLError {
	out := repeaterGraphQLError{Message: e.Message}
	if len(e.Locations) > 0 {
		out.Line, out.Column = e.Locations[0].Line, e.Locations[0].Column
		return out
	}
	// gqlparser's parse errors carry the position in the message ("input:4:11: ...") more often
	// than in Locations; the editor's squiggle needs it as numbers, not as text to re-parse.
	var line, col int
	if rest, found := strings.CutPrefix(e.Message, "input:"); found {
		if _, err := fmt.Sscanf(rest, "%d:%d:", &line, &col); err == nil {
			out.Line, out.Column = line, col
		}
	}
	return out
}

// repeaterGraphQLQueryReq is the POST body of /api/repeater/graphql-query: replace one
// operation's query inside the raw request's carrier.
type repeaterGraphQLQueryReq struct {
	Request string `json:"request"`
	// Index selects the operation in carrier order (a batched body carries several). Zero-based.
	Index int    `json:"index"`
	Query string `json:"query"`
}

type repeaterGraphQLQueryResp struct {
	Request string `json:"request"`
	// Source names the carrier the query was replaced in - "body" or "params" - so the console
	// can say what changed rather than the operator trusting that it did.
	Source string `json:"source"`
}

func (s *Server) handleRepeaterGraphQLQuery(w http.ResponseWriter, r *http.Request) {
	var req repeaterGraphQLQueryReq
	if err := requestJSON(w, r, nil).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if req.Index < 0 {
		http.Error(w, "index selects an operation; negative names none", http.StatusBadRequest)
		return
	}
	next, source, err := replaceGraphQLQuery(req.Request, req.Index, req.Query)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, repeaterGraphQLQueryResp{Request: next, Source: source})
}

// graphQLQuerySpan is one operation's query string inside a raw request: the byte span of the
// string CONTENT (between the JSON quotes, or after query= up to the next &), and how its
// bytes decode.
type graphQLQuerySpan struct {
	start, end int
	source     string // "body" | "params"
}

// replaceGraphQLQuery rewrites the Index'th operation's query inside raw, returning the whole
// request with exactly that span changed - plus Content-Length, when a body edit moved it.
func replaceGraphQLQuery(raw string, index int, query string) (string, string, error) {
	if refusal := graphQLAmbiguousFramingRefusal(raw); refusal != "" {
		return "", "", errors.New(refusal)
	}
	spans := findGraphQLQuerySpans(raw)
	if len(spans) == 0 {
		if reason := graphQLUneditableCarrierReason(raw); reason != "" {
			return "", "", errors.New(reason)
		}
		return "", "", errors.New("no GraphQL carrier: the request has no query parameter and no " +
			"JSON body field named \"query\" - write the query in the Raw view instead")
	}
	if index >= len(spans) {
		return "", "", fmt.Errorf("index %d names no operation: the carrier holds %d", index, len(spans))
	}
	span := spans[index]
	var replacement string
	if span.source == "params" {
		replacement = httputil.GraphQLPercentEncode(query)
	} else {
		replacement = httputil.GraphQLJSONStringContentEncode(query)
	}
	next := raw[:span.start] + replacement + raw[span.end:]
	if span.source == "body" {
		next = rewriteContentLength(next)
	}
	return next, span.source, nil
}

// findGraphQLQuerySpans locates every operation's query content in carrier order: the URL
// query parameter first (a request carries its GraphQL document in one place), then the JSON
// body's top-level "query" field or, for a batched body, each element's.
func findGraphQLQuerySpans(raw string) []graphQLQuerySpan {
	head, body, bodyOff := splitRequestHead(raw)
	if spans := graphQLParamSpans(head); len(spans) > 0 {
		return spans
	}
	spans := graphQLJSONSpans(body)
	for i := range spans {
		// The walk is body-relative; the replacer's spans are raw-relative.
		spans[i].start += bodyOff
		spans[i].end += bodyOff
	}
	return spans
}

// splitRequestHead cuts head from body at the first blank line. The body offset returned is
// raw-relative, so spans found in body are spans in raw.
func splitRequestHead(raw string) (head, body string, bodyOff int) {
	if i := strings.Index(raw, "\r\n\r\n"); i >= 0 {
		return raw[:i], raw[i+4:], i + 4
	}
	return raw, "", len(raw)
}

// graphQLParamSpans finds the query= parameter of the request target's query string. The
// request line is the head's first line; the parameter value runs to the next & or the end of
// the target. A '+' inside the value is data (the codec says so), so no splitting on it.
func graphQLParamSpans(head string) []graphQLQuerySpan {
	eol := strings.Index(head, "\r\n")
	line := head
	if eol >= 0 {
		line = head[:eol]
	}
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 2 {
		return nil
	}
	target := parts[1]
	q := strings.IndexByte(target, '?')
	if q < 0 {
		return nil
	}
	// The target sits inside the request line, which sits inside raw: its offset is the index
	// of the target in the head plus the query-string start.
	targetOff := strings.Index(head, target)
	rest := target[q+1:]
	// Walk the byte offset alongside the split: a first-text-match search for the part's text
	// can land inside an earlier lookalike parameter (oldquery=<same value>), not on the part
	// the loop is on.
	off := 0
	for _, p := range strings.Split(rest, "&") {
		if strings.HasPrefix(p, "query=") {
			// The console lists this carrier only when the value reads as a GraphQL document;
			// the server indexes the same list (httputil.LooksLikeGraphQLDocument is the one
			// predicate), or an index would land on a parameter the operator never saw.
			if !httputil.LooksLikeGraphQLDocument(httputil.GraphQLPercentDecode(p[len("query="):])) {
				return nil
			}
			start := targetOff + q + 1 + off + len("query=")
			return []graphQLQuerySpan{{start: start, end: start + len(p) - len("query="), source: "params"}}
		}
		off += len(p) + 1
	}
	return nil
}

// graphQLJSONSpans walks the body as JSON text without decoding it: a full unmarshal and
// re-encode would reorder keys and reflow whitespace, changing bytes the operator did not edit.
// The walk tracks string state and object/array depth, and records the content span of every
// string value of a key named "query" at operation depth - the top-level object's, or each
// batch element's.
func graphQLJSONSpans(body string) []graphQLQuerySpan {
	trimmed := strings.TrimLeft(body, " \t\r\n")
	if len(trimmed) == 0 {
		return nil
	}
	off := len(body) - len(trimmed)
	var spans []graphQLQuerySpan
	// wantDepth is the object depth at which a "query" key is an operation's: 1 for a bare
	// object, 2 for elements of a top-level batch array. Anything deeper is a variable or an
	// extension that happens to share the name, and is not the document.
	wantDepth := 0
	switch trimmed[0] {
	case '{':
		wantDepth = 1
	case '[':
		wantDepth = 2
	default:
		return nil
	}
	depth := 0
	inString := false
	escaped := false
	// JSON.parse reads a duplicate key last-wins, so the console's operation list carries one
	// "query" per operation object - the last one. The walk must count the same way or a
	// duplicate key shifts every index after it: one slot per operation object, the last
	// "query" key of that object taking it, a non-document or non-string value emptying it.
	objectSeq := 0
	slots := map[int]graphQLQuerySpan{}
	inOrder := map[int]bool{}
	var order []int
	for i := off; i < len(body); i++ {
		c := body[i]
		switch {
		case inString && escaped:
			escaped = false
		case inString && c == '\\':
			escaped = true
		case inString && c == '"':
			inString = false
		case !inString && c == '"':
			inString = true
			if end, ok := graphQLKeyContent(body, i); ok && depth == wantDepth {
				// i is at the opening quote of a key "query"; find its string value. Only a
				// value that reads as a GraphQL document is an operation (the console's list
				// is this same filter - one predicate, httputil.LooksLikeGraphQLDocument): a
				// batch element whose "query" is a URL or a note is data, not an operation,
				// and indexing it would land the edit on an entry the operator never saw.
				if vs, ve, ok := graphQLStringValueSpan(body, end); ok {
					// The value is consumed through its closing quote: leave string state
					// and skip the content, so a "query" inside it is data, not a key.
					inString = false
					i = ve
					if httputil.LooksLikeGraphQLDocument(httputil.GraphQLJSONStringContentDecode(body[vs:ve])) {
						if !inOrder[objectSeq] {
							// Membership, not presence: a deleted slot (a shadowing
							// non-document key) must not append the object twice, or the
							// span after it answers two indexes.
							inOrder[objectSeq] = true
							order = append(order, objectSeq)
						}
						slots[objectSeq] = graphQLQuerySpan{start: vs, end: ve, source: "body"}
					} else {
						delete(slots, objectSeq)
					}
					continue
				}
				delete(slots, objectSeq)
			}
		case !inString && (c == '{' || c == '['):
			depth++
			if c == '{' && depth == wantDepth {
				objectSeq++
			}
		case !inString && (c == '}' || c == ']'):
			depth--
		}
	}
	for _, seq := range order {
		if span, ok := slots[seq]; ok {
			spans = append(spans, span)
		}
	}
	return spans
}

// graphQLKeyContent reports whether body[i:] opens a key whose decoded content is "query", and
// the index just past its closing quote and any following whitespace and colon.
func graphQLKeyContent(body string, i int) (int, bool) {
	end := i + 1
	escaped := false
	for ; end < len(body); end++ {
		c := body[end]
		if escaped {
			escaped = false
			continue
		}
		if c == '\\' {
			escaped = true
			continue
		}
		if c == '"' {
			break
		}
	}
	if end >= len(body) {
		return 0, false
	}
	if httputil.GraphQLJSONStringContentDecode(body[i+1:end]) != "query" {
		return 0, false
	}
	j := end + 1
	for j < len(body) && isJSONSpace(body[j]) {
		j++
	}
	if j >= len(body) || body[j] != ':' {
		return 0, false
	}
	j++
	for j < len(body) && isJSONSpace(body[j]) {
		j++
	}
	return j, true
}

// graphQLStringValueSpan returns the content span of the JSON string value starting at j
// (after the colon). A non-string value - an object, a number, null - is not an editable
// document and is skipped rather than rewritten.
func graphQLStringValueSpan(body string, j int) (int, int, bool) {
	if j >= len(body) || body[j] != '"' {
		return 0, 0, false
	}
	escaped := false
	for end := j + 1; end < len(body); end++ {
		c := body[end]
		if escaped {
			escaped = false
			continue
		}
		if c == '\\' {
			escaped = true
			continue
		}
		if c == '"' {
			return j + 1, end, true
		}
	}
	return 0, 0, false
}

// rewriteContentLength sets the head's Content-Length to the body's new length after a
// surgical edit. A request whose header disagrees with its bytes is a different request than
// the operator approved. The header keeps its own name's casing; an absent header stays absent
// (HTTP/1 requests without a body-framing header frame by connection close, which is the
// sender's business, not this edit's).
func rewriteContentLength(raw string) string {
	_, body, bodyOff := splitRequestHead(raw)
	head := raw[:bodyOff]
	for _, line := range strings.Split(head, "\r\n") {
		name, _, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(name), "Content-Length") {
			start := strings.Index(raw, line)
			return raw[:start] + name + ": " + strconv.Itoa(len(body)) + raw[start+len(line):]
		}
	}
	return raw
}

// isJSONSpace is the JSON grammar's whole whitespace set: space, tab, LF and CR. A body
// pretty-printed by a client puts newlines around the colon, and a walker that reads only
// space and tab loses the carrier the console found.
func isJSONSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\r' || c == '\n'
}

// graphQLAmbiguousFramingRefusal names why a request's framing makes it uneditable, or ""
// when it does not. Duplicate Content-Length is the request-smuggling shape: which length a
// server trusts is not this route's guess to make, and the edit rewrites framing bytes, so
// the refusal is by name rather than a winner picked in silence. Any Transfer-Encoding is
// the same class: the edit rewrites Content-Length and does not re-frame chunks.
func graphQLAmbiguousFramingRefusal(raw string) string {
	head, _, _ := splitRequestHead(raw)
	contentLengths := 0
	for _, line := range strings.Split(head, "\r\n") {
		name, _, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch {
		case strings.EqualFold(strings.TrimSpace(name), "Content-Length"):
			contentLengths++
		case strings.EqualFold(strings.TrimSpace(name), "Transfer-Encoding"):
			return "ambiguous framing: the request carries Transfer-Encoding - the edit path " +
				"rewrites Content-Length and will not re-frame a chunked or otherwise encoded " +
				"message; edit it on the Raw view instead"
		}
	}
	if contentLengths > 1 {
		return fmt.Sprintf("ambiguous framing: the request carries %d Content-Length headers - "+
			"the edit path rewrites framing bytes and refuses to guess which one a server "+
			"trusts; edit it on the Raw view instead", contentLengths)
	}
	return ""
}

// graphQLUneditableCarrierReason names a carrier the console reads but the edit path does
// not rewrite, or "" when no half-recognized carrier is present. A request whose body IS
// the document (application/graphql) or whose form carries query= is GraphQL the operator
// can see; answering "no GraphQL carrier" would deny what the screen shows, so the refusal
// names the carrier and the way out.
func graphQLUneditableCarrierReason(raw string) string {
	head, body, _ := splitRequestHead(raw)
	contentType := ""
	for _, line := range strings.Split(head, "\r\n") {
		if name, value, ok := strings.Cut(line, ":"); ok &&
			strings.EqualFold(strings.TrimSpace(name), "Content-Type") {
			contentType = strings.ToLower(strings.TrimSpace(value))
			break
		}
	}
	switch {
	case strings.Contains(contentType, "application/graphql") && !strings.Contains(contentType, "json"):
		return "uneditable carrier: the body IS the GraphQL document (application/graphql) - " +
			"the edit path rewrites the URL query parameter and JSON body carriers only; edit " +
			"it on the Raw view instead"
	case strings.Contains(contentType, "x-www-form-urlencoded"):
		for _, pair := range strings.Split(body, "&") {
			if strings.HasPrefix(pair, "query=") {
				return "uneditable carrier: the GraphQL document rides a url-encoded form " +
					"field - the edit path rewrites the URL query parameter and JSON body " +
					"carriers only; edit it on the Raw view instead"
			}
		}
	}
	return ""
}
