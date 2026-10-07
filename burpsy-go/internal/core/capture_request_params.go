package core

import (
	"bytes"
	"strings"
)

// RequestParameterCount is how many parameters a request carries, in Burp's sense: the query
// string's, plus a form body's when there is one.
//
// # Why the query string alone is wrong
//
// Burp's SHOW_ONLY_PARAMETERIZED_REQUESTS accepts `HttpParameterType.URL` **or**
// `HttpParameterType.BODY` (burp-re/out/clean/root/Zb2y.java:270-273,450-455). Counting only the URL
// classifies every body-only parameterized request as unparameterized — a JSON API POST with a body
// and no query string, a multipart upload, an XML API call — and those are precisely the requests an
// operator filters to parameterized traffic in order to find. The filter did not mean what its name
// said (burpsy-react-ui-7py5).
//
// # Why it is computed at capture and not on demand
//
// A history row is an index entry and carries no request body, and a consumer that wanted the count
// would have to read the body back to derive it — the cost the history/message split exists to
// prevent (internal/web/AGENTS.md: "a list endpoint serves index rows and never resolves message
// payloads"). This is the same seam as Mime and RequestFingerprint: the one place the raw bytes are
// already in hand, so a consumer pays nothing for a column it never has to read bytes for.
//
// # The unexamined case, which is the load-bearing decision
//
// A body in a format this function does not parse — JSON, XML, anything that is not name/value — is
// counted as ONE, not zero. Reporting zero would tell an operator a request has no parameters when
// nobody examined it, and a filter that hides requests it could not read reports a clean answer about
// a request nobody looked at. That is the same overclaim as an unexamined response reported as
// "no content".
//
// It is ONE and not a guess at how many: nobody knows, and a bigger number would be a claim this
// function has no basis for. The consequence is that the count is exact for the formats it parses
// and a lower bound otherwise, and that is worth saying rather than hiding — see the field's own doc
// on Exchange.RequestParams.
//
// A request with no body and no query string is zero, and that is a real answer: there is nothing
// there to be uncertain about.
func RequestParameterCount(raw []byte) int {
	if len(raw) == 0 {
		return 0
	}
	// The request line, the headers and the body, each read once. Head and body are split on the
	// header terminator rather than through a full parse, because this runs on every captured request
	// and a caller that needed a parse tree would be using Parse.
	head, body := splitHeadBody(raw)
	// The start line carries the URL, so the query string is counted from the PATH the exchange row
	// already holds rather than by re-finding it here — the two can disagree when an operator edited
	// the request, and the row is what the filter is filtering.
	n := countNameValuePairs(queryOf(startLine(head)))
	if len(body) == 0 {
		return n
	}
	counted := countBodyParameters(mediaTypeOf(headerValue(head, "content-type")), string(body))
	if counted > 0 {
		return n + counted
	}
	if n > 0 {
		// The query string already answered the question; an unreadable body changes nothing about it.
		return n
	}
	// Unexamined, not parameterless. See the note above.
	return 1
}

// splitHeadBody returns the header block and the body of a raw HTTP message.
//
// Tolerant of both CRLF and bare LF, like Parse, because a captured message can be either and a
// count that reads a CRLF-only message as having no body would be wrong about every request that
// went through a client which used bare LFs.
func splitHeadBody(raw []byte) (head, body []byte) {
	if i := bytes.Index(raw, []byte("\r\n\r\n")); i >= 0 {
		return raw[:i], raw[i+4:]
	}
	if i := bytes.Index(raw, []byte("\n\n")); i >= 0 {
		return raw[:i], raw[i+2:]
	}
	// No terminator: the whole thing is a head with no body. Counting parameters from a fragment is
	// better than reporting none, and this is what a CONNECT tunnel or a malformed capture looks like.
	return raw, nil
}

// startLine returns the request line, or "" when there is none.
func startLine(head []byte) string {
	if i := bytes.IndexByte(head, '\n'); i >= 0 {
		return string(head[:i])
	}
	return string(head)
}

// queryOf returns the query string of a request line, or "".
func queryOf(requestLine string) string {
	fields := strings.Fields(requestLine)
	if len(fields) < 2 {
		return ""
	}
	target := fields[1]
	// The request-target may be absolute (a proxy-style request) rather than origin-form, so the query
	// is found by the first "?" rather than by assuming the string starts with a path.
	if i := strings.IndexByte(target, '?'); i >= 0 {
		return target[i+1:]
	}
	return ""
}

// headerValue returns one header's value, case-insensitively, or "".
func headerValue(head []byte, name string) string {
	lines := strings.Split(string(head), "\n")
	for i, line := range lines {
		if i == 0 {
			continue // the request line is not a header
		}
		line = strings.TrimRight(line, "\r")
		colon := strings.IndexByte(line, ':')
		if colon < 0 {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(line[:colon]), name) {
			continue
		}
		return strings.TrimSpace(line[colon+1:])
	}
	return ""
}

// mediaTypeOf returns a Content-Type's media type, lowercased and without its parameters.
func mediaTypeOf(contentType string) string {
	if contentType == "" {
		return ""
	}
	if semi := strings.IndexByte(contentType, ';'); semi >= 0 {
		contentType = contentType[:semi]
	}
	return strings.ToLower(strings.TrimSpace(contentType))
}

// parameterisedMediaTypes are the two body formats whose parameters enumerate as name/value pairs.
// Anything else is not guessed at, because guessing wrong here changes which rows a filter keeps.
var parameterisedMediaTypes = map[string]bool{
	"application/x-www-form-urlencoded": true,
	"multipart/form-data":               true,
}

// countBodyParameters counts a body's name/value pairs, or 0 for a format this does not parse.
func countBodyParameters(mediaType, body string) int {
	if !parameterisedMediaTypes[mediaType] {
		return 0
	}
	if mediaType == "multipart/form-data" {
		return countMultipartParts(body)
	}
	return countNameValuePairs(body)
}

// countNameValuePairs counts the pairs in a query string or a urlencoded body.
//
// A bare `flag` with no `=` is a parameter: it is a flag, and a filter that hid it would hide a
// request whose behaviour the operator is trying to explain. An empty segment between separators is
// not, because it names nothing.
func countNameValuePairs(s string) int {
	if s == "" {
		return 0
	}
	n := 0
	for _, pair := range strings.FieldsFunc(s, func(r rune) bool { return r == '&' || r == ';' }) {
		if pair != "" {
			n++
		}
	}
	return n
}

// countMultipartParts counts the named parts of a multipart body.
//
// Counted from the part headers rather than by locating the boundary, because a body whose boundary
// is missing or malformed still declares its parts and the operator asked about parameters, not about
// well-formed multipart. A file part counts: `filename=` names it, and a multipart upload IS
// parameterized traffic however large it is.
func countMultipartParts(body string) int {
	n := 0
	for _, part := range strings.Split(body, "--") {
		if strings.TrimSpace(part) == "" || strings.Trim(part, "-") == "" {
			continue
		}
		headers := part
		if end := strings.Index(part, "\n\n"); end >= 0 {
			headers = part[:end]
		} else if end := strings.Index(part, "\r\n\r\n"); end >= 0 {
			headers = part[:end]
		}
		lower := strings.ToLower(headers)
		if strings.Contains(lower, `name="`) || strings.Contains(lower, `filename="`) {
			n++
		}
	}
	if n > 0 {
		return n
	}
	// A body with content but no part headers at all has been mis-declared rather than unparameterized.
	if strings.TrimSpace(body) == "" {
		return 0
	}
	return 1
}
