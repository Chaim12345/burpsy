package httputil

// GraphQL carrier codecs (burpsy-react-ui-4xqt.3). A GraphQL request carries its query inside
// one string - a JSON body field or a URL/form parameter - and the Repeater's query editor must
// decode that string to edit and re-encode it to send, with the scanner's ingest gate's
// semantics, or the operator edits one document and the scanner proves another. Semantically
// identical to the project's two existing unexported copies - the ENCODED form differs only
// where the JSON grammar does (U+2028/U+2029 and invalid UTF-8, which Go's encoder escapes
// and a byte-level decode does not): the same document, not always the same bytes:
// internal/bcheck/insertion.go's percentDecode/percentEscape and
// internal/scanner/graphql_ingest.go's graphQLPercentDecode (itself a copy of bcheck's), and
// bcheck insertion_graphql.go's jsonStringContentDecode. The parity tests pin the shared
// fixtures; the triplication is recorded for the helper-collapse bead (6858).

import (
	"encoding/json"
	"fmt"
	"strings"
)

// GraphQLPercentDecode decodes %XX escapes and nothing else: '+' is an ordinary byte, not a
// space. An escape with no hex digits survives as-is; a partial hex scan (%2G) decodes its
// valid prefix (0x02) - fmt.Sscanf semantics, NOT verbatim preservation. net/url's
// QueryUnescape drifts on both counts, which is why this exists.
func GraphQLPercentDecode(s string) string {
	var sb strings.Builder
	sb.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			var b byte
			if _, err := fmt.Sscanf(s[i+1:i+3], "%02X", &b); err == nil {
				sb.WriteByte(b)
				i += 2
				continue
			}
		}
		sb.WriteByte(s[i])
	}
	return sb.String()
}

// GraphQLPercentEncode is the default-policy inverse of GraphQLPercentDecode: the separators
// (&, =, +, ;), %, #, control bytes, bytes outside printable ASCII, and the RFC 3986
// request-line-illegal bytes are %XX-escaped; everything else passes through. '+' is escaped,
// which is what keeps the decode/encode round trip stable when the value rides a query string.
func GraphQLPercentEncode(s string) string {
	var sb strings.Builder
	sb.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '&' || c == '=' || c == '+' || c == ';' || c == '#' || c == '%' ||
			c <= 0x20 || c >= 0x7f || graphQLRequestLineIllegal(c) {
			fmt.Fprintf(&sb, "%%%02X", c)
		} else {
			sb.WriteByte(c)
		}
	}
	return sb.String()
}

// graphQLRequestLineIllegal is bcheck's requestLineIllegal: the bytes RFC 3986 forbids in a
// request target, which strict servers (Tomcat, Spring Boot) answer 400 before the application
// runs.
func graphQLRequestLineIllegal(c byte) bool {
	switch c {
	case '"', '<', '>', '\\', '^', '`', '{', '|', '}', '[', ']':
		return true
	}
	return false
}

// GraphQLJSONStringContentDecode unescapes the content of a JSON string literal (the bytes
// between its quotes). Content that does not unescape is returned unchanged, exactly as
// bcheck's jsonStringContentDecode behaves.
func GraphQLJSONStringContentDecode(s string) string {
	if !strings.ContainsRune(s, '\\') {
		return s
	}
	var out string
	if err := json.Unmarshal([]byte(`"`+s+`"`), &out); err != nil {
		return s
	}
	return out
}

// GraphQLJSONStringContentEncode is the exact inverse: the bytes that belong between the
// quotes of a JSON string literal carrying s. json.Marshal's HTML escaping (<, >, & as
// \u003c...) is disabled because the decoder above does not produce those escapes on a round
// trip through Go, and the surgical replacer must change nothing it was not asked to change.
func GraphQLJSONStringContentEncode(s string) string {
	var sb strings.Builder
	enc := json.NewEncoder(&sb)
	enc.SetEscapeHTML(false)
	// Encode cannot fail for a string; the error is for the writer.
	if err := enc.Encode(s); err != nil {
		return s
	}
	out := sb.String()
	// Encode appends a newline; the quotes are the replacer's, not ours.
	return strings.TrimSuffix(out, "\n")[1 : len(strings.TrimSuffix(out, "\n"))-1]
}

// LooksLikeGraphQLDocument reports whether text reads as a GraphQL document: a leading
// operation keyword, or a '{' opener that does not parse as JSON (an anonymous operation and
// a JSON object share the opener; only one of them parses). Leading '#' comment lines are
// legal GraphQL and are skipped first.
//
// This is one predicate with two spellings: this Go one, and looksLikeGraphQLDocument in
// internal/web/ui/src/lib/message-views.ts. The console lists the operations it will edit by
// this test, and the edit-apply route indexes by it - the two lists must be the same list or
// an index lands on an operation the operator never saw, so any change here is a change
// there.
func LooksLikeGraphQLDocument(text string) bool {
	trimmed := strings.TrimLeftFunc(text, isJSWhitespace)
	for strings.HasPrefix(trimmed, "#") {
		nl := strings.IndexByte(trimmed, '\n')
		if nl < 0 {
			return false
		}
		trimmed = strings.TrimLeftFunc(trimmed[nl+1:], isJSWhitespace)
	}
	if trimmed == "" {
		return false
	}
	for _, kw := range []string{"query", "mutation", "subscription", "fragment"} {
		if rest, ok := strings.CutPrefix(trimmed, kw); ok {
			if rest == "" || !isJSWordByte(rest[0]) {
				return true
			}
		}
	}
	if trimmed[0] != '{' {
		return false
	}
	return !json.Valid([]byte(trimmed))
}

// isJSWhitespace is JavaScript's WhiteSpace + LineTerminator set - what the console's
// trimStart and \s strip. Notably IN: U+FEFF (the BOM); notably OUT: U+0085 (NEL), which
// unicode.IsSpace would strip and JavaScript does not. The two predicates index the same
// operation list, so "leading whitespace" is one set, spelled twice.
func isJSWhitespace(r rune) bool {
	switch r {
	case '\t', '\n', '\v', '\f', '\r', ' ', 0x00A0, 0x1680, 0x2028, 0x2029, 0x202F, 0x205F, 0x3000, 0xFEFF:
		return true
	}
	return r >= 0x2000 && r <= 0x200A
}

// isJSWordByte mirrors the \b in the console's keyword test: JavaScript's \w is ASCII-only
// ([A-Za-z0-9_] - no '$', no accented letters), so the boundary check is a byte check and a
// multibyte rune's first byte is already non-word, exactly what \b says there.
func isJSWordByte(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}
