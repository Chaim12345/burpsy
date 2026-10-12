package bcheck

// GraphQL argument insertion points (burpsy-react-ui-0vzb.13).
//
// A GraphQL request carries its parameters INSIDE one string: `{"query":"{book(title:\"Dune\")
// {author}}"}` has one JSON body point, `query`, whose value is a whole document. Probing that
// point replaces the document, so the server answers a syntax error and the resolver that reads
// `title` never sees the payload. Every server-side injection check (SQL, NoSQL, command, path
// traversal, template) therefore tested nothing on a GraphQL endpoint whose arguments are
// literals rather than variables.
//
// This file makes each string-literal argument of such a document a nested insertion point, the
// way a JSON-valued parameter already yields one point per JSON string. The splice lands between
// the literal's quotes, escaped by GraphQL's string grammar (whose escapes are JSON's), then the
// document is re-encoded into whatever carried it: a JSON body string (codingJSONString), a form
// or query-string value (percent-encoding), so the request still parses at every layer and only
// the argument changes.
//
// Arguments passed as variables need nothing from here: the `variables` object of a JSON body is
// ordinary JSON, and its string values are already body points.
//
// What is NOT a point: numeric, boolean and enum literals. GraphQL validates their type before
// any resolver runs, so a payload in an Int position is refused by the server's validator, never
// by the code under test, and probing it could only produce noise. Block strings ("""...""") are
// skipped too: their escaping rules differ and they almost never carry an argument.

import (
	"encoding/json"
	"strings"
)

// maxGraphQLDocumentLen bounds the documents scanned for arguments. A document is parsed once per
// enumeration; anything this large is a generated query rather than a request an operator would
// expect to be audited argument by argument, and the flat point still covers it.
const maxGraphQLDocumentLen = 64 << 10

// graphQLArg is one string-literal argument: the argument (or input-object field) name it was
// passed as, and the byte range of its content between the quotes.
type graphQLArg struct {
	name  string
	start int
	end   int
}

// appendGraphQLPoints appends one nested point per string-literal argument of the GraphQL document
// carried by parent, if it carries one. Only JSON string values and form/query values are read:
// those are the encodings GraphQL-over-HTTP defines (a JSON POST body, a GET query string, and the
// form body many servers also accept).
func appendGraphQLPoints(nested []InsertionPoint, parent InsertionPoint) []InsertionPoint {
	var doc string
	var outer coding
	switch parent.coding {
	case codingJson:
		doc, outer = jsonStringContentDecode(parent.BaseValue), codingJSONString
	case codingForm:
		doc, outer = percentDecode(parent.BaseValue), codingForm
	default:
		return nested
	}
	if len(doc) > maxGraphQLDocumentLen || !looksLikeGraphQLDocument(doc) {
		return nested
	}
	for _, a := range graphQLStringArgs(doc) {
		if len(nested) >= maxNestedPoints {
			break
		}
		name := parent.Name + "[graphql:" + a.name + "]"
		nested = append(nested, InsertionPoint{
			Kind:            parent.Kind,
			Name:            name,
			BaseValue:       parent.BaseValue,
			containerCoding: outer,
			nested:          nestedGraphQL,
			refuse:          parent.refuse,
			coding:          codingNested,
			loc: loc{
				kind:       parent.loc.kind,
				index:      parent.loc.index,
				start:      parent.loc.start,
				end:        parent.loc.end,
				innerStart: a.start,
				innerEnd:   a.end,
			},
		})
	}
	return nested
}

// jsonStringContentDecode unescapes the content of a JSON string literal (the bytes between its
// quotes). Content that does not unescape is returned unchanged, which can then only fail the
// GraphQL recogniser.
func jsonStringContentDecode(s string) string {
	if !strings.ContainsRune(s, '\\') {
		return s
	}
	var out string
	if err := json.Unmarshal([]byte(`"`+s+`"`), &out); err != nil {
		return s
	}
	return out
}

// looksLikeGraphQLDocument reports whether s reads as a GraphQL executable document: after
// whitespace and comments it opens with a selection set or an operation keyword, its braces
// and parentheses balance outside string literals, and it has at least one selection set. A
// JSON value never qualifies (JSON has no parentheses around its strings, and the argument scan
// requires them), and neither does free text that merely starts with a word.
func looksLikeGraphQLDocument(s string) bool {
	t := strings.TrimSpace(stripLeadingGraphQLComments(s))
	if t == "" {
		return false
	}
	if t[0] != '{' {
		kw := false
		for _, k := range []string{"query", "mutation", "subscription"} {
			if strings.HasPrefix(t, k) && len(t) > len(k) && !isGraphQLNameByte(t[len(k)]) {
				kw = true
				break
			}
		}
		if !kw {
			return false
		}
	}
	braces, parens, sawBrace := 0, 0, false
	ok := scanGraphQL(s, func(c byte, _ int) bool {
		switch c {
		case '{':
			braces++
			sawBrace = true
		case '}':
			braces--
		case '(':
			parens++
		case ')':
			parens--
		}
		return braces >= 0 && parens >= 0
	}, nil)
	return ok && sawBrace && braces == 0 && parens == 0
}

func stripLeadingGraphQLComments(s string) string {
	for {
		t := strings.TrimLeft(s, " \t\r\n,\ufeff")
		if !strings.HasPrefix(t, "#") {
			return t
		}
		nl := strings.IndexAny(t, "\r\n")
		if nl < 0 {
			return ""
		}
		s = t[nl:]
	}
}

func isGraphQLNameByte(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

// graphQLStringArgs returns every string literal that sits inside an argument list, with the
// name it was passed under. A string inside parentheses is an argument value, a list element of
// one, or a field of an input object passed as one; those are the only places an executable
// document holds a string, apart from directive arguments, which are argument lists too.
func graphQLStringArgs(s string) []graphQLArg {
	var out []graphQLArg
	parens := 0
	lastName := ""
	var name strings.Builder
	scanGraphQL(s, func(c byte, _ int) bool {
		switch {
		case c == '(':
			parens++
		case c == ')':
			parens--
		case c == ':':
			lastName = name.String()
		}
		if isGraphQLNameByte(c) {
			name.WriteByte(c)
		} else if c != ' ' && c != '\t' && c != '\r' && c != '\n' && c != ',' {
			name.Reset()
		}
		return true
	}, func(start, end int) {
		if parens > 0 {
			n := lastName
			if n == "" {
				n = "arg"
			}
			out = append(out, graphQLArg{name: n, start: start, end: end})
		}
	})
	return out
}

// scanGraphQL walks s outside comments and string literals, calling punct for every byte there
// (a false return stops the walk and reports failure) and str with the content range of every
// ordinary string literal. Block strings are stepped over without being reported. It reports
// false for an unterminated string.
func scanGraphQL(s string, punct func(c byte, i int) bool, str func(start, end int)) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '#':
			for i < len(s) && s[i] != '\n' && s[i] != '\r' {
				i++
			}
		case strings.HasPrefix(s[i:], `"""`):
			// A block string ends at the first """ not escaped as \""".
			j := i + 3
			for j < len(s) && !(strings.HasPrefix(s[j:], `"""`) && s[j-1] != '\\') {
				j++
			}
			if j >= len(s) {
				return false
			}
			i = j + 2
		case c == '"':
			j := i + 1
			for j < len(s) && s[j] != '"' {
				if s[j] == '\\' {
					j++
				}
				if j < len(s) && (s[j] == '\n' || s[j] == '\r') {
					return false
				}
				j++
			}
			if j >= len(s) {
				return false
			}
			if str != nil {
				str(i+1, j)
			}
			i = j
		default:
			if !punct(c, i) {
				return false
			}
		}
	}
	return true
}
