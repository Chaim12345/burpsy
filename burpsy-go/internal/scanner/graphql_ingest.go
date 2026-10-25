package scanner

// GraphQL document validation at audit-item ingestion (burpsy-react-ui-4xqt child).
//
// bcheck's nested GraphQL argument points are derived by a string scan
// (internal/bcheck/insertion_graphql.go's looksLikeGraphQLDocument): it balances braces and
// quotes but cannot tell a grammar violation from a document. A malformed document that
// happens to balance - trailing garbage after the operation, an argument name starting
// with a digit - still yields "argument" points, and every server-side injection check then
// probes positions no resolver will ever parse: the server answers a syntax error and the
// probe measures the parser, not the code under test.
//
// This file gates those points on a real parse: vektah/gqlparser's parser validates the
// parent document of every derived argument point at ingestion, and a document no GraphQL
// server would accept yields no argument points. The flat parent point stays - a payload
// replacing the whole document is still a meaningful probe - but the derived argument
// positions are rejected. A valid document keeps exactly the positions the enumerator
// derived, and a non-GraphQL item takes a nil parse path: no candidate document, no parser
// call, bytes unchanged.
//
// The gate arbitrates real grammar, which cuts both ways: gqlparser also ACCEPTS what a
// stricter hand rule would refuse - `{book(title: "Dune" ,,){author}}` is valid because
// GraphQL's commas are insignificant - so nothing the grammar allows is lost to a guess.

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/burpsy-go/burpsy/internal/bcheck"
	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/parser"
)

// graphQLIngestMarker joins a parent point's name to the argument the nested point carries,
// the same "[graphql:" naming bcheck gives the nested points it derives.
const graphQLIngestMarker = "[graphql:"

// graphQLIngestMaxDocumentLen mirrors bcheck's maxGraphQLDocumentLen: a document past the
// cap was never scanned for arguments, so there are no derived points to gate and the
// parser is never asked to chew a generated megabyte.
const graphQLIngestMaxDocumentLen = 64 << 10

// graphQLIngestTokenLimit bounds the parser's work on one document. The 64KB document cap
// implies well under this many tokens; the limit is the hard stop that keeps a hostile
// document's pathological nesting from buying parser CPU the audit never budgeted.
const graphQLIngestTokenLimit = 1 << 18

// graphQLDocumentValid reports whether doc parses as a GraphQL executable document under
// any of the wire decodings bcheck could have read it through. "Valid under any decoding"
// keeps the gate conservative in the direction of coverage: only a document malformed under
// EVERY decoding loses its points. bcheck decodes by the parent's coding, a field this
// package cannot read, so the gate tries each decoding bcheck's GraphQL expansion uses and
// trusts the union; the decoding bcheck itself used is always in the set.
func graphQLDocumentValid(doc string) bool {
	for _, cand := range graphQLDecodings(doc) {
		// The cap bounds the parser's work on the DECODED document - the same measurement
		// bcheck applies before scanning one for arguments. A candidate past it is skipped,
		// not trusted; the decoding bcheck itself used is always under it (bcheck scanned
		// the decoded document, which its own 64KB cap bounds), so the skip can only bite
		// a document bcheck never derived argument points from.
		if len(cand) > graphQLIngestMaxDocumentLen {
			continue
		}
		if graphQLParses(cand) {
			return true
		}
	}
	return false
}

// graphQLDecodings returns the candidate decodings of a wire value, deduplicated: the value
// as it sits on the wire, then percent-decoded, then as the content of a JSON string
// literal. Each decoding matches bcheck's exactly - bcheck owns decode semantics, and the
// gate follows, or it would keep points bcheck's own decode of the value never probes.
func graphQLDecodings(doc string) []string {
	out := make([]string, 0, 3)
	seen := map[string]bool{}
	for _, cand := range []string{doc, graphQLPercentDecode(doc), graphQLJSONStringContentDecode(doc)} {
		if !seen[cand] {
			seen[cand] = true
			out = append(out, cand)
		}
	}
	return out
}

// graphQLPercentDecode decodes %XX escapes and nothing else: '+' is an ordinary byte, not
// a space, and an escape that is not two hex digits survives verbatim. This replicates
// internal/bcheck/insertion.go's percentDecode - unexported there - which matches the
// project's own percentEscape (which escapes '+') and so keeps the round trip stable.
// net/url's QueryUnescape drifts on both counts.
func graphQLPercentDecode(s string) string {
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

// graphQLJSONStringContentDecode unescapes the content of a JSON string literal (the bytes
// between its quotes). Content that does not unescape is returned unchanged, exactly as
// internal/bcheck/insertion_graphql.go's jsonStringContentDecode behaves.
func graphQLJSONStringContentDecode(s string) string {
	if !strings.ContainsRune(s, '\\') {
		return s
	}
	var out string
	if err := json.Unmarshal([]byte(`"`+s+`"`), &out); err != nil {
		return s
	}
	return out
}

func graphQLParses(doc string) bool {
	_, err := parser.ParseQueryWithTokenLimit(&ast.Source{Input: doc}, graphQLIngestTokenLimit)
	return err == nil
}

// filterGraphQLPointsByValidation drops the nested GraphQL argument points whose parent
// document no decoding parses as a valid GraphQL executable document. Every other point -
// the flat parent included - passes through unchanged, in order. Each distinct parent is
// validated once.
func filterGraphQLPointsByValidation(points []bcheck.InsertionPoint) []bcheck.InsertionPoint {
	// parents maps a parent point (kind + name) to its wire value, for the nested points
	// that name it. The flat point always enumerates with its nested ones, but a parent
	// that never appears leaves its nested points unproven rather than rejected: dropping
	// on absence would punish coverage for the gate's own blind spot.
	parents := make(map[bcheck.InsertionPoint]string, len(points))
	for _, p := range points {
		if !strings.Contains(p.Name, graphQLIngestMarker) {
			parents[p] = p.BaseValue
		}
	}
	valid := map[string]bool{}
	out := make([]bcheck.InsertionPoint, 0, len(points))
	for _, p := range points {
		i := strings.Index(p.Name, graphQLIngestMarker)
		if i < 0 {
			out = append(out, p)
			continue
		}
		parentName, ok := lookupGraphQLParent(parents, p, i)
		if !ok {
			out = append(out, p) // unproven, not rejected - see parents above
			continue
		}
		v, seen := valid[parentName]
		if !seen {
			v = graphQLDocumentValid(parentName)
			valid[parentName] = v
		}
		if v {
			out = append(out, p)
		}
	}
	return out
}

// lookupGraphQLParent finds the flat point a nested GraphQL argument point was derived
// from: same kind, name exactly the nested point's name up to the marker. It returns the
// parent's wire value (the document to validate).
func lookupGraphQLParent(parents map[bcheck.InsertionPoint]string, nested bcheck.InsertionPoint, marker int) (string, bool) {
	want := nested.Name[:marker]
	for p, base := range parents {
		if p.Kind == nested.Kind && p.Name == want {
			return base, true
		}
	}
	return "", false
}
