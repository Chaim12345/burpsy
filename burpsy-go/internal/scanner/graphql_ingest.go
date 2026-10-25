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
// parent document at ingestion, and a document no GraphQL server would accept yields no
// argument points. The flat parent point stays - a payload replacing the whole document is
// still a meaningful probe - but the derived argument positions are rejected. A valid
// document keeps exactly the positions the enumerator derived, and a non-GraphQL item
// takes a nil parse path: no candidate document, no parser call, bytes unchanged.
//
// The gate arbitrates real grammar, which cuts both ways: gqlparser also ACCEPTS what a
// stricter hand rule would refuse - `{book(title: "Dune" ,,){author}}` is valid because
// GraphQL's commas are insignificant - so nothing the grammar allows is lost to a guess.

import (
	"github.com/burpsy-go/burpsy/internal/bcheck"
)

// filterGraphQLPointsByValidation drops the nested GraphQL argument points whose parent
// document no decoding parses as a valid GraphQL executable document. Every other point
// passes through unchanged, in order.
//
// STUB (red commit): the identity. The gate lands in the green commit; the tests pin the
// required behavior against this signature now.
func filterGraphQLPointsByValidation(points []bcheck.InsertionPoint) []bcheck.InsertionPoint {
	return points
}
