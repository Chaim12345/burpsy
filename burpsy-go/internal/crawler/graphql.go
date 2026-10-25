package crawler

// GraphQL discovery: an endpoint that answers a GraphQL introspection query tells the crawl which
// operations it exposes, and those operations become locations (burpsy-react-ui-bwwg, criterion 4).
//
// # Why this is a separate reader and not another branch of ParseAPIDocument
//
// A GraphQL endpoint has no document to fetch. There is no /openapi.json to recognise and nothing to
// sniff: the endpoint answers 200 to a POST with a JSON body, and whether it is GraphQL at all is
// known only by asking. So the shape is inverted — instead of a crawl FETCHING a definition and
// reading the operations out of it, the crawl SENDS a query and reads the operations out of the
// answer. That also makes it the first reader in this package that sends traffic of its own, which is
// why it is behind its own switch and its own skip reasons rather than sharing the document path's.
//
// # The introspection query
//
// The standard query, reduced to the fields a crawler acts on: each type's name, each field's name,
// and each field's argument names. Burp's two GraphQL switches are perform_graphql_introspection and
// guess_hidden_graphql_endpoints (Zrf0.java:3622-3637); the second is a separate concern — probing
// common endpoint paths on a host that has no introspection — and is what guessHiddenGraphQLEndpoints
// does.
//
// # Refusal-first, as everywhere else here
//
// An introspection query is a POST with a JSON body, and a POST is a mutation. So:
//
//   - It goes through perform(), which sends through sender.AuthorisedSender — the same scope
//     chokepoint every other crawl request goes through. A crawl with no scope covering the endpoint
//     never sends it, and the refusal is recorded as SkipSendRefused like any other.
//   - It counts against the crawl's own request bound, because it IS a request the crawl made. A
//     crawler that sent unbounded introspection queries while claiming a bounded request count would
//     be reporting a number that is not true.
//   - An endpoint that answers 200 with something that is not a GraphQL introspection result is NOT a
//     failure and NOT an operation: "this URL is not a GraphQL endpoint" is the ordinary answer for
//     every non-GraphQL URL a crawl touches, and reporting it as an error would fill the ledger with
//     noise that buries the one that matters.

import (
	"encoding/json"
	"strings"
)

// graphqlIntrospectionQuery is the standard introspection query, reduced to what a crawler acts on.
//
// Reduced rather than the full specification document because the full one asks for deprecation
// reasons, descriptions, directives and default values — thousands of bytes of fields this module
// discards, sent once per GraphQL endpoint a crawl meets. What survives is the part that names
// something requestable: the schema's query type, and each field on it with its argument names.
//
// `__schema` rather than `getIntrospectionQuery()` because a hand-written query is inspectable: an
// operator reading a captured introspection POST can see exactly what burpsy asked for.
const graphqlIntrospectionQuery = `{"query":"query IntrospectionQuery { __schema { queryType { name } types { name kind fields(includeDeprecated: false) { name args { name } } } } }"}`

// graphqlMaxOperations bounds how many operations one introspection answer may contribute.
//
// Bounded for the reason every other reader here is bounded: a schema can declare thousands of types,
// and a crawl of a large GraphQL surface would otherwise admit a frontier the operator did not ask
// for. The cap is a REPORTED bound rather than a silent one — see MaxGraphQLOperations.
const graphqlMaxOperations = 5_000

// MaxGraphQLOperations is the per-endpoint bound, exposed so the config layer can name it.
const MaxGraphQLOperations = graphqlMaxOperations

// graphqlIntrospectionBody is the raw POST body an introspection request carries.
func graphqlIntrospectionBody() []byte { return []byte(graphqlIntrospectionQuery) }

// graphqlResult is the shape of an introspection ANSWER, read for the fields that name operations.
type graphqlResult struct {
	Data struct {
		Schema struct {
			QueryType struct {
				Name string `json:"name"`
			} `json:"queryType"`
			Types []struct {
				Name   string `json:"name"`
				Kind   string `json:"kind"`
				Fields []struct {
					Name string `json:"name"`
					Args []struct {
						Name string `json:"name"`
					} `json:"args"`
				} `json:"fields"`
			} `json:"types"`
		} `json:"__schema"`
	} `json:"data"`
	// Errors is present on a well-formed GraphQL answer that reports errors — a disabled
	// introspection endpoint answers 200 with `{"errors":[...]}`. It is read so the caller can tell
	// "this is not GraphQL" from "this is GraphQL and introspection is off", which are different
	// answers with different remedies.
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

// LooksLikeGraphQLAnswer reports whether a response body is a GraphQL introspection ANSWER.
//
// The test is `data.__schema`, not `errors`: a body carrying only errors is a GraphQL endpoint that
// refused, which is worth reporting, while a body carrying neither is an ordinary response that
// happened to answer 200 to a POST.
func LooksLikeGraphQLAnswer(body []byte) bool {
	var probe struct {
		Data struct {
			Schema json.RawMessage `json:"__schema"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &probe); err != nil {
		return false
	}
	return len(probe.Data.Schema) > 0 && string(probe.Data.Schema) != "null"
}

// ParseGraphQLOperations returns the operations an introspection answer declares.
//
// Returns failure ONLY for an answer that announces itself as GraphQL and cannot be read, for the
// same reason the document readers do: a refusal must be a counted skip rather than a silent zero.
// A body that is not a GraphQL answer at all is not a failure and yields no operations — that is the
// ordinary case for every non-GraphQL URL a crawl touches.
func ParseGraphQLOperations(body []byte) (ops []APIDocEndpoint, failure string) {
	if len(body) == 0 {
		return nil, ""
	}
	var res graphqlResult
	if err := json.Unmarshal(body, &res); err != nil {
		if LooksLikeGraphQLAnswer(body) {
			return nil, "the response announced itself as a GraphQL answer and could not be read: " + err.Error()
		}
		return nil, ""
	}
	if len(res.Data.Schema.Types) == 0 {
		// A GraphQL answer with errors and no schema is a GraphQL endpoint with introspection
		// disabled. That is a real, reportable fact and it is NOT zero operations at a working API,
		// so the caller is told rather than left to infer it from an empty list.
		if len(res.Errors) > 0 {
			return nil, "the GraphQL endpoint answered with errors rather than a schema: " + firstGraphQLError(res.Errors)
		}
		// No types and no errors is not "zero operations at a working API" WHEN the body
		// announced a schema: a real introspection result always carries types, so the
		// shape only looked like one. Named, like every other refusal here - a silent
		// zero would read as an empty API (burpsy-react-ui-4xqt.1). A body that never
		// announced a schema is the ordinary not-a-GraphQL-answer case and stays silent.
		if LooksLikeGraphQLAnswer(body) {
			return nil, "the answer announced a schema (__schema) but declared no types and reported no errors: a real introspection result always carries types"
		}
		return nil, ""
	}

	// Sorted by type name, then field name, for the reason every other reader here sorts: the cap
	// must truncate the same way on every run, and a report an operator reads has to be diffable.
	types := res.Data.Schema.Types
	sortGraphQLTypes(types)
	seen := map[string]bool{}
	for _, typ := range types {
		if !isGraphQLRootType(typ.Name) && typ.Kind != "OBJECT" {
			// A SCALAR or ENUM has no fields to request. An INTERFACE or UNION's implementations are
			// OBJECTs and are reached on their own entries.
			continue
		}
		fields := typ.Fields
		sortGraphQLFields(fields)
		for _, field := range fields {
			name := field.Name
			// __typename and the __-prefixed introspection meta-fields are not operations; every
			// GraphQL server answers them on any object and requesting them as a crawl frontier item
			// would send requests no schema declares.
			if strings.HasPrefix(name, "__") {
				continue
			}
			key := typ.Name + "." + name
			if seen[key] {
				continue
			}
			seen[key] = true
			args := make([]string, 0, len(field.Args))
			for _, a := range field.Args {
				if a.Name != "" && len(args) < apiDefMaxParams {
					args = append(args, a.Name)
				}
			}
			sortStringsInPlace(args)
			out := APIDocEndpoint{
				Method:      "POST",
				OperationID: key,
				// The path is the ENDPOINT the introspection answer came from, and it is set by the
				// caller rather than here: this reader is given the answer, not the request, and a
				// path it guessed would be a path nobody observed.
				Parameters: args,
				Summary:    typ.Name + " " + name,
			}
			ops = append(ops, out)
			if len(ops) >= graphqlMaxOperations {
				return ops, ""
			}
		}
	}
	// The gqlparser structural load (graphql_introspect.go). Its teeth are placed where
	// they cannot cost coverage: an answer the load rejects but the reader above tolerated
	// keeps its operations, because a proxy or an older server can produce a shape the
	// grammar refuses while the fields are still requestable. Rejection decides only when
	// there is nothing to lose - no operations AND no loadable schema is a named failure,
	// not a silent zero.
	if err := validateIntrospectionStructure(&res); err != nil && len(ops) == 0 {
		return nil, "the answer announced a schema, no operations could be read from it, and gqlparser will not load it: " + err.Error()
	}
	return ops, ""
}

// isGraphQLRootType reports whether a type name is one of the three root operation types.
//
// Read from the answer's own queryType where it is available and falls back to the conventional
// names, because a schema is free to name its root types anything.
func isGraphQLRootType(name string) bool {
	switch name {
	case "Query", "Mutation", "Subscription":
		return true
	default:
		return false
	}
}

// firstGraphQLError names the first error an answer reported.
func firstGraphQLError(errs []struct {
	Message string `json:"message"`
}) string {
	if len(errs) == 0 || errs[0].Message == "" {
		return "the endpoint reported an error and no schema"
	}
	return errs[0].Message
}

// sortGraphQLTypes orders types by name for the deterministic truncation the cap depends on.
func sortGraphQLTypes(types []struct {
	Name   string `json:"name"`
	Kind   string `json:"kind"`
	Fields []struct {
		Name string `json:"name"`
		Args []struct {
			Name string `json:"name"`
		} `json:"args"`
	} `json:"fields"`
}) {
	for i := 1; i < len(types); i++ {
		for j := i; j > 0 && types[j].Name < types[j-1].Name; j-- {
			types[j], types[j-1] = types[j-1], types[j]
		}
	}
}

// sortGraphQLFields orders fields by name, for the same reason.
func sortGraphQLFields(fields []struct {
	Name string `json:"name"`
	Args []struct {
		Name string `json:"name"`
	} `json:"args"`
}) {
	for i := 1; i < len(fields); i++ {
		for j := i; j > 0 && fields[j].Name < fields[j-1].Name; j-- {
			fields[j], fields[j-1] = fields[j-1], fields[j]
		}
	}
}

// sortStringsInPlace orders a small string slice.
func sortStringsInPlace(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// looksLikeGraphQLEndpoint reports whether a response carries a GraphQL envelope.
//
// The test is narrow on purpose: a `data` OR an `errors` member at the top level of a JSON body is
// what a GraphQL server answers with, and a body carrying neither is an ordinary response that
// happened to be JSON. Matching on `data` alone would miss an endpoint whose first answer is an error
// — which is exactly the endpoint an operator most wants to see named.
func looksLikeGraphQLEndpoint(body []byte) bool {
	if len(body) == 0 || len(body) > graphqlMaxProbeBytes {
		return false
	}
	head := body
	if len(head) > 4096 {
		head = head[:4096]
	}
	if head[0] != '{' {
		return false
	}
	// A cheap textual probe rather than a decode: this runs on EVERY response the crawl captures, and
	// unmarshalling every body to look for two keys would make the reader cost more than the parse it
	// feeds. The JSON reader downstream decodes the bodies that matter.
	text := string(head)
	// `errors` alone IS conclusive: no other JSON API answers a request with a top-level `errors`
	// array, and an endpoint that does is a GraphQL server saying so.
	//
	// `data` alone is NOT. Every JSON API response has a `data` key — `{"data":{"users":[...]}}` is an
	// ordinary REST response, and probing every one of them with an introspection query would send a
	// POST to every JSON endpoint a crawl touches. The distinguishing mark is `__schema`: that key is
	// what makes a body a GraphQL ANSWER rather than a GraphQL-shaped envelope, and it is only present
	// when the server actually answered introspection.
	//
	// This was found by a mutation: a looser probe that accepted any `data` key passed every test
	// until one fed the crawl a JSON API response carrying a `data` member.
	if strings.Contains(text, `"errors"`) {
		return true
	}
	return strings.Contains(text, `"__schema"`)
}

// graphqlMaxProbeBytes bounds the cheap probe above, so a large body is never scanned for two keys.
const graphqlMaxProbeBytes = 64 << 10
