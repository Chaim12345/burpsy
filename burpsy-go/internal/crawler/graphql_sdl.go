package crawler

import (
	"regexp"
	"strings"

	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/parser"
	"github.com/vektah/gqlparser/v2/validator"
)

// graphQLSDLTokenLimit bounds the lexer work on one schema document, the same bound the
// scanner's ingestion gate puts on a query document (graphql_ingest.go). The bounded parse
// path, not gqlparser.LoadSchema: LoadSchema alone parses with no limit, and this input came
// off a target.
const graphQLSDLTokenLimit = 1 << 18

// sdlRootOpening matches the opening line of a root operation type declaration in the
// shapes gqlparser parses in conventional SDL: spaces or tabs before the brace, an
// implements-clause, applied directives, and the minified brace-adjacent form. The accepted
// subset, stated exactly:
//
//	accept:  "type Query {", "type Query\t{", "type Query   {", "type Query{...}",
//	         "type Query implements Node {", "type Query @key(...) {", and the Mutation /
//	         Subscription spellings
//	decline: "extend type Query {" (an extension is not a standalone schema),
//	         "type Query = {...}" (a TypeScript alias; "=" is no SDL continuation),
//	         prose that mentions the shape, and root types under unconventional names
//
// Line-anchored, lowercased; the validity call belongs to the parser, the same division of
// labour every other sniff branch uses.
var sdlRootOpening = regexp.MustCompile(`^type\s+(query|mutation|subscription)\s*(\{|implements\s|@)`)

func looksLikeSDLDocument(head string) bool {
	for _, line := range strings.Split(head, "\n") {
		if sdlRootOpening.MatchString(strings.TrimSpace(strings.ToLower(line))) {
			return true
		}
	}
	return false
}

// sdlContentTypes is the media-type allowlist that announces a GraphQL schema document. An
// allowlist, not a substring: application/graphql-response+json announces an introspection
// ANSWER (JSON), and routing it to the SDL reader would misjudge the body's own format.
var sdlContentTypes = map[string]bool{
	"application/graphql":        true,
	"application/graphql-schema": true,
	"text/graphql":               true,
}

// parseGraphQLSDL reads a GraphQL schema document - SDL, as servers publish it at
// /schema.graphql and repositories carry it - through the pinned gqlparser, and derives
// operations the way the introspection reader (ParseGraphQLOperations) derives them from a
// result: every object type's fields are operations, types and fields and arguments sorted,
// so a schema and an introspection of that schema admit the same frontier (the parity bar,
// burpsy-react-ui-4xqt.2).
//
// The prelude is prepended exactly as gqlparser.LoadSchema does (validator.Prelude first),
// because a schema document refers to the builtins without declaring them.
func parseGraphQLSDL(body []byte) ([]APIDocEndpoint, string) {
	sd, err := parser.ParseSchemasWithLimit(graphQLSDLTokenLimit, validator.Prelude,
		&ast.Source{Name: "schema", Input: string(body)})
	if err != nil {
		return nil, "the document announced itself as a GraphQL schema and could not be parsed: " + err.Error()
	}
	schema, err := validator.ValidateSchemaDocument(sd)
	if err != nil {
		return nil, "the document announced itself as a GraphQL schema and is not a valid one: " + err.Error()
	}
	var ops []APIDocEndpoint
	for _, typeName := range sortedKeys(schema.Types) {
		def := schema.Types[typeName]
		// Mirror the introspection reader: a SCALAR or ENUM has no fields to request, an
		// INTERFACE or UNION's implementations are OBJECTs reached on their own entries, and
		// the builtins the prelude brought in are not the target's surface.
		if def.BuiltIn || strings.HasPrefix(def.Name, "__") || def.Kind != ast.Object {
			continue
		}
		fields := make([]string, 0, len(def.Fields))
		byName := make(map[string]*ast.FieldDefinition, len(def.Fields))
		for _, f := range def.Fields {
			// __typename and the __-prefixed meta-fields are not operations; every server
			// answers them on any object.
			if strings.HasPrefix(f.Name, "__") {
				continue
			}
			fields = append(fields, f.Name)
			byName[f.Name] = f
		}
		sortStringsInPlace(fields)
		for _, fieldName := range fields {
			args := make([]string, 0, len(byName[fieldName].Arguments))
			for _, a := range byName[fieldName].Arguments {
				if a.Name != "" && len(args) < apiDefMaxParams {
					args = append(args, a.Name)
				}
			}
			sortStringsInPlace(args)
			ops = append(ops, APIDocEndpoint{
				Method:      "POST",
				OperationID: typeName + "." + fieldName,
				// The path is the ENDPOINT the document came from, set by the caller: this
				// reader is given the document, not the request.
				Parameters: args,
				Summary:    typeName + " " + fieldName,
			})
			if len(ops) >= graphqlMaxOperations {
				return ops, ""
			}
		}
	}
	return ops, ""
}
