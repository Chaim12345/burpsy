package crawler

// Introspection-result loading through gqlparser (burpsy-react-ui-4xqt.1, the second of the
// four named gqlparser uses in 4xqt).
//
// The crawler's introspection query is the REDUCED one (2026-10-25 ruling: no traffic-shape
// change, no server-compat risk), and a reduced answer carries no type references, so no real
// schema can be built from it. What can be built is its structure: render the answer's user
// types as SDL with placeholder String types and let gqlparser's validator.LoadSchema judge
// whether the names and the shape are ones a GraphQL schema could declare - valid identifiers,
// no duplicate declarations, a resolvable query root. gqlparser owns what "a schema" means;
// this file owns the render.
//
// The validation's teeth sit where they cannot cost coverage (the standing direction, and the
// lesson of the scanner's ingestion gate): an answer the loader rejects but the hand-rolled
// reader tolerated keeps its operations - a proxy or an older server can produce a shape the
// grammar refuses while the fields are still requestable, and probing them is worth more than
// the purity of refusing them. Rejection decides something only when there is nothing to
// lose: zero derived operations AND a result gqlparser will not load is a named failure
// rather than a silent zero, on the document path and the live answer path alike.
//
// The document path is the "loading" the bead names: a saved introspection result met during
// a crawl is an API document (ParseAPIDocument), and its operations are read by the SAME
// loader the live answer uses, so a saved result and a live answer get one judgment.

import (
	"fmt"
	"strings"

	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/validator"
)

// validateIntrospectionStructure renders the user types of a reduced introspection answer as
// SDL and asks gqlparser whether the render is a schema. Every field and argument renders
// with the placeholder type String - the reduced answer does not name real types - so what
// the load validates is structure, never types. A type the reduced answer cannot express (a
// union carries no possible types here, an enum no values, an input object no input fields)
// renders as a scalar, which validates its NAME without pretending its kind.
func validateIntrospectionStructure(res *graphqlResult) error {
	var sdl strings.Builder
	declared := map[string]bool{}
	for _, typ := range res.Data.Schema.Types {
		name := typ.Name
		if name == "" {
			return fmt.Errorf("a type declares no name")
		}
		if strings.HasPrefix(name, "__") {
			continue // the introspection meta-types are the query's machinery, not declarations
		}
		if isIntrospectionBuiltin(name) {
			continue // the prelude declares the built-in scalars; redeclaring one is the render's error, not the answer's
		}
		if declared[name] {
			return fmt.Errorf("type %s is declared twice", name)
		}
		declared[name] = true
		switch typ.Kind {
		case "OBJECT", "INTERFACE":
			keyword := "type"
			if typ.Kind == "INTERFACE" {
				keyword = "interface"
			}
			var fields []string
			for _, f := range typ.Fields {
				if strings.HasPrefix(f.Name, "__") {
					continue
				}
				args := make([]string, 0, len(f.Args))
				for _, a := range f.Args {
					args = append(args, a.Name+": String")
				}
				field := f.Name
				if len(args) > 0 {
					field += "(" + strings.Join(args, ", ") + ")"
				}
				fields = append(fields, field+": String")
			}
			if len(fields) == 0 {
				fmt.Fprintf(&sdl, "%s %s\n", keyword, name)
			} else {
				fmt.Fprintf(&sdl, "%s %s { %s }\n", keyword, name, strings.Join(fields, " "))
			}
		default:
			fmt.Fprintf(&sdl, "scalar %s\n", name)
		}
	}
	if root := res.Data.Schema.QueryType.Name; root != "" {
		fmt.Fprintf(&sdl, "schema { query: %s }\n", root)
	}
	_, err := validator.LoadSchema(&ast.Source{Input: sdl.String()})
	return err
}

// isIntrospectionBuiltin reports whether name is a scalar gqlparser's prelude declares.
func isIntrospectionBuiltin(name string) bool {
	switch name {
	case "String", "Int", "Float", "Boolean", "ID":
		return true
	default:
		return false
	}
}
