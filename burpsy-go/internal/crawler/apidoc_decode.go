package crawler

// Decoding for the API-document reader: JSON and YAML into ONE shape, and the two scalar conversions
// that shape needs.
//
// # Why the shape is map[string]any and not typed structs
//
// Three facts force it:
//
//  1. yaml.v3 cannot unmarshal into a json.RawMessage. Verified, not assumed:
//     `yaml.Unmarshal([]byte("openapi: 3.0.0\npaths:\n  /x:\n    get: {}"), &doc)` where doc has a
//     `Paths json.RawMessage` answers "cannot unmarshal !!map into json.RawMessage" and leaves Paths
//     empty. A document model built on RawMessage would therefore work for every JSON definition and
//     silently read zero endpoints from every YAML one — and YAML is the majority in the wild. That
//     failure is invisible, which is the worst shape a defect can take here.
//  2. OpenAPI 3 and Swagger 2 disagree about where an operation's parameters live (`parameters` at the
//     operation level in both, but reusable ones under `components.parameters` in one and
//     `definitions.parameters` in the other). Two typed models is two traversals for one grammar.
//  3. A definition carries extension keys and vendor metadata at every level. A struct drops what it
//     does not name, which is fine, but it also FAILS on a type it did not expect, so one unusual
//     document would fail entirely rather than yielding the paths it does declare.
//
// map[string]any costs a type assertion per field and buys one traversal, one accessor, and no way for
// an unmodelled key to fail the read. The traversal in apidoc.go is the only place a field is read, so
// the cost of the loose shape is paid once and in one place.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"

	"gopkg.in/yaml.v3"
)

// decodeAPIDocTree decodes a document that may be JSON or YAML into a map tree.
//
// JSON is tried first, then YAML, and the error reported is the SECOND one — because a file that is
// perfectly good YAML but not a mapping (a list or a scalar at the top level) fails both, and saying
// "neither JSON nor YAML" for it describes the language rather than the shape that was wanted.
//
// A document that decodes to something other than a map is not an API definition even though its text
// sniffs like one — a list of OpenAPI documents is a valid YAML file and not a valid definition, and
// this returns the "not a mapping" failure rather than zero endpoints.
func decodeAPIDocTree(body []byte) (map[string]any, error) {
	// The marker strip first, so the JSON path sees the same bytes the YAML path does. Without it a
	// document pasted out of a Swagger editor — which routinely carries a leading `---` — is valid
	// YAML but not valid JSON, so the JSON attempt fails on framing rather than on content and a
	// test comparing the two paths is comparing the framing.
	body = trimYAMLDocument(body)

	var asJSON map[string]any
	if err := json.Unmarshal(body, &asJSON); err == nil && asJSON != nil {
		return asJSON, nil
	}

	// Through the node rather than straight into the map: the node is the document itself, and
	// decoding its content is what rejects a top-level LIST (a valid YAML file, not a valid
	// definition) with the shape that was wanted instead of a nil map and a confusing message.
	var node yaml.Node
	if err := yaml.Unmarshal(body, &node); err != nil {
		return nil, err
	}
	if node.Kind != yaml.DocumentNode || len(node.Content) == 0 {
		return nil, fmt.Errorf("the document is empty")
	}
	root := node.Content[0]
	if root.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("the document's top level is %s, not a mapping", yamlKindName(root.Kind))
	}
	var out map[string]any
	if err := root.Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

// itoa64 is the int64 case of the same conversion. yaml.v3 produces int64 for a large integer
// literal where json produces float64, so the scalar reader has to normalise both rather than drop
// one and silently report a schema version as empty.
func itoa64(i int64) string { return strconv.FormatInt(i, 10) }

// yamlKindName names a node kind for an error message, so the message describes the shape that was
// found rather than restating the parse error the caller already has.
func yamlKindName(k yaml.Kind) string {
	switch k {
	case yaml.SequenceNode:
		return "a list"
	case yaml.ScalarNode:
		return "a scalar"
	case yaml.AliasNode:
		return "an alias"
	default:
		return "not a mapping"
	}
}

// fmtFloat renders a JSON number without a trailing ".0".
//
// JSON has one numeric type and yaml.v3 has several, so a schema version arrives as 3 under one
// grammar and 3.0 under the other. Without this the same document read twice yields two different
// version strings, and a report that says "OpenAPI 3.0.0" for one and "OpenAPI 3" for the other is
// reporting a difference that is not there.
func fmtFloat(f float64) string { return strconv.FormatFloat(f, 'f', -1, 64) }

// trimYAMLDocument removes a leading YAML document marker and any BOM.
//
// Not cosmetic: a definition pasted out of a Swagger editor commonly carries a `---` document start,
// and yaml.v3 accepts that but json.Unmarshal does not — so a document that is BOTH valid JSON
// semantics and YAML-with-marker would take the JSON path, fail, and fall through to YAML, which is
// fine, but only because this reader tries both. The marker is stripped so the two paths see the same
// bytes and a test comparing them is comparing the document rather than the framing.
func trimYAMLDocument(body []byte) []byte {
	body = bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF})
	trimmed := bytes.TrimLeft(body, " \t\r\n")
	if bytes.HasPrefix(trimmed, []byte("---")) {
		trimmed = bytes.TrimPrefix(trimmed, []byte("---"))
		trimmed = bytes.TrimLeft(trimmed, " \t\r\n")
	}
	return trimmed
}
