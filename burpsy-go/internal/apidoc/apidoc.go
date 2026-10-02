// Package apidoc parses an API definition into the concrete requests an API scan sends.
//
// Burp's "API-only scan" (Zhw0 in the 2026.7.1 teardown) takes an API *definition* as its seed rather
// than a URL: the wizard grows an API_DEFINITION step, and the scan enumerates the endpoints the
// document describes instead of discovering them by crawling. burpsy had no parser of any kind, which
// is why that card stayed disabled with the reason on it (burpsy-react-ui-93o4). This is the missing
// half — the launch surface (internal/web/api_apiscan.go) hands a document here and gets back one
// request per described operation.
//
// # What it reads, and what it refuses by name
//
// OpenAPI 3.x and Swagger 2.0, in JSON or YAML, including local `$ref`s into the document's own
// schema section. Everything else is refused with the document's own flavour named: an AsyncAPI
// document, a Swagger 1.x document, a RAML or Postman file, or a JSON object that is simply not a
// definition. That refusal matters more than it looks — a loader that treated an unreadable document as
// an empty one would report "0 endpoints", which reads as an empty API rather than as a document nobody
// could read, and the operator would go looking at their API instead of at their file.
//
// RAML is the one flavour recognised from the document's *text* rather than from its parsed tree: its
// version lives in a `#%RAML 1.0` comment, so a parsed RAML file is an empty YAML document and a
// tree-shaped test would report it as unreadable rather than as RAML. See startsWithRAML.
//
// WSDL, GraphQL SDL, Postman collections and RAML are all things Burp's loader accepts and this one
// does not. They are named in the refusal for the same reason.
//
// # Values, and why every one of them says where it came from
//
// A definition describes parameters; a scan needs values. Where the document supplies one — an
// `example`, an `examples` map, a `default`, an `enum` — this package uses it and records that it did.
// Where it does not, it invents a placeholder and records that too, as ValuePlaceholder, so the reply
// can say "9 of 31 parameter values were invented" instead of presenting a scan driven by guesses as
// one driven by the document. A placeholder is deliberately *recognisable* rather than plausible: a
// path parameter named `id` becomes `1` and a string parameter named `q` becomes `q`, so a reader of
// the captured traffic can tell at a glance which values came from the API's own authors.
//
// # What this package deliberately does not do
//
// It sends nothing and it stores nothing. A parsed Document is a description, not a run: internal/web
// turns it into seeds and hands those to the crawler in seeds-only mode, so the fetches go through the
// same scope gate, the same capture path and the same rate limits as any other scan.
package apidoc

import (
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Format is the document's own flavour, as it named itself.
type Format string

const (
	// FormatOpenAPI3 is an `openapi: 3.x` document.
	FormatOpenAPI3 Format = "openapi-3"
	// FormatSwagger2 is a `swagger: "2.0"` document.
	FormatSwagger2 Format = "swagger-2"
)

// ValueSource says where one parameter's value came from. Reported so a run can state how much of
// itself was driven by the document and how much was invented.
type ValueSource string

const (
	// ValueExample is an `example` or `examples` entry on the parameter or its schema.
	ValueExample ValueSource = "example"
	// ValueDefault is a schema `default`.
	ValueDefault ValueSource = "default"
	// ValueEnum is the first value of a schema `enum`.
	ValueEnum ValueSource = "enum"
	// ValuePlaceholder was invented, because the document gave nothing. These are the numbers worth
	// reading in a scan report.
	ValuePlaceholder ValueSource = "placeholder"
)

// Parameter is one value the request needs: a path segment, a query pair, a header, or a body field.
//
// It carries its source because the alternative — a bag of values with no provenance — makes
// "where did this request's `?limit=1` come from" unanswerable, and the answer is the difference
// between the API's own example and a guess.
type Parameter struct {
	Name   string      `json:"name"`
	In     string      `json:"in"` // path | query | header | body | formData
	Value  string      `json:"value"`
	Source ValueSource `json:"source"`
	// Type is the schema type as the document stated it, or "" when it stated none. Carried so a
	// reader can see why a placeholder looks the way it does.
	Type string `json:"type,omitempty"`
	// Format is the schema's declared string format ("email", "date-time", "uuid", ...), or ""
	// when the document stated none. Carried so a payload generator can target a format-specific
	// violation (burpsy-react-ui-ghpy) without re-parsing the document itself.
	Format string `json:"format,omitempty"`
	// Enum is the schema's declared enum values, verbatim as the document wrote them, or nil when
	// it declared none. Populated regardless of which ValueSource this parameter's own Value came
	// from, because a payload generator sweeping "everything outside the enum" needs the whole
	// set, not just the first value valueFor picked for the request itself.
	Enum []string `json:"enum,omitempty"`
	// Required is the document's own statement, which is why an optional parameter is still sent:
	// the definition is the only thing that knows which parameters a given API tolerates missing.
	Required bool `json:"required,omitempty"`
}

// Operation is one endpoint the definition describes, already shaped into a request.
type Operation struct {
	Method string `json:"method"`
	// Template is the path as the document wrote it, parameter names included.
	Template string `json:"template"`
	// Path is the same path with every parameter substituted — what actually goes on the wire.
	Path  string `json:"path"`
	Query []Parameter
	// Header carries only the headers the document itself declares as parameters, plus a Content-Type
	// when a body was synthesised. It is not a claim about what the API needs.
	Header      []Parameter
	ContentType string `json:"content_type,omitempty"`
	Body        []byte `json:"-"`
	OperationID string `json:"operation_id,omitempty"`
	Summary     string `json:"summary,omitempty"`
	// Parameters is every declared parameter that produced a value, in declaration order, for the
	// scan's own reporting.
	Parameters []Parameter `json:"parameters,omitempty"`
}

// Document is one parsed definition.
type Document struct {
	Format  Format `json:"format"`
	Title   string `json:"title,omitempty"`
	Version string `json:"version,omitempty"`
	// Servers are the base URLs the document offers, in its own order. More than one is normal (a
	// production and a sandbox URL); the caller picks, and the scan says which it used.
	Servers []string `json:"servers,omitempty"`
	// SpecVersion is the raw version string from the document's own key, so a refusal or a report can
	// quote what the file actually said.
	SpecVersion string      `json:"spec_version"`
	Operations  []Operation `json:"operations"`
}

// PlaceholderValues counts the parameter values this package invented, across every operation. The
// number to quote beside a scan's endpoint count, and the reason it exists as a method rather than as
// a field: it is derived from the operations and cannot drift from them.
//
// "Parameter" means a declared path, query or header parameter — the things that appear in
// Operation.Parameters. A request body synthesised from a schema is counted by neither this method nor
// DeclaredValues, which is why every message built from the two says "parameter value(s) in the path,
// query string and headers" rather than "values": a body of invented properties is not covered here,
// and a caller that counted it would be over-claiming in exactly the direction this package exists to
// avoid.
func (d *Document) PlaceholderValues() int {
	n := 0
	for _, op := range d.Operations {
		for _, p := range op.Parameters {
			if p.Source == ValuePlaceholder {
				n++
			}
		}
	}
	return n
}

// DeclaredValues counts every parameter value in the document, invented or not.
func (d *Document) DeclaredValues() int {
	n := 0
	for _, op := range d.Operations {
		n += len(op.Parameters)
	}
	return n
}

// Parse reads a definition and returns the operations it describes.
//
// The bytes may be JSON or YAML; the choice is made by trying JSON first and falling back, because
// every JSON document is valid YAML and the reverse is false. A JSON parse failure is therefore not
// reported unless YAML fails too, and then the YAML error is the one that gets quoted — it is the
// parser that had the better chance.
func Parse(data []byte) (*Document, error) {
	// RAML is detected from the text rather than from the tree, because a RAML file's version lives in
	// a `#%RAML 1.0` *comment* — YAML parses the whole file as an empty document, so a tree-shaped test
	// would report it as "not an OpenAPI or Swagger document" and tell the operator nothing. Named
	// because this is the one flavour whose own header has to be read to be recognised.
	if startsWithRAML(data) {
		return nil, fmt.Errorf("this is a RAML document (its first line is a `#%%RAML` directive); this build reads OpenAPI 3.x and Swagger 2.0")
	}
	root, err := decode(data)
	if err != nil {
		return nil, err
	}
	format, specVersion, err := detectFormat(root)
	if err != nil {
		return nil, err
	}
	doc := &Document{Format: format, SpecVersion: specVersion}
	info, _ := root["info"].(map[string]any)
	if info != nil {
		doc.Title, _ = info["title"].(string)
		doc.Version, _ = info["version"].(string)
	}
	if format == FormatOpenAPI3 {
		doc.Servers = openAPI3Servers(root)
	} else {
		doc.Servers = swagger2Servers(root)
	}

	paths, _ := root["paths"].(map[string]any)
	if paths == nil {
		return nil, fmt.Errorf("the definition has no `paths` object, so it describes no endpoints")
	}
	// Sorted, and that is not cosmetic: map iteration order in Go is random, so an unsorted walk makes
	// two scans of the same document fetch the same endpoints in a different order and produce two
	// different-looking reports of identical work.
	pathNames := make([]string, 0, len(paths))
	for name := range paths {
		pathNames = append(pathNames, name)
	}
	sort.Strings(pathNames)

	resolver := newResolver(root, format)
	for _, name := range pathNames {
		item, _ := paths[name].(map[string]any)
		if item == nil {
			continue
		}
		pathParams := declaredParams(item["parameters"], format)
		methods := make([]string, 0, len(item))
		for key := range item {
			if isMethod(key) {
				methods = append(methods, key)
			}
		}
		sort.Strings(methods)
		for _, method := range methods {
			op, _ := item[method].(map[string]any)
			if op == nil {
				continue
			}
			operation, err := buildOperation(name, method, op, pathParams, resolver, format)
			if err != nil {
				return nil, err
			}
			doc.Operations = append(doc.Operations, operation)
		}
	}
	if len(doc.Operations) == 0 {
		return nil, fmt.Errorf("the definition's `paths` object describes no operations, so there is nothing to scan")
	}
	// A template with no declared parameter still needs a value; the ones that were inferred are
	// reported through the same ValuePlaceholder count as everything else.
	return doc, nil
}

// decode turns definition bytes into a generic tree. JSON first, YAML second — see Parse.
func decode(data []byte) (map[string]any, error) {
	var asJSON map[string]any
	if json.Valid(data) {
		if err := json.Unmarshal(data, &asJSON); err == nil && asJSON != nil {
			return asJSON, nil
		}
	}
	var asYAML map[string]any
	if err := yaml.Unmarshal(data, &asYAML); err != nil {
		// "neither JSON nor YAML" would be wrong for the common case that lands here — a file that is
		// perfectly good YAML but not a *mapping*, such as one whose top level is a list or a scalar —
		// so the message names the shape that was wanted rather than the language that was tried.
		return nil, fmt.Errorf("the document could not be read as a JSON object or a YAML mapping: %w", err)
	}
	if asYAML == nil {
		return nil, fmt.Errorf("the document parsed as empty, so it describes no API")
	}
	return asYAML, nil
}

// detectFormat names the document's flavour, or refuses it by what it actually is.
func detectFormat(root map[string]any) (Format, string, error) {
	if raw, ok := root["openapi"].(string); ok {
		if strings.HasPrefix(strings.TrimSpace(raw), "3.") {
			return FormatOpenAPI3, raw, nil
		}
		return "", "", fmt.Errorf("this is an OpenAPI %s document; this build reads OpenAPI 3.x and Swagger 2.0. "+
			"An OpenAPI 2.0 document is spelled `swagger: \"2.0\"`, and this one is not that", raw)
	}
	if raw, ok := root["swagger"]; ok {
		version := strings.TrimSpace(scalarString(raw))
		// `2` as well as `2.0`, and that is not a nicety: an unquoted `swagger: 2.0` is a *float* to
		// YAML, and rendering a float with Go's shortest round-trip form yields "2". Refusing it would
		// fail on one of the two commonest spellings of the only version this reads — and it would fail
		// by calling the file "Swagger 2", i.e. by naming the very version it had just refused.
		if version == "2" || version == "2.0" {
			// Reported as the spec spells it rather than as the file did, because the file's "2" and "2.0"
			// are the same document and a report that echoed "swagger-2 2" would read as a typo.
			return FormatSwagger2, "2.0", nil
		}
		return "", "", fmt.Errorf("this is a Swagger %s document; this build reads Swagger 2.0 and OpenAPI 3.x. "+
			"Swagger 1.x has no `definitions`/`paths` shape in common with 2.0 and cannot be read as one", version)
	}
	// The remaining refusals name the document rather than the absence of a key: "no `openapi` or
	// `swagger` version key" is true of all of these and tells the operator nothing about their file.
	switch {
	case root["asyncapi"] != nil:
		return "", "", fmt.Errorf("this is an AsyncAPI document, which describes message channels rather than HTTP " +
			"operations; an API scan cannot enumerate it")
	case root["info"] != nil && root["item"] != nil:
		return "", "", fmt.Errorf("this looks like a Postman collection; this build reads OpenAPI 3.x and Swagger 2.0")
	case root["openapi"] != nil:
		return "", "", fmt.Errorf("the `openapi` key is not a version string, so this document's flavour is unknown")
	}
	return "", "", fmt.Errorf("this is not an OpenAPI or Swagger document: it has neither an `openapi` nor a " +
		"`swagger` version key, and a scan needs one to know how to read the rest")
}

// startsWithRAML reports whether the document opens with RAML's own version directive, ignoring a
// byte-order mark and leading blank lines. Whitespace-insensitive because the directive may follow a
// comment block, and the alternative — anchoring on the first byte — would miss those files and report
// them as unreadable rather than as RAML.
func startsWithRAML(data []byte) bool {
	s := strings.TrimLeft(string(data), " \t\r\n\ufeff")
	return strings.HasPrefix(s, "#%RAML")
}

// scalarString renders a scalar from either parser without depending on its concrete type. YAML
// happily produces a float for `swagger: 2.0` and a string for `swagger: "2.0"`, and both mean 2.0.
func scalarString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case int:
		return strconv.Itoa(t)
	case bool:
		return strconv.FormatBool(t)
	default:
		return ""
	}
}

// openAPI3Servers reads `servers[].url`, substituting each server variable's default so a templated
// base URL becomes a concrete one. A server that cannot be resolved to something absolute is dropped
// rather than guessed at.
func openAPI3Servers(root map[string]any) []string {
	servers, _ := root["servers"].([]any)
	out := make([]string, 0, len(servers))
	for _, raw := range servers {
		server, _ := raw.(map[string]any)
		if server == nil {
			continue
		}
		base, _ := server["url"].(string)
		if base == "" {
			continue
		}
		if vars, ok := server["variables"].(map[string]any); ok {
			for name, rawVar := range vars {
				variable, _ := rawVar.(map[string]any)
				if variable == nil {
					continue
				}
				if def, ok := variable["default"]; ok {
					base = strings.ReplaceAll(base, "{"+name+"}", scalarString(def))
				}
			}
		}
		if strings.Contains(base, "{") {
			// A variable with no default: the URL is not a URL yet, and fetching it would be a request
			// to a host named `{region}`.
			continue
		}
		out = append(out, strings.TrimRight(base, "/"))
	}
	return out
}

// swagger2Servers assembles a base URL from `schemes`/`host`/`basePath`, which is how a 2.0 document
// states one. All of them are optional in the spec, and a document with none of them yields no server:
// the caller then has to supply a base URL, which is a question it can ask, unlike a guess.
func swagger2Servers(root map[string]any) []string {
	host, _ := root["host"].(string)
	basePath, _ := root["basePath"].(string)
	schemes, _ := root["schemes"].([]any)
	var scheme string
	for _, raw := range schemes {
		if s := scalarString(raw); s != "" {
			scheme = s
			break
		}
	}
	if host == "" {
		return nil
	}
	if scheme == "" {
		scheme = "http"
	}
	out := []string{scheme + "://" + host + strings.TrimRight(basePath, "/")}
	return out
}

func isMethod(key string) bool {
	switch strings.ToLower(key) {
	case "get", "put", "post", "delete", "options", "head", "patch", "trace":
		return true
	}
	return false
}

// declaredParams reads a parameter list — path-level or the document's own components — into the
// generic shape buildOperation wants. A `$ref` is resolved, because a path-level parameter almost
// always is one.
func declaredParams(raw any, format Format) []map[string]any {
	list, _ := raw.([]any)
	out := make([]map[string]any, 0, len(list))
	for _, entry := range list {
		param, _ := entry.(map[string]any)
		if param == nil {
			continue
		}
		out = append(out, param)
	}
	return out
}

// buildOperation turns one path+method into a concrete request.
func buildOperation(template, method string, op map[string]any, pathLevel []map[string]any, r *resolver, format Format) (Operation, error) {
	operation := Operation{
		Method:      strings.ToUpper(method),
		Template:    template,
		OperationID: stringField(op, "operationId"),
		Summary:     stringField(op, "summary"),
	}
	// Path-level parameters first, then the operation's own, which override by (name, in). The spec
	// says the same thing, and getting it backwards would let a path-level `id` shadow the operation's
	// — the more specific declaration is the operation's.
	params := make([]map[string]any, 0, len(pathLevel)+4)
	params = append(params, pathLevel...)
	params = append(params, refList(r, op["parameters"])...)

	var query []string
	pathValues := map[string]string{}
	var formData []Parameter

	for _, raw := range params {
		param := r.resolveMap(raw)
		if param == nil {
			continue
		}
		name := stringField(param, "name")
		in := stringField(param, "in")
		if name == "" || in == "" {
			continue
		}
		p := valueFor(param, r, format)
		p.Name, p.In = name, in
		p.Required, _ = param["required"].(bool)
		switch in {
		case "path":
			pathValues[name] = p.Value
			operation.Parameters = append(operation.Parameters, p)
		case "query":
			query = append(query, url.QueryEscape(name)+"="+url.QueryEscape(p.Value))
			operation.Parameters = append(operation.Parameters, p)
		case "header":
			// Accept/Content-Type are set by the body synthesis below when it has something to say;
			// a document declaring them as parameters is restating the protocol, and sending the
			// placeholder would override the real value with a guess.
			if strings.EqualFold(name, "Accept") || strings.EqualFold(name, "Content-Type") {
				continue
			}
			operation.Header = append(operation.Header, p)
			operation.Parameters = append(operation.Parameters, p)
		case "formData":
			formData = append(formData, p)
			operation.Parameters = append(operation.Parameters, p)
		case "body":
			// Swagger 2's whole-body parameter: its schema becomes the request body.
			if schema, ok := param["schema"].(map[string]any); ok {
				body, contentType := r.bodyFor(schema, "application/json")
				operation.Body = body
				operation.ContentType = contentType
			}
		case "cookie":
			// Deliberately not sent. A cookie is a credential the operator's session jar owns, and a
			// scan that minted a placeholder one would be sending a made-up credential to a real
			// target — noise in the logs at best, an authentication attempt at worst.
			continue
		}
	}

	// A template that names a parameter the document never declared still has to be fetched, so the
	// name is used as the value and counted as invented. Refusing would drop a described endpoint for
	// a documentation defect.
	operation.Path = fillTemplate(template, pathValues)

	if format == FormatOpenAPI3 {
		// OpenAPI 3 puts the body in requestBody, and the media type is part of the key: the document
		// choosing `application/json` is what tells the scan to send JSON.
		if rb, _ := op["requestBody"].(map[string]any); rb != nil {
			content, _ := r.resolveMap(rb)["content"].(map[string]any)
			body, contentType := r.bodyFromContent(content)
			if len(body) > 0 {
				operation.Body = body
				operation.ContentType = contentType
			}
		}
	} else if len(formData) > 0 {
		// Swagger 2's form body: one urlencoded pair per formData parameter, in declaration order.
		values := make([]string, 0, len(formData))
		for _, p := range formData {
			values = append(values, url.QueryEscape(p.Name)+"="+url.QueryEscape(p.Value))
		}
		operation.Body = []byte(strings.Join(values, "&"))
		operation.ContentType = "application/x-www-form-urlencoded"
	}

	if len(query) > 0 {
		operation.Path = operation.Path + "?" + strings.Join(query, "&")
	}
	return operation, nil
}

// fillTemplate substitutes every `{name}` in a path template. A name with no value gets itself as its
// value, which is the same recognisable-invention rule the parameters follow.
func fillTemplate(template string, values map[string]string) string {
	out := template
	for {
		open := strings.Index(out, "{")
		if open < 0 {
			return out
		}
		close := strings.Index(out[open:], "}")
		if close < 0 {
			return out
		}
		name := out[open+1 : open+close]
		value, ok := values[name]
		if !ok {
			value = name
		}
		out = out[:open] + url.PathEscape(value) + out[open+close+1:]
	}
}

// valueFor decides one parameter's value and where it came from. The order is the document's own
// preference order: an explicit example beats a default, a default beats an enum's first value, and
// only when the document says nothing at all is a placeholder invented.
func valueFor(param map[string]any, r *resolver, format Format) Parameter {
	schema := map[string]any(nil)
	if raw, ok := param["schema"]; ok {
		schema, _ = raw.(map[string]any)
	}
	param = r.resolveMap(param)
	if schema != nil {
		schema = r.resolveMap(schema)
	}
	typ := typeOf(param, schema)
	fmtStr := formatOf(param, schema)
	enumVals := enumOf(param, schema)

	// OpenAPI 3: `example` on the parameter, then `examples.<first>.value`, then the schema.
	if v, ok := param["example"]; ok {
		return Parameter{Value: scalarString(v), Source: ValueExample, Type: typ, Format: fmtStr, Enum: enumVals}
	}
	if examples, ok := param["examples"].(map[string]any); ok {
		for _, name := range sortedKeys(examples) {
			entry, _ := r.resolveMap(examples[name].(map[string]any))["value"].(any)
			if entry != nil {
				return Parameter{Value: scalarString(entry), Source: ValueExample, Type: typ, Format: fmtStr, Enum: enumVals}
			}
		}
	}
	if schema != nil {
		if v, ok := schema["example"]; ok {
			return Parameter{Value: scalarString(v), Source: ValueExample, Type: typ, Format: fmtStr, Enum: enumVals}
		}
		if v, ok := schema["default"]; ok {
			return Parameter{Value: scalarString(v), Source: ValueDefault, Type: typ, Format: fmtStr, Enum: enumVals}
		}
		if enum, ok := schema["enum"].([]any); ok && len(enum) > 0 {
			return Parameter{Value: scalarString(enum[0]), Source: ValueEnum, Type: typ, Format: fmtStr, Enum: enumVals}
		}
	}
	// Swagger 2 states these on the parameter itself.
	if v, ok := param["default"]; ok {
		return Parameter{Value: scalarString(v), Source: ValueDefault, Type: typ, Format: fmtStr, Enum: enumVals}
	}
	if enum, ok := param["enum"].([]any); ok && len(enum) > 0 {
		return Parameter{Value: scalarString(enum[0]), Source: ValueEnum, Type: typ, Format: fmtStr, Enum: enumVals}
	}
	name := stringField(param, "name")
	return Parameter{Value: placeholder(name, typ, schema, r), Source: ValuePlaceholder, Type: typ, Format: fmtStr, Enum: enumVals}
}

// placeholder invents a value that reads as invented. See the package comment: a path parameter named
// `id` becomes `1` when it is typed as an integer and `id` when it is not, so captured traffic shows
// which values the API's authors chose.
func placeholder(name, typ string, schema map[string]any, r *resolver) string {
	switch strings.ToLower(typ) {
	case "integer", "number":
		return "1"
	case "boolean":
		return "true"
	case "array":
		items, _ := schema["items"].(map[string]any)
		if items != nil {
			items = r.resolveMap(items)
			return placeholder(name, stringField(items, "type"), items, r)
		}
		return "1"
	default:
		return name
	}
}

// typeOf reads a parameter's declared type from wherever the document put it: OpenAPI 3 nests it under
// `schema`, Swagger 2 states it inline.
func typeOf(param, schema map[string]any) string {
	if schema != nil {
		if t := stringField(schema, "type"); t != "" {
			return t
		}
	}
	return stringField(param, "type")
}

// formatOf reads a parameter's declared string format the same way typeOf reads its type:
// OpenAPI 3 nests it under `schema`, Swagger 2 states it inline.
func formatOf(param, schema map[string]any) string {
	if schema != nil {
		if f := stringField(schema, "format"); f != "" {
			return f
		}
	}
	return stringField(param, "format")
}

// enumOf reads a parameter's declared enum values, wherever the document put them, rendered as
// strings so a caller never has to type-switch the underlying JSON/YAML scalar. Independent of
// valueFor's own value selection: an enum still counts here even when an example or default won
// the value that actually goes on the wire, because a caller sweeping "everything outside the
// enum" needs the whole declared set, not just the one value valueFor picked.
func enumOf(param, schema map[string]any) []string {
	if schema != nil {
		if enum, ok := schema["enum"].([]any); ok && len(enum) > 0 {
			return enumStrings(enum)
		}
	}
	if enum, ok := param["enum"].([]any); ok && len(enum) > 0 {
		return enumStrings(enum)
	}
	return nil
}

func enumStrings(enum []any) []string {
	out := make([]string, 0, len(enum))
	for _, v := range enum {
		out = append(out, scalarString(v))
	}
	return out
}

// bodyFromContent picks a media type out of an OpenAPI 3 `content` map and synthesises a body for it.
// `application/json` wins when it is offered, because a JSON API that also advertises `*/*` means the
// former.
func (r *resolver) bodyFromContent(content map[string]any) ([]byte, string) {
	if content == nil {
		return nil, ""
	}
	if entry, ok := content["application/json"].(map[string]any); ok {
		return r.bodyFor(entry, "application/json")
	}
	for _, mediaType := range sortedKeys(content) {
		entry, _ := content[mediaType].(map[string]any)
		if entry == nil {
			continue
		}
		return r.bodyFor(entry, mediaType)
	}
	return nil, ""
}

// bodyFor renders a schema as a body of the given media type. Only JSON is synthesised: any other type
// is sent with no body at all and its Content-Type declared, which is the honest outcome — the
// alternative is inventing bytes for a format this package cannot render.
func (r *resolver) bodyFor(entry map[string]any, mediaType string) ([]byte, string) {
	const jsonMediaType = "application/json"
	if !strings.Contains(mediaType, "json") {
		return nil, mediaType
	}
	schema, _ := entry["schema"].(map[string]any)
	if schema == nil {
		// The media type entry may *be* the schema in a hand-written document.
		schema = entry
	}
	value, ok := r.exampleValue(schema, 0)
	if !ok {
		return nil, jsonMediaType
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, jsonMediaType
	}
	return encoded, jsonMediaType
}

// maxRefDepth bounds $ref resolution. A document whose schemas reference each other in a cycle is
// legal-ish and would otherwise recurse until the stack runs out; past this depth the value is
// reported as a placeholder instead.
const maxRefDepth = 6

// exampleValue renders a schema as a JSON value: the document's example where there is one, an object
// built from its properties where it is an object, and a typed placeholder otherwise.
func (r *resolver) exampleValue(schema map[string]any, depth int) (any, bool) {
	if schema == nil || depth > maxRefDepth {
		return nil, false
	}
	schema = r.resolveMap(schema)
	if schema == nil {
		return nil, false
	}
	if v, ok := schema["example"]; ok {
		return v, true
	}
	if v, ok := schema["default"]; ok {
		return v, true
	}
	if enum, ok := schema["enum"].([]any); ok && len(enum) > 0 {
		return enum[0], true
	}

	switch strings.ToLower(stringField(schema, "type")) {
	case "object", "":
		properties, _ := schema["properties"].(map[string]any)
		if properties == nil {
			// A schema with no type and no properties is unconstrained; `{}` is the honest body —
			// a request the API's validator will accept or reject on its own terms.
			return map[string]any{}, true
		}
		out := make(map[string]any, len(properties))
		for _, name := range sortedKeys(properties) {
			property, _ := properties[name].(map[string]any)
			if value, ok := r.exampleValue(property, depth+1); ok {
				out[name] = value
			} else {
				out[name] = placeholderValue(property)
			}
		}
		return out, true
	case "array":
		items, _ := schema["items"].(map[string]any)
		if items == nil {
			return []any{}, true
		}
		value, ok := r.exampleValue(items, depth+1)
		if !ok {
			return []any{}, true
		}
		return []any{value}, true
	case "integer", "number":
		return float64(1), true
	case "boolean":
		return true, true
	default:
		return stringPlaceholder(schema), true
	}
}

// stringPlaceholder invents a string body value, preferring a format that will parse as itself.
func stringPlaceholder(schema map[string]any) string {
	switch strings.ToLower(stringField(schema, "format")) {
	case "date-time":
		return "1970-01-01T00:00:00Z"
	case "date":
		return "1970-01-01"
	case "uuid":
		return "00000000-0000-0000-0000-000000000000"
	case "email":
		return "user@example.com"
	case "uri", "url":
		return "http://example.com/"
	case "byte":
		return "AA=="
	}
	return "string"
}

// placeholderValue is placeholder() for a body property, which has no parameter to name.
func placeholderValue(schema map[string]any) any {
	switch strings.ToLower(stringField(schema, "type")) {
	case "integer", "number":
		return float64(1)
	case "boolean":
		return true
	case "array":
		return []any{}
	case "object":
		return map[string]any{}
	default:
		return stringPlaceholder(schema)
	}
}

// resolver follows local `$ref`s. Only in-document references are resolved: a `$ref` that names another
// file or a URL would be a fetch, and a scan that fetched a document the operator did not name would
// be sending traffic they never asked for.
type resolver struct {
	root   map[string]any
	format Format
	// resolved caches by ref so a schema referenced by forty operations is walked once.
	resolved map[string]map[string]any
}

func newResolver(root map[string]any, format Format) *resolver {
	return &resolver{root: root, format: format, resolved: map[string]map[string]any{}}
}

// resolveMap follows a node's `$ref`, if it has one, and returns the node it names.
func (r *resolver) resolveMap(node map[string]any) map[string]any {
	if node == nil {
		return nil
	}
	ref, _ := node["$ref"].(string)
	if ref == "" {
		return node
	}
	if cached, ok := r.resolved[ref]; ok {
		return cached
	}
	target := r.follow(ref)
	if target != nil {
		r.resolved[ref] = target
	}
	return target
}

// follow walks a local JSON pointer such as `#/components/schemas/Pet`.
func (r *resolver) follow(ref string) map[string]any {
	if !strings.HasPrefix(ref, "#/") {
		return nil
	}
	var current any = r.root
	for _, segment := range strings.Split(strings.TrimPrefix(ref, "#/"), "/") {
		// JSON pointer escaping: ~1 is "/" and ~0 is "~" inside a segment name.
		segment = strings.ReplaceAll(strings.ReplaceAll(segment, "~1", "/"), "~0", "~")
		container, ok := current.(map[string]any)
		if !ok {
			return nil
		}
		current = container[segment]
	}
	target, _ := current.(map[string]any)
	return target
}

// refList reads a parameter list whose entries may be `$ref`s.
func refList(r *resolver, raw any) []map[string]any {
	list, _ := raw.([]any)
	out := make([]map[string]any, 0, len(list))
	for _, entry := range list {
		node, _ := entry.(map[string]any)
		if node == nil {
			continue
		}
		if target := r.resolveMap(node); target != nil {
			out = append(out, target)
		}
	}
	return out
}

func stringField(node map[string]any, key string) string {
	if node == nil {
		return ""
	}
	s, _ := node[key].(string)
	return s
}

// sortedKeys gives a map's keys in a stable order, so two scans of one document produce byte-identical
// requests. Go's map iteration order is random, and a request whose query string is reordered between
// runs looks like the API changed.
func sortedKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
