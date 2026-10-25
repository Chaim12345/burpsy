package web

// Typed request schemas for every route-verb that takes a body (burpsy-react-ui-3zw0).
//
// # The single source, and the checker that keeps it single
//
// Before this file, the MCP descriptor for every route said its body was "JSON … See /api/apidoc" —
// a route that does not exist — and a model guessed each wire shape. Burp binds each agent tool to a
// typed args record (toolargs/*.java, @Description on every field). The burpsy equivalent cannot be a
// second, hand-written schema per route: that is a second definition of the payload that nothing
// checks, which is exactly the objection the old comment raised.
//
// So the schema is REFLECTED from the handler's own request type, and the binding between the two is
// proven rather than asserted:
//
//   - routeSchemas (below) names, per "VERB /pattern", the Go type the handler decodes into.
//   - Every handler decodes through requestJSON, which in an in-process probe (a context value no wire
//     request can carry) records the type it was handed and stops before the handler does anything.
//     TestEveryBodyTakingRouteDecodesItsDeclaredType drives each route through the real mux with a
//     probe and asserts the handler decoded into exactly the declared type, that an example generated
//     from the published schema decodes, and that an unknown field is refused. A declaration that
//     drifts from the handler fails that test; there is no way for the two to disagree silently.
//   - A request from an agent transport (AgentHeader, which burpsy-mcp sets on every call) is decoded
//     strictly — an unknown field is HTTP 400 naming the field — so a model that guesses a field name
//     is told, instead of having the field silently dropped and the request run without it.
//
// # Why strictness is agent-only
//
// The console's own UI round-trips several GET shapes back into PUTs, and those shapes carry derived
// fields the PUT type does not have. Refusing unknown fields for every caller would break the UI in
// ways no Go test sees. The agent path is where a guessed name is the realistic failure, so that is
// where the contract is enforced; the UI keeps the lenient decoding it was written against.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"sort"
	"strings"
	"time"
)

// AgentHeader marks a request as made by an agent transport. Its presence opts the request into
// strict body decoding (an unknown field is refused with 400). burpsy-mcp sets it on every call.
//
// It is a marker, not an authentication: anything that can reach the console can send it, and the
// only thing it buys a caller is a stricter refusal.
const AgentHeader = "X-Burpsy-Agent"

func isAgentRequest(r *http.Request) bool { return strings.TrimSpace(r.Header.Get(AgentHeader)) != "" }

// BodyErrorHeader carries the JSON decoder's own error on a refused body, so a caller learns WHICH
// field was wrong even from a handler whose message predates this (most say "Invalid request body").
// The MCP transport prints it into the tool result.
const BodyErrorHeader = "X-Burpsy-Body-Error"

// decodeProbeKey carries a *decodeProbe in a request's context. Unexported, so only this package's
// tests can set it: a wire request cannot reach the probe branch.
type decodeProbeKey struct{}

// decodeProbe records what a handler asked its body decoder to decode into.
type decodeProbe struct {
	called bool
	typ    reflect.Type
	err    error
}

// errDecodeProbed is what a probed Decode returns: not io.EOF, so every handler — including the ones
// that treat an empty body as optional — takes its own refusal branch and stops before it acts.
var errDecodeProbed = errors.New("decode probe: stopped before the handler acted")

// bodyDecoder decodes a request's JSON body. It is what every handler uses in place of
// json.NewDecoder(r.Body), and it adds exactly three things: strict decoding for an agent caller, the
// decoder's own error in BodyErrorHeader, and the in-process probe the schema sweep drives.
type bodyDecoder struct {
	w     http.ResponseWriter
	dec   *json.Decoder
	probe *decodeProbe
}

// requestJSON returns the body decoder for r. body is the reader to decode (a size-limited wrapper
// of r.Body, say); nil means r.Body itself.
func requestJSON(w http.ResponseWriter, r *http.Request, body io.Reader) *bodyDecoder {
	if body == nil {
		body = r.Body
	}
	if body == nil {
		body = http.NoBody
	}
	d := &bodyDecoder{w: w, dec: json.NewDecoder(body)}
	d.probe, _ = r.Context().Value(decodeProbeKey{}).(*decodeProbe)
	if d.probe != nil || isAgentRequest(r) {
		d.dec.DisallowUnknownFields()
	}
	return d
}

// Decode decodes the next JSON value into v.
func (d *bodyDecoder) Decode(v any) error {
	err := d.dec.Decode(v)
	if d.probe != nil {
		d.probe.called = true
		d.probe.typ = reflect.TypeOf(v)
		d.probe.err = err
		return errDecodeProbed
	}
	if err != nil && !errors.Is(err, io.EOF) && d.w != nil {
		d.w.Header().Set(BodyErrorHeader, strings.Map(func(r rune) rune {
			if r < 0x20 || r == 0x7f {
				return ' '
			}
			return r
		}, err.Error()))
	}
	return err
}

// withDecodeProbe returns r carrying a fresh probe, for this package's tests.
func withDecodeProbe(r *http.Request) (*http.Request, *decodeProbe) {
	p := &decodeProbe{}
	return r.WithContext(context.WithValue(r.Context(), decodeProbeKey{}, p)), p
}

// ---- the declarations ---------------------------------------------------------------------------

// queryParam is one query-string parameter a route reads.
type queryParam struct {
	name string
	// kind is the JSON Schema type the value parses as: "string", "integer" or "boolean". The wire
	// value is always a string; the kind says what it must spell.
	kind string
	desc string
	enum []string
}

// opSchema is what one route-verb accepts.
type opSchema struct {
	// body is the handler's own request type. Nil for an op that takes no JSON body.
	body reflect.Type
	// optional: the body may be omitted (the handler treats it as the zero value).
	optional bool
	// variants is for a subtree op whose body depends on the action in its path — "POST
	// /api/session/rules/{id}/move" and "…/{id}/run" are one route-verb with two bodies. Keyed by
	// the action sub-path the manifest's subPath/actionPaths use ("1/move"); body is unused then.
	variants map[string]reflect.Type
	// raw describes a body that is not a JSON object the probe can check — an uploaded file, a HAR
	// document whose members are the producer's, not ours. The op is exempt from the decode probe, and
	// the published schema says what to send.
	raw string
	// schema builds the published body schema by hand, for a handler that decodes a key→value map and
	// checks each key against a table of its own (scanner configuration keys, network setting
	// sections, proxy option keys). It is built FROM that table, so it is still the handler's own
	// vocabulary; keysCheckedBy names the table and says where an unknown key is refused, because the
	// probe cannot see that refusal — the map decode accepts any key, and the handler refuses it after.
	schema        func() map[string]any
	keysCheckedBy string
	// query lists the query parameters the handler reads.
	query []queryParam
	// response is the type the handler's success path encodes (burpsy-react-ui-pg5a), declared from
	// a code read of that path — CONFIRMED in the SOURCE-OF-TRUTH sense, and marked in the published
	// document as declared. Nil means the shape is not verified, and the document says so rather
	// than publishing a guess.
	response reflect.Type
}

func typeOf[T any]() reflect.Type { return reflect.TypeFor[T]() }

// sortedKeys is every key of a string-keyed map in order — the deterministic iteration the schema
// table, the OpenAPI builder, and their tests all need.
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// noBody is an op whose whole request is its path and query.
var noBody = opSchema{}

// ---- the schema generator -----------------------------------------------------------------------

// schemaOverrides is the schema for a type whose JSON form is not its Go structure — a custom
// (Un)MarshalJSON. Reflecting such a type would publish the wrong shape, so the test refuses any
// custom-decoded type that is not listed here.
var schemaOverrides = map[reflect.Type]map[string]any{
	typeOf[time.Time]():       {"type": "string", "format": "date-time"},
	typeOf[json.RawMessage](): {"description": "any JSON value"},
	typeOf[time.Duration]():   {"type": "integer", "description": "nanoseconds"},
}

var (
	jsonUnmarshalerType = reflect.TypeFor[json.Unmarshaler]()
	textUnmarshalerType = reflect.TypeFor[interface{ UnmarshalText([]byte) error }]()
)

// schemaGen reflects JSON Schema from Go types. It records types it could not describe honestly so
// the test can name them instead of publishing a guess.
type schemaGen struct {
	visiting   map[reflect.Type]bool
	unresolved []string
}

// jsonSchemaOf is the published schema for a request type.
func jsonSchemaOf(t reflect.Type) (map[string]any, []string) {
	g := &schemaGen{visiting: map[reflect.Type]bool{}}
	return g.of(t), g.unresolved
}

func (g *schemaGen) of(t reflect.Type) map[string]any {
	if s, ok := schemaOverrides[t]; ok {
		return cloneSchema(s)
	}
	if t.Kind() == reflect.Pointer {
		return g.of(t.Elem())
	}
	if s, ok := schemaOverrides[reflect.PointerTo(t)]; ok {
		return cloneSchema(s)
	}
	if t.Implements(jsonUnmarshalerType) || reflect.PointerTo(t).Implements(jsonUnmarshalerType) ||
		t.Implements(textUnmarshalerType) || reflect.PointerTo(t).Implements(textUnmarshalerType) {
		g.unresolved = append(g.unresolved, t.String()+" decodes itself (UnmarshalJSON/UnmarshalText) and has no schema override")
		return map[string]any{"description": "custom encoding (" + t.String() + ")"}
	}
	switch t.Kind() {
	case reflect.Bool:
		return map[string]any{"type": "boolean"}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return map[string]any{"type": "integer"}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return map[string]any{"type": "integer", "minimum": 0}
	case reflect.Float32, reflect.Float64:
		return map[string]any{"type": "number"}
	case reflect.String:
		return map[string]any{"type": "string"}
	case reflect.Interface:
		return map[string]any{"description": "any JSON value"}
	case reflect.Slice:
		if t.Elem().Kind() == reflect.Uint8 {
			return map[string]any{"type": "string", "contentEncoding": "base64"}
		}
		return map[string]any{"type": "array", "items": g.of(t.Elem())}
	case reflect.Array:
		return map[string]any{"type": "array", "items": g.of(t.Elem()), "minItems": t.Len(), "maxItems": t.Len()}
	case reflect.Map:
		return map[string]any{"type": "object", "additionalProperties": g.of(t.Elem())}
	case reflect.Struct:
		if g.visiting[t] {
			return map[string]any{"type": "object", "description": "recursive " + t.Name()}
		}
		g.visiting[t] = true
		defer delete(g.visiting, t)
		props := map[string]any{}
		required := []string{}
		g.fields(t, props, &required)
		s := map[string]any{"type": "object", "properties": props, "additionalProperties": false}
		if len(required) > 0 {
			sort.Strings(required)
			s["required"] = required
		}
		return s
	default:
		g.unresolved = append(g.unresolved, fmt.Sprintf("%s has kind %s, which has no JSON form", t, t.Kind()))
		return map[string]any{}
	}
}

// fields adds t's JSON-visible fields to props, flattening embedded structs the way encoding/json
// does.
func (g *schemaGen) fields(t reflect.Type, props map[string]any, required *[]string) {
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		tag := f.Tag.Get("json")
		if tag == "-" {
			continue
		}
		name, opts, _ := strings.Cut(tag, ",")
		if f.Anonymous && name == "" {
			ft := f.Type
			if ft.Kind() == reflect.Pointer {
				ft = ft.Elem()
			}
			if ft.Kind() == reflect.Struct {
				g.fields(ft, props, required)
				continue
			}
		}
		if !f.IsExported() {
			continue
		}
		if name == "" {
			name = f.Name
		}
		s := g.of(f.Type)
		if strings.Contains(","+opts+",", ",string,") {
			s = map[string]any{"type": "string", "description": "a " + fmt.Sprint(s["type"]) + " spelled as a string"}
		}
		if d := f.Tag.Get("desc"); d != "" {
			if prev, ok := s["description"].(string); ok && prev != "" {
				d = d + " (" + prev + ")"
			}
			s["description"] = d
		}
		if e := f.Tag.Get("enum"); e != "" {
			s["enum"] = strings.Split(e, "|")
		}
		if f.Tag.Get("required") == "true" {
			*required = append(*required, name)
		}
		props[name] = s
	}
}

func cloneSchema(s map[string]any) map[string]any {
	out := make(map[string]any, len(s))
	for k, v := range s {
		out[k] = v
	}
	return out
}

// querySchemaOf is the published schema for an op's query parameters.
func querySchemaOf(params []queryParam) map[string]any {
	props := map[string]any{}
	for _, p := range params {
		s := map[string]any{"type": "string"}
		desc := p.desc
		switch p.kind {
		case "integer":
			s["pattern"] = "^-?[0-9]+$"
			desc = strings.TrimSpace(desc + " (an integer)")
		case "boolean":
			s["enum"] = []string{"true", "false", "1", "0"}
		}
		if len(p.enum) > 0 {
			s["enum"] = p.enum
		}
		if desc != "" {
			s["description"] = desc
		}
		props[p.name] = s
	}
	return map[string]any{"type": "object", "properties": props, "additionalProperties": map[string]any{"type": "string"}}
}

// ---- the exported view for the MCP transport ----------------------------------------------------

// MCPOpSchema is one route-verb's published input shape.
type MCPOpSchema struct {
	// Body is the JSON Schema of the request body, reflected from the handler's own type. Nil when
	// the op takes no JSON body.
	Body map[string]any
	// BodyRequired reports that a body must be sent (it is not optional for the handler).
	BodyRequired bool
	// Query is the JSON Schema of the query parameters the handler reads; nil when it reads none.
	Query map[string]any
	// Note describes a non-JSON body, when there is one.
	Note string
}

// MCPSchemaFor answers the published input shape of one route-verb, and false when the manifest has
// no declaration for it.
func MCPSchemaFor(method, pattern string) (MCPOpSchema, bool) {
	spec, ok := routeSchemas[strings.ToUpper(method)+" "+pattern]
	if !ok {
		return MCPOpSchema{}, false
	}
	out := MCPOpSchema{Note: spec.raw}
	switch {
	case len(spec.variants) > 0:
		keys := make([]string, 0, len(spec.variants))
		for k := range spec.variants {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		branches := make([]any, 0, len(keys))
		for _, k := range keys {
			if spec.variants[k] == nil {
				continue // an action that takes no body
			}
			s, _ := jsonSchemaOf(spec.variants[k])
			s["title"] = "body for " + pattern + k
			branches = append(branches, s)
		}
		out.Body = map[string]any{"anyOf": branches, "description": "the body depends on the action in the path; each branch is titled with the path it belongs to"}
		out.BodyRequired = !spec.optional
	case spec.schema != nil:
		out.Body = spec.schema()
		out.BodyRequired = !spec.optional
	case spec.body != nil:
		out.Body, _ = jsonSchemaOf(spec.body)
		out.BodyRequired = !spec.optional
	case spec.raw != "":
		out.Body = map[string]any{"description": spec.raw}
		out.BodyRequired = !spec.optional
	}
	if len(spec.query) > 0 {
		out.Query = querySchemaOf(spec.query)
	}
	return out, true
}

// MCPAgentHeaderName is AgentHeader, exported under the transport's naming convention.
const MCPAgentHeaderName = AgentHeader
