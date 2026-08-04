// A deliberately small, hand-rolled JSON path: the shapes a login flow actually needs, and an
// explicit refusal by name for everything else.
//
// # Why a subset, stated before what it does
//
// The UI's ExtractHow union offers `{json_path: string}` and the Rust crate implements it, so an
// operator selecting it in this port used to hit a flat "not implemented" wall. What it must not turn
// into is a JSONPath engine: the full grammar has recursive descent, wildcards, slices, filter
// expressions and script expressions, all of which either need a dependency this repo does not carry
// or select *many* values — and an extraction lifts exactly one. So the subset is fixed here, in one
// place, and anything outside it is refused when the rule is configured (see validate.go and
// Extraction.Recompile), naming the construct that was unsupported.
//
// Refusing at configuration time rather than at run time is the whole point. A path this package
// cannot walk, accepted and then quietly resolving to nothing, reads to an operator as "the token was
// not in the response" — a statement about the target, when the truth is a statement about this
// scanner. The wall is honest; a wall in the wrong place is not.
//
// # What is supported
//
//	token                the top-level key "token"
//	data.token           a key inside an object inside an object, to any depth
//	items[0].id          an array element by index, zero-based, then a key inside it
//	[0].id               a top-level array
//	$.data.token         an optional leading $ or $. , because that is how operators write a path
//
// A key may hold anything a JSON object key can hold except `.`, `[`, `]`, `*`, `$` and whitespace,
// which are the characters this grammar spends. A value is lifted as text: a string as itself, a
// number as the digits the server actually sent (never re-formatted through a float, so a 64-bit id
// survives), a boolean as "true"/"false".
//
// # What is refused, and what to write instead
//
//	..a          recursive descent — name the path, or use a regex extraction
//	a.*          wildcard — an extraction lifts one value, and which one a wildcard carried would
//	             depend on the order the JSON happened to be written in
//	a[*]         same
//	a[1:3]       array slice — name one index
//	a[?(@.x)]    filter expression — not this scanner's job
//	a['b.c']     bracketed key — a key containing a dot or a bracket cannot be named in this subset
//	a[-1]        negative index — count from the front
//
// # Three outcomes, never two
//
// Walking a path returns one of: a value (which may be the empty string, and that is a real answer);
// nothing, because the path does not resolve against this document; or "that is not a value", because
// the path landed on an object, an array or a null. They are kept apart for the same reason
// scanner.CoverageTracker keeps "never ran" apart from "ran and found nothing" — an empty token and a
// wrong path are different problems, and collapsing them into "" makes the operator debug the wrong
// one. Extraction.RunResult carries the distinction out; whether the *body* was JSON at all is a
// fourth answer it adds on top.
package session

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// jsonStep is one hop along a path: a key in an object, or an index into an array.
type jsonStep struct {
	// key is set for an object hop. index is set for an array hop, and isIndex says which of the two
	// this is — rather than treating an empty key as "must be an index", which would make a malformed
	// path silently become an index-0 lookup.
	key     string
	index   int
	isIndex bool
}

// jsonPath is a parsed path: the hops in order. A nil jsonPath is an unparsed one, which is the state
// validate.go refuses rather than letting run silently resolve nothing.
type jsonPath []jsonStep

// String renders the path back in the syntax it was written in, so a refusal or a walk failure can
// name the exact prefix that resolved.
func (p jsonPath) String() string {
	var b strings.Builder
	for i, s := range p {
		if s.isIndex {
			b.WriteByte('[')
			b.WriteString(strconv.Itoa(s.index))
			b.WriteByte(']')
			continue
		}
		if i > 0 {
			b.WriteByte('.')
		}
		b.WriteString(s.key)
	}
	if b.Len() == 0 {
		return "$"
	}
	return b.String()
}

// errEmptyJSONPath is the one refusal two doors share: parseJSONPath's, and
// NewJSONPathExtraction's own check for a path that is empty before it ever gets here (an empty
// JSONPath reads as "not a json path at all" to Recompile, so the constructor cannot delegate).
var errEmptyJSONPath = errors.New("the json path is empty, so there is nothing to look up")

// parseJSONPath parses one path, or says which unsupported construct stopped it.
//
// Every error names the construct rather than the offset alone: "the path is invalid at character 7"
// tells an operator nothing they can act on, and the whole reason this refusal happens at
// configuration time is so that they can act on it.
func parseJSONPath(path string) (jsonPath, error) {
	raw := strings.TrimSpace(path)
	if raw == "" {
		return nil, errEmptyJSONPath
	}
	if strings.ContainsAny(raw, " \t\r\n") {
		return nil, fmt.Errorf("the json path %q carries whitespace; this subset spells a path as key.key[0].key with no spaces", path)
	}
	if strings.Contains(raw, "..") {
		return nil, fmt.Errorf("the json path %q uses recursive descent (`..`), which this subset does not "+
			"support: name the keys along the way, or extract with a regex", path)
	}
	if strings.Contains(raw, "*") {
		return nil, fmt.Errorf("the json path %q uses a wildcard (`*`), which this subset does not support: "+
			"an extraction lifts exactly one value, and which value a wildcard carried would depend on the "+
			"order the JSON happened to be written in", path)
	}
	// A leading root is accepted and dropped, because that is how a path is conventionally written and
	// refusing it would be a refusal about spelling rather than about capability.
	rest := raw
	if rest == "$" {
		return nil, fmt.Errorf("the json path %q names the whole document, not a value inside it; use `whole` to take the body as it stands", path)
	}
	if strings.HasPrefix(rest, "$.") {
		rest = rest[2:]
	} else if strings.HasPrefix(rest, "$[") {
		rest = rest[1:]
	} else if strings.HasPrefix(rest, "$") {
		return nil, fmt.Errorf("the json path %q starts with `$` followed by %q; write `$.key`, `$[0]` or just `key`",
			path, rest[1:2])
	}
	if strings.Contains(rest, "$") {
		return nil, fmt.Errorf("the json path %q carries `$` past its start, which this subset has no meaning for", path)
	}

	var out jsonPath
	for rest != "" {
		switch {
		case rest[0] == '[':
			end := strings.IndexByte(rest, ']')
			if end < 0 {
				return nil, fmt.Errorf("the json path %q opens `[` and never closes it", path)
			}
			inner := rest[1:end]
			step, err := parseIndex(path, inner)
			if err != nil {
				return nil, err
			}
			out = append(out, step)
			rest = rest[end+1:]
			// A key after an index has to be introduced by a dot: `[0]id` is not a spelling this
			// grammar has, and guessing that it meant `[0].id` would be inventing syntax.
			if rest != "" && rest[0] != '.' && rest[0] != '[' {
				return nil, fmt.Errorf("the json path %q continues with %q straight after `]`; separate a key from an index with a dot",
					path, rest[:1])
			}
			if rest != "" && rest[0] == '.' {
				rest = rest[1:]
				if rest == "" {
					return nil, fmt.Errorf("the json path %q ends with a dot, so it names no final key", path)
				}
			}
		case rest[0] == '.':
			return nil, fmt.Errorf("the json path %q has an empty key (a dot with no name before it)", path)
		default:
			cut := strings.IndexAny(rest, ".[")
			name := rest
			if cut >= 0 {
				name = rest[:cut]
			}
			if name == "" {
				return nil, fmt.Errorf("the json path %q has an empty key", path)
			}
			if strings.ContainsAny(name, "]'\"") {
				return nil, fmt.Errorf("the json path %q uses a bracketed or quoted key, which this subset does "+
					"not support: a key containing a dot, a bracket or a quote cannot be named here — extract it with a regex", path)
			}
			out = append(out, jsonStep{key: name})
			if cut < 0 {
				rest = ""
				break
			}
			rest = rest[cut:]
			if rest[0] == '.' {
				rest = rest[1:]
				if rest == "" {
					return nil, fmt.Errorf("the json path %q ends with a dot, so it names no final key", path)
				}
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("the json path %q names no key or index", path)
	}
	return out, nil
}

// parseIndex reads what was between one pair of brackets, refusing every JSONPath bracket form this
// subset does not carry by the name that form goes by.
func parseIndex(path, inner string) (jsonStep, error) {
	switch {
	case inner == "":
		return jsonStep{}, fmt.Errorf("the json path %q has empty brackets; name an index, as in items[0]", path)
	case strings.HasPrefix(inner, "?"):
		return jsonStep{}, fmt.Errorf("the json path %q uses a filter expression (`[?...]`), which this subset does not support", path)
	case strings.Contains(inner, ":"):
		return jsonStep{}, fmt.Errorf("the json path %q uses an array slice (`[%s]`), which this subset does not "+
			"support: an extraction lifts one value, so name one index", path, inner)
	case strings.HasPrefix(inner, "'") || strings.HasPrefix(inner, `"`):
		return jsonStep{}, fmt.Errorf("the json path %q uses a quoted key inside brackets, which this subset does "+
			"not support: write it as a dot path, or extract it with a regex", path)
	case strings.HasPrefix(inner, "-"):
		return jsonStep{}, fmt.Errorf("the json path %q uses a negative index (`[%s]`), which this subset does not "+
			"support: count from the front", path, inner)
	}
	n, err := strconv.Atoi(inner)
	if err != nil {
		return jsonStep{}, fmt.Errorf("the json path %q has %q inside brackets, which is not an index", path, inner)
	}
	return jsonStep{index: n, isIndex: true}, nil
}

// jsonWalk is what walking a path against one document produced.
type jsonWalk int

const (
	// jsonWalkFound: the path resolved to a value, which may legitimately be the empty string.
	jsonWalkFound jsonWalk = iota
	// jsonWalkMissing: the path does not resolve against this document — a key that is not there, an
	// index past the end, or a hop whose container is the wrong kind.
	jsonWalkMissing
	// jsonWalkNull: the path resolved, and the value is JSON null. Kept apart from missing because
	// "the server sent null for this" is an answer about the target, and "that key is not there" is an
	// answer about the path.
	jsonWalkNull
	// jsonWalkNotAValue: the path resolved to an object or an array, which is not something a
	// {{placeholder}} can carry.
	jsonWalkNotAValue
)

// walkJSON decodes src and walks p through it.
//
// Numbers are decoded with UseNumber so a value is lifted as the digits the server sent. Through
// float64 a 64-bit identifier or a long numeric token loses its low bits, and a session id that is
// almost right is worse than one that is missing: the request goes out and fails somewhere else.
//
// ok is false when src is not JSON at all, which is the fourth outcome and the one that must never
// look like an absent value.
func walkJSON(src []byte, p jsonPath) (value string, outcome jsonWalk, detail string, ok bool) {
	dec := json.NewDecoder(bytes.NewReader(src))
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil {
		return "", jsonWalkMissing, err.Error(), false
	}
	cur := doc
	for i, step := range p {
		// The prefix that did resolve, so a failure says where the walk stopped rather than only that it
		// did. jsonPath.String renders an empty prefix as "$", which is what the whole document is.
		reached := p[:i].String()
		if step.isIndex {
			arr, isArr := cur.([]any)
			if !isArr {
				return "", jsonWalkMissing, fmt.Sprintf("%s is %s, so [%d] has nothing to index",
					reached, jsonKindOf(cur), step.index), true
			}
			if step.index >= len(arr) {
				return "", jsonWalkMissing, fmt.Sprintf("%s holds %d element(s), so there is no [%d]",
					reached, len(arr), step.index), true
			}
			cur = arr[step.index]
			continue
		}
		obj, isObj := cur.(map[string]any)
		if !isObj {
			return "", jsonWalkMissing, fmt.Sprintf("%s is %s, so it has no key %q",
				reached, jsonKindOf(cur), step.key), true
		}
		next, present := obj[step.key]
		if !present {
			return "", jsonWalkMissing, fmt.Sprintf("%s has no key %q", reached, step.key), true
		}
		cur = next
	}
	switch v := cur.(type) {
	case string:
		return v, jsonWalkFound, "", true
	case json.Number:
		return v.String(), jsonWalkFound, "", true
	case bool:
		return strconv.FormatBool(v), jsonWalkFound, "", true
	case nil:
		return "", jsonWalkNull, p.String() + " is null", true
	default:
		return "", jsonWalkNotAValue, fmt.Sprintf("%s is %s, which is not a single value a {{placeholder}} can carry",
			p.String(), jsonKindOf(cur)), true
	}
}

// jsonKindOf names what a decoded value is, for a failure detail an operator can read against the
// response they are looking at.
func jsonKindOf(v any) string {
	switch v.(type) {
	case map[string]any:
		return "an object"
	case []any:
		return "an array"
	case string:
		return "a string"
	case json.Number:
		return "a number"
	case bool:
		return "a boolean"
	case nil:
		return "null"
	}
	return "an unknown kind of value"
}
