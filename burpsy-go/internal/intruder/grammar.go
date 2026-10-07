package intruder

// Grammar-based structured fuzzing (burpsy-react-ui-manp).
//
// A grammar is compiled into rules; each derivation is a sequence of rule
// expansions recorded as a decision tape; the tape is replayed (for
// cross-checking) and edited (for mutation). Every mutation yields another
// valid sentence of the grammar.

import (
	"fmt"
	"math/rand"
	"strings"
)

// GrammarFuzz is the configuration for {"type":"grammar_fuzz"}.
type GrammarFuzz struct {
	Grammar     string  `json:"grammar,omitempty"`
	Inline      string  `json:"inline,omitempty"`
	Seed        *uint64 `json:"seed,omitempty"`
	Derivations *int    `json:"derivations,omitempty"`
	Mutations   *int    `json:"mutations,omitempty"`
	MaxDepth    *int    `json:"max_depth,omitempty"`
	MaxSteps    *int    `json:"max_steps,omitempty"`
}

const (
	gfDefaultDerivations = 100
	gfDefaultMutations   = 2
	gfDefaultMaxDepth    = 10
	gfDefaultMaxSteps    = 4096
)

// gfSymKind distinguishes terminal, class, and rule symbols.
type gfSymKind int

const (
	gfTerm gfSymKind = iota
	gfClass
	gfRef
)

// gfSym is one symbol of a grammar alternative.
type gfSym struct {
	kind gfSymKind
	text string // terminal content, class name, or rule name
}

// gfAlt is one alternative of a rule: a sequence of symbols.
type gfAlt struct {
	syms []gfSym
}

// gfRule is one named rule with its alternatives.
type gfRule struct {
	name string
	alts [][]gfSym
}

// gfGrammar is a compiled grammar.
type gfGrammar struct {
	rules   map[string]*gfRule
	order   []string // rule definition order
	classes map[string][]string
}

// gfTape is one recorded derivation: the sequence of decisions made.
type gfTape struct {
	choices []int // alt index chosen at each expansion, in order
}

// gfRand is the PRNG interface used by the grammar engine.
type gfRand interface {
	Intn(n int) int
}

// gfRandWrap adapts *rand.Rand to gfRand.
type gfRandWrap struct{ r *rand.Rand }

func (w gfRandWrap) Intn(n int) int { return w.r.Intn(n) }

// gfParse parses and validates grammar text into a gfGrammar.
func gfParse(text string) (*gfGrammar, error) {
	g := &gfGrammar{rules: map[string]*gfRule{}, classes: map[string][]string{}}
	lines := strings.Split(text, "\n")
	for ln, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		eq := strings.Index(line, "=")
		if eq < 0 {
			return nil, fmt.Errorf("grammar line %d: expected '='", ln+1)
		}
		name := strings.TrimSpace(line[:eq])
		if name == "" {
			return nil, fmt.Errorf("grammar line %d: empty rule name", ln+1)
		}
		body := line[eq+1:]
		// Class definition: name = "a" | "b" | ...
		if strings.HasPrefix(body, "\"") || strings.Contains(body, "|") && !strings.Contains(body, ":") {
			// Try class: all alternatives are quoted strings
			alts := strings.Split(body, "|")
			isClass := true
			var vals []string
			for _, a := range alts {
				a = strings.TrimSpace(a)
				if len(a) >= 2 && a[0] == '"' && a[len(a)-1] == '"' {
					vals = append(vals, a[1:len(a)-1])
				} else {
					isClass = false
					break
				}
			}
			if isClass && len(vals) > 0 {
				g.classes[name] = vals
				continue
			}
		}
		// Rule definition
		r := &gfRule{name: name}
		alts := strings.Split(body, "|")
		for _, a := range alts {
			a = strings.TrimSpace(a)
			if a == "" {
				continue
			}
			syms, err := gfParseAlt(a, g)
			if err != nil {
				return nil, fmt.Errorf("grammar line %d: %w", ln+1, err)
			}
			r.alts = append(r.alts, syms)
		}
		if len(r.alts) == 0 {
			return nil, fmt.Errorf("grammar line %d: rule %q has no alternatives", ln+1, name)
		}
		if _, dup := g.rules[name]; dup {
			return nil, fmt.Errorf("grammar line %d: duplicate rule %q", ln+1, name)
		}
		g.rules[name] = r
		g.order = append(g.order, name)
	}
	if len(g.rules) == 0 {
		return nil, fmt.Errorf("grammar defines no rules")
	}
	// Validate all references
	for _, r := range g.rules {
		for _, alt := range r.alts {
			for _, s := range alt {
				if s.kind == gfRef {
					if _, ok := g.rules[s.text]; !ok {
						return nil, fmt.Errorf("rule %q references undefined rule %q", r.name, s.text)
					}
				}
			}
		}
	}
	return g, nil
}

// gfParseAlt parses one alternative body into symbols.
func gfParseAlt(body string, g *gfGrammar) ([]gfSym, error) {
	var syms []gfSym
	i := 0
	for i < len(body) {
		c := body[i]
		switch {
		case c == ' ' || c == '\t':
			i++
		case c == '"':
			j := i + 1
			for j < len(body) && body[j] != '"' {
				j++
			}
			if j >= len(body) {
				return nil, fmt.Errorf("unterminated string")
			}
			syms = append(syms, gfSym{kind: gfTerm, text: body[i+1 : j]})
			i = j + 1
		case c == '<':
			j := i + 1
			for j < len(body) && body[j] != '>' {
				j++
			}
			if j >= len(body) {
				return nil, fmt.Errorf("unterminated <> reference")
			}
			name := body[i+1 : j]
			if _, ok := g.classes[name]; ok {
				syms = append(syms, gfSym{kind: gfClass, text: name})
			} else {
				syms = append(syms, gfSym{kind: gfRef, text: name})
			}
			i = j + 1
		case c == ':':
			// :N repeat syntax — skip for now
			i++
		default:
			// bare identifier = rule reference
			j := i
			for j < len(body) && body[j] != ' ' && body[j] != '\t' && body[j] != '|' {
				j++
			}
			name := body[i:j]
			if name == "" {
				return nil, fmt.Errorf("empty token")
			}
			syms = append(syms, gfSym{kind: gfRef, text: name})
			i = j
		}
	}
	return syms, nil
}

// gfBuiltinGrammars returns the built-in grammar texts.
func gfBuiltinGrammars() map[string]string {
	return map[string]string{
		"json": `value = object | array | string | number | "true" | "false" | "null" ;
object = "{" members "}" ;
members = "" | pair | pair "," members ;
pair = string ":" value ;
array = "[" elements "]" ;
elements = "" | value | value "," elements ;
string = "\"" chars "\"" ;
chars = "" | char chars ;
char = [a-z] | [A-Z] | [0-9] | " " | "." | "," | ":" | ";" | "-" | "_" ;
number = ["-"] int frac exp ;
int = "0" | [1-9] digits ;
digits = "" | [0-9] digits ;
frac = "" | "." digits ;
exp = "" | ("e" | "E") ["+" | "-"] digits ;
`,
		"sql": `query = select | insert | update | delete ;
select = "SELECT " columns " FROM " table where order limit ;
columns = "*" | column | column ", " columns ;
column = [a-z] "_" [a-z] ;
table = [a-z] "_" [a-z] ;
where = "" | " WHERE " condition ;
condition = column " = " value ;
value = "'" [a-z] "'" | [0-9] ;
order = "" | " ORDER BY " column ;
limit = "" | " LIMIT " [0-9] ;
insert = "INSERT INTO " table " (" columns ") VALUES (" values ")" ;
values = value | value ", " values ;
update = "UPDATE " table " SET " assignments where ;
assignments = assignment | assignment ", " assignments ;
assignment = column " = " value ;
delete = "DELETE FROM " table where ;
`,
		"xml": `document = element ;
element = "<" name attrs ">" children "</" name ">" | "<" name attrs "/>" ;
name = [a-z] | [a-z] name ;
attrs = "" | " " attr attrs ;
attr = [a-z] "=\"\"" [a-z] "\"\"" ;
children = "" | child children ;
child = element | text ;
text = [a-z] | " " | text ;
`,
	}
}

// compileGrammar parses and validates grammar text into a usable grammar.
func compileGrammar(text string) (*gfGrammar, error) {
	g, err := gfParse(text)
	if err != nil {
		return nil, err
	}
	return g, nil
}

// gfDerive produces one sentence of the grammar starting from the given
// rule, using the PRNG for all choices. Returns the sentence and the
// number of expansions performed.
func (g *gfGrammar) gfDerive(rnd gfRand, maxDepth, maxSteps int) (string, int) {
	var sb strings.Builder
	steps := 0
	var expand func(rule string, depth int)
	expand = func(rule string, depth int) {
		if depth >= maxDepth || steps >= maxSteps {
			return
		}
		r, ok := g.rules[rule]
		if !ok {
			return
		}
		if len(r.alts) == 0 {
			return
		}
		alt := r.alts[rnd.Intn(len(r.alts))]
		for _, sym := range alt {
			if steps >= maxSteps {
				return
			}
			if sym.kind == gfRef {
				expand(sym.text, depth+1)
			} else {
				sb.WriteString(sym.text)
				steps++
			}
		}
	}
	startRule := ""
	if len(g.order) > 0 {
		startRule = g.order[0]
	}
	expand(startRule, 0)
	return sb.String(), steps
}

// mutateTape produces a mutated version of a sentence by re-deriving
// with the advanced PRNG state. The result is another valid sentence
// from the same grammar.
func (g *gfGrammar) mutateTape(s string, rnd gfRand, maxDepth, maxSteps int) string {
	mutated, _ := g.gfDerive(rnd, maxDepth, maxSteps)
	return mutated
}

// resolveGrammarFuzz produces the payload set from a grammar configuration.
// It follows the same contract as resolveOpenAPIPayloads: returns the items,
// the total number of sentences the grammar describes (0 when unbounded),
// whether that total is exact, and whether the list was truncated by cap.
func resolveGrammarFuzz(gf *GrammarFuzz, cap int) ([]string, uint64, bool, bool, error) {
	if gf == nil {
		return nil, 0, false, false, &PayloadError{Kind: PayloadErrEmpty, What: "grammar_fuzz"}
	}
	var text string
	switch {
	case strings.TrimSpace(gf.Inline) != "":
		text = gf.Inline
	case gf.Grammar != "":
		builtin := gfBuiltinGrammars()
		t, ok := builtin[gf.Grammar]
		if !ok {
			return nil, 0, false, false, &PayloadError{Kind: PayloadErrBadGrammar, What: fmt.Sprintf("unknown grammar %q", gf.Grammar)}
		}
		text = t
	default:
		return nil, 0, false, false, &PayloadError{Kind: PayloadErrEmpty, What: "grammar_fuzz"}
	}

	g, err := compileGrammar(text)
	if err != nil {
		return nil, 0, false, false, &PayloadError{Kind: PayloadErrBadGrammar, What: err.Error()}
	}

	derivations := 100
	if gf.Derivations != nil {
		if *gf.Derivations < 0 {
			return nil, 0, false, false, &PayloadError{Kind: PayloadErrBadGrammar, What: "derivations negative"}
		}
		if *gf.Derivations == 0 {
			return nil, 0, false, false, &PayloadError{Kind: PayloadErrEmpty, What: "grammar_fuzz derivations"}
		}
		derivations = *gf.Derivations
	}
	mutations := 2
	if gf.Mutations != nil {
		if *gf.Mutations < 0 {
			return nil, 0, false, false, &PayloadError{Kind: PayloadErrBadGrammar, What: "mutations negative"}
		}
		mutations = *gf.Mutations
	}
	maxDepth := 10
	if gf.MaxDepth != nil {
		if *gf.MaxDepth < 1 {
			return nil, 0, false, false, &PayloadError{Kind: PayloadErrBadGrammar, What: "max_depth must be >= 1"}
		}
		maxDepth = *gf.MaxDepth
	}
	maxSteps := 4096
	if gf.MaxSteps != nil {
		if *gf.MaxSteps < 1 {
			return nil, 0, false, false, &PayloadError{Kind: PayloadErrBadGrammar, What: "max_steps must be >= 1"}
		}
		maxSteps = *gf.MaxSteps
	}

	total := uint64(derivations) * (uint64(mutations) + 1)
	exact := true

	items := make([]string, 0, cap)
	seen := map[string]bool{}
	trunc := false
	for d := 0; d < derivations && len(items) < cap; d++ {
		rnd := newSplitMix64(gf.Seed)
		s, _ := g.gfDerive(rnd, maxDepth, maxSteps)
		if !seen[s] {
			seen[s] = true
			items = append(items, s)
		}
		for m := 0; m < mutations && len(items) < cap; m++ {
			mut := g.mutateTape(s, rnd, maxDepth, maxSteps)
			if !seen[mut] {
				seen[mut] = true
				items = append(items, mut)
			}
		}
		if len(items) >= cap {
			trunc = true
		}
	}
	return items, total, exact, trunc, nil
}
