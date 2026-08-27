package web

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/query"
)

// The Discover page's query examples, checked against the shipped parser.
//
// # Why this file exists, and what it says about documented guarantees
//
// `ui/src/lib/reference.ts` opens with a header stating that
//
//	Every QUERY_EXAMPLES entry is fed to internal/query.Parse, and every QUERY_REFUSALS entry is
//	required to fail it, by internal/web/reference_examples_test.go. A grammar this page documents
//	and the parser rejects is a test failure, not a support ticket.
//
// That file did not exist. The guarantee had been written down and never built, so the page could
// document a query the parser rejects and nothing would notice — which is the precise failure the
// paragraph promises is impossible. It was found by mutation-testing an example into an invalid one
// (`length > 1tb`) and watching the suite stay green.
//
// So this is that test, written to make the comment true rather than to soften it. It matters more
// than an ordinary documentation check because this page is where an operator goes to learn what the
// filter box accepts: an example that does not parse teaches them a language the tool does not have,
// and they will conclude the filter is broken rather than that the docs are.
//
// # Why it reads the TypeScript rather than a generated artefact
//
// The alternative is exporting the arrays into JSON at build time, which puts a build step between
// the claim and the check and gives the check something to be stale against. The arrays are declared
// one entry per line for exactly this reason, and the extractor below is deliberately strict: if it
// finds fewer entries than the floor, it fails rather than passing on an empty set — the way this
// test would otherwise rot into decoration the moment the file is reformatted.

// queryEntry matches `{ query: "…", …` and `{ query: '…', …` — one entry per line, which is what the
// arrays' own doc comment requires of contributors.
var queryEntry = regexp.MustCompile(`\{\s*query:\s*(?:"((?:[^"\\]|\\.)*)"|'((?:[^'\\]|\\.)*)')`)

const referencePath = "ui/src/lib/reference.ts"

// extractQueries pulls the `query:` values out of one exported array literal.
func extractQueries(t *testing.T, src, arrayName string) []string {
	t.Helper()
	start := strings.Index(src, "export const "+arrayName)
	if start < 0 {
		t.Fatalf("%s does not declare %s — this test cannot check what it cannot find", referencePath, arrayName)
	}
	// The array ends at the first `];` after its declaration. Sound because these arrays hold object
	// literals with no nested arrays; a future entry containing one would have to revisit this.
	end := strings.Index(src[start:], "];")
	if end < 0 {
		t.Fatalf("could not find the end of %s in %s", arrayName, referencePath)
	}
	body := src[start : start+end]

	var out []string
	for _, match := range queryEntry.FindAllStringSubmatch(body, -1) {
		value := match[1]
		if value == "" {
			value = match[2]
		}
		// The five escapes the TS source may carry, undone so the parser sees what the page shows.
		value = strings.NewReplacer(`\"`, `"`, `\\`, `\`, `\'`, `'`).Replace(value)
		out = append(out, value)
	}
	return out
}

func referenceSource(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(referencePath)
	if err != nil {
		t.Fatalf("reading %s: %v", referencePath, err)
	}
	return string(data)
}

// Every documented example must parse. This is the direction that misleads an operator.
func TestEveryDocumentedQueryExampleParses(t *testing.T) {
	examples := extractQueries(t, referenceSource(t), "QUERY_EXAMPLES")

	// The floor. Without it, a regex that stopped matching — a reformat, a changed quote style —
	// would make this test pass by checking nothing, which is how the guarantee got lost the first
	// time. The number is well below the current count so ordinary additions do not touch it.
	if len(examples) < 10 {
		t.Fatalf("extracted only %d examples from %s; the extractor is not reading the array and this "+
			"test would pass without checking anything", len(examples), referencePath)
	}

	for _, example := range examples {
		if _, err := query.Parse(example); err != nil {
			t.Errorf("the Discover page documents %q as a valid filter, and the shipped parser rejects "+
				"it: %v\n\nAn operator reading that example learns a language this tool does not have, "+
				"and concludes the filter box is broken.", example, err)
		}
	}
}

// Every documented refusal must actually be refused. The weaker direction, but the one that decays
// silently: a grammar that grew to accept a query listed here would leave the page telling operators
// something is impossible when it is not.
func TestEveryDocumentedRefusalIsRefused(t *testing.T) {
	refusals := extractQueries(t, referenceSource(t), "QUERY_REFUSALS")
	if len(refusals) < 3 {
		t.Fatalf("extracted only %d refusals from %s; the extractor is not reading the array",
			len(refusals), referencePath)
	}

	for _, refusal := range refusals {
		if _, err := query.Parse(refusal); err == nil {
			t.Errorf("the Discover page documents %q as refused at parse time, and the parser now "+
				"accepts it. Either the grammar gained a capability the page should describe, or it "+
				"lost a check the page is still promising.", refusal)
		}
	}
}

// The grammar block on the page lists the field names. A field the parser knows and the block omits
// is undiscoverable; a field the block lists and the parser does not know is a lie.
func TestTheDocumentedGrammarListsExactlyTheFieldsTheParserKnows(t *testing.T) {
	src := referenceSource(t)

	// Taken from internal/query's fieldByName. Kept as a literal rather than exported from that
	// package: the point is to compare the page against the parser's real behaviour, and a shared
	// constant would let both drift together.
	known := []string{"host", "method", "path", "mime", "status", "body", "length", "duration", "header", "extension", "params"}

	// header is the one field whose usable form is not `field op value`: it takes a subscript naming
	// which header. Spelled out here rather than folded into the loop below, because a loop that
	// silently accepted "neither form parses" for one field would be the hole this test exists to
	// close.
	usableForm := map[string]string{"header": `header["server"] ~ "nginx"`}

	grammarStart := strings.Index(src, "const QUERY_GRAMMAR")
	if grammarStart < 0 {
		t.Fatal("reference.ts does not declare QUERY_GRAMMAR")
	}
	grammarEnd := strings.Index(src[grammarStart:], "`;")
	if grammarEnd < 0 {
		t.Fatal("could not find the end of QUERY_GRAMMAR")
	}
	grammar := src[grammarStart : grammarStart+grammarEnd]

	for _, field := range known {
		if !strings.Contains(grammar, `"`+field+`"`) {
			t.Errorf("the parser accepts the field %q and the documented grammar does not list it; an "+
				"operator has no way to discover it", field)
		}
		// And it must be usable, not merely named.
		if form, special := usableForm[field]; special {
			if _, err := query.Parse(form); err != nil {
				t.Errorf("field %q is documented and its own usable form %q does not parse: %v", field, form, err)
			}
			continue
		}
		if _, err := query.Parse(field + ` ~ "x"`); err != nil {
			// Numeric fields legitimately refuse `~`; try a numeric comparison before concluding.
			if _, numErr := query.Parse(field + " > 1"); numErr != nil {
				t.Errorf("field %q is documented but neither %s ~ \"x\" nor %s > 1 parses: %v / %v",
					field, field, field, err, numErr)
			}
		}
	}
}
