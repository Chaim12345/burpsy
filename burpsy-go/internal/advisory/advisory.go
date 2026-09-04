// Package advisory holds the issue-definition catalogue: the long-form description, remediation,
// references and vulnerability classifications that turn a finding's one-line name into something an
// operator can act on and put in a report.
//
// # Provenance and distribution
//
// The bundled catalogue is extracted from a local Burp Suite installation's own resource bundle
// (resources/KnowledgeBase/Issues). That text is PortSwigger's copyrighted content, licensed to the
// operator who licensed Burp — it is not open content, and this package embeds it on the explicit
// instruction that this build is for personal use out of a private repository.
//
// Two consequences a future reader must not discover the hard way:
//
//   - `go:embed` puts the catalogue in the repository *and* in every binary built from it. Opening
//     the repository, or handing a compiled binary to anyone, is redistribution of PortSwigger's
//     content. If either becomes likely, drop the embed and switch Load to read from an operator-
//     supplied directory instead — the rest of this package is written so that swap is a one-line
//     change to Load, with no caller affected.
//   - Definitions are keyed by Burp's own hexadecimal type index, which is a stable public
//     identifier. Nothing else in burpsy depends on the catalogue being present: every lookup can
//     miss, and a miss is a normal answer, not an error.
package advisory

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
)

//go:embed definitions/*.json
var bundled embed.FS

// Severity is the severity a definition says this issue class typically carries.
//
// Deliberately distinct from a finding's own severity. The catalogue describes the *class* — "SQL
// injection is typically high" — while a finding carries what this particular occurrence was rated.
// Collapsing the two would let a catalogue lookup silently rewrite a scanner's verdict.
type Severity string

const (
	SeverityHigh   Severity = "HIGH"
	SeverityMedium Severity = "MEDIUM"
	SeverityLow    Severity = "LOW"
	SeverityInfo   Severity = "INFO"
)

// Classification is one external taxonomy entry — a CWE, CAPEC or OWASP reference.
type Classification struct {
	Title string `json:"title"`
	URL   string `json:"url"`
}

// Reference is a further-reading link.
type Reference struct {
	Title string `json:"title"`
	URL   string `json:"url"`
}

// Definition is one issue class.
//
// Description and Remediation are HTML fragments, not plain text — the source stores them as
// paragraph markup. They are carried through verbatim rather than stripped, because the paragraph
// breaks are the difference between readable remediation advice and a wall. Every consumer that
// renders them is responsible for doing so safely; see SanitisedHTML.
type Definition struct {
	TypeIndex      int              `json:"typeIndex"`
	Name           string           `json:"name"`
	Description    string           `json:"description"`
	Remediation    string           `json:"remediation"`
	WebIntro       *string          `json:"webIntro"`
	Severity       Severity         `json:"typicalSeverity"`
	References     []Reference      `json:"references"`
	Classification []Classification `json:"vulnerabilityClassifications"`

	// fileIndex is the index implied by the definition's own filename (%08x of typeIndex; see
	// HexIndex). Kept so the loader can tell which of two colliding definitions actually owns
	// the index. Unexported and unserialised: it is provenance about where the definition came
	// from, not part of the advisory the operator reads.
	fileIndex int
}

// HexIndex is the type index in the hexadecimal form Burp's own UI and filenames use, so an operator
// comparing burpsy against Burp is reading the same identifier.
func (d Definition) HexIndex() string { return fmt.Sprintf("%08x", d.TypeIndex) }

// Catalogue is a loaded, read-only set of definitions.
//
// Read-only after construction, so it needs no lock: Load builds it once at startup and every
// consumer only ever looks things up.
type Catalogue struct {
	byIndex map[int]*Definition
	byName  map[string]*Definition // normalised name -> definition
	ordered []*Definition
	// shadowed holds definitions that lost an index collision. They stay in ordered and in
	// byName — they are real definitions, reachable by name — they simply are not what ByIndex
	// answers for their declared index. Exposed via ShadowedByIndex so a caller counting the
	// catalogue can report "183 loaded, 181 indexable" instead of implying those agree.
	shadowed []*Definition
}

// Load reads the bundled catalogue.
//
// A malformed file is a build-time mistake, not a runtime condition, so it is returned as an error
// rather than skipped — a catalogue that silently loaded 182 of 183 definitions would present as
// "that issue has no advisory", which is indistinguishable from an unmapped check.
func Load() (*Catalogue, error) { return loadFS(bundled, "definitions") }

func loadFS(fsys fs.FS, dir string) (*Catalogue, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, fmt.Errorf("read advisory definitions: %w", err)
	}
	c := &Catalogue{byIndex: map[int]*Definition{}, byName: map[string]*Definition{}}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		raw, err := fs.ReadFile(fsys, dir+"/"+e.Name())
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", e.Name(), err)
		}
		var d Definition
		if err := json.Unmarshal(raw, &d); err != nil {
			return nil, fmt.Errorf("parse %s: %w", e.Name(), err)
		}
		if d.Name == "" {
			return nil, fmt.Errorf("%s has no name", e.Name())
		}
		def := &d
		if fileIdx, ok := indexFromFilename(e.Name()); ok {
			def.fileIndex = fileIdx
		} else {
			def.fileIndex = d.TypeIndex
		}
		// Two definitions genuinely collide on typeIndex, and the collision is Burp's own:
		// 00101200_ReactServerComponentsRemoteCodeExecutionReact2shell.json declares Perl code
		// injection's index (1052160), and 09008000_BambdaGeneratedIssue.json declares BCheck's
		// (150994944). Burp's shipped KnowledgeBase/Issues carries the identical mismatch — 183
		// files, 181 distinct indices — so this data is faithful to the oracle and must NOT be
		// "corrected" here. Editing a typeIndex to tidy an internal map would be a divergence
		// from Burp dressed up as a bug fix.
		//
		// What was wrong was this map's behaviour. A bare assignment let whichever file was read
		// last win, so ByIndex(1052160) answered "React Server Components RCE" to a caller asking
		// for Perl code injection — and GET /api/advisories/{index} served that wrong advisory,
		// with the wrong severity and remediation, to the operator. NormaliseName's own comment
		// says a match that attaches the wrong advisory to a finding is worse than no advisory;
		// that rule was enforced on the name path and quietly not on this one.
		//
		// The filename decides, because it is the authoritative half: the convention is %08x of
		// the index, Burp's own resource list is where these names come from, and in both
		// collisions exactly one file's name agrees with its own field. That file owns the index.
		// The loser is recorded as shadowed rather than dropped, so the loss is countable.
		if prior, taken := c.byIndex[d.TypeIndex]; taken {
			priorAgrees := prior.TypeIndex == prior.fileIndex
			thisAgrees := d.TypeIndex == def.fileIndex
			if thisAgrees && !priorAgrees {
				c.shadowed = append(c.shadowed, prior)
				c.byIndex[d.TypeIndex] = def
			} else {
				// The incumbent agrees with its filename, or neither does. Keep the incumbent so
				// the result is deterministic rather than a function of directory order.
				c.shadowed = append(c.shadowed, def)
			}
		} else {
			c.byIndex[d.TypeIndex] = def
		}
		// byName is deliberately untouched by the collision: the colliding definitions have
		// distinct names, so both stay reachable by name even when one cannot own its index.
		c.byName[NormaliseName(d.Name)] = def
		c.ordered = append(c.ordered, def)
	}
	sort.Slice(c.ordered, func(i, j int) bool { return c.ordered[i].Name < c.ordered[j].Name })
	return c, nil
}

// NormaliseName folds a check or issue name to a lookup key.
//
// Lowercased, with every run of non-alphanumeric characters collapsed to a single space and the ends
// trimmed. This is what lets burpsy's own "Missing X-Frame-Options Header" meet the catalogue's
// "Frame injection" family without either side having to store the other's exact spelling — and it
// is deliberately conservative: it normalises punctuation and case, never word order or synonyms,
// because a fuzzy match that attaches the wrong advisory to a finding is worse than no advisory.
func NormaliseName(s string) string {
	var b strings.Builder
	lastSpace := true
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			lastSpace = false
		default:
			if !lastSpace {
				b.WriteByte(' ')
				lastSpace = true
			}
		}
	}
	return strings.TrimSpace(b.String())
}

// ByIndex looks a definition up by Burp type index.
func (c *Catalogue) ByIndex(i int) (*Definition, bool) {
	if c == nil {
		return nil, false
	}
	d, ok := c.byIndex[i]
	return d, ok
}

// ByName looks a definition up by issue or check name, normalised.
func (c *Catalogue) ByName(name string) (*Definition, bool) {
	if c == nil {
		return nil, false
	}
	d, ok := c.byName[NormaliseName(name)]
	return d, ok
}

// All returns every definition, name-ordered. The slice is the catalogue's own; callers must not
// mutate it.
func (c *Catalogue) All() []*Definition {
	if c == nil {
		return nil
	}
	return c.ordered
}

// Len reports how many definitions loaded.
//
// This is the count of definitions, not the count of reachable indices, and the two differ:
// see IndexedLen and ShadowedByIndex. Len stays the definition count because that is the true
// answer to "how big is the catalogue" — the shadowed entries are real advisories, readable by
// name — but a caller reporting Len as though every entry were addressable by index would be
// overstating by two.
func (c *Catalogue) Len() int {
	if c == nil {
		return 0
	}
	return len(c.ordered)
}

// IndexedLen reports how many distinct indices ByIndex can answer for.
//
// Len minus IndexedLen is exactly len(ShadowedByIndex). Kept as its own method rather than
// left for callers to compute, because the subtraction is the kind of thing a caller does once
// and then forgets when the numbers drift.
func (c *Catalogue) IndexedLen() int {
	if c == nil {
		return 0
	}
	return len(c.byIndex)
}

// ShadowedByIndex returns the definitions that lost an index collision, in load order.
//
// Non-empty is the normal, expected state for faithful Burp data: two of Burp's own definition
// files declare a neighbour's typeIndex, so two advisories are not addressable by index. It is
// exported so that anything counting or displaying the catalogue can say so out loud instead of
// presenting a total that quietly does not add up. An empty result means every definition owns
// its index — which would be true of a corrected data set, and this API does not need to change
// if that ever happens upstream.
func (c *Catalogue) ShadowedByIndex() []*Definition {
	if c == nil {
		return nil
	}
	return c.shadowed
}

// indexFromFilename reads the index a definition's filename claims.
//
// The convention is "%08x_Name.json" (HexIndex), so the prefix before the first underscore is
// the index in hex. Returns false for any name that does not follow it, which the loader treats
// as "this file makes no claim" rather than as an error — a definition with an unconventional
// name is still a definition, and refusing to load the catalogue over a filename would take the
// whole advisory surface down to enforce a naming rule.
func indexFromFilename(name string) (int, bool) {
	prefix, _, found := strings.Cut(name, "_")
	if !found || len(prefix) != 8 {
		return 0, false
	}
	v, err := strconv.ParseInt(prefix, 16, 64)
	if err != nil {
		return 0, false
	}
	return int(v), true
}
