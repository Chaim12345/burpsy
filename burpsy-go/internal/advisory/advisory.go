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
		c.byIndex[d.TypeIndex] = def
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
func (c *Catalogue) Len() int {
	if c == nil {
		return 0
	}
	return len(c.ordered)
}
