// Package bundled is the BCheck corpus compiled into burpsy: the checks from PortSwigger's
// published BChecks repository (github.com/PortSwigger/BChecks, LGPL-3.0) that burpsy's
// interpreter can run, embedded verbatim, with a manifest that accounts for every upstream file.
//
// # The manifest is the point
//
// Every `.bcheck` file in the upstream tree at the pinned commit has exactly one manifest entry,
// whether or not it was imported, enabled, or even parsed. An entry that is not enabled says why,
// in a named category and a sentence:
//
//   - passive: a `given response` check. check_corpus gates the active audit, so the passive
//     set is recorded here and not embedded — it would be compiled in with nothing to run it.
//   - unsafe: the probe executes a command, writes to the target, creates or changes an account,
//     guesses credentials, retrieves live secrets, scans ports, or amplifies traffic. Not
//     embedded at all: a disabled flag is a weaker guarantee than an absent file.
//   - interpreter-gap: the check needs a language feature this interpreter does not have; the
//     reason names the feature.
//   - weak-evidence: the reporting condition is a common word or a bare status code, which a
//     page that merely mentions the word satisfies.
//   - false-positive: the check fired on a safe twin, or on an endpoint whose declared
//     vulnerability it does not test for, in the vulnapp sweep (scanner's bundled-corpus test).
//
// A check that is dropped without an entry is the failure this package exists to prevent, so the
// consistency test asserts the manifest and the embedded tree describe each other exactly.
//
// # Off by default
//
// Loading this corpus does not turn anything on. The audit engine dispatches it only under the
// check_corpus switch, which stays off until the operator sets it.
package bundled

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"sort"

	"github.com/burpsy-go/burpsy/internal/bcheck"
)

// Root is the embedded directory: LICENSE, NOTICE, manifest.json and checks/.
const Root = "portswigger"

// ManifestPath is the manifest's path inside FS.
const ManifestPath = Root + "/manifest.json"

//go:embed portswigger
var files embed.FS

// FS is the embedded tree, for the consistency test and for anything that wants the source text.
func FS() fs.FS { return files }

// Exclusion categories. Every entry that is not enabled carries exactly one.
const (
	CategoryPassive        = "passive"
	CategoryUnsafe         = "unsafe"
	CategoryInterpreterGap = "interpreter-gap"
	CategoryWeakEvidence   = "weak-evidence"
	CategoryFalsePositive  = "false-positive"
	CategoryParseError     = "parse-error"
	CategoryUnreviewed     = "unreviewed"
)

// Families, as the scanner's load report classifies a check.
const (
	FamilyPassive        = "passive"
	FamilyActive         = "active"
	FamilyInsertionPoint = "insertion-point"
	FamilyCollaborator   = "collaborator"
	FamilyTool           = "tool"
)

// Source describes where the corpus came from.
type Source struct {
	Repository string `json:"repository"`
	Commit     string `json:"commit"`
	CommitDate string `json:"commit_date"`
	License    string `json:"license"`
	// LicenseFile and NoticeFile are paths inside FS.
	LicenseFile string `json:"license_file"`
	NoticeFile  string `json:"notice_file"`
	ImportedAt  string `json:"imported_at"`
	Importer    string `json:"importer"`
}

// Exclusion is why an entry is not enabled.
type Exclusion struct {
	Category string `json:"category"`
	Reason   string `json:"reason"`
}

// Entry is one upstream `.bcheck` file.
type Entry struct {
	// SourcePath is the file's path in the upstream repository.
	SourcePath string `json:"source_path"`
	// SHA256 is the hex digest of the upstream file, which is also the embedded file's digest
	// when Imported: files are copied verbatim.
	SHA256 string `json:"sha256"`
	Name   string `json:"name,omitempty"`
	Given  string `json:"given,omitempty"`
	Family string `json:"family,omitempty"`
	// Parses is whether bcheck.Parse accepts the file; ParseError is its message when not.
	Parses     bool   `json:"parses"`
	ParseError string `json:"parse_error,omitempty"`
	// Runs is whether the check executes under this interpreter with every reference it makes
	// resolved — demonstrated by the scanner's bundled-corpus sweep, not assumed. False for an
	// entry that is not imported (it was never executed). RunGap names the missing language
	// feature of an imported check that does not run, and is set exactly for interpreter-gap.
	Runs   bool   `json:"runs"`
	RunGap string `json:"run_gap,omitempty"`
	// Imported is whether the file is embedded (under File). Passive and unsafe checks are not.
	Imported bool   `json:"imported"`
	File     string `json:"file,omitempty"`
	// Enabled is whether the check is in the set Checks returns. Exactly the entries with no
	// Exclusion are enabled.
	Enabled   bool       `json:"enabled"`
	Exclusion *Exclusion `json:"exclusion,omitempty"`
}

// Manifest is the whole accounting.
type Manifest struct {
	Source  Source  `json:"source"`
	Entries []Entry `json:"entries"`
}

// Counts summarises a manifest.
type Counts struct {
	Upstream   int
	Imported   int
	Parses     int
	Runs       int
	Enabled    int
	ByCategory map[string]int
}

// LoadManifest reads and decodes the embedded manifest.
func LoadManifest() (*Manifest, error) {
	raw, err := files.ReadFile(ManifestPath)
	if err != nil {
		return nil, fmt.Errorf("bundled corpus: read manifest: %w", err)
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("bundled corpus: decode manifest: %w", err)
	}
	return &m, nil
}

// Counts tallies the manifest.
func (m *Manifest) Counts() Counts {
	c := Counts{Upstream: len(m.Entries), ByCategory: map[string]int{}}
	for _, e := range m.Entries {
		if e.Imported {
			c.Imported++
		}
		if e.Parses {
			c.Parses++
		}
		if e.Runs {
			c.Runs++
		}
		if e.Enabled {
			c.Enabled++
		}
		if e.Exclusion != nil {
			c.ByCategory[e.Exclusion.Category]++
		}
	}
	return c
}

// Verify checks the manifest against the embedded tree and against itself: every embedded check
// file has exactly one imported entry and the other way round, every imported file's digest is the
// recorded one, every enabled entry parses and runs, and every entry that is not enabled says why.
// It returns every problem found, not just the first.
func (m *Manifest) Verify() []error {
	var errs []error
	seenSrc := map[string]bool{}
	byFile := map[string]*Entry{}
	for i := range m.Entries {
		e := &m.Entries[i]
		if seenSrc[e.SourcePath] {
			errs = append(errs, fmt.Errorf("%s: listed twice", e.SourcePath))
		}
		seenSrc[e.SourcePath] = true
		if e.Enabled != (e.Exclusion == nil) {
			errs = append(errs, fmt.Errorf("%s: enabled=%v but exclusion=%v — an entry is enabled exactly when nothing excludes it", e.SourcePath, e.Enabled, e.Exclusion))
		}
		if e.Exclusion != nil && (e.Exclusion.Category == "" || e.Exclusion.Reason == "") {
			errs = append(errs, fmt.Errorf("%s: an exclusion needs both a category and a reason", e.SourcePath))
		}
		if e.Enabled && (!e.Imported || !e.Parses || !e.Runs) {
			errs = append(errs, fmt.Errorf("%s: enabled but imported=%v parses=%v runs=%v", e.SourcePath, e.Imported, e.Parses, e.Runs))
		}
		gap := e.Exclusion != nil && e.Exclusion.Category == CategoryInterpreterGap
		if gap != (e.RunGap != "") {
			errs = append(errs, fmt.Errorf("%s: run_gap %q must be set exactly for an interpreter-gap exclusion", e.SourcePath, e.RunGap))
		}
		if e.Imported && e.Parses && !e.Runs && !gap {
			errs = append(errs, fmt.Errorf("%s: imported and parses but does not run, and names no missing feature", e.SourcePath))
		}
		if e.Runs && (!e.Imported || !e.Parses || gap) {
			errs = append(errs, fmt.Errorf("%s: runs=true needs an imported, parsing check with no interpreter gap", e.SourcePath))
		}
		if !e.Imported {
			if e.File != "" {
				errs = append(errs, fmt.Errorf("%s: not imported but names an embedded file %q", e.SourcePath, e.File))
			}
			continue
		}
		if e.File == "" {
			errs = append(errs, fmt.Errorf("%s: imported but names no embedded file", e.SourcePath))
			continue
		}
		byFile[e.File] = e
		raw, err := files.ReadFile(path.Join(Root, e.File))
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: embedded file %q: %w", e.SourcePath, e.File, err))
			continue
		}
		sum := sha256.Sum256(raw)
		if got := hex.EncodeToString(sum[:]); got != e.SHA256 {
			errs = append(errs, fmt.Errorf("%s: embedded sha256 %s, manifest says %s", e.SourcePath, got, e.SHA256))
		}
		_, perr := bcheck.Parse(string(raw))
		if (perr == nil) != e.Parses {
			errs = append(errs, fmt.Errorf("%s: manifest says parses=%v, parser says %v", e.SourcePath, e.Parses, perr))
		}
	}
	// The other direction: no embedded check file the manifest does not account for.
	_ = fs.WalkDir(files, path.Join(Root, "checks"), func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			errs = append(errs, err)
			return nil
		}
		if d.IsDir() {
			return nil
		}
		rel := p[len(Root)+1:]
		if byFile[rel] == nil {
			errs = append(errs, fmt.Errorf("%s: embedded but not in the manifest", rel))
		}
		return nil
	})
	return errs
}

// Checks parses and returns the enabled checks, in manifest order. An enabled entry that fails to
// read or parse is an error rather than a silent omission: the manifest promised it runs.
func Checks() ([]*bcheck.Check, error) {
	m, err := LoadManifest()
	if err != nil {
		return nil, err
	}
	return m.EnabledChecks()
}

// EnabledChecks parses the manifest's enabled entries from the embedded tree.
func (m *Manifest) EnabledChecks() ([]*bcheck.Check, error) {
	var out []*bcheck.Check
	for _, e := range m.Entries {
		if !e.Enabled {
			continue
		}
		c, err := m.parseEntry(e)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

// Check parses one imported entry by its upstream path, enabled or not. The scanner's precision
// test uses it to show an excluded check really does misfire.
func (m *Manifest) Check(sourcePath string) (*bcheck.Check, error) {
	for _, e := range m.Entries {
		if e.SourcePath == sourcePath {
			if !e.Imported {
				return nil, fmt.Errorf("bundled corpus: %s is not imported (%v)", sourcePath, e.Exclusion)
			}
			return m.parseEntry(e)
		}
	}
	return nil, fmt.Errorf("bundled corpus: no entry %s", sourcePath)
}

// Entry returns the entry for an upstream path.
func (m *Manifest) Entry(sourcePath string) (Entry, bool) {
	for _, e := range m.Entries {
		if e.SourcePath == sourcePath {
			return e, true
		}
	}
	return Entry{}, false
}

func (m *Manifest) parseEntry(e Entry) (*bcheck.Check, error) {
	raw, err := files.ReadFile(path.Join(Root, e.File))
	if err != nil {
		return nil, fmt.Errorf("bundled corpus: %s: %w", e.SourcePath, err)
	}
	c, err := bcheck.Parse(string(raw))
	if err != nil {
		return nil, fmt.Errorf("bundled corpus: %s: %w", e.SourcePath, err)
	}
	return c, nil
}

// Categories returns the exclusion categories present, sorted, for reports.
func (c Counts) Categories() []string {
	out := make([]string, 0, len(c.ByCategory))
	for k := range c.ByCategory {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
