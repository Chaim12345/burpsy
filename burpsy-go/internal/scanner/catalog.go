// Burp's shipped issue catalog: background, remediation, typical severity, and CWE/CAPEC
// classifications for the 183 issue types in `resources/KnowledgeBase/Issues/`.
//
// # Why the data is separate from the code
//
// catalog.go holds the shape and the lookup; catalog_data.go holds the transcribed
// `IssueDefinition` values. catalog_data.go is **generated** by tools/gen_catalog.py from the
// Burp jar extraction — do not hand-edit it, and never write a second copy of the data by hand,
// because the next regenerate would silently clobber your fixes. Both the Rust crate
// (crates/scanner/src/catalog*.rs) and this file document the same provenance rule.
//
// # No invented remediation
//
// Every remediation here is the shipped text from the Burp knobownledge base, transcribed
// mechanically — never paraphrased. Invented remediation is invented security advice presented to
// a target operator as authoritative. `Remediation` string is empty exactly when the source has
// none, so an absent one can never read as "nothing to do".
//
// # `TypeIndex` vs `DeclaredTypeIndex`
//
// `TypeIndex` is the ID encoded in the filename, unique across all 183 files. `DeclaredTypeIndex`
// is the `typeIndex` field inside the JSON body; it disagrees in 2 of 183 cases, where the stale
// value duplicates another issue's ID. Both are kept verbatim rather than reconciled, because
// silently picking one loses the forensic value of knowing the shipped data disagrees with itself.
//
// # No CVSS
//
// There is no CVSS anywhere in the shipped catalog — 433 classifications across the catalog: 306
// CWE, 126 CAPEC, 1 OWASP Top Ten. So there is no CVSS field here, mirroring the Rust catalog.
package scanner

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// IssueDefinition is one entry in Burp's shipped issue catalog.
type IssueDefinition struct {
	// TypeIndex is the ID encoded in the resource filename; unique across the catalog.
	TypeIndex uint32 `json:"type_index"`
	// DeclaredTypeIndex is the `typeIndex` field inside the JSON body. It differs from TypeIndex
	// for exactly the two stale cases the generator records; both are kept verbatim.
	DeclaredTypeIndex uint32 `json:"declared_type_index"`
	// Name is the catalogued issue name.
	Name string `json:"name"`
	// TypicalSeverity is the shipped typical severity, canonical lower-case ("high", "medium",
	// "low", "info") so it maps directly onto Finding.Severity.
	TypicalSeverity string `json:"typical_severity"`
	// Description is the background, as an HTML fragment.
	Description string `json:"description"`
	// Remediation is the shipped remediation as an HTML fragment, or "" when the source has none.
	Remediation string `json:"remediation"`
	// References are the shipped external references (title + URL).
	References []Reference `json:"references"`
	// Classifications are the shipped CWE/CAPEC (and one OWASP) classifications.
	Classifications []Classification `json:"classifications"`
}

// HasRemediation reports whether the issue ships remediation text — callers must not render an
// empty string as "nothing to do".
func (i IssueDefinition) HasRemediation() bool {
	return i.Remediation != ""
}

// Reference is one shipped reference.
type Reference struct {
	Title string `json:"title"`
	URL   string `json:"url"`
}

// Classification is one shipped vulnerability classification.
type Classification struct {
	Title string `json:"title"`
	URL   string `json:"url"`
}

var (
	cweRE   = regexp.MustCompile(`CWE\-(\d+)`)
	capecRE = regexp.MustCompile(`CAPEC\-(\d+)`)
)

// CWEs returns the CWE ids this classification names, parsing them from its title. Empty when the
// classification is not a CWE (e.g. the single OWASP Top Ten entry).
func (c Classification) CWEs() []uint32 {
	return parseIDs(c.Title, cweRE)
}

// CAPECs returns the CAPEC ids this classification names its title. Empty when it is not a CAPEC.
func (c Classification) CAPECs() []uint32 {
	return parseIDs(c.Title, capecRE)
}

// CWEs returns every CWE id across all of this issue's classifications, in the order they appear.
func (i IssueDefinition) CWEs() []uint32 {
	var out []uint32
	for _, c := range i.Classifications {
		out = append(out, c.CWEs()...)
	}
	return out
}

// CAPECs returns every CAPEC id across all of this issue's classifications, in the order they
// appear.
func (i IssueDefinition) CAPECs() []uint32 {
	var out []uint32
	for _, c := range i.Classifications {
		out = append(out, c.CAPECs()...)
	}
	return out
}

func parseIDs(title string, re *regexp.Regexp) []uint32 {
	var out []uint32
	for _, m := range re.FindAllStringSubmatch(title, -1) {
		if v, err := strconv.ParseUint(m[1], 10, 32); err == nil {
			out = append(out, uint32(v))
		}
	}
	return out
}

// CatalogProvenance records what the generated data claims about itself, so a report can speak it
// rather than a caller having to trust the counts are right. Populated once at init from
// catalog_data.go's marker, not from the slice (which would let a transcription bug report itself
// as healthy).
type CatalogProvenance struct {
	Issues       int
	Declared     int // issues with a non-empty remediation
	WithoutRemed int // issues whose remediation is absent in source
}

func (p CatalogProvenance) String() string {
	return strings.TrimSpace(
		"catalog: " + strconv.Itoa(p.Issues) + " issue definitions, " +
			strconv.Itoa(p.Declared) + " with remediation, " +
			strconv.Itoa(p.WithoutRemed) + " without",
	)
}

// Provenance reports the generator's recorded counts for the shipped transcript.
func Provenance() CatalogProvenance {
	return CatalogProvenance{
		Issues:       catalogMetaIssues,
		Declared:     catalogMetaWithRemed,
		WithoutRemed: catalogMetaWithoutRemed,
	}
}

// All returns the whole catalog, ordered by TypeIndex (binary-searchable).
func All() []IssueDefinition {
	return catalogData
}

// ByTypeIndex looks up one issue by its filename-encoded id, binary-searching the sorted catalog.
func ByTypeIndex(typeIndex uint32) (IssueDefinition, bool) {
	i := sort.Search(len(catalogData), func(i int) bool { return catalogData[i].TypeIndex >= typeIndex })
	if i < len(catalogData) && catalogData[i].TypeIndex == typeIndex {
		return catalogData[i], true
	}
	return IssueDefinition{}, false
}

// ByName looks up one issue by its exact catalogued name. Names are not guaranteed unique in the
// shipped corpus, so this returns the first match; prefer ByTypeIndex where an id is available.
func ByName(name string) (IssueDefinition, bool) {
	for _, d := range catalogData {
		if d.Name == name {
			return d, true
		}
	}
	return IssueDefinition{}, false
}
