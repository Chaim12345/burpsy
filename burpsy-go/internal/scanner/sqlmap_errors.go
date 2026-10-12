package scanner

// sqlmap's DBMS error-message bank as a second SQL error-signature bank (burpsy-react-ui-v0ei.2).
//
// sqlmapdata/errors.xml is sqlmap's data/xml/errors.xml, embedded verbatim with sqlmap's LICENSE
// (GPLv2-or-later; burpsy is GPL-3.0-or-later; see sqlmapdata/README.md). It complements
// SQLErrorSignatures (Burp's recovered substring bank, burp.Ze2s): those are plain substrings,
// these are sqlmap's per-DBMS regular expressions — 187 of them across 31 engines — and every one
// names the engine (and, where sqlmap knows it, the fork) whose error it is.
//
// # The evidence rule is the substring bank's, unchanged
//
//   - a pattern counts only when the injected response matches it and the baseline does not; a
//     pattern the baseline already matched is recorded as pre-existing and makes the probe
//     undecided, never positive (ClassifyErrorEvidence's rule);
//   - both banks look at the body as received and HTML-unescaped (matchableForms);
//   - a pattern every one of whose matches sits on a command shell's own diagnostic line is the
//     shell's, not a database's, and is recorded as Foreign (the attribution rule of
//     sqli_error_attribution.go, applied per match position instead of per substring).
//
// The bank adds patterns; it never relaxes the rule. A broken-syntax probe and its repaired twin
// are still told apart by the same comparison: the error must be introduced by the probe.

import (
	_ "embed"
	"encoding/xml"
	"regexp"
	"sync"
)

//go:embed sqlmapdata/errors.xml
var sqlmapErrorsXML []byte

// sqlmapErrorPattern is one <error> row: the engine it fingerprints and its compiled regexp.
type sqlmapErrorPattern struct {
	DBMS string
	Fork string
	Re   *regexp.Regexp
	src  string
}

// Engine is the DBMS the pattern names, with its fork when sqlmap gives one ("MySQL (MariaDB)").
func (p sqlmapErrorPattern) Engine() string {
	if p.Fork != "" {
		return p.DBMS + " (" + p.Fork + ")"
	}
	return p.DBMS
}

// Label names the pattern in a probe's detail: the engine and the expression, attributed.
func (p sqlmapErrorPattern) Label() string {
	return p.Engine() + " error /" + p.src + "/ (sqlmap errors.xml)"
}

var (
	sqlmapPatternsOnce sync.Once
	sqlmapPatterns     []sqlmapErrorPattern
	sqlmapPatternsErr  error
)

// sqlmapErrorPatterns parses the embedded bank once. sqlmap matches case-insensitively
// (re.search(regex, page, re.I)), so every pattern is compiled with (?i). A pattern Go cannot
// compile is an error rather than a silent skip: a shrunken bank would read as clean on exactly
// the engines it no longer covers.
func sqlmapErrorPatterns() ([]sqlmapErrorPattern, error) {
	sqlmapPatternsOnce.Do(func() {
		var doc struct {
			DBMS []struct {
				Value  string `xml:"value,attr"`
				Errors []struct {
					Regexp string `xml:"regexp,attr"`
					Fork   string `xml:"fork,attr"`
				} `xml:"error"`
			} `xml:"dbms"`
		}
		if sqlmapPatternsErr = xml.Unmarshal(sqlmapErrorsXML, &doc); sqlmapPatternsErr != nil {
			return
		}
		for _, d := range doc.DBMS {
			for _, e := range d.Errors {
				re, err := regexp.Compile("(?i)" + e.Regexp)
				if err != nil {
					sqlmapPatternsErr = err
					sqlmapPatterns = nil
					return
				}
				sqlmapPatterns = append(sqlmapPatterns,
					sqlmapErrorPattern{DBMS: d.Value, Fork: e.Fork, Re: re, src: e.Regexp})
			}
		}
	})
	return sqlmapPatterns, sqlmapPatternsErr
}

// regexOwnedByShell is signatureOwnedByShell for a pattern: true when the pattern matches the body
// and every match starts on a line a shell's own diagnostic owns. Matching runs over the same
// lowercased forms the substring rule reads, so the line-head grammar applies unchanged.
func regexOwnedByShell(body string, re *regexp.Regexp) bool {
	seen := false
	for _, form := range matchableForms(body) {
		for _, loc := range re.FindAllStringIndex(form, -1) {
			seen = true
			if !foreignDiagnosticHead(lineHead(form, loc[0])) {
				return false
			}
		}
	}
	return seen
}

func matchesAnyForm(forms []string, re *regexp.Regexp) bool {
	for _, f := range forms {
		if re.MatchString(f) {
			return true
		}
	}
	return false
}

// addSqlmapErrorEvidence folds sqlmap's bank into ev under the rule above and recomputes the
// verdict. ev is the substring bank's (already attributed) result for the same pair of bodies.
func addSqlmapErrorEvidence(ev ErrorEvidence, baselineBody, injectedBody string) ErrorEvidence {
	patterns, err := sqlmapErrorPatterns()
	if err != nil {
		// TestSqlmapErrorPatternsLoad pins that this does not happen with the embedded file; if it
		// ever did, the substring bank still stands on its own.
		return ev
	}
	baseForms := matchableForms(baselineBody)
	injForms := matchableForms(injectedBody)
	for _, p := range patterns {
		if !matchesAnyForm(injForms, p.Re) {
			continue
		}
		switch {
		case matchesAnyForm(baseForms, p.Re):
			ev.Preexisting = append(ev.Preexisting, p.Label())
		case regexOwnedByShell(injectedBody, p.Re):
			ev.Foreign = append(ev.Foreign, p.Label())
		default:
			ev.Matched = append(ev.Matched, p.Label())
			ev.DBMS = appendUnique(ev.DBMS, p.Engine())
		}
	}
	switch {
	case len(ev.Matched) > 0:
		ev.Evidence = InjectionEvidenceErrorSignature
	case len(ev.Preexisting) > 0:
		ev.Evidence = InjectionEvidenceInconclusive
	default:
		ev.Evidence = InjectionEvidenceNone
	}
	return ev
}

// sqlmapErrorInBody is the no-sender read of the bank: the first pattern the captured body
// matches that is not a shell's own diagnostic, as its label and engine.
func sqlmapErrorInBody(body string) (label, engine string, ok bool) {
	patterns, err := sqlmapErrorPatterns()
	if err != nil {
		return "", "", false
	}
	forms := matchableForms(body)
	for _, p := range patterns {
		if matchesAnyForm(forms, p.Re) && !regexOwnedByShell(body, p.Re) {
			return p.Label(), p.Engine(), true
		}
	}
	return "", "", false
}

func appendUnique(list []string, s string) []string {
	for _, have := range list {
		if have == s {
			return list
		}
	}
	return append(list, s)
}
