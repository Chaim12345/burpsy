package scanner

// sqlmap's DBMS error-message bank, embedded verbatim (sqlmapdata/errors.xml; GPL, see
// sqlmapdata/README.md before distributing a build). It complements SQLErrorSignatures: those are
// substrings, these are sqlmap's per-DBMS regular expressions — 187 of them across 31 engines —
// and a match names the engine (and the fork, where sqlmap knows one).

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
}

// Label names the pattern in a finding's detail.
func (p sqlmapErrorPattern) Label() string {
	engine := p.DBMS
	if p.Fork != "" {
		engine += " (" + p.Fork + ")"
	}
	return "sqlmap " + engine + " error /" + p.Re.String()[len("(?i)"):] + "/"
}

var (
	sqlmapPatternsOnce sync.Once
	sqlmapPatterns     []sqlmapErrorPattern
	sqlmapPatternsErr  error
)

// sqlmapErrorPatterns parses the embedded bank once. sqlmap matches case-insensitively, so every
// pattern is compiled with (?i). A pattern Go cannot compile is an error rather than a silent
// skip: a shrunken bank would read as clean on exactly the engines it no longer covers.
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
				sqlmapPatterns = append(sqlmapPatterns, sqlmapErrorPattern{DBMS: d.Value, Fork: e.Fork, Re: re})
			}
		}
	})
	return sqlmapPatterns, sqlmapPatternsErr
}

// classifySqlmapErrors applies the baseline rule ClassifyErrorEvidence applies to substrings: a
// pattern counts only when the injected body matches it and the baseline does not. Bodies are
// checked in the same forms (as received and HTML-unescaped).
func classifySqlmapErrors(baselineBody, injectedBody string) (matched, preexisting []string) {
	patterns, err := sqlmapErrorPatterns()
	if err != nil {
		return nil, nil
	}
	baseForms := matchableForms(baselineBody)
	injForms := matchableForms(injectedBody)
	anyMatch := func(forms []string, re *regexp.Regexp) bool {
		for _, f := range forms {
			if re.MatchString(f) {
				return true
			}
		}
		return false
	}
	for _, p := range patterns {
		if !anyMatch(injForms, p.Re) {
			continue
		}
		if anyMatch(baseForms, p.Re) {
			preexisting = append(preexisting, p.Label())
		} else {
			matched = append(matched, p.Label())
		}
	}
	return matched, preexisting
}
