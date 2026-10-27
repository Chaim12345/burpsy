package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/burpsy-go/burpsy/internal/advisory"
)

// The issue-definition catalogue, browsable on its own terms.
//
// # Why this is a separate surface from /api/issues
//
// /api/issues answers "what did we find", and joins a catalogue entry onto each finding. It cannot
// answer "what can this tool describe at all", because a finding that does not exist has no row to
// hang a definition off. Burp's Target tool keeps these apart for the same reason: Issue definitions
// is a reference work an operator reads *before* there is a finding — to decide what to look for, to
// quote remediation text into a report, or to check what a CWE maps to.
//
// # Index rows here, detail on the other route
//
// Per internal/web/AGENTS.md, a list endpoint returns index rows and the payload is fetched when one
// row is opened. The catalogue is ~416 KB of prose across 183 definitions; serving all of it to draw
// a list of 183 names would be the same mistake as resolving message bodies to draw a history table.
// So advisoryIndexView carries the three fields a row renders and nothing else, and
// GET /api/advisories/{typeIndex} serves one definition in full.
//
// # Why the search runs here and not in the browser
//
// The requirement is search over name *and* description. Description is the thing that is expensive
// to ship, so a client-side search over it would force the whole catalogue onto the wire — defeating
// the index/detail split for a text box. Filtering server-side keeps the wire small and, more
// usefully, lets the search run over the *same plain-text prose the console renders* rather than over
// the raw HTML fragment, where "p", "href" and "li" would all be matchable words that appear nowhere
// on screen.
//
// # What this endpoint deliberately does not claim
//
// A definition existing says nothing about whether burpsy runs a check for it. The catalogue is
// transcribed reference text; registration and runtime demonstration are separate facts, counted
// separately in docs/SCANNER-COVERAGE.md (183 registered, 145 runtime-demonstrated). No field here
// implies otherwise, and no coverage figure is served from this route, because the only figure it
// could compute honestly is the registration one — and publishing registration alone, with no
// counterpart, is exactly how "183" starts being read as "183 working checks".

// advisoryIndexView is one row of the catalogue list.
//
// TypeIndex is the hexadecimal form, which is what Burp's own UI and the definition filenames use, so
// an operator cross-checking burpsy against Burp is reading the same identifier. It is also the
// segment GET /api/advisories/{typeIndex} takes.
//
// TypicalSeverity is the severity this issue *class* usually carries. It is deliberately not called
// "severity": a finding's severity is what the scanner concluded about one occurrence, and the two
// must never be read as the same number.
type advisoryIndexView struct {
	TypeIndex       string `json:"type_index"`
	Name            string `json:"name"`
	TypicalSeverity string `json:"typical_severity"`
}

// advisoryCatalogueView is the list response.
//
// Loaded, Count and Matched are three different facts and are all reported, because collapsing them
// is how a screen starts lying. A nil catalogue is a supported state (see server.go's advisories
// field): Loaded false with Count 0 says "nothing was loaded", while Loaded true with Count 183 and
// Matched 0 says "the catalogue is here and your filter excluded all of it". An empty list alone
// cannot tell those apart, and they call for opposite reactions from the operator.
type advisoryCatalogueView struct {
	Loaded bool `json:"loaded"`
	// Count is the whole catalogue, before any filter.
	Count int `json:"count"`
	// Matched is how many rows survived the filter. Equal to Count when nothing was filtered.
	Matched int `json:"matched"`
	// SeverityCounts partitions the *whole* catalogue by typical severity, not the filtered set — it
	// labels the severity filter's own options, so it has to describe what selecting one would find.
	// Summing it must give Count; the handler test asserts that, because a partition that stops
	// summing is the quiet failure mode of a per-bucket count.
	SeverityCounts map[string]int `json:"severity_counts,omitempty"`
	// Hint explains an empty or absent catalogue. Empty when there is nothing to explain.
	Hint       string              `json:"hint,omitempty"`
	Advisories []advisoryIndexView `json:"advisories"`
}

// advisorySeverities is the severity set the catalogue uses, worst first. Written out rather than
// derived from the loaded files so an unknown ?severity= is refused rather than silently matching
// nothing — "no results" and "you asked for a severity that does not exist" are different answers.
var advisorySeverities = []advisory.Severity{
	advisory.SeverityHigh, advisory.SeverityMedium, advisory.SeverityLow, advisory.SeverityInfo,
}

func knownAdvisorySeverity(s string) bool {
	for _, known := range advisorySeverities {
		if string(known) == s {
			return true
		}
	}
	return false
}

// advisoryMatches reports whether a definition matches a lowercased search term.
//
// Name first because it is the cheap test and the common hit. The description is searched as the
// plain-text prose PlainParagraphs produces, which is the exact text the console shows — so a row
// that matches is a row whose visible words contain the term, rather than one whose markup does.
func advisoryMatches(d *advisory.Definition, needle string) bool {
	if strings.Contains(strings.ToLower(d.Name), needle) {
		return true
	}
	for _, para := range advisory.PlainParagraphs(d.Description) {
		if strings.Contains(strings.ToLower(para), needle) {
			return true
		}
	}
	return false
}

// handleAdvisories serves GET /api/advisories: the catalogue index, optionally filtered.
//
// ?q= searches name and description prose. ?severity= restricts to one typical severity and is
// validated rather than tolerated, per the tree's refuse-by-default rule for input it cannot read.
func (s *Server) handleAdvisories(w http.ResponseWriter, r *http.Request) {

	severity := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("severity")))
	if severity != "" && !knownAdvisorySeverity(severity) {
		names := make([]string, 0, len(advisorySeverities))
		for _, known := range advisorySeverities {
			names = append(names, string(known))
		}
		// Refused, not ignored: silently serving the whole catalogue for a severity nobody defined
		// would answer a question the caller did not ask, and look like a filter that does nothing.
		http.Error(w, fmt.Sprintf("Unknown severity %q; the catalogue uses %s",
			severity, strings.Join(names, ", ")), http.StatusBadRequest)
		return
	}
	needle := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))

	all := s.advisories.All() // nil-safe: a nil catalogue returns no definitions, not a panic
	rows := make([]advisoryIndexView, 0, len(all))
	counts := make(map[string]int, len(advisorySeverities))
	for _, d := range all {
		counts[string(d.Severity)]++
		if severity != "" && string(d.Severity) != severity {
			continue
		}
		if needle != "" && !advisoryMatches(d, needle) {
			continue
		}
		rows = append(rows, advisoryIndexView{
			TypeIndex:       d.HexIndex(),
			Name:            d.Name,
			TypicalSeverity: string(d.Severity),
		})
	}

	view := advisoryCatalogueView{
		Loaded:         s.advisories != nil,
		Count:          s.advisories.Len(),
		Matched:        len(rows),
		SeverityCounts: counts,
		Advisories:     rows,
	}
	if !view.Loaded {
		// The same distinction /api/issues draws with its catalogue size: an operator has to be able
		// to tell "no catalogue is loaded" from "this issue has no definition".
		view.Hint = "no issue-definition catalogue is loaded, so no definition can be shown for any finding"
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(view)
}

// handleAdvisoryDetail serves GET /api/advisories/{typeIndex}: one definition in full.
//
// The response is issueAdvisoryView — the same shape /api/issues attaches to a finding, deliberately
// reused rather than redeclared. The console renders both with one component, and two producers of
// one shape drift (the reason events.go carries change kinds instead of rows).
//
// The method is checked before the path. A caller who POSTs here has the verb wrong whatever segment
// they sent, and "wrong verb" is the more actionable answer than "no such definition".
func (s *Server) handleAdvisoryDetail(w http.ResponseWriter, r *http.Request) {
	segment := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/advisories/"), "/")
	if segment == "" || strings.Contains(segment, "/") {
		http.Error(w, "Expected one type index: /api/advisories/{typeIndex}", http.StatusNotFound)
		return
	}
	// Hexadecimal, because that is the form the index rows carry and the form Burp uses. Accepting
	// decimal as well would make "100200" ambiguous between two real definitions.
	index, err := strconv.ParseUint(segment, 16, 32)
	if err != nil {
		http.Error(w, fmt.Sprintf("Type index %q is not a hexadecimal issue type index", segment),
			http.StatusNotFound)
		return
	}
	if s.advisories == nil {
		// Stated separately from a miss on purpose. "The catalogue is not loaded" is a server state an
		// operator can fix; "there is no definition with that index" is a fact about the catalogue.
		http.Error(w, "No issue-definition catalogue is loaded", http.StatusNotFound)
		return
	}
	def, ok := s.advisories.ByIndex(int(index))
	if !ok {
		http.Error(w, fmt.Sprintf("No issue definition with type index %s", segment), http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(advisoryDetailView(def))
}

// advisoryDetailView converts a catalogue entry into the wire shape a finding's advisory already uses.
//
// Factored out of findingToIssueView's inline literal so the two cannot diverge: a field added for the
// browsable catalogue and forgotten on the finding path would give the same component two shapes.
func advisoryDetailView(d *advisory.Definition) issueAdvisoryView {
	return issueAdvisoryView{
		TypeIndex:             d.HexIndex(),
		Name:                  d.Name,
		Description:           d.Description,
		Remediation:           d.Remediation,
		DescriptionParagraphs: advisory.PlainParagraphs(d.Description),
		RemediationParagraphs: advisory.PlainParagraphs(d.Remediation),
		TypicalSeverity:       string(d.Severity),
		References:            advisoryLinks(d.References, nil),
		Classifications:       advisoryLinks(nil, d.Classification),
	}
}
