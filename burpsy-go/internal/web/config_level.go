package web

// The user/project configuration split (burpsy-react-ui-wfiw).
//
// # The defect
//
// The bundle was one flat set of sections, so an import was all-or-nothing across two kinds of
// setting that have nothing to do with each other. Burp divides them for a reason an operator feels
// immediately: PROJECT settings describe the engagement (what is in scope, which session rules
// apply, how the scanner is configured) and USER settings describe the person and the machine
// (which headers their editor hides, their upstream proxy, their client certificates). Handing a
// colleague an engagement's scope should not also overwrite their proxy settings, and restoring
// your own preferences on a new laptop should not import someone else's scope.
//
// # Why a section is declared at exactly one level
//
// A section listed at both levels would make `?level=user` and `?level=project` overlap, and an
// operator importing one after the other would silently get whichever ran last. The manifest is
// therefore exhaustive and exclusive, and a test asserts both — a section at two levels, or at
// none, is a test failure rather than a judgement call made at request time.

import (
	"errors"
	"net/http"
	"sort"
	"strings"
)

// errLevelUnknown is the refusal for a ?level= value this server does not know. A named error
// rather than an inline one because both handlers answer it and they must answer identically: a
// typo that exported the whole bundle when the operator asked for one half would have them hand a
// colleague a file believing it carried no personal settings.
var errLevelUnknown = errors.New("level must be \"user\" or \"project\"")

// configLevel is which half of the configuration a section belongs to.
type configLevel string

const (
	// configLevelProject is the engagement: scope, the session rules that describe its logins, the
	// scanner's configuration, the pools and schedules that pace it.
	configLevelProject configLevel = "project"
	// configLevelUser is the person and the machine: editor preferences, the network path out, the
	// credentials this operator holds.
	configLevelUser configLevel = "user"
)

// configSectionLevel declares the level of every section the bundle knows, included or omitted.
//
// Omitted sections are listed too, and that is deliberate: `?level=user` has to be able to report
// "this is what user-level coverage looks like" including the parts that are NOT carried, or the
// per-level coverage block would overstate exactly the way the flat one did.
var configSectionLevel = map[string]configLevel{
	// Project — the engagement.
	"scope":           configLevelProject,
	"session_rules":   configLevelProject,
	"scanner_config":  configLevelProject,
	"resource_pools":  configLevelProject,
	"scheduled_tasks": configLevelProject,
	// Match & replace rules rewrite the traffic of THIS engagement's targets, so they travel with
	// it rather than with the operator.
	"match_replace_rules": configLevelProject,

	// User — the person and the machine.
	"intercept":               configLevelUser,
	"uninteresting_headers":   configLevelUser,
	"network_settings":        configLevelUser,
	"platform_authentication": configLevelUser,
	"proxy_options":           configLevelUser,
	"client_certificates":     configLevelUser,
	"tls_passthrough":         configLevelUser,
	"upstream_proxy":          configLevelUser,
}

// parseConfigLevel reads the ?level= parameter. An absent parameter means BOTH levels, which is
// what every existing caller sends and what keeps the un-narrowed bundle behaving as it did.
//
// An unrecognised value is refused rather than read as "both": a typo that silently exported the
// whole bundle when the operator asked for one half is the quiet wrong answer — they would hand a
// colleague a file believing it carried no personal settings.
func parseConfigLevel(r *http.Request) (configLevel, bool, error) {
	raw := strings.TrimSpace(r.URL.Query().Get("level"))
	if raw == "" {
		return "", false, nil
	}
	switch configLevel(strings.ToLower(raw)) {
	case configLevelUser:
		return configLevelUser, true, nil
	case configLevelProject:
		return configLevelProject, true, nil
	}
	return "", false, errLevelUnknown
}

// sectionInLevel reports whether a section belongs in a bundle narrowed to `level`. An unfiltered
// request (narrowed false) admits everything.
//
// A section with no declared level is admitted when unfiltered and excluded from every narrowed
// request, so a surface added without a manifest entry cannot silently ride along in a bundle the
// operator believes is one half. The manifest test is what makes that state temporary.
func sectionInLevel(section string, level configLevel, narrowed bool) bool {
	if !narrowed {
		return true
	}
	declared, ok := configSectionLevel[section]
	return ok && declared == level
}

// sectionsAtLevel filters one list of section names by level, preserving order.
func sectionsAtLevel(sections []string, level configLevel, narrowed bool) []string {
	out := make([]string, 0, len(sections))
	for _, s := range sections {
		if sectionInLevel(s, level, narrowed) {
			out = append(out, s)
		}
	}
	return out
}

// exportCoverageAt is exportCoverage narrowed to one level, so "project: 3 of 9" and "user: 1 of 6"
// are different claims from "4 of 15" — criterion 2. The note names the level, because the file is
// most likely read in an editor at the moment it matters.
func exportCoverageAt(level configLevel, narrowed bool) configCoverage {
	if !narrowed {
		return exportCoverage()
	}
	included := sectionsAtLevel(configIncludedSections, level, true)
	omitted := sectionsAtLevel(configOmittedSections, level, true)
	return configCoverage{
		Partial:  len(omitted) > 0,
		Included: included,
		Omitted:  omitted,
		Note: "This bundle carries only the " + string(level) + "-level sections listed in " +
			"\"included\". The sections in \"omitted\" are " + string(level) + "-level settings " +
			"configured on this instance that are NOT exported, and the other level's settings are " +
			"not in this file at all.",
	}
}

// configLevelsOf reports every level a section is declared at, for the manifest test. A section
// declared twice or not at all is what this exists to surface.
func configLevelsOf(section string) []configLevel {
	var out []configLevel
	if lvl, ok := configSectionLevel[section]; ok {
		out = append(out, lvl)
	}
	return out
}

// allConfigSections is every section the bundle knows, included and omitted, sorted so two reads
// agree.
func allConfigSections() []string {
	out := append(append([]string(nil), configIncludedSections...), configOmittedSections...)
	sort.Strings(out)
	return out
}
