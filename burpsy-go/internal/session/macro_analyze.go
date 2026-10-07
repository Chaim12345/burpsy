package session

// Automatic macro parameter analysis and Re-analyze (burpsy-react-ui-e23c) — Burp's
// settings/sessions/macros.html: "When you define a new macro, Burp automatically tries to
// find any relationships ... identifying parameters whose values can be determined from the
// preceding response ... form field values, redirection targets, or query strings in links."
//
// # What the analyzer reads, and why the dry-run report is the input
//
// Burp analyzes the macro as it runs — the responses it would get. burpsy already has exactly
// that: RunMacroDetailed reports every step's response (StepResult: status, headers, body,
// final URL) without touching login-run memory, so the analyzer has a real, honest corpus to
// read: not the operator's guess of what the target returns, but what it returned. A skipped
// step (out of scope, send failure) has no response and contributes nothing — an analysis
// that hallucinated relationships over a step that never ran would be worse than none.
//
// # What is suggested, and what is deliberately not
//
// Three source classes, the ones Burp names, in the order of confidence:
//
//  1. Hidden form fields — <input type="hidden" name="csrf" value="...">. The classic CSRF
//     token: the field is present because the response put it there, and a later step's
//     {{csrf}} is exactly how the value crosses steps.
//  2. Set-Cookie names — a response that sets sess=abc is naming a value it just minted, and
//     a later step that needs to carry it back can extract it (the jar also absorbs it, but an
//     extraction is how the value becomes visible and referenceable in a step's body).
//  3. Query strings in links — href="/next?token=xyz": a redirect target carrying a token is
//     the third source Burp names, and the only one whose value lives in a link rather than
//     a form.
//
// NOT suggested: visible form fields. A visible field's value is the operator's to type (a
// username), not something the response determined, and suggesting every visible input would
// bury the three signals in noise. The pattern for each suggestion is exact enough to lift
// the value on the next run and permissive enough to survive the target rotating it —
// the value is a capture group, the surroundings are the literal.
//
// # Suggestion identity
//
// Each suggestion names the extraction it would add: name, from, pattern, group, step. The
// name is derived from the field/cookie/parameter it lifts, sanitised to the {{name}} marker
// grammar. A suggestion is skipped when the rule already extracts a value with that name
// (from any step): re-suggesting what the operator already wired would be a list that trains
// them to ignore it, the same failure the editor's tab-availability rule exists to avoid.

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// ExtractionSuggestion is one relationship the analyzer found: a value the step's response
// determines, as an Extraction the rule could add.
type ExtractionSuggestion struct {
	// Name is the {{marker}} name the extraction would carry, derived from the source.
	Name string `json:"name"`
	// From is "body" or "header" — the Extraction field of the same name.
	From string `json:"from"`
	// Header is the response header to read, for a Set-Cookie suggestion (From: "header").
	Header string `json:"header,omitempty"`
	// Pattern is the extraction's regex, with the value as capture group `Group`.
	Pattern string `json:"pattern"`
	Group   int    `json:"group"`
	// Step is the index of the response this value was found in — the extraction's Step.
	Step int `json:"step"`
	// Source is where the value was found: "hidden form field", "set-cookie" or "query in link".
	// Carried so the UI can say WHY it is suggesting, which is what makes a suggestion
	// checkable rather than magic.
	Source string `json:"source"`
	// Value is what the dry-run's response actually carried — shown so the operator can see
	// the relationship is real before applying it, rather than trusting a name.
	Value string `json:"value"`
}

var (
	// hiddenInput matches <input ... type="hidden" ... name="..." value="..."> in either
	// attribute order, single or double quoted. The value is capture 1. HTML's own case
	// insensitivity is honoured because real pages mix.
	hiddenInput = regexp.MustCompile(`(?is)<input\b[^>]*?type\s*=\s*["']?hidden["']?[^>]*?>`)
	nameAttr    = regexp.MustCompile(`(?is)\bname\s*=\s*["']([^"']+)["']`)
	valueAttr   = regexp.MustCompile(`(?is)\bvalue\s*=\s*["']([^"']*)["']`)
	// linkQuery matches href="...?...token=xyz..." and captures the query string; the pairs
	// inside are split afterwards. Relative and absolute hrefs both, because a redirect
	// target is as often one as the other.
	hrefAttr = regexp.MustCompile(`(?is)\bhref\s*=\s*["']([^"']+)["']`)
)

// AnalyzeMacro walks a dry-run report's responses and returns the parameter relationships it
// found, as extraction suggestions. Pure over the report: no store, no network, no writes —
// the caller decides what to do with the list, and the tests decide it without a server.
//
// Suggestion order is by step then by first appearance, so the list reads in the order the
// macro's own story runs. A rule already holding an extraction with the same name (any step)
// suppresses the suggestion — the operator wired that one already.
func AnalyzeMacro(rule *SessionRule, report MacroRunReport) []ExtractionSuggestion {
	if rule == nil {
		return nil
	}
	// The names already wired, from the rule's extraction list — every name a {{marker}} in
	// any step can already resolve. Re-suggesting a wired name would be a list that trains the
	// operator to ignore it.
	existing := make(map[string]bool)
	for _, ex := range rule.Extractions {
		if ex != nil {
			existing[strings.TrimSpace(ex.Name)] = true
		}
	}

	var out []ExtractionSuggestion
	seen := make(map[string]bool)
	for _, step := range report.Steps {
		if step.Response == nil || step.Skipped != "" {
			continue
		}
		body := string(step.Response.Body)

		// 1. Hidden form fields.
		for _, m := range hiddenInput.FindAllStringSubmatch(body, -1) {
			tag := m[0]
			nameM := nameAttr.FindStringSubmatch(tag)
			if nameM == nil {
				continue
			}
			name := strings.TrimSpace(nameM[1])
			if name == "" {
				continue
			}
			var value string
			if v := valueAttr.FindStringSubmatch(tag); v != nil {
				value = v[1]
			}
			if existing[name] || seen[name] {
				continue
			}
			seen[name] = true
			// The pattern re-finds the tag by name and re-captures its value, so the
			// extraction keeps working when the token rotates.
			pattern := fmt.Sprintf(`(?is)<input\b[^>]*?\bname\s*=\s*["']?%s["']?[^>]*?\bvalue\s*=\s*["']([^"']*)["']`, regexp.QuoteMeta(name))
			out = append(out, ExtractionSuggestion{
				Name: name, From: "body", Pattern: pattern, Group: 1,
				Step: step.Index, Source: "hidden form field", Value: value,
			})
		}

		// 2. Set-Cookie names the response minted.
		for _, raw := range step.SetCookies {
			pair := strings.TrimSpace(raw)
			name := pair
			if i := strings.IndexAny(pair, "="); i >= 0 {
				name = strings.TrimSpace(pair[:i])
			}
			if name == "" || existing[name] || seen[name] {
				continue
			}
			seen[name] = true
			// The extraction reads the Set-Cookie header and captures the value after =.
			pattern := fmt.Sprintf(`(?i)^%s=([^;]*)`, regexp.QuoteMeta(name))
			value := ""
			if i := strings.Index(pair, "="); i >= 0 {
				value = strings.TrimSpace(pair[i+1:])
				if j := strings.Index(value, ";"); j >= 0 {
					value = strings.TrimSpace(value[:j])
				}
			}
			out = append(out, ExtractionSuggestion{
				Name: name, From: "header", Header: "Set-Cookie", Pattern: pattern, Group: 1,
				Step: step.Index, Source: "set-cookie", Value: value,
			})
		}

		// 3. Query strings in links — a href whose query pairs carry token-like values.
		for _, m := range hrefAttr.FindAllStringSubmatch(body, -1) {
			href := m[1]
			q := href
			if i := strings.Index(href, "?"); i >= 0 {
				q = href[i+1:]
			} else {
				continue
			}
			for _, pair := range strings.Split(q, "&") {
				eq := strings.Index(pair, "=")
				if eq <= 0 {
					continue
				}
				name := strings.TrimSpace(pair[:eq])
				value := pair[eq+1:]
				if name == "" || value == "" || existing[name] || seen[name] {
					continue
				}
				seen[name] = true
				pattern := fmt.Sprintf(`[?&]%s=([^&\s"']+)`, regexp.QuoteMeta(name))
				out = append(out, ExtractionSuggestion{
					Name: name, From: "body", Pattern: pattern, Group: 1,
					Step: step.Index, Source: "query in link", Value: value,
				})
			}
		}
	}

	sort.SliceStable(out, func(i, j int) bool { return out[i].Step < out[j].Step })
	return out
}
