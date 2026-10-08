package mcpscan

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// The MCP-specific checks (burpsy-react-ui-wflj). Each reads the enumeration and yields findings; none
// sends traffic (the enumeration and probes already did), so they are pure and fully unit-testable.
//
// What these can and cannot see is stated honestly per check: a static read of tool names, schemas and
// descriptions plus the probe outcomes catches the classes that live in that data — over-broad
// capability, instructions smuggled into descriptions, unauthenticated exposure, a tool that takes a
// URL/host (an SSRF reach waiting to happen) — and does not claim the ones that need live exploitation.

// Finding is one MCP-target finding, mapped by the web layer onto core.NewFinding.
type Finding struct {
	Name        string
	Severity    string // "info" | "low" | "medium" | "high"
	Confidence  string // "tentative" | "firm" | "certain"
	Description string
	// Subject is the tool/resource/prompt name the finding is about, "" for a server-wide one. It is
	// the finding's merge identity, so re-scanning the same server does not pile up duplicates.
	Subject string
}

// dangerousCapabilityRe matches the words a tool name or description uses when it can touch the file
// system, run a command, or reach the network — the capabilities that make an over-broad MCP tool the
// agent-era equivalent of an unsandboxed plugin.
var dangerousCapabilityRe = regexp.MustCompile(`(?i)\b(exec|execute|shell|command|cmd|bash|sh|eval|spawn|subprocess|system|run_?code|file|read_?file|write_?file|delete|unlink|fs|filesystem|path|directory|sql|query|database|fetch|http|request|url|curl|download|upload|ssrf|proxy|socket|dns|kubernetes|kubectl|docker|secret|credential|token|password|env|environment)\b`)

// networkParamRe matches an input-schema property name or description that names a URL/host/endpoint —
// a tool that takes one can be pointed at an internal service, the MCP form of SSRF.
var networkParamRe = regexp.MustCompile(`(?i)\b(url|uri|host|hostname|endpoint|address|server|target|link|webhook|callback)\b`)

// injectionMarkerRe matches the phrasings a prompt-injection payload smuggled into a tool or resource
// *description* uses to redirect the agent reading it — the description is fed to the model verbatim,
// so an imperative aimed at the model is an instruction, not documentation.
var injectionMarkerRe = regexp.MustCompile(`(?i)(ignore (all |the |your )?(previous|prior|above) (instructions|prompts?)|disregard (the|your|all) |you (are|must|should) now|system prompt|<\s*(system|instructions?)\s*>|do not (tell|inform|mention)|instead of|new instructions?:|act as|pretend to be|reveal (your|the) )`)

// Checks runs every MCP check over an enumeration and returns the findings, most severe first and
// stable within a severity so a report reads the same twice.
func Checks(en *Enumeration) []Finding {
	var out []Finding
	out = append(out, checkUnauthenticated(en)...)
	out = append(out, checkDangerousTools(en)...)
	out = append(out, checkNetworkTools(en)...)
	out = append(out, checkDescriptionInjection(en)...)
	out = append(out, checkReachableErrors(en)...)
	sort.SliceStable(out, func(i, j int) bool { return severityRank(out[i].Severity) > severityRank(out[j].Severity) })
	return out
}

func severityRank(s string) int {
	switch s {
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

// checkUnauthenticated: a server that handed over its whole tool/resource/prompt inventory without a
// credential is exposed to anyone who can reach it — the first thing an MCP audit asks.
func checkUnauthenticated(en *Enumeration) []Finding {
	if en.Authenticated {
		return nil
	}
	if len(en.Tools)+len(en.Resources)+len(en.Prompts) == 0 {
		return nil
	}
	return []Finding{{
		Name:       "MCP server enumerable without authentication",
		Severity:   "medium",
		Confidence: "firm",
		Description: fmt.Sprintf("The server completed the MCP handshake and listed %d tool(s), %d resource(s) and %d prompt(s) without any credential being presented. "+
			"Anyone who can reach this endpoint can enumerate and invoke its surface. If this server is meant to be reached only by an authenticated agent, it is missing that control.",
			len(en.Tools), len(en.Resources), len(en.Prompts)),
	}}
}

// checkDangerousTools: tools whose name or description names a dangerous capability. Reported low on
// its own (a tool named "run_query" may be entirely intended) but it is the inventory an operator
// needs — the over-broad-tool-exposure question.
func checkDangerousTools(en *Enumeration) []Finding {
	var out []Finding
	for _, t := range en.Tools {
		hit := dangerousCapabilityRe.FindString(t.Name + " " + t.Description)
		if hit == "" {
			continue
		}
		out = append(out, Finding{
			Name:       "MCP tool exposes a sensitive capability",
			Severity:   "low",
			Confidence: "tentative",
			Subject:    t.Name,
			Description: fmt.Sprintf("The tool %q is described in terms of a sensitive capability (%q). An agent that can be steered into calling it — by a prompt injection elsewhere in its context — "+
				"reaches whatever this tool can do. Confirm the tool is scoped to what the agent legitimately needs and cannot be driven with attacker-chosen arguments.", t.Name, strings.ToLower(hit)),
		})
	}
	return out
}

// checkNetworkTools: tools whose input schema or description names a URL/host parameter. These are the
// SSRF reach — a tool the agent can be told to point at http://169.254.169.254/ or an internal host.
func checkNetworkTools(en *Enumeration) []Finding {
	var out []Finding
	for _, t := range en.Tools {
		schema := strings.ToLower(string(t.InputSchema))
		if !networkParamRe.MatchString(schema) && !networkParamRe.MatchString(t.Description) {
			continue
		}
		out = append(out, Finding{
			Name:       "MCP tool takes a URL or host (SSRF reach)",
			Severity:   "medium",
			Confidence: "tentative",
			Subject:    t.Name,
			Description: fmt.Sprintf("The tool %q accepts a URL/host argument. A tool that fetches an operator- or agent-supplied address can be pointed at internal services or cloud metadata "+
				"(169.254.169.254), making it an SSRF primitive the agent itself can be induced to fire. Verify the tool restricts destinations to an allow-list and refuses internal and link-local addresses.", t.Name),
		})
	}
	return out
}

// checkDescriptionInjection: a tool/resource/prompt whose description carries an instruction aimed at
// the model. The description is fed to the agent verbatim, so an imperative there is a tool-poisoning
// payload — the MCP class that has no classic-web equivalent.
func checkDescriptionInjection(en *Enumeration) []Finding {
	var out []Finding
	report := func(kind, name, desc string) {
		if m := injectionMarkerRe.FindString(desc); m != "" {
			out = append(out, Finding{
				Name:       "MCP " + kind + " description contains agent-directed instructions",
				Severity:   "high",
				Confidence: "firm",
				Subject:    name,
				Description: fmt.Sprintf("The %s %q has a description that reads as an instruction to the agent (%q), not as documentation. An MCP client feeds these descriptions to the model, "+
					"so this is tool-poisoning: a server (or anyone who could edit its manifest) can redirect any agent that connects. Treat the description as untrusted and review why it is phrased this way.", kind, name, strings.TrimSpace(m)),
			})
		}
	}
	for _, t := range en.Tools {
		report("tool", t.Name, t.Description)
	}
	for _, r := range en.Resources {
		report("resource", r.Name, r.Description)
	}
	for _, p := range en.Prompts {
		report("prompt", p.Name, p.Description)
	}
	return out
}

// internalHostRe matches an internal, link-local or loopback address surfacing in a probe response —
// the strongest signal the scanner gets without live exploitation that a tool reached somewhere it
// should not have.
var internalHostRe = regexp.MustCompile(`(?i)(169\.254\.169\.254|metadata\.google|127\.0\.0\.1|localhost|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|\.internal\b|\.local\b|\.svc\b|ECONNREFUSED|dial tcp)`)

// checkReachableErrors: a probe whose response leaked an internal host or a connection error naming
// one. An empty-argument probe that comes back talking about 127.0.0.1 or ECONNREFUSED to an internal
// address is a tool actively reaching inward.
func checkReachableErrors(en *Enumeration) []Finding {
	var out []Finding
	for _, p := range en.Probes {
		if m := internalHostRe.FindString(p.Excerpt); m != "" {
			out = append(out, Finding{
				Name:       "MCP tool response references an internal host",
				Severity:   "medium",
				Confidence: "tentative",
				Subject:    p.Tool,
				Description: fmt.Sprintf("A representative call to %q returned content referencing an internal or link-local address (%q). The tool appears to reach internal infrastructure; "+
					"confirm whether its destination can be influenced by the caller, which would make it an SSRF vector.", p.Tool, m),
			})
		}
	}
	return out
}

// sortByDanger orders tools so the dangerous-capability ones come first, used to spend the probe
// budget where a finding is likeliest.
func sortByDanger(tools []Tool) {
	sort.SliceStable(tools, func(i, j int) bool {
		di := dangerousCapabilityRe.MatchString(tools[i].Name + " " + tools[i].Description)
		dj := dangerousCapabilityRe.MatchString(tools[j].Name + " " + tools[j].Description)
		return di && !dj
	})
}
