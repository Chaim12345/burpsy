package mcpscan

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// The MCP-specific checks (burpsy-react-ui-wflj). Each reads the Enumeration and yields findings; none
// sends traffic (enumeration and the operator's probes already did), so they are pure and unit-tested.
//
// What they can see is the server's metadata — names, schemas, descriptions, server instructions — plus
// the outcomes of the probes the operator asked for. They catch the classes that live in that data:
// unauthenticated exposure, instructions aimed at the model, invisible characters, a tool that takes a
// URL or host, an inventory of sensitive capabilities, and a probe answer naming an internal host. They
// do not claim what needs live exploitation (driving a tool with crafted arguments), and every
// phrase-matching check is "tentative" because a regular expression cannot read intent.

// Finding is one MCP-target finding, mapped by the web layer onto core.NewFinding.
type Finding struct {
	Name        string
	Severity    string // "info" | "low" | "medium" | "high"
	Confidence  string // "tentative" | "firm" | "certain"
	Description string
	// Subject is "<kind> <name>" of the tool/resource/prompt the finding is about, "" for a server-wide
	// one. It is part of the finding's merge identity, so re-scanning a server does not pile up copies.
	Subject string
	// Evidence is the matched text, bounded.
	Evidence string
}

// dangerousCapabilityRe matches the words a tool's name or description uses when it can touch the file
// system, run a command, reach the network or handle secrets. Matched against a normalised text in
// which snake_case, kebab-case and camelCase names are split into words.
var dangerousCapabilityRe = regexp.MustCompile(`(?i)\b(exec|execute|shell|command|cmd|bash|powershell|eval|spawn|subprocess|run code|read file|write file|delete|unlink|rm|filesystem|directory|sql|database|fetch|curl|download|upload|proxy|socket|kubernetes|kubectl|docker|secret|secrets|credential|credentials|password|environment)\b`)

// networkParamRe matches an input-schema property name that names a URL or host.
var networkParamRe = regexp.MustCompile(`(?i)^(url|uri|urls|link|href|host|hostname|endpoint|webhook|callback|domain|base url|target url|server url|ip|ip address)$`)

// injectionMarkerRe matches phrasings a tool-poisoning payload uses to redirect the model reading a
// description: the description is fed to the model verbatim, so an imperative aimed at it is an
// instruction, not documentation.
var injectionMarkerRe = regexp.MustCompile(`(?i)(ignore (all |any |the |your )?(previous|prior|above|earlier) (instructions|prompts?|messages?)|disregard (the|your|all|any) (previous|prior|above|instructions|rules)|you (are|must|should) now|<\s*/?\s*(system|instructions?|important)\s*>|do not (tell|inform|mention|reveal|show) (this |it )?(to )?the user|without (telling|informing|asking) the user|new instructions?:|pretend (to be|you are)|reveal (your|the) (system prompt|instructions)|before (using|calling) (this|any) tool,? (you must |always )?(read|send|call|include|pass))`)

// invisibleRe matches characters that render as nothing but are read by a model: zero-width
// characters, bidirectional controls and the Unicode tag block, the known carriers for instructions
// hidden from a human reviewing the same text.
var invisibleRe = regexp.MustCompile(`[\x{200B}-\x{200F}\x{202A}-\x{202E}\x{2060}-\x{2064}\x{2066}-\x{2069}\x{FEFF}\x{E0000}-\x{E007F}]`)

// Checks runs every MCP check over an enumeration and returns the findings, most severe first and
// stable within a severity so a report reads the same twice.
func Checks(en *Enumeration) []Finding {
	var out []Finding
	out = append(out, checkUnauthenticated(en)...)
	texts := metadataTexts(en)
	out = append(out, checkDescriptionInjection(texts)...)
	out = append(out, checkInvisibleText(texts)...)
	out = append(out, checkNetworkTools(en)...)
	out = append(out, checkDangerousTools(en)...)
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

const unauthName = "MCP server enumerable without authentication"

// checkUnauthenticated: a server that handed over its inventory with no credential is exposed to anyone
// who can reach it. Two ways to know: the scan carried no credential and listed something, or it
// carried one and the repeated handshake without it listed tools anyway.
func checkUnauthenticated(en *Enumeration) []Finding {
	if !en.Authenticated {
		if len(en.Tools)+len(en.Resources)+len(en.Prompts) == 0 {
			return nil
		}
		return []Finding{{
			Name: unauthName, Severity: "medium", Confidence: "firm",
			Description: fmt.Sprintf("The server completed the MCP handshake and listed %d tool(s), %d resource(s) and %d prompt(s) without any credential being presented. "+
				"Anyone who can reach this endpoint can enumerate its surface and attempt to invoke it. If the server is meant to be reached only by an authenticated agent, it is missing that control.",
				len(en.Tools), len(en.Resources), len(en.Prompts)),
		}}
	}
	if en.AuthCheck != nil && en.AuthCheck.State == AuthNotEnforced && en.AuthCheck.ToolsListed > 0 {
		return []Finding{{
			Name: unauthName, Severity: "medium", Confidence: "firm",
			Description: "The scan was given a credential, and the server accepted it — but the same handshake repeated without the credential also succeeded. " +
				en.AuthCheck.Detail + ". The credential is not what controls access to this server.",
		}}
	}
	return nil
}

// metadataText is one piece of server-supplied text a client feeds to its model.
type metadataText struct {
	kind, name, field, text string
}

// metadataTexts collects every description-like string the server supplied.
func metadataTexts(en *Enumeration) []metadataText {
	var out []metadataText
	if en.Instructions != "" {
		out = append(out, metadataText{"server", en.Server.Name, "instructions", en.Instructions})
	}
	for _, t := range en.Tools {
		out = append(out, metadataText{"tool", t.Name, "description", t.Description})
		if t.Title != "" {
			out = append(out, metadataText{"tool", t.Name, "title", t.Title})
		}
		for _, d := range schemaDescriptions(t.InputSchema) {
			out = append(out, metadataText{"tool", t.Name, "input schema description", d})
		}
	}
	for _, r := range en.Resources {
		out = append(out, metadataText{"resource", r.Name, "description", r.Description})
	}
	for _, p := range en.Prompts {
		out = append(out, metadataText{"prompt", p.Name, "description", p.Description})
		for _, a := range p.Arguments {
			out = append(out, metadataText{"prompt", p.Name, "argument " + a.Name + " description", a.Description})
		}
	}
	return out
}

// schemaDescriptions returns every "description" string in a JSON schema, depth- and count-bounded.
// Parameter descriptions are as model-visible as the tool's own and are where tool-poisoning payloads
// have been hidden.
func schemaDescriptions(schema json.RawMessage) []string {
	if len(schema) == 0 {
		return nil
	}
	var v any
	if json.Unmarshal(schema, &v) != nil {
		return nil
	}
	var out []string
	var walk func(any, int)
	walk = func(n any, depth int) {
		if depth > 8 || len(out) >= 200 {
			return
		}
		switch x := n.(type) {
		case map[string]any:
			for k, val := range x {
				if s, ok := val.(string); ok && k == "description" && s != "" {
					out = append(out, s)
					continue
				}
				walk(val, depth+1)
			}
		case []any:
			for _, val := range x {
				walk(val, depth+1)
			}
		}
	}
	walk(v, 0)
	sort.Strings(out)
	return out
}

func subject(kind, name string) string { return kind + " " + name }

// checkDescriptionInjection: server-supplied text that reads as an instruction to the model. High
// severity because the class is tool poisoning — any agent that connects can be redirected — but
// tentative, because a phrase match cannot tell a payload from a documentation sentence that happens
// to use the same words.
func checkDescriptionInjection(texts []metadataText) []Finding {
	var out []Finding
	seen := map[string]bool{}
	for _, mt := range texts {
		m := injectionMarkerRe.FindString(mt.text)
		if m == "" {
			continue
		}
		key := mt.kind + "\x00" + mt.name
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, Finding{
			Name:       fmt.Sprintf("MCP %s metadata contains agent-directed instructions", mt.kind),
			Severity:   "high",
			Confidence: "tentative",
			Subject:    subject(mt.kind, mt.name),
			Evidence:   excerpt(mt.text),
			Description: fmt.Sprintf("The %s %q has a %s that reads as an instruction to the model (%q), not as documentation. An MCP client passes this text to its model, "+
				"so an imperative here can redirect any agent that connects (tool poisoning). Review why the text is phrased this way and who can change it.",
				mt.kind, mt.name, mt.field, strings.TrimSpace(m)),
		})
	}
	return out
}

// checkInvisibleText: server-supplied text containing characters a human reviewer cannot see but a
// model reads. Their presence is a fact (firm); what they encode is for the operator to decode.
func checkInvisibleText(texts []metadataText) []Finding {
	var out []Finding
	seen := map[string]bool{}
	for _, mt := range texts {
		hits := invisibleRe.FindAllString(mt.text, -1)
		if len(hits) == 0 {
			continue
		}
		key := mt.kind + "\x00" + mt.name
		if seen[key] {
			continue
		}
		seen[key] = true
		var cps []string
		for i, h := range hits {
			if i == 5 {
				cps = append(cps, "…")
				break
			}
			cps = append(cps, fmt.Sprintf("U+%04X", []rune(h)[0]))
		}
		out = append(out, Finding{
			Name:       fmt.Sprintf("MCP %s metadata contains invisible Unicode characters", mt.kind),
			Severity:   "medium",
			Confidence: "firm",
			Subject:    subject(mt.kind, mt.name),
			Evidence:   strings.Join(cps, " "),
			Description: fmt.Sprintf("The %s of %s %q contains %d invisible character(s) (%s). These render as nothing to a person reviewing the server, "+
				"but a model reads them, which makes them a carrier for instructions hidden from review. Decode the characters and remove them.",
				mt.field, mt.kind, mt.name, len(hits), strings.Join(cps, " ")),
		})
	}
	return out
}

// checkNetworkTools: tools whose input schema takes a URL or host — the SSRF reach an agent can be
// induced to fire. Read from top-level property names and string formats, not free text, so an
// "email address" field does not count.
func checkNetworkTools(en *Enumeration) []Finding {
	var out []Finding
	for _, t := range en.Tools {
		param := networkParam(t.InputSchema)
		if param == "" {
			continue
		}
		out = append(out, Finding{
			Name:       "MCP tool takes a URL or host argument",
			Severity:   "low",
			Confidence: "tentative",
			Subject:    subject("tool", t.Name),
			Evidence:   param,
			Description: fmt.Sprintf("The tool %q accepts a URL or host argument (%q). A tool that reaches an address its caller supplies can be pointed at internal services or "+
				"cloud metadata (169.254.169.254), which makes it an SSRF primitive an agent can be induced to fire. Verify it restricts destinations to an allow-list and refuses internal and link-local addresses.",
				t.Name, param),
		})
	}
	return out
}

// networkParam returns the first top-level property that names a URL or host, "" when none does.
func networkParam(schema json.RawMessage) string {
	var s struct {
		Properties map[string]struct {
			Format string `json:"format"`
		} `json:"properties"`
	}
	if len(schema) == 0 || json.Unmarshal(schema, &s) != nil {
		return ""
	}
	names := make([]string, 0, len(s.Properties))
	for name := range s.Properties {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		switch strings.ToLower(s.Properties[name].Format) {
		case "uri", "url", "iri", "uri-reference", "hostname", "idn-hostname", "ipv4", "ipv6":
			return name
		}
		if networkParamRe.MatchString(normaliseName(name)) {
			return name
		}
	}
	return ""
}

// checkDangerousTools: tools named or described in terms of a sensitive capability. Informational
// inventory, not a vulnerability: a tool named run_query may be exactly what the server is for. It is
// the over-broad-exposure question an operator needs answered, so it is listed — at "info".
func checkDangerousTools(en *Enumeration) []Finding {
	var out []Finding
	for _, t := range en.Tools {
		hit := dangerousCapabilityRe.FindString(normaliseName(t.Name) + " " + t.Description)
		if hit == "" {
			continue
		}
		destructive := ""
		if t.Annotations != nil && t.Annotations.DestructiveHint != nil && *t.Annotations.DestructiveHint {
			destructive = " The server itself annotates it destructiveHint: true."
		}
		out = append(out, Finding{
			Name:       "MCP tool exposes a sensitive capability",
			Severity:   "info",
			Confidence: "tentative",
			Subject:    subject("tool", t.Name),
			Evidence:   strings.ToLower(hit),
			Description: fmt.Sprintf("The tool %q is named or described in terms of a sensitive capability (%q).%s An agent that can be steered into calling it — by a prompt injection elsewhere in its context — "+
				"reaches whatever this tool can do. Confirm the tool is scoped to what the agent legitimately needs.", t.Name, strings.ToLower(hit), destructive),
		})
	}
	return out
}

// internalHostRe matches an internal, link-local or loopback address, or a connection error naming one,
// in a probe answer.
var internalHostRe = regexp.MustCompile(`(?i)(169\.254\.169\.254|metadata\.google\.internal|\b127\.0\.0\.1\b|\blocalhost\b|\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b|\b192\.168\.\d{1,3}\.\d{1,3}\b|\b172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b|\.internal\b|\.svc\.cluster\.local\b|ECONNREFUSED)`)

// checkReachableErrors: a probe whose answer names an internal host — the strongest signal available
// without driving the tool that it reaches inward.
func checkReachableErrors(en *Enumeration) []Finding {
	var out []Finding
	for _, p := range en.Probes {
		m := internalHostRe.FindString(p.Excerpt)
		if m == "" {
			continue
		}
		out = append(out, Finding{
			Name:       "MCP tool response references an internal host",
			Severity:   "low",
			Confidence: "tentative",
			Subject:    subject("tool", p.Tool),
			Evidence:   p.Excerpt,
			Description: fmt.Sprintf("A call to %q with empty arguments returned content naming an internal, loopback or link-local address (%q). The tool appears to reach internal infrastructure; "+
				"establish whether its destination can be influenced by the caller, which would make it an SSRF vector.", p.Tool, m),
		})
	}
	return out
}

// normaliseName splits snake_case, kebab-case, dotted and camelCase identifiers into lower-case words,
// so a word-boundary pattern can see "run_shell" and "readFile" as "run shell" and "read file".
func normaliseName(s string) string {
	var b strings.Builder
	prevLower := false
	for _, r := range s {
		switch {
		case r == '_' || r == '-' || r == '.' || r == '/':
			b.WriteByte(' ')
			prevLower = false
			continue
		case r >= 'A' && r <= 'Z':
			if prevLower {
				b.WriteByte(' ')
			}
			b.WriteRune(r + ('a' - 'A'))
			prevLower = false
			continue
		}
		b.WriteRune(r)
		prevLower = (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
	}
	return b.String()
}
