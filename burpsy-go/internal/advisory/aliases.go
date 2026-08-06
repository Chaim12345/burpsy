package advisory

// Aliases from burpsy's own check names to the catalogue's type indices.
//
// # Why an explicit table and not fuzzy matching
//
// burpsy names its checks after the *condition it tests for* ("Missing X-Frame-Options Header"),
// while the catalogue names issues after the *vulnerability class* ("Frameable response (potential
// Clickjacking)"). Those are different sentences about the same finding, and no string-similarity
// function reliably connects them — but plenty of functions will connect the wrong pair with high
// confidence. Attaching "Cookie manipulation (DOM-based)" to a missing-HttpOnly finding would put
// remediation advice in a report that does not address the finding, which is worse than leaving the
// advisory blank.
//
// So every mapping here is a decision someone made and can be argued with, keyed on the hexadecimal
// type index rather than on a name, because the index is what Burp itself treats as the identity.
//
// # What is deliberately absent
//
// Three of burpsy's checks have no catalogue equivalent and are listed in unmapped() with the reason.
// They keep their own description and remediation. A check missing from both tables resolves to no
// advisory at all, which the UI renders as the finding's own text — the honest outcome, and the same
// one an unmapped BCheck gets.
var aliases = map[string]int{
	// Header checks. burpsy tests for an absent header; the catalogue names the exposure that
	// absence creates.
	"missing x frame options header":        0x005009a0, // Frameable response (potential Clickjacking)
	"missing x content type options header": 0x00800500, // Content type is not specified

	// Cookie flags. The catalogue splits these by flag, and so does burpsy, so these are direct.
	"cookie missing httponly flag": 0x00500600, // Cookie without HttpOnly flag set
	"cookie missing secure flag":   0x00500200, // TLS cookie without secure flag set

	// Injection families. burpsy uses the umbrella name; the catalogue's reflected variant is the
	// one burpsy's reflected-payload check actually demonstrates.
	"cross site scripting xss": 0x00200100, // Cross-site scripting (reflected)
	"path traversal":           0x00100300, // File path traversal

	// JWT. burpsy suffixes some names with a requirement id; NormaliseName does not strip that, so
	// both spellings are mapped rather than relying on the caller to pass the clean one.
	"jwt none algorithm supported":             0x00200901,
	"jwt algorithm none":                       0x00200901,
	"jwt weak hmac secret":                     0x00200903,
	"jwt weak hmac secret scan 02":             0x00200903,
	"vulnerable javascript dependency":         0x00500080,
	"vulnerable javascript dependency scan 01": 0x00500080,
}

// unmapped records checks that intentionally have no catalogue entry, and why. Kept as code rather
// than a comment so the reasoning is greppable from the check name that prompted the question.
func unmapped() map[string]string {
	return map[string]string{
		"missing content security policy header": "The catalogue splits CSP into seven findings about a policy that exists and is weak " +
			"(allowlisted resources, allows clickjacking, malformed syntax, not enforced, …). None of them means " +
			"'no policy at all', which is what burpsy's check reports. Mapping to any one of them would claim a " +
			"specific weakness the check never looked for.",
		"cookie missing samesite flag": "The catalogue has no SameSite entry — it predates the attribute being a " +
			"standalone finding. Related but distinct entries exist for scope and HttpOnly; neither describes this.",
		"information disclosure password in response": "The catalogue's password entries are about submission " +
			"(cleartext submission, value set in cookie), not about a password appearing in a response body.",
	}
}

// Resolve finds the definition for a finding, by explicit alias first and by name second.
//
// Alias before name is deliberate. A burpsy check whose name happens to equal a catalogue name still
// goes through the alias table if one exists, so a mapping decision always beats a coincidence.
//
// The second return value distinguishes the two ways a lookup produces nothing: Unmapped carries the
// documented reason a check has no catalogue entry, so the UI can say "this check has no catalogue
// advisory because …" rather than showing an empty panel that looks like a loading failure.
func (c *Catalogue) Resolve(checkName string) (def *Definition, reason string) {
	if c == nil || checkName == "" {
		return nil, ""
	}
	key := NormaliseName(checkName)
	if idx, ok := aliases[key]; ok {
		if d, ok := c.ByIndex(idx); ok {
			return d, ""
		}
		// An alias pointing at an index the catalogue does not carry is a table bug, not a miss.
		return nil, "this check is mapped to an issue definition that is not in the loaded catalogue"
	}
	if d, ok := c.byName[key]; ok {
		return d, ""
	}
	if why, ok := unmapped()[key]; ok {
		return nil, why
	}
	return nil, ""
}
