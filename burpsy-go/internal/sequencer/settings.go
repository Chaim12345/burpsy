package sequencer

import (
	"fmt"
	"sort"
	"strings"
)

// Settings is Burp's Sequencer analysis configuration, keyed exactly as Burp keys it
// (burpsy-react-ui-nm81): the nine sequencer.token_analysis.* switches (Zsiz.java:177-186) and
// sequencer.token_handling.base_64_decode_before_analyzing. Burp's panel title says what they are
// for — "Use these settings to control the types of analysis performed by Burp Sequencer" — and that
// is what they do here: an analysis that does not name its own tests runs the ones these leave on.
//
// # Why the keys are Burp's names and not burpsy's test ids
//
// The point of carrying Burp's keys is that an operator can read a Burp configuration and know what
// it means here, and tell a colleague which tests a shared verdict rests on in the vocabulary both
// tools use. AnalysisTests is the one table that maps each key to the test it switches, so the two
// names cannot drift apart.
type Settings struct {
	// TokenAnalysis maps every token_analysis key to whether that analysis runs. Always carries all
	// nine keys once normalised, so a reader never has to know which absent key means "on".
	TokenAnalysis map[string]bool `json:"token_analysis"`
	TokenHandling TokenHandling   `json:"token_handling"`
}

// TokenHandling is sequencer.token_handling.*.
type TokenHandling struct {
	// Base64DecodeBeforeAnalyzing is Burp's "Base64-decode before analyzing", off by default as it is
	// in Burp: decoding is a claim about the token's alphabet the operator makes, not one to assume.
	Base64DecodeBeforeAnalyzing bool `json:"base_64_decode_before_analyzing"`
}

// CountBurpKey is sequencer.token_analysis.count — Burp's character-level count analysis.
//
// It is readable and stays on: in burpsy the per-position character count is the base
// characterisation every other result is read against (the effective-entropy figure and both
// batteries' sample description come from it), not a separable test with its own verdict row. A
// switch that accepted "off" and changed nothing would be a control that lies, so "off" is refused
// with that reason instead.
const CountBurpKey = "count"

// DefaultSettings is Burp's default: every analysis on, base64 decoding off.
func DefaultSettings() Settings {
	ta := map[string]bool{CountBurpKey: true}
	for _, t := range AnalysisTests {
		ta[t.BurpKey] = true
	}
	return Settings{TokenAnalysis: ta}
}

// SettingsKeys lists every token_analysis key, sorted — what a refusal names as the accepted set.
func SettingsKeys() []string {
	keys := []string{CountBurpKey}
	for _, t := range AnalysisTests {
		keys = append(keys, t.BurpKey)
	}
	sort.Strings(keys)
	return keys
}

// Normalise fills every key a stored document lacks with its default and drops keys this build does
// not know. A document saved before a key existed therefore reads as that analysis running — the
// behaviour it had when it was saved — rather than as a silent "off" from a missing map entry.
func (s Settings) Normalise() Settings {
	out := DefaultSettings()
	for k, v := range s.TokenAnalysis {
		if _, known := out.TokenAnalysis[k]; known {
			out.TokenAnalysis[k] = v
		}
	}
	// count cannot be off; a stored false (hand-edited, or from Burp) reads as on rather than failing
	// the load, because Apply is where an operator's edit is refused and a load is not an edit.
	out.TokenAnalysis[CountBurpKey] = true
	out.TokenHandling = s.TokenHandling
	return out
}

// SettingsEdit is a partial update: only the keys present change.
type SettingsEdit struct {
	TokenAnalysis map[string]bool `json:"token_analysis"`
	TokenHandling struct {
		Base64DecodeBeforeAnalyzing *bool `json:"base_64_decode_before_analyzing"`
	} `json:"token_handling"`
}

// Apply merges an edit onto s. An unknown key is refused naming the accepted set — a key that was
// silently dropped would leave the operator believing a test was off while it still ran — and so is
// switching count off, for the reason CountBurpKey states. Nothing changes when an error is returned.
func (s Settings) Apply(edit SettingsEdit) (Settings, error) {
	next := s.Normalise()
	for k, v := range edit.TokenAnalysis {
		key := strings.TrimSpace(k)
		if key == CountBurpKey {
			if !v {
				return s, fmt.Errorf("token_analysis.count cannot be switched off: the character count is " +
					"the base characterisation every other result is read against, not a separate test")
			}
			continue
		}
		if _, ok := AnalysisTestByBurpKey(key); !ok {
			return s, fmt.Errorf("unknown token_analysis key %q; the keys are %s",
				key, strings.Join(SettingsKeys(), ", "))
		}
		next.TokenAnalysis[key] = v
	}
	if b := edit.TokenHandling.Base64DecodeBeforeAnalyzing; b != nil {
		next.TokenHandling.Base64DecodeBeforeAnalyzing = *b
	}
	return next, nil
}

// DisabledTests is the disable list these settings imply, as AnalysisTest ids in a stable order — the
// form Options.DisabledTests takes.
func (s Settings) DisabledTests() []string {
	var out []string
	for _, t := range AnalysisTests {
		if on, present := s.TokenAnalysis[t.BurpKey]; present && !on {
			out = append(out, t.ID)
		}
	}
	return out
}
