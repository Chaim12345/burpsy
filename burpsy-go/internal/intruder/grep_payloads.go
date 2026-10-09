package intruder

import "bytes"

// Grep - Payloads (burpsy-react-ui-7qc3): "flag result items containing reflections of the submitted
// payload" (configure-attack/settings.html). burpsy has always asked this question of every attack —
// the reflected flag is a third of the bucket key — but as a fixed one: case-sensitive, headers
// included, matched against the payload as sent. Burp makes it four settings and a count column per
// payload set, and this is that.
//
// Ground truth, from the decompiled original:
//
//   - The panel (Zruj) persists payloadgrep.dogrep / casesensitive / excludeheaders /
//     matchpreencoded; its reset (Zruj.Zc5) is off / off / off / ON.
//   - The engine (Zu8d.Zb) keeps one count per payload set. For each set it fetches that set's payload
//     for the attempt — pre-encoding when matchpreencoded is on, as sent otherwise (Zw_x.Zl's third
//     argument is !matchpreencoded): one form or the other, never both — and counts its occurrences
//     in the response (Zmlq.ZY), from the body offset when exclude-headers is on and from 0 otherwise.
//   - The baseline row has no payload (Zsj.Zef() == -1) and keeps a zero in every column.

// GrepPayloads is the attack's Grep - Payloads configuration.
type GrepPayloads struct {
	// Enabled is "Search responses for payload strings". Off, no response is ever reflective and
	// there are no count columns; the bucket key's reflected slot is then always false.
	Enabled bool `json:"enabled"`
	// CaseSensitive is "Case sensitive match". Off folds ASCII letters only — a payload is a byte
	// string, and Unicode case folding can change a sequence's length, which a byte count must not.
	CaseSensitive bool `json:"case_sensitive"`
	// ExcludeHeaders is "Exclude HTTP headers": search from the first byte after the header block's
	// blank line. A response with no blank line is searched whole, as Burp does with no body offset.
	ExcludeHeaders bool `json:"exclude_headers"`
	// MatchPreURLEncoded is "Match against pre-URL-encoded payloads": search for the payload as it
	// was before "URL-encode these characters" rewrote it (URLEncodeSet), because "these are
	// normally decoded by the application and echoed in their original form". Off searches for the
	// bytes that were sent.
	MatchPreURLEncoded bool `json:"match_pre_url_encoded"`
}

// LegacyGrepPayloads is the reflection check every attack ran before the settings existed: on,
// case-sensitive, headers included, against the payload as sent. An API request that does not name
// grep_payloads keeps it, so no scripted attack's buckets change without the request saying so.
func LegacyGrepPayloads() GrepPayloads {
	return GrepPayloads{Enabled: true, CaseSensitive: true}
}

// maxReflectionsCounted caps one payload's count on one response, for the same reason
// MatchList.maxMatchesPerItem does: a response that echoes a short payload a million times must not
// make per-response counting a per-response cost without bound. Far above any real count.
const maxReflectionsCounted = 10_000

// reflectProbe is one payload set's contribution to an attempt: the set's index and its payload in
// both forms. pre is sent when the set had nothing URL-encoded.
type reflectProbe struct {
	set  int
	sent []byte
	pre  []byte
}

// WithGrepPayloads attaches the Grep - Payloads settings.
func (a *Attack) WithGrepPayloads(g GrepPayloads) *Attack {
	a.GrepPayloads = g
	return a
}

// prepareReflection materialises the pre-encoding payload bytes, once, before the first send — and
// only when the attack will read them: matching enabled, pre-encoded matching on, and a set whose
// URL-encoding actually changed something (PayloadSet.Unencoded is nil otherwise). Every other
// attack allocates nothing here.
func (a *Attack) prepareReflection() {
	a.setPreBytes = nil
	if !a.GrepPayloads.Enabled || !a.GrepPayloads.MatchPreURLEncoded {
		return
	}
	for i, s := range a.Sets {
		if len(s.Unencoded) != len(s.Items) || s.Unencoded == nil {
			continue
		}
		if a.setPreBytes == nil {
			a.setPreBytes = make([][][]byte, len(a.Sets))
		}
		a.setPreBytes[i] = make([][]byte, len(s.Unencoded))
		for j, it := range s.Unencoded {
			a.setPreBytes[i][j] = []byte(it)
		}
	}
}

// probe is the reflection probe for set s's payload p. The pre-encoding form falls back to the sent
// form when the set kept none — nothing in it was encoded, so the two are the same bytes.
func (a *Attack) probe(s, p int) reflectProbe {
	sent := a.setBytes[s][p]
	pre := sent
	if a.setPreBytes != nil && a.setPreBytes[s] != nil && p < len(a.setPreBytes[s]) {
		pre = a.setPreBytes[s][p]
	}
	return reflectProbe{set: s, sent: sent, pre: pre}
}

// reflection answers Grep - Payloads for one response: whether any set's payload came back, and how
// many times each set's payload occurs, one slot per payload set in set order. Disabled is (false,
// []). A set that contributed no payload to this attempt (the baseline row has none at all) counts 0.
// A set filling several positions with one payload — battering ram — is counted once: the column is
// per set, and summing per position would double the same occurrences.
func (a *Attack) reflection(raw []byte, probes []reflectProbe) (bool, []int) {
	g := a.GrepPayloads
	if !g.Enabled {
		return false, []int{}
	}
	counts := make([]int, len(a.Sets))
	if len(probes) == 0 {
		return false, counts
	}
	hay := raw
	if g.ExcludeHeaders {
		if i := bytes.Index(raw, []byte("\r\n\r\n")); i >= 0 {
			hay = raw[i+4:]
		}
	}
	counted := make([]bool, len(a.Sets))
	reflected := false
	for _, pr := range probes {
		if pr.set < 0 || pr.set >= len(counts) || counted[pr.set] {
			continue
		}
		counted[pr.set] = true
		needle := pr.sent
		if g.MatchPreURLEncoded {
			needle = pr.pre
		}
		n := countOccurrences(hay, needle, g.CaseSensitive)
		counts[pr.set] = n
		if n > 0 {
			reflected = true
		}
	}
	return reflected, counts
}

// countOccurrences counts non-overlapping occurrences of needle in hay, capped at
// maxReflectionsCounted. An empty needle occurs nowhere: a zero-length payload is not a reflection
// and must never make every response look reflective (containsBytes' rule). Case-insensitive
// matching folds ASCII letters only, without allocating a folded copy of the response.
func countOccurrences(hay, needle []byte, caseSensitive bool) int {
	n := len(needle)
	if n == 0 || len(hay) < n {
		return 0
	}
	count := 0
	if caseSensitive {
		for count < maxReflectionsCounted {
			i := bytes.Index(hay, needle)
			if i < 0 {
				break
			}
			count++
			hay = hay[i+n:]
		}
		return count
	}
	first := foldByte(needle[0])
	for i := 0; i <= len(hay)-n && count < maxReflectionsCounted; {
		if foldByte(hay[i]) == first && equalFoldASCII(hay[i:i+n], needle) {
			count++
			i += n
			continue
		}
		i++
	}
	return count
}

func foldByte(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}

func equalFoldASCII(a, b []byte) bool {
	for i := range a {
		if foldByte(a[i]) != foldByte(b[i]) {
			return false
		}
	}
	return true
}
