package scanner

import (
	"sync"

	"github.com/burpsy-go/burpsy/internal/bcheck"
)

// pointEffectiveness is the per-point oracle behind Burp's
// `scanner/audit_optimization/skip_ineffective_checks` (burpsy-react-ui-y4om).
//
// Burp's gate is per INSERTION POINT, not per check: Zfhb.java:81-83 drops a point the
// engine cannot get an interesting response from, before its payloads are sent. The exact
// predicate Burp uses is not recoverable from the decompiled tree (Zc3c is two trivial
// cases; the interestingness is computed inside the point), so what is modelled here is the
// decision, honestly bounded: a point is dropped only when THIS RUN has already probed it
// enough times to have seen it inert.
//
// # Why the prior is per (kind, name, host) and not per point index
//
// A point is a place in a request, and the same parameter is reached on every re-dispatch of
// that item, every follow-up pass, and every other item that shares the URL. Keying by
// (kind, name, host) therefore recognises the same place across all of them, which is what
// makes the gate save anything at all; a per-index key would never fire, because a new
// dispatch is a new index. The host is in the key for the same reason the light-audit tier
// has it: the same parameter on two hosts is two applications' handling.
//
// # What the counting means
//
// A point with no prior is UNKNOWN and is probed — an unjudged place must be tested, and a
// gate that dropped unprobed points would report a target as clean because the engine chose
// not to look. After MinPointEffectivenessProbes PRIORS with nothing found, the point is
// judged ineffective. Raising the bound is the operator's lever; the default is low on
// purpose, because the cost of being wrong in either direction is asymmetric: a point
// dropped that would have found something is a false negative this project treats as the
// worse error, so the default sits at the smallest count that saves a measurable number of
// requests.
type pointEffectiveness struct {
	mu sync.Mutex
	// silent counts the priors found NOTHING, per place. Per PLACE, not per run: a run-wide
	// total would mean the first parameter that failed to answer silences every other
	// parameter on the target, which is a false negative dressed as a saving.
	silent map[string]int
	// answered records the places that have answered something, which are retired from the
	// gate permanently. A place in this map is never counted, never dropped.
	answered map[string]bool
}

// MinPointEffectivenessProbes is how many priors with nothing found a point needs before the
// gate drops it.
//
// Two, so a point is always probed at least twice before being judged: one probe that finds
// nothing says the payload set was wrong, not that the point is inert, and the second is what
// makes the judgement a fact about the point rather than about one guess.
const MinPointEffectivenessProbes = 2

func newPointEffectiveness() *pointEffectiveness {
	return &pointEffectiveness{
		silent:   make(map[string]int),
		answered: make(map[string]bool),
	}
}

// key is the (kind, name, host) identity of a place. An unnamed place — the entire body, a
// synthesised header — falls back to its kind, because there is no parameter name to tell
// two of them apart and the kind is then the honest identity.
func (pe *pointEffectiveness) key(check, kind, name, host string) string {
	if name == "" {
		name = "\x00" + kind
	}
	return check + "\x00" + kind + "\x00" + name + "\x00" + host
}

// effective reports whether p should be probed. A point with any recorded evidence is
// effective by definition — it has already answered something, which is the only ground this
// gate will ever stand on. A point with fewer than MinPointEffectivenessProbes priors is
// unjudged and therefore probed.
//
// The predicate is nil-safe in the sense that matters to callers: it never consults anything
// outside its own ledger, so a context built without a run simply has no ledger and the gate
// is never installed.
func (pe *pointEffectiveness) effective(check string, p bcheck.InsertionPoint, host string) bool {
	pe.mu.Lock()
	defer pe.mu.Unlock()
	k := pe.key(check, string(p.Kind), p.Name, host)
	if pe.answered == nil {
		// A zero ledger has answered nothing, so every place is unjudged and therefore
		// probed. Reading nil as "nothing to skip" is what makes the zero value safe to
		// embed in a run without a constructor call.
		return true
	}
	if pe.answered[k] {
		// A place that has answered is effective whatever its history, and a place that has
		// answered is retired from the count below so a later silent probe cannot re-earn it.
		return true
	}
	return pe.silent[k] < MinPointEffectivenessProbes
}

// record notes one probe on p and whether it found anything. evidence=true retires the point
// permanently as effective: a parameter that has answered a differential, an error signature,
// an out-of-band callback or a timing signal is never dropped by this gate, however many inert
// siblings it has.
func (pe *pointEffectiveness) record(check string, p bcheck.InsertionPoint, host string, evidence bool) {
	pe.mu.Lock()
	defer pe.mu.Unlock()
	k := pe.key(check, string(p.Kind), p.Name, host)
	if pe.answered == nil {
		pe.answered = make(map[string]bool)
	}
	if pe.silent == nil {
		pe.silent = make(map[string]int)
	}
	if evidence {
		pe.answered[k] = true
		delete(pe.silent, k)
		return
	}
	if !pe.answered[k] {
		pe.silent[k]++
	}
}

// Count is how many priors have been recorded with nothing found — the run's own evidence
// for the gate, surfaced so a report can say why points were dropped rather than leaving the
// operator to infer it from a smaller request count.
func (pe *pointEffectiveness) Count() int {
	pe.mu.Lock()
	defer pe.mu.Unlock()
	total := 0
	for _, n := range pe.silent {
		total += n
	}
	return total
}
