package intruder

import "math"

// Attack shapes, generated lazily.
//
// # Why a plan is a function, not a list
//
// A cluster bomb over three 1,000-entry payload sets is a billion requests.
// Materialising that as a slice is not "a lot of memory", it is gigabytes of
// indices before a single byte has been sent — and the whole reason this project
// exists is that Burp's memory model does the moral equivalent and then sheds work
// when it runs out.
//
// So an AttackPlan stores only the *shape* of the attack: a mode, a position count,
// and the length of each payload set. Request i is derived arithmetically from i —
// mixed-radix decoding for cluster bomb, division for sniper — so the plan costs a
// few dozen bytes regardless of whether it describes 10 requests or 10^12, and any
// request can be reconstructed later from its ordinal alone. That last property is
// what lets attack *results* store an ordinal instead of a payload list.
//
// # Bounding
//
// The plan is constructed with an explicit maxRequests. Where it bites, Truncated
// says so and Combinations reports what the unbounded attack would have been. A cap
// the operator cannot see is a cap that silently turns "I tested every combination"
// into a lie.

// AttackKind is one of the four Burp attack shapes.
type AttackKind int

const (
	// AttackKindSniper attacks one position at a time, one payload set.
	// positions × payloads requests.
	AttackKindSniper AttackKind = iota
	// AttackKindBatteringRam puts the *same* payload in every position.
	// payloads requests.
	AttackKindBatteringRam
	// AttackKindPitchfork advances N sets in lockstep: request i uses set[j][i] at
	// position j. Stops at the shortest set.
	AttackKindPitchfork
	// AttackKindClusterBomb is the cartesian product of N sets.
	AttackKindClusterBomb
)

// String returns the canonical wire form.
func (k AttackKind) String() string {
	switch k {
	case AttackKindSniper:
		return "sniper"
	case AttackKindBatteringRam:
		return "battering_ram"
	case AttackKindPitchfork:
		return "pitchfork"
	case AttackKindClusterBomb:
		return "cluster_bomb"
	default:
		return "unknown"
	}
}

// MarshalJSON renders the attack kind as its wire string ("sniper", "cluster_bomb", …), matching
// the Rust serde snake_case form the web UI consumes in AttackReport.kind.
func (k AttackKind) MarshalJSON() ([]byte, error) {
	return []byte(`"` + k.String() + `"`), nil
}

// ParseAttackKind parses the wire form. It returns false for anything else — an
// unrecognised mode must be an error at the edge, never a silent fallback to sniper.
func ParseAttackKind(s string) (AttackKind, bool) {
	switch s {
	case "sniper":
		return AttackKindSniper, true
	case "battering_ram", "batteringram", "ram":
		return AttackKindBatteringRam, true
	case "pitchfork":
		return AttackKindPitchfork, true
	case "cluster_bomb", "clusterbomb":
		return AttackKindClusterBomb, true
	default:
		return 0, false
	}
}

// Slot is one payload landing in one position.
type Slot struct {
	// Point is the index into the caller's selected insertion points.
	Point int
	// Set is the index into the caller's payload sets.
	Set int
	// Payload is the index within that set.
	Payload int
}

// Assignment is one request's worth of work. Reused across iterations by
// AttackPlan.Fill: a 500k-request attack allocates this once.
type Assignment struct {
	Slots []Slot
}

// AttackPlan is the shape of an attack. It holds no requests and no payloads — just
// enough to derive request i.
type AttackPlan struct {
	kind         AttackKind
	points       int
	setLengths   []int
	setsUsed     int
	combinations uint64
	saturated    bool
	len          int
	maxRequests  int
}

// saturatingMul multiplies, capping at MaxUint64. The second return is true when the
// true product exceeds uint64. The Rust original counts in u128; a saturated uint64
// is indistinguishable from it through every observable surface (see Combinations).
func saturatingMul(a, b uint64) (uint64, bool) {
	if a == 0 || b == 0 {
		return 0, false
	}
	if a > math.MaxUint64/b {
		return math.MaxUint64, true
	}
	return a * b, false
}

// NewAttackPlan describes an attack over points positions and the given payload set
// lengths.
//
// Total by construction, so a caller cannot produce a panicking plan: a mode with no
// positions or an empty payload set simply plans zero requests. Rejecting nonsense
// input with a useful message is the edge's job, not this one's.
func NewAttackPlan(kind AttackKind, points int, setLens []int, maxRequests int) *AttackPlan {
	setsUsed := 0
	switch kind {
	// Both single-set modes read set 0 only; extra sets are the caller's business.
	case AttackKindSniper, AttackKindBatteringRam:
		if len(setLens) > 0 {
			setsUsed = 1
		}
	case AttackKindPitchfork, AttackKindClusterBomb:
		if points < len(setLens) {
			setsUsed = points
		} else {
			setsUsed = len(setLens)
		}
	}
	lens := setLens[:setsUsed]

	var combinations uint64
	var saturated bool
	switch kind {
	case AttackKindSniper:
		first := uint64(0)
		if len(lens) > 0 {
			first = uint64(lens[0])
		}
		combinations, saturated = saturatingMul(uint64(points), first)
	case AttackKindBatteringRam:
		if points == 0 {
			combinations = 0
		} else if len(lens) > 0 {
			combinations = uint64(lens[0])
		}
	case AttackKindPitchfork:
		combinations = uint64(0)
		for _, l := range lens {
			if uint64(l) < combinations || combinations == 0 {
				combinations = uint64(l)
			}
		}
	case AttackKindClusterBomb:
		combinations = 1
		for _, l := range lens {
			var over bool
			combinations, over = saturatingMul(combinations, uint64(l))
			if over {
				saturated = true
				break
			}
		}
	}

	length := combinations
	if uint64(maxRequests) < length {
		length = uint64(maxRequests)
	}
	return &AttackPlan{
		kind:         kind,
		points:       points,
		setLengths:   lens,
		setsUsed:     setsUsed,
		combinations: combinations,
		saturated:    saturated,
		len:          int(length),
		maxRequests:  maxRequests,
	}
}

// Kind returns the attack shape.
func (p *AttackPlan) Kind() AttackKind { return p.kind }

// Len returns the requests this plan will actually produce, after the bound.
func (p *AttackPlan) Len() int { return p.len }

// IsEmpty reports whether the plan produces no requests.
func (p *AttackPlan) IsEmpty() bool { return p.len == 0 }

// Combinations reports the requests the mode describes with no bound applied,
// saturating at MaxUint64. CombinationsExact says when the number is a floor.
func (p *AttackPlan) Combinations() uint64 { return p.combinations }

// CombinationsExact is false when Combinations saturated and is a lower bound.
func (p *AttackPlan) CombinationsExact() bool {
	return !p.saturated && p.combinations <= math.MaxUint64
}

// Truncated reports whether the bound cut the attack short.
func (p *AttackPlan) Truncated() bool { return p.combinations > uint64(p.len) }

// MaxRequests returns the bound the plan was constructed with.
func (p *AttackPlan) MaxRequests() int { return p.maxRequests }

// SetsUsed returns the payload sets this mode reads.
func (p *AttackPlan) SetsUsed() int { return p.setsUsed }

// setLens exposes the (sliced) set lengths; used by tests to show nothing was
// materialised.
func (p *AttackPlan) setLens() []int { return p.setLengths }

// Fill writes request i's payload placement into out, reusing its buffer. It returns
// false when i is past the end. Pure arithmetic: no state, so ordinals may be
// requested in any order, which is what lets a result row hold an ordinal and
// nothing else.
func (p *AttackPlan) Fill(i int, out *Assignment) bool {
	out.Slots = out.Slots[:0]
	if i >= p.len {
		return false
	}
	switch p.kind {
	case AttackKindSniper:
		n := p.setLengths[0]
		out.Slots = append(out.Slots, Slot{Point: i / n, Set: 0, Payload: i % n})
	case AttackKindBatteringRam:
		for pt := 0; pt < p.points; pt++ {
			out.Slots = append(out.Slots, Slot{Point: pt, Set: 0, Payload: i})
		}
	case AttackKindPitchfork:
		for j := range p.setLengths {
			out.Slots = append(out.Slots, Slot{Point: j, Set: j, Payload: i})
		}
	case AttackKindClusterBomb:
		// Mixed-radix decode with set 0 as the *fastest*-varying digit. With usernames
		// in set 0 and passwords in set 1 that means every username is tried against
		// password 1 before password 2 — a spray, which is the lockout-safe ordering.
		// The reverse ordering hammers one account with every password and locks it
		// out first.
		weight := 1
		for j, l := range p.setLengths {
			out.Slots = append(out.Slots, Slot{Point: j, Set: j, Payload: (i / weight) % l})
			// Saturating: once the weight exceeds any reachable i, i/weight is 0,
			// which is the correct digit anyway.
			weight = saturatingIntMul(weight, l)
		}
	}
	return true
}

// saturatingIntMul multiplies two ints, capping at MaxInt. The only consumer is the
// cluster-bomb weight, whose value beyond MaxInt is immaterial because i/weight is
// already 0 there.
func saturatingIntMul(a, b int) int {
	if a == 0 || b == 0 {
		return 0
	}
	if a > math.MaxInt/b {
		return math.MaxInt
	}
	return a * b
}

// planPair is one (point, payload) placement in a single-set attack.
type planPair struct {
	Point   int
	Payload int
}

// Plan flattens a sniper/battering-ram plan to (point, payload) pairs.
//
// Only meaningful for the two single-set modes: in pitchfork and cluster bomb a
// request is a *combination* of positions, which a pair cannot express — use
// AttackPlan directly. Battering ram reports math.MaxInt as the position because the
// payload goes in all of them. (The Rust original reports usize::MAX; Go's int is
// signed, so MaxInt is the closest sentinel.)
func Plan(points, payloads int, kind AttackKind) []planPair {
	p := NewAttackPlan(kind, points, []int{payloads}, math.MaxInt)
	var asg Assignment
	var out []planPair
	for i := 0; i < p.Len(); i++ {
		p.Fill(i, &asg)
		if len(asg.Slots) == 0 {
			continue
		}
		s := asg.Slots[0]
		if kind == AttackKindBatteringRam {
			out = append(out, planPair{Point: math.MaxInt, Payload: s.Payload})
		} else {
			out = append(out, planPair{Point: s.Point, Payload: s.Payload})
		}
	}
	return out
}
