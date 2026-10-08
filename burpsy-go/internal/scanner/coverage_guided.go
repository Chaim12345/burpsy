package scanner

// Coverage-guided mutation for a remote target (burpsy-react-ui-6c90).
//
// gofuzz instruments the target binary and keeps the inputs that discover new basic
// blocks, mutating those first: coverage is the fitness function, and mutation effort
// flows toward whatever has historically opened new ground. burpsy's target is
// remote — it cannot be instrumented, and no model of its internals changes what a
// response can show. What a response CAN show is where the request landed: its
// status, and the shape of the body it produced. So the coverage signal here is the
// response space, and one (status, length-bucket) cell observed at a place is one
// code path of the target proven reachable.
//
// Two ledgers, one feedback loop:
//
//   - PathCoverage records every probe's response cell per exchange. It answers "what
//     has this scan already reached?" — the honest-counting half, in the same spirit
//     as CoverageTracker for the passive set.
//   - payloadGuide records, per place and payload, how many NEW cells that payload's
//     probes have opened. It answers the gofuzz question "which input do I mutate
//     next?" restated for a scanner: which payload goes first at a place that has
//     not answered yet.
//
// The guide never invents coverage. A payload is prioritised only on cells its own
// probes actually opened, and a place with no history gets its payload list exactly
// as written — the operator's order is a prior too, and reshuffling on no evidence
// would be the guide guessing.

import (
	"sort"
	"sync"

	"github.com/burpsy-go/burpsy/internal/bcheck"
)

// pathCell is one observable outcome of a target path: a response's status plus the
// magnitude bucket of its body length.
//
// Buckets are decimal magnitudes (0; 1-9; 10-99; …) rather than exact lengths, for
// the same reason the intruder engine buckets response_len: two bodies of 412 and
// 487 bytes are the same path for guidance purposes, while exact-length equality
// would make every probe "novel" and the signal would carry no information.
type pathCell struct {
	status int
	bucket int
}

// lengthBucket buckets a body length by decimal magnitude: 0 for an empty body, 1 for
// 1-9 bytes, 2 for 10-99, and so on. Negative lengths bucket as 0 — a length is a
// count, and the only honest bucket for a nonsensical one is "empty".
func lengthBucket(n int) int {
	if n <= 0 {
		return 0
	}
	b := 0
	for n > 0 {
		n /= 10
		b++
	}
	return b
}

// PathCoverage is the per-exchange record of which response cells the scan has
// observed. One instance per ActiveScanner; every probe path — the built-in checks
// through ProbeHarness and the BCheck corpus through bcheckSink — folds its
// responses into it.
//
// The zero value is NOT ready to use: NewActiveScanner installs one, and tests that
// build a scanner through it inherit the same ledger.
type PathCoverage struct {
	mu sync.RWMutex
	// cells maps exchangeID → the distinct cells observed for it. The key is the
	// exchange's own id: coverage is a statement about ONE request's probes, and
	// folding two exchanges together would let one endpoint's novelty pay for
	// another's.
	cells map[string]map[pathCell]struct{}
	// total is the number of distinct (exchange, cell) pairs — Cells.Len summed
	// across exchanges. Maintained incrementally so Total stays O(1) for reports.
	total int
}

func newPathCoverage() *PathCoverage {
	return &PathCoverage{cells: make(map[string]map[pathCell]struct{})}
}

// Record folds one probe's response into the table for one exchange.
//
// It returns novel=true exactly when this (exchange, cell) pair had never been
// observed before — the signal the payload guide scores on. A repeated cell is still
// recorded truthfully in the ledger's history (the set simply does not grow); only
// the novelty verdict distinguishes first sighting from confirmation.
func (c *PathCoverage) Record(exchangeID string, status, bodyLen int) (novel bool) {
	cell := pathCell{status: status, bucket: lengthBucket(bodyLen)}
	c.mu.Lock()
	defer c.mu.Unlock()
	set := c.cells[exchangeID]
	if set == nil {
		set = make(map[pathCell]struct{})
		c.cells[exchangeID] = set
	}
	if _, seen := set[cell]; seen {
		return false
	}
	set[cell] = struct{}{}
	c.total++
	return true
}

// Cells returns the sorted cells observed for one exchange, so a report is
// deterministic and two snapshots of the same coverage compare equal. A exchange
// with no recorded cells returns nil, not an empty slice: "never probed" and
// "probed, empty response" are different facts.
func (c *PathCoverage) Cells(exchangeID string) []pathCell {
	c.mu.RLock()
	defer c.mu.RUnlock()
	set := c.cells[exchangeID]
	if len(set) == 0 {
		return nil
	}
	out := make([]pathCell, 0, len(set))
	for cell := range set {
		out = append(out, cell)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].status != out[j].status {
			return out[i].status < out[j].status
		}
		return out[i].bucket < out[j].bucket
	})
	return out
}

// Total is the number of distinct (exchange, cell) pairs recorded across the scan —
// the scan's coverage count, honest in the sense that every one of them was actually
// observed by a probe.
func (c *PathCoverage) Total() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.total
}

// Exchanges is how many distinct exchanges have at least one recorded cell.
func (c *PathCoverage) Exchanges() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.cells)
}

// Snapshot returns an owned, point-in-time copy of the table for a report — the same
// shape as PassiveScanner.Coverage's owned report: a caller can hold it after the
// call returns instead of holding the lock while it renders.
type PathCoverageReport struct {
	// Exchanges is how many distinct exchanges have at least one recorded cell.
	Exchanges int `json:"exchanges"`
	// Cells is the number of distinct (exchange, cell) pairs — Total.
	Cells int `json:"cells"`
	// ByExchange maps each covered exchange to its distinct cell count, in the
	// table's own (sorted-by-id) order.
	ByExchange map[string]int `json:"by_exchange"`
}

// Snapshot copies the table. ByExchange is keyed by the exchange id string the
// ledger uses internally, so a caller rendering it can sort or translate ids without
// reaching back into the scanner.
func (c *PathCoverage) Snapshot() PathCoverageReport {
	c.mu.RLock()
	defer c.mu.RUnlock()
	by := make(map[string]int, len(c.cells))
	for id, set := range c.cells {
		by[id] = len(set)
	}
	return PathCoverageReport{Exchanges: len(c.cells), Cells: c.total, ByExchange: by}
}

// payloadGuide is the feedback half: which payloads have historically opened new
// response cells at which places.
//
// gofuzz keeps corpus entries that increased block coverage and mutates those
// first. The guide is that policy restated for a scanner's unit of mutation — a
// payload tried at a place — and a scanner's unit of budget — a request:
//
//	novelty[place, payload] = how many times a probe of that payload at that place
//	reached a response cell never seen there before.
//
// The zero value is NOT ready to use, matching PathCoverage: NewActiveScanner
// installs one.
type payloadGuide struct {
	mu      sync.Mutex
	novelty map[string]uint64 // place\x00payload → new cells opened
}

func newPayloadGuide() *payloadGuide {
	return &payloadGuide{novelty: make(map[string]uint64)}
}

// pointPlace is the guide's key for a place: host, then the point's kind, then its
// name. The host is in the key because the same parameter on two hosts is two
// applications' handling — the same reason pointEffectiveness includes it.
func pointPlace(host string, p bcheck.InsertionPoint) string {
	return host + "\x00" + string(p.Kind) + "\x00" + p.Name
}

// RecordOutcome notes one payload's outcome at one place.
//
// novel is the verdict PathCoverage returned for that probe: true when the response
// opened a cell never seen for that exchange. Empty payloads are skipped — the
// baseline and observation canaries are not candidate payloads to prioritise, they
// are the measurement apparatus. A non-novel probe updates nothing: repeating a
// known cell is confirmation, not discovery, and scoring it would teach the guide
// to re-send what it already knows.
func (g *payloadGuide) RecordOutcome(place, payload string, novel bool) {
	if !novel || payload == "" {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.novelty[place+"\x00"+payload]++
}

// Novelty reports how many new cells one payload has opened at one place. Zero
// means "never opened one" — which includes "never tried", and the two are not
// conflated here because Order treats both as no-prior and leaves the caller's list
// alone.
func (g *payloadGuide) Novelty(place, payload string) uint64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.novelty[place+"\x00"+payload]
}

// Order sorts a place's payload list so the payloads that have opened the most new
// cells at that place go first.
//
// Stable, and deliberately inert on a place with no history: payloads with equal
// novelty keep their relative order, and an untouched place gets the list back
// exactly as written. The operator's order is a prior — a check author who put the
// most diagnostic payload first knew something the ledger does not — and a guide
// that reshuffled on no evidence would be guessing while looking confident.
func (g *payloadGuide) Order(place string, payloads []string) []string {
	type scored struct {
		payload string
		novelty uint64
	}
	g.mu.Lock()
	out := make([]scored, len(payloads))
	for i, p := range payloads {
		out[i] = scored{payload: p, novelty: g.novelty[place+"\x00"+p]}
	}
	g.mu.Unlock()
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].novelty > out[j].novelty
	})
	res := make([]string, len(out))
	for i, s := range out {
		res[i] = s.payload
	}
	return res
}
