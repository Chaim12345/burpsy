package scanner

// Second-order input correlation: plant a token at endpoint A, find it at endpoint B.
// PriorExchange only gives same-endpoint history, which cannot express that.

import (
	"crypto/rand"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
)

// Alphanumeric only: every other byte class gets mangled by HTML/JSON/URL encoders,
// and a mangled token reads as "not vulnerable".
const (
	storedCanaryAlphabet     = "abcdefghijklmnopqrstuvwxyz0123456789"
	storedCanaryPrefix       = "bsy"
	storedCanaryEntropyChars = 13
)

type StoredCanaryState int

const (
	// Planted and never seen. Not a clean result: we have not looked where it landed.
	StoredCanaryOutstanding StoredCanaryState = iota
	// Echoed by the submitting response only. Reflection, not persistence.
	StoredCanaryReflectedOnly
	StoredCanaryStored
)

func (s StoredCanaryState) Label() string {
	switch s {
	case StoredCanaryOutstanding:
		return "planted, not yet observed"
	case StoredCanaryReflectedOnly:
		return "reflected in the submitting response only"
	case StoredCanaryStored:
		return "observed in a later, different exchange"
	}
	return "unknown"
}

type StoredCanary struct {
	Token          string
	Origin         core.ExchangeID
	OriginPath     string
	InsertionPoint string
	PlantedAt      time.Time
}

type StoredObservation struct {
	Canary   StoredCanary
	SeenIn   core.ExchangeID
	SeenPath string
	SeenAt   time.Time
	Offset   int
}

func (o StoredObservation) IsSecondOrder() bool { return o.SeenIn != o.Canary.Origin }

type storedEntry struct {
	canary       StoredCanary
	observations []StoredObservation
}

func (e *storedEntry) state() StoredCanaryState {
	for _, o := range e.observations {
		if o.IsSecondOrder() {
			return StoredCanaryStored
		}
	}
	if len(e.observations) > 0 {
		return StoredCanaryReflectedOnly
	}
	return StoredCanaryOutstanding
}

type StoredLedger struct {
	mu      sync.RWMutex
	entries map[string]*storedEntry
	order   []string
	// plantedIn records exchanges already planted, so several stored checks auditing one
	// exchange do not each plant a fresh set of canaries into the same parameters.
	plantedIn map[core.ExchangeID]struct{}

	now      func() time.Time
	randRead func([]byte) (int, error)
}

func NewStoredLedger() *StoredLedger {
	return &StoredLedger{
		entries:   make(map[string]*storedEntry),
		plantedIn: make(map[core.ExchangeID]struct{}),
		now:       time.Now,
		randRead:  rand.Read,
	}
}

// Plant records before the send: a submission that times out may still have been stored.
func (l *StoredLedger) Plant(origin core.ExchangeID, originPath, insertionPoint string) (StoredCanary, error) {
	token, err := l.mintToken()
	if err != nil {
		return StoredCanary{}, err
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if _, exists := l.entries[token]; exists {
		return StoredCanary{}, fmt.Errorf("stored ledger: token %q already planted", token)
	}

	canary := StoredCanary{
		Token:          token,
		Origin:         origin,
		OriginPath:     originPath,
		InsertionPoint: insertionPoint,
		PlantedAt:      l.now(),
	}
	l.entries[token] = &storedEntry{canary: canary}
	l.order = append(l.order, token)
	return canary, nil
}

func (l *StoredLedger) mintToken() (string, error) {
	buf := make([]byte, storedCanaryEntropyChars)
	if _, err := l.randRead(buf); err != nil {
		return "", fmt.Errorf("stored ledger: cannot mint canary: %w", err)
	}
	var sb strings.Builder
	sb.Grow(len(storedCanaryPrefix) + storedCanaryEntropyChars)
	sb.WriteString(storedCanaryPrefix)
	for _, b := range buf {
		sb.WriteByte(storedCanaryAlphabet[int(b)%len(storedCanaryAlphabet)])
	}
	return sb.String(), nil
}

// Observe returns only second-order sightings; reflections are recorded but not returned.
// Case-insensitive because applications routinely re-case stored input.
func (l *StoredLedger) Observe(seenIn core.ExchangeID, seenPath string, body []byte) []StoredObservation {
	if len(body) == 0 {
		return nil
	}
	haystack := strings.ToLower(string(body))
	at := l.now()

	l.mu.Lock()
	defer l.mu.Unlock()

	var secondOrder []StoredObservation
	for _, token := range l.order {
		entry := l.entries[token]
		if entry == nil {
			continue
		}
		idx := strings.Index(haystack, token)
		if idx < 0 {
			continue
		}
		obs := StoredObservation{
			Canary:   entry.canary,
			SeenIn:   seenIn,
			SeenPath: seenPath,
			SeenAt:   at,
			Offset:   idx,
		}
		entry.observations = append(entry.observations, obs)
		if obs.IsSecondOrder() {
			secondOrder = append(secondOrder, obs)
		}
	}
	return secondOrder
}

// State's second return distinguishes "planted, unobserved" from "never planted".
func (l *StoredLedger) State(token string) (StoredCanaryState, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	entry, ok := l.entries[strings.ToLower(token)]
	if !ok {
		return StoredCanaryOutstanding, false
	}
	return entry.state(), true
}

// Outstanding is input we put in the target and have not found again. Reporting it as
// clean would claim completeness the scan has not earned.
func (l *StoredLedger) Outstanding() []StoredCanary {
	l.mu.RLock()
	defer l.mu.RUnlock()
	var out []StoredCanary
	for _, token := range l.order {
		if entry := l.entries[token]; entry != nil && entry.state() == StoredCanaryOutstanding {
			out = append(out, entry.canary)
		}
	}
	return out
}

func (l *StoredLedger) SecondOrderObservations() []StoredObservation {
	l.mu.RLock()
	defer l.mu.RUnlock()
	var out []StoredObservation
	for _, token := range l.order {
		entry := l.entries[token]
		if entry == nil {
			continue
		}
		for _, o := range entry.observations {
			if o.IsSecondOrder() {
				out = append(out, o)
			}
		}
	}
	return out
}

// Tokens returns every canary the scan has planted, in planting order.
//
// Deliberately not Outstanding(): a browser looking for stored input has to ask about canaries
// that already surfaced over plain HTTP too. A value the raw response carries AND a script also
// feeds to a sink is two different findings, and filtering to the unseen ones would silence the
// second whenever the first happened to fire.
func (l *StoredLedger) Tokens() []string {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return append([]string(nil), l.order...)
}

// CanaryFor resolves a token back to the canary record, so an observer holding only the matched
// string can say which exchange planted it.
func (l *StoredLedger) CanaryFor(token string) (StoredCanary, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	entry, ok := l.entries[strings.ToLower(token)]
	if !ok || entry == nil {
		return StoredCanary{}, false
	}
	return entry.canary, true
}

// CanariesFrom returns the canaries one exchange planted.
//
// Scoping matters here: the ledger is scan-wide, so a check asking "did anything I planted get
// anywhere" must ask about its own plantings. Answering from the whole ledger is the bleed that
// once let one vulnerable endpoint's sighting satisfy every later stored audit, safe ones included.
func (l *StoredLedger) CanariesFrom(origin core.ExchangeID) []StoredCanary {
	l.mu.RLock()
	defer l.mu.RUnlock()
	var out []StoredCanary
	for _, token := range l.order {
		if entry := l.entries[token]; entry != nil && entry.canary.Origin == origin {
			out = append(out, entry.canary)
		}
	}
	return out
}

func (l *StoredLedger) PlantedCount() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.order)
}

type StoredCoverageSummary struct {
	Planted       int
	Stored        int
	ReflectedOnly int
	Outstanding   int
}

// Planted == Stored + ReflectedOnly + Outstanding.
func (l *StoredLedger) Summarise() StoredCoverageSummary {
	l.mu.RLock()
	defer l.mu.RUnlock()
	s := StoredCoverageSummary{Planted: len(l.order)}
	for _, token := range l.order {
		entry := l.entries[token]
		if entry == nil {
			continue
		}
		switch entry.state() {
		case StoredCanaryStored:
			s.Stored++
		case StoredCanaryReflectedOnly:
			s.ReflectedOnly++
		case StoredCanaryOutstanding:
			s.Outstanding++
		}
	}
	return s
}

// ClaimPlanting reports whether the caller is the first to plant into this exchange. The
// second and later callers get false and must not plant again.
func (l *StoredLedger) ClaimPlanting(id core.ExchangeID) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.plantedIn == nil {
		l.plantedIn = make(map[core.ExchangeID]struct{})
	}
	if _, done := l.plantedIn[id]; done {
		return false
	}
	l.plantedIn[id] = struct{}{}
	return true
}
