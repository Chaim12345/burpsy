package scanner

import (
	"context"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"go.uber.org/zap"
)

func TestCanaryTokenIsAlphanumericSoEncodersCannotMangleIt(t *testing.T) {
	l := NewStoredLedger()
	for range 200 {
		c, err := l.Plant(1, "/post", "comment")
		if err != nil {
			t.Fatalf("Plant: %v", err)
		}
		if !strings.HasPrefix(c.Token, storedCanaryPrefix) {
			t.Fatalf("token %q lacks the %q prefix that identifies scanner artefacts", c.Token, storedCanaryPrefix)
		}
		for _, r := range c.Token {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') {
				t.Fatalf("token %q contains %q; non-alnum bytes get re-encoded and the match is lost", c.Token, r)
			}
		}
	}
}

func TestEchoInTheSubmittingExchangeIsReflectionNotStorage(t *testing.T) {
	l := NewStoredLedger()
	c, _ := l.Plant(7, "/post", "comment")

	got := l.Observe(7, "/post", []byte("thanks for "+c.Token))
	if len(got) != 0 {
		t.Fatalf("Observe returned %d second-order sightings for an echo in the submitting exchange; reflection is not persistence", len(got))
	}

	state, known := l.State(c.Token)
	if !known {
		t.Fatal("ledger lost a canary it planted")
	}
	if state != StoredCanaryReflectedOnly {
		t.Fatalf("state = %v, want StoredCanaryReflectedOnly", state)
	}
}

func TestObservationInADifferentExchangeIsSecondOrder(t *testing.T) {
	l := NewStoredLedger()
	c, _ := l.Plant(7, "/post", "comment")

	got := l.Observe(9, "/moderation-queue", []byte("<li>"+c.Token+"</li>"))
	if len(got) != 1 {
		t.Fatalf("Observe returned %d sightings, want 1 for a token surfacing on another endpoint", len(got))
	}
	if got[0].SeenPath != "/moderation-queue" || got[0].Canary.OriginPath != "/post" {
		t.Fatalf("sighting lost its provenance: %+v", got[0])
	}
	if state, _ := l.State(c.Token); state != StoredCanaryStored {
		t.Fatalf("state = %v, want StoredCanaryStored", state)
	}
}

func TestReCasedTokenIsStillMatched(t *testing.T) {
	l := NewStoredLedger()
	c, _ := l.Plant(1, "/signup", "username")

	if got := l.Observe(2, "/admin/users", []byte(strings.ToUpper(c.Token))); len(got) != 1 {
		t.Fatalf("an uppercased token was not matched; applications routinely re-case stored input")
	}
}

// The property the primitive exists for: planted-and-unobserved must never be reported as
// a clean result, because it means the scan has not looked where the input landed.
func TestPlantedButUnobservedIsOutstandingNotClean(t *testing.T) {
	l := NewStoredLedger()
	c, _ := l.Plant(1, "/ticket", "subject")

	l.Observe(2, "/unrelated", []byte("nothing of interest here"))

	out := l.Outstanding()
	if len(out) != 1 || out[0].Token != c.Token {
		t.Fatalf("Outstanding() = %+v, want the one unobserved canary", out)
	}
	if state, _ := l.State(c.Token); state != StoredCanaryOutstanding {
		t.Fatalf("state = %v, want StoredCanaryOutstanding", state)
	}
	if len(l.SecondOrderObservations()) != 0 {
		t.Fatal("an unobserved canary produced a second-order sighting")
	}
}

func TestStateDistinguishesNeverPlantedFromUnobserved(t *testing.T) {
	l := NewStoredLedger()
	if _, known := l.State("bsyneverplanted"); known {
		t.Fatal("State claimed to know a token that was never planted")
	}
	c, _ := l.Plant(1, "/p", "q")
	if _, known := l.State(c.Token); !known {
		t.Fatal("State did not recognise a planted token")
	}
}

func TestSummarisePartitionsEveryPlantedCanary(t *testing.T) {
	l := NewStoredLedger()
	stored, _ := l.Plant(1, "/a", "p")
	reflected, _ := l.Plant(2, "/b", "p")
	l.Plant(3, "/c", "p") // left outstanding

	l.Observe(99, "/elsewhere", []byte(stored.Token))
	l.Observe(2, "/b", []byte(reflected.Token))

	s := l.Summarise()
	if s.Planted != 3 || s.Stored != 1 || s.ReflectedOnly != 1 || s.Outstanding != 1 {
		t.Fatalf("Summarise() = %+v, want 3 planted split 1/1/1", s)
	}
	if s.Stored+s.ReflectedOnly+s.Outstanding != s.Planted {
		t.Fatalf("buckets do not partition Planted: %+v", s)
	}
}

func TestOneCanaryObservedOnSeveralPagesKeepsEverySighting(t *testing.T) {
	l := NewStoredLedger()
	c, _ := l.Plant(1, "/post", "body")

	l.Observe(2, "/feed", []byte(c.Token))
	l.Observe(3, "/admin/log", []byte(c.Token))

	if got := l.SecondOrderObservations(); len(got) != 2 {
		t.Fatalf("kept %d sightings, want 2; each surfacing page is separate evidence", len(got))
	}
}

func TestPlantRefusesWhenEntropyIsUnavailable(t *testing.T) {
	l := NewStoredLedger()
	l.randRead = func([]byte) (int, error) { return 0, errNoEntropy }

	if _, err := l.Plant(1, "/p", "q"); err == nil {
		t.Fatal("Plant succeeded without entropy; a predictable canary can be forged by the target")
	}
	if l.PlantedCount() != 0 {
		t.Fatalf("a failed Plant recorded %d canaries, want 0", l.PlantedCount())
	}
}

// Several stored checks run against the same exchange, and each one would otherwise plant
// its own canaries into every insertion point. That is not just wasted traffic: the second
// planting overwrites the parameter values the first one is waiting to observe, so a canary
// that was going to surface elsewhere never does. Exactly one caller may plant per exchange.
func TestOnlyTheFirstCallerMayPlantIntoAnExchange(t *testing.T) {
	l := NewStoredLedger()

	if !l.ClaimPlanting(core.ExchangeID(7)) {
		t.Fatal("the first caller was refused the planting claim")
	}
	for i := range 3 {
		if l.ClaimPlanting(core.ExchangeID(7)) {
			t.Fatalf("caller %d also won the claim for exchange 7; every stored check would replant", i+2)
		}
	}

	// The guard is per exchange, not global — a different exchange is still plantable, or
	// only the first exchange of a scan would ever be tested.
	if !l.ClaimPlanting(core.ExchangeID(8)) {
		t.Fatal("a different exchange was refused; the guard is meant to be per exchange")
	}
}

// The wiring guard. This is the test whose absence let ten wired rows be permanently silent.
//
// PlantStoredCanaries and StoredLedger were both correct and both tested. What nobody asserted was
// that anything in the production audit path ever fed a response back to the ledger — and nothing
// did. ObserveStoredCanaries existed, was documented in two places as being called for every
// response a scan sees, and was reachable only from tests. Every stored row therefore counted as
// coverage while being incapable of reporting anything, which this project holds to be worse than
// an honest decline.
//
// The assertion is deliberately about the ENGINE, not the ledger: it audits an exchange through
// AuditWithin and requires the canary planted earlier to be seen. A unit test of the ledger cannot
// catch a missing call site.
func TestAuditingAnExchangeFeedsItToTheStoredLedger(t *testing.T) {
	store := core.NewTrafficStore()
	ledger := NewStoredLedger()

	// A canary planted while auditing some earlier endpoint.
	canary, err := ledger.Plant(core.ExchangeID(1), "/comment", "query")
	if err != nil {
		t.Fatalf("Plant: %v", err)
	}

	// A later exchange whose response carries that canary — the second-order sighting.
	surfaced := seedAuditExchange(t, store, "app.test", 80, "/feed",
		"<html><body><p>latest comment: "+canary.Token+"</p></body></html>")

	scan := NewActiveScanner(store, zap.NewNop()).
		WithStoredLedger(ledger).
		WithConfig(&ScanConfig{MaxConcurrency: 1, CheckStored: true})

	if before := ledger.SecondOrderObservations(); len(before) != 0 {
		t.Fatalf("ledger already held %d observations before the audit", len(before))
	}

	scan.AuditWithin(context.Background(), surfaced, DefaultAuditConfig())

	got := ledger.SecondOrderObservations()
	if len(got) == 0 {
		t.Fatal("auditing an exchange whose response carries a planted canary recorded no " +
			"second-order observation. The audit path is not feeding responses to the ledger, so every " +
			"stored row is wired, counted as coverage, and unable to report anything.")
	}
	var found bool
	for _, o := range got {
		if o.Canary.Token == canary.Token {
			found = true
			if o.SeenIn != surfaced {
				t.Errorf("observation attributed to exchange %d, want %d", o.SeenIn, surfaced)
			}
		}
	}
	if !found {
		t.Errorf("the planted token was not among the %d observation(s) recorded", len(got))
	}
}

var errNoEntropy = errStoredTest("no entropy")

type errStoredTest string

func (e errStoredTest) Error() string { return string(e) }

var _ = core.ExchangeID(0)
