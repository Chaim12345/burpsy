package scanner

// The credit-card detector must not read the fractional part of a decimal as a
// PAN: random metric output mints long digit runs whose Luhn checksum passes
// about one time in ten, which made the Tentative row appear and disappear
// between otherwise identical runs.

import "testing"

func TestCreditCardIgnoresDecimalFractions(t *testing.T) {
	// A real capture line whose fraction is Luhn-valid (this exact string
	// produced the row in one bench run and not the next two).
	body := `nodejs_gc_duration_seconds{app="juiceshop"} 0.010186612109289618`
	for _, d := range ScanDisclosures(body) {
		if d.Kind == DisclosureCreditCardNumber {
			t.Fatalf("a decimal fraction was reported as a credit card: %q", d.Match)
		}
	}
}

func TestCreditCardStillFiresOnAPAN(t *testing.T) {
	body := `{"order": {"card": "4532 0151 1283 0366", "cvv": "123"}}`
	found := false
	for _, d := range ScanDisclosures(body) {
		if d.Kind == DisclosureCreditCardNumber {
			found = true
		}
	}
	if !found {
		t.Fatal("a grouped PAN in card context was not reported")
	}
}
