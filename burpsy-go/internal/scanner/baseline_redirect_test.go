package scanner

import "testing"

// A 4-character code is data; only a bare acknowledgement is not.
func TestShortCodeIsDataAcknowledgementIsNot(t *testing.T) {
	if bodyCarriesNoData("A1B2") {
		t.Error(`"A1B2" read as no data: a short code a privileged identity was shown`)
	}
	if !bodyCarriesNoData(" OK ") {
		t.Error(`"OK" read as data`)
	}
}

// A redirect answering a write is a served form post: the verdict is drawn from it. The same
// baseline on a read stays Ambiguous.
func TestRedirectBaselineIsAReferenceForWritesOnly(t *testing.T) {
	same := NewBaselineSample(302, "Location: /orders/7\n", 0)
	base, err := CalibrateBaseline([]BaselineSample{same, same, same})
	if err != nil {
		t.Fatal(err)
	}
	th := DefaultDeviationThreshold()
	th.TimingSigma = 1e9
	if d := base.DiffAccessControl("POST", same, th); d.Ambiguous || !d.Matched {
		t.Errorf("POST, same redirect: %+v, want Matched", d)
	}
	if d := base.DiffAccessControl("POST", NewBaselineSample(302, "Location: /login\n", 0), th); d.Ambiguous || d.Matched {
		t.Errorf("POST, bounced to /login: %+v, want not matched", d)
	}
	if d := base.DiffAccessControl("GET", same, th); !d.Ambiguous {
		t.Errorf("GET against a redirected baseline: %+v, want Ambiguous", d)
	}
}
