package sequencer

import (
	"math"
	"testing"
)

// The chi-square upper tail is the number an operator acts on, so it is checked
// against closed forms and published critical values rather than against
// itself. A wrong tail does not crash anything — it makes every extended test
// report a confident verdict computed from the wrong distribution, which is the
// failure mode this package exists to refuse.

// The chi-square distribution with two degrees of freedom is exponential with
// mean 2, so the tail is exactly exp(-x/2) for every x. This is the whole
// distribution, not an approximation, which makes it the strongest check
// available: it exercises both the series branch (small x) and the continued
// fraction (x >= a+1 = 2) and runs out to a tail far too deep for any table.
func TestChiSquareTailMatchesTheExponentialClosedFormAtTwoDegreesOfFreedom(t *testing.T) {
	for _, x := range []float64{0.5, 1, 2, 3.5, 10, 40, 200} {
		want := math.Exp(-x / 2)
		got := chiSquareUpperTail(x, 2)
		if math.Abs(got-want) > want*1e-12 {
			t.Errorf("chiSquareUpperTail(%g, 2) = %.17g, want exp(-x/2) = %.17g "+
				"(the two-degree-of-freedom tail IS the exponential tail; a disagreement means the "+
				"series and continued-fraction branches disagree about the same distribution)", x, got, want)
		}
	}
}

// With one degree of freedom the tail is erfc(sqrt(x/2)) exactly — the same
// quantity the standard normal table expresses.
func TestChiSquareTailMatchesTheErrorFunctionAtOneDegreeOfFreedom(t *testing.T) {
	for _, x := range []float64{0.25, 1, 3.841458820694124, 10, 100} {
		want := math.Erfc(math.Sqrt(x / 2))
		got := chiSquareUpperTail(x, 1)
		if math.Abs(got-want) > want*1e-12+1e-15 {
			t.Errorf("chiSquareUpperTail(%g, 1) = %.17g, want erfc(sqrt(x/2)) = %.17g", x, got, want)
		}
	}
}

// The 5% critical values, whatever the degrees of freedom and whichever branch
// the implementation took to get there. They are the published table values
// where the table is conventional, and the values were independently re-derived
// for this test from the closed forms and the P(a+1) recurrence rather than
// from this implementation.
func TestChiSquareTailLandsOnFivePercentAtCriticalValues(t *testing.T) {
	cases := []struct {
		df   int
		crit float64
	}{
		{1, 3.8414588206941254},
		{2, 5.991464547107983},
		{5, 11.070497693516351},
		{10, 18.30703805327515},
		{30, 43.77297182574219},
		{100, 124.3421134040041},
		// 2,047.5 is half of 4,095 — the largest table the spectral test can
		// build — so this is an a value the battery actually reaches, not a
		// number picked to be convenient.
		{4095, 4244.985307925495},
	}
	for _, tc := range cases {
		got := chiSquareUpperTail(tc.crit, tc.df)
		if math.Abs(got-0.05) > 1e-4 {
			t.Errorf("chiSquareUpperTail(%.10f, %d) = %.6g, want 0.05 (the critical value's own definition); "+
				"a tail that is wrong here gives every extended test the wrong significance verdict", tc.crit, tc.df, got)
		}
	}
}

// Degenerate inputs are answered rather than guessed. x <= 0 cannot be
// exceeded, df < 1 is a caller error that must not read as "not significant".
func TestChiSquareTailRefusesDegenerateInputs(t *testing.T) {
	if got := chiSquareUpperTail(0, 3); got != 1 {
		t.Errorf("chiSquareUpperTail(0, 3) = %g, want exactly 1 (a non-negative statistic cannot exceed zero)", got)
	}
	if got := chiSquareUpperTail(-1, 3); got != 1 {
		t.Errorf("chiSquareUpperTail(-1, 3) = %g, want exactly 1", got)
	}
	if got := chiSquareUpperTail(1, 0); !math.IsNaN(got) {
		t.Errorf("chiSquareUpperTail(1, 0) = %g, want NaN: one cell has no degrees of freedom, and 1.0 "+
			"would read as 'not significant' instead of 'you asked a meaningless question'", got)
	}
}

// The tail decreases in x, which is what makes "smaller p means more evidence
// against uniformity" true rather than merely conventional.
func TestChiSquareTailIsMonotoneInTheStatistic(t *testing.T) {
	previous := 1.1
	for x := 0.0; x <= 60; x += 0.25 {
		got := chiSquareUpperTail(x, 4)
		if got > previous {
			t.Fatalf("tail rose from %.17g to %.17g at x = %g; a larger statistic must be less likely, "+
				"or 'significant' becomes unreadable", previous, got, x)
		}
		previous = got
	}
}
