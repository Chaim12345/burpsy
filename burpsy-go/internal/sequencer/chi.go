package sequencer

// The chi-square upper-tail probability, which is what turns an observed
// statistic into the one thing an operator can act on: how likely a sample this
// skewed is if the source really is uniform.
//
// The package deliberately went without this for a long time. `ChiSquare` in
// sequencer.go reports a raw character-uniformity statistic and says, in its
// own doc, that it is NOT a p-value and carries no degrees-of-freedom verdict,
// because inventing a test's distribution is how a tool ends up printing a
// confident number that means nothing. That refusal still holds for the raw
// statistic. What follows is the distribution itself, written out rather than
// assumed, so the extended tests can have a verdict without their verdict being
// a guess.
//
// P(chi2_df > x) = Q(df/2, x/2), the regularized upper incomplete gamma
// function, evaluated by the standard series / continued-fraction split
// (Abramowitz & Stegun 6.5.29 and 6.5.31; the implementation follows the
// classic Numerical Recipes gser/gcf pair). The series converges quickly for
// x < a+1 and the continued fraction for x >= a+1, so each branch is used where
// it is stable rather than one formula forced to cover both.

import "math"

// chiSquareUpperTail returns P(X > x) for X ~ chi-square with df degrees of
// freedom.
//
// x <= 0 returns 1: no non-negative chi-square statistic can exceed a
// non-positive value. df < 1 returns NaN, which is a programming error at the
// call site — a contingency table with one cell has no degrees of freedom and
// no caller here should ever reach this with one. NaN is chosen over 1.0 so
// that such a call cannot quietly read as "not significant".
func chiSquareUpperTail(x float64, df int) float64 {
	if df < 1 {
		return math.NaN()
	}
	if x <= 0 {
		return 1
	}
	return regularizedGammaQ(float64(df)/2, x/2)
}

// regularizedGammaQ returns Q(a, x) = 1 - P(a, x), the regularized upper
// incomplete gamma function, for a > 0 and x >= 0.
func regularizedGammaQ(a, x float64) float64 {
	if a <= 0 || x < 0 {
		return math.NaN()
	}
	if x == 0 {
		return 1
	}
	if x < a+1 {
		return 1 - gammaSeriesP(a, x)
	}
	return gammaContinuedFractionQ(a, x)
}

// gammaSeriesP evaluates P(a, x) by its series expansion,
//
//	P(a, x) = x^a e^-x / Gamma(a) * sum_{n>=0} x^n / (a(a+1)...(a+n))
//
// which converges quickly for x < a+1 and loses precision to cancellation for
// larger x — hence the split in regularizedGammaQ.
func gammaSeriesP(a, x float64) float64 {
	lg, _ := math.Lgamma(a)
	ap := a
	sum := 1 / a
	del := sum
	for n := 0; n < maxGammaIterations; n++ {
		ap++
		del *= x / ap
		sum += del
		if math.Abs(del) < math.Abs(sum)*gammaEpsilon {
			break
		}
	}
	return sum * math.Exp(-x+a*math.Log(x)-lg)
}

// gammaContinuedFractionQ evaluates Q(a, x) by its continued fraction via the
// modified Lentz algorithm, the stable form for x >= a+1.
func gammaContinuedFractionQ(a, x float64) float64 {
	const tiny = 1e-300
	lg, _ := math.Lgamma(a)
	b := x + 1 - a
	c := 1 / tiny
	d := 1 / b
	h := d
	for i := 1; i <= maxGammaIterations; i++ {
		an := -float64(i) * (float64(i) - a)
		b += 2
		d = an*d + b
		if math.Abs(d) < tiny {
			d = tiny
		}
		c = b + an/c
		if math.Abs(c) < tiny {
			c = tiny
		}
		d = 1 / d
		del := d * c
		h *= del
		if math.Abs(del-1) < gammaEpsilon {
			break
		}
	}
	return math.Exp(-x+a*math.Log(x)-lg) * h
}

const (
	// maxGammaIterations bounds both branches. The series needs O(sqrt(a))
	// terms and the continued fraction converges in a similar number for the
	// a values this package reaches (a is half a degrees-of-freedom count, so
	// at most a few thousand for the largest tuplet table the battery builds).
	maxGammaIterations = 2000
	// gammaEpsilon is the relative convergence tolerance. float64 carries ~1e-16
	// of relative precision; asking for much less than that only burns terms.
	gammaEpsilon = 1e-14
)
