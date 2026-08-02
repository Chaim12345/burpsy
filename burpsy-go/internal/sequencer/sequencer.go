// Package sequencer implements token randomness analysis.
// Adapted from the Rust burpsy-sequencer crate (entropy, chi-square,
// serial correlation, Monte Carlo pi estimation, character analysis).
package sequencer

import (
	"math"
	"sort"
	"strings"
	"sync"
)

// TokenList is a collected set of tokens to analyse.
type TokenList struct {
	mu     sync.Mutex
	tokens []string
}

func NewTokenList() *TokenList { return &TokenList{} }

// Collect appends one token.
func (tl *TokenList) Collect(token string) {
	tl.mu.Lock()
	tl.tokens = append(tl.tokens, token)
	tl.mu.Unlock()
}

// CollectAll appends multiple tokens.
func (tl *TokenList) CollectAll(tokens []string) {
	tl.mu.Lock()
	tl.tokens = append(tl.tokens, tokens...)
	tl.mu.Unlock()
}

// Tokens returns a copy of the collected tokens.
func (tl *TokenList) Tokens() []string {
	tl.mu.Lock()
	defer tl.mu.Unlock()
	out := make([]string, len(tl.tokens))
	copy(out, tl.tokens)
	return out
}

// Count returns the number of collected tokens.
func (tl *TokenList) Count() int { tl.mu.Lock(); defer tl.mu.Unlock(); return len(tl.tokens) }

// ---- Character-level analysis ----

// CharStats holds per-character frequency statistics.
type CharStats struct {
	Counts  map[rune]int
	Total   int
	Charset string
}

// AnalyseCharacters computes character frequencies across all tokens.
func AnalyseCharacters(tokens []string) CharStats {
	cs := CharStats{Counts: make(map[rune]int)}
	seen := make(map[rune]struct{})
	for _, tok := range tokens {
		for _, c := range tok {
			cs.Counts[c]++
			cs.Total++
			seen[c] = struct{}{}
		}
	}
	chars := make([]string, 0, len(seen))
	for c := range seen {
		chars = append(chars, string(c))
	}
	sort.Strings(chars)
	cs.Charset = strings.Join(chars, "")
	return cs
}

// ShannonEntropy computes the Shannon entropy (bits per symbol) from a CharStats.
func ShannonEntropy(cs CharStats) float64 {
	if cs.Total == 0 {
		return 0
	}
	var ent float64
	for _, cnt := range cs.Counts {
		p := float64(cnt) / float64(cs.Total)
		if p > 0 {
			ent -= p * math.Log2(p)
		}
	}
	return ent
}

// Reliability rates entropy: Excellent / Good / Fair / Poor.
type Rating int

const (
	Excellent Rating = iota
	Good
	Fair
	Poor
)

func (r Rating) String() string {
	switch r {
	case Excellent:
		return "Excellent"
	case Good:
		return "Good"
	case Fair:
		return "Fair"
	default:
		return "Poor"
	}
}

// RateEntropy maps a bits-per-symbol value to a rating.
func RateEntropy(entropy float64, charsetSize int) Rating {
	if charsetSize == 0 {
		return Poor
	}
	maxEnt := math.Log2(float64(charsetSize))
	ratio := entropy / maxEnt
	switch {
	case ratio >= 0.95:
		return Excellent
	case ratio >= 0.80:
		return Good
	case ratio >= 0.60:
		return Fair
	default:
		return Poor
	}
}

// ---- Statistical tests ----

// ChiSquare computes the chi-square statistic for character uniformity.
// A larger value means the distribution is less uniform (less random).
func ChiSquare(cs CharStats) float64 {
	if cs.Total == 0 || len(cs.Counts) == 0 {
		return 0
	}
	expected := float64(cs.Total) / float64(len(cs.Counts))
	if expected == 0 {
		return 0
	}
	var chi float64
	for _, cnt := range cs.Counts {
		diff := float64(cnt) - expected
		chi += diff * diff / expected
	}
	return chi
}

// SerialCorrelation computes the serial correlation coefficient for
// a sequence of byte/code values. Returns a value in [-1, 1]; random
// data should be close to 0.
func SerialCorrelation(values []int) float64 {
	if len(values) < 2 {
		return 0
	}
	var sum, sumSq, cross float64
	n := float64(len(values))
	for i := 0; i < len(values); i++ {
		v := float64(values[i])
		sum += v
		sumSq += v * v
	}
	mean := sum / n
	for i := 0; i < len(values)-1; i++ {
		cross += (float64(values[i]) - mean) * (float64(values[i+1]) - mean)
	}
	denom := sumSq - sum*sum/n
	if denom == 0 {
		return 0
	}
	return cross / denom
}

// MonteCarloPi estimates pi using pairs of random-looking values.
// Returns the estimated value and the deviation from actual pi.
func MonteCarloPi(values []float64) (piEst, deviation float64) {
	if len(values) < 2 {
		return 0, math.Pi
	}
	n := len(values) / 2
	if n == 0 {
		return 0, math.Pi
	}
	inside := 0
	for i := 0; i < n; i++ {
		x, y := values[2*i], values[2*i+1]
		if x*x+y*y <= 1.0 {
			inside++
		}
	}
	piEst = 4.0 * float64(inside) / float64(n)
	deviation = math.Abs(piEst - math.Pi)
	return
}

// ---- Pattern detection ----

// Patterns reports repeated sequences or substrings in the token set.
type Patterns struct {
	Repeated     int // tokens that are exact duplicates
	RepeatedList []string
}

// DetectPatterns finds exact duplicates.
func DetectPatterns(tokens []string) Patterns {
	seen := make(map[string]int)
	for _, tok := range tokens {
		seen[tok]++
	}
	p := Patterns{}
	for tok, n := range seen {
		if n > 1 {
			p.Repeated++
			p.RepeatedList = append(p.RepeatedList, tok)
		}
	}
	return p
}

// ---- Full analysis ----

// Analysis combines all tests into one result.
type Analysis struct {
	SampleCount    int
	CharsetSize    int
	Entropy        float64
	GoodnessRating Rating
	ChiSquare      float64
	SerialCorr     float64
	MonteCarloPi   float64
	MonteCarloDev  float64
	RepeatedTokens int
}

// Analyse runs the full statistical suite on a token list.
func Analyse(tl *TokenList) Analysis {
	tokens := tl.Tokens()
	cs := AnalyseCharacters(tokens)
	ent := ShannonEntropy(cs)
	// Flatten all characters into rune codes for serial correlation.
	var codes []int
	for _, tok := range tokens {
		for _, c := range tok {
			codes = append(codes, int(c))
		}
	}
	var piValues []float64
	for _, c := range codes {
		piValues = append(piValues, float64(c)/256.0)
	}
	pi, dev := MonteCarloPi(piValues)
	pats := DetectPatterns(tokens)
	return Analysis{
		SampleCount:    tl.Count(),
		CharsetSize:    len(cs.Counts),
		Entropy:        ent,
		GoodnessRating: RateEntropy(ent, len(cs.Counts)),
		ChiSquare:      ChiSquare(cs),
		SerialCorr:     SerialCorrelation(codes),
		MonteCarloPi:   pi,
		MonteCarloDev:  dev,
		RepeatedTokens: pats.Repeated,
	}
}
