package intruder

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
)

// Ports burpsy-intruder::engine's test suite (engine.rs:577-1452).

// basePoints stores raw, finds its insertion points, and hands back the raw bytes plus them.
func basePoints(t *testing.T, raw string) ([]byte, []InsertionPoint) {
	t.Helper()
	m := storeReq(t, raw)
	pts := FindPoints(m, DefaultPointConfig())
	return m.Raw(), pts
}

// sets builds payload sets from string lists.
func sets(rows ...[]string) []PayloadSet {
	out := make([]PayloadSet, len(rows))
	for i, r := range rows {
		out[i] = itemSet(r)
	}
	return out
}

// itemSet wraps strings as a resolved payload set, all bounds reported exact.
func itemSet(items []string) PayloadSet {
	return PayloadSet{Kind: "list", Items: items, Count: len(items), Total: uint64(len(items)), TotalExact: true}
}

// numItems builds n payloads named by the format string.
func numItems(n int, format string) PayloadSet {
	items := make([]string, n)
	for i := range items {
		items[i] = fmt.Sprintf(format, i)
	}
	return itemSet(items)
}

// recordingSender answers instantly and records every request it was given.
func recordingSender(seen *[][]byte, mu *sync.Mutex, body string) SendFn {
	return func(raw []byte) (Sent, error) {
		mu.Lock()
		*seen = append(*seen, append([]byte(nil), raw...))
		mu.Unlock()
		return Sent{Raw: []byte(body), Duration: time.Millisecond, Status: ptr(200)}, nil
	}
}

// requestLines returns each recorded request's first line, \r stripped like str::lines.
func requestLines(seen [][]byte) []string {
	var out []string
	for _, b := range seen {
		line := string(b)
		if i := bytes.IndexByte(b, '\n'); i >= 0 {
			line = string(b[:i])
		}
		out = append(out, strings.TrimSuffix(line, "\r"))
	}
	return out
}

func re(p string) *regexp.Regexp { return regexp.MustCompile(p) }

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}

// varyingSender responds with the same status and same length for every payload, so the bucket key
// cannot tell responses apart — which is the point of the grep tests below.
func varyingSender() SendFn {
	return func(raw []byte) (Sent, error) {
		if bytes.Contains(raw, []byte("a=admin")) {
			return Sent{Raw: []byte("HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nrole=ADMIN."),
				Duration: time.Millisecond, Status: ptr(200)}, nil
		}
		return Sent{Raw: []byte("HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nrole=user.."),
			Duration: time.Millisecond, Status: ptr(200)}, nil
	}
}

// ---- the guard -----------------------------------------------------------------------------
//
// The attack this defends against: the operator's scope excludes /admin, the host-level check
// authorises the host anyway, and a payload spliced into a path position then rewrites the
// request onto the excluded path. Nothing upstream ever sees that request.

func TestPayloadThatRewritesThePathOutOfScopeIsNeverSent(t *testing.T) {
	// A filename position, which is exactly what lets a payload move the path.
	m := storeReq(t, "GET /search HTTP/1.1\r\nHost: shop.test\r\n\r\n")
	pts := FindPoints(m, AllPointConfig())
	var sel []InsertionPoint
	for _, p := range pts {
		if p.Kind == PointURLPathFilename {
			sel = append(sel, p)
		}
	}
	if len(sel) != 1 {
		t.Fatalf("expected one filename position in /search, got %d", len(sel))
	}

	payloads := sets([]string{"products", "admin", "help"})
	plan := NewAttackPlan(AttackKindSniper, 1, []int{3}, 1_000)
	var seen [][]byte
	var mu sync.Mutex

	// Stand-in for the real scope predicate: /admin is excluded.
	guard := func(raw []byte) error {
		shape, err := core.Parse(raw, core.DirectionRequest)
		if err != nil {
			return err
		}
		target := shape.SecondToken
		path := string(raw[target.Offset:min(target.End(), len(raw))])
		if strings.HasPrefix(path, "/admin") {
			return fmt.Errorf("refused: %s is out of scope", path)
		}
		return nil
	}

	a := NewAttack(m.Raw(), sel, payloads, plan).
		WithLimits(Unthrottled(4)).
		WithGuard(guard)
	r := Run(a, recordingSender(&seen, &mu, "HTTP/1.1 200 OK\r\n\r\nok"), nil)

	mu.Lock()
	sent := requestLines(seen)
	mu.Unlock()
	for _, line := range sent {
		if strings.Contains(line, "/admin") {
			t.Fatalf("an out-of-scope request reached the sender: %v", sent)
		}
	}
	if r.Sent != 2 {
		t.Fatalf("sent = %d, want the two in-scope payloads", r.Sent)
	}
	if r.Failed != 1 {
		t.Fatalf("failed = %d, want the refused one counted, not dropped silently", r.Failed)
	}
}

func TestARefusalIsReportedWithItsReason(t *testing.T) {
	// A refusal the operator cannot see is indistinguishable from a target that said nothing.
	base, pts := basePoints(t, "GET /?a=1 HTTP/1.1\r\nHost: t.test\r\n\r\n")
	sel := pts[:1]
	payloads := sets([]string{"x"})
	plan := NewAttackPlan(AttackKindSniper, 1, []int{1}, 10)
	var seen [][]byte
	var mu sync.Mutex

	guard := func([]byte) error { return fmt.Errorf("refused: out of scope") }
	a := NewAttack(base, sel, payloads, plan).WithLimits(Unthrottled(2)).WithGuard(guard)
	r := Run(a, recordingSender(&seen, &mu, "HTTP/1.1 200 OK\r\n\r\nok"), nil)

	if r.Sent != 0 {
		t.Fatalf("sent = %d, want 0", r.Sent)
	}
	if r.Failed != 1 {
		t.Fatalf("failed = %d, want 1", r.Failed)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 0 {
		t.Fatalf("nothing may reach the sender, saw %d", len(seen))
	}
	found := false
	for _, e := range r.Errors {
		if strings.Contains(e.Error, "out of scope") {
			found = true
		}
	}
	if !found {
		t.Fatalf("the reason must survive into the report: %+v", r.Errors)
	}
}

// ---- attack shapes -------------------------------------------------------------------------

func TestPitchforkSendsOneRequestPerLockstepPair(t *testing.T) {
	base, pts := basePoints(t, "GET /?a=1&b=2 HTTP/1.1\r\nHost: t.test\r\n\r\n")
	sel := pts[:2]
	payloads := sets([]string{"u1", "u2", "u3"}, []string{"p1", "p2"})
	plan := NewAttackPlan(AttackKindPitchfork, 2, []int{3, 2}, 1_000)
	var seen [][]byte
	var mu sync.Mutex

	a := NewAttack(base, sel, payloads, plan).WithLimits(Unthrottled(4))
	r := Run(a, recordingSender(&seen, &mu, "HTTP/1.1 200 OK\r\n\r\nok"), nil)

	if r.Sent != 2 {
		t.Fatalf("sent = %d, want the 2-entry set to end the attack", r.Sent)
	}
	mu.Lock()
	got := requestLines(seen)
	mu.Unlock()
	sortStrings(got)
	want := []string{"GET /?a=u1&b=p1 HTTP/1.1", "GET /?a=u2&b=p2 HTTP/1.1"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("pitchfork must pair set members by index, not cross them: %v", got)
	}
}

func TestClusterBombSendsEveryCombination(t *testing.T) {
	base, pts := basePoints(t, "GET /?a=1&b=2 HTTP/1.1\r\nHost: t.test\r\n\r\n")
	sel := pts[:2]
	payloads := sets([]string{"x", "y"}, []string{"1", "2", "3"})
	plan := NewAttackPlan(AttackKindClusterBomb, 2, []int{2, 3}, 1_000)
	var seen [][]byte
	var mu sync.Mutex

	a := NewAttack(base, sel, payloads, plan).WithLimits(Unthrottled(4))
	r := Run(a, recordingSender(&seen, &mu, "HTTP/1.1 200 OK\r\n\r\nok"), nil)

	if r.Sent != 6 {
		t.Fatalf("sent = %d, want 6", r.Sent)
	}
	if r.Combinations != 6 {
		t.Fatalf("combinations = %d, want 6", r.Combinations)
	}
	if r.Truncated {
		t.Fatal("6 under a 1000 bound is not truncated")
	}
	mu.Lock()
	got := requestLines(seen)
	mu.Unlock()
	sortStrings(got)
	want := []string{
		"GET /?a=x&b=1 HTTP/1.1", "GET /?a=x&b=2 HTTP/1.1", "GET /?a=x&b=3 HTTP/1.1",
		"GET /?a=y&b=1 HTTP/1.1", "GET /?a=y&b=2 HTTP/1.1", "GET /?a=y&b=3 HTTP/1.1",
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("combos = %v, want %v", got, want)
	}
}

func TestBatteringRamPutsTheSamePayloadEverywhereAtOnce(t *testing.T) {
	base, pts := basePoints(t, "GET /?a=1&b=2 HTTP/1.1\r\nHost: t.test\r\n\r\n")
	sel := pts[:2]
	payloads := sets([]string{"ZZ", "QQ"})
	plan := NewAttackPlan(AttackKindBatteringRam, 2, []int{2}, 1_000)
	var seen [][]byte
	var mu sync.Mutex

	a := NewAttack(base, sel, payloads, plan).WithLimits(Unthrottled(4))
	r := Run(a, recordingSender(&seen, &mu, "HTTP/1.1 200 OK\r\n\r\nok"), nil)

	if r.Sent != 2 {
		t.Fatalf("sent = %d, want one request per payload, both positions filled", r.Sent)
	}
	mu.Lock()
	got := requestLines(seen)
	mu.Unlock()
	sortStrings(got)
	want := []string{"GET /?a=QQ&b=QQ HTTP/1.1", "GET /?a=ZZ&b=ZZ HTTP/1.1"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

// ---- buckets and errors --------------------------------------------------------------------

func TestResultsCollapseToBucketsKeyedOnStatusLengthAndReflection(t *testing.T) {
	base, pts := basePoints(t, "GET /?a=1 HTTP/1.1\r\nHost: t.test\r\n\r\n")
	sel := pts[:1]
	words := numItems(30, "w%02d")
	payloads := []PayloadSet{words}
	plan := NewAttackPlan(AttackKindSniper, 1, []int{30}, 1_000)

	var stored atomic.Int64
	record := func([]byte) uint64 {
		return uint64(stored.Add(1)) - 1
	}

	// w00 is echoed back; w01 gets a 500; everything else is an identical 200.
	sender := func(raw []byte) (Sent, error) {
		var resp []byte
		status := 200
		switch {
		case bytes.Contains(raw, []byte("a=w00")):
			resp = []byte("HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nw00")
		case bytes.Contains(raw, []byte("a=w01")):
			resp = []byte("HTTP/1.1 500 Err\r\nContent-Length: 2\r\n\r\nno")
			status = 500
		default:
			resp = []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
		}
		return Sent{Raw: resp, Duration: time.Millisecond, Status: ptr(status)}, nil
	}

	a := NewAttack(base, sel, payloads, plan).WithLimits(Unthrottled(8))
	r := Run(a, sender, record)

	if r.Sent != 30 {
		t.Fatalf("sent = %d, want 30", r.Sent)
	}
	if len(r.Buckets) != 3 {
		t.Fatalf("30 responses, %d distinct behaviours, want 3", len(r.Buckets))
	}
	if r.BucketsTruncated {
		t.Fatal("3 buckets under the 2000 cap is not truncated")
	}
	if r.Buckets[0].Count != 1 || r.Buckets[1].Count != 1 || r.Buckets[2].Count != 28 {
		t.Fatalf("counts = [%d %d %d], want rarest first [1 1 28]", r.Buckets[0].Count, r.Buckets[1].Count, r.Buckets[2].Count)
	}
	if r.Buckets[2].Status == nil || *r.Buckets[2].Status != 200 {
		t.Fatalf("the 28-strong baseline must be 200, got %+v", r.Buckets[2].Status)
	}
	var reflected []*ResultBucket
	for i := range r.Buckets {
		if r.Buckets[i].Reflected {
			reflected = append(reflected, &r.Buckets[i])
		}
	}
	if len(reflected) != 1 {
		t.Fatalf("only w00 came back in its response, found %d", len(reflected))
	}
	if reflected[0].FirstOrdinal != 0 {
		t.Fatalf("and it was the first payload, ordinal %d", reflected[0].FirstOrdinal)
	}
	var fiveHundred []*ResultBucket
	for i := range r.Buckets {
		if r.Buckets[i].Status != nil && *r.Buckets[i].Status == 500 {
			fiveHundred = append(fiveHundred, &r.Buckets[i])
		}
	}
	if len(fiveHundred) != 1 || fiveHundred[0].FirstOrdinal != 1 {
		t.Fatalf("the 500 must be ordinal 1: %+v", fiveHundred)
	}
	if got := stored.Load(); got != 3 {
		t.Fatalf("30 responses must cost %d stored bodies, one exemplar per bucket; stored %d", 3, got)
	}
}

func TestABoundedClusterBombReportsWhatItDidNotSend(t *testing.T) {
	base, pts := basePoints(t, "GET /?a=1&b=2 HTTP/1.1\r\nHost: t.test\r\n\r\n")
	sel := pts[:2]
	big := numItems(100, "p%d")
	payloads := []PayloadSet{big, big}
	plan := NewAttackPlan(AttackKindClusterBomb, 2, []int{100, 100}, 25)
	var seen [][]byte
	var mu sync.Mutex

	a := NewAttack(base, sel, payloads, plan).WithLimits(Unthrottled(8))
	r := Run(a, recordingSender(&seen, &mu, "HTTP/1.1 200 OK\r\n\r\nok"), nil)

	if r.Combinations != 10_000 {
		t.Fatalf("combinations = %d, want 10000; the operator is told the real size", r.Combinations)
	}
	if r.MaxRequests != 25 {
		t.Fatalf("max_requests = %d, want 25", r.MaxRequests)
	}
	if !r.Truncated {
		t.Fatal("the bound bit and must say so")
	}
	if r.Planned != 25 || r.Sent != 25 {
		t.Fatalf("planned = %d, sent = %d, want 25 and 25", r.Planned, r.Sent)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 25 {
		t.Fatalf("no request beyond the bound went out: %d", len(seen))
	}
}

func TestFailuresAreGroupedAndDoNotStopTheAttack(t *testing.T) {
	base, pts := basePoints(t, "GET /?a=1 HTTP/1.1\r\nHost: t.test\r\n\r\n")
	sel := pts[:1]
	payloads := sets([]string{"a", "b", "c", "d"})
	plan := NewAttackPlan(AttackKindSniper, 1, []int{4}, 100)

	sender := func(raw []byte) (Sent, error) {
		if bytes.Contains(raw, []byte("a=b")) || bytes.Contains(raw, []byte("a=c")) {
			return Sent{}, fmt.Errorf("connect 127.0.0.1:1: connection refused")
		}
		return Sent{Raw: []byte("HTTP/1.1 200 OK\r\n\r\n"), Duration: time.Millisecond, Status: ptr(200)}, nil
	}

	// One slot, so the first failure absorbed is deterministically ordinal 1 — the Rust original
	// gets the same guarantee from its single-threaded test runtime.
	a := NewAttack(base, sel, payloads, plan).WithLimits(Unthrottled(1))
	r := Run(a, sender, nil)

	if r.Sent != 2 {
		t.Fatalf("sent = %d, want 2", r.Sent)
	}
	if r.Failed != 2 {
		t.Fatalf("failed = %d, want 2", r.Failed)
	}
	if len(r.Errors) != 1 {
		t.Fatalf("one message, %d occurrences", len(r.Errors))
	}
	if r.Errors[0].Count != 2 {
		t.Fatalf("error count = %d, want 2", r.Errors[0].Count)
	}
	if r.Errors[0].FirstOrdinal == nil || *r.Errors[0].FirstOrdinal != 1 {
		t.Fatalf("first_ordinal = %+v, want a replayable 1", r.Errors[0].FirstOrdinal)
	}
	if len(r.Attempts) != 4 {
		t.Fatalf("every attempt still has a row: %d", len(r.Attempts))
	}
	if r.Attempts[1].Error == nil || !strings.Contains(*r.Attempts[1].Error, "connection refused") {
		t.Fatalf("attempt 1 must carry the error: %+v", r.Attempts[1].Error)
	}
	if r.Attempts[0].Error != nil {
		t.Fatalf("attempt 0 must have no error: %+v", r.Attempts[0].Error)
	}
}

// ---- grep-match and grep-extract -------------------------------------------------------------

func TestGrepMatchFlagsTheResponsesThatMatchAndLeavesTheRestAlone(t *testing.T) {
	base, pts := basePoints(t, "GET /?a=1 HTTP/1.1\r\nHost: t.test\r\n\r\n")
	sel := pts[:1]
	payloads := sets([]string{"guest", "admin", "other"})
	plan := NewAttackPlan(AttackKindSniper, 1, []int{3}, 100)

	a := NewAttack(base, sel, payloads, plan).
		WithLimits(Unthrottled(4)).
		WithGrep(Grep{MatchRe: re("ADMIN")})
	r := Run(a, varyingSender(), nil)

	if r.Sent != 3 {
		t.Fatalf("sent = %d, want 3", r.Sent)
	}
	if r.GrepMatched != 1 {
		t.Fatalf("grep_matched = %d, want only the admin payload's response", r.GrepMatched)
	}
	var matched []int
	for _, x := range r.Attempts {
		if x.GrepMatched != nil && *x.GrepMatched {
			matched = append(matched, x.Ordinal)
		}
	}
	if fmt.Sprint(matched) != "[1]" {
		t.Fatalf("the second payload is `admin`: %v", matched)
	}
	for _, x := range r.Attempts {
		if x.GrepMatched == nil || x.GrepExtract != nil {
			t.Fatalf("every row was asked the match question and none the extract one: %+v", x)
		}
	}
}

func TestAGrepResultDoesNotSplitABucketItIsCountedInsideIt(t *testing.T) {
	// Three responses agree on (status, length, reflected) and must collapse into one bucket even
	// though the grep disagrees; the disagreement survives as a count.
	base, pts := basePoints(t, "GET /?a=1 HTTP/1.1\r\nHost: t.test\r\n\r\n")
	sel := pts[:1]
	payloads := sets([]string{"guest", "admin", "other"})
	plan := NewAttackPlan(AttackKindSniper, 1, []int{3}, 100)

	a := NewAttack(base, sel, payloads, plan).
		WithLimits(Unthrottled(4)).
		WithGrep(Grep{MatchRe: re("ADMIN")})
	r := Run(a, varyingSender(), nil)

	if len(r.Buckets) != 1 {
		t.Fatalf("the grep must not have become part of the key: %+v", r.Buckets)
	}
	if r.Buckets[0].Count != 3 {
		t.Fatalf("bucket count = %d, want 3", r.Buckets[0].Count)
	}
	if r.Buckets[0].GrepMatches != 1 {
		t.Fatalf("grep_matches = %d, want 1 of 3, a mixture visible as one", r.Buckets[0].GrepMatches)
	}
}

func TestGrepExtractReturnsTheFirstCaptureGroupOrTheWholeMatch(t *testing.T) {
	base, pts := basePoints(t, "GET /?a=1 HTTP/1.1\r\nHost: t.test\r\n\r\n")
	sel := pts[:1]
	payloads := sets([]string{"guest", "admin"})
	plan := NewAttackPlan(AttackKindSniper, 1, []int{2}, 100)

	// With a group: just the value. One slot, so ordinal 0 is absorbed before ordinal 1 and the
	// bucket's exemplar is deterministically ordinal 0's — the Rust original relies on its
	// single-threaded test runtime for the same thing.
	a := NewAttack(base, sel, payloads, plan).
		WithLimits(Unthrottled(1)).
		WithGrep(Grep{ExtractRe: re("role=([A-Za-z]+)")})
	r := Run(a, varyingSender(), nil)
	got := make([]*string, len(r.Attempts))
	for i, x := range r.Attempts {
		got[i] = x.GrepExtract
	}
	if got[0] == nil || *got[0] != "user" || got[1] == nil || *got[1] != "ADMIN" {
		t.Fatalf("extracts = %v, want user and ADMIN", got)
	}
	if r.Buckets[0].GrepExtract == nil || *r.Buckets[0].GrepExtract != "user" {
		t.Fatalf("the bucket carries its exemplar's value, which is ordinal 0's: %v", r.Buckets[0].GrepExtract)
	}

	// Without a group: the whole match, because a pattern with no parentheses still means
	// something and returning nothing would be a silent failure.
	a = NewAttack(base, sel, payloads, plan).
		WithLimits(Unthrottled(1)).
		WithGrep(Grep{ExtractRe: re("role=[A-Za-z]+")})
	r = Run(a, varyingSender(), nil)
	if r.Attempts[1].GrepExtract == nil || *r.Attempts[1].GrepExtract != "role=ADMIN" {
		t.Fatalf("no-group extract = %v, want the whole match", r.Attempts[1].GrepExtract)
	}
}

func TestAnExtractionLongerThanTheCapIsCutToIt(t *testing.T) {
	base, pts := basePoints(t, "GET /?a=1 HTTP/1.1\r\nHost: t.test\r\n\r\n")
	sel := pts[:1]
	payloads := sets([]string{"x"})
	plan := NewAttackPlan(AttackKindSniper, 1, []int{1}, 10)

	big := []byte("HTTP/1.1 200 OK\r\n\r\n" + strings.Repeat("z", MAX_EXTRACT*3))
	sender := func([]byte) (Sent, error) {
		return Sent{Raw: big, Duration: time.Millisecond, Status: ptr(200)}, nil
	}

	a := NewAttack(base, sel, payloads, plan).
		WithLimits(Unthrottled(2)).
		WithGrep(Grep{ExtractRe: re("z+")})
	r := Run(a, sender, nil)
	if r.Attempts[0].GrepExtract == nil || len(*r.Attempts[0].GrepExtract) != MAX_EXTRACT {
		t.Fatalf("a whole-body capture must not land in the report: %d", len(*r.Attempts[0].GrepExtract))
	}
}

func TestAnAttackWithNoGrepReportsNoGrepResultsAtAll(t *testing.T) {
	// The no-change guarantee: an attack that configures no grep must report "not asked" rather
	// than "no".
	base, pts := basePoints(t, "GET /?a=1 HTTP/1.1\r\nHost: t.test\r\n\r\n")
	sel := pts[:1]
	payloads := sets([]string{"guest", "admin"})
	plan := NewAttackPlan(AttackKindSniper, 1, []int{2}, 100)

	a := NewAttack(base, sel, payloads, plan).WithLimits(Unthrottled(4))
	r := Run(a, varyingSender(), nil)

	if r.GrepMatched != 0 {
		t.Fatalf("grep_matched = %d, want 0", r.GrepMatched)
	}
	for _, x := range r.Attempts {
		if x.GrepMatched != nil || x.GrepExtract != nil {
			t.Fatalf("an unasked question must not be answered: %+v", x)
		}
	}
	for _, b := range r.Buckets {
		if b.GrepMatches != 0 {
			t.Fatalf("bucket grep_matches = %d, want 0", b.GrepMatches)
		}
	}
	if r.Pool != nil {
		t.Fatalf("pool = %v, want none", r.Pool)
	}
	if r.AutoThrottleEngaged != 0 {
		t.Fatalf("auto_throttle_engaged = %d, want 0", r.AutoThrottleEngaged)
	}
}

// ---- resource pools ---------------------------------------------------------------------------

func TestATargetAnswering429MakesTheEngineSlowItselfDownAndReportIt(t *testing.T) {
	base, pts := basePoints(t, "GET /?a=1 HTTP/1.1\r\nHost: t.test\r\n\r\n")
	sel := pts[:1]
	payloads := numItems(12, "p%d")
	plan := NewAttackPlan(AttackKindSniper, 1, []int{12}, 100)

	sender := func([]byte) (Sent, error) {
		return Sent{Raw: []byte("HTTP/1.1 429 Too Many\r\n\r\n"), Duration: time.Millisecond, Status: ptr(429)}, nil
	}

	// One slot, so responses are observed strictly before the next request asks for a token.
	rps := 200.0
	limits := NewRateLimit(&rps, 1, 1).Named("cautious").WithAutoThrottle(
		&AutoThrottle{Statuses: []int{429}, After: 2, Factor: 4.0, RecoverAfter: 100})
	a := NewAttack(base, sel, []PayloadSet{payloads}, plan).WithLimits(limits)
	r := Run(a, sender, nil)

	if r.Sent != 12 {
		t.Fatalf("throttling must not lose requests: sent %d", r.Sent)
	}
	if r.AutoThrottleEngaged < 1 {
		t.Fatalf("twelve 429s should have engaged the throttle at least once: %d", r.AutoThrottleEngaged)
	}
	if r.Pool == nil || *r.Pool != "cautious" {
		t.Fatalf("the pool name must come back for the operator to reuse: %v", r.Pool)
	}
}

func TestAnAutoThrottleThatNeverTriggersChangesNothingAboutTheAttack(t *testing.T) {
	base, pts := basePoints(t, "GET /?a=1 HTTP/1.1\r\nHost: t.test\r\n\r\n")
	sel := pts[:1]
	payloads := sets([]string{"a", "b", "c", "d"})
	plan := NewAttackPlan(AttackKindSniper, 1, []int{4}, 100)
	var seen [][]byte
	var mu sync.Mutex

	a := NewAttack(base, sel, payloads, plan).
		WithLimits(Unthrottled(4).WithAutoThrottle(DefaultAutoThrottle()))
	r := Run(a, recordingSender(&seen, &mu, "HTTP/1.1 200 OK\r\n\r\nok"), nil)

	if r.Sent != 4 {
		t.Fatalf("sent = %d, want 4", r.Sent)
	}
	if r.Failed != 0 {
		t.Fatalf("failed = %d, want 0", r.Failed)
	}
	if r.AutoThrottleEngaged != 0 {
		t.Fatalf("a healthy target must not have tripped it: %d", r.AutoThrottleEngaged)
	}
}

func TestDetailRowsAreCappedButBucketCountsAreNot(t *testing.T) {
	base, pts := basePoints(t, "GET /?a=1 HTTP/1.1\r\nHost: t.test\r\n\r\n")
	sel := pts[:1]
	payloads := numItems(200, "p%d")
	plan := NewAttackPlan(AttackKindSniper, 1, []int{200}, 1_000)
	var seen [][]byte
	var mu sync.Mutex

	a := NewAttack(base, sel, []PayloadSet{payloads}, plan).WithLimits(Unthrottled(16))
	a.DetailLimit = 10
	r := Run(a, recordingSender(&seen, &mu, "HTTP/1.1 204 No\r\n\r\n"), nil)

	if r.Sent != 200 {
		t.Fatalf("sent = %d, want 200", r.Sent)
	}
	if len(r.Attempts) != 10 {
		t.Fatalf("detail is bounded: %d rows", len(r.Attempts))
	}
	if r.DetailLimit != 10 {
		t.Fatalf("and the bound is stated, not left to be inferred: %d", r.DetailLimit)
	}
	for i, x := range r.Attempts {
		if x.Ordinal != i {
			t.Fatalf("rows must stay in plan order: %+v", x)
		}
	}
	total := 0
	for _, b := range r.Buckets {
		total += b.Count
	}
	if total != 200 {
		t.Fatalf("counts are not bounded: %d", total)
	}
}

// A result row that cannot name its request is a dead end: it can be read but not sent anywhere
// (burpsy-react-ui-79u). RequestFn is how the caller stores the exact spliced bytes, and the two
// bounds on it are the point — recording follows the rows an operator can act on, not the 100k
// sends the report exists to summarise.
func TestRecordedRequestsAreTheSplicedBytesAndAreBoundedByTheDetailLimit(t *testing.T) {
	base, pts := basePoints(t, "GET /?a=1 HTTP/1.1\r\nHost: t.test\r\n\r\n")
	sel := pts[:1]
	payloads := numItems(40, "p%d")
	plan := NewAttackPlan(AttackKindSniper, 1, []int{40}, 1_000)
	var seen [][]byte
	var mu sync.Mutex

	// Requests are handed out ids from a counter and kept, so the test can assert the id an
	// attempt names resolves back to that attempt's own bytes.
	var storeMu sync.Mutex
	stored := map[uint64][]byte{}
	var next uint64

	a := NewAttack(base, sel, []PayloadSet{payloads}, plan).WithLimits(Unthrottled(8))
	a.DetailLimit = 5
	a.RecordRequest = true
	a.RequestFn = func(raw []byte) uint64 {
		storeMu.Lock()
		defer storeMu.Unlock()
		next++
		stored[next] = append([]byte(nil), raw...)
		return next
	}
	r := Run(a, recordingSender(&seen, &mu, "HTTP/1.1 200 OK\r\n\r\nok"), nil)

	if r.Sent != 40 {
		t.Fatalf("sent = %d, want 40", r.Sent)
	}
	if len(r.Attempts) != 5 {
		t.Fatalf("detail rows = %d, want 5", len(r.Attempts))
	}
	// Every detail row names a request, and the bytes behind that name are the ones the payload
	// for that ordinal produced. Anything else and "Send to Repeater" resends someone else's
	// request while claiming to resend this row's.
	for _, x := range r.Attempts {
		if x.RequestID == nil {
			t.Fatalf("attempt %d has no request id, so it cannot be sent anywhere", x.Ordinal)
		}
		storeMu.Lock()
		raw, ok := stored[*x.RequestID]
		storeMu.Unlock()
		if !ok {
			t.Fatalf("attempt %d names request %d, which was never stored", x.Ordinal, *x.RequestID)
		}
		want := fmt.Sprintf("p%d", x.Ordinal)
		if !bytes.Contains(raw, []byte("a="+want)) {
			t.Fatalf("attempt %d's stored request is not its own splice: %q", x.Ordinal, raw)
		}
	}
	// One bucket here, every response being identical. Its exemplar is FirstOrdinal's send, and
	// FirstOrdinal is whichever outcome landed first under 8-way concurrency — not necessarily 0,
	// and not necessarily inside the detail window. Either way the bytes behind the exemplar id
	// must be that ordinal's own splice.
	if len(r.Buckets) != 1 {
		t.Fatalf("buckets = %d, want 1", len(r.Buckets))
	}
	b := r.Buckets[0]
	if b.ExampleRequestID == nil {
		t.Fatal("the bucket exemplar has no request, so a bucket row is still a dead end")
	}
	storeMu.Lock()
	exemplar, ok := stored[*b.ExampleRequestID]
	total := len(stored)
	storeMu.Unlock()
	if !ok {
		t.Fatalf("the bucket names request %d, which was never stored", *b.ExampleRequestID)
	}
	if want := fmt.Sprintf("a=p%d", b.FirstOrdinal); !bytes.Contains(exemplar, []byte(want)) {
		t.Fatalf("the bucket exemplar is not ordinal %d's splice: %q", b.FirstOrdinal, exemplar)
	}
	// When the bucket opened inside the detail window, that ordinal's row and the bucket name the
	// same id — one store, two references. Two ids for one send would show the operator the same
	// request twice with no way to tell.
	if b.FirstOrdinal < a.DetailLimit {
		row := r.Attempts[b.FirstOrdinal]
		if row.Ordinal != b.FirstOrdinal {
			t.Fatalf("detail rows are meant to be in plan order: row %d at index %d", row.Ordinal, b.FirstOrdinal)
		}
		if *row.RequestID != *b.ExampleRequestID {
			t.Fatalf("bucket exemplar %d and its own detail row %d stored the same send twice",
				*b.ExampleRequestID, *row.RequestID)
		}
		if total != a.DetailLimit {
			t.Fatalf("stored %d requests for %d detail rows sharing the exemplar", total, a.DetailLimit)
		}
	} else if total != a.DetailLimit+1 {
		// The opener sits past the detail window, so it is the one send stored that no row names.
		t.Fatalf("stored %d requests: %d detail rows plus the out-of-window exemplar", total, a.DetailLimit)
	}
}

// The default is to store nothing. Every caller that predates the results context menu — the MCP
// surface, the CLI, the tests above — must keep its no-storage memory profile.
func TestRequestsAreNotRecordedUnlessTheCallerOptsIn(t *testing.T) {
	base, pts := basePoints(t, "GET /?a=1 HTTP/1.1\r\nHost: t.test\r\n\r\n")
	sel := pts[:1]
	payloads := numItems(3, "p%d")
	plan := NewAttackPlan(AttackKindSniper, 1, []int{3}, 100)
	var seen [][]byte
	var mu sync.Mutex

	calls := 0
	a := NewAttack(base, sel, []PayloadSet{payloads}, plan).WithLimits(Unthrottled(1))
	// A RequestFn without RecordRequest is not an opt-in: the flag is what says "store these".
	a.RequestFn = func([]byte) uint64 {
		calls++
		return 1
	}
	r := Run(a, recordingSender(&seen, &mu, "HTTP/1.1 200 OK\r\n\r\nok"), nil)

	if calls != 0 {
		t.Fatalf("RequestFn was called %d times without RecordRequest set", calls)
	}
	for _, x := range r.Attempts {
		if x.RequestID != nil {
			t.Fatalf("attempt %d names request %d that was never stored", x.Ordinal, *x.RequestID)
		}
	}
	for _, b := range r.Buckets {
		if b.ExampleRequestID != nil {
			t.Fatalf("bucket at ordinal %d names request %d that was never stored", b.FirstOrdinal, *b.ExampleRequestID)
		}
	}
}

// The report's row slices must reach the browser as arrays, even when empty (burpsy-react-ui-9pxd).
//
// This is asserted on the marshalled JSON rather than on the struct because Go cannot tell the two
// apart: a nil slice and an empty slice have the same len, range the same way, and every existing
// test in this file passes against either. The difference only appears on the wire, where nil
// becomes `null` — and types.tools.ts declares these fields as non-nullable arrays, so a clean
// attack was handing the Results tab a `null` it then called `.length` on.
func TestAZeroFailureReportMarshalsItsRowsAsArraysNotNull(t *testing.T) {
	base, pts := basePoints(t, "GET /?a=1 HTTP/1.1\r\nHost: t.test\r\n\r\n")
	sel := pts[:1]
	payloads := numItems(3, "p%d")
	plan := NewAttackPlan(AttackKindSniper, 1, []int{3}, 100)
	var seen [][]byte
	var mu sync.Mutex

	a := NewAttack(base, sel, []PayloadSet{payloads}, plan).WithLimits(Unthrottled(2))
	r := Run(a, recordingSender(&seen, &mu, "HTTP/1.1 200 OK\r\n\r\nok"), nil)

	if r.Failed != 0 {
		t.Fatalf("this fixture is meant to have nothing fail: %d", r.Failed)
	}
	if len(r.Errors) != 0 {
		t.Fatalf("and therefore no error groups: %d", len(r.Errors))
	}

	encoded, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var wire map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &wire); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, field := range []string{"buckets", "errors", "attempts"} {
		raw, ok := wire[field]
		if !ok {
			t.Fatalf("the report dropped %q entirely", field)
		}
		if string(raw) == "null" {
			t.Fatalf("%q went out as null; the browser declares it an array and reads .length on it", field)
		}
		if len(raw) == 0 || raw[0] != '[' {
			t.Fatalf("%q is not a JSON array: %s", field, raw)
		}
	}
}

// The same guarantee for an attack that sent nothing at all, where buckets and attempts are the
// empty ones. A guard that refuses every request is the reachable way to get there.
func TestAReportWithNoSendsAtAllStillMarshalsArrays(t *testing.T) {
	base, pts := basePoints(t, "GET /?a=1 HTTP/1.1\r\nHost: t.test\r\n\r\n")
	sel := pts[:1]
	payloads := numItems(3, "p%d")
	plan := NewAttackPlan(AttackKindSniper, 1, []int{3}, 100)

	a := NewAttack(base, sel, []PayloadSet{payloads}, plan).
		WithLimits(Unthrottled(1)).
		WithGuard(func([]byte) error { return fmt.Errorf("out of scope") })
	r := Run(a, func([]byte) (Sent, error) {
		t.Fatal("a refused request must never reach the sender")
		return Sent{}, nil
	}, nil)

	if r.Sent != 0 || len(r.Buckets) != 0 || len(r.Attempts) == 0 {
		t.Fatalf("fixture: sent=%d buckets=%d attempts=%d", r.Sent, len(r.Buckets), len(r.Attempts))
	}
	encoded, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if bytes.Contains(encoded, []byte(`"buckets":null`)) {
		t.Fatalf("buckets went out as null: %s", encoded)
	}
}

// ---- Time-of-day, Cookies, Timeout (burpsy-react-ui-c7w6) ---------------------------------------
//
// Burp's results table (tools/intruder/results/viewing-results.html) carries four columns burpsy's
// Attempt never had: Time of day, Cookies, Comment and a Timeout distinct from Error. Comment has no
// server-side row to live on (an attack report is generated once per run and never persisted; it is
// a browser-only annotation — see intruder.tsx and intruder-export.ts), so only the other three are
// engine fields, and these tests are what proves them wired rather than merely declared.

// fakeTimeoutErr is a minimal net.Error whose Timeout() is the only thing isTimeout may consult for
// a send that never went through a context deadline — the pipeline/h2 path's own signal.
type fakeTimeoutErr struct{}

func (fakeTimeoutErr) Error() string   { return "i/o timeout" }
func (fakeTimeoutErr) Timeout() bool   { return true }
func (fakeTimeoutErr) Temporary() bool { return true }

func TestEveryAttemptCarriesATimeOfDayEvenWhenRefused(t *testing.T) {
	base, pts := basePoints(t, "GET /?a=1 HTTP/1.1\r\nHost: t.test\r\n\r\n")
	sel := pts[:1]
	payloads := sets([]string{"ok", "blocked"})
	plan := NewAttackPlan(AttackKindSniper, 1, []int{2}, 100)

	before := time.Now()
	a := NewAttack(base, sel, payloads, plan).
		WithLimits(Unthrottled(1)).
		WithGuard(func(raw []byte) error {
			if bytes.Contains(raw, []byte("a=blocked")) {
				return fmt.Errorf("refused: out of scope")
			}
			return nil
		})
	r := Run(a, recordingSender(&[][]byte{}, &sync.Mutex{}, "HTTP/1.1 200 OK\r\n\r\nok"), nil)
	after := time.Now()

	if len(r.Attempts) != 2 {
		t.Fatalf("want a row for both the sent and the refused attempt, got %d", len(r.Attempts))
	}
	for _, x := range r.Attempts {
		if x.TimeOfDay.Before(before) || x.TimeOfDay.After(after) {
			t.Fatalf("attempt %d's time_of_day %v is outside the run window [%v, %v] — a refusal must "+
				"be timestamped too, not left at the zero time", x.Ordinal, x.TimeOfDay, before, after)
		}
	}
}

func TestAttemptCookiesNamesTheSetCookiesAndIsNeverNil(t *testing.T) {
	base, pts := basePoints(t, "GET /?a=1 HTTP/1.1\r\nHost: t.test\r\n\r\n")
	sel := pts[:1]
	payloads := sets([]string{"with-cookie", "without"})
	plan := NewAttackPlan(AttackKindSniper, 1, []int{2}, 100)

	sender := func(raw []byte) (Sent, error) {
		if bytes.Contains(raw, []byte("a=with-cookie")) {
			return Sent{
				Raw: []byte("HTTP/1.1 200 OK\r\nSet-Cookie: sessid=abc123; Path=/\r\n" +
					"Set-Cookie: csrf=xyz; HttpOnly\r\nContent-Length: 2\r\n\r\nok"),
				Duration: time.Millisecond, Status: ptr(200),
			}, nil
		}
		return Sent{Raw: []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"), Duration: time.Millisecond, Status: ptr(200)}, nil
	}

	a := NewAttack(base, sel, payloads, plan).WithLimits(Unthrottled(1))
	r := Run(a, sender, nil)

	if len(r.Attempts) != 2 {
		t.Fatalf("want both rows, got %d", len(r.Attempts))
	}
	byOrdinal := map[int]Attempt{}
	for _, x := range r.Attempts {
		byOrdinal[x.Ordinal] = x
	}
	if got := byOrdinal[0].Cookies; fmt.Sprint(got) != "[sessid csrf]" {
		t.Fatalf("cookies = %v, want [sessid csrf] in header order", got)
	}
	if got := byOrdinal[1].Cookies; got == nil || len(got) != 0 {
		t.Fatalf("cookies = %#v, want a non-nil empty slice for a response with no Set-Cookie", got)
	}

	encoded, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if bytes.Contains(encoded, []byte(`"cookies":null`)) {
		t.Fatalf("an attempt's cookies went out as null; types.tools.ts declares Attempt.cookies "+
			"non-nullable: %s", encoded)
	}
}

func TestTimeoutIsTrueOnlyForTheDeadlineNotForAnyOtherFailure(t *testing.T) {
	base, pts := basePoints(t, "GET /?a=1 HTTP/1.1\r\nHost: t.test\r\n\r\n")
	sel := pts[:1]
	payloads := sets([]string{"deadline", "netTimeout", "refused", "guarded"})
	plan := NewAttackPlan(AttackKindSniper, 1, []int{4}, 100)

	sender := func(raw []byte) (Sent, error) {
		switch {
		case bytes.Contains(raw, []byte("a=deadline")):
			// The exact wrapping internal/sender/cancel.go's explainCancellation produces for the
			// intruder's own per-request context.WithTimeout expiring.
			return Sent{}, fmt.Errorf("the send exceeded its deadline: %w", context.DeadlineExceeded)
		case bytes.Contains(raw, []byte("a=netTimeout")):
			return Sent{}, fakeTimeoutErr{}
		default:
			return Sent{}, fmt.Errorf("connection failed: connection refused")
		}
	}

	a := NewAttack(base, sel, payloads, plan).
		WithLimits(Unthrottled(1)).
		WithGuard(func(raw []byte) error {
			if bytes.Contains(raw, []byte("a=guarded")) {
				return fmt.Errorf("refused: out of scope")
			}
			return nil
		})
	r := Run(a, sender, nil)

	if r.Failed != 4 {
		t.Fatalf("failed = %d, want all four", r.Failed)
	}
	byOrdinal := map[int]Attempt{}
	for _, x := range r.Attempts {
		byOrdinal[x.Ordinal] = x
	}
	if !byOrdinal[0].Timeout {
		t.Fatalf("ordinal 0 wrapped context.DeadlineExceeded and must read as a timeout: %+v", byOrdinal[0])
	}
	if !byOrdinal[1].Timeout {
		t.Fatalf("ordinal 1 is a net.Error with Timeout()==true and must read as a timeout: %+v", byOrdinal[1])
	}
	if byOrdinal[2].Timeout {
		t.Fatalf("ordinal 2 is a connection refusal, not a timeout: %+v", byOrdinal[2])
	}
	if byOrdinal[3].Timeout {
		t.Fatalf("ordinal 3 is a guard refusal, not a timeout: %+v", byOrdinal[3])
	}
}

// A payload its container cannot hold must be reported, never sent as the base request.
//
// ApplyAll drops a position whose payload escapePayload refuses and builds the request from what
// remains. For a single-position attack "what remains" is the BASE request — so the attempt went
// out unmodified and landed in the report among the real sends, indistinguishable from a payload
// that was actually tried. An operator reading that report would conclude the payload had been
// delivered and the target was unmoved by it, when in fact it was never delivered at all. That is
// the worst kind of wrong answer this tool can give: a negative result that was never tested.
func TestAPayloadItsContainerRefusesIsReportedAndTheBaseRequestIsNeverSentInstead(t *testing.T) {
	raw, _ := multipartFixture()
	m := storeReq(t, raw)
	pts := FindPoints(m, DefaultPointConfig())
	user := findPoint(t, pts, PointBodyMultipartValue, "user")
	sel := []InsertionPoint{*user}

	// A CRLF followed by this body's boundary delimiter cannot live inside a part's content: those
	// bytes ARE the end of the part, so splicing them would terminate the container the payload is
	// spliced into and send a corrupt request rather than a mutated one. (A bare `--X` with no CRLF
	// in front of it is legal and IS spliced verbatim — see the sibling test — so this payload is
	// specifically the refused shape, not merely a suspicious-looking one.)
	payloads := sets([]string{"before\r\n--X after"})
	plan := NewAttackPlan(AttackKindSniper, 1, []int{1}, 10)
	var seen [][]byte
	var mu sync.Mutex

	a := NewAttack(m.Raw(), sel, payloads, plan).WithLimits(Unthrottled(2))
	r := Run(a, recordingSender(&seen, &mu, "HTTP/1.1 200 OK\r\n\r\nok"), nil)

	mu.Lock()
	sent := append([][]byte(nil), seen...)
	mu.Unlock()

	if len(sent) != 0 {
		t.Fatalf("a request was sent for a payload the container refused; the bytes on the wire were the unmodified base request, which the report would have counted as a real send: %q", string(sent[0]))
	}
	if r.Sent != 0 {
		t.Fatalf("sent = %d, want 0 — nothing could be delivered, so nothing may be counted as delivered", r.Sent)
	}
	if r.Failed != 1 {
		t.Fatalf("failed = %d, want the refused attempt counted rather than dropped silently", r.Failed)
	}
	// The reason must be the enumerator's own, so Intruder and the scanner describe the same
	// refusal of the same payload at the same point identically.
	var reasons []string
	for _, at := range r.Attempts {
		if at.Error != nil {
			reasons = append(reasons, *at.Error)
		}
	}
	if len(reasons) != 1 {
		t.Fatalf("attempts carrying an error = %d, want 1 naming the refusal; a refusal the operator cannot read is indistinguishable from a target that said nothing", len(reasons))
	}
	if !strings.Contains(reasons[0], "could not be placed") {
		t.Errorf("the reported reason %q does not name the container's own refusal, so the report cannot say WHY the payload was undeliverable", reasons[0])
	}
}
