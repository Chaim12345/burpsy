package intruder

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

// Grep - Payloads (burpsy-react-ui-7qc3): Burp's four settings and the per-set count column, asked of
// real attack runs through the engine's Run.

// echoSender answers every request with resp(request).
func echoSender(resp func(raw []byte) string) SendFn {
	return func(raw []byte) (Sent, error) {
		return Sent{Raw: []byte(resp(raw)), Duration: time.Millisecond, Status: ptr(200)}, nil
	}
}

// runGrepPayloads runs a sniper attack over the q value of a fixed request, one payload per attempt,
// with the given settings, against a sender whose response is resp(payload).
func runGrepPayloads(t *testing.T, g *GrepPayloads, set PayloadSet, resp func(payload string) string) *AttackReport {
	t.Helper()
	raw, pts := basePoints(t, "GET /s?q=v HTTP/1.1\r\nHost: t.test\r\n\r\n")
	plan := NewAttackPlan(AttackKindSniper, 1, []int{len(set.Items)}, 100)
	a := NewAttack(raw, pts[:1], []PayloadSet{set}, plan)
	if g != nil {
		a.WithGrepPayloads(*g)
	}
	byOrdinal := map[string]string{}
	for i, item := range set.Items {
		pre := item
		if set.Unencoded != nil {
			pre = set.Unencoded[i]
		}
		byOrdinal[item] = resp(pre)
	}
	send := echoSender(func(req []byte) string {
		line := strings.SplitN(string(req), " ", 3)[1] // "/s?q=<payload>"
		return byOrdinal[strings.TrimPrefix(line, "/s?q=")]
	})
	return Run(a, send, nil)
}

func ok200(body string, headers ...string) string {
	return "HTTP/1.1 200 OK\r\n" + strings.Join(headers, "") + "Content-Length: " + itoaStr(len(body)) + "\r\n\r\n" + body
}

func itoaStr(n int) string { return string(itoa(n)) }

func TestGrepPayloadsCaseSensitivity(t *testing.T) {
	resp := func(p string) string { return ok200("hello " + strings.ToUpper(p) + " and " + strings.ToUpper(p)) }
	set := itemSet([]string{"admin"})

	legacy := runGrepPayloads(t, nil, set, resp)
	if legacy.Attempts[0].Reflected || !reflect.DeepEqual(legacy.Attempts[0].ReflectedCounts, []int{0}) {
		t.Fatalf("legacy (case-sensitive) = %v %v, want not reflected: ADMIN is not admin", legacy.Attempts[0].Reflected, legacy.Attempts[0].ReflectedCounts)
	}
	if !legacy.GrepPayloads.Enabled || !legacy.GrepPayloads.CaseSensitive {
		t.Fatalf("an attack that never named Grep - Payloads must report the legacy settings, got %+v", legacy.GrepPayloads)
	}
	folded := runGrepPayloads(t, &GrepPayloads{Enabled: true}, set, resp)
	if !folded.Attempts[0].Reflected || !reflect.DeepEqual(folded.Attempts[0].ReflectedCounts, []int{2}) {
		t.Fatalf("case-insensitive = %v %v, want reflected twice", folded.Attempts[0].Reflected, folded.Attempts[0].ReflectedCounts)
	}
	if b := folded.Buckets[0]; !b.Reflected || !reflect.DeepEqual(b.ReflectedCountTotals, []int{2}) {
		t.Fatalf("bucket = %+v, want reflected with totals [2]", b)
	}
}

func TestGrepPayloadsExcludeHeaders(t *testing.T) {
	// The payload comes back in a header only.
	resp := func(p string) string { return ok200("nothing here", "X-Echo: "+p+"\r\n") }
	set := itemSet([]string{"zq9"})

	withHeaders := runGrepPayloads(t, &GrepPayloads{Enabled: true, CaseSensitive: true}, set, resp)
	if !withHeaders.Attempts[0].Reflected {
		t.Fatal("headers included: a header reflection must count")
	}
	bodyOnly := runGrepPayloads(t, &GrepPayloads{Enabled: true, CaseSensitive: true, ExcludeHeaders: true}, set, resp)
	if bodyOnly.Attempts[0].Reflected || !reflect.DeepEqual(bodyOnly.Attempts[0].ReflectedCounts, []int{0}) {
		t.Fatalf("exclude headers = %v %v, want a header-only reflection excluded",
			bodyOnly.Attempts[0].Reflected, bodyOnly.Attempts[0].ReflectedCounts)
	}
}

// The application decodes the URL-encoded payload and echoes it in its original form. Only "Match
// against pre-URL-encoded payloads" sees that; matching the bytes sent misses it.
func TestGrepPayloadsMatchPreURLEncoded(t *testing.T) {
	set := itemSet([]string{"<a b>"})
	URLEncodeSet(&set, "<>")
	if set.Items[0] != "%3Ca%20b%3E" || !reflect.DeepEqual(set.Unencoded, []string{"<a b>"}) {
		t.Fatalf("URLEncodeSet: items %q unencoded %q", set.Items, set.Unencoded)
	}
	resp := func(pre string) string { return ok200("you searched for " + pre) }

	asSent := runGrepPayloads(t, &GrepPayloads{Enabled: true, CaseSensitive: true}, set, resp)
	if asSent.Attempts[0].Reflected {
		t.Fatal("matching the encoded payload must miss a decoded echo")
	}
	pre := runGrepPayloads(t, &GrepPayloads{Enabled: true, CaseSensitive: true, MatchPreURLEncoded: true}, set, resp)
	if !pre.Attempts[0].Reflected || !reflect.DeepEqual(pre.Attempts[0].ReflectedCounts, []int{1}) {
		t.Fatalf("pre-URL-encoded = %v %v, want the decoded echo counted", pre.Attempts[0].Reflected, pre.Attempts[0].ReflectedCounts)
	}
}

func TestURLEncodeSetKeepsNoCopyWhenNothingChanged(t *testing.T) {
	set := itemSet([]string{"plain", "words"})
	URLEncodeSet(&set, "<>")
	if set.Unencoded != nil {
		t.Fatalf("Unencoded = %q, want nil when the encoding changed nothing", set.Unencoded)
	}
	mixed := itemSet([]string{"ok", "a<b", "fine"})
	URLEncodeSet(&mixed, "<")
	if !reflect.DeepEqual(mixed.Unencoded, []string{"ok", "a<b", "fine"}) || mixed.Items[1] != "a%3Cb" {
		t.Fatalf("mixed: items %q unencoded %q", mixed.Items, mixed.Unencoded)
	}
}

func TestGrepPayloadsDisabledReportsNoColumns(t *testing.T) {
	resp := func(p string) string { return ok200(p) }
	r := runGrepPayloads(t, &GrepPayloads{}, itemSet([]string{"x1"}), resp)
	a := r.Attempts[0]
	if a.Reflected || a.ReflectedCounts == nil || len(a.ReflectedCounts) != 0 {
		t.Fatalf("disabled: reflected=%v counts=%v, want false and an empty, non-nil slice", a.Reflected, a.ReflectedCounts)
	}
	if r.Buckets[0].ReflectedCountTotals == nil || len(r.Buckets[0].ReflectedCountTotals) != 0 {
		t.Fatalf("disabled bucket totals = %v, want []", r.Buckets[0].ReflectedCountTotals)
	}
}

// One column per payload SET: pitchfork's two sets get two columns; battering ram's one set filling
// two positions is counted once, not once per position; the baseline row has zeros.
func TestGrepPayloadsCountsPerSet(t *testing.T) {
	raw, pts := basePoints(t, "GET /s?a=1&b=2 HTTP/1.1\r\nHost: t.test\r\n\r\n")
	echoRequestLine := echoSender(func(req []byte) string {
		return ok200(strings.SplitN(string(req), "\r\n", 2)[0])
	})

	pf := NewAttack(raw, pts[:2], sets([]string{"AAA"}, []string{"BB"}), NewAttackPlan(AttackKindPitchfork, 2, []int{1, 1}, 10))
	pf.WithGrepPayloads(GrepPayloads{Enabled: true, CaseSensitive: true}).WithBaseline(true)
	r := Run(pf, echoRequestLine, nil)
	if len(r.Attempts) != 2 {
		t.Fatalf("attempts = %+v, want the baseline and one attack row", r.Attempts)
	}
	if got := r.Attempts[0].ReflectedCounts; !reflect.DeepEqual(got, []int{0, 0}) {
		t.Fatalf("baseline counts = %v, want a zero per set", got)
	}
	if got := r.Attempts[1].ReflectedCounts; !reflect.DeepEqual(got, []int{1, 1}) {
		t.Fatalf("pitchfork counts = %v, want one column per set", got)
	}

	br := NewAttack(raw, pts[:2], sets([]string{"ZZ"}), NewAttackPlan(AttackKindBatteringRam, 2, []int{1}, 10))
	br.WithGrepPayloads(GrepPayloads{Enabled: true, CaseSensitive: true})
	r = Run(br, echoRequestLine, nil)
	// The request line is "GET /s?a=ZZ&b=ZZ HTTP/1.1": ZZ occurs twice. Counted once for the one set,
	// not twice per position (which would read four).
	if got := r.Attempts[0].ReflectedCounts; !reflect.DeepEqual(got, []int{2}) {
		t.Fatalf("battering ram counts = %v, want [2]", got)
	}
}

func TestCountOccurrences(t *testing.T) {
	cases := []struct {
		hay, needle string
		cs          bool
		want        int
	}{
		{"abcabc", "abc", true, 2},
		{"aaaa", "aa", true, 2}, // non-overlapping
		{"ABCabc", "abc", true, 1},
		{"ABCabc", "abc", false, 2},
		{"xyz", "", false, 0}, // an empty payload is no reflection
		{"ab", "abc", false, 0},
		{"İx", "ix", false, 0}, // non-ASCII bytes are compared exactly
	}
	for _, c := range cases {
		if got := countOccurrences([]byte(c.hay), []byte(c.needle), c.cs); got != c.want {
			t.Errorf("countOccurrences(%q, %q, %v) = %d, want %d", c.hay, c.needle, c.cs, got, c.want)
		}
	}
	big := []byte(strings.Repeat("a", 3*maxReflectionsCounted))
	if got := countOccurrences(big, []byte("a"), false); got != maxReflectionsCounted {
		t.Fatalf("cap: got %d, want %d", got, maxReflectionsCounted)
	}
}
