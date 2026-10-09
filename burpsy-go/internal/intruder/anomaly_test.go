package intruder

import (
	"bytes"
	"encoding/json"
	"errors"
	"slices"
	"testing"
)

// Anomaly ranking (pglp): the row whose response differs from the crowd ranks first, rows that look
// alike share a rank, and the report names the attributes that varied.

func anomalySender(raw []byte) (Sent, error) {
	ok := 200
	switch {
	case bytes.Contains(raw, []byte("a=p3")):
		redirect := 302
		return Sent{Raw: []byte("HTTP/1.1 302 Found\r\nLocation: /admin\r\nContent-Type: text/html\r\nContent-Length: 0\r\n\r\n"), Status: &redirect}, nil
	case bytes.Contains(raw, []byte("a=p5")):
		return Sent{}, errors.New("connection refused")
	}
	body := "<html><title>Search</title>no results</html>"
	return Sent{Raw: []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\r\n" + body), Status: &ok}, nil
}

func TestTheOddResponseRanksFirstAndTheVariantAttributesAreNamed(t *testing.T) {
	base, pts := basePoints(t, "GET /?a=1 HTTP/1.1\r\nHost: t.test\r\n\r\n")
	n := 8
	plan := NewAttackPlan(AttackKindSniper, 1, []int{n}, 1_000)
	r := Run(NewAttack(base, pts[:1], []PayloadSet{numPayloads(n)}, plan), anomalySender, nil)

	ranks := map[int]int{}
	for _, a := range r.Attempts {
		ranks[a.Ordinal] = a.AnomalyRank
	}
	if len(ranks) != n {
		t.Fatalf("want %d detail rows, got %d: %+v", n, len(ranks), r.Attempts)
	}
	// Ordinals are 1-based: p3 is ordinal 3, p5 ordinal 5.
	redirect, failed := ranks[3], ranks[5]
	common := ranks[1]
	if redirect == 0 || failed == 0 || common == 0 {
		t.Fatalf("every row must be ranked: %v", ranks)
	}
	if redirect >= common || failed >= common {
		t.Errorf("the redirect (%d) and the failure (%d) must outrank the ordinary rows (%d): %v", redirect, failed, common, ranks)
	}
	for o, rk := range ranks {
		if o != 3 && o != 5 && rk != common {
			t.Errorf("identical responses must share a rank: ordinal %d has %d, want %d", o, rk, common)
		}
	}
	for _, want := range []string{"status_code", "location", "outcome", "content_type"} {
		if !slices.Contains(r.VariantAttributes, want) {
			t.Errorf("variant attributes %v lack %q", r.VariantAttributes, want)
		}
	}
	if slices.Contains(r.VariantAttributes, "cookie_names") {
		t.Errorf("no response set a cookie, yet cookie_names is variant: %v", r.VariantAttributes)
	}
}

func TestAnAttackWithNothingVaryingMarshalsAnEmptyVariantList(t *testing.T) {
	base, pts := basePoints(t, "GET /?a=1 HTTP/1.1\r\nHost: t.test\r\n\r\n")
	plan := NewAttackPlan(AttackKindSniper, 1, []int{3}, 1_000)
	same := func([]byte) (Sent, error) {
		ok := 200
		return Sent{Raw: []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"), Status: &ok}, nil
	}
	r := Run(NewAttack(base, pts[:1], []PayloadSet{numPayloads(3)}, plan), same, nil)
	out, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(out, []byte(`"variant_attributes":[]`)) {
		t.Errorf("want variant_attributes [] (never null), got %s", out)
	}
	for _, a := range r.Attempts {
		if a.AnomalyRank != 1 {
			t.Errorf("with nothing varying every row ties at rank 1, got %d", a.AnomalyRank)
		}
	}
}
