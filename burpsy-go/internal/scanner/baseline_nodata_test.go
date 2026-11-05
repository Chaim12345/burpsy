package scanner

import (
	"strconv"
	"strings"
	"testing"
	"time"
)

// The no-data rule must call an empty collection empty and must never call a record empty: the first
// direction removes the false "Bypassed" rows an empty job list produced for every role, the second is
// what keeps a real bypass from being hidden as "Ambiguous". The negative rows are the proof the rule
// is conservative.
func TestBodyCarriesNoDataCallsEmptyCollectionsEmptyAndRecordsData(t *testing.T) {
	for _, tc := range []struct {
		body   string
		noData bool
	}{
		// No data: empty collections, envelopes around them, and near-empty non-JSON.
		{"", true},
		{"  \n", true},
		{"[]", true},
		{"{}", true},
		{"null", true},
		{`""`, true},
		{`{"data":[]}`, true},
		{`{"rows":[],"count":0}`, true},
		{`{"success":true,"items":[],"page":1,"total":0}`, true},
		{`{"data":{"items":[],"total":0}}`, true},
		{"OK", true},
		{"done", true},
		// Data: anything a privileged identity could have been shown, or an action's acknowledgement.
		{`[{"id":1}]`, false},
		{`[0]`, false},
		{`{"success":true}`, false},
		{`{"id":5,"name":"x","roles":[]}`, false},
		{`{"data":[],"message":"no jobs"}`, false},
		{`{"data":[{"id":1}],"count":1}`, false},
		{`1234`, false},
		{`true`, false},
		{`"secret"`, false},
		{"<html>user 42</html>", false},
		{"hello", false},
		{"[" + strings.Repeat(" ", noDataParseCap) + "]", false},
	} {
		if got := bodyCarriesNoData(tc.body); got != tc.noData {
			t.Errorf("bodyCarriesNoData(%q) = %v, want %v", tc.body, got, tc.noData)
		}
	}
}

func calibrated(t *testing.T, status int, body string) *Baseline {
	t.Helper()
	var samples []BaselineSample
	for i := 0; i < 3; i++ {
		samples = append(samples, NewBaselineSample(status, body, 30*time.Millisecond))
	}
	b, err := CalibrateBaseline(samples)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// A baseline that was not served is no reference: an identity refused the same way "matches" it and an
// identity that got a 200 "differs" from it, and before this those read as Bypassed and Enforced — the
// verdicts inverted. Every verdict against such a baseline is Ambiguous, and the reason names the
// status so the operator knows to pick a privileged baseline.
func TestDiffAccessControlIsAmbiguousAgainstABaselineThatWasNotServed(t *testing.T) {
	for _, status := range []int{400, 403, 500, 302} {
		b := calibrated(t, status, "denied")
		for _, other := range []BaselineSample{
			NewBaselineSample(status, "denied", 30*time.Millisecond),
			NewBaselineSample(200, `{"jobs":[{"id":1}]}`, 30*time.Millisecond),
		} {
			got := b.DiffAccessControl("GET", other, DefaultDeviationThreshold())
			if !got.Ambiguous || got.Matched {
				t.Errorf("baseline %d vs other %d: %+v, want Ambiguous and not Matched", status, other.Status, got)
			}
			if !strings.Contains(got.Reason, "status "+strconv.Itoa(status)) || !strings.Contains(got.Reason, "privileged baseline") {
				t.Errorf("baseline %d: reason %q does not name the status and the remedy", status, got.Reason)
			}
		}
	}
}

// A served baseline with no data proves nothing when matched on a read: both identities saw nothing.
// A differing answer keeps its Enforced reading, and a write keeps its bypass, because an action
// acknowledged identically for every role is the function-level bypass itself.
func TestDiffAccessControlIsAmbiguousWhenAnEmptyBaselineIsMatchedOnARead(t *testing.T) {
	b := calibrated(t, 200, `{"rows":[],"count":0}`)
	same := NewBaselineSample(200, `{"rows":[],"count":0}`, 30*time.Millisecond)

	got := b.DiffAccessControl("GET", same, DefaultDeviationThreshold())
	if !got.Ambiguous || got.Matched || got.Reason != "baseline returned no data; seed data the baseline can see" {
		t.Errorf("an empty read baseline matched: %+v, want Ambiguous with the seed-data reason", got)
	}
	if denied := b.DiffAccessControl("GET", NewBaselineSample(403, "forbidden", 30*time.Millisecond), DefaultDeviationThreshold()); denied.Ambiguous || denied.Matched {
		t.Errorf("a 403 against an empty baseline: %+v, want Enforced (not Matched, not Ambiguous)", denied)
	}
	if write := b.DiffAccessControl("POST", same, DefaultDeviationThreshold()); write.Ambiguous || !write.Matched {
		t.Errorf("a write acknowledged identically: %+v, want Matched (the function-level bypass)", write)
	}
	// The existing behaviour stands: a baseline with data, matched, is a bypass.
	full := calibrated(t, 200, `{"rows":[{"id":7,"owner":"admin"}],"count":1}`)
	if leak := full.DiffAccessControl("GET", NewBaselineSample(200, `{"rows":[{"id":7,"owner":"admin"}],"count":1}`, 30*time.Millisecond), DefaultDeviationThreshold()); leak.Ambiguous || !leak.Matched {
		t.Errorf("a populated baseline matched: %+v, want Matched", leak)
	}
}
