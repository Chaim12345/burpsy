package persist

import (
	"encoding/json"
	"testing"

	"github.com/burpsy-go/burpsy/internal/pool"
	"github.com/burpsy-go/burpsy/internal/schedule"
)

// A pool survives the round trip with every field it was saved with, in the order it was saved in.
//
// Field-by-field rather than by reflect.DeepEqual on the slice alone, so a failure says *which*
// bound was lost: a pool that comes back with its delay dropped is a pool that will hit the target
// as fast as the network allows, and "not deep-equal" would not say so.
func Test_a_pool_survives_the_round_trip(t *testing.T) {
	p := newTestStore(t)
	saved := []pool.Pool{
		{Name: "Out Of Hours", MaxConcurrent: 2, DelayMs: 500, Throttle: &pool.Throttle{
			IncrementMs: 250, Statuses: []int{429, 503, 429}, After: 5, RecoverAfter: 100,
		}},
		// No throttle: the nil must come back nil rather than as an all-zero throttle, because an
		// all-zero throttle is a *saved* safeguard that does nothing, which Validate refuses.
		{Name: "flat out", MaxConcurrent: 20, DelayMs: 0},
	}
	p.SavePools(saved)

	got, err := p.LoadPools()
	if err != nil {
		t.Fatalf("LoadPools: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("%d pools came back, want 2", len(got))
	}
	// Order first: a list that reshuffles itself on every restart is a list nobody can navigate.
	if got[0].Name != "Out Of Hours" || got[1].Name != "flat out" {
		t.Fatalf("the pools came back in the order %q, %q; they were saved the other way round",
			got[0].Name, got[1].Name)
	}
	first := got[0]
	if first.MaxConcurrent != 2 {
		t.Errorf("max concurrent came back as %d, want 2", first.MaxConcurrent)
	}
	if first.DelayMs != 500 {
		t.Errorf("the delay came back as %dms, want 500 — a lost delay is a pool sending as fast as "+
			"the network allows", first.DelayMs)
	}
	if first.Throttle == nil {
		t.Fatal("the automatic throttle came back nil, so a restart silently switched a safeguard off")
	}
	if first.Throttle.IncrementMs != 250 || first.Throttle.After != 5 || first.Throttle.RecoverAfter != 100 {
		t.Errorf("the throttle came back as %+v, want increment 250, after 5, recover 100", *first.Throttle)
	}
	if len(first.Throttle.Statuses) != 3 {
		t.Errorf("the throttle's statuses came back as %v, want the three that were saved",
			first.Throttle.Statuses)
	}
	if got[1].Throttle != nil {
		t.Error("a pool saved with no throttle came back with one, which would show the operator a " +
			"safeguard they did not configure")
	}

	// And the restored set goes through the same validation a freshly-typed pool does, so a round trip
	// cannot smuggle in a pool the registry would have refused.
	reg := pool.New()
	if refused := reg.Restore(got); len(refused) != 0 {
		t.Errorf("the round-tripped pools were refused by the registry: %v", refused)
	}
	if reg.Len() != 2 {
		t.Errorf("%d pools installed after the round trip, want 2", reg.Len())
	}
}

// Saving replaces rather than accumulates: a pool the operator deleted must not come back.
func Test_saving_pools_replaces_the_previous_set(t *testing.T) {
	p := newTestStore(t)
	p.SavePools([]pool.Pool{
		{Name: "keep", MaxConcurrent: 1},
		{Name: "delete me", MaxConcurrent: 1},
	})
	p.SavePools([]pool.Pool{{Name: "keep", MaxConcurrent: 1}})

	got, err := p.LoadPools()
	if err != nil {
		t.Fatalf("LoadPools: %v", err)
	}
	if len(got) != 1 || got[0].Name != "keep" {
		t.Errorf("after deleting one of two pools the saved set is %v; a deleted pool that comes back "+
			"on restart is a bound the operator thought they had removed", got)
	}
}

// A schedule survives with both halves: the configured fields *and* the record of what has happened
// to it. The counters are the point — see Schedule's doc on why a PUT does not reset them either.
func Test_a_schedule_survives_the_round_trip_with_its_counters(t *testing.T) {
	p := newTestStore(t)
	saved := []schedule.Schedule{{
		Name: "nightly audit", Kind: "audit", Enabled: true,
		FirstMs: 1_700_000_000_000, IntervalSecs: 24 * 3600,
		Pool:      "Out Of Hours",
		Params:    json.RawMessage(`{"exchange_id":0,"config":"thorough"}`),
		NextMs:    1_700_086_400_000,
		LastRunMs: 1_700_000_000_000,
		Runs:      30, Failures: 30, Missed: 2,
		LastNote: "the target refused the connection",
	}}
	p.SaveSchedules(saved)

	got, err := p.LoadSchedules()
	if err != nil {
		t.Fatalf("LoadSchedules: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("%d schedules came back, want 1", len(got))
	}
	s := got[0]
	if s.Name != "nightly audit" || s.Kind != "audit" || !s.Enabled {
		t.Errorf("the configured half came back as name=%q kind=%q enabled=%v", s.Name, s.Kind, s.Enabled)
	}
	if s.FirstMs != 1_700_000_000_000 || s.IntervalSecs != 24*3600 {
		t.Errorf("the timing came back as first=%d interval=%d", s.FirstMs, s.IntervalSecs)
	}
	if s.Pool != "Out Of Hours" {
		t.Errorf("the pool reference came back as %q; a scheduled run that lost it would fall back to "+
			"whatever bounds its tool defaults to", s.Pool)
	}
	if string(s.Params) != `{"exchange_id":0,"config":"thorough"}` {
		t.Errorf("the params came back as %s, unchanged from what was saved is the contract", s.Params)
	}
	// Runs 30 with Failures 30 is a schedule that has fired every night and failed every night. Either
	// number alone reads as healthy, which is why both are persisted.
	if s.Runs != 30 || s.Failures != 30 || s.Missed != 2 {
		t.Errorf("the counters came back as runs=%d failures=%d missed=%d, want 30/30/2; a restart that "+
			"reset them would erase the evidence that this schedule has been failing",
			s.Runs, s.Failures, s.Missed)
	}
	if s.NextMs != 1_700_086_400_000 {
		t.Errorf("the armed occurrence came back as %d, want 1700086400000 — usually in the past, which "+
			"is what lets the first tick apply the missed-window rule to it", s.NextMs)
	}
	if s.LastNote != "the target refused the connection" {
		t.Errorf("the last note came back as %q", s.LastNote)
	}
}

// A schedule with nothing to say in its optional columns comes back with empty values rather than
// failing the scan. NULL and "" mean the same thing here, and both are honest.
func Test_a_schedule_with_no_pool_or_params_round_trips(t *testing.T) {
	p := newTestStore(t)
	p.SaveSchedules([]schedule.Schedule{{
		Name: "bare", Kind: "crawl", FirstMs: 1_700_000_000_000, NextMs: 1_700_000_000_000,
	}})
	got, err := p.LoadSchedules()
	if err != nil {
		t.Fatalf("LoadSchedules: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("%d schedules came back, want 1", len(got))
	}
	if got[0].Pool != "" || len(got[0].Params) != 0 || got[0].LastNote != "" {
		t.Errorf("a schedule with no pool, params or note came back as %+v", got[0])
	}
	if got[0].Enabled {
		t.Error("a schedule saved disabled came back enabled, which would fire something the operator " +
			"had switched off")
	}
}

// Both tables come back empty on a fresh database — the honest starting state, distinguishable from a
// load that failed because the table was missing.
func Test_a_fresh_database_has_no_pools_or_schedules(t *testing.T) {
	p := newTestStore(t)
	pools, err := p.LoadPools()
	if err != nil {
		t.Fatalf("LoadPools on a fresh database: %v", err)
	}
	if len(pools) != 0 {
		t.Errorf("a fresh database holds %d pools", len(pools))
	}
	schedules, err := p.LoadSchedules()
	if err != nil {
		t.Fatalf("LoadSchedules on a fresh database: %v", err)
	}
	if len(schedules) != 0 {
		t.Errorf("a fresh database holds %d schedules", len(schedules))
	}
}
