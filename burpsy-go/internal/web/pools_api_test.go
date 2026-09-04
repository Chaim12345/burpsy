package web

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/intruder"
	"github.com/burpsy-go/burpsy/internal/pool"
	"github.com/burpsy-go/burpsy/internal/schedule"
)

// do performs one request against the server's mux and returns the recorder.
func do(t *testing.T, s *Server, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var reader *bytes.Reader
	if body == nil {
		reader = bytes.NewReader(nil)
	} else {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		reader = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, path, reader)
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	return rec
}

// decodePools reads a pools view off a recorder, failing the test if the status is not what was
// expected — so a test that meant to assert on content does not silently assert on an error body.
func decodePools(t *testing.T, rec *httptest.ResponseRecorder, wantStatus int) poolsView {
	t.Helper()
	if rec.Code != wantStatus {
		t.Fatalf("status %d, want %d: %s", rec.Code, wantStatus, strings.TrimSpace(rec.Body.String()))
	}
	var view poolsView
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatalf("decoding the answer: %v (body: %s)", err, rec.Body.String())
	}
	return view
}

// An empty pool list is an answer, not an absence: the count is stated, and the table of what each
// tool can honour is served whether or not any pool exists.
func Test_pools_get_on_a_fresh_server_reports_empty_rather_than_nothing(t *testing.T) {
	s := newTestServer()
	view := decodePools(t, do(t, s, http.MethodGet, "/api/pools", nil), http.StatusOK)
	if view.Count != 0 || len(view.Pools) != 0 {
		t.Errorf("a fresh server reports %d pools", view.Count)
	}
	if len(view.Support) == 0 {
		t.Error("no tool path declares which pool bounds it honours, so an operator saving their first " +
			"pool cannot tell what it will actually do")
	}
	if view.UnhonouredBounds != len(pool.Unhonoured()) {
		t.Errorf("unhonoured_bounds is %d, want %d", view.UnhonouredBounds, len(pool.Unhonoured()))
	}
	// The New dialog's starting point is served rather than invented in TypeScript, so the two cannot
	// drift into offering different defaults. It is deliberately unnamed — the operator supplies that —
	// so what is checked is that its *bounds* are savable as they stand: a template a dialog offers and
	// the registry would then refuse would be a form that cannot be submitted without editing.
	named := view.Default
	named.Name = "whatever the operator types"
	if err := named.Validate(); err != nil {
		t.Errorf("the bounds offered for a new pool would be refused if saved: %v", err)
	}
}

// The whole lifetime: create, list, edit, delete — each answering with the confirmed state.
func Test_a_pool_can_be_created_edited_and_deleted(t *testing.T) {
	s := newTestServer()

	created := decodePools(t, do(t, s, http.MethodPost, "/api/pools", pool.Pool{
		Name: "Out Of Hours", MaxConcurrent: 2, DelayMs: 500,
		Throttle: &pool.Throttle{IncrementMs: 250},
	}), http.StatusCreated)
	if created.Count != 1 {
		t.Fatalf("after one POST the server reports %d pools", created.Count)
	}
	if created.Pools[0].Name != "Out Of Hours" {
		t.Errorf("the pool came back named %q; the operator's own capitalisation should be kept",
			created.Pools[0].Name)
	}

	// The name is operator prose, so it reaches the URL percent-encoded. A route that could not
	// address "Out Of Hours" would be a route that only works for names without spaces.
	edited := decodePools(t, do(t, s, http.MethodPut, "/api/pools/Out%20Of%20Hours", pool.Pool{
		Name: "Out Of Hours", MaxConcurrent: 8, DelayMs: 500,
		Throttle: &pool.Throttle{IncrementMs: 250},
	}), http.StatusOK)
	if edited.Pools[0].MaxConcurrent != 8 {
		t.Errorf("after the edit max concurrent is %d, want 8", edited.Pools[0].MaxConcurrent)
	}

	deleted := decodePools(t, do(t, s, http.MethodDelete, "/api/pools/Out%20Of%20Hours", nil), http.StatusOK)
	if deleted.Count != 0 {
		t.Errorf("after the delete the server reports %d pools", deleted.Count)
	}
}

// A PUT that omits the name keeps the one in the path, so editing only the limits does not require
// restating the name.
func Test_a_put_without_a_name_keeps_the_one_in_the_path(t *testing.T) {
	s := newTestServer()
	do(t, s, http.MethodPost, "/api/pools", pool.Pool{Name: "p", MaxConcurrent: 1})
	view := decodePools(t, do(t, s, http.MethodPut, "/api/pools/p",
		map[string]any{"max_concurrent": 5}), http.StatusOK)
	if view.Count != 1 || view.Pools[0].Name != "p" || view.Pools[0].MaxConcurrent != 5 {
		t.Errorf("after a PUT with no name the saved set is %+v, want one pool 'p' at 5", view.Pools)
	}
}

// A duplicate name is 409, not 400: the request is well formed and the operator's mistake is about
// the state of the world.
func Test_a_duplicate_pool_name_is_a_conflict(t *testing.T) {
	s := newTestServer()
	do(t, s, http.MethodPost, "/api/pools", pool.Pool{Name: "p", MaxConcurrent: 1})
	rec := do(t, s, http.MethodPost, "/api/pools", pool.Pool{Name: "P", MaxConcurrent: 9})
	if rec.Code != http.StatusConflict {
		t.Errorf("a second pool named 'P' beside 'p' answered %d, want 409", rec.Code)
	}
}

// A malformed pool is refused with a reason that names the field, and nothing is saved.
func Test_a_malformed_pool_is_refused_with_its_reason(t *testing.T) {
	s := newTestServer()
	// Zero concurrency would deadlock rather than throttle.
	rec := do(t, s, http.MethodPost, "/api/pools", pool.Pool{Name: "p", MaxConcurrent: 0})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("a pool with no concurrency answered %d, want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "concurrent") {
		t.Errorf("the refusal (%q) does not say which field is wrong", strings.TrimSpace(rec.Body.String()))
	}
	if view := decodePools(t, do(t, s, http.MethodGet, "/api/pools", nil), http.StatusOK); view.Count != 0 {
		t.Errorf("a refused pool was saved anyway: %d pools", view.Count)
	}
}

// Editing or deleting a pool that is not there is 404, not a silent success.
func Test_acting_on_an_unsaved_pool_is_not_found(t *testing.T) {
	s := newTestServer()
	if rec := do(t, s, http.MethodDelete, "/api/pools/nonesuch", nil); rec.Code != http.StatusNotFound {
		t.Errorf("deleting an unsaved pool answered %d, want 404", rec.Code)
	}
	rec := do(t, s, http.MethodPut, "/api/pools/nonesuch", pool.Pool{Name: "nonesuch", MaxConcurrent: 1})
	if rec.Code != http.StatusNotFound {
		t.Errorf("editing an unsaved pool answered %d, want 404", rec.Code)
	}
}

// A pool a schedule still references cannot be deleted, and the refusal names the schedules.
//
// The failure this prevents: a dangling reference leaves the scheduled run to fall back to whatever
// bounds its tool defaults to, at the hour nobody is watching.
func Test_a_pool_a_schedule_references_cannot_be_deleted(t *testing.T) {
	s := newTestServer()
	do(t, s, http.MethodPost, "/api/pools", pool.Pool{Name: "Out Of Hours", MaxConcurrent: 2, DelayMs: 500})
	armed := do(t, s, http.MethodPost, "/api/schedules", schedule.Schedule{
		Name: "nightly", Kind: scheduleKindCrawl, Enabled: true,
		FirstMs: time.Now().Add(time.Hour).UnixMilli(), IntervalSecs: 24 * 3600,
		Pool:   "Out Of Hours",
		Params: json.RawMessage(`{"seeds":["https://example.test/"]}`),
	})
	if armed.Code != http.StatusCreated {
		t.Fatalf("arming the schedule answered %d: %s", armed.Code, strings.TrimSpace(armed.Body.String()))
	}

	rec := do(t, s, http.MethodDelete, "/api/pools/Out%20Of%20Hours", nil)
	if rec.Code != http.StatusConflict {
		t.Fatalf("deleting a referenced pool answered %d, want 409", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "nightly") {
		t.Errorf("the refusal (%q) does not name the schedule that still references the pool",
			strings.TrimSpace(rec.Body.String()))
	}
	// And the GET says so up front, so the console can show it before the operator tries.
	view := decodePools(t, do(t, s, http.MethodGet, "/api/pools", nil), http.StatusOK)
	if len(view.InUse["Out Of Hours"]) != 1 {
		t.Errorf("in_use reports %v for the referenced pool, want the one schedule", view.InUse)
	}

	// Delete the schedule and the pool becomes deletable — the refusal is about the reference, not a
	// permanent lock.
	if rec := do(t, s, http.MethodDelete, "/api/schedules/nightly", nil); rec.Code != http.StatusOK {
		t.Fatalf("deleting the schedule answered %d", rec.Code)
	}
	if rec := do(t, s, http.MethodDelete, "/api/pools/Out%20Of%20Hours", nil); rec.Code != http.StatusOK {
		t.Errorf("deleting the pool after its last reference went answered %d, want 200", rec.Code)
	}
}

// ---- schedules ---------------------------------------------------------------------------------

func decodeSchedules(t *testing.T, rec *httptest.ResponseRecorder, wantStatus int) schedulesView {
	t.Helper()
	if rec.Code != wantStatus {
		t.Fatalf("status %d, want %d: %s", rec.Code, wantStatus, strings.TrimSpace(rec.Body.String()))
	}
	var view schedulesView
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatalf("decoding the answer: %v (body: %s)", err, rec.Body.String())
	}
	return view
}

// The GET states what this build can start, what the clock has done, and — crucially — whether
// anything is watching the clock at all.
func Test_schedules_get_states_the_kinds_the_policy_and_whether_anything_is_ticking(t *testing.T) {
	s := newTestServer()
	view := decodeSchedules(t, do(t, s, http.MethodGet, "/api/schedules", nil), http.StatusOK)
	if view.Count != 0 {
		t.Errorf("a fresh server reports %d schedules", view.Count)
	}
	if len(view.Kinds) == 0 {
		t.Fatal("no kinds are registered, so nothing could ever be scheduled")
	}
	kinds := strings.Join(view.Kinds, ",")
	if !strings.Contains(kinds, scheduleKindCrawl) || !strings.Contains(kinds, scheduleKindAudit) {
		t.Errorf("the registered kinds are %v, want at least a crawl and an audit", view.Kinds)
	}
	if view.MissedWindowPolicy == "" {
		t.Error("the missed-window behaviour is not stated, so an operator would meet it as a surprise")
	}
	// A test server has no ticker on purpose. Reporting that honestly is what keeps a list of armed
	// schedules from claiming to be armed in a process that will never fire them.
	if view.Running {
		t.Error("a directly-constructed server claims to be running the scheduler; nothing started one")
	}
}

// A schedule naming a kind this build cannot start is refused at save time, not at 02:00.
func Test_a_schedule_naming_an_unstartable_kind_is_refused(t *testing.T) {
	s := newTestServer()
	rec := do(t, s, http.MethodPost, "/api/schedules", schedule.Schedule{
		Name: "n", Kind: "teleport", Enabled: true, FirstMs: time.Now().UnixMilli(),
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("a schedule naming an unknown kind answered %d, want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), scheduleKindCrawl) {
		t.Errorf("the refusal (%q) does not say what this build can start",
			strings.TrimSpace(rec.Body.String()))
	}
}

// A schedule naming a pool that is not saved is refused at save time too, and the refusal names the
// pools that are. Both checks are at save time for the same reason: a schedule that fails at 02:00
// fails where nobody is looking.
func Test_a_schedule_naming_an_unsaved_pool_is_refused(t *testing.T) {
	s := newTestServer()
	do(t, s, http.MethodPost, "/api/pools", pool.Pool{Name: "exists", MaxConcurrent: 1})
	rec := do(t, s, http.MethodPost, "/api/schedules", schedule.Schedule{
		Name: "n", Kind: scheduleKindCrawl, Enabled: true,
		FirstMs: time.Now().UnixMilli(), Pool: "nonesuch",
	})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("a schedule naming an unsaved pool answered %d, want 404", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "exists") {
		t.Errorf("the refusal (%q) does not name the pools that are saved",
			strings.TrimSpace(rec.Body.String()))
	}
}

// The schedule lifetime, and the counter-preserving edit.
func Test_a_schedule_can_be_created_edited_and_deleted(t *testing.T) {
	s := newTestServer()
	first := time.Now().Add(time.Hour).UnixMilli()
	created := decodeSchedules(t, do(t, s, http.MethodPost, "/api/schedules", schedule.Schedule{
		Name: "nightly crawl", Kind: scheduleKindCrawl, Enabled: true,
		FirstMs: first, IntervalSecs: 24 * 3600,
		Params: json.RawMessage(`{"seeds":["https://example.test/"]}`),
	}), http.StatusCreated)
	if created.Count != 1 {
		t.Fatalf("after one POST the server reports %d schedules", created.Count)
	}
	if created.Schedules[0].NextMs != first {
		t.Errorf("the schedule was armed for %d, want its first occurrence %d",
			created.Schedules[0].NextMs, first)
	}

	moved := time.Now().Add(48 * time.Hour).UnixMilli()
	edited := decodeSchedules(t, do(t, s, http.MethodPut, "/api/schedules/nightly%20crawl",
		schedule.Schedule{
			Name: "nightly crawl", Kind: scheduleKindCrawl, Enabled: false,
			FirstMs: moved, IntervalSecs: 24 * 3600,
		}), http.StatusOK)
	if edited.Schedules[0].NextMs != moved {
		t.Errorf("after an edit that moved the timing the schedule is armed for %d, want %d — an "+
			"un-re-armed schedule fires at the old time", edited.Schedules[0].NextMs, moved)
	}
	if edited.Schedules[0].Enabled {
		t.Error("the edit did not switch the schedule off")
	}

	if rec := do(t, s, http.MethodDelete, "/api/schedules/nightly%20crawl", nil); rec.Code != http.StatusOK {
		t.Errorf("deleting the schedule answered %d", rec.Code)
	}
}

// A due schedule actually starts the work — the seam from the clock to the task registry, driven at
// an instant this test chose rather than by waiting for one.
func Test_a_due_schedule_starts_a_registered_task(t *testing.T) {
	s := newTestServer()
	at := time.Now()
	if rec := do(t, s, http.MethodPost, "/api/schedules", schedule.Schedule{
		Name: "now", Kind: scheduleKindCrawl, Enabled: true, FirstMs: at.UnixMilli(),
		Params: json.RawMessage(`{"seeds":["https://example.test/"],"max_requests":1}`),
	}); rec.Code != http.StatusCreated {
		t.Fatalf("arming answered %d: %s", rec.Code, strings.TrimSpace(rec.Body.String()))
	}

	before := len(s.tasks.Snapshot())
	fired := s.schedules.Tick(at)
	if len(fired) != 1 {
		t.Fatalf("the tick acted on %d schedules, want 1", len(fired))
	}
	if !fired[0].Started {
		t.Fatalf("the due schedule did not start: %+v", fired[0])
	}
	if fired[0].Note == "" {
		t.Error("the firing left no note saying what it started")
	}
	if got := len(s.tasks.Snapshot()); got <= before {
		t.Errorf("the task registry holds %d tasks, was %d: a scheduled crawl that registers no task "+
			"would run invisibly", got, before)
	}
	// The counters move with it, which is what a settings page reads.
	view := decodeSchedules(t, do(t, s, http.MethodGet, "/api/schedules", nil), http.StatusOK)
	if view.Totals.Fired != 1 || view.Totals.Failed != 0 {
		t.Errorf("totals are fired=%d failed=%d, want 1 and 0", view.Totals.Fired, view.Totals.Failed)
	}
	if view.Schedules[0].Runs != 1 {
		t.Errorf("the schedule reports %d runs, want 1", view.Schedules[0].Runs)
	}
}

// A scheduled crawl whose params are unusable fails as a run rather than as silence: it counts as
// fired *and* failed, and the reason is on the schedule for an operator to read.
func Test_a_scheduled_crawl_with_unusable_params_reports_the_failure(t *testing.T) {
	s := newTestServer()
	at := time.Now()
	// No seeds: the crawl start refuses it, which is the same refusal the route gives.
	if rec := do(t, s, http.MethodPost, "/api/schedules", schedule.Schedule{
		Name: "broken", Kind: scheduleKindCrawl, Enabled: true, FirstMs: at.UnixMilli(),
		Params: json.RawMessage(`{"seeds":[]}`),
	}); rec.Code != http.StatusCreated {
		t.Fatalf("arming answered %d", rec.Code)
	}
	fired := s.schedules.Tick(at)
	if len(fired) != 1 || fired[0].Started {
		t.Fatalf("the tick produced %+v, want one entry that did not start", fired)
	}
	if fired[0].Err == "" {
		t.Error("the failure carries no reason")
	}
	view := decodeSchedules(t, do(t, s, http.MethodGet, "/api/schedules", nil), http.StatusOK)
	if view.Totals.Fired != 1 || view.Totals.Failed != 1 {
		t.Errorf("totals are fired=%d failed=%d, want 1 and 1: a start that returned an error still "+
			"happened, and it also failed", view.Totals.Fired, view.Totals.Failed)
	}
	if view.Schedules[0].LastNote == "" {
		t.Error("the schedule carries no note, so an operator cannot see why the nightly run failed")
	}
}

// A schedule's own pool wins over a stale one in its saved params, and the pair is not refused as a
// contradiction the operator never stated.
func Test_a_scheduled_crawls_pool_comes_from_the_schedule(t *testing.T) {
	s := newTestServer()
	do(t, s, http.MethodPost, "/api/pools", pool.Pool{Name: "slow", MaxConcurrent: 1, DelayMs: 1000})
	at := time.Now()
	if rec := do(t, s, http.MethodPost, "/api/schedules", schedule.Schedule{
		Name: "n", Kind: scheduleKindCrawl, Enabled: true, FirstMs: at.UnixMilli(), Pool: "slow",
		// requests_per_second is what a saved form carries. Together with a pool it would be refused as
		// a contradiction, so the starter must clear it.
		Params: json.RawMessage(`{"seeds":["https://example.test/"],"requests_per_second":50}`),
	}); rec.Code != http.StatusCreated {
		t.Fatalf("arming answered %d: %s", rec.Code, strings.TrimSpace(rec.Body.String()))
	}
	fired := s.schedules.Tick(at)
	if len(fired) != 1 || !fired[0].Started {
		t.Fatalf("the scheduled crawl did not start: %+v", fired)
	}
}

// ---- the tools referencing a pool by name --------------------------------------------------------

// A crawl can name a pool, and an unknown name is refused rather than run at a default.
func Test_a_crawl_can_name_a_pool_and_an_unknown_name_is_refused(t *testing.T) {
	s := newTestServer()
	do(t, s, http.MethodPost, "/api/pools", pool.Pool{Name: "slow", MaxConcurrent: 1, DelayMs: 1000})

	rec := do(t, s, http.MethodPost, "/api/crawl", map[string]any{
		"seeds": []string{"https://example.test/"}, "pool": "slow", "max_requests": 1,
	})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("a crawl naming a saved pool answered %d: %s", rec.Code,
			strings.TrimSpace(rec.Body.String()))
	}

	rec = do(t, s, http.MethodPost, "/api/crawl", map[string]any{
		"seeds": []string{"https://example.test/"}, "pool": "nonesuch",
	})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("a crawl naming an unsaved pool answered %d, want 404: running at a default while the "+
			"operator believes a pool is in force is the failure a named pool exists to prevent", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "slow") {
		t.Errorf("the refusal (%q) does not name the pools that are saved",
			strings.TrimSpace(rec.Body.String()))
	}
}

// A crawl that names a pool *and* an inline rate is refused, rather than one of the two being
// silently dropped.
func Test_a_crawl_cannot_name_a_pool_and_an_inline_rate(t *testing.T) {
	s := newTestServer()
	do(t, s, http.MethodPost, "/api/pools", pool.Pool{Name: "slow", MaxConcurrent: 1, DelayMs: 1000})
	rec := do(t, s, http.MethodPost, "/api/crawl", map[string]any{
		"seeds": []string{"https://example.test/"}, "pool": "slow", "requests_per_second": 50,
	})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("a crawl naming both a pool and a rate answered %d, want 400", rec.Code)
	}
}

// The inline crawl form still works with no pool at all, which is what every caller predating pools
// sends. A pool is a resolution step, not a replacement.
func Test_the_inline_crawl_form_still_works(t *testing.T) {
	s := newTestServer()
	rec := do(t, s, http.MethodPost, "/api/crawl", map[string]any{
		"seeds": []string{"https://example.test/"}, "requests_per_second": 2, "max_requests": 1,
	})
	if rec.Code != http.StatusAccepted {
		t.Errorf("an inline crawl answered %d: %s", rec.Code, strings.TrimSpace(rec.Body.String()))
	}
}

// An audit naming an unsaved pool is refused before any traffic is planned.
func Test_an_audit_naming_an_unsaved_pool_is_refused(t *testing.T) {
	s := newTestServer()
	rec := do(t, s, http.MethodPost, "/api/audit/0", map[string]any{"pool": "nonesuch"})
	if rec.Code != http.StatusNotFound {
		t.Errorf("an audit naming an unsaved pool answered %d, want 404", rec.Code)
	}
}

// An intruder attack naming an unsaved pool is refused, where it used to be accepted as a bare label
// and run at whatever the inline default was while the report named the pool.
//
// Asserted at Server.intruderLimits rather than over the wire, deliberately: POST /api/intruder/run
// resolves the stored message before it looks at any limit, so a request with no real message 404s
// for that reason instead. A wire-level test here would pass whether or not pool resolution existed —
// which is exactly the kind of assertion that looks like coverage and is not. The status mapping is
// covered by intruderLimitStatus below.
func Test_an_intruder_attack_naming_an_unsaved_pool_is_refused(t *testing.T) {
	s := newTestServer()
	do(t, s, http.MethodPost, "/api/pools", pool.Pool{Name: "slow", MaxConcurrent: 1, DelayMs: 1000})
	missing := "nonesuch"
	_, err := s.intruderLimits(intruderRunReq{Pool: &missing})
	if err == nil {
		t.Fatal("an attack naming an unsaved pool was accepted, so it would run unbounded while the " +
			"report named a pool that does not exist")
	}
	if !errors.Is(err, pool.ErrNoSuchPool) {
		t.Errorf("the refusal is %v, want ErrNoSuchPool so the route can answer 404", err)
	}
	if intruderLimitStatus(err) != http.StatusNotFound {
		t.Errorf("an unsaved pool maps to status %d, want 404", intruderLimitStatus(err))
	}
	if !strings.Contains(err.Error(), "slow") {
		t.Errorf("the refusal (%q) does not name the pools that are saved", err)
	}
}

// An attack that names a pool and its own limits is refused: two answers to "how fast may this run",
// one of which would be dropped while the report named the pool either way.
func Test_an_intruder_attack_cannot_name_a_pool_and_inline_limits(t *testing.T) {
	s := newTestServer()
	do(t, s, http.MethodPost, "/api/pools", pool.Pool{Name: "slow", MaxConcurrent: 1, DelayMs: 1000})
	name := "slow"
	rps := 50.0
	inFlight := 20
	for what, req := range map[string]intruderRunReq{
		"rps":           {Pool: &name, RPS: &rps},
		"max_in_flight": {Pool: &name, MaxInFlight: &inFlight},
		"auto_throttle": {Pool: &name, AutoThrottle: &intruder.AutoThrottle{Statuses: []int{429}}},
	} {
		if _, err := s.intruderLimits(req); err == nil {
			t.Errorf("an attack naming a pool and %s was accepted; one of the two numbers the operator "+
				"typed would be silently dropped", what)
		} else if intruderLimitStatus(err) != http.StatusBadRequest {
			t.Errorf("naming a pool and %s maps to status %d, want 400", what, intruderLimitStatus(err))
		}
	}
}

// The named pool resolves to the saved bounds, checked at the resolution point rather than through a
// live attack — the attack path is exercised by the intruder's own tests, and what is new here is the
// resolution.
func Test_an_intruder_pool_name_resolves_to_the_saved_bounds(t *testing.T) {
	s := newTestServer()
	do(t, s, http.MethodPost, "/api/pools", pool.Pool{
		Name: "two a second", MaxConcurrent: 3, DelayMs: 500,
		Throttle: &pool.Throttle{IncrementMs: 500},
	})
	name := "two a second"
	limits, err := s.intruderLimits(intruderRunReq{Pool: &name})
	if err != nil {
		t.Fatalf("resolving a saved pool: %v", err)
	}
	if limits.MaxInFlight != 3 {
		t.Errorf("max in flight is %d, want the saved 3", limits.MaxInFlight)
	}
	if limits.PerSecond == nil || *limits.PerSecond != 2 {
		t.Errorf("the rate is %v, want 2 a second (a 500ms delay)", limits.PerSecond)
	}
	if limits.AutoThrottle == nil {
		t.Error("the pool's automatic throttling did not reach the attack's limits")
	}
	if limits.Name != name {
		t.Errorf("the limit is named %q, want %q so the report can say what bounded the attack",
			limits.Name, name)
	}
}

// The inline intruder form is unchanged, including its own bounds at both ends.
func Test_the_inline_intruder_form_still_works(t *testing.T) {
	s := newTestServer()
	rps := 5.0
	limits, err := s.intruderLimits(intruderRunReq{RPS: &rps})
	if err != nil {
		t.Fatalf("the inline form was refused: %v", err)
	}
	if limits.PerSecond == nil || *limits.PerSecond != 5 {
		t.Errorf("the inline rate is %v, want 5", limits.PerSecond)
	}
	tooSlow := 0.0001
	if _, err := s.intruderLimits(intruderRunReq{RPS: &tooSlow}); err == nil {
		t.Error("a rate below the floor was accepted")
	}
}
