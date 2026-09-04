package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/intruder"
	"github.com/burpsy-go/burpsy/internal/pool"
	"github.com/burpsy-go/burpsy/internal/schedule"
)

// Scheduled tasks: Burp's configPanelScheduledTasks and configPanelTaskAutoStart, as an API.
//
// # What a schedule is here
//
// A name, a kind, a first occurrence, an optional interval, an optional resource pool, and the
// kind's own parameters. The kinds are registered by this file — a crawl and an audit — because this
// is the layer that can actually start either, and internal/schedule deliberately knows nothing
// about tasks (see its package docs on why it owns the clock and not the work).
//
// A schedule naming a kind this build cannot start is refused at save time by the runner, so an
// operator cannot arm something that would fail at 02:00. A schedule naming a pool that is not saved
// is refused here, for the same reason and at the same moment.
//
// # The missed-window behaviour, stated where an operator can read it
//
// A schedule outlives the process, so the interesting case is a window that passed while burpsy was
// not running. The decision is internal/schedule's and it is (3) of three: do not fire, count what
// was missed, arm the next occurrence. Firing every missed occurrence would put a week of nightly
// crawls on a production target at once; firing one "catch-up" run would start an out-of-hours scan
// at half past nine in the morning, in the middle of the working day it was scheduled to avoid.
//
// This endpoint serves that policy as a string on the GET, and the per-schedule `missed` count
// beside it. A behaviour chosen and left undocumented is a behaviour an operator discovers from an
// incident, so it is stated in the API, in schedule's package docs, and in the commit.

// scheduleKind values are the wire names of what can be started on a schedule. Constants rather than
// bare strings so the registration and the UI's option list cannot disagree by a typo.
const (
	scheduleKindCrawl  = "crawl"
	scheduleKindAudit  = "audit"
	scheduleKindBackup = "backup"
)

// missedWindowPolicy is what happens to an occurrence whose window passed while nothing was running.
// Served to the client so the console can state it where the operator is configuring the schedule,
// rather than leaving it to be discovered.
const missedWindowPolicy = "An occurrence that came due while burpsy was not running does not fire " +
	"late: it is counted as missed and the next occurrence is armed. Catching up would run every " +
	"missed occurrence at once, and a single late run would start in a window the schedule was " +
	"written to avoid."

// schedulesView is one GET's answer.
type schedulesView struct {
	Schedules []schedule.Schedule `json:"schedules"`
	// Count is len(Schedules), stated for the reason poolsView.Count is: an empty list and a failed
	// fetch are different facts, and a client that computes the count cannot tell them apart.
	Count int `json:"count"`
	// Kinds is what this build can start on a schedule. Served rather than hard-coded in the console,
	// so a build without a capability cannot offer it.
	Kinds []string `json:"kinds"`
	// Pools is the saved pool names a schedule may reference, so the form need not fetch twice.
	Pools []string `json:"pools"`
	// Totals is the process's own account of what the clock has done. Four numbers because there are
	// four outcomes — see schedule.Runner.Totals.
	Totals scheduleTotals `json:"totals"`
	// MissedWindowPolicy is missedWindowPolicy. On the wire because the behaviour is a decision, and a
	// decision an operator cannot read is one they will meet as a surprise.
	MissedWindowPolicy string `json:"missed_window_policy"`
	// Running says whether anything is consulting the clock. A schedule list served by a process with
	// no ticker would otherwise look armed while nothing could ever fire — the exact "looks configured,
	// does nothing" reading every honesty rule in this package exists to prevent.
	Running bool `json:"running"`
}

// scheduleTotals is Runner.Totals in a shape with names on the wire.
type scheduleTotals struct {
	// Fired is occurrences whose work was started; Failed is the subset of those whose start returned
	// an error. Both, because "it fired" and "it worked" are different facts: 30 and 30 is a schedule
	// failing every night, and either number alone reads as healthy.
	Fired  int `json:"fired"`
	Failed int `json:"failed"`
	// Missed is occurrences written off unrun, and Unstarted is occurrences due for a kind nothing in
	// this build could start. Different faults with different fixes, so not one number.
	Missed    int `json:"missed"`
	Unstarted int `json:"unstarted"`
}

// handleSchedules serves GET/POST /api/schedules.
func (s *Server) handleSchedules(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.viewSchedules())

	case http.MethodPost:
		sc, err := s.decodeSchedule(r)
		if err != nil {
			http.Error(w, err.Error(), scheduleErrStatus(err))
			return
		}
		if err := s.schedules.Add(sc); err != nil {
			http.Error(w, err.Error(), scheduleErrStatus(err))
			return
		}
		writeJSON(w, http.StatusCreated, s.viewSchedules())

	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleScheduleDetail serves PUT/DELETE /api/schedules/{name}.
func (s *Server) handleScheduleDetail(w http.ResponseWriter, r *http.Request) {
	// Verb before path, matching handlePoolDetail: a wrong verb is 405 whether or not the schedule
	// exists, and the route manifest's 405 test drives this URL directly.
	switch r.Method {
	case http.MethodPut, http.MethodDelete:
	default:
		w.Header().Set("Allow", "PUT, DELETE")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	name, ok := pathName(r.URL.Path, "/api/schedules/")
	if !ok {
		http.Error(w, "The path must name a schedule: /api/schedules/{name}", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodPut:
		sc, err := s.decodeSchedule(r)
		if err != nil {
			http.Error(w, err.Error(), scheduleErrStatus(err))
			return
		}
		if strings.TrimSpace(sc.Name) == "" {
			sc.Name = name
		}
		if err := s.schedules.Update(name, sc); err != nil {
			http.Error(w, err.Error(), scheduleErrStatus(err))
			return
		}
		writeJSON(w, http.StatusOK, s.viewSchedules())

	case http.MethodDelete:
		if !s.schedules.Remove(name) {
			http.Error(w, fmt.Sprintf("No schedule named %q is saved", name), http.StatusNotFound)
			return
		}
		writeJSON(w, http.StatusOK, s.viewSchedules())
	}
}

// decodeSchedule reads a schedule off the wire and checks the one thing the runner cannot: that the
// pool it references is saved.
//
// The runner owns "is this kind startable" because it holds the starters; this layer owns "is this
// pool saved" because it holds the registry. Both are refused at save time rather than at fire time,
// which is the whole point — a schedule that fails at 02:00 fails where nobody is looking, and the
// operator's next information about it is a target that was never scanned.
func (s *Server) decodeSchedule(r *http.Request) (schedule.Schedule, error) {
	var sc schedule.Schedule
	if err := json.NewDecoder(r.Body).Decode(&sc); err != nil {
		return sc, errors.New("Body must be a JSON schedule: name, kind, first_ms, and optionally interval_secs, pool and params")
	}
	if sc.Pool != "" {
		if _, err := s.pools.Get(sc.Pool); err != nil {
			return sc, fmt.Errorf("%w (saved pools: %s)", err, availablePools(s.pools))
		}
	}
	return sc, nil
}

// scheduleErrStatus maps a save failure to its status, for the reasons poolErrStatus gives.
func scheduleErrStatus(err error) int {
	switch {
	case errors.Is(err, schedule.ErrNoSuchSchedule), errors.Is(err, pool.ErrNoSuchPool):
		return http.StatusNotFound
	case errors.Is(err, schedule.ErrDuplicateName):
		return http.StatusConflict
	default:
		return http.StatusBadRequest
	}
}

// viewSchedules assembles the whole confirmed state.
func (s *Server) viewSchedules() schedulesView {
	fired, failed, missed, unstarted := s.schedules.Totals()
	list := s.schedules.List()
	return schedulesView{
		Schedules:          list,
		Count:              len(list),
		Kinds:              s.schedules.Kinds(),
		Pools:              s.pools.Names(),
		Totals:             scheduleTotals{Fired: fired, Failed: failed, Missed: missed, Unstarted: unstarted},
		MissedWindowPolicy: missedWindowPolicy,
		Running:            s.schedulerRunning.Load(),
	}
}

// ---- what a schedule can start -----------------------------------------------------------------

// registerScheduleKinds teaches the runner what this build can start.
//
// Called from NewServer, so a schedule restored from disk finds its kind registered by the time the
// first tick happens. Each starter is deliberately thin: it decodes the kind's params and calls the
// same function the corresponding route calls, so a scheduled crawl and a clicked crawl are one code
// path. A starter that re-implemented its tool would be the version nobody watches, and therefore
// the version that drifts.
//
// Each returns promptly — the work runs on a goroutine the tool itself owns — because Tick holds no
// lock while a starter runs but does run them in sequence.
func (s *Server) registerScheduleKinds() {
	s.schedules.Register(scheduleKindCrawl, func(ctx context.Context, sc schedule.Schedule) (string, error) {
		var req crawlStartReq
		if len(sc.Params) > 0 {
			if err := json.Unmarshal(sc.Params, &req); err != nil {
				return "", fmt.Errorf("this schedule's params are not a crawl request: %w", err)
			}
		}
		// The schedule's pool wins over anything in the params, because the schedule is where the
		// operator set it and the params are a saved copy of a form. Cleared rather than compared: a
		// params blob carrying a stale pool name would otherwise make startCrawl refuse the pair as a
		// contradiction the operator never stated.
		req.Pool = sc.Pool
		if sc.Pool != "" {
			// The inline rate goes with it, for the same reason: startCrawl refuses a pool and an inline
			// rate together, and a saved form almost always carries one.
			req.RequestsPerSecond = 0
		}
		taskID, seeds, err := s.startCrawl(req)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("crawl task %d from %s", taskID, strings.Join(seeds, ", ")), nil
	})

	// The project backup — Burp's configPanelAutomaticProjectBackup (W6 #2). Nothing in this build
	// ever copied the project file: persistence existed, and an operator who lost the machine lost
	// the engagement.
	//
	// A schedule rather than a write-triggered copy because Store.Backup is VACUUM INTO, which reads
	// the whole database and writes a whole snapshot — O(size) in time and disk. Firing that per
	// write would make the proxy slower the longer an engagement ran, which is the wrong shape of
	// cost for a background safety net.
	s.schedules.Register(scheduleKindBackup, func(ctx context.Context, sc schedule.Schedule) (string, error) {
		var params backupParams
		if len(sc.Params) > 0 {
			if err := json.Unmarshal(sc.Params, &params); err != nil {
				return "", fmt.Errorf("this schedule's params are not a backup request: %w", err)
			}
		}
		return s.runProjectBackup(params)
	})

	s.schedules.Register(scheduleKindAudit, func(ctx context.Context, sc schedule.Schedule) (string, error) {
		var params struct {
			ExchangeID *uint64 `json:"exchange_id"`
			Config     string  `json:"config"`
		}
		if len(sc.Params) > 0 {
			if err := json.Unmarshal(sc.Params, &params); err != nil {
				return "", fmt.Errorf("this schedule's params are not an audit request: %w", err)
			}
		}
		// A pointer, because exchange ids are a dense counter from zero: exchange 0 is the first request
		// of the session and a real target, so "absent" cannot be spelled as 0. Both audit routes make
		// the same distinction for the same reason.
		if params.ExchangeID == nil {
			return "", errors.New("a scheduled audit needs params.exchange_id: the exchange to audit")
		}
		cfg, named, err := s.resolveAuditConfig(params.Config)
		if err != nil {
			return "", err
		}
		limiter, err := s.poolLimiter(sc.Pool)
		if err != nil {
			return "", err
		}
		id := core.ExchangeID(*params.ExchangeID)
		// Detached from the tick's context on purpose, for the reason a crawl started from a request is
		// detached from r.Context(): an audit outlives the tick that started it, and Tick returns as soon
		// as every starter has. The bound that stops it is the audit's own wall-clock budget.
		go func() {
			auditCtx := pool.WithLimiter(context.Background(), limiter)
			s.runAudit(auditCtx, id, cfg, named)
			s.live.notify(changeIssues)
			s.live.notify(changeDashboard)
		}()
		return fmt.Sprintf("audit of exchange %d", id), nil
	})
}

// poolLimiter resolves a pool name to the one live limiter every tool under that name shares, or nil
// for no pool at all.
//
// nil is unpaced and is the state every tool was in before pools existed. What must never happen is
// a *named* pool resolving to nil, which is why the error is returned rather than swallowed: running
// unbounded while an operator believes a pool is in force is the failure mode this whole unit exists
// to close, and it would show up as a target under more load than anyone authorised.
func (s *Server) poolLimiter(name string) (*intruder.RateLimiter, error) {
	if strings.TrimSpace(name) == "" {
		return nil, nil
	}
	limiter, err := s.pools.Limiter(name)
	if err != nil {
		return nil, fmt.Errorf("%w (saved pools: %s)", err, availablePools(s.pools))
	}
	return limiter, nil
}

// runScheduler consults the clock until ctx ends.
//
// Started from ListenAndServe rather than NewServer, and that is the point rather than a
// convenience: a Server built in a test has no ticker, so nothing fires behind a test's back and
// every schedule test drives Tick at an instant it chose. The flag it sets is served as
// schedulesView.Running, so a list of armed schedules can never claim to be armed in a process that
// is not watching the clock.
func (s *Server) runScheduler(ctx context.Context, resolution time.Duration) {
	s.schedulerRunning.Store(true)
	defer s.schedulerRunning.Store(false)
	s.schedules.Run(ctx, resolution)
}
