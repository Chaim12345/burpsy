package web

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/burpsy-go/burpsy/internal/pool"
)

// Named resource pools: Burp's configPanelResourcePools, as an API.
//
// # What was missing, precisely
//
// The limits themselves were never missing. internal/intruder/limit.go has had a token bucket, an
// in-flight bound and an auto-throttle since the intruder landed, and POST /api/intruder/run has
// accepted rps, max_in_flight and auto_throttle per call for as long. What did not exist was a pool
// as an *object*: `RateLimit.Name` was documented as "an identifier, not a handle: nothing here looks
// it up", so every tool re-specified its own bounds and an operator had no way to say "everything in
// this engagement runs at two requests a second" once. The crawler hard-coded five requests a second
// and the audit path was not rate limited at all.
//
// These four routes are that object's lifetime. Resolution — name to bounds — happens in exactly one
// place (pool.Registry.Limiter), and every tool that accepts a pool name goes through it.
//
// # Why the GET answer carries a table of exceptions
//
// A pool is a promise made here and kept three layers away in three different tools, and one of
// those tools cannot keep all of it: the crawl loop is sequential, so a max-concurrent above 1 bounds
// nothing there. ROADMAP.md is explicit that concurrency must be gated because unbounded parallelism
// DoSes the target, and this tree's rule is that a bound not honoured is reported rather than
// dropped. So pool.Support() is served as data beside the pools, and `unhonoured_bounds` counts it —
// an operator reads "3 tools accept a pool; 1 cannot honour every bound" instead of reading Go.
//
// Every mutation answers with the whole confirmed state, the convention the passthrough, scanner-
// config and proxy-option endpoints share: a client never renders a state it has not seen confirmed.

// poolsView is one GET's answer.
type poolsView struct {
	Pools []pool.Pool `json:"pools"`
	// Count is len(Pools), stated rather than left to the client to compute — an empty list and a
	// failed fetch look identical in a UI that infers the count, and those are different facts.
	Count int `json:"count"`
	// Default is what a New dialog should open on: the intruder's own long-standing defaults written
	// as a pool. Served rather than hard-coded in TypeScript so the first pool an operator saves
	// cannot be more aggressive than what the tools already did, and so the two cannot drift.
	Default pool.Pool `json:"default"`
	// Support is which of a pool's bounds each tool path actually enforces, and UnhonouredBounds is
	// how many of those rows fall short. See the file docs.
	Support          []pool.Honoured `json:"support"`
	UnhonouredBounds int             `json:"unhonoured_bounds"`
	// InUse maps a pool's name to the schedules that reference it. The reason a DELETE can be
	// refused, surfaced before the operator tries it rather than as an error afterwards.
	InUse map[string][]string `json:"in_use"`
}

// handlePools serves GET/POST /api/pools.
func (s *Server) handlePools(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.viewPools())

	case http.MethodPost:
		var p pool.Pool
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			http.Error(w, "Body must be a JSON resource pool: name, max_concurrent, delay_ms and an optional throttle", http.StatusBadRequest)
			return
		}
		if err := s.pools.Add(p); err != nil {
			// A duplicate name is 409 rather than 400: the request is well-formed and the operator's
			// mistake is about the state of the world, not the shape of what they sent. The name is the
			// pool's identity — it is what a tool references — so two pools sharing one is not cosmetic.
			status := http.StatusBadRequest
			if errors.Is(err, pool.ErrDuplicateName) {
				status = http.StatusConflict
			}
			http.Error(w, err.Error(), status)
			return
		}
		writeJSON(w, http.StatusCreated, s.viewPools())

	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handlePoolDetail serves PUT/DELETE /api/pools/{name}.
//
// The name is in the path and may also appear in a PUT body, and they are allowed to differ: that is
// how a rename is expressed — the path says which pool to replace, the body says what it becomes.
func (s *Server) handlePoolDetail(w http.ResponseWriter, r *http.Request) {
	// The verb guard precedes the path parse so a GET here is 405 and not "pool not found". A wrong
	// verb is a wrong verb whether or not the pool exists, and the route manifest's 405 test drives
	// exactly this URL.
	switch r.Method {
	case http.MethodPut, http.MethodDelete:
	default:
		w.Header().Set("Allow", "PUT, DELETE")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	name, ok := pathName(r.URL.Path, "/api/pools/")
	if !ok {
		http.Error(w, "The path must name a pool: /api/pools/{name}", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodPut:
		var p pool.Pool
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			http.Error(w, "Body must be a JSON resource pool", http.StatusBadRequest)
			return
		}
		// An empty name in the body means "keep the one in the path", so an edit that changes only the
		// limits does not have to restate the name. A body that names a *different* pool is a rename and
		// is applied as one.
		if strings.TrimSpace(p.Name) == "" {
			p.Name = name
		}
		if err := s.pools.Update(name, p); err != nil {
			http.Error(w, err.Error(), poolErrStatus(err))
			return
		}
		writeJSON(w, http.StatusOK, s.viewPools())

	case http.MethodDelete:
		// Refused while a schedule references it, and the refusal names them. A dangling reference
		// would leave a scheduled run to fall back to whatever bounds its tool defaults to, at the
		// exact hour nobody is watching — which is the failure a named pool exists to prevent, so
		// deleting one out from under a schedule cannot be allowed to cause it quietly.
		if used := s.schedules.UsingPool(name); len(used) > 0 {
			http.Error(w, fmt.Sprintf(
				"Pool %q still bounds %s (%s), so deleting it would leave %s running under whatever "+
					"limits its tool defaults to. Point them at another pool first, or delete them.",
				name, countNoun(len(used), "schedule"), strings.Join(used, ", "),
				pluralThey(len(used))), http.StatusConflict)
			return
		}
		if !s.pools.Remove(name) {
			http.Error(w, fmt.Sprintf("No pool named %q is saved", name), http.StatusNotFound)
			return
		}
		writeJSON(w, http.StatusOK, s.viewPools())
	}
}

// viewPools assembles the whole confirmed state.
func (s *Server) viewPools() poolsView {
	pools := s.pools.List()
	inUse := make(map[string][]string, len(pools))
	for _, p := range pools {
		if used := s.schedules.UsingPool(p.Name); len(used) > 0 {
			inUse[p.Name] = used
		}
	}
	return poolsView{
		Pools:            pools,
		Count:            len(pools),
		Default:          pool.DefaultPool(""),
		Support:          pool.Support(),
		UnhonouredBounds: len(pool.Unhonoured()),
		InUse:            inUse,
	}
}

// poolErrStatus maps a registry error to the status that describes it.
//
// Three outcomes rather than one, because they need different actions from the operator: a name
// nothing holds is 404 (the pool is gone — reload), a name another pool holds is 409 (pick another),
// and anything else is a malformed pool at 400. Collapsing them into 400 would tell an operator to
// fix what they typed when what they actually need to do is refresh.
func poolErrStatus(err error) int {
	switch {
	case errors.Is(err, pool.ErrNoSuchPool):
		return http.StatusNotFound
	case errors.Is(err, pool.ErrDuplicateName):
		return http.StatusConflict
	default:
		return http.StatusBadRequest
	}
}

// pathName pulls a percent-decoded object name out of a subtree path.
//
// Decoded because a pool name is operator prose — "engagement 4 — production, out of hours" is a
// legal name, and its spaces and dashes reach the URL percent-encoded. A path that decodes to empty
// is refused rather than treated as the whole collection: the caller asked to act on one object.
func pathName(path, prefix string) (string, bool) {
	raw := strings.TrimSuffix(strings.TrimPrefix(path, prefix), "/")
	if raw == "" {
		return "", false
	}
	decoded, err := url.PathUnescape(raw)
	if err != nil {
		return "", false
	}
	decoded = strings.TrimSpace(decoded)
	if decoded == "" {
		return "", false
	}
	return decoded, true
}

// countNoun writes a count with its noun pluralised, so no message has to say "1 schedules".
func countNoun(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

// pluralThey picks the pronoun for a count, for the same reason countNoun exists.
func pluralThey(n int) string {
	if n == 1 {
		return "it"
	}
	return "them"
}
