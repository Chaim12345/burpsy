package pool

// Which of a pool's bounds each tool path actually enforces.
//
// # Why this is data and not a paragraph in a doc
//
// ROADMAP.md is explicit that concurrency must be gated behind a limiter because unbounded
// parallelism DoSes the target, and this tree's house rule is that a gated or unhonoured thing is
// reported rather than silently dropped. A pool is a promise made in a settings dialog and kept — or
// not — three layers away in three different tools. A promise whose exceptions live in prose gets
// read by nobody and drifts on the first refactor.
//
// So the exceptions are a value the API returns. GET /api/pools serves this table, the console
// renders it beside the pools, and Test_every_tool_states_which_pool_bounds_it_honours fails if a
// tool is added without an entry. An operator who saves a pool with 8 concurrent requests can see,
// without reading any Go, that the crawler will still send one at a time.

// Honoured says, for one tool path, which of a pool's three bounds that path enforces.
//
// "Not honoured" here never means "exceeded silently" — that would be a defect, not a caveat. It
// means the bound does not constrain this path, and Detail says why. Under-use is as much a
// departure from what the operator typed as over-use, and both belong in the same table.
type Honoured struct {
	// Tool is the surface, named as the operator meets it.
	Tool string `json:"tool"`
	// Route is the API path that accepts a pool name for this tool, so the claim is checkable.
	Route string `json:"route"`
	// MaxConcurrent is whether this path bounds requests in flight by the pool's ceiling.
	MaxConcurrent bool `json:"max_concurrent"`
	// Delay is whether this path spaces requests by the pool's delay.
	Delay bool `json:"delay"`
	// Throttle is whether this path reacts to the target with the pool's automatic throttling.
	Throttle bool `json:"throttle"`
	// Detail explains any false above, and is empty only when all three are true.
	Detail string `json:"detail,omitempty"`
}

// Complete reports whether this path enforces every bound a pool carries.
func (h Honoured) Complete() bool { return h.MaxConcurrent && h.Delay && h.Throttle }

// Support is the whole table, one row per tool path that accepts a pool name.
//
// Returned as a fresh slice so a caller that sorts or filters it cannot edit the answer.
func Support() []Honoured {
	return []Honoured{
		{
			Tool: "Intruder", Route: "POST /api/intruder/run",
			MaxConcurrent: true, Delay: true, Throttle: true,
		},
		{
			Tool: "Scanner (audit)", Route: "POST /api/audit/{id}",
			MaxConcurrent: true, Delay: true, Throttle: true,
		},
		{
			Tool: "Crawler", Route: "POST /api/crawl",
			MaxConcurrent: false, Delay: true, Throttle: true,
			Detail: "the crawl loop is sequential — it sends one request at a time and waits for the " +
				"response before building the next — so a concurrency ceiling above 1 bounds nothing " +
				"here. The delay and the throttle are applied per host as well as across the crawl.",
		},
	}
}

// Unhonoured is every row that does not enforce all three bounds. The count an honest surface
// leads with: "3 tools accept a pool; 1 cannot honour every bound".
func Unhonoured() []Honoured {
	var out []Honoured
	for _, h := range Support() {
		if !h.Complete() {
			out = append(out, h)
		}
	}
	return out
}
