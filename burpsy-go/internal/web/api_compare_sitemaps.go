package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"

	"github.com/burpsy-go/burpsy/internal/core"
)

// Compare site maps (burpsy-react-ui-k3a7): Burp's context-menu action, "Compares site maps,
// helping you to find access control vulnerabilities and identify areas to inspect manually."
//
// What a site map IS here: the set of (host, port, tls, path) tuples a run reached — the tree
// /api/sitemap folds from the same store, minus the per-node aggregation. The comparison Burp
// offers is between two crawl sessions, so the unit is the run: every exchange the dashboard
// registry attributed to task A, against every exchange attributed to task B. TaskID attribution
// is stamped at capture (crawler.WithTaskID → cfg.Capture.TaskID), which is what makes "the path
// set of crawl A vs crawl B" a query the store can answer without guessing from timestamps.
//
// The diff is presence-only, by design. Two crawls that reach the same URL with different
// payloads have not discovered different surface: what access-control analysis needs is "the
// anonymous crawl never saw /admin, the authenticated one did" — and mixing in content
// differences would bury that in per-request noise the byte Comparer already serves. The row
// answer names which side(s) a path is present on, so an operator can see the shape of the
// access difference at a glance and jump to history for the bytes.

// sitemapPathDiffRow is one path's presence verdict across the two runs.
type sitemapPathDiffRow struct {
	// Host, Port and TLS name the authority, the same identity the site map's host nodes carry
	// (see sitemapNodeView). Port and TLS rather than a composed "host:port" string, so a client
	// can address the exact connection tuple without parsing.
	Host string `json:"host"`
	Port uint16 `json:"port"`
	TLS  bool   `json:"tls"`
	Path string `json:"path"`
	// Side says which run(s) reached it: "a", "b" or "both".
	Side string `json:"side"`
	// StatusA/StatusB are each run's first status for the path, 0 when that run never reached it.
	// One path can carry several statuses across a run's requests; the first is the honest
	// headline, and the full set is in history behind the task field the grammar gained with
	// this bead (`task = N`).
	StatusA int `json:"status_a,omitempty"`
	StatusB int `json:"status_b,omitempty"`
}

// toolsCompareSitemapsReq is the request body handleToolsCompareSitemaps decodes (hoisted for its published schema, burpsy-react-ui-3zw0).
type toolsCompareSitemapsReq struct {
	TaskA uint64 `json:"task_a"`
	TaskB uint64 `json:"task_b"`
}

// handleToolsCompareSitemaps serves POST /api/tools/compare-sitemaps.
//
// POST rather than GET because the two task ids are a work request rather than a resource name —
// the same call this API's other compare route makes. riskRead: nothing is sent to any target;
// the walk is over the local store.
func (s *Server) handleToolsCompareSitemaps(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req toolsCompareSitemapsReq
	if err := requestJSON(w, r, http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if req.TaskA == 0 || req.TaskB == 0 {
		http.Error(w, "Both task_a and task_b are required — a site map comparison is between two runs", http.StatusBadRequest)
		return
	}
	if req.TaskA == req.TaskB {
		http.Error(w, "task_a and task_b are the same run; comparing a site map with itself answers nothing", http.StatusBadRequest)
		return
	}

	// Walk the store once, keeping only the two runs' rows. Task ids start at 1 (dash.Registry),
	// so a stored 0 means "no task owns this row" and no operator can name it here — which is
	// also why the request refuses 0 above rather than quietly diffing "everything untracked".
	type presence struct {
		seenA, seenB     bool
		statusA, statusB int
	}
	reached := make(map[[3]string] /*host|port|tls*/ map[string]*presence)
	keyOf := func(ex *core.Exchange) [3]string {
		return [3]string{ex.Host, fmt.Sprintf("%d", ex.Port), fmt.Sprintf("%v", ex.TLS)}
	}
	for _, ex := range s.store.Exchanges() {
		if ex.TaskID != req.TaskA && ex.TaskID != req.TaskB {
			continue
		}
		authority := keyOf(ex)
		byPath := reached[authority]
		if byPath == nil {
			byPath = make(map[string]*presence)
			reached[authority] = byPath
		}
		p := byPath[ex.Path]
		if p == nil {
			p = &presence{}
			byPath[ex.Path] = p
		}
		status := 0
		if ex.Status != nil {
			status = int(*ex.Status)
		}
		if ex.TaskID == req.TaskA {
			p.seenA = true
			if p.statusA == 0 {
				p.statusA = status
			}
		} else {
			p.seenB = true
			if p.statusB == 0 {
				p.statusB = status
			}
		}
	}

	// The answer is sorted — authority, then path — because an operator scanning for "what did the
	// authenticated crawl see that the anonymous one did not" reads the tree the site map taught
	// them, and a reshuffling diff is one nobody can scan.
	authorities := make([][3]string, 0, len(reached))
	for k := range reached {
		authorities = append(authorities, k)
	}
	sort.Slice(authorities, func(i, j int) bool {
		if reached[authorities[i]] == nil {
			return false
		}
		if authorities[i][0] != authorities[j][0] {
			return authorities[i][0] < authorities[j][0]
		}
		return authorities[i][1] < authorities[j][1]
	})

	rows := make([]sitemapPathDiffRow, 0, 64)
	onlyA, onlyB, both := 0, 0, 0
	for _, auth := range authorities {
		byPath := reached[auth]
		paths := make([]string, 0, len(byPath))
		for p := range byPath {
			paths = append(paths, p)
		}
		sort.Strings(paths)
		var port uint16
		var tls bool
		fmt.Sscanf(auth[1], "%d", &port)
		tls = auth[2] == "true"
		for _, path := range paths {
			p := byPath[path]
			side := "both"
			switch {
			case p.seenA && !p.seenB:
				side = "a"
				onlyA++
			case p.seenB && !p.seenA:
				side = "b"
				onlyB++
			default:
				both++
			}
			rows = append(rows, sitemapPathDiffRow{
				Host: auth[0], Port: port, TLS: tls,
				Path: path, Side: side,
				StatusA: p.statusA, StatusB: p.statusB,
			})
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"task_a": req.TaskA,
		"task_b": req.TaskB,
		"rows":   rows,
		// The summary counts are derived from rows, but computed server-side so the two cannot
		// drift: a client that summed the rows its page happens to hold would under-report on a
		// truncated list, and "only in A: 12" is exactly the sentence an operator reports.
		"only_a": onlyA,
		"only_b": onlyB,
		"both":   both,
	})
}
