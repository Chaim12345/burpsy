package web

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/dash"
	"github.com/burpsy-go/burpsy/internal/query"
)

// ---- Passively scan a branch (burpsy-react-ui-p09) ---------------------------------------------
//
// Burp offers "Passively scan this branch" and "Passively scan selected branches" from the site map.
// burpsy had the scanner and no way to point it at a subtree.
//
// # The two decisions this needed before it needed code
//
// **What risk class.** A passive sweep sends nothing: it re-reads responses already in the store. So
// it fits none of the manifest's classes by analogy, and copying /api/scanner/audit's riskAttack
// would have been wrong. riskRead understates it — a sweep produces findings, and findings are what
// an operator reports, so manufacturing them under an unattended caller's control is not a read.
// riskAttack overstates it and would demand confirmation for an operation that touches no target,
// which trains operators to click through the confirmations that matter. It is riskLocal: it mutates
// burpsy's own findings state and sends no traffic. Recorded in the manifest next to the route, which
// is the whole reason that field exists.
//
// **What scope means for bytes already captured.** This is the one with a wrong answer that looks
// right. The responses were captured earlier, possibly while the scope was wider than it is now, so
// re-scanning can produce a finding about a host the operator has since excluded.
//
// The choice made here: the sweep FILTERS by current scope, and reports how many exchanges it skipped
// for that reason. Scope is the standing statement of what this engagement may touch, and a finding
// about an excluded host is one an operator cannot act on and should not report. But skipping
// silently would make the counts unreconcilable against the branch — an operator would point at 40
// paths, see 12 scanned, and have no way to learn why. So the count is partitioned and the skip has
// its own field.
//
// # Why the counts are a partition and not a summary
//
// scanned + skipped_out_of_scope + skipped_no_response == matched, always. internal/crawler's Report
// is the model: a caller can always answer "what happened to the other ones", which is what makes a
// report readable as coverage rather than as a highlight reel. A sweep that answered only
// "12 findings" could not be reconciled against anything the operator can see.

// passiveBranchReq names the subtree to sweep.
type passiveBranchReq struct {
	// Host is required. A sweep with no host is the whole store, which is what the live audit already
	// does and is not what "this branch" means.
	Host string `json:"host"`
	// PathPrefix narrows within the host. Empty means the whole host, which is Burp's "scan this
	// branch" pointed at the root.
	PathPrefix string `json:"path_prefix"`
	// Port, when non-zero, narrows to one port. Zero means every port on the host, because a site map
	// branch is an authority and an operator pointing at example.com means both 80 and 443.
	Port uint16 `json:"port"`
	// Exclude is Burp's pre-scan filter step (burpsy-react-ui-a13), as a query over this package's own
	// filter grammar: exchanges the query does not match are dropped from the sweep before the
	// scanner sees them. Empty means no filter, so every caller predating this field is unchanged.
	//
	// A query that MATCHES the items to drop — the opposite polarity from /api/history?q=, which
	// keeps what it matches. Same grammar, same adapter, opposite question, and the field is named
	// `exclude` so the polarity is stated rather than inferred.
	//
	// A query rather than four booleans because the filters and the filter language are then one
	// thing. Burp's shipped list (`extension != "js"` and its siblings) is a query like any other, an
	// operator can narrow past the presets, and "what filtered this sweep" is a string the audit
	// trail can record — none of which four booleans would give.
	Exclude string `json:"exclude,omitempty"`
}

// passiveBranchResp is the sweep's whole outcome.
type passiveBranchResp struct {
	Host       string `json:"host"`
	PathPrefix string `json:"path_prefix,omitempty"`
	Port       uint16 `json:"port,omitempty"`

	// Matched is every stored exchange in the branch, before any filtering.
	Matched int `json:"matched"`
	// Scanned is how many were handed to the scanner.
	Scanned int `json:"scanned"`
	// SkippedOutOfScope is how many were in the branch and refused by the CURRENT scope. Its own
	// field because these were captured — possibly under a wider scope — and an operator who cannot
	// see this number cannot reconcile Scanned against Matched.
	SkippedOutOfScope int `json:"skipped_out_of_scope"`
	// SkippedNoResponse is how many had no response to scan. A passive check reads a response; a
	// request still in flight is not a failure and not a clean result either.
	SkippedNoResponse int `json:"skipped_no_response"`

	// Findings is how many the sweep produced, after the finding store's own deduplication — so it
	// is what an operator will actually see, not how many times a check fired.
	Findings int `json:"findings"`
	// Filtered is how many were in the branch and removed by the operator's pre-scan filter, before
	// any of the sweep's own gates. Its own field for the reason the others have one: without it,
	// "12 scanned of 40" cannot be reconciled — an operator who asked to drop static assets and then
	// watched 20 of them vanish would have no way to learn the filter ran at all.
	Filtered int `json:"filtered"`
	// Exclude echoes the filter the sweep actually applied, so the response states the rule rather
	// than leaving the caller to remember what it sent.
	Exclude string `json:"exclude,omitempty"`
	// Loaded is how many passive checks were available. Zero means the sweep ran and could not have
	// found anything, which is not the same as a clean branch, and the caller must not render them
	// alike.
	Loaded int `json:"loaded"`
	// Summary states the counts with their caveats in one line, so a surface that renders nothing
	// else still cannot present a partial result as a complete one.
	Summary string `json:"summary"`
}

// handlePassiveBranch serves POST /api/scanner/passive-branch.
func (s *Server) handlePassiveBranch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req passiveBranchReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	req.Host = strings.TrimSpace(req.Host)
	if req.Host == "" {
		http.Error(w, "A host is required: a sweep with no host is the whole store, which is what the "+
			"live audit already does and is not what scanning a branch means", http.StatusBadRequest)
		return
	}
	if s.passiveScanner == nil {
		http.Error(w, "No passive scanner is attached to this server, so nothing could be scanned",
			http.StatusServiceUnavailable)
		return
	}

	// The pre-scan filter (a13), compiled once and refused with the grammar's own error — the caret
	// included — rather than a boolean that silently does nothing. An operator who typed a filter the
	// server ignored would be reading a sweep that did not honour it, which is the exact failure
	// the honest-counting rule exists to prevent.
	//
	// Empty means no filter rather than a query that matches nothing: a nil *queryFilter matches
	// everything, which is what an absent filter has to mean, and the same shape /api/history?q= uses.
	var filter *queryFilter
	if trimmed := strings.TrimSpace(req.Exclude); trimmed != "" {
		var err error
		filter, err = compileQuery(trimmed, s.store)
		if err != nil {
			http.Error(w, "The pre-scan filter is not a valid query:\n"+query.Render(err), http.StatusBadRequest)
			return
		}
	}

	resp := passiveBranchResp{
		Host:       req.Host,
		PathPrefix: req.PathPrefix,
		Port:       req.Port,
		Exclude:    strings.TrimSpace(req.Exclude),
		Loaded:     s.passiveScanner.Loaded(),
	}

	// The task exists so the sweep appears on the dashboard like every other unit of work, and so its
	// findings carry a task id an operator can correlate. Total is unknown until the store has been
	// walked, so it starts at 0 and the breakdown at the end carries the real numbers.
	task := s.tasks.Start(dash.KindPassiveBranch, req.Host+req.PathPrefix, 0)

	for _, ex := range s.store.Exchanges() {
		if !branchContains(ex, req) {
			continue
		}
		resp.Matched++

		// The operator's filter, ahead of every gate the sweep owns: a filtered exchange is one the
		// operator asked not to spend on, so it leaves before the no-response and scope partitions
		// count it. Putting it after them would report the same exchange as both filtered and
		// skipped, and the partition would no longer add up.
		if filter != nil && filter.match(ex) {
			resp.Filtered++
			continue
		}

		if ex.Response == nil {
			// A passive check reads a response. No response is not a clean result.
			resp.SkippedNoResponse++
			continue
		}
		// Current scope, not the scope in force when this was captured. See the file comment: a
		// finding about a host the operator has since excluded is one they cannot act on.
		if !s.scope.Contains(ex.Host, ex.Port, ex.Path, ex.TLS) {
			resp.SkippedOutOfScope++
			continue
		}

		resp.Scanned++
		for _, f := range s.passiveScanner.Scan(ex) {
			s.findings.Add(s.activeFinding(f, task.ID()))
			resp.Findings++
		}
	}

	resp.Summary = passiveBranchSummary(resp)

	// The breakdown is the same partition the response carries, in the dashboard's vocabulary, so the
	// coverage summary cannot disagree with what this endpoint answered. Gated, not Skipped, for the
	// scope refusals: those are work a policy declined, which is what Gated means here, and folding
	// them into Skipped would lose the reason.
	task.FinishWithNote(dash.Breakdown{
		Found:   uint64(resp.Findings),
		Skipped: uint64(resp.SkippedNoResponse),
		Gated:   uint64(resp.SkippedOutOfScope + resp.Filtered),
	}, resp.Summary)

	s.live.notify(changeIssues)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// branchContains decides whether one exchange is in the requested subtree.
//
// Path matching is a prefix on the path only, with the query string included in what is compared —
// core.Exchange.Path carries it — because a branch is a path space and `/app` should match
// `/app/x?y=1`. It is case-sensitive per RFC 3986, matching the query DSL's `path` field rather than
// inventing a second rule.
func branchContains(ex *core.Exchange, req passiveBranchReq) bool {
	if !strings.EqualFold(ex.Host, req.Host) {
		return false
	}
	if req.Port != 0 && ex.Port != req.Port {
		return false
	}
	if req.PathPrefix != "" && !strings.HasPrefix(ex.Path, req.PathPrefix) {
		return false
	}
	return true
}

// passiveBranchSummary states the counts and the caveats that make them readable.
//
// The order is deliberate: what was found, then what was not looked at and why. A summary that led
// with the finding count would let a reader stop before the part that says how much of the branch the
// number covers.
func passiveBranchSummary(r passiveBranchResp) string {
	if r.Matched == 0 {
		return "no captured exchange is in this branch, so nothing was scanned — this says nothing " +
			"about the branch, only that burpsy has not seen it"
	}

	var b strings.Builder

	// What happened to the branch, first. An earlier version returned the no-checks caveat and
	// stopped, which swallowed the skip accounting: a branch where the current scope refused every
	// exchange AND no checks were loaded reported only the checks, so the operator never learned that
	// their scope was the reason nothing ran. Both facts are real and both are actionable, so the
	// summary composes rather than short-circuits.
	if r.Findings == 0 {
		b.WriteString("no findings")
	} else {
		b.WriteString(plural(r.Findings, "finding", "findings"))
	}
	b.WriteString(" from ")
	b.WriteString(plural(r.Scanned, "exchange", "exchanges"))
	b.WriteString(" of the ")
	b.WriteString(strconv.Itoa(r.Matched))
	b.WriteString(" in this branch")

	var skips []string
	if r.Filtered > 0 {
		filter := "the pre-scan filter"
		if r.Exclude != "" {
			filter = "the pre-scan filter (" + r.Exclude + ")"
		}
		skips = append(skips, strconv.Itoa(r.Filtered)+" removed by "+filter)
	}
	if r.SkippedOutOfScope > 0 {
		skips = append(skips, strconv.Itoa(r.SkippedOutOfScope)+" refused by the current scope (they "+
			"were captured, possibly under a wider scope)")
	}
	if r.SkippedNoResponse > 0 {
		skips = append(skips, strconv.Itoa(r.SkippedNoResponse)+" with no response to scan")
	}
	if len(skips) > 0 {
		b.WriteString("; not scanned: ")
		b.WriteString(strings.Join(skips, ", "))
	}

	// The caveat last, and unconditional on the counts above: with no checks loaded the sweep could
	// not have found anything, so "no findings" above is not a statement about the target.
	if r.Loaded == 0 {
		b.WriteString(". No passive checks are loaded, so the sweep could not have found anything — " +
			"this is not a clean branch")
	}
	return b.String()
}

func plural(n int, one, many string) string {
	if n == 1 {
		return strconv.Itoa(n) + " " + one
	}
	return strconv.Itoa(n) + " " + many
}
