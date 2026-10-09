package web

// The filtered, long-polling half of POST /api/collaborator/poll (burpsy-react-ui-myr2).
//
// Burp's poll_for_collaborator_interactions takes payload ids and, optionally, wait_seconds and
// min_interactions: "block until at least min_interactions arrive or this many seconds elapse". Before
// this, burpsy's poll re-read the whole log and answered at once, so an agent waiting for a blind
// callback had to spin on status, re-reading every interaction of the engagement each time.
//
// The reply is the ordinary status object with a "poll" block added, so a caller that reads only the
// status keeps working. The block's status follows Burp's three words:
//
//   - complete: at least min_interactions attributable to the named payloads are in the log;
//   - timeout: wait_seconds elapsed with fewer — the ones that did arrive are listed;
//   - empty: none at all (a non-blocking poll, or a wait that saw nothing).
//
// and a fourth burpsy adds, because the honest answer differs: unavailable — no channel is open, so
// nothing can arrive and the call does not wait for nothing.
//
// wait_seconds is bounded at 60, below Burp's 300: a long-poll holds an HTTP request (and an MCP tool
// call) open for its whole wait, and 60 seconds sits well inside every client timeout on the path. A
// caller wanting longer polls again. Recorded in gaps.md.

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

// collaboratorPollReq is POST /api/collaborator/poll's optional body.
type collaboratorPollReq struct {
	PayloadIDs      []string `json:"payload_ids" desc:"payload addresses (or their markers) minted here to poll for; empty means every payload"`
	WaitSeconds     int      `json:"wait_seconds" desc:"long-poll: block until min_interactions arrive or this many seconds elapse (1-60); 0 returns at once"`
	MinInteractions int      `json:"min_interactions" desc:"interactions to wait for; default 1; only used with wait_seconds"`
}

func (q collaboratorPollReq) empty() bool {
	return len(q.PayloadIDs) == 0 && q.WaitSeconds == 0 && q.MinInteractions == 0
}

// maxCollaboratorWaitSeconds bounds a long-poll; see the file comment.
const maxCollaboratorWaitSeconds = 60

// collaboratorPollInterval is how often a long-poll re-reads the local log. The log is a local file
// the client subprocess appends to, so a re-read is cheap; half a second keeps a callback's latency
// well under the client's own server-poll interval.
var collaboratorPollInterval = 500 * time.Millisecond

// collaboratorPollView is the poll block.
type collaboratorPollView struct {
	Status string `json:"status"`
	// PayloadIDs is the payload addresses this poll was attributed to, resolved from the request.
	PayloadIDs      []string `json:"payload_ids"`
	MinInteractions int      `json:"min_interactions"`
	WaitSeconds     int      `json:"wait_seconds"`
	WaitedMs        int64    `json:"waited_ms"`
	// Received is how many interactions in the log are attributable to those payloads; Distinct counts
	// them after one lookup's resolver fan-out is collapsed, per payload (collaboratorEventKey).
	Received int `json:"received"`
	Distinct int `json:"distinct"`
	// Interactions are their index rows (no raw bytes — fetch one with GET
	// /api/collaborator/interaction/{id}). Always an array.
	Interactions []collaboratorInteractionRow `json:"interactions"`
	Hint         string                       `json:"hint,omitempty"`
}

type collaboratorPollReply struct {
	collaboratorStatus
	Poll collaboratorPollView `json:"poll"`
}

// resolvePayloadIDs maps requested ids — full addresses or bare markers, any case — to the minted
// payloads' addresses, and names the ones that match nothing.
func resolvePayloadIDs(ids []string, minted []mintedPayload) (addresses []string, unknown []string) {
	if len(ids) == 0 {
		for _, p := range minted {
			addresses = append(addresses, p.Address)
		}
		return addresses, nil
	}
	for _, id := range ids {
		want := strings.ToLower(strings.TrimSpace(id))
		found := ""
		for _, p := range minted {
			if want == strings.ToLower(p.Address) || want == strings.ToLower(p.Marker) {
				found = p.Address
				break
			}
		}
		if found == "" {
			unknown = append(unknown, id)
			continue
		}
		addresses = append(addresses, found)
	}
	return addresses, unknown
}

func (s *Server) collaboratorLongPoll(w http.ResponseWriter, r *http.Request, req collaboratorPollReq) {
	if req.WaitSeconds < 0 || req.WaitSeconds > maxCollaboratorWaitSeconds {
		http.Error(w, fmt.Sprintf("wait_seconds must be 0..%d; a longer wait is a second poll", maxCollaboratorWaitSeconds), http.StatusBadRequest)
		return
	}
	if req.MinInteractions < 0 {
		http.Error(w, "min_interactions must be at least 1", http.StatusBadRequest)
		return
	}
	minWant := req.MinInteractions
	if minWant == 0 {
		minWant = 1
	}

	minted, _ := s.collab().snapshot()
	addresses, unknown := resolvePayloadIDs(req.PayloadIDs, minted)
	if len(unknown) > 0 {
		// Refused rather than waited on: a payload this process never minted cannot be attributed, so
		// the wait would run its full length for nothing and then report "empty" as though it meant
		// "no callback".
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error":               "payload_ids names payloads this process did not mint",
			"unknown_payload_ids": unknown,
		})
		return
	}
	want := make(map[string]bool, len(addresses))
	for _, a := range addresses {
		want[a] = true
	}

	start := time.Now()
	deadline := start.Add(time.Duration(req.WaitSeconds) * time.Second)
	for {
		status := s.collaboratorStatusNow(true)
		view := collaboratorPollView{
			PayloadIDs:      append([]string{}, addresses...),
			MinInteractions: minWant,
			WaitSeconds:     req.WaitSeconds,
			Interactions:    []collaboratorInteractionRow{},
		}
		if status.State != collabActive && status.State != collabOpen {
			view.Status = "unavailable"
			view.Hint = "no out-of-band channel is open (state " + status.State + "), so no interaction can arrive; " + status.Hint
			view.WaitedMs = time.Since(start).Milliseconds()
			writeJSON(w, http.StatusOK, collaboratorPollReply{status, view})
			return
		}
		if status.Interactions == nil {
			// The read failed. Said, not waited through: a wait over a log that cannot be read would
			// end as "empty", which is the one answer that would be false.
			view.Status = "unavailable"
			view.Hint = "the interaction log could not be read"
			if status.LastRead != nil {
				view.Hint += ": " + status.LastRead.Error
			}
			view.WaitedMs = time.Since(start).Milliseconds()
			writeJSON(w, http.StatusOK, collaboratorPollReply{status, view})
			return
		}
		all, _ := s.collaboratorInteractions()
		for _, row := range collaboratorRows(all, minted) {
			if row.Payload != "" && want[row.Payload] {
				view.Interactions = append(view.Interactions, row)
				// Collapsed is scoped to the row's own payload (collaboratorEventKey), and every
				// row of a wanted payload is in this view, so the row it folds into is counted here.
				if !row.Collapsed {
					view.Distinct++
				}
			}
		}
		view.Received = len(view.Interactions)
		done := view.Received >= minWant
		expired := req.WaitSeconds == 0 || !time.Now().Before(deadline)
		if done || expired || r.Context().Err() != nil {
			switch {
			case done:
				view.Status = "complete"
			case view.Received == 0:
				view.Status = "empty"
			default:
				view.Status = "timeout"
				view.Hint = fmt.Sprintf("received %d (expected at least %d)", view.Received, minWant)
			}
			view.WaitedMs = time.Since(start).Milliseconds()
			writeJSON(w, http.StatusOK, collaboratorPollReply{status, view})
			return
		}
		wait := collaboratorPollInterval
		if left := time.Until(deadline); left < wait {
			wait = left
		}
		select {
		case <-r.Context().Done():
		case <-time.After(wait):
		}
	}
}
