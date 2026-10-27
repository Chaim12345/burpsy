package web

import (
	"bytes"
	"fmt"
	"net/http"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/sender"
)

// Burp's "Request item again" (desktop/tools/intruder/results/workflow.html, burpsy-react-ui-2rw7):
// "Queue the selected items to be requested again by the attack engine … useful when attack requests
// have failed due to network errors". POST /api/intruder/again re-sends each named attempt's exact
// stored request — the bytes the attack put on the wire — through the same scope-gated sender every
// attempt uses, records the new request and response, and answers one replacement row per item.
//
// The attack itself is over by the time an operator reads its results, so this re-requests the
// stored bytes rather than re-running the engine: the grep and capture settings of the original
// attack are not re-applied, and the row says so by carrying no grep columns.

const maxIntruderAgain = 500

type intruderAgainReq struct {
	Target     string   `json:"target" desc:"the attack's target, scheme://host:port; each re-send is scope-checked against it"`
	RequestIDs []uint64 `json:"request_ids" desc:"stored request message ids of the attempts to re-send (an attack row's request_id), 1-500"`
}

type intruderAgainRow struct {
	// OriginalRequestID is the attempt's request as the attack sent it — the row being replaced.
	OriginalRequestID uint64  `json:"original_request_id"`
	RequestID         *uint64 `json:"request_id"`
	ResponseID        *uint64 `json:"response_id"`
	Status            *int    `json:"status"`
	ResponseLen       int     `json:"response_len"`
	DurationMS        int64   `json:"duration_ms"`
	Error             *string `json:"error"`
}

func (s *Server) handleIntruderAgain(w http.ResponseWriter, r *http.Request) {
	var req intruderAgainReq
	if err := requestJSON(w, r, nil).Decode(&req); err != nil {
		http.Error(w, "Body must be {\"target\": \"https://host:port\", \"request_ids\": [...]}", http.StatusBadRequest)
		return
	}
	if len(req.RequestIDs) == 0 || len(req.RequestIDs) > maxIntruderAgain {
		http.Error(w, fmt.Sprintf("request_ids must name 1 to %d attempts", maxIntruderAgain), http.StatusBadRequest)
		return
	}
	host, port, tls, err := targetParts(req.Target)
	if err != nil {
		http.Error(w, "bad target: "+err.Error(), http.StatusBadRequest)
		return
	}
	if s.sender == nil {
		http.Error(w, "No sender is attached to this server", http.StatusServiceUnavailable)
		return
	}
	auth := sender.NewAuthorisedSender(s.scope, s.sender, host, port, tls)
	rows := make([]intruderAgainRow, 0, len(req.RequestIDs))
	for _, id := range req.RequestIDs {
		row := intruderAgainRow{OriginalRequestID: id}
		fail := func(msg string) {
			row.Error = &msg
			rows = append(rows, row)
		}
		msg, gerr := s.store.Get(core.MsgId(id))
		if gerr != nil || bytes.HasPrefix(msg.Raw(), []byte("HTTP/")) {
			fail("no stored request with that id: the attack did not store this attempt's request")
			continue
		}
		raw := msg.Raw()
		res, serr := auth.Send(r.Context(), raw)
		if serr != nil {
			// Refused by scope or failed on the wire: the reason is the row's error, as an attempt's is.
			fail(serr.Error())
			continue
		}
		reqID, _ := s.store.Put(raw, core.DirectionRequest)
		reqU := uint64(reqID)
		row.RequestID = &reqU
		row.Status = res.Status
		row.DurationMS = res.Duration.Milliseconds()
		row.ResponseLen = len(res.Raw)
		if len(res.Raw) > 0 {
			respID, _ := s.store.Put(res.Raw, core.DirectionResponse)
			respU := uint64(respID)
			row.ResponseID = &respU
			ex := &core.Exchange{Request: core.MsgPtr(reqID), Response: &respID, Host: host, Port: port, TLS: tls,
				Source: core.SourceIntruder}
			if p, ok := requestTarget(raw); ok {
				ex.Method, ex.Path = p[0], p[1]
			}
			if res.Status != nil {
				st := uint16(*res.Status)
				ex.Status = &st
			}
			s.store.AddExchange(ex)
		}
		rows = append(rows, row)
	}
	writeJSON(w, http.StatusOK, map[string]any{"rows": rows})
}

// requestTarget reads the method and target off a raw request line.
func requestTarget(raw []byte) ([2]string, bool) {
	line := raw
	for i, b := range raw {
		if b == '\n' {
			line = raw[:i]
			break
		}
	}
	var method, target string
	if n, _ := fmt.Sscanf(string(line), "%s %s", &method, &target); n == 2 {
		return [2]string{method, target}, true
	}
	return [2]string{}, false
}
