package web

import (
	"encoding/json"
	"net/http"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/session"
)

// handleSessionMacroSteps serves POST /api/session/macro-steps: Burp's Macro Recorder.
//
// Burp's copy is explicit about where a macro's steps come from —
// settings/sessions/macros.html: "Macros are made up of requests taken from the Proxy history …
// Select the items you need from the Proxy history list" — and until this endpoint existed the
// console could only type them by hand, so reproducing a documented login flow meant transcribing a
// request the proxy had already captured (burpsy-react-ui-escl).
//
// # Why the conversion is server-side
//
// The stored request is origin-form (`POST /login HTTP/1.1`) with its authority carried on the
// exchange row, not in the URL. Turning that into a macro step is therefore a join between two
// records, and the join has rules — which port is omitted, how an IPv6 literal is bracketed, what
// happens when a header repeats — that the session package's own validator also depends on. Doing it
// in the browser would put a second copy of those rules next to the one that validates the saved
// rule, and the copy is what drifts: a step the UI builds but the validator refuses, or worse, one it
// accepts spelled differently from what the operator selected. So the rendering lives in
// session.MacroStepFromRequest and this handler is only the join.
//
// # The variant
//
// A history row has up to three readings of its request (original, auto-modified, edited — see
// core.Variant). The default is VariantEdited, the bytes that actually travelled, because a macro is
// meant to replay what the client sent. The variant is selectable because the other two are
// occasionally the point: an operator diagnosing a Match & Replace rule wants the pre-rule request.
//
// # Partial success is reported, never hidden
//
// A row whose request bytes are missing (evicted, or never captured) cannot become a step. The
// alternative to reporting that is a macro that is silently one step short, which fails at login time
// with nothing to point at. So the answer carries both lists: `steps` in the order asked for, and
// `skipped` naming each row dropped and why. The UI is responsible for showing the second list; the
// endpoint does not pretend a partial result is a whole one.
func (s *Server) handleSessionMacroSteps(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.store == nil {
		http.Error(w, "The exchange store is not wired, so no history row can be read", http.StatusServiceUnavailable)
		return
	}
	var body struct {
		Exchanges []uint64 `json:"exchanges"`
		Variant   string   `json:"variant"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if len(body.Exchanges) == 0 {
		// Not an empty success: a recorder handed no rows has recorded nothing, and answering
		// {"steps":[]} would look exactly like a successful recording of nothing.
		http.Error(w, "Name at least one exchange to record a macro from", http.StatusBadRequest)
		return
	}
	variant, ok := core.ParseVariant(body.Variant)
	if !ok {
		// ParseVariant refuses an unknown name rather than falling back, for the same reason here:
		// a caller asking for a reading that does not exist must not be answered with different
		// bytes than were asked for.
		http.Error(w, "variant must be one of original, auto-modified or edited", http.StatusBadRequest)
		return
	}

	type skippedRow struct {
		Exchange uint64 `json:"exchange"`
		Reason   string `json:"reason"`
	}
	steps := make([]sessionStepDto, 0, len(body.Exchanges))
	skipped := make([]skippedRow, 0)
	for _, rawID := range body.Exchanges {
		id := core.ExchangeID(rawID)
		ex, err := s.store.GetExchange(id)
		if err != nil {
			skipped = append(skipped, skippedRow{Exchange: rawID, Reason: "no such exchange"})
			continue
		}
		msgID, ok := ex.VariantFor(core.DirectionRequest, variant)
		if !ok {
			skipped = append(skipped, skippedRow{Exchange: rawID, Reason: "this exchange holds no request bytes"})
			continue
		}
		msg, err := s.message(uint64(msgID))
		if err != nil {
			skipped = append(skipped, skippedRow{Exchange: rawID, Reason: "this exchange's request bytes are not readable"})
			continue
		}
		step, err := session.MacroStepFromRequest(msg.Raw(), ex.Host, ex.Port, ex.TLS)
		if err != nil {
			skipped = append(skipped, skippedRow{Exchange: rawID, Reason: err.Error()})
			continue
		}
		steps = append(steps, macroStepToDto(step))
	}

	writeJSON(w, http.StatusOK, map[string]any{"steps": steps, "skipped": skipped})
}
