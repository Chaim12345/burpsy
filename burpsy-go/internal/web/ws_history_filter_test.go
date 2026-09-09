package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

// The frame-list filter (burpsy-react-ui-5k4): direction, opcode and payload substring, answered
// by the same endpoint the page lists from. Server-side on purpose — a frame's payload bytes are
// not on the row, so a client-side substring filter could only ever hide the frame whose detail
// fetch had landed.

// putWsMessages loads a store with frames across both directions, several opcodes and
// distinguishable payloads, newest-first ordering preserved by the store itself.
func putWsMessages(t *testing.T, s *Server) {
	t.Helper()
	ex := core.ExchangeID(0)
	mk := func(fromClient bool, opcode core.WsOpcode, payload string) {
		s.store.AddWsMessage(&core.WsMessage{
			Exchange:   ex,
			FromClient: fromClient,
			Opcode:     opcode,
			Len:        len(payload),
		}, []byte(payload))
	}
	mk(true, core.WsOpcodeText, `{"role":"user"}`)
	mk(false, core.WsOpcodeText, `{"role":"ADMIN token=abc"}`)
	mk(true, core.WsOpcodeBinary, "\x00\x01rawbytes")
	mk(false, core.WsOpcodePing, "pingdata")
}

func wsHistoryGet(t *testing.T, s *Server, query string) (int, []wsRowView) {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/ws/history"+query, nil)
	s.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		return rec.Code, nil
	}
	var body wsHistoryResp
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode history: %v", err)
	}
	return rec.Code, body.Rows
}

func TestWsHistoryFiltersByDirectionOpcodeAndPayload(t *testing.T) {
	s := newTestServer()
	putWsMessages(t, s)

	// Unfiltered: every frame is listed.
	if _, rows := wsHistoryGet(t, s, ""); len(rows) != 4 {
		t.Fatalf("unfiltered history has %d rows, want 4", len(rows))
	}

	// Direction narrows to the sent frames.
	_, sent := wsHistoryGet(t, s, "?direction=client_to_server")
	if len(sent) != 2 {
		t.Fatalf("direction filter left %d rows, want the 2 sent frames", len(sent))
	}
	for _, row := range sent {
		if row.Direction != "client_to_server" {
			t.Errorf("a %s frame survived the client_to_server filter", row.Direction)
		}
	}

	// Opcode narrows independently.
	_, pings := wsHistoryGet(t, s, "?opcode=ping")
	if len(pings) != 1 || pings[0].Opcode != "ping" {
		t.Fatalf("opcode filter left %+v, want exactly the ping", pings)
	}

	// Payload substring is case-insensitive over the stored bytes and reaches frames whose
	// bytes are not on any row.
	_, admin := wsHistoryGet(t, s, "?payload=admin")
	if len(admin) != 1 || admin[0].Direction != "server_to_client" {
		t.Fatalf("payload filter left %+v, want exactly the ADMIN frame", admin)
	}

	// The three compose: text frames carrying "role", whichever direction.
	_, both := wsHistoryGet(t, s, "?opcode=text&payload=role")
	if len(both) != 2 {
		t.Fatalf("opcode+payload left %d rows, want the 2 text role frames", len(both))
	}

	// An empty result is a valid answer, not an error: the connection holds no frame matching
	// the substring, which is what the empty state must be able to distinguish from "nothing
	// captured at all".
	if _, none := wsHistoryGet(t, s, "?payload=nothing-matches-this"); len(none) != 0 {
		t.Fatalf("a substring nothing carries matched %d rows", len(none))
	}
}

// An unknown direction or opcode value is refused rather than ignored — the same rule the
// exchange parameter follows. A filter that silently does not filter would answer with every
// frame while the operator believes they are looking at a narrowed list.
func TestWsHistoryRefusesUnknownFilterValues(t *testing.T) {
	s := newTestServer()
	putWsMessages(t, s)

	for _, q := range []string{"?direction=both", "?opcode=notanopcode"} {
		code, _ := wsHistoryGet(t, s, q)
		if code != http.StatusBadRequest {
			t.Errorf("%s answered %d, want 400 — an unknown filter value must be refused, not ignored", q, code)
		}
	}
}
