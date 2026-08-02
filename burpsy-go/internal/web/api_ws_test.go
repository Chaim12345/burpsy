package web

// The WebSocket capture surface, exercised through the mux rather than by
// calling the handlers directly, because the contract under test is the JSON
// wshistory.ts reads — field names included. A handler that returned the right
// values under the wrong keys would pass a direct call and leave the tab blank.

import (
	"encoding/json"
	"net/http"
	"strconv"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

// wsTestServer returns a server over a store the caller can populate.
func wsTestServer() (*Server, *core.TrafficStore) {
	store := core.NewTrafficStore()
	return NewServer(store, core.NewScope()), store
}

// addWsHandshake records a handshake exchange and returns its id, which is what
// every message on that connection names.
func addWsHandshake(store *core.TrafficStore, host string, port uint16, path string) uint64 {
	ex := &core.Exchange{Host: host, Port: port, Path: path, Method: "GET", Protocol: core.ProtocolHTTP1}
	store.AddExchange(ex)
	return ex.ID
}

func addWsMessage(store *core.TrafficStore, exchange uint64, fromClient bool, opcode core.WsOpcode, payload string, atMs uint64) core.MsgId {
	return store.AddWsMessage(&core.WsMessage{
		Exchange:   exchange,
		FromClient: fromClient,
		Opcode:     opcode,
		Len:        len(payload),
		Fragments:  1,
		AtMs:       atMs,
	}, []byte(payload))
}

func decodeWsHistory(t *testing.T, s *Server, path string) wsHistoryResp {
	t.Helper()
	rec := get(t, s, path)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s = %d, want 200: %s", path, rec.Code, rec.Body.String())
	}
	var resp wsHistoryResp
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
	return resp
}

func TestWsHistoryServesTheCapturedMessagesNewestFirstWithTheirTotal(t *testing.T) {
	s, store := wsTestServer()
	ex := addWsHandshake(store, "chat.test", 80, "/socket")
	addWsMessage(store, ex, true, core.WsOpcodeText, "first", 1000)
	addWsMessage(store, ex, false, core.WsOpcodeText, "second", 2000)

	resp := decodeWsHistory(t, s, "/api/ws/history")
	if resp.Total != 2 {
		t.Errorf("total = %d, want 2; the UI pages against this number, so an undercount hides messages that were captured", resp.Total)
	}
	if len(resp.Rows) != 2 {
		t.Fatalf("rows = %d, want 2", len(resp.Rows))
	}
	if resp.Rows[0].AtMs != 2000 {
		t.Errorf("the newest message is not first (at_ms = %d), so a live socket pushes new traffic off the end of the page", resp.Rows[0].AtMs)
	}
	if resp.Rows[0].Direction != "server_to_client" || resp.Rows[1].Direction != "client_to_server" {
		t.Errorf("directions came back as %q/%q; the two sides of a socket are not interchangeable",
			resp.Rows[0].Direction, resp.Rows[1].Direction)
	}
	if resp.Rows[0].Opcode != "text" {
		t.Errorf("opcode = %q, want text", resp.Rows[0].Opcode)
	}
}

func TestWsHistoryFilteredByConnectionKeepsTheWholeIndexAsTheTotal(t *testing.T) {
	s, store := wsTestServer()
	a := addWsHandshake(store, "a.test", 80, "/a")
	b := addWsHandshake(store, "b.test", 80, "/b")
	addWsMessage(store, a, true, core.WsOpcodeText, "one", 1000)
	addWsMessage(store, b, true, core.WsOpcodeText, "two", 2000)
	addWsMessage(store, b, false, core.WsOpcodeText, "three", 3000)

	resp := decodeWsHistory(t, s, "/api/ws/history?exchange="+itoa(b))
	if len(resp.Rows) != 2 {
		t.Fatalf("rows = %d, want the 2 messages on connection b", len(resp.Rows))
	}
	for _, row := range resp.Rows {
		if row.Exchange != b {
			t.Errorf("row from exchange %d leaked into connection %d's page", row.Exchange, b)
		}
	}
	if resp.Total != 3 {
		t.Errorf("total = %d, want 3; filtering narrows the rows, not the size of the index they came from", resp.Total)
	}
}

func TestWsConnectionsGroupsMessagesByHandshakeAndCountsEachDirection(t *testing.T) {
	// Burp has no equivalent endpoint — its WebSockets history is a flat list
	// with a socket-id column and no per-connection aggregate. This is the
	// deliberate divergence, so it is tested as a contract rather than left to
	// the UI to derive.
	s, store := wsTestServer()
	a := addWsHandshake(store, "a.test", 8080, "/alpha")
	b := addWsHandshake(store, "b.test", 443, "/beta")
	addWsMessage(store, a, true, core.WsOpcodeText, "hello", 1000)
	addWsMessage(store, a, false, core.WsOpcodeText, "hi", 1500)
	addWsMessage(store, a, true, core.WsOpcodeText, "again", 1800)
	addWsMessage(store, b, false, core.WsOpcodeBinary, "\x00\x01", 9000)

	rec := get(t, s, "/api/ws/connections")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/ws/connections = %d: %s", rec.Code, rec.Body.String())
	}
	var conns []wsConnectionView
	if err := json.Unmarshal(rec.Body.Bytes(), &conns); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
	if len(conns) != 2 {
		t.Fatalf("connections = %d, want 2; four messages across two sockets must fold to two rows", len(conns))
	}
	if conns[0].Exchange != b {
		t.Errorf("connections are not ordered by most recent activity; first row is exchange %d", conns[0].Exchange)
	}

	var alpha *wsConnectionView
	for i := range conns {
		if conns[i].Exchange == a {
			alpha = &conns[i]
		}
	}
	if alpha == nil {
		t.Fatal("the first connection is missing from the fold")
	}
	if alpha.Messages != 3 || alpha.Sent != 2 || alpha.Received != 1 {
		t.Errorf("counts = %d messages (%d sent, %d received), want 3 (2 sent, 1 received)",
			alpha.Messages, alpha.Sent, alpha.Received)
	}
	if alpha.Host != "a.test" || alpha.Port != 8080 || alpha.Path != "/alpha" {
		t.Errorf("the connection was not joined to its handshake: %s:%d%s", alpha.Host, alpha.Port, alpha.Path)
	}
	if alpha.LastMs != 1800 {
		t.Errorf("last_ms = %d, want the newest message's timestamp 1800", alpha.LastMs)
	}
}

func TestWsMessageServesOnePayloadAsBothTextAndHex(t *testing.T) {
	s, store := wsTestServer()
	ex := addWsHandshake(store, "chat.test", 80, "/socket")
	id := addWsMessage(store, ex, true, core.WsOpcodeBinary, "\x00\xffhi", 1000)

	rec := get(t, s, "/api/ws/message/"+itoa(uint64(id)))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET message = %d: %s", rec.Code, rec.Body.String())
	}
	var resp wsMessageResp
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
	if resp.Hex != "00ff6869" {
		t.Errorf("hex = %q, want 00ff6869; a binary frame is unreadable as text, so the hex view is the only honest rendering", resp.Hex)
	}
	if resp.ID != uint64(id) || resp.Opcode != "binary" {
		t.Errorf("the row was not flattened into the response: id = %d, opcode = %q", resp.ID, resp.Opcode)
	}
}

func TestWsMessageDecodesACloseFramesStatusAsANumberNotAsTwoCharacters(t *testing.T) {
	s, store := wsTestServer()
	ex := addWsHandshake(store, "chat.test", 80, "/socket")
	id := addWsMessage(store, ex, false, core.WsOpcodeClose, "\x03\xe8going away", 1000)

	rec := get(t, s, "/api/ws/message/"+itoa(uint64(id)))
	var resp wsMessageResp
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
	if resp.Close == nil {
		t.Fatal("a close frame came back with no decoded status, leaving the UI to render 0x03 0xe8 as mojibake instead of 1000")
	}
	if resp.Close.Code != 1000 || resp.Close.Reason != "going away" {
		t.Errorf("close = %d %q, want 1000 \"going away\"", resp.Close.Code, resp.Close.Reason)
	}
}

func TestATruncatedRowSaysSoRatherThanPresentingItsLengthAsTheMessageSize(t *testing.T) {
	s, store := wsTestServer()
	ex := addWsHandshake(store, "chat.test", 80, "/socket")
	store.AddWsMessage(&core.WsMessage{
		Exchange:  ex,
		Opcode:    core.WsOpcodeText,
		Len:       4,
		Dropped:   9000,
		Fragments: 3,
		AtMs:      1000,
		Note:      "message exceeded the capture cap",
	}, []byte("kept"))

	resp := decodeWsHistory(t, s, "/api/ws/history")
	row := resp.Rows[0]
	if !row.Truncated {
		t.Error("a row that dropped bytes is not flagged truncated, so len reads as the size of the message when it is the size of what survived")
	}
	if row.Dropped != 9000 {
		t.Errorf("dropped = %d, want 9000; the shortfall has to be countable, not merely implied", row.Dropped)
	}
	if row.Note == "" {
		t.Error("the note explaining the shortfall was dropped on the way to the UI")
	}
	if row.Fragments != 3 {
		t.Errorf("fragments = %d, want 3", row.Fragments)
	}
}

func TestAWsMessageThatWasNeverCapturedIsReportedMissingRatherThanEmpty(t *testing.T) {
	s, _ := wsTestServer()
	rec := get(t, s, "/api/ws/message/42")
	if rec.Code != http.StatusNotFound {
		t.Errorf("GET /api/ws/message/42 = %d, want 404; an empty 200 is indistinguishable from a genuinely empty frame", rec.Code)
	}
}

func TestTheWsSurfaceIsEmptyRatherThanBrokenBeforeAnythingIsCaptured(t *testing.T) {
	s, _ := wsTestServer()
	resp := decodeWsHistory(t, s, "/api/ws/history")
	if resp.Total != 0 || len(resp.Rows) != 0 {
		t.Errorf("a fresh store reported %d rows of %d", len(resp.Rows), resp.Total)
	}
	rec := get(t, s, "/api/ws/connections")
	if rec.Code != http.StatusOK || rec.Body.String() == "null\n" {
		t.Errorf("connections on a fresh store = %d %q, want 200 and an empty array (null makes the picker throw)", rec.Code, rec.Body.String())
	}
}

func itoa(v uint64) string { return strconv.FormatUint(v, 10) }
