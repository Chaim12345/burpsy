package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A Repeater tab's note (burpsy-react-ui-jva5) is recorded as the sent exchange's comment, and
// from there it travels: Organizer's add copies it onto the item. Burp: "if you send a message
// from Repeater to another tool, your notes and highlights are copied across."
//
// Driven through the real routes — /api/repeater/send, GET /api/exchange/{id}, POST
// /api/tools/organizer, GET /api/tools/organizer — and asserted on the marshalled JSON each one
// returns, because the note's whole value is that a different surface can read it.
func TestARepeaterTabNoteRidesTheExchangeIntoOrganizer(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer origin.Close()
	authority := strings.TrimPrefix(origin.URL, "http://")
	s := newTestServer()

	const note = "reflected in <title>; try the encoded variant next"
	rec := postJSON(t, s, "/api/repeater/send", map[string]any{
		"target":  authority,
		"request": "GET /n HTTP/1.1\r\nHost: " + authority + "\r\n\r\n",
		"note":    note,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("send = %d: %s", rec.Code, rec.Body.String())
	}
	var sent struct {
		ExchangeID int `json:"exchange_id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &sent); err != nil {
		t.Fatalf("decode send: %v", err)
	}

	exRec := getJSON(t, s, "/api/exchange/"+itoa(uint64(sent.ExchangeID)))
	var ex map[string]any
	if err := json.Unmarshal(exRec.Body.Bytes(), &ex); err != nil {
		t.Fatalf("decode exchange: %v (%s)", err, exRec.Body.String())
	}
	if ex["notes"] != note {
		t.Fatalf("exchange notes = %#v, want the tab's note %q", ex["notes"], note)
	}

	orgRec := postJSON(t, s, "/api/tools/organizer", map[string]any{"exchange": sent.ExchangeID})
	if orgRec.Code != http.StatusOK {
		t.Fatalf("organizer add = %d: %s", orgRec.Code, orgRec.Body.String())
	}
	var added map[string]any
	if err := json.Unmarshal(orgRec.Body.Bytes(), &added); err != nil {
		t.Fatalf("decode organizer add: %v", err)
	}
	if added["note"] != note {
		t.Fatalf("organizer item note = %#v, want the exchange's comment %q copied across", added["note"], note)
	}

	var listed struct {
		Items []struct {
			Note string `json:"note"`
		} `json:"items"`
	}
	if err := json.Unmarshal(getJSON(t, s, "/api/tools/organizer").Body.Bytes(), &listed); err != nil {
		t.Fatalf("decode organizer list: %v", err)
	}
	if len(listed.Items) != 1 || listed.Items[0].Note != note {
		t.Fatalf("organizer list = %+v, want one item carrying the note", listed.Items)
	}
}

// A send with no note records no comment — absent, not an empty string an operator would read
// as "someone cleared this".
func TestARepeaterSendWithoutANoteRecordsNoComment(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer origin.Close()
	authority := strings.TrimPrefix(origin.URL, "http://")
	s := newTestServer()

	rec := postJSON(t, s, "/api/repeater/send", map[string]any{
		"target":  authority,
		"request": "GET / HTTP/1.1\r\nHost: " + authority + "\r\n\r\n",
	})
	var sent struct {
		ExchangeID int `json:"exchange_id"`
	}
	json.Unmarshal(rec.Body.Bytes(), &sent)
	var ex map[string]any
	json.Unmarshal(getJSON(t, s, "/api/exchange/"+itoa(uint64(sent.ExchangeID))).Body.Bytes(), &ex)
	if v, present := ex["notes"]; present && v != nil {
		t.Fatalf("notes = %#v, want absent or null for a send with no note", v)
	}
	orgRec := postJSON(t, s, "/api/tools/organizer", map[string]any{"exchange": sent.ExchangeID})
	var added map[string]any
	json.Unmarshal(orgRec.Body.Bytes(), &added)
	if added["note"] != "" || added["highlight"] != "none" {
		t.Fatalf("an item from an unannotated exchange = note %#v highlight %#v, want \"\" and \"none\"", added["note"], added["highlight"])
	}
}

// An oversized note is refused before anything is sent, with the bound named — for the single
// send and for a group item, which names its tab.
func TestAnOversizedTabNoteIsRefusedBeforeTheWire(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("a refused send must not reach the origin")
	}))
	defer origin.Close()
	authority := strings.TrimPrefix(origin.URL, "http://")
	s := newTestServer()
	huge := strings.Repeat("x", maxRepeaterNoteBytes+1)

	rec := postJSON(t, s, "/api/repeater/send", map[string]any{
		"target": authority, "request": "GET / HTTP/1.1\r\nHost: x\r\n\r\n", "note": huge,
	})
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "at most 65536 bytes") {
		t.Fatalf("single send = %d %q, want 400 naming the bound", rec.Code, rec.Body.String())
	}
	group := postJSON(t, s, "/api/repeater/send-group", map[string]any{
		"mode": "sequence_separate_conn",
		"items": []map[string]any{
			{"tab_id": "a", "target": authority, "request": "GET / HTTP/1.1\r\nHost: x\r\n\r\n"},
			{"tab_id": "b", "target": authority, "request": "GET / HTTP/1.1\r\nHost: x\r\n\r\n", "note": huge},
		},
	})
	if group.Code != http.StatusBadRequest || !strings.Contains(group.Body.String(), "(tab b)") {
		t.Fatalf("group send = %d %q, want 400 naming tab b", group.Code, group.Body.String())
	}
}
