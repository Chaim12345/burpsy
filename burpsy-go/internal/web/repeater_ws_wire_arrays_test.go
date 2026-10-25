package web

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

// The ws-send route's wire arrays are `[]`, never `null` (burpsy-react-ui-i9ti.3).
//
// Same defect class as intruder_wire_arrays_test.go: Go cannot see a nil slice — it ranges and
// len()s like an empty one — but JSON spells it `null`, and the Repeater pane declares
// `messages` non-nullable, so a send whose target answers with no data frames threw in the view
// instead of showing an empty conversation. The clean run is the case that pins it: handshake
// accepted, frame delivered, target closes politely without a single data frame.
func TestAWsSendWithNoReplyFramesSendsAnEmptyMessagesArray(t *testing.T) {
	target := wsSilentTarget(t)
	host, port := repeaterWsTargetOf(target)

	s := newTestServer()
	s.scope.AddInclude(host)
	rec := postJSON(t, s, "/api/repeater/ws-send", map[string]any{
		"target":  host + ":" + strconv.Itoa(int(port)),
		"path":    "/",
		"opcode":  "text",
		"payload": "a frame with no answer",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("silent-target send: status = %d (%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"messages":[]`) {
		t.Fatalf("wire body = %s — a reply-less send must marshal \"messages\":[], not null: "+
			"the pane reads .length on it without a guard", rec.Body.String())
	}
}

// wsSilentTarget completes the upgrade and reads one client frame, then closes with a polite
// close frame and no data: the target half of "no reply frames".
func wsSilentTarget(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			http.Error(w, "not a websocket upgrade", http.StatusBadRequest)
			return
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "no hijack", http.StatusInternalServerError)
			return
		}
		conn, rw, err := hj.Hijack()
		if err != nil {
			return
		}
		defer conn.Close()

		key := base64.StdEncoding.EncodeToString(make([]byte, 16))
		resp := "HTTP/1.1 101 Switching Protocols\r\n" +
			"Upgrade: websocket\r\n" +
			"Connection: Upgrade\r\n" +
			"Sec-WebSocket-Accept: " + wsAccept(key) + "\r\n\r\n"
		if _, err := rw.WriteString(resp); err != nil {
			return
		}
		rw.Flush()

		if _, err := readOneFrame(rw.Reader); err != nil {
			return
		}
		_, _ = conn.Write(core.EncodeWsFrame(core.WsOpcodeClose, []byte{0x03, 0xe8}, nil))
	}))
	t.Cleanup(srv.Close)
	return srv
}
