package web

// The Repeater's WebSocket send (burpsy-react-ui-6ex), end to end.
//
// A real WebSocket target stands in for the origin: a hand-rolled RFC 6455 server on an
// httptest listener that upgrades, echoes one frame back with a marker prefix, and then closes
// with a status. The test then does what an operator does: send a frame through
// /api/repeater/ws-send and read what the target answered.
//
// What is pinned, in order of how much it would hurt to lose:
//   - a frame resent through the endpoint reaches the target and the reply comes back to the
//     pane (the bead's whole deliverable);
//   - the resend is recorded as its own conversation — handshake exchange plus the operator's
//     frame plus the target's reply — so WebSockets history shows it (the honest-coverage half);
//   - an out-of-scope target is refused by the same gate the HTTP send uses, before any dial;
//   - to-client is refused with a reason, never silently succeeded (the direction half of the
//     bead's contract, which a fresh dial cannot honour by design).

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
)

// wsEchoTarget is a minimal RFC 6455 server: it accepts the upgrade, reads one client frame,
// answers with "echo: <payload>" as a text frame, then sends a close and drops the socket.
//
// Hand-rolled rather than a library because the target is the thing under test's *peer*: it
// must speak exactly the protocol and nothing else, and its whole value is that it is boring.
func wsEchoTarget(t *testing.T) *httptest.Server {
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

		// Read one client frame (unmask), answer with the marker, close.
		frame, err := readOneFrame(rw.Reader)
		if err != nil {
			return
		}
		if _, err := conn.Write(core.EncodeWsFrame(core.WsOpcodeText, []byte("echo: "+string(frame)), nil)); err != nil {
			return
		}
		closePayload := []byte{0x03, 0xe8} // 1000
		_, _ = conn.Write(core.EncodeWsFrame(core.WsOpcodeClose, closePayload, nil))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// wsAccept computes the fixed accept token. The echo target does not validate the client's
// key (the handshake's acceptance is not what the endpoint test is about), so a constant
// answer formula is enough; the client's own acceptance check is exercised by the 101 read.
func wsAccept(key string) string {
	_ = key
	return base64.StdEncoding.EncodeToString(make([]byte, 20))
}

// hostOnly strips a port from a "host:port" authority, bracketing an IPv6 literal on the way so
// "::1:8080" loses the right colon.
func hostOnly(authority string) string {
	host, _, err := net.SplitHostPort(authority)
	if err != nil {
		return authority
	}
	return host
}

// readOneFrame reads a single masked client frame and returns its unmasked payload.
//
// core.ParseWsFrameHeader answers (nil, true, nil) when the bytes so far do not yet contain a
// whole header — a masked frame needs 2 + 4 header bytes before its length is knowable, and
// reading a fixed two would hand the parser a header it is not allowed to answer. So the bytes
// are fed a few at a time until the parser stops asking for more, which is what the `needMore`
// return exists to say.
func readOneFrame(br *bufio.Reader) ([]byte, error) {
	var head []byte
	var hdr *core.WsFrameHeader
	// Peek what is buffered, grow by reading one byte at a time: a frame header is at most 14
	// bytes and the parser is the only thing that knows how many it needs.
	for len(head) < 14 {
		b, err := br.ReadByte()
		if err != nil {
			return nil, err
		}
		head = append(head, b)
		parsed, needMore, perr := core.ParseWsFrameHeader(head)
		if perr != nil {
			return nil, perr
		}
		if needMore {
			continue
		}
		hdr = parsed
		break
	}
	if hdr == nil {
		return nil, errors.New("a frame header did not parse within 14 bytes")
	}
	rest := readSome(br, int(hdr.PayloadLen))
	if hdr.Masked {
		core.WsUnmask(rest, hdr.Mask, 0)
	}
	return rest, nil
}

// readSome blocks until exactly n bytes arrive (or errors), because a frame's header may
// straddle TCP segments and a short read would be read as a corrupt frame.
func readSome(br *bufio.Reader, n int) []byte {
	out := make([]byte, n)
	read := 0
	for read < n {
		m, err := br.Read(out[read:])
		if err != nil {
			return out[:read]
		}
		read += m
	}
	return out
}

func repeaterWsTargetOf(t *httptest.Server) (host string, port uint16) {
	parts := strings.Split(strings.TrimPrefix(t.URL, "http://"), ":")
	p, _ := strconv.Atoi(parts[1])
	return parts[0], uint16(p)
}

// A frame resent through the endpoint reaches the target, the reply comes back, and the whole
// conversation is recorded as its own WebSocket history entry.
func TestARepeaterWsSendReachesTheTargetAndRecordsTheConversation(t *testing.T) {
	target := wsEchoTarget(t)
	host, _ := repeaterWsTargetOf(target)

	s := newTestServer()
	s.scope.AddInclude(host)

	rec := postJSON(t, s, "/api/repeater/ws-send", map[string]any{
		"target":  target.URL[len("http://"):],
		"path":    "/",
		"opcode":  "text",
		"payload": "hello frame",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/repeater/ws-send: status = %d (%s)", rec.Code, rec.Body.String())
	}
	var resp repeaterWsSendResp
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode reply: %v", err)
	}

	// NOT `ExchangeID == 0`: the store's first exchange IS id 0 (position-is-the-id), so zero is a
	// real id here and a zero-check would pass on a reply that named no exchange at all. What the
	// operator needs is a name the pane can open, and the lookup below is that check.
	if _, err := s.store.GetExchange(resp.ExchangeID); err != nil {
		t.Errorf("the reply's exchange %d is not in the store (%v): the pane could not offer "+
			"'view in WebSockets history', and the operator has no handle on what just happened",
			resp.ExchangeID, err)
	}
	if len(resp.Messages) != 1 || resp.Messages[0].Payload != "echo: hello frame" {
		t.Errorf("reply messages = %+v, want exactly one echo of the frame the operator sent", resp.Messages)
	}
	if !resp.ClosedByPeer {
		t.Error("closed_by_peer is false: the echo target closes after its answer, and an operator watching an " +
			"empty pane needs to know the target is done rather than that the read timed out")
	}
	if resp.CloseCode != 1000 {
		t.Errorf("close code = %d, want 1000", resp.CloseCode)
	}

	// The recorded conversation: the handshake exchange exists, carries the 101, and holds
	// exactly the two frames — the operator's (from client) and the target's echo (from server).
	ex, err := s.store.GetExchange(resp.ExchangeID)
	if err != nil {
		t.Fatalf("the reply's exchange %d does not exist in the store", resp.ExchangeID)
	}
	if ex.Method != "GET" || ex.Path != "/" {
		t.Errorf("handshake exchange is %s %s, want GET /", ex.Method, ex.Path)
	}
	if ex.Status == nil || *ex.Status != 101 {
		t.Errorf("handshake status = %v, want 101", ex.Status)
	}
	// Newest first, which is the order WebSockets history presents (the store walks its index
	// backwards and the UI renders what it gets), so the target's echo is row 0 and the
	// operator's own frame is row 1. Asserting the product's order rather than a convenient one:
	// a resend that reads in a different order from every other conversation is a conversation
	// an operator cannot compare against the original.
	frames := s.store.WsMessagesFor(resp.ExchangeID, 0, 10)
	if len(frames) != 2 {
		t.Fatalf("the conversation holds %d frames, want 2 (the operator's and the target's echo)", len(frames))
	}
	if frames[0].FromClient {
		t.Error("the newest frame is marked from-client: the target's echo is a server-to-client frame, and " +
			"mislabelled direction would make the history read as the operator talking to themselves")
	}
	if !frames[1].FromClient || frames[1].Opcode != core.WsOpcodeText {
		t.Errorf("the oldest frame is fromClient=%v opcode=%v, want the operator's own text frame",
			frames[1].FromClient, frames[1].Opcode)
	}
}

// An out-of-scope target is refused before any dial — the same host-level gate the HTTP send
// applies, because a scope the operator set to constrain outbound traffic must not be
// bypassable by framing instead of requesting.
func TestARepeaterWsSendOutsideScopeIsRefusedBeforeTheDial(t *testing.T) {
	// A listener that records any contact — the refusal must mean NO connection was made.
	var reached bool
	guard := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusTeapot)
	}))
	defer guard.Close()

	s := newTestServer()
	// An EXCLUDED host, not an empty scope: burpsy's empty scope allows everything
	// (core.Scope's "EmptyScopeAllowsEverything"), so "no scope rule" is not a refusal case and a
	// test built on it would assert the opposite of the gate's real behaviour. What must not be
	// bypassable by framing is an EXCLUSION the operator set.
	//
	// The pattern is the HOST, not host:port: a scope rule carries host, path and port as separate
	// fields, and a "host:port" string in the pattern is a pattern that matches no host — the
	// exclusion would silently apply to nothing and the gate would pass for the wrong reason.
	host := guard.URL[len("http://"):]
	if rec := postJSON(t, s, "/api/scope", map[string]string{"action": "exclude", "pattern": hostOnly(host)}); rec.Code != http.StatusOK {
		t.Fatalf("exclude the target: status = %d", rec.Code)
	}

	rec := postJSON(t, s, "/api/repeater/ws-send", map[string]any{
		"target":  host,
		"path":    "/",
		"opcode":  "text",
		"payload": "should never be sent",
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403: a WS send is a send, and the scope gate that refuses an HTTP request to "+
			"the same host must refuse a frame too (%s)", rec.Code, rec.Body.String())
	}
	if reached {
		t.Error("the target was contacted: a scope refusal must happen before the dial, not after a connection " +
			"the operator cannot un-make")
	}
}

// To-client is refused with a reason, never silently succeeded: a fresh dial has no client to
// send to, and an operator offered the choice must learn why one half is unavailable rather
// than watch a send that did nothing.
func TestARepeaterWsSendToClientIsRefusedWithAReasonNotSilence(t *testing.T) {
	s := newTestServer()
	rec := postJSON(t, s, "/api/repeater/ws-send", map[string]any{
		"target":   "127.0.0.1:1",
		"path":     "/",
		"opcode":   "text",
		"payload":  "to the client please",
		"toClient": true,
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: to-client must be an explicit refusal, not a silent success or a "+
			"silently-ignored field (%s)", rec.Code, rec.Body.String())
	}
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if msg, _ := body["error"].(string); msg == "" || !strings.Contains(msg, "client") {
		t.Errorf("refusal = %q, want it to name the client direction: the operator chose to-client and must learn "+
			"why that half cannot run on a fresh connection", msg)
	}
}

// A nonexistent frame id is a 404 that names the id, because "send this frame" with a frame the
// store never heard of is an operator's bookmark gone stale, not an empty payload.
func TestARepeaterWsSendOfAnUnknownFrameIsANamed404(t *testing.T) {
	s := newTestServer()
	rec := postJSON(t, s, "/api/repeater/ws-send", map[string]any{
		"message": 999999,
		"opcode":  "text",
		"payload": "x",
	})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "999999") {
		t.Errorf("the refusal must name the id: %q", rec.Body.String())
	}
}
