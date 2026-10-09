package sender

import (
	"bytes"
	"context"
	"crypto/des"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/burpsy-go/burpsy/internal/netauth"
)

// burpsy-react-ui-sel6: NTLM is driven as a connection-bound handshake, verified against an
// in-process NTLM server double that behaves like an SSPI server does:
//
//   - the CHALLENGE is kept in the state of the connection the NEGOTIATE arrived on;
//   - an AUTHENTICATE is verified only on that connection, with an independent MS-NLMP 3.3.2
//     recomputation (NTOWFv2 → NTProofStr over the client's own temp blob, and the LMv2 response);
//   - a verified connection is authenticated for every later request on it, and only for it.
//
// The double records every leg with the connection it rode, so "the three legs used one
// connection" is an observation, not an inference from a 200.

type connKey struct{}

// ntlmLeg is one request the double saw: the connection, and the NTLM message type it carried
// (0 for none).
type ntlmLeg struct {
	conn net.Conn
	kind uint32
	// wire is the Authorization scheme the leg carried: "NTLM", "Negotiate" or "".
	wire string
}

type ntlmConnState struct {
	challenge       []byte
	targetInfo      []byte
	serverChallenge [8]byte
	authed          string
}

type ntlmDouble struct {
	t *testing.T
	// domain is the NetBIOS domain the server names in its challenge.
	domain string
	// accounts maps "DOMAIN\user" (upper-cased) to the password the server knows.
	accounts map[string]string
	// closeAfterChallenge makes the challenge 401 carry Connection: close.
	closeAfterChallenge bool
	// bareOffer answers a NEGOTIATE with a bare "NTLM" instead of a CHALLENGE.
	bareOffer bool
	// negotiateOnly is a server with only the Negotiate provider: the NTLM header is ignored (401
	// offering Negotiate), and raw NTLM inside "Negotiate" is answered in the Negotiate header.
	negotiateOnly bool
	// spnegoReply answers a Negotiate NEGOTIATE with a SPNEGO token, as a Kerberos-only server does.
	spnegoReply bool
	// v1Only sends a challenge with no target info (a server that wants NTLMv1); ess sets
	// NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY in it.
	v1Only, ess bool
	// v1Verified and v2Verified count the AUTHENTICATE messages verified under each version.
	v1Verified, v2Verified int

	mu     sync.Mutex
	legs   []ntlmLeg
	conns  map[net.Conn]*ntlmConnState
	closed map[net.Conn]bool
}

func newNTLMDouble(t *testing.T) *ntlmDouble {
	return &ntlmDouble{
		t:        t,
		domain:   "CORP",
		accounts: map[string]string{},
		conns:    map[net.Conn]*ntlmConnState{},
		closed:   map[net.Conn]bool{},
	}
}

// serve wires the double into an unstarted httptest server so every request can name its conn.
func (d *ntlmDouble) serve(server *httptest.Server) {
	server.Config.Handler = d
	server.Config.ConnContext = func(ctx context.Context, c net.Conn) context.Context {
		return context.WithValue(ctx, connKey{}, c)
	}
	server.Config.ConnState = func(c net.Conn, state http.ConnState) {
		if state == http.StateClosed || state == http.StateHijacked {
			d.mu.Lock()
			d.closed[c] = true
			d.mu.Unlock()
		}
	}
}

func (d *ntlmDouble) record(conn net.Conn, kind uint32, wire string) {
	d.mu.Lock()
	d.legs = append(d.legs, ntlmLeg{conn: conn, kind: kind, wire: wire})
	d.mu.Unlock()
}

// verified reports how many AUTHENTICATE messages verified under v1 and under v2.
func (d *ntlmDouble) verified() (v1, v2 int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.v1Verified, d.v2Verified
}

func (d *ntlmDouble) seen() []ntlmLeg {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]ntlmLeg(nil), d.legs...)
}

func (d *ntlmDouble) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	conn, _ := r.Context().Value(connKey{}).(net.Conn)
	d.mu.Lock()
	state := d.conns[conn]
	if state == nil {
		state = &ntlmConnState{}
		d.conns[conn] = state
	}
	authed := state.authed
	d.mu.Unlock()

	header := r.Header.Get("Authorization")
	wire, token, _ := strings.Cut(header, " ")
	accepted := wire == "NTLM" && !d.negotiateOnly || wire == "Negotiate"
	if !accepted {
		d.record(conn, 0, wire)
		if authed != "" {
			// The connection authenticated earlier: an SSPI server serves it as that account.
			fmt.Fprintf(w, "hello %s (connection already authenticated)", authed)
			return
		}
		w.Header().Add("WWW-Authenticate", "Negotiate")
		if !d.negotiateOnly {
			w.Header().Add("WWW-Authenticate", "NTLM")
		}
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	msg, err := base64.StdEncoding.DecodeString(token)
	if err != nil || len(msg) < 12 || string(msg[0:8]) != "NTLMSSP\x00" {
		d.t.Errorf("the double received a malformed %s message: %q", wire, header)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	kind := binary.LittleEndian.Uint32(msg[8:12])
	d.record(conn, kind, wire)
	switch kind {
	case 1:
		flags := binary.LittleEndian.Uint32(msg[12:16])
		const unicode, ntlm, extendedSecurity = 0x1, 0x200, 0x80000
		if flags&unicode == 0 || flags&ntlm == 0 || flags&extendedSecurity == 0 {
			d.t.Errorf("NEGOTIATE flags %#x lack UNICODE, NTLM or EXTENDED_SESSIONSECURITY", flags)
		}
		if d.bareOffer {
			w.Header().Set("WWW-Authenticate", wire)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if d.spnegoReply && wire == "Negotiate" {
			// A SPNEGO NegTokenResp (ASN.1 [1]), what a Kerberos-only server answers with.
			w.Header().Set("WWW-Authenticate", "Negotiate "+base64.StdEncoding.EncodeToString([]byte{0xa1, 0x81, 0x9e, 0x30, 0x81, 0x9b}))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		challenge, targetInfo, serverChallenge := d.challenge()
		d.mu.Lock()
		state.challenge, state.targetInfo, state.serverChallenge = challenge, targetInfo, serverChallenge
		d.mu.Unlock()
		if d.closeAfterChallenge {
			w.Header().Set("Connection", "close")
		}
		w.Header().Set("WWW-Authenticate", wire+" "+base64.StdEncoding.EncodeToString(challenge))
		w.WriteHeader(http.StatusUnauthorized)
	case 3:
		d.mu.Lock()
		challenged := state.challenge != nil
		serverChallenge, targetInfo := state.serverChallenge, state.targetInfo
		d.mu.Unlock()
		if !challenged {
			// An AUTHENTICATE on a connection that was never challenged cannot verify: exactly what
			// an SSPI server answers to one that arrived on a pooled sibling connection.
			w.Header().Set("WWW-Authenticate", wire)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		account, ok := d.verify(msg, serverChallenge, targetInfo)
		if !ok {
			w.Header().Set("WWW-Authenticate", wire)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		d.mu.Lock()
		state.authed = account
		d.mu.Unlock()
		fmt.Fprintf(w, "hello %s", account)
	default:
		d.t.Errorf("unexpected NTLM message type %d", kind)
		w.WriteHeader(http.StatusBadRequest)
	}
}

// challenge builds a CHALLENGE_MESSAGE (MS-NLMP 2.2.1.2) with a fresh server challenge and a target
// info list carrying the domain, a computer name and a timestamp.
func (d *ntlmDouble) challenge() (msg, targetInfo []byte, serverChallenge [8]byte) {
	if _, err := rand.Read(serverChallenge[:]); err != nil {
		d.t.Fatal(err)
	}
	pair := func(id uint16, value []byte) []byte {
		out := make([]byte, 4, 4+len(value))
		binary.LittleEndian.PutUint16(out[0:2], id)
		binary.LittleEndian.PutUint16(out[2:4], uint16(len(value)))
		return append(out, value...)
	}
	var stamp [8]byte
	binary.LittleEndian.PutUint64(stamp[:], uint64(time.Now().UnixNano()/100)+116444736000000000)
	targetInfo = append(targetInfo, pair(2, utf16leOf(d.domain))...)
	targetInfo = append(targetInfo, pair(1, utf16leOf("SRV01"))...)
	targetInfo = append(targetInfo, pair(7, stamp[:])...)
	targetInfo = append(targetInfo, pair(0, nil)...)

	flags := uint32(0x00898205)
	if d.v1Only {
		// A server that wants NTLMv1: no target info, and ESS only when asked for.
		targetInfo = nil
		flags = 0x00008205
		if d.ess {
			flags |= 0x00080000
		}
	}
	msg = make([]byte, 48)
	copy(msg[0:8], "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(msg[8:12], 2)
	binary.LittleEndian.PutUint32(msg[16:20], 48) // empty TargetName at the payload start
	binary.LittleEndian.PutUint32(msg[20:24], flags)
	copy(msg[24:32], serverChallenge[:])
	binary.LittleEndian.PutUint16(msg[40:42], uint16(len(targetInfo)))
	binary.LittleEndian.PutUint16(msg[42:44], uint16(len(targetInfo)))
	binary.LittleEndian.PutUint32(msg[44:48], 48)
	msg = append(msg, targetInfo...)
	return msg, targetInfo, serverChallenge
}

// field reads an AUTHENTICATE_MESSAGE field descriptor's payload, or nil when it runs out of range.
func ntlmFieldOf(msg []byte, off int) []byte {
	if len(msg) < off+8 {
		return nil
	}
	length := int(binary.LittleEndian.Uint16(msg[off : off+2]))
	start := int(binary.LittleEndian.Uint32(msg[off+4 : off+8]))
	if start < 0 || start+length > len(msg) {
		return nil
	}
	return msg[start : start+length]
}

func utf16TextOf(b []byte) string {
	units := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		units = append(units, binary.LittleEndian.Uint16(b[i:i+2]))
	}
	return string(utf16.Decode(units))
}

// verify is the server half of MS-NLMP 3.3.2, from the AUTHENTICATE message alone: the account and
// domain it names, the password the server holds for them, and both v2 responses recomputed.
func (d *ntlmDouble) verify(msg []byte, serverChallenge [8]byte, targetInfo []byte) (string, bool) {
	if len(msg) < 88 {
		d.t.Errorf("AUTHENTICATE is %d bytes, under the 88-byte fixed part", len(msg))
		return "", false
	}
	lm, nt := ntlmFieldOf(msg, 12), ntlmFieldOf(msg, 20)
	domain, user := utf16TextOf(ntlmFieldOf(msg, 28)), utf16TextOf(ntlmFieldOf(msg, 36))
	password, ok := d.accounts[strings.ToUpper(domain+`\`+user)]
	if !ok || len(lm) != 24 {
		return "", false
	}
	if len(nt) == 24 {
		// NTLMv1 (MS-NLMP 3.3.1): only a server that issued a v1 challenge accepts it.
		if !d.v1Only {
			d.t.Errorf("an NTLMv1 response was sent to a server whose challenge offered NTLMv2")
			return "", false
		}
		if !bytes.Equal(nt, v1ResponseOf(password, serverChallenge, lm, d.ess)) {
			return "", false
		}
		if d.ess && !bytes.Equal(lm[8:], make([]byte, 16)) {
			d.t.Errorf("an ESS LmChallengeResponse is not the client challenge padded with zeros: %x", lm)
			return "", false
		}
		if !d.ess && !bytes.Equal(lm, nt) {
			d.t.Errorf("a plain v1 LmChallengeResponse is not the NT response (an LM hash was sent?): %x", lm)
			return "", false
		}
		d.mu.Lock()
		d.v1Verified++
		d.mu.Unlock()
		return domain + `\` + user, true
	}
	if len(nt) < 16+28 {
		return "", false
	}
	key := hmacMD5(ntHashOf(password), utf16leOf(strings.ToUpper(user)+domain))
	temp := nt[16:]
	if !bytes.Equal(hmacMD5(key, append(serverChallenge[:], temp...)), nt[:16]) {
		return "", false
	}
	// The client's temp must carry the server's own target info, or it answered some other challenge.
	if !bytes.Contains(temp, targetInfo[:len(targetInfo)-4]) {
		d.t.Errorf("the NTLMv2 response does not carry the target info this connection's challenge sent")
		return "", false
	}
	if !bytes.Equal(hmacMD5(key, append(serverChallenge[:], lm[16:24]...)), lm[:16]) {
		d.t.Errorf("the LMv2 response does not verify though the NTLMv2 one did")
		return "", false
	}
	d.mu.Lock()
	d.v2Verified++
	d.mu.Unlock()
	return domain + `\` + user, true
}

// v1ResponseOf is the server's own NTLMv1 computation (MS-NLMP 3.3.1), written independently of
// netauth: the 56-bit DES keys are expanded bit by bit rather than by the shift table netauth uses.
// The ESS input is MD5(ServerChallenge || ClientChallenge)[:8], the client challenge read back out
// of the LmChallengeResponse.
func v1ResponseOf(password string, serverChallenge [8]byte, lm []byte, ess bool) []byte {
	data := serverChallenge[:]
	if ess {
		sum := md5.Sum(append(append([]byte{}, serverChallenge[:]...), lm[:8]...))
		data = sum[:8]
	}
	key := append(ntHashOf(password), make([]byte, 5)...) // 21 bytes
	var out []byte
	for third := 0; third < 3; third++ {
		var desKey [8]byte
		for bit := 0; bit < 56; bit++ {
			src := third*56 + bit
			if key[src/8]&(0x80>>(src%8)) != 0 {
				desKey[bit/7] |= 0x80 >> (bit % 7)
			}
		}
		block, err := des.NewCipher(desKey[:])
		if err != nil {
			panic(err)
		}
		sealed := make([]byte, 8)
		block.Encrypt(sealed, data)
		out = append(out, sealed...)
	}
	return out
}

// ntlmSenderWith is a sender holding one NTLM rule of the given scheme for 127.0.0.1.
func ntlmSenderWith(t *testing.T, scheme netauth.Scheme, user, password string) (*Sender, *netauth.Credentials) {
	t.Helper()
	store := mustCredentials(t, "127.0.0.1", scheme, user, password, "")
	store.SetPromptOnFailure(true)
	config := DefaultSenderConfig()
	config.PlatformAuth = store
	config.TLSVerify = false
	return NewSender(config), store
}

// ntlmSender is a sender holding one NTLM rule for 127.0.0.1.
func ntlmSender(t *testing.T, user, password string) (*Sender, *netauth.Credentials) {
	t.Helper()
	store := mustCredentials(t, "127.0.0.1", netauth.SchemeNTLMv2, user, password, "")
	store.SetPromptOnFailure(true)
	config := DefaultSenderConfig()
	config.PlatformAuth = store
	config.TLSVerify = false
	return NewSender(config), store
}

func startNTLMDouble(t *testing.T, d *ntlmDouble) *httptest.Server {
	t.Helper()
	server := httptest.NewUnstartedServer(nil)
	d.serve(server)
	server.Start()
	t.Cleanup(server.Close)
	return server
}

// The acceptance criterion: type 1, type 2 and type 3 verified, all on one connection.
func Test_ntlm_authenticates_with_all_three_legs_on_one_connection(t *testing.T) {
	d := newNTLMDouble(t)
	d.accounts[`CORP\ALICE`] = "correct horse"
	server := startNTLMDouble(t, d)
	s, store := ntlmSender(t, "alice", "correct horse")

	resp, err := s.Send(context.Background(), requestFor(t, http.MethodGet, server.URL+"/protected"))
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(resp.Body), `hello CORP\alice`) {
		t.Fatalf("the NTLM exchange ended %d %q, want 200 as CORP\\alice", resp.StatusCode, resp.Body)
	}
	legs := d.seen()
	if len(legs) != 2 || legs[0].kind != 1 || legs[1].kind != 3 {
		t.Fatalf("the double saw legs %+v, want NEGOTIATE then AUTHENTICATE (the CHALLENGE rides the 401 between them)", legs)
	}
	if legs[0].conn != legs[1].conn {
		t.Fatal("the AUTHENTICATE rode a different connection than the NEGOTIATE it answers")
	}
	if got := store.Failures(); len(got) != 0 {
		t.Errorf("a successful handshake recorded failures: %+v", got)
	}
	if resp.Outcome.Downgrade == nil || resp.Outcome.Downgrade.Reason != DowngradePlaintextTarget {
		t.Errorf("a plaintext NTLM send's outcome is %+v, want the plaintext reason", resp.Outcome.Downgrade)
	}
}

// A wrong password is a failure, recorded as one, and presented exactly once.
func Test_ntlm_with_a_wrong_password_is_a_recorded_failure_and_is_not_retried(t *testing.T) {
	d := newNTLMDouble(t)
	d.accounts[`CORP\ALICE`] = "correct horse"
	server := startNTLMDouble(t, d)
	s, store := ntlmSender(t, "alice", "battery staple")

	resp, err := s.Send(context.Background(), requestFor(t, http.MethodGet, server.URL+"/protected"))
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("a wrong password ended %d, want the server's 401", resp.StatusCode)
	}
	if legs := d.seen(); len(legs) != 2 || legs[1].kind != 3 {
		t.Fatalf("legs %+v: a refused AUTHENTICATE must not be followed by another attempt", legs)
	}
	failures := store.Failures()
	if len(failures) != 1 || failures[0].Host != "127.0.0.1" || failures[0].Reason != netauth.FailureRejected ||
		failures[0].Scheme != "NTLM" || failures[0].Count != 1 {
		t.Fatalf("failures = %+v, want one rejected NTLM failure for 127.0.0.1", failures)
	}
}

// A "DOMAIN\user" username authenticates in that domain, not the server's.
func Test_ntlm_uses_the_domain_named_in_the_username(t *testing.T) {
	d := newNTLMDouble(t)
	d.accounts[`RESOURCE\BOB`] = "pw"
	server := startNTLMDouble(t, d)
	s, _ := ntlmSender(t, `RESOURCE\bob`, "pw")

	resp, err := s.Send(context.Background(), requestFor(t, http.MethodGet, server.URL+"/"))
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(resp.Body), `hello RESOURCE\bob`) {
		t.Fatalf("got %d %q, want 200 as RESOURCE\\bob (the server's own domain is CORP)", resp.StatusCode, resp.Body)
	}
}

// A server that closes the challenged connection gets no AUTHENTICATE at all: on a fresh connection
// it could not verify, and the credential is not presented where it cannot work.
func Test_ntlm_does_not_send_the_authenticate_on_a_new_connection(t *testing.T) {
	d := newNTLMDouble(t)
	d.accounts[`CORP\ALICE`] = "pw"
	d.closeAfterChallenge = true
	server := startNTLMDouble(t, d)
	s, store := ntlmSender(t, "alice", "pw")

	resp, err := s.Send(context.Background(), requestFor(t, http.MethodGet, server.URL+"/"))
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("got %d, want the challenge 401: the handshake cannot complete", resp.StatusCode)
	}
	for _, leg := range d.seen() {
		if leg.kind == 3 {
			t.Fatal("an AUTHENTICATE was sent after the server closed the connection it challenged")
		}
	}
	if len(store.Failures()) != 1 {
		t.Errorf("an NTLM handshake that could not complete was not recorded: %+v", store.Failures())
	}
}

// A bare "NTLM" in answer to the NEGOTIATE is the server declining the handshake; nothing more goes out.
func Test_ntlm_refuses_a_bare_offer_in_answer_to_its_negotiate(t *testing.T) {
	d := newNTLMDouble(t)
	d.bareOffer = true
	server := startNTLMDouble(t, d)
	s, store := ntlmSender(t, "alice", "pw")

	resp, err := s.Send(context.Background(), requestFor(t, http.MethodGet, server.URL+"/"))
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if resp.StatusCode != http.StatusUnauthorized || len(d.seen()) != 1 {
		t.Fatalf("got %d after %d legs, want the 401 after the NEGOTIATE alone", resp.StatusCode, len(d.seen()))
	}
	if len(store.Failures()) != 1 {
		t.Errorf("the declined handshake was not recorded: %+v", store.Failures())
	}
}

// The authenticated connection is the exchange's alone: it is closed when the exchange returns, and
// the next request to the host — here one carrying the caller's own header, so the shared pool
// carries it — arrives on a connection the server has not authenticated.
func Test_the_authenticated_connection_never_carries_another_request(t *testing.T) {
	d := newNTLMDouble(t)
	d.accounts[`CORP\ALICE`] = "pw"
	server := startNTLMDouble(t, d)
	s, _ := ntlmSender(t, "alice", "pw")

	if resp, err := s.Send(context.Background(), requestFor(t, http.MethodGet, server.URL+"/")); err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("the NTLM exchange did not authenticate: %v %+v", err, resp)
	}
	ntlmConn := d.seen()[1].conn

	other := requestFor(t, http.MethodGet, server.URL+"/")
	other.Headers = map[string]string{"Authorization": "Bearer operator-typed"}
	resp, err := s.Send(context.Background(), other)
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	legs := d.seen()
	if last := legs[len(legs)-1]; last.conn == ntlmConn || resp.StatusCode == http.StatusOK {
		t.Fatalf("a later request rode the NTLM-authenticated connection (%d %q)", resp.StatusCode, resp.Body)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		d.mu.Lock()
		closed := d.closed[ntlmConn]
		d.mu.Unlock()
		if closed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the NTLM-authenticated connection was left open after its exchange")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Over TLS against a server that offers h2, the handshake rides HTTP/1.1, the outcome says why, and
// the protocol table does not learn "this host speaks HTTP/1.1" from a send that never offered h2.
func Test_ntlm_over_tls_rides_http11_without_teaching_the_protocol_table(t *testing.T) {
	d := newNTLMDouble(t)
	d.accounts[`CORP\ALICE`] = "pw"
	server := httptest.NewUnstartedServer(nil)
	d.serve(server)
	server.EnableHTTP2 = true
	server.StartTLS()
	t.Cleanup(server.Close)
	s, _ := ntlmSender(t, "alice", "pw")

	req := requestFor(t, http.MethodGet, server.URL+"/")
	resp, err := s.Send(context.Background(), req)
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if resp.StatusCode != http.StatusOK || resp.Version != "HTTP/1.1" {
		t.Fatalf("got %d over %s, want 200 over HTTP/1.1", resp.StatusCode, resp.Version)
	}
	if resp.Outcome.Downgrade == nil || resp.Outcome.Downgrade.Reason != DowngradeConnectionBoundAuth {
		t.Errorf("outcome downgrade = %+v, want the connection-bound-auth reason", resp.Outcome.Downgrade)
	}
	if got := s.protocols.Lookup(req.Host, req.Port, true); got != ProtocolSupportUnknown {
		t.Errorf("the protocol table learned %v from an NTLM send that never offered h2", got)
	}
}

// Concurrent sends each run their own handshake on their own connection; none answers another's
// challenge. Run under -race, this is also the data-race check for the exchange path.
func Test_concurrent_ntlm_sends_each_complete_their_own_handshake(t *testing.T) {
	d := newNTLMDouble(t)
	d.accounts[`CORP\ALICE`] = "pw"
	server := startNTLMDouble(t, d)
	s, store := ntlmSender(t, "alice", "pw")

	const n = 8
	var wg sync.WaitGroup
	codes := make([]int, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			resp, err := s.Send(context.Background(), requestFor(t, http.MethodGet, server.URL+"/"))
			if err != nil {
				t.Errorf("Send %d: %v", i, err)
				return
			}
			codes[i] = resp.StatusCode
		}(i)
	}
	wg.Wait()
	for i, code := range codes {
		if code != http.StatusOK {
			t.Errorf("concurrent send %d ended %d", i, code)
		}
	}
	perConn := map[net.Conn][]uint32{}
	for _, leg := range d.seen() {
		perConn[leg.conn] = append(perConn[leg.conn], leg.kind)
	}
	if len(perConn) != n {
		t.Errorf("%d sends used %d connections, want one each", n, len(perConn))
	}
	for _, kinds := range perConn {
		if len(kinds) != 2 || kinds[0] != 1 || kinds[1] != 3 {
			t.Errorf("a connection carried legs %v, want exactly NEGOTIATE then AUTHENTICATE", kinds)
		}
	}
	if len(store.Failures()) != 0 {
		t.Errorf("concurrent handshakes recorded failures: %+v", store.Failures())
	}
}

// ---- NTLMv1 (opt-in) and NTLM inside Negotiate ---------------------------------------------

// The double's own v1 computation is checked against MS-NLMP 4.2.2.2.1 and 4.2.3.2.2 before it is
// trusted to judge the client: a verifier that agreed with the client by sharing its bug would pass
// everything.
func Test_the_doubles_ntlmv1_verifier_reproduces_the_published_vectors(t *testing.T) {
	server := [8]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}
	lm := append(bytes.Repeat([]byte{0xaa}, 8), make([]byte, 16)...)
	for ess, want := range map[bool]string{
		false: "67c43011f30298a2ad35ece64f16331c44bdbed927841f94",
		true:  "7537f803ae367128ca458204bde7caf81e97ed2683267232",
	} {
		if got := fmt.Sprintf("%x", v1ResponseOf("Password", server, lm, ess)); got != want {
			t.Errorf("double's v1 response (ess=%v) = %s, want %s", ess, got, want)
		}
	}
}

// The opt-in: an ntlmv1 rule authenticates against a v1 server — with ESS when the challenge sets it,
// plain v1 otherwise — and every handshake records the weak-authentication warning.
func Test_an_ntlmv1_rule_authenticates_and_every_handshake_records_the_warning(t *testing.T) {
	for _, ess := range []bool{true, false} {
		t.Run(fmt.Sprintf("ess=%v", ess), func(t *testing.T) {
			d := newNTLMDouble(t)
			d.accounts[`CORP\ALICE`] = "pw"
			d.v1Only, d.ess = true, ess
			server := startNTLMDouble(t, d)
			s, store := ntlmSenderWith(t, netauth.SchemeNTLMv1, `CORP\alice`, "pw")
			store.SetPromptOnFailure(false) // the warning is recorded whatever the prompt says

			for i := 1; i <= 2; i++ {
				resp, err := s.Send(context.Background(), requestFor(t, http.MethodGet, server.URL+"/"))
				if err != nil || resp.StatusCode != http.StatusOK {
					t.Fatalf("send %d: %v %+v", i, err, resp)
				}
				want := "NTLMv1"
				if ess {
					want = "NTLMv1 (ESS)"
				}
				w := store.Warnings()
				if len(w) != 1 || w[0].Count != i || w[0].Scheme != want || w[0].Wire != "NTLM" || !strings.Contains(w[0].Warning, "weak") {
					t.Fatalf("after send %d warnings = %+v, want one %s warning counted %d", i, w, want, i)
				}
			}
			if v1, v2 := d.verified(); v1 != 2 || v2 != 0 {
				t.Fatalf("the double verified v1=%d v2=%d, want two NTLMv1 answers", v1, v2)
			}
		})
	}
}

// v1 is never sent without the opt-in: an ntlmv2 rule against a server that only offers v1 sends
// the NEGOTIATE and nothing else, records the failure, and records no weak-auth warning.
func Test_an_ntlmv2_rule_never_sends_ntlmv1(t *testing.T) {
	d := newNTLMDouble(t)
	d.accounts[`CORP\ALICE`] = "pw"
	d.v1Only, d.ess = true, true
	server := startNTLMDouble(t, d)
	s, store := ntlmSender(t, "alice", "pw")

	resp, err := s.Send(context.Background(), requestFor(t, http.MethodGet, server.URL+"/"))
	if err != nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("got %v %+v, want the 401: an ntlmv2 rule cannot answer a v1-only server", err, resp)
	}
	for _, leg := range d.seen() {
		if leg.kind == 3 {
			t.Fatal("an AUTHENTICATE went to a v1-only server under an ntlmv2 rule")
		}
	}
	if v1, _ := d.verified(); v1 != 0 || len(store.Warnings()) != 0 {
		t.Fatalf("v1Verified=%d warnings=%+v: NTLMv1 was used without the opt-in", v1, store.Warnings())
	}
	if len(store.Failures()) != 1 {
		t.Errorf("the unanswerable v1 challenge was not recorded: %+v", store.Failures())
	}
}

// A server offering only Negotiate: the NTLM header is ignored, the same NEGOTIATE goes again as raw
// NTLM in the Negotiate header on the same connection, and the challenge is answered there. The host
// is remembered, so the next send starts in the Negotiate header.
func Test_a_negotiate_only_server_is_answered_with_raw_ntlm_inside_negotiate(t *testing.T) {
	d := newNTLMDouble(t)
	d.accounts[`CORP\ALICE`] = "pw"
	d.negotiateOnly = true
	server := startNTLMDouble(t, d)
	s, _ := ntlmSender(t, "alice", "pw")

	resp, err := s.Send(context.Background(), requestFor(t, http.MethodGet, server.URL+"/"))
	if err != nil || resp.StatusCode != http.StatusOK || !strings.Contains(string(resp.Body), `hello CORP\alice`) {
		t.Fatalf("got %v %+v, want 200 as CORP\\alice", err, resp)
	}
	legs := d.seen()
	if len(legs) != 3 || legs[0].wire != "NTLM" || legs[1].wire != "Negotiate" || legs[1].kind != 1 ||
		legs[2].wire != "Negotiate" || legs[2].kind != 3 {
		t.Fatalf("legs %+v, want NTLM (ignored), then Negotiate NEGOTIATE and Negotiate AUTHENTICATE", legs)
	}
	if legs[0].conn != legs[1].conn || legs[1].conn != legs[2].conn {
		t.Fatal("the Negotiate legs did not ride the challenged connection")
	}

	before := len(legs)
	if resp, err := s.Send(context.Background(), requestFor(t, http.MethodGet, server.URL+"/")); err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("second send: %v %+v", err, resp)
	}
	second := d.seen()[before:]
	if len(second) != 2 || second[0].wire != "Negotiate" {
		t.Fatalf("second send legs %+v, want two legs starting in the Negotiate header", second)
	}
}

// A Negotiate token that is SPNEGO/Kerberos, not raw NTLM, is refused: no AUTHENTICATE, and the
// failure is recorded under Negotiate.
func Test_a_spnego_negotiate_token_is_refused(t *testing.T) {
	d := newNTLMDouble(t)
	d.accounts[`CORP\ALICE`] = "pw"
	d.negotiateOnly, d.spnegoReply = true, true
	server := startNTLMDouble(t, d)
	s, store := ntlmSender(t, "alice", "pw")

	resp, err := s.Send(context.Background(), requestFor(t, http.MethodGet, server.URL+"/"))
	if err != nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("got %v %+v, want the 401", err, resp)
	}
	for _, leg := range d.seen() {
		if leg.kind == 3 {
			t.Fatal("an AUTHENTICATE answered a SPNEGO token")
		}
	}
	if f := store.Failures(); len(f) != 1 || f[0].Scheme != "Negotiate" {
		t.Fatalf("failures = %+v, want one Negotiate failure", f)
	}
}

// The opt-in also works inside Negotiate, and the warning names the header it travelled in.
func Test_ntlmv1_inside_negotiate_records_the_warning_with_its_wire(t *testing.T) {
	d := newNTLMDouble(t)
	d.accounts[`CORP\ALICE`] = "pw"
	d.negotiateOnly, d.v1Only, d.ess = true, true, true
	server := startNTLMDouble(t, d)
	s, store := ntlmSenderWith(t, netauth.SchemeNTLMv1, `CORP\alice`, "pw")

	resp, err := s.Send(context.Background(), requestFor(t, http.MethodGet, server.URL+"/"))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("got %v %+v", err, resp)
	}
	if v1, _ := d.verified(); len(store.Warnings()) != 1 || store.Warnings()[0].Wire != "Negotiate" || v1 != 1 {
		t.Fatalf("warnings = %+v (v1Verified %d), want one weak-auth warning over Negotiate", store.Warnings(), v1)
	}
}
