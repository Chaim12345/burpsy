package scanner

// HTTP request smuggling, detected by timing (burpsy-react-ui-0vzb.1).
//
// # The technique, and why it is the safe one
//
// A front end and a back end that disagree about where a request ends can be told apart without
// smuggling anything into anybody else's request. The probe is a request whose body is complete under
// one framing rule and incomplete under the other (James Kettle, "HTTP Desync Attacks", 2019, the
// timing technique HTTP Request Smuggler and smuggler.py both use):
//
//   - CL.TE. Content-Length: 4 over the body "1\r\nZ\r\nQ\r\n\r\n". A front end honouring
//     Content-Length forwards "1\r\nZ" and stops; a back end honouring chunked encoding has read a
//     one-byte chunk and waits for the next chunk-size line, which never comes. A single server that
//     honours chunked reads "Q" as a chunk size and rejects it at once; one that honours
//     Content-Length reads four bytes and answers. Only the disagreeing pair goes quiet.
//   - TE.CL. Content-Length: 6 over "0\r\n\r\nX". A front end honouring chunked forwards the five
//     bytes up to the terminating chunk; a back end honouring Content-Length waits for a sixth. Any
//     single server answers: chunked stops at the terminator, Content-Length reads all six.
//
// Neither probe leaves bytes on a back-end connection. In the disagreeing pair the back end is waiting
// for OUR request to finish, and what the front end did not forward (CL.TE's "\r\nQ\r\n\r\n", TE.CL's
// "X") sits on our own client connection, which is closed when the read window ends. The one ordering
// that WOULD poison a shared socket is the TE.CL probe against a CL.TE pair: the front end forwards all
// six bytes, the back end stops at the terminator, and "X" becomes the first byte of the next request
// on that back-end connection — possibly another user's. So TE.CL is only ever sent for a header
// variant whose CL.TE probe was answered promptly, which is the evidence that the pair is not CL.TE for
// that variant. The confirmation technique that queues a poisoned prefix for the next request on the
// back-end socket (Burp's "Back-end socket poisoning" method) is deliberately not implemented.
//
// # Evidence
//
// A finding needs, for one technique and one Transfer-Encoding spelling:
//
//   - a baseline (a consistently framed POST) answered well inside the read window, which also sets the
//     window: five times the baseline, clamped to [minSettle, maxSettle];
//   - the attack request timing out twice — no complete response inside the window;
//   - a control timing out neither time: the same request line and headers, the same Transfer-Encoding
//     spelling, with a body that is complete under BOTH rules, answered in under half the window. It is
//     sent between the two attacks, so a target that simply stalls on this header, or on POSTs, or that
//     went slow for a moment, stalls the control too and the verdict is "undecided", not a finding.
//
// # Transfer-Encoding spellings
//
// The disagreement is usually in whether a hop recognises the Transfer-Encoding header at all, so each
// probe is sent with the plain header and then with the obfuscations HTTP Request Smuggler and
// smuggler.py enumerate (teVariants). The finding names the technique and the spelling that produced
// it, because that pair is what an operator reproduces by hand.
//
// # HTTP/2 downgrades
//
// When the origin negotiates h2, the same idea is applied to a front end that rewrites HTTP/2 into
// HTTP/1.1 for its back end: an h2 request carrying a content-length larger than its DATA (H2.CL), or a
// transfer-encoding: chunked header over an incomplete chunk (H2.TE). Both leave the back end waiting
// for bytes of our own request and nothing behind. They are sent through SendH2Fields, which writes the
// header list literally, with the same baseline/attack/control discipline.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	burpsyhttp2 "github.com/burpsy-go/burpsy/internal/http2"
	"github.com/burpsy-go/burpsy/internal/sender"
)

const smugglingRow = "HTTP request smuggling"

// smugglingTiming bounds the read window. A package variable rather than constants so the tests can
// shorten the minimum; nothing in the product writes it.
var smugglingTiming = struct {
	minSettle, maxSettle time.Duration
	factor               int64
}{minSettle: 5 * time.Second, maxSettle: 20 * time.Second, factor: 5}

// teVariant is one spelling of "this body is chunked".
type teVariant struct {
	name   string
	header string // the header line(s), without the trailing CRLF
}

// teVariants are the Transfer-Encoding spellings tried, plain first. Each is a way real front ends
// and back ends have been shown to disagree about whether the header is present or means chunked.
var teVariants = []teVariant{
	{"plain", "Transfer-Encoding: chunked"},
	{"space-before-colon", "Transfer-Encoding : chunked"},
	{"tab-separator", "Transfer-Encoding:\tchunked"},
	{"vertical-tab", "Transfer-Encoding:\x0bchunked"},
	{"xchunked", "Transfer-Encoding: xchunked"},
	{"quoted", `Transfer-Encoding: "chunked"`},
	{"uppercase-value", "Transfer-Encoding: CHUNKED"},
	{"identity-then-chunked", "Transfer-Encoding: identity, chunked"},
	{"duplicate-chunked-first", "Transfer-Encoding: chunked\r\nTransfer-Encoding: x"},
	{"duplicate-chunked-last", "Transfer-Encoding: x\r\nTransfer-Encoding: chunked"},
	{"line-folded", "Transfer-Encoding:\r\n chunked"},
	{"bare-lf", "X-Desync: 1\nTransfer-Encoding: chunked"},
}

// smugglingEnabled admits the check on its own switch, or with the extended active family that
// admitted the row before the switch existed.
func smugglingEnabled(c *ScanConfig) bool {
	return c != nil && (c.CheckRequestSmuggling || c.CheckExtendedActive)
}

// smugglingAuthority is the Host header value for an exchange: the port only when it is not the
// scheme's default.
func smugglingAuthority(host string, port uint16, tls bool) string {
	if (tls && port == 443) || (!tls && port == 80) || port == 0 {
		if strings.Contains(host, ":") {
			return "[" + host + "]"
		}
		return host
	}
	return net.JoinHostPort(host, strconv.Itoa(int(port)))
}

// smugglingRequest renders one HTTP/1.1 POST with the given framing headers and body, byte for byte.
func smugglingRequest(path, authority, framing string, contentLength int, body string) []byte {
	var b strings.Builder
	b.WriteString("POST " + path + " HTTP/1.1\r\n")
	b.WriteString("Host: " + authority + "\r\n")
	b.WriteString("Content-Type: application/x-www-form-urlencoded\r\n")
	if framing != "" {
		b.WriteString(framing + "\r\n")
	}
	b.WriteString("Content-Length: " + strconv.Itoa(contentLength) + "\r\n")
	b.WriteString("\r\n")
	b.WriteString(body)
	return []byte(b.String())
}

// h1Pair is one technique's attack and its consistently framed control, for one TE spelling.
type h1Pair struct {
	technique, variant string
	attack, control    []byte
}

func clteProbe(path, authority string, v teVariant) h1Pair {
	return h1Pair{
		technique: "CL.TE", variant: v.name,
		// Content-Length covers "1\r\nZ" only; chunked parsing needs the rest of a chunk.
		attack: smugglingRequest(path, authority, v.header, 4, "1\r\nZ\r\nQ\r\n\r\n"),
		// Complete under both rules: 11 bytes, and a chunk followed by the terminating chunk.
		control: smugglingRequest(path, authority, v.header, 11, "1\r\nZ\r\n0\r\n\r\n"),
	}
}

func teclProbe(path, authority string, v teVariant) h1Pair {
	return h1Pair{
		technique: "TE.CL", variant: v.name,
		// The terminating chunk is five bytes; Content-Length claims six.
		attack: smugglingRequest(path, authority, v.header, 6, "0\r\n\r\nX"),
		// Complete under both rules.
		control: smugglingRequest(path, authority, v.header, 5, "0\r\n\r\n"),
	}
}

// timedProbe is one observation: did a complete response arrive inside the window, and how fast.
type timedProbe struct {
	timedOut bool
	elapsed  time.Duration
	status   string
}

// smugglingRun is one host's probe session.
type smugglingRun struct {
	cc     *CheckContext
	gate   *sender.AuthorisedSender
	settle time.Duration
	// path and authority address every probe at the exchange's own request target.
	path, authority string
	sent            int
}

var errSmugglingRefused = errors.New("refused: outside the engagement scope")

// h1 sends one raw request with the run's window.
func (r *smugglingRun) h1(ctx context.Context, raw []byte, settle time.Duration) (timedProbe, error) {
	meter := meterFrom(ctx)
	meter.attempt()
	before := r.gate.Refused()
	out, err := r.gate.TimedRead(ctx, raw, settle)
	if r.gate.Refused() > before {
		meter.refusal()
		return timedProbe{}, fmt.Errorf("%w: %v", errSmugglingRefused, err)
	}
	if err != nil {
		meter.failure()
		return timedProbe{}, err
	}
	meter.succeeded()
	r.sent++
	return timedProbe{timedOut: out.TimedOut, elapsed: out.Elapsed, status: smugglingStatusLine(out.Response)}, nil
}

func smugglingStatusLine(b []byte) string {
	s := string(b)
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	return s
}

// prompt is a control answered well inside the window.
func (r *smugglingRun) prompt(p timedProbe) bool {
	return !p.timedOut && p.elapsed < r.settle/2
}

// confirmation is what a confirmed technique carries into its finding.
type confirmation struct {
	technique, variant string
	attack             []byte
	attackTimeouts     int
	controls           []timedProbe
}

// confirm runs control, attack, control, attack after an attack has timed out once. Every control must
// be prompt and the repeated attack must time out again; anything else is undecided.
func (r *smugglingRun) confirm(ctx context.Context, technique, variant string, attack []byte,
	send func(context.Context, []byte) (timedProbe, error), control []byte) (*confirmation, error) {
	c := &confirmation{technique: technique, variant: variant, attack: attack, attackTimeouts: 1}
	for i := 0; i < 2; i++ {
		ctl, err := send(ctx, control)
		if err != nil {
			return nil, err
		}
		if !r.prompt(ctl) {
			return nil, nil
		}
		c.controls = append(c.controls, ctl)
		if i == 1 {
			break
		}
		again, err := send(ctx, attack)
		if err != nil {
			return nil, err
		}
		if !again.timedOut {
			return nil, nil
		}
		c.attackTimeouts++
	}
	return c, nil
}

// maxUnconfirmed bounds a host that times out on attacks but never confirms: after this many
// unconfirmed timeouts the check stops and says it could not decide, rather than spending a read window
// on every remaining spelling.
const maxUnconfirmed = 3

func checkRequestSmuggling(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	if err := cc.RequireEgress(); err != nil {
		return nil, err
	}
	ex := cc.Exchange
	r := &smugglingRun{
		cc:        cc,
		gate:      cc.Scanner.probeGate(ctx, ex),
		path:      ex.Path,
		authority: smugglingAuthority(ex.Host, ex.Port, ex.TLS),
	}
	if r.path == "" || r.path[0] != '/' {
		r.path = "/" + r.path
	}

	// Baseline: a consistently framed POST, read with the widest window. It sets the window for the
	// rest of the run and rules out a host that is simply slow to answer a POST.
	base, err := r.h1(ctx, smugglingRequest(r.path, r.authority, "", 3, "x=1"), smugglingTiming.maxSettle)
	if err != nil {
		return nil, fmt.Errorf("%s: baseline: %w", smugglingRow, err)
	}
	if base.timedOut {
		return nil, fmt.Errorf("%s: the consistently framed baseline POST got no response within %s, so a "+
			"timing differential cannot be read here: %w", smugglingRow, smugglingTiming.maxSettle, errCheckInconclusive)
	}
	r.settle = time.Duration(smugglingTiming.factor) * base.elapsed
	if r.settle < smugglingTiming.minSettle {
		r.settle = smugglingTiming.minSettle
	}
	if r.settle > smugglingTiming.maxSettle {
		r.settle = smugglingTiming.maxSettle
	}

	send := func(ctx context.Context, raw []byte) (timedProbe, error) { return r.h1(ctx, raw, r.settle) }
	unconfirmed := 0
	for _, v := range teVariants {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		clte := clteProbe(r.path, r.authority, v)
		first, err := send(ctx, clte.attack)
		if errors.Is(err, errSmugglingRefused) {
			return nil, err
		}
		if err != nil {
			// The connection failed (often a reset on a header the front end will not accept). That is
			// not a prompt answer, so the TE.CL probe stays unsent for this spelling.
			continue
		}
		if first.timedOut {
			c, err := r.confirm(ctx, clte.technique, v.name, clte.attack, send, clte.control)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", smugglingRow, err)
			}
			if c != nil {
				return []*Finding{r.finding(c)}, nil
			}
			if unconfirmed++; unconfirmed >= maxUnconfirmed {
				return nil, fmt.Errorf("%s: %d attack probes timed out but none confirmed against its control: %w",
					smugglingRow, unconfirmed, errCheckInconclusive)
			}
			// Never TE.CL after a CL.TE timeout: against a CL.TE pair it would leave a byte on the back end.
			continue
		}
		if !r.prompt(first) {
			// Answered, but slowly: possibly a back end that waited and gave up. Same reason as above.
			continue
		}
		tecl := teclProbe(r.path, r.authority, v)
		got, err := send(ctx, tecl.attack)
		if errors.Is(err, errSmugglingRefused) {
			return nil, err
		}
		if err != nil || !got.timedOut {
			continue
		}
		c, err := r.confirm(ctx, tecl.technique, v.name, tecl.attack, send, tecl.control)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", smugglingRow, err)
		}
		if c != nil {
			return []*Finding{r.finding(c)}, nil
		}
		if unconfirmed++; unconfirmed >= maxUnconfirmed {
			return nil, fmt.Errorf("%s: %d attack probes timed out but none confirmed against its control: %w",
				smugglingRow, unconfirmed, errCheckInconclusive)
		}
	}

	if ex.TLS {
		f, err := r.http2Downgrade(ctx)
		if err != nil || f != nil {
			return f, err
		}
	}
	return nil, nil
}

// http2Downgrade runs the H2.TE and H2.CL probes when the origin negotiates h2.
func (r *smugglingRun) http2Downgrade(ctx context.Context) ([]*Finding, error) {
	ex := r.cc.Exchange
	proto, err := r.cc.Scanner.sender.ProtocolFor(ctx, ex.Host, ex.Port, ex.TLS)
	if err != nil || proto != sender.ProtocolSupportH2 {
		return nil, nil
	}
	send := func(ctx context.Context, raw []byte) (timedProbe, error) { return r.h2(ctx, raw) }

	// Each pair is encoded as "header-name: value\n\nbody" so the shared confirm loop can carry it as
	// bytes; h2 decodes it back into a field list.
	type h2Pair struct {
		technique, variant string
		attack, control    []byte
	}
	pairs := []h2Pair{
		{"H2.TE", "transfer-encoding: chunked",
			h2Spec("transfer-encoding", "chunked", "1\r\nZ"),
			h2Spec("transfer-encoding", "chunked", "0\r\n\r\n")},
		{"H2.CL", "content-length larger than DATA",
			h2Spec("content-length", "6", "x=1"),
			h2Spec("content-length", "3", "x=1")},
	}
	for _, p := range pairs {
		first, err := send(ctx, p.attack)
		if errors.Is(err, errSmugglingRefused) {
			return nil, err
		}
		if err != nil || !first.timedOut {
			continue
		}
		c, err := r.confirm(ctx, p.technique, p.variant, p.attack, send, p.control)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", smugglingRow, err)
		}
		if c != nil {
			return []*Finding{r.finding(c)}, nil
		}
	}
	return nil, nil
}

// h2Spec packs one framing header and a body for h2.
func h2Spec(name, value, body string) []byte {
	return []byte(name + "\x00" + value + "\x00" + body)
}

// h2 sends one HTTP/2 request whose framing header is written literally, with the run's window as its
// deadline.
func (r *smugglingRun) h2(ctx context.Context, spec []byte) (timedProbe, error) {
	parts := strings.SplitN(string(spec), "\x00", 3)
	if len(parts) != 3 {
		return timedProbe{}, fmt.Errorf("malformed h2 probe")
	}
	fields := []burpsyhttp2.HeaderField{
		burpsyhttp2.NewHeaderField(":method", "POST"),
		burpsyhttp2.NewHeaderField(":path", r.path),
		burpsyhttp2.NewHeaderField(":scheme", "https"),
		burpsyhttp2.NewHeaderField(":authority", r.authority),
		burpsyhttp2.NewHeaderField("content-type", "application/x-www-form-urlencoded"),
		burpsyhttp2.NewHeaderField(parts[0], parts[1]),
	}
	meter := meterFrom(ctx)
	meter.attempt()
	sendCtx, cancel := context.WithTimeout(ctx, r.settle)
	defer cancel()
	before := r.gate.Refused()
	start := time.Now()
	res, err := r.gate.SendH2Fields(sendCtx, fields, []byte(parts[2]))
	elapsed := time.Since(start)
	if r.gate.Refused() > before {
		meter.refusal()
		return timedProbe{}, fmt.Errorf("%w: %v", errSmugglingRefused, err)
	}
	if res.TimedOut() {
		meter.succeeded()
		r.sent++
		return timedProbe{timedOut: true, elapsed: elapsed}, nil
	}
	if err != nil {
		meter.failure()
		return timedProbe{}, err
	}
	meter.succeeded()
	r.sent++
	return timedProbe{elapsed: elapsed, status: ":status " + strconv.Itoa(res.Status)}, nil
}

// finding renders a confirmation.
func (r *smugglingRun) finding(c *confirmation) *Finding {
	var ctl []string
	for _, p := range c.controls {
		ctl = append(ctl, fmt.Sprintf("%s in %s", nonEmpty(p.status, "answered"), p.elapsed.Round(time.Millisecond)))
	}
	evidence := fmt.Sprintf("%s via %s: the attack request got no response within %s on all %d sends; "+
		"the same request with consistent framing was answered every time (%s)",
		c.technique, c.variant, r.settle, c.attackTimeouts, strings.Join(ctl, "; "))
	detail := fmt.Sprintf("A front end and a back end disagree about where this request ends (%s, "+
		"Transfer-Encoding spelling: %s). The attack request below is complete under one framing rule and "+
		"incomplete under the other, so the back end waited for bytes the front end never forwarded; a "+
		"control with the same headers and a body complete under both rules was answered promptly, "+
		"interleaved with the attacks. Detection was by timing only: nothing was queued on a back-end "+
		"connection, and no other user's request was affected.\n\nAttack request:\n%q",
		c.technique, c.variant, string(c.attack))
	f := buildHeaderFinding(r.cc, smugglingRow, "high", "firm", evidence, detail)
	f.Param = c.technique + " " + c.variant
	return f
}

func nonEmpty(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

// checkClientSideDesync is the "Client-side desync" row's runner, and it declines.
//
// Client-side desync is a server that answers a POST without reading its Content-Length body. The
// cheap half — the server answering before a declared body arrives — is a hint, not a proof, and the
// proof (sending a body that is itself a request and watching it get answered on the same connection)
// poisons the back-end connection whenever a front end that does honour Content-Length streams the
// request to that server. The previous runner sent exactly such a pipelined framing pair, unauthorised,
// and fired on its socket-poisoning side effect. Until a confirmation exists that cannot leave bytes
// on a connection someone else will use, the row is honestly unsupported.
func checkClientSideDesync(context.Context, *CheckContext) ([]*Finding, error) {
	return nil, fmt.Errorf("Client-side desync: no detection that cannot poison a shared back-end connection "+
		"is implemented, so no probe is sent: %w", errCheckUnsupported)
}
