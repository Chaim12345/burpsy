package intercept

import (
	"strings"
	"testing"
)

// History's "Edited" column is Burp's `ProxyHttpRequestResponse.edited()`: "True if the request or
// response was edited", where "the user" is the operator at the hold and nobody else
// (burpsy-react-ui-sd0d).
//
// # Why these tests exist rather than the caller comparing bytes
//
// The console sends the editor's current contents on every forward — intercept.tsx forwards row.raw,
// the same buffer it rendered — so "a buffer arrived" is not an edit and a caller cannot tell an
// untouched buffer from a retyped one. Only this package holds both the bytes the operator was shown
// and the bytes they handed back.
//
// # The case that makes it a defect rather than a nicety
//
// Deriving the flag from the recorded bytes differing from an earlier stage of themselves reads
// burpsy's own rewrites as the operator's work: a request whose Proxy-Connection header an egress
// option strips, or whose Content-Length the content-length fix corrects, differs from the client's
// bytes without anyone having edited anything. That is what history used to report, and
// TestTheContentLengthRewriteIsNotAnOperatorEdit below is the half of it that lives in this package.

// holdForFlag holds one message in the given direction, with ordinary HTTP bytes unless the test
// replaces them.
func holdForFlag(t *testing.T, raw string) (*Engine, *Held) {
	t.Helper()
	e := NewEngine()
	e.SetEnabled(true)
	if err := e.SetRules(DirectionRequest, true, nil); err != nil {
		t.Fatalf("SetRules: %v", err)
	}
	held := e.Hold(&Message{
		Direction: DirectionRequest,
		Host:      "shop.test",
		Port:      80,
		Path:      "/cart",
		Raw:       []byte(raw),
	})
	if held == nil {
		t.Fatal("an unconditional active list did not hold the request")
	}
	return e, held
}

// waitForFlag resolves nothing itself; it reads the decision the test's Forward produced.
func waitForFlag(t *testing.T, e *Engine, held *Held, edited *string, fixContentLength bool) (Action, []byte, bool) {
	t.Helper()
	type decision struct {
		action     Action
		raw        []byte
		userEdited bool
	}
	got := make(chan decision, 1)
	go func() {
		action, raw, _, userEdited := held.Wait()
		got <- decision{action, raw, userEdited}
	}()
	if err := e.Forward(held.ID, edited, fixContentLength, nil); err != nil {
		t.Fatalf("Forward: %v", err)
	}
	d := <-got
	return d.action, d.raw, d.userEdited
}

// The ordinary forward: the console hands back the bytes it was showing. Nothing was edited, so the
// row must not say it was — this is the commonest case in any capture, and a flag that fired here
// would mark every forwarded request in history.
func TestForwardingTheBufferUnchangedIsNotAnOperatorEdit(t *testing.T) {
	const raw = "GET /cart HTTP/1.1\r\nHost: shop.test\r\n\r\n"
	e, held := holdForFlag(t, raw)

	same := raw
	_, out, userEdited := waitForFlag(t, e, held, &same, true)

	if string(out) != raw {
		t.Fatalf("forwarded %q, want the held bytes", out)
	}
	if userEdited {
		t.Error("the operator forwarded the bytes they were shown, unaltered, and the exchange was reported as edited — history would mark a row nobody touched")
	}
}

// A single character changed by hand. The flag is about the operator's buffer versus the bytes they
// were shown, so this is the case it exists for, and it is asserted separately from the case above so
// a rule that always answered "not edited" cannot pass both.
func TestForwardingChangedBytesIsAnOperatorEdit(t *testing.T) {
	const raw = "GET /cart HTTP/1.1\r\nHost: shop.test\r\n\r\n"
	e, held := holdForFlag(t, raw)

	changed := strings.Replace(raw, "/cart", "/cart?coupon=1", 1)
	_, out, userEdited := waitForFlag(t, e, held, &changed, true)

	if string(out) != changed {
		t.Fatalf("forwarded %q, want the operator's bytes %q", out, changed)
	}
	if !userEdited {
		t.Error("the operator retyped the request and the exchange was reported as unedited; the Edited column would never fire")
	}
}

// The defect, at the layer that decides it. The held request carries a Content-Length that does not
// match its body, and the console forwards it with "fix content length" on — the default the
// Intercept page ships. The bytes that go on the wire are therefore *not* the bytes the operator was
// shown, and nobody edited anything.
//
// Deriving the flag from that difference reports the operator's own tool as their work. It is the
// same shape as the live case that produced this bug: a curl request through the proxy was recorded
// as edited because an egress option stripped its Proxy-Connection header.
func TestTheContentLengthRewriteIsNotAnOperatorEdit(t *testing.T) {
	const raw = "POST /cart HTTP/1.1\r\nHost: shop.test\r\nContent-Length: 99\r\n\r\namount=1"
	e, held := holdForFlag(t, raw)

	same := raw
	_, out, userEdited := waitForFlag(t, e, held, &same, true)

	if string(out) == raw {
		t.Fatal("the content-length fix left the message alone, so this test is asserting nothing; the seed must disagree with its own body")
	}
	if userEdited {
		t.Error("burpsy corrected the framing of an untouched request and history reported it as edited by the operator — this is the false badge this flag was fixed to stop producing")
	}
}

// Burp's "Edit target" is an edit even when it does not change a byte: the item the client sent and
// the item that goes out are addressed to different origins, so the row is not the one the client
// made. core.Exchange.UserEdited states this case by name, and it is asserted separately from the
// byte-comparison cases above because it is the one path where the bytes agree and the answer is
// still yes.
func TestRetargetingTheMessageIsAnOperatorEdit(t *testing.T) {
	const raw = "GET /cart HTTP/1.1\r\nHost: shop.test\r\n\r\n"
	e, held := holdForFlag(t, raw)

	same := raw
	done := make(chan bool, 1)
	go func() {
		_, _, _, userEdited := held.Wait()
		done <- userEdited
	}()
	if err := e.Forward(held.ID, &same, true, &Target{Host: "other.test", Port: 8443, TLS: true}); err != nil {
		t.Fatalf("Forward: %v", err)
	}
	if !<-done {
		t.Error("the operator sent the request to another origin and the row is not marked edited; the destination is not the one the client sent, so this is not the client's item")
	}
}

// The console sends the destination it is showing on *every* forward, so a forward that names the
// message's own authority must collapse and stay unedited. Without that collapse the flag would fire
// on every ordinary tunnel forward, which is the same false badge the byte comparison is written to
// avoid.
func TestForwardingToTheMessagesOwnDestinationIsNotAnEdit(t *testing.T) {
	const raw = "GET /cart HTTP/1.1\r\nHost: shop.test\r\n\r\n"
	e, held := holdForFlag(t, raw)

	same := raw
	done := make(chan bool, 1)
	go func() {
		_, _, _, userEdited := held.Wait()
		done <- userEdited
	}()
	if err := e.Forward(held.ID, &same, true, &Target{Host: "shop.test", Port: 80, TLS: false}); err != nil {
		t.Fatalf("Forward: %v", err)
	}
	if <-done {
		t.Error("forwarding a message to the destination it already had was recorded as an operator edit; the console sends the shown destination on every forward, so this would mark all of them")
	}
}

// A drop is nobody's edit: there is no edited message, and a dropped hold never reaches a record at
// all. Asserted so that a future caller cannot raise the flag from the action rather than the bytes.
func TestADroppedMessageIsNotAnOperatorEdit(t *testing.T) {
	const raw = "GET /cart HTTP/1.1\r\nHost: shop.test\r\n\r\n"
	e, held := holdForFlag(t, raw)

	done := make(chan bool, 1)
	go func() {
		_, _, _, userEdited := held.Wait()
		done <- userEdited
	}()
	if err := e.Drop(held.ID, "not interesting"); err != nil {
		t.Fatalf("Drop: %v", err)
	}
	if <-done {
		t.Error("a dropped message reported an operator edit; nothing was forwarded, so there is no edited message to point at")
	}
}

// "Forward all" is the bulk action, and no human read what it forwarded. Its own documentation makes
// that the promise ("no edited bytes and no content-length rewrite, because a bulk action never had a
// human read what it is forwarding"), and the flag has to agree with it: a bulk forward of a request
// whose framing is wrong must not be reported as the operator's edit.
func TestForwardAllIsNotAnOperatorEdit(t *testing.T) {
	const raw = "POST /cart HTTP/1.1\r\nHost: shop.test\r\nContent-Length: 99\r\n\r\namount=1"
	e, held := holdForFlag(t, raw)

	done := make(chan bool, 1)
	rawSeen := make(chan string, 1)
	go func() {
		_, out, _, userEdited := held.Wait()
		done <- userEdited
		rawSeen <- string(out)
	}()
	if n := e.ForwardAll(); n != 1 {
		t.Fatalf("ForwardAll forwarded %d messages, want 1", n)
	}
	if <-done {
		t.Error("a bulk forward was reported as an operator edit, though nobody read the message it forwarded")
	}
	if got := <-rawSeen; got != raw {
		t.Errorf("forwarded %q, want the held bytes untouched — the bulk action promises no rewrite", got)
	}
}
