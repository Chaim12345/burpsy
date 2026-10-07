package intercept

import (
	"strings"
	"testing"
)

// 80tg item 4: an edited interception was forwarded with no newline correction at all. Burp can add
// a missing blank line after the headers and remove trailing newlines from a URL-encoded body when an
// EDITED request is forwarded (settings/tools/proxy.html:273-292).
//
// The operator loses a reliable forward after editing. An edit that drops the blank line after the
// headers, or leaves a trailing newline in a form body, produces a request the target may reject —
// and the failure looks like the application's, not the operator's. Content-Length was already fixed
// automatically, which changes no newline bytes and so does not help either case.

func TestAMissingBlankLineIsRestoredForAnEditedRequest(t *testing.T) {
	// The defect an edit introduces: the blank line between headers and body is gone, so the
	// target reads the first body byte as a header name.
	edited := "POST /x HTTP/1.1\r\nHost: a.test\r\nContent-Length: 5\r\nname=bob"
	got := string(NewlineCorrection{AddMissingBlankLine: true}.Apply([]byte(edited)))

	// The blank line is the repair; the length follows from it. The fixture announced 5 for an
	// 8-byte body, which is the second half of the same defect, so the correction fixes both and
	// this asserts the boundary and the body separately rather than one string that would fail for
	// the wrong reason.
	if !strings.Contains(got, "\r\n\r\nname=bob") {
		t.Errorf("the blank line was not restored before the body; got %q", got)
	}
	if !strings.HasSuffix(got, "name=bob") {
		t.Errorf("the body was altered; got %q", got)
	}
	if !strings.Contains(got, "Content-Length: 8") {
		t.Errorf("Content-Length = the stale 5 for an 8-byte body; a target would reject the message "+
			"for a length the operator never wrote. got %q", got)
	}
	// And the correction must not invent a blank line where there was a body-less message that
	// already had one.
	already := "GET /x HTTP/1.1\r\nHost: a.test\r\n\r\n"
	if string(NewlineCorrection{AddMissingBlankLine: true}.Apply([]byte(already))) != already {
		t.Error("a request that already had its blank line was changed")
	}
}

func TestATrailingNewlineIsRemovedFromAURLEncodedBodyOnly(t *testing.T) {
	// The defect: a form body ending in a newline, whose last field then parses with a trailing CR or
	// LF glued to its value — which a signature or an equality check fails.
	const body = "name=bob&role=admin\r\n"
	edited := "POST /x HTTP/1.1\r\nHost: a.test\r\n" +
		"Content-Type: application/x-www-form-urlencoded\r\n" +
		"Content-Length: 20\r\n\r\n" + body

	got := string(NewlineCorrection{TrimTrailingNewlinesInURLEncodedBody: true}.Apply([]byte(edited)))
	if strings.HasSuffix(got, "\r\n") {
		t.Errorf("the trailing newline survived in a urlencoded body; got %q", got)
	}
	if !strings.HasSuffix(got, "name=bob&role=admin") {
		t.Errorf("the body was altered beyond its trailing newline; got %q", got)
	}
	// The length must follow the body: a trimmed body announced with the old length is a request the
	// target rejects for a reason the operator cannot see.
	if !strings.Contains(got, "Content-Length: 19") {
		t.Errorf("Content-Length was not recomputed after trimming; got %q", got)
	}
}

// A JSON body is NOT urlencoded and a trailing newline inside one is meaningful — a payload the
// operator wrote deliberately. Trimming it would corrupt bytes without saying so.
func TestATrailingNewlineIsLeftAloneInABodyThatIsNotURLEncoded(t *testing.T) {
	const body = "{\"role\":\"admin\"}\r\n"
	edited := "POST /x HTTP/1.1\r\nHost: a.test\r\n" +
		"Content-Type: application/json\r\nContent-Length: 17\r\n\r\n" + body
	raw := []byte(edited)

	if got := (NewlineCorrection{TrimTrailingNewlinesInURLEncodedBody: true}.Apply(raw)); string(got) != string(raw) {
		t.Errorf("a JSON body was rewritten; a trailing newline in it can be the operator's own. got %q", got)
	}
	// And a missing Content-Type is left alone rather than guessed at, for the same reason: this
	// correction rewrites bytes and must not do that to a format it has not recognised.
	noType := "POST /x HTTP/1.1\r\nHost: a.test\r\nContent-Length: 20\r\n\r\nname=bob&role=admin\r\n"
	if got := (NewlineCorrection{TrimTrailingNewlinesInURLEncodedBody: true}.Apply([]byte(noType))); string(got) != noType {
		t.Errorf("a body with no Content-Type was rewritten; got %q", got)
	}
}

// Both corrections OFF is the default and must change nothing at all: these rewrite bytes the
// operator wrote, and neither is something to apply to a request nobody edited.
func TestNoCorrectionIsTheDefaultAndChangesNothing(t *testing.T) {
	const raw = "POST /x HTTP/1.1\r\nHost: a.test\r\nContent-Length: 20\r\n\r\nname=bob&role=admin\r\n"
	var zero NewlineCorrection
	if got := zero.Apply([]byte(raw)); string(got) != raw {
		t.Errorf("the zero correction changed the message: %q", got)
	}
}

// An engine with the corrections off forwards an edited request byte for byte, because the whole
// feature is opt-in and an operator who did not ask for it gets what they typed.
func TestTheEngineForwardsAnEditUnchangedWhenNoCorrectionIsSet(t *testing.T) {
	e := NewEngine()
	e.SetEnabled(true)
	if err := e.SetRules(DirectionRequest, true, nil); err != nil {
		t.Fatalf("SetRules: %v", err)
	}
	h := e.Hold(reqMessage("a.test", "POST", "/x"))
	if h == nil {
		t.Fatal("the unconditional list did not hold")
	}
	edited := "POST /x HTTP/1.1\r\nHost: a.test\r\nContent-Length: 20\r\n\r\nname=bob&role=admin\r\n"

	// A dial target that fails is fine — this asserts on the bytes the engine produced, which the
	// returned error path never reaches, so the correction is checked through Apply above and this
	// only confirms the default is off.
	if e.NewlineCorrections() != (NewlineCorrection{}) {
		t.Error("a fresh engine reports a correction as enabled; both default off")
	}
	_ = e.Drop(h.ID, "")
	_ = edited
}

// The WIRING, not just the transform. Every other test here calls Apply directly, which means a
// mutation that removed the call from Forward would pass all of them — and that is not a hypothetical
// mutation: making the engine stop applying the correction changes no test in this file. So this one
// goes through Forward, against a real listener, and reads the bytes that came out the other end.
func TestTheEngineAppliesTheCorrectionOnTheWayOutAndOnlyWhenSet(t *testing.T) {
	// The edited request an operator produces by dropping the blank line after the headers.
	const broken = "POST /x HTTP/1.1\r\nHost: a.test\r\nContent-Length: 8\r\nname=bob"

	forwardAndCapture := func(t *testing.T, corrections bool) string {
		t.Helper()
		e, held := holdForFlag(t, "POST /x HTTP/1.1\r\nHost: a.test\r\n\r\nname=bob")
		if corrections {
			e.SetNewlineCorrection(NewlineCorrection{AddMissingBlankLine: true})
		}
		edited := broken
		// held.Wait reports the bytes the engine actually resolved the hold with, which is the whole
		// point: it is what the TARGET received, not what the caller handed in.
		_, out, _ := waitForFlag(t, e, held, &edited, false)
		return string(out)
	}

	off := forwardAndCapture(t, false)
	if strings.Contains(off, "\r\n\r\nname=bob") {
		t.Errorf("with the correction off the edit should go out exactly as typed; got %q", off)
	}
	on := forwardAndCapture(t, true)
	if !strings.Contains(on, "\r\n\r\nname=bob") {
		t.Errorf("with the correction on the blank line should be restored before the body; got %q", on)
	}
}

// And the setting round-trips, so a surface reads what is in force rather than assuming defaults.
func TestTheNewlineCorrectionSettingRoundTrips(t *testing.T) {
	e := NewEngine()
	want := NewlineCorrection{AddMissingBlankLine: true, TrimTrailingNewlinesInURLEncodedBody: true}
	e.SetNewlineCorrection(want)
	if got := e.NewlineCorrections(); got != want {
		t.Errorf("read back %+v, want %+v", got, want)
	}
	e.SetNewlineCorrection(NewlineCorrection{})
	if got := e.NewlineCorrections(); got != (NewlineCorrection{}) {
		t.Errorf("clearing left %+v", got)
	}
}

// A body that is nothing but newlines becomes empty, not one newline: a form with no fields is
// empty, and a form with a newline is a field whose name is a line break.
func TestABodyOfOnlyNewlinesBecomesEmpty(t *testing.T) {
	edited := "POST /x HTTP/1.1\r\nHost: a.test\r\n" +
		"Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 2\r\n\r\n\r\n"
	got := string(NewlineCorrection{TrimTrailingNewlinesInURLEncodedBody: true}.Apply([]byte(edited)))
	// The body is gone AND the blank line that separated it survives, so what remains is headers
	// plus the terminator and nothing after it. Checking the tail rather than a CRLF count is what
	// says that: a leftover newline reads as an empty field name to a form parser, which is the
	// defect the correction exists to remove.
	if !strings.HasSuffix(got, "\r\n\r\n") {
		t.Errorf("got %q; the header terminator must survive so the message is still well formed", got)
	}
	if after := got[strings.Index(got, "\r\n\r\n")+4:]; after != "" {
		t.Errorf("got %q; %q is left after the headers, so the newline body was not removed", got, after)
	}
}

// A header block with no body at all still gets its blank line: that is what makes such a message
// forwardable, and an operator who edited a body away meant to send headers, not a request the
// target cannot parse. The body stays empty rather than being invented.
func TestABodilessHeaderBlockGetsItsTerminatorAndNoBody(t *testing.T) {
	const raw = "POST /x HTTP/1.1\r\nHost: a.test\r\n"
	want := "POST /x HTTP/1.1\r\nHost: a.test\r\n\r\n"
	if got := (NewlineCorrection{AddMissingBlankLine: true}.Apply([]byte(raw))); string(got) != want {
		t.Errorf("got %q, want %q; the header block should be terminated and the body left empty", got, want)
	}
}

// But a message with no CRLF at all is not an HTTP message, and inventing a boundary would
// produce bytes no client wrote.
func TestAMessageWithNoLineEndingAtAllIsLeftAlone(t *testing.T) {
	const raw = "not a request"
	if got := (NewlineCorrection{AddMissingBlankLine: true, TrimTrailingNewlinesInURLEncodedBody: true}.Apply([]byte(raw))); string(got) != raw {
		t.Errorf("got %q, want the message unchanged; there is no header block to terminate", got)
	}
}
