package proxy

import (
	"errors"
	"strconv"

	"github.com/burpsy-go/burpsy/internal/httputil"
)

// salvagedBody is what a buffered response-body read leaves the proxy to forward and record.
type salvagedBody struct {
	// head is the head to forward: the origin's own, or reframed close-delimited when the
	// Content-Length it declares no longer describes the bytes being forwarded.
	head []byte
	// note is the record's note for a body that is not whole; empty for a whole body.
	note string
	// endConn reports that the exchange must end both the upstream connection (its framing is
	// unknowable after a short or cut body) and the client connection (the forwarded response is
	// close-delimited, or chunked without its terminating chunk, so only the close ends it).
	endConn bool
}

// salvageResponseBody decides what httputil.ReadResponseBody's (body, err) leaves to forward. ok is
// false for a real failure: nothing arrived that can be presented honestly.
//
// Two errors carry bytes worth forwarding, and both end the connection:
//
//   - *httputil.TruncatedBodyError: the origin closed short of its Content-Length. The head goes
//     out close-delimited and the note says what was declared and what arrived.
//   - *httputil.BodyCapError (burpsy-react-ui-h1-cap-silent): the body passed the cap and reading
//     stopped there. This used to be returned as a whole body with no word, and the keep-alive loop
//     then read the rest of it as the NEXT response. Now the prefix is forwarded and noted with the
//     same sentence the h2 and h3 legs use. A Content-Length head goes out close-delimited (the
//     declared length is false for what is forwarded); a chunked one goes out as it came, so the
//     client sees a chunked body that never reached its last chunk — incomplete, which it is,
//     rather than a terminator the origin never sent.
func salvageResponseBody(head, body []byte, err error) (salvagedBody, bool) {
	if err == nil {
		return salvagedBody{head: head}, true
	}
	var truncated *httputil.TruncatedBodyError
	if errors.As(err, &truncated) && len(body) > 0 {
		return salvagedBody{
			head: httputil.CloseDelimitedHead(head),
			note: "upstream closed the response body short of its declared Content-Length (" +
				truncated.Declared + " declared, " + strconv.Itoa(len(body)) + " received); " +
				"the partial body was forwarded close-delimited",
			endConn: true,
		}, true
	}
	var capped *httputil.BodyCapError
	if errors.As(err, &capped) {
		out := salvagedBody{
			head:    head,
			note:    capSalvageNote(capped),
			endConn: true,
		}
		if capped.Framing == httputil.FramingContentLength {
			out.head = httputil.CloseDelimitedHead(head)
		}
		return out, true
	}
	return salvagedBody{}, false
}

// capSalvageNote is the record's note for a body the proxy forwarded cut at the cap: the h2/h3
// sentence, plus what the proxy did about it.
func capSalvageNote(capped *httputil.BodyCapError) string {
	return capped.Note() + "; the partial body was forwarded and the connection closed"
}
