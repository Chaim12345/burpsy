package proxy

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	burpsyhttp2 "github.com/burpsy-go/burpsy/internal/http2"
	"github.com/burpsy-go/burpsy/internal/scanner"
	"go.uber.org/zap"
	"golang.org/x/net/http2"
)

// relayH2 drives HTTP/2 on both decrypted legs, recording each stream as its own
// exchange rendered in HTTP/1 shape for history.
func (s *Server) relayH2(clientTLS, upstreamTLS net.Conn, host string, port uint16) {
	authority := host
	if port != 443 {
		authority = netJoinHostPort(host, port)
	}

	transport := &http2.Transport{}
	upstreamH2, err := transport.NewClientConn(upstreamTLS)
	if err != nil {
		s.config.logger.Error("h2 upstream handshake failed",
			zap.String("host", host), zap.Error(err))
		return
	}

	server := &http2.Server{}
	server.ServeConn(clientTLS, &http2.ServeConnOpts{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			s.relayH2Stream(w, r, upstreamH2, host, port, authority, serverIPOf(upstreamTLS), listenerPortOf(clientTLS))
		}),
	})
}

// serverIP and listenerPort are threaded in because this function's upstream handle is an h2
// client connection rather than a net.Conn: relayH2 holds both sockets, so the two socket facts are
// derived there once per connection instead of per stream
// (burpsy-react-ui-mr4p, burpsy-react-ui-he81).
func (s *Server) relayH2Stream(w http.ResponseWriter, r *http.Request, upstream *http2.ClientConn, host string, port uint16, authority, serverIP string, listenerPort uint16) {
	startTime := time.Now()
	path := r.URL.RequestURI()
	if path == "" {
		path = "/"
	}

	reqBody, _ := io.ReadAll(r.Body)
	_ = r.Body.Close()

	// Rendered now, indexed later. This used to index the request on its own and
	// fill the response fields in afterwards, which was wrong twice over: the
	// mutation happened outside the store's lock on a pointer the store had
	// already handed to its readers, and an origin error left the row indexed with
	// no response for good — the shape that stalls a cursor walking the index. The
	// bytes are held here instead and both halves are captured together, through
	// the same producer as every other exchange in this package.
	inScope := s.config.scope.Contains(host, port, path, true)

	// Retention, not rewriting: dont_log_out_of_scope off keeps an out-of-scope h2
	// exchange just as it keeps an HTTP/1 one, and the rendered request is what the
	// row needs either way. See OptDontLogOutOfScope.
	recorded := inScope || !s.config.options.Get(OptDontLogOutOfScope)
	var reqRaw []byte
	if recorded {
		reqRaw = burpsyhttp2.RenderRequest(
			r.Method, path, host,
			filterHopHeaders(r.Header),
			reqBody,
		)
	}

	targetStr := "https://" + authority + path
	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, targetStr, bytes.NewReader(reqBody))
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	outReq.Header = cloneHeaderWithoutHop(r.Header)
	if len(reqBody) > 0 {
		outReq.ContentLength = int64(len(reqBody))
	}

	resp, err := upstream.RoundTrip(outReq)
	if err != nil {
		// Logged, not indexed. There is no exchange: the origin never answered, so
		// the pair this would record is half a pair. That is the same choice the
		// HTTP/1 paths in proxy.go make for a forward that fails, and the same one
		// the crawler makes when a send fails (it records a skip, not a capture).
		// The row this used to leave behind carried the error in a note it attached
		// *after* indexing — so the durable mirror never saw the note — and had no
		// response, which is precisely the state that stops the live-audit sweep at
		// that index for the life of the process.
		s.config.logger.Error("h2 origin error",
			zap.String("host", host),
			zap.String("method", r.Method),
			zap.String("path", path),
			zap.Error(err))
		http.Error(w, "upstream error: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// An open-ended response is streamed: each chunk is written and flushed as it arrives, so a
	// server-sent-event feed on an h2 origin reaches the browser while it is still being produced.
	//
	// io.ReadAll was here until burpsy-react-ui-wet3, and on an SSE stream it is the same defect the
	// HTTP/1 legs had: ReadAll does not return until the body ends, and an event stream's body does
	// not end, so the browser waited on a response that would never complete.
	//
	// The predicate is resp.ContentLength < 0, which Go's HTTP/2 client reports for a response whose
	// length is unknown — the same "nothing says when this ends" fact the HTTP/1 legs read off the
	// head, and knowable BEFORE any body byte is read. That ordering is what lets the head go out
	// first: there is no need to read a byte to decide, so there is no risk of having to hold the
	// head back until the first chunk arrives, and a browser can start rendering immediately.
	for k, vals := range resp.Header {
		for _, v := range vals {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)

	policy := s.config.Streaming()
	// A response whose length is unknown streams on its framing alone; the text/event-stream switch
	// adds the one shape framing does not catch — a framed event stream, which Go's h2 client reports
	// with a non-negative ContentLength and which would otherwise be read to completion before the
	// browser saw a byte. Strip is not expressible here: net/http owns the h2 framing to the client, so
	// there is no Transfer-Encoding header for the operator to strip.
	streamed := resp.ContentLength < 0
	if policy.TreatEventStreamAsStreaming() && isEventStreamHTTP(resp.Header) {
		streamed = true
	}
	var respBody []byte
	if streamed {
		window := policy.Window()
		respBody = s.streamH2Body(resp.Body, w, window)
		if resp.ContentLength < 0 {
			// Only a response nothing framed is "unframed". A framed event stream the switch admitted is
			// framed, so counting it would muddy the diagnostic NoteUnframed exists to answer.
			policy.NoteUnframed()
		}
	} else {
		respBody, _ = io.ReadAll(resp.Body)
		_, _ = w.Write(respBody)
	}
	// Store off: the client already has the streamed body; history records the head without it, the h2
	// counterpart of the HTTP/1 legs recording the head and a note. There is no note field on this
	// hand-built row, so the omitted body is the whole of the record's "not stored".
	recordedBody := respBody
	if streamed && !policy.Store() {
		recordedBody = nil
	}

	// The response modification rules do not run here, and the count says so rather
	// than a caveat in a doc file. This path does not have one response message it
	// can rewrite: the origin's headers and body are copied to the client through
	// net/http's ResponseWriter, and the HTTP/1-shaped Response recorded below is a
	// *re-rendering* for history. Rewriting that rendering would put bytes in history
	// the browser never received; rewriting the copy above would need the rules
	// reimplemented against http.Header and a body writer. See Options.NoteRelayedHTTP2.
	s.config.options.NoteRelayedHTTP2()

	if recorded {
		// ResponseLen is the whole rendered message, where the hand-rolled row
		// counted the body alone. Every HTTP/1 row in this package has always meant
		// the whole message, so h2 was the one protocol reporting a different
		// quantity under the same name.
		s.record(scanner.CapturedExchange{
			Host:   host,
			Port:   port,
			TLS:    true,
			Method: r.Method,
			// The whole request target, query string included, exactly as the HTTP/1 paths in
			// proxy.go record it. This used to run through a pathOnly() helper that truncated at
			// the first '?', which made h2 the one protocol whose captured Path disagreed with the
			// request bytes stored beside it: the request line said
			// `GET /search?q=secret HTTP/2` and the exchange said `/search`.
			//
			// It was not cosmetic. The site map derives a node's parameter list by splitting the
			// stored path on '?' (see splitPathQuery in internal/web/api_toolkit.go), so every h2
			// node reported no parameters at all — and h2 is what nearly every TLS origin
			// negotiates, so the tree showed parameters only for the plaintext minority. Query-
			// filtering, reporting and issue attribution all read the same truncated value.
			Path: path,
			// Rendered in HTTP/1 shape for history, which is what makes an h2 stream
			// readable next to everything else and lets one status parser serve both.
			Request: reqRaw,
			Response: burpsyhttp2.RenderResponse(
				resp.StatusCode,
				filterHopHeaders(resp.Header),
				recordedBody,
			),
			Started:  startTime,
			Duration: time.Since(startTime),
			Protocol: core.ProtocolHTTP2,

			ServerIP:     serverIP,
			ListenerPort: listenerPort,
		})
	} else {
		s.config.options.NoteOutOfScopeDrop()
	}
}

// isEventStreamHTTP reports whether an http.Header declares a text/event-stream body, the h2
// counterpart of headIsEventStream: it ignores parameters such as `; charset=utf-8` and compares
// case-insensitively, because `text/event-stream; charset=utf-8` is the same media type.
func isEventStreamHTTP(hdr http.Header) bool {
	ct := hdr.Get("Content-Type")
	if ct == "" {
		return false
	}
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	return strings.EqualFold(strings.TrimSpace(ct), "text/event-stream")
}

func filterHopHeaders(hdr http.Header) []burpsyhttp2.Header {
	if len(hdr) == 0 {
		return nil
	}
	out := make([]burpsyhttp2.Header, 0, len(hdr))
	for name, vals := range hdr {
		if burpsyhttp2.IsHopHeader(name) {
			continue
		}
		for _, v := range vals {
			out = append(out, burpsyhttp2.Header{Name: name, Value: v})
		}
	}
	return out
}

func cloneHeaderWithoutHop(hdr http.Header) http.Header {
	out := make(http.Header, len(hdr))
	for k, vals := range hdr {
		if burpsyhttp2.IsHopHeader(k) {
			continue
		}
		out[k] = append([]string(nil), vals...)
	}
	return out
}

func netJoinHostPort(host string, port uint16) string {
	return host + ":" + strconv.Itoa(int(port))
}
