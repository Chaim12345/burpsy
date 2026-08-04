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
			s.relayH2Stream(w, r, upstreamH2, host, port, authority)
		}),
	})
}

func (s *Server) relayH2Stream(w http.ResponseWriter, r *http.Request, upstream *http2.ClientConn, host string, port uint16, authority string) {
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
	var reqRaw []byte
	if inScope {
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

	respBody, _ := io.ReadAll(resp.Body)
	for k, vals := range resp.Header {
		for _, v := range vals {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(respBody)

	if inScope {
		// ResponseLen is the whole rendered message, where the hand-rolled row
		// counted the body alone. Every HTTP/1 row in this package has always meant
		// the whole message, so h2 was the one protocol reporting a different
		// quantity under the same name.
		s.record(scanner.CapturedExchange{
			Host:   host,
			Port:   port,
			TLS:    true,
			Method: r.Method,
			Path:   pathOnly(path),
			// Rendered in HTTP/1 shape for history, which is what makes an h2 stream
			// readable next to everything else and lets one status parser serve both.
			Request: reqRaw,
			Response: burpsyhttp2.RenderResponse(
				resp.StatusCode,
				filterHopHeaders(resp.Header),
				respBody,
			),
			Started:  startTime,
			Duration: time.Since(startTime),
			Protocol: core.ProtocolHTTP2,
		})
	}
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

func pathOnly(requestURI string) string {
	if i := strings.Index(requestURI, "?"); i >= 0 {
		return requestURI[:i]
	}
	return requestURI
}

func netJoinHostPort(host string, port uint16) string {
	return host + ":" + strconv.Itoa(int(port))
}
