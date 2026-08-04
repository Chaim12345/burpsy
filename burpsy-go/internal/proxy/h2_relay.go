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

	inScope := s.config.scope.Contains(host, port, path, true)
	var ex *core.Exchange
	if inScope {
		reqRaw := burpsyhttp2.RenderRequest(
			r.Method, path, host,
			filterHopHeaders(r.Header),
			reqBody,
		)
		reqID, err := s.config.store.Put(reqRaw, core.DirectionRequest)
		if err != nil {
			s.config.logger.Error("failed to store h2 request", zap.Error(err))
		}
		ex = &core.Exchange{
			Request:   reqID,
			Host:      host,
			Port:      port,
			TLS:       true,
			Method:    r.Method,
			Path:      pathOnly(path),
			StartedMs: uint64(startTime.UnixMilli()),
			Protocol:  core.ProtocolHTTP2,
		}
		s.config.store.AddExchange(ex)
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
		if ex != nil {
			note := "origin h2 error: " + err.Error()
			ex.Notes = &note
			ex.DurationMs = uint64(time.Since(startTime).Milliseconds())
		}
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

	if ex != nil {
		respRaw := burpsyhttp2.RenderResponse(
			resp.StatusCode,
			filterHopHeaders(resp.Header),
			respBody,
		)
		respID, err := s.config.store.Put(respRaw, core.DirectionResponse)
		if err != nil {
			s.config.logger.Error("failed to store h2 response", zap.Error(err))
			return
		}
		status := uint16(resp.StatusCode)
		ex.Response = &respID
		ex.Status = &status
		ex.ResponseLen = len(respBody)
		ex.DurationMs = uint64(time.Since(startTime).Milliseconds())
		s.runPassiveScan(ex)
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
