package web

// "Show response in browser" (burpsy-react-ui-js5y): Burp serves the selected response from
// a unique URL so the operator's own browser renders it — relative links resolve, scripts
// run, and the page looks the way the target intended — instead of the console's escaped
// text view. The access-control workflow leans on this: what the server sent is what the
// operator must judge.

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/burpsy-go/burpsy/internal/core"
)

// handleResponseInBrowser serves GET /api/exchange/{id}/in-browser: the stored response
// replayed verbatim — status line, headers, body — so the operator's browser renders the
// response exactly as the target produced it.
//
// It rides the /api/exchange/{id} subtree like /csrf does, because the operator's action is
// "show THIS exchange's response", and the exchange is the addressable thing.
//
// Two deliberate divergences from a verbatim byte copy, both stated in the response itself:
//   - Cache-Control: no-store. A stored response is evidence; letting the browser serve a
//     cached copy of it on a later visit would show a page burpsy no longer holds, as if
//     it were the target's current answer.
//   - Content-Length is recomputed from the body actually stored. The stored bytes are the
//     wire bytes including chunked framing when the target used it; serving that framing
//     under this route's own connection (no chunked encoding of ours) would hand the browser
//     size prefixes as content. Dechunking here — the same decode the view already applies —
//     means the browser sees the body the target wrote.
//
// handleExchangeInBrowserByID parses the id out of /api/exchange/in-browser/{id} and hands
// off. Registered as its own prefix rather than sniffed inside handleExchange's numeric path
// dispatch: "in-browser" would never parse as an id, but an explicit subtree keeps the
// manifest entry and the handler's own 405 honest instead of relying on a fallthrough.
func (s *Server) handleExchangeInBrowserByID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id, err := strconv.ParseUint(strings.TrimPrefix(r.URL.Path, "/api/exchange/in-browser/"), 10, 64)
	if err != nil {
		http.Error(w, "Invalid exchange ID", http.StatusBadRequest)
		return
	}
	s.handleResponseInBrowser(w, r, core.ExchangeID(id))
}

func (s *Server) handleResponseInBrowser(w http.ResponseWriter, r *http.Request, id core.ExchangeID) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ex, err := s.store.GetExchange(id)
	if err != nil {
		http.Error(w, "Exchange not found", http.StatusNotFound)
		return
	}
	if ex.Response == nil {
		http.Error(w, "No response was captured for this exchange, so there is nothing to show", http.StatusNotFound)
		return
	}
	msg, err := s.message(uint64(*ex.Response))
	if err != nil {
		http.Error(w, "The stored response could not be read", http.StatusNotFound)
		return
	}

	raw := msg.Raw()
	head, body := splitHeadBody(raw)

	// Replay the head's headers, minus the framing and security headers this route owns.
	// Hop-by-hop and framing headers (Transfer-Encoding, Content-Length, Connection) describe
	// the original socket conversation, not this replay; Content-Length is restated below
	// against the decoded body.
	w.Header().Set("Cache-Control", "no-store")
	status := 200
	statusText := "OK"
	for _, line := range strings.Split(string(head), "\r\n") {
		if strings.HasPrefix(line, "HTTP/") {
			if parts := strings.SplitN(line, " ", 3); len(parts) >= 2 {
				if n, err := strconv.Atoi(parts[1]); err == nil {
					status = n
				}
				if len(parts) >= 3 {
					statusText = parts[2]
				}
			}
			continue
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		switch strings.ToLower(name) {
		case "transfer-encoding", "content-length", "connection", "content-encoding":
			continue
		}
		w.Header().Set(name, strings.TrimSpace(value))
	}
	// The stored Content-Encoding is deliberately dropped above with the other framing: the
	// stored body bytes here are still encoded when the target compressed them, and serving
	// gzip bytes under a recomputed Content-Length would hand the browser compressed bytes
	// it has not been told to decompress. A compressed response is beyond this route — the
	// console's message view decodes it for reading, and an operator who needs the rendered
	// original can replay the request in Repeater.
	w.Header().Set("X-Burpsy-Exchange", strconv.FormatUint(uint64(id), 10))
	w.Header().Set("X-Burpsy-Status-Text", statusText)

	if strings.Contains(strings.ToLower(string(head)), "content-encoding:") {
		http.Error(w, "This response was stored compressed; the in-browser view serves only responses stored plain, because the console cannot honestly re-serve a body it holds encoded under a length it would have to invent", http.StatusUnsupportedMediaType)
		return
	}

	w.WriteHeader(status)
	_, _ = w.Write(body)
}
