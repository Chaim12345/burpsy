package web

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
)

// This file is HAR import: it brings traffic captured elsewhere — a browser's DevTools export, a CI
// run, a colleague's session — into history for replay and analysis, without re-proxying it live
// (burpsy-react-ui-eyi1). Burp, ZAP and Caido all accept HAR; it is the standard way an offline
// capture reaches a review tool.
//
// # Why it is a parser plus a bulk insert, not new storage
//
// The ingest target already exists: a traffic store keyed by message ids with an exchange index on
// top (core.TrafficStore). An imported exchange is built exactly as a Repeater send is — Put the two
// message halves, build an Exchange that references them, AddExchange — so an imported row is a
// first-class history row that History lists and Repeater can resend. The only new work is turning a
// HAR entry's structured request/response into the raw HTTP/1 bytes the store holds.
//
// # Why the rendered bytes are HTTP/1 regardless of the capture's protocol
//
// A HAR entry records an exchange, not a wire capture: its headers are a name/value list and its body
// is decoded text, with no framing. So there are no original bytes to preserve — the bytes are
// rendered — and HTTP/1 is the shape the rest of the store already renders an h2 exchange into for
// history (see h2_relay's RenderResponse). Pseudo-headers (`:method`, `:authority`) are dropped
// because they are h2 framing, not header lines, and the framing headers (Content-Length,
// Transfer-Encoding, Content-Encoding) are recomputed because the HAR body is already decoded — a
// stored Content-Length that disagreed with the body, or a Content-Encoding on a body that is no
// longer encoded, is the exact inconsistency that makes a message unreadable.

// maxHARImportBytes bounds a HAR upload. Larger than the ordinary request cap because a HAR carries
// every response body it captured, base64-expanded for binary ones, so a session of any length is
// many megabytes — but still bounded, because an unbounded read of an uploaded file is a memory
// denial of service against the console.
const maxHARImportBytes = 64 * 1024 * 1024

// harFile is the HTTP Archive 1.2 envelope. Only the fields import needs are modelled; the rest of the
// format (pages, timings, cache, cookies) is ignored, which is why this is a parser for import rather
// than a full HAR codec.
type harFile struct {
	Log harLog `json:"log"`
}

type harLog struct {
	Version string     `json:"version"`
	Entries []harEntry `json:"entries"`
}

type harEntry struct {
	StartedDateTime string      `json:"startedDateTime"`
	Time            float64     `json:"time"`
	Request         harRequest  `json:"request"`
	Response        harResponse `json:"response"`
}

type harRequest struct {
	Method      string       `json:"method"`
	URL         string       `json:"url"`
	HTTPVersion string       `json:"httpVersion"`
	Headers     []harNVP     `json:"headers"`
	PostData    *harPostData `json:"postData"`
}

type harResponse struct {
	Status      int        `json:"status"`
	StatusText  string     `json:"statusText"`
	HTTPVersion string     `json:"httpVersion"`
	Headers     []harNVP   `json:"headers"`
	Content     harContent `json:"content"`
}

type harNVP struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type harPostData struct {
	MimeType string `json:"mimeType"`
	Text     string `json:"text"`
}

type harContent struct {
	Size     int64  `json:"size"`
	MimeType string `json:"mimeType"`
	Text     string `json:"text"`
	Encoding string `json:"encoding"`
}

// harImportResult is what an import answers with: how many exchanges reached history, how many entries
// were skipped because they could not be rendered, and the first handful of reasons. The error list is
// capped so one malformed file cannot produce a response as large as the file.
type harImportResult struct {
	Imported int      `json:"imported"`
	Skipped  int      `json:"skipped"`
	Errors   []string `json:"errors,omitempty"`
}

const maxHARImportErrors = 50

func (r *harImportResult) note(entry int, err error) {
	if len(r.Errors) < maxHARImportErrors {
		r.Errors = append(r.Errors, fmt.Sprintf("entry %d: %v", entry, err))
	}
}

// handleHistoryImportHar serves POST /api/history/import/har.
//
// POST because it is a work request that mutates the store, not a resource name. riskLocal: it writes
// to burpsy's own history and sends nothing to any target — the imported requests are not replayed,
// only recorded, so an unattended caller importing a file is not launching traffic.
func (s *Server) handleHistoryImportHar(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxHARImportBytes))
	if err != nil {
		http.Error(w, "the HAR upload could not be read or exceeded the size limit", http.StatusBadRequest)
		return
	}
	var har harFile
	if err := json.Unmarshal(raw, &har); err != nil {
		http.Error(w, "not a HAR file: the body is not the JSON an HTTP Archive is ("+err.Error()+")",
			http.StatusBadRequest)
		return
	}
	if len(har.Log.Entries) == 0 {
		http.Error(w, "the HAR has no log.entries to import", http.StatusBadRequest)
		return
	}

	result := s.importHAREntries(har.Log.Entries)
	writeJSON(w, http.StatusOK, result)
}

// importHAREntries renders each entry and inserts it into the store, carrying on past an entry it
// cannot render rather than failing the whole import — a single malformed entry in a thousand-entry
// capture should not cost the other 999.
func (s *Server) importHAREntries(entries []harEntry) harImportResult {
	var result harImportResult
	for i, e := range entries {
		reqRaw, host, port, tls, method, target, err := renderHARRequest(e.Request)
		if err != nil {
			result.Skipped++
			result.note(i, err)
			continue
		}
		reqID, err := s.store.Put(reqRaw, core.DirectionRequest)
		if err != nil {
			result.Skipped++
			result.note(i, fmt.Errorf("store request: %w", err))
			continue
		}

		ex := &core.Exchange{
			Host:      host,
			Port:      port,
			TLS:       tls,
			Method:    method,
			Path:      target,
			Request:   core.MsgPtr(reqID),
			Protocol:  core.ProtocolHTTP1,
			Source:    core.SourceImport,
			StartedMs: harStartedMs(e.StartedDateTime),
			Duration:  harDuration(e.Time),
		}

		// The response half, when the entry carried one. A status of 0 is HAR's "no response recorded"
		// (an in-flight or failed request), which is imported as a request-only row rather than a
		// fabricated empty response — the same nil-Response shape a blind CONNECT tunnel leaves.
		if e.Response.Status > 0 {
			if respRaw, rerr := renderHARResponse(e.Response); rerr != nil {
				result.note(i, fmt.Errorf("response: %w", rerr))
			} else if respID, perr := s.store.Put(respRaw, core.DirectionResponse); perr != nil {
				result.note(i, fmt.Errorf("store response: %w", perr))
			} else {
				status := uint16(e.Response.Status)
				ex.Response = &respID
				ex.Status = &status
				ex.ResponseLen = len(respRaw)
				// Typed from the rendered bytes, for the same reason the proxy does: history lists a MIME
				// column without reopening the response.
				ex.Mime = core.MimeEssence(respRaw)
			}
		}

		s.store.AddExchange(ex)
		result.Imported++
	}
	return result
}

// renderHARRequest renders one HAR request into raw HTTP/1 bytes and returns the routing facts the
// Exchange index needs. It fails only when the URL is not absolute — without a host there is no
// exchange to record.
func renderHARRequest(req harRequest) (raw []byte, host string, port uint16, tls bool, method, target string, err error) {
	u, perr := url.Parse(req.URL)
	if perr != nil || u.Host == "" {
		return nil, "", 0, false, "", "", fmt.Errorf("request url %q is not an absolute URL", req.URL)
	}
	tls = strings.EqualFold(u.Scheme, "https")
	host = u.Hostname()
	port = harPort(u, tls)
	method = req.Method
	if method == "" {
		method = http.MethodGet
	}
	target = u.RequestURI()
	if target == "" {
		target = "/"
	}

	body := ""
	if req.PostData != nil {
		body = req.PostData.Text
	}

	var b bytes.Buffer
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\n", method, target)
	// u.Host carries the authority with its port, which is the right Host header value when the capture
	// did not include one.
	renderHARHeaders(&b, req.Headers, u.Host, len(body), body != "")
	b.WriteString("\r\n")
	b.WriteString(body)
	return b.Bytes(), host, port, tls, method, target, nil
}

// renderHARResponse renders one HAR response into raw HTTP/1 bytes.
func renderHARResponse(resp harResponse) ([]byte, error) {
	body, err := harResponseBody(resp.Content)
	if err != nil {
		return nil, err
	}
	statusText := resp.StatusText
	if statusText == "" {
		statusText = http.StatusText(resp.Status)
	}

	var b bytes.Buffer
	fmt.Fprintf(&b, "HTTP/1.1 %d %s\r\n", resp.Status, statusText)
	// A response always gets a Content-Length for the body we hold (zero is a valid length), so the
	// stored message is framed and a history reader or Repeater resend can parse it.
	renderHARHeaders(&b, resp.Headers, "", len(body), true)
	b.WriteString("\r\n")
	b.Write(body)
	return b.Bytes(), nil
}

// renderHARHeaders writes the header lines of a message, minus the blank line that ends the head. It
// drops HTTP/2 pseudo-headers and the framing headers it recomputes, guarantees a Host header on a
// request (ensureHost non-empty), and writes the recomputed Content-Length when the message has a body
// to frame.
func renderHARHeaders(b *bytes.Buffer, headers []harNVP, ensureHost string, bodyLen int, frameBody bool) {
	sawHost := false
	for _, h := range headers {
		if h.Name == "" || strings.HasPrefix(h.Name, ":") {
			// An h2 pseudo-header is framing, not a header line; rendering ":authority: x" would be a
			// malformed header the store could not parse.
			continue
		}
		switch strings.ToLower(h.Name) {
		case "content-length", "transfer-encoding", "content-encoding":
			// Recomputed or irrelevant: the HAR body is already decoded, so a carried length or encoding
			// would describe bytes that no longer exist.
			continue
		case "host":
			sawHost = true
		}
		fmt.Fprintf(b, "%s: %s\r\n", h.Name, h.Value)
	}
	if ensureHost != "" && !sawHost {
		fmt.Fprintf(b, "Host: %s\r\n", ensureHost)
	}
	if frameBody {
		fmt.Fprintf(b, "Content-Length: %d\r\n", bodyLen)
	}
}

// harResponseBody decodes a HAR response body: base64 when the entry says so, the text verbatim
// otherwise. An empty body is nil, not an error.
func harResponseBody(c harContent) ([]byte, error) {
	if c.Text == "" {
		return nil, nil
	}
	if strings.EqualFold(c.Encoding, "base64") {
		decoded, err := base64.StdEncoding.DecodeString(c.Text)
		if err != nil {
			return nil, fmt.Errorf("content is marked base64 but did not decode: %w", err)
		}
		return decoded, nil
	}
	return []byte(c.Text), nil
}

// harPort reads the authority's explicit port, falling back to the scheme default. An out-of-range or
// unparseable port falls back too rather than refusing the entry — the scheme default is the honest
// guess, and a port is not worth dropping an exchange over.
func harPort(u *url.URL, tls bool) uint16 {
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err == nil && n > 0 && n <= 65535 {
			return uint16(n)
		}
	}
	if tls {
		return 443
	}
	return 80
}

// harStartedMs parses HAR's ISO-8601 startedDateTime to a Unix-millisecond instant, or 0 when it is
// absent or unparseable — the same "unmeasured" zero the store uses elsewhere, never a fabricated now.
func harStartedMs(started string) uint64 {
	if started == "" {
		return 0
	}
	t, err := time.Parse(time.RFC3339, started)
	if err != nil {
		// RFC3339Nano covers the sub-second precision most HAR writers emit.
		t, err = time.Parse(time.RFC3339Nano, started)
		if err != nil {
			return 0
		}
	}
	ms := t.UnixMilli()
	if ms < 0 {
		return 0
	}
	return uint64(ms)
}

// harDuration turns HAR's millisecond entry time into an ExchangeDuration, treating the spec's -1
// ("timing unknown") and any non-positive value as unmeasured rather than a zero-length exchange.
func harDuration(ms float64) core.ExchangeDuration {
	if ms <= 0 {
		return core.UnmeasuredDuration()
	}
	return core.MeasuredMicros(uint64(ms * 1000))
}
