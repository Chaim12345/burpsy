package web

// Kettled HTTP/2 requests in Repeater (burpsy-react-ui-jae5).
//
// Burp calls an HTTP/2 request "kettled" when the Inspector has made its header list into something HTTP/1
// text cannot show without losing information — a CR/LF inside a value, an uppercase name, a second
// :path. Burp then stops showing the HTTP/1 rendering, shows "This request is kettled because:" and the
// reasons in its place, and sends the field list exactly as edited.
//
// Two halves live here:
//
//   - POST /api/http2/kettle answers "is this list kettled, and why" with internal/http2's KettleReasons,
//     and also "would sending it be refused, and why" with http2.Authorise run on the exact HEADERS block
//     a send would write. The two are separate questions — a CR/LF in a regular header is kettled and
//     sendable, a space in :path is kettled and refused — and the editor shows both before the operator
//     presses Send, rather than letting a refusal be the first they hear of it.
//   - a Repeater send carrying h2_headers takes sendKettledRepeaterRequest instead of the text path: the
//     list goes out through sender.AuthorisedSender.SendH2Fields, literally encoded, gated per addressed
//     request by the same classifier and scope switch as a raw frame program.
//
// # What the stored exchange says
//
// History stores HTTP/1-shaped bytes, and a kettled list has no faithful HTTP/1 form — that is the
// definition. Writing a CR/LF value into the rendering literally would split it into two header lines
// and record a request that was never sent. So the stored request is a rendering in which CR and LF
// inside a field are written as the two characters \r and \n, pseudo-headers fold into the request line
// and Host, and the exchange note says so and lists every field as sent, Go-quoted, in order. The note is
// the authoritative record; the rendering is what lets every tool that indexes HTTP/1 bytes still read
// the row.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/http2"
	"github.com/burpsy-go/burpsy/internal/sender"
	"github.com/burpsy-go/burpsy/internal/toollog"
)

// maxKettledFields and maxKettledFieldBytes bound a kettled list. A request header list past either is a
// paste into the wrong box, refused with the bound named.
const (
	maxKettledFields     = 1000
	maxKettledFieldBytes = 1 << 20
)

// h2FieldView is one HTTP/2 header field on the wire between the console and this server. Strings, not
// base64: JSON carries CR, LF and every other code point a header editor can produce, and the Inspector
// edits text.
type h2FieldView struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// h2KettleReq is POST /api/http2/kettle's body.
type h2KettleReq struct {
	Fields []h2FieldView `json:"fields"`
	// TLS is the connection's scheme, which a :scheme value is compared against.
	TLS bool `json:"tls"`
}

// kettleReasonView is one reason, as the editor's note lists it.
type kettleReasonView struct {
	Kind  string `json:"kind"`
	Index int    `json:"index"`
	Name  string `json:"name"`
	Text  string `json:"text"`
}

// h2KettleResp answers whether a list is kettled and whether it would be sent.
type h2KettleResp struct {
	Kettled bool               `json:"kettled"`
	Reasons []kettleReasonView `json:"reasons"`
	// SendRefusals is what the frame-program classifier says about the exact HEADERS block a send would
	// write: empty when the list is decidable, otherwise each construct that will refuse the send. A scope
	// refusal is not included — that depends on the engagement scope at send time, and is reported then.
	SendRefusals []string `json:"send_refusals"`
}

// validKettledFields checks a list against the bounds and turns it into HPACK fields. field names the
// request key.
func validKettledFields(field string, views []h2FieldView) ([]http2.HeaderField, error) {
	if len(views) == 0 {
		return nil, fmt.Errorf("%s is empty; a kettled request needs at least its pseudo-headers", field)
	}
	if len(views) > maxKettledFields {
		return nil, fmt.Errorf("%s carries %d fields; a kettled request may carry at most %d", field, len(views), maxKettledFields)
	}
	total := 0
	out := make([]http2.HeaderField, len(views))
	for i, v := range views {
		total += len(v.Name) + len(v.Value)
		if total > maxKettledFieldBytes {
			return nil, fmt.Errorf("%s exceeds %d bytes at field %d", field, maxKettledFieldBytes, i)
		}
		out[i] = http2.NewHeaderField(v.Name, v.Value)
	}
	return out, nil
}

// kettleAnswer computes both answers for a list.
func kettleAnswer(fields []http2.HeaderField, tls bool) h2KettleResp {
	resp := h2KettleResp{Reasons: []kettleReasonView{}, SendRefusals: []string{}}
	for _, r := range http2.KettleReasons(fields, tls) {
		resp.Reasons = append(resp.Reasons, kettleReasonView{Kind: r.Kind.Slug(), Index: r.Index, Name: r.Name, Text: r.Text})
	}
	resp.Kettled = len(resp.Reasons) > 0
	program := http2.NewH2FrameProgram(http2.NewFrameSpec(http2.TypeHeaders,
		http2.FlagEndHeaders|http2.FlagEndStream, 1, http2.EncodeLiteral(fields)))
	for _, r := range http2.Authorise(program).Refusals {
		resp.SendRefusals = append(resp.SendRefusals, r.String())
	}
	return resp
}

// handleHTTP2Kettle serves POST /api/http2/kettle. It sends nothing.
func (s *Server) handleHTTP2Kettle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req h2KettleReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	fields, err := validKettledFields("fields", req.Fields)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, kettleAnswer(fields, req.TLS))
}

// kettledSendView is what a kettled send adds to the Repeater's answer.
type kettledSendView struct {
	// Fields is how many header fields went out.
	Fields int `json:"fields"`
	// Notes names each tab setting this send did not honour, and why. Never null.
	Notes []string `json:"notes"`
	// Ended is what ended the response read: the stream ending, a GOAWAY, the deadline.
	Ended string `json:"ended"`
}

// kettledRequestFields applies the tab's request transforms to a kettled list and its body.
//
// The field list is the request: every transform is either applied to it in its own terms or not
// applied at all, and the ones that are not are returned as notes for the answer to carry.
func kettledRequestFields(fields []http2.HeaderField, body []byte, opts repeaterSendOptions, cookieHeader string) ([]http2.HeaderField, []byte, []string) {
	notes := []string{}
	out := append([]http2.HeaderField(nil), fields...)
	has := func(name string) bool {
		for _, f := range out {
			if strings.EqualFold(string(f.Name), name) {
				return true
			}
		}
		return false
	}
	if opts.ProcessCookies && cookieHeader != "" && !has("cookie") {
		out = append(out, http2.NewHeaderField("cookie", cookieHeader))
	}
	if opts.StripConnection {
		kept := out[:0:0]
		for _, f := range out {
			if !strings.EqualFold(string(f.Name), "connection") {
				kept = append(kept, f)
			}
		}
		out = kept
	}
	if opts.NormalizeLineEndings {
		body = []byte(strings.ReplaceAll(strings.ReplaceAll(string(body), "\r\n", "\n"), "\n", "\r\n"))
		notes = append(notes, "Normalize line endings was applied to the body only: the header fields are sent exactly as written, CR/LF included")
	}
	if opts.UpdateContentLength {
		kept := out[:0:0]
		at := -1
		for _, f := range out {
			if strings.EqualFold(string(f.Name), "content-length") {
				if at < 0 {
					at = len(kept)
					kept = append(kept, http2.NewHeaderField(string(f.Name), fmt.Sprint(len(body))))
				}
				continue
			}
			kept = append(kept, f)
		}
		if at < 0 && len(body) > 0 {
			kept = append(kept, http2.NewHeaderField("content-length", fmt.Sprint(len(body))))
		}
		if at >= 0 && len(body) == 0 {
			kept = append(kept[:at], kept[at+1:]...)
		}
		out = kept
	}
	if opts.H2ConnectionReuse {
		notes = append(notes, "HTTP/2 connection reuse is on for this tab, but a kettled request is always sent as the first request on its own fresh connection")
	}
	if opts.StreamingTimeoutMS != nil {
		notes = append(notes, "the streaming response timeout bounds only a host declared as streaming here; a kettled send does not promote an event-stream response to a streaming read")
	}
	return out, body, notes
}

// kettledRendering is the HTTP/1-shaped record of a kettled request. See the file header.
func kettledRendering(fields []http2.HeaderField, body []byte) []byte {
	escape := func(b []byte) string {
		return strings.NewReplacer("\r", `\r`, "\n", `\n`).Replace(string(b))
	}
	method, path, authority := "", "", ""
	var b strings.Builder
	var regular []http2.HeaderField
	for _, f := range fields {
		switch strings.ToLower(string(f.Name)) {
		case ":method":
			if method == "" {
				method = escape(f.Value)
			}
		case ":path":
			if path == "" {
				path = escape(f.Value)
			}
		case ":authority":
			if authority == "" {
				authority = escape(f.Value)
			}
		case ":scheme":
		default:
			regular = append(regular, f)
		}
	}
	fmt.Fprintf(&b, "%s %s HTTP/2\r\n", method, path)
	if authority != "" {
		fmt.Fprintf(&b, "Host: %s\r\n", authority)
	}
	for _, f := range regular {
		fmt.Fprintf(&b, "%s: %s\r\n", escape(f.Name), escape(f.Value))
	}
	b.WriteString("\r\n")
	b.Write(body)
	return []byte(b.String())
}

// kettledNote is the exchange note that makes the record exact.
func kettledNote(fields []http2.HeaderField, tabNote string) string {
	quoted := make([]string, len(fields))
	for i, f := range fields {
		quoted[i] = fmt.Sprintf("%q: %q", f.Name, f.Value)
	}
	note := fmt.Sprintf("[burpsy] kettled HTTP/2 request: sent as %d header fields written literally "+
		"(HPACK literals, no indexing). The request recorded here is a rendering — CR and LF inside a field "+
		"are shown as \\r and \\n, and the pseudo-headers fold into the request line and Host. "+
		"The fields as sent, in order: %s", len(fields), strings.Join(quoted, ", "))
	if tabNote != "" {
		return tabNote + "\n\n" + note
	}
	return note
}

// errKettledRefused marks a kettled send the server refused before anything was dialled, so the handler
// answers 400 rather than 502.
var errKettledRefused = errors.New("refused")

// sendKettledRepeaterRequest is a Repeater send whose source is a kettled field list rather than the
// request text. spec carries the target, options, note and SNI exactly as for a text send; body is the
// request text's body.
func (s *Server) sendKettledRepeaterRequest(ctx context.Context, spec repeaterSendSpec, fields []http2.HeaderField, body []byte) (repeaterSendResp, int, error) {
	if !spec.TLS {
		return repeaterSendResp{}, http.StatusBadRequest, fmt.Errorf("%w: a kettled request exists only as HTTP/2, and Repeater speaks HTTP/2 only over TLS — this target is plain HTTP", errKettledRefused)
	}
	if spec.Options.ProtocolPreference == "http1" {
		return repeaterSendResp{}, http.StatusBadRequest, fmt.Errorf("%w: this tab pins HTTP/1, and a kettled request has no HTTP/1 form; downgrade it in the Inspector (which normalises it) or unpin the protocol", errKettledRefused)
	}
	// The jar's path-match (RFC 6265 §5.4) runs against the list's own :path, query cut, as the text
	// path's runs against the target's path.
	cookiePath := "/"
	for _, f := range fields {
		if strings.EqualFold(string(f.Name), ":path") {
			cookiePath, _, _ = strings.Cut(string(f.Value), "?")
			break
		}
	}
	fields, body, notes := kettledRequestFields(fields, body, spec.Options, s.cookieHeaderFor(spec.Host, spec.Port, spec.TLS, cookiePath))

	sendCtx := spec.sendContext(ctx)
	authorised := sender.NewAuthorisedSender(s.scope, s.sender, spec.Host, spec.Port, spec.TLS)
	started := time.Now()
	res, err := authorised.SendH2Fields(sendCtx, fields, body)
	if err != nil {
		s.toolLog.Record(toollog.ToolRepeater, spec.Host, spec.Port, spec.TLS, "SEND", "", 0, nil, 0, err.Error(), nil)
		if authorised.Refused() > 0 {
			return repeaterSendResp{}, http.StatusForbidden, err
		}
		return repeaterSendResp{}, http.StatusBadGateway, err
	}
	rendering := kettledRendering(fields, body)
	spec.Raw = rendering
	spec.AsWritten = string(rendering)
	spec.Note = kettledNote(fields, spec.Note)
	resp, _ := s.recordRepeaterExchange(spec, res.Response, core.ProtocolHTTP2, core.MeasuredDuration(res.Duration), started)
	if status := res.Status; status >= 300 && status < 400 {
		if policy := spec.Options.redirectPolicy(s.sender.Network().Redirects); policy.Mode != sender.RedirectNever {
			notes = append(notes, fmt.Sprintf("this response is a %d redirect and the tab's policy would follow it, but a kettled request's redirects are not followed", status))
		}
	}
	resp.Kettled = &kettledSendView{Fields: len(fields), Notes: notes, Ended: res.Ended}
	return resp, 0, nil
}
