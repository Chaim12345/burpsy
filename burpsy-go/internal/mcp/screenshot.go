package mcp

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/burpsy-go/burpsy/internal/web"
)

// screenshotToolName is the transport's picture of one stored record. Like burpsy_confirm and
// burpsy_task_status it is not a manifest route: no console endpoint answers with an image, so the
// tool reads the record through the console's own read routes and renders it here.
const screenshotToolName = "burpsy_message_screenshot"

const (
	snapshotDefaultWidth  = 1400
	snapshotDefaultHeight = 800
	snapshotMinWidth      = 600
	snapshotMaxWidth      = 2400
	snapshotMinHeight     = 300
	snapshotMaxHeight     = 1600
	// maxSnapshotRecordBytes caps one record read from the console. A record past it is refused
	// rather than rendered from a prefix: a cut-off message pictured as the stored one is the
	// partial-result-shown-as-complete this project treats as a defect.
	maxSnapshotRecordBytes = 64 << 20
)

// MessageRenderer turns the console's stored records for one exchange or message into a PNG of the
// console's History message section.
type MessageRenderer interface {
	RenderMessage(ctx context.Context, snap MessageSnapshot) ([]byte, error)
}

// MessageSnapshot is what a renderer is given: the records exactly as the console served them —
// /api/exchange/{id}'s ExchangeView and /api/message/{id}'s MessageView, unparsed — and the size of
// the section. It is the window.__BURPSY_SNAPSHOT__ payload of ui/src/snapshot/message-snapshot.tsx.
type MessageSnapshot struct {
	// Exchange is the ExchangeView, or null when the caller named a message.
	Exchange json.RawMessage `json:"exchange"`
	// Messages is every MessageView fetched, keyed by decimal message id.
	Messages map[string]json.RawMessage `json:"messages"`
	// MessageID is the message the caller named, when it named one.
	MessageID *uint64 `json:"message_id,omitempty"`
	Width     int     `json:"width"`
	Height    int     `json:"height"`
}

// screenshotContentArgs are argument names that would hand the tool the message itself. They are
// refused by name rather than as merely unknown, so a caller trying to picture text it holds learns
// that the tool pictures only what the store holds.
var screenshotContentArgs = map[string]bool{
	"text": true, "raw": true, "body": true, "request": true, "response": true, "message": true,
	"http": true, "bytes": true, "base64": true, "data": true, "content": true, "html": true,
	"file": true, "path": true, "filename": true, "url": true, "value": true,
}

type screenshotArgs struct {
	exchangeID *uint64
	messageID  *uint64
	width      int
	height     int
}

func screenshotDescriptor() tool {
	return tool{
		Name: screenshotToolName,
		Description: "Returns a PNG of one stored exchange (or one stored message) as the console's HTTP history shows it: " +
			"the message section with its Request and Response panes, rendered from the console's own editor component and stylesheet. " +
			"Pass exchange_id (a history row id) or message_id (a request_id/response_id from a row) — exactly one. " +
			"The bytes pictured are read from the project store by that id; the tool takes no message text, body or file, and refuses a call that supplies one. " +
			"Optional width and height set the section's size in CSS pixels. Reading a record changes nothing.",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"exchange_id": map[string]any{"type": "integer", "minimum": 0, "description": "the exchange (history row) id, as /api/history lists it"},
				"message_id":  map[string]any{"type": "integer", "minimum": 0, "description": "a stored message id (an exchange's request or response), as /api/message/{id} reads it"},
				"width":       map[string]any{"type": "integer", "minimum": snapshotMinWidth, "maximum": snapshotMaxWidth, "default": snapshotDefaultWidth, "description": "section width in CSS pixels"},
				"height":      map[string]any{"type": "integer", "minimum": snapshotMinHeight, "maximum": snapshotMaxHeight, "default": snapshotDefaultHeight, "description": "section height in CSS pixels"},
			},
			"oneOf": []any{
				map[string]any{"required": []string{"exchange_id"}},
				map[string]any{"required": []string{"message_id"}},
			},
			"additionalProperties": false,
		},
		Annotations: map[string]any{
			"readOnlyHint": true, "idempotentHint": true, "destructiveHint": false, "openWorldHint": false,
			"riskClass": "read", "requiresConfirmation": false, "group": groupRequests,
			"shortDescription": "PNG of a stored exchange's request/response, as the console's history pane renders it.",
		},
	}
}

// callScreenshot answers tools/call for burpsy_message_screenshot, honouring -only and the agent
// policy the same way a manifest tool does.
func (s *Server) callScreenshot(ctx context.Context, req request, raw json.RawMessage) response {
	published := false
	for _, t := range s.tools {
		if t.Name == screenshotToolName {
			published = true
			break
		}
	}
	if !published {
		return s.fail(req, codeInvalidParams, "no tool named %q; call tools/list for the surface", screenshotToolName)
	}
	if why := s.refusedByPolicy(screenshotToolName); why != "" {
		return s.ok(req, map[string]any{"content": errResult(why).Content, "isError": true})
	}
	res := s.messageScreenshot(ctx, raw)
	out := map[string]any{"content": res.Content}
	if res.IsError {
		out["isError"] = true
	}
	return s.ok(req, out)
}

func parseScreenshotArgs(raw json.RawMessage) (screenshotArgs, error) {
	a := screenshotArgs{width: snapshotDefaultWidth, height: snapshotDefaultHeight}
	if t := bytes.TrimSpace(raw); len(t) == 0 || bytes.Equal(t, []byte("null")) {
		return a, fmt.Errorf("pass exchange_id or message_id: the id of a record already in the project store")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return a, fmt.Errorf("arguments must be an object with exchange_id or message_id: %v", err)
	}
	names := make([]string, 0, len(fields))
	for k := range fields {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		v := fields[k]
		switch k {
		case "exchange_id", "message_id":
			id, err := parseRecordID(v)
			if err != nil {
				return a, fmt.Errorf("%s: %v", k, err)
			}
			if k == "exchange_id" {
				a.exchangeID = &id
			} else {
				a.messageID = &id
			}
		case "width", "height":
			n, err := parseRecordID(v)
			lo, hi := snapshotMinWidth, snapshotMaxWidth
			if k == "height" {
				lo, hi = snapshotMinHeight, snapshotMaxHeight
			}
			if err != nil || n < uint64(lo) || n > uint64(hi) {
				return a, fmt.Errorf("%s must be an integer from %d to %d", k, lo, hi)
			}
			if k == "width" {
				a.width = int(n)
			} else {
				a.height = int(n)
			}
		default:
			if screenshotContentArgs[strings.ToLower(k)] {
				return a, fmt.Errorf("refused: %q would supply the message to picture. This tool pictures only a record already in the project store — pass its exchange_id or message_id, and the bytes are read from the store", k)
			}
			return a, fmt.Errorf("unknown argument %q: the arguments are exchange_id or message_id, and optionally width and height", k)
		}
	}
	switch {
	case a.exchangeID == nil && a.messageID == nil:
		return a, fmt.Errorf("pass exchange_id or message_id: the id of a record already in the project store")
	case a.exchangeID != nil && a.messageID != nil:
		return a, fmt.Errorf("pass exchange_id or message_id, not both")
	}
	return a, nil
}

// parseRecordID reads a non-negative integer id, as a JSON number or a decimal string.
func parseRecordID(v json.RawMessage) (uint64, error) {
	t := strings.TrimSpace(string(v))
	if s, err := strconv.Unquote(t); err == nil {
		t = strings.TrimSpace(s)
	}
	n, err := strconv.ParseUint(t, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("want a non-negative integer id, got %s", string(v))
	}
	return n, nil
}

// messageScreenshot loads the named record from the console and renders it.
func (s *Server) messageScreenshot(ctx context.Context, raw json.RawMessage) callResult {
	args, err := parseScreenshotArgs(raw)
	if err != nil {
		return errResult(err.Error())
	}
	snap := MessageSnapshot{Messages: map[string]json.RawMessage{}, Width: args.width, Height: args.height}
	type loaded struct {
		role string
		id   uint64
		len  int
		none bool
	}
	var shown []loaded
	var heading string

	if args.exchangeID != nil {
		exID := *args.exchangeID
		body, err := s.readRecord(ctx, fmt.Sprintf("/api/exchange/%d", exID), "exchange", exID)
		if err != nil {
			return errResult(err.Error())
		}
		var ex struct {
			ID       uint64  `json:"id"`
			Method   string  `json:"method"`
			Host     string  `json:"host"`
			Port     uint16  `json:"port"`
			Path     string  `json:"path"`
			Status   *uint16 `json:"status"`
			Request  *uint64 `json:"request"`
			Response *uint64 `json:"response"`
			Variants struct {
				RequestOriginal  *uint64 `json:"request_original"`
				RequestAuto      *uint64 `json:"request_auto_modified"`
				ResponseOriginal *uint64 `json:"response_original"`
				ResponseAuto     *uint64 `json:"response_auto_modified"`
			} `json:"variants"`
		}
		if err := json.Unmarshal(body, &ex); err != nil {
			return errResult(fmt.Sprintf("the console's exchange %d is not an ExchangeView: %v", exID, err))
		}
		if ex.ID != exID {
			return errResult(fmt.Sprintf("asked the console for exchange %d and it answered with exchange %d; refusing to picture another record", exID, ex.ID))
		}
		snap.Exchange = body
		status := "no response"
		if ex.Status != nil {
			status = strconv.Itoa(int(*ex.Status))
		}
		heading = fmt.Sprintf("exchange %d — %s %s:%d%s → %s", exID, ex.Method, ex.Host, ex.Port, ex.Path, status)
		// Every reading the section can open on, so the snapshot resolves the pane's message id
		// with the console's own variant rule rather than this file guessing it.
		for _, m := range []struct {
			role string
			id   *uint64
		}{
			{"request", ex.Request}, {"response", ex.Response},
			{"original request", ex.Variants.RequestOriginal}, {"auto-modified request", ex.Variants.RequestAuto},
			{"original response", ex.Variants.ResponseOriginal}, {"auto-modified response", ex.Variants.ResponseAuto},
		} {
			if m.id == nil {
				if m.role == "request" || m.role == "response" {
					shown = append(shown, loaded{role: m.role, none: true})
				}
				continue
			}
			n, err := s.loadMessage(ctx, snap.Messages, *m.id)
			if err != nil {
				return errResult(fmt.Sprintf("exchange %d's %s: %v", exID, m.role, err))
			}
			shown = append(shown, loaded{role: m.role, id: *m.id, len: n})
		}
	} else {
		id := *args.messageID
		n, err := s.loadMessage(ctx, snap.Messages, id)
		if err != nil {
			return errResult(err.Error())
		}
		snap.MessageID = &id
		heading = fmt.Sprintf("message %d", id)
		shown = append(shown, loaded{role: "message", id: id, len: n})
	}

	s.renderOnce.Do(func() {
		if s.render == nil {
			s.render = newUIRenderer()
		}
	})
	png, err := s.render.RenderMessage(ctx, snap)
	if err != nil {
		return errResult(fmt.Sprintf("could not render %s: %v", heading, err))
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%s, pictured from the project store as the console's HTTP history message section (%d×%d CSS px).\n", heading, args.width, args.height)
	for _, m := range shown {
		if m.none {
			fmt.Fprintf(&b, "%s: none captured\n", m.role)
			continue
		}
		fmt.Fprintf(&b, "%s: message %d, %d bytes\n", m.role, m.id, m.len)
	}
	b.WriteString("Console preferences kept in the operator's browser (theme, editor font, hidden headers) are not visible to this tool; the picture uses their defaults.")
	return callResult{Content: []contentBlock{
		{Type: "image", Data: base64.StdEncoding.EncodeToString(png), MimeType: "image/png"},
		{Type: "text", Text: b.String()},
	}}
}

// loadMessage reads /api/message/{id} into into[id] and returns the message's stored length.
func (s *Server) loadMessage(ctx context.Context, into map[string]json.RawMessage, id uint64) (int, error) {
	key := strconv.FormatUint(id, 10)
	if v, ok := into[key]; ok {
		var m struct {
			Len int `json:"len"`
		}
		_ = json.Unmarshal(v, &m)
		return m.Len, nil
	}
	body, err := s.readRecord(ctx, "/api/message/"+key, "message", id)
	if err != nil {
		return 0, err
	}
	var m struct {
		ID   uint64 `json:"id"`
		Len  int    `json:"len"`
		Text string `json:"text"`
	}
	if err := json.Unmarshal(body, &m); err != nil {
		return 0, fmt.Errorf("the console's message %d is not a MessageView: %v", id, err)
	}
	if m.ID != id {
		return 0, fmt.Errorf("asked the console for message %d and it answered with message %d; refusing to picture another record", id, m.ID)
	}
	into[key] = body
	return m.Len, nil
}

// readRecord GETs one record from the console. A 404 is the store saying the id does not exist.
func (s *Server) readRecord(ctx context.Context, path, kind string, id uint64) (json.RawMessage, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.baseURL+path, nil)
	if err != nil {
		return nil, fmt.Errorf("could not build the request: %v", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set(web.MCPAgentHeaderName, "burpsy-mcp")
	resp, err := s.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("could not reach the burpsy console at %s: %v", s.baseURL, err)
	}
	defer resp.Body.Close()
	body, truncated, err := readCapped(resp.Body, maxSnapshotRecordBytes)
	if err != nil {
		return nil, fmt.Errorf("could not read the console's %s %d: %v", kind, id, err)
	}
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return nil, fmt.Errorf("no %s %d in the project store (the console answered HTTP 404 for GET %s)", kind, id, path)
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("the console answered HTTP %d for GET %s: %s", resp.StatusCode, path, strings.TrimSpace(string(body)))
	case truncated:
		return nil, fmt.Errorf("%s %d is larger than the %d bytes this tool reads; refusing to picture a prefix of it as the stored record", kind, id, maxSnapshotRecordBytes)
	}
	return body, nil
}
