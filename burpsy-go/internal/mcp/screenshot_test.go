package mcp

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"image"
	"image/color"
	"image/png"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/web"
)

// The stored bytes carry a marker no argument ever does, so a picture of them is told apart from a
// picture of anything a caller typed.
const (
	storedRequest  = "GET /snapshot?q=1 HTTP/1.1\r\nHost: shop.test\r\nX-Store-Marker: from-the-store-7f3a\r\n\r\n"
	storedResponse = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 11\r\n\r\nstored-body"
)

// snapshotConsole is a real console whose store holds one exchange.
func snapshotConsole(t *testing.T) (base string, ex *core.Exchange) {
	t.Helper()
	store := core.NewTrafficStore()
	reqID, _ := store.Put([]byte(storedRequest), core.DirectionRequest)
	respID, _ := store.Put([]byte(storedResponse), core.DirectionResponse)
	status := uint16(200)
	store.AddExchange(&core.Exchange{Request: core.MsgPtr(reqID), Response: &respID, Host: "shop.test", Port: 80,
		Method: "GET", Path: "/snapshot?q=1", Status: &status, Source: core.SourceProxy})
	_, url := newConsoleWith(t, store)
	return url, store.Exchanges()[0]
}

func newConsoleWith(t *testing.T, store *core.TrafficStore) (*web.Server, string) {
	t.Helper()
	srv := web.NewServer(store, core.NewScope())
	ts := httptest.NewServer(srv.MCPGuarded())
	t.Cleanup(ts.Close)
	return srv, ts.URL
}

// recordingRenderer stands in for the headless page: it keeps every snapshot it is handed and
// answers with a real PNG.
type recordingRenderer struct {
	mu    sync.Mutex
	snaps []MessageSnapshot
}

func (r *recordingRenderer) RenderMessage(_ context.Context, snap MessageSnapshot) ([]byte, error) {
	r.mu.Lock()
	r.snaps = append(r.snaps, snap)
	r.mu.Unlock()
	img := image.NewRGBA(image.Rect(0, 0, 4, 3))
	img.Set(1, 1, color.RGBA{R: 200, A: 255})
	var b bytes.Buffer
	if err := png.Encode(&b, img); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func (r *recordingRenderer) calls() []MessageSnapshot {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]MessageSnapshot(nil), r.snaps...)
}

// shoot runs one burpsy_message_screenshot call on the grouped surface and returns the raw result.
func shoot(t *testing.T, base string, r MessageRenderer, args any) json.RawMessage {
	t.Helper()
	replies := askWith(t, Options{BaseURL: base, Renderer: r},
		rpcRequest(t, 1, "tools/call", map[string]any{"name": screenshotToolName, "arguments": args}))
	if len(replies) != 1 || replies[0].Error != nil {
		t.Fatalf("tools/call %s drew %+v, want one tool result", screenshotToolName, replies)
	}
	return replies[0].Result
}

type shotResult struct {
	Content []map[string]any `json:"content"`
	IsError bool             `json:"isError"`
}

func decodeShot(t *testing.T, raw json.RawMessage) shotResult {
	t.Helper()
	var res shotResult
	if err := json.Unmarshal(raw, &res); err != nil {
		t.Fatalf("decoding the result: %v", err)
	}
	return res
}

func TestScreenshotOfAStoredExchangeIsAPNGRenderedFromTheStoresBytes(t *testing.T) {
	base, ex := snapshotConsole(t)
	rec := &recordingRenderer{}
	res := decodeShot(t, shoot(t, base, rec, map[string]any{"exchange_id": uint64(ex.ID)}))
	if res.IsError || len(res.Content) != 2 {
		t.Fatalf("a stored exchange must picture as one image and one text block, got %+v", res)
	}

	img := res.Content[0]
	if img["type"] != "image" || img["mimeType"] != "image/png" {
		t.Fatalf("the first block must be an image/png block, got %v", img)
	}
	if _, hasText := img["text"]; hasText {
		t.Fatalf("an image block carries no text member, got %v", img)
	}
	data, err := base64.StdEncoding.DecodeString(img["data"].(string))
	if err != nil {
		t.Fatalf("image data is not base64: %v", err)
	}
	if _, err := png.Decode(bytes.NewReader(data)); err != nil {
		t.Fatalf("image data is not a PNG: %v", err)
	}

	calls := rec.calls()
	if len(calls) != 1 {
		t.Fatalf("the renderer ran %d times, want 1", len(calls))
	}
	snap := calls[0]
	got := map[string]string{}
	for id, raw := range snap.Messages {
		var mv struct {
			Text string `json:"text"`
		}
		if err := json.Unmarshal(raw, &mv); err != nil {
			t.Fatalf("message %s handed to the renderer is not a MessageView: %v", id, err)
		}
		got[id] = mv.Text
	}
	reqKey, respKey := jsonID(uint64(*ex.Request)), jsonID(uint64(*ex.Response))
	if got[reqKey] != storedRequest || got[respKey] != storedResponse {
		t.Fatalf("the renderer must be handed the store's bytes for messages %s and %s, got %q", reqKey, respKey, got)
	}
	var exView struct {
		ID uint64 `json:"id"`
	}
	if err := json.Unmarshal(snap.Exchange, &exView); err != nil || exView.ID != uint64(ex.ID) {
		t.Fatalf("the renderer must be handed the console's ExchangeView for %d, got %s (%v)", ex.ID, snap.Exchange, err)
	}

	text := res.Content[1]["text"].(string)
	for _, want := range []string{"exchange " + jsonID(uint64(ex.ID)), "message " + reqKey + ", " + jsonID(uint64(len(storedRequest))) + " bytes",
		"message " + respKey + ", " + jsonID(uint64(len(storedResponse))) + " bytes"} {
		if !strings.Contains(text, want) {
			t.Errorf("the text block must name the ids and lengths (%q missing): %s", want, text)
		}
	}
	if strings.Contains(text, "from-the-store-7f3a") || strings.Contains(text, base64.StdEncoding.EncodeToString([]byte(storedRequest))[:16]) {
		t.Errorf("the text block must not carry the message itself: %s", text)
	}
}

func TestScreenshotOfAStoredMessageIDHandsTheRendererThatMessageOnly(t *testing.T) {
	base, ex := snapshotConsole(t)
	rec := &recordingRenderer{}
	res := decodeShot(t, shoot(t, base, rec, map[string]any{"message_id": uint64(*ex.Response)}))
	if res.IsError {
		t.Fatalf("a stored message id must picture, got %+v", res)
	}
	snap := rec.calls()[0]
	if snap.Exchange != nil || snap.MessageID == nil || *snap.MessageID != uint64(*ex.Response) || len(snap.Messages) != 1 {
		t.Fatalf("a message picture is that one message and no exchange, got %+v", snap)
	}
}

func TestScreenshotOfAnIDTheStoreDoesNotHoldIsAToolError(t *testing.T) {
	base, _ := snapshotConsole(t)
	for _, args := range []map[string]any{{"exchange_id": 4242}, {"message_id": 4242}} {
		rec := &recordingRenderer{}
		res := decodeShot(t, shoot(t, base, rec, args))
		if !res.IsError {
			t.Fatalf("%v names no stored record and must be a tool error, got %+v", args, res)
		}
		if text, _ := res.Content[0]["text"].(string); !strings.Contains(text, "4242") || !strings.Contains(text, "404") {
			t.Errorf("the error must name the id and the store's 404: %s", text)
		}
		if n := len(rec.calls()); n != 0 {
			t.Errorf("nothing may be rendered for a missing record, renderer ran %d times", n)
		}
	}
}

func TestScreenshotRefusesACallThatSuppliesTheMessageItself(t *testing.T) {
	base, ex := snapshotConsole(t)
	forged := "GET /forged HTTP/1.1\r\nHost: evil.test\r\n\r\n"
	cases := []map[string]any{
		{"exchange_id": uint64(ex.ID), "text": forged},
		{"exchange_id": uint64(ex.ID), "body": forged},
		{"raw": forged},
		{"request": forged, "response": "HTTP/1.1 200 OK\r\n\r\n"},
		{"file": "/tmp/message.txt"},
		{"message_id": uint64(*ex.Request), "path": "/etc/passwd"},
		{"html": "<pre>" + forged + "</pre>"},
	}
	for _, args := range cases {
		rec := &recordingRenderer{}
		res := decodeShot(t, shoot(t, base, rec, args))
		if !res.IsError {
			t.Fatalf("%v supplies the message and must be refused, got %+v", args, res)
		}
		if text, _ := res.Content[0]["text"].(string); !strings.Contains(text, "refused") || !strings.Contains(text, "project store") {
			t.Errorf("the refusal must say only stored records are pictured: %s", text)
		}
		if n := len(rec.calls()); n != 0 {
			t.Errorf("%v reached the renderer (%d calls); a refused call renders nothing", args, n)
		}
	}
	for _, args := range []any{map[string]any{}, nil, map[string]any{"exchange_id": 1, "message_id": 1}, map[string]any{"exchange_id": "x"}} {
		if res := decodeShot(t, shoot(t, base, &recordingRenderer{}, args)); !res.IsError {
			t.Errorf("%v names no single record and must be a tool error, got %+v", args, res)
		}
	}
}

func TestScreenshotToolIsListedReadOnlyOnBothSurfaces(t *testing.T) {
	base, _ := snapshotConsole(t)
	for _, surface := range []Surface{SurfaceGrouped, SurfaceRoutes} {
		replies := askWith(t, Options{BaseURL: base, Surface: surface}, rpcRequest(t, 1, "tools/list", nil))
		var list toolList
		if err := json.Unmarshal(replies[0].Result, &list); err != nil {
			t.Fatal(err)
		}
		found := false
		for _, tl := range list.Tools {
			if tl.Name != screenshotToolName {
				continue
			}
			found = true
			if tl.Annotations["readOnlyHint"] != true || tl.Annotations["destructiveHint"] != false {
				t.Errorf("%s surface: the screenshot tool must be annotated read-only, got %v", surface, tl.Annotations)
			}
			if tl.InputSchema["additionalProperties"] != false {
				t.Errorf("%s surface: the schema must refuse extra arguments, got %v", surface, tl.InputSchema)
			}
		}
		if !found {
			t.Errorf("%s surface does not list %s", surface, screenshotToolName)
		}
	}
	replies := askWith(t, Options{BaseURL: base, Only: []string{"burpsy_history"}},
		rpcRequest(t, 1, "tools/call", map[string]any{"name": screenshotToolName, "arguments": map[string]any{"exchange_id": 0}}))
	if replies[0].Error == nil {
		t.Errorf("-only without %s must not serve it, got %s", screenshotToolName, replies[0].Result)
	}
}

// The real renderer: the console's snapshot entry, built from the UI source, laid out and
// rasterised headless. This is the test that may claim the picture is the console's section — it
// checks the page the PNG was taken of mounted the editors and shows the store's bytes in them.
func TestScreenshotRendersTheConsolesOwnMessageSection(t *testing.T) {
	missing := ""
	if lookFirst("BURPSY_BUN", "bun") == "" {
		if home, _ := os.UserHomeDir(); !fileExists(home + "/.bun/bin/bun") {
			missing = "bun"
		}
	}
	if lookFirst("BURPSY_SNAPSHOT_CHROME", "chrome-headless-shell", "chromium", "chromium-browser", "google-chrome", "google-chrome-stable") == "" {
		missing = "a headless Chrome"
	}
	if missing != "" {
		if os.Getenv("BURPSY_ALLOW_NO_CHROME") == "1" {
			t.Skipf("no %s on this machine (BURPSY_ALLOW_NO_CHROME=1)", missing)
		}
		t.Fatalf("no %s on this machine: the real snapshot path cannot run (set BURPSY_ALLOW_NO_CHROME=1 to accept that deliberately)", missing)
	}
	base, ex := snapshotConsole(t)
	shot := &domRecorder{inner: newUIRenderer()}
	res := decodeShot(t, shoot(t, base, shot, map[string]any{"exchange_id": uint64(ex.ID), "width": 1000, "height": 500}))
	if res.IsError {
		t.Fatalf("the real renderer failed: %v", res.Content)
	}
	data, _ := base64.StdEncoding.DecodeString(res.Content[0]["data"].(string))
	img, err := png.Decode(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("not a PNG: %v", err)
	}
	if b := img.Bounds(); b.Dx() != 1000 || b.Dy() != 500 {
		t.Fatalf("the picture is %v, want the 1000x500 section", b)
	}
	colours := map[color.Color]bool{}
	for y := 0; y < 500; y += 7 {
		for x := 0; x < 1000; x += 7 {
			colours[img.At(x, y)] = true
		}
	}
	if len(colours) < 8 {
		t.Fatalf("the picture has %d distinct colours: a blank page, not a rendered section", len(colours))
	}

	dom := string(shot.dom)
	for _, want := range []string{`class="editor-grid"`, `editor-shell`, `cm-content`, "from-the-store-7f3a", "stored-body", ">Request<", ">Response<"} {
		if !strings.Contains(dom, want) {
			t.Errorf("the page the picture was taken of lacks %q: it is not the console's section showing the stored exchange", want)
		}
	}
}

// domRecorder runs the real renderer and keeps the DOM of the run it took the picture in.
type domRecorder struct {
	inner *uiRenderer
	dom   []byte
}

func (d *domRecorder) RenderMessage(ctx context.Context, snap MessageSnapshot) ([]byte, error) {
	png, dom, err := d.inner.render(ctx, snap)
	d.dom = dom
	return png, err
}

func jsonID(n uint64) string { b, _ := json.Marshal(n); return string(b) }
