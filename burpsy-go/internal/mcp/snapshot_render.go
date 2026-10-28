package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"image"
	"image/png"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// uiRenderer pictures a MessageSnapshot by running the console's own code, not by drawing HTTP.
//
// The page is ui/src/snapshot/message-snapshot.tsx: the History page's HttpEditor, ReadingPane and
// MessageDecodeStrip in its editor-grid, bundled by bun from the UI source and styled by the same
// styles.css the console ships. Laying that out honestly takes a CSS engine and a JavaScript engine —
// CodeMirror measures the DOM it renders into — so the rasteriser is a headless Chrome binary run
// once per picture with --screenshot against a file this function wrote. It is not browser
// automation: no DevTools protocol, no console URL, no session, no operator browser. The page's
// Content-Security-Policy forbids every connection, so the record it pictures is only ever the one
// embedded in it, which came from the console's store by id.
//
// A picture is accepted only when the same run's DOM says the section mounted, painted, and fit the
// viewport; a blank or half-drawn page is an error, never an image.
type uiRenderer struct {
	once   sync.Once
	js     []byte // the built snapshot entry
	css    []byte // the built stylesheet
	chrome string
	err    error
}

func newUIRenderer() *uiRenderer { return &uiRenderer{} }

const (
	snapshotEntry = "src/snapshot/message-snapshot.tsx"
	// snapshotWindowSlack is how much taller than the section the window is opened: a headed
	// Chrome's headless window loses its frame's height from the viewport (87 px measured on
	// Chromium 147), and the picture is cropped back to the section afterwards.
	snapshotWindowSlack = 200
	snapshotTimeout     = 90 * time.Second
)

// snapshotUIDir is the console's UI source tree: $BURPSY_UI_DIR, else the tree this package was
// built from.
func snapshotUIDir() (string, error) {
	dir := os.Getenv("BURPSY_UI_DIR")
	if dir == "" {
		_, file, _, ok := runtime.Caller(0)
		if !ok {
			return "", errors.New("cannot locate the console UI source; set BURPSY_UI_DIR to burpsy-go/internal/web/ui")
		}
		dir = filepath.Join(filepath.Dir(file), "..", "web", "ui")
	}
	for _, need := range []string{snapshotEntry, "src/styles.css", "node_modules"} {
		if _, err := os.Stat(filepath.Join(dir, need)); err != nil {
			return "", fmt.Errorf("the console UI tree at %s has no %s (set BURPSY_UI_DIR; run bun install there): %v", dir, need, err)
		}
	}
	return dir, nil
}

func lookFirst(env string, names ...string) string {
	if p := os.Getenv(env); p != "" {
		return p
	}
	for _, n := range names {
		if p, err := exec.LookPath(n); err == nil {
			return p
		}
	}
	return ""
}

// build bundles the snapshot entry and the stylesheet once per process.
func (r *uiRenderer) build() {
	dir, err := snapshotUIDir()
	if err != nil {
		r.err = err
		return
	}
	bun := lookFirst("BURPSY_BUN", "bun")
	if bun == "" {
		if home, _ := os.UserHomeDir(); home != "" {
			if p := filepath.Join(home, ".bun", "bin", "bun"); fileExists(p) {
				bun = p
			}
		}
	}
	if bun == "" {
		r.err = errors.New("bun is not on PATH (set BURPSY_BUN): it builds the console's snapshot entry")
		return
	}
	r.chrome = lookFirst("BURPSY_SNAPSHOT_CHROME", "chrome-headless-shell", "chromium", "chromium-browser", "google-chrome", "google-chrome-stable")
	if r.chrome == "" {
		r.err = errors.New("no headless Chrome found (set BURPSY_SNAPSHOT_CHROME): it lays out and rasterises the console's message section")
		return
	}
	out, err := os.MkdirTemp("", "burpsy-snapshot-assets-")
	if err != nil {
		r.err = err
		return
	}
	defer os.RemoveAll(out)
	for _, args := range [][]string{
		{"build", snapshotEntry, "--outdir", out, "--minify", "--format=iife"},
		{"build", "src/styles.css", "--outfile", filepath.Join(out, "style.css"), "--minify"},
	} {
		cmd := exec.Command(bun, args...)
		cmd.Dir = dir
		if msg, err := cmd.CombinedOutput(); err != nil {
			r.err = fmt.Errorf("bun %s: %v: %s", strings.Join(args, " "), err, tail(msg, 2000))
			return
		}
	}
	if r.js, err = os.ReadFile(filepath.Join(out, "message-snapshot.js")); err != nil {
		r.err = fmt.Errorf("bun built no snapshot entry: %v", err)
		return
	}
	if r.css, err = os.ReadFile(filepath.Join(out, "style.css")); err != nil {
		r.err = fmt.Errorf("bun built no stylesheet: %v", err)
	}
}

var (
	snapshotReadyRe    = regexp.MustCompile(`data-snapshot="ready"`)
	snapshotErrorRe    = regexp.MustCompile(`data-snapshot-error="([^"]*)"`)
	snapshotViewportRe = regexp.MustCompile(`data-viewport="(\d+)x(\d+)"`)
	cmEditorRe         = regexp.MustCompile(`class="cm-editor[ "]`)
)

func (r *uiRenderer) RenderMessage(ctx context.Context, snap MessageSnapshot) ([]byte, error) {
	png, _, err := r.render(ctx, snap)
	return png, err
}

// render returns the picture and the DOM of the run that took it.
func (r *uiRenderer) render(ctx context.Context, snap MessageSnapshot) ([]byte, []byte, error) {
	r.once.Do(r.build)
	if r.err != nil {
		return nil, nil, r.err
	}
	work, err := os.MkdirTemp("", "burpsy-snapshot-")
	if err != nil {
		return nil, nil, err
	}
	defer os.RemoveAll(work)

	page, err := snapshotPage(snap, work)
	if err != nil {
		return nil, nil, err
	}
	pagePath := filepath.Join(work, "index.html")
	for name, b := range map[string][]byte{"index.html": page, "message-snapshot.js": r.js, "style.css": r.css} {
		if err := os.WriteFile(filepath.Join(work, name), b, 0o600); err != nil {
			return nil, nil, err
		}
	}
	shot := filepath.Join(work, "shot.png")
	args := []string{
		"--headless", "--disable-gpu", "--hide-scrollbars", "--force-device-scale-factor=1",
		"--no-first-run", "--no-default-browser-check", "--disable-extensions", "--disable-sync",
		"--disable-background-networking", "--disable-component-update", "--mute-audio",
		"--user-data-dir=" + filepath.Join(work, "profile"),
		fmt.Sprintf("--window-size=%d,%d", snap.Width, snap.Height+snapshotWindowSlack),
		"--virtual-time-budget=5000",
		"--screenshot=" + shot,
		"--dump-dom",
		(&url.URL{Scheme: "file", Path: pagePath}).String(),
	}
	if os.Geteuid() == 0 {
		args = append([]string{"--no-sandbox"}, args...)
	}
	runCtx, cancel := context.WithTimeout(ctx, snapshotTimeout)
	defer cancel()
	cmd := exec.CommandContext(runCtx, r.chrome, args...)
	var dom, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &dom, &stderr
	if err := cmd.Run(); err != nil {
		return nil, nil, fmt.Errorf("%s: %v: %s", filepath.Base(r.chrome), err, tail(stderr.Bytes(), 2000))
	}

	if m := snapshotErrorRe.FindSubmatch(dom.Bytes()); m != nil {
		return nil, nil, fmt.Errorf("the message section failed to render: %s", html.UnescapeString(string(m[1])))
	}
	if !snapshotReadyRe.Match(dom.Bytes()) {
		return nil, nil, errors.New("the message section never finished mounting in the headless page; refusing a picture of a half-drawn page")
	}
	want := 2
	if snap.MessageID != nil {
		want = 1
	}
	if got := len(cmEditorRe.FindAll(dom.Bytes(), -1)); got < want {
		return nil, nil, fmt.Errorf("the page mounted %d message editor(s), want %d; refusing the picture", got, want)
	}
	if m := snapshotViewportRe.FindSubmatch(dom.Bytes()); m == nil {
		return nil, nil, errors.New("the page did not report its viewport")
	} else if w, _ := strconv.Atoi(string(m[1])); w < snap.Width {
		return nil, nil, fmt.Errorf("the headless viewport is %s px wide, narrower than the %d px section", m[1], snap.Width)
	} else if h, _ := strconv.Atoi(string(m[2])); h < snap.Height {
		return nil, nil, fmt.Errorf("the headless viewport is %s px tall, shorter than the %d px section", m[2], snap.Height)
	}

	raw, err := os.ReadFile(shot)
	if err != nil {
		return nil, nil, fmt.Errorf("%s wrote no screenshot: %v: %s", filepath.Base(r.chrome), err, tail(stderr.Bytes(), 2000))
	}
	out, err := cropPNG(raw, snap.Width, snap.Height)
	return out, dom.Bytes(), err
}

// snapshotPage is the document the rasteriser loads: the built stylesheet and entry, and the
// records as the console served them. json.Marshal escapes <, > and &, so no record can close the
// script element it is embedded in.
func snapshotPage(snap MessageSnapshot, assets string) ([]byte, error) {
	payload, err := json.Marshal(snap)
	if err != nil {
		return nil, err
	}
	css := (&url.URL{Scheme: "file", Path: filepath.Join(assets, "style.css")}).String()
	js := (&url.URL{Scheme: "file", Path: filepath.Join(assets, "message-snapshot.js")}).String()
	var b bytes.Buffer
	b.WriteString(`<!doctype html><html lang="en"><head><meta charset="utf-8">`)
	b.WriteString(`<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src file: 'unsafe-inline'; style-src file: 'unsafe-inline'; font-src file: data:; img-src file: data: blob:; connect-src 'none'; frame-src 'none'">`)
	fmt.Fprintf(&b, `<link rel="stylesheet" href="%s"></head><body><div id="root"></div>`, html.EscapeString(css))
	b.WriteString(`<script>window.__BURPSY_SNAPSHOT__=`)
	b.Write(payload)
	fmt.Fprintf(&b, `;</script><script src="%s"></script></body></html>`, html.EscapeString(js))
	return b.Bytes(), nil
}

// cropPNG cuts the window's picture down to the section's box. It removes pixels; it draws none.
func cropPNG(raw []byte, w, h int) ([]byte, error) {
	img, err := png.Decode(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("the screenshot is not a PNG: %v", err)
	}
	b := img.Bounds()
	if b.Dx() < w || b.Dy() < h {
		return nil, fmt.Errorf("the screenshot is %dx%d, smaller than the %dx%d section", b.Dx(), b.Dy(), w, h)
	}
	sub, ok := img.(interface {
		SubImage(image.Rectangle) image.Image
	})
	if !ok {
		return nil, fmt.Errorf("cannot crop a %T screenshot", img)
	}
	var out bytes.Buffer
	if err := png.Encode(&out, sub.SubImage(image.Rect(b.Min.X, b.Min.Y, b.Min.X+w, b.Min.Y+h))); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

func tail(b []byte, n int) string {
	s := strings.TrimSpace(string(b))
	if len(s) > n {
		s = "…" + s[len(s)-n:]
	}
	return s
}
