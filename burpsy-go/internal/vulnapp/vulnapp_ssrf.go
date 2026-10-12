package vulnapp

// In-band server-side request forgery behind the filters real fetchers apply (burpsy-react-ui-j1mk.9).
//
// The scanner's in-band SSRF technique plants a URL to a canary it serves on loopback and reports when
// the response carries what the canary returned. A fetcher with no filter at all is the easy case; the
// two vulnerable endpoints here each apply a filter a real application ships, so that the scanner's
// bypass spellings are what the assertion depends on:
//
//   - /ssrf/preview refuses the literal loopback names ("127.0.0.1", "localhost") and then hands the
//     URL to a client that also reaches loopback under every other spelling of it.
//   - /ssrf/thumbnail accepts only an image-looking URL (the path must end in an image extension) and
//     then follows redirects, so a URL that LOOKS like an image and redirects elsewhere is fetched.
//     Its parameter is named "item": only its VALUE says it carries a URL.
//
// Both put what they fetched into their response, which is what "in-band" means. The safe twins take
// the same parameter, echo it back when they refuse it (the echo is what catches a detector matching
// its own URL), and fetch nothing: they accept one allowlisted host, compared after parsing, and serve
// a fixed document for it.
//
// "No real damage, ever": the vulnerable fetchers dial loopback ONLY. ssrfLoopbackClient refuses any
// connection whose resolved address is not a loopback or unspecified address, so a probe naming the
// metadata service or a public host is refused before a packet leaves the process.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"
)

// ssrfAllowedHost is the safe twins' allowlist and the seeds' host.
const ssrfAllowedHost = "cdn.example.test"

func ssrfEndpoints() []Endpoint {
	const row = "Out-of-band resource load (HTTP)"
	return []Endpoint{
		{Path: "/ssrf/preview?src=https%3A%2F%2F" + ssrfAllowedHost + "%2Fabout.html", Row: row,
			Note: "fetches the URL in src and returns its body in a JSON field; refuses only the literal " +
				"host names 127.0.0.1 and localhost"},
		{Path: "/ssrf/safe/preview?src=https%3A%2F%2F" + ssrfAllowedHost + "%2Fabout.html", Row: row, Safe: true,
			Note: "accepts only the allowlisted host (compared after parsing), serves a fixed document " +
				"for it and fetches nothing; echoes a refused URL"},
		{Path: "/ssrf/thumbnail?item=https%3A%2F%2F" + ssrfAllowedHost + "%2Flogo.png", Row: row,
			Note: "fetches the URL in item when its path ends in an image extension, following redirects, " +
				"and returns the body; the parameter name does not say URL, the value does"},
		{Path: "/ssrf/safe/thumbnail?item=https%3A%2F%2F" + ssrfAllowedHost + "%2Flogo.png", Row: row, Safe: true,
			Note: "same extension rule plus the allowlisted host, never follows a redirect and fetches " +
				"nothing; echoes a refused URL"},
	}
}

func registerSSRF(mux *http.ServeMux) {
	mux.HandleFunc("/ssrf/preview", ssrfPreview)
	mux.HandleFunc("/ssrf/safe/preview", ssrfSafePreview)
	mux.HandleFunc("/ssrf/thumbnail", ssrfThumbnail)
	mux.HandleFunc("/ssrf/safe/thumbnail", ssrfSafeThumbnail)
}

// errSSRFNotLoopback is what the fixture client answers for any address it will not dial.
var errSSRFNotLoopback = errors.New("vulnapp: the SSRF fixtures dial loopback only")

// ssrfLoopbackClient is the vulnerable fetchers' client. It follows redirects (the Go default, and
// what the thumbnail defect needs) and dials only loopback or unspecified addresses, checked on the
// RESOLVED address in the dialer's Control hook, so no spelling of a public host gets through.
func ssrfLoopbackClient() *http.Client {
	dialer := &net.Dialer{
		Timeout: 2 * time.Second,
		Control: func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return errSSRFNotLoopback
			}
			ip := net.ParseIP(host)
			if ip == nil || !(ip.IsLoopback() || ip.IsUnspecified()) {
				return errSSRFNotLoopback
			}
			return nil
		},
	}
	return &http.Client{
		Timeout:   3 * time.Second,
		Transport: &http.Transport{DialContext: dialer.DialContext, Proxy: nil},
	}
}

// ssrfFetch GETs u with the loopback-only client and returns at most 4 KiB of the body.
func ssrfFetch(u string) (string, error) {
	resp, err := ssrfLoopbackClient().Get(u)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return string(b), err
}

func ssrfJSON(w http.ResponseWriter, v map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// ssrfPreview is the textual-blocklist defect: it refuses the two literal loopback names and nothing
// else, so 0.0.0.0, [::1] and the IPv4-mapped spellings all reach the same loopback.
func ssrfPreview(w http.ResponseWriter, r *http.Request) {
	src := r.URL.Query().Get("src")
	u, err := url.Parse(src)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		ssrfJSON(w, map[string]any{"ok": false, "error": "not a URL"})
		return
	}
	switch strings.ToLower(u.Hostname()) {
	case "127.0.0.1", "localhost":
		ssrfJSON(w, map[string]any{"ok": false, "error": "internal addresses are not allowed"})
		return
	}
	if u.Hostname() == ssrfAllowedHost {
		ssrfJSON(w, map[string]any{"ok": true, "preview": "<h1>About us</h1>"})
		return
	}
	body, err := ssrfFetch(u.String())
	if err != nil {
		ssrfJSON(w, map[string]any{"ok": false, "error": "fetch failed"})
		return
	}
	ssrfJSON(w, map[string]any{"ok": true, "preview": body})
}

// ssrfSafePreview fetches nothing: one allowlisted host, compared on the parsed host name.
func ssrfSafePreview(w http.ResponseWriter, r *http.Request) {
	src := r.URL.Query().Get("src")
	u, err := url.Parse(strings.TrimSpace(src))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() != ssrfAllowedHost || u.User != nil {
		ssrfJSON(w, map[string]any{"ok": false, "error": fmt.Sprintf("refused %s", src)})
		return
	}
	ssrfJSON(w, map[string]any{"ok": true, "preview": "<h1>About us</h1>"})
}

// ssrfImagePath reports whether a URL's path ends in an image extension.
func ssrfImagePath(u *url.URL) bool {
	p := strings.ToLower(u.Path)
	for _, ext := range []string{".png", ".jpg", ".jpeg", ".gif", ".webp"} {
		if strings.HasSuffix(p, ext) {
			return true
		}
	}
	return false
}

// ssrfThumbnail is the extension-filter defect: it checks how the URL LOOKS and then follows
// wherever the server it names redirects it.
func ssrfThumbnail(w http.ResponseWriter, r *http.Request) {
	item := r.URL.Query().Get("item")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	u, err := url.Parse(item)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || !ssrfImagePath(u) {
		fmt.Fprint(w, "thumbnails are made from image URLs only")
		return
	}
	if u.Hostname() == ssrfAllowedHost {
		fmt.Fprint(w, "thumbnail: 64x64 PNG")
		return
	}
	body, err := ssrfFetch(u.String())
	if err != nil {
		fmt.Fprint(w, "could not fetch the image")
		return
	}
	fmt.Fprintf(w, "thumbnail source (%d bytes): %s", len(body), body)
}

// ssrfSafeThumbnail fetches nothing: the extension rule AND the allowlisted host.
func ssrfSafeThumbnail(w http.ResponseWriter, r *http.Request) {
	item := r.URL.Query().Get("item")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	u, err := url.Parse(strings.TrimSpace(item))
	if err != nil || u.Scheme != "https" || u.Hostname() != ssrfAllowedHost || u.User != nil || !ssrfImagePath(u) {
		fmt.Fprintf(w, "refused %s", item)
		return
	}
	fmt.Fprint(w, "thumbnail: 64x64 PNG")
}
