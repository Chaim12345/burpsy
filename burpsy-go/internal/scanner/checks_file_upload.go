package scanner

// The active file-upload check (burpsy-react-ui-0vzb.15).
//
// # What it proves, and what it refuses to claim
//
// A multipart file part is re-sent as a series of files the application should not accept, and each
// claim is reported only at the strength its evidence reaches:
//
//   - Cross-site scripting (stored): an HTML or SVG file carrying an inert script canary was accepted,
//     FETCHED BACK from where the application put it, and served with a content type a browser
//     renders as a document (no attachment disposition, no script-less CSP sandbox), canary intact.
//   - File path traversal: a filename with a `../` component was stored, while the same filename
//     under a non-existent directory was refused — the application hands the name's directory
//     components to the filesystem rather than flattening them — and the response names the
//     traversed location (or the file was fetched from the parent directory).
//   - File upload functionality (CWE-434), at low severity: a file with an extension that is active
//     content or a server-side script (.html, .svg, .jsp, .php) was accepted and the application
//     reported a stored location that keeps that extension. Execution is NEVER claimed: every file
//     this check sends is an inert marker string, so nothing it uploads can run, and a server-script
//     extension being stored says nothing about whether a handler would execute it.
//
// # Polyglots
//
// A filter that inspects the file's bytes rather than its name asks for a different bypass: the
// GIF89a HTML polyglot is a valid GIF header followed by an HTML document carrying the script
// canary, so a content sniffer reads it as image/gif while a browser served it as text/html renders
// the document. It is probed as its own class (.gif, active), and two further variants carry the
// bypass in the bytes and the declared type rather than the name: image magic over the class's real
// content, and an active content type declared over a body that sniffs as an image. An active class
// that was STORED but is not served as a renderable document keeps probing its remaining variants:
// "accepted, does not render" and "accepted, renders" are different findings.
//
// # Cleaning up
//
// Every stored probe file is tracked. After the findings are built the check tries DELETE on each
// stored URL through the same scope-enforcing gate and verifies the removal by re-fetching; what it
// removed and what remains - with every stored location named, so the tester can clean up by hand -
// is appended to each finding. On endpoints with no delete the attempts cost little and the list is
// the finding's cleanup trail; on endpoints with nothing to report the removal runs silently.
//
// # Why "accepted" needs a reference
//
// An upload endpoint answers 200 to a rejected file as often as to an accepted one ("Input is
// invalid", "isValid": false). Status alone would report every endpoint that echoes the filename. A
// file therefore counts as accepted only when the response NAMES a stored location for it (a path
// carrying this upload's unique token) or the file is fetched back, AND the response has the same
// shape as the reference upload — a benign file the application did accept — once the location and
// the digits are masked. A rejection message that happens to quote the name differs from the
// acceptance in shape and is not read as one.
//
// # Safety
//
// Every file is a marker string. The HTML and SVG canaries hold a script element whose body is a
// comment, so even a victim who opens one runs nothing. No file is executable server-side, no request
// is large, and the probe count is bounded per point (maxUploadProbesPerPoint). Fetches go out through
// the same scope-enforcing gate as every probe: a stored location outside the engagement scope is
// refused at the sender and is simply not confirmed.
//
// # Where it lives in the registry
//
// The registry holds one descriptor per catalogue type and every type is claimed, so this check
// runs under the "Cross-site scripting (stored)" descriptor — the row its strongest finding files
// under, and the intrusive tier its uploads belong in — behind its own switch, CheckFileUpload. The
// stored second-order check under that row keeps its own switch (CheckStored); see
// storedXSSOrFileUpload.

import (
	"context"
	"errors"
	"fmt"
	"html"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/burpsy-go/burpsy/internal/bcheck"
	"github.com/burpsy-go/burpsy/internal/core"
)

// fileUploadEnabled is the check's own switch.
func fileUploadEnabled(c *ScanConfig) bool { return c != nil && c.CheckFileUpload }

// maxUploadPointsPerRequest bounds how many file parts of one request are probed. Every point costs
// a reference upload plus up to maxUploadProbesPerPoint more requests.
const maxUploadPointsPerRequest = 2

// maxUploadProbesPerPoint bounds the requests (uploads, fetches, deletes) one file part may cost.
// The polyglot class and its keep-probing variants, plus one delete and one verification fetch per
// stored file, raised the worst case past the original 60.
const maxUploadProbesPerPoint = 90

// storedXSSOrFileUpload runs the "Cross-site scripting (stored)" row's two techniques, each behind its
// own switch: the second-order canary check (CheckStored) and the file-upload check (CheckFileUpload).
//
// A proven upload finding is returned even when the stored half came back undecided: that half's
// claim is already registered with the pending registry and is resolved by FinishScan on its own, so
// returning the inconclusive sentinel here would make the engine drop a finding that WAS proven,
// while dropping the sentinel loses nothing but this one row's Unmeasurable count. A stored half that
// genuinely failed is still reported as the failure when the upload half found nothing.
func storedXSSOrFileUpload(stored CheckRunner) CheckRunner {
	return func(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
		if cc == nil || cc.Scanner == nil {
			return nil, nil
		}
		var storedF []*Finding
		var storedErr error
		if storedChecksEnabled(cc.Config) {
			storedF, storedErr = stored(ctx, cc)
		}
		var uploadF []*Finding
		var uploadErr error
		if fileUploadEnabled(cc.Config) {
			uploadF, uploadErr = checkFileUpload(ctx, cc)
		}
		switch {
		case len(uploadF) > 0:
			return append(storedF, uploadF...), nil
		case storedErr != nil:
			return storedF, storedErr
		case uploadErr != nil:
			return nil, uploadErr
		}
		return storedF, nil
	}
}

// checkFileUpload probes every multipart file part of the audited request.
func checkFileUpload(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	if cc == nil || cc.Scanner == nil || cc.Exchange == nil {
		return nil, nil
	}
	raw := []byte(requestRaw(cc.Scanner, cc.Exchange))
	if len(raw) == 0 {
		return nil, nil
	}
	// Decide whether there is anything to do before the harness sends its baseline: a request with
	// no file part costs nothing.
	pre, _ := bcheck.EnumerateWith(raw, []string{"body"}, cc.ProbeEnumerateOptions())
	if len(uploadPoints(pre, raw)) == 0 {
		return nil, nil
	}
	h, err := NewProbeHarness(ctx, cc, []string{"body"})
	if err != nil {
		return nil, err
	}
	points := uploadPoints(h.Points(), h.reqBytes)
	var findings []*Finding
	var failures []string
	for i, point := range points {
		if i >= maxUploadPointsPerRequest {
			break
		}
		p := newUploadProber(h, cc, point)
		f, err := p.run(ctx)
		if err != nil {
			failures = append(failures, err.Error())
		}
		findings = append(findings, f...)
	}
	if len(findings) == 0 && len(failures) > 0 {
		return nil, fmt.Errorf("file upload: %s", strings.Join(failures, "; "))
	}
	return findings, nil
}

// uploadPoints are the content points of multipart FILE parts.
func uploadPoints(points []bcheck.InsertionPoint, req []byte) []bcheck.InsertionPoint {
	var out []bcheck.InsertionPoint
	for i := range points {
		if points[i].Kind != bcheck.IpBody {
			continue
		}
		if _, ok := points[i].UploadFilename(req); ok {
			out = append(out, points[i])
		}
	}
	return out
}

// uploadProber is one file part's probe run.
type uploadProber struct {
	h     *ProbeHarness
	cc    *CheckContext
	point bcheck.InsertionPoint
	// origin and reqURL resolve the locations a response names.
	origin *url.URL
	reqURL *url.URL
	cookie string
	// sent counts this point's requests against maxUploadProbesPerPoint.
	sent int
	// ref is the accepted benign upload every other attempt is compared with.
	ref *uploadAttempt
	// stored is every URL a confirmed-stored probe file was read back from or named at, so the
	// run can try to remove them afterwards.
	stored []string
}

// uploadAttempt is one upload and what became of it.
type uploadAttempt struct {
	name, contentType, token, marker string
	resp                             ProbeResponse
	// location is the stored location the response named, unescaped; empty when none was named.
	location string
	// storedName is the filename part of location from the token on: what the application says it
	// stored this file as.
	storedName string
	// fetched is the URL the file was read back from, and fetchedResp that response.
	fetched     string
	fetchedResp ProbeResponse
	accepted    bool
}

func newUploadProber(h *ProbeHarness, cc *CheckContext, point bcheck.InsertionPoint) *uploadProber {
	ex := cc.Exchange
	scheme := "http"
	if ex.TLS {
		scheme = "https"
	}
	origin := &url.URL{Scheme: scheme, Host: hostPort(ex.Host, ex.Port, ex.TLS)}
	reqURL, err := origin.Parse(ex.Path)
	if err != nil {
		reqURL = origin
	}
	return &uploadProber{h: h, cc: cc, point: point, origin: origin, reqURL: reqURL,
		cookie: headerValue(string(h.reqBytes), "Cookie")}
}

// hostPort renders a Host header value, leaving out the scheme's default port.
func hostPort(host string, port uint16, tls bool) string {
	if (tls && port == 443) || (!tls && port == 80) || port == 0 {
		return host
	}
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}
	return host + ":" + strconv.Itoa(int(port))
}

// errUploadBudget stops a point's run once it has spent its request bound.
var errUploadBudget = errors.New("file upload: per-point request bound reached")

func (p *uploadProber) spend() error {
	if p.sent >= maxUploadProbesPerPoint {
		return errUploadBudget
	}
	p.sent++
	return nil
}

// upload sends one file and judges whether the application accepted it.
func (p *uploadProber) upload(ctx context.Context, name, contentType, content, token, marker string) (*uploadAttempt, error) {
	if err := p.spend(); err != nil {
		return nil, err
	}
	mutated, err := p.point.ApplyUpload(p.h.reqBytes, content, name, contentType)
	if err != nil {
		return nil, err
	}
	resp, err := p.h.send(ctx, mutated)
	if err != nil {
		return nil, err
	}
	p.h.recordCoverage(&p.point, name, resp)
	a := &uploadAttempt{name: name, contentType: contentType, token: token, marker: marker, resp: resp}
	a.location, a.storedName = namedLocation(resp, token)
	return a, nil
}

// fetch reads one URL back through the scope-enforcing gate.
func (p *uploadProber) fetch(ctx context.Context, target *url.URL) (ProbeResponse, error) {
	return p.request(ctx, "GET", target)
}

// request sends one bare method against a stored-file URL through the scope-enforcing gate.
func (p *uploadProber) request(ctx context.Context, method string, target *url.URL) (ProbeResponse, error) {
	if err := p.spend(); err != nil {
		return ProbeResponse{}, err
	}
	host := target.Hostname()
	port := 80
	tls := target.Scheme == "https"
	if tls {
		port = 443
	}
	if ps := target.Port(); ps != "" {
		n, err := strconv.Atoi(ps)
		if err != nil || n <= 0 || n > 65535 {
			return ProbeResponse{}, fmt.Errorf("bad port in %s", target)
		}
		port = n
	}
	path := target.EscapedPath()
	if path == "" {
		path = "/"
	}
	if target.RawQuery != "" {
		path += "?" + target.RawQuery
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\nHost: %s\r\nAccept: */*\r\n", method, path, hostPort(host, uint16(port), tls))
	// The session the upload was made in, for the same origin only: an upload area is often behind
	// a login, and a cookie is never carried to another origin.
	if p.cookie != "" && strings.EqualFold(target.Host, p.origin.Host) && target.Scheme == p.origin.Scheme {
		fmt.Fprintf(&b, "Cookie: %s\r\n", p.cookie)
	}
	b.WriteString("Connection: close\r\n\r\n")
	gate := p.h.scanner.probeGate(ctx, &core.Exchange{Host: host, Port: uint16(port), TLS: tls})
	if gate == nil {
		return ProbeResponse{}, errors.New("no authorised sender")
	}
	resp, _, err := p.h.sendVia(ctx, gate, []byte(b.String()))
	return resp, err
}

// locate fetches the candidate URLs for an attempt until one serves its marker.
func (p *uploadProber) locate(ctx context.Context, a *uploadAttempt, extra []*url.URL) {
	seen := map[string]bool{}
	for _, u := range append(p.candidates(a.location), extra...) {
		if u == nil || seen[u.String()] {
			continue
		}
		seen[u.String()] = true
		resp, err := p.fetch(ctx, u)
		if err != nil {
			if errors.Is(err, errUploadBudget) {
				return
			}
			continue
		}
		if resp.Status >= 200 && resp.Status < 300 && strings.Contains(resp.Body, a.marker) {
			a.fetched, a.fetchedResp = u.String(), resp
			return
		}
	}
}

// candidates turns a location string a response named into the URLs it may mean. An absolute URL
// or an absolute path means one thing; a relative one is tried against the origin root (a
// context-path-relative answer like "app/upload/x" is the common shape) and against the request.
func (p *uploadProber) candidates(loc string) []*url.URL {
	if loc == "" {
		return nil
	}
	var out []*url.URL
	add := func(base *url.URL, ref string) {
		r, err := url.Parse(ref)
		if err != nil {
			return
		}
		u := base.ResolveReference(r)
		if u.Scheme == "http" || u.Scheme == "https" {
			out = append(out, u)
		}
	}
	// The run read around the token can carry a label in front of the location ("url=/up/x",
	// "saved:http://h/x"); the URL or path after it is tried as well as the run as a whole.
	forms := []string{loc}
	for _, scheme := range []string{"https://", "http://"} {
		if i := strings.Index(loc, scheme); i > 0 {
			forms = append(forms, loc[i:])
		}
	}
	if i := strings.LastIndexByte(loc, '='); i >= 0 && strings.Contains(loc[i+1:], "/") {
		forms = append(forms, loc[i+1:])
	}
	for _, f := range forms {
		switch {
		case strings.HasPrefix(f, "http://"), strings.HasPrefix(f, "https://"), strings.HasPrefix(f, "/"):
			add(p.reqURL, f)
		default:
			add(p.origin, "/"+f)
			add(p.reqURL, f)
		}
	}
	return out
}

// predictable are the directories an upload with no named location is looked for in, relative to
// the request's directory and to the root. Tried once, for the reference upload, so the cost is
// bounded no matter how many variants follow.
var predictableUploadDirs = []string{"uploads/", "upload/", "files/", "/uploads/", "/upload/", "/files/", "/static/uploads/", ""}

func (p *uploadProber) guessed(name string) []*url.URL {
	var out []*url.URL
	for _, d := range predictableUploadDirs {
		r, err := url.Parse(d + url.PathEscape(name))
		if err != nil {
			continue
		}
		out = append(out, p.reqURL.ResolveReference(r))
	}
	return out
}

// uploadToken is a unique, filename-safe token per upload.
func uploadToken() string { return "bfu" + randomLetters(10) }

// uploadMarker is the inert text every file carries, so a fetch can tell this file from any other.
func uploadMarker(token string) string { return "burpsy-upload-probe-" + token }

// fileClass is one kind of file the application should not accept.
type fileClass struct {
	ext         string
	contentType string
	// active marks a class a browser renders as a document, whose fetch-back is an XSS test.
	active bool
	// alt are further extensions of the same class (".htm" for HTML).
	alt []string
	// note, when set, says what the class IS in an accepted entry ("image/HTML polyglot").
	note string
	// content builds the file body for a token; canary is what a fetch must carry intact.
	content func(marker string) (body, canary string)
}

func htmlCanary(marker string) (string, string) {
	c := "<script>/*" + marker + "*/</script>"
	return "<!DOCTYPE html><html><body>" + c + "<p>" + marker + "</p></body></html>", c
}

func svgCanary(marker string) (string, string) {
	c := "<script>/*" + marker + "*/</script>"
	return `<svg xmlns="http://www.w3.org/2000/svg">` + c + "<text>" + marker + "</text></svg>", c
}

func plainMarker(marker string) (string, string) { return marker + "\n", marker }

// gifMagic is the header that makes a content sniffer read the file as image/gif: the signature,
// a 1x1 logical screen descriptor, and a black-only global colour table.
const gifMagic = "GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00"

// gifHTMLPolyglot is both faces of the classic image/HTML polyglot: GIF89a magic for the sniffer,
// then an HTML document carrying the script canary for a browser told it is text/html.
func gifHTMLPolyglot(marker string) (string, string) {
	c := "<script>/*" + marker + "*/</script>"
	return gifMagic + "<!DOCTYPE html><html><body>" + c + "<p>" + marker + "</p></body></html>", c
}

// dangerousFileClasses are probed in this order: the classes a browser runs first, because their
// fetch-back is the strongest finding this check can make.
var dangerousFileClasses = []fileClass{
	{ext: "html", contentType: "text/html", active: true, alt: []string{"htm"}, content: htmlCanary},
	{ext: "svg", contentType: "image/svg+xml", active: true, content: svgCanary},
	{ext: "gif", contentType: "image/gif", active: true, note: "image/HTML polyglot", content: gifHTMLPolyglot},
	{ext: "jsp", contentType: "application/octet-stream", content: plainMarker},
	{ext: "php", contentType: "application/octet-stream", content: plainMarker},
}

// variant is one filter bypass: the filename and declared type to send for a class.
type variant struct {
	label       string
	name        func(token, ext, safe string) string
	contentType func(c fileClass, safe string) string
	// body, when set, rewrites the class's file body: the bypass is in the bytes, not the name.
	body func(c fileClass, marker string) (string, string)
}

var uploadVariants = []variant{
	{label: "plain extension", name: func(t, e, _ string) string { return t + "." + e },
		contentType: func(c fileClass, _ string) string { return c.contentType }},
	{label: "declared Content-Type of an image", name: func(t, e, _ string) string { return t + "." + e },
		contentType: func(_ fileClass, s string) string { return mimeForExt(s) }},
	{label: "double extension", name: func(t, e, s string) string { return t + "." + s + "." + e },
		contentType: func(_ fileClass, s string) string { return mimeForExt(s) }},
	{label: "mixed-case extension", name: func(t, e, _ string) string { return t + "." + mixedCase(e) },
		contentType: func(c fileClass, _ string) string { return c.contentType }},
	{label: "null byte before an allowed extension", name: func(t, e, s string) string { return t + "." + e + "\x00." + s },
		contentType: func(_ fileClass, s string) string { return mimeForExt(s) }},
	{label: "GIF89a image magic over the real content", name: func(t, e, _ string) string { return t + "." + e },
		contentType: func(c fileClass, _ string) string { return c.contentType },
		body: func(c fileClass, marker string) (string, string) {
			body, canary := c.content(marker)
			return gifMagic + body, canary
		}},
	{label: "an active Content-Type declared over image-sniffing content", name: func(t, e, _ string) string { return t + "." + e },
		contentType: func(c fileClass, _ string) string {
			if c.active && c.contentType == "image/gif" {
				return "text/html"
			}
			return c.contentType
		},
		body: func(c fileClass, marker string) (string, string) {
			body, canary := c.content(marker)
			return gifMagic + body, canary
		}},
}

func mixedCase(s string) string {
	b := []byte(s)
	for i := range b {
		if i%2 == 1 && b[i] >= 'a' && b[i] <= 'z' {
			b[i] -= 'a' - 'A'
		}
	}
	return string(b)
}

func mimeForExt(ext string) string {
	switch strings.ToLower(ext) {
	case "png":
		return "image/png"
	case "jpg", "jpeg":
		return "image/jpeg"
	case "gif":
		return "image/gif"
	case "txt":
		return "text/plain"
	case "pdf":
		return "application/pdf"
	}
	return "application/octet-stream"
}

// run probes one file part.
func (p *uploadProber) run(ctx context.Context) ([]*Finding, error) {
	ref, safe, err := p.reference(ctx)
	if err != nil {
		return nil, err
	}
	if ref == nil {
		// The application accepted none of the benign files, so nothing here can tell an accepted
		// dangerous file from a rejected one. That is a fact about this endpoint, not a clean
		// result for the row, and it is not reported as one.
		return nil, nil
	}
	p.ref = ref
	p.track(ref)

	var findings []*Finding
	var accepted []string
	var xss *uploadAttempt
	for _, c := range dangerousFileClasses {
		exts := append([]string{c.ext}, c.alt...)
	classLoop:
		for _, v := range uploadVariants {
			for _, ext := range exts {
				if v.label != "plain extension" && ext != c.ext {
					continue // the alternative extensions are tried plain only
				}
				token := uploadToken()
				marker := uploadMarker(token)
				bodyFn := c.content
				if v.body != nil {
					bodyFn = func(marker string) (string, string) { return v.body(c, marker) }
				}
				body, canary := bodyFn(marker)
				a, err := p.upload(ctx, v.name(token, ext, safe), v.contentType(c, safe), body, token, marker)
				if err != nil {
					if errors.Is(err, errUploadBudget) {
						break classLoop
					}
					continue
				}
				if !p.judge(ctx, a, ext) {
					continue
				}
				how := v.label
				if c.note != "" {
					how += ", " + c.note
				}
				where := "the response names it stored at " + strconv.Quote(a.location)
				if a.fetched != "" {
					where = "it is served back from " + a.fetched + " (Content-Type " +
						strconv.Quote(rawHeaderValue(string(a.fetchedResp.Raw), "Content-Type")) + ")"
				}
				accepted = append(accepted, fmt.Sprintf("%q accepted (%s); %s", a.name, how, where))
				p.track(a)
				if c.active && xss == nil && servesActive(a, canary) {
					xss = a
				}
				if c.active && xss == nil {
					// Stored, but not served as a document that renders: keep probing this class's
					// remaining bypasses - "accepted, does not render" and "accepted, renders" are
					// different findings.
					continue
				}
				break classLoop
			}
		}
	}

	if xss != nil {
		ct := rawHeaderValue(string(xss.fetchedResp.Raw), "Content-Type")
		findings = append(findings, buildHeaderFinding(p.cc, "Cross-site scripting (stored)", "high", "firm",
			fmt.Sprintf("uploaded %q to %s %q; fetched %s: HTTP %d, Content-Type %q, script canary %q intact",
				xss.name, p.point.Kind, p.point.Name, xss.fetched, xss.fetchedResp.Status, ct,
				"<script>/*"+xss.marker+"*/</script>"),
			fmt.Sprintf("a file uploaded through %s %q is served back from %s as a document a browser "+
				"renders, with the script it carried intact, so anyone sent that link runs it in this "+
				"origin. The uploaded script was an inert comment; nothing was executed by this check.",
				p.point.Kind, p.point.Name, xss.fetched)))
	}
	if t := p.traversal(ctx, safe); t != nil {
		findings = append(findings, t)
	}
	if len(accepted) > 0 {
		findings = append(findings, buildHeaderFinding(p.cc, "File upload functionality", "low", "firm",
			strings.Join(accepted, "\n"),
			fmt.Sprintf("%s %q accepts files whose extension is active content or a server-side script, "+
				"or an image/HTML polyglot that is an active document under image magic bytes, and the "+
				"application reports storing them under the name it was sent. Every file sent was an "+
				"inert marker string: this shows the filter is missing or bypassable, NOT that "+
				"anything executes - whether a handler would run a stored server-script file was not tested.",
				p.point.Kind, p.point.Name)))
	}
	p.sweep(ctx, findings)
	return findings, nil
}

// reference uploads a benign file the application should accept: the original part's own
// extension first, then common image and text types. It returns the first accepted attempt and the
// extension that worked, or nil when none was accepted.
func (p *uploadProber) reference(ctx context.Context) (*uploadAttempt, string, error) {
	orig, _ := p.point.UploadFilename(p.h.reqBytes)
	var exts []string
	if i := strings.LastIndexByte(orig, '.'); i >= 0 && i < len(orig)-1 {
		e := strings.ToLower(orig[i+1:])
		if !isDangerousExt(e) && isFilenameSafe(e) {
			exts = append(exts, e)
		}
	}
	for _, e := range []string{"png", "jpg", "txt"} {
		if len(exts) == 0 || exts[0] != e {
			exts = append(exts, e)
		}
	}
	var lastErr error
	answered := false
	for _, e := range exts {
		token := uploadToken()
		marker := uploadMarker(token)
		a, err := p.upload(ctx, token+"."+e, mimeForExt(e), marker+"\n", token, marker)
		if err != nil {
			lastErr = err
			if errors.Is(err, errUploadBudget) {
				break
			}
			continue
		}
		answered = true
		if a.resp.Status < 200 || a.resp.Status >= 300 {
			continue
		}
		// Where did it go? A named location first; with none, the predictable directories.
		var guesses []*url.URL
		if a.location == "" || !strings.Contains(a.location, "/") {
			name := a.storedName
			if name == "" {
				name = a.name
			}
			guesses = p.guessed(name)
		}
		p.locate(ctx, a, guesses)
		if a.fetched == "" && !strings.Contains(a.location, "/") {
			// Neither a path nor the file: nothing says this upload was stored anywhere.
			continue
		}
		a.accepted = true
		return a, e, nil
	}
	if answered {
		// The application answered and refused every benign file: a result, not a failure.
		return nil, "", nil
	}
	return nil, "", lastErr
}

// judge decides whether a dangerous attempt was accepted under extension ext: it reported (or
// served) a stored location keeping that extension, in the same response shape as the reference.
func (p *uploadProber) judge(ctx context.Context, a *uploadAttempt, ext string) bool {
	if a.resp.Status < 200 || a.resp.Status >= 300 {
		return false
	}
	if !sameUploadShape(p.ref, a) {
		return false
	}
	var extra []*url.URL
	if p.ref.fetched != "" && a.storedName != "" {
		// The reference was found at a URL; this file's stored name in the same directory.
		if dir, err := url.Parse(p.ref.fetched); err == nil {
			if r, err := url.Parse("./" + url.PathEscape(a.storedName)); err == nil {
				extra = append(extra, dir.ResolveReference(r))
			}
		}
	}
	p.locate(ctx, a, extra)
	stored := a.storedName
	if a.fetched != "" {
		if u, err := url.Parse(a.fetched); err == nil {
			stored = u.Path[strings.LastIndexByte(u.Path, '/')+1:]
		}
	}
	if stored == "" || (!strings.Contains(a.location, "/") && a.fetched == "") {
		return false
	}
	a.accepted = strings.HasSuffix(strings.ToLower(stored), "."+strings.ToLower(ext))
	return a.accepted
}

// servesActive reports whether a fetched file is served as a document a browser runs script in.
func servesActive(a *uploadAttempt, canary string) bool {
	if a.fetched == "" || !strings.Contains(a.fetchedResp.Body, canary) {
		return false
	}
	raw := string(a.fetchedResp.Raw)
	ct := strings.ToLower(strings.TrimSpace(rawHeaderValue(raw, "Content-Type")))
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	switch ct {
	case "text/html", "application/xhtml+xml", "image/svg+xml":
	default:
		// No type at all is sniffed as HTML only when the body starts like one and sniffing is on.
		if ct != "" || strings.EqualFold(strings.TrimSpace(rawHeaderValue(raw, "X-Content-Type-Options")), "nosniff") ||
			!strings.HasPrefix(strings.ToLower(strings.TrimSpace(a.fetchedResp.Body)), "<!doctype html") {
			return false
		}
	}
	if d := strings.ToLower(rawHeaderValue(raw, "Content-Disposition")); strings.HasPrefix(strings.TrimSpace(d), "attachment") {
		return false
	}
	if csp := strings.ToLower(rawHeaderValue(raw, "Content-Security-Policy")); strings.Contains(csp, "sandbox") &&
		!strings.Contains(csp, "allow-scripts") {
		return false
	}
	return true
}

// traversal tests whether the filename's directory components reach the filesystem: a name under a
// directory that does not exist must fail, and the same file one directory up must be stored.
func (p *uploadProber) traversal(ctx context.Context, safe string) *Finding {
	ref := p.ref
	if ref == nil || ref.location == "" && ref.fetched == "" {
		return nil
	}
	// The control: a name under a directory that cannot exist. A server that flattens names to their
	// last component stores it like any other file, and then "../" proves nothing.
	ct := uploadToken()
	missing := "bfudir" + randomLetters(8)
	ctrl, err := p.upload(ctx, missing+"/"+ct+"."+safe, mimeForExt(safe), uploadMarker(ct)+"\n", ct, uploadMarker(ct))
	if err != nil || p.storedLike(ctx, ctrl) {
		return nil
	}
	tt := uploadToken()
	name := "../" + tt + "." + safe
	up, err := p.upload(ctx, name, mimeForExt(safe), uploadMarker(tt)+"\n", tt, uploadMarker(tt))
	if err != nil || up.resp.Status < 200 || up.resp.Status >= 300 || !sameUploadShape(ref, up) {
		return nil
	}
	// The traversed file, read back from the reference's parent directory, is the strongest proof.
	var parent []*url.URL
	if ref.fetched != "" {
		if base, err := url.Parse(ref.fetched); err == nil {
			if r, err := url.Parse("../" + tt + "." + safe); err == nil {
				parent = append(parent, base.ResolveReference(r))
			}
		}
	}
	for _, u := range parent {
		if resp, err := p.fetch(ctx, u); err == nil && resp.Status >= 200 && resp.Status < 300 &&
			strings.Contains(resp.Body, up.marker) {
			up.fetched, up.fetchedResp = u.String(), resp
		}
	}
	echoed := strings.Contains(up.location, "../"+tt)
	if !echoed && up.fetched == "" {
		return nil
	}
	p.track(up)
	confidence, proof := "firm", fmt.Sprintf("the response names the stored location %q", up.location)
	if up.fetched != "" {
		confidence, proof = "certain", "the file was read back from "+up.fetched+", outside the upload directory"
	}
	return buildHeaderFinding(p.cc, "File path traversal", "high", confidence,
		fmt.Sprintf("filename %q: stored (HTTP %d, same response as an accepted upload), %s; control filename %q "+
			"under a directory that does not exist: refused (HTTP %d)",
			name, up.resp.Status, proof, ctrl.name, ctrl.resp.Status),
		fmt.Sprintf("the filename sent in %s %q is used as a filesystem path: its directory components are "+
			"resolved rather than stripped (a name under a missing directory fails), and a \"../\" component "+
			"stores the file outside the upload directory. The file written was an inert marker.",
			p.point.Kind, p.point.Name))
}

// track remembers where one confirmed-stored attempt's file lives, for the cleanup pass.
func (p *uploadProber) track(a *uploadAttempt) {
	if a.fetched != "" {
		p.stored = append(p.stored, a.fetched)
		return
	}
	if cs := p.candidates(a.location); len(cs) > 0 && cs[0] != nil {
		p.stored = append(p.stored, cs[0].String())
	}
}

// sweep removes every probe file this run stored, then appends the outcome - what was removed,
// and every location that remains for the tester to clean up by hand - to each finding. With no
// findings the removal still runs, silently: a quiet endpoint is not a reason to leave markers.
func (p *uploadProber) sweep(ctx context.Context, findings []*Finding) {
	removed, remaining := p.cleanup(ctx)
	if len(removed) == 0 && len(remaining) == 0 {
		return
	}
	note := uploadCleanupNote(removed, remaining)
	for _, f := range findings {
		f.Description += note
	}
}

// cleanup tries DELETE on every stored probe URL through the same scope-enforcing gate.
func (p *uploadProber) cleanup(ctx context.Context) (removed, remaining []string) {
	seen := map[string]bool{}
	for _, raw := range p.stored {
		if seen[raw] {
			continue
		}
		seen[raw] = true
		target, err := url.Parse(raw)
		if err != nil {
			remaining = append(remaining, raw)
			continue
		}
		if p.remove(ctx, target) {
			removed = append(removed, raw)
		} else {
			remaining = append(remaining, raw)
		}
	}
	return removed, remaining
}

// remove deletes one stored probe file and verifies the removal by re-fetching. A delete the
// application refuses - most expose none - or a file still served afterwards reports false. When
// the delete was accepted but the budget ran out before the verification fetch, the removal is
// taken on the accepted delete.
func (p *uploadProber) remove(ctx context.Context, target *url.URL) bool {
	resp, err := p.request(ctx, "DELETE", target)
	if err != nil || resp.Status < 200 || resp.Status >= 300 {
		return false
	}
	check, err := p.fetch(ctx, target)
	if err != nil {
		return true
	}
	return check.Status < 200 || check.Status >= 300
}

// uploadCleanupNote is the finding paragraph reporting the probe-file cleanup.
func uploadCleanupNote(removed, remaining []string) string {
	var b strings.Builder
	b.WriteString("\n\nStored probe files: ")
	if len(removed) > 0 {
		fmt.Fprintf(&b, "this check removed %d file(s) it had uploaded, each verified gone by re-fetching: %s. ",
			len(removed), strings.Join(removed, ", "))
	}
	if len(remaining) > 0 {
		fmt.Fprintf(&b, "the application exposes no delete for %d stored probe file(s), which remain for the tester to clean up: %s. ",
			len(remaining), strings.Join(remaining, ", "))
	}
	b.WriteString("Every file was an inert marker string; none of them can execute.")
	return b.String()
}

// storedLike reports whether an attempt was stored the way the reference was.
func (p *uploadProber) storedLike(ctx context.Context, a *uploadAttempt) bool {
	if a.resp.Status < 200 || a.resp.Status >= 300 || !sameUploadShape(p.ref, a) {
		return false
	}
	if strings.Contains(a.location, "/") {
		return true
	}
	p.locate(ctx, a, nil)
	return a.fetched != ""
}

// sameUploadShape compares two upload responses with each one's named location and every digit
// run masked: an acceptance and a rejection differ in more than the stored name.
func sameUploadShape(ref, a *uploadAttempt) bool {
	if ref == nil || a == nil || ref.resp.Status != a.resp.Status {
		return false
	}
	return maskUploadBody(ref) == maskUploadBody(a)
}

var digitRun = regexp.MustCompile(`[0-9]+`)

func maskUploadBody(a *uploadAttempt) string {
	body := unescapeLocationText(a.resp.Body)
	if a.location != "" {
		body = strings.ReplaceAll(body, a.location, "\x01")
	}
	// The stored name may appear on its own too (a "filename" field beside a "url" one).
	if a.storedName != "" {
		body = strings.ReplaceAll(body, a.storedName, "\x01")
	}
	// Whatever is left of this upload's own filename (the name as sent, echoed).
	body = strings.ReplaceAll(body, a.name, "\x01")
	body = strings.ReplaceAll(body, a.token, "\x01")
	return digitRun.ReplaceAllString(body, "0")
}

// unescapeLocationText undoes the escapings a location travels in: JSON's `\/` and `/`, and
// HTML character references.
func unescapeLocationText(s string) string {
	s = strings.ReplaceAll(s, `\/`, "/")
	s = strings.ReplaceAll(s, `/`, "/")
	s = strings.ReplaceAll(s, `/`, "/")
	return html.UnescapeString(s)
}

// isLocationByte is the characters a location is read over, on both sides of the token.
func isLocationByte(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	}
	return strings.IndexByte("-._~%/:+@!$&()*,;=?#[]", c) >= 0
}

// isFilenameByte bounds the stored name rightwards: the name ends at a query, fragment or separator.
func isFilenameByte(c byte) bool {
	return isLocationByte(c) && strings.IndexByte("/?#&=;,", c) < 0
}

// namedLocation finds the stored location a response names for the upload carrying token: the
// Location header, Content-Location, or the body. It returns the location as written (unescaped)
// and the stored filename from the token on, or empty strings when the token is not there.
func namedLocation(resp ProbeResponse, token string) (string, string) {
	raw := string(resp.Raw)
	for _, h := range []string{"Location", "Content-Location"} {
		if v := strings.TrimSpace(rawHeaderValue(raw, h)); strings.Contains(v, token) {
			return v, storedNameAt(v, token)
		}
	}
	body := unescapeLocationText(resp.Body)
	best, bestName := "", ""
	for from := 0; ; {
		i := strings.Index(body[from:], token)
		if i < 0 {
			break
		}
		i += from
		start := i
		for start > 0 && isLocationByte(body[start-1]) {
			start--
		}
		end := i + len(token)
		for end < len(body) && isLocationByte(body[end]) {
			end++
		}
		loc := body[start:end]
		// Prefer a path-like occurrence over a bare echo of the name.
		if best == "" || (!strings.Contains(best, "/") && strings.Contains(loc, "/")) {
			// The stored name is read with what follows the location in the body, so a NUL the
			// location scan stopped at is still seen (storedNameAt).
			best, bestName = loc, storedNameAt(loc+body[end:min(len(body), end+6)], token)
		}
		from = i + len(token)
	}
	return best, bestName
}

// storedNameAt is the filename in loc that holds token: from the token (with whatever the
// application prefixed to it) to the end of that path segment or parameter value.
func storedNameAt(loc, token string) string {
	i := strings.Index(loc, token)
	if i < 0 {
		return ""
	}
	start := i
	for start > 0 && isFilenameByte(loc[start-1]) {
		start--
	}
	end := i + len(token)
	for end < len(loc) && isFilenameByte(loc[end]) {
		end++
	}
	name := loc[start:end]
	// A name that runs on into a NUL was NOT truncated there: the application kept (and echoed) the
	// bytes after it, so "x.html\x00.png" is stored as that whole name, not as "x.html". The scan
	// above stops at the NUL because it is not a filename byte, so the cut is undone here rather
	// than letting the null-byte variant read as a bypass that never happened.
	if rest := loc[end:]; strings.HasPrefix(rest, "\x00") || strings.HasPrefix(rest, `\u0000`) {
		name += "\x00"
	}
	return name
}

func isDangerousExt(e string) bool {
	for _, c := range dangerousFileClasses {
		if e == c.ext {
			return true
		}
		for _, a := range c.alt {
			if e == a {
				return true
			}
		}
	}
	switch e {
	case "asp", "aspx", "jspx", "phtml", "php5", "shtml", "xhtml", "xml", "js", "exe", "sh":
		return true
	}
	return false
}

func isFilenameSafe(e string) bool {
	if len(e) == 0 || len(e) > 8 {
		return false
	}
	for i := 0; i < len(e); i++ {
		c := e[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}
