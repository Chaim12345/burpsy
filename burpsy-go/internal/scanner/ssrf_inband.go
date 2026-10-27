package scanner

// In-band server-side request forgery (0vzb.6).
//
// # The gap this closes
//
// The tree had exactly one SSRF row, "Out-of-band resource load (HTTP)", and it needs a collaborator:
// it plants a callback domain and waits for a DNS or HTTP interaction. That is the right test for a
// BLIND SSRF, and it is the only test for one. It is not the only SSRF: an application that fetches a
// URL and puts the fetched body into its own response proves the same primitive — the server made a
// request an attacker chose — with evidence visible in the response itself. Measured on OWASP
// VulnerableApp: `LEVEL_1?fileurl=http://127.0.0.1:9090/VulnerableApp/scanner` returns that endpoint's
// JSON body, while the SECURE `LEVEL_5` answers "Provided URL not valid". With only the OOB row
// admitted, all four vulnerable levels reported clean.
//
// # Why it is the same catalogued issue
//
// Both are CWE-918, and Burp's "Out-of-band resource load (HTTP)" definition covers content fetched
// from an arbitrary external location AND INCORPORATED INTO THE APPLICATION'S OWN RESPONSE — the
// in-band case is inside that sentence. So this files under the same row rather than inventing a name
// a report reader would not find in Burp. It is admitted by its own switch, because it sends requests
// to a URL the PROBE chooses and an operator should opt into that separately from the passive rows.
//
// # What it does NOT do
//
// It does not chase a URL it chooses at random. It plants a URL pointing at a canary endpoint on THIS
// scanner's own listener — a path only this process serves — and looks for that endpoint's marker in
// the response. A target that fetches it proves the fetch; a target that merely echoes the URL string
// back does not, because the marker is not in the URL, it is in what the URL RETURNS. That is the
// difference between "the application repeated my input" and "the application made the request".
//
// # Same-host only
//
// The canary listens on 127.0.0.1. A target fetches it only when the target and this scanner share a
// host (or a network namespace): a remote target that requests http://127.0.0.1:N/… reaches ITS OWN
// loopback, finds nothing, and the canary payloads are silent there. They never produce a false
// positive that way (the marker is random and only this listener serves it), but they also prove
// nothing against a remote target. Against one, the file and metadata payloads below are what can
// fire, and a BLIND fetch is the out-of-band row's job. There is no collaborator or listener address
// in ScanConfig to bind to instead; binding to a routable interface would also turn the canary into a
// listener reachable from the network, which this check deliberately is not.

//
// # Filter bypasses (j1mk.9)
//
// A fetcher that accepts the plain canary URL proves the primitive at once. One that refuses it has
// usually filtered on the URL's TEXT — a literal loopback host, a scheme prefix, an allowlisted host
// that must appear somewhere, a required file extension — and then handed the URL to a parser or a
// client that reads it differently. On a parameter that looks like it carries a URL (by name or by
// value, ssrfURLLikePoint) the check also plants the same canary written the ways such filters miss:
//
//   - alternate spellings of loopback: 127.1, 127.0.1, the 32-bit integer, hex, 0.0.0.0, 0, the
//     IPv4-mapped IPv6 forms, [::1] (a second canary listener on the IPv6 loopback), localhost in
//     two cases. Every spelling means loopback under every parser that accepts it; a parser that does
//     not accepts it as a host NAME, which fails to resolve. No spelling was chosen whose decimal
//     reading is a public address (0177.0.0.1 is 177.0.0.1 to a parser without octal, so it is not
//     here).
//   - scheme variations: mixed case, scheme-relative, scheme-less, a leading space (Java's URL and
//     several others trim it, a startsWith filter does not), single slash and backslash forms that the
//     WHATWG URL parser normalises.
//   - allowlist confusion with the host the parameter already held: the allowed host as userinfo,
//     in the fragment and in the query, so a "contains the allowed host" filter passes while the
//     request goes to the canary.
//   - a redirect through the canary itself: a path ending in an image extension that answers 302 to
//     the marker (a fetcher that checks the extension and follows redirects), and one that answers 302
//     to the instance metadata address (a fetcher that blocks the metadata host in the URL it was
//     given and not in the one it was redirected to).
//   - the file scheme and the metadata addresses written the ways startsWith and host-equality
//     filters miss (file:/, file://localhost/, upper case, a leading space, Java's `url:` prefix; the
//     metadata IP as an integer and IPv4-mapped, and the ECS task metadata address).
//
// DNS-rebinding names (127.0.0.1.nip.io and the like) are deliberately NOT planted: they depend on a
// third-party resolver, so they are not offline, and they would tell that resolver what is scanned.
// gopher:// and dict:// are not planted either: they are how an SSRF is turned into writes against an
// internal service, which is exploitation, not detection.
//
// The evidence rule does not change with the spelling. The canary marker is in what the canary
// RETURNS, so no spelling of the URL can carry it; the file and metadata signatures still have to be
// absent from the baseline and from the payload.

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/burpsy-go/burpsy/internal/bcheck"
)

// ssrfAWSMetadataURL is the IMDS listing, the one metadata document the check reads. It is the
// directory of key names, never a credential path.
const ssrfAWSMetadataURL = "http://169.254.169.254/latest/meta-data/"

// The canary's redirect hops. Each ends in an image extension so a fetcher that only accepts
// image-looking URLs still takes it; what it then follows is the redirect.
const (
	ssrfHopToCanary   = "/r/i.png"
	ssrfHopToMetadata = "/r/m.png"
)

// ssrfCanaryServer is a loopback listener this scanner owns, serving a unique marker at a unique
// path. A target that fetches the planted URL returns the marker; a target that only echoes the URL
// cannot, because the marker never appears in the URL.
type ssrfCanaryServer struct {
	srvs []*http.Server
	// addr is 127.0.0.1:port; port is its port alone, for the alternate loopback spellings.
	addr string
	port string
	// addr6 is the [::1] listener's address, empty when this host has no IPv6 loopback.
	addr6  string
	path   string
	marker string
}

// startSSRFCanary binds the listener. It binds loopback only (see "Same-host only" above): nothing
// outside this host can reach it, which keeps the canary from being an open reflector, and a target on
// another host cannot fetch it either. The IPv6 loopback listener is best-effort: without it the [::1]
// spellings are simply not planted.
func startSSRFCanary() (*ssrfCanaryServer, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("ssrf canary: listen: %w", err)
	}
	c := &ssrfCanaryServer{
		addr:   ln.Addr().String(),
		path:   "/burpsy-ssrf-" + domCanary("canary"),
		marker: "bsySSRF" + domCanary("mark"),
	}
	_, c.port, _ = net.SplitHostPort(c.addr)
	c.serveOn(ln)
	if ln6, err := net.Listen("tcp6", "[::1]:0"); err == nil {
		c.addr6 = ln6.Addr().String()
		c.serveOn(ln6)
	}
	return c, nil
}

func (c *ssrfCanaryServer) serveOn(ln net.Listener) {
	srv := &http.Server{Handler: http.HandlerFunc(c.serve), ReadHeaderTimeout: 5 * time.Second}
	c.srvs = append(c.srvs, srv)
	go func() { _ = srv.Serve(ln) }()
}

// serve answers the marker at the canary path, and the two redirect hops beneath it. A redirect's
// Location and body name a URL, never the marker, so a target that returns the 302 itself rather than
// following it carries no evidence.
func (c *ssrfCanaryServer) serve(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case c.path, c.path + "/":
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(c.marker))
	case c.path + ssrfHopToCanary:
		http.Redirect(w, r, c.URL(), http.StatusFound)
	case c.path + ssrfHopToMetadata:
		http.Redirect(w, r, ssrfAWSMetadataURL, http.StatusFound)
	default:
		http.NotFound(w, r)
	}
}

// URL is the address a probe plants.
func (c *ssrfCanaryServer) URL() string { return "http://" + c.addr + c.path }

// Marker is the token a successful fetch returns.
func (c *ssrfCanaryServer) Marker() string { return c.marker }

func (c *ssrfCanaryServer) Close() {
	if c == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	for _, srv := range c.srvs {
		_ = srv.Shutdown(ctx)
	}
}

// checkSSRFInBand plants this scanner's own canary URL and reports when the target fetched it and
// returned its body.
func checkSSRFInBand(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	const row = "Out-of-band resource load (HTTP)"
	if err := cc.RequireEgress(); err != nil {
		return nil, fmt.Errorf("%s: %w", row, err)
	}
	h, err := NewProbeHarness(ctx, cc, cc.ProbeInsertionKinds())
	if err != nil {
		return nil, err
	}
	points := h.Points()
	if len(points) == 0 {
		return nil, nil
	}
	// URL-shaped parameters first, so the per-check cap never drops the parameter most likely to be
	// fetched in favour of one that is not. The sort is stable: request order otherwise.
	points = append([]bcheck.InsertionPoint(nil), points...)
	sort.SliceStable(points, func(i, j int) bool {
		return ssrfURLLikePoint(points[i]) && !ssrfURLLikePoint(points[j])
	})
	if len(points) > MaxInjectionPointsPerCheck {
		points = points[:MaxInjectionPointsPerCheck]
	}
	canary, err := startSSRFCanary()
	if err != nil {
		// No listener means no capability, which must never read as no vulnerability.
		return nil, fmt.Errorf("%s: %w", row, err)
	}
	defer canary.Close()

	var targetHost string
	if cc.Exchange != nil {
		targetHost = cc.Exchange.Host
	}
	baseline := h.Baseline().Body
	for _, point := range points {
		for _, probe := range ssrfInBandProbes(canary, point, targetHost) {
			res, err := h.Send(ctx, point, probe.value)
			if err != nil {
				continue
			}
			// The marker is in what the canary RETURNS, never in the URL, so finding it in the response
			// means the target made the request. A target that echoed the URL back carries the address
			// but not the marker. The file and metadata payloads are judged by their own content.
			if what, ok := ssrfInBandEvidence(res.Body, baseline, probe.value, canary.Marker()); ok {
				return []*Finding{buildHeaderFinding(cc, row, "high", "firm",
					probe.value,
					fmt.Sprintf("%s %q: %s (planted as %s), so a server-side request can be sent to an attacker-chosen address",
						point.Kind, point.Name, what, probe.how))}, nil
			}
		}
	}
	// Nothing fetched it. That is a result, and the honest reading is "no in-band fetch observed" —
	// a BLIND effect is what the collaborator row is for, and it is a separate admission.
	return nil, nil
}

// ssrfProbe is one planted value and the technique it exercises, which the finding names so a reader
// knows which filter the target failed to apply.
type ssrfProbe struct {
	value string
	how   string
}

// ssrfInBandPayloads are the URL-shaped values planted in EVERY parameter.
//
// The HTTP canary URL is the strongest probe — it proves the server made an attacker-chosen request
// and returned its body, with the marker living in what the URL RETURNS rather than in the URL. The
// rest cover the other resource schemes and addresses an SSRF actually reaches, each judged by content
// only the fetched resource produces:
//
//   - `file:///etc/passwd` and the Windows equivalent: the classic local-file read, evidenced by a
//     known line of the file.
//   - the cloud metadata addresses (AWS IMDS, GCP): an in-band read of the instance identity, evidenced
//     by the listing and document shapes those services return — never by a word the URL itself
//     contains, because an application that echoes the URL would then match.
func ssrfInBandPayloads(canaryURL string) []string {
	upper := canaryURL
	if len(upper) >= 4 {
		upper = strings.ToUpper(upper[:4]) + upper[4:]
	}
	return []string{
		canaryURL, canaryURL + "/", upper,
		"file:///etc/passwd",
		"file:///c:/windows/win.ini",
		ssrfAWSMetadataURL,
		"http://metadata.google.internal/computeMetadata/v1/instance/?recursive=true",
		"http://169.254.169.254/metadata/instance?api-version=2021-02-01",
		"http://100.100.100.200/latest/meta-data/",
	}
}

// ssrfInBandProbes is the ordered probe list for one point: the canary, then (on a URL-like point
// only) the bypass spellings of it, then the file and metadata reads and their bypass spellings. The
// addresses that can hang on a host with nothing behind them (the metadata ones) come last, so a
// fetch the canary can prove ends the point before they are sent.
func ssrfInBandProbes(c *ssrfCanaryServer, point bcheck.InsertionPoint, targetHost string) []ssrfProbe {
	base := ssrfInBandPayloads(c.URL())
	plain := func(vs []string, how string) []ssrfProbe {
		out := make([]ssrfProbe, 0, len(vs))
		for _, v := range vs {
			out = append(out, ssrfProbe{v, how})
		}
		return out
	}
	if !ssrfURLLikePoint(point) {
		// Azure and Alibaba (base[7:]) go to URL-like points only.
		return append(plain(base[:3], "the scanner's canary URL"), plain(base[3:7], "a local or metadata resource URL")...)
	}
	out := plain(base[:3], "the scanner's canary URL")
	out = append(out, ssrfLoopbackSpellings(c)...)
	out = append(out, ssrfSchemeSpellings(c)...)
	out = append(out, ssrfAllowlistConfusion(c, ssrfAllowedHost(point, targetHost))...)
	out = append(out, ssrfProbe{"http://" + c.addr + c.path + ssrfHopToCanary,
		"an image-looking canary URL that redirects to the canary"})
	out = append(out, plain(base[3:5], "a local file URL")...)
	out = append(out, plain([]string{
		"file:/etc/passwd", "file://localhost/etc/passwd", "FILE:///etc/passwd",
		" file:///etc/passwd", "url:file:///etc/passwd",
	}, "a file URL spelled past a scheme-prefix filter")...)
	out = append(out, ssrfProbe{"http://" + c.addr + c.path + ssrfHopToMetadata,
		"an image-looking canary URL that redirects to the instance metadata address"})
	out = append(out, plain(base[5:], "the instance metadata URL")...)
	out = append(out, plain([]string{
		"http://[::ffff:169.254.169.254]/latest/meta-data",
		"http://2852039166/latest/meta-data",
		"http://169.254.170.2/v2/metadata",
	}, "the metadata address spelled past a host filter")...)
	return out
}

// ssrfLoopbackSpellings are the canary URL with its loopback host written the ways a textual
// blocklist misses. See "Filter bypasses" for why each is safe to plant.
func ssrfLoopbackSpellings(c *ssrfCanaryServer) []ssrfProbe {
	hosts := []string{
		"localhost", "LOCALHOST", "127.1", "127.0.1", "2130706433", "0x7f000001", "0x7f.0.0.1",
		"0.0.0.0", "0", "[::ffff:127.0.0.1]", "[0:0:0:0:0:ffff:127.0.0.1]",
	}
	out := make([]ssrfProbe, 0, len(hosts)+2)
	for _, h := range hosts {
		out = append(out, ssrfProbe{"http://" + h + ":" + c.port + c.path, "the canary with loopback written as " + h})
	}
	if c.addr6 != "" {
		_, p6, _ := net.SplitHostPort(c.addr6)
		for _, h := range []string{"[::1]", "[0:0:0:0:0:0:0:1]"} {
			out = append(out, ssrfProbe{"http://" + h + ":" + p6 + c.path, "the canary with loopback written as " + h})
		}
	}
	return out
}

// ssrfSchemeSpellings are the canary URL with its scheme written the ways a prefix filter misses.
func ssrfSchemeSpellings(c *ssrfCanaryServer) []ssrfProbe {
	rest := c.addr + c.path
	return []ssrfProbe{
		{"hTtP://" + rest, "the canary with a mixed-case scheme"},
		{"//" + rest, "the canary as a scheme-relative URL"},
		{rest, "the canary without a scheme"},
		{" http://" + rest, "the canary behind a leading space"},
		{"http:/" + rest, "the canary with a single-slash authority"},
		{`http:\\` + rest, "the canary with backslashes for slashes"},
	}
}

// ssrfAllowlistConfusion plants the canary with the host the parameter already trusted written into
// it where a substring or prefix check finds it and a URL parser does not route to it.
func ssrfAllowlistConfusion(c *ssrfCanaryServer, allowed string) []ssrfProbe {
	if allowed == "" {
		return nil
	}
	return []ssrfProbe{
		{"http://" + allowed + "@" + c.addr + c.path, "the canary behind the allowed host as userinfo"},
		{"http://" + c.addr + c.path + "#" + allowed, "the canary with the allowed host in the fragment"},
		{"http://" + c.addr + c.path + "?" + allowed, "the canary with the allowed host in the query"},
	}
}

// ssrfAllowedHost is the host a filter most plausibly trusts: the one already in the parameter's
// value, else the target's own. Empty when neither is a usable host name.
func ssrfAllowedHost(point bcheck.InsertionPoint, targetHost string) string {
	v := ssrfDecodedBase(point.BaseValue)
	if u, err := url.Parse(v); err == nil && u.Hostname() != "" {
		return u.Hostname()
	}
	if strings.HasPrefix(v, "//") {
		if u, err := url.Parse("http:" + v); err == nil && u.Hostname() != "" {
			return u.Hostname()
		}
	}
	if targetHost != "" && !strings.ContainsAny(targetHost, "@/#?") {
		return targetHost
	}
	return ""
}

// ssrfDecodedBase is a point's base value as the application reads it: percent-decoded, without the
// quotes and escaped slashes a JSON string carries on the wire.
func ssrfDecodedBase(v string) string {
	if d, err := url.QueryUnescape(v); err == nil {
		v = d
	}
	v = strings.TrimSpace(v)
	if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
		v = v[1 : len(v)-1]
	}
	return strings.ReplaceAll(v, `\/`, `/`)
}

// ssrfURLNameWords are parameter-name parts that say the value is a location to fetch. A name is split
// on case changes and punctuation and compared word by word, so "ip" matches "server_ip" and not
// "recipient". ssrfURLNameFragments are matched anywhere in the lowercased name, because they are long
// enough not to occur inside unrelated words and are often run together ("imageurl", "feeduri").
var (
	ssrfURLNameWords = map[string]bool{
		"uri": true, "src": true, "source": true, "dest": true, "destination": true, "redir": true,
		"link": true, "feed": true, "rss": true, "fetch": true, "load": true, "proxy": true,
		"host": true, "domain": true, "site": true, "img": true, "icon": true, "logo": true,
		"file": true, "path": true, "doc": true, "document": true, "page": true, "target": true,
		"remote": true, "resource": true, "location": true, "continue": true, "next": true,
		"return": true, "goto": true, "to": true, "ip": true, "addr": true, "address": true,
		"server": true, "origin": true, "ref": true, "reference": true, "u": true, "endpoint": true,
		"download": true, "upload": true, "preview": true, "import": true, "pdf": true,
	}
	ssrfURLNameFragments = []string{"url", "href", "webhook", "callback", "redirect", "image", "avatar", "uri"}
	ssrfNameSplitRE      = regexp.MustCompile(`[A-Z]+[a-z]*|[a-z]+`)
	ssrfURLValueRE       = regexp.MustCompile(`(?i)^(?:[a-z][a-z0-9+.-]*://|//|(?:https?|file|ftp|jar|netdoc):|www\.)` +
		`|^(?i)[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,}(?::\d+)?(?:/|$)` +
		`|^\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?(?:/|$)`)
)

// ssrfURLLikePoint reports whether a point looks like it carries a URL or a host: by its name, or by
// its value. Only these points get the bypass spellings; every point still gets the plain canary.
func ssrfURLLikePoint(p bcheck.InsertionPoint) bool {
	lower := strings.ToLower(p.Name)
	for _, f := range ssrfURLNameFragments {
		if strings.Contains(lower, f) {
			// "uri" inside "security" or "during" is not a URL: only count it as a word boundary
			// fragment (whole name, or a name that starts or ends with it).
			if f == "uri" && !(lower == "uri" || strings.HasPrefix(lower, "uri") || strings.HasSuffix(lower, "uri")) {
				continue
			}
			return true
		}
	}
	for _, w := range ssrfNameSplitRE.FindAllString(p.Name, -1) {
		if ssrfURLNameWords[strings.ToLower(w)] {
			return true
		}
	}
	return ssrfURLValueRE.MatchString(ssrfDecodedBase(p.BaseValue))
}

// ssrfInBandSignature is one piece of content a fetched resource carries.
type ssrfInBandSignature struct {
	re   *regexp.Regexp
	what string
}

// ssrfInBandSignatures are judged by ssrfInBandEvidence under the echo and baseline rules.
//
//   - /etc/passwd: the root entry.
//   - win.ini: its section headers and the 16-bit comment it ships with.
//   - AWS IMDS: the meta-data listing is one key per line in a fixed order, so `ami-id` directly
//     followed by `ami-launch-index` and `ami-manifest-path` is the listing itself. The separator may
//     be a newline, or nothing at all: a fetcher that reads the body line by line and joins the lines
//     (a common shape) returns the keys run together, and three keys in the listing's own order are
//     still the listing. `instance-id` alone on its own line is a key of it.
//   - ECS task metadata: a JSON document with a task ARN.
//   - GCP: the recursive instance document is JSON whose keys include `machineType` and
//     `serviceAccounts`; a quoted key followed by a colon is the document, not prose mentioning it.
//   - Azure: the instance document's `azEnvironment` key, or IMDS's own missing-header error.
//   - Alibaba Cloud: the meta-data listing's `zone-id` key on its own line.
//
// Every signature is matched against the body as served AND with JSON string escapes undone, because
// an application that wraps the fetched content in a JSON field turns its newlines into `\n`.
var ssrfInBandSignatures = []ssrfInBandSignature{
	{regexp.MustCompile(`root:[x*]:0:0:`), "/etc/passwd was read"},
	{regexp.MustCompile(`(?m)^\[fonts\]\r?$`), "win.ini was read"},
	{regexp.MustCompile(`(?m)^\[extensions\]\r?$`), "win.ini was read"},
	{regexp.MustCompile(`for 16-bit app support`), "win.ini was read"},
	{regexp.MustCompile(`(?m)ami-id\r?\n?ami-launch-index\r?\n?ami-manifest-path`), "the AWS instance metadata listing was read"},
	{regexp.MustCompile(`(?m)^instance-id\r?$`), "the instance metadata listing was read"},
	{regexp.MustCompile(`"TaskARN"\s*:\s*"arn:aws:ecs:`), "the ECS task metadata document was read"},
	{regexp.MustCompile(`"machineType"\s*:\s*"projects/`), "the GCP instance metadata document was read"},
	{regexp.MustCompile(`"serviceAccounts"\s*:\s*\{`), "the GCP instance metadata document was read"},
	// Azure IMDS answers a request without its Metadata header with this error, which only IMDS sends.
	{regexp.MustCompile(`Required metadata header not specified`), "the Azure instance metadata service answered"},
	{regexp.MustCompile(`"azEnvironment"\s*:\s*"`), "the Azure instance metadata document was read"},
	{regexp.MustCompile(`(?m)^zone-id\r?$`), "the Alibaba Cloud instance metadata listing was read"},
}

// ssrfJSONUnescaper undoes the string escapes a JSON encoder applies to fetched content.
var ssrfJSONUnescaper = strings.NewReplacer(`\r`, "\r", `\n`, "\n", `\t`, "\t", `\/`, "/", `\"`, `"`, `\\`, `\`)

// ssrfInBandEvidence reports whether a response body carries evidence that the planted URL was
// fetched, and what that evidence was.
//
// The canary marker is the unambiguous case: it lives only in what the canary RETURNS. Every other
// signature counts only when it is ABSENT from the baseline response (a page that already shows a
// passwd line or an IMDS listing proves nothing by showing it again) and is NOT a substring of the
// payload that was sent (an application that echoes the URL must never match the URL's own words).
// Both rules apply to the JSON-unescaped reading as well as the raw one.
func ssrfInBandEvidence(body, baseline, payload, marker string) (string, bool) {
	if marker != "" && strings.Contains(body, marker) && !strings.Contains(payload, marker) && !strings.Contains(baseline, marker) {
		return "the scanner's canary endpoint was fetched and its body returned", true
	}
	bodies := []string{body}
	if u := ssrfJSONUnescaper.Replace(body); u != body {
		bodies = append(bodies, u)
	}
	baselines := []string{baseline, ssrfJSONUnescaper.Replace(baseline)}
	for _, sig := range ssrfInBandSignatures {
		if sig.re.MatchString(baselines[0]) || sig.re.MatchString(baselines[1]) {
			continue
		}
		for _, b := range bodies {
			m := sig.re.FindString(b)
			if m == "" || strings.Contains(payload, m) {
				continue
			}
			return sig.what, true
		}
	}
	return "", false
}
