package scanner

import (
	"context"
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/bcheck"
	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/sender"
	"github.com/burpsy-go/burpsy/internal/vulnapp"
	"go.uber.org/zap"
)

func deserServe(t *testing.T, h http.Handler) (string, uint16) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	host, portStr, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(portStr)
	return host, uint16(port)
}

// deserAudit audits one GET (with extra request headers) with ONLY the deserialization switch on.
func deserAudit(t *testing.T, host string, port uint16, path string, headers map[string]string) []*Finding {
	t.Helper()
	store := core.NewTrafficStore()
	var b strings.Builder
	b.WriteString("GET " + path + " HTTP/1.1\r\nHost: " + net.JoinHostPort(host, strconv.Itoa(int(port))) + "\r\n")
	for k, v := range headers {
		b.WriteString(k + ": " + v + "\r\n")
	}
	b.WriteString("\r\n")
	reqID, err := store.Put([]byte(b.String()), core.DirectionRequest)
	if err != nil {
		t.Fatal(err)
	}
	respID, err := store.Put([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nseed"), core.DirectionResponse)
	if err != nil {
		t.Fatal(err)
	}
	ex := &core.Exchange{Request: core.MsgPtr(reqID), Response: &respID, Host: host, Port: port, Method: "GET", Path: path}
	store.AddExchange(ex)
	scan := NewActiveScanner(store, zap.NewNop()).
		WithSender(sender.NewSender(sender.DefaultSenderConfig())).
		WithConfig(&ScanConfig{MaxConcurrency: 1, Timeout: 60 * time.Second, CheckInsecureDeserialization: true})
	_, findings := scan.AuditSession(context.Background(), []core.ExchangeID{ex.ID}, DefaultAuditConfig())
	return findings
}

func deserFinding(fs []*Finding) *Finding {
	for _, f := range fs {
		if f.Name == IssueInsecureDeserialization {
			return f
		}
	}
	return nil
}

// Each vulnerable fixture is reported by the family that matches its format, at that family's
// severity, and each safe twin is quiet. The runtime corpus asserts only the row; this pins WHICH
// proof fired, so a fixture passing on the wrong family's differential cannot hide.
func TestDeserializationFixturesFireTheirOwnFamily(t *testing.T) {
	host, port := deserServe(t, vulnapp.Handler())
	want := map[string]struct{ family, severity, confidence string }{
		"/deser/java/profile":        {"Java object stream (base64)", "high", "firm"},
		"/deser/php/cart":            {"PHP serialize() (text)", "high", "firm"},
		"/deser/pickle/session":      {"Python pickle (base64)", "high", "firm"},
		"/deser/activity":            {"Jackson polymorphic JSON (@class) (base64)", "high", "firm"},
		"/deser/prefs":               {"unsigned JSON state (base64)", "low", "tentative"},
		"/deser/safe/java/profile":   {},
		"/deser/safe/php/cart":       {},
		"/deser/safe/pickle/session": {},
		"/deser/safe/activity":       {},
		"/deser/safe/prefs-param":    {},
	}
	seen := 0
	for _, e := range vulnapp.Vulnerabilities() {
		if e.Row != IssueInsecureDeserialization {
			continue
		}
		path, _, _ := strings.Cut(e.Path, "?")
		w, ok := want[path]
		if !ok {
			t.Errorf("fixture %s has no expectation here", e.Path)
			continue
		}
		seen++
		f := deserFinding(deserAudit(t, host, port, e.Path, e.RequestHeaders))
		if e.Safe {
			if f != nil {
				t.Errorf("safe twin %s reported: %s", e.Path, f.Evidence)
			}
			continue
		}
		if f == nil {
			t.Errorf("%s not reported", e.Path)
			continue
		}
		if !strings.HasPrefix(f.Evidence, w.family) || f.Severity != w.severity || f.Confidence != w.confidence {
			t.Errorf("%s: got %s/%s %q, want %s/%s from %q", e.Path, f.Severity, f.Confidence, f.Evidence,
				w.severity, w.confidence, w.family)
		}
		t.Logf("%s: %s", e.Path, f.Evidence)
	}
	if seen != len(want) {
		t.Fatalf("exercised %d fixtures, want %d", seen, len(want))
	}
}

// A response that alternates by itself must not line up with the pairs. The probes go accepted,
// rejected, rejected, accepted, so an A/B/A/B target answers the two accepted probes differently and
// the repeat refuses it. Negative control: dropping the repeat comparison makes this fire.
func TestDeserializationAlternatingTargetIsNotAFinding(t *testing.T) {
	var n atomic.Int64
	host, port := deserServe(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1)%2 == 0 {
			_, _ = w.Write([]byte("blue page"))
			return
		}
		_, _ = w.Write([]byte("green page"))
	}))
	if f := deserFinding(deserAudit(t, host, port, "/state", map[string]string{"Cookie": "state=opaque"})); f != nil {
		t.Fatalf("an alternating target was reported: %s", f.Evidence)
	}
}

// A filter that blocks a keyword (here, any decoded value naming a java.util class) answers 403 to
// one side of the type-id pair and passes the other, which is a differential the application's
// deserializer had no part in. Negative control: without the filtered-status rule this fires.
func TestDeserializationFilteredAnswerIsNotAFinding(t *testing.T) {
	host, port := deserServe(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, _ := r.Cookie("state")
		if c != nil {
			if b, err := base64.StdEncoding.DecodeString(c.Value); err == nil && strings.Contains(string(b), "java.util") {
				http.Error(w, "blocked by policy", http.StatusForbidden)
				return
			}
		}
		_, _ = w.Write([]byte("welcome"))
	}))
	if f := deserFinding(deserAudit(t, host, port, "/state", map[string]string{"Cookie": "state=opaque"})); f != nil {
		t.Fatalf("a keyword filter was reported as deserialization: %s", f.Evidence)
	}
}

// A value echoed back is not parsed. The target repeats the decoded cookie inside an otherwise fixed
// page, so the two sides of every pair differ only in what was sent.
func TestDeserializationEchoIsNotAFinding(t *testing.T) {
	host, port := deserServe(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, _ := r.Cookie("state")
		v := ""
		if c != nil {
			v = c.Value
			if b, err := base64.StdEncoding.DecodeString(v); err == nil {
				v = string(b)
			}
		}
		_, _ = w.Write([]byte("<p>you sent " + v + "</p>"))
	}))
	if f := deserFinding(deserAudit(t, host, port, "/state", map[string]string{"Cookie": "state=opaque"})); f != nil {
		t.Fatalf("an echo was reported as deserialization: %s", f.Evidence)
	}
}

// Probe selection: a recognised value is probed in its own format only; base64 JSON gets the
// unsigned-state probe in a cookie and not in a query parameter; an opaque query parameter and a
// session-id cookie are not probed at all.
func TestDeserializationPlans(t *testing.T) {
	java := base64.StdEncoding.EncodeToString(deserJavaStream("a.B", 0x73))
	raw := "GET /p?q=hello&j=" + java + "&b=e30%3D&t=%7B%22%40type%22%3A%22a.b.C%22%7D HTTP/1.1\r\nHost: x\r\n" +
		"Cookie: JSESSIONID=abc; prefs=e30=; opaque=zzz\r\n\r\n"
	points, _ := bcheck.EnumerateWith([]byte(raw), deserKinds, bcheck.EnumerateOptions{})
	got := map[string][]string{}
	for _, c := range deserCandidates(points) {
		for _, p := range c.plans {
			got[c.point.Name] = append(got[c.point.Name], p.fam.name+"/"+p.enc.String())
		}
	}
	want := map[string]string{
		"j":      "Java object stream/base64",
		"b":      "Jackson polymorphic JSON (@class)/base64",
		"t":      "fastjson polymorphic JSON (@type)/text",
		"prefs":  "Jackson polymorphic JSON (@class)/base64,unsigned JSON state/base64",
		"opaque": "Java object stream/base64,PHP serialize()/base64,PHP serialize()/text,Python pickle/base64,Jackson polymorphic JSON (@class)/base64,unsigned JSON state/base64",
	}
	for name, w := range want {
		if g := strings.Join(got[name], ","); g != w {
			t.Errorf("%s: got %q, want %q", name, g, w)
		}
	}
	for _, name := range []string{"q", "JSESSIONID"} {
		if len(got[name]) > 0 {
			t.Errorf("%s should not be probed, got %v", name, got[name])
		}
	}
}

// ---------------------------------------------------------------------------
// passive recognition
// ---------------------------------------------------------------------------

func TestDetectSerializedObjectNewFormats(t *testing.T) {
	cases := map[string]SerializedObjectKind{
		"state=aced00057372000a":                                                    SerializedJava,
		"STATE=ACED00057372000A":                                                    SerializedJava,
		"\x04\x08{\x06:\x06aT":                                                      SerializedRuby,
		"BAh7BkkiCGZvbwY6BkVUSSIIYmFyBjsAVA==":                                      SerializedRuby, // whole value base64
		`{"session":"BAh7BkkiCGZvbwY6BkVUSSIIYmFyBjsAVA=="}`:                        SerializedRuby, // embedded run
		"user: !!python/object:__main__.User {name: a}":                             SerializedYAML,
		"- !ruby/object:Gem::Requirement\n  requirements: []":                       SerializedYAML,
		"x: !!javax.script.ScriptEngineManager [a]":                                 SerializedYAML,
		`{"@class":"com.example.Visit","section":"home"}`:                           SerializedJSONTyped,
		`{"@type":"com.alibaba.Foo"}`:                                               SerializedJSONTyped,
		`{"$type":"System.Windows.Data.ObjectDataProvider, PresentationFramework"}`: SerializedJSONTyped,
		"data=" + base64.StdEncoding.EncodeToString([]byte(`{"@class":"a.b.C"}`)):   SerializedJSONTyped,
		"x=1&s=" + base64.StdEncoding.EncodeToString([]byte(`a:1:{s:1:"a";i:1;}`)):  SerializedPHP,
	}
	for in, want := range cases {
		if got := DetectSerializedObject([]byte(in)); got != want {
			t.Errorf("%q: got %v, want %v", in, got, want)
		}
	}
}

// Each recogniser's false-positive guard. Negative controls: removing the class-name check fires on
// JSON-LD and MongoDB, removing the YAML position rule fires on prose, and searching embedded base64
// runs anywhere instead of at their start fires on the binary run, and matching Ruby's two-byte
// header anywhere fires on the GIF.
func TestDetectSerializedObjectNewFormatsNegatives(t *testing.T) {
	// A base64 run whose decoded bytes hold a Java magic and pickle header mid-buffer.
	binary := append([]byte("\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"), 0xAC, 0xED, 0x00, 0x05, 0x80, 0x02, 'K', 0x01)
	cases := []string{
		`{"@context":"https://schema.org","@type":"Person","name":"Ada"}`,
		`{"@type":"type.googleapis.com/google.rpc.ErrorInfo"}`,
		`{"bin":{"$binary":"AAEC","$type":"00"}}`,
		`<p>Never load untrusted YAML: a !!python/object tag runs code.</p>`,
		"img=" + base64.StdEncoding.EncodeToString(binary),
		"run " + base64.StdEncoding.EncodeToString(append([]byte("zzzz"), 0x04, 0x08, '{')),
		"GIF89a\x01\x00\x04\x08{\x00\x00",
	}
	for _, in := range cases {
		if got := DetectSerializedObject([]byte(in)); got != SerializedNone {
			t.Errorf("%q: got %v, want none", in, got)
		}
	}
}

// The passive row now reads request cookies and query parameters, not only bodies.
func TestSerializedObjectInRequestCookieAndQuery(t *testing.T) {
	for _, req := range []string{
		"GET / HTTP/1.1\r\nHost: app.test\r\nCookie: a=1; state=rO0ABXNyAAFh\r\n\r\n",
		"GET /?cart=O%3A4%3A%22Cart%22%3A0%3A%7B%7D HTTP/1.1\r\nHost: app.test\r\n\r\n",
	} {
		cc := postureFixture(t, req, htmlResponse("ok"), true)
		got := runPosture(t, checkSerializedObjectInMessage, cc)
		if len(got) != 1 {
			t.Fatalf("%q: got %d findings, want 1", req, len(got))
		}
		if !strings.Contains(got[0].Evidence, "request") {
			t.Errorf("evidence does not name where: %q", got[0].Evidence)
		}
	}
}
