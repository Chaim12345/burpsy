// End-to-end tests for the collaborator seam: a check that generates an
// interaction address, sends it to a live target, and verdicts on the
// interaction the target's behaviour attracts. These prove the whole path —
// builtin resolution, address tracking, the settle window and the condition
// evaluation — against a real HTTP server, not mocks.
package bcheck

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/collaborator"
)

// liveSink performs real sends against the target's authority, rendering the
// response back into raw HTTP bytes for the evaluator's messageFields. Without
// it the check's send would be a no-op and no interaction could ever fire.
type liveSink struct{}

func (liveSink) Send(target *Target, raw []byte) ([]byte, error) {
	addr := net.JoinHostPort(target.Host, strconv.Itoa(int(target.Port)))
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if _, err := conn.Write(raw); err != nil {
		return nil, err
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "%s %s\r\n", resp.Proto, resp.Status)
	for k, vs := range resp.Header {
		for _, v := range vs {
			fmt.Fprintf(&sb, "%s: %s\r\n", k, v)
		}
	}
	sb.WriteString("\r\n")
	sb.Write(body)
	return []byte(sb.String()), nil
}

// startCollab binds a full three-protocol interaction server for the test.
func startCollab(t *testing.T) *collaborator.Server {
	t.Helper()
	srv, err := collaborator.New(collaborator.Config{Base: "burpsy.test", HTTP: "127.0.0.1:0", DNS: "127.0.0.1:0", SMTP: "127.0.0.1:0"})
	if err != nil {
		t.Fatalf("collaborator.New: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	return srv
}

// collabTarget sets up an httptest server whose handler is `hit` and returns
// the host and port an active run should target.
func collabTarget(t *testing.T, hit func(r *http.Request)) (string, uint16, *httptest.Server) {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit(r)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(ts.Close)
	u, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatal(err)
	}
	return u.Hostname(), uint16(port), ts
}

// fetchTriggeredURL fetches every `http(s)://…` query value through the
// interaction server's HTTP listener, preserving the issued address as the
// Host header — what an app that fetches a user-supplied URL does once its
// resolver points at the recorder.
func fetchTriggeredURL(srv *collaborator.Server, r *http.Request) {
	for _, v := range r.URL.Query() {
		for _, u := range v {
			if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
				continue
			}
			parsed, err := url.Parse(u)
			if err != nil {
				continue
			}
			req, err := http.NewRequest(http.MethodGet, "http://"+srv.HTTPAddr()+parsed.Path, nil)
			if err != nil {
				continue
			}
			req.Host = parsed.Host
			resp, err := http.DefaultClient.Do(req)
			if err == nil {
				resp.Body.Close()
			}
		}
	}
}

// blindSSRFCheck is the corpus's Blind-SSRF-By-Collaborator shape: two
// addresses defined up front, both sent as query values, verdict on http
// interactions — the whole point is that both addresses poll together.
const blindSSRFCheck = `define:
    url_ssrf = ` + "`https://{generate_collaborator_address()}/url`" + `
    proxy_ssrf = ` + "`http://{generate_collaborator_address()}/proxy`" + `
given request then
  send request:
    appending queries:
      ` + "`proxy={proxy_ssrf}`" + `,
      ` + "`url={url_ssrf}`" + `
  if http interactions then
    report issue:
      severity: high
      confidence: certain
  end if`

func runActiveAt(t *testing.T, src string, srv *collaborator.Server, host string, port uint16) ([]Finding, error) {
	t.Helper()
	c := parseCheck(src)
	ctx := NewContext()
	ctx.Request = []byte("GET /go HTTP/1.1\r\nHost: " + host + "\r\n\r\n")
	ctx.Response = []byte(ok200("ok"))
	ctx.Host = host
	ctx.Port = port
	ctx.Path = "/go"
	if srv != nil {
		ctx.SetCollaborator(srv)
	}
	return RunActive(c, ctx, liveSink{}, &Target{Host: host, Port: port, TLS: false})
}

// A generated address embeds a token, and an address generated twice is never
// the same — a check that sends two probes must see two distinct addresses.
func TestCollaboratorAddressesAreUniqueWithinACheckRun(t *testing.T) {
	srv := startCollab(t)
	c := parseCheck(`given request then
  send request:
    appending queries:
      ` + "`a={generate_collaborator_address()}`" + `,
      ` + "`b={generate_collaborator_address()}`" + `
  end if`)
	ctx := activeCtx()
	ctx.SetCollaborator(srv)
	m := &mockSink{}
	f, err := RunActive(c, ctx, m, tgt())
	if err != nil {
		t.Fatal(err)
	}
	if len(f) != 0 {
		t.Fatalf("expected no findings, got %d", len(f))
	}
	addrs := regexp.MustCompile(`[0-9a-f]{12}\.burpsy\.test`).FindAllString(m.first(), -1)
	if len(addrs) != 2 {
		t.Fatalf("expected two addresses in the sent request, got %d: %q", len(addrs), m.first())
	}
	if addrs[0] == addrs[1] {
		t.Fatalf("two addresses in one check run were identical: %q", addrs[0])
	}
}

func TestActiveBlindSSRFCheckReportsTheHTTPInteraction(t *testing.T) {
	srv := startCollab(t)
	host, port, _ := collabTarget(t, func(r *http.Request) {
		fetchTriggeredURL(srv, r)
	})
	findings, err := runActiveAt(t, blindSSRFCheck, srv, host, port)
	if err != nil {
		t.Fatalf("RunActive: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if !strings.EqualFold(string(findings[0].Severity), "high") || !strings.EqualFold(string(findings[0].Confidence), "certain") {
		t.Fatalf("finding %+v lost its severity/confidence", findings[0])
	}
}

// The DNS leg: the vulnerable app resolves the injected hostname. With the
// resolver pointed at the recorder, that lookup lands on its DNS listener —
// here simulated by the handler querying the listener directly, exactly what
// the A-record answer would make a real resolver do.
func TestActiveCollaboratorCheckReportsTheDNSInteraction(t *testing.T) {
	srv := startCollab(t)
	host, port, _ := collabTarget(t, func(r *http.Request) {
		for _, v := range r.URL.Query() {
			for _, u := range v {
				if !strings.HasPrefix(u, "rmi://") {
					continue
				}
				parsed, err := url.Parse(u)
				if err != nil {
					continue
				}
				conn, err := net.Dial("udp", srv.DNSAddr())
				if err != nil {
					continue
				}
				_, _ = conn.Write(dnsQueryPkt(0x4242, parsed.Host, 1))
				conn.Close()
			}
		}
	})

	check := `given request then
  send request:
    appending queries: ` + "`ds=rmi://{generate_collaborator_address()}/x`\n" + `
  if dns interactions then
    report issue:
      severity: high
      confidence: certain
  end if`
	findings, err := runActiveAt(t, check, srv, host, port)
	if err != nil {
		t.Fatalf("RunActive: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
}

// Async-style: the target answers the probe first and forwards the injected
// value afterwards (a proxy honouring X-Forwarded-For, a mail relay after the
// probe response was read). The settle window must catch the late interaction.
func TestActiveCollaboratorCheckWaitsForAnAsynchronousInteraction(t *testing.T) {
	srv := startCollab(t)
	host, port, _ := collabTarget(t, func(r *http.Request) {
		u := r.Header.Get("X-Forwarded-For")
		if u == "" {
			return
		}
		parsed, err := url.Parse("http://" + u)
		if err != nil {
			return
		}
		target := parsed.Host
		httpAddr := srv.HTTPAddr()
		path := parsed.Path
		time.AfterFunc(150*time.Millisecond, func() {
			req, err := http.NewRequest(http.MethodGet, "http://"+httpAddr+path, nil)
			if err != nil {
				return
			}
			req.Host = target
			resp, err := http.DefaultClient.Do(req)
			if err == nil {
				resp.Body.Close()
			}
		})
	})

	check := `given request then
  send request:
    appending headers:
      x-forwarded-for: ` + "`{generate_collaborator_address()}`\n" + `
  if any interactions then
    report issue:
      severity: info
      confidence: firm
  end if`
	findings, err := runActiveAt(t, check, srv, host, port)
	if err != nil {
		t.Fatalf("RunActive: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for the late interaction, got %d", len(findings))
	}
}

func TestActiveCollaboratorCheckIsRefusedWithoutASeam(t *testing.T) {
	m := &mockSink{}
	_, err := runActive(t, blindSSRFCheck, m)
	var ae *ActiveError
	if !errors.As(err, &ae) || ae.Kind != ActiveUnsupported {
		t.Fatalf("expected ActiveUnsupported without a seam, got %v", err)
	}
	if m.count() != 0 {
		t.Fatalf("no probe may leave when a collaborator check cannot run: %d sent", m.count())
	}
}

// The classifier must agree with the parser: a check polling `<type>
// interactions` is NeedsCollaborator, never a runnable active check. It used to
// test for a different parse shape and answered false, dispatching blind checks
// that sent empty-address probes instead of refusing them.
func TestInteractionsChecksAreClassifiedAsNeedingCollaborator(t *testing.T) {
	c := parseCheck(`given request then
  send request:
    appending queries: ` + "`u={generate_collaborator_address()}`\n" + `
  if dns interactions then
    report issue:
      severity: high
      confidence: certain
  end if`)
	if !c.NeedsCollaborator() {
		t.Fatal("a check polling `<type> interactions` must be NeedsCollaborator")
	}
	if c.M2Runnable() {
		t.Fatal("a collaborator check must not be in the M2 dispatch set")
	}
	plain := parseCheck(`given request then
  send request:
    appending queries: "u=1"
  end if`)
	if plain.NeedsCollaborator() {
		t.Fatal("a check without `<type> interactions` must not be NeedsCollaborator")
	}
	if !plain.M2Runnable() {
		t.Fatal("a plain request check must be M2 runnable")
	}
}

func TestActiveCollaboratorCheckReportsNoFindingWithoutAnInteraction(t *testing.T) {
	srv := startCollab(t)
	// A target that ignores the injected value entirely: the check sends, the
	// address attracts nothing, and the honest result is no finding — never a
	// false positive from the addresses existing.
	host, port, _ := collabTarget(t, func(r *http.Request) {})
	findings, err := runActiveAt(t, blindSSRFCheck, srv, host, port)
	if err != nil {
		t.Fatalf("RunActive: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings for an unresponsive target, got %d", len(findings))
	}
}

// dnsQueryPkt builds a single-question DNS query — the bytes a resolver would
// emit for the injected hostname.
func dnsQueryPkt(id uint16, name string, qtype uint16) []byte {
	out := []byte{byte(id >> 8), byte(id), 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	for _, label := range strings.Split(name, ".") {
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	out = append(out, 0)
	out = append(out, byte(qtype>>8), byte(qtype))
	out = append(out, 0, 1) // IN
	return out
}
