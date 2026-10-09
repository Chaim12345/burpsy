package web

// The Collaborator health check (burpsy-react-ui-8e3n): Burp's "Run health check", which "verifies whether
// it is possible to interact with the server using various network services, and whether it can
// retrieve the details of these interactions via polling" (desktop/settings/project/collaborator.html).
//
// # What it does, in Burp's own item order (burp/Zcnu, 2026.7.1)
//
// Burp checks, in this order: server address resolution, server HTTP connection, HTTPS with trust
// enforced and with trust not enforced, SMTP on port 25 and on port 587, SMTPS with trust enforced and
// with trust not enforced, and then a poll for the interactions those connections should have caused.
// This handler runs the same eight connection items against a freshly minted health-check address on
// the registered domain. It then waits for the DNS, HTTP and SMTP interactions to come back through the
// interactsh-client log, the same path every out-of-band check reads.
//
// # Why the capture rows are the verdict
//
// A connection item says this machine reached the interaction server, which is necessary but is not
// what an out-of-band check depends on. A check depends on the interaction coming back through polling.
// A server that accepts the connection but never reports it, or a client that is not polling, would
// pass every connection item and still turn every out-of-band check into a silent false negative. So
// the overall status is decided by the capture rows, and the connection rows explain them. A protocol
// whose every trigger failed is "not_triggered", not "not captured". Nothing was sent that could have
// come back, and the operator needs the remedy for this machine's egress, not for the server.
//
// # The channel and the cost
//
// Like minting, this may register the channel, because it is an explicit operator action. It does not
// open a second channel: the address is minted on the scanner's own registered domain, so the check
// tests the channel the scanner's checks use.

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/smtp"
	"strings"
	"sync"
	"time"

	"github.com/burpsy-go/burpsy/internal/oob"
)

const (
	healthOK           = "ok"
	healthError        = "error"
	healthNotTriggered = "not_triggered"

	// collaboratorProbeTimeout bounds each connection item. All eight run concurrently.
	collaboratorProbeTimeout = 8 * time.Second
	// collaboratorCaptureWait bounds how long the check waits for the interactions to come back. The
	// interactsh client polls on its own schedule (a few seconds by default), so a too-short wait would
	// report a healthy server as broken.
	collaboratorCaptureWait = 25 * time.Second
)

// collaboratorProbes are the network actions the health check takes. A field rather than direct calls,
// so the route's whole decision logic can be tested with no network.
type collaboratorProbes struct {
	resolve func(ctx context.Context, host string) error
	httpGet func(ctx context.Context, url string, verifyTLS bool) error
	// smtp delivers a message to <marker>@host on port. implicitTLS selects SMTPS.
	smtp func(ctx context.Context, host string, port int, implicitTLS, verifyTLS bool, marker string) error
}

func defaultCollaboratorProbes() collaboratorProbes {
	return collaboratorProbes{
		resolve: func(ctx context.Context, host string) error {
			_, err := net.DefaultResolver.LookupHost(ctx, host)
			return err
		},
		httpGet: func(ctx context.Context, url string, verifyTLS bool) error {
			client := &http.Client{
				Transport: &http.Transport{
					Proxy: nil, // straight to the server: a configured proxy is not what a target uses
					// The "trust not enforced" item exists precisely to separate a TLS-trust failure
					// from a connection failure, so the skip is the item's whole purpose.
					TLSClientConfig: &tls.Config{InsecureSkipVerify: !verifyTLS}, //nolint:gosec
				},
				// Any response proves the connection. A redirect is not followed, because following it
				// would test some other host.
				CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
			}
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			if err != nil {
				return err
			}
			resp, err := client.Do(req)
			if err != nil {
				return err
			}
			return resp.Body.Close()
		},
		smtp: smtpDeliver,
	}
}

// smtpDeliver runs Burp's SMTP conversation (Zcnu: HELO, MAIL FROM, RCPT TO <marker@host>, DATA carrying
// the marker, QUIT). The recipient carries the marker so the interaction can be attributed.
func smtpDeliver(ctx context.Context, host string, port int, implicitTLS, verifyTLS bool, marker string) error {
	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, fmt.Sprint(port)))
	if err != nil {
		return err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if implicitTLS {
		tlsConn := tls.Client(conn, &tls.Config{ServerName: host, InsecureSkipVerify: !verifyTLS}) //nolint:gosec
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			conn.Close()
			return err
		}
		conn = tlsConn
	}
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		conn.Close()
		return err
	}
	defer c.Close()
	if err := c.Hello("client.test.com"); err != nil {
		return err
	}
	if err := c.Mail("user@client.domain.net"); err != nil {
		return err
	}
	if err := c.Rcpt(marker + "@" + host); err != nil {
		return err
	}
	wc, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(wc, "Subject: %s\r\n\r\n%s\r\n", marker, marker); err != nil {
		return err
	}
	if err := wc.Close(); err != nil {
		return err
	}
	return c.Quit()
}

// collaboratorHealthItem is one row of the check, under Burp's own label.
type collaboratorHealthItem struct {
	Name string `json:"name"`
	// Protocol is the interaction this item should cause: "dns", "http" or "smtp".
	Protocol string `json:"protocol"`
	// Status is "ok" or "error" for a connection item. A capture item can also be "not_triggered".
	Status string `json:"status"`
	Detail string `json:"detail"`
	// LatencyMS is how long the item took. It is null when the item did not complete.
	LatencyMS *int64 `json:"latency_ms"`
}

// collaboratorHealthReport is the outcome of one health check.
type collaboratorHealthReport struct {
	// Status is "healthy" (every protocol came back through polling), "degraded" (some did), or
	// "failed" (none did).
	Status  string `json:"status"`
	Summary string `json:"summary"`
	Server  string `json:"server,omitempty"`
	// Domain is the registered payload domain, and Address is the health-check address minted on it.
	Domain  string `json:"domain"`
	Address string `json:"address"`
	// Connections are Burp's eight connection items, in Burp's order.
	Connections []collaboratorHealthItem `json:"connections"`
	// Captures says, per protocol, whether the interaction came back through polling. They decide Status.
	Captures []collaboratorHealthItem `json:"captures"`
	// WaitedMS is how long the check waited for captures. Polling says what that wait observed.
	WaitedMS int64  `json:"waited_ms"`
	Polling  string `json:"polling"`
}

type healthProbe struct {
	name, protocol string
	run            func(ctx context.Context) error
}

// handleCollaboratorHealth serves POST /api/collaborator/health.
func (s *Server) handleCollaboratorHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	reg, configured := s.wiredScanner().OOBRegistration()
	if !configured {
		status := s.collaboratorStatusNow(false)
		writeJSON(w, http.StatusConflict, map[string]any{
			"error":  "no out-of-band interaction channel is configured, so there is no server to check",
			"hint":   status.Hint,
			"status": status,
		})
		return
	}
	channel, err := s.wiredScanner().OOBChannel(r.Context())
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"error":  err.Error(),
			"hint":   "the interaction server is configured but no channel could be opened, so nothing could be checked",
			"status": s.collaboratorStatusNow(false),
		})
		return
	}
	marker, err := collaboratorMarker()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	hub := s.collab()
	hub.mu.Lock()
	probes, wait := hub.healthProbes, hub.healthWait
	hub.mu.Unlock()
	if probes == nil {
		d := defaultCollaboratorProbes()
		probes = &d
	}
	if wait <= 0 {
		wait = collaboratorCaptureWait
	}
	report := runCollaboratorHealth(r.Context(), channel, *probes, marker, wait)
	report.Server = reg.Server
	writeJSON(w, http.StatusOK, report)
}

// collaboratorHealthChannel is what the check reads interactions from.
type collaboratorHealthChannel interface {
	Domain() string
	InteractionsFor(marker string) ([]oob.Interaction, error)
}

func runCollaboratorHealth(ctx context.Context, channel collaboratorHealthChannel, probes collaboratorProbes, marker string, wait time.Duration) collaboratorHealthReport {
	domain := channel.Domain()
	host := marker + "." + domain
	list := []healthProbe{
		{"Server address resolution", "dns", func(ctx context.Context) error { return probes.resolve(ctx, host) }},
		{"Server HTTP connection", "http", func(ctx context.Context) error { return probes.httpGet(ctx, "http://"+host+"/", true) }},
		{"Server HTTPS connection (trust enforced)", "http", func(ctx context.Context) error { return probes.httpGet(ctx, "https://"+host+"/", true) }},
		{"Server HTTPS connection (trust not enforced)", "http", func(ctx context.Context) error { return probes.httpGet(ctx, "https://"+host+"/", false) }},
		{"Server SMTP connection on port 25", "smtp", func(ctx context.Context) error { return probes.smtp(ctx, host, 25, false, false, marker) }},
		{"Server SMTP connection on port 587", "smtp", func(ctx context.Context) error { return probes.smtp(ctx, host, 587, false, false, marker) }},
		{"Server SMTPS connection (trust enforced)", "smtp", func(ctx context.Context) error { return probes.smtp(ctx, host, 465, true, true, marker) }},
		{"Server SMTPS connection (trust not enforced)", "smtp", func(ctx context.Context) error { return probes.smtp(ctx, host, 465, true, false, marker) }},
	}
	connections := make([]collaboratorHealthItem, len(list))
	var wg sync.WaitGroup
	for i, p := range list {
		wg.Add(1)
		go func(i int, p healthProbe) {
			defer wg.Done()
			pctx, cancel := context.WithTimeout(ctx, collaboratorProbeTimeout)
			defer cancel()
			start := time.Now()
			err := p.run(pctx)
			item := collaboratorHealthItem{Name: p.name, Protocol: p.protocol}
			if err != nil {
				item.Status = healthError
				item.Detail = err.Error()
				if errors.Is(err, context.DeadlineExceeded) {
					item.Detail = fmt.Sprintf("no answer within %s", collaboratorProbeTimeout)
				}
			} else {
				ms := time.Since(start).Milliseconds()
				item.Status, item.LatencyMS = healthOK, &ms
				item.Detail = "connected"
			}
			connections[i] = item
		}(i, p)
	}
	wg.Wait()

	// Which protocols had at least one trigger that went out: only those can come back.
	triggered := map[string]bool{}
	for _, c := range connections {
		if c.Status == healthOK {
			triggered[c.Protocol] = true
		}
	}
	protocols := []string{"dns", "http", "smtp"}
	captured := map[string]time.Duration{}
	start := time.Now()
	var readErr error
	for {
		all, err := channel.InteractionsFor("")
		readErr = err
		for _, in := range all {
			// Case-insensitive, for the reason attributeTo gives: DNS-0x20 randomises the case of the
			// queried name in a DNS raw request.
			if !strings.Contains(strings.ToLower(in.RawRequest+" "+in.FullID), marker) {
				continue
			}
			p := strings.ToLower(in.Protocol)
			if _, seen := captured[p]; !seen {
				captured[p] = time.Since(start)
			}
		}
		done := true
		for _, p := range protocols {
			if _, ok := captured[p]; triggered[p] && !ok {
				done = false
			}
		}
		if done || time.Since(start) >= wait || ctx.Err() != nil {
			break
		}
		pause := 500 * time.Millisecond
		if q := wait/4 + time.Millisecond; q < pause {
			pause = q
		}
		select {
		case <-ctx.Done():
		case <-time.After(pause):
		}
	}
	waited := time.Since(start)

	labels := map[string]string{"dns": "DNS interaction captured", "http": "HTTP interaction captured", "smtp": "SMTP interaction captured"}
	captures := make([]collaboratorHealthItem, 0, len(protocols))
	got := 0
	for _, p := range protocols {
		item := collaboratorHealthItem{Name: labels[p], Protocol: p}
		if d, ok := captured[p]; ok {
			ms := d.Milliseconds()
			item.Status, item.LatencyMS = healthOK, &ms
			item.Detail = "the interaction came back through polling"
			got++
		} else if !triggered[p] {
			item.Status = healthNotTriggered
			item.Detail = fmt.Sprintf("every %s connection item failed, so nothing was sent that could come back; "+
				"an out-of-band %s interaction cannot be confirmed from this machine", strings.ToUpper(p), strings.ToUpper(p))
		} else {
			item.Status = healthError
			item.Detail = fmt.Sprintf("the %s trigger reached the server but no interaction came back within %s",
				strings.ToUpper(p), wait.Round(time.Second))
			if readErr != nil {
				item.Detail += ": reading the interaction log failed: " + readErr.Error()
			}
		}
		captures = append(captures, item)
	}

	report := collaboratorHealthReport{
		Domain:      domain,
		Address:     host,
		Connections: connections,
		Captures:    captures,
		WaitedMS:    waited.Milliseconds(),
		Polling:     pollingContract,
	}
	switch got {
	case len(protocols):
		report.Status = "healthy"
		report.Summary = "every protocol's interaction came back through polling, so out-of-band checks can be trusted"
	case 0:
		report.Status = "failed"
		report.Summary = "no interaction came back through polling, so an out-of-band check's negative result means nothing"
	default:
		report.Status = "degraded"
		missing := []string{}
		for _, c := range captures {
			if c.Status != healthOK {
				missing = append(missing, strings.ToUpper(c.Protocol))
			}
		}
		report.Summary = fmt.Sprintf("%s interactions did not come back, so a negative result from a check that relies on them means nothing",
			strings.Join(missing, " and "))
	}
	return report
}
