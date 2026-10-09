package web

// burpsy-react-ui-saq3.3.2: the live sweep's passive pass honours the run configuration's per-issue
// selection, through the sweep's own entry point.
//
// The configuration is imported the way -scan-config imports one (scanner.ApplyBurpConfigFile over a
// Burp-shaped file) and installed as the server's audit default the way cmd/burpsy installs it
// (WithAuditConfig). The sweep is then started and switched on through POST /api/scanner/live, and the
// captured exchange carries both a cleartext password form and a cookie with no HttpOnly flag: the
// first type is deselected, the second is the control that proves the passive pass still ran.

import (
	"context"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/scanner"
)

// deselectCleartextPassword is a selected_issues override in Burp's own shape: select_individual_issues
// without scan_only_selected_issues, so the list is per-issue overrides and enabled:false removes one
// type (Zwnn.java:13-25). 0x00300100 is "Cleartext submission of password".
const deselectCleartextPassword = `{
  "scanner": {
    "issues_reported": {
      "select_individual_issues": true,
      "selected_issues": [
        {"type_index": "0x00300100", "enabled": false, "detection_methods": []}
      ]
    }
  }
}`

func TestTheSweepPassivePassDoesNotRaiseAnIssueTypeTheRunConfigurationDeselected(t *testing.T) {
	srv, _ := passiveFormOrigin(t)
	host, port := targetHostPort(t, srv.URL)
	s := auditableServer(t, srv.URL)

	cfg, unapplied, err := scanner.ApplyBurpConfigFile(scanner.DefaultAuditConfig(), []byte(deselectCleartextPassword))
	if err != nil {
		t.Fatalf("import the selection: %v", err)
	}
	if len(unapplied) != 0 {
		t.Fatalf("the selection imported with unapplied keys %v — the test would not be testing the selection", unapplied)
	}
	if len(cfg.DisabledIssueTypes) != 1 || cfg.DisabledIssueTypes[0] != 0x00300100 {
		t.Fatalf("the import did not deny the cleartext-password type: disabled = %#v", cfg.DisabledIssueTypes)
	}
	s.scanner.WithAuditConfig(cfg)

	// A completed in-scope proxied capture whose response carries BOTH passive issues.
	reqID, _ := s.store.Put([]byte("GET /login HTTP/1.1\r\nHost: "+host+"\r\n\r\n"), core.DirectionRequest)
	respID, _ := s.store.Put([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nSet-Cookie: sid=abc; Path=/\r\n\r\n"+
		"<form action=\"http://"+host+"/login\" method=\"POST\"><input type=\"password\" name=\"password\"></form>"), core.DirectionResponse)
	s.store.AddExchange(&core.Exchange{
		Request: core.MsgPtr(reqID), Response: &respID, Host: host, Port: port, Method: "GET", Path: "/login",
		Source: core.SourceProxy,
	})
	before := s.liveAudit.Swept()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.startLiveAuditSweep(ctx, sweepTick)
	postJSON(t, s, "/api/scanner/live", map[string]bool{"enabled": true})

	// Swept moves only after both halves of the tick finished, so once it has advanced past the
	// seeded exchanges the passive loop over the new one is complete.
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) && s.liveAudit.Swept() < before+3 {
		time.Sleep(sweepTick)
	}
	if got := s.liveAudit.Swept(); got < before+3 {
		t.Fatalf("the sweep swept %d exchanges, not the three seeded — nothing below would be evidence", got-before)
	}

	var cleartext, cookie bool
	for _, f := range s.findings.All() {
		switch f.Name {
		case "Cleartext submission of password":
			cleartext = true
		case "Cookie without HttpOnly flag set":
			cookie = true
		}
	}
	if !cookie || s.liveAudit.PassiveFindings() == 0 {
		t.Fatalf("control: the passive pass raised no cookie finding (passive count %d) — the deselection test proves nothing",
			s.liveAudit.PassiveFindings())
	}
	if cleartext {
		t.Fatal("the sweep raised \"Cleartext submission of password\", which the run configuration deselected: " +
			"the passive pass ignores the selection the audit dispatch honours")
	}
}
