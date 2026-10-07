package web

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/scanner"
	"github.com/burpsy-go/burpsy/internal/sender"
	"github.com/burpsy-go/burpsy/internal/vulnapp"
	"go.uber.org/zap"
)

// burpsy-react-ui-saq3.1 / 2hze, end to end: Burp's own "Audit checks - all except time-based
// detection methods.json" is imported through the path -scan-config uses (scanner.ApplyBurpConfigFile,
// which cmd/burpsy/main.go calls), installed as the server's audit default the way main.go installs
// it (WithAuditConfig), and audits are run through the console's own route, POST /api/audit/{id},
// against vulnapp. There is no console route that imports a Burp file; -scan-config is the import path.

const timeBasedPreset = "../scanner/testdata/burp-configs/Audit checks - all except time-based detection methods.json"

// recordingTarget serves vulnapp and keeps every request URI it received.
type recordingTarget struct {
	mu   sync.Mutex
	uris []string
	srv  *httptest.Server
}

func startRecordingTarget(t *testing.T) *recordingTarget {
	t.Helper()
	rt := &recordingTarget{}
	inner := vulnapp.Handler()
	rt.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rt.mu.Lock()
		rt.uris = append(rt.uris, r.URL.RawQuery)
		rt.mu.Unlock()
		inner.ServeHTTP(w, r)
	}))
	t.Cleanup(rt.srv.Close)
	return rt
}

func (rt *recordingTarget) received() []string {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return append([]string(nil), rt.uris...)
}

// seedVulnapp captures each path once, the way the proxy would, and returns the exchange ids.
func seedVulnapp(t *testing.T, rt *recordingTarget, store *core.TrafficStore, paths ...string) []core.ExchangeID {
	t.Helper()
	host, portStr, _ := strings.Cut(strings.TrimPrefix(rt.srv.URL, "http://"), ":")
	port, _ := strconv.ParseUint(portStr, 10, 16)
	var ids []core.ExchangeID
	for _, path := range paths {
		res, err := rt.srv.Client().Get(rt.srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
		_ = res.Body.Close()
		reqID, _ := store.Put([]byte("GET "+path+" HTTP/1.1\r\nHost: "+host+"\r\n\r\n"), core.DirectionRequest)
		respID, _ := store.Put([]byte("HTTP/1.1 200 OK\r\nContent-Type: "+res.Header.Get("Content-Type")+
			"\r\nContent-Length: "+strconv.Itoa(len(body))+"\r\n\r\n"+string(body)), core.DirectionResponse)
		ex := &core.Exchange{Request: core.MsgPtr(reqID), Response: &respID, Host: host, Port: uint16(port),
			Method: "GET", Path: path}
		store.AddExchange(ex)
		ids = append(ids, ex.ID)
	}
	return ids
}

type auditReply struct {
	ActiveChecks int `json:"active_checks"`
	Outcome      struct {
		Ran             int                     `json:"ran"`
		Skipped         int                     `json:"skipped"`
		SendFailures    int                     `json:"send_failures"`
		MethodsDeclined []scanner.MethodDecline `json:"methods_declined"`
	} `json:"outcome"`
	Config map[string]json.RawMessage `json:"config"`
}

// runImportedAudit audits the SQL injection and Python code injection endpoints through the console
// route, under the imported preset when imported is true and under the plain default otherwise.
func runImportedAudit(t *testing.T, imported bool) (*recordingTarget, *Server, []auditReply) {
	t.Helper()
	cfg := scanner.DefaultAuditConfig()
	if imported {
		data, err := os.ReadFile(timeBasedPreset)
		if err != nil {
			t.Fatal(err)
		}
		var unapplied []string
		cfg, unapplied, err = scanner.ApplyBurpConfigFile(cfg, data)
		if err != nil {
			t.Fatal(err)
		}
		if len(unapplied) != 0 {
			t.Fatalf("Burp's own preset reports unapplied keys %v", unapplied)
		}
	}
	rt := startRecordingTarget(t)
	store := core.NewTrafficStore()
	ids := seedVulnapp(t, rt, store, "/products?sort_col=seed", "/ij/scripts/python?snippet=seed")
	active := scanner.NewActiveScanner(store, zap.NewNop()).
		WithSender(sender.NewSender(sender.DefaultSenderConfig())).
		WithConfig(&scanner.ScanConfig{MaxConcurrency: 1, Timeout: time.Minute, CheckSqli: true, CheckActiveInjection: true}).
		WithAuditConfig(cfg)
	s := NewServer(store, core.NewScope()).WithScanner(active)
	var replies []auditReply
	for _, id := range ids {
		rec := postJSON(t, s, "/api/audit/"+strconv.FormatUint(uint64(id), 10), nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("audit %d = %d: %s", id, rec.Code, rec.Body.String())
		}
		var r auditReply
		if err := json.Unmarshal(rec.Body.Bytes(), &r); err != nil {
			t.Fatal(err)
		}
		considered := r.Outcome.Ran + r.Outcome.Skipped + r.Outcome.SendFailures
		if considered != r.ActiveChecks {
			t.Errorf("exchange %d: reply says %d active checks, outcome accounts for %d", id, r.ActiveChecks, considered)
		}
		replies = append(replies, r)
	}
	return rt, s, replies
}

func findingNames(s *Server) map[string]bool {
	out := map[string]bool{}
	for _, f := range s.findings.All() {
		out[f.Name] = true
	}
	return out
}

func TestTheImportedTimeBasedExclusionPresetRunsEverythingExceptWhatItRemoves(t *testing.T) {
	_, controlServer, control := runImportedAudit(t, false)
	rt, s, imported := runImportedAudit(t, true)

	controlFound, found := findingNames(controlServer), findingNames(s)
	// The error-based SQL injection finding still fires: the preset removes Time delays, not SQL
	// injection, and reading its list as a whitelist would not have changed this — the five removals
	// below are what tells the two readings apart.
	if !found["SQL injection"] {
		t.Errorf("findings %v: SQL injection must still be found under the preset", found)
	}
	// Python code injection is one of the five types the file sets enabled:false. The control proves
	// the endpoint yields it when the type is not removed.
	if !controlFound["Python code injection"] {
		t.Fatalf("control findings %v: vulnapp's Python endpoint did not yield Python code injection, so its absence below would prove nothing", controlFound)
	}
	if found["Python code injection"] {
		t.Error("Python code injection was dispatched and reported; the preset removes that type")
	}
	// Four of the five removed types are in the injection family this scanner runs (Perl, Ruby, Python,
	// server-side JavaScript; unidentified code injection is a reflection-probe row): the run's check
	// set is exactly four smaller, and nothing else moved.
	for i := range imported {
		if d := control[i].ActiveChecks - imported[i].ActiveChecks; d != 4 {
			t.Errorf("item %d: the preset removed %d check(s) from the run, want the 4 enabled:false types in this family set", i, d)
		}
	}
	// No time-delay probe reached the target. This is vacuous today and the report says so: no native
	// burpsy check sends one (ProbeTiming has no production caller). It stays here so the day one is
	// added, this preset is proved to withhold it end to end; the harness gate is unit-tested directly.
	for _, q := range rt.received() {
		l := strings.ToLower(q)
		for _, marker := range []string{"sleep", "waitfor", "benchmark("} {
			if strings.Contains(l, marker) {
				t.Errorf("a time-delay probe reached the target: %q", q)
			}
		}
	}
	// The SQL injection item names what its check did not try, Burp Infiltrator included.
	declined := false
	for _, d := range imported[0].Outcome.MethodsDeclined {
		if d.TypeIndex == 0x00100200 && d.Method == scanner.MethodInfiltrator {
			declined = true
		}
	}
	if !declined {
		t.Errorf("SQL injection item methods_declined = %+v, want Burp Infiltrator", imported[0].Outcome.MethodsDeclined)
	}
	// The reply's config block carries the selection as the console reads it.
	var disabled []uint32
	if err := json.Unmarshal(imported[0].Config["disabled_issue_types"], &disabled); err != nil || len(disabled) != 5 {
		t.Errorf("config.disabled_issue_types = %s, want the five removed types", imported[0].Config["disabled_issue_types"])
	}
}

// Every new list on the configuration view is an array, [] when empty, never null.
func TestTheSelectionFieldsOnTheConfigurationViewMarshalAsArrays(t *testing.T) {
	b, err := json.Marshal(newAuditConfigView(scanner.AuditConfig{}))
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"disabled_issue_types", "disabled_detection_methods",
		"declined_detection_methods", "skip_server_side_injection_for_parameters"} {
		if !strings.Contains(string(b), `"`+key+`":[]`) {
			t.Errorf("%s is not [] on an empty configuration: %s", key, b)
		}
	}
}

// The server-side list is written exactly like the skip-all list.
func TestTheServerSideSkipListOverlaysLikeTheSkipAllList(t *testing.T) {
	cfg, err := applyConfigOverlay(t, scanner.AuditConfig{}, `{"skip_server_side_injection_for_parameters":[" sort_col ","id"]}`)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.SkipServerSideInjectionForParameters) != 2 || cfg.SkipServerSideInjectionForParameters[0] != "sort_col" {
		t.Errorf("list = %v, want trimmed names", cfg.SkipServerSideInjectionForParameters)
	}
	if _, err := applyConfigOverlay(t, scanner.AuditConfig{}, `{"skip_server_side_injection_for_parameters":["  "]}`); err == nil {
		t.Error("an empty name was accepted")
	}
	kept, _ := applyConfigOverlay(t, cfg, `{"nested_insertion_points":true}`)
	if len(kept.SkipServerSideInjectionForParameters) != 2 {
		t.Error("an absent field cleared the list")
	}
}
