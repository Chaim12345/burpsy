package proxy

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/intercept"
	"github.com/burpsy-go/burpsy/internal/matchreplace"
	"github.com/burpsy-go/burpsy/internal/scanner"
	"go.uber.org/zap"
)

// What a Match & Replace rule did to live traffic has to be readable afterwards (burpsy-react-ui-c05,
// under epic mrjw).
//
// Before this, burpsy kept one version of every message and counted the rewrites it could not show:
// Counters.ModifiedUnrecorded existed precisely because "the rewrite is real but invisible in
// history". These tests are the other half of that sentence — the rewrite is visible, and visible
// per direction, because the bytes a rule produced are the bytes the operator has to be able to
// compare against the ones their client sent.
//
// # Why these assert on the wire's bytes and on the store's, not on the store's alone
//
// A test that only compared two stored messages would pass for a proxy that kept the right copies of
// the wrong conversation: the origin's view of the request is what a request rule changed, and the
// client's view of the response is what a response rule changed. So the origin records what it
// actually received, and each assertion pairs the stored reading with the bytes that really crossed
// one of the two sockets.

// stageProxy starts a proxy on a loopback listener with the given rule set, and returns a client
// routed through it plus the listener address. Modelled on the match-replace wiring test's setup,
// because the point of both is a real client talking to a real origin through a real proxy.
func stageProxy(t *testing.T, rules *matchreplace.RuleSet) (*http.Client, *core.TrafficStore) {
	t.Helper()
	store := core.NewTrafficStore()
	config := NewProxyConfig(store).
		WithScope(testScope()).
		WithLogger(zap.NewNop()).
		WithScanner(scanner.NewPassiveScanner(store, zap.NewNop())).
		WithFindings(core.NewFindingStore())
	if rules != nil {
		config = config.WithMatchReplace(rules)
	}
	srv := NewServer(config)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go srv.handleConnection(conn)
		}
	}()
	return &http.Client{Transport: &http.Transport{
		Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: ln.Addr().String()}),
	}}, store
}

// messageText reads one message's raw bytes back out of the store, so an assertion can say what the
// operator would see rather than only that two ids differ.
func messageText(t *testing.T, store *core.TrafficStore, id core.MsgId) string {
	t.Helper()
	msg, err := store.Get(id)
	if err != nil {
		t.Fatalf("message %d is not in the store; the reading points at bytes nothing kept: %v", id, err)
	}
	return string(msg.Raw())
}

// A request-direction rule rewrites the bytes that go upstream, and the bytes the client actually
// sent are still readable as the original reading. The origin's copy is the proof that the rewrite
// was real; the stored original is the proof that it is comparable.
func TestARequestRewriteKeepsWhatTheClientSentAsTheOriginal(t *testing.T) {
	var originSaw string
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originSaw = r.Header.Get("X-Secret")
		_, _ = w.Write([]byte("ok"))
	}))
	defer origin.Close()
	host, port := originHostPort(t, origin)

	rules := matchreplace.NewRuleSet()
	rules.SetRules([]*matchreplace.Rule{
		mustRule(t, matchreplace.TargetRequestHeader, matchreplace.CategoryLiteral, "hunter2", "scrubbed"),
	})
	client, store := stageProxy(t, rules)

	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://%s:%d/one", host, port), nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("X-Secret", "hunter2")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("through proxy: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.ReadAll(resp.Body)

	if originSaw != "scrubbed" {
		t.Fatalf("the origin received X-Secret %q, want the rule's output; the rest of this test would be vacuous", originSaw)
	}
	ex := awaitExchangeFor(t, store, "/one", "proxy")

	if got, _ := ex.VariantFor(core.DirectionRequest, core.VariantEdited); got != ex.Request {
		t.Fatalf("the edited request reading is %d, want the recorded request %d", got, ex.Request)
	}
	if !ex.HasRetainedStage(core.DirectionRequest) {
		t.Fatal("a rewritten request retained nothing; the rule's effect on live traffic is unreadable again")
	}
	original := messageText(t, store, mustReading(t, ex, core.DirectionRequest, core.VariantOriginal))
	if !strings.Contains(original, "hunter2") {
		t.Errorf("the original request reading is %q, want the client's bytes carrying hunter2", original)
	}
	if strings.Contains(messageText(t, store, ex.Request), "hunter2") {
		t.Error("the recorded request still carries the rule's input; the rule did not reach the stored bytes")
	}
}

func TestAResponseRewriteKeepsWhatTheOriginSentAsTheOriginal(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("wrap RESP-ORIG wrap"))
	}))
	defer origin.Close()
	host, port := originHostPort(t, origin)

	rules := matchreplace.NewRuleSet()
	rules.SetRules([]*matchreplace.Rule{
		mustRule(t, matchreplace.TargetResponseBody, matchreplace.CategoryLiteral, "RESP-ORIG", "RESP-PROXY"),
	})
	client, store := stageProxy(t, rules)

	resp, err := client.Get(fmt.Sprintf("http://%s:%d/one", host, port))
	if err != nil {
		t.Fatalf("through proxy: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "RESP-PROXY") {
		t.Fatalf("the client received %q, want the rule's output; the rest of this test would be vacuous", body)
	}
	ex := awaitExchangeFor(t, store, "/one", "proxy")

	if !ex.HasRetainedStage(core.DirectionResponse) {
		t.Fatal("a rewritten response retained nothing")
	}
	original := messageText(t, store, mustReading(t, ex, core.DirectionResponse, core.VariantOriginal))
	if !strings.Contains(original, "RESP-ORIG") {
		t.Errorf("the original response reading is %q, want the origin's bytes", original)
	}
	if strings.Contains(messageText(t, store, *ex.Response), "RESP-ORIG") {
		t.Error("the recorded response still carries the origin's pre-rule text")
	}
	// The request was not touched by anything, and must not claim a comparison it cannot offer. This
	// is the half that keeps the feature from marking every row in a capture as edited.
	if ex.HasRetainedStage(core.DirectionRequest) {
		t.Error("the request reports a retained stage although no rule and no edit touched it")
	}
}

// An operator's own intercept edit is the other way a message changes, and it produces the same two
// readable readings — with the pre-edit bytes coming from the *auto-modified* stage rather than the
// original one, because with no rule firing those two stages are the same bytes. That distinction is
// the whole reason the walk exists, and this is the end-to-end version of it.
func TestAnInterceptEditKeepsThePreEditBytesReadable(t *testing.T) {
	var originSaw string
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originSaw = r.Header.Get("X-Marker")
		_, _ = w.Write([]byte("ok"))
	}))
	defer origin.Close()
	host, port := originHostPort(t, origin)

	engine := intercept.NewEngine()
	engine.SetEnabled(true)
	// An empty rule list on an active list is Burp's "intercept everything".
	if err := engine.SetRules(intercept.DirectionRequest, true, nil); err != nil {
		t.Fatalf("SetRules: %v", err)
	}

	store := core.NewTrafficStore()
	srv := NewServer(NewProxyConfig(store).
		WithScope(testScope()).
		WithIntercept(engine).
		WithLogger(zap.NewNop()))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go srv.handleConnection(conn)
		}
	}()

	// The operator: take the hold, edit the marker, forward the edited bytes.
	go func() {
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			for _, held := range engine.Held() {
				if held.Direction != intercept.DirectionRequest {
					continue
				}
				edited := strings.Replace(string(held.Raw), "as-sent", "as-edited", 1)
				_ = engine.Forward(held.ID, &edited, false)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()

	client := &http.Client{Transport: &http.Transport{
		Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: ln.Addr().String()}),
	}}
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://%s:%d/one", host, port), nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("X-Marker", "as-sent")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("through proxy: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.ReadAll(resp.Body)

	if originSaw != "as-edited" {
		t.Fatalf("the origin received X-Marker %q, want the operator's edit", originSaw)
	}
	ex := awaitExchangeFor(t, store, "/one", "proxy")
	if !ex.HasRetainedStage(core.DirectionRequest) {
		t.Fatal("an edited request retained nothing; the operator cannot see what they changed")
	}
	original := messageText(t, store, mustReading(t, ex, core.DirectionRequest, core.VariantOriginal))
	if !strings.Contains(original, "as-sent") {
		t.Errorf("the original request reading is %q, want the pre-edit bytes", original)
	}
	edited := messageText(t, store, ex.Request)
	if !strings.Contains(edited, "as-edited") {
		t.Errorf("the recorded request is %q, want the operator's edit", edited)
	}
	if !strings.Contains(edited, "as-edited") || strings.Contains(original, "as-edited") {
		t.Error("the two readings are not what they claim: one must hold the edit and the other must not")
	}
}

// The memory guarantee, stated as an assertion: traffic nothing modified retains nothing. The whole
// cost model of this store is that the resident set does not scale with traffic, and a feature that
// kept a second copy of every untouched message would pass every functional test in this repository
// while quietly tripling it.
func TestUnmodifiedTrafficRetainsNoExtraBytes(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("plain"))
	}))
	defer origin.Close()
	host, port := originHostPort(t, origin)

	rules := matchreplace.NewRuleSet()
	// A rule that is enabled but does not match this request: the stage boundaries are still
	// reached, and the storage rule must still see "nothing differed".
	rules.SetRules([]*matchreplace.Rule{
		mustRule(t, matchreplace.TargetRequestHeader, matchreplace.CategoryLiteral, "absent-header-value", "x"),
	})
	client, store := stageProxy(t, rules)

	resp, err := client.Get(fmt.Sprintf("http://%s:%d/one", host, port))
	if err != nil {
		t.Fatalf("through proxy: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.ReadAll(resp.Body)

	ex := awaitExchangeFor(t, store, "/one", "proxy")
	if ex.RequestOriginal != nil || ex.RequestAuto != nil || ex.ResponseOriginal != nil || ex.ResponseAuto != nil {
		t.Fatalf("unmodified traffic retained stages: req=(%v,%v) resp=(%v,%v)",
			ex.RequestOriginal, ex.RequestAuto, ex.ResponseOriginal, ex.ResponseAuto)
	}
	// And the store really holds only the two messages: the id assertions above would miss a second
	// copy that nothing points at, so the count is asserted too. The crawl in the parity test also
	// writes /robots.txt into its own store, which is why this compares against the count for this
	// leg rather than a constant.
	messages, exchanges := store.Count()
	if exchanges != 1 {
		t.Fatalf("the store holds %d exchanges, want the one just relayed", exchanges)
	}
	if messages != 2 {
		t.Errorf("the store holds %d messages for one unmodified exchange, want 2; an extra copy is memory the cost model did not pay for", messages)
	}
}

func originHostPort(t *testing.T, srv *httptest.Server) (string, int) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatalf("split %q: %v", srv.URL, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("port %q: %v", portStr, err)
	}
	return host, port
}

// mustReading resolves one reading of a stored message or fails the test, so each assertion can be
// written in terms of the reading rather than in terms of the ids behind it.
func mustReading(t *testing.T, ex *core.Exchange, dir core.Direction, variant core.Variant) core.MsgId {
	t.Helper()
	id, ok := ex.VariantFor(dir, variant)
	if !ok {
		t.Fatalf("the exchange has no %s reading of its %v; the comparison the operator asked for is not available", variant, dir)
	}
	return id
}
