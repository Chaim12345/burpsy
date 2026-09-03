package proxy

// CRAWL-02, made checkable: the same traffic, captured through the proxy and through the crawler,
// must produce the same shape of exchange row.
//
// The requirement says crawled traffic is "captured, scoped and scanned through exactly the same path
// as proxied traffic". Until both surfaces called scanner.Capture.Record, that sentence could only be
// read as an intention — there were two independent implementations of "put the bytes, build the row,
// index it", and they had already drifted apart within hours of the second one being written. The
// drift was not caught by any test because no test compared the two.
//
// So this one does, end to end: a real proxy with a real client on one side of a real origin, and a
// real crawl of the same URL on the other. It deliberately does not call Record directly — that would
// prove the producer agrees with itself. What is under test is that neither surface has grown its own
// copy again.
//
// A note on why the two legs use separate stores: the row under comparison is then selected from a
// store only that leg wrote to, so neither leg can be mistaken for the other's. The seed's path is
// what picks it, because a crawl also asks the authority for /robots.txt and so records more than the
// one row.

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/crawler"
	"github.com/burpsy-go/burpsy/internal/scanner"
	"github.com/burpsy-go/burpsy/internal/sender"
	"go.uber.org/zap"
)

// parityBody has no links and no forms, so a crawl of it is exactly one fetch — the same single
// exchange the proxy leg produces.
const parityBody = "<html><head><title>parity</title></head><body><p>one exchange</p></body></html>"

// fieldRule says what the parity comparison expects of one core.Exchange field. Every field must have
// one: a field added to the struct without a rule fails the test rather than silently escaping the
// comparison, which is the only way this test keeps meaning something as the type grows.
type fieldRule int

const (
	// ruleIdentical: both producers must write the same value. This is the bulk of the row — the
	// addressing and the protocol are properties of the exchange, not of who captured it.
	ruleIdentical fieldRule = iota
	// rulePopulated: both must write something non-zero, but the values are per-store (message ids) or
	// per-run (timestamps) and cannot be equal.
	rulePopulated
	// ruleMayDiffer: a field the two are entitled to disagree on, named so the disagreement is a
	// decision and not an oversight.
	ruleMayDiffer
	// ruleAbsent: neither producer sets it for ordinary traffic.
	ruleAbsent
)

// exchangeFieldRules is the whole of core.Exchange, classified.
var exchangeFieldRules = map[string]fieldRule{
	"ID":       rulePopulated, // position-is-the-id, per store
	"Request":  rulePopulated, // a message id, per store
	"Response": rulePopulated, // ditto, and non-nil is the invariant Record now enforces
	"Host":     ruleIdentical,
	"Port":     ruleIdentical,
	"TLS":      ruleIdentical,
	"Method":   ruleIdentical,
	"Path":     ruleIdentical,
	"Status":   ruleIdentical,
	// Not identical, and this is the one difference worth spelling out. The proxy relays the origin's
	// bytes verbatim, while the crawler's sender re-renders the response it parsed, so the two counts
	// differ by whatever the stdlib transport normalised. What must hold for both — and is checked
	// per leg below, because it is the property that actually broke — is that ResponseLen describes the
	// message the row points at.
	"ResponseLen": rulePopulated,
	// Identical, and it is the stronger claim on purpose — note that it is a stronger claim than the
	// ResponseLen rule immediately above, for a reason. ResponseLen has to be rulePopulated because the
	// crawler's sender re-renders the response it parsed and the byte count shifts by whatever the
	// stdlib transport normalised. The *media type* does not shift: it is what the origin declared, and
	// core.MimeEssence strips parameters and folds case, which is exactly the normalisation the
	// re-render could otherwise introduce. So a proxied and a crawled fetch of the same resource must
	// agree here, and a leg that started deriving the type from something other than the response's own
	// Content-Type is what this catches.
	"Mime":      ruleIdentical,
	"StartedMs": rulePopulated,
	// The two legs time different work — a relayed exchange and a crawler fetch — so their durations are
	// not comparable and no rule here can say anything about the *value*. What must hold for both is that
	// they measured at all, and that is asserted explicitly per leg below rather than through
	// rulePopulated.
	//
	// Deliberately not rulePopulated, even though it would now pass: that rule fails a field on IsZero,
	// and reading "the duration is non-zero" as "the exchange was timed" is the exact conflation that made
	// this field a false failure earlier today. A sub-millisecond loopback exchange legitimately rounded to
	// 0 and *both* sides "failed" identically, which was the tell that the assertion was wrong rather than
	// two producers being broken. core.ExchangeDuration.Measured is now the thing that is actually being
	// claimed, so the test claims it by name — and it stays true on a fast machine, with no sleep anywhere
	// to clear a threshold.
	"Duration": ruleMayDiffer,
	// Source is the one field that must differ: it names which surface produced the row, and that is
	// the point of it. Everything else being equal is what makes it useful.
	"Source": ruleMayDiffer,
	"Notes":  ruleAbsent, // set only when the capture is not verbatim
	// Highlight, like Notes, is an operator annotation added after the fact through PATCH
	// /api/exchange/{id} — neither the proxy nor the crawler has an opinion about it at capture time,
	// so both legs must record it as unset.
	"Highlight": ruleAbsent,
	"Related":   ruleAbsent, // WebSocket children hang off a handshake row, not off these
	"Protocol":  ruleIdentical,
	// Which *run* produced the row, where Source says which kind of surface did. Neither leg of this
	// test runs under a registry task — the proxy never does, and this crawl is driven directly rather
	// than through the dashboard — so both are legitimately unset here. ruleAbsent rather than
	// ruleMayDiffer, because "0 on both sides" is the specific thing that must hold: a producer that
	// started stamping a task id onto plain proxy traffic would be claiming an owner that does not
	// exist, and this is the assertion that would catch it.
	"TaskID": ruleAbsent,
	// Lineage. A proxied request and a crawled fetch both have no antecedent exchange; only a Repeater
	// resend, an Intruder payload or a followed redirect does.
	"ParentID": ruleAbsent,
	// Identical: both legs record through scanner.Capture.Record, which derives these from
	// the response bytes in hand. The origin above serves a title and a cookie so the
	// comparison is over real values, not two empty cells agreeing vacuously.
	"Cookies": ruleIdentical,
	"Title":   ruleIdentical,
}

func TestTheProxyAndTheCrawlerRecordTheSameShapeOfExchange(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		// A cookie, so the Cookies rule below compares something real on both legs rather
		// than two empty lists. The title already comes from parityBody itself.
		w.Header().Set("Set-Cookie", "parity_probe=1; Path=/")
		io.WriteString(w, parityBody)
	}))
	defer origin.Close()

	host, portStr, _ := net.SplitHostPort(strings.TrimPrefix(origin.URL, "http://"))
	port, _ := strconv.Atoi(portStr)
	target := fmt.Sprintf("http://%s:%d/one", host, port)

	proxied, proxyStore := proxyOneExchange(t, target)
	crawled, crawlStore := crawlOneExchange(t, target)

	// Guard the classification first: an unclassified field means core.Exchange grew and nobody said
	// whether the two producers have to agree about the new part.
	typ := reflect.TypeOf(core.Exchange{})
	for i := 0; i < typ.NumField(); i++ {
		name := typ.Field(i).Name
		if _, ok := exchangeFieldRules[name]; !ok {
			t.Fatalf("core.Exchange.%s has no parity rule: say whether the proxy and the crawler must "+
				"populate it identically, and add it to exchangeFieldRules", name)
		}
	}
	if len(exchangeFieldRules) != typ.NumField() {
		t.Fatalf("exchangeFieldRules has %d entries for %d fields; a field was removed and its rule left behind",
			len(exchangeFieldRules), typ.NumField())
	}

	pv := reflect.ValueOf(*proxied)
	cv := reflect.ValueOf(*crawled)
	for i := 0; i < typ.NumField(); i++ {
		name := typ.Field(i).Name
		p, c := pv.Field(i), cv.Field(i)
		switch exchangeFieldRules[name] {
		case ruleIdentical:
			if !reflect.DeepEqual(deref(p), deref(c)) {
				t.Errorf("%s: proxy has %v, crawler has %v — the two capture paths disagree about the same traffic",
					name, deref(p), deref(c))
			}
		case rulePopulated:
			// ID and Request are exempt from the non-zero part: both are positions, and position 0 is a
			// perfectly good one — the first row in a store has ID 0 and its request is message 0. They are
			// classified here for the other half of the rule, that the two legs need not agree on them.
			if p.IsZero() && name != "ID" && name != "Request" {
				t.Errorf("%s: the proxy left it unset", name)
			}
			if c.IsZero() && name != "ID" && name != "Request" {
				t.Errorf("%s: the crawler left it unset", name)
			}
		case ruleAbsent:
			if !p.IsZero() {
				t.Errorf("%s: the proxy set %v on ordinary traffic", name, deref(p))
			}
			if !c.IsZero() {
				t.Errorf("%s: the crawler set %v on ordinary traffic", name, deref(c))
			}
		case ruleMayDiffer:
		}
	}

	// Named explicitly rather than left to the rules above, because these are the two properties the
	// divergence actually broke: a row must point at a response, and it must describe the bytes it
	// points at.
	for _, leg := range []struct {
		name  string
		ex    *core.Exchange
		store *core.TrafficStore
	}{{"proxy", proxied, proxyStore}, {"crawler", crawled, crawlStore}} {
		if leg.ex.Response == nil {
			t.Fatalf("%s: the row has no response, which is the shape that stalls a cursor walking the index", leg.name)
		}
		if leg.ex.Status == nil || *leg.ex.Status != 200 {
			t.Errorf("%s: status = %v, want 200", leg.name, leg.ex.Status)
		}
		if leg.ex.Source != core.SourceProxy && leg.ex.Source != core.SourceCrawl {
			t.Errorf("%s: the row is unattributed, so history cannot say which surface produced it", leg.name)
		}
		// Both producers must *time* their exchange. Only the flag is asserted, deliberately: against a
		// loopback origin the elapsed time is often under a millisecond and can be under a microsecond, so
		// any assertion about the magnitude would be an assertion about the machine — which is how this
		// field became a false failure before core.ExchangeDuration existed.
		if !leg.ex.Duration.Measured {
			t.Errorf("%s: the row carries no measurement, so history cannot tell a fast exchange from an "+
				"untimed one for this producer", leg.name)
		}
		// And the honest converse, stated so a future reader does not "fix" the check above by requiring a
		// non-zero value: a measured zero is a legitimate row, not a missing measurement.
		if leg.ex.Duration.Measured && leg.ex.Duration.Us == 0 {
			t.Logf("%s: measured 0µs — a legitimate value on a fast loopback, and distinguishable from "+
				"unmeasured only because Measured is carried separately", leg.name)
		}
		// The row describes the bytes it points at. This is what the plain-HTTP proxy path got wrong: it
		// stored one version of the response and then described it with another's status and length.
		stored, err := leg.store.Get(*leg.ex.Response)
		if err != nil {
			t.Fatalf("%s: the response id does not resolve: %v", leg.name, err)
		}
		if leg.ex.ResponseLen != len(stored.Raw()) {
			t.Errorf("%s: ResponseLen = %d but the stored response is %d bytes",
				leg.name, leg.ex.ResponseLen, len(stored.Raw()))
		}
		if !strings.Contains(string(stored.Raw()), parityBody) {
			t.Errorf("%s: the stored response is not the origin's", leg.name)
		}
		// Both must have stored the request they sent, too: an exchange is a pair, and half of one is
		// exactly what this refactor removed the ability to record.
		if _, err := leg.store.Get(leg.ex.Request); err != nil {
			t.Errorf("%s: the request id does not resolve: %v", leg.name, err)
		}
	}
	if proxied.Source != core.SourceProxy {
		t.Errorf("proxied traffic is attributed to %q", proxied.Source)
	}
	if crawled.Source != core.SourceCrawl {
		t.Errorf("crawled traffic is attributed to %q", crawled.Source)
	}
}

// deref makes a *uint16 or *string comparable to another one by value, so a status of 200 on both
// sides compares equal instead of comparing two different addresses.
func deref(v reflect.Value) any {
	if v.Kind() == reflect.Ptr {
		if v.IsNil() {
			return nil
		}
		return v.Elem().Interface()
	}
	return v.Interface()
}

// proxyOneExchange sends one request for target through a real proxy and returns the row it recorded,
// with the store that holds it.
func proxyOneExchange(t *testing.T, target string) (*core.Exchange, *core.TrafficStore) {
	t.Helper()
	store := core.NewTrafficStore()
	srv := NewServer(NewProxyConfig(store).
		WithScope(testScope()).
		WithLogger(zap.NewNop()).
		WithScanner(scanner.NewPassiveScanner(store, zap.NewNop())).
		WithFindings(core.NewFindingStore()))
	proxyAddr := startProxy(t, srv)

	client := &http.Client{Transport: &http.Transport{
		Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: proxyAddr}),
	}}
	resp, err := client.Get(target)
	if err != nil {
		t.Fatalf("request through proxy: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != parityBody {
		t.Fatalf("the client did not receive the origin's body: %q", body)
	}
	// The row is written after the response has been handed to the client, so a client that has read
	// its body proves nothing about the capture goroutine yet — the same reason the tests in
	// proxy_test.go poll.
	return awaitExchangeFor(t, store, "/one", "proxy"), store
}

// crawlOneExchange crawls target with one seed and no links to follow, and returns the row it recorded,
// with the store that holds it.
func crawlOneExchange(t *testing.T, target string) (*core.Exchange, *core.TrafficStore) {
	t.Helper()
	store := core.NewTrafficStore()
	c, err := crawler.New(crawler.Config{
		Seeds:  []string{target},
		Scope:  core.NewScope(),
		Sender: sender.NewSender(&sender.SenderConfig{Timeout: 5 * time.Second}),
		Capture: scanner.Capture{
			Store:    store,
			Scanner:  scanner.NewPassiveScanner(store, zap.NewNop()),
			Findings: core.NewFindingStore(),
			Logger:   zap.NewNop(),
		},
		RequestsPerSecond: 2000,
		Logger:            zap.NewNop(),
	})
	if err != nil {
		t.Fatalf("crawler.New: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	rep := c.Run(ctx)
	if rep.Fetched == 0 {
		t.Fatalf("the crawl fetched nothing: %+v", rep.Skips)
	}
	// A crawl also asks for /robots.txt, so its store holds more than the seed's row. That extra row is
	// not noise to be filtered quietly: every row in the store is checked for the invariant below, and
	// only the seed's is compared against the proxy's.
	return awaitExchangeFor(t, store, "/one", "crawler"), store
}

// awaitExchangeFor returns the row for path, and asserts on the way that every row the store holds
// carries a response. That second check is the property the wedge came from: it must hold for whatever
// else the surface happened to capture, not only for the one row under comparison.
func awaitExchangeFor(t *testing.T, store *core.TrafficStore, path, leg string) *core.Exchange {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	var found *core.Exchange
	for time.Now().Before(deadline) && found == nil {
		for _, ex := range store.Exchanges() {
			if ex.Path == path {
				found = ex
			}
		}
		if found == nil {
			time.Sleep(10 * time.Millisecond)
		}
	}
	if found == nil {
		t.Fatalf("%s: no exchange recorded for %s (rows: %d)", leg, path, len(store.Exchanges()))
	}
	for _, ex := range store.Exchanges() {
		if ex.Response == nil {
			t.Fatalf("%s: exchange %d (%s %s) has no response, which is the shape that stalls a cursor walking the index",
				leg, ex.ID, ex.Method, ex.Path)
		}
	}
	return found
}
