package sender

// burpsy-react-ui-o2p3: a scan run's own timeouts, on a sender derived for it, never on the engagement
// sender; and a followed redirect hop is paced like the request that started the chain.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type admitAll struct{}

func (admitAll) AuthoriseRaw(string, uint16, bool, []byte) error { return nil }

func hostPortOf(t *testing.T, url string) (string, uint16) {
	t.Helper()
	h, p, _ := strings.Cut(strings.TrimPrefix(url, "http://"), ":")
	n, err := strconv.Atoi(p)
	if err != nil {
		t.Fatalf("port of %s: %v", url, err)
	}
	return h, uint16(n)
}

func TestADerivedRunSenderCarriesTheRunsTimeoutsAndLeavesTheEngagementSenderAlone(t *testing.T) {
	eng := NewSender(&SenderConfig{Timeout: 30 * time.Second})
	before := eng.Network()

	connect, normal := 4*time.Second, 2*time.Second
	run, err := eng.DeriveWithTimeouts(TimeoutOverride{Connect: &connect, Normal: &normal})
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	got := run.Network().Timeouts
	if got.ConnectMS != 4000 || got.ReadMS != 2000 || got.TotalMS != 6000 {
		t.Errorf("run timeouts = %+v, want connect 4000, read 2000, total 6000 (connect + normal)", got)
	}
	if after := eng.Network(); !reflect.DeepEqual(before, after) {
		t.Errorf("deriving changed the engagement sender:\nbefore %+v\nafter  %+v", before, after)
	}
	if run.httpClient() == eng.httpClient() {
		t.Error("the run shares the engagement's transport, whose timeouts are fixed at connection time")
	}

	// Zero is Burp's "never time out": the phase is unbounded, and so is the total that would cut it.
	zero := time.Duration(0)
	never, err := eng.DeriveWithTimeouts(TimeoutOverride{Normal: &zero})
	if err != nil {
		t.Fatalf("derive never: %v", err)
	}
	if n := never.Network().Timeouts; n.ReadMS != 0 || n.TotalMS != 0 || n.ConnectMS != before.Timeouts.ConnectMS {
		t.Errorf("normal 0 = %+v, want read 0, total 0, connect the engagement's %d", n, before.Timeouts.ConnectMS)
	}
}

func TestADerivedRunSendersBoundIsNotLoosenedByALongerContextDeadline(t *testing.T) {
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(2 * time.Second):
		case <-r.Context().Done():
		}
	}))
	defer slow.Close()
	host, port := hostPortOf(t, slow.URL)
	raw := []byte("GET / HTTP/1.1\r\nHost: " + host + "\r\n\r\n")

	eng := NewSender(&SenderConfig{Timeout: 30 * time.Second})
	normal := 200 * time.Millisecond
	run, err := eng.DeriveWithTimeouts(TimeoutOverride{Normal: &normal})
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	// A per-probe budget far longer than the run's bound, as the scanner's ProbeTimeout would set.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	start := time.Now()
	_, err = NewAuthorisedSender(admitAll{}, run, host, port, false).Send(ctx, raw)
	if err == nil {
		t.Fatal("a 2 s answer came back under a 200 ms run timeout")
	}
	if took := time.Since(start); took > time.Second {
		t.Errorf("the send took %s: the context's 30 s deadline replaced the run's 200 ms bound", took)
	}
}

type countingPacer struct{ n atomic.Int64 }

func (p *countingPacer) Pace(context.Context) (func(), error) {
	p.n.Add(1)
	return func() {}, nil
}

func TestAFollowedRedirectHopIsPacedLikeTheRequestThatStartedTheChain(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/from" {
			http.Redirect(w, r, "/to", http.StatusFound)
			return
		}
		w.Write([]byte("landed"))
	}))
	defer srv.Close()
	host, port := hostPortOf(t, srv.URL)
	pace := &countingPacer{}
	gate := NewAuthorisedSender(admitAll{}, NewSender(DefaultSenderConfig()), host, port, false).WithPace(pace)
	raw := []byte("GET /from HTTP/1.1\r\nHost: " + host + "\r\n\r\n")
	first, err := gate.Send(context.Background(), raw)
	if err != nil {
		t.Fatalf("first send: %v", err)
	}
	res, err := gate.FollowRedirectsAfterPolicy(context.Background(), raw, first.Raw,
		RedirectSettings{Mode: RedirectOnSite, MaxHops: 3})
	if err != nil || len(res.Hops) != 1 || !res.Hops[0].Followed {
		t.Fatalf("the chain was not followed: %+v %v", res, err)
	}
	if got := pace.n.Load(); got != 2 {
		t.Errorf("the pool paced %d sends for a request and one hop, want 2 — the hop left unpaced", got)
	}
}
