// Tests for generate_collaborator_address() and the `<type> interactions` conditions
// (burpsy-react-ui-ar8v). Every assertion about traffic reads the mock sink's own record, and every
// assertion about a verdict runs the check through RunActive and Deferred.Resolve — never a helper
// that skips the evaluator.
package bcheck

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
)

// fakeCollab is an interaction server whose callbacks the test controls.
type fakeCollab struct {
	mu      sync.Mutex
	minted  []string
	got     map[string][]Interaction
	mintErr error
	polls   int
}

func (f *fakeCollab) NewAddress() (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.mintErr != nil {
		return "", f.mintErr
	}
	a := fmt.Sprintf("m%d.collab.test", len(f.minted)+1)
	f.minted = append(f.minted, a)
	return a, nil
}

func (f *fakeCollab) Interactions(addr string) ([]Interaction, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.polls++
	return append([]Interaction(nil), f.got[addr]...), nil
}

// callback makes the target "contact" addr over protocol.
func (f *fakeCollab) callback(addr, protocol string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.got == nil {
		f.got = map[string][]Interaction{}
	}
	f.got[addr] = append(f.got[addr], Interaction{Protocol: protocol, Address: addr, From: "203.0.113.7",
		Detail: protocol + " interaction for " + addr})
}

func collabCtx(c Collaborator) *Context {
	ctx := activeCtx()
	ctx.SetCollaborator(c)
	return ctx
}

const httpInteractionsCheck = `define:
  addr = ` + "`{generate_collaborator_address()}`" + `
given request then
  send request:
    headers:
      "Referer": ` + "`http://{addr}/`" + `
  if http interactions then
    report issue:
      severity: high
      confidence: firm
      detail: "fetched the referer"
  end if
`

// The classifier bug ar8v found: the parser emits `<type> interactions` as Operator
// "interactions", but NeedsCollaborator looked for Operator "is" / Right "interactions", a shape
// the parser never produces. Every corpus collaborator check was therefore counted runnable, sent
// an empty address and read clean.
func TestAParsedInteractionsConditionIsClassifiedAsNeedingACollaborator(t *testing.T) {
	for _, kind := range []string{"dns", "http", "smtp", "any"} {
		c := parseCheck(`given request then
  send request:
    method: "GET"
  if ` + kind + ` interactions then
    report issue:
      severity: high
      confidence: firm
  end if
`)
		if !c.NeedsCollaborator() {
			t.Errorf("%s interactions: NeedsCollaborator() = false for a parsed check", kind)
		}
		if c.M2Runnable() {
			t.Errorf("%s interactions: M2Runnable() = true, so it would be counted as an ordinary active check", kind)
		}
	}
	// generate_collaborator_address() alone still needs a server to mint from.
	only := parseCheck(`given request then
  send request:
    headers:
      "X-Probe": ` + "`{generate_collaborator_address()}`" + `
`)
	if !only.NeedsCollaborator() {
		t.Error("a check that only calls generate_collaborator_address() is not classified as needing a collaborator")
	}
	plain := parseCheck(`given request then
  send request:
    method: "GET"
`)
	if plain.NeedsCollaborator() {
		t.Error("a check with neither construct is classified as needing a collaborator")
	}
}

// With no interaction server the check is refused with a reason and sends nothing — never run with
// an empty address and read as clean.
func TestWithoutACollaboratorTheCheckIsRefusedAndSendsNothing(t *testing.T) {
	m := &mockSink{}
	f, err := RunActive(parseCheck(httpInteractionsCheck), activeCtx(), m, tgt())
	var ae *ActiveError
	if !errors.As(err, &ae) || ae.Kind != ActiveUnsupported {
		t.Fatalf("err = %v, want ActiveUnsupported", err)
	}
	if !strings.Contains(err.Error(), "collaborator") || !strings.Contains(err.Error(), "not run") {
		t.Errorf("reason %q does not say the check was not run for want of a collaborator", err.Error())
	}
	if len(f) != 0 || m.count() != 0 {
		t.Errorf("findings = %d, sends = %d; want 0 and 0", len(f), m.count())
	}
}

// Every call is a new address: two calls in one run, and one call per insertion point.
func TestEveryGenerateCallMintsAUniqueAddress(t *testing.T) {
	fc := &fakeCollab{}
	m := &mockSink{}
	_, err := RunActive(parseCheck(`given request then
  send request:
    headers:
      "X-A": `+"`{generate_collaborator_address()}`"+`,
      "X-B": `+"`{generate_collaborator_address()}`"+`
`), collabCtx(fc), m, tgt())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(fc.minted) != 2 || fc.minted[0] == fc.minted[1] {
		t.Fatalf("minted %v, want two distinct addresses", fc.minted)
	}
	for _, a := range fc.minted {
		if !strings.Contains(m.first(), a) {
			t.Errorf("probe %q does not carry minted address %s", m.first(), a)
		}
	}

	// Per insertion point: the define runs once per point, so each parameter gets its own.
	fc2 := &fakeCollab{}
	m2 := &mockSink{}
	ctx := collabCtx(fc2)
	ctx.Request = []byte("GET /f?u=1&v=2 HTTP/1.1\r\nHost: x.test\r\n\r\n")
	_, err = RunActive(parseCheck(`define:
  a = `+"`{generate_collaborator_address()}`"+`
given query insertion point then
  send payload:
    replacing: {a}
  if dns interactions then
    report issue:
      severity: high
      confidence: firm
  end if
`), ctx, m2, tgt())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(fc2.minted) != 2 || fc2.minted[0] == fc2.minted[1] {
		t.Fatalf("minted %v, want one distinct address per insertion point", fc2.minted)
	}
	if !strings.Contains(m2.sent[0], "u="+fc2.minted[0]) || !strings.Contains(m2.sent[1], "v="+fc2.minted[1]) {
		t.Errorf("probes %q do not carry their own point's address", m2.sent)
	}
	if n := len(ctx.Deferred()); n != 2 {
		t.Errorf("deferred runs = %d, want 2 (one per point, each awaiting its own address)", n)
	}
}

// A callback that has already arrived when the condition is reached settles the check in the live
// pass, with the interaction as the finding's evidence.
func TestACallbackAlreadyReceivedReportsInTheLivePass(t *testing.T) {
	fc := &fakeCollab{}
	m := &mockSink{}
	// The "target" calls back synchronously: the callback lands while the probe is in flight.
	sink := &callbackSink{inner: m, onSend: func(raw string) {
		for _, a := range fc.minted {
			if strings.Contains(raw, a) {
				fc.callback(a, "http")
			}
		}
	}}
	ctx := collabCtx(fc)
	f, err := RunActive(parseCheck(httpInteractionsCheck), ctx, sink, tgt())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(f) != 1 {
		t.Fatalf("findings = %d, want 1", len(f))
	}
	if len(f[0].Interactions) != 1 || f[0].Interactions[0].Protocol != "http" {
		t.Errorf("finding evidence = %+v, want the http interaction", f[0].Interactions)
	}
	if len(ctx.Deferred()) != 0 {
		t.Errorf("deferred = %d, want 0: nothing was left unknown", len(ctx.Deferred()))
	}
}

type callbackSink struct {
	inner  *mockSink
	onSend func(string)
}

func (c *callbackSink) Send(t *Target, raw []byte) ([]byte, error) {
	c.onSend(string(raw))
	return c.inner.Send(t, raw)
}

// The common case: the callback arrives after the probe. The live pass reports nothing and defers;
// Resolve before the callback stays unsettled; after it, Resolve reports exactly once — and never
// sends.
func TestALateCallbackIsReportedByTheDeferredReplayWithoutResending(t *testing.T) {
	fc := &fakeCollab{}
	m := &mockSink{}
	ctx := collabCtx(fc)
	f, err := RunActive(parseCheck(httpInteractionsCheck), ctx, m, tgt())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(f) != 0 {
		t.Fatalf("live pass reported %d finding(s) with no callback yet", len(f))
	}
	ds := ctx.Deferred()
	if len(ds) != 1 {
		t.Fatalf("deferred = %d, want 1", len(ds))
	}
	d := ds[0]
	if got := d.Addresses(); len(got) != 1 || got[0] != fc.minted[0] {
		t.Errorf("deferred addresses = %v, want %v", got, fc.minted)
	}
	sent := m.count()

	got, settled, err := d.Resolve()
	if err != nil || settled || len(got) != 0 {
		t.Fatalf("Resolve before any callback = (%d findings, settled %v, %v); want (0, false, nil): "+
			"no callback yet is not an answer", len(got), settled, err)
	}

	// A DNS lookup alone does not satisfy `http interactions`.
	fc.callback(fc.minted[0], "dns")
	if got, settled, _ := d.Resolve(); len(got) != 0 || settled {
		t.Fatalf("a dns callback satisfied `http interactions`: %d findings, settled %v", len(got), settled)
	}

	fc.callback(fc.minted[0], "http")
	got, settled, err = d.Resolve()
	if err != nil || !settled || len(got) != 1 {
		t.Fatalf("Resolve after the http callback = (%d, %v, %v); want (1, true, nil)", len(got), settled, err)
	}
	if got[0].Description != "fetched the referer" || len(got[0].Interactions) == 0 {
		t.Errorf("finding = %+v, want the check's detail and the interaction as evidence", got[0])
	}
	again, _, _ := d.Resolve()
	if len(again) != 0 {
		t.Errorf("a second Resolve re-reported %d finding(s)", len(again))
	}
	if m.count() != sent {
		t.Errorf("the replay sent %d request(s); a deferred replay must never send", m.count()-sent)
	}
}

// `any` matches every protocol; `smtp` and `dns` match only their own.
func TestInteractionKindsMatchTheirOwnProtocol(t *testing.T) {
	cases := []struct {
		kind, arrived string
		want          bool
	}{
		{"dns", "dns", true}, {"dns", "http", false},
		{"smtp", "smtp", true}, {"smtp", "dns", false},
		{"any", "smtp", true}, {"any", "dns", true}, {"http", "HTTP", true},
	}
	for _, c := range cases {
		fc := &fakeCollab{}
		ctx := collabCtx(fc)
		_, err := RunActive(parseCheck(strings.Replace(httpInteractionsCheck, "if http interactions", "if "+c.kind+" interactions", 1)),
			ctx, &mockSink{}, tgt())
		if err != nil {
			t.Fatalf("%s: run: %v", c.kind, err)
		}
		fc.callback(fc.minted[0], c.arrived)
		got, _, err := ctx.Deferred()[0].Resolve()
		if err != nil {
			t.Fatalf("%s: resolve: %v", c.kind, err)
		}
		if (len(got) == 1) != c.want {
			t.Errorf("`%s interactions` with a %s callback: findings = %d, want fired=%v", c.kind, c.arrived, len(got), c.want)
		}
	}
}

// Kleene logic: a decided operand decides the whole; absence-so-far never becomes "false".
func TestInteractionsConditionsUseThreeValuedLogic(t *testing.T) {
	run := func(cond string) (*Context, []Finding) {
		fc := &fakeCollab{}
		ctx := collabCtx(fc)
		f, err := RunActive(parseCheck(strings.Replace(httpInteractionsCheck, "if http interactions", "if "+cond, 1)),
			ctx, &mockSink{replies: []mockReply{{body: ok200("plain")}}}, tgt())
		if err != nil {
			t.Fatalf("%s: %v", cond, err)
		}
		return ctx, f
	}
	// The response rules it out, so nothing is left to wait for.
	if ctx, f := run(`"zzz" in {latest.response.body} and http interactions`); len(f) != 0 || len(ctx.Deferred()) != 0 {
		t.Errorf("a condition the response already decides was deferred (%d) or fired (%d)", len(ctx.Deferred()), len(f))
	}
	// The response decides it true without the collaborator.
	if ctx, f := run(`"plain" in {latest.response.body} or http interactions`); len(f) != 1 || len(ctx.Deferred()) != 0 {
		t.Errorf("a condition the response already makes true: findings %d, deferred %d; want 1, 0", len(f), len(ctx.Deferred()))
	}
	// not(...) of an unanswered question is still unanswered: never fires, stays deferred.
	ctx, f := run(`not(http interactions)`)
	if len(f) != 0 || len(ctx.Deferred()) != 1 {
		t.Fatalf("not(http interactions): findings %d, deferred %d; want 0 and 1 — no callback yet must not read as 'no callback'", len(f), len(ctx.Deferred()))
	}
	if got, settled, _ := ctx.Deferred()[0].Resolve(); len(got) != 0 || settled {
		t.Errorf("not(http interactions) settled (%v) or fired (%d) without any evidence", settled, len(got))
	}
}

// An `else` branch of an unknown condition does not run: it would treat "not yet" as "no".
func TestAnUnknownConditionRunsNeitherBranch(t *testing.T) {
	fc := &fakeCollab{}
	ctx := collabCtx(fc)
	f, err := RunActive(parseCheck(`define:
  a = `+"`{generate_collaborator_address()}`"+`
given request then
  send request:
    headers:
      "X-A": {a}
  if dns interactions then
    report issue and continue:
      severity: high
      confidence: firm
      detail: "dns"
  else then
    report issue:
      severity: info
      confidence: tentative
      detail: "no dns"
  end if
`), ctx, &mockSink{}, tgt())
	if err != nil {
		t.Fatal(err)
	}
	if len(f) != 0 {
		t.Fatalf("an unknown condition ran a branch: %+v", f)
	}
}

// A replay that would need a probe the live pass never sent stops rather than sending.
func TestAReplayThatNeedsANewProbeDivergesInsteadOfSending(t *testing.T) {
	fc := &fakeCollab{}
	m := &mockSink{}
	ctx := collabCtx(fc)
	_, err := RunActive(parseCheck(`define:
  a = `+"`{generate_collaborator_address()}`"+`
given request then
  send request:
    headers:
      "X-A": {a}
  if dns interactions then
    send request called confirm:
      path: "/confirm"
    if "ok" in {confirm.response.body} then
      report issue:
        severity: high
        confidence: firm
    end if
  end if
`), ctx, m, tgt())
	if err != nil {
		t.Fatal(err)
	}
	sent := m.count()
	fc.callback(fc.minted[0], "dns")
	_, settled, err := ctx.Deferred()[0].Resolve()
	var ae *ActiveError
	if !errors.As(err, &ae) || ae.Kind != ActiveReplayDiverged || settled {
		t.Fatalf("Resolve = (settled %v, %v), want an unsettled ActiveReplayDiverged", settled, err)
	}
	if m.count() != sent {
		t.Errorf("the diverged replay sent %d request(s)", m.count()-sent)
	}
}

// A server that cannot mint abandons the check before any probe carries an empty host.
func TestAMintFailureAbandonsTheCheckBeforeAnyProbe(t *testing.T) {
	fc := &fakeCollab{mintErr: errors.New("registration timed out")}
	m := &mockSink{}
	_, err := RunActive(parseCheck(httpInteractionsCheck), collabCtx(fc), m, tgt())
	var ae *ActiveError
	if !errors.As(err, &ae) || ae.Kind != ActiveUnsupported || !strings.Contains(err.Error(), "registration timed out") {
		t.Fatalf("err = %v, want ActiveUnsupported naming the mint failure", err)
	}
	if m.count() != 0 {
		t.Errorf("sent %d probe(s) after the address could not be minted", m.count())
	}
}

// A `run for each` sends every payload in the live pass even though each iteration's condition is
// unknown; the replay then reports the iteration whose own address was contacted.
func TestForEachIterationsEachAskAboutTheirOwnAddress(t *testing.T) {
	fc := &fakeCollab{}
	m := &mockSink{}
	ctx := collabCtx(fc)
	_, err := RunActive(parseCheck(`run for each:
  scheme = "http", "https", "ftp"
given request then
  send request:
    headers:
      "X-U": `+"`{scheme}://{generate_collaborator_address()}/`"+`
  if http interactions then
    report issue:
      severity: high
      confidence: firm
      detail: `+"`{scheme}`"+`
  end if
`), ctx, m, tgt())
	if err != nil {
		t.Fatal(err)
	}
	if m.count() != 3 || len(fc.minted) != 3 {
		t.Fatalf("sent %d / minted %d, want 3 / 3: an unknown condition must not stop the iteration", m.count(), len(fc.minted))
	}
	fc.callback(fc.minted[1], "http") // only the https iteration's address
	got, settled, err := ctx.Deferred()[0].Resolve()
	if err != nil || !settled || len(got) != 1 || got[0].Description != "https" {
		t.Fatalf("Resolve = (%+v, %v, %v), want one finding for the https iteration", got, settled, err)
	}
}

// PortSwigger corpus check `SSRFInjection.bcheck` (v1-beta), as transcribed verbatim — tabs
// included — in docs/BCHECK-RESEARCH.md fixture F4: one collaborator address per insertion point,
// appended, then `if http interactions`.
const ssrfInjectionBCheck = "metadata:\n" +
	"    language: v1-beta\n" +
	"    name: \"SSRF in each insetpoint\"\n" +
	"    description: \"Insert an Collaborator address into each parameter to detect SSRF\"\n" +
	"    author: \"xelkomy\"\n" +
	"\n" +
	"define:\n" +
	"    ssrfaddress=`{generate_collaborator_address()}`\n" +
	"\n" +
	"# we will automatically insert into nested insertion points\n" +
	"given insertion point then\n" +
	"    send payload:\n" +
	"        appending: {ssrfaddress}\n" +
	"\t\t\n" +
	"\tif http interactions then\n" +
	"        report issue:\n" +
	"            severity: high\n" +
	"            confidence: firm\n" +
	"            detail: \"SSRF Discovery by BCheck\"\n" +
	"            remediation: \"Implement SSRF remediation measures.\"\n" +
	"    end if\n"

func TestTheCorpusSSRFInjectionCheckReportsOnlyTheParameterThatCalledBack(t *testing.T) {
	c, err := Parse(ssrfInjectionBCheck)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !c.NeedsCollaborator() {
		t.Fatal("SSRFInjection.bcheck is not classified as needing a collaborator")
	}
	fc := &fakeCollab{}
	m := &mockSink{}
	ctx := collabCtx(fc)
	ctx.Request = []byte("GET /fetch?url=http://a.test/&q=x HTTP/1.1\r\nHost: x.test\r\n\r\n")
	if _, err := RunActive(c, ctx, m, tgt()); err != nil {
		t.Fatalf("run: %v", err)
	}
	ds := ctx.Deferred()
	if len(ds) != 2 || len(fc.minted) != 2 {
		t.Fatalf("deferred %d / minted %d, want 2 / 2 (one per query parameter)", len(ds), len(fc.minted))
	}
	// Only the url parameter's address is fetched.
	fc.callback(ds[0].Addresses()[0], "http")
	var fired []string
	for _, d := range ds {
		got, _, err := d.Resolve()
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		for _, f := range got {
			fired = append(fired, f.Param)
		}
	}
	if len(fired) != 1 || fired[0] != "url" {
		t.Errorf("findings at %v, want exactly one at parameter url", fired)
	}
}
