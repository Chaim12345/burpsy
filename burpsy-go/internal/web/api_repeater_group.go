package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/toollog"
)

// ---- Repeater: send a tab group ----------------------------------------------------------------
//
// Burp grows a dropdown arrow beside Send when the active tab belongs to a group, offering three ways
// to send the whole group. This is that endpoint. The three modes are not three implementations: two
// of them fan /api/repeater/send's own wire half (Server.sendOneRepeaterRequest) out over the group,
// sequentially or concurrently, and only the single-connection mode needs anything new — one socket
// carrying every request in tab order, which is sender.SendKeepAlive.
//
// # What the single-connection mode is for
//
// Every send this tool made before this endpoint dialled fresh and closed, which cannot represent an
// HTTP request smuggling or a client-side desync at all: the evidence in both is what the *second*
// request on a reused socket is treated as, and there was no way to put a second request on a reused
// socket from Repeater. internal/sender/pipeline.go is the primitive that fixes that, and it had no
// caller outside the sender's own tests until this file.
//
// # Authorisation
//
// pipeline.go's package doc is explicit that its primitives carry no scope handle and that a caller
// MUST run every raw request through ScopeChecker.AuthoriseRaw — one call per raw, because "a smuggled
// prefix can address a different target than the socket it rides in on". sendGroupOnOneConnection does
// exactly that, per item, and refuses the whole group before dialling if any item fails. That
// refuse-before-any-send order is the same validate-all-before-apply contract repeaterSendOptions has:
// a group that put three requests on the wire and then refused the fourth would already have sent
// traffic the operator's group was not authorised to send in full.

const (
	// repeaterGroupSequenceSingleConn sends every request in tab order down one shared socket. HTTP/1.1
	// keep-alive, via sender.SendKeepAlive: write one, read its response, write the next on the same
	// connection. True HTTP/2 multiplexing on one connection is a separate piece of work
	// (burpsy-react-ui-745) and is deliberately not what this mode claims to be.
	repeaterGroupSequenceSingleConn = "sequence_single_conn"
	// repeaterGroupSequenceSeparateConn sends every request in tab order, each on its own fresh
	// connection — the ordinary single send, N times, one after another.
	repeaterGroupSequenceSeparateConn = "sequence_separate_conn"
	// repeaterGroupParallel fires every request at once, each on its own connection. This is the
	// race-condition workflow: the whole point is that the requests overlap in time at the target.
	repeaterGroupParallel = "parallel"

	// repeaterGroupMaxItems bounds one group send. A Repeater group is tabs an operator made by hand, so
	// this is far above any real group; it is here because an endpoint that fans out concurrently must
	// name its own ceiling rather than let a caller decide how much traffic one POST becomes.
	repeaterGroupMaxItems = 64
)

// repeaterGroupSendReq is an ordered group send: the mode, and the group's tabs in tab order.
type repeaterGroupSendReq struct {
	// Mode is one of the three constants above. An unknown mode is refused rather than defaulted:
	// silently sending on separate connections when the caller asked for one socket would answer a
	// different question from the one asked, and the difference is the entire feature.
	Mode string `json:"mode"`
	// Items is the group in the order the requests go out. Order is the caller's — the panel sends the
	// group's tabs in the order the tab strip shows them — and it is preserved exactly, because in a
	// smuggling or desync test which request is first is the test.
	Items []repeaterGroupSendItem `json:"items"`
}

// repeaterGroupSendItem is one tab's send within a group: the same payload /api/repeater/send takes,
// plus the tab id the result is keyed by so the panel can put each response in the tab that produced it.
type repeaterGroupSendItem struct {
	// TabID is opaque to the server and is echoed back on this item's result. It is the only thing that
	// lets the panel append N results to N different tab histories rather than N to one.
	TabID        string               `json:"tab_id"`
	Target       string               `json:"target"`
	Protocol     string               `json:"protocol"`
	Request      string               `json:"request"`
	FromExchange *core.ExchangeID     `json:"from_exchange,omitempty"`
	Options      *repeaterSendOptions `json:"options,omitempty"`
}

// repeaterGroupSendResp is the group's outcome: one result per item, in the order they were sent.
type repeaterGroupSendResp struct {
	// Mode is the mode that actually ran, echoed so a client can never render one mode's results under
	// another mode's label.
	Mode  string                    `json:"mode"`
	Items []repeaterGroupItemResult `json:"items"`
	// SharedConnection names the authority the one socket addressed, and is present only for
	// sequence_single_conn. It is the claim the mode makes, said out loud: every item in this response
	// rode that one connection.
	SharedConnection string `json:"shared_connection,omitempty"`
	// BatchDurationMs is the wall time of the whole group send. For sequence_single_conn it is the only
	// honest timing available — see repeaterGroupItemResult.DurationMeasured — and for parallel it is
	// the fact a per-request duration cannot give you: how long the group took as one unit.
	BatchDurationMs uint64 `json:"batch_duration_ms"`
	// FollowedRedirects says whether this mode applied each send's redirect policy at all. False for
	// sequence_single_conn: a redirect hop is a new request to whatever a Location named, on a new
	// connection, so following one would leave the shared socket — the only thing that mode exists to
	// keep. Reported rather than left implicit, because "no chain" and "we did not look" are different
	// facts and an operator who set a redirect policy is owed the difference.
	FollowedRedirects bool `json:"followed_redirects"`
}

// repeaterGroupItemResult is one tab's outcome. Result is the exact shape /api/repeater/send returns,
// so the panel renders a group send's results with the code it already has.
//
// Result and Error are not exclusive. A response whose head arrived and whose body then failed to
// delimit is precisely the evidence a smuggling test is looking for, so those bytes are reported *and*
// the failure is named; discarding either half would be the defect.
type repeaterGroupItemResult struct {
	TabID string `json:"tab_id"`
	// Result is nil only when nothing came back at all — no bytes, no exchange row.
	Result *repeaterSendResp `json:"result,omitempty"`
	// Error names what went wrong, empty when nothing did.
	Error string `json:"error,omitempty"`
	// Framing names the HTTP/1.1 rule that delimited this response's body — "content-length",
	// "chunked", "eof" or "none". Present only for sequence_single_conn, where it is the comparison a
	// framing-disagreement test is made of; empty elsewhere, because a fresh-connection send reads one
	// response and has no second take to compare it against. See sender.PipelinedExchange.Framing.
	Framing string `json:"framing,omitempty"`
	// ResponseComplete is false when the response was not read to a boundary this process is confident
	// of. A pointer because it is only knowable for sequence_single_conn: nil means "not applicable
	// here", which is a different statement from false.
	ResponseComplete *bool `json:"response_complete,omitempty"`
	// DurationMeasured is false when Result.DurationMs is not a measurement. It is false for every
	// sequence_single_conn item: sender.SendKeepAlive owns the write/read loop and reports no
	// per-exchange timing, so this endpoint has none to give, and writing the batch total onto each
	// item would be a number that looks measured and is not. BatchDurationMs is the real one.
	DurationMeasured bool `json:"duration_measured"`
}

func (s *Server) handleRepeaterSendGroup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req repeaterGroupSendReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	switch req.Mode {
	case repeaterGroupSequenceSingleConn, repeaterGroupSequenceSeparateConn, repeaterGroupParallel:
	default:
		http.Error(w, fmt.Sprintf("refused: unknown mode %q (want %s, %s or %s)", req.Mode,
			repeaterGroupSequenceSingleConn, repeaterGroupSequenceSeparateConn, repeaterGroupParallel),
			http.StatusBadRequest)
		return
	}
	if len(req.Items) == 0 {
		http.Error(w, "refused: a group send needs at least one request", http.StatusBadRequest)
		return
	}
	if len(req.Items) > repeaterGroupMaxItems {
		http.Error(w, fmt.Sprintf("refused: %d requests in one group send, and the cap is %d",
			len(req.Items), repeaterGroupMaxItems), http.StatusBadRequest)
		return
	}

	// Every item is prepared — target parsed, options validated, transforms applied, host-level scope
	// gate cleared — before any of them is sent. A refusal is the whole group's refusal: see the
	// authorisation note at the top of this file for why partial egress is not an option here.
	specs := make([]repeaterSendSpec, len(req.Items))
	seen := make(map[string]struct{}, len(req.Items))
	for i, item := range req.Items {
		if item.TabID == "" {
			http.Error(w, fmt.Sprintf("refused: item %d names no tab_id, so its result could not be routed back to a tab", i),
				http.StatusBadRequest)
			return
		}
		if _, dup := seen[item.TabID]; dup {
			http.Error(w, fmt.Sprintf("refused: tab_id %q appears twice, and one tab cannot be two positions in one group send", item.TabID),
				http.StatusBadRequest)
			return
		}
		seen[item.TabID] = struct{}{}
		spec, code, err := s.prepareRepeaterSend(item.Target, item.Protocol, item.Request, item.Options, item.FromExchange)
		if err != nil {
			// Named by tab, not by index: the operator is looking at a tab strip, and "item 2" is not
			// something they can act on.
			http.Error(w, fmt.Sprintf("%s (tab %s)", err.Error(), item.TabID), code)
			return
		}
		specs[i] = spec
	}

	ctx := r.Context()
	started := time.Now()
	var items []repeaterGroupItemResult
	shared := ""
	switch req.Mode {
	case repeaterGroupSequenceSingleConn:
		var err error
		items, shared, err = s.sendGroupOnOneConnection(ctx, req.Items, specs, started)
		if err != nil {
			// A dial failure or a mismatched authority: nothing was sent, so there is no per-item
			// outcome to report and a 200 carrying N empty results would claim otherwise.
			code := http.StatusBadGateway
			var refusal repeaterGroupRefusal
			if errors.As(err, &refusal) {
				code = refusal.code
			}
			http.Error(w, err.Error(), code)
			return
		}
	case repeaterGroupSequenceSeparateConn:
		items = s.sendGroupSequentially(ctx, req.Items, specs)
	case repeaterGroupParallel:
		items = s.sendGroupInParallel(ctx, req.Items, specs)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(repeaterGroupSendResp{
		Mode:             req.Mode,
		Items:            items,
		SharedConnection: shared,
		BatchDurationMs:  uint64(time.Since(started).Milliseconds()),
		// True for both separate-connection modes because each item runs the ordinary single send,
		// redirect policy included. False for the shared socket — see the field's doc comment.
		FollowedRedirects: req.Mode != repeaterGroupSequenceSingleConn,
	})
}

// repeaterGroupRefusal is a group-send refusal that already knows its HTTP status, so the handler does
// not have to re-derive "was that a scope refusal or a dial failure" from an error string.
type repeaterGroupRefusal struct {
	code int
	err  error
}

func (r repeaterGroupRefusal) Error() string { return r.err.Error() }
func (r repeaterGroupRefusal) Unwrap() error { return r.err }

// sendGroupSequentially runs the ordinary single send once per item, in order, each on its own fresh
// connection.
//
// A failure does not stop the sequence: the later tabs are a different request each, the operator asked
// for all of them, and abandoning them would leave the group half-sent with no record of the rest. Each
// item carries its own error instead. (The single-connection mode is the one place where a failure
// genuinely is fatal to what follows — there, the socket is shared.)
func (s *Server) sendGroupSequentially(
	ctx context.Context, sent []repeaterGroupSendItem, specs []repeaterSendSpec,
) []repeaterGroupItemResult {
	items := make([]repeaterGroupItemResult, len(specs))
	for i := range specs {
		items[i] = s.sendGroupItemOnItsOwnConnection(ctx, sent[i].TabID, specs[i])
	}
	return items
}

// sendGroupInParallel fires every item at once, each on its own connection, and waits for all of them.
//
// Results are written to their own index rather than appended, so the response order is tab order no
// matter which request finishes first: the operator reads the results against the tab strip, and a
// list that reordered itself by latency would make the fastest tab look like the first one sent.
//
// Every goroutine here is doing exactly what sendGroupSequentially's loop body does — the concurrency is
// the only difference, which is the point of the mode. The store is mutex-guarded (core.TrafficStore.Put
// and AddExchange both take the write lock), and the scope is read concurrently by the intruder's own
// fan-out already, so neither is new ground.
func (s *Server) sendGroupInParallel(
	ctx context.Context, sent []repeaterGroupSendItem, specs []repeaterSendSpec,
) []repeaterGroupItemResult {
	items := make([]repeaterGroupItemResult, len(specs))
	var wg sync.WaitGroup
	for i := range specs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			items[i] = s.sendGroupItemOnItsOwnConnection(ctx, sent[i].TabID, specs[i])
		}(i)
	}
	wg.Wait()
	return items
}

// sendGroupItemOnItsOwnConnection is one item of a separate-connection mode: the ordinary single send,
// with its failure recorded as this item's error rather than as the group's.
func (s *Server) sendGroupItemOnItsOwnConnection(
	ctx context.Context, tabID string, spec repeaterSendSpec,
) repeaterGroupItemResult {
	resp, err := s.sendOneRepeaterRequest(ctx, spec)
	if err != nil {
		return repeaterGroupItemResult{TabID: tabID, Error: err.Error()}
	}
	// DurationMeasured is true here and only here: this item had its own connection and its own
	// stopwatch, so resp.DurationMs is a measurement.
	return repeaterGroupItemResult{TabID: tabID, Result: &resp, DurationMeasured: true}
}

// sendGroupOnOneConnection puts every request in the group down one socket, in order, through
// sender.SendKeepAlive.
//
// Two refusals happen before the dial, and both are the whole group's:
//
//   - One socket addresses one authority. A group whose tabs name different targets cannot be sent on
//     one connection, and picking the first tab's authority for all of them would send the other tabs'
//     bytes to a host their target line did not name — which is the exact confusion the per-raw
//     AuthoriseRaw gate below exists to prevent, committed on purpose.
//   - Every raw request clears ScopeChecker.AuthoriseRaw individually, as pipeline.go requires. This is
//     stricter than the single send's host-level gate — it reads the request line out of the bytes and
//     checks that path against scope — and it is stricter deliberately: a request that shares a socket
//     with another is the one case where the path in the bytes is not necessarily the path the socket's
//     authority implies.
//
// That second point makes this mode measurably stricter than the two separate-connection modes, and
// the difference is worth naming because it is not subtle: core.Scope.MayContainHost, which is the gate
// /api/repeater/send has always used and which the other two modes therefore inherit unchanged, answers
// "could any request to this host be in scope". It refuses a host that matches no include rule outright
// — the day this used to answer true for such a host, sending to it was the scope bug this tightening
// fixed. What it still waves through is a *path* within an included host: a path-scoped include
// (`include(h, "/allowed")`) makes the whole host possible to the pre-filter even though Contains, and
// therefore AuthoriseRaw, refuse paths outside it. So the shared-socket mode, which runs AuthoriseRaw
// per raw, refuses a request to /blocked that the single send — matching both separate-connection
// modes — sends out. That residual asymmetry is not something this endpoint invented and it is not
// something it can fix here: MayContainHost is the gate the single send, the intruder and the proxy
// pre-filter all share, and tightening it further is a decision above one endpoint's pay grade.
// TestRepeaterGroupSharedSocketIsStricterThanTheHostLevelGateTheOtherModesInherit pins it.
//
// SendKeepAlive rather than SendPipelined because "in sequence" is what the mode says and what it must
// do: write one request, read its whole response, then write the next on the same connection. That
// ordering is what makes the second request's *treatment* the evidence, and pipeline.go's own comment
// records why the two are separate primitives — a pipelined write can mask a server that closes the
// connection between requests, which is the behaviour this mode is most often used to expose.
// SendPipelined therefore still has no caller here; a pipelined-write mode would be its own mode with
// its own label, not this one relabelled.
func (s *Server) sendGroupOnOneConnection(
	ctx context.Context, sent []repeaterGroupSendItem, specs []repeaterSendSpec, started time.Time,
) ([]repeaterGroupItemResult, string, error) {
	first := specs[0]
	for i, spec := range specs {
		if spec.Host != first.Host || spec.Port != first.Port || spec.TLS != first.TLS {
			return nil, "", repeaterGroupRefusal{code: http.StatusBadRequest, err: fmt.Errorf(
				"refused: one connection addresses one target, and this group names two — tab %s is %s and tab %s is %s. "+
					"Send it on separate connections, or point the group's tabs at one target",
				sent[0].TabID, repeaterAuthority(first), sent[i].TabID, repeaterAuthority(spec))}
		}
	}
	// Per raw, before anything is written. See this function's doc comment and pipeline.go's package
	// doc: the batch entry points authorise one call per raw precisely because the requests share a
	// socket, and a refusal here refuses the group rather than the item — nothing has been sent yet,
	// and it must stay that way.
	raws := make([][]byte, len(specs))
	for i, spec := range specs {
		if err := s.scope.AuthoriseRaw(spec.Host, spec.Port, spec.TLS, spec.Raw); err != nil {
			return nil, "", repeaterGroupRefusal{code: http.StatusForbidden, err: fmt.Errorf(
				"%s (tab %s, on the shared connection every request is authorised individually)", err.Error(), sent[i].TabID)}
		}
		raws[i] = spec.Raw
	}

	exchanges, err := s.sender.SendKeepAlive(ctx, first.Host, first.Port, first.TLS, raws)
	if err != nil {
		// SendKeepAlive's error return is reserved for a failure before any exchange could be attempted
		// — the dial. Nothing went out, so this is the group's failure, not an item's.
		s.toolLog.Record(toollog.ToolRepeater, first.Host, first.Port, first.TLS, "SEND-GROUP", "", 0, nil, 0, err.Error(), nil)
		return nil, "", err
	}

	items := make([]repeaterGroupItemResult, len(specs))
	for i, exchange := range exchanges {
		items[i] = repeaterGroupItemResult{TabID: sent[i].TabID, Framing: exchange.Framing}
		complete := exchange.ResponseComplete
		items[i].ResponseComplete = &complete
		if exchange.ReadErr != nil {
			items[i].Error = exchange.ReadErr.Error()
		}
		if len(exchange.Response) == 0 {
			// Nothing came back for this request — it was never written, or the peer closed before
			// answering. No bytes means no exchange row: an empty response recorded as a send would be
			// indistinguishable in history from a target that answered with nothing.
			if items[i].Error == "" {
				items[i].Error = "no response bytes arrived on the shared connection, and no reason was reported"
			}
			s.toolLog.Record(toollog.ToolRepeater, first.Host, first.Port, first.TLS, "SEND", "", 0, nil, 0, items[i].Error, nil)
			continue
		}
		// Whatever arrived is recorded even when the read did not complete: a head without a
		// delimitable body is the ambiguity a smuggling test is reading, so those bytes are evidence
		// and the exchange row is where evidence lives. The item still carries the error above.
		//
		// core.ProtocolHTTP1 is not a guess: sender.dialOne offers only http/1.1 on this path
		// (alpn.EgressOffer(false)), because pipelining and keep-alive desync are HTTP/1.1-specific.
		// core.UnmeasuredDuration because there is no per-exchange timing to report — see
		// repeaterGroupItemResult.DurationMeasured.
		resp, _ := s.recordRepeaterExchange(specs[i], exchange.Response, core.ProtocolHTTP1, core.UnmeasuredDuration(), started)
		items[i].Result = &resp
	}
	return items, repeaterAuthority(first), nil
}

// repeaterAuthority renders one spec's target the way a refusal should name it.
func repeaterAuthority(spec repeaterSendSpec) string {
	scheme := "http"
	if spec.TLS {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s:%d", scheme, spec.Host, spec.Port)
}
