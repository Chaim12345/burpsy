// The one path from "an exchange happened" to "stored, indexed, passively scanned, DOM-analysed,
// findings recorded".
//
// # Why this is a type and not just a function the proxy happens to own
//
// The proxy reached this pipeline first, so it lived inside Server.runPassiveScan: store the
// request, store the response, index the exchange, run the passive check set, run the static DOM
// pass, enrich each finding, write it to the finding store. Six steps in a fixed order, three of
// which have honest-reporting behaviour that took a phase each to get right — CoverageTracker's
// skip counters, DOMAnalysis.Caveat, EnrichFinding's catalogue lookup.
//
// CRAWL-02 requires that crawled traffic be "captured, scoped and scanned through exactly the same
// path as proxied traffic". A second copy of those six steps would satisfy the sentence and betray
// the requirement: the copy would drift, and the first thing to drift is always the reporting, so
// the crawler would end up with a coverage story that quietly disagrees with the proxy's about the
// same response. This type is that path, extracted, so there is exactly one of it and both surfaces
// call it rather than resembling each other.
//
// # What it deliberately does not do
//
// It does not decide whether a request may be sent. Egress authorisation is
// sender.AuthorisedSender's job, on the bytes actually about to go on the wire, and it happens
// before the transport is reached — long before anything here runs. What this type is handed is an
// exchange that already happened.
//
// It also does not decide whether an exchange is *worth* scanning. PassiveScanner.Scan and
// ScanDOM each apply the engagement scope themselves and record a skip when it excludes the
// exchange (ScanSkipOutOfScope, DOMSkipOutOfScope), which is what keeps the count of "scanned and
// clean" apart from the count of "never looked". Re-checking scope here would double-count those
// skips against a single response.
package scanner

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"go.uber.org/zap"
)

// Capture bundles the four collaborators the pipeline needs. A zero-valued field is tolerated
// rather than fatal, matching what Server.runPassiveScan already did: a proxy configured without a
// scanner or a finding store still captures traffic, and a caller that wants scanning wires both.
//
// Copied by value at every call site: the four fields are handles to shared, internally-locked
// objects, so a copy addresses the same store, the same scanner and the same finding store.
type Capture struct {
	// Store receives both messages and the exchange index row. Required by Record; ScanExchange
	// needs it only for the DOM pass, which reads the response back out of it.
	Store *core.TrafficStore
	// Scanner runs the passive check set and the static DOM pass. Nil means neither runs.
	Scanner *PassiveScanner
	// Findings receives every finding produced. Nil means findings are produced and dropped, so
	// Scanner and Findings are wired together or not at all — see ScanExchange.
	Findings *core.FindingStore
	// Logger carries the DOM pass's truncation caveat. Nil is tolerated and silences it.
	Logger *zap.Logger
	// Source is the default attribution for every exchange recorded through this handle, for a surface
	// that only ever produces one kind. A CapturedExchange naming its own Source overrides it.
	//
	// Set once at construction rather than repeated per call because the failure mode is forgetting:
	// the proxy has five capture sites and a sixth would inherit the attribution rather than have to
	// remember it. That is the same reason this seam exists at all — a property that has to be restated
	// at every site is a property that will eventually be restated wrong at one of them.
	//
	// Unset means core.SourceUnattributed, and Record does not substitute anything for it. See
	// Record's own note on why that stays a legal, visible value rather than a refusal.
	Source core.Source
	// TaskID is the run every exchange and finding recorded through this handle belongs to, or 0 for
	// a surface no task owns. Carried beside Source for the same reason Source is carried here: a
	// surface sets it once, so a capture site added later inherits the attribution instead of having
	// to remember it. A CapturedExchange naming its own TaskID overrides it.
	TaskID uint64
}

// CapturedExchange is one completed request/response pair, as bytes, for Record.
//
// Bytes rather than a parsed shape: the store parses them itself, and handing it anything already
// interpreted would mean two parsers disagreeing about the same message. Host, Port, TLS, Method
// and Path are the addressing the caller knows and the raw bytes do not always carry — a proxied
// request in origin form has no host in its request line, and neither does one the crawler built.
type CapturedExchange struct {
	Host   string
	Port   uint16
	TLS    bool
	Method string
	Path   string
	// Request and Response are the exact bytes sent and received.
	Response []byte
	Request  []byte
	// RequestOriginal and RequestAuto are the request's earlier stages (burpsy-react-ui-c05), and
	// ResponseOriginal and ResponseAuto the response's — see core.Exchange's four fields for what a
	// stage is and for the rule that a variant is written only where it differs from the next one.
	//
	// Nil is the common case and means "nothing differed", so a producer that never touches bytes
	// passes nothing and stores nothing extra. Record enforces the rule rather than trusting the
	// producer: a stage equal to the one after it is not written, because the difference between
	// two identical byte slices is not information and paying a second copy of every unmodified
	// message to record "nothing changed" would undo the store's whole cost model.
	RequestOriginal  []byte
	RequestAuto      []byte
	ResponseOriginal []byte
	ResponseAuto     []byte
	// UserEdited says the operator modified this exchange by hand (Burp's history "Edited"
	// column). Carried from the producing site rather than derived here, because only that site
	// knows: it is the one that compares the bytes it showed the operator with the bytes the hold
	// returned. See core.Exchange.UserEdited for why the stage fields cannot stand in for it.
	UserEdited bool
	// Started is when the request went out and Duration how long the exchange took; both are
	// carried rather than measured here, because Record runs after the fact.
	//
	// A Duration of exactly zero is taken to mean "this producer did not time the exchange" and is
	// recorded as core.UnmeasuredDuration — see the duration method for why that reading is safe at
	// microsecond resolution and was not at millisecond resolution.
	Started  time.Time
	Duration time.Duration
	// Protocol is which protocol carried the exchange. The zero value is core.ProtocolHTTP1.
	Protocol core.Protocol
	// Source names the surface this exchange came from, so an operator reading history can tell traffic
	// their own browser produced from traffic a crawl produced.
	//
	// The zero value is core.SourceUnattributed, which is deliberate on core.Exchange's side and worth
	// repeating here: a capture that forgets to say where it came from shows as unattributed, which is
	// visible and fixable, rather than defaulting to "proxy" and reading as a plausible lie about who
	// caused the request.
	Source core.Source
	// TaskID overrides the handle's default for this one exchange. Zero means "use the handle's",
	// which is safe because registry task ids start at 1 — see dash.Registry.Start.
	TaskID uint64
	// Notes says something about this capture that its bytes cannot say for themselves.
	//
	// Carried here rather than assigned to the returned exchange afterwards, because the store's
	// observers — the durable mirror and the live site map — run inside AddExchange, so a note
	// attached after Record returns is a note neither of them ever sees. The two live uses are both
	// "the recorded bytes are not the peer's bytes, and that difference is invisible in the bytes":
	// a WebSocket handshake the proxy rewrote before forwarding, and a response the operator
	// dropped so the client received nothing.
	Notes *string
	// Highlight is the operator's colour tag on this capture, "" when unset — the
	// operator's intercept annotation riding to history (burpsy-react-ui-5q8u). Same
	// carry-here rule as Notes: the store's observers run inside AddExchange, so a
	// highlight attached afterwards is one none of them ever record. Same vocabulary
	// as core.ValidHighlights.
	Highlight string
	// ServerIP is the destination server's resolved IP for this exchange, and ListenerPort the
	// proxy listener port the request arrived on. Both empty/zero for a producer that has neither
	// in hand — see core.Exchange's fields of the same names for what each means and why they are
	// recorded here rather than derived at list time (burpsy-react-ui-mr4p, burpsy-react-ui-he81).
	ServerIP     string
	ListenerPort uint16
}

// ErrNoResponse is returned by Record when there are no response bytes to capture.
//
// It is a named error rather than a generic one because the caller has to distinguish "this attempt
// produced nothing to store" from "the store is broken", and because the invariant it protects — see
// Record — is one a future caller must be able to look up.
var ErrNoResponse = errors.New("capture: no response bytes, so there is no exchange to index")

// Record stores both messages, indexes the exchange, and scans it — the same six steps, in the same
// order, that a proxied response takes.
//
// # An indexed exchange always has a stored response
//
// This is the invariant, and it is enforced rather than merely usual: Record indexes nothing unless
// both messages are in the store. An earlier version indexed the request and left Response nil when
// there were no response bytes or when the response failed to parse, on the reasoning that a
// half-exchange is more honest than dropping one.
//
// That reasoning was wrong, and the cost is severe. internal/web/liveaudit.go's sweep walks the
// exchange index from a monotonic high-water cursor and `break`s on the first `ex.Response == nil`
// (liveaudit.go:157). A single nil-Response row therefore does not skip one exchange — it stops the
// sweep at that index **for the life of the process**, while the sweep's own counter keeps reporting
// the number it did reach. One failed crawl request would silently disable live audit and leave its
// progress counter looking healthy. A shared seam whose failure mode is "another subsystem quietly
// stops working" is not a seam worth sharing, so the failure is returned to the caller, who has a
// skip ledger to name it in.
//
// The caller therefore gets an error, not a degraded exchange, in every case where either message is
// missing: no response bytes (ErrNoResponse), a request the store rejects, or a response the store
// rejects. Nothing is indexed and nothing is scanned, because there is nothing to scan.
//
// # An unattributed source is *not* refused, and that asymmetry is deliberate
//
// The obvious next question, having tightened the response, is whether an exchange with no Source
// should be refused too, forcing every caller to name itself. It is not, because the two states fail
// in opposite directions.
//
// A row with no response *lies*: nothing can distinguish it from an exchange whose answer has not
// arrived yet, so a consumer must either stop at it or risk skipping a live one. A row with no source
// says exactly what is true — nobody claimed it — and core.Source.String renders it as
// "unattributed". Refusing it would convert an honest label into dropped traffic, which is the very
// outcome the response rule exists to prevent being created silently. It would also mean a producer
// added later cannot record anything at all until someone picks its name for it, and the failure
// would land on the capture rather than on the reporting.
//
// Attribution is enforced where it costs nothing instead: Capture.Source sets it once per surface, and
// the tests assert that every row a surface produces is attributed.
//
// # The exchange is published before it has been scanned
//
// AddExchange runs, and only then ScanExchange. So an observer that sees the exchange — a store
// observer, a test, the site map — cannot assume its findings exist yet. The order is forced: a
// finding references its exchange by id, and the id is assigned by AddExchange. It is worth stating
// because a reader reasonably guesses the other way round, and because the window is no longer
// negligible: ScanExchange now runs the static DOM pass as well as the passive check set, so the gap
// between "row visible" and "findings recorded" is milliseconds rather than microseconds. A test that
// asserts on findings straight after observing the exchange is racing this, and will lose
// intermittently.
func (c Capture) Record(x CapturedExchange) (*core.Exchange, error) {
	if len(x.Response) == 0 {
		return nil, ErrNoResponse
	}
	reqID, err := c.Store.Put(x.Request, core.DirectionRequest)
	if err != nil {
		return nil, fmt.Errorf("capture: storing the request: %w", err)
	}
	// The earlier stages, walked forward so each is compared against the stage that follows it —
	// which is the rule the store reads back with (core.Exchange.VariantFor). A failure to store an
	// *extra* copy is reported but never fatal: the exchange's own bytes are already committed, and
	// losing a variant costs the operator a comparison view, whereas refusing the exchange would
	// cost them the traffic. The error is returned only for the request/response themselves.
	reqOriginal, reqAuto := c.storeStages("request", x.RequestOriginal, x.RequestAuto, x.Request, core.DirectionRequest)

	respID, err := c.Store.Put(x.Response, core.DirectionResponse)
	if err != nil {
		// The request is already in the message log, which is append-only and has no retraction. That
		// is acceptable: an orphaned message row costs its bytes and is reachable by id, whereas an
		// exchange row with no response wedges the live-audit sweep. Nothing indexes this request, so
		// nothing will read it as a completed exchange.
		return nil, fmt.Errorf("capture: storing the response: %w", err)
	}
	respOriginal, respAuto := c.storeStages("response", x.ResponseOriginal, x.ResponseAuto, x.Response, core.DirectionResponse)
	ex := &core.Exchange{
		Request:  reqID,
		Response: &respID,

		RequestOriginal:  reqOriginal,
		RequestAuto:      reqAuto,
		ResponseOriginal: respOriginal,
		ResponseAuto:     respAuto,

		Status:      storedStatus(c.Store, respID),
		Host:        x.Host,
		Port:        x.Port,
		TLS:         x.TLS,
		Method:      x.Method,
		Path:        x.Path,
		Duration:    x.duration(),
		StartedMs:   uint64(x.Started.UnixMilli()),
		Protocol:    x.Protocol,
		ResponseLen: len(x.Response),
		// Denormalised here because this is where the response bytes are, and history must never read
		// them again to answer "what type was it". See core.Exchange.Mime. This is the seam nearly all
		// proxy traffic comes through, so it is the site that decides whether the History MIME column
		// and filter have anything to work with at all.
		Mime: core.MimeEssence(x.Response),
		// Same seam as Mime: the bytes are here, so the derived columns are decided here.
		Cookies:   core.CookieNames(x.Response),
		Title:     core.ResponseTitle(x.Response),
		Notes:     x.Notes,
		Highlight: x.Highlight,
		// The per-exchange source wins when it is set, so a surface with a default can still record one
		// exchange as something else; otherwise the handle's default applies. Neither is substituted for
		// the other when both are unset — unattributed is a real answer, see above.
		Source: sourceOf(x.Source, c.Source),
		TaskID: taskOf(x.TaskID, c.TaskID),
		// Carried, not derived — the producing site is the only one that saw both the bytes it showed
		// the operator and the bytes the hold returned. See core.Exchange.UserEdited.
		UserEdited: x.UserEdited,
		// Carried, never derived. Both describe sockets that are closed by the time a row is
		// listed, so this seam is the only place either answer exists.
		ServerIP:     x.ServerIP,
		ListenerPort: x.ListenerPort,
	}
	c.Store.AddExchange(ex)
	c.ScanExchange(ex)
	return ex, nil
}

// storeStages writes the earlier stages of one message and returns the ids worth recording, or nil
// nils when nothing differed (burpsy-react-ui-c05).
//
// It walks forward — original against auto, auto against the final — so the two comparisons are the
// same ones core.Exchange.VariantFor walks backwards to read. Both directions having to agree is why
// the rule lives in one place per side rather than being re-decided at each capture site, and it is
// the reason a stage is dropped when it is byte-identical to the next: two references to one message
// would be the store's honest shape for "nothing changed", but a *fourth* copy of an unmodified
// message per exchange is not, and the difference is what keeps this feature from multiplying the
// resident set by three.
//
// A failure to store an extra stage is logged and the stage is dropped rather than failing the
// capture: the exchange's own bytes are already committed, and losing a comparison view costs the
// operator far less than losing the traffic. Under-recorded and said so, which is this project's
// direction for every partial result.
func (c Capture) storeStages(what string, original, auto, final []byte, dir core.Direction) (origID, autoID *core.MsgId) {
	if auto == nil && original == nil {
		return nil, nil
	}
	keep := func(stage []byte, next []byte) *core.MsgId {
		if stage == nil || bytes.Equal(stage, next) {
			return nil
		}
		id, err := c.Store.Put(stage, dir)
		if err != nil {
			if c.Logger != nil {
				c.Logger.Warn("capture: keeping the earlier stage of a message failed, so this exchange records only the later one",
					zap.String("message", what), zap.Error(err))
			}
			return nil
		}
		return &id
	}
	// Auto is compared against the final first; the original is then compared against auto when auto
	// was kept, and against the final when it was not — which is exactly "compared against the next
	// stage that exists".
	autoID = keep(auto, final)
	next := final
	if autoID != nil {
		next = auto
	}
	origID = keep(original, next)
	return origID, autoID
}

// duration reads CapturedExchange.Duration as a measurement or as the absence of one.
//
// Zero means unmeasured, and that reading is sound precisely because core.ExchangeDuration counts
// microseconds. A real exchange — a socket write, a wait, a read — cannot complete in zero microseconds
// on a monotonic clock, so an exact zero is a producer that never set the field. At millisecond
// resolution the same rule would have been wrong for every loopback fetch, which is the whole reason
// the underlying representation changed rather than just its accessors.
//
// A producer that measures and legitimately wants to record "under a microsecond" gets
// core.MeasuredDuration on the exchange it builds itself; this seam's contract is the zero rule, stated
// on the field.
func (x CapturedExchange) duration() core.ExchangeDuration {
	if x.Duration == 0 {
		return core.UnmeasuredDuration()
	}
	return core.MeasuredDuration(x.Duration)
}

// sourceOf picks the attribution for one row: what the exchange named, else what the handle defaults
// to. A named function rather than an inline `if` so the precedence is stated once and can be tested
// on its own.
func sourceOf(perExchange, handleDefault core.Source) core.Source {
	if perExchange.Attributed() {
		return perExchange
	}
	return handleDefault
}

// taskOf resolves a per-exchange task id against the handle's default, the same precedence sourceOf
// applies. Zero means "unset" on both sides, which is unambiguous only because registry ids start at
// 1 — see dash.Registry.Start.
func taskOf(perExchange, handleDefault uint64) uint64 {
	if perExchange != 0 {
		return perExchange
	}
	return handleDefault
}

// storedStatus reads the status code back off the stored response's parsed shape.
//
// Through the store rather than with a status-line parser of its own: core.Parse has already split
// that line, and a second parser here could disagree with the one the whole store is indexed by.
// A response whose status token is not a number yields nil — absent, which Exchange.Status already
// models — rather than a zero that would read as a real status code.
func storedStatus(store *core.TrafficStore, id core.MsgId) *uint16 {
	if store == nil {
		return nil
	}
	msg, err := store.Get(id)
	if err != nil {
		return nil
	}
	code, err := strconv.Atoi(msg.Text(msg.Shape.SecondToken))
	if err != nil || code < 100 || code > 599 {
		return nil
	}
	u := uint16(code)
	return &u
}

// ScanExchange runs the passive check set and the static DOM pass over an already-indexed exchange
// and writes every finding into the finding store.
//
// This is verbatim what Server.runPassiveScan did, moved so that the crawler reaches the same code
// rather than a lookalike. Scanner and Findings are checked together because a scan whose findings
// go nowhere is work done for nothing, and a finding store fed by no scanner has nothing to hold.
func (c Capture) ScanExchange(ex *core.Exchange) {
	if c.Scanner == nil || c.Findings == nil {
		return
	}
	findings := c.Scanner.Scan(ex)

	// Static DOM analysis reads the same captured response as the passive check set, so it belongs
	// at the same call site rather than behind a second dispatch. Its caveat is logged rather than
	// discarded: a DOM pass that hit its per-item budget analysed only part of the item, and
	// letting that land in the finding store as an ordinary "nothing more here" is exactly what
	// DOM-03 forbids.
	dom := c.Scanner.ScanDOM(ex)
	if caveat := dom.Caveat(); caveat != "" && dom.Skip == nil && c.Logger != nil {
		c.Logger.Warn("static DOM analysis did not cover the whole response",
			zap.String("host", ex.Host),
			zap.String("path", ex.Path),
			zap.String("caveat", caveat))
	}
	findings = append(findings, dom.Findings()...)

	for _, f := range findings {
		EnrichFinding(f)
		nf := core.NewFinding{
			Name:        f.Name,
			Severity:    core.ParseSeverity(f.Severity),
			Confidence:  core.ParseConfidence(f.Confidence),
			Description: f.Description,
			Remediation: f.Solution,
			Param:       f.Param,
			// The dedup target, taken from the exchange in hand rather than resolved later. This is
			// the path that produces the most duplicates by far — a passive check re-fires on every
			// response — so it is the one that most needs the store to be able to merge.
			Target: core.FindingTarget{Host: ex.Host, Port: ex.Port, TLS: ex.TLS, Path: ex.Path},
		}
		nf.TaskID = ex.TaskID
		if ex.Response != nil {
			nf.Occurrences = []core.Occurrence{{
				ExchangeID: ex.ID,
				Request:    ex.Request,
				Response:   ex.Response,
			}}
		}
		c.Findings.Add(nf)
	}
}
