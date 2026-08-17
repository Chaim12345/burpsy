package scanner

// The stored (second-order) rows: the planting producer plus the evaluators that read it.
//
// # Why planting is separate from observing
//
// StoredLedger correlates a canary with the exchange it surfaces in. PlantStoredCanaries is the
// half that puts canaries into the target: it walks an endpoint's insertion points, plants one
// token in each, and records it before the send so a submission that times out is still tracked.
//
// The observing half is ActiveScanner.ObserveStoredCanaries, called from auditItem for every
// exchange a scan audits. This comment previously asserted that feeding already happened, and it
// did not — the function existed and only the tests called it, so the ledger's observation set
// stayed empty and every row in this file was wired, counted as coverage, and unable to report
// anything. The wiring is what makes these rows real; if it is ever removed, they should go back
// to being declined rather than stay silently runnable.
//
// # What a stored check can and cannot conclude
//
// A stored finding needs the canary to surface in an exchange *other* than the one that planted
// it. Until that happens the canary is Outstanding, which is not a clean result — the payload
// may be awaiting moderation or live on a page the crawl has not reached. Every evaluator here
// returns no finding in that state, and the ledger's Summarise() is what a report must use to
// say how much planted input is still unaccounted for.
//
// # Which scan modes can actually complete the cycle
//
// Planting happens while auditing exchange A; observing happens when the scan audits an exchange
// whose response carries the canary. In a BATCH audit over already-captured traffic that cycle
// cannot close: every stored response predates the planting, so nothing a batch scan observes can
// contain a token it has only just invented. Batch mode therefore produces Outstanding canaries and
// no stored findings, which is honest but easy to mistake for "the target has no stored injection".
//
// The cycle closes when new traffic arrives after planting — the live-proxy path, where the operator
// or a crawler revisits the page that renders the planted input, and internal/web's live audit then
// audits that fresh exchange. The alternative, not yet built, is for the scan to re-fetch the URLs
// it planted into once probing is finished, which would make batch mode work too. Until then
// Summarise()'s Outstanding count is the only truthful thing a batch report can say about this
// family, and a caller that omits it is claiming coverage this file did not provide.

import (
	"context"
	"fmt"
	"strings"

	"github.com/burpsy-go/burpsy/internal/core"
)

func storedChecksEnabled(c *ScanConfig) bool { return c != nil && c.CheckStored }

// MaxStoredPlantsPerExchange bounds how many canaries one exchange contributes, so an endpoint
// with fifty parameters does not fill the ledger from a single request.
const MaxStoredPlantsPerExchange = 8

// PlantStoredCanaries submits one canary per insertion point and records each in the ledger.
//
// It returns the canaries it planted. Sends that fail are still recorded: a submission the
// transport gave up on may have reached the application anyway, and dropping the token would
// leave input in the target that nothing is looking for.
func PlantStoredCanaries(ctx context.Context, cc *CheckContext) ([]StoredCanary, error) {
	ledger, err := cc.StoredLedger()
	if err != nil {
		return nil, err
	}
	h, err := NewProbeHarness(ctx, cc, DefaultProbeInsertionKinds)
	if err != nil {
		return nil, err
	}
	points := h.Points()
	if len(points) > MaxStoredPlantsPerExchange {
		points = points[:MaxStoredPlantsPerExchange]
	}

	var planted []StoredCanary
	for _, point := range points {
		canary, err := ledger.Plant(cc.Exchange.ID, cc.Exchange.Path, point.Name)
		if err != nil {
			continue
		}
		planted = append(planted, canary)
		// The send's outcome does not change whether the canary is tracked.
		_, _ = h.Send(ctx, point, canary.Token)
	}
	return planted, nil
}

// storedSightingFor returns a second-order sighting whose canary surfaced in this exchange, if
// any, together with the surrounding response text so a caller can judge context.
func storedSightingFor(cc *CheckContext) (StoredObservation, string, bool) {
	ledger, err := cc.StoredLedger()
	if err != nil {
		return StoredObservation{}, "", false
	}
	body := responseBody(responseRaw(cc.Scanner, cc.Exchange))
	if body == "" {
		return StoredObservation{}, "", false
	}
	lower := strings.ToLower(body)
	for _, o := range ledger.SecondOrderObservations() {
		if o.SeenIn != cc.Exchange.ID {
			continue
		}
		if !strings.Contains(lower, strings.ToLower(o.Canary.Token)) {
			continue
		}
		return o, body, true
	}
	return StoredObservation{}, "", false
}

// storedContextCheck builds an evaluator that fires when a planted canary surfaces in this
// exchange and the surrounding markup puts it in the context the row is about.
//
// context decides the row: a canary inside a <script> block is stored JavaScript injection, one
// inside an href is stored link manipulation, and one merely present in the body is stored input
// reflection. Without that distinction one sighting would fire every stored row at once.
func storedContextCheck(row, severity string, inContext func(body, token string) (string, bool)) CheckRunner {
	return func(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
		if cc == nil || cc.Scanner == nil || cc.Exchange == nil {
			return nil, nil
		}
		ledger, err := cc.StoredLedger()
		if err != nil {
			return nil, err
		}
		// Plant into this endpoint's own inputs first, once per exchange however many
		// stored rows audit it. A canary planted here can only ever be confirmed by a
		// later exchange, which is what makes the finding second-order.
		if ledger.ClaimPlanting(cc.Exchange.ID) {
			if _, err := PlantStoredCanaries(ctx, cc); err != nil {
				return nil, err
			}
		}
		o, body, ok := storedSightingFor(cc)
		if !ok {
			// Nothing has surfaced yet, and nothing could have: every response this scan holds
			// was captured before the planting above. Returning nil here was the defect - it
			// reported a clean second-order result at the one moment the answer was guaranteed
			// to be unavailable. The claim is handed to the registry instead, and FinishScan
			// asks again after re-fetching the pages that might render it.
			return nil, deferStoredClaim(cc, row, severity, inContext)
		}
		evidence, matched := inContext(body, o.Canary.Token)
		if !matched {
			return nil, nil
		}
		return []*Finding{buildHeaderFinding(cc, row, severity, "firm", evidence,
			fmt.Sprintf("a value submitted to %s (parameter %q) in exchange %d is rendered here",
				o.Canary.OriginPath, o.Canary.InsertionPoint, o.Canary.Origin))}, nil
	}
}

// deferStoredClaim hands this row's canaries to the pending registry and returns the sentinel that
// makes the audit count the check as undecided.
//
// It is deliberately per-row rather than per-canary: each stored row decides a different context
// for the same sighting, so all of them are waiting on the same token and each must judge it with
// its own matcher when it arrives.
func deferStoredClaim(cc *CheckContext, row, severity string,
	inContext func(body, token string) (string, bool)) error {

	outstanding := cc.Scanner.stored.Outstanding()
	if len(outstanding) == 0 {
		// Nothing was planted here at all - no inputs to plant into. There is no claim to defer
		// and nothing was suppressed, so a clean result is the truth.
		return nil
	}

	deadline := nowUTC().Add(DefaultPendingDeadline)
	if cc.Config != nil && cc.Config.PendingDeadline > 0 {
		deadline = nowUTC().Add(cc.Config.PendingDeadline)
	}
	err := cc.Scanner.Pending().Register(PendingItem{
		Row:      row,
		Exchange: cc.Exchange.ID,
		Deadline: deadline,
		What: fmt.Sprintf("%d canary(ies) planted in %s, awaiting a sighting on another page",
			len(outstanding), cc.Exchange.Path),
	}, func(context.Context) (*Finding, bool, error) {
		for _, o := range cc.Scanner.stored.SecondOrderObservations() {
			body := responseBody(responseRaw(cc.Scanner, sightingExchange(cc.Scanner, o.SeenIn)))
			if body == "" {
				continue
			}
			evidence, matched := inContext(body, o.Canary.Token)
			if !matched {
				continue
			}
			return buildHeaderFinding(cc, row, severity, "firm", evidence,
				fmt.Sprintf("a value submitted to %s (parameter %q) in exchange %d is rendered in exchange %d",
					o.Canary.OriginPath, o.Canary.InsertionPoint, o.Canary.Origin, o.SeenIn)), true, nil
		}
		return nil, false, nil
	})
	if err != nil {
		return err
	}
	return fmt.Errorf("%s: canaries planted, no sighting yet: %w", row, errCheckInconclusive)
}

// sightingExchange resolves the exchange a canary was seen in, so its body can be re-read for the
// per-row context decision.
func sightingExchange(s *ActiveScanner, id core.ExchangeID) *core.Exchange {
	if s == nil || s.store == nil {
		return nil
	}
	ex, err := s.store.GetExchange(id)
	if err != nil {
		return nil
	}
	return ex
}

// contextAnywhere matches a canary wherever it appears.
func contextAnywhere(body, token string) (string, bool) {
	i := indexFold(body, token)
	if i < 0 {
		return "", false
	}
	return excerpt(body, i, len(token)), true
}

// contextInsideTag matches a canary appearing between an opening and closing tag.
func contextInsideTag(tag string) func(string, string) (string, bool) {
	open, close := "<"+tag, "</"+tag
	return func(body, token string) (string, bool) {
		lower := strings.ToLower(body)
		pos := 0
		for {
			start := strings.Index(lower[pos:], strings.ToLower(open))
			if start < 0 {
				return "", false
			}
			start += pos
			end := strings.Index(lower[start:], strings.ToLower(close))
			if end < 0 {
				return "", false
			}
			end += start
			if indexFold(body[start:end], token) >= 0 {
				return excerpt(body, start, end-start), true
			}
			pos = end + len(close)
		}
	}
}

// contextInAttribute matches a canary appearing inside the named attribute's value.
func contextInAttribute(attr string) func(string, string) (string, bool) {
	return func(body, token string) (string, bool) {
		lower := strings.ToLower(body)
		needle := strings.ToLower(attr) + "="
		pos := 0
		for {
			at := strings.Index(lower[pos:], needle)
			if at < 0 {
				return "", false
			}
			at += pos
			// Bound the attribute value at the next quote or whitespace.
			rest := body[at+len(needle):]
			end := len(rest)
			if len(rest) > 0 && (rest[0] == '"' || rest[0] == '\'') {
				if q := strings.IndexByte(rest[1:], rest[0]); q >= 0 {
					end = q + 1
				}
			} else if sp := strings.IndexAny(rest, " \t\r\n>"); sp >= 0 {
				end = sp
			}
			if indexFold(rest[:end], token) >= 0 {
				return excerpt(body, at, len(needle)+end), true
			}
			pos = at + len(needle)
		}
	}
}

func indexFold(haystack, needle string) int {
	return strings.Index(strings.ToLower(haystack), strings.ToLower(needle))
}

// excerpt returns a bounded slice around a match, so evidence text names the surrounding
// markup without carrying a whole page.
func excerpt(body string, at, length int) string {
	const pad = 40
	start := at - pad
	if start < 0 {
		start = 0
	}
	end := at + length + pad
	if end > len(body) {
		end = len(body)
	}
	return strings.TrimSpace(body[start:end])
}

// StoredCheckDescriptors returns the stored rows that a sighting plus its context can decide.
func StoredCheckDescriptors() []CheckDescriptor {
	rows := []struct {
		row, severity string
		ctx           func(string, string) (string, bool)
	}{
		{"Input returned in response (stored)", "info", contextAnywhere},
		{"Password returned in later response", "high", contextAnywhere},
		{"Suspicious input transformation (stored)", "info", contextAnywhere},
		{"Cross-site scripting (stored)", "high", contextInsideTag("script")},
		{"CSS injection (stored)", "medium", contextInsideTag("style")},
		{"Open redirection (stored)", "low", contextInAttribute("href")},
		{"Link manipulation (stored)", "low", contextInAttribute("href")},
		{"Form action hijacking (stored)", "medium", contextInAttribute("action")},
		{"Client-side HTTP parameter pollution (stored)", "low", contextInAttribute("src")},
		{"SQL injection (second order)", "high", contextAnywhere},
	}
	out := make([]CheckDescriptor, 0, len(rows))
	for _, r := range rows {
		out = append(out, nativeDescriptor(r.row, DispatchScopeStoredPerInsertionPoint,
			storedChecksEnabled, storedContextCheck(r.row, r.severity, r.ctx)))
	}
	return out
}
