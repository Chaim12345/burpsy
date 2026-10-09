// The crawl's bounds, and why hitting one can never be silent (CRAWL-07).
//
// # Why cutoffs are mandatory and not a tuning knob
//
// PortSwigger's crawler documentation makes the point with a calendar: an application that renders
// "next month" forever is not a bug, and a crawler without cutoffs will crawl it until it runs out
// of disk. Session ids in URLs, cache-busting query parameters and paginated infinite scrolls all
// produce the same unbounded frontier. Every real crawler therefore stops early, and the only
// question is whether it says so.
//
// # The pattern, taken from scanner.DOMBudgetReport
//
// LimitReport.Truncated is *derived from the Stops slice* rather than stored beside it. That is not
// a stylistic choice: a separate boolean can be false while a stop is recorded, and a stop can be
// recorded with nothing incrementing the boolean, and both of those bugs read as "the crawl
// finished". Deriving the answer makes them unrepresentable — there is no way to stop early without
// naming which bound stopped you, and no way to name a bound without the report saying it is
// incomplete.
//
// The second half of CRAWL-07 is "what it did not reach", which a stop reason alone does not
// answer: "the request budget ran out" says nothing about whether four URLs or four thousand were
// left in the queue. So the report also carries the six ways a discovered URL can go unfetched —
// still queued, dropped at the frontier bound, past the depth limit, past the per-page link bound,
// past a template quota, or refused because a request-identity table was full — counted separately
// and summed by Unfetched.
//
// # What a limited crawl must never be renderable as
//
// Report.Complete is false and Report.Caveat returns a non-empty line whenever any stop fired, so a
// caller that renders a summary without consulting either is the only way a truncated crawl can be
// presented as a whole one — and Summary, the obvious thing to render, includes the caveat itself.
package crawler

import (
	"fmt"
	"strings"
	"time"
)

// Limits bounds one crawl. Zero fields are replaced with the defaults by normalise, so a caller can
// override one bound without restating the rest.
//
// There is deliberately no "unlimited" spelling for MaxRequests or MaxDuration. An unbounded crawl
// against an application that generates URLs does not finish, and offering the option would mean
// offering a configuration whose failure mode is a full disk. An operator who wants more can say a
// bigger number.
type Limits struct {
	// MaxRequests caps requests that reach the target. The bound that actually governs cost.
	MaxRequests int
	// MaxDepth caps how many links from a seed the crawl will follow. A seed is depth 0.
	MaxDepth int
	// MaxDuration caps wall-clock time. Checked between fetches, so one slow response can overrun
	// it by that response's timeout — the sender's own timeout is the bound on that.
	MaxDuration time.Duration
	// MaxLocations caps distinct content fingerprints. This is the bound that stops an application
	// whose URLs are unbounded but whose *pages* are not: a calendar generates a new URL per month
	// and a small number of distinct locations, so the request budget would be spent long before
	// this fires. When it does fire, it means the application really does have that many pages.
	MaxLocations int
	// MaxFrontier caps queued-but-unfetched URLs. Bounds the queue's memory; links arriving at a
	// full frontier are dropped and counted.
	MaxFrontier int
	// MaxLinksPerPage caps links and forms taken from one response. A generated index page can
	// carry a hundred thousand links, and admitting them all would fill the frontier from one
	// document.
	MaxLinksPerPage int
	// MaxSpeculativeLinks caps how many speculative-phase candidates (burpsy-react-ui-t5m0 —
	// URLs mined from HTML comments and script bodies) are admitted across the whole crawl.
	// The cap is crawl-wide rather than per-page because a single script bundle can carry a
	// hundred router paths: the per-page bound counts links a page LINKS to, this one counts
	// links a page merely MENTIONS, which is a different and much larger set. Zero takes the
	// default (DefaultMaxSpeculativeLinks, Burp's own shipped default).
	MaxSpeculativeLinks int
	// MaxParseBytes caps how much of a response body is parsed for links. The body is stored and
	// scanned in full regardless — this bounds only the HTML walk.
	MaxParseBytes int
	// MaxTemplateVisits caps how many distinct URLs sharing one template are fetched. See urlTemplate
	// for what a template is and why this, rather than the frontier bound, is what stops an
	// application with an unbounded id space.
	MaxTemplateVisits int
	// MaxCaptureBytes caps a response that will be stored and scanned. A response larger than this is
	// fetched and then deliberately not captured, because storing a multi-gigabyte download in full to
	// have half a megabyte of it analysed is a resource failure disguised as thoroughness. The hole is
	// counted (SkipResponseTooLarge) rather than left to be inferred.
	MaxCaptureBytes int
	// MaxFingerprints caps each of the two tables the crawl uses to remember request identity: the
	// exact-request fingerprint set (which answers "have I sent this already") and the URL-template
	// table (which holds the per-template quota's counts). Both are in RAM for the whole crawl.
	//
	// # Why this bound has to exist at all
	//
	// Phase 1's premise is that the *store* is bounded by disk rather than by RAM, and an unbounded
	// in-process map is against that grain. Neither table had a bound of its own:
	//
	//   - the fingerprint set was bounded only *derivatively*, at MaxFrontier + MaxRequests, since an
	//     entry is added exactly when an item is queued. A derivative bound is not a stated one: nothing
	//     reported the set's size, and raising either of those two limits raised this one silently.
	//   - the template table was not bounded at all. An entry is created before the frontier-capacity
	//     check, so every link dropped at a full frontier still adds one for a template not seen before,
	//     and an application that mints path shapes (rather than ids inside a known shape) grows it
	//     without limit for a crawl that is fetching nothing new.
	//
	// # Why the same number bounds both
	//
	// They grow together — one entry each per newly-admitted request shape — so bounding one while the
	// other ran free would bound nothing. One named limit and one stop reason keeps the report readable;
	// the stop's Detail names *which* table filled, and LimitReport.Fingerprints and .Templates report
	// both sizes on every crawl whether or not the bound was reached.
	MaxFingerprints int
	// MaxSubmissionsPerForm caps how many times ONE form is submitted, whatever page carried it
	// (burpsy-react-ui-u0k3). Burp's crawler.crawl_optimization.max_submissions_per_form, whose
	// shipped default is 6 (Zgjj.java:143, resolved through Zfj.Zc -> Zshz).
	//
	// ZERO means unbounded, and that is deliberately NOT a default that normalise() fills in. The
	// phase is off by default anyway (Config.SubmitForms), so a crawl that never submits is
	// unaffected; and an operator who turned submission ON has opted into submitting forms, not into
	// submitting each one a fixed number of times. Burp applies 6 unconditionally because it applies
	// it to a phase Burp also has on by default.
	//
	// A search box or a pagination form is the case this exists for: a document carrying one such
	// form on every page turns an unbounded crawl into one that submits it thousands of times and
	// learns nothing after the first few.
	//
	// LEFT OUT of normalise on purpose — see above. A bound that silently became 6 for every caller
	// would be a behaviour change disguised as a default.
	MaxSubmissionsPerForm int
	// LocationToleranceBand is how many of a page's link targets may differ before it counts as a
	// different location (location_band.go). nil means Burp's normal crawl strategy, 2. Set by
	// crawl_strategy (strategy.go), where 0 is a real value, which is why this is a pointer.
	LocationToleranceBand *int
	// MaxRelogins caps how many times this crawl may attempt to restore an expired session
	// (Gap A). Every attempt costs the target a login macro and every failure costs repeated
	// login-page fetches, so both are bounded by one number. Unlike some bounds this is not a
	// request-exactness bound: it is spoken of per attempt, because the measure that matters is
	// how many times the crawl asked the target for a session it could have asked for once.
	// Sequential waves of expiry — login expires, relogin, expires again — count the same as
	// concurrent ones: the counter is a generation counter, not a concurrent-request counter.
	MaxRelogins int
}

// DefaultLimits is the bound used when a caller does not supply one.
//
// 500 requests at the default rate is under a minute of traffic and enough to map a small
// application's structure; five minutes of wall clock is the bound that actually fires first
// against a slow target. Both are deliberately small: a crawl that stops early and says so is
// recoverable in one command, and a crawl that ran for an hour unattended against a live
// application is not.
// DefaultMaxSpeculativeLinks is the speculative-hidden-link cap (burpsy-react-ui-t5m0) when
// the operator sets none: 1000, which is Burp's own shipped default
// (Preferences/CrawlDefaults.json, crawler.customization.maximum_speculative_links).
const DefaultMaxSpeculativeLinks = 1000

func DefaultLimits() Limits {
	return Limits{
		MaxRequests:         500,
		MaxDepth:            6,
		MaxDuration:         5 * time.Minute,
		MaxLocations:        300,
		MaxFrontier:         5_000,
		MaxLinksPerPage:     500,
		MaxSpeculativeLinks: DefaultMaxSpeculativeLinks,
		MaxParseBytes:       2 * 1024 * 1024,
		// Twenty samples of one shape is enough to see whether the shape behaves consistently, which
		// is what a crawl of `/orders/{id}` is actually for; the ninety-thousandth order adds nothing
		// a scanner will act on. katana defaults its depth to 3 and colly defaults MaxDepth to 0,
		// meaning infinite — neither bounds this axis at all, and an unbounded default in a tool that
		// hits real targets is exactly PortSwigger's infinite-calendar problem.
		MaxTemplateVisits: 20,
		// 8 MiB covers any page, any script bundle and most documents. httputil already refuses to
		// read past 64 MiB, so this is the narrower, crawl-specific bound between the two.
		MaxCaptureBytes: 8 * 1024 * 1024,
		// A fingerprint is a normalised method+URL and a template is a URL with its ids replaced, so an
		// entry costs on the order of a hundred bytes plus map overhead: 50 000 of each is single-digit
		// megabytes per table. With the default request and frontier bounds the fingerprint set cannot
		// reach 5 500 entries, so this never fires on a default crawl — which is the point. It is the
		// stated ceiling for the crawl whose other bounds were raised, and for the template table, which
		// grows even while the crawl fetches nothing new.
		MaxFingerprints: 50_000,
		// Relogin is cheap when the macro is short and expensive when it is not, and it is always
		// a burst of traffic the operator did not explicitly ask for. Five is enough for the
		// common wave — session dies once, recovers — while still truncating the crawl that keeps
		// losing its session, which is a target- or macro-problem the crawl should report rather
		// than hammer.
		MaxRelogins: 5,
	}
}

func (l Limits) normalise() Limits {
	d := DefaultLimits()
	if l.MaxRequests <= 0 {
		l.MaxRequests = d.MaxRequests
	}
	if l.MaxDepth <= 0 {
		l.MaxDepth = d.MaxDepth
	}
	if l.MaxDuration <= 0 {
		l.MaxDuration = d.MaxDuration
	}
	if l.MaxLocations <= 0 {
		l.MaxLocations = d.MaxLocations
	}
	if l.MaxFrontier <= 0 {
		l.MaxFrontier = d.MaxFrontier
	}
	if l.MaxLinksPerPage <= 0 {
		l.MaxLinksPerPage = d.MaxLinksPerPage
	}
	if l.MaxSpeculativeLinks <= 0 {
		l.MaxSpeculativeLinks = d.MaxSpeculativeLinks
	}
	if l.MaxParseBytes <= 0 {
		l.MaxParseBytes = d.MaxParseBytes
	}
	if l.MaxTemplateVisits <= 0 {
		l.MaxTemplateVisits = d.MaxTemplateVisits
	}
	if l.MaxCaptureBytes <= 0 {
		l.MaxCaptureBytes = d.MaxCaptureBytes
	}
	if l.MaxFingerprints <= 0 {
		l.MaxFingerprints = d.MaxFingerprints
	}
	if l.MaxRelogins <= 0 {
		l.MaxRelogins = d.MaxRelogins
	}
	return l
}

// CrawlStop names one bound that was hit. Every value here is a reason the crawl's coverage claim
// is narrower than the application, and each carries a line an operator can act on.
type CrawlStop int

const (
	// StopRequestBudget means the request budget was spent with the frontier non-empty.
	StopRequestBudget CrawlStop = iota
	// StopDuration means the wall-clock budget was spent with the frontier non-empty.
	StopDuration
	// StopLocationBudget means the distinct-location budget was spent.
	StopLocationBudget
	// StopDepth means links were found at the depth limit and not followed. Unlike the budgets
	// above, this one can fire on a crawl that otherwise ran to completion — which is exactly why
	// it is a stop: the frontier emptied, but not because the application ended.
	StopDepth
	// StopFrontierCapacity means links were dropped because the frontier was full.
	StopFrontierCapacity
	// StopSpeculativeLinks means at least one speculative-phase candidate (a URL mined from a
	// comment or script body, burpsy-react-ui-t5m0) was refused because the crawl-wide
	// speculative cap was spent. Unlike the other stops this one names a phase the operator
	// can raise the budget for — the cap is a choice about how much hidden-link following a
	// crawl may do, not a property of the application.
	StopSpeculativeLinks
	// StopLinksPerPage means at least one page carried more links than the per-page bound admits,
	// so the excess was never considered.
	StopLinksPerPage
	// StopParseBytes means at least one response body was longer than the parse bound, so its tail
	// was never examined for links. The body was still stored and scanned in full.
	StopParseBytes
	// StopCancelled means the caller's context ended the crawl. Not a budget, and recorded the same
	// way for the same reason: a cancelled crawl is not a finished one.
	StopCancelled
	// StopTemplateQuota means at least one URL template was sampled to its quota, so the application
	// has more URLs of that shape than the crawl fetched. The honest name for the infinite-application
	// cutoff, which is why it is not allowed to surface as StopFrontierCapacity.
	StopTemplateQuota
	// StopCaptureBytes means at least one response was larger than the capture bound, so it was
	// neither stored nor scanned.
	StopCaptureBytes
	// StopFingerprintBudget means one of the two request-identity tables reached MaxFingerprints, so
	// URLs the crawl had never seen were refused admission rather than remembered.
	//
	// # Why refusing admission, and not evicting
	//
	// The alternative was to keep admitting URLs and evict old fingerprints, on the reasoning that a
	// dropped fingerprint costs at most a re-fetch of a page already seen, where a dropped frontier entry
	// costs a page never visited. The re-fetch cost is bounded — MaxRequests still bounds total fetches —
	// but that argument understates what eviction actually does here:
	//
	//   - The frontier is FIFO and bounded. Re-admitted duplicates *displace* genuine unvisited work at
	//     MaxFrontier, so the coverage loss does not stay a re-fetch; it becomes unvisited pages
	//     attributed to StopFrontierCapacity. That is precisely the laundering SkipTemplateQuota exists to
	//     prevent: a true statement about the wrong bound.
	//   - The loss is unmeasurable. Nothing can say which pages went unvisited because the budget went on
	//     repeats, so the report would carry a smaller Unfetched than the truth.
	//
	// Refusing admission fails visibly instead: one counted decline per URL (SkipFingerprintBudget, with
	// the URL in the skip sample), one stop, and LimitReport.FingerprintDropped folded into Unfetched, so
	// Complete() is false and Caveat names it. The residual cost is stated rather than hidden: a crawl
	// that reaches this keeps fetching what is already queued and stops discovering, and it says so.
	StopFingerprintBudget
	// StopReloginBudget means the crawl tried to restore an expired session MaxRelogins times and
	// every attempt is spent, with the frontier still non-empty. Recorded by recoverSession when the
	// budget is checked before a login macro runs, so the stop fires exactly when the re-login
	// budget is the thing in the way — the crawl is authenticating with a cookie from a session the
	// application no longer honours, and the rest of the crawl is unauthenticated whether it knows
	// it or not.
	StopReloginBudget
	// StopPausedTimeouts means the crawl stopped because PAUSED BY POLICY: this many CONSECUTIVE
	// requests timed out. Distinct from StopDuration and StopRequestBudget because the crawl did not
	// run out of anything — it was told to stop by the operator's own error_handling configuration,
	// which is a different fact and a different response. An operator who set 5 to spare a slow
	// target needs the report to say the crawl honoured that, not that it finished.
	StopPausedTimeouts
	// StopPausedTimeoutPercentage means the same, on the PERCENTAGE axis: this share of the crawl's
	// requests timed out. Separate from the count because the two answer different questions — a
	// count is about a streak, a percentage about a host that is broadly slow — and an operator
	// reading "paused" cannot choose between them.
	StopPausedTimeoutPercentage
	// StopPausedAuthFailures means the crawl stopped because this many consecutive requests were
	// REJECTED for authentication. The most actionable of the three: every page from here on would
	// have been a 401 page, so continuing would have filled the report with coverage of a login form.
	StopPausedAuthFailures
	// StopFollowUpBudget means a follow-up pass wanted to retry and the request budget was spent.
	// A distinct stop because the failure is not "the target is broken" — it is "this crawl was not
	// allowed to try again", which is a coverage hole of a different kind and one an operator can fix
	// by raising a bound rather than by waiting.
	StopFollowUpBudget
	// StopFollowUpCancelled means a follow-up pass was abandoned because the caller's context ended.
	// Recorded rather than folded into StopCancelled because the two cancel different amounts of
	// work: StopCancelled is a crawl that stopped mid-frontier, this is one that finished its main
	// pass and then ran out of time on the retries.
	StopFollowUpCancelled
	// StopLoginFailed means the crawl was given a recorded login (burpsy-react-ui-xhtk) and the replay
	// before the first fetch did not log in. Burp runs the scan anyway ("If Burp Scanner is unable to
	// replay a recorded login sequence during a scan then it cannot perform an authenticated crawl.
	// However, the scan will still run."), and so does this one — but as a stop, so a crawl that was
	// meant to be authenticated and was not can never read as done.
	StopLoginFailed
)

// CrawlStopAll is every stop, so a caller can render a legend without hard-coding the set.
var CrawlStopAll = [19]CrawlStop{
	StopRequestBudget,
	StopDuration,
	StopLocationBudget,
	StopDepth,
	StopFrontierCapacity,
	StopSpeculativeLinks,
	StopLinksPerPage,
	StopParseBytes,
	StopCancelled,
	StopTemplateQuota,
	StopCaptureBytes,
	StopFingerprintBudget,
	StopReloginBudget,
	StopPausedTimeouts,
	StopPausedTimeoutPercentage,
	StopPausedAuthFailures,
	StopFollowUpBudget,
	StopFollowUpCancelled,
	StopLoginFailed,
}

func (s CrawlStop) String() string {
	switch s {
	case StopRequestBudget:
		return "request-budget"
	case StopDuration:
		return "duration"
	case StopLocationBudget:
		return "location-budget"
	case StopDepth:
		return "depth"
	case StopFrontierCapacity:
		return "frontier-capacity"
	case StopSpeculativeLinks:
		return "speculative-links"
	case StopLinksPerPage:
		return "links-per-page"
	case StopParseBytes:
		return "parse-bytes"
	case StopCancelled:
		return "cancelled"
	case StopTemplateQuota:
		return "template-quota"
	case StopCaptureBytes:
		return "capture-bytes"
	case StopFingerprintBudget:
		return "fingerprint-budget"
	case StopReloginBudget:
		return "relogin-budget"
	case StopPausedTimeouts:
		return "paused-timeouts"
	case StopPausedTimeoutPercentage:
		return "paused-timeout-percentage"
	case StopPausedAuthFailures:
		return "paused-auth-failures"
	case StopFollowUpBudget:
		return "follow-up-budget"
	case StopFollowUpCancelled:
		return "follow-up-cancelled"
	case StopLoginFailed:
		return "login-failed"
	}
	return "unknown"
}

// MarshalText puts a stop on the wire by its NAME (burpsy-react-ui-j5j7). As a bare integer the stop
// list meant nothing to a reader that did not share this package's iota order, and a stop added later
// shifted every number after it; "paused-timeouts" means the same thing in every build.
func (s CrawlStop) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// UnmarshalText reads a stop back by name, refusing a name this build does not have rather than
// mapping it to some other stop.
func (s *CrawlStop) UnmarshalText(b []byte) error {
	for _, stop := range CrawlStopAll {
		if stop.String() == string(b) {
			*s = stop
			return nil
		}
	}
	return fmt.Errorf("unknown crawl stop %q", string(b))
}

// Explanation is one line an operator can act on.
func (s CrawlStop) Explanation() string {
	switch s {
	case StopRequestBudget:
		return "the request budget was spent while URLs were still queued; the rest of the application was not reached"
	case StopDuration:
		return "the wall-clock budget was spent while URLs were still queued; the rest of the application was not reached"
	case StopLocationBudget:
		return "the distinct-location budget was spent; further pages were not fetched"
	case StopDepth:
		return "links were found at the depth limit and not followed; anything only reachable past that depth was not seen"
	case StopFrontierCapacity:
		return "the frontier reached its capacity bound and further links were dropped"
	case StopSpeculativeLinks:
		return "the speculative-link cap is spent, so a hidden link mined from a comment or script was not followed"
	case StopLinksPerPage:
		return "a page carried more links than the per-page bound admits; the excess was not considered"
	case StopParseBytes:
		return "a response body was longer than the parse bound, so its tail was not examined for links (the body itself was stored and scanned in full)"
	case StopCancelled:
		return "the crawl was cancelled before the frontier emptied"
	case StopTemplateQuota:
		return "a URL template was sampled to its quota; the application has more URLs of that shape than were fetched"
	case StopCaptureBytes:
		return "a response was larger than the capture bound, so it was neither stored nor scanned"
	case StopFingerprintBudget:
		return "a request-identity table reached its bound, so URLs the crawl had never seen were refused rather than remembered; the application is larger than this crawl can keep track of"
	case StopReloginBudget:
		return "the re-login budget was spent while URLs were still queued; anything beyond the last re-login was crawled unauthenticated"
	case StopPausedTimeouts:
		return "paused by policy: consecutive requests timed out past the error-handling threshold, so the crawl stopped rather than keep sending to a target that had stopped answering"
	case StopPausedTimeoutPercentage:
		return "paused by policy: the share of requests that timed out passed the error-handling threshold, so the crawl stopped against a broadly unresponsive target"
	case StopPausedAuthFailures:
		return "paused by policy: consecutive re-logins failed past the error-handling threshold; everything after would have been crawled as a logged-out user"
	case StopFollowUpBudget:
		return "requests that failed were not retried because the request budget was spent; they remain failed in this report"
	case StopFollowUpCancelled:
		return "the crawl was cancelled during its follow-up pass, so some failed requests were not retried"
	case StopLoginFailed:
		return "the recorded login did not log in before the crawl started, so the whole crawl ran unauthenticated; the report's login block says which step failed"
	}
	return "unknown stop"
}

// LimitReport is what the bounds allowed, what was consumed, which bounds stopped the crawl, and
// how many discovered URLs were never fetched.
type LimitReport struct {
	// Limits is the effective bound set after defaults were filled in.
	Limits Limits `json:"limits"`
	// OutOfScopeResources is how many SUBRESOURCE requests were refused because they name a host
	// outside the engagement scope (burpsy-react-ui-hgor). Reported on the limits because it is a
	// claim about coverage, not a ledger detail: a page whose content came from a CDN contributes
	// nothing, and the crawl is otherwise indistinguishable from one of an empty site.
	//
	// Separate from the navigational out-of-scope count because the two mean opposite things to an
	// operator. A navigational refusal is scope working. A resource refusal is burpsy being STRICTER
	// than Burp, whose crawler fetches out-of-scope resources by default
	// (crawler.customization.allow_out_of_scope_resources = true, Preferences/CrawlDefaults.json).
	OutOfScopeResources int `json:"out_of_scope_resources"`
	// Requests, Locations, DeepestDepth and Elapsed are what was actually consumed.
	Requests     int           `json:"requests"`
	Locations    int           `json:"locations"`
	DeepestDepth int           `json:"deepest_depth"`
	Elapsed      time.Duration `json:"elapsed"`
	// Stops names every bound that was hit, in the order first hit, each at most once. Truncated is
	// derived from this slice, so a stop can never be recorded without surfacing, and the crawl can
	// never stop early without recording one.
	Stops []CrawlStop `json:"stops,omitempty"`

	// The six ways a discovered URL goes unfetched. Kept apart rather than summed into one field,
	// because they call for different responses: a large FrontierRemaining means raise the request
	// budget, a large DepthDeferred means raise the depth, and a large FrontierDropped means the
	// frontier bound is the thing in the way.

	// FrontierRemaining counts URLs still queued when the crawl stopped.
	FrontierRemaining int `json:"frontier_remaining"`
	// FrontierDropped counts URLs refused admission because the frontier was at capacity.
	FrontierDropped int `json:"frontier_dropped"`
	// SpeculativeDropped counts speculative-phase candidates (burpsy-react-ui-t5m0) refused
	// admission because the crawl-wide speculative cap was spent. Reported beside
	// FrontierDropped for the same reason: a drop is a coverage hole, and an operator
	// reading a smaller fetch count needs to know which bound caused it.
	SpeculativeDropped int `json:"speculative_dropped"`
	// DepthDeferred counts links discovered at the depth limit and never queued.
	DepthDeferred int `json:"depth_deferred"`
	// LinksDropped counts links never even considered, because their page carried more than the
	// per-page bound.
	LinksDropped int `json:"links_dropped"`
	// TemplateQuotaDropped counts URLs not queued because their template was already at quota.
	TemplateQuotaDropped int `json:"template_quota_dropped"`
	// FingerprintDropped counts URLs the crawl had never seen and refused to admit because a
	// request-identity table was at MaxFingerprints. See StopFingerprintBudget for why these are refused
	// rather than made room for by eviction.
	FingerprintDropped int `json:"fingerprint_dropped"`
	// Templates counts distinct URL templates seen, so an operator can read the ratio of templates to
	// requests and tell a wide application from a deep one.
	Templates int `json:"templates"`
	// Fingerprints counts entries in the exact-request fingerprint set — every distinct request the crawl
	// queued and therefore has to remember for the rest of the run.
	//
	// Reported on every crawl, not only when the bound was reached. Both this and Templates are the sizes
	// of tables that live in RAM for the whole crawl, and a bound whose consumption is invisible until it
	// fires is a bound nobody can plan around: an operator raising MaxRequests or MaxFrontier is raising
	// what these two cost, and this is where they can see by how much.
	Fingerprints int `json:"fingerprints"`
}

// Truncated reports whether any bound was hit. Derived from Stops, never stored — see the package
// docs for why that distinction is load-bearing.
func (r LimitReport) Truncated() bool { return len(r.Stops) > 0 }

// Hit reports whether one specific bound was hit.
func (r LimitReport) Hit(stop CrawlStop) bool {
	for _, s := range r.Stops {
		if s == stop {
			return true
		}
	}
	return false
}

// Unfetched is how many URLs the crawl discovered and never fetched, across all four ways that
// happens. This is CRAWL-07's "what it did not reach", as a number.
//
// It is a lower bound on what was missed, not an estimate of it: each of those URLs might have led
// to pages that were never discovered at all, and nothing here can count those. A caller reporting
// this should say "at least", and Caveat does. It also excludes responses dropped at the capture bound
// — those were fetched, so they are not unfetched; Report.NotCaptured counts them.
func (r LimitReport) Unfetched() int {
	return r.FrontierRemaining + r.FrontierDropped + r.DepthDeferred + r.LinksDropped +
		r.TemplateQuotaDropped + r.FingerprintDropped + r.SpeculativeDropped
}

// record adds a stop, at most once each. Order of first occurrence is preserved, so the list reads
// as the sequence of bounds the crawl ran into.
func (r *LimitReport) record(stop CrawlStop) {
	if r.Hit(stop) {
		return
	}
	r.Stops = append(r.Stops, stop)
}

// Caveat is the line that must accompany any rendering of a truncated crawl, and is empty for a
// crawl that ran to completion. Naming every stop rather than only the first: a crawl can hit the
// depth limit early and then run out of request budget, and an operator raising only one of them
// gets the same truncated result again.
func (r LimitReport) Caveat() string {
	// The out-of-scope-resource count is stated EVEN FOR A COMPLETE CRAWL, which is the whole reason
	// it is here rather than in the truncated branch below. A crawl that refused every CDN-hosted
	// asset is not truncated — it ran to completion, within a narrower world than the operator
	// thinks — and the existing caveat is therefore silent about the one thing that explains an
	// unexpectedly small crawl. Silence here is the defect hgor is about.
	resourceNote := ""
	if r.OutOfScopeResources > 0 {
		resourceNote = fmt.Sprintf(
			"; %d subresource(s) were refused for naming a host outside the engagement scope — burpsy "+
				"refuses these and Burp's crawler fetches them by default (allow_out_of_scope_resources), "+
				"so a page served largely from a CDN or a third-party API contributes no locations here",
			r.OutOfScopeResources)
	}
	if !r.Truncated() {
		return strings.TrimPrefix(resourceNote, "; ")
	}
	reasons := make([]string, 0, len(r.Stops))
	for _, s := range r.Stops {
		reasons = append(reasons, s.Explanation())
	}
	return fmt.Sprintf(
		"this crawl is incomplete: at least %d discovered URLs went unfetched (%d still queued, %d dropped at the frontier bound, %d past the depth limit, %d past the per-page link bound, %d past a template quota, %d refused with the identity tables full) — %s",
		r.Unfetched(),
		r.FrontierRemaining,
		r.FrontierDropped,
		r.DepthDeferred,
		r.LinksDropped,
		r.TemplateQuotaDropped,
		r.FingerprintDropped,
		strings.Join(reasons, "; ")+resourceNote,
	)
}
