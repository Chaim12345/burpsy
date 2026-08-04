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
// left in the queue. So the report also carries the five ways a discovered URL can go unfetched —
// still queued, dropped at the frontier bound, past the depth limit, past the per-page link bound, or
// past a template quota — counted separately and summed by Unfetched.
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
}

// DefaultLimits is the bound used when a caller does not supply one.
//
// 500 requests at the default rate is under a minute of traffic and enough to map a small
// application's structure; five minutes of wall clock is the bound that actually fires first
// against a slow target. Both are deliberately small: a crawl that stops early and says so is
// recoverable in one command, and a crawl that ran for an hour unattended against a live
// application is not.
func DefaultLimits() Limits {
	return Limits{
		MaxRequests:     500,
		MaxDepth:        6,
		MaxDuration:     5 * time.Minute,
		MaxLocations:    300,
		MaxFrontier:     5_000,
		MaxLinksPerPage: 500,
		MaxParseBytes:   2 * 1024 * 1024,
		// Twenty samples of one shape is enough to see whether the shape behaves consistently, which
		// is what a crawl of `/orders/{id}` is actually for; the ninety-thousandth order adds nothing
		// a scanner will act on. katana defaults its depth to 3 and colly defaults MaxDepth to 0,
		// meaning infinite — neither bounds this axis at all, and an unbounded default in a tool that
		// hits real targets is exactly PortSwigger's infinite-calendar problem.
		MaxTemplateVisits: 20,
		// 8 MiB covers any page, any script bundle and most documents. httputil already refuses to
		// read past 64 MiB, so this is the narrower, crawl-specific bound between the two.
		MaxCaptureBytes: 8 * 1024 * 1024,
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
	if l.MaxParseBytes <= 0 {
		l.MaxParseBytes = d.MaxParseBytes
	}
	if l.MaxTemplateVisits <= 0 {
		l.MaxTemplateVisits = d.MaxTemplateVisits
	}
	if l.MaxCaptureBytes <= 0 {
		l.MaxCaptureBytes = d.MaxCaptureBytes
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
)

// CrawlStopAll is every stop, so a caller can render a legend without hard-coding the set.
var CrawlStopAll = [10]CrawlStop{
	StopRequestBudget,
	StopDuration,
	StopLocationBudget,
	StopDepth,
	StopFrontierCapacity,
	StopLinksPerPage,
	StopParseBytes,
	StopCancelled,
	StopTemplateQuota,
	StopCaptureBytes,
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
	}
	return "unknown"
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
	}
	return "unknown stop"
}

// LimitReport is what the bounds allowed, what was consumed, which bounds stopped the crawl, and
// how many discovered URLs were never fetched.
type LimitReport struct {
	// Limits is the effective bound set after defaults were filled in.
	Limits Limits `json:"limits"`
	// Requests, Locations, DeepestDepth and Elapsed are what was actually consumed.
	Requests     int           `json:"requests"`
	Locations    int           `json:"locations"`
	DeepestDepth int           `json:"deepest_depth"`
	Elapsed      time.Duration `json:"elapsed"`
	// Stops names every bound that was hit, in the order first hit, each at most once. Truncated is
	// derived from this slice, so a stop can never be recorded without surfacing, and the crawl can
	// never stop early without recording one.
	Stops []CrawlStop `json:"stops,omitempty"`

	// The five ways a discovered URL goes unfetched. Kept apart rather than summed into one field,
	// because they call for different responses: a large FrontierRemaining means raise the request
	// budget, a large DepthDeferred means raise the depth, and a large FrontierDropped means the
	// frontier bound is the thing in the way.

	// FrontierRemaining counts URLs still queued when the crawl stopped.
	FrontierRemaining int `json:"frontier_remaining"`
	// FrontierDropped counts URLs refused admission because the frontier was at capacity.
	FrontierDropped int `json:"frontier_dropped"`
	// DepthDeferred counts links discovered at the depth limit and never queued.
	DepthDeferred int `json:"depth_deferred"`
	// LinksDropped counts links never even considered, because their page carried more than the
	// per-page bound.
	LinksDropped int `json:"links_dropped"`
	// TemplateQuotaDropped counts URLs not queued because their template was already at quota.
	TemplateQuotaDropped int `json:"template_quota_dropped"`
	// Templates counts distinct URL templates seen, so an operator can read the ratio of templates to
	// requests and tell a wide application from a deep one.
	Templates int `json:"templates"`
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
	return r.FrontierRemaining + r.FrontierDropped + r.DepthDeferred + r.LinksDropped + r.TemplateQuotaDropped
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
	if !r.Truncated() {
		return ""
	}
	reasons := make([]string, 0, len(r.Stops))
	for _, s := range r.Stops {
		reasons = append(reasons, s.Explanation())
	}
	return fmt.Sprintf(
		"this crawl is incomplete: at least %d discovered URLs went unfetched (%d still queued, %d dropped at the frontier bound, %d past the depth limit, %d past the per-page link bound, %d past a template quota) — %s",
		r.Unfetched(),
		r.FrontierRemaining,
		r.FrontierDropped,
		r.DepthDeferred,
		r.LinksDropped,
		r.TemplateQuotaDropped,
		strings.Join(reasons, "; "),
	)
}
