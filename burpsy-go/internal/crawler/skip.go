// Everything the crawl declined to fetch, why, and what matched.
//
// # Why a refused link is a shorter frontier and never a silent hole
//
// A crawler's output is a claim about coverage: these are the locations the application has. Every
// link the crawl declines to follow weakens that claim, and a decline that is not recorded weakens
// it invisibly — the operator reads "41 locations" and cannot tell whether the 42nd was absent or
// merely skipped. That is the same defect scanner.CoverageTracker exists to fix for the passive
// check set, and this is the same fix applied to the frontier: every decline lands in exactly one
// bucket, the buckets are enumerable, and the totals are reported whether or not anything was
// found.
//
// So the shape here is deliberately CoverageReport's shape. SkipAll enumerates the reasons so a
// caller can render a legend without hard-coding the set; per-reason counts come back in SkipAll
// order; a bounded sample of individual records carries the URL, the link text and the matched
// signal, and records dropped at that bound are *counted*, never silently absent.
//
// # Why one enum covers safety, scope, policy, duplicates, limits and response handling
//
// They are not the same kind of event, and splitting them into five enums was the first design. It
// was wrong for one reason: the question an operator asks is "what did the crawl not fetch", and
// five ledgers cannot answer it without a sixth thing summing them. One enum with a Category
// accessor answers it directly and still rolls up per category, so "3 destructive, 9 already seen,
// 1 out of scope" reads off the same table that "12 skipped" does.
package crawler

import (
	"fmt"
	"sync"
)

// Skip is one reason the crawl declined to fetch something.
//
// Every value is a reason a coverage claim is narrower than it looks. There is no "skipped for
// other reasons" value on purpose: a decline with no bucket to land in is a bug in the caller, and
// SkipUnclassified would let that bug look like an ordinary result.
type Skip int

const (
	// ---- destructive-action refusals: CRAWL-04, matched on link target and link text ----

	// SkipDestructiveLogout means the link would have ended the session the crawl authenticated
	// with. Refusing this is what lets an authenticated crawl stay authenticated.
	SkipDestructiveLogout Skip = iota
	// SkipDestructiveDelete means the link signals deleting or destroying a record.
	SkipDestructiveDelete
	// SkipDestructivePurge means the link signals emptying a collection wholesale — trash, cache,
	// queue, table.
	SkipDestructivePurge
	// SkipDestructiveDeactivate means the link signals deactivating, disabling or closing an
	// account or subscription.
	SkipDestructiveDeactivate
	// SkipDestructiveAdminPlugin means the link signals an administrative install, upgrade, setup
	// or reset action — the class of action that can take an application offline in one request.
	SkipDestructiveAdminPlugin
	// SkipDestructiveStateChange means the link's text or target carries some other state-changing
	// verb from the table in destructive.go.
	SkipDestructiveStateChange

	// ---- safety refusals: the URL itself is not something to dial ----

	// SkipUnsupportedScheme means the URL is not http or https. A hostile page can offer
	// javascript:, data:, file: or mailto: links, and a crawler that dials whatever it is handed is
	// an SSRF engine with a scope list attached.
	SkipUnsupportedScheme
	// SkipMalformedURL means the URL could not be parsed or resolved against its page, or resolved
	// to something with no host.
	SkipMalformedURL
	// SkipCredentialsInURL means the URL carried userinfo. A target that can choose which
	// credentials the crawler presents can make it authenticate somewhere it was never meant to.
	SkipCredentialsInURL

	// ---- scoping refusals ----

	// SkipOutOfScope means the engagement scope excludes the URL. This is the pre-fetch pre-filter,
	// not the authorisation: sender.AuthorisedSender re-checks the bytes actually going on the wire,
	// and SkipSendRefused is what that gate produces.
	SkipOutOfScope
	// SkipSendRefused means the URL cleared the pre-filter and was still refused by the scope
	// chokepoint on the exact request bytes, before the dial. Counted apart from SkipOutOfScope
	// because the two firing at different rates is the signal that the pre-filter and the
	// authoriser disagree.
	SkipSendRefused
	// SkipQueryExcluded means the operator's crawl-scope query (DSL-03) does not match the URL.
	SkipQueryExcluded

	// ---- policy: the operator's configuration, not the target's content ----

	// SkipFormSubmissionDisabled means a form was discovered and not submitted because form
	// submission is off. This is CRAWL-03's default, and it is counted rather than assumed so that
	// "no forms submitted" is distinguishable from "no forms found".
	SkipFormSubmissionDisabled
	// SkipFormNotSubmittable means form submission is on but this form could not be submitted —
	// a multipart or plaintext enctype, or a method the crawler does not build.
	SkipFormNotSubmittable

	// ---- duplicates: the frontier's own bookkeeping ----

	// SkipAlreadyQueued means an identical request fingerprint has already been queued or fetched.
	SkipAlreadyQueued
	// SkipTemplateQuota means this URL's *template* — its path with id-shaped segments replaced and
	// its parameter names without values — has already been visited as many times as the quota
	// allows. This is the cutoff that actually stops an "infinite" application, and it has its own
	// reason for a specific reporting reason: without it, an exact-URL set never repeats on an app
	// that generates URLs, SkipAlreadyQueued stays at zero, and the only thing that eventually stops
	// the crawl is the frontier's *memory* bound — which would launder an infinite-app cutoff through
	// a resource limit and tell the operator the wrong thing about why their crawl ended.
	SkipTemplateQuota
	// SkipDuplicateLocation means the response's content fingerprint had already been seen, so the
	// links it carries were not queued a second time. See fingerprint.go for why a location is
	// identified by its contents and not by the URL used to reach it.
	SkipDuplicateLocation

	// ---- limits: also recorded as a CrawlStop, because they truncate the crawl ----

	// SkipDepthLimit means the link was discovered at the depth limit and never queued.
	SkipDepthLimit
	// SkipFrontierFull means the frontier was at its capacity bound and the link was dropped.
	SkipFrontierFull
	// SkipLinksPerPage means the page carried more links than the per-page bound admits.
	SkipLinksPerPage
	// SkipFingerprintBudget means the URL had never been seen and was refused anyway, because one of the
	// two tables the crawl remembers request identity in — the exact-request fingerprint set or the
	// URL-template table — was at MaxFingerprints. The record's Detail names which table.
	//
	// Its own reason rather than SkipFrontierFull, which is the bound it would otherwise be laundered
	// through: "the queue was full" and "I have run out of room to remember what I have already sent" are
	// different problems with different fixes, and the second is the one whose failure mode is a
	// re-crawl. See StopFingerprintBudget for why the alternative — evicting a fingerprint to make room —
	// is the less honest direction.
	SkipFingerprintBudget

	// ---- response handling: fetched, but nothing further came of it ----

	// SkipNotHTML means the response was fetched, stored and scanned, but is not HTML, so no links
	// were extracted from it. Not an error and not a gap in the scan — only in the traversal.
	SkipNotHTML
	// SkipContentEncoded means the response body carries a Content-Encoding, so it is not the text
	// the server rendered and link extraction would read compressed bytes as markup. The crawler
	// asks for `identity`; a target that encodes anyway lands here.
	SkipContentEncoded
	// SkipSendFailed means the request was authorised and then failed at the transport — a refused
	// connection, a timeout, an unreadable response. Neither sent nor refused, so it is its own
	// bucket rather than being folded into either.
	SkipSendFailed
	// SkipResponseUnreadable means bytes came back and could not be captured or read back: the
	// message would not parse as HTTP, or the store rejected it. Its own reason rather than folded
	// into SkipSendFailed, because the send worked — what failed is downstream of it, and a crawl
	// where this fires repeatedly has a store or a target problem, not a network one.
	SkipResponseUnreadable
	// SkipResponseTooLarge means the response exceeded the capture bound, so it was neither stored nor
	// scanned. A deliberate coverage hole, counted precisely because it is one: one multi-gigabyte
	// download would otherwise be stored in full to have 512 KB of it analysed.
	SkipResponseTooLarge
	// SkipRetentionExcluded means the response was fetched, captured and scanned, and the operator's
	// crawl-retention query does not match it, so its links were not followed.
	//
	// Deliberately *not* a scope refusal. CRAWL-02 means the request had already gone out and the
	// response is already in history — it cannot be un-captured, and calling this "excluded" in the
	// scope sense would make the crawl's request counts disagree with the store's. What the retention
	// query gates is traversal, and this reason says exactly that.
	SkipRetentionExcluded
	// SkipSessionExpired means the response's contents say the session the crawl authenticates with is
	// gone (a template that flipped 200→non-200, or the configured login-page pattern). The response was
	// captured and scanned like any other — CRAWL-02 does not un-store bytes — but it is a login redirect, not
	// application content, so its links are not followed. Seen when recovery failed or the budget is spent.
	SkipSessionExpired
	// SkipReloginFailed means the session-expiry detector fired and the session-login macro could not restore the
	// session (no rule covers the host, the macro failed, or it succeeded but the jar stayed empty), so
	// the request was not retried with a fresh cookie. Its own skip rather than SkipSendRefused: nothing
	// was refused, a recovery was attempted and did not succeed, and the two read very differently in a
	// report.
	SkipReloginFailed
	// SkipRenderUnavailable means the response was HTML and would have had a rendered-DOM second
	// pass, but the render hook the crawl was given failed for this URL — no browser, a dead browser,
	// a navigation error. Its own reason rather than silence, because the rendered pass is the only
	// place a single-page application's routes exist at all: a crawl that wanted the rendered view
	// and did not get it is narrower than its counts say, and the operator must be able to see by how
	// much. See Config.Render (burpsy-react-ui-nx7b).
	SkipRenderUnavailable
	// SkipSitemapUnparsed means a response that LOOKED like a sitemap — by its content type or by
	// the element names in its own body — could not be decoded as one. It is a distinct reason
	// because the alternative is the defect this bead is about: a sitemap fetched, stored, scanned
	// and reported as a non-HTML body, indistinguishable from a target that published no URL list
	// at all. The operator's two possible causes (a gzipped sitemap, a truncated fetch) are both
	// things they can see and act on, so the crawl must be able to tell them apart
	// (burpsy-react-ui-qjtx).
	SkipSitemapUnparsed
	// SkipJSONUnparsed means a response that looked like JSON — by its content type or by its own
	// opening brace — could not be decoded as one, so the locations it might name were not
	// followed. Distinct from SkipNotHTML for the same reason SkipSitemapUnparsed is: "this is
	// not JSON" and "this is JSON I could not read" have different remedies, and folding them
	// together is the defect mz1n is about (burpsy-react-ui-mz1n).
	SkipJSONUnparsed
	// SkipSpeculativeLimit means a speculative-phase candidate (a URL mined from a comment or
	// script body, burpsy-react-ui-t5m0) was refused because the crawl-wide speculative cap
	// was spent. It is a phase bound, not a property of the target: the remedy is raising
	// maximum_speculative_links, which is why it is its own reason rather than a frontier-full
	// variant — the two have different causes and different fixes.
	SkipSpeculativeLimit
	// SkipAPIUnparsed means a response that announced itself as an API DEFINITION — an OpenAPI or
	// Swagger document, a SOAP WSDL — could not be read, so the endpoints it declares were never
	// admitted. Its own reason, and not SkipJSONUnparsed, for the same reason that one is distinct
	// from SkipNotHTML: the three answers have three different remedies.
	//
	// "this was not an API document" is the absence of a thing and is not a skip at all.
	// "this was JSON I could not read" is a truncated or mislabelled fetch.
	// "this was an API definition I could not read" is a document the operator almost certainly wants
	// to know about — it is the one case where the target PUBLISHED its API surface and the crawl
	// still cannot see it. Reporting it as zero endpoints would tell the operator their target has
	// no API, which is the exact failure burpsy-react-ui-bwwg exists to stop.
	SkipAPIUnparsed
	// SkipGraphQLUnparsed means a response that WAS a GraphQL introspection answer could not be read,
	// so the operations it named were not crawled. Distinct from the absence of a GraphQL endpoint,
	// which is not a skip at all: almost every URL a crawl touches is not GraphQL, and a refusal per
	// non-GraphQL URL would bury the one that mattered. This reason fires only where the endpoint
	// answered with a schema the crawl could not parse (burpsy-react-ui-bwwg).
	SkipGraphQLUnparsed
	// SkipGraphQLIntrospection means a GraphQL probe was NOT sent: the crawl-wide request bound was
	// already spent. Its own reason because the request never went out, and a report that said
	// "0 GraphQL endpoints found" without it would read as "this target has none" when the crawl
	// simply ran out of budget first.
	SkipGraphQLIntrospection
	// SkipOutOfScopeResource means a URL was refused because it names a HOST OUTSIDE the engagement
	// scope AND it was found as a SUBRESOURCE — an image, script, stylesheet, font or frame that the
	// page loads to work at all, rather than a link a person would follow (burpsy-react-ui-hgor).
	//
	// Its own reason because "why is my crawl empty" has two very different answers that both look
	// like a scope refusal in one number. A navigational link to an out-of-scope host is scope doing
	// its job; a page whose entire content came from a CDN is the case burpsy is STRICTER than Burp
	// about, because Burp's crawler fetches such resources by default
	// (crawler.customization.allow_out_of_scope_resources = true, Preferences/CrawlDefaults.json)
	// while burpsy refuses them. Merged into SkipOutOfScope, the operator cannot tell which happened,
	// and the second is the one that explains an empty crawl on a modern site.
	//
	// Deliberately NOT a relaxation: burpsy's refusal stands. This reason exists so the refusal says
	// which kind of refusal it was, which is the diagnostic the bead asks for and the only thing it
	// proposes to change.
	SkipOutOfScopeResource
	// SkipFormSubmissionCap means a form was NOT submitted because this form has already been
	// submitted the number of times the operator allowed (burpsy-react-ui-u0k3).
	//
	// Its own reason rather than SkipTemplateQuota, the closest neighbour: that one counts a URL
	// TEMPLATE (a path with its ids replaced), so a search box posting to the same path with different
	// values is ONE template there and many submissions here. Merged, a pagination form hitting the
	// form cap would report as having hit the template quota, naming a limit that never fired.
	//
	// Recorded rather than silently dropped: a form refused by a cap is a hole in the crawl's coverage,
	// and an operator reading "N forms submitted" needs to know why it was not more.
	SkipFormSubmissionCap
	// SkipFormDestinationExhausted means a form was NOT submitted because the number of distinct
	// destinations the crawl has already submitted THIS form to has reached
	// Config.FormSubmissionOptimizationThreshold (burpsy-react-ui-ddln).
	//
	// A different bound from SkipFormSubmissionCap, and the difference is the whole reason the two
	// thresholds are separate keys in Burp. That one bounds how many times ONE destination may be
	// submitted; this one bounds how many DESTINATIONS are worth trying before the form's input
	// strategy is judged to have stopped yielding new locations. A pagination control whose page
	// parameter walks forward forever hits this one with its cap untouched: every submission is a
	// new URL, so a per-destination cap never fires, and the form is still submitting into a space
	// with nothing left to learn from.
	//
	// Recorded rather than silently dropped, for the same honest-counting reason as the cap: a form
	// refused here is a hole in the crawl's coverage and the operator has to be able to see it.
	SkipFormDestinationExhausted
	// SkipLocationFolded means the response was recognised as a location already seen by the
	// TOLERANCE BAND rather than by exact fingerprint equality (burpsy-react-ui-9x67,
	// location_band.go): same structure, same text bucket, same set of link paths and parameter
	// names, with at most locationToleranceBand of the link VALUES moved. Its links were not queued
	// again, exactly as for SkipDuplicateLocation.
	//
	// Its own reason rather than being counted as SkipDuplicateLocation, because that reason's whole
	// claim is that the contents were IDENTICAL and this one's is that they were CLOSE. An operator
	// seeing "duplicate" learns the crawl is exact; an operator seeing this learns the crawl is
	// within a tolerance, which is a different and weaker thing to rely on, and is the difference
	// between a coverage claim and a claim about coverage.
	SkipLocationFolded
)

// SkipAll is every reason, in declaration order — which is also the order per-reason counts are
// reported in, so a caller can render a table without hard-coding the set.
var SkipAll = [40]Skip{
	SkipDestructiveLogout,
	SkipDestructiveDelete,
	SkipDestructivePurge,
	SkipDestructiveDeactivate,
	SkipDestructiveAdminPlugin,
	SkipDestructiveStateChange,
	SkipUnsupportedScheme,
	SkipMalformedURL,
	SkipCredentialsInURL,
	SkipOutOfScope,
	SkipSendRefused,
	SkipQueryExcluded,
	SkipFormSubmissionDisabled,
	SkipFormNotSubmittable,
	SkipAlreadyQueued,
	SkipTemplateQuota,
	SkipDuplicateLocation,
	SkipDepthLimit,
	SkipFrontierFull,
	SkipLinksPerPage,
	SkipFingerprintBudget,
	SkipNotHTML,
	SkipContentEncoded,
	SkipSendFailed,
	SkipResponseUnreadable,
	SkipResponseTooLarge,
	SkipRetentionExcluded,
	SkipSessionExpired,
	SkipReloginFailed,
	SkipRenderUnavailable,
	SkipSitemapUnparsed,
	SkipJSONUnparsed,
	SkipSpeculativeLimit,
	SkipAPIUnparsed,
	SkipGraphQLUnparsed,
	SkipGraphQLIntrospection,
	SkipOutOfScopeResource,
	SkipFormSubmissionCap,
	SkipFormDestinationExhausted,
	SkipLocationFolded,
}

// slot is the position in SkipAll and the matching counter slot. A switch rather than a search:
// the mapping must be total at compile time, not discovered at runtime and possibly come back
// empty.
func (s Skip) slot() int {
	switch s {
	case SkipDestructiveLogout:
		return 0
	case SkipDestructiveDelete:
		return 1
	case SkipDestructivePurge:
		return 2
	case SkipDestructiveDeactivate:
		return 3
	case SkipDestructiveAdminPlugin:
		return 4
	case SkipDestructiveStateChange:
		return 5
	case SkipUnsupportedScheme:
		return 6
	case SkipMalformedURL:
		return 7
	case SkipCredentialsInURL:
		return 8
	case SkipOutOfScope:
		return 9
	case SkipSendRefused:
		return 10
	case SkipQueryExcluded:
		return 11
	case SkipFormSubmissionDisabled:
		return 12
	case SkipFormNotSubmittable:
		return 13
	case SkipAlreadyQueued:
		return 14
	case SkipTemplateQuota:
		return 15
	case SkipDuplicateLocation:
		return 16
	case SkipDepthLimit:
		return 17
	case SkipFrontierFull:
		return 18
	case SkipLinksPerPage:
		return 19
	case SkipFingerprintBudget:
		return 20
	case SkipNotHTML:
		return 21
	case SkipContentEncoded:
		return 22
	case SkipSendFailed:
		return 23
	case SkipResponseUnreadable:
		return 24
	case SkipResponseTooLarge:
		return 25
	case SkipRetentionExcluded:
		return 26
	case SkipSessionExpired:
		return 27
	case SkipReloginFailed:
		return 28
	case SkipRenderUnavailable:
		return 29
	case SkipSitemapUnparsed:
		return 30
	case SkipJSONUnparsed:
		return 31
	case SkipSpeculativeLimit:
		return 32
	case SkipAPIUnparsed:
		return 33
	case SkipGraphQLUnparsed:
		return 34
	case SkipGraphQLIntrospection:
		return 35
	case SkipOutOfScopeResource:
		return 36
	case SkipFormSubmissionCap:
		return 37
	case SkipFormDestinationExhausted:
		return 38
	case SkipLocationFolded:
		return 39
	}
	panic("unknown Skip")
}

// String is the short name, for log lines and wire formats.
func (s Skip) String() string {
	switch s {
	case SkipDestructiveLogout:
		return "destructive-logout"
	case SkipDestructiveDelete:
		return "destructive-delete"
	case SkipDestructivePurge:
		return "destructive-purge"
	case SkipDestructiveDeactivate:
		return "destructive-deactivate"
	case SkipDestructiveAdminPlugin:
		return "destructive-admin-plugin"
	case SkipDestructiveStateChange:
		return "destructive-state-change"
	case SkipUnsupportedScheme:
		return "unsupported-scheme"
	case SkipMalformedURL:
		return "malformed-url"
	case SkipCredentialsInURL:
		return "credentials-in-url"
	case SkipOutOfScope:
		return "out-of-scope"
	case SkipSendRefused:
		return "send-refused"
	case SkipQueryExcluded:
		return "query-excluded"
	case SkipFormSubmissionDisabled:
		return "form-submission-disabled"
	case SkipFormNotSubmittable:
		return "form-not-submittable"
	case SkipAlreadyQueued:
		return "already-queued"
	case SkipTemplateQuota:
		return "template-quota"
	case SkipDuplicateLocation:
		return "duplicate-location"
	case SkipDepthLimit:
		return "depth-limit"
	case SkipFrontierFull:
		return "frontier-full"
	case SkipLinksPerPage:
		return "links-per-page"
	case SkipFingerprintBudget:
		return "fingerprint-budget"
	case SkipNotHTML:
		return "not-html"
	case SkipContentEncoded:
		return "content-encoded"
	case SkipSendFailed:
		return "send-failed"
	case SkipResponseUnreadable:
		return "response-unreadable"
	case SkipResponseTooLarge:
		return "response-too-large"
	case SkipRetentionExcluded:
		return "retention-excluded"
	case SkipSessionExpired:
		return "session-expired"
	case SkipReloginFailed:
		return "relogin-failed"
	case SkipRenderUnavailable:
		return "render-unavailable"
	case SkipSitemapUnparsed:
		return "sitemap-unparsed"
	case SkipJSONUnparsed:
		return "json-unparsed"
	case SkipSpeculativeLimit:
		return "speculative-limit"
	case SkipAPIUnparsed:
		return "api-unparsed"
	case SkipGraphQLUnparsed:
		return "graphql-unparsed"
	case SkipGraphQLIntrospection:
		return "graphql-not-probed"
	case SkipOutOfScopeResource:
		return "out-of-scope-resource"
	case SkipFormSubmissionCap:
		return "form-submission-cap"
	case SkipFormDestinationExhausted:
		return "form-destination-exhausted"
	case SkipLocationFolded:
		return "location-folded"
	}
	return "unknown"
}

// Explanation is one line an operator can act on.
func (s Skip) Explanation() string {
	switch s {
	case SkipDestructiveLogout:
		return "the link would log the crawl out, ending the session it is authenticated with"
	case SkipDestructiveDelete:
		return "the link signals deleting or destroying a record"
	case SkipDestructivePurge:
		return "the link signals emptying a collection wholesale"
	case SkipDestructiveDeactivate:
		return "the link signals deactivating, disabling or closing an account"
	case SkipDestructiveAdminPlugin:
		return "the link signals an administrative install, upgrade, setup or reset"
	case SkipDestructiveStateChange:
		return "the link's text or target carries a state-changing verb"
	case SkipUnsupportedScheme:
		return "the URL is not http or https, so it is not something to dial"
	case SkipMalformedURL:
		return "the URL could not be parsed or resolved to a host"
	case SkipCredentialsInURL:
		return "the URL embeds credentials, which would let the target choose what the crawl authenticates with"
	case SkipOutOfScope:
		return "the engagement scope excludes the URL"
	case SkipSendRefused:
		return "the scope chokepoint refused the request bytes before the dial"
	case SkipQueryExcluded:
		return "the crawl-scope query does not match the URL"
	case SkipFormSubmissionDisabled:
		return "a form was found and not submitted, because form submission is off"
	case SkipFormNotSubmittable:
		return "the form's enctype or method is one the crawler does not build"
	case SkipFormSubmissionCap:
		return "this form was already submitted the maximum number of times the crawl allows, so it was " +
			"not submitted again: raise max_submissions_per_form to explore it further"
	case SkipFormDestinationExhausted:
		return "this form has been submitted to as many distinct destinations as the optimization " +
			"threshold allows, so its input strategy is treated as exhausted: raise " +
			"form_submission_optimization_threshold to explore further"
	case SkipAlreadyQueued:
		return "an identical request has already been queued or fetched"
	case SkipTemplateQuota:
		return "this URL's template has been visited as many times as the per-template quota allows"
	case SkipDuplicateLocation:
		return "the response's contents had already been seen at another URL"
	case SkipDepthLimit:
		return "the link was found at the depth limit and was not queued"
	case SkipFrontierFull:
		return "the frontier was at its capacity bound and the link was dropped"
	case SkipLinksPerPage:
		return "the page carried more links than the per-page bound admits"
	case SkipFingerprintBudget:
		return "a request-identity table was full, so this URL could not be remembered and was not queued"
	case SkipNotHTML:
		return "the response was fetched and scanned but is not HTML, so no links were extracted"
	case SkipContentEncoded:
		return "the response body is content-encoded, so it is not the markup the server rendered"
	case SkipSendFailed:
		return "the request was authorised and then failed at the transport"
	case SkipResponseUnreadable:
		return "the response came back and could not be captured or read back, so no links were taken from it"
	case SkipResponseTooLarge:
		return "the response was larger than the capture bound, so it was neither stored nor scanned"
	case SkipRetentionExcluded:
		return "the response was captured and scanned, and the crawl-retention query does not match it, so its links were not followed"
	case SkipSessionExpired:
		return "the response is a login page or a template that flipped from 200, so its links were not followed: the session was gone and its links are not the application"
	case SkipReloginFailed:
		return "session expiry was detected and the login macro could not restore the session, so the request was not retried with a fresh cookie"
	case SkipJSONUnparsed:
		return "the response looked like JSON — by its content type or its opening brace — and could not be parsed as one, so any locations it names were not followed"
	case SkipSitemapUnparsed:
		return "the response looked like a sitemap — by its content type or the element names in its body — and could not be parsed as one, so the URLs it publishes were not followed"
	case SkipRenderUnavailable:
		return "the response was HTML but the browser render failed, so links that exist only after the page's script runs were not discovered"
	case SkipSpeculativeLimit:
		return "the speculative-link cap is spent: the URL was mined from a comment or script body and the crawl-wide bound on hidden links is reached"
	case SkipAPIUnparsed:
		return "the response is an API definition (OpenAPI, Swagger or WSDL) that could not be read, so the endpoints it declares were not crawled: check that the document was fetched whole"
	case SkipGraphQLUnparsed:
		return "the endpoint answered a GraphQL introspection query with a schema that could not be read, so its operations were not crawled"
	case SkipGraphQLIntrospection:
		return "the crawl-wide request bound was already spent, so the GraphQL endpoint was not probed"
	case SkipOutOfScopeResource:
		return "the page loads this from a host outside the engagement scope. Burp's crawler fetches such resources by default (allow_out_of_scope_resources); burpsy refuses them, so a page whose content lives on a CDN or a third-party API contributes no locations"
	case SkipLocationFolded:
		return "this page was recognised as one already seen within a tolerance: the same structure and the same set of link paths, with a few link values changed, so its links were not walked again. Counted apart from an exact duplicate because the location count it contributes rests on a tolerance rather than on identical contents"
	}
	return "unknown skip"
}

// SkipCategory groups reasons for a per-category rollup. The categories are what an operator
// triages by: a destructive refusal is a deliberate safety decision, a duplicate is bookkeeping,
// and a limit means the crawl was cut short — three very different things to read in one total.
type SkipCategory int

const (
	// CategoryDestructive is CRAWL-04's refusals.
	CategoryDestructive SkipCategory = iota
	// CategorySafety is a URL that is not safe to dial at all.
	CategorySafety
	// CategoryScope is the engagement scope and the operator's crawl-scope query.
	CategoryScope
	// CategoryPolicy is the operator's own configuration, form submission above all.
	CategoryPolicy
	// CategoryDuplicate is the frontier's and the location map's bookkeeping.
	CategoryDuplicate
	// CategoryLimit is a bound that truncated the crawl; each of these also records a CrawlStop.
	CategoryLimit
	// CategoryResponse is a fetched response that yielded no further links.
	CategoryResponse
)

// SkipCategoryAll is every category, so a rollup can be built without hard-coding the set.
var SkipCategoryAll = [7]SkipCategory{
	CategoryDestructive,
	CategorySafety,
	CategoryScope,
	CategoryPolicy,
	CategoryDuplicate,
	CategoryLimit,
	CategoryResponse,
}

func (c SkipCategory) String() string {
	switch c {
	case CategoryDestructive:
		return "destructive"
	case CategorySafety:
		return "safety"
	case CategoryScope:
		return "scope"
	case CategoryPolicy:
		return "policy"
	case CategoryDuplicate:
		return "duplicate"
	case CategoryLimit:
		return "limit"
	case CategoryResponse:
		return "response"
	}
	return "unknown"
}

// Category is the group this reason rolls up into. Spelled out per reason rather than derived from
// the enum's ordering, so inserting a reason forces a decision here instead of inheriting the
// neighbouring one's category.
func (s Skip) Category() SkipCategory {
	switch s {
	case SkipDestructiveLogout, SkipDestructiveDelete, SkipDestructivePurge,
		SkipDestructiveDeactivate, SkipDestructiveAdminPlugin, SkipDestructiveStateChange:
		return CategoryDestructive
	case SkipUnsupportedScheme, SkipMalformedURL, SkipCredentialsInURL:
		return CategorySafety
	case SkipOutOfScope, SkipSendRefused, SkipQueryExcluded, SkipOutOfScopeResource:
		return CategoryScope
	case SkipFormSubmissionDisabled, SkipFormNotSubmittable, SkipFormSubmissionCap,
		SkipFormDestinationExhausted:
		return CategoryPolicy
	case SkipAlreadyQueued, SkipDuplicateLocation, SkipLocationFolded:
		return CategoryDuplicate
	case SkipDepthLimit, SkipFrontierFull, SkipLinksPerPage, SkipTemplateQuota, SkipFingerprintBudget,
		SkipSpeculativeLimit, SkipGraphQLIntrospection:
		return CategoryLimit
	case SkipNotHTML, SkipSitemapUnparsed, SkipJSONUnparsed, SkipAPIUnparsed,
		SkipGraphQLUnparsed, SkipContentEncoded, SkipSendFailed, SkipResponseUnreadable,
		SkipResponseTooLarge, SkipRetentionExcluded, SkipSessionExpired, SkipReloginFailed,
		SkipRenderUnavailable:
		return CategoryResponse
	}
	panic("unknown Skip")
}

// Destructive reports whether this reason is one of CRAWL-04's refusals.
func (s Skip) Destructive() bool { return s.Category() == CategoryDestructive }

// SkipRecord is one individual decline, kept so a refusal names the thing it refused rather than
// only incrementing a total.
type SkipRecord struct {
	// Reason is the bucket. Count is the aggregate; this is the instance.
	Reason Skip `json:"reason"`
	// URL is the absolute URL that was not fetched, or the raw href when it could not be resolved.
	URL string `json:"url"`
	// Method is the method the crawler would have used.
	Method string `json:"method,omitempty"`
	// Text is the link text or form label the link was found under, normalised to single spaces.
	// Empty for a redirect target or a seed, which have no text.
	Text string `json:"text,omitempty"`
	// Signal is the exact token sequence from the destructive table that matched, and where it
	// matched — "delete (target)" or "log out (text)". Empty for a non-destructive reason. This is
	// the field that makes a refusal reviewable: an operator who thinks it was wrong can see what
	// tripped it.
	Signal string `json:"signal,omitempty"`
	// Detail carries a reason-specific line, such as the scope's own explanation of a refusal.
	Detail string `json:"detail,omitempty"`
	// FoundAt is the URL of the page the link was discovered on, empty for a seed.
	FoundAt string `json:"found_at,omitempty"`
}

// SkipCount is one reason and how many times it fired.
type SkipCount struct {
	Reason Skip   `json:"reason"`
	Name   string `json:"name"`
	Count  uint64 `json:"count"`
}

// CategoryCount is one category and how many declines rolled up into it.
type CategoryCount struct {
	Category SkipCategory `json:"category"`
	Name     string       `json:"name"`
	Count    uint64       `json:"count"`
}

// DefaultMaxSkipRecords bounds the sample of individual records one crawl keeps.
//
// A crawl of a large application can decline tens of thousands of links — mostly duplicates — and
// keeping every one would make the report the memory problem. The per-reason counts are unbounded
// and exact; only the sample is capped, and SkipReport.RecordsDropped says how much of it was
// discarded, so the cap cannot be mistaken for the total.
const DefaultMaxSkipRecords = 500

// SkipReport is an owned, point-in-time snapshot of the ledger.
//
// Owned rather than a lock guard: a caller renders this after the call returns instead of holding
// the crawl's ledger locked while it does, the same shape scanner.CoverageReport has.
type SkipReport struct {
	// Counts holds one entry per reason, in SkipAll order, including the zeroes. A reason that
	// never fired is reported as zero rather than omitted — "no destructive links were refused" is
	// a result, and an absent row would read as "this crawler does not check for that".
	Counts []SkipCount `json:"counts"`
	// Categories is the same totals rolled up, in SkipCategoryAll order.
	Categories []CategoryCount `json:"categories"`
	// Records is the bounded sample of individual declines, in the order they happened.
	Records []SkipRecord `json:"records,omitempty"`
	// RecordsDropped counts declines that were counted but whose record did not fit the sample.
	RecordsDropped int `json:"records_dropped"`
}

// Total is every decline, across every reason.
func (r SkipReport) Total() uint64 {
	var n uint64
	for _, c := range r.Counts {
		n += c.Count
	}
	return n
}

// Count reports how many times one reason fired.
func (r SkipReport) Count(s Skip) uint64 {
	for _, c := range r.Counts {
		if c.Reason == s {
			return c.Count
		}
	}
	return 0
}

// CategoryTotal reports how many declines rolled up into one category.
func (r SkipReport) CategoryTotal(c SkipCategory) uint64 {
	for _, cc := range r.Categories {
		if cc.Category == c {
			return cc.Count
		}
	}
	return 0
}

// DestructiveRecords returns the sampled records for CRAWL-04's refusals only — the list an
// operator reviews to decide whether the crawler was too shy.
func (r SkipReport) DestructiveRecords() []SkipRecord {
	out := make([]SkipRecord, 0, len(r.Records))
	for _, rec := range r.Records {
		if rec.Reason.Destructive() {
			out = append(out, rec)
		}
	}
	return out
}

// Summary formats the ledger for reports and logs. It always names the total and the per-category
// split, including zeroes, so "nothing was skipped" is stated rather than inferred from silence.
func (r SkipReport) Summary() string {
	return fmt.Sprintf(
		"%d links not fetched: %d destructive, %d unsafe, %d out of scope or query, %d by policy, %d duplicates, %d at a limit, %d yielded no links",
		r.Total(),
		r.CategoryTotal(CategoryDestructive),
		r.CategoryTotal(CategorySafety),
		r.CategoryTotal(CategoryScope),
		r.CategoryTotal(CategoryPolicy),
		r.CategoryTotal(CategoryDuplicate),
		r.CategoryTotal(CategoryLimit),
		r.CategoryTotal(CategoryResponse),
	)
}

// skipLedger is the mutable table the crawl writes into.
//
// Unexported, with Snapshot the only way out, so a caller can never hold the lock or mutate the
// counts. Behind a mutex even though the crawl loop is sequential: a progress reader on another
// goroutine is the whole point of being able to snapshot mid-crawl, and a racy read of the counts
// would be a data race whether or not it produced a wrong number.
type skipLedger struct {
	mu sync.Mutex
	// Sized from SkipAll rather than written as a number, because the two were hand-maintained and
	// drifted: SkipAll's length is checked by the compiler, this one is not, and a Skip value added
	// to the first and forgotten in the second panics on the first decline rather than at build.
	counts     [len(SkipAll)]uint64
	records    []SkipRecord
	dropped    int
	maxRecords int
}

func newSkipLedger(maxRecords int) *skipLedger {
	if maxRecords < 0 {
		maxRecords = 0
	}
	return &skipLedger{maxRecords: maxRecords}
}

// record counts one decline and keeps its detail if the sample has room. The count is incremented
// whether or not the record fits — that asymmetry is the point of the bound.
func (l *skipLedger) record(rec SkipRecord) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.counts[rec.Reason.slot()]++
	if len(l.records) < l.maxRecords {
		l.records = append(l.records, rec)
		return
	}
	l.dropped++
}

// Snapshot returns an owned copy of the ledger.
func (l *skipLedger) Snapshot() SkipReport {
	l.mu.Lock()
	defer l.mu.Unlock()

	counts := make([]SkipCount, 0, len(SkipAll))
	byCategory := make(map[SkipCategory]uint64, len(SkipCategoryAll))
	for _, s := range SkipAll {
		n := l.counts[s.slot()]
		counts = append(counts, SkipCount{Reason: s, Name: s.String(), Count: n})
		byCategory[s.Category()] += n
	}
	cats := make([]CategoryCount, 0, len(SkipCategoryAll))
	for _, c := range SkipCategoryAll {
		cats = append(cats, CategoryCount{Category: c, Name: c.String(), Count: byCategory[c]})
	}
	records := make([]SkipRecord, len(l.records))
	copy(records, l.records)
	return SkipReport{
		Counts:         counts,
		Categories:     cats,
		Records:        records,
		RecordsDropped: l.dropped,
	}
}
