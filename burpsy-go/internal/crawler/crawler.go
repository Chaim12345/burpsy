// Package crawler discovers an application's structure from a seed URL, feeding everything it
// fetches through the same capture-and-scan path proxied traffic takes.
//
// This is roadmap Phase 6's CRAWL-01, CRAWL-02, CRAWL-03, CRAWL-04, CRAWL-07 and DSL-03. It is new
// work, not a port: the Rust original has no crawler at all.
//
// # The one architectural constraint (CRAWL-02)
//
// Crawled traffic is captured, scoped and scanned through *exactly* the same path as proxied
// traffic. Not an equivalent path — the same one:
//
//   - **Egress** goes through sender.AuthorisedSender, the Phase 1 scope chokepoint, which checks
//     the request bytes actually about to be written and refuses before the dial. There is no other
//     way out of this package: Crawler holds no net.Dialer, no http.Client and no *sender.Sender it
//     can reach around the authoriser with.
//   - **Capture and scan** go through scanner.Capture, which is Server.runPassiveScan's body,
//     extracted so both surfaces call it. Store the request, store the response, index the exchange,
//     run the passive check set, run the static DOM pass, enrich, record the findings — one
//     implementation, so the crawler's coverage story cannot drift from the proxy's.
//
// The reason this is a constraint and not a feature is that the second copy always drifts, and the
// first thing to drift is the honest-reporting behaviour that took a phase each to get right.
//
// ## Why not route crawl traffic through burpsy's own proxy listener
//
// It looks like it would enforce scope for free, and it would not. internal/proxy/proxy.go's plain
// path reads `inScope := scope.Contains(...)` and then, when the answer is no, calls forwardOnly —
// whose own comment is "Forward without storing". The TLS path and the HTTP/2 relay have the same
// shape. Scope gates *capture* in the proxy, never *forwarding*, and that is correct for a proxy: a
// tool must not break the operator's browsing because they clicked an out-of-scope link.
//
// For a crawler it is the worst of both worlds. A crawl pointed at the proxy could wander onto another
// host or an internal service, every request would reach it, and none of it would be recorded —
// off-scope *and* invisible, which is worse than either alone. So AuthorisedSender is the egress, and
// the proxy is not a shortcut to it.
//
// ## Why no crawler library
//
// Both viable Go options were assessed and rejected. katana's options struct exposes no custom
// http.Client, RoundTripper or per-request authorisation hook, and its OnResult/OnSkipURL callbacks
// fire around a request it has already decided to send — observational, not gating, so it cannot
// satisfy CRAWL-02 or HARD-03 without a fork. colly *can* be given a RoundTripper and so could route
// through AuthorisedSender, but its deduplication is URL-keyed (AllowURLRevisit, HasVisited(url)),
// which is precisely the model PortSwigger says is insufficient and this package replaces — adopting
// it would mean fighting it to get content-based location identity — and it brings goquery, xmlquery,
// chardet and robotstxt into a security tool's supply chain. What either library would actually have
// supplied is HTML parsing, a queue and a rate limiter; golang.org/x/net/html, a slice and
// internal/intruder's limiter cover all three with no new dependency. Everything that makes this
// phase what it is — the chokepoint, destructive refusal *with reporting*, unfetched-frontier
// accounting, query scoping, content fingerprinting — would have been custom either way.
//
// One idea was worth taking from colly and one from katana: its LimitRule's per-host shape (this
// package keeps a limiter per authority, see limiterFor) and katana's OnSkipURL as evidence that a
// skip should be a first-class observable rather than a counter (hence skip.go's SkipRecord). colly's
// randomised delay was considered and left out: randomising a crawl's spacing buys evasion, not
// politeness, and this package's rate limit exists for politeness.
//
// # Traversal: breadth-first over a frontier queue
//
// Breadth-first, because it prioritises discovering new content over exhausting one path — the same
// reason PortSwigger's crawler is breadth-first. A depth-first crawl of a paginated list spends its
// whole budget on page 2, 3, 4… of one list; a breadth-first crawl sees the rest of the navigation
// first.
//
// ## Named limit: a queue, not a state machine
//
// Burp models the application as a directed graph of locations and edges, and *re-navigates from a
// known point* rather than jumping straight at a queued URL — so a link that only works as the third
// step of a wizard is reached by walking the wizard. This package does not do that. It holds a
// frontier queue and issues each queued request directly, in isolation.
//
// What that costs: any location that is only reachable through a sequence of state-changing requests
// is not reached, and the crawl cannot tell that it missed it. That is a real gap, it is the largest
// single gap in this package, and it is stated here rather than implied away — a frontier crawler
// that presents itself as graph-accurate is exactly the kind of over-claim the rest of this file is
// organised against.
//
// Worth being precise about the scope of that gap, though, because it is narrower than it sounds for
// this slice: everything a re-navigating graph buys — multi-step wizards, POST-only intermediate
// steps, one-shot tokens consumed by an earlier request — is reachable only by *submitting forms*,
// and CRAWL-03 has form submission off by default. A default crawl therefore cannot encounter any of
// those cases, so the frontier queue is not a compromise for it; it becomes one exactly when an
// operator turns form submission on, and that is the point at which the graph work is worth doing.
//
// ## Named limit: no JavaScript execution
//
// Links are read from the markup as it arrived. A single-page application whose navigation is built
// at runtime presents one location — its shell — and the crawl of it is honest but nearly empty.
// Phase 12's dynamic-confirmation work is where a real browser enters this codebase; until then, a
// crawl of an SPA reporting one location is the truth about what this crawler saw, not a claim about
// the application.
//
// ## Named limit: subresources are neither fetched nor fingerprinted
//
// `img`, `script`, `link`, `video` and friends are never queued, and their `src` values are kept out
// of the location fingerprint as well — a rebuilt bundle hash in a filename would otherwise make every
// page a new location on every deploy. Two consequences: a crawl will not tell you `/static/app.js`
// returned 500, and two pages differing only in their images are one location. See discover.go.
//
// ## Named limit: one request at a time
//
// The loop is sequential. Concurrency is bounded at one by construction rather than by a configurable
// in-flight count — so a crawl of a large application is slow in exact proportion to its size. Stated
// as a bound rather than exposed as a knob that is silently ignored. Two rate limiters sit on top of
// that: a crawl-wide cap so discovering fifty hosts does not multiply the traffic by fifty, and one
// per authority carrying an AutoThrottle so a target's own 429s slow that target and not the others.
//
// # Identity: locations are identified by their contents
//
// The insight this package takes from PortSwigger's own design, and the reason a URL-keyed crawler
// fails on ordinary applications: a location is identified by what came back, not by the URL used to
// reach it. CSRF tokens, cache-busters and session ids in URLs all make URL-keyed deduplication fail
// open, and an "infinite" application — their example is a calendar — will consume any budget you
// give it. fingerprint.go implements both the pre-fetch request fingerprint and the post-fetch
// content fingerprint, and documents what each of them costs.
//
// # Safety, and the crawler as an SSRF risk
//
// A hostile or compromised target can steer a crawler at hosts it was never pointed at — a link, a
// redirect, or a sitemap naming an internal service. So:
//
//   - The **scheme** is checked before anything else. http and https only; `javascript:`, `data:`,
//     `file:`, `mailto:`, `ws:` and everything else is refused and counted.
//   - **Userinfo in a URL is refused.** A target that chooses which credentials the crawl presents
//     can make it authenticate somewhere it should not.
//   - **A redirect is not followed.** The `Location` of a 3xx response re-enters the frontier as an
//     ordinary discovered link, through every gate a link from the body would pass, and is
//     authorised against scope again on its own request bytes. A cross-host redirect therefore
//     cannot escape scope, because there is no code path that dials a redirect target without
//     re-authorising it.
//   - **Every request is rate limited.** intruder.RateLimiter, reused rather than reimplemented, so
//     this package does not become the third rate limiter in the repository.
//
// # robots.txt: read as a discovery source, never obeyed as a restriction
//
// This is a deliberate two-part decision, and the second part is the one that matters. **Do not fix
// this later by adding Disallow enforcement.**
//
// *Not obeyed*, because robots.txt is a crawl-budget convention for indexing bots and not an access
// control. A pentest tool that honoured it would be deferring to a preference the application's owner
// expressed to search engines rather than to the authorisation the operator actually holds — and the
// paths it names are exactly the ones worth testing. An assessment that skipped `/admin` because the
// target asked nicely would produce its emptiest results on its most interesting targets, and nothing
// in the report would say why. Burp makes the same call.
//
// *But read*, because a Disallow list is the target's own inventory of what it would rather nobody
// looked at, which is free reconnaissance. So the crawl fetches /robots.txt once per seed authority
// and offers every Disallow, Allow and Sitemap path to the frontier.
//
// Two properties of how that is done are load-bearing:
//
//   - Robots-derived paths enter as **discovered links, not seeds**, so they pass the
//     destructive-action check, the scope gate and the crawl-scope query like any other
//     target-supplied URL. A `Disallow: /admin/purge-all` line must not become a request, and it does
//     not: seeds skip the destructive check because they are the operator's instruction, and this is
//     not that.
//   - The robots.txt request itself goes through enqueue, so it is rate limited, scope-gated and
//     captured through the shared seam like every other request. It is not a privileged side channel.
//
// Report.RobotsPathsFound counts what came from there, so a crawl's coverage can be attributed.
package crawler

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/intruder"
	"github.com/burpsy-go/burpsy/internal/query"
	"github.com/burpsy-go/burpsy/internal/scanner"
	"github.com/burpsy-go/burpsy/internal/sender"
	"go.uber.org/zap"
)

// RobotsPolicy is this crawler's robots.txt decision, carried in every report so the choice is
// visible to whoever reads one instead of being an absence they have to notice. See the package docs
// for the reasoning.
const RobotsPolicy = "robots.txt is neither fetched nor honoured — deliberate, see internal/crawler's package documentation"

// DefaultUserAgent identifies the crawler honestly. A tool that disguises itself as a browser makes
// the target's own logs lie to its operator about who caused what, which on an authorised engagement
// is a cost with no benefit.
const DefaultUserAgent = "burpsy-crawler/1.0"

// DefaultRequestsPerSecond is the crawl's default rate.
//
// Half of intruder's 20/s default, deliberately. An attack is a bounded burst the operator is
// watching; a crawl is an unattended traversal that can run for minutes and touch every endpoint an
// application has, including the expensive ones. The politeness bound should be tighter for the
// thing that runs unwatched.
const DefaultRequestsPerSecond = 10.0

// Scope is the engagement scope handle a crawl needs: the per-request raw-bytes gate that
// AuthorisedSender enforces, plus the pre-fetch host/path pre-filter that keeps out-of-scope links
// off the frontier in the first place.
//
// Both checks, because they answer different questions. Contains answers "is this URL worth queuing"
// before a request exists to check; AuthoriseRaw answers "may these exact bytes go on the wire" and
// is the only one that authorises anything. *core.Scope and *core.SharedScope both satisfy this.
type Scope interface {
	sender.ScopeChecker
	Contains(host string, port uint16, path string, isTLS bool) bool
}

// Config configures one crawl. Zero-valued Limits and RequestsPerSecond take their defaults; the
// collaborators are required and New says so rather than crawling with a piece missing.
type Config struct {
	// Seeds are the URLs the crawl starts from. At least one is required, and each must be an
	// absolute http or https URL with a host.
	Seeds []string
	// Scope is the engagement scope. Required: a crawler with no scope gate is an SSRF engine that
	// dials whatever the target names.
	Scope Scope
	// Sender is the raw transport. It is never used directly — every send is wrapped in a
	// sender.AuthorisedSender bound to the target origin, which is what makes the scope check
	// unavoidable rather than customary.
	Sender *sender.Sender
	// Capture is the shared capture-and-scan seam (CRAWL-02). Its Store is required; a nil Scanner or
	// Findings means traffic is captured and not scanned, which is scanner.Capture's own documented
	// behaviour and not this package's business to override.
	Capture scanner.Capture
	// Query is the crawl-scope query (DSL-03), in internal/query's grammar. Empty means no query
	// filter. It is evaluated before each fetch, so it may only name fields a frontier URL has —
	// host and method. New refuses a query naming status, mime or body, rather than evaluating it
	// against absent values and silently matching or not matching.
	Query string
	// RetentionQuery is the crawl-*retention* query (DSL-03's second gate), in the same grammar. Empty
	// means no filter. Unlike Query it is evaluated after the fetch, so it may name every field the
	// grammar has — host, method, status, mime and body. It does not decide whether to send a request;
	// CRAWL-02 has already captured and scanned the response by the time it runs. What it decides is
	// whether that response's links are followed, which is why a non-match is a response-category skip
	// (SkipRetentionExcluded) and not a scope refusal.
	RetentionQuery string
	// SubmitForms turns form submission on (CRAWL-03). The zero value is off, and that is the
	// requirement, not a default: a crawl that submits forms writes to the application.
	SubmitForms bool
	// Limits bounds the crawl. See Limits and DefaultLimits.
	Limits Limits
	// RequestsPerSecond caps the request rate. Zero takes DefaultRequestsPerSecond.
	RequestsPerSecond float64
	// Pool is a resolved named resource pool's limits, or nil for this package's own defaults.
	//
	// It is the *resolved* RateLimit rather than a pool name because this package has no business
	// looking names up: the caller that holds the registry resolves once — see internal/pool — and
	// hands the answer down. Set, it overrides RequestsPerSecond and replaces the per-host
	// DefaultAutoThrottle with the pool's own.
	//
	// One of a pool's three bounds cannot be honoured here and is not silently dropped: MaxInFlight.
	// The crawl loop sends one request and waits for the response before building the next, so a
	// ceiling above 1 bounds nothing. Report.Pool says which pool ran and Report.PoolConcurrency
	// records the ceiling that did not apply, and pool.Support() states the same thing on the API.
	Pool *intruder.RateLimit
	// UserAgent is the User-Agent header sent. Empty takes DefaultUserAgent.
	UserAgent string
	// Headers are extra request headers, sent on every request — a Cookie header from a
	// recorded login is what makes an authenticated crawl authenticated. Host, Content-Length and
	// Content-Type are refused here because they are framing the crawler computes per request, and
	// a name or value carrying CR or LF is refused because that is request splitting.
	Headers map[string]string
	// SessionCoordinator is the optional re-login seam. nil keeps the static-Headers
	// behaviour exactly: a session that dies stays dead, and the crawl honestly maps the
	// login page from then on. Set it and an expired session is detected and restored
	// within the re-login budget. See session_gate.go.
	SessionCoordinator SessionCoordinator
	// LoginPagePattern is a regex, matched against a response body, that identifies the
	// application's login page — the second signal (besides a 200→non-200 template flip)
	// that the session is gone. Empty (the default) disables this signal and keeps the
	// status-flip rule. Compiled in New; a malformed pattern is a construction error.
	LoginPagePattern string
	// MaxSkipRecords bounds the sampled refusal detail. Zero takes DefaultMaxSkipRecords; a negative
	// value keeps counts only.
	MaxSkipRecords int
	// Logger is optional.
	Logger *zap.Logger
}

// Fetch is one request the crawl actually sent, and what came back. The list of these is the "what
// it did reach" half of the coverage story CRAWL-07 asks about; LimitReport.Unfetched is the other.
type Fetch struct {
	URL    string `json:"url"`
	Method string `json:"method"`
	// Status is the response status, or 0 when the response could not be parsed.
	Status int `json:"status"`
	// ExchangeID is the store id, so a caller can pull the request and response bytes out of history.
	ExchangeID core.ExchangeID `json:"exchange_id"`
	// Depth is how many links from a seed this was. A seed is 0.
	Depth int `json:"depth"`
	// Fingerprint is the location fingerprint, empty for a redirect (which is an edge, not a
	// location) and for a response whose body could not be read.
	Fingerprint string `json:"fingerprint,omitempty"`
	// DuplicateOf is set when this response's contents had already been seen at another URL, which is
	// why the links it carries were not queued again.
	DuplicateOf string `json:"duplicate_of,omitempty"`
	// RetentionExcluded records that the crawl-retention query did not match this response, so it was
	// captured and scanned but not traversed.
	RetentionExcluded bool `json:"retention_excluded,omitempty"`
}

// Report is one crawl's whole outcome.
//
// Every count here is a partition of something, not a highlight: Fetched + Refused + Failed is every
// request the loop attempted, and Skips accounts for every URL that was discovered and not attempted.
// A caller can therefore always answer "what happened to the other ones", which is the property that
// makes a crawl report readable as coverage rather than as a highlight reel.
type Report struct {
	// Seeds is what the crawl was pointed at.
	Seeds []string `json:"seeds"`
	// Query is the crawl-scope query as the operator wrote it, empty when there was none.
	Query string `json:"query,omitempty"`
	// RetentionQuery is the post-fetch traversal query as the operator wrote it.
	RetentionQuery string `json:"retention_query,omitempty"`
	// FormSubmission records whether form submission was on (CRAWL-03), so a report cannot be read
	// as "this application has no forms" when it means "forms were not submitted".
	FormSubmission bool `json:"form_submission"`
	// RobotsPolicy is the constant of the same name — carried, not implied.
	RobotsPolicy string `json:"robots_policy"`
	// Pool is the named resource pool this crawl ran under, empty when it ran under this package's
	// own defaults. Carried so a report can say what bounded it rather than leaving the reader to
	// infer a rate from timestamps.
	Pool string `json:"pool,omitempty"`
	// PoolConcurrency is the pool's max-concurrent-requests ceiling, when a pool set one. Present
	// *because* it was not honoured: the crawl loop is sequential, so this records the bound that did
	// not apply. An operator who set 8 and sees 8 here alongside a sequential crawl has been told the
	// truth; a field omitted because it was unused would have told them nothing.
	PoolConcurrency int `json:"pool_concurrency,omitempty"`

	// Fetched, Refused, Failed and NotCaptured partition every request the loop attempted, exactly
	// once each. Fetched counts requests that reached the shared capture path; Refused counts the
	// scope chokepoint's refusals, which never reached a socket; Failed counts authorised requests
	// that failed at the transport or whose response the store rejected; NotCaptured counts responses
	// deliberately dropped at the capture bound.
	Fetched int `json:"fetched"`
	Refused int `json:"refused"`
	Failed  int `json:"failed"`
	// NotCaptured counts responses that came back and were deliberately not stored because they
	// exceeded the capture bound. Its own member of the partition rather than folded into Failed:
	// nothing failed, a bound was applied, and the two call for different responses from an operator.
	NotCaptured int `json:"not_captured"`

	// RobotsPathsFound counts paths taken from a robots.txt and offered to the frontier. Reported
	// separately from LinksFound because they are a different kind of discovery: nothing linked to
	// them, the target asked for them not to be visited, and that request was deliberately not
	// honoured. An operator reviewing a crawl should be able to see how much of it came from there.
	RobotsPathsFound int `json:"robots_paths_found"`
	// HeadersWithheld counts requests sent without Config.Headers because their origin was not one the
	// operator seeded. Non-zero means the crawl left the origins it was given credentials for, so any
	// "nothing found" beyond that point is unauthenticated coverage rather than a clean result — which
	// is exactly the distinction that would otherwise be invisible.
	HeadersWithheld int `json:"headers_withheld"`
	// LinksFound and FormsFound count what was discovered in responses, before any gate.
	// FormsSubmitted counts forms actually sent — zero unless FormSubmission is on.
	LinksFound     int `json:"links_found"`
	FormsFound     int `json:"forms_found"`
	FormsSubmitted int `json:"forms_submitted"`

	// Locations counts distinct content fingerprints; DuplicateLocations counts fetches whose
	// contents had already been seen. Their sum is every response that was fingerprinted at all.
	Locations          int `json:"locations"`
	DuplicateLocations int `json:"duplicate_locations"`

	// Fetches is one entry per request that reached the target, in the order sent.
	Fetches []Fetch `json:"fetches,omitempty"`
	// Skips accounts for every discovered URL that was not fetched, per reason (CRAWL-04).
	Skips SkipReport `json:"skips"`
	// Limits says which bounds were hit and how many URLs went unfetched (CRAWL-07).
	Limits LimitReport `json:"limits"`
	// Elapsed is the crawl's wall-clock duration.
	Elapsed time.Duration `json:"elapsed"`
}

// Complete reports whether the crawl exhausted its frontier without hitting a bound. False means the
// application is larger than what this report describes.
func (r Report) Complete() bool { return !r.Limits.Truncated() }

// Caveat is the line that must accompany any rendering of an incomplete crawl, empty for a complete
// one. Delegated to LimitReport.Caveat, which derives it from the recorded stops.
func (r Report) Caveat() string { return r.Limits.Caveat() }

// Summary is the crawl in one paragraph, ending with the caveat when there is one — so the obvious
// thing to render cannot present a truncated crawl as a whole one.
func (r Report) Summary() string {
	forms := "off"
	if r.FormSubmission {
		forms = "on"
	}
	s := fmt.Sprintf(
		"crawled %d URLs in %s: %d locations (%d duplicate), %d links and %d forms found, %d forms submitted (submission %s), %d refused by scope, %d failed to send; %s",
		r.Fetched,
		r.Elapsed.Round(time.Millisecond),
		r.Locations,
		r.DuplicateLocations,
		r.LinksFound,
		r.FormsFound,
		r.FormsSubmitted,
		forms,
		r.Refused,
		r.Failed,
		r.Skips.Summary(),
	)
	if c := r.Caveat(); c != "" {
		return s + " — " + c
	}
	return s + " — the frontier emptied, so this crawl is complete within its scope and query"
}

// frontierItem is one queued request.
type frontierItem struct {
	url    *url.URL
	method string
	// body and contentType are set for a form submission, empty otherwise.
	body        []byte
	contentType string
	depth       int
	// foundAt is the URL of the page this was discovered on, empty for a seed. Reporting only.
	foundAt string
	// text is the link text or form label, for reporting a later refusal against the right label.
	text string
	// fieldNames are a form submission's field names, for the URL template. Nil for a plain link: a
	// GET's parameters are already in its URL.
	fieldNames []string
	// robots marks the one request per authority that fetches /robots.txt. It travels the frontier as
	// an ordinary item — same rate limit, same scope gate, same capture — and differs only in that its
	// body is read as a path list instead of as markup. See seedFromRobots.
	robots bool
}

// Crawler runs one crawl. Not safe for concurrent Run calls: the frontier, the seen sets and the
// report are per-crawl state, and a Crawler is cheap enough that sharing one buys nothing.
type Crawler struct {
	cfg    Config
	limits Limits
	// query is the parsed crawl-scope query (DSL-03), nil when the operator gave none. Parsed once in
	// New, so a malformed query is a construction error and never a per-URL surprise.
	query *query.Expr
	// seedURLs are the validated, absolute seeds. Held parsed rather than re-parsed per Run, because
	// New has already rejected everything wrong with them.
	seedURLs []*url.URL
	// retention is the parsed post-fetch query (DSL-03 gate b), nil when the operator gave none.
	retention *query.Expr
	// limiter is the aggregate rate cap; hostLimiters holds one per authority. See visit for why both.
	limiter      *intruder.RateLimiter
	hostLimiters map[string]*intruder.RateLimiter
	requestsPer  float64
	// rateCapped says whether requestsPer is a cap at all. Only a named pool can turn the cap off,
	// and the two facts have to travel together — a bare 0 would otherwise read as "zero requests a
	// second", which is a stall rather than an absence of a limit.
	rateCapped bool
	// throttle is the per-host AutoThrottle, from the pool when there is one. nil is throttling off.
	throttle *intruder.AutoThrottle
	// poolName and poolConcurrency are carried for the report only: the name so a crawl can say what
	// bounded it, and the concurrency ceiling so it can say which of that pool's bounds it could not
	// honour. Neither is read on the request path.
	poolName        string
	poolConcurrency int
	skips           *skipLedger
	logger          *zap.Logger

	// senders caches one AuthorisedSender per origin. Cached because AuthorisedSender counts its own
	// sends and refusals per target, and building a fresh one per request would throw those counters
	// away — they are the crawler's cross-check that its own Refused count matches the chokepoint's.
	senders map[string]*sender.AuthorisedSender

	// credentialOrigins are the origins Config.Headers may be sent to: the seeds' own origins, and
	// nothing else. Keyed by originKey, so scheme, host and port all have to match.
	//
	// This exists because Config.Headers is where an operator puts a session cookie, and buildRequest
	// used to write them onto *every* request it built. Frontier items are not all operator-chosen:
	// they come from links in target-supplied markup, from Location headers on redirects, and from
	// robots.txt. So a page under an in-scope wildcard could name any sibling host — or the same host
	// over plain http — and the crawler would hand over the operator's session cookie, in cleartext in
	// the http case. Scope is not a defence here: a wildcard include, or an empty-but-non-nil Scope
	// (which default-allows), both authorise the request, and authorising a request is not the same
	// question as whether it should carry credentials.
	//
	// Seeds are the right boundary because they are the one set of origins the operator named
	// themselves. Everything else in the frontier is, ultimately, target-controlled.
	credentialOrigins map[string]bool
	// headersWithheld counts requests that did not carry Config.Headers because their origin was not a
	// seed origin. Counted rather than silent: a crawl that reached an authenticated area and then
	// quietly stopped authenticating would otherwise look like a crawl that found nothing there.
	headersWithheld int

	frontier []frontierItem
	// queued holds one exact-request fingerprint per request ever queued, which is what makes
	// SkipAlreadyQueued possible: an entry stays after the item leaves the frontier, because the question
	// it answers is "have I already sent this", not "is this waiting". It is therefore the one structure
	// that grows for the whole crawl and never shrinks, and it is bounded by Limits.MaxFingerprints —
	// stated rather than left at the MaxFrontier + MaxRequests it worked out to before, since a
	// derivative bound moves whenever either of those does and nothing reported it.
	queued    map[string]bool
	locations map[string]string
	// templates counts fetches admitted per URL template, for the quota. Bounded by
	// Limits.MaxFingerprints as well: an entry is created for every template not seen before, including
	// for links dropped at a full frontier, so this one grows even while the crawl fetches nothing new.
	templates map[string]int
	// templateOK remembers the URL templates this crawl has seen return 200, so the session
	// expiry detector can tell a template that flipped from one that simply never worked. Set at
	// most per template, like the quota table; an entry is removed when a template stops matching.
	templateOK map[string]bool
	// relogins counts every attempt to restore the session (re-login budget generation counter).
	// Bounded by Limits.MaxRelogins. Counted per attempt, so concurrent and sequential waves of
	// expiry share one budget. Success or failure moves the counter; see session_gate.go.
	relogins int
	// loginPage is the compiled LoginPagePattern, nil when none was given. The regex is compiled
	// in New so a malformed pattern is a construction error, never a per-URL surprise.
	loginPage *regexp.Regexp
	// robotsSeeded records the authorities whose robots.txt has already been read, so it is read once
	// per authority and never in a loop.
	robotsSeeded map[string]bool
}

// New validates a configuration and returns a crawler for it.
//
// Everything that can be wrong with a configuration is wrong here, before a single request is sent: a
// seed that is not an http URL, a missing scope, a query that cannot be parsed, a query naming a
// field a frontier URL does not have, a header that would split a request. A crawl that started and
// then reported those as per-URL skips would bury an operator's typo in a refusal ledger.
func New(cfg Config) (*Crawler, error) {
	if len(cfg.Seeds) == 0 {
		return nil, fmt.Errorf("a crawl needs at least one seed URL")
	}
	if cfg.Scope == nil {
		return nil, fmt.Errorf("a crawl needs a scope: without one the crawler dials whatever the target names, which is an SSRF engine and not a crawler")
	}
	if cfg.Sender == nil {
		return nil, fmt.Errorf("a crawl needs a sender to reach the target through")
	}
	if cfg.Capture.Store == nil {
		return nil, fmt.Errorf("a crawl needs a traffic store: CRAWL-02 requires crawled traffic to be captured through the same path as proxied traffic, and there is nowhere to capture it to")
	}

	seeds := make([]*url.URL, 0, len(cfg.Seeds))
	for _, s := range cfg.Seeds {
		u, err := url.Parse(strings.TrimSpace(s))
		if err != nil {
			return nil, fmt.Errorf("seed %q is not a URL: %w", s, err)
		}
		if !supportedScheme(u.Scheme) {
			return nil, fmt.Errorf("seed %q has scheme %q; a crawl can only start from http or https", s, u.Scheme)
		}
		if u.Host == "" {
			return nil, fmt.Errorf("seed %q has no host", s)
		}
		if u.User != nil {
			return nil, fmt.Errorf("seed %q embeds credentials in the URL; put them in Config.Headers instead, which are sent only to the origins you seed and never to a host discovered from the target's own content", s)
		}
		u.Fragment = ""
		u.RawFragment = ""
		if u.Path == "" {
			u.Path = "/"
		}
		seeds = append(seeds, u)
	}

	var expr *query.Expr
	if strings.TrimSpace(cfg.Query) != "" {
		parsed, err := query.Parse(cfg.Query)
		if err != nil {
			// Returned unwrapped so a caller can errors.As it back to *query.QueryError and render
			// the caret — DSL-04's guarantee has to survive being reused here.
			return nil, err
		}
		if bad := unavailablePreFetch(parsed.Fields()); len(bad) > 0 {
			return nil, fmt.Errorf(
				"the crawl-scope query names %s, which a frontier URL does not have: the query decides whether to fetch a URL, so it is evaluated before there is a response to ask about. Pre-fetch the query may name host, method and path only",
				strings.Join(bad, " and "),
			)
		}
		expr = parsed
	}

	// The retention query takes the whole grammar, because by the time it runs the response exists.
	// Parsed here rather than per response so a malformed one is a construction error, exactly like
	// the scope query's.
	var retention *query.Expr
	if strings.TrimSpace(cfg.RetentionQuery) != "" {
		parsed, err := query.Parse(cfg.RetentionQuery)
		if err != nil {
			return nil, err
		}
		retention = parsed
	}

	for name, value := range cfg.Headers {
		if err := validateHeader(name, value); err != nil {
			return nil, err
		}
	}

	// The login-page pattern decides whether a captured response means the session is gone.
	// Compiled here so a malformed one is a construction error like every other misconfiguration,
	// not a per-URL surprise that surfaces mid-crawl.
	var loginPage *regexp.Regexp
	if strings.TrimSpace(cfg.LoginPagePattern) != "" {
		re, err := regexp.Compile(cfg.LoginPagePattern)
		if err != nil {
			return nil, fmt.Errorf("login-page pattern is not a valid regex: %w", err)
		}
		loginPage = re
	}

	// Three states, not two: a rate this crawl was given, this package's default, and — only ever
	// from a named pool — no rate cap at all. The third is why `capped` exists rather than a bare
	// float: a pool whose delay between requests is zero is an operator saying "concurrency only",
	// and folding that into DefaultRequestsPerSecond would impose a cap they explicitly did not set.
	// It is safe here in a way it would not be elsewhere because the loop is sequential: "no rate
	// cap" on this path still means one request at a time.
	rps, capped := cfg.RequestsPerSecond, cfg.RequestsPerSecond > 0
	if !capped {
		rps, capped = DefaultRequestsPerSecond, true
	}
	// The per-host throttle comes from the pool when there is one, so switching automatic throttling
	// off in a pool switches it off here. That is a real loss of protection for an unattended crawl
	// and it is the operator's own instruction, made in a dialog that says so, rather than a default
	// this package quietly overrides.
	throttle := intruder.DefaultAutoThrottle()
	poolName := ""
	poolConcurrency := 0
	if p := cfg.Pool; p != nil {
		poolName = p.Name
		poolConcurrency = p.MaxInFlight
		throttle = p.AutoThrottle
		if p.PerSecond != nil {
			rps, capped = *p.PerSecond, true
		} else {
			rps, capped = 0, false
		}
	}
	// perSecond hands each limiter its own pointer. One shared pointer would be a single mutable
	// rate behind every limiter in the crawl, which is a bug waiting for the first caller that
	// writes through it.
	perSecond := func() *float64 {
		if !capped {
			return nil
		}
		v := rps
		return &v
	}
	maxRecords := cfg.MaxSkipRecords
	if maxRecords == 0 {
		maxRecords = DefaultMaxSkipRecords
	}
	logger := cfg.Logger
	if logger == nil {
		logger = zap.NewNop()
	}

	c := &Crawler{
		cfg:    cfg,
		limits: cfg.Limits.normalise(),
		query:  expr,
		// MaxInFlight of 1 states the sequential loop as a bound rather than accepting an in-flight
		// count the loop would ignore. Burst of 1 is strict spacing, which is what politeness means
		// for an unattended traversal. No AutoThrottle on the aggregate limiter: a 429 belongs to the
		// host that sent it, so throttling lives on the per-host limiters instead.
		limiter: intruder.NewRateLimiter(&intruder.RateLimit{
			PerSecond: perSecond(), Burst: 1, MaxInFlight: 1, Name: limiterName("crawl", poolName),
		}),
		skips:   newSkipLedger(maxRecords),
		logger:  logger,
		senders: make(map[string]*sender.AuthorisedSender),
		// Built from the validated seeds below rather than from cfg.Seeds' raw strings, so the key is
		// computed from the same parse the requests are.
		credentialOrigins: make(map[string]bool),
		queued:            make(map[string]bool),
		locations:         make(map[string]string),
		templates:         make(map[string]int),
		templateOK:        make(map[string]bool),
		hostLimiters:      make(map[string]*intruder.RateLimiter),
		robotsSeeded:      make(map[string]bool),
		requestsPer:       rps,
		rateCapped:        capped,
		throttle:          throttle,
		poolName:          poolName,
		poolConcurrency:   poolConcurrency,
		retention:         retention,
		loginPage:         loginPage,
	}
	// Seeds enter through the same admission gates as any discovered link, minus the destructive
	// check — see destructive.go for why the operator's own instruction is not second-guessed. They
	// are recorded on the report's LimitReport through the same counters, so a seed refused by scope
	// is visible rather than a crawl that mysteriously fetched nothing.
	c.seedURLs = seeds
	// Config.Headers travel only to the origins the operator seeded. Recorded here, from the parsed
	// seeds, so the key is computed by the same function that keys the outgoing request.
	for _, s := range seeds {
		c.credentialOrigins[originKey(s)] = true
	}
	return c, nil
}

// limiterName labels a limiter with what it bounds and, when a named pool is in force, which pool
// that is. The name reaches an operator through AttackReport.Pool and the limiter's own PoolName, so
// "crawl:api.example.com:443 (out-of-hours)" answers both halves of "what slowed this down" without
// the reader having to correlate two fields.
func limiterName(scope, pool string) string {
	if pool == "" {
		return scope
	}
	return scope + " (" + pool + ")"
}

// unavailablePreFetch returns the queried fields that no frontier URL can answer. Derived from the
// field list rather than a hard-coded blocklist, so a field added to the grammar defaults to
// "unavailable" — the fail-safe direction, since the alternative is silently evaluating it against a
// value that does not exist.
func unavailablePreFetch(fields []string) []string {
	var bad []string
	for _, f := range fields {
		switch f {
		case "host", "method", "path":
			// All three are properties of the request the crawler is about to build, so all three
			// are known. Path in particular is the same value the scope check one gate over already
			// reads off the frontier URL.
		default:
			bad = append(bad, f)
		}
	}
	return bad
}

// validateHeader refuses the headers a caller must not set and the values that would split a request.
func validateHeader(name, value string) error {
	if name == "" {
		return fmt.Errorf("a request header with an empty name cannot be sent")
	}
	if strings.ContainsAny(name, "\r\n:") || strings.ContainsAny(value, "\r\n") {
		return fmt.Errorf("request header %q carries CR, LF or a colon in its name, which would split the request into two", name)
	}
	switch strings.ToLower(name) {
	case "host", "content-length", "content-type":
		return fmt.Errorf("request header %q is framing the crawler computes per request; setting it here would make the request line and the body disagree", name)
	}
	return nil
}

// supportedScheme is the allowlist. An allowlist and not a denylist: a denylist of `javascript:` and
// `data:` is one novel scheme away from being wrong, and the set of schemes worth dialling is two.
func supportedScheme(scheme string) bool {
	return strings.EqualFold(scheme, "http") || strings.EqualFold(scheme, "https")
}

// Run crawls until the frontier empties or a bound stops it, and returns what happened either way.
//
// It does not return an error. Everything that can go wrong with an individual URL is a counted skip
// and everything that can stop the crawl is a recorded stop, so there is no failure left that a
// single error value would describe better than the report does. Configuration errors were already
// returned by New.
func (c *Crawler) Run(ctx context.Context) Report {
	started := time.Now()
	rep := Report{
		Seeds:          c.cfg.Seeds,
		Query:          c.cfg.Query,
		RetentionQuery: c.cfg.RetentionQuery,
		FormSubmission: c.cfg.SubmitForms,
		RobotsPolicy:   RobotsPolicy,
		// Both from the crawler rather than from cfg, so what is reported is the pool the limiters
		// were actually built from and not the pool the caller meant to pass.
		Pool:            c.poolName,
		PoolConcurrency: c.poolConcurrency,
	}
	lim := LimitReport{Limits: c.limits}

	for _, u := range c.seedURLs {
		c.admitSeed(u, &lim)
	}
	// One robots.txt per seed authority, queued behind the seeds so the operator's own starting points
	// are fetched first. Not honoured as a restriction — read as a list of paths the target would
	// rather nobody looked at. See the package docs.
	for _, u := range c.seedURLs {
		c.admitRobots(u, &lim)
	}

	for {
		// Frontier-empty is tested before every bound, so a crawl that fetched exactly its request
		// budget and had nothing left to do reports as complete rather than as truncated. A bound is
		// only a stop when there was still work it prevented.
		if len(c.frontier) == 0 {
			break
		}
		if err := ctx.Err(); err != nil {
			lim.record(StopCancelled)
			break
		}
		if rep.Fetched >= c.limits.MaxRequests {
			lim.record(StopRequestBudget)
			break
		}
		if time.Since(started) >= c.limits.MaxDuration {
			lim.record(StopDuration)
			break
		}
		if len(c.locations) >= c.limits.MaxLocations {
			lim.record(StopLocationBudget)
			break
		}

		item := c.frontier[0]
		c.frontier = c.frontier[1:]
		c.visit(ctx, item, &rep, &lim)
	}

	lim.FrontierRemaining = len(c.frontier)
	lim.Templates = len(c.templates)
	// Reported whether or not the bound was reached: these two tables are what the crawl holds in RAM for
	// its whole run, and a consumption nobody can see is a bound nobody can plan around.
	lim.Fingerprints = len(c.queued)
	lim.Requests = rep.Fetched
	lim.Locations = len(c.locations)
	lim.Elapsed = time.Since(started)
	rep.Elapsed = lim.Elapsed
	rep.Locations = len(c.locations)
	rep.HeadersWithheld = c.headersWithheld
	rep.Limits = lim
	rep.Skips = c.skips.Snapshot()
	return rep
}

// visit sends one frontier item, captures and scans the response through the shared seam, and folds
// whatever it discovered back into the frontier.
func (c *Crawler) visit(ctx context.Context, item frontierItem, rep *Report, lim *LimitReport) {
	c.perform(ctx, item, c.buildRequest(item), rep, lim)
}

// perform sends one request's raw bytes through the chokepoint, captures and scans the response
// through the shared seam (CRAWL-02), and folds whatever it discovered back into the frontier.
//
// raw is a parameter rather than rebuilt here because the session-recovery retry (handleExpired)
// re-enters through this same function with the request rebuilt to carry a refreshed cookie — one
// pipeline, so a retried request is captured, scanned and traversed exactly like a first attempt,
// and re-authorised against scope by the same AuthorisedSender. A crawl with no SessionCoordinator
// never reaches that retry: detectExpired short-circuits, so this function is byte-for-byte the old
// visit for the static-Headers case.
func (c *Crawler) perform(ctx context.Context, item frontierItem, raw []byte, rep *Report, lim *LimitReport) {
	as := c.senderFor(item.url)

	refusedBefore := as.Refused()
	// Two limiters, in a fixed order. The global one bounds the aggregate rate so that discovering
	// fifty hosts does not multiply the traffic this crawl generates by fifty; the per-host one gives
	// each target its own AutoThrottle, so a 429 from one host slows that host rather than every
	// host — which a single shared limiter gets wrong in the direction that matters, by throttling the
	// hosts that were behaving.
	global := c.limiter.Acquire()
	host := c.limiterFor(item.url).Acquire()
	res, err := as.Send(ctx, raw)
	host.Release()
	global.Release()

	if err != nil {
		// The chokepoint's own counter decides which bucket this is. Comparing counters rather than
		// inspecting the error text: the refusal message is core.Scope.Explain's operator-facing
		// prose and matching on it would make this classification break the next time that message
		// is improved.
		if as.Refused() > refusedBefore {
			rep.Refused++
			c.skips.record(SkipRecord{
				Reason: SkipSendRefused, URL: item.url.String(), Method: item.method,
				Text: item.text, FoundAt: item.foundAt, Detail: err.Error(),
			})
			return
		}
		rep.Failed++
		c.skips.record(SkipRecord{
			Reason: SkipSendFailed, URL: item.url.String(), Method: item.method,
			Text: item.text, FoundAt: item.foundAt, Detail: err.Error(),
		})
		return
	}
	c.observe(item.url, res.Status)

	// Capped before capture, not after. The bytes are already in memory — SendRaw read them, bounded
	// by httputil's own 64 MiB ceiling — but storing them would put them in the segment log for the
	// life of the capture, to have at most MaxParseBytes of them examined. Refusing to capture is a
	// deliberate coverage hole and is counted as one; truncating and storing the prefix would be
	// worse, because history would then hold bytes that are not the bytes the target sent.
	if len(res.Raw) > c.limits.MaxCaptureBytes {
		rep.NotCaptured++
		lim.record(StopCaptureBytes)
		c.skips.record(SkipRecord{
			Reason: SkipResponseTooLarge, URL: item.url.String(), Method: item.method,
			Text: item.text, FoundAt: item.foundAt,
			Detail: fmt.Sprintf("%d bytes exceeds the capture bound of %d", len(res.Raw), c.limits.MaxCaptureBytes),
		})
		return
	}

	ex, cerr := c.cfg.Capture.Record(scanner.CapturedExchange{
		Host:     item.url.Hostname(),
		Port:     portOf(item.url),
		TLS:      strings.EqualFold(item.url.Scheme, "https"),
		Method:   item.method,
		Path:     item.url.RequestURI(),
		Request:  raw,
		Response: res.Raw,
		Started:  time.Now().Add(-res.Duration),
		Duration: res.Duration,
		Protocol: core.ProtocolHTTP1,
		// Attributed, so history can distinguish what the crawl caused from what the operator's own
		// browser did. Leaving it unset would land this in the store as unattributed, which is the
		// store's honest default and the wrong answer when the surface is known.
		Source: core.SourceCrawl,
	})
	if cerr != nil {
		// The bytes came back and could not be stored, so they were never scanned either. It counts
		// against Failed rather than Fetched because a fetch this package counts is one that reached
		// the shared capture path, and this one did not — but its ledger reason says what actually
		// happened, which is not a transport failure.
		rep.Failed++
		c.skips.record(SkipRecord{
			Reason: SkipResponseUnreadable, URL: item.url.String(), Method: item.method,
			Text: item.text, FoundAt: item.foundAt,
			Detail: "the response could not be captured: " + cerr.Error(),
		})
		return
	}

	rep.Fetched++
	if item.depth > lim.DeepestDepth {
		lim.DeepestDepth = item.depth
	}
	fetch := Fetch{URL: item.url.String(), Method: item.method, ExchangeID: ex.ID, Depth: item.depth}
	if ex.Status != nil {
		fetch.Status = int(*ex.Status)
	}

	// Read the response back out of the store rather than re-parsing the wire bytes: this way the
	// markup the crawler extracts links from is byte-for-byte the markup the passive check set and
	// the DOM pass just examined, and there is no second HTTP parser here to disagree with core.Parse.
	//
	// ex.Response is non-nil by scanner.Capture.Record's contract — it indexes nothing unless both
	// messages stored — so there is no nil branch to handle here. That contract exists because a
	// nil-Response exchange row wedges the live-audit sweep permanently; see Record.
	msg, gerr := c.cfg.Capture.Store.Get(*ex.Response)
	if gerr != nil {
		c.skips.record(SkipRecord{
			Reason: SkipResponseUnreadable, URL: item.url.String(), Method: item.method,
			Text: item.text, FoundAt: item.foundAt,
			Detail: "the stored response could not be read back: " + gerr.Error(),
		})
		rep.Fetches = append(rep.Fetches, fetch)
		return
	}
	contentType := string(msg.Header("Content-Type"))
	body := msg.Body()

	// Session expiry (Phase 6, Gap A). Checked here — after CRAWL-02 has captured and scanned the
	// bytes, before the robots/redirect/content branches — so a login *redirect* (a template that was
	// 200 now answering 3xx toward /login) or a 401 is recognised as a lost session rather than
	// followed as an ordinary edge, and a login page served at 200 is caught by the pattern rule. The
	// whole block is inert without a coordinator: detectExpired returns "not expired" and templateOK
	// is never consulted, so the static-Headers crawl behaves exactly as before. The robots probe
	// carries no session and is skipped. See session_gate.go.
	if c.cfg.SessionCoordinator != nil && !item.robots {
		template := urlTemplate(item.method, item.url, item.fieldNames)
		if verdict := c.detectExpired(template, fetch.Status, body); verdict.yes {
			// The expired response is real traffic and stays in history as a Fetch, but it is a login
			// page, not application content: it is not fingerprinted and its links are not followed.
			// Recovery re-sends the original request with a refreshed cookie through this same
			// function, appending the retry's own Fetch in chronological order after this one.
			rep.Fetches = append(rep.Fetches, fetch)
			c.handleExpired(ctx, item, verdict, rep, lim)
			return
		}
		// Record that this template has legitimately answered 200, so a later non-200 for the same
		// template reads as a session that was lost rather than as a page that never worked. Set after
		// detection, so the verdict above always reflects prior visits, never this one.
		if fetch.Status == 200 {
			c.templateOK[template] = true
		}
	}

	// robots.txt is captured and scanned like everything else — it has already been, above — and then
	// read as a path list rather than as a location. It is deliberately not fingerprinted as a
	// location: it is metadata about the application, not a page of it, and counting it as one would
	// put a text file in the location total.
	if item.robots {
		if fetch.Status == 200 {
			c.seedFromRobots(body, item, rep, lim)
		}
		rep.Fetches = append(rep.Fetches, fetch)
		return
	}

	// A redirect is an edge, not a location: it has no content of its own to fingerprint, and
	// fingerprinting its empty body would make every redirect after the first look like a duplicate.
	// Its target re-enters the frontier as an ordinary link, so it passes every gate again — which is
	// what makes a cross-host redirect unable to escape scope.
	if fetch.Status >= 300 && fetch.Status < 400 {
		if loc := string(msg.Header("Location")); loc != "" {
			c.admit(discoveredLink{raw: loc, tag: "redirect"}, item.url, item.depth+1, rep, lim)
		}
		rep.Fetches = append(rep.Fetches, fetch)
		return
	}

	if enc := strings.ToLower(strings.TrimSpace(string(msg.Header("Content-Encoding")))); enc != "" && enc != "identity" {
		// The body was stored and scanned; only link extraction is affected, because reading
		// compressed bytes as markup finds nothing and would report that as "no links here".
		fetch.Fingerprint = rawBodyFingerprint(contentType, body)
		c.recordLocation(fetch.Fingerprint, item.url.String(), &fetch, rep)
		c.skips.record(SkipRecord{
			Reason: SkipContentEncoded, URL: item.url.String(), Method: item.method,
			FoundAt: item.foundAt, Detail: "Content-Encoding: " + enc,
		})
		rep.Fetches = append(rep.Fetches, fetch)
		return
	}

	if !isHTML(contentType) {
		fetch.Fingerprint = rawBodyFingerprint(contentType, body)
		c.recordLocation(fetch.Fingerprint, item.url.String(), &fetch, rep)
		c.skips.record(SkipRecord{
			Reason: SkipNotHTML, URL: item.url.String(), Method: item.method,
			FoundAt: item.foundAt, Detail: "Content-Type: " + contentType,
		})
		rep.Fetches = append(rep.Fetches, fetch)
		return
	}

	// Gate (b) of DSL-03: crawl *retention*, evaluated after the fetch with the full grammar, because
	// by now every field the grammar has really does have a value. It gates traversal and nothing
	// else. CRAWL-02 means this response is already captured and already scanned — it cannot be
	// un-captured, and calling this a scope exclusion would make the crawl's counts disagree with the
	// store's. So it is a response-category skip, and the request that produced it still counts as a
	// fetch.
	if c.retention != nil && !c.retention.Match(fetchedRow{
		host: item.url.Hostname(), method: item.method, path: item.url.Path, status: fetch.Status,
		mime: contentType, body: body,
	}) {
		fetch.RetentionExcluded = true
		c.skips.record(SkipRecord{
			Reason: SkipRetentionExcluded, URL: item.url.String(), Method: item.method,
			FoundAt: item.foundAt, Detail: "crawl-retention query: " + c.cfg.RetentionQuery,
		})
		rep.Fetches = append(rep.Fetches, fetch)
		return
	}

	page := parsePage(body, item.url, c.limits)
	if page.truncated {
		lim.record(StopParseBytes)
	}
	if page.dropped > 0 {
		lim.record(StopLinksPerPage)
		lim.LinksDropped += page.dropped
		c.skips.record(SkipRecord{
			Reason: SkipLinksPerPage, URL: item.url.String(), Method: item.method,
			FoundAt: item.foundAt,
			Detail:  fmt.Sprintf("%d links past the per-page bound of %d", page.dropped, c.limits.MaxLinksPerPage),
		})
	}
	fetch.Fingerprint = page.fingerprint
	if !c.recordLocation(page.fingerprint, item.url.String(), &fetch, rep) {
		// Already seen at another URL: the links here are the links there, so descending again would
		// spend budget re-walking a subtree already covered.
		rep.Fetches = append(rep.Fetches, fetch)
		return
	}

	rep.LinksFound += len(page.links)
	rep.FormsFound += len(page.forms)
	for _, l := range page.links {
		c.admit(l, item.url, item.depth+1, rep, lim)
	}
	for _, f := range page.forms {
		c.admitForm(f, item.url, item.depth+1, rep, lim)
	}
	rep.Fetches = append(rep.Fetches, fetch)
}

// recordLocation folds one fingerprint into the location map. It reports false when the fingerprint
// had already been seen, in which case the fetch is annotated with where it was first seen and the
// duplicate is counted.
func (c *Crawler) recordLocation(fingerprint, at string, fetch *Fetch, rep *Report) bool {
	if fingerprint == "" {
		return true
	}
	if first, seen := c.locations[fingerprint]; seen {
		rep.DuplicateLocations++
		fetch.DuplicateOf = first
		c.skips.record(SkipRecord{
			Reason: SkipDuplicateLocation, URL: at,
			Detail: "the same contents were already seen at " + first,
		})
		return false
	}
	c.locations[fingerprint] = at
	return true
}

// admitSeed puts one validated seed on the frontier. Seeds skip the destructive check (see
// destructive.go) and pass every other gate.
func (c *Crawler) admitSeed(u *url.URL, lim *LimitReport) {
	c.enqueue(frontierItem{url: u, method: "GET", depth: 0}, "", lim)
}

// admitRobots queues the one /robots.txt request for a seed's authority, at most once per authority.
//
// It goes through enqueue like everything else, so an authority the scope or the crawl-scope query
// excludes is not asked for its robots.txt either — the file is a request like any other and gets no
// exemption from the gates.
func (c *Crawler) admitRobots(seed *url.URL, lim *LimitReport) {
	key := strings.ToLower(seed.Scheme) + "://" + strings.ToLower(seed.Hostname()) + ":" + strconv.Itoa(int(portOf(seed)))
	if c.robotsSeeded[key] {
		return
	}
	c.robotsSeeded[key] = true
	u := *seed
	u.Path = "/robots.txt"
	u.RawQuery = ""
	c.enqueue(frontierItem{url: &u, method: "GET", depth: 0, robots: true}, "", lim)
}

// seedFromRobots reads a robots.txt body as a list of paths worth trying.
//
// Every path found is offered to the frontier as an ordinary *discovered link*, not as a seed. That
// distinction is the whole safety argument for doing this at all: robots.txt is written by the
// target, so its contents are target-supplied input and must pass the destructive-action check, the
// scope gate and the query gate exactly like a link scraped from a page. Seeds bypass the destructive
// check because they are the operator's own instruction; a `Disallow: /admin/delete-everything` line
// is emphatically not that.
//
// Disallow and Allow are both read, because both name a path the target's author thought about.
// Sitemap lines are queued as links so the sitemap itself is captured and scanned; its XML is not
// parsed for the URLs inside it, which is a named limit rather than an oversight — that would want an
// XML pass this slice does not have.
//
// Wildcards and `$` anchors are stripped to their literal prefix: `Disallow: /admin/*.bak` yields
// `/admin/`, which is a real path to try, where the pattern itself is not a URL at all. A pattern
// that reduces to nothing is dropped.
func (c *Crawler) seedFromRobots(body []byte, item frontierItem, rep *Report, lim *LimitReport) {
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		colon := strings.IndexByte(line, ':')
		if colon < 0 {
			continue
		}
		directive := strings.ToLower(strings.TrimSpace(line[:colon]))
		value := strings.TrimSpace(line[colon+1:])
		if i := strings.IndexByte(value, '#'); i >= 0 {
			value = strings.TrimSpace(value[:i])
		}
		if value == "" {
			continue
		}
		switch directive {
		case "disallow", "allow":
			path := robotsLiteralPrefix(value)
			// "/" on its own is the whole site, which the crawl already has from its seed.
			if path == "" || path == "/" {
				continue
			}
			rep.RobotsPathsFound++
			c.admit(discoveredLink{raw: path, tag: "robots"}, item.url, 1, rep, lim)
		case "sitemap":
			rep.RobotsPathsFound++
			c.admit(discoveredLink{raw: value, tag: "robots-sitemap"}, item.url, 1, rep, lim)
		}
	}
}

// robotsLiteralPrefix reduces a robots.txt path pattern to the longest leading literal, so a pattern
// becomes a path that can actually be requested.
func robotsLiteralPrefix(pattern string) string {
	if i := strings.IndexAny(pattern, "*$"); i >= 0 {
		pattern = pattern[:i]
	}
	pattern = strings.TrimSpace(pattern)
	if pattern == "" || !strings.HasPrefix(pattern, "/") {
		return ""
	}
	return pattern
}

// admit runs one discovered link through the frontier's gates, in this order:
//
//  1. resolution — a href that cannot be resolved to a host is nothing to fetch;
//  2. scheme — http and https only, before any other consideration;
//  3. userinfo — a target must not choose what the crawl authenticates with;
//  4. destructive action (CRAWL-04) — before scope, so a logout link that is *also* out of scope
//     reports as a logout refusal, which is the more actionable of the two facts;
//  5. engagement scope — the pre-fetch pre-filter, not the authorisation;
//  6. crawl-scope query (DSL-03);
//  7. depth, then duplicate, then frontier capacity — the bookkeeping gates, cheapest last because
//     they are the ones that fire most often and their reasons are the least interesting.
//
// Every gate that refuses records a SkipRecord naming the URL, the link text and, for a destructive
// refusal, the exact signal that matched. There is no path out of this function that declines a link
// without recording why.
func (c *Crawler) admit(l discoveredLink, base *url.URL, depth int, rep *Report, lim *LimitReport) {
	u, err := resolveAgainst(base, l.raw)
	if err != nil {
		c.skips.record(SkipRecord{
			Reason: SkipMalformedURL, URL: strings.TrimSpace(l.raw), Text: l.text,
			FoundAt: base.String(),
		})
		return
	}
	// Scheme before host, deliberately: `javascript:void(0)` and `data:text/html,...` resolve to a
	// URL with a scheme and no host, and reporting those as malformed would hide the thing that is
	// actually interesting about them. A relative href inherits the page's own scheme, so a link that
	// reaches the scheme gate with something else in it said so explicitly.
	if !supportedScheme(u.Scheme) {
		c.skips.record(SkipRecord{
			Reason: SkipUnsupportedScheme, URL: u.String(), Text: l.text,
			FoundAt: base.String(), Detail: "scheme " + u.Scheme,
		})
		return
	}
	if u.Host == "" {
		c.skips.record(SkipRecord{
			Reason: SkipMalformedURL, URL: u.String(), Text: l.text,
			FoundAt: base.String(), Detail: "the URL resolved to no host",
		})
		return
	}
	if u.User != nil {
		c.skips.record(SkipRecord{
			Reason: SkipCredentialsInURL, URL: u.Redacted(), Text: l.text, FoundAt: base.String(),
		})
		return
	}
	if v := classifyDestructive(u.String(), l.text); v.Refused {
		c.skips.record(SkipRecord{
			Reason: v.Reason, URL: u.String(), Method: "GET", Text: l.text,
			Signal: v.Signal, FoundAt: base.String(),
		})
		return
	}
	c.enqueue(frontierItem{url: u, method: "GET", depth: depth, foundAt: base.String(), text: l.text}, base.String(), lim)
}

// admitForm turns one discovered form into a request, or records why it did not.
//
// CRAWL-03 lives at the top of this function: with submission off, every form is counted as
// discovered-and-not-submitted and nothing is built. A GET form is included in that, deliberately —
// a GET form is still a form the application meant a user to fill in, and the operator's decision
// was about forms, not about methods.
func (c *Crawler) admitForm(f discoveredForm, base *url.URL, depth int, rep *Report, lim *LimitReport) {
	target := f.action
	if strings.TrimSpace(target) == "" {
		// The HTML specification: an empty action submits to the document's own URL.
		target = base.String()
	}
	if !c.cfg.SubmitForms {
		c.skips.record(SkipRecord{
			Reason: SkipFormSubmissionDisabled, URL: target, Method: f.method, Text: f.label,
			FoundAt: base.String(),
			Detail:  fmt.Sprintf("%d fields; turn form submission on to submit it", len(f.fields)),
		})
		return
	}

	if f.method != "GET" && f.method != "POST" {
		c.skips.record(SkipRecord{
			Reason: SkipFormNotSubmittable, URL: target, Method: f.method, Text: f.label,
			FoundAt: base.String(), Detail: "method " + f.method + " is not one this crawler builds",
		})
		return
	}
	if f.hasFileInput || (f.enctype != "" && f.enctype != "application/x-www-form-urlencoded") {
		detail := "enctype " + f.enctype
		if f.hasFileInput {
			detail = "the form carries a file input, so a urlencoded submission is not the request the application expects"
		}
		c.skips.record(SkipRecord{
			Reason: SkipFormNotSubmittable, URL: target, Method: f.method, Text: f.label,
			FoundAt: base.String(), Detail: detail,
		})
		return
	}

	u, err := resolveAgainst(base, target)
	if err != nil {
		c.skips.record(SkipRecord{
			Reason: SkipMalformedURL, URL: target, Method: f.method, Text: f.label, FoundAt: base.String(),
		})
		return
	}
	// Scheme before host, for the reason given in admit.
	if !supportedScheme(u.Scheme) {
		c.skips.record(SkipRecord{
			Reason: SkipUnsupportedScheme, URL: u.String(), Method: f.method, Text: f.label,
			FoundAt: base.String(), Detail: "scheme " + u.Scheme,
		})
		return
	}
	if u.Host == "" {
		c.skips.record(SkipRecord{
			Reason: SkipMalformedURL, URL: u.String(), Method: f.method, Text: f.label,
			FoundAt: base.String(), Detail: "the URL resolved to no host",
		})
		return
	}
	if u.User != nil {
		c.skips.record(SkipRecord{
			Reason: SkipCredentialsInURL, URL: u.Redacted(), Method: f.method, Text: f.label, FoundAt: base.String(),
		})
		return
	}

	values := url.Values{}
	for _, fl := range f.fields {
		values.Add(fl.name, fl.value)
	}
	encoded := values.Encode()

	// The destructive check reads the whole request intent, not just the action: a hidden
	// `action=delete` field is the request that deletes, and an action URL alone would miss it.
	if v := classifyDestructive(u.String()+" "+encoded, f.label); v.Refused {
		c.skips.record(SkipRecord{
			Reason: v.Reason, URL: u.String(), Method: f.method, Text: f.label,
			Signal: v.Signal, FoundAt: base.String(),
		})
		return
	}

	names := make([]string, 0, len(f.fields))
	for _, fl := range f.fields {
		names = append(names, fl.name)
	}
	item := frontierItem{url: u, method: f.method, depth: depth, foundAt: base.String(), text: f.label, fieldNames: names}
	if f.method == "GET" {
		// A GET submission replaces the action's query string with the form data set, which is what
		// the specification says and what every browser does.
		q := *u
		q.RawQuery = encoded
		item.url = &q
	} else {
		item.body = []byte(encoded)
		item.contentType = "application/x-www-form-urlencoded"
	}
	if c.enqueue(item, base.String(), lim) {
		rep.FormsSubmitted++
	}
}

// enqueue is the tail of the admission pipeline shared by links, forms and seeds: scope, query,
// depth, duplicate, capacity. It reports whether the item was queued.
func (c *Crawler) enqueue(item frontierItem, foundAt string, lim *LimitReport) bool {
	host := item.url.Hostname()
	port := portOf(item.url)
	tls := strings.EqualFold(item.url.Scheme, "https")

	if !c.cfg.Scope.Contains(host, port, item.url.Path, tls) {
		detail := ""
		if s, ok := c.cfg.Scope.(interface {
			Explain(string, uint16, string, bool) string
		}); ok {
			detail = s.Explain(host, port, item.url.Path, tls)
		}
		c.skips.record(SkipRecord{
			Reason: SkipOutOfScope, URL: item.url.String(), Method: item.method,
			Text: item.text, FoundAt: foundAt, Detail: detail,
		})
		return false
	}
	if c.query != nil && !c.query.Match(frontierRow{host: host, method: item.method, path: item.url.Path}) {
		c.skips.record(SkipRecord{
			Reason: SkipQueryExcluded, URL: item.url.String(), Method: item.method,
			Text: item.text, FoundAt: foundAt, Detail: "crawl-scope query: " + c.cfg.Query,
		})
		return false
	}
	if item.depth > c.limits.MaxDepth {
		lim.record(StopDepth)
		lim.DepthDeferred++
		c.skips.record(SkipRecord{
			Reason: SkipDepthLimit, URL: item.url.String(), Method: item.method,
			Text: item.text, FoundAt: foundAt,
			Detail: fmt.Sprintf("depth %d is past the bound of %d", item.depth, c.limits.MaxDepth),
		})
		return false
	}
	key := requestFingerprint(item.method, item.url, item.body)
	if c.queued[key] {
		c.skips.record(SkipRecord{
			Reason: SkipAlreadyQueued, URL: item.url.String(), Method: item.method,
			Text: item.text, FoundAt: foundAt,
		})
		return false
	}
	// The template quota, which is the cutoff that actually stops an application with an unbounded id
	// space. Checked after the exact key so that a genuine repeat reports as a repeat, and before the
	// frontier bound so that an infinite application reports as an infinite application rather than as
	// a full queue — see SkipTemplateQuota for why that distinction is the whole point.
	template := urlTemplate(item.method, item.url, item.fieldNames)
	if n := c.templates[template]; n >= c.limits.MaxTemplateVisits {
		lim.record(StopTemplateQuota)
		lim.TemplateQuotaDropped++
		c.skips.record(SkipRecord{
			Reason: SkipTemplateQuota, URL: item.url.String(), Method: item.method,
			Text: item.text, FoundAt: foundAt,
			Detail: fmt.Sprintf("template %s has been sampled %d times, the quota is %d", template, n, c.limits.MaxTemplateVisits),
		})
		return false
	}
	// The RAM bound on the two tables that remember request identity, checked here — after the template
	// quota, so an application with an unbounded id space still reports as a template quota, and *before*
	// the two inserts below, because a table that cannot record this request cannot dedup it either. See
	// StopFingerprintBudget for why a full table refuses the URL instead of evicting an old entry to make
	// room for it, and Limits.MaxFingerprints for why one number bounds both tables.
	if _, knownTemplate := c.templates[template]; !knownTemplate && len(c.templates) >= c.limits.MaxFingerprints {
		c.recordFingerprintBudget(item, foundAt, lim, fmt.Sprintf(
			"the URL-template table is at its bound of %d, so this new template could not be recorded",
			c.limits.MaxFingerprints))
		return false
	}
	if len(c.queued) >= c.limits.MaxFingerprints {
		c.recordFingerprintBudget(item, foundAt, lim, fmt.Sprintf(
			"the request-fingerprint set is at its bound of %d, so this request could not be remembered as sent",
			c.limits.MaxFingerprints))
		return false
	}
	c.templates[template]++
	if len(c.frontier) >= c.limits.MaxFrontier {
		lim.record(StopFrontierCapacity)
		lim.FrontierDropped++
		c.skips.record(SkipRecord{
			Reason: SkipFrontierFull, URL: item.url.String(), Method: item.method,
			Text: item.text, FoundAt: foundAt,
			Detail: fmt.Sprintf("the frontier is at its bound of %d", c.limits.MaxFrontier),
		})
		return false
	}
	c.queued[key] = true
	c.frontier = append(c.frontier, item)
	return true
}

// recordFingerprintBudget records one URL refused because a request-identity table was full: the
// stop, the unfetched count that feeds LimitReport.Unfetched, and the skip record naming the URL and
// which table it was.
//
// One helper for both tables so the three bookkeeping steps cannot drift apart between them — a
// refusal that records the skip and forgets the stop would be a URL counted as skipped on a crawl that
// still claimed to be complete.
func (c *Crawler) recordFingerprintBudget(item frontierItem, foundAt string, lim *LimitReport, detail string) {
	lim.record(StopFingerprintBudget)
	lim.FingerprintDropped++
	c.skips.record(SkipRecord{
		Reason: SkipFingerprintBudget, URL: item.url.String(), Method: item.method,
		Text: item.text, FoundAt: foundAt, Detail: detail,
	})
}

// frontierRow is what a crawl-scope query is evaluated against (DSL-03).
//
// Host, Method and Path are the request the crawler is about to build, and are real answers. Status,
// Mime and Body report absent, because before the fetch there is no response — and New has already
// refused any query that names them, so no comparison ever reaches those three. They are implemented
// as absent rather than left to panic because query.Queryable requires all six, and because a
// caller constructing this type directly should get the documented "absent fields are absent"
// behaviour rather than a crash.
type frontierRow struct {
	host   string
	method string
	path   string
}

func (r frontierRow) Host() string   { return r.host }
func (r frontierRow) Method() string { return r.method }
func (r frontierRow) Path() string   { return r.path }
func (r frontierRow) Status() int    { return 0 }
func (r frontierRow) Mime() string   { return "" }
func (r frontierRow) Body() []byte   { return nil }

// fetchedRow is what a crawl-retention query is evaluated against: a response that exists, so every
// field the grammar has is a real answer rather than an absence. This is the difference between the
// two DSL-03 gates, and the reason the pre-fetch one has to refuse queries this one accepts.
type fetchedRow struct {
	host   string
	method string
	path   string
	status int
	mime   string
	body   []byte
}

func (r fetchedRow) Host() string   { return r.host }
func (r fetchedRow) Method() string { return r.method }
func (r fetchedRow) Path() string   { return r.path }
func (r fetchedRow) Status() int    { return r.status }
func (r fetchedRow) Mime() string   { return r.mime }
func (r fetchedRow) Body() []byte   { return r.body }

// senderFor returns the AuthorisedSender bound to one origin, building it on first use. The scope
// handle passed in is the crawl's, so every send this package makes is checked against the same
// scope by the same chokepoint.
// originKey identifies one origin: scheme, host and port together.
//
// The scheme is part of the identity on purpose. An origin that differs only by scheme is a different
// origin for credential purposes — sending a cookie issued over https to an http URL on the same host
// puts it on the wire in cleartext, which is the TLS-downgrade half of the credential leak this key
// exists to prevent.
func originKey(u *url.URL) string {
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Hostname()) + ":" + strconv.Itoa(int(portOf(u)))
}

func (c *Crawler) senderFor(u *url.URL) *sender.AuthorisedSender {
	tls := strings.EqualFold(u.Scheme, "https")
	host := u.Hostname()
	port := portOf(u)
	key := originKey(u)
	if s, ok := c.senders[key]; ok {
		return s
	}
	s := sender.NewAuthorisedSender(c.cfg.Scope, c.cfg.Sender, host, port, tls)
	c.senders[key] = s
	return s
}

// limiterFor returns the rate limiter for one authority, building it on first use.
//
// Per authority rather than one for the whole crawl, so that AutoThrottle attributes a target's 429s
// and 503s to the target that sent them. A single shared limiter would let one overloaded host slow
// every other host in the crawl, which is the wrong direction: the hosts being slowed are the ones
// that were coping. The aggregate cap that stops fifty hosts from multiplying the traffic is the
// separate crawl-wide limiter, held in Crawler.limiter — see visit.
func (c *Crawler) limiterFor(u *url.URL) *intruder.RateLimiter {
	key := strings.ToLower(u.Hostname()) + ":" + strconv.Itoa(int(portOf(u)))
	if l, ok := c.hostLimiters[key]; ok {
		return l
	}
	var per *float64
	if c.rateCapped {
		v := c.requestsPer
		per = &v
	}
	l := intruder.NewRateLimiter(&intruder.RateLimit{
		PerSecond: per, Burst: 1, MaxInFlight: 1, Name: limiterName("crawl:"+key, c.poolName),
		// A run of 429s or 503s from one host halves the rate at that host for the next fifty grants.
		// An unattended crawl needs this: nobody is watching to notice the target asking for mercy.
		// A named pool supplies its own reaction here, including "none" — see Config.Pool.
		AutoThrottle: c.throttle,
	})
	c.hostLimiters[key] = l
	return l
}

// observe tells the host's limiter what that host answered, so the throttle reacts to the right
// target. The aggregate limiter is deliberately not told: it has no AutoThrottle to feed.
func (c *Crawler) observe(u *url.URL, status *int) {
	c.limiterFor(u).Observe(status)
}

// buildRequest renders one frontier item as HTTP/1.1 request bytes.
//
// Built here rather than through net/http because AuthorisedSender authorises *bytes* — that is the
// whole point of the chokepoint, since a request assembled after the check is a request that was
// never checked. `Connection: close` because each fetch is one exchange on its own socket, which is
// what makes the sequential loop's accounting exact.
//
// `Accept-Encoding: identity` because the body this crawler stores, scans and reads links out of
// should be the body the server rendered — a gzipped body is not markup, and every consumer
// downstream would have to inflate it or silently find nothing. The cost is real and worth stating:
// text compresses roughly three to five to one, so an identity crawl moves and stores several times
// the bytes a browser-driven capture would for the same pages. That is a deliberate trade of
// bandwidth and store growth for a capture every later pass can read. A target that encodes anyway is
// counted as SkipContentEncoded rather than parsed as though it were text.
func (c *Crawler) buildRequest(item frontierItem) []byte {
	ua := c.cfg.UserAgent
	if ua == "" {
		ua = DefaultUserAgent
	}
	target := item.url.RequestURI()
	if target == "" {
		target = "/"
	}

	var b strings.Builder
	b.WriteString(item.method)
	b.WriteByte(' ')
	b.WriteString(target)
	b.WriteString(" HTTP/1.1\r\nHost: ")
	b.WriteString(hostHeader(item.url))
	b.WriteString("\r\nUser-Agent: ")
	b.WriteString(ua)
	b.WriteString("\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	b.WriteString("\r\nAccept-Encoding: identity")
	b.WriteString("\r\nConnection: close\r\n")
	// Operator headers go only to a seed origin. See Crawler.credentialOrigins for why scope is not
	// the right gate for this: scope decides whether a request may be sent, which is a different
	// question from whether it may carry the operator's session.
	if len(c.cfg.Headers) > 0 {
		if c.credentialOrigins[originKey(item.url)] {
			for name, value := range c.cfg.Headers {
				b.WriteString(name)
				b.WriteString(": ")
				b.WriteString(value)
				b.WriteString("\r\n")
			}
		} else {
			c.headersWithheld++
		}
	}
	if len(item.body) > 0 {
		b.WriteString("Content-Type: ")
		b.WriteString(item.contentType)
		b.WriteString("\r\nContent-Length: ")
		b.WriteString(strconv.Itoa(len(item.body)))
		b.WriteString("\r\n")
	}
	b.WriteString("\r\n")
	b.Write(item.body)
	return []byte(b.String())
}

// hostHeader is the authority for the Host header: the port is omitted when it is the scheme's
// default, included otherwise, which is what a browser sends and what virtual-host routing expects.
func hostHeader(u *url.URL) string {
	host := u.Hostname()
	port := portOf(u)
	if (strings.EqualFold(u.Scheme, "http") && port == 80) || (strings.EqualFold(u.Scheme, "https") && port == 443) {
		return host
	}
	return host + ":" + strconv.Itoa(int(port))
}

// isHTML reports whether a Content-Type is markup this crawler extracts links from.
//
// An empty Content-Type is treated as HTML. Absent is not "not HTML": a server that omits the header
// on an HTML page is common enough, and the cost of being wrong is one wasted parse of bytes that
// contain no tags, against the cost of silently not traversing an application that forgot a header.
func isHTML(contentType string) bool {
	ct := strings.ToLower(strings.TrimSpace(contentType))
	if ct == "" {
		return true
	}
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	switch ct {
	case "text/html", "application/xhtml+xml", "application/xhtml", "text/xhtml":
		return true
	}
	return false
}
