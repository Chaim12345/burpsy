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
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"sort"
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

// LoginCredential represents one set of login credentials for application authentication.
// Mirrors Burp's username/password pairs (burpsy-react-ui-uzil).
type LoginCredential struct {
	// Username is the login username. Empty means no username for this credential set.
	Username string
	// Password is the login password. Empty means no password for this credential set.
	Password string
}

// Config configures one crawl. Zero-valued Limits and RequestsPerSecond take their defaults; the
// collaborators are required and New says so rather than crawling with a piece missing.
type Config struct {
	// Seeds are the URLs the crawl starts from. At least one is required — unless SeedRequests is
	// set — and each must be an absolute http or https URL with a host.
	Seeds []string
	// SeedRequests are concrete requests to send instead of, or beside, Seeds: a method, a URL, the
	// headers belonging to that one request, and a body. They exist for the one caller whose attack
	// surface is not a set of URLs — the API-only scan, whose definition names methods and bodies, so
	// `DELETE /items/1` and `GET /items/1` are two endpoints of one path and cannot both be a URL.
	//
	// Only honoured when SeedsOnly is set, and refused by New otherwise rather than ignored: a plain
	// crawl silently dropping the caller's method and body would send a GET at a path the operator
	// meant to POST to, and nothing on screen would say so.
	SeedRequests []SeedRequest
	// SeedsOnly fetches exactly what Seeds and SeedRequests name and follows nothing: no robots.txt
	// probe, no link or form extraction, no redirect traversal. See Run and perform.
	//
	// This is a different scan rather than a tighter bound on the same one. A crawl's job is
	// discovery, so every mechanism that adds a request the operator did not name is a feature of it;
	// an API-only scan's job is to send the endpoints a definition describes and audit the replies, so
	// the same mechanisms are switched off rather than merely budgeted — a definition describing
	// twelve operations should produce twelve requests and a report that says twelve, not twelve
	// requests plus whatever a JSON response's embedded links happened to suggest. Report.SeedsOnly
	// records which of the two ran, so a report can be read without knowing what was launched.
	SeedsOnly bool
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
	// FragmentsRoute turns on Burp's "Application uses fragments for routing"
	// (customization/application_uses_fragments_for_routing, scanning-spas.html): a fragment that
	// contains any of `/ \ ? = &` is treated as a client-side route, so `#/orders/7` and `#/orders/8`
	// are two locations of one GET rather than one location.
	//
	// OFF by default, matching Burp, which needs the operator to select the option when its automatic
	// character test is not enough. The automatic half is always on: a fragment that looks like a
	// route is carried as identity even when this is false, because that is what the donor does and a
	// crawl that dropped it would silently collapse a hash-routed SPA to one location (wbqx).
	//
	// The fragment is NEVER sent. It is identity only — see resolveAgainstRoute.
	FragmentsRoute bool
	// FormSubmissionOptimizationThreshold bounds how many DISTINCT destinations the crawl submits
	// ONE form to before it treats that form's input strategy as exhausted
	// (burpsy-react-ui-ddln). Burp's crawler.crawl_optimization.form_submission_optimization_threshold,
	// whose own decompiled name is
	// minimumFormInputStrategyChainLengthBeforeDiscontinuationStrategyApplied (Zclg.java:47 via
	// Zeuc.java:16) — the length of a form's input-strategy chain at which Burp stops generating
	// further strategies for it.
	//
	// A Config field rather than a Limits field, and for the same reason
	// Limits.MaxSubmissionsPerForm is not one either: it bounds a PHASE, not the crawl. The request
	// count is unchanged by it, which is why folding it into Limits would make a report claim the
	// crawl ran out of budget when it ran out of form targets.
	//
	// The two form bounds answer different questions and neither implies the other.
	// MaxSubmissionsPerForm bounds how many times ONE destination may be submitted; this bounds how
	// many DESTINATIONS are worth trying. A pagination control whose page parameter walks forward
	// forever passes the first with its cap untouched, because every submission is a new URL, and is
	// stopped only by this one.
	//
	// 0 means off, the same reading MaxSubmissionsPerForm gives its own zero, and left as written by
	// normalise for the same reason: an operator who never set the key gets the zero value, and a
	// bound that silently appeared would be a behaviour change disguised as a default.
	FormSubmissionOptimizationThreshold int
	// NoMetaRefresh and NoRefreshHeader turn off following a <meta http-equiv="refresh"> target and a
	// Refresh response header (q0qr). They are Burp's project options
	// http.redirections.understand_meta_refresh_tag and understand_refresh_header set false. Both
	// default to true in Burp (Preferences/ProjectDefaults.json), so the zero value here follows them.
	// Negative names keep the zero value equal to Burp's default.
	NoMetaRefresh   bool
	NoRefreshHeader bool
	// NoNotFoundProbe turns off not-found detection (s92h): the per-directory probe for a
	// nonexistent sibling that teaches the crawl what a soft 404 looks like. On by default, as Burp's
	// is.
	NoNotFoundProbe bool
	// NoSubresources stops the crawl fetching images, stylesheets, icons and media (4ocj). Burp's
	// crawler fetches them, which is the default here. Scripts and embedded objects are fetched
	// regardless, because their contents are read for locations.
	NoSubresources bool
	// RequestSpeculative turns on the speculative-hidden-link phase (burpsy-react-ui-t5m0):
	// candidate URLs are also mined from HTML comments and script bodies — the places
	// single-page apps and comment-leaked admin paths live. Off by default is NOT a statement
	// about the value — Burp ships the phase ON by default (1000 links) — it is because burpsy's
	// default crawl has been narrower than the donor's until this lands, and an operator who
	// never heard of the setting should get the behaviour they have always got. The wire field
	// is the opt-in; the Burp-config key lands through the customization table.
	RequestSpeculative bool
	// The API-discovery switches (burpsy-react-ui-bwwg). Each corresponds to one Burp
	// `crawler/customization/*` key and to one thing this crawler can now do with a definition it
	// meets during a crawl.
	//
	// The zero value is OFF for all four, and nothing in this package or in the web layer sets them
	// otherwise: an operator crawl turns them on only through a named configuration that names the
	// key (burpsy-react-ui-tyso wired that path). An earlier version of this comment said "defaulted
	// ON", which no code ever did. Burp ships the hidden-endpoint guess off (see commonGraphQLPaths),
	// matching this; whether its shipped defaults turn the other three on is not established in this
	// tree, and if they do, a crawl started here with no configuration reads less than Burp's would.
	// Any change to these defaults is its own decision, because it changes the traffic every existing
	// operator crawl sends.
	// The two GraphQL switches are the only ones here that make the crawl POST of its own initiative;
	// every such request goes through perform (the scope-authorised sender) after a check against the
	// crawl-wide request bound.
	ParseAPIDefinitions         bool
	ParseSOAPWSDLs              bool
	PerformGraphQLIntrospection bool
	GuessHiddenGraphQLEndpoints bool
	// Limits bounds the crawl. See Limits and DefaultLimits.
	Limits Limits
	// ErrorHandling is what the crawl does about requests that FAIL, rather than only counting
	// them (burpsy-react-ui-o0c5). The zero value means "the caller named none of these" and the
	// engine's documented defaults apply — which is a DIFFERENT state from a family whose
	// thresholds are all zero, which means never pause. That distinction is why every field is a
	// pointer; see ErrorHandling.
	ErrorHandling ErrorHandling
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
	// BrowserLogin is a recorded login sequence (burpsy-react-ui-xhtk): replayed in a browser before
	// the first fetch, its cookies carried on every request, and replayed again when the session is
	// detected as lost, within Limits.MaxRelogins. nil is a crawl with no recorded login. See
	// recorded_login.go.
	BrowserLogin BrowserLogin
	// OnSend, when set, is called with each request's method and URL immediately before it is sent
	// — the "page the crawler is on now" half of the live crawl view (burpsy-react-ui-1l3x), which
	// OnFetch cannot answer because it fires only after the response is captured. Synchronous on the
	// crawl goroutine, like OnFetch, so it must return at once.
	OnSend func(method, url string)
	// LoginPagePattern is a regex, matched against a response body, that identifies the
	// application's login page — the second signal (besides a 200→non-200 template flip)
	// that the session is gone. Empty (the default) disables this signal and keeps the
	// status-flip rule. Compiled in New; a malformed pattern is a construction error.
	LoginPagePattern string
	// LoginCredentials are the username/password pairs the crawler uses to authenticate
	// to the application (burpsy-react-ui-uzil). When set, the crawler attempts to identify
	// login forms (input elements with type=password) and submits the provided credentials.
	// Empty means no credential submission; static headers (Headers) are the only auth.
	LoginCredentials []LoginCredential
	// AuthenticatedCrawlOnly, when true, restricts the crawl to only authenticated areas of
	// the application — pages that require login (burpsy-react-ui-uzil). This prevents the
	// crawler from exploring public/unauthenticated parts of the site.
	AuthenticatedCrawlOnly bool
	// AttemptSelfRegister, when true, attempts to self-register a new user account if the
	// crawler encounters registration forms (burpsy-react-ui-uzil).
	AttemptSelfRegister bool
	// UseInvalidUsernames, when true, tests login with intentionally invalid usernames to
	// help identify login forms and error responses (burpsy-react-ui-uzil).
	UseInvalidUsernames bool
	// OnFetch, when set, is called once for every fetch that reached the shared capture path, at the
	// moment its exchange exists in the store — while the crawl is still running.
	//
	// It exists for one caller and one gap. Burp's crawl→audit bridge is per-URL and event-driven: a
	// newly-reached URL is published to the audit bus as it is reached, so the audit of the first page
	// overlaps the crawl of the twentieth. burpsy's caller audited Report.Fetches after Run returned,
	// which made "crawl and audit" a crawl *then* an audit — the first finding of a twenty-minute
	// crawl could not appear until minute twenty, and a crawl stopped at minute nineteen produced
	// none at all. This callback is the smallest thing that closes that.
	//
	// It deliberately changes nothing the crawl counts: Report is built exactly as before, a nil
	// callback is the previous behaviour to the byte, and the crawler learns nothing about auditing —
	// it announces a fetch and the caller decides what that is worth. The alternative shape, pushing
	// ids straight into the live sweep's queue, was rejected: the sweep walks store ids in order
	// because an id is handed out at capture time and a later one can complete first, and auditing
	// past that gap would skip a request still in flight.
	//
	// Two things a consumer must know. It runs synchronously on the crawl goroutine, so a callback
	// that blocks throttles the crawl — take the id, hand it to a consumer, return. And the Fetch is
	// a capture-time snapshot: URL, Method, Status, ExchangeID, Depth, FoundAt and LinkText are final,
	// while Fingerprint, DuplicateOf and RetentionExcluded are decided on branches below this point
	// and are zero here. The matching entry in Report.Fetches carries the completed record.
	OnFetch func(Fetch)
	// RequestWellKnown requests the standard .well-known documents once per seed authority
	// (burpsy-react-ui-bc2x). Opt-in, like Katana's -kf: it adds seven requests per authority to every
	// crawl, which changes what a crawl sends — a decision for the operator, not a silent default.
	RequestWellKnown bool
	// Render, when set, is how the crawler sees the DOM a browser builds: it returns the
	// rendered document for a URL, and the crawler extracts links from it that the wire
	// markup never carried (burpsy-react-ui-nx7b).
	//
	// Burp has this shape as browser-based navigation
	// (crawler.customization.browser_based_navigation_mode), and the reason is the same
	// here: a single-page application's routes and script-built hrefs are structurally
	// invisible to a parser over the wire response, and a crawl that never sees them
	// under-reports coverage while looking complete.
	//
	// The function is a hook rather than a *domexec.Browser for two reasons. The crawler
	// must not depend on chromedp at the point of use — the same discipline that keeps
	// BrowserProvider an interface on the scanner — and the caller owns the browser's
	// lifetime: the web layer hands the crawl the same lazy provider the audit's DOM
	// checks use, so one process runs one browser, not one per subsystem.
	//
	// Honesty rules the caller must know. A nil Render is the previous crawl to the byte —
	// no skip is recorded, because nothing was declined. A non-nil Render that fails is
	// SkipRenderUnavailable, counted and sampled like any other refusal, so a crawl whose
	// browser died says so instead of quietly claiming the wire parse was the whole story.
	// The rendered pass runs AFTER the static parse of the same response and admits only
	// links the wire parse did not already carry; its discoveries count in LinksFound like
	// any other link and are depth-bounded by the same frontier gates, and MaxLocations
	// still bounds the crawl as a whole.
	Render func(ctx context.Context, url string) (string, error)
	// RenderWithOutcome is Render plus HOW the render ended. It is the optional form: a caller that
	// only has Render is still wired, and a caller that supplies this one gets a capped page reported
	// as capped rather than presented as an empty one (burpsy-react-ui-efra).
	//
	// A render that reaches its cap has read the DOM while the page was still changing, so whatever
	// content it had not yet produced is MISSING rather than absent — and a crawl that counted it as
	// an empty page reports an application as having fewer locations than it has. That is the
	// confident wrong answer this field exists to prevent, and it is why RenderWithOutcome is
	// preferred at every call site in this repository.
	RenderWithOutcome func(ctx context.Context, url string) (string, RenderOutcome, error)
	// Interact, when set, drives the rendered page in a browser — clicking its navigational controls
	// and, when the options say so, filling and submitting its forms — so the routes a single-page
	// application reaches only through interaction are discoverable at all (burpsy-react-ui-spa1).
	//
	// A ONE-SHOT render reads a page; it does not press anything. A SPA whose `/orders` route is a
	// button click renders only the seed view, and a crawl that never clicks reports the application
	// as having one page. This hook is the press: the caller returns the views, the run-time requests
	// and the honest caps, and the crawler admits whatever links and requests they contain through
	// the same gates a rendered link passes.
	//
	// A hook rather than a *domexec.Browser for the same two reasons Render is one: this package must
	// not depend on chromedp at the point of use, and the caller owns the browser's lifetime — and,
	// crucially, the SCOPE GATE. A browser interaction navigates, so the crawler's must run inside a
	// gate Session (domexec.Session.Interact); this package cannot enforce that, which is why the
	// caller wires it and why the interaction function is documented as needing a gate.
	//
	// Honesty rules the caller must know. A nil Interact is the previous crawl to the byte. A
	// non-nil one that fails is SkipInteractionUnavailable, counted and sampled like any other
	// refusal, so a crawl whose browser died says so instead of quietly claiming the one-shot render
	// was the whole story. A pass that hit its own bounds is reported as capped on the crawl's
	// report, never as an exploration that finished.
	Interact func(ctx context.Context, url string, opts InteractionOptions) (Interaction, error)
	// InteractOptions tunes the pass. Zero takes the package defaults, which are non-zero.
	InteractOptions InteractionOptions
	// RenderOptions tunes the wait. Zero-valued takes the package defaults, which are NON-ZERO: the
	// floor of this feature is the fixed sleep the previous implementation used, so a crawl
	// configured with nothing waits at least as long as it always did and no crawl gets slower.
	RenderOptions RenderOptions
	// MaxSkipRecords bounds the sampled refusal detail. Zero takes DefaultMaxSkipRecords; a negative
	// value keeps counts only.
	MaxSkipRecords int
	// Logger is optional.
	Logger *zap.Logger
}

// RenderOptions is what a render waits for before it reads the DOM. Mirrored rather than imported
// from internal/domexec, because the crawler must not depend on chromedp at the point of use — the
// same discipline that keeps the render a hook rather than a *domexec.Browser.
type RenderOptions struct {
	// DOMQuiet is how long the DOM must be UNCHANGED before the page counts as settled.
	// Non-positive takes DefaultRenderDOMQuiet.
	DOMQuiet time.Duration
	// NetworkIdle is how long no request may be in flight before the page counts as settled.
	// Non-positive takes DefaultRenderNetworkIdle.
	NetworkIdle time.Duration
	// MaxWait is the hard cap on the whole wait. Non-positive takes DefaultRenderMaxWait; without it
	// a page that never goes quiet — a websocket, a polling dashboard — waits forever.
	MaxWait time.Duration
}

// The render defaults, and why none of them is zero. The previous implementation slept a fixed
// 300 ms, so that is the FLOOR this feature may not go below: a crawl configured with nothing must
// wait at least as long as it always did. Zero would mean "read at the load event", which is the
// defect (burpsy-react-ui-efra).
const (
	// DefaultRenderDOMQuiet is the settle window for the DOM.
	//
	// 300 ms, not shorter, and that is the floor rather than a preference: the implementation this
	// replaces slept a fixed 300 ms before reading the DOM, so a crawl configured with nothing must
	// not read the DOM EARLIER than it always did. The wait is now conditional — a page that settles
	// early returns as soon as it does, so the common case is FASTER than the old fixed sleep and the
	// 300 ms only applies to a page that keeps changing.
	DefaultRenderDOMQuiet = 300 * time.Millisecond
	// DefaultRenderNetworkIdle is the settle window for in-flight requests. Longer than the DOM
	// window because a pending request is a stronger signal that something is coming.
	DefaultRenderNetworkIdle = 500 * time.Millisecond
	// DefaultRenderMaxWait caps the whole wait. Ten seconds is longer than any first paint an operator
	// will sit through and short enough that a thousand-page crawl does not spend hours on the ones
	// that never settle.
	DefaultRenderMaxWait = 10 * time.Second
)

func (o RenderOptions) withDefaults() RenderOptions {
	if o.DOMQuiet <= 0 {
		o.DOMQuiet = DefaultRenderDOMQuiet
	}
	if o.NetworkIdle <= 0 {
		o.NetworkIdle = DefaultRenderNetworkIdle
	}
	if o.MaxWait <= 0 {
		o.MaxWait = DefaultRenderMaxWait
	}
	return o
}

// RenderOutcome says how a render ended.
//
// Settled and Capped are opposites on purpose: exactly one is true for a render that returned. A
// caller that checks neither is assuming every page it rendered was complete, which is the claim that
// makes a thin crawl look like a small application.
type RenderOutcome struct {
	// Settled reports that the page went quiet inside MaxWait.
	Settled bool
	// Capped reports that MaxWait was reached first, so the DOM was read while the page was still
	// changing. What it did not have yet is missing, not absent.
	Capped bool
	// Waited is how long the render actually took.
	Waited time.Duration
	// Requests are the XHR/fetch requests the page issued while it rendered (burpsy-react-ui-hzzl).
	Requests []RenderedRequest
}

// RenderedRequest is one request a rendered page issued at run time.
type RenderedRequest struct {
	URL    string
	Method string
}

// InteractionOptions tunes the browser-interaction pass (burpsy-react-ui-spa1). Zero-valued takes the
// package defaults, which are NON-ZERO, so a crawl that sets nothing is bounded exactly as the
// documented defaults say.
type InteractionOptions struct {
	// MaxClicks is how many navigational controls one page may be driven through. Zero takes
	// DefaultMaxInteractionClicks.
	MaxClicks int
	// MaxForms is how many forms one page's pass may fill and submit. Zero takes
	// DefaultMaxInteractionForms.
	MaxForms int
	// MaxWait caps the whole pass. Zero takes DefaultMaxInteractionWait.
	MaxWait time.Duration
	// FillForms types defaults into each visible field and submits the form. STATE-CHANGING: it
	// writes to the application, so a crawl turnes it on deliberately.
	FillForms bool
}

// The interaction bounds, mirrored here so the crawler's own report can cite them without importing
// the browser package's constants into a JSON schema.
const (
	DefaultMaxInteractionClicks = 25
	DefaultMaxInteractionForms  = 5
	DefaultMaxInteractionWait   = 30 * time.Second
)

func (o InteractionOptions) withDefaults() InteractionOptions {
	if o.MaxClicks <= 0 {
		o.MaxClicks = DefaultMaxInteractionClicks
	}
	if o.MaxForms <= 0 {
		o.MaxForms = DefaultMaxInteractionForms
	}
	if o.MaxWait <= 0 {
		o.MaxWait = DefaultMaxInteractionWait
	}
	return o
}

// InteractionView is one browser action the pass performed, and what it produced. It is the
// crawler-facing shape: the browser's own InteractionView carries the DOM, which the crawler turns
// into links and requests rather than holding.
type InteractionView struct {
	Action   string
	Selector string
	Label    string
	URL      string
	DOM      string
	Changed  bool
	Error    string
}

// Interaction is one interaction pass's outcome, as the crawler consumes it.
type Interaction struct {
	Views           []InteractionView
	Requests        []RenderedRequest
	FormsFound      int
	FormsSubmitted  int
	ClicksAttempted int
	ClicksAvailable int
	Capped          bool
}

// SeedRequest is one concrete request a seeds-only run sends: what one operation of an API
// definition reduces to.
//
// It carries a method, headers and a body rather than a URL, because those are the whole identity of
// the endpoint. A URL is what a crawl starts from; a request is what a scan of a *described* API
// starts from, and a described API's endpoints are distinguished by their verbs and their bodies.
// The values themselves come from wherever the definition's schema or schema-free request line came
// from (see internal/apidoc, which is the package that builds these).
type SeedRequest struct {
	// Method is the HTTP method. Empty means GET, which is what a definition that omits `method`
	// means too.
	Method string
	// URL is the absolute request target, query string included.
	URL string
	// Headers are headers for this one request, on top of Config.Headers. Framing headers — Host,
	// Content-Length, Content-Type — are refused at construction rather than written, because the
	// request line and the body would disagree. See validateHeader.
	Headers map[string]string
	// Body, when non-empty, is sent with ContentType below and a computed Content-Length.
	Body []byte
	// ContentType is the body's media type. Empty with a non-empty Body sends no Content-Type at
	// all, which is a request the target has to decide how to read — so callers give one whenever
	// they can, and internal/apidoc always does when it synthesises a body.
	ContentType string
}

// Fetch is one request the crawl actually sent, and what came back. The list of these is the "what
// it did reach" half of the coverage story CRAWL-07 asks about; LimitReport.Unfetched is the other.
type Fetch struct {
	// SoftNotFound marks a 2xx response that was its directory's custom "not found" page (s92h).
	SoftNotFound bool `json:"soft_not_found,omitempty"`
	// NotFoundProbe marks the request the crawl made itself to learn a directory's not-found page.
	NotFoundProbe bool   `json:"not_found_probe,omitempty"`
	URL           string `json:"url"`
	Method        string `json:"method"`
	// Status is the response status, or 0 when the response could not be parsed.
	Status int `json:"status"`
	// ExchangeID is the store id, so a caller can pull the request and response bytes out of history.
	ExchangeID core.ExchangeID `json:"exchange_id"`
	// Depth is how many links from a seed this was. A seed is 0.
	Depth int `json:"depth"`
	// Fragment is the client-side ROUTE this fetch stood for, when the application routes on its
	// fragment (burpsy-react-ui-wbqx). Empty for every ordinary fetch.
	//
	// Reported because the route is the whole point: `#/orders/7` and `#/orders/8` produce the same
	// URL, status and often the same body, so without this field a report of a hash-routed crawl
	// would show N identical rows and an operator could not tell which route each one was.
	Fragment string `json:"fragment,omitempty"`
	// Fingerprint is the location fingerprint, empty for a redirect (which is an edge, not a
	// location) and for a response whose body could not be read.
	Fingerprint string `json:"fingerprint,omitempty"`
	// DuplicateOf is set when this response's contents had already been seen at another URL, which is
	// why the links it carries were not queued again.
	DuplicateOf string `json:"duplicate_of,omitempty"`
	// RetentionExcluded records that the crawl-retention query did not match this response, so it was
	// captured and scanned but not traversed.
	RetentionExcluded bool `json:"retention_excluded,omitempty"`

	// FoundAt is the URL of the page this one was discovered on, empty for a seed.
	//
	// # Why a successful fetch needs it, when refusals already had it
	//
	// frontierItem.foundAt existed and was documented "reporting only": every SkipRecord carried it,
	// so the crawler could say why a URL it declined had been considered. Nothing carried it for a
	// URL the crawl actually fetched, so the graph the crawler walks was reconstructible only for
	// the parts it refused.
	//
	// That is the data behind Burp's "Crawl paths view", and the reason burpsy had no such view was
	// not a missing UI — it was that the edge was thrown away on success. Depth already said HOW FAR
	// a page was from a seed; this says WHICH WAY, which is the question an operator has when a page
	// they expected is absent: not "how deep is it" but "what should have linked to it".
	//
	// Empty means seed, and a reader must not treat empty as "unknown provenance": a seed genuinely
	// has no referring page. LinkText below is what distinguishes the two in a rendering.
	FoundAt string `json:"found_at,omitempty"`
	// LinkText is the link text or form label this URL was reached through, empty for a seed and for
	// a link with no text. Carried because "which of the four links to /logout was followed" is not
	// answerable from the URL alone, and because a rendering needs something to label an edge with.
	LinkText string `json:"link_text,omitempty"`
	// FoundByRender marks a fetch whose link existed only in the DOM a browser built for the
	// page it was discovered on (Config.Render) — invisible to the wire markup the static parse
	// read (nx7b). The crawl-paths edge carries it so an operator can see which of the crawl's
	// edges a browser-less crawl would not have found at all, which is the honest shape of the
	// coverage claim a rendered pass adds.
	FoundByRender bool `json:"found_by_render,omitempty"`
}

// Report is one crawl's whole outcome.
//
// Every count here is a partition of something, not a highlight: Fetched + Refused + Failed is every
// request the loop attempted, and Skips accounts for every URL that was discovered and not attempted.
// A caller can therefore always answer "what happened to the other ones", which is the property that
// makes a crawl report readable as coverage rather than as a highlight reel.
type Report struct {
	// Seeds is what the crawl was pointed at. On a seeds-only run every SeedRequest's URL appears
	// here too, so the field answers "what did this scan point at" for both scan kinds.
	Seeds []string `json:"seeds"`
	// SeedsOnly records that this run followed nothing: it fetched exactly the URLs it was given and
	// stopped. Carried rather than inferred from the absence of links, because a crawl that found no
	// links and a scan that never looked for any produce identical counts and are different runs.
	SeedsOnly bool `json:"seeds_only,omitempty"`
	// Query is the crawl-scope query as the operator wrote it, empty when there was none.
	Query string `json:"query,omitempty"`
	// RetentionQuery is the post-fetch traversal query as the operator wrote it.
	RetentionQuery string `json:"retention_query,omitempty"`
	// FormSubmission records whether form submission was on (CRAWL-03), so a report cannot be read
	// as "this application has no forms" when it means "forms were not submitted".
	FormSubmission bool `json:"form_submission"`
	// RequestSpeculative records whether the speculative-hidden-link phase ran
	// (burpsy-react-ui-t5m0) — whether the crawl followed links mined from comments
	// and script bodies at all.
	RequestSpeculative bool `json:"request_speculative,omitempty"`
	// SpeculativeAdmitted counts the speculative-phase candidates the crawl actually
	// enqueued and therefore followed. Beside RequestSpeculative so a report says
	// both "the phase ran" and "it followed N hidden links".
	SpeculativeAdmitted int `json:"speculative_admitted,omitempty"`
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
	// FollowUpRecovered counts requests that failed at the transport in the main pass and were fetched
	// by a follow-up pass (o0c5). They are in Fetched, not Failed — the partition above still holds,
	// each request counted once by how it ENDED — and this says how much coverage the retry bought.
	FollowUpRecovered int `json:"follow_up_recovered,omitempty"`

	// RobotsPathsFound counts paths taken from a robots.txt and offered to the frontier. Reported
	// separately from LinksFound because they are a different kind of discovery: nothing linked to
	// them, the target asked for them not to be visited, and that request was deliberately not
	// honoured. An operator reviewing a crawl should be able to see how much of it came from there.
	RobotsPathsFound int `json:"robots_paths_found"`
	// SitemapsParsed counts sitemap documents read, and SitemapLocationsFound the URLs they named.
	// Reported together because either alone is unreadable: a count of documents with no locations
	// says the operator's target publishes empty sitemaps, and a count of locations with no documents
	// says nothing about where they came from (burpsy-react-ui-qjtx).
	SitemapsParsed        int `json:"sitemaps_parsed"`
	SitemapLocationsFound int `json:"sitemap_locations_found"`
	// JSONDocumentsRead counts JSON bodies scanned for locations, and JSONLocationsFound the
	// locations they named (burpsy-react-ui-mz1n). Reported together for the same reason the
	// sitemap pair is: documents with no locations and locations with no documents are
	// different facts about a target, and one number cannot carry both.
	JSONDocumentsRead  int `json:"json_documents_read"`
	JSONLocationsFound int `json:"json_locations_found"`
	// JavaScriptRead counts script responses read for locations, JavaScriptLocationsFound the
	// candidates the two extractors produced before admit()'s gates (burpsy-react-ui-jwy5).
	// JavaScriptParseFailures counts scripts the AST pass could not parse — the text miner still read
	// them — and JavaScriptTruncated those read only up to MaxParseBytes.
	JavaScriptRead           int `json:"javascript_read,omitempty"`
	JavaScriptLocationsFound int `json:"javascript_locations_found,omitempty"`
	JavaScriptParseFailures  int `json:"javascript_parse_failures,omitempty"`
	JavaScriptTruncated      int `json:"javascript_truncated,omitempty"`
	// RenderedRequestsAdmitted counts same-origin GET requests a rendered page issued at run time and
	// that were admitted as locations; the other two count what was observed and deliberately not sent
	// — a page's own non-GET requests, and requests to another origin (burpsy-react-ui-hzzl).
	RenderedRequestsAdmitted    int `json:"rendered_requests_admitted,omitempty"`
	RenderedRequestsNotGET      int `json:"rendered_requests_not_get,omitempty"`
	RenderedRequestsOtherOrigin int `json:"rendered_requests_other_origin,omitempty"`
	// The interaction pass (burpsy-react-ui-spa1). InteractionsRun counts pages the crawl drove in a
	// browser; InteractionClicks the controls it dispatched against; the form pair the forms it found and
	// the forms it submitted; InteractionsCapped the pages whose pass hit a bound before the page was
	// exhausted. Capped is reported separately because a truncated exploration that reads as a complete
	// one is exactly the confident wrong answer the bound exists to prevent.
	InteractionsRun           int `json:"interactions_run,omitempty"`
	InteractionClicks         int `json:"interaction_clicks,omitempty"`
	InteractionFormsFound     int `json:"interaction_forms_found,omitempty"`
	InteractionFormsSubmitted int `json:"interaction_forms_submitted,omitempty"`
	InteractionsCapped        int `json:"interactions_capped,omitempty"`
	// APIDocumentsRead counts API definitions (OpenAPI, Swagger, WSDL) the crawl read, and
	// APIEndpointsFound the operations they declared (burpsy-react-ui-bwwg). Reported as a pair for
	// the same reason the JSON pair is: a definition read is not a definition understood, and a
	// report carrying only the first would read as success.
	APIDocumentsRead  int `json:"api_documents_read,omitempty"`
	APIEndpointsFound int `json:"api_endpoints_found,omitempty"`
	// SourceMapsFetched counts the source maps this crawl fetched (burpsy-react-ui-jwy5). Reported so
	// an operator can see that the map pass ran and found something, which is otherwise invisible: a
	// .map is an artifact of a bundle, not a location, so it never appears in the location counts.
	SourceMapsFetched int `json:"source_maps_fetched,omitempty"`
	// Phases counts locations admitted, by the phase that produced them
	// (burpsy-react-ui-hbjo). Every phase is present with a zero rather than only the ones that
	// fired, so a reader can tell "this crawl never reached the rendered pass" from "this crawl has no
	// rendered pass", and the numbers sum to the discovered total because an unrecognised tag is
	// counted under PhaseNone rather than dropped.
	Phases map[CrawlPhase]int `json:"phases,omitempty"`
	// EdgeKinds counts discovered locations by the kind of edge that led to them, in Burp's crawl
	// telemetry vocabulary (burpsy-react-ui-ylr1, EdgeKindsAll): anchor, form, frame, iframe, area,
	// redirect, delayed redirect, origin, submit, clickable, speculative, API, SOAP and GraphQL. Counted
	// at discovery, before any gate, like Phases. Burp's non-deterministic-location count is
	// LocationFolds: a page that came back with its links moved under the same structure.
	EdgeKinds map[string]int `json:"edge_kinds"`
	// SitemapSeeded counts requests this crawl did not make because the site map already held that
	// exact request (burpsy-react-ui-z8qf). Zero for a crawl seeded from nothing, which is the
	// common case and the one that must not read as a failure.
	//
	// Deliberately separate from the request and location counts: a seeded request is one this crawl
	// declined to make, and folding it into either of those would either inflate what the crawl did
	// or hide what it saved.
	SitemapSeeded int `json:"sitemap_seeded"`
	// GraphQLEndpointsFound counts the operations a GraphQL introspection answer declared. Beside
	// APIEndpointsFound rather than folded into it, because a GraphQL operation is a FIELD on one
	// endpoint's type rather than a path of its own, and counting them together would hide which
	// surface they came from.
	GraphQLEndpointsFound int `json:"graphql_endpoints_found,omitempty"`
	// SitemapIndexesFollowed counts <sitemapindex> documents whose entries were themselves sitemaps.
	// A large site publishes a handful of sitemaps pointing at the rest, so this is the difference
	// between "read one file" and "read the list the operator published".
	SitemapIndexesFollowed int `json:"sitemap_indexes_followed"`
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
	// LocationFolds counts responses recognised as a known location by the TOLERANCE BAND rather
	// than by exact fingerprint equality (burpsy-react-ui-9x67, location_band.go). Reported beside
	// DuplicateLocations, and not folded into it, because it is the only number that says how much
	// of the crawl's location count rests on a tolerance: a report claiming 300 locations where 120
	// were folded by a band of 2 is making a coverage claim a reader cannot audit from
	// `locations` alone, and this is where they learn it.
	//
	// Always a subset of DuplicateLocations, and it counts an actual loss of a second traversal
	// rather than a guess at one: a folded page's links were NOT queued again, so this is the
	// number of pages the band kept out of the frontier.
	LocationFolds int `json:"location_folds,omitempty"`
	// SoftNotFound counts 2xx responses recognised as their directory's custom "not found" page (s92h).
	SoftNotFound int `json:"soft_not_found"`
	// NotFoundProbes counts the per-directory probes for a nonexistent name (s92h). Each is also a Fetch.
	NotFoundProbes int `json:"not_found_probes"`
	// RenderedAudit is the browser's second look over the crawl's locations (burpsy-react-ui-xuim):
	// which distinct locations were rendered in a headless browser, and at how many of them the
	// page's own script produced content the wire response never contained. Nil when the pass did
	// not run — no browser configured — which the crawl reports through Skips
	// (SkipRenderUnavailable) rather than through this block, so a missing block is never
	// mistaken for a pass that found nothing.
	RenderedAudit *RenderedAuditReport `json:"rendered_audit,omitempty"`
	// Login is the recorded login's account (burpsy-react-ui-xhtk): whether the crawl was
	// authenticated, every replay, and what the replays' scope gate refused. Absent for a crawl
	// with no recorded login.
	Login *LoginReport `json:"login,omitempty"`
	// Elapsed is the crawl's wall-clock duration.
	Elapsed time.Duration `json:"elapsed"`
}

// RenderedAuditReport is what the rendered-DOM audit over a crawl's locations managed to do
// (burpsy-react-ui-xuim). The counters are the StoredDOMRenderOutcome shape, because the two
// passes answer the same question over different inputs — "what did a browser see that the
// HTTP pass did not" — and an operator reading both reports should not have to learn two
// vocabularies for it.
type RenderedAuditReport struct {
	// Candidates is how many distinct location URLs existed to render.
	Candidates int `json:"candidates"`
	// NoScript is how many were skipped because their wire response carries no script: a page
	// with no script renders to what it already was, so a browser cannot reveal anything new.
	NoScript int `json:"no_script"`
	// Capped is how many were dropped by MaxRenderedLocations and never looked at.
	Capped int `json:"capped"`
	// Rendered is how many pages were loaded in a browser.
	Rendered int `json:"rendered"`
	// Failed is how many could not be loaded.
	Failed int `json:"failed"`
	// ScriptOnly is how many rendered pages carried content the wire response never contained —
	// the finding: content that exists only after the page's script runs is invisible to every
	// wire-bytes check, including the crawl's own audit.
	ScriptOnly int `json:"script_only"`
	// Declined explains a pass that did not run for a reason that is not an error.
	Declined string `json:"declined,omitempty"`
}

// Summary renders the outcome in the vocabulary a report can print.
func (r RenderedAuditReport) Summary() string {
	if r.Declined != "" {
		return "no rendered-DOM audit: " + r.Declined
	}
	return fmt.Sprintf("%d of %d location(s) rendered in a browser, %d with content the wire response never carried",
		r.Rendered, r.Candidates, r.ScriptOnly)
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
	// The location clause says how much of the count rests on a tolerance rather than on exact
	// identity, because that is the number a reader cannot otherwise audit: `locations` alone reads
	// as 300 distinct pages whether or not 120 of them were recognised by a band. Only stated when
	// non-zero — a crawl that folded nothing has nothing to disclaim.
	locs := fmt.Sprintf("%d locations (%d duplicate)", r.Locations, r.DuplicateLocations)
	if r.LocationFolds > 0 {
		locs += fmt.Sprintf(", %d of the duplicates by the location tolerance band", r.LocationFolds)
	}
	s := fmt.Sprintf(
		"crawled %d URLs in %s: %s, %d links and %d forms found, %d forms submitted (submission %s), %d refused by scope, %d failed to send; %s",
		r.Fetched,
		r.Elapsed.Round(time.Millisecond),
		locs,
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
	// body and contentType are set for a form submission and for a seeds-only request, empty
	// otherwise.
	body        []byte
	contentType string
	// headers are per-request headers on top of Config.Headers, set only by admitSeedRequest. Kept
	// on the item rather than folded into Config.Headers because they belong to one request: an API
	// definition's declared header parameter is that operation's, and putting it in Config.Headers
	// would send it on every other operation's request as well.
	headers map[string]string
	depth   int
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
	// renderedOrigin marks an item whose link existed only in the DOM a browser built for the
	// page it came from (Config.Render) — invisible to the wire markup the static parse read
	// (nx7b). Carried to the Fetch edge so the crawl paths can say which edges a browser-less
	// crawl would not have found at all.
	renderedOrigin bool
	// phase is the crawl phase that owns this item (burpsy-react-ui-crediso): the phase a
	// transport-failure retry must execute within, because re-issuing it under another phase's
	// session is a different request. Stamped at admission.
	phase int
	// maskValues are the secrets this request carries on the wire whose values history must not
	// keep: the stored exchange's request bytes replace each with a placeholder (credential
	// login, burpsy-react-ui-uzil). Nil for every ordinary request.
	maskValues []string
	// loginCred is the username this item logs in as, and marks the item as a credential login
	// submission: its response's Set-Cookie is harvested into the crawl's session jar. Empty for
	// every ordinary request.
	loginCred string
	// tag is the element the item was discovered from — "a", "img", "script", "form", "sitemap",
	// "api:openapi", and so on. Carried onto the item because the scope gate has to distinguish a
	// SUBRESOURCE refusal from a navigational one (burpsy-react-ui-hgor), and the tag is the only
	// thing that says which it was. Empty for a seed, which is what a seed is: something the operator
	// named rather than something a page carried.
	tag string
	// speculative marks an item the speculative-hidden-link phase mined from a comment or
	// script body (burpsy-react-ui-t5m0). It passes every gate a navigational link passes;
	// the flag exists so the crawl-wide cap can count it and the report can say how many
	// hidden links the crawl followed.
	speculative bool
	// fragment is the client-side ROUTE this item stands for, when the application routes on its
	// fragment (burpsy-react-ui-wbqx). It is identity ONLY and never goes on the wire: url is
	// always the fragment-less form, so buildRequest and the sender's authorisation both see a
	// request that is safe to send, while the frontier, the request fingerprint and the location
	// map all key on this so `#/orders/7` and `#/orders/8` stay two locations of one GET.
	//
	// Empty for every ordinary item, including an in-page anchor (`#top`), which is still
	// stripped at resolveAgainst as it always was.
	fragment string
}

// Crawler runs one crawl. Not safe for concurrent Run calls: the frontier, the seen sets and the
// report are per-crawl state, and a Crawler is cheap enough that sharing one buys nothing.
type Crawler struct {
	cfg    Config
	limits Limits
	// suiteGate blocks while the dashboard's suite-wide pause is set. A plain func rather than a
	// *dash.Registry so this package keeps not importing the dashboard: the crawl engine has no
	// business knowing what a task row is, and the caller that owns both can hand the two together.
	// Nil means unpaced, which is what every caller outside the web layer is.
	suiteGate func(context.Context)
	// eh is the resolved error-handling policy: what this crawl does about requests that fail rather
	// than only counting them (burpsy-react-ui-o0c5). Resolved once in New, so every reader sees the
	// same set and a threshold cannot differ between the pass that trips it and the report that
	// names it.
	eh ErrorHandling
	// followUpPassesSpent is how many of this crawl phase's configured follow-up passes have
	// run: the per-request retry bound (o0c5) is per PHASE under credential phases
	// (burpsy-react-ui-crediso), reset at each phase boundary.
	followUpPassesSpent int
	// followUp is the set of requests that ended in a transport failure, kept for the follow-up pass.
	// Per-crawl, not per-run, and drained pass by pass so a request that fails twice is retried on
	// the NEXT pass rather than twice in the same one.
	followUp []frontierItem
	// The three running counters the pause thresholds read (o0c5). Per-crawl, and reset by any
	// success — a threshold is about CONSECUTIVE failures, and a counter that only ever went up would
	// be a lifetime total, which is a different policy and a much more trigger-happy one.
	consecutiveTimeouts     int
	consecutiveAuthFailures int
	timeouts                int
	// speculativeAdmitted counts the speculative-phase links actually enqueued (burpsy-react-ui-t5m0).
	// Counted at admission, after every other gate has passed, so the cap bounds what the crawl
	// FOLLOWS — not what it saw. Refusals at the cap are SkipSpeculativeLimit, and the stop is
	// StopSpeculativeLinks.
	speculativeAdmitted int
	// query is the parsed crawl-scope query (DSL-03), nil when the operator gave none. Parsed once in
	// New, so a malformed query is a construction error and never a per-URL surprise.
	query *query.Expr
	// seedURLs are the validated, absolute seeds. Held parsed rather than re-parsed per Run, because
	// New has already rejected everything wrong with them.
	seedURLs []*url.URL
	// seedRequests are the validated SeedRequests as frontier items, admitted by Run in place of the
	// seed loop when SeedsOnly is set. Built here for the same reason seedURLs is: New is where a
	// malformed method, URL or header gets refused, so Run has nothing left to validate.
	seedRequests []frontierItem
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
	// graphqlAnswer receives the body of a response that was captured for an introspection query, and
	// returns the operations to admit from it.
	//
	// A HOOK rather than a second send, and that is the whole point: perform() already has the bytes
	// in hand after capture, so a reader that wanted them has to be given them here or it has to ask
	// the target again. Asking again would double the traffic for one fact, and would make the second
	// request the one whose answer differed from the first — a schema that changed mid-crawl would
	// then be reported as whatever the second request saw. nil means nobody asked, which is every
	// crawl that is not looking for GraphQL.
	graphqlAnswer func(u *url.URL, body []byte) []APIDocEndpoint
	// guessedGraphQL records the guessed paths already probed, so a host is probed once per path
	// rather than once per page that happens to sit on it.
	// startedAt is when Run began, so the requests a visit itself triggers — the GraphQL guess
	// probes and the introspection query — answer to the same MaxDuration the loop checks between
	// visits (burpsy-react-ui-u4mm). Set once at Run's first line; a zero value means the check
	// stands down, which no production path can produce.
	startedAt time.Time

	guessedGraphQL map[string]bool
	// introspected records the URLs already introspected, so an endpoint reached from five
	// pages is asked once rather than five times.
	introspected map[string]bool
	// formSubmissions counts submissions per FORM SIGNATURE, for the per-form cap
	// (burpsy-react-ui-u0k3). Bounded in use by the cap itself: an entry is created only when a form is
	// actually submitted, and that form is never submitted again once the cap is reached, so the map
	// grows with the number of DISTINCT forms submitted rather than with the number of submissions.
	formSubmissions map[string]int
	// formDestinations maps a FORM SIGNATURE to the set of distinct destinations it has already been
	// submitted to, for the optimization threshold (burpsy-react-ui-ddln). The SET, not a count, is
	// what the bound is about: Burp's own name for the setting is the length of the form's input
	// strategy CHAIN, so submitting the same destination twice — which MaxSubmissionsPerForm already
	// bounds — must not spend this budget, or the two bounds would double-count one submission and
	// the threshold would fire sooner than its number says.
	//
	// Bounded in use by the threshold itself: a form whose set has reached the bound is never
	// submitted again, so the total growth is (forms submitted x threshold) rather than unbounded.
	// The inner sets are small for the same reason.
	formDestinations map[string]map[string]struct{}
	// guessHiddenGraphQL is the armed state of the guess, as opposed to guessedGraphQL which is
	// the set of paths already probed. Two names because one is a switch and one is a ledger.
	guessHiddenGraphQL bool
	senders            map[string]*sender.AuthorisedSender

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
	queued map[string]bool
	// locations maps one exact location fingerprint to where it was first seen, plus the link
	// targets the tolerance band compares against. The extra fields are the band's price and
	// nothing else: only recordStructuredLocation writes an entry with targets, and only it reads
	// them.
	locations map[string]locationEntry
	// locationShapes indexes locations by their shape digest — skeleton, form signatures and text
	// bucket, everything but the link targets — so the tolerance band compares a candidate only
	// against locations that share its shape. Bounded by the same MaxFingerprints the location map
	// itself is: one entry per distinct shape, and a shape cannot exist without a location, so the
	// index is never the largest of the two. See location_band.go for what a fold may tolerate.
	locationShapes map[string][]string
	// phaseLocations and phaseLocationShapes are the same two structures, scoped to the current
	// crawl phase and reset when a credential phase begins (burpsy-react-ui-crediso): they decide
	// only whether a response's links are walked (see recordPhaseWalk), so a page another phase
	// already walked does not suppress this phase's walk, while the location count above stays
	// global and honest — identical content is one location however many phases fetched it.
	phaseLocations      map[string]locationEntry
	phaseLocationShapes map[string][]string
	// notFound is each probed directory's answer for a nonexistent name (s92h); nil marks a directory
	// whose probe could not be read. notFoundProbes counts probes against maxNotFoundProbes.
	notFound       map[string]*notFoundShape
	notFoundProbes int
	// templates counts fetches admitted per URL template, for the quota. Bounded by
	// Limits.MaxFingerprints as well: an entry is created for every template not seen before, including
	// for links dropped at a full frontier, so this one grows even while the crawl fetches nothing new.
	templates map[string]int
	// sitemapSeeded counts the requests pre-marked from the site map (burpsy-react-ui-z8qf).
	// Reported rather than assumed: a seeding feature whose saving nobody can see is one nobody
	// can tell is working. See sitemap_seed.go for what is seeded and — the more important half —
	// what deliberately is not.
	sitemapSeeded int
	// templateOK remembers the URL templates this crawl has seen return 200, so the session
	// expiry detector can tell a template that flipped from one that simply never worked. Set at
	// most per template, like the quota table; an entry is removed when a template stops matching.
	templateOK map[string]bool
	// relogins counts every attempt to restore the session (re-login budget generation counter).
	// Bounded by Limits.MaxRelogins. Counted per attempt, so concurrent and sequential waves of
	// expiry share one budget. Success or failure moves the counter; see session_gate.go.
	relogins int
	// login is the recorded login's jar and report, nil without Config.BrowserLogin.
	login *loginState
	// credPhase is which crawl phase is running (burpsy-react-ui-crediso): 0 for the
	// unauthenticated phase, N >= 1 for the phase crawling behind LoginCredentials[N-1]. Frontier
	// dedup and template quotas are namespaced by it, so each credential's phase re-crawls the
	// application behind its own login — per-phase state, no cross-credential leakage. Phases are
	// sequential: the frontier drains before the next phase begins, so every item in flight
	// belongs to the current phase and c.login is always the current phase's session.
	credPhase int
	// loginForm records the first identified login form when credentials are configured; the
	// phases build their login submissions from it at phase start rather than at discovery —
	// Burp discovers login functions unauthenticated and answers them per credential.
	loginForm *credentialLoginForm
	// authChallenged are the GET URLs the unauthenticated phase bounced off (401/403): each
	// credential phase re-fetches them WITH its session. GET-only, deliberately: replaying a
	// challenged POST would re-send a body under a session the unauthenticated phase did not
	// hold — a write with new authority, which the re-fetch is not licensed to make. Bounded
	// (maxAuthChallenged); discovery-order. The seen-map is bounded by construction: every URL
	// in it was admitted to the frontier, and the admitted-request table is bounded by
	// MaxFingerprints (SkipFingerprintBudget refuses past it). challengedSeeded marks that the
	// current phase has already issued its re-fetches, so a re-login does not re-seed them.
	authChallenged     []string
	authChallengedSeen map[string]bool
	challengedSeeded   bool
	// credLoginLocationBase is len(c.locations) at the moment the first credential login
	// succeeded: locations the crawl already knew before it had a session, so the report's
	// PagesFoundAfterLogin counts what the login actually unlocked rather than the whole map.
	credLoginLocationBase int
	// loginPage is the compiled LoginPagePattern, nil when none was given. The regex is compiled
	// in New so a malformed pattern is a construction error, never a per-URL surprise.
	loginPage *regexp.Regexp
	// wellKnownSeeded records the authorities whose .well-known documents were admitted (bc2x).
	wellKnownSeeded map[string]bool
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
	if len(cfg.Seeds) == 0 && len(cfg.SeedRequests) == 0 {
		return nil, fmt.Errorf("a crawl needs at least one seed URL")
	}
	if len(cfg.SeedRequests) > 0 && !cfg.SeedsOnly {
		return nil, fmt.Errorf("SeedRequests was set without SeedsOnly: a crawl that follows links does not know what to do with a method, a body or a per-request header, so it would send a GET at a path meant for a POST. Set SeedsOnly, or pass the URLs as Seeds")
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
	if cfg.BrowserLogin != nil && len(cfg.LoginCredentials) > 0 {
		// Burp's own rule: one authentication method per scan — a recorded login replaces
		// credentials, never joins them. Two methods would leave the report unable to say which
		// session a page was reached under.
		return nil, fmt.Errorf("a crawl gets one authentication method: BrowserLogin (a recorded login) and LoginCredentials (form login) are alternatives, not a pair — set one")
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

	// SeedRequests become frontier items here, and their URLs join the seed *set*: credentialOrigins,
	// the robots decision and Report.Seeds all key off "the URLs the operator named", and a request
	// the operator named is one of those. Validated to exactly the standard a seed URL is, because a
	// definition is input like any other — the fact that it arrived as a file rather than as a typed
	// URL changes nothing about what a request built from it may contain.
	seedRequests := make([]frontierItem, 0, len(cfg.SeedRequests))
	for i, req := range cfg.SeedRequests {
		method := strings.ToUpper(strings.TrimSpace(req.Method))
		if method == "" {
			method = "GET"
		}
		label := fmt.Sprintf("request %d (%s %s)", i+1, method, req.URL)
		u, err := url.Parse(strings.TrimSpace(req.URL))
		if err != nil {
			return nil, fmt.Errorf("%s is not a URL: %w", label, err)
		}
		if !supportedScheme(u.Scheme) {
			return nil, fmt.Errorf("%s has scheme %q; a scan can only send http or https", label, u.Scheme)
		}
		if u.Host == "" {
			return nil, fmt.Errorf("%s has no host", label)
		}
		if u.User != nil {
			return nil, fmt.Errorf("%s embeds credentials in the URL; put them in Config.Headers or the request's own Headers", label)
		}
		u.Fragment = ""
		u.RawFragment = ""
		if u.Path == "" {
			u.Path = "/"
		}
		for name, value := range req.Headers {
			if err := validateHeader(name, value); err != nil {
				return nil, fmt.Errorf("%s: %w", label, err)
			}
		}
		if len(req.Body) > 0 && req.ContentType == "" {
			return nil, fmt.Errorf("%s carries a %d-byte body with no Content-Type; a target has no way to know how to read it", label, len(req.Body))
		}
		seeds = append(seeds, u)
		cfg.Seeds = append(cfg.Seeds, u.String())
		seedRequests = append(seedRequests, frontierItem{
			url: u, method: method, depth: 0,
			body: req.Body, contentType: req.ContentType, headers: req.Headers,
		})
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
		// Resolved ONCE, here, so the pass that trips a threshold and the report that names it read
		// the same numbers. A zero ErrorHandling is filled from the defaults; a family the caller
		// populated — including one it filled with zeros, meaning never pause — is left alone.
		eh:    cfg.ErrorHandling.resolved(),
		query: expr,
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
		credentialOrigins:   make(map[string]bool),
		queued:              make(map[string]bool),
		locations:           make(map[string]locationEntry),
		locationShapes:      make(map[string][]string),
		phaseLocations:      make(map[string]locationEntry),
		phaseLocationShapes: make(map[string][]string),
		notFound:            make(map[string]*notFoundShape),
		templates:           make(map[string]int),
		templateOK:          make(map[string]bool),
		authChallengedSeen:  make(map[string]bool),
		// -1 until the first SUCCESSFUL credential login: "no login has unlocked anything
		// yet" must read differently from "the login unlocked everything from location 0".
		credLoginLocationBase: -1,
		hostLimiters:          make(map[string]*intruder.RateLimiter),
		robotsSeeded:          make(map[string]bool),
		requestsPer:           rps,
		rateCapped:            capped,
		throttle:              throttle,
		poolName:              poolName,
		poolConcurrency:       poolConcurrency,
		retention:             retention,
		loginPage:             loginPage,
		login:                 newLoginStateOrNil(cfg.BrowserLogin),
	}
	// Seeds enter through the same admission gates as any discovered link, minus the destructive
	// check — see destructive.go for why the operator's own instruction is not second-guessed. They
	// are recorded on the report's LimitReport through the same counters, so a seed refused by scope
	// is visible rather than a crawl that mysteriously fetched nothing.
	c.seedURLs = seeds
	c.seedRequests = seedRequests
	// Config.Headers travel only to the origins the operator seeded. Recorded here, from the parsed
	// seeds, so the key is computed by the same function that keys the outgoing request.
	for _, s := range seeds {
		c.credentialOrigins[originKey(s)] = true
	}

	// The two GraphQL bookkeeping sets, always present. Unconditional rather than armed with the
	// reader: a nil map here panics on assignment the first time a crawl reaches a GraphQL envelope,
	// and a panic is a worse answer than an empty crawl.
	if c.guessedGraphQL == nil {
		c.guessedGraphQL = map[string]bool{}
	}
	if c.introspected == nil {
		c.introspected = map[string]bool{}
	}
	if c.formSubmissions == nil {
		c.formSubmissions = map[string]int{}
	}
	if c.formDestinations == nil {
		c.formDestinations = map[string]map[string]struct{}{}
	}

	// The GraphQL reader, armed only if the operator's configuration asks for it. Here rather than at
	// each use, so there is exactly ONE place that decides whether this crawl will send a POST of its
	// own initiative — and so the answer is visible in one glance rather than spread across the reader.
	if cfg.PerformGraphQLIntrospection || cfg.GuessHiddenGraphQLEndpoints {
		c.armGraphQL()
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
// WithSuiteGate attaches the dashboard's suite-wide pause. The crawl calls it between fetches;
// nil, the default, is a crawl nothing can pause but its own context.
func (c *Crawler) WithSuiteGate(gate func(context.Context)) *Crawler {
	c.suiteGate = gate
	return c
}

// WithTaskID stamps every exchange and finding this crawl captures with the registry task that owns
// it, returning the crawler so it reads as part of a construction chain.
//
// A method rather than a Config field because of an ordering constraint that cannot be removed: the
// id is handed out when the task is registered, and the config is built *before* that, so a
// configuration mistake is a refusal the operator can fix rather than a task that appears only to
// fail. Config.Capture.TaskID therefore cannot be set by the caller that knows the id, and the only
// alternative would be for every crawl caller to rebuild the whole config after registering.
//
// Nothing here is crawler-specific — it writes Config.Capture.TaskID, which scanner.Capture already
// documented as the one place a surface states whose run its traffic belongs to. Without it a crawl's
// exchanges are indistinguishable from the operator's own browsing, and "audit what I just crawled"
// has to be answered by guessing from timestamps.
func (c *Crawler) WithTaskID(id uint64) *Crawler {
	c.cfg.Capture.TaskID = id
	return c
}

func (c *Crawler) Run(ctx context.Context) Report {
	started := time.Now()
	c.startedAt = started
	rep := Report{
		Seeds:              c.cfg.Seeds,
		SeedsOnly:          c.cfg.SeedsOnly,
		Query:              c.cfg.Query,
		RetentionQuery:     c.cfg.RetentionQuery,
		FormSubmission:     c.cfg.SubmitForms,
		RequestSpeculative: c.cfg.RequestSpeculative,
		RobotsPolicy:       RobotsPolicy,
		// Both from the crawler rather than from cfg, so what is reported is the pool the limiters
		// were actually built from and not the pool the caller meant to pass.
		Pool:            c.poolName,
		PoolConcurrency: c.poolConcurrency,
		// The count is on the Crawler rather than only the Report, because SeedFromSiteMap is called
		// by a caller that may run before Run (burpsy-react-ui-z8qf) and a report that only learned
		// of it at Run time would report a seed it did not cause.
		SitemapSeeded: c.sitemapSeeded,
	}
	// Every edge kind is on the wire from the start, zeros included (ylr1), so a crawl that found
	// nothing reports {"anchor":0,...} rather than null.
	seedEdgeKinds(&rep)
	lim := LimitReport{Limits: c.limits}
	// The recorded login runs before anything is admitted or fetched, so the first request — the
	// seed — already carries the session (burpsy-react-ui-xhtk).
	c.loginBeforeCrawl(ctx, &rep, &lim)

	if c.cfg.SeedsOnly {
		// The definition is the attack surface, so the frontier starts as the definition's endpoints
		// and — because perform returns before link extraction — stays that. No robots.txt: the probe
		// is a request nobody described, which is the thing this mode exists to exclude.
		for _, item := range c.seedRequests {
			c.admitSeedRequest(item, &lim)
		}
	} else {
		for _, u := range c.seedURLs {
			c.countEdge(&rep, "origin")
			c.admitSeed(u, &lim)
		}
		// One robots.txt per seed authority, queued behind the seeds so the operator's own starting
		// points are fetched first. Not honoured as a restriction — read as a list of paths the target
		// would rather nobody looked at. See the package docs.
		for _, u := range c.seedURLs {
			c.admitRobots(u, &lim)
		}
		// The standard .well-known documents, once per seed authority (burpsy-react-ui-bc2x).
		if c.cfg.RequestWellKnown {
			for _, u := range c.seedURLs {
				c.admitWellKnown(u, &rep, &lim)
			}
		}
	}

	// pausedByPolicy is set when the error-handling thresholds end the crawl (o0c5).
	pausedByPolicy := false
	for {
		// Frontier-empty is tested before every bound, so a crawl that fetched exactly its request
		// budget and had nothing left to do reports as complete rather than as truncated. A bound is
		// only a stop when there was still work it prevented.
		if len(c.frontier) == 0 {
			// Owed retries run before the drain is declared: a recovered request's links are
			// admitted to THIS phase's frontier and execute under THIS phase's session — a
			// phase whose retry recovered something is not drained (burpsy-react-ui-crediso).
			// A no-op with nothing owed or the phase's pass budget spent.
			c.runFollowUpPasses(ctx, &rep, &lim)
			if len(c.frontier) > 0 {
				continue
			}
			// A retry inside the pass may be what tripped the error-handling policy: re-check
			// BEFORE the next phase's login is admitted — the policy just said this target is
			// not to be sent to.
			if c.checkPauseThresholds(&rep, &lim) {
				pausedByPolicy = true
				break
			}
			// The unauthenticated phase drains first; then each credential in turn gets its
			// own phase behind its own login (burpsy-react-ui-crediso).
			if c.startNextCredentialPhase(ctx, &rep, &lim) {
				continue
			}
			break
		}
		if err := ctx.Err(); err != nil {
			lim.record(StopCancelled)
			break
		}
		// The dashboard's "Pause all tasks", between fetches (burpsy-react-ui-cijs). Held here
		// rather than inside a fetch so the request in flight always completes and is recorded
		// whole — the same placement the sequencer's capture loop uses. Cancellation stays senior:
		// GateCheck answers ctx.Done, and the ctx.Err above runs on the next turn of the loop.
		if c.suiteGate != nil {
			c.suiteGate(ctx)
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
		// One GraphQL probe pass per origin, after the origin's first page has been fetched. After,
		// not before, because a probe is a request and the crawl's own coverage claim is better
		// served by reaching a page the operator seeded first; and keyed on the origin rather than
		// the URL so a site with two hundred pages is probed four times, not eight hundred.
		if c.guessHiddenGraphQL {
			c.guessGraphQL(ctx, item.url, &rep, &lim)
		}
		// The operator's error-handling policy (o0c5), checked after every visit: a target that keeps
		// timing out, or keeps rejecting the session, ends the crawl with a NAMED stop rather than the
		// crawl grinding through the rest of its budget against it.
		if c.checkPauseThresholds(&rep, &lim) {
			pausedByPolicy = true
			break
		}
	}

	// The follow-up pass, run after the main loop and before the report is assembled, so the counts
	// it produces are the counts the report carries (o0c5).
	//
	// AFTER, not during: a follow-up pass is defined as re-issuing what the crawl FAILED to fetch,
	// and the crawl does not know which requests those are until it has tried them all. Retrying
	// inside the loop would also spend the request budget twice per request, which is the one thing a
	// bound on cost must not do.
	//
	// Not after a policy pause: the policy just said this target is timing out or rejecting the
	// session, and retrying its failures is exactly the traffic the operator configured it to stop.
	if !pausedByPolicy {
		c.runFollowUpPasses(ctx, &rep, &lim)
	}
	// Retries an ENDED phase still owes can never run — the session they belong to is retired —
	// so they are abandoned here, counted and named per request, rather than silently kept.
	c.dropAbandonedPhaseItems(&lim)

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
	rep.SpeculativeAdmitted = c.speculativeAdmitted
	if c.login != nil {
		login := c.login.report
		if login.Method == "credentials" {
			// What the first successful credential login unlocked, however the LAST phase
			// ended: a failed later phase makes the crawl's ENDING unauthenticated (the
			// Authenticated flag above is the current phase's, burpsy-react-ui-crediso); it
			// does not un-find the pages an earlier phase's session reached.
			if c.credLoginLocationBase >= 0 {
				login.PagesFoundAfterLogin = rep.Locations - c.credLoginLocationBase
			}
		} else if login.Authenticated {
			login.PagesFoundAfterLogin = rep.Locations
		}
		rep.Login = &login
	}
	return rep
}

// runFollowUpPasses re-issues the requests that ended in a transport failure, up to the configured
// count (burpsy-react-ui-o0c5). Runs at each credential phase's drain as well as at the crawl's
// end, and only for the CURRENT phase's items: the retry carries the session, so it belongs to
// the phase whose session it was (burpsy-react-ui-crediso).
//
// Through the ordinary perform path, deliberately: a retried request is captured, scanned and
// traversed exactly like a first attempt, so a flaky endpoint that answers on the second try
// contributes its links like any other. A retry that bypassed perform would re-send the bytes and
// discard the answer, which recovers a status code and no coverage — the opposite of the point.
//
// Bounded twice, and the second bound is the one that matters: at most FollowUpPasses extra attempts
// per request, and never more than MaxRequests sends in total, because a follow-up pass spends the
// SAME request budget the main pass spent. A crawl that retried without that second bound would send
// up to 2x its stated maximum, which is the one way a retry feature can make a tool cost more than
// the operator agreed to.
//
// A request that fails again stays in the set, so a later pass retries it again — a target that is
// down for the whole crawl ends with a report naming every one of its failures rather than a single
// mention per pass.
func (c *Crawler) runFollowUpPasses(ctx context.Context, rep *Report, lim *LimitReport) {
	passes := c.eh.followUpPasses()
	if passes <= 0 || len(c.followUp) == 0 {
		return
	}
	// The budget is rep.Fetched against MaxRequests — the SAME measure the main loop stops on. It was
	// lim.Requests, which is assigned once after the loop and reads zero for the whole crawl, so a
	// follow-up pass could spend a second full request budget on top of the first: the one way a
	// retry feature makes a tool cost more than the operator agreed to.
	// The pass budget is per crawl PHASE (burpsy-react-ui-crediso): the drain-time call and a
	// later crawl-end call in the same phase share it, so a request still gets at most
	// FollowUpPasses extra attempts per phase — the bound o0c5 states, carried into phases.
	for ; c.followUpPassesSpent < passes; c.followUpPassesSpent++ {
		if len(c.followUp) == 0 {
			break
		}
		// Cancellation is honoured between passes, and a cancelled retry stops the whole family:
		// a caller who pressed stop is not asking for the requests that already failed either.
		if ctx.Err() != nil {
			lim.record(StopFollowUpCancelled)
			return
		}
		// A fresh slice, not c.followUp[:0]: a request that fails again is appended to c.followUp
		// while this pass is still iterating, and appending into the same backing array would
		// overwrite the requests this pass has not reached yet.
		remaining := c.followUp
		c.followUp = nil
		for i, item := range remaining {
			if item.phase != c.credPhase {
				// Owed by a phase that has ended: not this pass's to run, because the session
				// it belongs to is retired. It stays queued; dropAbandonedPhaseItems is what
				// becomes of it (burpsy-react-ui-crediso).
				c.followUp = append(c.followUp, item)
				continue
			}
			if ctx.Err() != nil {
				c.followUp = append(c.followUp, remaining[i:]...)
				lim.record(StopFollowUpCancelled)
				return
			}
			if rep.Fetched >= c.limits.MaxRequests {
				// Put BACK rather than dropped: it failed and this crawl was not allowed to try again,
				// so it belongs in the report as an untried request rather than vanish.
				c.followUp = append(c.followUp, remaining[i:]...)
				lim.record(StopFollowUpBudget)
				return
			}
			// Failed counts requests that ENDED failed, not attempts: the earlier failure is withdrawn
			// before the retry, and perform counts it again only if the retry fails too. Without this a
			// recovered request would stay in Failed and Fetched at once.
			rep.Failed--
			fetchedBefore := rep.Fetched
			c.perform(ctx, item, c.buildRequest(item), rep, lim)
			if rep.Fetched > fetchedBefore {
				rep.FollowUpRecovered++
			}
			// The policy holds during a follow-up pass too: retrying a host that has started timing out
			// again is the traffic the operator configured the crawl to stop.
			if c.checkPauseThresholds(rep, lim) {
				c.followUp = append(c.followUp, remaining[i+1:]...)
				return
			}
		}
	}
}

// dropAbandonedPhaseItems abandons the follow-up retries owed by phases that have already ended
// (burpsy-react-ui-crediso). A retry is the same request under the same session; the phase
// boundary retired the session, so the owed retry is dropped with the count and a per-request
// record rather than sent under another phase's session — or silently dropped. The LAST phase's
// own leftovers keep the pre-crediso treatment: the crawl is over, their report is the Failed
// count they already carry.
func (c *Crawler) dropAbandonedPhaseItems(lim *LimitReport) {
	var kept []frontierItem
	for _, item := range c.followUp {
		if item.phase == c.credPhase {
			kept = append(kept, item)
			continue
		}
		lim.PhaseDropped++
		c.skips.record(SkipRecord{
			Reason: SkipPhaseAbandoned, URL: item.url.String(), Method: item.method,
			Text: item.text, FoundAt: item.foundAt,
			Detail: "the crawl phase that owed this retry ended; re-issuing it under another phase's session would be a different request",
		})
	}
	c.followUp = kept
}

// noteTransportFailure records a send that never came back, for the follow-up pass, and advances the
// timeout counters the pause thresholds read (o0c5).
//
// The two are one function because they happen at the same moment: a failure is both something to
// retry and something that counts toward "this target keeps timing out". Splitting them would let a
// caller wire one without the other, and the half that retries is the half an operator notices.
//
// Only a TIMEOUT extends the consecutive streak; a refused connection or reset breaks it, because
// Burp's threshold is about a target that has stopped answering, not one that answers "no".
func (c *Crawler) noteTransportFailure(item frontierItem, timedOut bool) {
	// Backstop for the few requests that never passed enqueue (a source-map fetch, an
	// introspection): the failing send belongs to the phase that sent it.
	item.phase = c.credPhase
	c.followUp = append(c.followUp, item)
	if timedOut {
		c.timeouts++
		c.consecutiveTimeouts++
		return
	}
	c.consecutiveTimeouts = 0
}

// noteSent records a send that came back with a response, whatever its status: the target answered,
// so the consecutive-timeout streak is over.
func (c *Crawler) noteSent() { c.consecutiveTimeouts = 0 }

// noteAuth records the outcome of restoring an expired session: a failed re-login extends the
// consecutive authentication-failure streak, a successful one ends it.
func (c *Crawler) noteAuth(ok bool) {
	if ok {
		c.consecutiveAuthFailures = 0
		return
	}
	c.consecutiveAuthFailures++
}

// isTimeout reports whether a send failed because it ran out of time — a dial, read or overall
// deadline — as opposed to being refused or reset.
func isTimeout(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// checkPauseThresholds trips the crawl's pause policy, returning true when the crawl must stop.
//
// A DISTINCT stop per threshold rather than one "paused" reason, because an operator reading
// "paused" cannot tell whether the target is slow, refusing, or rejecting their credentials, and
// those three call for three different responses.
func (c *Crawler) checkPauseThresholds(rep *Report, lim *LimitReport) bool {
	// A family with every threshold at 0 is a crawl that never pauses — the shape of Burp's shipped
	// "Never stop crawl due to application errors". Checked as a whole, because a 0 threshold must
	// not read as "unbounded": `armed` is what makes 0 mean disarmed rather than unset.
	if !c.eh.PauseConfigured() {
		return false
	}
	if n, want := c.consecutiveTimeouts, c.eh.timeoutCount(); armed(&n) && want > 0 && c.consecutiveTimeouts >= want {
		lim.record(StopPausedTimeouts)
		return true
	}
	// The denominator is the sends this crawl has made — fetched plus failed — NOT lim.Requests,
	// which is assigned once after the loop and reads zero for the whole crawl (see introspect): a
	// percentage over it could never fire.
	if want, sent := c.eh.timeoutPercent(), rep.Fetched+rep.Failed; want > 0 && sent > 0 &&
		100*c.timeouts/sent >= want {
		lim.record(StopPausedTimeoutPercentage)
		return true
	}
	if n, want := c.consecutiveAuthFailures, c.eh.authFailures(); armed(&n) && want > 0 && c.consecutiveAuthFailures >= want {
		lim.record(StopPausedAuthFailures)
		return true
	}
	return false
}

// fetchSourceMap fetches one source map and mines the paths out of it.
//
// A source map's `sources` array is the ORIGINAL file list of a bundle — the pre-minification paths,
// which for a SPA is the route table written in readable form. That is a higher-value find than the
// minified body it came from, and it is one request to obtain.
//
// The map is NOT parsed as an exchange or traversed: its sources are file paths, not locations, and
// treating "/src/routes/dashboard.ts" as a URL to fetch would flood the frontier with TypeScript
// filenames that 404. What is taken is the PATH STRINGS inside each source's `sourcesContent` when
// the map carries it, which is the same mining the speculative phase already does, applied to better
// text. A map with no embedded content (the common case for a production build that ships maps
// without sources) therefore yields nothing — and says so, rather than reporting a fetch that found
// nothing as a success.
func (c *Crawler) fetchSourceMap(ctx context.Context, mapURL string, item frontierItem, rep *Report, lim *LimitReport) {
	if mapURL == item.url.String() {
		return
	}
	u, err := url.Parse(mapURL)
	if err != nil {
		return
	}
	mapItem := frontierItem{url: u, method: "GET", depth: item.depth, foundAt: item.url.String(),
		text: "source map for " + item.url.String()}
	// Captured through perform, so this request is bounded, rate-limited and recorded. The response is
	// NOT counted as a location: a .map is an artifact of a bundle, not a page of the application.
	before := rep.Fetched
	c.perform(ctx, mapItem, c.buildRequest(mapItem), rep, lim)
	if rep.Fetched <= before {
		// Scope refused it, or the transport failed. Both are already recorded by perform with their own
		// reasons; nothing to add, and adding a second reason here would double-count one event.
		return
	}
	rep.SourceMapsFetched++
	c.mineSourceMapBody(mapItem, item, rep, lim)
}

// mineSourceMapBody reads a fetched map's sourcesContent back out of the store and admits the
// URL-shaped paths inside it, through the same speculative gates every other hidden link passes.
//
// # Why sourcesContent and never `sources`
//
// The map's `sources` array is a file list — "/src/routes/dashboard.ts" is a TypeScript path inside
// the build tree, not a URL the application serves. Admitting those would flood the frontier with
// filenames that 404. sourcesContent is the ORIGINAL SOURCE TEXT itself, which for a SPA is where
// the route table lives in readable form — `router.get("/admin", …)` written by a human. The
// speculativeURLFields gates (root-relative or absolute only, punctuation-aware) are applied to it
// unchanged: the same discipline that keeps a comment's prose out of the frontier also keeps a
// TypeScript import path out, which is the exact reason to reuse them rather than write looser
// rules "just for maps".
//
// # Why read the body back rather than hold the bytes
//
// The map was captured through the shared seam; its bytes live in the store indexed by exchange id.
// Reading them back through GetExchange→Get→Body means the text mined is byte-for-byte the bytes the
// passive check set already examined, and no copy of a potentially multi-megabyte map is held by the
// frontier or the report. This is the architecture's own rule: raw bytes are written once and never
// copied (AGENTS.md, "The one invariant").
//
// # The cap and the honest empty
//
// A map whose sourcesContent is absent (the common case for a production build that ships maps
// without sources) yields nothing, and that is the true answer — the fetch is counted and the
// report says so, rather than padded into a success. The MaxSpeculativeLinks cap still bounds the
// mining through the same accounting every other speculative overflow takes.
func (c *Crawler) mineSourceMapBody(mapItem frontierItem, item frontierItem, rep *Report, lim *LimitReport) {
	// The map's own fetch row, found BY URL rather than by position. The obvious `rep.Fetches[len-1]`
	// is wrong: perform appends the map's row, but the crawl is concurrent and by the time this runs
	// the rows for the root page and the robots probe may already sit after it — the map's row was
	// not last on the first probe, and the row that WAS last was the root page's, whose ExchangeID is
	// 0. A store assigns ids from 0, so "ExchangeID == 0" is a real id and cannot be the sentinel
	// either; matching the URL is the only lookup that cannot confuse a row for the wrong one.
	var fetch Fetch
	found := false
	for _, f := range rep.Fetches {
		if f.URL == mapItem.url.String() {
			fetch, found = f, true
			break
		}
	}
	if !found {
		return
	}
	ex, err := c.cfg.Capture.Store.GetExchange(fetch.ExchangeID)
	if err != nil || ex.Response == nil {
		return
	}
	msg, gerr := c.cfg.Capture.Store.Get(*ex.Response)
	if gerr != nil {
		return
	}
	content := sourceMapSourcesContent(msg.Body())
	// No emptiness guard, deliberately: speculativeURLFields("") returns no candidates, so an absent
	// sourcesContent produces no admission and no request — the honest empty — without a branch that
	// a reader has to verify against the extractor to know it is not load-bearing.
	// The map was fetched for item; the paths inside it are found relative to the page that named
	// the map, at the page's own depth so the map pass cannot dig deeper than the page that carried it.
	for _, raw := range speculativeURLFields(content) {
		c.admit(discoveredLink{raw: raw, tag: "source map", speculative: true}, item.url, item.depth, rep, lim)
	}
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
	if c.cfg.OnSend != nil {
		c.cfg.OnSend(item.method, item.url.String())
	}
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
		// Kept for the follow-up pass and counted toward the timeout thresholds (o0c5): before this,
		// a failed request was recorded and forgotten, and a flaky target left a coverage hole with no
		// second attempt.
		c.noteTransportFailure(item, isTimeout(err))
		return
	}
	c.noteSent()
	c.observe(item.url, res.Status)

	// A 401/403 in the unauthenticated phase is a page the login exists to unlock: remembered so
	// each credential phase re-fetches it WITH its session (burpsy-react-ui-crediso). GET-only —
	// see the field. Past maxAuthChallenged the overflow is counted, not silent.
	if c.credPhase == 0 && item.method == "GET" && res.Status != nil && (*res.Status == 401 || *res.Status == 403) {
		k := item.url.String()
		if !c.authChallengedSeen[k] {
			c.authChallengedSeen[k] = true
			if len(c.authChallenged) >= maxAuthChallenged {
				lim.AuthChallengedDropped++
			} else {
				c.authChallenged = append(c.authChallenged, k)
			}
		}
	}

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
		Host:   item.url.Hostname(),
		Port:   portOf(item.url),
		TLS:    strings.EqualFold(item.url.Scheme, "https"),
		Method: item.method,
		Path:   item.url.RequestURI(),
		// Masked, when this request carries credential values: the wire bytes were the real
		// ones, history's are not (burpsy-react-ui-uzil; HeadersWithheld is the precedent).
		Request:  maskStoredValues(raw, item.maskValues),
		Response: res.Raw,
		Started:  time.Now().Add(-res.Duration),
		Duration: res.Duration,
		Protocol: core.ProtocolHTTP1,
		// The address the fetch's socket actually reached — SendOutcome carries it read off the
		// live connection, so a crawled row answers "which host did this name resolve to" the way
		// a proxied row does (burpsy-react-ui-gj4f). Empty only when the send failed, and this
		// path only runs after a successful one.
		ServerIP: res.Outcome.ServerIP,
		// Attributed, so history can distinguish what the crawl caused from what the operator's own
		// browser did. Leaving it unset would land this in the store as unattributed, which is the
		// store's honest default and the wrong answer when the surface is known.
		Source: c.captureSource(),
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

	// A session the application rotates is kept current from every response the crawl captured.
	c.login.absorb(item.url, res.Raw)

	// A credential login's response is where the session arrives (burpsy-react-ui-uzil).
	if item.loginCred != "" {
		c.completeCredentialLogin(item, res.Raw, rep, lim)
	}

	rep.Fetched++
	if item.depth > lim.DeepestDepth {
		lim.DeepestDepth = item.depth
	}
	// FoundAt and LinkText come straight off the frontier item, which has carried them all along for
	// the refusal reports. Populating them here is the whole of what a crawl-paths view needed.
	fetch := Fetch{
		URL: item.url.String(), Method: item.method, ExchangeID: ex.ID, Depth: item.depth,
		FoundAt: item.foundAt, LinkText: item.text,
		FoundByRender: item.renderedOrigin,
		// The route, when this item stands for one (burpsy-react-ui-wbqx). URL above stays
		// fragment-less on purpose: it is the request that actually went out, and the fragment is
		// reported separately so a reader can see the route without being able to mistake it for
		// part of the sent request.
		Fragment: item.fragment,
	}
	if ex.Status != nil {
		fetch.Status = int(*ex.Status)
	}
	// Announced here, where the record is complete, rather than beside each rep.Fetches append. The
	// appends are at ten return sites — the unreadable stored response, the expired session, a
	// seeds-only run, robots.txt, a redirect, an encoded body, a non-HTML body, a retention-excluded
	// response, a duplicate location, and the ordinary tail — and a consumer wired at each of them
	// would silently miss whichever branch the next edit adds, auditing less than the crawl fetched
	// with nothing on screen saying so. One call at the one point every branch passes through cannot
	// drift that way. See Config.OnFetch for what the snapshot does and does not carry.
	if c.cfg.OnFetch != nil {
		c.cfg.OnFetch(fetch)
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

	// A GraphQL introspection answer, read here because this is where the DECODED body exists. It was
	// first installed just after the capture, against res.Raw — which is the whole raw HTTP response,
	// status line and headers included, so every probe against it was reading the head and never the
	// body. That is worth recording: a hook placed one step too early looks correct, compiles, and
	// silently never fires, and the only symptom is a feature that reports nothing.
	if c.graphqlAnswer != nil {
		if ops := c.graphqlAnswer(item.url, body); len(ops) > 0 {
			c.admitGraphQLOperations(item.url, ops, rep, lim)
		} else if looksLikeGraphQLEndpoint(body) && !c.introspected[item.url.String()] {
			// The body carries a GraphQL envelope, so this URL is a GraphQL endpoint and the only way
			// to learn its operations is to ask. Recorded once per URL, because a crawl that fetches
			// the same endpoint from five pages must not introspect it five times.
			c.introspected[item.url.String()] = true
			c.introspect(ctx, item.url, rep, lim)
		}
	}

	// Session expiry (Phase 6, Gap A). Checked here — after CRAWL-02 has captured and scanned the
	// bytes, before the robots/redirect/content branches — so a login *redirect* (a template that was
	// 200 now answering 3xx toward /login) or a 401 is recognised as a lost session rather than
	// followed as an ordinary edge, and a login page served at 200 is caught by the pattern rule. The
	// whole block is inert without a coordinator: detectExpired returns "not expired" and templateOK
	// is never consulted, so the static-Headers crawl behaves exactly as before. The robots probe
	// carries no session and is skipped. See session_gate.go.
	if c.sessionAware() && !item.robots {
		template := urlTemplate(item.method, item.url, item.fieldNames, item.fragment)
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

	// A seeds-only run is done with this request. It has been scope-authorised, sent, captured and
	// scanned — everything above is shared with a crawl on purpose, so a definition-driven scan is no
	// more privileged and no less recorded than any other traffic. What is skipped is everything that
	// would add a request the definition did not name: the robots probe (not admitted at all), the
	// redirect target, the retention query's traversal gate, and link and form extraction.
	//
	// Deliberately no fingerprint and no location record either. A fingerprint exists so a crawl can
	// tell "the same page again" from "a new page" and not re-descend a subtree; this run never
	// descends, so the map would only serve to collapse two endpoints returning the same bytes into
	// one location — which is a coverage claim about a scan that made no such claim. Report.Locations
	// is 0 for a seeds-only run and that number is true.
	if c.cfg.SeedsOnly {
		rep.Fetches = append(rep.Fetches, fetch)
		return
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

	// A sitemap, admitted from a robots.txt `Sitemap:` line (burpsy-react-ui-qjtx). It arrives here
	// looking exactly like the defect it replaces: fetched, stored, scanned, and about to be recorded
	// as a non-HTML body — indistinguishable from a target that published no URL list at all.
	//
	// A SIBLING of the HTML gate, not a relaxation of it. isHTML exists for HTML extraction — the
	// link walk, form submit, base-href resolution — and none of that applies here; admitting XML
	// through that gate would hand every non-HTML response to the HTML extractor looking for anchors
	// it will never find. A PDF below still records SkipNotHTML exactly as before.
	// Not a document that sniffs as an API definition: LooksLikeSitemap claims every XML content type,
	// so a WSDL served as text/xml or application/wsdl+xml was read as a sitemap and its operations
	// never crawled (found by burpsy-react-ui-ai64; an existing WSDL test had been passing only because
	// the HTML page linking to the WSDL was itself misread as one).
	if LooksLikeSitemap(contentType, body) && sniffAPIDocument(contentType, item.url.Path, body) == APIDocNone {
		c.consumeSitemap(item, contentType, body, &fetch, rep, lim)
		rep.Fetches = append(rep.Fetches, fetch)
		return
	}

	// A JSON document that names its own endpoints (burpsy-react-ui-mz1n), branch (b) of the
	// same shape as the sitemap sibling above: a SIBLING of the HTML gate, not a relaxation of
	// it. Burp reads non-HTML for locations (its API / DISCOVERED_CONTENT action kinds), and a
	// documented API reachable from the crawled HTML contributed nothing here before this.
	//
	// The JSON reader is deliberately narrow: it takes URLs, slash-rooted paths, and relative
	// references only under a key that names a link. A bare word is not a path — guessing that
	// an arbitrary string is one is how a crawler invents URLs nobody observed.
	// An API DEFINITION — OpenAPI, Swagger, WSDL (burpsy-react-ui-bwwg). Checked BEFORE the
	// generic JSON gate below, and the order is load-bearing: a definition is also valid JSON, so
	// the narrow reader would look at it first, find the URL-shaped strings inside a `servers` block
	// or an example, and admit those — while missing every route the document actually declares. A
	// document read by the wrong reader is worse than one not read, because it produces locations.
	if c.cfg.ParseAPIDefinitions || c.cfg.ParseSOAPWSDLs {
		if c.consumeAPIDocument(item, contentType, body, &fetch, rep, lim) {
			rep.Fetches = append(rep.Fetches, fetch)
			return
		}
	}

	if LooksLikeJSON(contentType, body) {
		c.consumeJSON(item, contentType, body, &fetch, rep, lim)
		rep.Fetches = append(rep.Fetches, fetch)
		return
	}

	// A JavaScript response (burpsy-react-ui-jwy5): a SPA's routes live in its bundles, and before
	// this an external script reached the not-HTML skip below with every path inside it unread. A
	// SIBLING of the HTML gate, like the sitemap and JSON readers above, for the same reason.
	if LooksLikeJavaScript(contentType, item.url.Path) {
		c.consumeJavaScript(ctx, item, contentType, body, &fetch, rep, lim)
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
	// by now every field the grammar has really does have a value — including `header`, which is why
	// the stored response is handed to fetchedRow rather than only its body. `duration` is the one
	// exception and reports itself unmeasured: the crawler does not time fetches at this layer. It gates traversal and nothing
	// else. CRAWL-02 means this response is already captured and already scanned — it cannot be
	// un-captured, and calling this a scope exclusion would make the crawl's counts disagree with the
	// store's. So it is a response-category skip, and the request that produced it still counts as a
	// fetch.
	if c.retention != nil && !c.retention.Match(fetchedRow{
		host: item.url.Hostname(), method: item.method, path: item.url.Path, status: fetch.Status,
		mime: contentType, body: body, resp: msg,
	}) {
		fetch.RetentionExcluded = true
		c.skips.record(SkipRecord{
			Reason: SkipRetentionExcluded, URL: item.url.String(), Method: item.method,
			FoundAt: item.foundAt, Detail: "crawl-retention query: " + c.cfg.RetentionQuery,
		})
		rep.Fetches = append(rep.Fetches, fetch)
		return
	}

	page := parsePage(body, item.url, c.limits, c.cfg.RequestSpeculative)
	if c.cfg.NoSubresources {
		for tag := range subresourceTags {
			page.links = withoutTag(page.links, tag)
		}
	}
	if c.cfg.NoMetaRefresh {
		page.links = withoutTag(page.links, tagMetaRefresh)
	}
	if page.truncated {
		lim.record(StopParseBytes)
	}
	// The Refresh response header (q0qr), the header form of a meta refresh: a delayed redirect the
	// body never mentions.
	if msg != nil && !c.cfg.NoRefreshHeader {
		if target, ok := refreshTarget(string(msg.Header("Refresh"))); ok {
			page.links = append(page.links, discoveredLink{raw: target, tag: tagRefreshHeader})
		}
	}
	// A source map the page's scripts named (burpsy-react-ui-jwy5, criterion 2). Fetched through the
	// ordinary perform() path rather than from a side channel, so the request is scope-authorised,
	// rate-limited, captured and counted exactly like any other — which is what keeps the bead's
	// "passive: no requests beyond fetching a .map" true in a way an operator can check: the map
	// fetch appears in the fetch log like everything else this crawl sent.
	if page.sourceMap != "" {
		c.fetchSourceMap(ctx, page.sourceMap, item, rep, lim)
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
	// A 2xx page that matches its directory's answer for a missing name is that directory's custom
	// "not found" page, not a location (s92h): it is neither recorded as one nor walked.
	if fetch.Status >= 200 && fetch.Status <= 299 && c.isSoftNotFound(ctx, item, page, rep) {
		fetch.SoftNotFound = true
		rep.SoftNotFound++
		c.skips.record(SkipRecord{
			Reason: SkipSoftNotFound, URL: item.url.String(), Method: item.method,
			FoundAt: item.foundAt, Text: item.text,
			Detail: "matched what " + notFoundKey(item.url) + " answers for a nonexistent name",
		})
		rep.Fetches = append(rep.Fetches, fetch)
		return
	}
	c.recordStructuredLocation(page, item.url.String(), &fetch, rep)
	if !c.recordPhaseWalk(page, item.url.String()) {
		// Already walked in THIS crawl phase, exactly or within the tolerance band: the links here
		// are the links there, so descending again would spend budget re-walking a subtree already
		// covered. The duplicate was still counted above — the count is global; only the walk is
		// per-phase (burpsy-react-ui-crediso).
		rep.Fetches = append(rep.Fetches, fetch)
		return
	}

	staticTargets := make(map[string]bool, len(page.links))
	for _, l := range page.links {
		if u, err := resolveAgainst(item.url, l.raw); err == nil {
			staticTargets[u.String()] = true
		}
	}
	rep.LinksFound += len(page.links)
	rep.FormsFound += len(page.forms)
	for _, l := range page.links {
		c.admit(l, item.url, item.depth+1, rep, lim)
	}
	for _, f := range page.forms {
		c.admitForm(f, item.url, item.depth+1, rep, lim)
	}

	// The rendered second pass (burpsy-react-ui-nx7b): the DOM a browser builds for this
	// URL, read for links the wire markup never carried. An SPA's routes and a script-built
	// href exist only after the page's own script has run, so the static parse above cannot
	// see them no matter how well it parses — this is the whole reason Burp has a
	// browser-based navigation mode, and it is why the pass runs only for HTML and only
	// when the caller gave the crawler a browser.
	//
	// Ordering rules the shape of everything below:
	//
	//   - The rendered pass runs AFTER the static links were admitted, so a link present in
	//     both readings is discovered once, by the wire parse, and attributed to it.
	//   - The frontier gates apply unchanged: admit() is the same scope, destructive,
	//     depth and dedup machinery any other link goes through, so a rendered discovery
	//     gets no exemption and no second-class treatment.
	//   - Failures are SkipRenderUnavailable, never silent: the rendered view is the only
	//     place these links exist, so a render that did not happen narrows the coverage
	//     claim, and a narrowed claim the operator cannot see is the defect this ledger
	//     exists to prevent.
	// The outcome form when the caller supplied one, so a CAPPED render is reported as capped. The
	// plain form still works and still reports nothing about settling, because a caller that wired
	// only Render has not told this engine it cares (burpsy-react-ui-efra).
	render := c.cfg.Render
	var renderOutcome *RenderOutcome
	if c.cfg.RenderWithOutcome != nil {
		render = func(ctx context.Context, url string) (string, error) {
			html, outcome, err := c.cfg.RenderWithOutcome(ctx, url)
			renderOutcome = &outcome
			return html, err
		}
	}
	if render != nil {
		rendered, rerr := render(ctx, item.url.String())
		if rerr != nil {
			c.skips.record(SkipRecord{
				Reason: SkipRenderUnavailable, URL: item.url.String(), Method: item.method,
				FoundAt: item.foundAt,
				Detail:  "the rendered-DOM pass failed: " + rerr.Error(),
			})
		} else {
			// A render that hit its cap was read while the page was still changing. Its links are
			// still admitted -- they are real -- but the page is also recorded as capped, because
			// whatever it had not rendered yet is missing rather than absent, and a crawl that
			// presents a capped page as an empty one reports the application as smaller than it is.
			if renderOutcome != nil && renderOutcome.Capped {
				c.skips.record(SkipRecord{
					Reason: SkipRenderUnavailable, URL: item.url.String(), Method: item.method,
					FoundAt: item.foundAt,
					Detail: "the rendered-DOM pass reached its " +
						c.cfg.RenderOptions.withDefaults().MaxWait.String() +
						" cap while the page was still changing, so its links are incomplete",
				})
			}
			renderedPage := parsePage([]byte(rendered), item.url, c.limits, c.cfg.RequestSpeculative)
			for _, l := range renderedPage.links {
				if u, err := resolveAgainst(item.url, l.raw); err == nil {
					if staticTargets[u.String()] {
						continue
					}
				}
				// The edge names the rendering as the origin (nx7b's honesty rule): a reader
				// of the crawl paths must be able to tell that this link was invisible to
				// the wire bytes and only the browser found it. The rendered document is
				// tagged "rendered" and keeps the link's own text, so the edge reads the
				// same as any other in every other respect.
				l.foundAtRendered = true
				rep.LinksFound++
				c.admit(l, item.url, item.depth+1, rep, lim)
			}
			if renderOutcome != nil {
				c.admitRenderedRequests(renderOutcome.Requests, item, rep, lim)
			}
		}
	}
	// The interaction pass (burpsy-react-ui-spa1): drive the page in a browser — click its navigational
	// controls and, when the options say so, fill and submit its forms — so the routes a single-page
	// application reaches only through a click are discoverable at all. It runs AFTER the one-shot render,
	// so the controls it clicks are the ones a browser actually built rather than whatever the wire bytes
	// happened to carry.
	//
	// A failed pass is SkipInteractionUnavailable, its own reason and not SkipRenderUnavailable, because
	// the two narrow the coverage claim for different content: a failed render loses the script-built
	// routes, a failed interaction loses the routes behind a click.
	if c.cfg.Interact != nil {
		interaction, ierr := c.cfg.Interact(ctx, item.url.String(), c.cfg.InteractOptions)
		if ierr != nil {
			c.skips.record(SkipRecord{
				Reason: SkipInteractionUnavailable, URL: item.url.String(), Method: item.method,
				FoundAt: item.foundAt,
				Detail:  "the browser-interaction pass failed: " + ierr.Error(),
			})
		} else {
			c.admitInteraction(interaction, item, rep, lim)
		}
	}
	rep.Fetches = append(rep.Fetches, fetch)
}

// admitInteraction folds one browser-interaction pass into the crawl: each view's resulting page is
// parsed for links (discovered from a click, so the edge is tagged "clickable") and each same-origin
// GET the pass observed is admitted as an API location. It mirrors the rendered pass's honesty rules:
// a capped pass is recorded as capped, and an action that changed nothing is not a discovery.
func (c *Crawler) admitInteraction(inter Interaction, item frontierItem, rep *Report, lim *LimitReport) {
	rep.InteractionsRun++
	rep.InteractionClicks += inter.ClicksAttempted
	rep.InteractionFormsFound += inter.FormsFound
	rep.InteractionFormsSubmitted += inter.FormsSubmitted
	if inter.Capped {
		rep.InteractionsCapped++
		c.skips.record(SkipRecord{
			Reason: SkipInteractionUnavailable, URL: item.url.String(), Method: item.method,
			FoundAt: item.foundAt,
			Detail: "the interaction pass reached a bound (clicks, forms or time) while the page was " +
				"still yielding controls, so its discoveries are incomplete",
		})
	}
	for _, v := range inter.Views {
		if v.Error != "" || !v.Changed || v.DOM == "" {
			// Nothing was discovered: either the action could not be dispatched (Error), or it changed
			// nothing. Not a skip — an honest "this control led nowhere".
			continue
		}
		page := parsePage([]byte(v.DOM), item.url, c.limits, c.cfg.RequestSpeculative)
		for _, l := range page.links {
			// Tagged "clickable" rather than the element's own tag, so the edge kind says HOW the
			// location was found — behind a click — which is the fact a browser-less crawl would not
			// have at all. The element may be an anchor, but the anchor existed only in the DOM the
			// click produced.
			l.tag = "clickable"
			l.foundAtRendered = true
			rep.LinksFound++
			c.admit(l, item.url, item.depth+1, rep, lim)
		}
	}
	c.admitRenderedRequests(inter.Requests, item, rep, lim)
}

// admitRenderedRequests admits the requests a rendered page issued at run time (burpsy-react-ui-hzzl)
// — the API calls a single-page app makes, which no served byte and no rendered link names. Measured
// as the largest class of locations a headless crawler reached and burpsy did not (dvi7).
//
// Only SAME-ORIGIN GETs become discovered links, through admit()'s gates like any other link. A
// cross-origin request is a third party the page talks to (analytics, a CDN) — admitting it would fill
// the skip ledger with out-of-scope refusals; a non-GET is the page ACTING (a POST it made), and
// replaying it from a crawler would be acting rather than discovering. Both are counted, never sent.
func (c *Crawler) admitRenderedRequests(reqs []RenderedRequest, item frontierItem, rep *Report, lim *LimitReport) {
	for _, r := range reqs {
		u, err := url.Parse(r.URL)
		if err != nil || !strings.EqualFold(u.Scheme, item.url.Scheme) || !strings.EqualFold(u.Host, item.url.Host) {
			rep.RenderedRequestsOtherOrigin++
			continue
		}
		if m := strings.ToUpper(r.Method); m != "" && m != "GET" {
			rep.RenderedRequestsNotGET++
			continue
		}
		rep.RenderedRequestsAdmitted++
		c.admit(discoveredLink{raw: u.String(), tag: "rendered:xhr", foundAtRendered: true}, item.url, item.depth+1, rep, lim)
	}
}

// admitSeed puts one validated seed on the frontier. Seeds skip the destructive check (see
// destructive.go) and pass every other gate.
func (c *Crawler) admitSeed(u *url.URL, lim *LimitReport) {
	c.enqueue(frontierItem{url: u, method: "GET", depth: 0}, "", lim)
}

// admitSeedRequest puts one validated SeedRequest on the frontier. It goes through enqueue exactly as
// a seed does — same scope gate, same crawl-scope query, same rate limiters, same capture — and
// differs only in that it carries a method, a body and its own headers rather than being a URL.
// Skipping the destructive check is the same judgement admitSeed makes, for the same reason: this is
// the operator's own instruction, in this case one their API definition stated.
func (c *Crawler) admitSeedRequest(item frontierItem, lim *LimitReport) {
	c.enqueue(item, "", lim)
}

// wellKnownPaths are the RFC 8615 documents an application publishes about itself — a security
// contact, its OpenID / OAuth metadata (which names its endpoints), a password-change URL, the app-link
// association files, a CSAF advisory index. Measured as a class a known-files crawler reached and
// burpsy never requested (the dvi7 benchmark).
var wellKnownPaths = []string{
	"/.well-known/security.txt",
	"/.well-known/openid-configuration",
	"/.well-known/oauth-authorization-server",
	"/.well-known/change-password",
	"/.well-known/apple-app-site-association",
	"/.well-known/assetlinks.json",
	"/.well-known/csaf/provider-metadata.json",
}

// admitWellKnown admits the .well-known documents for a seed's authority, once per authority, as
// discovered links through admit() — scope, the destructive gate, dedup and the phase tally apply
// exactly as to any link, so an authority the scope excludes is not asked for them either.
func (c *Crawler) admitWellKnown(seed *url.URL, rep *Report, lim *LimitReport) {
	key := strings.ToLower(seed.Scheme) + "://" + strings.ToLower(seed.Hostname()) + ":" + strconv.Itoa(int(portOf(seed)))
	if c.wellKnownSeeded[key] {
		return
	}
	if c.wellKnownSeeded == nil {
		c.wellKnownSeeded = map[string]bool{}
	}
	c.wellKnownSeeded[key] = true
	root := &url.URL{Scheme: seed.Scheme, Host: seed.Host, Path: "/"}
	for _, p := range wellKnownPaths {
		c.admit(discoveredLink{raw: p, tag: "well-known"}, root, 1, rep, lim)
	}
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

// consumeSitemap reads one sitemap document and admits what it names.
//
// Every <loc> enters as a DISCOVERED LINK rather than a seed, for the same reason robots.txt paths
// do: a target-supplied URL passes the destructive-action check, the scope gate and the crawl-scope
// query like anything else the response contained. A sitemap naming /admin/purge-all must not
// become a privileged request just because the target wrote it down.
//
// A <sitemapindex> entry is re-admitted as a sitemap to fetch — depth-limited like any other link —
// because its <loc>s are sitemaps rather than pages, and following only the index would find every
// one of them empty.
func (c *Crawler) consumeSitemap(item frontierItem, contentType string, body []byte, fetch *Fetch, rep *Report, lim *LimitReport) {
	entries, _, failure := ParseSitemap(body)
	if failure != "" {
		// A parse failure is REPORTED, not folded into "0 locations". A gzipped sitemap, a truncated
		// fetch and a document that was never a sitemap are three different facts, and an operator
		// seeing "0 locations" has no way to tell which they are looking at.
		c.skips.record(SkipRecord{
			Reason: SkipSitemapUnparsed, URL: item.url.String(), Method: item.method,
			FoundAt: item.foundAt, Detail: failure,
		})
		return
	}
	rep.SitemapsParsed++
	fetch.Fingerprint = rawBodyFingerprint(contentType, body)
	c.recordLocation(fetch.Fingerprint, item.url.String(), fetch, rep)

	for _, e := range entries {
		rep.SitemapLocationsFound++
		if e.IsIndex {
			rep.SitemapIndexesFollowed++
		}
		c.admit(discoveredLink{raw: e.Loc, tag: "sitemap", text: e.LastMod}, item.url, item.depth+1, rep, lim)
	}
}

// consumeJavaScript reads one script for locations and admits them (burpsy-react-ui-jwy5). See
// jsextract.go for the two extractors and why their union is taken.
//
// Passive in the sense the bead asks for: reading the script sends nothing. The one request this
// function can cause itself is the script's own source map, through fetchSourceMap — the same path an
// inline script's map already takes — and every location it admits goes through admit()'s gates like
// any link.
func (c *Crawler) consumeJavaScript(ctx context.Context, item frontierItem, contentType string, body []byte, fetch *Fetch, rep *Report, lim *LimitReport) {
	fetch.Fingerprint = rawBodyFingerprint(contentType, body)
	c.recordLocation(fetch.Fingerprint, item.url.String(), fetch, rep)
	rep.JavaScriptRead++

	parse := body
	if max := c.limits.MaxParseBytes; max > 0 && len(parse) > max {
		// Bounded like every other parse: a 40 MB vendor bundle is read up to the cap and the report
		// says so, rather than the crawl stalling on one file.
		parse = parse[:max]
		rep.JavaScriptTruncated++
	}
	cands, parseFailed := extractJavaScript(parse)
	if parseFailed {
		rep.JavaScriptParseFailures++
	}
	for _, cand := range cands {
		rep.JavaScriptLocationsFound++
		c.admit(discoveredLink{raw: cand.raw, tag: cand.tag, text: cand.note}, item.url, item.depth+1, rep, lim)
	}

	// The script's own source map, resolved against the script — the map is the bundle's original file
	// list, and an external bundle's map was never followed before because external bundles were never
	// read.
	if ref := sourceMapReference(string(body)); ref != "" {
		if mapURL, err := resolveAgainst(item.url, ref); err == nil {
			c.fetchSourceMap(ctx, mapURL.String(), item, rep, lim)
		}
	}
}

// consumeJSON reads one JSON document and admits the locations it names.
//
// Every location enters as a DISCOVERED LINK rather than a seed, going through the same gates a
// sitemap's <loc> does — destructiveness, scope, the crawl-scope query, depth, dedup, capacity —
// because a URL a target published is exactly as untrusted as one it linked from a page. A JSON
// body naming /admin/purge-all must not become a privileged request because the API documented it.
//
// A document that parses but names nothing records NO skip: SkipNotHTML used to fire for it and
// told an operator nothing true, since the response was read and simply had no locations in it.
// A document that fails to parse records SkipJSONUnparsed, whose remedy is different from
// "this is not HTML" (burpsy-react-ui-mz1n).
func (c *Crawler) consumeJSON(item frontierItem, contentType string, body []byte, fetch *Fetch, rep *Report, lim *LimitReport) {
	locs, failure := ParseJSONLocations(body)
	if failure != "" {
		// Only a body that CLAIMED to be JSON and then failed gets the distinct reason. A
		// response whose content type is JSON but whose body is HTML at an /api path is a
		// target quirk, and reporting it as a parse failure would be noise; the branch only
		// runs when LooksLikeJSON already said the body announces itself as one, so a failure
		// here is real.
		c.skips.record(SkipRecord{
			Reason: SkipJSONUnparsed, URL: item.url.String(), Method: item.method,
			FoundAt: item.foundAt, Detail: failure,
		})
		rep.JSONDocumentsRead++
		return
	}
	rep.JSONDocumentsRead++
	fetch.Fingerprint = rawBodyFingerprint(contentType, body)
	c.recordLocation(fetch.Fingerprint, item.url.String(), fetch, rep)
	for _, loc := range locs {
		rep.JSONLocationsFound++
		c.admit(discoveredLink{raw: loc.Raw, tag: "json:" + loc.Key}, item.url, item.depth+1, rep, lim)
	}
}

// consumeAPIDocument reads an API definition and admits the endpoints it declares, reporting whether
// it consumed this response.
//
// The bool is "this was a definition and I handled it", so the caller returns rather than falling
// through to the JSON or HTML gates. A body that is NOT a definition returns false and is left
// entirely alone — which is the overwhelming majority of what a crawl fetches, and it must reach the
// gates below untouched.
//
// Every endpoint enters as a DISCOVERED LINK, through the same admit() gates a page's href goes
// through, for the reason consumeJSON argues and it is worth repeating because it is the whole safety
// argument: a URL a target published is exactly as untrusted as one it linked from a page. A JSON
// body naming /admin/purge-all must not become a privileged request because the API documented it, and
// the destructiveness gate runs before scope so a documented logout reports as the logout it is.
//
// The path is the document's own template, and it is resolved against the URL the document was
// FETCHED FROM rather than a base declared inside it. A definition that says `servers: [{url:
// https://elsewhere.test}]` is a claim about another host; following it would take the crawl off the
// target the operator scoped, and admit() is where scope is decided.
func (c *Crawler) consumeAPIDocument(item frontierItem, contentType string, body []byte, fetch *Fetch, rep *Report, lim *LimitReport) bool {
	if LooksLikeWSDL(contentType, body) && !c.cfg.ParseSOAPWSDLs {
		// The document IS a WSDL and the operator's configuration turned the WSDL reader off.
		// Falling through is the honest reading: the body is XML, so the JSON gate will not claim it
		// and it records SkipNotHTML like any other document this crawl cannot read. Recording a
		// skip reason here would imply the reader tried and failed, when it was switched off.
		return false
	}
	if !LooksLikeWSDL(contentType, body) && !c.cfg.ParseAPIDefinitions {
		return false
	}

	format, eps, failure := ParseAPIDocument(contentType, item.url.Path, body)
	if format == APIDocNone {
		return false
	}
	if format == APIDocGraphQLIntrospection && c.graphqlAnswer != nil {
		// One admission owner per body (burpsy-react-ui-4xqt.1 pre-review): an armed live
		// introspection reader already judges EVERY response that carries a __schema result,
		// this one included, so reading it here too would admit and count every operation
		// twice - and the count increments before enqueue dedup, which cannot hide it. The
		// document path owns a GraphQL result only when no live reader is armed to claim it.
		return false
	}
	rep.APIDocumentsRead++
	if format == APIDocWSDL {
		// Burp names WSDL failures apart from API-definition failures (ai64), and a WSDL that broke
		// mid-document still names the operations read before the break, which are crawled below.
		switch {
		case failure != "":
			c.skips.record(SkipRecord{
				Reason: SkipWSDLInvalid, URL: item.url.String(), Method: item.method,
				FoundAt: item.foundAt, Detail: failure,
			})
		case len(eps) == 0:
			c.skips.record(SkipRecord{
				Reason: SkipWSDLNoOperations, URL: item.url.String(), Method: item.method,
				FoundAt: item.foundAt, Detail: "no wsdl:operation was declared",
			})
		}
		failure = ""
	}
	if failure != "" {
		// The acceptance criterion, and the reason this is a distinct skip: the target PUBLISHED an
		// API definition and the crawl still cannot see it. Reporting zero endpoints here would tell
		// the operator their target has no API, which is the failure this whole change exists to
		// remove.
		c.skips.record(SkipRecord{
			Reason: SkipAPIUnparsed, URL: item.url.String(), Method: item.method,
			FoundAt: item.foundAt, Detail: string(format) + ": " + failure,
		})
		return true
	}

	fetch.Fingerprint = rawBodyFingerprint(contentType, body)
	c.recordLocation(fetch.Fingerprint, item.url.String(), fetch, rep)
	if format == APIDocGraphQLIntrospection || format == APIDocGraphQLSDL {
		// A GraphQL operation has no path of its own, so the document's own URL is re-fed to
		// the ordinary GET admission once per operation - the crawl will GET the endpoint the
		// document came from as each operation's location (admitGraphQLOperations), tagged
		// and counted as GraphQL endpoints, exactly as a live introspection answer's
		// operations are. A schema document needs no dual-reader guard: the armed live
		// reader judges introspection results only, so a body claimed by the exclusion above
		// can never reach this branch as SDL.
		c.admitGraphQLOperations(item.url, eps, rep, lim)
		return true
	}
	for _, ep := range eps {
		rep.APIEndpointsFound++
		c.admit(discoveredLink{raw: apiEndpointPath(ep), text: ep.OperationID, tag: "api:" + string(format)},
			item.url, item.depth+1, rep, lim)
	}
	return true
}

// apiEndpointPath is the path one declared operation is requested at.
//
// A templated path keeps its braces here: admit() resolves the reference, and the fetch that follows
// fills the parameters. Substituting a placeholder value at this point would be inventing data the
// document never declared, and the crawl's fingerprinting would then treat every such URL as one
// location — which is true, and less useful than the template that says which segment is a parameter.
//
// A WSDL operation carries no path at all (it lives in the port's <soap:address>), so it yields the
// document's own URL rather than an empty one, which would resolve to the current page and re-fetch
// what has already been fetched.
func apiEndpointPath(ep APIDocEndpoint) string {
	if strings.TrimSpace(ep.Path) != "" {
		return ep.Path
	}
	return ""
}

// ---- GraphQL discovery (burpsy-react-ui-bwwg, criterion 4) ----------------------------------

// commonGraphQLPaths are the paths Burp's "Test common GraphQL endpoints" button probes
// (Zrf0.java:3629).
//
// They are a GUESS, not an observation, which is exactly what guess_hidden_graphql_endpoints says —
// and why Burp ships that switch OFF in its own defaults and this implementation honours that. Each
// is resolved against a host the crawl is ALREADY sending to, so a guess can never introduce an origin
// the operator did not scope.
var commonGraphQLPaths = []string{"/graphql", "/api/graphql", "/gql", "/query"}

// armGraphQL installs the introspection reader when the operator's configuration asks for it.
//
// Armed in New rather than checked at each use, so there is exactly one place that decides whether the
// crawl will send a POST of its own. Every reader here refuses by default — a crawl that sends traffic
// nobody asked for is the failure mode this package is built to avoid — and these two switches are the
// only ones that make it send on its own initiative.
func (c *Crawler) armGraphQL() {
	if c.cfg.PerformGraphQLIntrospection {
		c.graphqlAnswer = func(u *url.URL, body []byte) []APIDocEndpoint {
			if !LooksLikeGraphQLAnswer(body) {
				// Not a GraphQL answer. Not a failure and not a skip: this is the ordinary answer for
				// every POST the crawl makes against an endpoint that is not GraphQL, and recording a
				// refusal here would fill the ledger with noise that buries the real one.
				return nil
			}
			ops, failure := ParseGraphQLOperations(body)
			if failure != "" {
				// The endpoint IS GraphQL and the answer could not be read. Distinct from the case
				// above in the only way that matters to an operator: this one is worth a look.
				c.skips.record(SkipRecord{
					Reason: SkipGraphQLUnparsed, URL: u.String(), Method: "POST", Detail: failure,
				})
				return nil
			}
			return ops
		}
	}
	if c.cfg.GuessHiddenGraphQLEndpoints {
		c.guessHiddenGraphQL = true
	}
}

// pastDuration reports whether the crawl's wall-clock limit has already passed, for the requests
// a visit triggers from INSIDE the visit (burpsy-react-ui-u4mm). The main loop checks MaxDuration
// between visits; a visit that ends after the limit has passed must not be followed by requests of
// its own — a probe or introspection sent then is traffic after the operator's time limit, under a
// report that claims the limit was in force.
func (c *Crawler) pastDuration() bool {
	return !c.startedAt.IsZero() && time.Since(c.startedAt) >= c.limits.MaxDuration
}

// introspect sends one introspection query to a URL the crawl has established is a GraphQL endpoint.
//
// Straight to perform, for the reason guessGraphQL gives: this is a request, so it is scope-authorised,
// rate limited, captured and counted by the same path every other crawl request takes. A separate send
// would be traffic the crawl's own report does not mention.
func (c *Crawler) introspect(ctx context.Context, u *url.URL, rep *Report, lim *LimitReport) {
	// rep.Fetched, NOT lim.Requests: lim.Requests is assigned once from rep.Fetched AFTER the loop
	// finishes, so for the whole crawl it reads zero and a bound checked against it is no bound at
	// all. Reading the live counter is the difference between a stated request limit and one that
	// only appears to hold.
	if c.pastDuration() {
		c.skips.record(SkipRecord{
			Reason: SkipGraphQLIntrospection, URL: u.String(), Method: "POST",
			Detail: "the crawl's time limit has passed, so the endpoint was not introspected",
		})
		return
	}
	if rep.Fetched >= c.limits.MaxRequests {
		c.skips.record(SkipRecord{
			Reason: SkipGraphQLIntrospection, URL: u.String(), Method: "POST",
			Detail: "the crawl-wide request bound is spent, so the endpoint was not introspected",
		})
		return
	}
	item := frontierItem{url: u, method: "POST", foundAt: u.String(),
		body: graphqlIntrospectionBody(), contentType: "application/json"}
	c.perform(ctx, item, c.buildRequest(item), rep, lim)
}

// guessGraphQL probes the common GraphQL paths on one origin, once each.
//
// Behind its own switch, which Burp ships off. Same-origin only: the paths hang off the URL the crawl
// is already on, so a guess cannot reach a host the operator did not scope. Each probe goes through
// perform() like every other request, so it is scope-authorised, rate limited, captured and counted —
// and an introspection query that scope refuses is recorded as SkipSendRefused rather than sent.
func (c *Crawler) guessGraphQL(ctx context.Context, u *url.URL, rep *Report, lim *LimitReport) {
	if !c.guessHiddenGraphQL {
		return
	}
	base := *u
	base.Path, base.RawQuery, base.Fragment = "/", "", ""
	for _, path := range commonGraphQLPaths {
		probe := base
		probe.Path = path
		if c.guessedGraphQL[probe.String()] {
			continue
		}
		// The duration bound first (burpsy-react-ui-u4mm): it is checked per probe, not only per
		// visit, so a probe pass that starts inside the limit still stops the moment it runs out —
		// up to four requests used to go out after it.
		if c.pastDuration() {
			c.skips.record(SkipRecord{
				Reason: SkipGraphQLIntrospection, URL: probe.String(), Method: "POST",
				Detail: "the crawl's time limit has passed, so the GraphQL probe was not sent",
			})
			return
		}
		// The bound is checked BEFORE the request goes out, not after: an operator reading the request
		// count must never see a number that omits what was actually sent. rep.Fetched, not
		// lim.Requests — see introspect for why the latter reads zero throughout the crawl.
		if rep.Fetched >= c.limits.MaxRequests {
			c.skips.record(SkipRecord{
				Reason: SkipGraphQLIntrospection, URL: probe.String(), Method: "POST",
				Detail: "the crawl-wide request bound is spent, so the GraphQL probe was not sent",
			})
			return
		}
		c.guessedGraphQL[probe.String()] = true
		item := frontierItem{url: &probe, method: "POST", foundAt: u.String(),
			body: graphqlIntrospectionBody(), contentType: "application/json"}
		// Straight to perform, NOT through visit/enqueue: a guessed path must not be depth-counted or
		// admitted as a location before the answer says there is anything there. perform is where the
		// send, the scope gate and the capture happen, which is all a probe needs.
		c.perform(ctx, item, c.buildRequest(item), rep, lim)
	}
}

// admitGraphQLOperations puts the operations an introspection answer named on the frontier.
//
// Every operation goes to the ENDPOINT the answer came from, not to a path from the schema: a GraphQL
// operation is a field on the endpoint's own type, so they all share one URL and differ only in the
// query they send. Admitting the endpoint is what makes the crawl fetch it, and the operation name
// travels as the item's text so a report says which field was found.
func (c *Crawler) admitGraphQLOperations(u *url.URL, ops []APIDocEndpoint, rep *Report, lim *LimitReport) {
	rep.GraphQLEndpointsFound += len(ops)
	for _, op := range ops {
		c.admit(discoveredLink{raw: u.RequestURI(), text: op.OperationID, tag: "graphql:" + op.OperationID},
			u, 0, rep, lim)
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

// countPhase adds one to a phase's tally on the report.
//
// The map is created with every phase at zero rather than lazily on first use, so the report always
// carries the full legend. A reader showing "0 rendered" has been told the crawl never got there; a
// reader with no "rendered" key at all can only guess.
func (c *Crawler) countPhase(rep *Report, phase CrawlPhase) {
	if rep.Phases == nil {
		rep.Phases = make(map[CrawlPhase]int, len(CrawlPhaseAll)+1)
		for _, p := range CrawlPhaseAll {
			rep.Phases[p] = 0
		}
		rep.Phases[PhaseNone] = 0
	}
	rep.Phases[phase]++
}

// countEdge counts one discovered edge by kind (ylr1), seeding every kind at zero on first use.
func (c *Crawler) countEdge(rep *Report, kind string) {
	seedEdgeKinds(rep)
	rep.EdgeKinds[kind]++
}

// seedEdgeKinds puts every kind in EdgeKindsAll on the report at zero, once.
func seedEdgeKinds(rep *Report) {
	if rep.EdgeKinds != nil {
		return
	}
	rep.EdgeKinds = make(map[string]int, len(EdgeKindsAll)+1)
	for _, k := range EdgeKindsAll {
		rep.EdgeKinds[k] = 0
	}
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
	// Counted FIRST, before any gate can refuse. A link the crawl then declines is still something it
	// discovered and attributed: counting only what was fetched would make the tallies describe egress
	// rather than discovery, and an operator asking "did this crawl ever reach the sitemap" would be
	// answered by a number that says no when the answer is yes.
	c.countPhase(rep, PhaseOfTag(l.tag))
	c.countEdge(rep, EdgeKindOfTag(l.tag))
	// The routing-fragment decision (burpsy-react-ui-wbqx): a hash-routed SPA's location lives in
	// the fragment, so it is captured here as identity while `u` stays fragment-less and safe to
	// send. Burp's automatic half is always on — see fragmentIsRouting — and Config.FragmentsRoute
	// forces it for an application the character test misses.
	u, fragment, err := resolveAgainstRoute(base, l.raw, c.cfg.FragmentsRoute)
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
	c.enqueue(frontierItem{url: u, method: "GET", depth: depth, foundAt: base.String(), text: l.text, tag: l.tag, renderedOrigin: l.foundAtRendered, speculative: l.speculative, fragment: fragment}, base.String(), lim)
}

// admitForm turns one discovered form into a request, or records why it did not.
//
// CRAWL-03 lives at the top of this function: with submission off, every form is counted as
// discovered-and-not-submitted and nothing is built. A GET form is included in that, deliberately —
// a GET form is still a form the application meant a user to fill in, and the operator's decision
// was about forms, not about methods.
func (c *Crawler) admitForm(f discoveredForm, base *url.URL, depth int, rep *Report, lim *LimitReport) {
	c.countEdge(rep, "form")
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

	// The per-form cap (burpsy-react-ui-u0k3), checked here — after the enabled check, because a
	// crawl with submission off has submitted nothing and its count is meaningless, and before the
	// per-form shape checks, because a form that could not be submitted anyway should report THAT
	// rather than a cap it never reached.
	//
	// Counted against the form's SIGNATURE rather than its URL: a search box on every page of a site is
	// ONE form submitted N times, and a per-URL count would bound nothing on exactly the page that
	// needs the bound.
	if cap := c.limits.MaxSubmissionsPerForm; cap > 0 {
		sig := f.signature(base)
		if c.formSubmissions[sig] >= cap {
			c.skips.record(SkipRecord{
				Reason: SkipFormSubmissionCap, URL: target, Method: f.method, Text: f.label,
				FoundAt: base.String(),
				Detail: fmt.Sprintf("this form has already been submitted %d times, the configured cap "+
					"(max_submissions_per_form); raise it to explore further", c.formSubmissions[sig]),
			})
			return
		}
	}

	// The optimization threshold (burpsy-react-ui-ddln), checked on the DESTINATION the submission is
	// about to reach rather than on a submission count. Burp's own name for the setting is the length
	// of the form's input-strategy chain at which further strategies are discontinued, so the budget is
	// spent by reaching a new destination and not by repeating one — a repeat of a destination already
	// in the set is bounded by MaxSubmissionsPerForm above, and charging it here as well would make the
	// threshold fire before its number says.
	//
	// Checked after the per-form cap and before the shape checks, so a form this threshold has
	// exhausted is reported as exhausted rather than as unsubmittable. The destination key is computed
	// from the request the crawler would actually send — the resolved action plus the encoded field
	// values, GET query or POST body — because two forms with the same signature that submit to
	// different actions are, for this bound, two different destinations.
	if threshold := c.cfg.FormSubmissionOptimizationThreshold; threshold > 0 {
		sig := f.signature(base)
		if len(c.formDestinations[sig]) >= threshold {
			c.skips.record(SkipRecord{
				Reason: SkipFormDestinationExhausted, URL: target, Method: f.method, Text: f.label,
				FoundAt: base.String(),
				Detail: fmt.Sprintf("this form has been submitted to %d distinct destinations, the configured "+
					"optimization threshold (form_submission_optimization_threshold); raise it to explore "+
					"further", len(c.formDestinations[sig])),
			})
			return
		}
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
	//
	// Placed before the credential branches below, so it gates EVERY submission kind: the
	// ordinary placeholder submission and the credential, registration and invalid-username
	// ones alike. The credential mapping swaps only the username/password VALUES; the signals
	// this check reads — the action and the field names and hidden values — are identical in
	// all of them, so one check here is the check for every kind, and a login form whose intent
	// is destructive is refused even with credentials configured.
	if v := classifyDestructive(u.String()+" "+encoded, f.label); v.Refused {
		c.skips.record(SkipRecord{
			Reason: v.Reason, URL: u.String(), Method: f.method, Text: f.label,
			Signal: v.Signal, FoundAt: base.String(),
		})
		return
	}

	// A registration form (Burp's distinguishing rule: the password-carrying form with the most
	// password fields — two or more in practice) gets a generated account when the operator opted
	// in, never a provided credential: credentials belong to login forms. Self-registration is an
	// unauthenticated-phase act, as Burp runs it.
	if len(f.passwordFields) >= 2 && c.cfg.AttemptSelfRegister && !c.cfg.AuthenticatedCrawlOnly && c.credPhase == 0 {
		c.admitSelfRegistration(f, base, u, depth, rep, lim)
		return
	}
	// A login form with credentials configured is not submitted on discovery: it is RECORDED, and
	// each credential phase's first act is the login (burpsy-react-ui-crediso — Burp discovers
	// login functions in the unauthenticated phase, then logs in per credential). The
	// invalid-username probe (Burp's trigger_login_failures) is an unauthenticated-phase act too.
	// crawl_using_provided_logins_only (AuthenticatedCrawlOnly) takes authentication from the
	// provided credentials alone: no self-registration above, no invalid usernames here.
	if f.isLoginForm && len(f.passwordFields) < 2 {
		handled := false
		if len(c.cfg.LoginCredentials) > 0 {
			if f.method == "GET" {
				// A GET submission puts the form data set in the URL, and the URL is in every
				// log, history row and Referer the request ever touches. Credentials do not go
				// in URLs.
				c.skips.record(SkipRecord{
					Reason: SkipFormNotSubmittable, URL: u.String(), Method: f.method, Text: f.label,
					FoundAt: base.String(),
					Detail:  "a login form that submits GET would place the credentials in the URL; not submitted",
				})
			} else {
				c.recordLoginForm(f, base, u, depth)
			}
			handled = true
		}
		if c.cfg.UseInvalidUsernames && !c.cfg.AuthenticatedCrawlOnly && c.credPhase == 0 {
			c.admitInvalidUsernameLogin(f, base, u, depth, rep, lim)
			handled = true
		}
		if handled {
			return
		}
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
		// Counted here, on the SUCCESS path, so the cap counts submissions MADE rather than forms
		// CONSIDERED. Counting earlier would let a refused form consume budget and fire the cap on a
		// form that was never sent — which is the more confusing failure of the two.
		if cap := c.limits.MaxSubmissionsPerForm; cap > 0 {
			c.formSubmissions[f.signature(base)]++
		}
		// The destination is recorded on the same success path and for the same reason: a form that
		// was refused by a later gate was never submitted anywhere, and charging its destination to the
		// optimization threshold would spend the budget on a request that did not go out.
		//
		// Keyed on what actually goes on the wire — the method, the URL the request will reach (query
		// string included for a GET submission) and the body for a POST — so a form whose field values
		// change which resource it targets is submitting to a NEW destination, which is exactly the
		// signal this bound exists to read.
		if threshold := c.cfg.FormSubmissionOptimizationThreshold; threshold > 0 {
			sig := f.signature(base)
			set := c.formDestinations[sig]
			if set == nil {
				set = make(map[string]struct{})
				c.formDestinations[sig] = set
			}
			set[item.method+" "+item.url.String()+" "+string(item.body)] = struct{}{}
		}
	}
}

// dedupKey namespaces the frontier seen-set by the crawl phase (burpsy-react-ui-crediso): a
// request the unauthenticated phase made is MADE AGAIN in each credential phase, with that
// phase's session — an authenticated view is different content, and sharing the seen-set across
// phases would suppress exactly the fetches the phases exist for.
func (c *Crawler) dedupKey(method string, u *url.URL, body []byte, fragment string) string {
	return strconv.Itoa(c.credPhase) + "|" + requestFingerprint(method, u, body, fragment)
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
		// Two refusals that look identical in one number, told apart by WHAT the link was (its
		// tag): a subresource the page loads to work at all, versus a navigational link a person
		// would follow. The second is scope doing its job; the first is where burpsy is stricter
		// than Burp, whose crawler fetches out-of-scope resources by default
		// (allow_out_of_scope_resources = true in Preferences/CrawlDefaults.json). An operator
		// looking at "why is my crawl empty" needs those answered separately, because on a modern
		// site — fonts, a CDN-hosted app shell, a third-party API — the second is the whole
		// explanation and the first says nothing (burpsy-react-ui-hgor).
		//
		// The refusal itself is unchanged. This records WHICH refusal happened, which is all the
		// bead asks for: nothing here relaxes the chokepoint.
		reason := SkipOutOfScope
		switch {
		case hasTagPrefix(item.tag, "api:"):
			reason = SkipAPILocationOutOfScope
		case item.tag == "redirect" && item.depth == 1:
			// A redirect admitted at depth 1 came from a depth-0 item, and only seeds are depth 0.
			reason = SkipSeedRedirectedOutOfScope
		}
		if reason == SkipOutOfScope && isResourceTag(item.tag) {
			reason = SkipOutOfScopeResource
			// Counted on the LIMITS rather than only in the ledger, because the caveat a complete
			// crawl prints is built from the limits and would otherwise never mention it.
			lim.OutOfScopeResources++
		}
		c.skips.record(SkipRecord{
			Reason: reason, URL: item.url.String(), Method: item.method,
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
	// The owning phase is the one that admits the item: phases are sequential and the frontier
	// drains before the next begins, so the admission-time phase IS the phase the item executes
	// in — and the phase a transport-failure retry must stay within (burpsy-react-ui-crediso).
	item.phase = c.credPhase
	key := c.dedupKey(item.method, item.url, item.body, item.fragment)
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
	template := strconv.Itoa(c.credPhase) + "|" + urlTemplate(item.method, item.url, item.fieldNames, item.fragment)
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
	// The speculative-hidden-link cap (burpsy-react-ui-t5m0), checked LAST: every other
	// gate has passed, so what is counted is what the crawl will follow, not what it saw.
	// The link is admitted through the same frontier as a navigational one — the cap is
	// the only thing that distinguishes how many.
	if item.speculative && c.speculativeAdmitted >= c.limits.MaxSpeculativeLinks {
		lim.record(StopSpeculativeLinks)
		lim.SpeculativeDropped++
		c.skips.record(SkipRecord{
			Reason: SkipSpeculativeLimit, URL: item.url.String(), Method: item.method,
			Text: item.text, FoundAt: foundAt,
			Detail: fmt.Sprintf("the speculative-link bound of %d is spent", c.limits.MaxSpeculativeLinks),
		})
		return false
	}
	c.queued[key] = true
	if item.speculative {
		c.speculativeAdmitted++
	}
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
// Mime, Body, ResponseLen and DurationUs report absent, because before the fetch there is no
// response — and New has already refused any query that names them, so no comparison ever reaches
// them (unavailablePreFetch derives its answer from the field list, so a field added to the grammar
// defaults to unavailable). They are implemented as absent rather than left to panic because
// query.Queryable requires all of them, and because a caller constructing this type directly should
// get the documented "absent fields are absent" behaviour rather than a crash.
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

// Both absent, not zero: there is no response to have a size, and nothing has been timed.
func (r frontierRow) ResponseLen() (int64, bool) { return 0, false }
func (r frontierRow) DurationUs() (int64, bool)  { return 0, false }

// No response, so no headers. New refuses any query naming this field before the fetch.
func (r frontierRow) Header(string) ([]string, bool) { return nil, false }

// known=false, not empty strings: the crawler is deciding whether to fetch a URL, so there is no
// exchange to have been annotated, and reporting "" would tell a query that every frontier URL is
// unhighlighted and uncommented — a claim rather than an absence.
func (r frontierRow) Annotation() (string, string, bool) { return "", "", false }

// See fetchedRow.TaskID: a frontier candidate has no run attribution to answer with.
func (r frontierRow) TaskID() (uint64, bool) { return 0, false }

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
	// resp is the stored response, carried so Header can answer from the real head rather than
	// reporting every header absent. Without it the retention gate would evaluate
	// `header["set-cookie"] ~ "x"` as false for every response, which is a verdict about the target
	// rather than an admission that this type could not see its headers.
	resp *core.StoredMessage
}

func (r fetchedRow) Host() string   { return r.host }
func (r fetchedRow) Method() string { return r.method }
func (r fetchedRow) Path() string   { return r.path }
func (r fetchedRow) Status() int    { return r.status }
func (r fetchedRow) Mime() string   { return r.mime }
func (r fetchedRow) Body() []byte   { return r.body }

// ResponseLen is present because the response is: this type exists only after a fetch. len(body) is
// the honest answer even when the body is empty — a 204 is a zero-length response, not an absent one,
// which is the distinction the bool carries.
func (r fetchedRow) ResponseLen() (int64, bool) { return int64(len(r.body)), true }

// DurationUs is UNMEASURED. The crawler does not time its fetches at this layer, and reporting 0
// would tell an operator every crawled response arrived instantaneously — a measurement nobody made.
// If crawl timing is wanted, thread it onto this struct; returning false is what keeps the absence
// visible until then.
func (r fetchedRow) DurationUs() (int64, bool) { return 0, false }

// Header reads the stored response head. Absent when there is no stored response to read, which is
// distinct from a header that is genuinely not there — and both fail every comparison, so a caller
// cannot tell them apart from the verdict alone. That is acceptable here and stated rather than
// hidden: this type only exists after a successful fetch, so resp being nil means the read-back
// failed, and that path already recorded a SkipResponseUnreadable.
// known=false for the same reason as frontierRow: the retention gate runs immediately after the
// fetch, before an operator has seen the row, so an annotation cannot exist yet. A later re-scan
// through a different consumer can answer it.
func (r fetchedRow) Annotation() (string, string, bool) { return "", "", false }

// No run attribution: fetchedRow and frontierRow are per-fetch candidates, and the crawl's own
// task id is not a fact about a candidate — it is a fact about the crawl that will decide on it.
// (0, false): every task comparison fails, the same as the annotation ones.
func (r fetchedRow) TaskID() (uint64, bool) { return 0, false }

func (r fetchedRow) Header(name string) ([]string, bool) {
	if r.resp == nil {
		return nil, false
	}
	raw, present := r.resp.HeaderValues(name)
	if !present {
		return nil, false
	}
	out := make([]string, 0, len(raw))
	for _, value := range raw {
		out = append(out, string(value))
	}
	return out, true
}

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
	// The recorded login's session, by the jar's own RFC 6265 matching (burpsy-react-ui-xhtk). It
	// replaces an operator Cookie header rather than joining it: the replay just logged in, and a
	// static cookie from before it is the session the login exists to supersede.
	loginCookie := c.login.cookieFor(item.url)
	if loginCookie != "" {
		c.login.report.RequestsWithSession++
	}
	if len(c.cfg.Headers) > 0 {
		if c.credentialOrigins[originKey(item.url)] {
			for name, value := range c.cfg.Headers {
				if loginCookie != "" && strings.EqualFold(name, "Cookie") {
					continue
				}
				b.WriteString(name)
				b.WriteString(": ")
				b.WriteString(value)
				b.WriteString("\r\n")
			}
		} else {
			c.headersWithheld++
		}
	}
	// This request's own headers, which only a seeds-only run sets — an API definition's declared
	// header parameters. Sorted, because Go's map order is random and two scans of one definition
	// must produce byte-identical requests: a request whose headers swap places between runs looks
	// like the definition changed. validateHeader has already refused CR, LF, a colon in a name and
	// every framing header, so this loop writes nothing that could split the request.
	for _, name := range sortedHeaderNames(item.headers) {
		b.WriteString(name)
		b.WriteString(": ")
		b.WriteString(item.headers[name])
		b.WriteString("\r\n")
	}
	if loginCookie != "" {
		b.WriteString("Cookie: ")
		b.WriteString(loginCookie)
		b.WriteString("\r\n")
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

// sortedHeaderNames orders one request's headers. See buildRequest for why the order is fixed rather
// than incidental.
func sortedHeaderNames(headers map[string]string) []string {
	out := make([]string, 0, len(headers))
	for name := range headers {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
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

// isResourceTag reports whether a discovered link was a SUBRESOURCE — something the page EMBEDS to
// work at all — rather than a navigational link a person would follow.
//
// The set is only the elements discover.go actually queues. `img`, `script`, `link`, `source`,
// `video` and `audio` are NOT in it because the crawler never discovers them at all (discover.go:24),
// so no out-of-scope refusal can ever carry one of those tags — naming them here would be a classifier
// with no reachable input, and a table that claims to distinguish things this crawler never sees.
//
// That absence is itself half of this bead's answer, and the larger half: for a stylesheet, a script
// or a font on a CDN, burpsy produces NO ledger entry whatsoever. It does not refuse the asset — it
// never looks at it. An operator comparing against Burp, whose crawler fetches exactly those
// (allow_out_of_scope_resources = true), sees a page render as "found, no links" where Burp saw its
// full content. No skip reason can express that, because nothing was refused; see the bead.
//
// So the set here is what remains: frames and embedded documents. A browser loads them for the page;
// a person does not click them; and they are the one case where burpsy's scope refusal IS the reason
// the content is missing.
func isResourceTag(tag string) bool {
	// The synthetic prefixes are never resources: "json:", "api:" and "graphql:" name locations read
	// out of a document, and "speculative" is a URL mined from non-rendered text.
	if tag == "" || strings.Contains(tag, ":") {
		return false
	}
	switch tag {
	case "iframe", "frame", "object", "embed":
		return true
	default:
		// The subresources the crawl now fetches (4ocj): an out-of-scope image or stylesheet is a
		// refused resource, not a refused link.
		return subresourceTags[tag]
	}
}

// captureSource is the Source the crawl's captures carry: the capture's own when the caller set one
// (an isolated scan, 13uw), the crawl's otherwise.
func (c *Crawler) captureSource() core.Source {
	if c.cfg.Capture.Source != core.SourceUnattributed {
		return c.cfg.Capture.Source
	}
	return core.SourceCrawl
}

// withoutTag drops the links a page contributed through one tag, keeping the rest in order.
func withoutTag(links []discoveredLink, tag string) []discoveredLink {
	out := links[:0:0]
	for _, l := range links {
		if l.tag != tag {
			out = append(out, l)
		}
	}
	return out
}
