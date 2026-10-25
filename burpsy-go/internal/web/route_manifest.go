package web

import "strings"

// This file holds the route manifest and the risk taxonomy every consumer reads.
//
// It was extracted from route_manifest_test.go because the risk class is not a
// test artefact: it is the substrate the agent tool registry (burpsy-react-ui-acdv)
// derives each tool's safety string and escalation tier from, so it has to be
// reachable from non-test code. The manifest is still checked by the 405/400 sweep in
// the test file; only its storage moved.

// riskClass says what an unattended caller can do with a route. Declared per route so one shared
// server-side check can enforce confirmation, rather than 21 facades each deciding for themselves.
type riskClass string

const (
	// riskRead reads state and sends nothing outbound.
	riskRead riskClass = "read"
	// riskLocal mutates burpsy's own state — annotations, rules, settings — without sending traffic.
	riskLocal riskClass = "local-write"
	// riskEgress sends traffic to the engagement target. Bounded: one request, or a handful.
	riskEgress riskClass = "egress"
	// riskAttack sends unbounded traffic: an attack, an audit, a crawl, a capture. The class MCP-02
	// requires confirmation for, because a model that miscounts here is a denial of service against a
	// client's production system.
	riskAttack riskClass = "attack"
	// riskScope changes what the engagement is allowed to touch. Confirmation-worthy for the opposite
	// reason to riskAttack: it does not send anything itself, it removes the thing that says no.
	riskScope riskClass = "scope"
	// riskCredential reads or replays credentials — the cookie jar, session macros. Confirmation-worthy
	// because the output is secret, not because the call is dangerous.
	riskCredential riskClass = "credential"
	// riskDestructive irreversibly discards evidence.
	//
	// This class was added because writing the manifest found a route nobody had classified:
	// `DELETE /api/tools/log` answers {"cleared": true} and wipes the record of every request this
	// process has sent. On an engagement that log is the answer to "what did you send to my
	// production system", so losing it is not the same kind of act as clearing a filter box — and
	// riskLocal, which is what it would otherwise have been folded into, is defined as writing
	// burpsy's own state and is exactly the wrong shape for it. Discovered by
	// Test_every_route_rejects_a_verb_it_does_not_implement, which is the whole argument for having
	// a manifest: the verb was reachable, undocumented, and destructive.
	riskDestructive riskClass = "destructive"
	// riskAsset serves a static asset (the UI, the CA certificate).
	riskAsset riskClass = "asset"
	// riskExecute runs operator-supplied code in this process's privileges: it starts a plugin from the
	// -plugins allowlist as a child process, or invokes something that plugin registered.
	//
	// Its own class because none of the others fits and folding it into one of them would understate
	// it. riskLocal is defined as writing burpsy's own state, and this writes nothing; riskEgress and
	// riskAttack are about what leaves for the target, and a plugin may send nothing at all. What makes
	// it confirmation-worthy is the direction the others do not cover: the code on the far side is not
	// this program's, and after a load it is running until something stops it. The gate is the same as
	// scanner's `run tool` — the request names an allowlist key, never a path — so this class marks
	// "the operator already authorised this binary; a caller still has to mean it".
	riskExecute riskClass = "execute"
)

// route is one registered pattern and what it accepts.
type route struct {
	// methods is every verb the handler answers. The 405 test derives the disallowed set from it, so
	// an entry that overstates this weakens a real check — keep it exact.
	methods []string
	summary string
	risk    riskClass
	// subPath is a concrete path under a subtree pattern, for the routes registered with a trailing
	// slash. Required for those, because the pattern itself is not a requestable URL: "/api/audit/"
	// with no id is not what any caller sends, and testing the bare prefix would exercise a branch no
	// operator reaches.
	subPath string
	// actionPaths are the ACTION sub-paths under a subtree pattern, each with its own allowed-method
	// set — "1/run": {"POST"} under "/api/session/rules/". subPath alone cannot express these: one
	// subtree can route "/api/session/rules/1" to PUT and "/api/session/rules/1/run" to POST, and a
	// single concrete path tests exactly one of them.
	//
	// This exists because that gap shipped a bug. The /api/tasks/ entry's subPath was narrowed from
	// "{id}/cancel" to "1" in the same commit that moved cancel into an inline branch with no verb
	// guard, so GET /api/tasks/pause answered 200 and set the suite-wide pause
	// (burpsy-react-ui-0gg5). Naming each action path here is what makes the 405 sweep reach them.
	// (The tasks family itself is per-pattern routes since fxxm batch 2; the subtrees below that
	// still dispatch by suffix keep this field.)
	actionPaths map[string][]string
	// pathValidatedFirst marks a handler that resolves its path segment *before* checking the method,
	// so a bogus segment answers 404 rather than 405 whatever the verb. Correct behaviour — "there is
	// no such direction" is a truer answer than "wrong verb" — but it means the 405 test has to send a
	// valid segment, which is what subPath supplies.
	pathValidatedFirst bool
}

// concretePath builds the requestable URL a manifest entry's subPath names: appended
// under a subtree pattern, substituted for the wildcard in a "{id}" pattern
// (burpsy-react-ui-fxxm).
func concretePath(pattern, subPath string) string {
	if i := strings.Index(pattern, "{"); i >= 0 {
		return pattern[:i] + subPath + pattern[strings.Index(pattern, "}")+1:]
	}
	return pattern + subPath
}

// manifest is every route this server registers. Keep it sorted by pattern; the test enforces that,
// because a map this size that is not sorted is a merge conflict generator.
var manifest = map[string]route{
	"/": {
		methods: []string{"GET"}, risk: riskAsset,
		summary: "the operator console: index.html, app.js, style.css, and the SPA catch-all",
	},
	"/api/advisories": {
		methods: []string{"GET"}, risk: riskRead,
		summary: "the issue-definition catalogue as index rows, filterable by ?q= and ?severity=",
	},
	"/api/advisories/": {
		// 00100200 is SQL injection — a real type index, so the 405 test exercises the path a caller
		// actually sends rather than a segment that would 404 before reaching the verb guard.
		methods: []string{"GET"}, risk: riskRead, subPath: "00100200",
		summary: "one issue definition in full, by hexadecimal type index",
	},
	"/api/apiscan": {
		// POST only, and riskAttack for the same reason /api/crawl is: it sends unbounded traffic.
		// The bound it is given is the definition's own endpoint count, which for a large document is
		// large — and unlike a crawl, whose seed count an operator can see at a glance, a pasted
		// document's size is not visible until it has been parsed. Any model-driven caller therefore
		// needs confirmation here before it knows how much traffic it is about to cause.
		//
		// A `dry_run: true` body reads the definition and answers with what a run *would* send
		// (endpoint list, resolved base URL, how many values were invented) without starting anything,
		// which is what the New scan dialog renders before the operator commits.
		//
		// Read back through GET /api/crawl?task=N, as an API scan's run lives in the same registry.
		methods: []string{"POST"}, risk: riskAttack,
		summary: "start an API-only scan from an OpenAPI 3.x or Swagger 2.0 definition (JSON or YAML), sending the endpoints it describes in place of URLs to crawl; dry_run: true reports what a run would send instead",
	},
	"/api/apiscan/fetch": {
		// riskEgress, not riskAttack: one GET for the definition, plus one POST to a token endpoint when
		// OAuth2 client credentials is chosen — a fixed, tiny count, each authorised against scope on its
		// exact bytes before the dial. It carries the caller's credential for the fetch, and neither logs
		// nor persists it: the fetch is not recorded in history, and the tool-log row has no query string.
		methods: []string{"POST"}, risk: riskEgress,
		summary: "fetch an API definition from a URL for the API-only scan (Upload from URL), with optional " +
			"Basic, Bearer or OAuth2 client-credentials auth; scope-gated, size- and time-bounded, and " +
			"reports whether the document is OpenAPI, Swagger, Postman, WSDL or unrecognised",
	},
	"/api/audit/": {
		methods: []string{"POST"}, risk: riskAttack, subPath: "0",
		summary: "run an active audit over one captured exchange, by id (0 is valid — see HONEST-05)",
	},
	"/api/audit/selected": {
		// riskAttack, and the strongest case for it in the manifest: the pattern takes a list, so the
		// work is chosen by the caller's selection rather than by anything this server bounds. A model
		// that ticks every row in a 12,000-exchange capture and posts them is a scan of 12,000 items.
		//
		// Registered as a literal under the "/api/audit/" subtree; the more specific pattern wins, so
		// this is reachable and the subtree keeps its own subPath test.
		methods: []string{"POST"}, risk: riskAttack,
		summary: "run one active audit over a selection of captured exchanges (Burp's \"Audit selected " +
			"items\"); answers 202 with the task id, because a selection has no bound on its size",
	},
	"/api/backup": {
		// riskDestructive, not riskLocal, and the reasoning is worth stating because "take a backup"
		// sounds like the safest call in the manifest.
		//
		// It writes a snapshot, and then it *prunes*: snapshots beyond the retention count are
		// deleted. An unattended caller invoking this in a loop would therefore roll the entire
		// retention window off the disk — every older snapshot gone, irreversibly — while each
		// individual call reported success. That is the same shape as DELETE /api/tools/log, which is
		// what this class was created for, and riskLocal is defined as writing burpsy's own state,
		// which is exactly the wrong shape for it.
		//
		// Pruning only ever removes files matching the name pattern this feature writes, so an
		// operator's own files in the same directory are never touched.
		methods: []string{"POST"}, risk: riskDestructive,
		summary: "snapshot the project database now via VACUUM INTO, then prune snapshots beyond the " +
			"retention count; refuses with 503 when the instance has no -db",
	},
	"/api/backup/config": {
		// riskLocal, not riskDestructive, and the line is where the effect lands. The PUT writes
		// burpsy's own backup setting and reconciles one managed schedule — it takes no snapshot and
		// deletes no file itself. A destructive consequence (a scheduled prune, a delete-on-shutdown
		// sweep) is deferred to the schedule firing or to a clean shutdown, and each of those is already
		// bounded to the name pattern this feature writes. Saving the setting is the shape riskLocal
		// names: it changes burpsy's own state and sends nothing outbound.
		methods: []string{"GET", "PUT"}, risk: riskLocal,
		summary: "read or set the automatic-backup settings — the interval that drives a managed backup " +
			"schedule, and the delete-on-clean-shutdown switch; refuses with 503 when the instance has no -db",
	},
	"/api/blindxss": {
		// riskCredential, not riskRead, and the classification is the interesting part. A blind-XSS
		// callback carries `document.cookie` as the victim's browser saw it — a session token belonging
		// to someone who is very often not the engagement's subject. That is the definition of this
		// class ("the output is secret, not the call dangerous"), and reading it as riskRead would let an
		// unattended caller pull third-party session material without confirming.
		methods: []string{"GET"}, risk: riskCredential,
		summary: "the blind-XSS channel: whether it is listening and why not, every payload minted " +
			"through it, and the callbacks recorded against them",
	},
	"/api/blindxss/payload": {
		// Local: minting a token changes what the listener will answer for and sends nothing outbound.
		// The traffic a payload eventually causes comes from a victim's browser, not from here — which
		// is exactly why the response states that an unfired payload is outstanding rather than clean.
		methods: []string{"POST"}, risk: riskLocal,
		summary: "mint one blind-XSS correlation payload to plant: the token, the script URL and the " +
			"script tag carrying it",
	},
	"/api/collaborator/health": {
		// riskEgress, like /payload and for a stronger reason: it may register the channel, then sends
		// DNS, HTTP, HTTPS and SMTP traffic to the interaction server, a third party, to see whether the
		// interactions come back (Burp's "Run health check", 8e3n).
		methods: []string{"POST"}, risk: riskEgress,
		summary: "Burp's Collaborator health check: eight connection items against a fresh address on " +
			"the registered domain, then whether each protocol's interaction came back through polling",
	},
	"/api/collaborator/interaction/{id}": {
		methods: []string{"GET"}, risk: riskRead, subPath: "0",
		summary: "one out-of-band interaction's raw request and response, plus what its client IP means",
	},
	"/api/collaborator/interactions": {
		methods: []string{"GET"}, risk: riskRead,
		summary: "index rows for recorded out-of-band interactions: id, type, client IP, time",
	},
	"/api/collaborator/payload": {
		// riskEgress, and the one route in this manifest whose egress is NOT to the engagement target:
		// minting registers a payload domain with the interaction server, which tells a third party that
		// an engagement is running. Bounded (one registration per process), so not riskAttack — but a
		// read classification would be wrong, because this is the only route here that can open a
		// subprocess and a public DNS registration.
		methods: []string{"POST"}, risk: riskEgress,
		summary: "mint one out-of-band payload address; refuses with 409 and no address when no " +
			"interaction server is configured",
	},
	"/api/collaborator/poll": {
		// POST but riskRead, like /api/intruder/points and /api/sequencer/analyse: the verb marks an
		// operator asking for something now, not an outbound send. Nothing leaves the process — the
		// interactsh-client subprocess owns polling, and this re-reads the log it writes.
		methods: []string{"POST"}, risk: riskRead,
		summary: "re-read the interaction log now instead of waiting for the page's next tick",
	},
	"/api/collaborator/server": {
		// riskScope, not riskLocal, and the reasoning is worth stating because riskLocal is the
		// tempting reading: this route sends nothing. The provider it installs is lazy, so no
		// registration, no subprocess and no packet happens here.
		//
		// What it does is decide *which third party* subsequently learns that an engagement is
		// running, and where the callback data for it lands. /api/collaborator/payload is already
		// riskEgress on the grounds that registering a domain discloses the engagement to a third
		// party; the route that chooses that party is at least as confirmation-worthy as the one that
		// contacts it. Classified riskLocal, an unattended caller could silently repoint every future
		// out-of-band callback at a host of its choosing — including by passing the literal "public"
		// to send it to interactsh's shared pool — and no confirmation would be asked.
		//
		// Refuses with 409 once a channel has registered, so it cannot orphan payloads already handed
		// out; that is a correctness guard, not a reason to soften the class.
		//
		// DELETE is Burp's "Don't use Burp Collaborator" (8e3n). It shares the class: it decides that no
		// third party learns of the engagement from now on, and with an open channel it 409s unless the
		// caller explicitly discards the payloads minted from it.
		methods: []string{"POST", "DELETE"}, risk: riskScope,
		summary: "point this installation at an interaction server without restarting: a URL, or " +
			"\"public\" for interactsh's shared pool; refuses with 409 once a channel is registered. " +
			"DELETE stops using one (409 with an open channel unless discard_open_channel is set)",
	},
	"/api/collaborator/status": {
		methods: []string{"GET"}, risk: riskRead,
		summary: "the out-of-band channel's state: configured or not, the registered domain, minted " +
			"payloads, and how many corpus checks are gated without it",
	},
	"/api/config/export": {
		methods: []string{"GET"}, risk: riskRead,
		summary: "one JSON bundle of every configurable surface: scope, intercept rules, session handling rules",
	},
	// Import rewrites what the engagement may touch — the bundle carries scope — so it shares
	// /api/scope's confirmation-worthy class rather than sitting with ordinary writes.
	// /api/scanner/config joins it: flipping audit families mid-engagement changes what the
	// scanner is allowed to send, which is the same class of decision.
	"/api/config/import": {
		methods: []string{"POST"}, risk: riskScope,
		summary: "apply a configuration bundle; a bundle with any invalid rule is refused without applying any part",
	},
	"/api/crawl": {
		// GET reports the last crawl's coverage report; POST starts one.
		methods: []string{"GET", "POST"}, risk: riskAttack,
		summary: "GET: the last crawl's coverage report. POST: crawl from a seed URL under stated bounds",
	},
	"/api/crawl/live": {
		methods: []string{"GET"}, risk: riskRead,
		summary: "the live crawl view for ?task=N: the request in flight, the phase, the last 50 fetches, and a throttled frame from the render pass (null with a stated reason when there is no browser)",
	},
	"/api/crawl/logins": {
		// riskCredential: a sequence carries typed passwords and TOTP secrets. GET is the redacted
		// library (no secret on the wire); POST imports or edits one; DELETE removes one.
		methods: []string{"GET", "POST", "DELETE"}, risk: riskCredential,
		summary: "recorded login sequences (Burp's Login Recorder or Chrome Recorder import, step editor, See as JSON): GET redacted list, POST save/import, DELETE ?id=",
	},
	"/api/crawl/logins/replay": {
		// riskCredential: replays a stored login — typed passwords and a TOTP code — against the
		// target, in a browser session gated by scope on every request.
		methods: []string{"POST"}, risk: riskCredential,
		summary: "Burp's Replay: run a recorded login in an isolated, scope-gated browser and report each step, the status check, blocked requests and a screenshot",
	},
	"/api/dashboard": {
		methods: []string{"GET"}, risk: riskRead,
		summary: "running tasks, the activity log, and every coverage summary with its breakdown",
	},
	"/api/dashboard/events": {
		// riskDestructive, not riskLocal: the event log holds scope.changed and crawl.refused — the
		// trail of what the engagement was allowed to touch and what the tool refused to send — so a
		// DELETE discards evidence, the exact shape this class was created for at /api/tools/log.
		methods: []string{"DELETE"}, risk: riskDestructive,
		summary: "clears the dashboard's event log (Burp's \"Clear event log\"); the SSE stream at /api/events is a different resource",
	},
	"/api/datasets/": {
		// riskRead: a read-only table view over lists other read routes already serve
		// (burpsy-react-ui-co88). No credential-class list is offered as a source.
		methods: []string{"GET"}, risk: riskRead, subPath: "history",
		summary: "one table view over a list — history, issues, sitemap, tool-log, ws-history, intruder/{task}: " +
			"regex over columns, sort, offset/limit paging, facet counts, and a long-poll for new rows",
	},
	"/api/discovery": {
		// riskAttack for the same reason /api/crawl is: a POST hands a wordlist to ffuf, which then
		// sends one request per word — unbounded traffic at the target, chosen by a file rather than by
		// the caller. The GET is a read, but the manifest classifies a pattern and the stronger of the
		// two verbs is the one an unattended caller has to confirm.
		methods: []string{"GET", "POST"}, risk: riskAttack,
		summary: "GET: the ffuf allowlist state and the retained discovery runs. POST: sweep a host's " +
			"path space with a wordlist (Burp's \"Discover content\")",
	},
	"/api/target/analyze": {
		// Burp's Target analyzer (burpsy-react-ui-dnvi): counts over captured content, nothing sent.
		methods: []string{"GET"}, risk: riskRead,
		summary: "Target analyzer: dynamic and static URLs, parameters and unique parameter names for a host or branch; format=html saves the report",
	},
	"/api/engagement/clickbandit.js": {
		// burpsy's Clickbandit script (burpsy-react-ui-g67w), served as text for the console to copy.
		methods: []string{"GET"}, risk: riskAsset,
		summary: "the Clickbandit script to paste into a target page's developer console (clickjacking PoC recorder)",
	},
	"/api/engagement/": {
		methods: []string{"GET"}, risk: riskRead, subPath: "1",
		summary: "Burp's site-map engagement searches: comments, scripts, references to a URL",
	},
	"/api/events": {
		methods: []string{"GET"}, risk: riskRead,
		summary: "SSE change stream; the UI refetches on a frame rather than polling",
	},
	"/api/events/stats": {
		methods: []string{"GET"}, risk: riskRead,
		summary: "the stream's own counters: frames sent, subscribers, coalesced signals",
	},
	"/api/exchange/": {
		methods: []string{"GET", "PATCH"}, risk: riskLocal, subPath: "0",
		summary: "one exchange row by id; PATCH sets its notes and/or highlight (UX-15)",
	},
	"/api/exchange/in-browser/{id}": {
		methods: []string{"GET"}, risk: riskRead, subPath: "1",
		summary: "one exchange's stored response replayed verbatim for Show response in browser",
	},
	"/api/exchanges/": {
		methods: []string{"GET"}, risk: riskRead, subPath: "0",
		summary: "legacy alias for /api/exchange/ — kept because the Rust UI shipped against it",
	},
	"/api/extensions": {
		methods: []string{"GET"}, risk: riskRead,
		summary: "every allowlisted plugin, the state breakdown across them, and the policy in force",
	},
	"/api/extensions/apis": {
		methods: []string{"GET"}, risk: riskRead,
		summary: "the JSON-RPC contract a plugin is written against, generated from the dispatched method set",
	},
	"/api/extensions/console": {
		methods: []string{"GET"}, risk: riskRead,
		summary: "one plugin's output and error consoles, with what the bound dropped",
	},
	"/api/extensions/invoke": {
		// riskExecute, not riskLocal: this runs a registration inside an operator-supplied process and
		// hands it engagement data.
		methods: []string{"POST"}, risk: riskExecute,
		summary: "run one registration a loaded plugin declared: a context-menu item, a menu action, or an editor tab",
	},
	"/api/extensions/load": {
		// The one route on this API that starts a process. See riskExecute.
		methods: []string{"POST"}, risk: riskExecute,
		summary: "start one allowlisted plugin as a child process and complete the JSON-RPC handshake",
	},
	"/api/extensions/order": {
		// riskLocal, not riskExecute: a move permutes this process's own slice. No plugin is spawned
		// and none is called.
		methods: []string{"POST"}, risk: riskLocal,
		summary: "move one allowlisted plugin one place in the order its registrations are offered and invoked in",
	},
	"/api/extensions/unload": {
		methods: []string{"POST"}, risk: riskLocal,
		summary: "stop a running plugin: ask it to exit, then close its stdin, then kill it",
	},
	"/api/findings": {
		methods: []string{"GET"}, risk: riskRead,
		summary: "legacy alias for /api/issues",
	},
	"/api/graphql/sitemap": {
		// riskLocal: it writes generated requests into burpsy's own store and site map and sends
		// nothing — every item it adds is unrequested (Source "schema").
		methods: []string{"POST"}, risk: riskLocal,
		summary: "Save GraphQL queries to site map: one unsent request per query/mutation an introspection answer declares",
	},
	"/api/headers/uninteresting": {
		// riskLocal, and this one genuinely is: it changes how burpsy *presents* a comparison and
		// nothing else. No traffic, no credentials, and it cannot widen what the engagement may
		// touch. The lists only ever cause differences to be labelled — never dropped — so even a
		// maliciously broad list cannot hide a difference from an operator, it can only dim it.
		methods: []string{"GET", "PUT"}, risk: riskLocal,
		summary: "the header names the Comparer discounts, per direction, with the response-side " +
			"defaults and the list of surfaces that consult them",
	},
	"/api/hidden-inputs": {
		// riskAttack, like /api/discovery and /api/audit/: a POST sends up to the run's request budget
		// (500 by default) of guessed parameters, cookies and headers at a captured exchange's target.
		// It is a deliberately separate pattern from /api/exchange/, which is riskLocal — nested there,
		// the guess would inherit a class the confirmation gate does not stop. The GET is a read; the
		// pattern takes the stronger verb's class, as /api/discovery's does.
		methods: []string{"GET", "POST"}, risk: riskAttack,
		summary: "GET: retained hidden-input guessing runs. POST: guess hidden query parameters, cookies " +
			"and headers against one captured exchange (Burp's Param Miner \"Guess params\")",
	},
	"/api/history": {
		// GET only. The removal that used to share this pattern as a DELETE moved to
		// /api/history/rows (burpsy-react-ui-gf68): a risk class is per pattern, so a DELETE here
		// was either classed riskRead — and passed the confirmation gate ungated, which is what it
		// did — or it dragged the busiest read in the console into riskDestructive, making every
		// agent escalate to look at history. The pattern split is /api/dashboard vs
		// /api/dashboard/events, not /api/sitemap's whole-pattern class.
		methods: []string{"GET"}, risk: riskRead,
		summary: "proxy history, filtered by the typed query DSL",
	},
	"/api/history/extractors": {
		methods: []string{"GET", "PUT"}, risk: riskLocal,
		summary: "the custom extractor columns (burpsy-react-ui-28n8): named regex-group or json-path " +
			"extractors saved with the project and rendered as derived columns in history and Intruder results",
	},
	"/api/history/extract": {
		methods: []string{"POST"}, risk: riskLocal,
		summary: "run the saved extractors against the responses of the named exchange ids (history) or " +
			"response message ids (Intruder) and return each captured value, so the console can fill the " +
			"derived columns for the rows it is showing",
	},
	"/api/history/import/har": {
		methods: []string{"POST"}, risk: riskLocal,
		summary: "import a HAR (HTTP Archive 1.2) file: its log.entries become history rows, viewable " +
			"and resendable in Repeater; nothing is sent to any target — the requests are recorded, not replayed",
	},
	"/api/history/rows": {
		// riskDestructive (burpsy-react-ui-gf68), on the same line /api/sitemap's DELETE draws: the
		// removal is a tombstone on the operator's view, not on the stored bytes — positional ids stay
		// stable — but a row that leaves history leaves the record an operator reasons and reports
		// from, and "clear the capture" with no body empties all of it. Until gf68 this was DELETE
		// /api/history under that pattern's riskRead, so any same-origin caller could empty history
		// without the confirmation every other evidence-discarding route requires.
		methods: []string{"DELETE"}, risk: riskDestructive,
		summary: "Burp's \"Delete items\" / \"Clear (tool)\": remove the named rows ({\"ids\":[..]}) from " +
			"proxy history, or every row (no body); a view-level tombstone — ids stay stable and the bytes " +
			"are not erased",
	},
	"/api/http2/kettle": {
		// riskRead: it classifies a header list and sends nothing. POST because the list is a body.
		methods: []string{"POST"}, risk: riskRead,
		summary: "whether an HTTP/2 header list is kettled (HTTP/1 text cannot carry it) and whether a send would be refused",
	},
	"/api/http2/program": {
		methods: []string{"POST"}, risk: riskEgress,
		summary: "send a raw HTTP/2 frame program: the pseudo-header and frame-level surface",
	},
	"/api/intercept": {
		methods: []string{"GET"}, risk: riskRead,
		summary: "interception state: enabled, wired, and what is currently held",
	},
	"/api/intercept/": {
		// POST only, and this is also the catch-all under /api/intercept — see the note in setupRoutes
		// about preserving handleInterceptHeld's breadth through the Phase 1 ServeMux migration.
		methods: []string{"POST"}, risk: riskLocal, subPath: "1",
		summary: "resolve one held message: forward, drop, or forward edited bytes",
	},
	"/api/intercept/annotate/{id}": {
		// POST {comment, highlight} onto one held message (burpsy-react-ui-5q8u). Writes only the
		// operator's own annotation on the queue — no traffic is sent, resolved or changed, so the
		// risk is the same class as the queue view itself.
		methods: []string{"POST"}, risk: riskLocal, subPath: "1",
		summary: "annotate one held message: set or clear its operator comment and highlight",
	},
	"/api/intercept/drop-all": {
		methods: []string{"POST"}, risk: riskLocal,
		summary: "drop every held message in one round trip; answers the count actually dropped",
	},
	"/api/intercept/enable": {
		methods: []string{"POST"}, risk: riskLocal,
		summary: "turn interception on or off",
	},
	"/api/intercept/forward-all": {
		methods: []string{"POST"}, risk: riskLocal,
		summary: "forward every held message unmodified in one round trip; answers the count actually forwarded",
	},
	"/api/intercept/in-scope-only": {
		// riskLocal: it narrows what burpsy HOLDS and sends nothing. Worth stating why it is not
		// stronger, because turning it on means more traffic reaches the target without operator
		// review — but that traffic was going there anyway; interception is a hold, not a gate, and
		// the engagement scope already decides what may be touched.
		methods: []string{"POST"}, risk: riskLocal,
		summary: "Burp's \"Only intercept in-scope messages\": filter the hold queue to the engagement scope",
	},
	"/api/intercept/newline-correction": {
		// riskLocal, and the reasoning is the same as the in-scope switch below for a different
		// reason: this rewrites the bytes the OPERATOR is about to send, and the whole feature is
		// that they chose to. It is not burpsy sending anything of its own, and it is not a decision
		// about what may be touched — it is a correction to a request the operator is already holding
		// and has already edited. Both corrections default OFF, so the risk is opt-in twice over.
		//
		// GET as well as PUT because the surface must read what is in force rather than assume the
		// defaults: a plugin or a previous session may have set one, and a checkbox showing the wrong
		// state is a control that lies about what it is doing.
		methods: []string{"GET", "PUT"}, risk: riskLocal,
		summary: "Burp's two newline fixes for an EDITED interception: add a missing blank line after the headers, and strip trailing newlines from a urlencoded body",
	},
	"/api/intercept/rules/": {
		// "requests" and "responses", plural — see directionFor. The singular was a guess when this
		// entry was first written, and it answered 404 "Unknown direction" for every verb, which the
		// 405 test read as a missing guard. The handler was right; the manifest was wrong.
		methods: []string{"GET", "PUT"}, risk: riskLocal, subPath: "requests",
		pathValidatedFirst: true,
		summary:            "the match rules deciding which messages are held, per direction",
	},
	"/api/proxy/history-logging": {
		// Burp's "Proxy history logging" (burpsy-react-ui-z80e): a preference the console's Add to
		// scope reads. Writes only the operator's own preference, so riskLocal.
		methods: []string{"GET", "POST"}, risk: riskLocal,
		summary: "read or set what adding to scope does about out-of-scope proxy logging: stop, ask or nothing",
	},
	"/api/intercept/startup": {
		// Burp's "Default Proxy interception state" (burpsy-react-ui-7vy): a preference about
		// the NEXT server start, not a live toggle — /enable stays the switch. Writes only the
		// operator's own preference, so riskLocal like the rest of the intercept configuration.
		methods: []string{"GET", "POST"}, risk: riskLocal,
		summary: "read or set the startup interception preference: on, off, or restore-last-state",
	},
	"/api/intruder/again": {
		// Burp's "Request item again" (burpsy-react-ui-2rw7): re-sends stored attempt requests to the
		// target, each through the scope gate. riskAttack: a batch of up to 500 requests.
		methods: []string{"POST"}, risk: riskAttack,
		summary: "re-send selected Intruder attempts' exact stored requests and answer replacement result rows",
	},
	"/api/intruder/attacks": {
		methods: []string{"GET"}, risk: riskRead,
		summary: "every intruder attack this process is running, with its status; sends nothing",
	},
	"/api/intruder/attacks/": {
		methods: []string{"POST"}, risk: riskLocal, subPath: "1/stop",
		summary: "POST {task_id}/{pause|resume|stop}: control a running attack; unknown id answers 404, " +
			"an attack past acting on answers 409",
	},
	"/api/intruder/payload-files": {
		// riskLocal, not riskAttack: the upload stores a file the operator explicitly chose and
		// sends nothing to the target — the attack that consumes it is the run route's own
		// riskAttack decision. A random stored name (not the client's) is what keeps the route
		// from being a path-traversal primitive.
		methods: []string{"POST"}, risk: riskLocal,
		summary: "upload a payload wordlist (one per line); answers with the stored path the file " +
			"payload source resolves",
	},
	"/api/intruder/points": {
		methods: []string{"POST"}, risk: riskRead,
		summary: "enumerate insertion points in a stored request; sends nothing",
	},
	"/api/intruder/run": {
		methods: []string{"POST"}, risk: riskAttack,
		summary: "run an intruder attack: payloads spliced into one insertion point set",
	},
	"/api/issues": {
		methods: []string{"GET"}, risk: riskRead,
		summary: "findings, with the catalogue advisory each resolved to",
	},
	"/api/issues/": {
		// riskDestructive is on for the whole subtree because DELETE discards a finding — evidence,
		// per this file's own definition of the class — while the PUT beside it only writes burpsy's
		// own state (a triage decision) and would be riskLocal alone. One pattern, one class: the
		// manifest has no per-verb risk split, and understating the DELETE is the worse error.
		methods: []string{"PUT", "PATCH", "DELETE"}, risk: riskDestructive, subPath: "0",
		summary: "operator triage of one finding — severity/confidence override, false-positive, comment — or delete it",
	},
	"/api/issues/consolidation": {
		methods: []string{"GET", "PUT"}, risk: riskLocal,
		summary: "the issue consolidation policy — keep existing (merge), keep both or keep new on a duplicate, for every issue type with per-type overrides — and how many collisions each run resolved which way",
	},
	"/api/issues/record": {
		// POST creates the operator's hand-recorded finding and attaches it to one exchange. It
		// writes engagement evidence (like the triage PUT beside it) but discards nothing, so
		// riskLocal is the honest class; the subtree's riskDestructive is about DELETE, not this.
		methods: []string{"POST"}, risk: riskLocal,
		summary: "record an issue by hand against one exchange (Burp's 'Record an issue')",
	},
	"/api/issues/triage": {
		methods: []string{"POST"}, risk: riskLocal,
		summary: "the LLM post-scan second look over gated findings (Standard profile: High any-confidence, Medium tentative-or-better) — advice attached to findings, never a promotion",
	},
	"/api/message/{id}": {
		methods: []string{"GET"}, risk: riskRead, subPath: "0",
		summary: "raw bytes of one stored message, with pretty and hex views",
	},
	"/api/network/server-certificates": {
		// Burp's "Server TLS certificates" (burpsy-react-ui-t75m): an information-only list of the
		// certificates target servers presented. DELETE clears the list. riskLocal: public
		// certificates, no egress.
		methods: []string{"GET", "DELETE"}, risk: riskLocal,
		summary: "the X.509 certificates target servers presented to the sender and the proxy, deduplicated; DELETE clears",
	},
	"/api/network/auth/failures": {
		// Burp's "Prompt for credentials on platform authentication failure" (burpsy-react-ui-3xnt):
		// the hosts whose challenge failed, for the console to ask about. Names hosts and schemes,
		// never a credential; DELETE only dismisses one. riskLocal: it changes no egress.
		methods: []string{"GET", "DELETE"}, risk: riskLocal,
		summary: "platform-authentication failures waiting for credentials: list them, or dismiss one by host",
	},
	"/api/network/auth": {
		// riskCredential, and not riskLocal, because that is what these rows are: an
		// operator's account on the target. A GET cannot disclose the password — the wire
		// shape has no field for it — but it does enumerate which accounts are configured
		// against which hosts, and a POST arms every subsequent send to replay one. Both
		// are things an unattended caller should have to ask about.
		methods: []string{"GET", "POST", "PUT", "DELETE"}, risk: riskCredential,
		summary: "platform authentication: per-host HTTP credentials, and (PUT) whether a failure prompts for them (Basic and Digest; NTLM and Negotiate are not implemented). Never serves a password",
	},
	"/api/network/client-certs": {
		// Same class for the same reason: a TLS client identity is a credential, and DELETE
		// silently removing one would leave an app that had been reachable failing its
		// handshake with nothing on the panel to explain it.
		methods: []string{"GET", "POST", "DELETE"}, risk: riskCredential,
		summary: "client TLS certificates: PKCS#12 identities bound per host (PKCS#11 tokens are out of scope). Never serves a passphrase or key",
	},
	"/api/network/proxy": {
		// riskLocal by the letter of its definition — it mutates settings and sends nothing — and by
		// precedent: /api/tools/rules rewrites every proxied request and is classified here too.
		//
		// Recorded because there is a real argument for more: a rule set here redirects all future
		// egress, credentials and session cookies included, through a host the caller chose, which is
		// an exfiltration primitive in a way that editing a rewrite rule is not. It is left at
		// riskLocal rather than promoted quietly, because the confirmation-worthy sets below are
		// asserted deliberately and moving a route into one is a decision, not a side effect. A future
		// reader who wants it confirmed should add it to wantScope (or a new class) and say why here.
		methods: []string{"GET", "POST", "DELETE"}, risk: riskLocal,
		summary: "the upstream proxy / SOCKS chain both egress paths follow: ordered host-pattern rules " +
			"with a default. POST upserts a rule and/or the default, DELETE removes one by exact pattern " +
			"(404 when absent) or clears all with ?all=true",
	},
	"/api/network/settings": {
		// riskScope, not riskLocal, and the reason is the hostname-resolution table. The scope gate
		// authorises a *name*; an override decides which machine that name's authorised bytes are
		// delivered to. Writing one therefore changes what the engagement can reach without changing
		// what the scope says — which is riskScope's definition, "it removes the thing that says no",
		// arrived at from the other direction. The redirect mode belongs in the same class for the
		// plainer reason that it turns one authorised request into a chain of them.
		methods: []string{"GET", "PUT"}, risk: riskScope,
		summary: "hostname resolution overrides, DNS lookup policy, connect/read/total timeouts, the " +
			"opt-in redirect policy, 100-continue and open-ended response handling; PUT is a partial " +
			"patch that refuses an unknown key by name and persists what it accepts",
	},
	// Both pool routes are riskScope rather than riskLocal, and the reason is the whole point of the
	// class: a pool decides how hard every tool that names it may hit the target, so raising one from
	// two concurrent requests to two hundred arms every future crawl, audit and attack to send far
	// more traffic than the operator who set the pool authorised. That is the same kind of decision as
	// /api/scanner/config's audit families — it changes what this process is allowed to send — and it
	// is not made visible by the traffic at the moment it is made, which is exactly when an unattended
	// caller should have to confirm. Classifying a saved-limits editor as an ordinary local write
	// would be reading "sends nothing itself" as "harmless".
	"/api/pools": {
		methods: []string{"GET", "POST"}, risk: riskScope,
		summary: "the saved named resource pools, with which of each pool's bounds every tool path can " +
			"actually honour; POST saves a new one",
	},
	"/api/pools/": {
		methods: []string{"PUT", "DELETE"}, risk: riskScope, subPath: "nonesuch",
		summary: "replace or delete one pool by name; a DELETE is refused while a schedule still " +
			"references it, naming the schedules",
	},
	"/api/protocols": {
		methods: []string{"GET"}, risk: riskRead,
		summary: "per-surface HTTP/1.1 vs HTTP/2 counts, and why a send was downgraded",
	},

	"/api/project": {
		methods: []string{"GET"}, risk: riskRead,
		summary: "which project this instance is: the persisted project name (\"Unnamed\" when never set), " +
			"the -db file it lives in, and whether anything is durable at all — the readout the Project menu shows",
	},
	"/api/project/logging": {
		// Burp's Project settings → Logging (burpsy-react-ui-nvfl): which tools append their requests
		// and responses to which files. riskCredential: the files receive the raw messages, cookies
		// and Authorization headers included, at a path the caller names.
		methods: []string{"GET", "PUT"}, risk: riskCredential,
		summary: "per-tool request/response log files (Burp's Logging settings): read, or set the paths; empty is off",
	},
	"/api/project/name": {
		methods: []string{"GET", "PUT"}, risk: riskLocal,
		summary: "read or rename the project; the name is stored with the database, so it travels with the " +
			"project file and survives a restart. A blank name is refused rather than stored, because a stored " +
			"placeholder would be indistinguishable from a real name",
	},
	"/api/project/open": {
		methods: []string{"POST"}, risk: riskDestructive,
		summary: "switch the running process to another project file (relative paths resolve next to the " +
			"current one; a missing file is created): quiesces tasks, re-runs the one-time restore against " +
			"the new file and re-points every write-through sink, so every in-memory store is replaced",
	},
	"/api/projects": {
		methods: []string{"GET"}, risk: riskRead,
		summary: "the project (.db) files in the active project's own directory, with stored names and the " +
			"active one marked; never searches upward",
	},

	"/api/proxy/ca": {
		methods: []string{"GET"}, risk: riskRead,
		summary: "which CA is signing intercepted TLS right now: subject and expiry, never the key",
	},
	"/api/proxy/ca/import": {
		// riskCredential. The other classes are all worse fits: nothing is sent (not riskEgress or
		// riskAttack), and calling it riskLocal would put "replace the trust anchor this proxy signs
		// every intercepted site with" in the same class as a table-density preference.
		//
		// It belongs with the cookie jar and the client certificates because it *takes* a long-lived
		// private key over HTTP. The consequence is unusual for this manifest: a successful call
		// invalidates every trust-store install the operator has already done, because the previous CA
		// stops signing and every cached leaf is discarded. An unattended caller must not be able to
		// do that without asking, and an operator who is asked will understand why.
		methods: []string{"POST"}, risk: riskCredential,
		summary: "import an operator-supplied CA certificate and private key, replacing the signing CA " +
			"and clearing the leaf cache; refuses the whole pair if it is not a usable CA",
	},
	"/api/browser/launch": {
		// riskEgress: the browser it opens loads the URL through the proxy — traffic to a target.
		methods: []string{"POST"}, risk: riskEgress,
		summary: "open the operator's browser: Chromium on its own profile, routed through the first usable " +
			"proxy listener and trusting burpsy's CA by SPKI pin for that profile only; refuses by name with no " +
			"listener, no Chromium, root with the sandbox on, or no display. With url, opens it (in the running " +
			"browser when there is one)",
	},
	"/api/browser/settings": {
		methods: []string{"GET", "PUT"}, risk: riskLocal,
		summary: "the browser's settings under Burp's keys (browser_data_directory, allow_saving_browser_settings, " +
			"allow_running_without_sandbox, disable_gpu), saved with the project, plus the profile and listener a " +
			"launch would use",
	},
	"/api/browser/clear": {
		// riskDestructive: deletes the profile's cookies, logins and history; nothing brings them back.
		methods: []string{"POST"}, risk: riskDestructive,
		summary: "Burp's 'Clear all browser data': delete the stored browser profile; refused while the browser runs",
	},
	"/api/proxy/ca/export": {
		// riskDestructive, alongside regenerate: handing out the signing key is irreversible — once a
		// copy exists elsewhere nothing here can take it back, and whoever holds it can mint a leaf
		// every client trusting this CA accepts. The certificate kind shares the gate so one route has
		// one rule a caller cannot talk past by naming the cheap kind first.
		methods: []string{"POST"}, risk: riskDestructive,
		summary: "export the signing CA as kind cert (PEM), key (PKCS#8 PEM) or pkcs12 (password-protected " +
			"keystore carrying both), so another tool can intercept with the same CA; never logged, never cached",
	},
	"/api/proxy/ca/regenerate": {
		// riskDestructive, not riskLocal or riskCredential. riskLocal would put "throw away the trust
		// anchor this proxy signs every intercepted site with" in the same class as a table-density
		// preference. riskCredential is the class its sibling import sits in, but that class's stated
		// rationale is "takes a long-lived private key over HTTP" — this route takes nothing; it mints
		// the key itself and never serves it.
		//
		// What it does do is destroy: the previous CA stops signing, every cached leaf is discarded,
		// and persisting the new pair overwrites the old signing key on disk with no way back. Unlike
		// import, where the operator still holds the pair they pasted, a regenerated-over key is gone
		// for good — which is the point of rotation. That irreversibility is what riskDestructive marks,
		// alongside the tool-log clear and the backup prune, and it is why an unattended caller must
		// confirm before invoking it.
		methods: []string{"POST"}, risk: riskDestructive,
		summary: "regenerate the signing CA: mint a fresh self-signed CA, install it, and clear the " +
			"leaf cache; the previous CA is discarded and every client must be re-given the new one",
	},
	"/api/proxy/listener": {
		methods: []string{"GET", "PUT", "POST", "DELETE"}, risk: riskLocal,
		summary: "the proxy's listeners, Burp's list rather than one socket: GET answers every listener with its resolved address, redirect target, force-TLS and invisible-proxying setting; POST adds one, PUT ?id= replaces one's settings (bodied PUT with no id is the legacy re-bind of the boot listener), DELETE ?id= removes one. Every listed listener is a socket the accept loop is serving — a bind that fails is refused with the reason and nothing is added — and the new socket opens before the old closes, so a failed move leaves the listener serving. The boot listener (-proxy-bind) is re-bindable but not removable. Not persisted: -proxy-bind stays authoritative at boot",
	},
	"/api/proxy/options": {
		methods: []string{"GET", "PUT"}, risk: riskLocal,
		summary: "the proxy's live response modification rules and strip-Accept-Encoding knob, with the outcome counters",
	},
	"/api/proxy/passthrough": {
		methods: []string{"GET", "POST", "PUT", "DELETE"}, risk: riskLocal,
		summary: "the TLS passthrough host-pattern list, live: add and remove without restarting the proxy; PUT the two coupling switches (apply to out-of-scope items, auto-add on a client certificate rejection)",
	},
	"/api/repeater/browser-reissue": {
		// riskEgress, the same class as the WS resend: it mints URLs that re-send one stored
		// exchange, and both scope gates (host-level at mint, AuthoriseRaw on the bytes about
		// to go out) defend it — the mint IS the operator's right-click, and it cannot mint
		// for an authority the scope does not authorise.
		methods: []string{"POST"}, risk: riskEgress,
		summary: "mint two one-shot URLs that re-issue a stored exchange in the original and in the " +
			"current session, for the operator's own browser to open",
	},
	"/api/repeater/history-export": {
		// riskRead: it reads stored messages by id and sends nothing. POST because the body is the
		// tab's list of ids, which a query string would bound far below a long session's history.
		methods: []string{"POST"}, risk: riskRead,
		summary: "Repeater's Save entire history: a tab's sends as one file, request/response bytes base64 by message id",
	},
	"/api/repeater/send": {
		methods: []string{"POST"}, risk: riskEgress,
		summary: "send one operator-authored request and record the exchange",
	},
	"/api/repeater/send-group": {
		// riskEgress, not riskAttack: the group is tabs an operator authored by hand and the endpoint
		// caps one call at 64 of them, so this is "a handful", the same class as the single send. The
		// parallel mode fires them concurrently, which is a timing choice rather than an unbounded
		// volume one.
		methods: []string{"POST"}, risk: riskEgress,
		summary: "send a Repeater tab group in tab order on one shared socket, in tab order on separate " +
			"connections, or all at once in parallel; every raw request is authorised individually",
	},
	"/api/repeater/ws-send": {
		// riskEgress, the same class as /api/repeater/send: one operator-authored frame goes out on a
		// connection this endpoint dials itself, and the handshake's bytes pass the same two scope
		// gates the HTTP send applies. Not riskAttack — no scan is launched, nothing enumerates, and
		// the frame is a single message the operator typed.
		//
		// To-client is answered 400 with the reason rather than attempted, so an unattended caller
		// cannot reach the browser-facing half by omitting the direction.
		methods: []string{"POST"}, risk: riskEgress,
		summary: "resend one WebSocket frame on a freshly dialled connection (or, with clone, one opened " +
			"with a captured connection's own handshake), recording the handshake exchange and the reply " +
			"frames; to-client is refused with its reason",
	},
	"/api/repeater/ws-attach": {
		// riskEgress, the same class as ws-send: one operator-authored frame, into one connection. It
		// dials nothing — the socket must be one the proxy is relaying right now, looked up by its
		// WebSocket ID in the relay's own registry — and the connection's handshake target must be
		// in scope. To-client is allowed here, because an attached connection has a client.
		methods: []string{"POST"}, risk: riskEgress,
		summary: "write one WebSocket frame into a connection open through the proxy (Repeater attach), " +
			"to the server or to the client; scope-gated on the connection's target, recorded on its history",
	},
	"/api/report/": {
		methods: []string{"GET"}, risk: riskRead, subPath: "json",
		summary: "export findings as json, sarif, html or Burp-XML (m7dk)",
	},
	"/api/scanner/audit": {
		methods: []string{"POST"}, risk: riskAttack,
		summary: "legacy alias for /api/audit/{id}, taking the id in the body",
	},
	"/api/scanner/audit-items": {
		methods: []string{"GET"}, risk: riskRead,
		summary: "the audit queue: per-item state, plan progress, dispositions and the insertion points each covers",
	},
	"/api/scanner/audit-items/": {
		// Two actions, and they are NOT the same risk, which is the reason the manifest spells both
		// out rather than inheriting one class for the prefix.
		//
		// {id}/again is riskAttack, not riskLocal: it is not a state change on a row, it starts an
		// audit that sends real traffic, through the same runAudit as /api/audit/{id}. A verb in the
		// path is what makes that classifiable by reading the route; a PATCH of a "state" field that
		// happened to launch a scan would not be.
		//
		// {id}/cancel is riskLocal: it moves a queue row and sends nothing at all. Reading it as an
		// attack would make an unattended caller ask a human to confirm the one queue action that
		// cannot touch the target — and a control nobody can reach unattended is not much of a control
		// when the queue is filling up unattended, which is the case it exists for.
		methods: []string{"POST"}, risk: riskAttack, subPath: "0/again",
		pathValidatedFirst: true,
		summary: "one queued item: POST {id}/again re-audits it (Burp's auditItemContextMenuAuditAgain); " +
			"POST {id}/cancel stops it before dispatch and sends nothing (auditItemContextMenuCancel)",
	},
	"/api/scanner/config": {
		methods: []string{"GET", "PUT"}, risk: riskScope,
		summary: "the audit families and performance knobs, readable and editable while the process runs; PUT persists the overrides",
	},
	"/api/scanner/configs": {
		methods: []string{"GET", "POST", "PUT", "DELETE"}, risk: riskLocal,
		summary: "the scan configurations an audit can run under: the shipped presets, generated from the table rather than listed by hand, plus the operator's own saved ones (burpsy-react-ui-uxcs) in the same list and marked shipped:false. POST/PUT save, clone or rename one; DELETE removes one. A shipped name is read-only and every write refuses it with 409 — two lists answering the same name differently is what the refusal prevents. riskLocal rather than riskRead because the writes change what a later audit runs under, and riskDestructive is reserved for discarding recorded evidence; a deleted configuration is a setting, not a finding",
	},
	"/api/scanner/issue-types": {
		// riskRead: a static table this binary carries; it answers what can be selected and sends nothing.
		methods: []string{"GET"}, risk: riskRead,
		summary: "the issue catalogue a scan configuration's per-issue selection is chosen from: every type by name with " +
			"Burp's detection methods for it and which of them burpsy runs (burpsy-react-ui-saq3.3.1)",
	},
	"/api/scanner/checks": {
		// The corpus inventory: which custom checks are loaded, and whether each is enabled. riskRead
		// — it answers what this process already holds and sends nothing.
		methods: []string{"GET"}, risk: riskRead,
		summary: "the loaded BCheck corpus as rows: each custom check's name, enablement and run count, " +
			"so what the corpus covers is inspectable rather than only counted (burpsy-react-ui-kdqj)",
	},
	"/api/scanner/checks/validate": {
		// riskRead: parses a draft and answers whether it would load; nothing changes, nothing is sent.
		methods: []string{"POST"}, risk: riskRead,
		summary: "Burp's Validate for a custom scan check: parse a BCheck draft and report its name, kind and " +
			"the parse error with its line and column (burpsy-react-ui-kbu1)",
	},
	"/api/scanner/checks/import": {
		// riskLocal: adds a check to the corpus the next audit and the passive scanner dispatch.
		methods: []string{"POST"}, risk: riskLocal,
		summary: "Burp's Import / Save for a custom scan check: load a BCheck from the console into the corpus, " +
			"persisted with the project (burpsy-react-ui-kbu1)",
	},
	"/api/scanner/checks/source": {
		// GET is a read (Export, the editor); DELETE removes a console check — local-write, the stricter.
		methods: []string{"GET", "DELETE"}, risk: riskLocal,
		summary: "a loaded check's BCheck source for Export and editing, and Delete for a console-imported " +
			"check (burpsy-react-ui-kbu1)",
	},
	"/api/scanner/checks/reload": {
		// riskLocal: re-reads the --bchecks directory into the corpus.
		methods: []string{"POST"}, risk: riskLocal,
		summary: "re-read the --bchecks directory, keeping console-imported checks (burpsy-react-ui-kbu1)",
	},
	"/api/scanner/checks/test": {
		// riskAttack: an active draft sends its probes to each chosen exchange's target, through the same
		// scope-gated sender an audit uses.
		methods: []string{"POST"}, risk: riskAttack,
		summary: "Burp's Run test for a custom scan check: run a BCheck draft against chosen captured exchanges " +
			"and report its findings, probes sent and refused, and unresolved references, filing nothing " +
			"(burpsy-react-ui-kbu1)",
	},
	"/api/scanner/checks/enable": {
		// riskLocal, not riskRead: this changes what the NEXT audit dispatches. Not riskAttack —
		// nothing leaves the process — and not riskCredential — no secret is involved. The honest
		// class for "writes this tool's own configuration" is local-write, the same as the other
		// per-check switches under /api/scanner/.
		methods: []string{"PUT"}, risk: riskLocal,
		summary: "enable or disable one corpus check by name; a name the corpus does not contain is " +
			"refused before anything is recorded",
	},
	"/api/authz/identities": {
		methods: []string{"GET", "PUT"}, risk: riskLocal,
		summary: "the access-control test identities (burpsy-react-ui-cr37): named cookie/header role bundles saved with the project, one marked the high-privilege baseline the others are compared against",
	},
	"/api/authz/test": {
		methods: []string{"POST"}, risk: riskAttack,
		summary: "re-send one captured request under each saved identity and classify access control per identity: Enforced, Bypassed (the identity got the baseline's privileged content) or Ambiguous — Autorize's three-state BOLA/IDOR verdict",
	},
	"/api/protobuf/decode": {
		methods: []string{"POST"}, risk: riskLocal,
		summary: "decode a protobuf or gRPC-framed body into a field tree without a .proto (burpsy-react-ui-3x2g), so an operator can read an otherwise opaque binary body; a pure transform that sends nothing",
	},
	"/api/protobuf/reflect-decode": {
		methods: []string{"POST"}, risk: riskEgress,
		summary: "fetch a target's schema via gRPC server reflection the operator explicitly named, then decode the body with it (burpsy-react-ui-47id); one bounded exchange to the target per call, scope-authorised before any dial, and the response marks the target-served names as reflection-sourced",
	},
	"/api/protobuf/encode": {
		methods: []string{"POST"}, risk: riskLocal,
		summary: "re-encode an edited protobuf field tree back to body bytes, re-framing it when it was gRPC (burpsy-react-ui-3x2g)",
	},
	"/api/dominvader": {
		methods: []string{"GET", "PUT"}, risk: riskLocal,
		summary: "the operator-side DOM auditor (burpsy-react-ui-wl94): the canary the browser extension watches, the on/off switch, and the source/sink hits it has reported — read and set burpsy's own auditor state, nothing is sent",
	},
	"/api/dominvader/hit": {
		methods: []string{"POST"}, risk: riskLocal,
		summary: "the endpoint burpsy's own DOM-auditor extension reports one source/sink flow to; records a hit the operator's browser produced",
	},
	"/api/dominvader/hits": {
		methods: []string{"DELETE"}, risk: riskLocal,
		summary: "clear the DOM auditor's reported hits",
	},
	"/api/dominvader/messages/poll":      {methods: []string{"POST"}, risk: riskLocal, summary: "private capability-authenticated extension worker frame decision mailbox"},
	"/api/dominvader/messages/register":  {methods: []string{"POST"}, risk: riskLocal, summary: "private capability-authenticated extension worker frame registration"},
	"/api/dominvader/messages/ack":       {methods: []string{"POST"}, risk: riskLocal, summary: "private capability-authenticated extension worker frame-specific acknowledgment of a delivered decision (unverified worker claim)"},
	"/api/dominvader/messages":           {methods: []string{"GET"}, risk: riskLocal, summary: "console-only read of the DOM auditor's untrusted page-message observations and hold states"},
	"/api/dominvader/messages/intercept": {methods: []string{"PUT"}, risk: riskLocal, summary: "console-only switch for holding incoming page messages; controller state a worker report cannot change"},
	"/api/dominvader/messages/decide":    {methods: []string{"POST"}, risk: riskLocal, summary: "console-only operator decision (forward edited synthetic / drop) on a server-issued hold id; nothing is sent to a target"},
	"/api/dominvader/messages/report":    {methods: []string{"POST"}, risk: riskLocal, summary: "private capability-authenticated extension worker untrusted message observation"},

	"/api/scanner/secrets": {
		// riskLocal: the secret scan reads responses burpsy already captured and sends nothing; the
		// switch changes which findings future captures file, which is this tool's own state.
		methods: []string{"GET", "PUT"}, risk: riskLocal,
		summary: "secret detection over every captured response — the gitleaks rule corpus plus burpsy's own provider rules, " +
			"raising a finding per leaked key with its rule, location and a redacted excerpt; off until switched on (burpsy-react-ui-8j0d)",
	},
	"/api/scanner/coverage": {
		methods: []string{"GET"}, risk: riskRead,
		summary: "what the check set covers, and what it declines to look at",
	},
	"/api/scanner/live": {
		methods: []string{"GET", "POST"}, risk: riskAttack,
		summary: "the live sweep over newly-completed proxied traffic; POST opts in",
	},
	"/api/scanner/passive-branch": {
		// riskLocal, and the reasoning belongs here rather than only in the handler: a passive sweep
		// SENDS NOTHING. It re-reads responses the store already holds, so copying /api/scanner/audit's
		// riskAttack by analogy would demand confirmation for an operation that touches no target —
		// which trains operators to click through the confirmations that matter. riskRead understates
		// it, because the sweep manufactures findings and findings are what an operator reports. It
		// mutates burpsy's own findings state and nothing else, which is riskLocal exactly.
		methods: []string{"POST"}, risk: riskLocal,
		summary: "Burp's \"Passively scan this branch\": re-run the passive set over one site-map " +
			"branch's already-captured exchanges, reporting scanned/out-of-scope/no-response as a partition",
	},
	// riskAttack, on both, and not because a POST here sends anything: it arms something that will.
	// A saved schedule starts a crawl or an audit against a live target at a wall-clock time with
	// nobody watching, which is strictly more than /api/crawl does — a crawl launched now is at least
	// observed. Deferring an attack is not a way to make launching it cheaper, and a class assigned by
	// "did this call put bytes on the wire" would let an unattended caller arm a nightly scan without
	// the confirmation it needs to launch one.
	"/api/schedules": {
		methods: []string{"GET", "POST"}, risk: riskAttack,
		summary: "the saved scheduled tasks, what the clock has done with them (fired, failed, missed, " +
			"unstarted) and the missed-window policy; POST arms a new one",
	},
	"/api/schedules/": {
		methods: []string{"PUT", "DELETE"}, risk: riskAttack, subPath: "nonesuch",
		summary: "replace or delete one schedule by name; a replace re-arms the timing and keeps the " +
			"run counters",
	},
	"/api/scope": {
		methods: []string{"GET", "POST"}, risk: riskScope,
		summary: "the engagement scope: what every sender is allowed to reach",
	},
	"/api/scope/check": {
		// riskRead, and deliberately not riskScope like /api/scope beside it: this reads the rules and
		// answers a question about a URL; it changes nothing and sends nothing. POST takes a list, which
		// is the only reason it is not GET alone (burpsy-react-ui-z5z3).
		methods: []string{"GET", "POST"}, risk: riskRead,
		summary: "is a URL in scope: GET ?url= or POST {urls:[…]} answers in_scope (retained, and sendable " +
			"by the tools), proxy_forwards, and the rule that decided",
	},
	"/api/search": {
		// riskRead, and it stays riskRead however much it scans. It sends nothing, changes nothing, and
		// returns only offsets into messages every other read route already serves — the rows it walks
		// are the same rows /api/history and /api/tools/log hand out without a gate. Calling it a
		// heavier read would not make it a different class, and the safe reading of an unscoped GET is
		// the one to keep: a gate here would train an unattended caller to confirm without reading.
		//
		// The scan is deliberately *not* bounded by the scope unless in_scope is sent: this is the one
		// search that crosses tools, and refusing to look at traffic burpsy already captured and already
		// shows in History would answer "no matches" for bytes the operator can see on screen.
		methods: []string{"GET"}, risk: riskRead,
		summary: "Burp's suite-wide search across Proxy, Crawler, Repeater, Intruder, Scanner and " +
			"Organizer traffic, with the case/regex/negative, in-scope, location and area axes; " +
			"returns matching exchanges plus byte offsets, never message copies",
	},
	"/api/sequencer/analyse": {
		methods: []string{"POST"}, risk: riskRead,
		summary: "statistical analysis of a token sample; sends nothing. disabled_tests leaves named tests " +
			"out of this one run (they are reported as not run); absent, the saved sequencer settings decide",
	},
	"/api/sequencer/settings": {
		methods: []string{"GET", "PUT"}, risk: riskLocal,
		summary: "Burp's Sequencer analysis settings under Burp's keys: sequencer.token_analysis.* (which " +
			"tests run) and token_handling.base_64_decode_before_analyzing; saved with the project and applied " +
			"to every analysis that does not name its own tests",
	},
	"/api/sequencer/capture": {
		methods: []string{"POST"}, risk: riskAttack,
		summary: "start a capture: N sends of one request, one token extracted per response",
	},
	"/api/sequencer/capture/": {
		// Two operations under one subtree, and deliberately different verbs: reading a token list does
		// not change state, stopping a capture does. Unguarded, `GET .../stop` answered {"stopped":true}
		// — a state change reported for a request that could not have caused one.
		methods: []string{"GET", "POST"}, risk: riskRead, subPath: "1",
		summary: "GET {id}: one capture's accumulated tokens. POST stop: cancel a running capture",
	},
	"/api/session/cookies": {
		// POST is the jar's write surface (dkb): set, remove, clear — Burp's cookie jar dialog
		// verbs. riskCredential because the jar is exactly the credential store it reads.
		methods: []string{"GET", "POST"}, risk: riskCredential,
		summary: "the coordinator's cookie jar, per authority, with set/remove/clear writes " +
			"(see HONEST-03)",
	},
	"/api/session/login": {
		methods: []string{"POST"}, risk: riskCredential,
		summary: "run a login macro, or probe whether the current session is still valid",
	},
	"/api/session/prompts": {
		// The pending browser-recovery prompts, and resolving one. GET is riskRead: it lists which
		// session rules are stuck waiting on a human, which is a reading of state and sends nothing.
		// The resolve route is the POST under it.
		methods: []string{"GET"}, risk: riskRead,
		summary: "the pending browser-recovery prompts: which session rules are suspended waiting for " +
			"the operator to recover a login in their own browser (burpsy-react-ui-dq1g)",
	},
	"/api/session/prompts/": {
		// riskCredential, not riskLocal: resolving a prompt tells burpsy the operator has recovered
		// the session, and the engine then replays the stored login itself — so an unattended caller
		// who can resolve prompts can put burpsy's credentials back on the wire. That is the same
		// authority as replaying a macro, which is why it sits in this class.
		methods: []string{"POST"}, risk: riskCredential, subPath: "1/resolve",
		summary: "resolve one browser-recovery prompt by id: the operator says the session is " +
			"recovered, or that they could not, and the crawl or audit waiting on it continues or gives up",
	},
	"/api/session/macro-steps": {
		// riskRead, not riskCredential: the endpoint converts stored requests the engagement already
		// captured and sends nothing. The requests carry credentials, which is why it is not riskLocal
		// either — an unattended caller gets a reading of the traffic history out of it, so it sits
		// with the other reads over that history rather than with the rules that replay it.
		methods: []string{"POST"}, risk: riskRead,
		summary: "the macro recorder: turn selected Proxy-history rows into macro steps, naming any row " +
			"that could not be converted instead of dropping it (burpsy-react-ui-escl)",
	},
	"/api/session/rules": {
		methods: []string{"GET", "POST"}, risk: riskCredential,
		summary: "session handling rules: which hosts get re-authenticated, and how",
	},
	"/api/session/rules/": {
		// riskCredential stays for the whole subtree even though /test only sends: the macro steps
		// carry the rule's login credentials and the run replays them at the target, and the 405
		// test drives verbs the manifest lists — POST here is the Test-macro dry-run plus the
		// /run and /move actions that already lived under it.
		methods: []string{"PUT", "DELETE", "POST"}, risk: riskCredential, subPath: "1",
		// Named per action so the 405 fallback can answer Allow for the action the caller
		// actually hit (TestSessionRuleMoveRejectsOtherMethods pins "POST" for /move), and so
		// the sweep reaches each action with its own verb set rather than the subtree union.
		actionPaths: map[string][]string{"1/run": {"POST"}, "1/test": {"POST"}, "1/move": {"POST"}},
		summary: "one session rule by id: PUT replaces it (including macro promotion), DELETE removes it; " +
			"POST {id}/run replays the macro through the sender, POST {id}/test is Burp's Test macro — a " +
			"dry-run reporting each step's sent form, response, set cookies and extraction outcomes " +
			"(no login-run memory is written), POST {id}/move reorders the rule",
	},
	"/api/session/trace": {
		methods: []string{"GET"}, risk: riskRead,
		summary: "the session-handling tracer's recorded entries, and whether it is recording",
	},
	"/api/session/trace/enable": {
		// riskLocal: the toggle writes burpsy's own tracing state and sends nothing; the
		// overhead Burp warns about lands on requests the engine already makes, not on new
		// egress.
		methods: []string{"POST"}, risk: riskLocal,
		summary: "turn the session-handling tracer on or off (off by default — it imposes a per-request overhead, which is why it is opt-in)",
	},
	"/api/settings/triage": {
		// riskCredential: the PUT stores an API key. GET is riskRead-shaped but shares the door.
		methods: []string{"GET", "PUT"}, risk: riskCredential,
		summary: "the LLM triage endpoint configuration (base URL, model, key, enabled) — the key is write-only on the wire",
	},
	"/api/sitemap": {
		// DELETE is riskDestructive, not riskLocal, and the line between them is evidence: the
		// suppression never touches the stored exchanges (that is the recorded decision on
		// burpsy-react-ui-10e — history, findings and audit references keep naming them), but it
		// removes a branch from the view an operator reasons and reports from, and a branch that
		// stops being visible stops being worked. The same shape as DELETE /api/history/rows. GET is
		// riskRead unchanged.
		// POST is riskLocal: it records a host/path the operator wrote down. It sends no traffic, so
		// it cannot touch the target, and the nodes it adds live in their own store rather than in the
		// observed tree — the map then answers "what did we see" and "what did you note" as two
		// questions rather than pretending the second is the first (amu).
		methods: []string{"GET", "POST", "DELETE"}, risk: riskDestructive,
		summary: "GET: the site map as a real tree, with per-subtree exchange counts. POST: " +
			"record a host/path the operator added, kept separate from observed nodes and marked as " +
			"such. DELETE: suppress a host, branch or single node from the map — a view-level removal " +
			"that keeps the underlying exchanges and stays out across rebuilds and re-captures",
	},
	"/api/sitemap/record": {
		// riskLocal, following /api/issues/record rather than /api/sitemap's riskDestructive: recording
		// an exchange by id adds to burpsy's own view and removes nothing (burpsy-react-ui-4bfp).
		methods: []string{"POST"}, risk: riskLocal,
		summary: "record a captured exchange into the site map by id (Burp's add_to_sitemap): already on " +
			"the map, or pinned past the Delete host/branch/item suppression that hid it",
	},
	"/api/skills": {
		// riskRead: the library loaded from the operator's -skills directory, read-only (ulsy).
		methods: []string{"GET"}, risk: riskRead,
		summary: "the skill library from -skills DIR: each skill, the tools it calls, whether it is available " +
			"and disabled for this project, and every refused manifest with why",
	},
	"/api/skills/": {
		methods: []string{"GET"}, risk: riskRead, subPath: "none",
		summary: "one skill with its prompt rendered from ?argument=value; 409 when disabled or unavailable",
	},
	"/api/skills/disabled": {
		// riskLocal: a project setting naming which loaded skills are switched off; sends nothing.
		methods: []string{"PUT"}, risk: riskLocal,
		summary: "set which skills this project turns off: {\"disabled\":[names]}, the whole list",
	},
	"/api/stats": {
		methods: []string{"GET"}, risk: riskRead,
		summary: "proxy counters, tool counts, and the DOM engine's admission state",
	},
	"/api/tasks/pause": {
		// The suite-wide gate (burpsy-react-ui-8gw): Burp's dashboardPauseAllTasksButton. A literal
		// beside the {id} patterns - ServeMux resolves it ahead of "/api/tasks/{id}", so this never
		// parses "pause" as an id (TestTasksSuiteWidePauseResumeAreLiterals pins the precedence).
		methods: []string{"POST"}, risk: riskLocal,
		summary: "hold every running task at its next gate; the answer's count says how many were holding",
	},
	"/api/tasks/resume": {
		methods: []string{"POST"}, risk: riskLocal,
		summary: "release the suite-wide hold; the answer's count says how many were holding",
	},
	"/api/tasks/{id}": {
		// DELETE is riskLocal, not riskDestructive, and the line matters: it removes a ROW from the
		// task list, not any evidence the row pointed at. The crawl's findings, the exchanges it
		// captured and its coverage report all live elsewhere and survive it — the list entry is
		// burpsy's own state about past work, which is riskLocal's definition.
		// GET reads one task and, for async work (POST /api/audit/{id} {"async":true}), its
		// finished body (burpsy-react-ui-wdza). A read under riskLocal changes nothing.
		methods: []string{"GET", "DELETE"}, risk: riskLocal, subPath: "1",
		summary: "GET: one task's row and an async task's finished body. " +
			"DELETE removes a finished task's row (a running task answers 409 — cancel first)",
	},
	"/api/tasks/{id}/again": {
		// riskLocal by its route: it starts a crawl, but /api/crawl — the same act from the New
		// scan dialog — is classified by what the crawl does after the start, which the confirmation
		// gate already covers at its own route.
		methods: []string{"POST"}, risk: riskLocal, subPath: "1",
		summary: "re-run a crawl task at its target (only crawl kind re-runs; 409 otherwise)",
	},
	"/api/tasks/{id}/cancel": {
		methods: []string{"POST"}, risk: riskLocal, subPath: "1",
		summary: "ask a running task to stop (unknown or finished id answers 404)",
	},
	"/api/tasks/{id}/pause": {
		methods: []string{"POST"}, risk: riskLocal, subPath: "1",
		summary: "hold one task at its next gate (a task kind that never reaches a gate answers 409; g0ba)",
	},
	"/api/tasks/{id}/resume": {
		methods: []string{"POST"}, risk: riskLocal, subPath: "1",
		summary: "release one task's hold (a task kind that never reaches a gate answers 409; g0ba)",
	},
	"/api/tools/compare": {
		methods: []string{"POST"}, risk: riskRead,
		summary: "diff two messages or two pasted buffers",
	},
	"/api/tools/compare-sitemaps": {
		methods: []string{"POST"}, risk: riskRead,
		summary: "the path-set diff between two runs' site maps — Burp's Compare site maps, the " +
			"access-control view: what one crawl reached that the other did not",
	},
	"/api/tools/decode": {
		methods: []string{"POST"}, risk: riskRead,
		summary: "run one decode layer over a buffer, reporting whether it was partial",
	},
	"/api/tools/encode": {
		methods: []string{"POST"}, risk: riskRead,
		summary: "run one encode layer over a buffer",
	},
	"/api/tools/hash": {
		methods: []string{"POST"}, risk: riskRead,
		summary: "hash a buffer under a named algorithm",
	},
	"/api/tools/log": {
		// DELETE clears the whole log, which nothing documented and nothing had classified until the
		// 405 test found the verb reachable. See riskDestructive. POST toggles one tool's capture
		// axis — the destructive *incoming* arm: switching a tool off means its next requests are
		// sent and deliberately not recorded, so it is a local-write to a destructive fact rather
		// than a destructive act in itself.
		methods: []string{"GET", "POST", "DELETE"}, risk: riskDestructive,
		summary: "GET: every request this process sent, per tool, with what it dropped at the bound and " +
			"the capture axis (which tools are recorded at all, and how many requests went unrecorded). " +
			"POST: turn one tool's capture on or off. DELETE: clears it, discarding the record of what was sent to the target",
	},
	"/api/tools/log/": {
		// PATCH annotates one entry with a comment (burpsy-react-ui-5da) — a local write to the
		// running process's log, the same class as the organizer's POST edit. Not GET: the list
		// endpoint at /api/tools/log already returns the entries, so a bare GET here answers 405.
		methods: []string{"PATCH"}, risk: riskLocal, subPath: "1",
		summary: "one log entry by id: PATCH sets (or clears) its comment",
	},
	"/api/tools/organizer": {
		methods: []string{"GET", "POST"}, risk: riskLocal,
		summary: "the organizer's saved items",
	},
	"/api/tools/organizer/": {
		// POST updates title/note/highlight, PUT .../status sets the workflow status, DELETE removes.
		// Not GET. The status PUT exists because a status change is one deliberate operator decision
		// (Burp applies it from the item's status submenu), kept off the POST edit form the same way
		// the store keeps SetStatus apart from Update; an unrepresentable status is a 400 naming the
		// valid set, which is why PUT needs a real handler rather than a bare 405.
		methods: []string{"POST", "PUT", "DELETE"}, risk: riskLocal, subPath: "1",
		summary: "one organizer item by id: POST updates title/note/highlight, PUT status sets the workflow status, DELETE removes it",
	},
	"/api/tools/organizer/collections": {
		// POST creates a named group; GET is the organizer list's partner but the list endpoint
		// already carries collections, so a bare GET here answers 405 rather than a second copy
		// of the same shape that could drift from it.
		methods: []string{"POST"}, risk: riskLocal,
		summary: "create a collection: POST {name}; a duplicate name is a 400",
	},
	"/api/tools/organizer/collections/": {
		// The collections surface: PUT {id} renames / sets the About note, POST {id}/duplicate
		// copies the group with its items under fresh ids, PUT {id}/items moves or copies items
		// in (and PUT /inbox moves them back), DELETE {id} deletes with ?items=inbox (default,
		// unlink) or ?items=delete. One entry because one handler owns the whole subtree and the
		// id space is shared with the inbox literal.
		methods: []string{"PUT", "POST", "DELETE"}, risk: riskLocal, subPath: "1",
		summary: "organizer collections: rename/note, duplicate, move/copy items (inbox literal), delete with items inbox|delete",
	},
	"/api/tools/rules": {
		// PUT, not POST: the whole rule set is replaced as a document rather than appended to, which is
		// the right shape for a list whose order is its semantics.
		methods: []string{"GET", "PUT"}, risk: riskLocal,
		summary: "match & replace rules applied to proxied traffic; PUT replaces the whole set",
	},
	"/api/tools/rules/test": {
		methods: []string{"POST"}, risk: riskRead,
		summary: "dry-run the match & replace set against a buffer without installing it",
	},
	"/api/wordlists": {
		methods: []string{"GET"}, risk: riskRead,
		summary: "the wordlist inventory: the lists bundled into the binary (with payload counts) and the operator's uploads, so a tool points once instead of per attack",
	},
	"/api/ws/connections": {
		methods: []string{"GET"}, risk: riskRead,
		summary: "WebSocket connections the proxy has relayed",
	},
	"/api/ws/history": {
		methods: []string{"GET"}, risk: riskRead,
		summary: "WebSocket frames, per connection",
	},
	"/api/ws/message/{id}": {
		methods: []string{"GET"}, risk: riskRead, subPath: "1",
		summary: "one WebSocket frame's payload, as text or hex",
	},
	"/ca.crt": {
		methods: []string{"GET"}, risk: riskAsset,
		summary: "the CA certificate the proxy signs leaves with, so a browser can be told to trust it",
	}, "/reissue/": {
		// The minted URL's fetch surface, outside /api on purpose: it is what the operator
		// pastes into their browser, and it spends a token before anything else. riskEgress
		// because the fetch is the send; the token is the operator's own mint.
		methods: []string{"GET"}, risk: riskEgress, subPath: "token",
		summary: "spend one one-shot re-issue token: re-send its exchange under the minted session " +
			"variant, record the outcome, and answer with a page that names the variant",
	},
}
