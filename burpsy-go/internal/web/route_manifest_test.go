package web

import (
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// The route manifest.
//
// # Why this exists
//
// `setupRoutes` is one long run of `mux.HandleFunc` calls in one function, and until now nothing checked it. A
// route deleted or renamed in a refactor produced a 404 in production — discovered by an operator
// clicking something that used to work, with no test going red anywhere. That is a bad failure for a
// surface the UI is written against, and a worse one for the API surface this port is in the middle of
// tripling: an area that adds eight routes and drops one on merge would ship silently.
//
// So the expected set lives here, as data, with a one-line descriptor per route. A dropped
// registration now fails `Test_every_registered_route_is_in_the_manifest` **by name**, which tells the
// next reader what broke instead of leaving them to bisect a 404.
//
// # Why it is parsed out of the source rather than read off the mux
//
// `http.ServeMux` has no API to enumerate its patterns — not in 1.22's rewrite either. The three
// alternatives were: wrap HandleFunc in a recording helper (invasive, and a route registered directly
// would escape the recorder — exactly the case this test is for); probe every path in the manifest and
// check it does not 404 (proves the manifest's routes exist, but cannot notice a route that exists and
// is *not* in the manifest); or read the registrations out of the source. The third is the only one
// that catches both directions, so `setupRoutes` is parsed with go/ast.
//
// This is not as fragile as it sounds: it walks the AST for calls whose selector is `HandleFunc` and
// takes their first argument when it is a string literal, so reformatting, reordering and comment
// changes are all invisible to it. What it would miss is a pattern built at runtime from a variable —
// and `Test_every_route_pattern_is_a_literal` fails if anyone introduces one, rather than letting the
// manifest quietly stop covering it.
//
// # What a descriptor is for
//
// `summary` is documentation. `methods` is what the 405 test drives. `risk` is the field MCP-02 needs:
// scope-widening, attack-launching and credential-reading calls require per-call operator confirmation
// when driven by a model rather than by a human clicking, and the only place that can be declared
// without every future facade re-deciding it is next to the route.

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
	// set — "1/cancel": {"POST"} under "/api/tasks/". subPath alone cannot express these: one
	// subtree can route "/api/tasks/1" to DELETE and "/api/tasks/1/cancel" to POST, and a single
	// concrete path tests exactly one of them.
	//
	// This exists because that gap shipped a bug. The /api/tasks/ entry's subPath was narrowed from
	// "{id}/cancel" to "1" in the same commit that moved cancel into an inline branch with no verb
	// guard, so GET /api/tasks/pause answered 200 and set the suite-wide pause
	// (burpsy-react-ui-0gg5). Naming each action path here is what makes the 405 sweep reach them.
	actionPaths map[string][]string
	// pathValidatedFirst marks a handler that resolves its path segment *before* checking the method,
	// so a bogus segment answers 404 rather than 405 whatever the verb. Correct behaviour — "there is
	// no such direction" is a truer answer than "wrong verb" — but it means the 405 test has to send a
	// valid segment, which is what subPath supplies.
	pathValidatedFirst bool
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
	"/api/collaborator/interaction/": {
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
		methods: []string{"POST"}, risk: riskScope,
		summary: "point this installation at an interaction server without restarting: a URL, or " +
			"\"public\" for interactsh's shared pool; refuses with 409 once a channel is registered",
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
	"/api/dashboard": {
		methods: []string{"GET"}, risk: riskRead,
		summary: "running tasks, the activity log, and every coverage summary with its breakdown",
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
	"/api/exchange/in-browser/": {
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
	"/api/extensions/unload": {
		methods: []string{"POST"}, risk: riskLocal,
		summary: "stop a running plugin: ask it to exit, then close its stdin, then kill it",
	},
	"/api/findings": {
		methods: []string{"GET"}, risk: riskRead,
		summary: "legacy alias for /api/issues",
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
	"/api/history": {
		// DELETE is Burp's "Delete items"/"Clear (tool)" (r6li): a tombstone on the operator's
		// view, not on the stored bytes — positional ids stay stable, so the read route's contract
		// is untouched.
		methods: []string{"GET", "DELETE"}, risk: riskRead,
		summary: "proxy history, filtered by the typed query DSL; DELETE removes rows from the " +
			"operator's view (ids body) or clears the capture (no body)",
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
	"/api/intercept/annotate/": {
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
	"/api/intercept/rules/": {
		// "requests" and "responses", plural — see directionFor. The singular was a guess when this
		// entry was first written, and it answered 404 "Unknown direction" for every verb, which the
		// 405 test read as a missing guard. The handler was right; the manifest was wrong.
		methods: []string{"GET", "PUT"}, risk: riskLocal, subPath: "requests",
		pathValidatedFirst: true,
		summary:            "the match rules deciding which messages are held, per direction",
	},
	"/api/intercept/startup": {
		// Burp's "Default Proxy interception state" (burpsy-react-ui-7vy): a preference about
		// the NEXT server start, not a live toggle — /enable stays the switch. Writes only the
		// operator's own preference, so riskLocal like the rest of the intercept configuration.
		methods: []string{"GET", "POST"}, risk: riskLocal,
		summary: "read or set the startup interception preference: on, off, or restore-last-state",
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
	"/api/issues/record": {
		// POST creates the operator's hand-recorded finding and attaches it to one exchange. It
		// writes engagement evidence (like the triage PUT beside it) but discards nothing, so
		// riskLocal is the honest class; the subtree's riskDestructive is about DELETE, not this.
		methods: []string{"POST"}, risk: riskLocal,
		summary: "record an issue by hand against one exchange (Burp's 'Record an issue')",
	},
	"/api/message/": {
		methods: []string{"GET"}, risk: riskRead, subPath: "0",
		summary: "raw bytes of one stored message, with pretty and hex views",
	},
	"/api/network/auth": {
		// riskCredential, and not riskLocal, because that is what these rows are: an
		// operator's account on the target. A GET cannot disclose the password — the wire
		// shape has no field for it — but it does enumerate which accounts are configured
		// against which hosts, and a POST arms every subsequent send to replay one. Both
		// are things an unattended caller should have to ask about.
		methods: []string{"GET", "POST", "DELETE"}, risk: riskCredential,
		summary: "platform authentication: per-host HTTP credentials (Basic and Digest; NTLM and Negotiate are not implemented). Never serves a password",
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
	"/api/proxy/listener": {
		methods: []string{"GET", "PUT", "POST", "DELETE"}, risk: riskLocal,
		summary: "the proxy's listeners, Burp's list rather than one socket: GET answers every listener with its resolved address, redirect target, force-TLS and invisible-proxying setting; POST adds one, PUT ?id= replaces one's settings (bodied PUT with no id is the legacy re-bind of the boot listener), DELETE ?id= removes one. Every listed listener is a socket the accept loop is serving — a bind that fails is refused with the reason and nothing is added — and the new socket opens before the old closes, so a failed move leaves the listener serving. The boot listener (-proxy-bind) is re-bindable but not removable. Not persisted: -proxy-bind stays authoritative at boot",
	},
	"/api/proxy/options": {
		methods: []string{"GET", "PUT"}, risk: riskLocal,
		summary: "the proxy's live response modification rules and strip-Accept-Encoding knob, with the outcome counters",
	},
	"/api/proxy/passthrough": {
		methods: []string{"GET", "POST", "DELETE"}, risk: riskLocal,
		summary: "the TLS passthrough host-pattern list, live: add and remove without restarting the proxy",
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
	"/api/report/": {
		methods: []string{"GET"}, risk: riskRead, subPath: "json",
		summary: "export findings as json, sarif or html",
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
		// POST {id}/again only — Burp's "Audit again". riskAttack rather than riskLocal because it is
		// not a state change on a row: it starts an audit that sends real traffic, through the same
		// runAudit as /api/audit/{id}. A verb in the path is what makes that classifiable by reading
		// the route; a PATCH of a "state" field that happened to launch a scan would not be.
		methods: []string{"POST"}, risk: riskAttack, subPath: "0/again",
		pathValidatedFirst: true,
		summary:            "re-audit one queued item: POST {id}/again, Burp's auditItemContextMenuAuditAgain",
	},
	"/api/scanner/config": {
		methods: []string{"GET", "PUT"}, risk: riskScope,
		summary: "the audit families and performance knobs, readable and editable while the process runs; PUT persists the overrides",
	},
	"/api/scanner/configs": {
		methods: []string{"GET", "POST", "PUT", "DELETE"}, risk: riskLocal,
		summary: "the scan configurations an audit can run under: the shipped presets, generated from the table rather than listed by hand, plus the operator's own saved ones (burpsy-react-ui-uxcs) in the same list and marked shipped:false. POST/PUT save, clone or rename one; DELETE removes one. A shipped name is read-only and every write refuses it with 409 — two lists answering the same name differently is what the refusal prevents. riskLocal rather than riskRead because the writes change what a later audit runs under, and riskDestructive is reserved for discarding recorded evidence; a deleted configuration is a setting, not a finding",
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
		summary: "statistical analysis of a token sample; sends nothing",
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
		summary: "one session rule by id: PUT replaces it (including macro promotion), DELETE removes it; " +
			"POST {id}/run replays the macro through the sender, POST {id}/test is Burp's Test macro — a " +
			"dry-run reporting each step's sent form, response, set cookies and extraction outcomes " +
			"(no login-run memory is written), POST {id}/move reorders the rule",
	},
	"/api/sitemap": {
		// DELETE is riskDestructive, not riskLocal, and the line between them is evidence: the
		// suppression never touches the stored exchanges (that is the recorded decision on
		// burpsy-react-ui-10e — history, findings and audit references keep naming them), but it
		// removes a branch from the view an operator reasons and reports from, and a branch that
		// stops being visible stops being worked. The same shape as DELETE /api/history. GET is
		// riskRead unchanged.
		methods: []string{"GET", "DELETE"}, risk: riskDestructive,
		summary: "GET: the site map as a real tree, with per-subtree exchange counts. DELETE: " +
			"suppress a host, branch or single node from the map — a view-level removal that keeps the " +
			"underlying exchanges and stays out across rebuilds and re-captures",
	},
	"/api/stats": {
		methods: []string{"GET"}, risk: riskRead,
		summary: "proxy counters, tool counts, and the DOM engine's admission state",
	},
	"/api/tasks/": {
		// DELETE is riskLocal, not riskDestructive, and the line matters: it removes a ROW from the
		// task list, not any evidence the row pointed at. The crawl's findings, the exchanges it
		// captured and its coverage report all live elsewhere and survive it — the list entry is
		// burpsy's own state about past work, which is riskLocal's definition. POST {id}/again is
		// riskLocal too by its route: it starts a crawl, but /api/crawl — the same act from the New
		// scan dialog — is classified by what the crawl does after the start, which the confirmation
		// gate already covers at its own route.
		methods: []string{"POST", "DELETE"}, risk: riskLocal, subPath: "1",
		actionPaths: map[string][]string{
			"1/cancel": {"POST"},
			"pause":    {"POST"},
			"resume":   {"POST"},
		},
		summary: "POST {id}/cancel asks a running task to stop (unknown or finished id answers 404); " +
			"POST {id}/again re-runs a crawl task at its target (only crawl kind re-runs; 409 otherwise); " +
			"DELETE {id} removes a finished task's row (a running task answers 409 — cancel first)",
	},
	"/api/tools/compare": {
		methods: []string{"POST"}, risk: riskRead,
		summary: "diff two messages or two pasted buffers",
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
	"/api/ws/connections": {
		methods: []string{"GET"}, risk: riskRead,
		summary: "WebSocket connections the proxy has relayed",
	},
	"/api/ws/history": {
		methods: []string{"GET"}, risk: riskRead,
		summary: "WebSocket frames, per connection",
	},
	"/api/ws/message/": {
		methods: []string{"GET"}, risk: riskRead, subPath: "1",
		summary: "one WebSocket frame's payload, as text or hex",
	},
	"/ca.crt": {
		methods: []string{"GET"}, risk: riskAsset,
		summary: "the CA certificate the proxy signs leaves with, so a browser can be told to trust it",
	},
}

// registeredPatterns parses setupRoutes and returns every pattern it registers, plus every call whose
// pattern was not a string literal. See the file comment for why this is read out of the source.
func registeredPatterns(t *testing.T) (literal []string, nonLiteral int) {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "server.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse server.go: %v", err)
	}
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "HandleFunc" || len(call.Args) == 0 {
			return true
		}
		lit, ok := call.Args[0].(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			nonLiteral++
			return true
		}
		pattern, err := strconv.Unquote(lit.Value)
		if err != nil {
			nonLiteral++
			return true
		}
		literal = append(literal, pattern)
		return true
	})
	return literal, nonLiteral
}

func Test_every_registered_route_is_in_the_manifest(t *testing.T) {
	patterns, _ := registeredPatterns(t)
	if len(patterns) == 0 {
		t.Fatal("parsed no routes out of server.go; the AST walk is broken, not the routing")
	}
	seen := make(map[string]bool, len(patterns))
	for _, pattern := range patterns {
		seen[pattern] = true
		if _, ok := manifest[pattern]; !ok {
			t.Errorf("route %q is registered but has no manifest entry.\n"+
				"Add one: what it does, which verbs it answers, and its risk class — the risk class is "+
				"what decides whether an unattended caller has to confirm before invoking it.", pattern)
		}
	}
	// The other direction, and the reason this test is worth having: a route dropped in a refactor
	// used to surface as a 404 that an operator found by clicking something that had worked.
	for pattern := range manifest {
		if !seen[pattern] {
			t.Errorf("route %q is in the manifest but nothing registers it. Either setupRoutes lost a "+
				"HandleFunc call, or the route was deliberately removed and this entry should go with it.",
				pattern)
		}
	}
	// Registered twice would panic at startup, so this can only fire if the panic is ever relaxed —
	// but the duplicate is worth naming here rather than debugging as a boot crash.
	counts := map[string]int{}
	for _, pattern := range patterns {
		counts[pattern]++
	}
	for pattern, n := range counts {
		if n > 1 {
			t.Errorf("route %q is registered %d times; http.ServeMux panics on this", pattern, n)
		}
	}
}

// A pattern built from a variable would be invisible to the manifest, so it is refused rather than
// silently uncovered. If a future area genuinely needs one, this test is the place to decide how the
// manifest represents it — not the place to delete.
func Test_every_route_pattern_is_a_literal(t *testing.T) {
	_, nonLiteral := registeredPatterns(t)
	if nonLiteral > 0 {
		t.Errorf("%d route(s) registered with a non-literal pattern; the manifest cannot cover those",
			nonLiteral)
	}
}

// Sorted, because an unsorted literal of this size is a merge-conflict generator: two areas appending
// their routes at the end of a map both touch the same line.
func Test_the_manifest_is_sorted_by_pattern(t *testing.T) {
	got := make([]string, 0, len(manifest))
	for pattern := range manifest {
		got = append(got, pattern)
	}
	// The manifest is a map, so source order is not observable at runtime — the source itself is what
	// has to be ordered. Read it back and check the entries appear in sorted order.
	sorted := append([]string(nil), got...)
	sort.Strings(sorted)
	source, err := parser.ParseFile(token.NewFileSet(), "route_manifest_test.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse this file: %v", err)
	}
	var inSource []string
	ast.Inspect(source, func(n ast.Node) bool {
		kv, ok := n.(*ast.KeyValueExpr)
		if !ok {
			return true
		}
		if lit, ok := kv.Key.(*ast.BasicLit); ok && lit.Kind == token.STRING {
			if pattern, err := strconv.Unquote(lit.Value); err == nil && strings.HasPrefix(pattern, "/") {
				inSource = append(inSource, pattern)
			}
		}
		return true
	})
	if len(inSource) != len(manifest) {
		t.Skipf("found %d '/'-prefixed keys in source against %d manifest entries; ordering not checked",
			len(inSource), len(manifest))
	}
	if !sort.StringsAreSorted(inSource) {
		for i := 1; i < len(inSource); i++ {
			if inSource[i-1] > inSource[i] {
				t.Errorf("manifest is out of order: %q precedes %q", inSource[i-1], inSource[i])
			}
		}
	}
}

// allMethods is every verb the 405 test may send. TRACE and CONNECT are left out: neither is something
// a caller sends to this API, and CONNECT has a meaning to the proxy that has nothing to do with here.
var allMethods = []string{
	http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut,
	http.MethodPatch, http.MethodDelete, http.MethodOptions,
}

// Every route answers 405 to a verb it does not implement.
//
// Table-driven over the manifest, so a new route gets this check by existing rather than by its author
// remembering. The class it protects against is small but real: a handler with no verb guard decodes a
// GET's absent body and answers "Invalid request body" — a complaint about the payload for what is
// actually a wrong-method call, which sends the caller looking in the wrong place. Two routes were in
// that state (handleIntruderPoints, handleSequencerCapture) before this test existed.
//
// Phase 1's migration to Go 1.22 `"POST /api/..."` patterns makes the whole class unrepresentable. At
// that point this test stops being a check on handler discipline and becomes a check on the manifest's
// accuracy, which is still worth running.
func Test_every_route_rejects_a_verb_it_does_not_implement(t *testing.T) {
	// s is built once and shared by every subtest below, unlike everywhere else in this package where
	// a fresh server per test is the correct choice. Building a full Server (routes, sitemap,
	// dashboard registries, ...) once instead of once per (route, disallowed verb) pair is what turns
	// this table's ~190 cases from a quadratic cost into a linear one.
	//
	// What makes that safe, stated accurately: the subtests here are sequential - none calls
	// t.Parallel() - and every 405 in this package comes from a hand-written verb guard inside the
	// handler, which in each case precedes any state mutation. It is NOT true that ServeMux rejects a
	// wrong verb before the handler runs; this package does not use Go 1.22 method patterns
	// ("POST /api/..."), as the note above about that migration being future work says. An earlier
	// version of this comment claimed the structural guarantee, which would have been the better
	// reason had it existed - and will be, once those patterns land.
	s := newTestServer()
	for pattern, spec := range manifest {
		// The UI catch-all deliberately serves the SPA for anything it does not recognise, so it has no
		// wrong-verb answer to give. Asserting one would be asserting a behaviour nobody wants.
		if pattern == "/" {
			continue
		}
		allowed := make(map[string]bool, len(spec.methods))
		for _, method := range spec.methods {
			allowed[method] = true
		}
		// HEAD follows GET through net/http, so a GET route answering a HEAD is correct rather than a
		// missing guard. OPTIONS is left alone for the same reason: no route here implements CORS
		// preflight, and 405 for it is fine, but so is anything else.
		if allowed[http.MethodGet] {
			allowed[http.MethodHead] = true
		}

		path := pattern
		if spec.subPath != "" {
			path = pattern + spec.subPath
		}
		// Each action sub-path is swept with its own allowed set, so a verb guard missing from one
		// branch of a subtree cannot hide behind a sibling branch that has one.
		for suffix, verbs := range spec.actionPaths {
			actionAllowed := map[string]bool{}
			for _, v := range verbs {
				actionAllowed[v] = true
			}
			if actionAllowed[http.MethodGet] {
				actionAllowed[http.MethodHead] = true
			}
			actionPath := pattern + suffix
			for _, method := range allMethods {
				if actionAllowed[method] || method == http.MethodOptions {
					continue
				}
				t.Run(method+" "+actionPath, func(t *testing.T) {
					req := httptest.NewRequest(method, actionPath, nil)
					rec := httptest.NewRecorder()
					s.mux.ServeHTTP(rec, req)
					if rec.Code != http.StatusMethodNotAllowed {
						t.Errorf("%s %s answered %d, want 405. This is an ACTION path: it changes state, "+
							"so every verb it does not implement must be refused before it acts.\nbody: %s",
							method, actionPath, rec.Code, strings.TrimSpace(rec.Body.String()))
					}
				})
			}
		}
		for _, method := range allMethods {
			if allowed[method] || method == http.MethodOptions {
				continue
			}
			t.Run(method+" "+path, func(t *testing.T) {
				req := httptest.NewRequest(method, path, nil)
				rec := httptest.NewRecorder()
				s.mux.ServeHTTP(rec, req)
				if rec.Code != http.StatusMethodNotAllowed {
					t.Errorf("%s %s answered %d, want 405.\nEither the handler is missing a verb guard, "+
						"or the manifest's methods list for %q is wrong — check which before changing either.\n"+
						"body: %s", method, path, rec.Code, pattern, strings.TrimSpace(rec.Body.String()))
				}
			})
		}
	}
}

// Every route declares a risk class, and a summary that says what it does.
//
// This is the field MCP-02 needs: a model driving this API unattended must confirm before widening
// scope, launching an attack or reading credentials, and one shared server-side check can only enforce
// that if the declaration exists on every route. An empty risk class on a new route would make it
// invisible to that check — which is the failure mode where the confirmation gate looks like it covers
// everything and quietly does not.
func Test_every_route_declares_a_risk_class_and_a_summary(t *testing.T) {
	valid := map[riskClass]bool{
		riskRead: true, riskLocal: true, riskEgress: true, riskAttack: true,
		riskScope: true, riskCredential: true, riskAsset: true, riskDestructive: true,
		riskExecute: true,
	}
	for pattern, spec := range manifest {
		if !valid[spec.risk] {
			t.Errorf("route %q has risk class %q, which is not one of the declared classes", pattern, spec.risk)
		}
		if strings.TrimSpace(spec.summary) == "" {
			t.Errorf("route %q has no summary", pattern)
		}
		if len(spec.methods) == 0 {
			t.Errorf("route %q lists no methods, so nothing can be asserted about it", pattern)
		}
		// A subtree pattern is not a requestable URL: "/api/audit/" with no id is not what any caller
		// sends. Without a concrete segment the 405 test would exercise a branch no operator reaches.
		if strings.HasSuffix(pattern, "/") && pattern != "/" && spec.subPath == "" {
			t.Errorf("route %q is a subtree pattern with no subPath, so it is tested at a URL nobody requests",
				pattern)
		}
	}
}

// Every route that can send unbounded traffic or read a secret is one an unattended caller must
// confirm. Asserted as a set rather than per route so that adding a facade cannot quietly drop one out
// of the confirmation-worthy list — the count is stated, and changing it is a deliberate edit with a
// reason, not a side effect.
func Test_the_confirmation_worthy_routes_are_the_ones_we_think_they_are(t *testing.T) {
	var attack, scope, credential, destructive, execute []string
	for pattern, spec := range manifest {
		switch spec.risk {
		case riskAttack:
			attack = append(attack, pattern)
		case riskScope:
			scope = append(scope, pattern)
		case riskCredential:
			credential = append(credential, pattern)
		case riskDestructive:
			destructive = append(destructive, pattern)
		case riskExecute:
			execute = append(execute, pattern)
		}
	}
	sort.Strings(attack)
	sort.Strings(scope)
	sort.Strings(credential)
	sort.Strings(destructive)
	sort.Strings(execute)

	wantAttack := []string{
		"/api/apiscan", "/api/audit/", "/api/audit/selected", "/api/crawl", "/api/discovery", "/api/intruder/run", "/api/scanner/audit",
		// "Audit again" belongs here for the same reason /api/audit/ does: it re-runs the whole check set
		// against a live target through runAudit. That it is spelled as an action on an existing queue
		// row does not make it cheaper than a first audit — AuditWithin gives it a fresh admission
		// ledger precisely so that it is not.
		"/api/scanner/audit-items/",
		"/api/scanner/live",
		// The two schedule routes arm a crawl or an audit to run unattended at a wall-clock time. See
		// their manifest entries: deferring an attack does not make arming it a lesser act than
		// launching one, and the run happens with nobody watching.
		"/api/schedules", "/api/schedules/",
		"/api/sequencer/capture",
	}
	// The pool routes join this class because a pool decides how hard every tool that names it may
	// hit the target; /api/network/settings joins it because a resolution override sends a request
	// the scope authorised by name to an address the operator chose. Neither escapes the gate — the
	// scope still says yes or no about the name — but both change where the authorised bytes land,
	// which is an engagement-shaped decision an unattended caller must confirm.
	// /api/collaborator/server joins for the same reason as /api/network/settings, one step further
	// out: it does not change where the *target's* bytes land, it chooses which third party is told
	// the engagement exists and receives its out-of-band callbacks. Minting is already riskEgress on
	// the grounds that a registration discloses the engagement; picking the recipient is the decision
	// behind that disclosure, and an unattended caller repointing it — or passing "public" to use
	// interactsh's shared pool — is exactly what a confirmation gate is for.
	wantScope := []string{
		"/api/collaborator/server", "/api/config/import", "/api/network/settings", "/api/pools",
		"/api/pools/", "/api/scanner/config", "/api/scope",
	}
	// /api/blindxss is in the credential class because a callback carries the victim browser's
	// `document.cookie`. It is the first entry there whose secret is not a credential burpsy holds
	// but a third party's, which is a stronger reason to require confirmation rather than a weaker
	// one.
	// The two /api/network routes join this class because they hold the operator's own
	// credentials for the target: an HTTP password and a TLS client identity. Neither
	// route can serve the secret itself, but enumerating which accounts are bound to which
	// hosts is a read worth confirming, and a write arms every later send to present one.
	//
	// Sorted, like the manifest itself, because two branches each appended their own routes to
	// this list and the merge produced two declarations of it — a set this test compares by
	// joined string cannot afford an arbitrary order.
	// /api/proxy/ca/import joins because it accepts a CA private key. It is the only entry here whose
	// credential is a *signing* one rather than an authenticating one, and the only route in the whole
	// manifest whose success invalidates work the operator has already done outside burpsy: the
	// previous CA stops signing, so every trust store they installed it into has to be updated.
	wantCredential := []string{
		"/api/blindxss",
		"/api/network/auth", "/api/network/client-certs",
		"/api/proxy/ca/import",
		"/api/session/cookies", "/api/session/login", "/api/session/rules", "/api/session/rules/",
	}
	equal := func(name string, got, want []string) {
		if strings.Join(got, " ") != strings.Join(want, " ") {
			t.Errorf("%s routes are\n  %v\nand this test expects\n  %v\n"+
				"If a route was added, add it here too and say why it belongs in this class. If one was "+
				"reclassified, that is a decision about whether an unattended caller may invoke it without "+
				"asking — make it deliberately.", name, got, want)
		}
	}
	equal("attack", attack, wantAttack)
	equal("scope", scope, wantScope)
	equal("credential", credential, wantCredential)
	// /api/backup joins the destructive class because it prunes: each call keeps only `retention`
	// snapshots and deletes the rest, so a caller invoking it in a loop rolls the whole retention
	// window off the disk irreversibly while every individual response reports success. Same shape as
	// clearing the tool log, which is what this class was created for.
	// /api/issues/ joins because its DELETE discards a finding — engagement evidence, per the class
	// definition. The PUT on the same subtree is only a triage note on evidence that survives it; it
	// rides along rather than splitting one pattern across two classes.
	// /api/sitemap joins because its DELETE removes a branch from the view the operator reasons and
	// reports from (burpsy-react-ui-10e). The stored exchanges survive — the recorded decision — so
	// it is the mildest member here; it sits in the class because making a worked branch invisible
	// is closer to "discard evidence" than to "write burpsy's own state", and because an unattended
	// caller trimming the map would hide what the operator is being shown.
	equal("destructive", destructive, []string{"/api/backup", "/api/issues/", "/api/sitemap", "/api/tools/log"})
	// Exactly two routes execute operator-supplied code, and both are on the Extender surface: one
	// starts a plugin, one invokes something a running plugin registered. A third appearing here means
	// something new can reach exec, which is a decision to make on purpose.
	equal("execute", execute, []string{"/api/extensions/invoke", "/api/extensions/load"})
}
