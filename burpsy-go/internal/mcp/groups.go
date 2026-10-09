package mcp

// The capability-grouped tool surface (burpsy-react-ui-cvzq).
//
// # Why a curated table, and what in it is curated
//
// The route surface (one tool per manifest pattern) cost a model 146 descriptors, including the
// console's own index.html and CA download, and two spellings of every subtree ("api_pools" and
// "api_pools_subtree"). Burp's agent registry is 54 tools in 12 groups, each with a one-line short
// description. This table is burpsy's equivalent: each grouped tool fronts a handful of operations,
// and each OPERATION is exactly one (route pattern, verb) pair of the manifest.
//
// Only three things here are authored: the tool's name, its group and its one-line description, and
// which operations it fronts. Everything else is read from the manifest at build time — each
// operation's summary, the risk class, whether confirmation is required — so a grouped descriptor
// cannot disagree with the gate any more than a route descriptor could. Two rules make the curation
// safe, and both are enforced by tests rather than by review:
//
//   - every manifest route-verb is reachable from exactly one grouped tool, or sits on notExposed with
//     a reason (TestEveryRouteVerbIsReachableFromExactlyOneGroupedTool);
//   - a grouped tool never spans two risk classes (TestNoGroupedToolSpansTwoRiskClasses), so the
//     tool-level annotations — readOnlyHint, requiresConfirmation, the class a host gates on — are
//     true of every operation the tool can reach.
//
// The group labels are Burp's own ToolGroup labels (burp/agentic/tool/ToolGroup.java), so an
// operator who knows Burp's agent surface recognises where a burpsy tool sits.

// Burp's ToolGroup labels, used verbatim.
const (
	groupCollaborator = "Collaborator"
	groupConfig       = "Configuration"
	groupDatasets     = "Datasets"
	groupFuzzing      = "Fuzzing"
	groupInternal     = "Internal"
	groupIssues       = "Issues"
	groupRequests     = "Requests & Responses"
	groupScanChecks   = "Scan Checks"
	groupScanning     = "Scanning & Auditing"
	groupScope        = "Scope & Sitemap"
	groupScripting    = "Scripting"
	groupUtilities    = "Utilities"
)

// groupSpec is one grouped tool: its name, Burp group, one-line description, and the operations it
// fronts. An operation is spelled "VERB /pattern" — the verb and the manifest pattern verbatim —
// because that spelling IS the binding: there is no second name to map back, and a model reading the
// enum sees exactly which HTTP call each choice makes.
type groupSpec struct {
	name  string
	group string
	short string
	ops   []string
}

// groupedTools is the curated table. Ordered by group then name; the order is the tools/list order.
var groupedTools = []groupSpec{
	// ---- Requests & Responses ------------------------------------------------------------------
	{
		name: "history", group: groupRequests,
		short: "Reads captured proxy traffic: the history list, one exchange, a stored message, a suite-wide search, counters, the Target analyzer, and a Repeater tab's history as one export.",
		ops: []string{
			"GET /api/history", "GET /api/message/", "GET /api/search", "GET /api/stats",
			"GET /api/engagement/", "GET /api/exchange/in-browser/", "GET /api/target/analyze",
			"POST /api/repeater/history-export",
		},
	},
	{
		// Its own tool, not an op of `history`, although the manifest classes it riskRead with the
		// other history reads: a DELETE is not a read, and folding it into a tool whose annotations
		// say readOnlyHint would publish "clears the capture" as read-only (burpsy-react-ui-gf68).
		name: "history_delete", group: groupRequests,
		short: "Removes rows from proxy history (named ids, or every row). A view-level tombstone: ids stay stable and the bytes are not erased.",
		ops:   []string{"DELETE /api/history"},
	},
	{
		name: "history_annotate", group: groupRequests,
		short: "Reads or annotates one exchange (notes, highlight), manages history extractors, imports a HAR, saves an exchange's GraphQL introspection queries to the site map unsent, and sets the uninteresting-header list.",
		ops: []string{
			"GET /api/exchange/", "PATCH /api/exchange/",
			"GET /api/history/extractors", "PUT /api/history/extractors", "POST /api/history/extract",
			"POST /api/history/import/har", "POST /api/graphql/sitemap",
			"GET /api/headers/uninteresting", "PUT /api/headers/uninteresting",
		},
	},
	{
		name: "send", group: groupRequests,
		short: "Sends one request (or a group, a WebSocket message, an HTTP/2 frame program) to the target and returns the response.",
		ops: []string{
			"POST /api/repeater/send", "POST /api/repeater/send-group", "POST /api/repeater/ws-send",
			"POST /api/repeater/browser-reissue", "POST /api/http2/program",
		},
	},
	{
		name: "websockets", group: groupRequests,
		short: "Reads captured WebSocket connections, their message history, and one message.",
		ops:   []string{"GET /api/ws/connections", "GET /api/ws/history", "GET /api/ws/message/"},
	},
	{
		name: "intercept", group: groupRequests,
		short: "Reads the intercept switch and the held-message queue.",
		ops:   []string{"GET /api/intercept"},
	},
	{
		name: "intercept_control", group: groupRequests,
		short: "Forwards, drops, edits or annotates held messages, and sets the intercept switch and its rules.",
		ops: []string{
			"POST /api/intercept/", "POST /api/intercept/annotate/", "POST /api/intercept/drop-all",
			"POST /api/intercept/enable", "POST /api/intercept/forward-all", "POST /api/intercept/in-scope-only",
			"GET /api/intercept/newline-correction", "PUT /api/intercept/newline-correction",
			"GET /api/intercept/rules/", "PUT /api/intercept/rules/",
			"GET /api/intercept/startup", "POST /api/intercept/startup",
		},
	},

	// ---- Scope & Sitemap -----------------------------------------------------------------------
	{
		name: "scope", group: groupScope,
		short: "Reads or edits the engagement's target scope: include/exclude rules, the out-of-scope drop switch, saved rule sets.",
		ops:   []string{"GET /api/scope", "POST /api/scope"},
	},
	{
		name: "scope_check", group: groupScope,
		short: "Answers whether URLs are in scope — retained and sendable by the tools — and which rule decided.",
		ops:   []string{"GET /api/scope/check", "POST /api/scope/check"},
	},
	{
		name: "sitemap_record", group: groupScope,
		short: "Records a captured request/response into the site map by exchange id.",
		ops:   []string{"POST /api/sitemap/record"},
	},
	{
		name: "sitemap", group: groupScope,
		short: "Reads the site map, records a host/path into it, or suppresses a host, branch or node.",
		ops:   []string{"GET /api/sitemap", "POST /api/sitemap", "DELETE /api/sitemap"},
	},

	// ---- Issues --------------------------------------------------------------------------------
	{
		name: "issues", group: groupIssues,
		short: "Reads scanner issues, the issue-definition catalogue, the selectable issue types and their detection methods, report exports and coverage.",
		ops: []string{
			"GET /api/issues", "GET /api/advisories", "GET /api/advisories/", "GET /api/report/",
			"GET /api/scanner/coverage", "GET /api/scanner/issue-types",
		},
	},
	{
		name: "issues_edit", group: groupIssues,
		short: "Changes an issue's severity, confidence or state, or deletes it.",
		ops:   []string{"PUT /api/issues/", "PATCH /api/issues/", "DELETE /api/issues/"},
	},
	{
		name: "issues_record", group: groupIssues,
		short: "Manually reports an issue, runs triage, and reads or sets issue consolidation.",
		ops: []string{
			"POST /api/issues/record", "POST /api/issues/triage",
			"GET /api/issues/consolidation", "PUT /api/issues/consolidation",
		},
	},
	{
		name: "issues_triage_settings", group: groupIssues,
		short: "Reads or sets the triage model settings, which hold an API credential.",
		ops:   []string{"GET /api/settings/triage", "PUT /api/settings/triage"},
	},

	// ---- Scanning & Auditing -------------------------------------------------------------------
	{
		name: "scan", group: groupScanning,
		short: "Starts audits, crawls, API scans, content discovery, hidden-input guessing, BCheck draft test runs and the live audit — real traffic at the target.",
		ops: []string{
			"POST /api/audit/", "POST /api/audit/selected", "GET /api/crawl", "POST /api/crawl",
			"POST /api/apiscan", "GET /api/discovery", "POST /api/discovery",
			"GET /api/hidden-inputs", "POST /api/hidden-inputs", "POST /api/scanner/checks/test",
			"GET /api/scanner/live", "POST /api/scanner/live", "POST /api/scanner/audit-items/",
		},
	},
	{
		name: "scan_schedules", group: groupScanning,
		short: "Reads, arms, edits or removes scheduled crawls and audits that run unattended.",
		ops:   []string{"GET /api/schedules", "POST /api/schedules", "PUT /api/schedules/", "DELETE /api/schedules/"},
	},
	{
		name: "scan_queue", group: groupScanning,
		short: "Reads the audit queue: which items each audit is working on and their state.",
		ops:   []string{"GET /api/scanner/audit-items"},
	},
	{
		name: "tasks", group: groupScanning,
		short: "Reads one task (and an async audit's finished result), cancels, re-runs or removes it, and pauses or resumes every task.",
		ops:   []string{"GET /api/tasks/", "POST /api/tasks/", "DELETE /api/tasks/"},
	},
	{
		name: "datasets", group: groupDatasets,
		short: "Searches, filters, sorts, pages and summarises any list — history, issues, site map, logger, WebSockets, an attack's requests.",
		ops:   []string{"GET /api/datasets/"},
	},
	{
		name: "dashboard", group: groupDatasets,
		short: "Reads the dashboard: running tasks, the activity log, and every coverage summary.",
		ops:   []string{"GET /api/dashboard", "GET /api/events/stats"},
	},

	// ---- Scan Checks ---------------------------------------------------------------------------
	{
		name: "scan_checks", group: groupScanChecks,
		short: "Lists the scan checks in the corpus, and validates a BCheck draft without loading it.",
		ops:   []string{"GET /api/scanner/checks", "POST /api/scanner/checks/validate"},
	},
	{
		name: "scan_checks_edit", group: groupScanChecks,
		short: "Imports, exports, deletes, reloads, enables or disables corpus checks, sets the passive branch, and reads or sets secret-scanning rules.",
		ops: []string{
			"PUT /api/scanner/checks/enable", "POST /api/scanner/passive-branch",
			"GET /api/scanner/secrets", "PUT /api/scanner/secrets",
			"POST /api/scanner/checks/import", "GET /api/scanner/checks/source", "DELETE /api/scanner/checks/source",
			"POST /api/scanner/checks/reload",
		},
	},
	{
		name: "dom_invader", group: groupScanChecks,
		short: "Reads or sets the DOM auditor, records a source/sink hit, and clears recorded hits.",
		ops:   []string{"GET /api/dominvader", "PUT /api/dominvader", "POST /api/dominvader/hit", "DELETE /api/dominvader/hits"},
	},

	// ---- Configuration -------------------------------------------------------------------------
	{
		name: "scan_configs", group: groupConfig,
		short: "Lists, creates, edits or deletes saved scan configurations.",
		ops:   []string{"GET /api/scanner/configs", "POST /api/scanner/configs", "PUT /api/scanner/configs", "DELETE /api/scanner/configs"},
	},
	{
		name: "scanner_settings", group: groupConfig,
		short: "Reads or sets the suite-wide scanner configuration, which bounds every audit.",
		ops:   []string{"GET /api/scanner/config", "PUT /api/scanner/config"},
	},
	{
		name: "proxy_settings", group: groupConfig,
		short: "Reads or sets proxy options, listeners, TLS pass-through, the embedded browser's settings, the upstream proxy, and what adding to scope does about out-of-scope history logging.",
		ops: []string{
			"GET /api/proxy/options", "PUT /api/proxy/options",
			"GET /api/proxy/listener", "PUT /api/proxy/listener", "POST /api/proxy/listener", "DELETE /api/proxy/listener",
			"GET /api/proxy/passthrough", "POST /api/proxy/passthrough", "PUT /api/proxy/passthrough", "DELETE /api/proxy/passthrough",
			"GET /api/browser/settings", "PUT /api/browser/settings",
			"GET /api/network/proxy", "POST /api/network/proxy", "DELETE /api/network/proxy",
			"GET /api/proxy/history-logging", "POST /api/proxy/history-logging",
		},
	},
	{
		name: "proxy_ca", group: groupConfig,
		short: "Reads the proxy CA's status and fingerprint.",
		ops:   []string{"GET /api/proxy/ca"},
	},
	{
		name: "proxy_ca_admin", group: groupConfig,
		short: "Exports or regenerates the proxy CA, and clears the embedded browser's profile.",
		ops:   []string{"POST /api/proxy/ca/export", "POST /api/proxy/ca/regenerate", "POST /api/browser/clear"},
	},
	{
		name: "proxy_ca_import", group: groupConfig,
		short: "Imports a CA certificate and private key for the proxy to sign with.",
		ops:   []string{"POST /api/proxy/ca/import"},
	},
	{
		name: "browser_launch", group: groupConfig,
		short: "Launches the embedded browser, pointed at this proxy.",
		ops:   []string{"POST /api/browser/launch"},
	},
	{
		name: "network_settings", group: groupConfig,
		short: "Reads or sets DNS/resolution overrides and resource pools — where and how hard the target is hit.",
		ops:   []string{"GET /api/network/settings", "PUT /api/network/settings", "GET /api/pools", "POST /api/pools", "PUT /api/pools/", "DELETE /api/pools/"},
	},
	{
		name: "network_credentials", group: groupConfig,
		short: "Reads or sets platform authentication, whether a failed challenge prompts for credentials, and TLS client certificates for the target.",
		ops: []string{
			"GET /api/network/auth", "POST /api/network/auth", "PUT /api/network/auth", "DELETE /api/network/auth",
			"GET /api/network/client-certs", "POST /api/network/client-certs", "DELETE /api/network/client-certs",
		},
	},
	{
		name: "network_tls_auth_records", group: groupConfig,
		short: "Lists the TLS certificates target servers presented and the platform-authentication failures awaiting credentials; clears the certificate list or dismisses one failure.",
		ops: []string{
			"GET /api/network/server-certificates", "DELETE /api/network/server-certificates",
			"GET /api/network/auth/failures", "DELETE /api/network/auth/failures",
		},
	},
	{
		name: "session", group: groupConfig,
		short: "Reads the cookie jar, session rules and login, replays a login, and resolves a recovery prompt.",
		ops: []string{
			"GET /api/session/cookies", "POST /api/session/cookies", "POST /api/session/login",
			"POST /api/session/prompts/", "GET /api/session/rules", "POST /api/session/rules",
			"PUT /api/session/rules/", "DELETE /api/session/rules/", "POST /api/session/rules/",
		},
	},
	{
		name: "session_read", group: groupConfig,
		short: "Reads pending session prompts and the session trace, and previews macro steps.",
		ops:   []string{"GET /api/session/prompts", "GET /api/session/trace", "POST /api/session/macro-steps"},
	},
	{
		name: "session_trace", group: groupConfig,
		short: "Turns the session-handling trace on or off.",
		ops:   []string{"POST /api/session/trace/enable"},
	},
	{
		name: "project", group: groupConfig,
		short: "Reads the open project, the project list, the exported configuration, and the protocol inventory.",
		ops:   []string{"GET /api/project", "GET /api/projects", "GET /api/config/export", "GET /api/protocols"},
	},
	{
		name: "project_settings", group: groupConfig,
		short: "Reads or sets the project name and the automatic-backup settings.",
		ops:   []string{"GET /api/project/name", "PUT /api/project/name", "GET /api/backup/config", "PUT /api/backup/config"},
	},
	{
		name: "project_logging", group: groupConfig,
		short: "Reads or sets the per-tool files that requests and responses are appended to (Burp's Logging settings).",
		ops:   []string{"GET /api/project/logging", "PUT /api/project/logging"},
	},
	{
		name: "project_admin", group: groupConfig,
		short: "Opens another project, takes a backup (which prunes old ones), or clears the event log.",
		ops:   []string{"POST /api/project/open", "POST /api/backup", "DELETE /api/dashboard/events"},
	},
	{
		name: "config_import", group: groupConfig,
		short: "Imports a configuration document, which can replace the scope.",
		ops:   []string{"POST /api/config/import"},
	},

	// ---- Fuzzing -------------------------------------------------------------------------------
	{
		name: "intruder", group: groupFuzzing,
		short: "Launches an Intruder attack against the target with the chosen payloads, or re-sends chosen attempts' stored requests.",
		ops:   []string{"POST /api/intruder/run", "POST /api/intruder/again"},
	},
	{
		name: "intruder_read", group: groupFuzzing,
		short: "Reads attacks and their results, the wordlists, and the insertion points a request offers.",
		ops:   []string{"GET /api/intruder/attacks", "POST /api/intruder/points", "GET /api/wordlists"},
	},
	{
		name: "intruder_control", group: groupFuzzing,
		short: "Pauses, resumes or stops an attack, and uploads a payload file.",
		ops:   []string{"POST /api/intruder/attacks/", "POST /api/intruder/payload-files"},
	},
	{
		name: "authz", group: groupFuzzing,
		short: "Reads or sets the identities the authorization tester replays requests as.",
		ops:   []string{"GET /api/authz/identities", "PUT /api/authz/identities"},
	},
	{
		name: "authz_test", group: groupFuzzing,
		short: "Replays captured requests to the target under each identity and compares the answers.",
		ops:   []string{"POST /api/authz/test"},
	},
	{
		name: "sequencer", group: groupFuzzing,
		short: "Analyses token randomness and reads a live capture's samples.",
		ops:   []string{"POST /api/sequencer/analyse", "GET /api/sequencer/capture/", "POST /api/sequencer/capture/"},
	},
	{
		name: "sequencer_capture", group: groupFuzzing,
		short: "Starts a live token capture, which re-sends a request to the target many times.",
		ops:   []string{"POST /api/sequencer/capture"},
	},
	{
		name: "sequencer_settings", group: groupFuzzing,
		short: "Reads or sets the sequencer's analysis settings.",
		ops:   []string{"GET /api/sequencer/settings", "PUT /api/sequencer/settings"},
	},

	// ---- Collaborator --------------------------------------------------------------------------
	{
		name: "collaborator", group: groupCollaborator,
		short: "Polls for and reads out-of-band interactions, and reports the channel's status.",
		ops: []string{
			"POST /api/collaborator/poll", "GET /api/collaborator/status",
			"GET /api/collaborator/interactions", "GET /api/collaborator/interaction/",
		},
	},
	{
		name: "collaborator_payload", group: groupCollaborator,
		short: "Generates Collaborator payload addresses to embed in test traffic, and runs the interaction server's health check.",
		ops:   []string{"POST /api/collaborator/payload", "POST /api/collaborator/health"},
	},
	{
		name: "collaborator_server", group: groupCollaborator,
		short: "Chooses which interaction server receives this engagement's out-of-band callbacks, or stops using one.",
		ops:   []string{"POST /api/collaborator/server", "DELETE /api/collaborator/server"},
	},
	{
		name: "blind_xss", group: groupCollaborator,
		short: "Reads the blind-XSS channel: minted payloads and recorded callbacks (which carry victims' cookies).",
		ops:   []string{"GET /api/blindxss"},
	},
	{
		name: "blind_xss_payload", group: groupCollaborator,
		short: "Mints one blind-XSS correlation payload to plant.",
		ops:   []string{"POST /api/blindxss/payload"},
	},

	// ---- Utilities -----------------------------------------------------------------------------
	{
		name: "decoder", group: groupUtilities,
		short: "Encodes, decodes, hashes and diffs values, diffs site maps, and tests a match/replace rule.",
		ops: []string{
			"POST /api/tools/decode", "POST /api/tools/encode", "POST /api/tools/hash",
			"POST /api/tools/compare", "POST /api/tools/compare-sitemaps", "POST /api/tools/rules/test",
		},
	},
	{
		name: "protobuf", group: groupUtilities,
		short: "Decodes or encodes a protobuf message.",
		ops:   []string{"POST /api/protobuf/decode", "POST /api/protobuf/encode"},
	},
	{
		name: "match_replace", group: groupUtilities,
		short: "Reads or sets the match/replace rules applied to proxied traffic.",
		ops:   []string{"GET /api/tools/rules", "PUT /api/tools/rules"},
	},
	{
		name: "logger", group: groupDatasets,
		short: "Reads the log of every request burpsy itself sent, records into it, or clears it.",
		ops:   []string{"GET /api/tools/log", "POST /api/tools/log", "DELETE /api/tools/log"},
	},
	{
		name: "logger_comment", group: groupDatasets,
		short: "Sets the comment on one logger row.",
		ops:   []string{"PATCH /api/tools/log/"},
	},
	{
		name: "organizer", group: groupDatasets,
		short: "Reads and edits the Organizer: saved items, their notes and status, and collections.",
		ops: []string{
			"GET /api/tools/organizer", "POST /api/tools/organizer",
			"POST /api/tools/organizer/", "PUT /api/tools/organizer/", "DELETE /api/tools/organizer/",
			"POST /api/tools/organizer/collections",
			"PUT /api/tools/organizer/collections/", "POST /api/tools/organizer/collections/", "DELETE /api/tools/organizer/collections/",
		},
	},

	// ---- Scripting -----------------------------------------------------------------------------
	{
		name: "extensions", group: groupScripting,
		short: "Lists loaded extensions, the APIs they registered, and their console output.",
		ops:   []string{"GET /api/extensions", "GET /api/extensions/apis", "GET /api/extensions/console"},
	},
	{
		name: "extensions_run", group: groupScripting,
		short: "Loads an allowlisted extension or invokes something it registered — operator code in this process.",
		ops:   []string{"POST /api/extensions/load", "POST /api/extensions/invoke"},
	},
	{
		name: "extensions_manage", group: groupScripting,
		short: "Reorders or unloads extensions.",
		ops:   []string{"POST /api/extensions/order", "POST /api/extensions/unload"},
	},
}

// notExposed is every manifest route-verb the grouped surface deliberately does not reach, keyed
// "VERB /pattern", and why. A route-verb that is neither here nor in groupedTools fails
// TestEveryRouteVerbIsReachableFromExactlyOneGroupedTool, so a route added to the manifest has to be
// placed by someone — it cannot drop out of the agent surface by being forgotten.
//
// The route surface (-surface routes) still lists all of them, for debugging.
var notExposed = map[string]string{
	"GET /":       "the console's own index.html and SPA catch-all — an asset, not an operation",
	"GET /ca.crt": "the proxy CA certificate as a download for a browser's trust store; proxy_ca reports its status and fingerprint",
	"GET /api/engagement/clickbandit.js": "the Clickbandit script served as text/javascript for the operator to paste into a " +
		"browser's developer console — an asset that runs in a browser, not an operation",
	"GET /reissue/": "a one-shot URL the operator's own browser navigates to; fetching it from an agent would spend the browser's token",
	"GET /api/events": "the SSE change stream: it never ends, so it cannot be one tool result. The transport " +
		"itself is the stream's agent-side consumer",
	"GET /api/exchanges/":     "legacy alias of /api/exchange/ (history_annotate's GET); listing it would be a second spelling of one read",
	"GET /api/findings":       "legacy alias of /api/issues (issues' GET); a second spelling of one read",
	"POST /api/scanner/audit": "legacy alias of POST /api/audit/{id} (scan); a second spelling of one attack",
	"GET /api/skills":         "served as MCP prompts: prompts/list reads it, so a skill is invoked as a prompt, not called as a tool",
	"GET /api/skills/":        "served as MCP prompts: prompts/get renders a skill through it",
	"PUT /api/skills/disabled": "the operator's per-project switch, set in the console's Settings; an agent sees its effect " +
		"as the skills prompts/list no longer offers",
}
