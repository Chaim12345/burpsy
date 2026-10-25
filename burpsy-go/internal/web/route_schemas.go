package web

import (
	"encoding/json"
	"reflect"
	"sort"

	"github.com/burpsy-go/burpsy/internal/browser"
	"github.com/burpsy-go/burpsy/internal/dominvader"
	"github.com/burpsy-go/burpsy/internal/filelog"
	"github.com/burpsy-go/burpsy/internal/intruder"
	"github.com/burpsy-go/burpsy/internal/pool"
	"github.com/burpsy-go/burpsy/internal/proxy"
	"github.com/burpsy-go/burpsy/internal/schedule"
	"github.com/burpsy-go/burpsy/internal/sequencer"
)

// routeSchemas declares, per "VERB /pattern", the request type each body-taking handler decodes into
// and the query parameters it reads (burpsy-react-ui-3zw0). See route_schema.go for why the table is
// the handler's own type and how the sweep in route_schema_test.go proves it.
//
// Every mutating route-verb must appear here — with its body type, as noBody, or with a raw (non-JSON)
// description — and TestEveryMutatingRouteVerbDeclaresItsInput fails on one that does not, so a new
// route cannot reach the MCP surface untyped. GET entries are optional and carry query parameters.
var routeSchemas = map[string]opSchema{
	// ---- reads with query parameters ----------------------------------------------------------
	"GET /api/advisories": {query: []queryParam{
		{name: "q", kind: "string", desc: "substring filter over name and type index"},
		{name: "severity", kind: "string", desc: "only definitions of this typical severity"},
	}},
	"GET /api/crawl": {query: []queryParam{{name: "task", kind: "integer", desc: "a crawl or API-scan task id; omitted means the latest"}}},
	"GET /api/datasets/": {query: []queryParam{
		{name: "pattern", kind: "string", desc: "RE2 regex a row must match (in any column, or in columns)"},
		{name: "case_insensitive", kind: "boolean"},
		{name: "columns", kind: "string", desc: "comma-separated columns the pattern is matched against"},
		{name: "sort_by", kind: "string", desc: "column to sort by (default: the source's, usually id)"},
		{name: "sort_order", kind: "string", enum: []string{"asc", "desc"}},
		{name: "offset", kind: "integer", desc: "first matched row to return; copy next_offset to page on"},
		{name: "limit", kind: "integer", desc: "rows per page, 1-500 (default 25)"},
		{name: "return_columns", kind: "string", desc: "comma-separated columns to return (default: all)"},
		{name: "facets", kind: "string", desc: "true for the source's default facet columns, or a comma-separated list; facets is null unless asked"},
		{name: "since", kind: "integer", desc: "only rows whose id is greater than this"},
		{name: "wait_seconds", kind: "integer", desc: "long-poll up to this many seconds (0-60) for min_rows matched rows at or beyond offset"},
		{name: "min_rows", kind: "integer", desc: "rows to wait for with wait_seconds (default 1)"},
	}},
	"GET /api/crawl/live": {query: []queryParam{{name: "task", kind: "integer", desc: "the crawl task to watch"}}},
	"GET /api/discovery":  {query: []queryParam{{name: "task", kind: "integer", desc: "one discovery run by task id"}}},
	"GET /api/engagement/": {query: []queryParam{
		{name: "host", kind: "string", desc: "limit the search to one host"},
		{name: "q", kind: "string", desc: "the search term"},
		{name: "limit", kind: "integer", desc: "most rows to return"},
	}},
	"GET /api/extensions/console": {query: []queryParam{
		{name: "name", kind: "string", desc: "one extension's console"},
		{name: "limit", kind: "integer", desc: "most lines to return"},
	}},
	"GET /api/hidden-inputs": {query: []queryParam{{name: "task", kind: "integer", desc: "one guessing run by task id; omitted lists the retained runs"}}},
	"GET /api/history": {query: []queryParam{
		{name: "limit", kind: "integer", desc: "most rows to return, newest first (default 300)"},
		{name: "q", kind: "string", desc: "a burpsy-query filter expression over host/path/method/status"},
		{name: "search", kind: "string", desc: "Burp's Search box: a term matched over row columns and both messages"},
		{name: "search_case", kind: "boolean", desc: "case-sensitive search"},
		{name: "search_regex", kind: "boolean", desc: "search is a regular expression"},
		{name: "search_negate", kind: "boolean", desc: "keep rows that do NOT match"},
	}},
	"GET /api/issues": {query: []queryParam{{name: "include_isolated", kind: "boolean", desc: "also list issues raised only on an isolated scan's traffic, flagged isolated; All issues omits them"}}},
	"GET /api/message/{id}": {query: []queryParam{
		{name: "byte_offset", kind: "integer", desc: "where the body window starts: absolute (0 = start of body), or relative to the first pattern match (may be negative); copy next_offset to page on"},
		{name: "max_bytes", kind: "integer", desc: "body bytes in the window, 1-65536 (default 2048)"},
		{name: "pattern", kind: "string", desc: "an RE2 regular expression: anchor the window at its first match; matches lists up to 100 match offsets"},
		{name: "case_insensitive", kind: "boolean", desc: "compile pattern case-insensitively"},
		{name: "decoded", kind: "boolean", desc: "window the body with chunking and Content-Encoding undone instead of the wire bytes"},
	}},
	"GET /api/network/auth":         {query: []queryParam{{name: "host", kind: "string"}, {name: "scheme", kind: "string"}}},
	"GET /api/network/client-certs": {query: []queryParam{{name: "host", kind: "string"}}},
	"GET /api/report/": {query: []queryParam{
		{name: "severity", kind: "string", desc: "minimum severity to include"},
		{name: "host", kind: "string", desc: "only issues on this host"},
		{name: "exclude_false_positives", kind: "boolean"},
	}},
	"GET /api/scanner/audit-items":   {query: []queryParam{{name: "limit", kind: "integer"}}},
	"GET /api/scanner/checks/source": {query: []queryParam{{name: "name", kind: "string", desc: "the loaded check's name; required"}}},
	"GET /api/search": {query: []queryParam{
		{name: "q", kind: "string", desc: "the search term"},
		{name: "case", kind: "boolean", desc: "case-sensitive"},
		{name: "regex", kind: "boolean", desc: "the term is a regular expression"},
		{name: "negate", kind: "boolean", desc: "keep exchanges that do NOT match"},
		{name: "in_scope", kind: "boolean", desc: "only in-scope exchanges"},
		{name: "location", kind: "string", desc: "which message to search", enum: []string{"both", "request", "response"}},
		{name: "area", kind: "string", desc: "which part of the message to search"},
	}},
	"GET /api/sitemap": {query: []queryParam{
		{name: "host", kind: "string", desc: "one host's subtree"},
		{name: "path", kind: "string", desc: "one path's node"},
	}},
	"GET /api/target/analyze": {query: []queryParam{
		{name: "host", kind: "string", desc: "the host to analyze; required"},
		{name: "path", kind: "string", desc: "limit the report to the branch under this path (starts with /)"},
		{name: "port", kind: "integer", desc: "only this port, 1-65535"},
		{name: "tls", kind: "boolean", desc: "only https (true) or only http (false)"},
		{name: "format", kind: "string", desc: "json (default), or html for the saveable report", enum: []string{"json", "html"}},
	}},
	"GET /api/tools/log": {query: []queryParam{
		{name: "limit", kind: "integer"},
		{name: "filter", kind: "string", desc: "a burpsy-query filter expression"},
		{name: "search", kind: "string", desc: "a substring search"},
	}},
	"GET /api/ws/history": {query: []queryParam{
		{name: "exchange", kind: "integer", desc: "one WebSocket connection by its upgrade exchange id"},
		{name: "direction", kind: "string"},
		{name: "opcode", kind: "string"},
		{name: "payload", kind: "string", desc: "substring filter over the payload"},
		{name: "limit", kind: "integer"},
		{name: "offset", kind: "integer"},
	}},

	// ---- Requests & Responses -----------------------------------------------------------------
	"DELETE /api/history/rows":          {body: typeOf[historyDeleteReq](), optional: true},
	"PATCH /api/exchange/":              {body: typeOf[exchangePatchReq]()},
	"PUT /api/history/extractors":       {body: typeOf[historyExtractorsReq]()},
	"POST /api/history/extract":         {body: typeOf[historyExtractReq]()},
	"POST /api/history/import/har":      {raw: "an HTTP Archive (HAR 1.2) JSON document, as a browser or proxy exports it; its members are the producer's, so unknown ones are ignored"},
	"PUT /api/headers/uninteresting":    {body: typeOf[uninterestingHeadersReq]()},
	"POST /api/repeater/history-export": {body: typeOf[historyExportReq]()},
	"POST /api/http2/kettle":            {body: typeOf[h2KettleReq]()},

	"POST /api/repeater/send":            {body: typeOf[repeaterSendReq]()},
	"POST /api/repeater/send-group":      {body: typeOf[repeaterGroupSendReq]()},
	"POST /api/repeater/ws-send":         {body: typeOf[repeaterWsSendReq]()},
	"POST /api/repeater/ws-attach":       {body: typeOf[repeaterWsAttachReq]()},
	"POST /api/repeater/browser-reissue": {body: typeOf[repeaterBrowserReissueReq]()},
	"POST /api/http2/program":            {body: typeOf[frameProgramReq]()},

	"POST /api/intercept/": {variants: map[string]reflect.Type{
		"1/forward": typeOf[interceptForwardReq](),
		"1/drop":    typeOf[interceptDropReq](),
	}, optional: true},
	"POST /api/intercept/annotate/{id}":     {body: typeOf[interceptAnnotateReq]()},
	"POST /api/intercept/drop-all":          {body: typeOf[interceptDropAllReq](), optional: true},
	"POST /api/intercept/enable":            {body: typeOf[interceptEnableReq]()},
	"POST /api/intercept/forward-all":       noBody,
	"POST /api/intercept/in-scope-only":     {body: typeOf[interceptInScopeOnlyReq]()},
	"PUT /api/intercept/newline-correction": {body: typeOf[interceptNewlineCorrectionReq]()},
	"PUT /api/intercept/rules/":             {body: typeOf[interceptListState]()},
	"POST /api/intercept/startup":           {body: typeOf[interceptStartupReq]()},
	"POST /api/proxy/history-logging":       {body: typeOf[proxyHistoryLoggingReq]()},

	// ---- Scope & Sitemap ----------------------------------------------------------------------
	"POST /api/scope":           {body: typeOf[ScopeRequest]()},
	"GET /api/scope/check":      {query: []queryParam{{name: "url", kind: "string", desc: "an absolute http:// or https:// URL"}}},
	"POST /api/scope/check":     {body: typeOf[scopeCheckReq]()},
	"POST /api/sitemap":         {body: typeOf[sitemapInsertReq]()},
	"DELETE /api/sitemap":       {body: typeOf[sitemapDeleteReq]()},
	"PUT /api/skills/disabled":  {body: typeOf[skillsDisabledReq]()},
	"POST /api/sitemap/record":  {body: typeOf[sitemapRecordReq]()},
	"POST /api/graphql/sitemap": {body: typeOf[graphqlSitemapReq]()},

	// ---- Issues -------------------------------------------------------------------------------
	"PUT /api/issues/":              {body: typeOf[issueTriageReq](), optional: true},
	"PATCH /api/issues/":            {body: typeOf[issueTriageReq](), optional: true},
	"DELETE /api/issues/":           noBody,
	"POST /api/issues/record":       {body: typeOf[manualIssueReq]()},
	"POST /api/issues/triage":       noBody,
	"PUT /api/issues/consolidation": {body: typeOf[issueConsolidationReq]()},
	"PUT /api/settings/triage":      {body: typeOf[triageSettingsView]()},

	// ---- Scanning & Auditing ------------------------------------------------------------------
	"POST /api/audit/":         {body: typeOf[scannerAuditReq](), optional: true},
	"POST /api/audit/selected": {body: typeOf[auditSelectedReq]()},
	"POST /api/scanner/audit":  {body: typeOf[scannerAuditReq]()},
	"POST /api/crawl":          {body: typeOf[crawlStartReq]()},
	"POST /api/apiscan":        {body: typeOf[apiScanReq]()},
	"POST /api/apiscan/fetch":  {body: typeOf[apiScanFetchReq]()},
	"POST /api/discovery":      {body: typeOf[discoveryStartReq]()},
	"POST /api/hidden-inputs":  {body: typeOf[hiddenInputStartReq]()},
	"POST /api/scanner/live":   {body: typeOf[liveAuditEnableReq]()},
	"POST /api/scanner/audit-items/": {variants: map[string]reflect.Type{
		"0/again":  typeOf[scannerAuditReq](),
		"0/cancel": nil,
	}, optional: true},
	"POST /api/schedules":         {body: typeOf[schedule.Schedule]()},
	"PUT /api/schedules/":         {body: typeOf[schedule.Schedule]()},
	"DELETE /api/schedules/":      noBody,
	"POST /api/tasks/pause":       noBody,
	"POST /api/tasks/resume":      noBody,
	"DELETE /api/tasks/{id}":      noBody,
	"POST /api/tasks/{id}/again":  noBody,
	"POST /api/tasks/{id}/cancel": noBody,
	"POST /api/tasks/{id}/pause":  noBody,
	"POST /api/tasks/{id}/resume": noBody,

	// ---- Scan Checks / Configuration -----------------------------------------------------------
	"PUT /api/scanner/checks/enable":         {body: typeOf[corpusCheckEnableReq]()},
	"POST /api/scanner/checks/validate":      {body: typeOf[checkValidateReq]()},
	"POST /api/scanner/checks/import":        {body: typeOf[checkImportReq]()},
	"POST /api/scanner/checks/test":          {body: typeOf[checkTestReq]()},
	"POST /api/scanner/checks/reload":        noBody,
	"DELETE /api/scanner/checks/source":      {query: []queryParam{{name: "name", kind: "string", desc: "the console-imported check to delete; a file-loaded check is refused with 409"}}},
	"POST /api/scanner/passive-branch":       {body: typeOf[passiveBranchReq]()},
	"PUT /api/scanner/secrets":               {body: typeOf[scannerSecretsReq]()},
	"PUT /api/dominvader":                    {body: typeOf[domInvaderReq]()},
	"POST /api/dominvader/hit":               {body: typeOf[dominvader.Hit]()},
	"POST /api/dominvader/messages/register": {body: typeOf[domMessageWorkerReq]()},
	"POST /api/dominvader/messages/report":   {body: typeOf[domMessageWorkerReq]()},
	"POST /api/dominvader/messages/poll":     {body: typeOf[domMessageWorkerReq]()},
	"DELETE /api/dominvader/hits":            noBody,
	"POST /api/scanner/configs":              {body: typeOf[scanConfigWriteReq]()},
	"PUT /api/scanner/configs":               {body: typeOf[scanConfigWriteReq]()},
	"DELETE /api/scanner/configs":            {body: typeOf[scanConfigWriteReq]()},
	"PUT /api/scanner/config": {
		body: typeOf[map[string]json.RawMessage](), schema: scannerConfigPatchSchema,
		keysCheckedBy: "applyScannerConfigPatch refuses a key in none of scannerConfigBoolKeys, scannerConfigIntMSKeys, its named keys (max_concurrency, xss_browser_targets, only_rows, ...)",
	},

	"PUT /api/proxy/options": {
		body: typeOf[map[string]bool](), schema: proxyOptionsPatchSchema,
		keysCheckedBy: "handleProxyOptions refuses a key proxy.KnownOption does not know, before applying any",
	},
	"PUT /api/proxy/listener": {variants: map[string]reflect.Type{
		"":      typeOf[proxyListenerReq](),
		"?id=1": typeOf[proxyListenerBody](),
	}},
	"POST /api/proxy/listener":      {body: typeOf[proxyListenerBody]()},
	"DELETE /api/proxy/listener":    {query: []queryParam{{name: "id", kind: "string", desc: "the listener to remove"}}},
	"POST /api/proxy/passthrough":   {body: typeOf[tlsPassthroughAddReq]()},
	"PUT /api/proxy/passthrough":    {body: typeOf[tlsPassthroughSwitchesReq]()},
	"DELETE /api/proxy/passthrough": {query: []queryParam{{name: "pattern", kind: "string", desc: "the host pattern to remove"}}},
	"PUT /api/browser/settings":     {body: typeOf[browser.Settings]()},
	"POST /api/browser/launch":      {body: typeOf[browserLaunchReq](), optional: true},
	"POST /api/browser/clear":       noBody,
	"POST /api/network/proxy":       {body: typeOf[networkProxyUpdate]()},
	"DELETE /api/network/proxy": {query: []queryParam{
		{name: "pattern", kind: "string", desc: "the rule to remove, exactly"},
		{name: "all", kind: "boolean", desc: "true clears every rule and the default"},
	}},

	"POST /api/proxy/ca/export":     {body: typeOf[caExportRequest]()},
	"POST /api/proxy/ca/regenerate": noBody,
	"POST /api/proxy/ca/import":     {body: typeOf[caImportRequest]()},

	"PUT /api/network/settings": {
		body: typeOf[map[string]json.RawMessage](), schema: networkSettingsPatchSchema,
		keysCheckedBy: "applyNetworkSettingsPatch refuses a section or key networkPatchFields does not list, before applying any",
	},
	"POST /api/pools":                         {body: typeOf[pool.Pool]()},
	"PUT /api/pools/":                         {body: typeOf[pool.Pool]()},
	"DELETE /api/pools/":                      noBody,
	"POST /api/network/auth":                  {body: typeOf[postNetworkAuthReq]()},
	"DELETE /api/network/auth":                {query: []queryParam{{name: "host", kind: "string", desc: "the host pattern"}, {name: "scheme", kind: "string", desc: "the auth scheme the rule was stored under"}}},
	"POST /api/network/client-certs":          {body: typeOf[postNetworkClientCertsReq]()},
	"DELETE /api/network/client-certs":        {query: []queryParam{{name: "host", kind: "string", desc: "the host pattern"}}},
	"PUT /api/network/auth":                   {body: typeOf[putNetworkAuthPromptReq]()},
	"DELETE /api/network/auth/failures":       {query: []queryParam{{name: "host", kind: "string", desc: "the host whose recorded failure is dismissed"}}},
	"DELETE /api/network/server-certificates": noBody,
	"PUT /api/project/logging":                {body: typeOf[filelog.Settings]()},

	"POST /api/session/cookies":     {body: typeOf[sessionCookiesMutateReq]()},
	"POST /api/session/login":       {body: typeOf[sessionLoginReq]()},
	"POST /api/session/macro-steps": {body: typeOf[sessionMacroStepsReq]()},
	"POST /api/session/prompts/":    {body: typeOf[sessionPromptResolveReq]()},
	"POST /api/session/rules":       {body: typeOf[sessionRuleDto]()},
	"PUT /api/session/rules/":       {body: typeOf[sessionRuleDto]()},
	"DELETE /api/session/rules/":    noBody,
	"POST /api/session/rules/": {variants: map[string]reflect.Type{
		"1/update-macro":      nil,
		"1/run":               nil,
		"1/test":              nil,
		"1/analyze":           nil,
		"1/apply-extractions": typeOf[sessionRuleApplyExtractionsReq](),
		"1/move":              typeOf[sessionRuleMoveReq](),
	}},
	"POST /api/session/trace/enable": {body: typeOf[sessionTraceReq]()},

	"PUT /api/project/name":        {body: typeOf[projectNameReq]()},
	"POST /api/project/open":       {body: typeOf[projectOpenReq]()},
	"PUT /api/backup/config":       {body: typeOf[backupConfig]()},
	"POST /api/backup":             {body: typeOf[backupParams](), optional: true},
	"DELETE /api/dashboard/events": noBody,
	"POST /api/config/import":      {body: typeOf[configBundle]()},

	// ---- Fuzzing ------------------------------------------------------------------------------
	"POST /api/intruder/run":           {body: typeOf[intruderRunReq]()},
	"POST /api/intruder/again":         {body: typeOf[intruderAgainReq]()},
	"POST /api/crawl/logins":           {body: typeOf[recordedLoginSaveReq]()},
	"POST /api/crawl/logins/replay":    {body: typeOf[recordedLoginReplayReq]()},
	"DELETE /api/crawl/logins":         {query: []queryParam{{name: "id", kind: "string", desc: "the recorded login to remove"}}},
	"POST /api/intruder/points":        {body: typeOf[intruderPointsReq]()},
	"POST /api/intruder/attacks/":      noBody,
	"POST /api/intruder/payload-files": {raw: "the wordlist file's bytes, one payload per line (not JSON)"},
	"PUT /api/authz/identities":        {body: typeOf[authzIdentitiesReq]()},
	"POST /api/authz/test":             {body: typeOf[authzTestReq]()},
	"POST /api/sequencer/analyse":      {body: typeOf[sequencerAnalyseReq]()},
	"POST /api/sequencer/capture":      {body: typeOf[sequencerCaptureReq]()},
	"POST /api/sequencer/capture/":     noBody,
	"PUT /api/sequencer/settings":      {body: typeOf[sequencer.SettingsEdit]()},

	// ---- Collaborator -------------------------------------------------------------------------
	"POST /api/collaborator/payload":  {body: typeOf[collaboratorPayloadReq](), optional: true},
	"POST /api/collaborator/poll":     {body: typeOf[collaboratorPollReq](), optional: true},
	"POST /api/collaborator/server":   {body: typeOf[collaboratorServerRequest]()},
	"DELETE /api/collaborator/server": {body: typeOf[collaboratorServerUnsetReq](), optional: true},
	"POST /api/collaborator/health":   noBody,
	"POST /api/blindxss/payload":      noBody,

	// ---- Utilities ----------------------------------------------------------------------------
	"POST /api/tools/decode":                {body: typeOf[toolsDecodeReq]()},
	"POST /api/tools/encode":                {body: typeOf[toolsEncodeReq]()},
	"POST /api/tools/hash":                  {body: typeOf[toolsHashReq]()},
	"POST /api/tools/compare":               {body: typeOf[toolsCompareReq]()},
	"POST /api/tools/compare-sitemaps":      {body: typeOf[toolsCompareSitemapsReq]()},
	"POST /api/tools/rules/test":            {body: typeOf[matchReplaceTestReq]()},
	"PUT /api/tools/rules":                  {body: typeOf[matchReplaceSetSpec]()},
	"POST /api/protobuf/decode":             {body: typeOf[protobufDecodeReq]()},
	"POST /api/protobuf/reflect-decode":     {body: typeOf[protobufReflectReq]()},
	"POST /api/protobuf/encode":             {body: typeOf[protobufEncodeReq]()},
	"POST /api/tools/log":                   {body: typeOf[toolLogSetCaptureReq]()},
	"DELETE /api/tools/log":                 noBody,
	"PATCH /api/tools/log/":                 {body: typeOf[toolLogSetCommentReq]()},
	"POST /api/tools/organizer":             {body: typeOf[organizerReq]()},
	"POST /api/tools/organizer/":            {body: typeOf[organizerItemReq]()},
	"PUT /api/tools/organizer/":             {variants: map[string]reflect.Type{"1/status": typeOf[organizerItemStatusReq]()}},
	"DELETE /api/tools/organizer/":          noBody,
	"POST /api/tools/organizer/collections": {body: typeOf[organizerCollectionCreateReq]()},
	"PUT /api/tools/organizer/collections/": {variants: map[string]reflect.Type{
		"1":       typeOf[organizerCollectionUpdateReq](),
		"inbox":   typeOf[organizerInboxMoveReq](),
		"1/items": typeOf[organizerCollectionItemsReq](),
	}},
	"POST /api/tools/organizer/collections/": {variants: map[string]reflect.Type{
		"1/duplicate": nil,
	}},
	"DELETE /api/tools/organizer/collections/": {query: []queryParam{
		{name: "items", kind: "string", desc: "what happens to the collection's items", enum: []string{"inbox", "delete"}},
	}},

	// ---- Scripting ----------------------------------------------------------------------------
	"POST /api/extensions/load":   {body: typeOf[extensionNameRequest]()},
	"POST /api/extensions/unload": {body: typeOf[extensionNameRequest]()},
	"POST /api/extensions/invoke": {body: typeOf[extensionInvokeRequest]()},
	"POST /api/extensions/order":  {body: typeOf[extensionOrderRequest]()},
}

// ---- hand-built schemas for the key-table patches -------------------------------------------------

// scannerConfigPatchSchema publishes PUT /api/scanner/config's keys from the handler's own key tables.
func scannerConfigPatchSchema() map[string]any {
	props := map[string]any{
		"max_concurrency": map[string]any{"type": "integer", "minimum": 1, "description": "items audited at once"},
	}
	for k := range scannerConfigBoolKeys {
		props[k] = map[string]any{"type": "boolean"}
	}
	for k := range scannerConfigIntMSKeys {
		props[k] = map[string]any{"type": "integer", "minimum": 0, "description": "milliseconds"}
	}
	props["only_rows"] = map[string]any{
		"type": "array", "maxItems": MaxOnlyRows, "items": map[string]any{"type": "string"},
		"description": "restrict audits to the checks that can report these issue rows, named as findings name them; [] runs everything; an unknown name is refused",
	}
	str := map[string]any{"type": "string", "maxLength": maxXSSBrowserTargetField}
	props["xss_browser_targets"] = map[string]any{
		"type": "array", "maxItems": MaxXSSBrowserTargets,
		"description": "the reflected-XSS browser confirmation's application routes; replaces the whole list ([] clears it)",
		"items": map[string]any{
			"type": "object", "additionalProperties": false,
			"required": []string{"root_url", "master_selector", "master_text", "input_selector"},
			"properties": map[string]any{
				"match": str, "root_url": map[string]any{"type": "string", "maxLength": maxXSSBrowserTargetField, "description": "absolute http(s) URL on the audited origin"},
				"master_selector": str, "master_text": str, "level_selector": str, "level_text": str,
				"level_from_path": map[string]any{"type": "boolean"},
				"input_selector":  str, "submit_selector": str,
				"click_trigger": map[string]any{"type": "boolean"},
				"sink":          map[string]any{"type": "string", "description": "a domexec sink name; empty means the innerHTML family"},
			},
		},
	}
	return map[string]any{"type": "object", "properties": props, "additionalProperties": false,
		"description": "a patch: only the keys sent change"}
}

// proxyOptionsPatchSchema publishes PUT /api/proxy/options' keys from proxy.OptionKeys.
func proxyOptionsPatchSchema() map[string]any {
	props := map[string]any{}
	for _, k := range proxy.OptionKeys {
		props[string(k)] = map[string]any{"type": "boolean"}
	}
	return map[string]any{"type": "object", "properties": props, "additionalProperties": false, "minProperties": 1,
		"description": "a patch of option keys to booleans: only the keys sent change"}
}

// networkSettingsPatchSchema publishes PUT /api/network/settings' sections and keys from
// networkPatchFields. Each key's value type is the setting's own; the table holds an apply function
// rather than a type, so the value is published as "any JSON value" and the handler names a wrong one.
func networkSettingsPatchSchema() map[string]any {
	sections := map[string]any{}
	names := make([]string, 0, len(networkPatchFields))
	for name := range networkPatchFields {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		keys := map[string]any{}
		for key := range networkPatchFields[name] {
			keys[key] = map[string]any{"description": "the setting's value; GET /api/network/settings shows the current one"}
		}
		sections[name] = map[string]any{"type": "object", "properties": keys, "additionalProperties": false}
	}
	return map[string]any{"type": "object", "properties": sections, "additionalProperties": false, "minProperties": 1,
		"description": "a patch of sections: only the keys sent change"}
}

// payloadSourceVariants is intruder.PayloadSource's tagged union, tag -> the variant struct its
// UnmarshalJSON decodes the same object into. PayloadSource decodes itself, so reflecting its Go
// struct would publish a shape nobody can send; this table is the dispatch's own vocabulary, and
// TestEveryPayloadSourceTagDecodes drives each tag through the real UnmarshalJSON.
var payloadSourceVariants = []struct {
	tag string
	typ reflect.Type
}{
	{"list", typeOf[intruder.ListSource]()},
	{"numbers", typeOf[intruder.Numbers]()},
	{"dates", typeOf[intruder.Dates]()},
	{"brute_force", typeOf[intruder.BruteForce]()},
	{"custom_iterator", typeOf[intruder.CustomIterator]()},
	{"null", typeOf[intruder.NullSource]()},
	{"file", typeOf[intruder.FileSource]()},
	{"char_substitution", typeOf[intruder.CharSubstitution]()},
	{"case_modification", typeOf[intruder.CaseModification]()},
	{"illegal_unicode", typeOf[intruder.IllegalUnicode]()},
	{"character_blocks", typeOf[intruder.CharacterBlocks]()},
	{"character_frobber", typeOf[intruder.CharacterFrobber]()},
	{"bit_flipper", typeOf[intruder.BitFlipper]()},
	{"username", typeOf[intruder.UsernameGenerator]()},
	{"ecb_shuffler", typeOf[intruder.ECBShuffler]()},
	{"copy_other", typeOf[intruder.CopyOtherSource]()},
	{"recursive_grep", typeOf[intruder.RecursiveGrepSource]()},
	{"collaborator", typeOf[intruder.CollaboratorSource]()},
	{"character_substitution", typeOf[intruder.CharacterSubstitution]()},
	{"runtime_file", typeOf[intruder.RuntimeFileSource]()},
	{"openapi_payloads", typeOf[intruder.OpenAPIPayloads]()},
	{"grammar_fuzz", typeOf[intruder.GrammarFuzz]()},
}

func init() {
	branches := make([]any, 0, len(payloadSourceVariants))
	for _, v := range payloadSourceVariants {
		b, _ := jsonSchemaOf(v.typ)
		props, _ := b["properties"].(map[string]any)
		if props == nil {
			props = map[string]any{}
			b["properties"] = props
		}
		props["type"] = map[string]any{"type": "string", "enum": []string{v.tag}}
		b["required"] = []string{"type"}
		b["title"] = v.tag
		branches = append(branches, b)
	}
	schemaOverrides[typeOf[intruder.PayloadSource]()] = map[string]any{
		"anyOf":       branches,
		"description": "a payload source, tagged by \"type\"; each branch lists that type's own fields",
	}
}
