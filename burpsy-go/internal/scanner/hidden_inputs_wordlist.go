package scanner

// The built-in name lists the hidden-input guesser (hidden_inputs.go) sends.
//
// # Provenance
//
// Hand-assembled for burpsy (burpsy-react-ui-wlz8) from names that recur across web frameworks,
// debugging conventions, reverse-proxy and CDN deployments, and well-known feature-flag patterns:
// the framework documentation for Django, Rails, Laravel, Spring, ASP.NET and Express; the
// de-facto X-Forwarded-* family and the headers common load balancers and CDNs set; and the
// parameter names that recur in public write-ups of hidden debug or admin switches. It is NOT a
// copy of Param Miner's bundled wordlists, and it is far shorter than them on purpose: Param Miner
// mines tens of thousands of names, while this list is a few hundred so that a default run fits
// the guesser's request budget with room left for bisection and confirmation. A target whose
// hidden inputs are not on this list reports nothing about them — the run summary says the
// absence is an absence of guesses, not of inputs.
//
// # What is deliberately absent from the header list
//
// hiddenHeaderDenylist names the headers that change how the request is FRAMED or ROUTED rather
// than what the application reads (Host, Content-Length, Transfer-Encoding, Connection, …). Sending
// one with a random value is a malformed request, not a guess, and some of them are request
// smuggling primitives. Cookie and Authorization are absent too: Cookie has its own kind, and a
// random Authorization value is a failed login attempt against an account lockout policy rather
// than a probe of an unlinked input. TestHiddenInputWordlistsAreClean enforces the denylist.

// hiddenHeaderDenylist is checked against the header list in a test and against every header name
// at send time, so a wordlist edit cannot reintroduce a framing header.
var hiddenHeaderDenylist = map[string]bool{
	"host": true, "content-length": true, "transfer-encoding": true, "connection": true,
	"te": true, "trailer": true, "upgrade": true, "expect": true, "keep-alive": true,
	"proxy-connection": true, "proxy-authorization": true, "proxy-authenticate": true,
	"content-encoding": true, "content-type": true, "cookie": true, "authorization": true,
	"range": true, "if-range": true, "http2-settings": true,
}

var hiddenQueryWordlist = []string{
	// Debugging and diagnostics.
	"debug", "debug_mode", "debugmode", "dbg", "trace", "verbose", "test", "testing", "test_mode",
	"dev", "devmode", "development", "profile", "profiler", "explain", "show_errors", "showerrors",
	"display_errors", "errors", "stacktrace", "log", "logging", "loglevel", "log_level", "dump",
	"diag", "diagnostics", "inspect", "benchmark", "timing", "sql", "show_sql", "query_debug",
	// Access and role switches.
	"admin", "is_admin", "isadmin", "administrator", "role", "roles", "user_role", "access",
	"access_level", "level", "privilege", "priv", "superuser", "su", "root", "staff", "internal",
	"employee", "auth", "authenticated", "logged_in", "login", "bypass", "override", "force",
	"sudo", "impersonate", "as_user", "act_as", "user", "user_id", "uid", "userid", "account",
	"account_id", "tenant", "tenant_id", "org", "org_id", "group", "group_id",
	// Feature flags and preview modes.
	"beta", "preview", "draft", "experimental", "feature", "features", "flag", "flags", "enable",
	"enabled", "disable", "toggle", "mode", "variant", "ab", "experiment", "canary", "legacy",
	"new", "old", "v", "version", "api_version", "apiversion", "edition",
	// Output shaping.
	"format", "output", "type", "view", "template", "theme", "layout", "lang", "language", "locale",
	"callback", "jsonp", "cb", "json", "xml", "raw", "pretty", "fields", "include", "expand",
	"embed", "select", "columns", "sort", "order", "orderby", "sortby", "dir", "limit", "offset",
	"page", "per_page", "pagesize", "count", "size", "max", "filter", "where", "search", "q",
	"query", "keyword", "fmt",
	// Navigation and resource selectors.
	"redirect", "redirect_uri", "redirect_url", "return", "return_to", "returnurl", "next", "url",
	"uri", "target", "dest", "destination", "goto", "continue", "forward", "path", "file",
	"filename", "folder", "doc", "document", "resource", "source", "src", "ref", "referrer",
	"id", "key", "name", "action", "do", "cmd", "command", "func", "method", "op", "operation",
	"task", "step", "stage", "env", "environment", "config", "settings", "options", "opt",
	"cache", "nocache", "no_cache", "refresh", "reload", "reset", "token", "access_token",
	"api_key", "apikey", "secret", "signature", "sig", "hash", "nonce", "csrf", "state",
	"session", "sessionid", "sid", "preview_token", "share", "shared", "public", "private",
	"hidden", "show", "showall", "all", "full", "details", "extended", "export", "download",
	"print", "debug_token", "_debug", "__debug", "_method", "_format", "_escaped_fragment_",
}

var hiddenCookieWordlist = []string{
	"debug", "debug_mode", "dev", "devmode", "test", "testing", "beta", "preview", "admin",
	"is_admin", "isadmin", "role", "user_role", "access_level", "staff", "internal", "employee",
	"superuser", "su", "impersonate", "as_user", "user", "user_id", "uid", "userid", "username",
	"account", "tenant", "org", "lang", "language", "locale", "theme", "layout", "template", "view",
	"mode", "variant", "experiment", "ab_test", "abtest", "feature", "features", "flags",
	"canary", "legacy", "version", "api_version", "edition", "plan", "tier", "premium",
	"subscription", "trial", "region", "country", "currency", "timezone", "tz", "device",
	"platform", "mobile", "app", "client", "source", "ref", "referrer", "campaign", "affiliate",
	"partner", "promo", "coupon", "cart", "basket", "consent", "gdpr", "tracking", "optout",
	"remember", "remember_me", "auth", "authenticated", "logged_in", "login", "token", "jwt",
	"access_token", "api_key", "csrftoken", "xsrf", "sessionid", "sid", "session",
}

var hiddenHeaderWordlist = []string{
	// Origin and client-address reporting: the family reverse proxies set and applications trust.
	"X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Forwarded-Port",
	"X-Forwarded-Scheme", "X-Forwarded-Server", "X-Forwarded-Prefix", "X-Forwarded-Path",
	"X-Forwarded-Uri", "X-Forwarded-By", "X-Forwarded", "Forwarded", "X-Real-IP", "X-Client-IP",
	"X-Remote-IP", "X-Remote-Addr", "X-Originating-IP", "X-Host", "X-Original-Host",
	"X-Original-URL", "X-Rewrite-URL", "X-Original-URI", "X-Override-URL", "X-Custom-IP-Authorization",
	"True-Client-IP", "CF-Connecting-IP", "Fastly-Client-IP", "X-Cluster-Client-IP", "Client-IP",
	"X-ProxyUser-Ip", "Via", "X-Backend-Host", "X-Backend-Server", "X-Proxy-URL",
	"X-HTTP-Host-Override", "X-Http-Destinationurl",
	// Method and protocol overrides. Sent with a random value, never a real verb, so a framework
	// that honours the header sees an unknown method rather than a DELETE.
	"X-HTTP-Method-Override", "X-HTTP-Method", "X-Method-Override", "X-Original-Method",
	// Debugging and diagnostics.
	"X-Debug", "X-Debug-Mode", "X-Debug-Token", "X-Debug-Token-Link", "Debug", "X-Dev",
	"X-Developer", "X-Test", "X-Testing", "X-Trace", "X-Verbose", "X-Profile", "X-Profiler",
	"X-Show-Errors", "X-Internal", "X-Internal-Request", "X-Internal-Debug", "X-Bypass",
	"X-Bypass-Cache", "X-Cache-Bypass", "X-No-Cache", "X-Purge", "X-Feature", "X-Features",
	"X-Feature-Flag", "X-Feature-Flags", "X-Beta", "X-Preview", "X-Canary", "X-Experiment",
	"X-Variant", "X-Environment", "X-Env", "X-Stage", "X-Mode",
	// Versioning and content negotiation that applications read themselves.
	"X-Api-Version", "Api-Version", "X-Version", "Accept-Version", "X-App-Version",
	"X-Client-Version", "X-Requested-With", "X-Request-ID", "X-Correlation-ID", "X-Trace-ID",
	"X-Amzn-Trace-Id", "X-B3-TraceId", "Traceparent", "X-Device", "X-Platform", "X-Mobile",
	"X-Client", "X-Client-Name", "X-Locale", "X-Language", "X-Timezone", "X-Country",
	"X-Region", "X-Tenant", "X-Tenant-ID", "X-Org-ID", "X-Account-ID",
	// Identity assertions that some back ends accept from a trusted front end.
	"X-User", "X-User-ID", "X-User-Name", "X-Username", "X-Remote-User", "Remote-User",
	"X-Auth-User", "X-Authenticated-User", "X-Role", "X-Roles", "X-User-Role", "X-Admin",
	"X-Is-Admin", "X-Access-Level", "X-Impersonate", "X-Api-Key", "X-Api-Token",
	"X-Auth-Token", "X-Access-Token", "X-Csrf-Token", "X-Xsrf-Token", "X-Session-ID",
	// Cache and edge behaviour.
	"X-Cache-Key", "X-Cache-Status", "X-Edge-Location", "Surrogate-Control", "X-Accel-Buffering",
	"X-Wap-Profile", "X-ATT-DeviceId", "X-UIDH", "Pragma", "Max-Forwards", "From",
}
