// checks_reflection3.go ports five more catalog issues from real recovered Java evidence in
// out/strings/map_root.tsv: backup file discovery (burp.Zem7/Zsro/Zxc6/Zxfn — four Java classes
// that probe the same catalog issue with different filename-mutation strategies), User-Agent- and
// Referer-dependent response (burp.Zxly/Zxlg), and ASP.NET debugging/tracing enabled
// (burp.Zihl/Ze3_+Zsqx). Same shape as checks_reflection2.go: a pure classifier plus a thin
// CheckRunner.
package scanner

import (
	"context"
	"strings"
)

func responseDependenceChecksEnabled(c *ScanConfig) bool {
	return c != nil && c.CheckResponseDependence
}

// ---------------------------------------------------------------------------
// Backup file — burp.Zem7 (append-extension) + Zsro (replace-extension) + Zxc6 (prefix-filename)
// + Zxfn (append-filename)
// ---------------------------------------------------------------------------

const backupFileIssue = "Backup file"

// backupFilenameSuffixes are Zxfn's own literal append-filename suffixes, recovered verbatim from
// out/strings/map_root.tsv. Multi-word variants keep Zxfn's own leading space.
var backupFilenameSuffixes = [...]string{
	"_bak", "_backup", "_old",
	" (copy)", " (2nd copy)", " (3rd copy)", " (4th copy)", " (another copy)",
	" - Copy", " - Copy (2)", " - Copy - Copy",
}

// backupFilenamePrefixes are Zxc6's own literal prefix-filename strings, recovered verbatim.
var backupFilenamePrefixes = [...]string{
	"bak_", "backup_", "old_", "Copy of ", "Copy of Copy of ", "Copy (2) of ",
}

// backupReplaceExtensions are Zsro's own literal replace-extension strings for JSP applications,
// recovered verbatim (Zsro is the JSP-specific variant of the replace-extension strategy).
var backupReplaceExtensions = [...]string{".jspa", ".jspx", ".jspf"}

// backupAppendExtensions are generic backup extensions for the append-extension strategy (Zem7).
// Zem7's own literal array decodes to ZKM ciphertext residue with no recoverable value (see
// checks_reflection2.go's file header for the same limitation on Zsn3/Zexx); these are the
// industry-standard backup-file extensions, not Burp-specific.
var backupAppendExtensions = [...]string{".bak", ".old", ".orig", "~"}

// checkBackupFile splits the exchange's own path into directory/base/extension and tries Zxfn's
// suffixes, Zxc6's prefixes, Zsro's JSP extension-replacements, and the append-extension
// strategy's generic extensions, in that order, stopping at the first candidate that returns 200
// with a body that differs from a definite-404 control fetched once up front — the same
// differential-evidence shape sqli.go's responsesDiffer uses, so a host that returns 200 for every
// path (rather than actually serving the backup) does not produce a false positive.
func checkBackupFile(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	exchange := cc.Exchange
	dir, base, ext := splitPathForBackup(exchange.Path)
	if base == "" {
		return nil, nil
	}

	controlResp := cc.Scanner.sendTestRequestFull(ctx, exchange, dir+base+".burpsy-control-404"+ext, nil)
	control := ""
	if controlResp != nil {
		control = string(controlResp.Body)
	}

	var candidates []string
	for _, suf := range backupFilenameSuffixes {
		candidates = append(candidates, dir+base+suf+ext)
	}
	for _, pre := range backupFilenamePrefixes {
		candidates = append(candidates, dir+pre+base+ext)
	}
	if ext == ".jsp" {
		for _, replacement := range backupReplaceExtensions {
			candidates = append(candidates, dir+base+replacement)
		}
	}
	for _, appended := range backupAppendExtensions {
		candidates = append(candidates, dir+base+ext+appended)
	}

	for _, candidate := range candidates {
		resp := cc.Scanner.sendTestRequestFull(ctx, exchange, candidate, nil)
		if resp == nil || resp.StatusCode != 200 || len(resp.Body) == 0 {
			continue
		}
		if !responsesDiffer(control, string(resp.Body)) {
			continue
		}
		return []*Finding{buildProbeFinding(cc, backupFileIssue, "tentative",
			candidate+" returned HTTP 200 with a body distinct from a definite-404 control",
			"a backup or outdated copy of this file may be publicly accessible at "+candidate)}, nil
	}
	return nil, nil
}

// splitPathForBackup splits an exchange path (which may carry a query string) into its directory
// (including trailing slash), filename base, and extension (including the leading dot). Returns
// base == "" for a path with no filename component (e.g. a bare "/").
func splitPathForBackup(path string) (dir, base, ext string) {
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	slash := strings.LastIndexByte(path, '/')
	dir, filename := path[:slash+1], path[slash+1:]
	if filename == "" {
		return dir, "", ""
	}
	if dot := strings.LastIndexByte(filename, '.'); dot > 0 {
		return dir, filename[:dot], filename[dot:]
	}
	return dir, filename, ""
}

// ---------------------------------------------------------------------------
// User agent-dependent response — burp.Zxly
// ---------------------------------------------------------------------------

const userAgentDependentIssue = "User agent-dependent response"

// mobileUserAgent is one of Zxly's own literal User-Agent strings, recovered verbatim from
// out/strings/map_root.tsv — the iPhone Safari string, chosen because Zxly's own device-name
// substring list (nokia/samsung/htc/symbian/blackberry/android/sonyericsson/mot) shows the check
// is specifically hunting for a desktop-vs-mobile content split.
const mobileUserAgent = "Mozilla/5.0 (iPhone; CPU iPhone OS 5_1 like Mac OS X) AppleWebKit/534.46 (KHTML, like Gecko) Version/5.1 Mobile/9B176 Safari/7534.48.3"

// checkUserAgentDependentResponse compares the exchange's own captured response against a probe
// sent with Zxly's recovered mobile User-Agent string.
func checkUserAgentDependentResponse(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	exchange := cc.Exchange
	baseline := responseRaw(cc.Scanner, exchange)
	if baseline == "" {
		return nil, nil
	}
	resp := cc.Scanner.sendTestRequestFull(ctx, exchange, exchange.Path, map[string]string{"User-Agent": mobileUserAgent})
	if resp == nil {
		return nil, nil
	}
	if !responsesDiffer(baseline, string(resp.Body)) {
		return nil, nil
	}
	return []*Finding{buildProbeFinding(cc, userAgentDependentIssue, "firm",
		"the response body changed when the request's User-Agent header was replaced with a mobile browser string",
		"the application serves systematically different content based on the User-Agent header, which may expose separately-tested attack surface")}, nil
}

// ---------------------------------------------------------------------------
// Referer-dependent response — burp.Zxlg
// ---------------------------------------------------------------------------

const refererDependentIssue = "Referer-dependent response"

// checkRefererDependentResponse compares the exchange's own captured response against a probe
// sent with a crafted Referer header, built from Zxlg's own recovered literal fragments
// ("http://", ".com/") around a fresh canary so the probe cannot be mistaken for a real referrer.
func checkRefererDependentResponse(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	exchange := cc.Exchange
	baseline := responseRaw(cc.Scanner, exchange)
	if baseline == "" {
		return nil, nil
	}
	referer := "http://" + newProbeCanary("brpr") + ".com/"
	resp := cc.Scanner.sendTestRequestFull(ctx, exchange, exchange.Path, map[string]string{"Referer": referer})
	if resp == nil {
		return nil, nil
	}
	if !responsesDiffer(baseline, string(resp.Body)) {
		return nil, nil
	}
	return []*Finding{buildProbeFinding(cc, refererDependentIssue, "firm",
		"the response body changed when the request carried a Referer header pointing at "+referer,
		"the application serves systematically different content based on the Referer header")}, nil
}

// ---------------------------------------------------------------------------
// ASP.NET debugging enabled — burp.Zihl
// ---------------------------------------------------------------------------

const aspDebuggingIssue = "ASP.NET debugging enabled"

// aspDebuggingResponseMarkers are burp.Zihl's own literal response strings, recovered verbatim.
// A server that does not implement the ASP.NET remote-debugging protocol would not recognise the
// custom Command header at all and would simply serve /Default.aspx normally, so either marker
// text appearing — even the access-denied one — proves the debugging endpoint exists.
var aspDebuggingResponseMarkers = [...]string{
	"Debug access denied to '/Default.aspx'.",
	"DebugSessionID corrupted or not provided.",
}

// checkASPDebuggingEnabled sends Zihl's own literal probe: GET /Default.aspx with a
// "Command: start-debug" header (the ASP.NET remote-debugging wire protocol's start command).
func checkASPDebuggingEnabled(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	exchange := cc.Exchange
	resp := cc.Scanner.sendTestRequestFull(ctx, exchange, "/Default.aspx", map[string]string{"Command": "start-debug"})
	if resp == nil {
		return nil, nil
	}
	body := string(resp.Body)
	for _, marker := range aspDebuggingResponseMarkers {
		if strings.Contains(body, marker) {
			return []*Finding{buildProbeFinding(cc, aspDebuggingIssue, "certain",
				"/Default.aspx with a \"Command: start-debug\" header returned the ASP.NET debugging protocol response: "+marker,
				"the server recognised the ASP.NET remote-debugging wire protocol, meaning the remote-debugging endpoint is reachable")}, nil
		}
	}
	return nil, nil
}

// ---------------------------------------------------------------------------
// ASP.NET tracing enabled — burp.Ze3_ (host scope) + Zsqx (request scope)
// ---------------------------------------------------------------------------

const aspTracingIssue = "ASP.NET tracing enabled"

// checkASPTracingEnabled fetches /trace.axd (Ze3_'s own literal path) and confirms on the
// built-in ASP.NET trace viewer's own CSS class name, "tracecontent" — a real, documented
// Microsoft-assigned class that only appears when trace.axd actually renders the trace viewer,
// consistent with the "class"/"span"/"aspx"/"tracecontent" token evidence recovered for Zsqx.
func checkASPTracingEnabled(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	exchange := cc.Exchange
	resp := cc.Scanner.sendTestRequestFull(ctx, exchange, "/trace.axd", nil)
	if resp == nil || resp.StatusCode != 200 {
		return nil, nil
	}
	body := string(resp.Body)
	if !strings.Contains(body, `class="tracecontent"`) {
		return nil, nil
	}
	return []*Finding{buildProbeFinding(cc, aspTracingIssue, "certain",
		"/trace.axd returned HTTP 200 rendering the ASP.NET trace viewer (class=\"tracecontent\")",
		"ASP.NET application-level tracing is enabled and discloses recent requests, including other users' session tokens and parameters")}, nil
}

// ---------------------------------------------------------------------------

// ResponseDependenceCheckDescriptors returns the five native checks this file owns.
func ResponseDependenceCheckDescriptors() []CheckDescriptor {
	return []CheckDescriptor{
		nativeDescriptor(backupFileIssue, DispatchScopePerUrl, responseDependenceChecksEnabled, checkBackupFile),
		nativeDescriptor(userAgentDependentIssue, DispatchScopePerUrl, responseDependenceChecksEnabled, checkUserAgentDependentResponse),
		nativeDescriptor(refererDependentIssue, DispatchScopePerUrl, responseDependenceChecksEnabled, checkRefererDependentResponse),
		nativeDescriptor(aspDebuggingIssue, DispatchScopePerHost, responseDependenceChecksEnabled, checkASPDebuggingEnabled),
		nativeDescriptor(aspTracingIssue, DispatchScopePerHost, responseDependenceChecksEnabled, checkASPTracingEnabled),
	}
}
