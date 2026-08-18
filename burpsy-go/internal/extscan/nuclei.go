package extscan

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/report"
)

// TemplateHit is one nuclei match: a template fired at a location. The
// template's own identity is kept whole — id, name, severity, tags — because a
// hit is only actionable if a reader can find the template that produced it and
// judge it.
type TemplateHit struct {
	TemplateID string `json:"template_id"`
	Name       string `json:"name"`
	// Severity is nuclei's own string ("info".."critical"), kept verbatim
	// alongside the mapped value so a reader can see what was translated.
	Severity string `json:"severity"`
	// MatchedAt is the exact URL the template matched at, which is not always
	// the target: a template may follow a path of its own.
	MatchedAt   string   `json:"matched_at"`
	Host        string   `json:"host"`
	Port        string   `json:"port"`
	Path        string   `json:"path"`
	Type        string   `json:"type"`
	MatcherName string   `json:"matcher_name,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	Description string   `json:"description,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
	References  []string `json:"references,omitempty"`
	// Extracted is whatever the template's extractors pulled out — often the
	// single most useful line in a hit (a version, a leaked path).
	Extracted []string `json:"extracted,omitempty"`
	// CurlCommand is nuclei's own reproduction line, carried because a finding
	// someone can re-run is worth more than one they have to reconstruct.
	CurlCommand string `json:"curl_command,omitempty"`
}

// NucleiOptions are the knobs a caller may set on one nuclei run.
type NucleiOptions struct {
	// Templates restricts the run to specific template files or directories
	// (nuclei's -t). Empty runs nuclei's default corpus.
	Templates []string
	// Severities restricts the run by severity (nuclei's -severity), e.g.
	// "medium,high,critical". Empty runs every severity the corpus offers.
	Severities string
	// Tags restricts the run by template tag (nuclei's -tags).
	Tags string
	// RateLimit caps requests per second (nuclei's -rl). Zero takes nuclei's
	// own default; an engagement with a rate agreement should set it.
	RateLimit int
	// Interactsh turns nuclei's OAST templates back on. Off by default: those
	// templates report through a third-party interaction server, and an
	// engagement has to opt into that deliberately rather than inherit it.
	// burpsy has its own out-of-band channel in internal/oob.
	Interactsh bool
	// IncludeRaw keeps the request/response pair in each JSON record.
	//
	// Off by default because raw pairs are what make a nuclei stream unbounded,
	// and this package caps what it will hold. Omitting them does not change
	// which templates match or how many records arrive — it drops the request
	// and response bodies from each one. The cost is that a hit's evidence is
	// then its URL and nuclei's own curl line rather than the exchange itself,
	// which is why this is a knob and not a constant.
	IncludeRaw bool
}

// NucleiResult is one nuclei run. As with FFUFResult, Outcome and not
// len(Hits) is what says whether anything was examined.
type NucleiResult struct {
	Outcome Outcome
	Target  Target
	Hits    []TemplateHit
	// Err explains every outcome but OutcomeCompleted, and is nil for that one.
	Err error
	// Command is the argv actually executed.
	Command  []string
	ExitCode int
	// Truncated records that the captured output hit the configured cap, so the
	// hit list is a prefix of what nuclei reported rather than all of it. A
	// truncated run that still parsed is completed-but-partial, and a reader has
	// to be told which.
	Truncated bool
}

// nucleiRecord is one line of nuclei's -jsonl stream. Only the fields read here
// are mapped.
type nucleiRecord struct {
	TemplateID string `json:"template-id"`
	Info       struct {
		Name        string   `json:"name"`
		Severity    string   `json:"severity"`
		Description string   `json:"description"`
		Remediation string   `json:"remediation"`
		Tags        []string `json:"tags"`
		Reference   []string `json:"reference"`
	} `json:"info"`
	Type             string   `json:"type"`
	Host             string   `json:"host"`
	Port             string   `json:"port"`
	Path             string   `json:"path"`
	URL              string   `json:"url"`
	MatchedAt        string   `json:"matched-at"`
	MatcherName      string   `json:"matcher-name"`
	ExtractedResults []string `json:"extracted-results"`
	CurlCommand      string   `json:"curl-command"`
}

// RunNuclei runs nuclei's template corpus against target.
//
// As with RunFFUF the target must have come from Authorise: nuclei templates
// choose their own paths, so the subtree — not just the base URL — has to be in
// scope before the binary is launched.
//
// nuclei streams one JSON object per match to stdout under -jsonl, so unlike
// ffuf there is no output file to manage. The banner and progress lines go to
// stderr and -silent quiets them; the parser skips any non-JSON line regardless,
// because a tool's log noise must not be able to fail a scan.
func RunNuclei(ctx context.Context, cfg Config, scope ScopeAuthoriser, target Target, opts NucleiOptions) NucleiResult {
	res := NucleiResult{Target: target, ExitCode: -1}
	if !target.Authorised() {
		res.Outcome = OutcomeUnauthorised
		res.Err = fmt.Errorf("%w: this target did not come from Authorise", ErrUnauthorised)
		return res
	}
	path, err := cfg.resolve(ToolNuclei)
	if err != nil {
		res.Outcome = OutcomeNotAllowed
		if !isNotAllowed(err) {
			res.Outcome = OutcomeUnavailable
		}
		res.Err = err
		return res
	}

	args := []string{
		"-u", target.URL,
		"-jsonl",
		// -silent keeps the banner and progress off the stream, -nc drops ANSI
		// colouring, -duc stops nuclei reaching for the network to check for its
		// own updates mid-engagement, -ot drops the base64 template blob that
		// otherwise doubles every record.
		"-silent", "-nc", "-duc", "-ot",
	}
	if !opts.IncludeRaw {
		args = append(args, "-omit-raw")
	}
	if !opts.Interactsh {
		args = append(args, "-ni")
	}
	for _, t := range opts.Templates {
		args = append(args, "-t", t)
	}
	if opts.Severities != "" {
		args = append(args, "-severity", opts.Severities)
	}
	if opts.Tags != "" {
		args = append(args, "-tags", opts.Tags)
	}
	if opts.RateLimit > 0 {
		args = append(args, "-rl", strconv.Itoa(opts.RateLimit))
	}
	res.Command = append([]string{path}, args...)

	stdout, stderr, code, runErr := run(ctx, cfg, path, args)
	res.ExitCode = code
	hits, truncated, parseErr := parseNuclei(stdout)
	res.Truncated = truncated

	// A run that failed at the process level but still streamed usable records
	// is reported with what it produced — nuclei exits non-zero for reasons that
	// do not invalidate the matches already written. Only a run with nothing
	// parsed is a refusal.
	if len(hits) == 0 {
		switch {
		case runErr != nil:
			res.Outcome = OutcomeFailed
			res.Err = fmt.Errorf("extscan: nuclei: %w: %s", runErr, trimErr(stderr))
			return res
		case parseErr != nil:
			res.Outcome = OutcomeFailed
			res.Err = parseErr
			return res
		}
	}

	res.Hits = filterHitsInScope(scope, target, hits)
	res.Outcome = OutcomeCompleted
	return res
}

// parseNuclei reads the -jsonl stream.
//
// A line that is not JSON is skipped: nuclei writes log lines into the same
// stream in some modes, and refusing the whole run over one of them would turn
// cosmetic noise into a failed scan. A truncated final line — the capped buffer
// cutting mid-record — is reported through the truncated return rather than as
// an error, because everything before it is still real.
func parseNuclei(b []byte) (hits []TemplateHit, truncated bool, err error) {
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 0, 64*1024), 8<<20)
	var lines [][]byte
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		lines = append(lines, append([]byte(nil), line...))
	}
	if scErr := sc.Err(); scErr != nil {
		return nil, false, fmt.Errorf("extscan: reading nuclei output: %w", scErr)
	}
	for i, line := range lines {
		var rec nucleiRecord
		if uerr := json.Unmarshal(line, &rec); uerr != nil {
			// Only the last line can legitimately be half-written; anything
			// earlier is output this parser does not understand, and guessing is
			// the wrong response to that.
			if i == len(lines)-1 {
				truncated = true
				break
			}
			return hits, truncated, fmt.Errorf("extscan: unparseable nuclei record: %w", uerr)
		}
		hits = append(hits, hitOf(rec))
	}
	return hits, truncated, nil
}

func hitOf(rec nucleiRecord) TemplateHit {
	matchedAt := rec.MatchedAt
	if matchedAt == "" {
		matchedAt = rec.URL
	}
	p := rec.Path
	if p == "" {
		p = pathOf(matchedAt)
	}
	return TemplateHit{
		TemplateID:  rec.TemplateID,
		Name:        rec.Info.Name,
		Severity:    rec.Info.Severity,
		MatchedAt:   matchedAt,
		Host:        rec.Host,
		Port:        rec.Port,
		Path:        p,
		Type:        rec.Type,
		MatcherName: rec.MatcherName,
		Tags:        rec.Info.Tags,
		Description: rec.Info.Description,
		Remediation: rec.Info.Remediation,
		References:  rec.Info.Reference,
		Extracted:   rec.ExtractedResults,
		CurlCommand: rec.CurlCommand,
	}
}

// filterHitsInScope drops any hit whose path the scope does not authorise, for
// the same reason RunFFUF filters discoveries: a template that wandered outside
// the engagement must not report as though burpsy meant to go there.
func filterHitsInScope(scope ScopeAuthoriser, target Target, in []TemplateHit) []TemplateHit {
	if scope == nil {
		return nil
	}
	out := make([]TemplateHit, 0, len(in))
	for _, h := range in {
		if scope.Contains(target.Host, target.Port, h.Path, target.IsTLS) {
			out = append(out, h)
		}
	}
	return out
}

// MapSeverity translates nuclei's severity string into burpsy's own severity
// vocabulary.
//
// The mapping is deliberately the identity on the four names both vocabularies
// share and sends everything else — nuclei's "info" and its "unknown" alike —
// to Informational. That is what core.ParseSeverity already does for burpsy's
// own checks, so routing through it is what keeps one merged report from
// carrying two severity scales that only look alike. A nuclei "high" and a
// burpsy "high" sort together because they are the same value, not because a
// renderer happens to uppercase both.
func MapSeverity(nucleiSeverity string) core.Severity {
	return core.ParseSeverity(strings.TrimSpace(nucleiSeverity))
}

// Rows renders the run as report rows, one per distinct template.
//
// Grouping is by template rather than by hit because a template that matches at
// forty URLs is one issue observed forty times, which is exactly what Row's
// Occurrences and Evidence already express — and is how burpsy's own findings
// are counted, so the two sets are comparable in one report.
func (r NucleiResult) Rows() []report.Row {
	if r.Outcome != OutcomeCompleted || len(r.Hits) == 0 {
		return nil
	}
	byTemplate := map[string][]TemplateHit{}
	var order []string
	for _, h := range r.Hits {
		if _, seen := byTemplate[h.TemplateID]; !seen {
			order = append(order, h.TemplateID)
		}
		byTemplate[h.TemplateID] = append(byTemplate[h.TemplateID], h)
	}
	// Worst first, then by template id, so a rerun renders identically and a
	// reader meets the severe rows first.
	sortStringsBy(order, func(a, b string) bool {
		sa := MapSeverity(byTemplate[a][0].Severity)
		sb := MapSeverity(byTemplate[b][0].Severity)
		if sa != sb {
			return sa > sb
		}
		return a < b
	})

	rows := make([]report.Row, 0, len(order))
	for _, id := range order {
		group := byTemplate[id]
		first := group[0]
		evidence := make([]report.Evidence, 0, len(group))
		hosts := map[string]bool{}
		for _, h := range group {
			host := h.Host
			if h.Port != "" && h.Port != "80" && h.Port != "443" {
				host = h.Host + ":" + h.Port
			}
			evidence = append(evidence, report.Evidence{
				Host:   host,
				Path:   h.Path,
				Method: "GET",
			})
			hosts[host] = true
		}
		rows = append(rows, report.Row{
			Name:         nucleiRowName(first),
			Severity:     MapSeverity(first.Severity).String(),
			Confidence:   "Firm",
			Description:  nucleiDescription(first, group),
			Remediation:  nucleiRemediation(first),
			Hosts:        sortedKeys(hosts),
			Occurrences:  len(group),
			Evidence:     evidence,
			AdvisoryNote: nucleiAdvisoryNote(first),
		})
	}
	return rows
}

func nucleiRowName(h TemplateHit) string {
	if h.Name != "" {
		return h.Name
	}
	return h.TemplateID
}

// nucleiAdvisoryNote says why the row carries no catalogue entry.
//
// The bundled catalogue is Burp's 183 issue definitions keyed by Burp's own
// issue types, and a nuclei template id is not one of them. Naming the template
// is the honest substitute: it tells a reader exactly where the claim came from
// and what to read to check it.
func nucleiAdvisoryNote(h TemplateHit) string {
	return fmt.Sprintf("Reported by the external nuclei tool from template %q (severity %q as nuclei "+
		"rated it). The bundled issue-definition catalogue is keyed by Burp issue type and has no "+
		"entry for a nuclei template, so this row carries the template's own text instead.",
		h.TemplateID, h.Severity)
}

func nucleiDescription(first TemplateHit, group []TemplateHit) string {
	var b strings.Builder
	if first.Description != "" {
		b.WriteString(strings.TrimSpace(first.Description))
	} else {
		fmt.Fprintf(&b, "The nuclei template %q matched.", first.TemplateID)
	}
	if len(first.Tags) > 0 {
		fmt.Fprintf(&b, " Template tags: %s.", strings.Join(first.Tags, ", "))
	}
	// Extracted values are the concrete part of a template hit, so they are
	// stated rather than left for someone to re-run the tool to see.
	var extracted []string
	for _, h := range group {
		extracted = append(extracted, h.Extracted...)
	}
	if len(extracted) > 0 {
		fmt.Fprintf(&b, " Extracted: %s.", strings.Join(dedupe(extracted), ", "))
	}
	if first.CurlCommand != "" {
		fmt.Fprintf(&b, " Reproduce with: %s", first.CurlCommand)
	}
	return b.String()
}

func nucleiRemediation(h TemplateHit) string {
	if strings.TrimSpace(h.Remediation) != "" {
		return strings.TrimSpace(h.Remediation)
	}
	if len(h.References) > 0 {
		return "The template carries no remediation text. See: " + strings.Join(h.References, ", ")
	}
	return "The nuclei template carries no remediation text; consult the template " +
		h.TemplateID + " and confirm the match before acting on it."
}
