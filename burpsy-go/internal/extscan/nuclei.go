package extscan

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
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
	// RateLimit caps requests per second (nuclei's -rl). Zero takes
	// DefaultNucleiRateLimit — not nuclei's own default of 150, which is a load
	// test; an engagement with a rate agreement should set it.
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
	// OutOfScope counts hits the engagement scope does not authorise, dropped from
	// Hits and counted here for the same reason FFUFResult.OutOfScope is.
	OutOfScope int
	// EgressGate says what the run's egress gate enforced (EgressGatePerRequest
	// or EgressGatePerAuthority); empty when the tool was never launched.
	EgressGate string
	// GateRefused counts the requests the egress gate refused before they were
	// sent; GateRefusals is a sample (at most 50) naming them. A template whose
	// requests were refused did not run as written, so a non-zero count makes
	// the run OutcomePartial with IncompleteScopeRefused.
	GateRefused  int
	GateRefusals []string
	// Err explains every outcome but OutcomeCompleted, and is nil for that one.
	// For OutcomePartial it is why the run was cut short.
	Err error
	// Command is the argv actually executed.
	Command  []string
	ExitCode int
	// Truncated records that the captured output hit the configured cap, so the
	// hit list is a prefix of what nuclei reported rather than all of it. A
	// truncated run that still parsed is OutcomePartial with Incomplete
	// IncompleteCapped (unless something more fundamental also cut it short).
	Truncated bool
	// Incomplete says why an OutcomePartial run did not finish, and is ""
	// for every other outcome (burpsy-react-ui-b2wh).
	Incomplete IncompleteReason
}

// IncompleteReason names why a run that reported results did not finish.
type IncompleteReason string

const (
	// IncompleteTimeout: the run hit its timeout and nuclei was killed.
	IncompleteTimeout IncompleteReason = "timed out"
	// IncompleteStopped: the caller stopped the run and nuclei was killed.
	IncompleteStopped IncompleteReason = "stopped"
	// IncompleteOutput: nuclei exited but its output was not fully captured
	// (a process it started held the pipes open past procgroup.WaitDelay).
	IncompleteOutput IncompleteReason = "incomplete output"
	// IncompleteUnparseable: a record mid-stream could not be parsed, so the
	// records after it were not read.
	IncompleteUnparseable IncompleteReason = "unparseable output"
	// IncompleteCapped: the captured output hit Config.MaxOutputBytes.
	IncompleteCapped IncompleteReason = "output cap reached"
	// IncompleteScopeRefused: the egress gate refused requests templates made
	// outside the engagement scope, so those templates did not run as written.
	IncompleteScopeRefused IncompleteReason = "out-of-scope requests refused"
)

// incompleteOf classifies the process-level error run returned for a run that
// still produced records. Anything run reports as an error is a cut-short run:
// a non-zero exit on its own is not an error there (nuclei exits non-zero on
// ordinary conditions), so it never reaches this.
func incompleteOf(runErr error) IncompleteReason {
	switch {
	case errors.Is(runErr, ErrTimedOut):
		return IncompleteTimeout
	case errors.Is(runErr, ErrStopped):
		return IncompleteStopped
	default:
		return IncompleteOutput
	}
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

	gate, refusals, mode, err := startEgressGate(cfg, scope, target)
	if err != nil {
		res.Outcome = OutcomeUnauthorised
		if !errors.Is(err, ErrUnauthorised) {
			res.Outcome = OutcomeFailed
		}
		res.Err = err
		return res
	}
	defer gate.Close()
	res.EgressGate = mode

	args := nucleiArgs(target, opts, gate.URL())
	res.Command = append([]string{path}, args...)

	stdout, stderr, code, runErr := run(ctx, cfg, path, args)
	res.ExitCode = code
	res.GateRefused, res.GateRefusals = int(gate.Refused()), refusals.snapshot()
	hits, truncated, parseErr := parseNuclei(stdout)
	res.Truncated = truncated

	// A run that failed at the process level but still streamed usable records
	// is reported with what it produced — those matches are real evidence — but
	// as OutcomePartial with the reason, never as a completed run
	// (burpsy-react-ui-b2wh): a nuclei killed at its timeout has not run the
	// templates it had not reached, and a clean "completed" would tell a reader
	// they found nothing. A plain non-zero exit is not a process-level failure
	// (run returns it as data), so a finished run that exited non-zero is still
	// completed. Only a run with nothing parsed is a refusal.
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

	res.Hits, res.OutOfScope = filterHitsInScope(scope, target, hits)
	res.Outcome = OutcomeCompleted
	switch {
	case runErr != nil:
		res.Incomplete = incompleteOf(runErr)
		res.Err = fmt.Errorf("extscan: nuclei %s; the %d hit(s) parsed before that are reported, "+
			"and templates it had not reached are not represented: %w: %s",
			res.Incomplete, len(hits), runErr, trimErr(stderr))
	case parseErr != nil:
		res.Incomplete = IncompleteUnparseable
		res.Err = fmt.Errorf("extscan: nuclei output stopped parsing after %d hit(s); records after "+
			"that point were not read: %w", len(hits), parseErr)
	case truncated:
		res.Incomplete = IncompleteCapped
		res.Err = fmt.Errorf("extscan: nuclei output hit the %d-byte capture cap; the %d hit(s) "+
			"parsed are a prefix of what nuclei reported", cfg.maxOutput(), len(hits))
	case res.GateRefused > 0:
		res.Incomplete = IncompleteScopeRefused
		res.Err = fmt.Errorf("extscan: the egress gate refused %d out-of-scope request(s) nuclei templates "+
			"made, so those templates did not run as written (first: %s)", res.GateRefused, firstOr(res.GateRefusals))
	}
	if res.Incomplete != "" {
		res.Outcome = OutcomePartial
	}
	return res
}

// nucleiArgs builds nuclei's argv (after the binary). proxyURL is the run's
// egress gate and is always passed: there is no nuclei invocation from this
// package that dials on its own.
func nucleiArgs(target Target, opts NucleiOptions, proxyURL string) []string {
	args := []string{
		"-u", target.URL,
		"-jsonl",
		// -silent keeps the banner and progress off the stream, -nc drops ANSI
		// colouring, -duc stops nuclei reaching for the network to check for its
		// own updates mid-engagement, -ot drops the base64 template blob that
		// otherwise doubles every record.
		"-silent", "-nc", "-duc", "-ot",
		// Every HTTP request through the egress gate.
		"-proxy", proxyURL,
		// HTTP templates only. nuclei's HTTP proxy carries HTTP; its dns, tcp,
		// ssl, websocket, whois, headless, code and javascript protocols dial
		// (or execute) on their own and would bypass the gate, so they are not
		// run from here.
		"-pt", "http",
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
	rate := opts.RateLimit
	if rate <= 0 {
		rate = DefaultNucleiRateLimit
	}
	args = append(args, "-rl", strconv.Itoa(rate))
	return args
}

func firstOr(list []string) string {
	if len(list) == 0 {
		return "none recorded"
	}
	return list[0]
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
func filterHitsInScope(scope ScopeAuthoriser, target Target, in []TemplateHit) (kept []TemplateHit, dropped int) {
	if scope == nil {
		return nil, len(in)
	}
	out := make([]TemplateHit, 0, len(in))
	for _, h := range in {
		if scope.Contains(target.Host, target.Port, h.Path, target.IsTLS) {
			out = append(out, h)
			continue
		}
		dropped++
	}
	return out, dropped
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
	if !r.Outcome.Reported() || len(r.Hits) == 0 {
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
			AdvisoryNote: nucleiAdvisoryNote(first) + r.partialNote(),
		})
	}
	return rows
}

// partialNote is appended to every row of a cut-short run, so a report read on
// its own — without the command's console output — still says the run did not
// finish and the rows are not the whole of what nuclei would have found.
func (r NucleiResult) partialNote() string {
	if r.Outcome != OutcomePartial {
		return ""
	}
	return fmt.Sprintf(" This nuclei run did not finish (%s): the hit is real, but templates the run "+
		"had not reached are not represented, so the absence of other rows is not evidence of "+
		"absence.", r.Incomplete)
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
