package extscan

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/burpsy-go/burpsy/internal/report"
)

// Discovery is one path ffuf matched — the content-discovery result burpsy has
// no native equivalent for. It is deliberately the response's shape and not a
// verdict: a 403 at /admin is a discovery, and whether that is a finding is the
// reader's call, which is why every discriminator ffuf reported is carried
// through rather than collapsed into a severity here.
type Discovery struct {
	// URL is the full URL ffuf requested.
	URL string `json:"url"`
	// Path is the path component of URL, which is what a report row shows.
	Path string `json:"path"`
	// Word is the wordlist entry that produced this path (ffuf's FUZZ value).
	Word        string `json:"word,omitempty"`
	Status      int    `json:"status"`
	Length      int64  `json:"length"`
	Words       int64  `json:"words"`
	Lines       int64  `json:"lines"`
	ContentType string `json:"content_type,omitempty"`
	// Redirect is ffuf's redirectlocation, empty when the response did not
	// redirect. It is carried because a 301 to /admin/ and a 301 to /login are
	// very different discoveries.
	Redirect string `json:"redirect,omitempty"`
	Host     string `json:"host"`
}

// FFUFOptions are the knobs a caller may set on one ffuf run. Everything else
// about the invocation is fixed by this package, so a caller cannot reshape the
// command into something the allowlist and scope gates did not anticipate.
type FFUFOptions struct {
	// Wordlist is the path to the wordlist file. Required: ffuf with no
	// wordlist is not a smaller scan, it is no scan.
	Wordlist string
	// Extensions, when set, is ffuf's -e list ("php,bak") extending each word.
	Extensions string
	// MatchCodes overrides ffuf's -mc status matcher. Empty takes ffuf's own
	// default, which already excludes 404.
	MatchCodes string
	// Threads is ffuf's -t concurrency. Zero takes ffuf's default of 40.
	Threads int
	// Rate is ffuf's -rate cap in requests per second. Zero is uncapped, which
	// is ffuf's own default; an engagement with a rate agreement should set it.
	Rate int
}

// FFUFResult is one ffuf run. Outcome, not len(Discoveries), says whether the
// tool looked: an empty Discoveries with OutcomeCompleted means ffuf swept the
// wordlist and matched nothing, and with any other outcome it means nothing was
// swept at all.
type FFUFResult struct {
	Outcome     Outcome
	Target      Target
	Discoveries []Discovery
	// Err explains every outcome but OutcomeCompleted, and is nil for that one.
	Err error
	// Command is the argv actually executed, for the provenance a delegated
	// result has to carry — a reader must be able to see what was run.
	Command  []string
	ExitCode int
}

// ffufOutput is the envelope ffuf writes under -of json. Only the fields read
// here are mapped; ffuf also embeds its whole resolved config, which is noise
// for this purpose.
type ffufOutput struct {
	Results []ffufResult `json:"results"`
}

type ffufResult struct {
	Input            map[string]string `json:"input"`
	Status           int               `json:"status"`
	Length           int64             `json:"length"`
	Words            int64             `json:"words"`
	Lines            int64             `json:"lines"`
	ContentType      string            `json:"content-type"`
	RedirectLocation string            `json:"redirectlocation"`
	URL              string            `json:"url"`
	Host             string            `json:"host"`
}

// RunFFUF fuzzes target's path space with ffuf and returns what it matched.
//
// The target must have come from Authorise — a Target this package did not
// authorise is refused here rather than scanned, so there is no call shape that
// reaches the binary without passing the scope gate.
//
// ffuf writes its JSON to a file rather than to stdout (there is no stdout-JSON
// mode: -of selects a format for the -o file), so the run gets a temporary file
// in the caller's temp dir which is removed when the run ends. FUZZ is appended
// to the authorised path, which is why Authorise insists the whole subtree is
// in scope.
func RunFFUF(ctx context.Context, cfg Config, scope ScopeAuthoriser, target Target, opts FFUFOptions) FFUFResult {
	res := FFUFResult{Target: target, ExitCode: -1}
	if !target.Authorised() {
		res.Outcome = OutcomeUnauthorised
		res.Err = fmt.Errorf("%w: this target did not come from Authorise", ErrUnauthorised)
		return res
	}
	if strings.TrimSpace(opts.Wordlist) == "" {
		res.Outcome = OutcomeNotInvoked
		res.Err = fmt.Errorf("extscan: ffuf needs a wordlist; without one there is nothing to fuzz")
		return res
	}
	if _, err := os.Stat(opts.Wordlist); err != nil {
		res.Outcome = OutcomeNotInvoked
		res.Err = fmt.Errorf("extscan: wordlist %q is unreadable: %w", opts.Wordlist, err)
		return res
	}
	path, err := cfg.resolve(ToolFFUF)
	if err != nil {
		res.Outcome = OutcomeNotAllowed
		if !isNotAllowed(err) {
			res.Outcome = OutcomeUnavailable
		}
		res.Err = err
		return res
	}

	dir, err := os.MkdirTemp("", "burpsy-ffuf-")
	if err != nil {
		res.Outcome = OutcomeFailed
		res.Err = fmt.Errorf("extscan: ffuf output directory: %w", err)
		return res
	}
	defer os.RemoveAll(dir)
	outFile := filepath.Join(dir, "ffuf.json")

	fuzzURL := strings.TrimSuffix(target.URL, "/") + "/FUZZ"
	args := []string{
		"-u", fuzzURL,
		"-w", opts.Wordlist,
		"-of", "json",
		"-o", outFile,
		// -s keeps the progress spinner off the captured stream; -noninteractive
		// stops ffuf reaching for a console it does not have here.
		"-s", "-noninteractive",
	}
	if opts.Extensions != "" {
		args = append(args, "-e", opts.Extensions)
	}
	if opts.MatchCodes != "" {
		args = append(args, "-mc", opts.MatchCodes)
	}
	if opts.Threads > 0 {
		args = append(args, "-t", fmt.Sprint(opts.Threads))
	}
	if opts.Rate > 0 {
		args = append(args, "-rate", fmt.Sprint(opts.Rate))
	}
	res.Command = append([]string{path}, args...)

	_, stderr, code, runErr := run(ctx, cfg, path, args)
	res.ExitCode = code
	if runErr != nil {
		res.Outcome = OutcomeFailed
		res.Err = fmt.Errorf("extscan: ffuf: %w: %s", runErr, trimErr(stderr))
		return res
	}

	doc, readErr := os.ReadFile(outFile)
	if readErr != nil {
		res.Outcome = OutcomeFailed
		res.Err = fmt.Errorf("extscan: ffuf wrote no output file (exit %d): %s", code, trimErr(stderr))
		return res
	}
	discoveries, parseErr := parseFFUF(doc)
	if parseErr != nil {
		res.Outcome = OutcomeFailed
		res.Err = parseErr
		return res
	}

	// Every path ffuf reached is re-checked against scope before it is reported.
	// The requests are already sent by this point — that is the cost of
	// delegation, and Authorise is what keeps it bounded — but a result outside
	// the engagement must not enter a report as though burpsy meant to fetch it.
	res.Discoveries = filterInScope(scope, target, discoveries)
	res.Outcome = OutcomeCompleted
	return res
}

// parseFFUF turns ffuf's JSON envelope into discoveries.
func parseFFUF(doc []byte) ([]Discovery, error) {
	var out ffufOutput
	if err := json.Unmarshal(doc, &out); err != nil {
		return nil, fmt.Errorf("extscan: unparseable ffuf output: %w", err)
	}
	discoveries := make([]Discovery, 0, len(out.Results))
	for _, r := range out.Results {
		discoveries = append(discoveries, Discovery{
			URL:         r.URL,
			Path:        pathOf(r.URL),
			Word:        r.Input["FUZZ"],
			Status:      r.Status,
			Length:      r.Length,
			Words:       r.Words,
			Lines:       r.Lines,
			ContentType: r.ContentType,
			Redirect:    r.RedirectLocation,
			Host:        r.Host,
		})
	}
	return discoveries, nil
}

// filterInScope drops any discovery whose path the scope does not authorise.
func filterInScope(scope ScopeAuthoriser, target Target, in []Discovery) []Discovery {
	if scope == nil {
		return nil
	}
	out := make([]Discovery, 0, len(in))
	for _, d := range in {
		if scope.Contains(target.Host, target.Port, d.Path, target.IsTLS) {
			out = append(out, d)
		}
	}
	return out
}

// Rows renders the run as report rows.
//
// Content discovery is reported as one row per distinct status class rather
// than one row per path: a wordlist sweep that matches four hundred paths would
// otherwise bury every other finding in the report, and the thing a reader acts
// on is "these twelve paths answered 403", not four hundred separate items. The
// paths themselves are the row's evidence, so nothing is lost.
//
// Severity is Informational throughout. ffuf reports that a path exists, which
// is a fact and not a vulnerability; claiming otherwise would put burpsy's own
// severity vocabulary at the mercy of somebody's wordlist.
func (r FFUFResult) Rows() []report.Row {
	if r.Outcome != OutcomeCompleted || len(r.Discoveries) == 0 {
		return nil
	}
	// Grouped by status so the row names a class a reader recognises, and
	// ordered by status so a rerun renders identically.
	byStatus := map[int][]Discovery{}
	var statuses []int
	for _, d := range r.Discoveries {
		if _, seen := byStatus[d.Status]; !seen {
			statuses = append(statuses, d.Status)
		}
		byStatus[d.Status] = append(byStatus[d.Status], d)
	}
	sortInts(statuses)

	rows := make([]report.Row, 0, len(statuses))
	for _, status := range statuses {
		group := byStatus[status]
		evidence := make([]report.Evidence, 0, len(group))
		hosts := map[string]bool{}
		for _, d := range group {
			evidence = append(evidence, report.Evidence{
				Host:   d.Host,
				Path:   d.Path,
				Method: "GET",
				Status: d.Status,
			})
			hosts[d.Host] = true
		}
		rows = append(rows, report.Row{
			Name:        fmt.Sprintf("Content discovery: %d %s", status, statusText(status)),
			Severity:    "Informational",
			Confidence:  "Certain",
			Description: ffufDescription(status, group),
			Remediation: "Confirm each path is intended to be reachable. Remove or restrict any " +
				"backup file, administrative interface or development artefact that is not part of " +
				"the published application.",
			Hosts:        sortedKeys(hosts),
			Occurrences:  len(group),
			Evidence:     evidence,
			AdvisoryNote: ffufAdvisoryNote,
		})
	}
	return rows
}

// ffufAdvisoryNote explains why these rows carry no catalogue entry. The
// catalogue is Burp's 183 issue definitions, and "a path exists" is not one of
// them — saying so is the difference between a deliberate absence and a hole.
const ffufAdvisoryNote = "Content discovery has no issue-definition entry: the bundled catalogue " +
	"describes vulnerability classes, and a reachable path is an observation rather than a class. " +
	"Reported by the external ffuf tool."

func ffufDescription(status int, group []Discovery) string {
	var b strings.Builder
	fmt.Fprintf(&b, "External content discovery (ffuf) found %d path(s) answering HTTP %d. ",
		len(group), status)
	b.WriteString("These paths were not linked from the crawled application; they were found by " +
		"guessing names from a wordlist, so their presence says something about the deployment " +
		"rather than about the published site.")
	// A redirect target is the one extra fact that changes what a reader does
	// next, so it is stated rather than left in the evidence table alone.
	for _, d := range group {
		if d.Redirect != "" {
			fmt.Fprintf(&b, " %s redirects to %s.", d.Path, d.Redirect)
		}
	}
	return b.String()
}
