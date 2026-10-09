package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/burpsy-go/burpsy/internal/extscan"
	"github.com/burpsy-go/burpsy/internal/report"
)

func init() {
	registerCLI(&cliCommand{
		name: "extscan",
		usage: "delegate a scan phase to an external tool: burpsy -tools ffuf=ffuf,nuclei=nuclei " +
			"extscan (ffuf|nuclei|all) -target URL [-wordlist FILE] [-format json|sarif|html]",
		run: cmdExtScan,
	})
}

// cmdExtScan runs the delegated scan phase.
//
// It is off unless the operator named the tool in -tools, which is the same
// allowlist `run tool` bchecks resolve against — there is no separate switch to
// forget. With no -tools the command refuses and says which name is missing,
// rather than reporting a clean scan nobody ran.
func cmdExtScan(ctx *cliContext, args []string) error {
	sub := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		sub, args = args[0], args[1:]
	}
	switch sub {
	case "ffuf", "nuclei", "all":
	default:
		return fmt.Errorf("usage: burpsy extscan (ffuf|nuclei|all) -target URL [-wordlist FILE]")
	}

	fs := newFlagSet("extscan")
	target := fs.String("target", "", "target URL, e.g. https://host/app/ (must be in scope)")
	wordlist := fs.String("wordlist", "", "ffuf wordlist file (required for ffuf)")
	extensions := fs.String("extensions", "", "ffuf extension list, e.g. php,bak")
	matchCodes := fs.String("match-codes", "", "ffuf status matcher, e.g. 200,301,403")
	templates := fs.String("templates", "", "nuclei template files/dirs, comma-separated")
	severities := fs.String("severities", "", "nuclei severity filter, e.g. medium,high,critical")
	tags := fs.String("tags", "", "nuclei template tag filter")
	rate := fs.Int("rate", 0, "requests per second cap (0 = the tool's own default)")
	format := fs.String("format", "", "also render the rows as a report: json | sarif | html")
	out := fs.String("out", "", "write the rendered report to a file instead of stdout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*target) == "" {
		return errors.New("extscan needs -target URL")
	}

	// The scope gate, before anything is launched. A refusal here is the whole
	// point of the command's design: an external tool cannot be put behind the
	// per-request byte gate, so the decision is made once, up front, about the
	// whole subtree the tool may reach.
	authorised, err := extscan.Authorise(ctx.scope, *target)
	if err != nil {
		return err
	}

	cfg := extscan.Config{Tools: ctx.toolAllowlist}
	var rows []report.Row
	runCtx := context.Background()
	// Under `all`, a tool that could not look must still fail the command. The
	// other tool's rows are printed either way — they are real — but exiting 0
	// would tell a script that both phases ran, and one of them did not.
	var didNotLook []error
	// A tool that ran but was cut short reported real rows, which are kept, and
	// still fails the command for the same reason.
	var didNotFinish []error

	if sub == "ffuf" || sub == "all" {
		res := extscan.RunFFUF(runCtx, cfg, ctx.scope, authorised, extscan.FFUFOptions{
			Wordlist:   *wordlist,
			Extensions: *extensions,
			MatchCodes: *matchCodes,
			Rate:       *rate,
		})
		reportOutcome(ctx, "ffuf", res.Outcome, res.Err, res.Command)
		// A tool that could not look is an error the command exits on when it
		// was the only tool asked for; under `all` it is reported and the other
		// tool still runs, because one missing binary must not silently cancel
		// the phase that did run.
		if res.Outcome != extscan.OutcomeCompleted {
			if sub == "ffuf" {
				return res.Err
			}
			didNotLook = append(didNotLook, fmt.Errorf("ffuf: %w", res.Err))
		}
		ffufRows := res.Rows()
		rows = append(rows, ffufRows...)
		fmt.Fprintf(ctx.out, "ffuf: %d path(s) discovered, %d report row(s)\n",
			len(res.Discoveries), len(ffufRows))
		// Printed rather than left implicit in a shrunken count: a run that found
		// forty paths and dropped thirty-nine of them as out of engagement reads
		// identically to one that found one, unless the drop is stated.
		if res.OutOfScope > 0 {
			fmt.Fprintf(ctx.out, "ffuf: %d reported path(s) dropped as outside the engagement scope\n", res.OutOfScope)
		}
	}

	if sub == "nuclei" || sub == "all" {
		var tpl []string
		if strings.TrimSpace(*templates) != "" {
			tpl = strings.Split(*templates, ",")
		}
		res := extscan.RunNuclei(runCtx, cfg, ctx.scope, authorised, extscan.NucleiOptions{
			Templates:  tpl,
			Severities: *severities,
			Tags:       *tags,
			RateLimit:  *rate,
		})
		reportOutcome(ctx, "nuclei", res.Outcome, res.Err, res.Command)
		switch {
		case res.Outcome == extscan.OutcomePartial:
			// Cut short but with real hits (burpsy-react-ui-b2wh): the rows are
			// printed and written, and the command still fails, because a script
			// reading exit 0 would take a timed-out scan for a finished one.
			fmt.Fprintf(ctx.out, "nuclei: WARNING the run did not finish (%s); the hits below are what "+
				"it reported before that, not a complete scan\n", res.Incomplete)
			didNotFinish = append(didNotFinish, fmt.Errorf("nuclei: %w", res.Err))
		case res.Outcome != extscan.OutcomeCompleted:
			if sub == "nuclei" {
				return res.Err
			}
			didNotLook = append(didNotLook, fmt.Errorf("nuclei: %w", res.Err))
		}
		nucleiRows := res.Rows()
		rows = append(rows, nucleiRows...)
		fmt.Fprintf(ctx.out, "nuclei: %d template hit(s), %d report row(s)\n", len(res.Hits), len(nucleiRows))
		if res.OutOfScope > 0 {
			fmt.Fprintf(ctx.out, "nuclei: %d reported hit(s) dropped as outside the engagement scope\n", res.OutOfScope)
		}
	}

	// The runners cannot number their own rows: neither knows the other ran, and
	// neither is the finding store that owns burpsy's real ids. Numbering here,
	// where the whole set is in hand, is what stops SARIF emitting several rules
	// all called BURPSY-0.
	for i := range rows {
		rows[i].ID = uint64(i + 1)
	}

	for _, r := range rows {
		fmt.Fprintf(ctx.out, "  [%-13s] %-55s %d occurrence(s)\n", r.Severity, truncate(r.Name, 55), r.Occurrences)
	}

	if *format == "" {
		return joinDidNotLook(didNotLook, didNotFinish)
	}
	var doc []byte
	switch *format {
	case "json":
		doc, err = report.JSON(rows)
	case "sarif":
		doc, err = report.SARIF(rows)
	case "html":
		doc = report.HTML(rows)
	default:
		return fmt.Errorf("-format must be json, sarif or html")
	}
	if err != nil {
		return err
	}
	if *out != "" {
		if werr := os.WriteFile(*out, doc, 0o644); werr != nil {
			return werr
		}
		fmt.Fprintf(ctx.out, "wrote %s (%d bytes)\n", *out, len(doc))
		return joinDidNotLook(didNotLook, didNotFinish)
	}
	if _, werr := ctx.out.Write(doc); werr != nil {
		return werr
	}
	return joinDidNotLook(didNotLook, didNotFinish)
}

// joinDidNotLook turns the tools that could not look, and those that were cut
// short (burpsy-react-ui-b2wh), into the command's exit status. The report was still written — whatever did run is real — but the
// command must not exit 0 having skipped half the phase it was asked for.
func joinDidNotLook(errs, unfinished []error) error {
	var out []error
	if len(errs) > 0 {
		out = append(out, fmt.Errorf("%d of the requested tools did not run: %w", len(errs), errors.Join(errs...)))
	}
	if len(unfinished) > 0 {
		out = append(out, fmt.Errorf("%d of the requested tools did not finish; their rows are partial: %w",
			len(unfinished), errors.Join(unfinished...)))
	}
	return errors.Join(out...)
}

// reportOutcome prints what actually happened before any rows are shown. The
// outcome line is printed for a completed run too: "nuclei completed" above an
// empty row list is a different statement from silence, and only one of them is
// something a reader can act on.
func reportOutcome(ctx *cliContext, tool string, outcome extscan.Outcome, err error, command []string) {
	fmt.Fprintf(ctx.out, "%s: %s\n", tool, outcome)
	if len(command) > 0 {
		fmt.Fprintf(ctx.out, "%s: ran %s\n", tool, strings.Join(command, " "))
	}
	if err != nil {
		fmt.Fprintf(ctx.out, "%s: %v\n", tool, err)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
