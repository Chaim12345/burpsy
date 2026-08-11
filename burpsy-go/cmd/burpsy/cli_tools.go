package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/intruder"
	"github.com/burpsy-go/burpsy/internal/matchreplace"
	"github.com/burpsy-go/burpsy/internal/report"
	"github.com/burpsy-go/burpsy/internal/sender"
	"github.com/burpsy-go/burpsy/internal/sequencer"
	"github.com/burpsy-go/burpsy/internal/session"
	"github.com/burpsy-go/burpsy/internal/toollog"
	"github.com/burpsy-go/burpsy/internal/tools"
)

func init() {
	registerCLI(
		&cliCommand{
			name:  "repeater",
			usage: "send a raw request: burpsy repeater send -target host:port [-tls] -raw REQ",
			run:   cmdRepeater,
		},
		&cliCommand{
			name:  "intruder",
			usage: "run an intruder attack: burpsy intruder run -target host:port -raw REQ -payloads a,b -positions 0",
			run:   cmdIntruder,
		},
		&cliCommand{
			name:  "scan",
			usage: "active scan: burpsy scan audit -id EXCHANGE | burpsy scan live",
			run:   cmdScan,
		},
		&cliCommand{
			name:  "sequencer",
			usage: "analyse token randomness: burpsy sequencer analyse -tokens a,b,c",
			run:   cmdSequencer,
		},
		&cliCommand{
			name:  "tools",
			usage: "decode/encode/hash/compare: burpsy tools (decode|encode|hash|compare) ...",
			run:   cmdTools,
		},
		&cliCommand{
			name:  "matchreplace",
			usage: "manage match & replace rules: burpsy matchreplace (set|test|list|content-length)",
			run:   cmdMatchReplace,
		},
		&cliCommand{
			name:  "tool-log",
			usage: "show the tool activity log",
			run:   cmdToolLog,
		},
		&cliCommand{
			name:  "report",
			usage: "render findings: burpsy report (json|sarif|html) [-findings FILE]",
			run:   cmdReport,
		},
		&cliCommand{
			name:  "organizer",
			usage: "manage the organizer: burpsy organizer (list|add|update|remove)",
			run:   cmdOrganizer,
		},
	)
}

// ---- Repeater -----------------------------------------------------------------------------------

func cmdRepeater(ctx *cliContext, args []string) error {
	fs := newFlagSet("repeater")
	target := fs.String("target", "", "host[:port] to send to")
	tls := fs.Bool("tls", false, "use TLS")
	raw := fs.String("raw", "", "raw request (literal, @file, or - for stdin)")
	timeoutSec := fs.Int("timeout", 30, "request timeout in seconds")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *target == "" || *raw == "" {
		return fmt.Errorf("usage: burpsy repeater send -target host:port [-tls] -raw REQ")
	}
	host, port, err := resolveHostPort(*target, *tls)
	if err != nil {
		return err
	}
	reqBytes, err := readInput(*raw)
	if err != nil {
		return err
	}
	ctxb, cancel := context.WithTimeout(context.Background(), time.Duration(*timeoutSec)*time.Second)
	defer cancel()
	start := time.Now()
	// Through the chokepoint, not the raw sender. This used to call ctx.sender.SendRaw directly,
	// which authorises nothing: `-scope-include app.example.com repeater -target other.host` sent the
	// request anyway. HARD-03 names every request-originating surface, and the CLI is one — the fact
	// that cli_session.go already did this correctly is what made the omission here easy to miss.
	// AuthorisedSender.Send re-authorises the bytes actually going on the wire, so a hand-edited
	// request line cannot smuggle a different target past a check made on the flag.
	sent, err := sender.NewAuthorisedSender(ctx.scope, ctx.sender, host, port, *tls).Send(ctxb, reqBytes)
	resp := sent.Raw
	if err != nil {
		// nil, not zero: nothing came back, which is not the same as an empty response.
		ctx.toolLog.Record(toollog.ToolRepeater, host, port, *tls, "RAW", "/", 0, nil, 0, err.Error())
		return err
	}
	dur := uint64(time.Since(start).Milliseconds())
	status := parseStatus(resp)
	// The same len(resp) the summary line below prints, so the log and the terminal agree.
	ctx.toolLog.Record(toollog.ToolRepeater, host, port, *tls, "RAW", "/", status, toollog.Bytes(len(resp)), dur, "")
	_, werr := ctx.out.Write(resp)
	if werr != nil {
		return werr
	}
	fmt.Fprintf(ctx.out, "\n-- %d bytes, status %d, %dms --\n", len(resp), status, dur)
	return nil
}

func parseStatus(raw []byte) int {
	head := raw
	if i := strings.IndexByte(string(head), '\n'); i >= 0 {
		head = head[:i]
	}
	fields := strings.Fields(string(head))
	if len(fields) >= 2 {
		if n, err := strconv.Atoi(fields[1]); err == nil {
			return n
		}
	}
	return 0
}

// ---- Intruder ----------------------------------------------------------------------------------

func cmdIntruder(ctx *cliContext, args []string) error {
	fs := newFlagSet("intruder")
	target := fs.String("target", "", "host[:port] to attack")
	tls := fs.Bool("tls", false, "use TLS")
	raw := fs.String("raw", "", "base request (literal, @file, or - for stdin)")
	payloads := fs.String("payloads", "", "comma-separated payloads")
	positions := fs.String("positions", "", "comma-separated byte offsets into the base request to substitute")
	limit := fs.Int("limit", 0, "print at most this many results (0 = all)")
	timeoutSec := fs.Int("timeout", 60, "attack timeout in seconds")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *target == "" || *raw == "" || *payloads == "" {
		return fmt.Errorf("usage: burpsy intruder run -target host:port -raw REQ -payloads a,b -positions 0,5")
	}
	host, port, err := resolveHostPort(*target, *tls)
	if err != nil {
		return err
	}
	base, err := readInput(*raw)
	if err != nil {
		return err
	}
	payloadList := splitCSV(*payloads)
	var posList []int
	if *positions != "" {
		for _, p := range splitCSV(*positions) {
			n, err := strconv.Atoi(p)
			if err != nil {
				return fmt.Errorf("invalid position %q", p)
			}
			posList = append(posList, n)
		}
	} else {
		// Default to every occurrence of the literal "__PAYLOAD__" in the base.
		for i := 0; i+len("__PAYLOAD__") <= len(base); i++ {
			if string(base[i:i+len("__PAYLOAD__")]) == "__PAYLOAD__" {
				posList = append(posList, i)
			}
		}
		if len(posList) == 0 {
			return fmt.Errorf("no payload positions given and no __PAYLOAD__ marker found in the base request")
		}
	}
	ctxb, cancel := context.WithTimeout(context.Background(), time.Duration(*timeoutSec)*time.Second)
	defer cancel()
	results, err := ctx.intruder.Run(ctxb, string(base), host, port, *tls, payloadList, posList)
	if err != nil {
		return err
	}
	// nil: one row for the whole attack, which sends many requests and gets many responses back, so no
	// single response length belongs to it. The per-request lengths are in the result rows printed below.
	ctx.toolLog.Record(toollog.ToolIntruder, host, port, *tls, "ATTACK", "/", 0, nil, 0,
		fmt.Sprintf("%d payloads", len(payloadList)))
	count := 0
	for res := range results {
		count++
		if *limit > 0 && count > *limit {
			continue
		}
		row, err := json.Marshal(res)
		if err != nil {
			return err
		}
		fmt.Fprintln(ctx.out, string(row))
	}
	fmt.Fprintf(ctx.out, "-- %d result(s) --\n", count)
	return nil
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// ---- Scanner -----------------------------------------------------------------------------------

func cmdScan(ctx *cliContext, args []string) error {
	sub := "live"
	if len(args) > 0 && args[0] != "-h" && args[0] != "--help" && !strings.HasPrefix(args[0], "-") {
		sub = args[0]
		args = args[1:]
	}
	switch sub {
	case "live":
		return scanLive(ctx, args)
	case "audit":
		return scanAudit(ctx, args)
	default:
		return fmt.Errorf("usage: burpsy scan (live|audit -id EXCHANGE)")
	}
}

func scanLive(ctx *cliContext, args []string) error {
	fs := newFlagSet("scan live")
	jsonOut := fs.Bool("json", false, "emit findings as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	findings := ctx.findings.All()
	if *jsonOut {
		views := make([]map[string]interface{}, 0, len(findings))
		for _, f := range findings {
			views = append(views, map[string]interface{}{
				"name":        f.Name,
				"severity":    f.Severity.String(),
				"confidence":  f.Confidence.String(),
				"description": f.Description,
			})
		}
		return printJSON(ctx.out, map[string]interface{}{"scanning": false, "started": true, "findings": views, "total": len(views)})
	}
	for _, f := range findings {
		fmt.Fprintf(ctx.out, "%-8s %-10s %s\n", f.Severity, f.Confidence, f.Name)
	}
	fmt.Fprintf(ctx.out, "\n%d finding(s)\n", len(findings))
	return nil
}

func scanAudit(ctx *cliContext, args []string) error {
	fs := newFlagSet("scan audit")
	idStr := fs.String("id", "", "exchange id to audit")
	timeoutSec := fs.Int("timeout", 60, "audit timeout in seconds")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *idStr == "" && fs.NArg() > 0 {
		*idStr = fs.Arg(0)
	}
	if *idStr == "" {
		return fmt.Errorf("usage: burpsy scan audit -id EXCHANGE")
	}
	id, err := strconv.ParseUint(*idStr, 10, 64)
	if err != nil || id == 0 {
		return fmt.Errorf("invalid exchange id %q", *idStr)
	}
	ex, err := ctx.store.GetExchange(core.ExchangeID(id))
	if err != nil {
		return err
	}
	ctxb, cancel := context.WithTimeout(context.Background(), time.Duration(*timeoutSec)*time.Second)
	defer cancel()
	// AuditWithin rather than Audit: the outcome is what says which checks were *not* dispatched, and
	// a CLI that printed only findings would report a bounded audit as a clean one.
	outcome, findings := ctx.scanner.AuditWithin(ctxb, core.ExchangeID(id), ctx.scanner.AuditConfig())
	if outcome.Error != "" {
		return fmt.Errorf("exchange %d not audited: %s", id, outcome.Error)
	}
	// nil: one row for the whole audit, not for a single request/response pair.
	ctx.toolLog.Record(toollog.ToolScanner, ex.Host, ex.Port, ex.TLS, ex.Method, ex.Path, 0, nil, 0, "audit")
	for _, f := range findings {
		nf := core.NewFinding{
			Name:        f.Name,
			Severity:    core.ParseSeverity(f.Severity),
			Confidence:  core.ParseConfidence(f.Confidence),
			Description: f.Description,
			Remediation: f.Solution,
			Param:       f.Param,
		}
		ctx.findings.Add(nf)
		line := fmt.Sprintf("%-8s %-10s %s", nf.Severity, nf.Confidence, nf.Name)
		if nf.Param != "" {
			line += fmt.Sprintf(" (parameter %s)", nf.Param)
		}
		fmt.Fprintln(ctx.out, line)
	}
	fmt.Fprintf(ctx.out, "\n%d finding(s) from exchange %d\n", len(findings), id)
	// Printed unconditionally, including for a clean audit: "0 findings" means nothing without the
	// count of checks that actually ran alongside it.
	fmt.Fprintf(ctx.out, "%s\n", outcome.Summary())
	for _, d := range outcome.Dispositions() {
		if d.Count > 0 && d.StoppedLooking {
			fmt.Fprintf(ctx.out, "  %d check(s) not dispatched: %s\n", d.Count, d.Reason)
		}
	}
	return nil
}

// ---- Sequencer ---------------------------------------------------------------------------------

func cmdSequencer(ctx *cliContext, args []string) error {
	sub := "analyse"
	if len(args) > 0 && args[0] != "-h" && args[0] != "--help" && !strings.HasPrefix(args[0], "-") {
		sub = args[0]
		args = args[1:]
	}
	switch sub {
	case "analyse", "analyze":
		return sequencerAnalyse(ctx, args)
	case "capture":
		return sequencerCapture(ctx, args)
	default:
		return fmt.Errorf("usage: burpsy sequencer (analyse|capture)")
	}
}

func sequencerAnalyse(ctx *cliContext, args []string) error {
	fs := newFlagSet("sequencer analyse")
	tokens := fs.String("tokens", "", "comma-separated tokens (e.g. session ids)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *tokens == "" && fs.NArg() > 0 {
		*tokens = fs.Arg(0)
	}
	if *tokens == "" {
		return fmt.Errorf("usage: burpsy sequencer analyse -tokens a,b,c")
	}
	tl := sequencer.NewTokenList()
	tl.CollectAll(splitCSV(*tokens))
	analysis := sequencer.Analyse(tl)
	cs := sequencer.AnalyseCharacters(splitCSV(*tokens))
	view := map[string]interface{}{
		"total":           analysis.SampleCount,
		"entropy":         analysis.Entropy,
		"character_set":   analysis.CharsetSize,
		"rating":          analysis.GoodnessRating.String(),
		"chi_square":      analysis.ChiSquare,
		"serial_corr":     analysis.SerialCorr,
		"monte_carlo_pi":  analysis.MonteCarloPi,
		"repeated_tokens": analysis.RepeatedTokens,
		"characters":      cs.Counts,
	}
	return printJSON(ctx.out, view)
}

func sequencerCapture(ctx *cliContext, args []string) error {
	fs := newFlagSet("sequencer capture")
	token := fs.String("token", "", "token to collect")
	show := fs.Bool("show", false, "print the collected tokens instead of collecting one")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *show {
		return printJSON(ctx.out, map[string]interface{}{"tokens": ctx.sequencer.Tokens(), "total": ctx.sequencer.Count()})
	}
	if *token == "" && fs.NArg() > 0 {
		*token = fs.Arg(0)
	}
	if *token == "" {
		return fmt.Errorf("usage: burpsy sequencer capture -token VALUE | -show")
	}
	ctx.sequencer.Collect(*token)
	fmt.Fprintf(ctx.out, "collected token %d\n", ctx.sequencer.Count())
	return nil
}

// ---- Tools: decoder/encoder/hasher/comparer ----------------------------------------------------

func cmdTools(ctx *cliContext, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: burpsy tools (decode|encode|hash|compare) ...")
	}
	sub := args[0]
	switch sub {
	case "decode":
		return toolsDecode(ctx, args[1:])
	case "encode":
		return toolsEncode(ctx, args[1:])
	case "hash":
		return toolsHash(ctx, args[1:])
	case "compare":
		return toolsCompare(ctx, args[1:])
	default:
		return fmt.Errorf("unknown tools subcommand %q (decode|encode|hash|compare)", sub)
	}
}

func toolsDecode(ctx *cliContext, args []string) error {
	fs := newFlagSet("tools decode")
	alg := fs.String("algo", "base64", "base64 | hex | url | html")
	value := fs.String("value", "", "value to decode (literal, @file, or -)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *value == "" && fs.NArg() > 0 {
		*value = fs.Arg(0)
	}
	if *value == "" {
		return fmt.Errorf("usage: burpsy tools decode -algo base64|hex|url|html -value X")
	}
	dec := tools.NewDecoder()
	var out string
	var err error
	switch strings.ToLower(*alg) {
	case "base64", "b64":
		out, err = dec.DecodeBase64(*value)
	case "hex":
		out, err = dec.DecodeHex(*value)
	case "url":
		out, err = dec.DecodeURL(*value)
	case "html":
		out = dec.DecodeHTML(*value)
	default:
		return fmt.Errorf("unknown algo %q", *alg)
	}
	if err != nil {
		return err
	}
	fmt.Fprintln(ctx.out, out)
	return nil
}

func toolsEncode(ctx *cliContext, args []string) error {
	fs := newFlagSet("tools encode")
	alg := fs.String("algo", "base64", "base64 | hex | url | html")
	value := fs.String("value", "", "value to encode")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *value == "" && fs.NArg() > 0 {
		*value = fs.Arg(0)
	}
	if *value == "" {
		return fmt.Errorf("usage: burpsy tools encode -algo base64|hex|url|html -value X")
	}
	dec := tools.NewDecoder()
	var out string
	switch strings.ToLower(*alg) {
	case "base64", "b64":
		out = dec.EncodeBase64(*value)
	case "hex":
		out = dec.EncodeHex(*value)
	case "url":
		out = dec.EncodeURL(*value)
	case "html":
		out = dec.EncodeHTML(*value)
	default:
		return fmt.Errorf("unknown algo %q", *alg)
	}
	fmt.Fprintln(ctx.out, out)
	return nil
}

func toolsHash(ctx *cliContext, args []string) error {
	fs := newFlagSet("tools hash")
	alg := fs.String("algo", "sha256", "md5 | sha1 | sha256 | sha512")
	value := fs.String("value", "", "value to hash")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *value == "" && fs.NArg() > 0 {
		*value = fs.Arg(0)
	}
	if *value == "" {
		return fmt.Errorf("usage: burpsy tools hash -algo md5|sha1|sha256|sha512 -value X")
	}
	h := tools.NewHasher()
	var out string
	switch strings.ToLower(*alg) {
	case "md5":
		out = h.MD5(*value)
	case "sha1":
		out = h.SHA1(*value)
	case "sha256":
		out = h.SHA256(*value)
	case "sha512":
		out = h.SHA512(*value)
	default:
		return fmt.Errorf("unknown algo %q", *alg)
	}
	fmt.Fprintln(ctx.out, out)
	return nil
}

func toolsCompare(ctx *cliContext, args []string) error {
	fs := newFlagSet("tools compare")
	a := fs.String("a", "", "first text (literal, @file, or -)")
	b := fs.String("b", "", "second text")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *a == "" && fs.NArg() >= 2 {
		*a = fs.Arg(0)
		*b = fs.Arg(1)
	}
	ab, err := readInput(*a)
	if err != nil {
		return err
	}
	bb, err := readInput(*b)
	if err != nil {
		return err
	}
	dec := tools.NewDecoder()
	res := dec.Compare(ab, bb)
	if res != nil && res.Identical {
		fmt.Fprintln(ctx.out, "inputs are identical")
		return nil
	}
	for _, d := range res.Differences {
		fmt.Fprintf(ctx.out, "pos %d: a=%q b=%q\n", d.Position, string(d.Expected), string(d.Actual))
	}
	return nil
}

// ---- Match & Replace ---------------------------------------------------------------------------

func cmdMatchReplace(ctx *cliContext, args []string) error {
	sub := "list"
	if len(args) > 0 && args[0] != "-h" && args[0] != "--help" && !strings.HasPrefix(args[0], "-") {
		sub = args[0]
		args = args[1:]
	}
	switch sub {
	case "set":
		return mrSet(ctx, args)
	case "test":
		return mrTest(ctx, args)
	case "list":
		return mrList(ctx, args)
	case "content-length":
		return mrContentLength(ctx, args)
	default:
		return fmt.Errorf("usage: burpsy matchreplace (set|test|list|content-length)")
	}
}

// mrTarget maps a user-facing target name onto a matchreplace.Target.
func mrTarget(s string) (matchreplace.Target, error) {
	switch strings.ToLower(s) {
	case "request", "req":
		return matchreplace.TargetRequestBody, nil
	case "response", "resp":
		return matchreplace.TargetResponseBody, nil
	case "request-header", "request_header", "req-header":
		return matchreplace.TargetRequestHeader, nil
	case "response-header", "response_header", "resp-header":
		return matchreplace.TargetResponseHeader, nil
	default:
		return 0, fmt.Errorf("target must be request|response|request-header|response-header, got %q", s)
	}
}

func mrSet(ctx *cliContext, args []string) error {
	fs := newFlagSet("matchreplace set")
	target := fs.String("target", "", "request|response|request-header|response-header")
	cat := fs.String("cat", "regex", "literal | regex")
	match := fs.String("match", "", "pattern to find")
	replace := fs.String("replace", "", "replacement text")
	comment := fs.String("comment", "", "rule comment")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *match == "" {
		return fmt.Errorf("usage: burpsy matchreplace set -target response -match X -replace Y [-cat regex|literal]")
	}
	t, err := mrTarget(*target)
	if err != nil {
		return err
	}
	var c matchreplace.Category
	switch strings.ToLower(*cat) {
	case "literal":
		c = matchreplace.CategoryLiteral
	case "regex", "":
		c = matchreplace.CategoryRegex
	default:
		return fmt.Errorf("cat must be literal or regex, got %q", *cat)
	}
	rule, err := matchreplace.NewRule(t, c, *match, *replace, *comment)
	if err != nil {
		return fmt.Errorf("compile rule: %w", err)
	}
	ctx.mr.AddRule(rule)
	ctx.saveState()
	fmt.Fprintf(ctx.out, "added rule %q (%s, %s)\n", *match, *target, *cat)
	return nil
}

func mrList(ctx *cliContext, args []string) error {
	rules := ctx.mr.Rules()
	if len(rules) == 0 {
		fmt.Fprintln(ctx.out, "no match & replace rules")
		return nil
	}
	for _, r := range rules {
		enabled := "on"
		if !r.Enabled {
			enabled = "off"
		}
		fmt.Fprintf(ctx.out, "[%s] target=%d cat=%d match=%q replace=%q %s\n",
			enabled, r.Target, r.Category, r.StringMatch, r.StringReplace, r.Comment)
	}
	return nil
}

func mrTest(ctx *cliContext, args []string) error {
	fs := newFlagSet("matchreplace test")
	dir := fs.String("dir", "response", "request | response")
	input := fs.String("raw", "", "input bytes (literal, @file, or -)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *input == "" {
		return fmt.Errorf("usage: burpsy matchreplace test -dir request|response -raw INPUT")
	}
	in, err := readInput(*input)
	if err != nil {
		return err
	}
	var d matchreplace.Direction
	switch strings.ToLower(*dir) {
	case "request":
		d = matchreplace.DirRequest
	case "response":
		d = matchreplace.DirResponse
	default:
		return fmt.Errorf("dir must be request or response, got %q", *dir)
	}
	out := ctx.mr.Apply(d, in)
	_, err = ctx.out.Write(out)
	if err != nil {
		return err
	}
	return nil
}

func mrContentLength(ctx *cliContext, args []string) error {
	fs := newFlagSet("matchreplace content-length")
	state := fs.String("state", "", "on | off | get")
	if err := fs.Parse(args); err != nil {
		return err
	}
	switch strings.ToLower(*state) {
	case "on":
		ctx.mr.SetUpdateContentLength(true)
		ctx.saveState()
	case "off":
		ctx.mr.SetUpdateContentLength(false)
		ctx.saveState()
	case "get", "":
		if ctx.mr.UpdateContentLength() {
			fmt.Fprintln(ctx.out, "on")
		} else {
			fmt.Fprintln(ctx.out, "off")
		}
		return nil
	default:
		return fmt.Errorf("state must be on, off, or get")
	}
	return nil
}

// ---- Tool log ----------------------------------------------------------------------------------

func cmdToolLog(ctx *cliContext, args []string) error {
	fs := newFlagSet("tool-log")
	jsonOut := fs.Bool("json", false, "emit entries as JSON")
	limit := fs.Int("limit", 0, "print at most this many newest entries (0 = all)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	entries := ctx.toolLog.All()
	if *limit > 0 && len(entries) > *limit {
		entries = entries[len(entries)-*limit:]
	}
	if *jsonOut {
		return printJSON(ctx.out, map[string]interface{}{"entries": entries, "total": len(entries)})
	}
	for _, e := range entries {
		fmt.Fprintf(ctx.out, "%6d %-9s %s:%d %-6s %s %d\n", e.ID, e.Tool.String(), e.Host, e.Port, e.Method, e.Path, e.Status)
	}
	fmt.Fprintf(ctx.out, "\n%d entry(s), %d dropped\n", len(entries), ctx.toolLog.Dropped())
	return nil
}

// ---- Report ------------------------------------------------------------------------------------

func cmdReport(ctx *cliContext, args []string) error {
	fs := newFlagSet("report")
	format := fs.String("format", "", "json | sarif | html")
	findingsFile := fs.String("findings", "", "JSON file of findings (web /api/report/json output); empty store when omitted")
	out := fs.String("out", "", "write to file instead of stdout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *format == "" && fs.NArg() > 0 {
		*format = fs.Arg(0)
	}
	switch *format {
	case "json", "sarif", "html":
	default:
		return fmt.Errorf("usage: burpsy report (json|sarif|html) [-findings FILE] [-out FILE]")
	}
	rows, err := reportRows(ctx, *findingsFile)
	if err != nil {
		return err
	}
	var doc []byte
	switch *format {
	case "json":
		doc, err = reportJSON(rows)
	case "sarif":
		doc, err = reportSARIF(rows)
	case "html":
		doc = reportHTML(rows)
	}
	if err != nil {
		return err
	}
	if *out != "" {
		if err := os.WriteFile(*out, doc, 0o644); err != nil {
			return err
		}
		fmt.Fprintf(ctx.out, "wrote %s (%d bytes)\n", *out, len(doc))
		return nil
	}
	_, werr := ctx.out.Write(doc)
	return werr
}

// reportRows loads the rows a report renders from: either the finding store of
// this process, or a JSON file produced by the web's /api/report/json (either
// the {findings:[],total} envelope or a bare array of rows). A file is how a
// standalone CLI reports work that are scoped to a run the CLI never saw.
func reportRows(ctx *cliContext, findingsFile string) ([]report.Row, error) {
	if findingsFile != "" {
		doc, err := os.ReadFile(findingsFile)
		if err != nil {
			return nil, err
		}
		// Accept both the envelope and a bare array.
		var envelope struct {
			Findings []report.Row `json:"findings"`
		}
		if err := json.Unmarshal(doc, &envelope); err == nil && envelope.Findings != nil {
			return envelope.Findings, nil
		}
		var rows []report.Row
		if err := json.Unmarshal(doc, &rows); err != nil {
			return nil, fmt.Errorf("parse %s as report rows: %w", findingsFile, err)
		}
		return rows, nil
	}
	rows := make([]report.Row, 0)
	for _, f := range ctx.findings.All() {
		rows = append(rows, report.Row{
			ID:          f.ID,
			Name:        f.Name,
			Severity:    f.Severity.String(),
			Confidence:  f.Confidence.String(),
			Description: f.Description,
			Remediation: f.Remediation,
			Occurrences: len(f.Occurrences),
		})
	}
	return rows, nil
}

func reportJSON(rows []report.Row) ([]byte, error) { return report.JSON(rows) }

func reportSARIF(rows []report.Row) ([]byte, error) { return report.SARIF(rows) }

func reportHTML(rows []report.Row) []byte { return report.HTML(rows) }

// ---- Organizer ---------------------------------------------------------------------------------

func cmdOrganizer(ctx *cliContext, args []string) error {
	sub := "list"
	if len(args) > 0 && args[0] != "-h" && args[0] != "--help" && !strings.HasPrefix(args[0], "-") {
		sub = args[0]
		args = args[1:]
	}
	switch sub {
	case "list":
		return orgList(ctx, args)
	case "add":
		return orgAdd(ctx, args)
	case "update":
		return orgUpdate(ctx, args)
	case "remove":
		return orgRemove(ctx, args)
	default:
		return fmt.Errorf("usage: burpsy organizer (list|add|update|remove)")
	}
}

func orgList(ctx *cliContext, args []string) error {
	return printJSON(ctx.out, map[string]interface{}{"items": ctx.organizer.List()})
}

func orgAdd(ctx *cliContext, args []string) error {
	fs := newFlagSet("organizer add")
	exchange := fs.Int("exchange", 0, "exchange id to save")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *exchange <= 0 {
		return fmt.Errorf("usage: burpsy organizer add -exchange ID")
	}
	item := ctx.organizer.Add(*exchange)
	ctx.saveState()
	return printJSON(ctx.out, item)
}

func orgUpdate(ctx *cliContext, args []string) error {
	fs := newFlagSet("organizer update")
	id := fs.Int("id", 0, "item id")
	title := fs.String("title", "", "new title")
	note := fs.String("note", "", "new note")
	highlight := fs.String("highlight", "", "new highlight")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *id <= 0 {
		return fmt.Errorf("usage: burpsy organizer update -id ID [-title T -note N -highlight H]")
	}
	if !ctx.organizer.Update(*id, *title, *note, *highlight) {
		return fmt.Errorf("item %d not found", *id)
	}
	ctx.saveState()
	fmt.Fprintf(ctx.out, "updated item %d\n", *id)
	return nil
}

func orgRemove(ctx *cliContext, args []string) error {
	fs := newFlagSet("organizer remove")
	id := fs.Int("id", 0, "item id")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *id <= 0 {
		return fmt.Errorf("usage: burpsy organizer remove -id ID")
	}
	if !ctx.organizer.Remove(*id) {
		return fmt.Errorf("item %d not found", *id)
	}
	ctx.saveState()
	fmt.Fprintf(ctx.out, "removed item %d\n", *id)
	return nil
}

var _ = session.ValidityRule{}
var _ = intruder.AttackResult{}
