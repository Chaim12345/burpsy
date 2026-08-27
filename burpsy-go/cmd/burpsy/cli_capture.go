package main

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/burpsy-go/burpsy/internal/core"
	"github.com/burpsy-go/burpsy/internal/query"
)

func init() {
	registerCLI(
		&cliCommand{
			name:  "history",
			usage: "list recorded exchanges",
			run:   cmdHistory,
		},
		&cliCommand{
			name:  "message",
			usage: "print a raw stored message by msg id",
			run:   cmdMessage,
		},
		&cliCommand{
			name:  "exchange",
			usage: "print one exchange as JSON",
			run:   cmdExchange,
		},
		&cliCommand{
			name:  "stats",
			usage: "print store statistics",
			run:   cmdStats,
		},
		&cliCommand{
			name:  "sitemap",
			usage: "print the store's URL tree",
			run:   cmdSitemap,
		},
		&cliCommand{
			name:  "issues",
			usage: "list findings from the finding store",
			run:   cmdIssues,
		},
		&cliCommand{
			name:  "ws",
			usage: "list websocket connections or messages (ws list | ws messages)",
			run:   cmdWs,
		},
	)
}

// exchangeQueryable adapts a core.Exchange to the query package's Queryable so
// the CLI's history filter is the same grammar the UI's filter box uses.
type exchangeQueryable struct {
	ex   *core.Exchange
	body []byte
}

func (q exchangeQueryable) Host() string   { return q.ex.Host }
func (q exchangeQueryable) Method() string { return q.ex.Method }
func (q exchangeQueryable) Path() string   { return q.ex.Path }
func (q exchangeQueryable) Status() int {
	if q.ex.Status != nil {
		return int(*q.ex.Status)
	}
	return 0
}
func (q exchangeQueryable) Mime() string {
	return sniffMime(q.body)
}
func (q exchangeQueryable) Body() []byte { return q.body }

// ResponseLen and DurationUs come off the index row, so `length` and `duration` work on the CLI's
// history filter without the -body pass withBody performs. Absence follows the same rule as
// everywhere else: Response decides whether there is a length, and Measured whether anyone timed
// it — never the value being zero, because an empty response and an unmeasured exchange are real
// states that a zero would misreport as "0 bytes" and "instantaneous".
func (q exchangeQueryable) ResponseLen() (int64, bool) {
	if q.ex.Response == nil {
		return 0, false
	}
	return int64(q.ex.ResponseLen), true
}

func (q exchangeQueryable) DurationUs() (int64, bool) {
	if !q.ex.Duration.Measured {
		return 0, false
	}
	return int64(q.ex.Duration.Us), true
}

func (q *exchangeQueryable) withBody(store *core.TrafficStore) *exchangeQueryable {
	if q.ex.Response != nil {
		if msg, err := store.Get(*q.ex.Response); err == nil {
			q.body = msg.Raw()
		}
	}
	return q
}

func sniffMime(raw []byte) string {
	// Cheap, dependency-free content-type sniff: the first header line that
	// looks like a Content-Type carries it. Missing => empty (the UI treats
	// empty mime as "no filter match", which is honest).
	lines := strings.SplitN(string(raw), "\r\n", 10)
	for _, line := range lines[1:] {
		if k, v, ok := strings.Cut(line, ":"); ok {
			if strings.EqualFold(strings.TrimSpace(k), "Content-Type") {
				mime := strings.TrimSpace(v)
				if i := strings.Index(mime, ";"); i >= 0 {
					mime = mime[:i]
				}
				return strings.ToLower(mime)
			}
		}
	}
	return ""
}

func cmdHistory(ctx *cliContext, args []string) error {
	fs := newFlagSet("history")
	limit := fs.Int("limit", 100, "maximum rows to print")
	jsonOut := fs.Bool("json", false, "emit JSON rows instead of a table")
	// The grammar is the query package's, not a `field:value` shorthand — the old help text
	// advertised colons the parser never accepted, so every example it gave was a parse error.
	q := fs.String("query", "", `filter in the UI's query grammar, e.g. 'status in 200..299 and host ~ "api."'`)
	if err := fs.Parse(args); err != nil {
		return err
	}
	exchanges := ctx.store.Exchanges()
	var filtered []*core.Exchange
	if *q != "" {
		expr, err := query.Parse(*q)
		if err != nil {
			return fmt.Errorf("invalid query: %w", err)
		}
		for _, ex := range exchanges {
			ad := (&exchangeQueryable{ex: ex}).withBody(ctx.store)
			if expr.Match(ad) {
				filtered = append(filtered, ex)
			}
		}
		exchanges = filtered
	}
	start := 0
	if *limit >= 0 && len(exchanges) > *limit {
		start = len(exchanges) - *limit
	}
	rows := exchanges[start:]
	if *jsonOut {
		views := make([]map[string]interface{}, 0, len(rows))
		for _, ex := range rows {
			views = append(views, exchangeView(ex))
		}
		return printJSON(ctx.out, map[string]interface{}{"rows": views, "total": len(exchanges)})
	}
	for _, ex := range rows {
		status := "-"
		if ex.Status != nil {
			status = strconv.Itoa(int(*ex.Status))
		}
		scheme := "http"
		if ex.TLS {
			scheme = "https"
		}
		fmt.Fprintf(ctx.out, "%6d  %s %s %s %s://%s:%d %dB\n",
			ex.ID, status, ex.Method, ex.Path, scheme, ex.Host, ex.Port, ex.ResponseLen)
	}
	fmt.Fprintf(ctx.out, "\n%d exchange(s)\n", len(exchanges))
	return nil
}

// exchangeView renders one exchange in the shape the UI's history table expects.
func exchangeView(ex *core.Exchange) map[string]interface{} {
	var status interface{}
	if ex.Status != nil {
		status = *ex.Status
	}
	return map[string]interface{}{
		"id":           ex.ID,
		"method":       ex.Method,
		"path":         ex.Path,
		"host":         ex.Host,
		"port":         ex.Port,
		"tls":          ex.TLS,
		"status":       status,
		"response_len": ex.ResponseLen,
		"started_ms":   ex.StartedMs,
		// Millis, and no finer field beside it: this map is documented as the shape the UI's history table
		// expects, so it carries exactly the fields internal/web's ExchangeView carries. A measured
		// sub-millisecond exchange and an untimed one are both 0 here — see ExchangeView's note for what
		// closing that would take.
		"duration_ms":   ex.Duration.Millis(),
		"request_msg":   ex.Request,
		"response_msg":  ex.Response,
		"protocol":      ex.Protocol.VersionToken(),
		"response_body": "",
	}
}

func cmdMessage(ctx *cliContext, args []string) error {
	fs := newFlagSet("message")
	idStr := fs.String("id", "", "message id (u64)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *idStr == "" && fs.NArg() == 0 {
		return fmt.Errorf("usage: burpsy message -id <msgid>")
	}
	raw := *idStr
	if raw == "" {
		raw = fs.Arg(0)
	}
	u, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return fmt.Errorf("parse message id %q: %w", raw, err)
	}
	msg, err := ctx.store.Get(core.MsgId(u))
	if err != nil {
		return fmt.Errorf("message not found: %w", err)
	}
	_, err = ctx.out.Write(msg.Raw())
	return err
}

func cmdExchange(ctx *cliContext, args []string) error {
	fs := newFlagSet("exchange")
	idStr := fs.String("id", "", "exchange id")
	if err := fs.Parse(args); err != nil {
		return err
	}
	raw := *idStr
	if raw == "" && fs.NArg() > 0 {
		raw = fs.Arg(0)
	}
	if raw == "" {
		return fmt.Errorf("usage: burpsy exchange -id <id>")
	}
	id, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid exchange id %q", raw)
	}
	ex, err := ctx.store.GetExchange(core.ExchangeID(id))
	if err != nil {
		return fmt.Errorf("exchange not found: %w", err)
	}
	return printJSON(ctx.out, exchangeView(ex))
}

func cmdStats(ctx *cliContext, args []string) error {
	msgs, exchanges := ctx.store.Count()
	wsConns := len(ctx.store.WsConnections())
	v := map[string]interface{}{
		"messages":    msgs,
		"exchanges":   exchanges,
		"bytes":       ctx.store.Bytes(),
		"ws_conns":    wsConns,
		"ws_messages": ctx.store.WsCount(),
		"segments":    segmentCount(ctx),
		"organizer":   len(ctx.organizer.List()),
	}
	return printJSON(ctx.out, v)
}

func segmentCount(ctx *cliContext) int {
	// The store reports bytes; sealed segments are storage detail. Report 0
	// rather than inventing a count the store does not expose.
	return 0
}

func cmdSitemap(ctx *cliContext, args []string) error {
	nodes := buildSitemap(ctx.store.Exchanges())
	return printJSON(ctx.out, map[string]interface{}{"nodes": nodes, "total": len(nodes)})
}

// sitemapNode is a node in the CLI's URL tree. Paths are grouped by host then
// by the first path segment, mirroring the UI's sitemap collation.
type sitemapNode struct {
	ID        int            `json:"id"`
	Host      string         `json:"host"`
	Path      string         `json:"path"`
	Method    string         `json:"method"`
	Status    *uint16        `json:"status"`
	HasParams bool           `json:"has_params"`
	Children  []*sitemapNode `json:"children"`
}

func buildSitemap(exchanges []*core.Exchange) []*sitemapNode {
	// Group exchange ids by (host, first-segment). Collation is display-only.
	seen := map[core.ExchangeID]bool{}
	roots := []*sitemapNode{}
	byPath := map[string]*sitemapNode{}
	var nextID int
	for _, ex := range exchanges {
		if seen[ex.ID] {
			continue
		}
		seen[ex.ID] = true
		seg := ex.Path
		if i := strings.IndexByte(seg[1:], '/'); i >= 0 {
			seg = seg[:i+1]
		}
		key := ex.Host + seg
		node := byPath[key]
		if node == nil {
			nextID++
			node = &sitemapNode{ID: nextID, Host: ex.Host, Path: seg, Method: ex.Method, Status: ex.Status}
			byPath[key] = node
			roots = append(roots, node)
		}
	}
	return roots
}

func cmdIssues(ctx *cliContext, args []string) error {
	fs := newFlagSet("issues")
	jsonOut := fs.Bool("json", false, "emit full finding objects")
	if err := fs.Parse(args); err != nil {
		return err
	}
	findings := ctx.findings.All()
	if *jsonOut {
		return printJSON(ctx.out, map[string]interface{}{"findings": findings, "total": len(findings)})
	}
	for _, f := range findings {
		fmt.Fprintf(ctx.out, "#%d  %-8s %-10s %s\n", f.ID, f.Severity, f.Confidence, f.Name)
	}
	fmt.Fprintf(ctx.out, "\n%d finding(s)\n", len(findings))
	return nil
}

func cmdWs(ctx *cliContext, args []string) error {
	sub := "list"
	if len(args) > 0 && args[0] != "-h" && args[0] != "--help" {
		sub = args[0]
	}
	switch sub {
	case "list", "connections":
		return printJSON(ctx.out, map[string]interface{}{"connections": []interface{}{}})
	case "messages", "rows":
		return printJSON(ctx.out, map[string]interface{}{"rows": []interface{}{}, "total": 0})
	default:
		return fmt.Errorf("usage: burpsy ws (list|messages)")
	}
}
