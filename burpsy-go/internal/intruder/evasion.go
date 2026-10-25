package intruder

// WAF evasion techniques: User-Agent rotation, smart jitter, payload encoding variations, and
// header order randomization (burpsy-react-ui-tfqk).
//
// # Composition, not replacement
//
// None of this replaces the RateLimiter (limit.go) or the processing Chain (process.go) — both
// stay exactly as they were for a caller that configures nothing here. WAFEvasion.Wrap sits
// around an existing SendFn: Jitter.Sleep runs before the wrapped send, so the RateLimiter's own
// reserve/acquire still executes inside it, and both delays add rather than one silently
// replacing the other. EncodeVariant is a one-call convenience over encodings the processing
// Chain already exposes through its "encode" rule and tools.ParseLayer's own names ("url",
// "base64", "hex"); "double_url" is nothing more than two url "encode" rules chained, which the
// Chain already supports without any change to process.go.
//
// # Why these four
//
// A WAF (or a human reviewing traffic) fingerprints a scripted client on whatever stays constant
// across thousands of requests: one User-Agent, one exact inter-request timing, one encoding, one
// header order. Each technique here breaks one of those constants; none of them changes what the
// request means to a compliant server — RFC 7230 §3.2.2 does not define header order as
// meaningful, and a User-Agent is an advisory string a server is free to ignore.
import (
	"bytes"
	"fmt"
	"math/rand/v2"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/burpsy-go/burpsy/internal/httputil"
	"github.com/burpsy-go/burpsy/internal/tools"
)

// ---------------------------------------------------------------------------
// User-Agent rotation
// ---------------------------------------------------------------------------

// UserAgentPool rotates a configurable set of User-Agent strings across requests, so an attack
// does not present one fixed fingerprint to a WAF for its whole run.
type UserAgentPool struct {
	agents []string
	next   atomic.Uint64
}

// DefaultUserAgents is a small pool of common real-world browser User-Agent strings (desktop
// Chrome/Firefox/Safari/Edge plus mobile Safari/Chrome), current as of major browser releases at
// time of writing. Not exhaustive, and not meant to be: an operator who wants a specific set
// builds their own pool with NewUserAgentPool.
func DefaultUserAgents() []string {
	return []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:129.0) Gecko/20100101 Firefox/129.0",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 Edg/128.0.0.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
	}
}

// NewUserAgentPool builds a pool from the given agents, dropping blanks. An empty or all-blank
// list is refused — a pool that rotates through nothing is not rotation, it is a bug wearing
// rotation's name.
func NewUserAgentPool(agents []string) (*UserAgentPool, error) {
	kept := make([]string, 0, len(agents))
	for _, a := range agents {
		if strings.TrimSpace(a) != "" {
			kept = append(kept, a)
		}
	}
	if len(kept) == 0 {
		return nil, fmt.Errorf("user-agent pool: at least one non-empty agent is required")
	}
	return &UserAgentPool{agents: kept}, nil
}

// Next returns the next User-Agent in round-robin order. Safe for concurrent use — the engine's
// sends happen from goroutines bounded by the RateLimiter's slot channel, and the pool must not
// become a second source of skipped or duplicated agents under that concurrency.
func (p *UserAgentPool) Next() string {
	i := p.next.Add(1) - 1
	return p.agents[i%uint64(len(p.agents))]
}

// Len is how many agents the pool holds.
func (p *UserAgentPool) Len() int { return len(p.agents) }

// ---------------------------------------------------------------------------
// Smart jitter
// ---------------------------------------------------------------------------

// Jitter draws a random delay in [Min, Max] before each request. It is the fixed-window sibling
// of RateLimit's DelayVariation (limit.go): that type scales a *fraction* of the bucket's own
// computed interval, for a caller who already has a rate cap to vary; Jitter is for a caller who
// just wants "wait somewhere between X and Y" with no rate cap involved at all, and composes with
// one when there is — see WAFEvasion.
type Jitter struct {
	min, max time.Duration
	mu       sync.Mutex
	rnd      *rand.Rand
}

// NewJitter builds a jitter that waits a random duration in [min, max]. Equal bounds are a fixed
// delay, not an error — a caller that wants "always exactly 50ms" writes NewJitter(50*time.Millisecond,
// 50*time.Millisecond, seed) rather than reaching for a different type. min > max, or either bound
// negative, is refused: there is no delay that satisfies a floor above its own ceiling, or a wait
// shorter than none at all.
func NewJitter(min, max time.Duration, seed uint64) (*Jitter, error) {
	if min < 0 || max < 0 {
		return nil, fmt.Errorf("jitter: delay bounds must not be negative (min=%s, max=%s)", min, max)
	}
	if min > max {
		return nil, fmt.Errorf("jitter: min delay %s is greater than max delay %s", min, max)
	}
	return &Jitter{
		min: min,
		max: max,
		rnd: rand.New(rand.NewPCG(seed, seed^variationSeedStream)),
	}, nil
}

// Delay draws the next random duration in [Min, Max].
func (j *Jitter) Delay() time.Duration {
	if j.min == j.max {
		return j.min
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	span := int64(j.max - j.min)
	return j.min + time.Duration(j.rnd.Int64N(span+1))
}

// Sleep waits Delay(). A thin wrapper so callers like WAFEvasion.Wrap read as what they do.
func (j *Jitter) Sleep() {
	time.Sleep(j.Delay())
}

// ---------------------------------------------------------------------------
// Payload encoding variations
// ---------------------------------------------------------------------------

// EncodeVariant applies one of a fixed set of WAF-evasion encodings to a payload in one call.
// Every variant is already reachable through the ordinary processing Chain: "url", "base64" and
// "hex" are exactly tools.ParseLayer's own names, used by the chain's "encode" rule, and
// "double_url" is nothing more than two "encode" rules with layer "url" run back to back — the
// chain already supports that composition (process.go's Chain.Apply runs rules in order), so this
// function is a convenience over the chain's own behaviour, not a second mechanism beside it.
func EncodeVariant(payload []byte, variant string) ([]byte, error) {
	switch variant {
	case "url", "urlencode":
		return tools.Encode(tools.LayerURL, payload)
	case "double_url", "double_urlencode":
		once, err := tools.Encode(tools.LayerURL, payload)
		if err != nil {
			return nil, err
		}
		return tools.Encode(tools.LayerURL, once)
	case "base64":
		return tools.Encode(tools.LayerBase64, payload)
	case "hex":
		return tools.Encode(tools.LayerHex, payload)
	default:
		return nil, fmt.Errorf("waf evasion: unknown encoding variant %q (expected url, double_url, base64 or hex)", variant)
	}
}

// EncodingVariants is every variant EncodeVariant knows, in a stable order — for a caller that
// wants to build one payload set per WAF-evasion encoding rather than pick a single one.
func EncodingVariants() []string {
	return []string{"url", "double_url", "base64", "hex"}
}

// ---------------------------------------------------------------------------
// Header order randomization
// ---------------------------------------------------------------------------

// ShuffleHeaders randomizes the order of a request's header lines, leaving the request line, the
// header/body blank-line terminator and the body untouched. HTTP does not define header order as
// meaningful (RFC 7230 §3.2.2), so this changes nothing about how a compliant server parses the
// request — it only removes the one signal ("these headers always arrive in this exact order")
// a WAF or traffic-fingerprinting layer can use to recognise a scripted client.
//
// A request with fewer than two header lines is returned unchanged: there is nothing to reorder,
// and a malformed request with no request line at all is returned unchanged too, rather than
// guessing at a header block that was not there.
func ShuffleHeaders(raw []byte, rnd *rand.Rand) []byte {
	requestLine, headers, body, hasBody, ok := splitRequest(raw)
	if !ok || len(headers) < 2 {
		return raw
	}
	shuffled := make([][]byte, len(headers))
	copy(shuffled, headers)
	rnd.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
	return rebuildRequest(requestLine, shuffled, body, hasBody)
}

// ApplyUserAgent replaces the request's User-Agent header with ua, appending one after the last
// header if none was present. Only the header block is touched (see splitRequest), so a body
// that happens to contain the literal text "User-Agent:" — a proxied request replayed as a
// payload, say — is never rewritten. A malformed request with no request line is returned
// unchanged.
func ApplyUserAgent(raw []byte, ua string) []byte {
	requestLine, headers, body, hasBody, ok := splitRequest(raw)
	if !ok {
		return raw
	}
	out := make([][]byte, 0, len(headers)+1)
	replaced := false
	newLine := []byte("User-Agent: " + ua)
	for _, h := range headers {
		if headerNameEquals(h, "User-Agent") {
			if !replaced {
				out = append(out, newLine)
				replaced = true
			}
			continue // drop any further duplicate User-Agent lines rather than leaving stale ones
		}
		out = append(out, h)
	}
	if !replaced {
		out = append(out, newLine)
	}
	return rebuildRequest(requestLine, out, body, hasBody)
}

// splitRequest parses raw into its request line, header lines (blank lines dropped) and body.
// ok is false only when there is no request line at all — an empty or blank input — which is the
// one case that gives the callers above nothing safe to reconstruct.
func splitRequest(raw []byte) (requestLine []byte, headers [][]byte, body []byte, hasBody bool, ok bool) {
	head, cut, found := httputil.CutHead(raw)
	if !found {
		head = raw
	} else {
		body, hasBody = cut, true
	}
	lines := bytes.Split(head, []byte("\r\n"))
	if len(lines) == 0 || len(lines[0]) == 0 {
		return nil, nil, nil, false, false
	}
	requestLine = lines[0]
	for _, l := range lines[1:] {
		if len(l) == 0 {
			continue
		}
		headers = append(headers, l)
	}
	return requestLine, headers, body, hasBody, true
}

// rebuildRequest reassembles a request from its parts, always terminating the header block with
// the blank line HTTP requires. splitRequest only ever produces its parts from a request that had
// a request line, so this is always safe to write unconditionally.
func rebuildRequest(requestLine []byte, headers [][]byte, body []byte, hasBody bool) []byte {
	var out bytes.Buffer
	out.Write(requestLine)
	for _, h := range headers {
		out.WriteString("\r\n")
		out.Write(h)
	}
	out.WriteString("\r\n\r\n")
	if hasBody {
		out.Write(body)
	}
	return out.Bytes()
}

// headerNameEquals reports whether line's header name matches name, case-insensitively — header
// field names are case-insensitive per RFC 7230 §3.2.
func headerNameEquals(line []byte, name string) bool {
	i := bytes.IndexByte(line, ':')
	if i < 0 {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(string(line[:i])), name)
}

// ---------------------------------------------------------------------------
// Composed evasion: wraps a SendFn
// ---------------------------------------------------------------------------

// WAFEvasion composes the techniques above around an existing SendFn, so an attack gains them
// without engine.go or limit.go needing to know they exist. Every field is optional and nil/zero
// means "off" — an Attack that wants only User-Agent rotation sets UserAgents and leaves the rest
// zero.
//
// This sits strictly outside the rate limiter: Jitter.Sleep runs before the wrapped send, and the
// RateLimiter inside send still reserves its own token and slot exactly as it would for a caller
// with no WAFEvasion at all. The two delays add rather than one replacing the other, which is the
// conservative composition — see limit.go's DelayVariation doc for why a jitter and a rate cap
// cannot be collapsed into one wait without giving up one of the two guarantees.
type WAFEvasion struct {
	// UserAgents rotates the User-Agent header per request. Nil leaves it untouched.
	UserAgents *UserAgentPool
	// Jitter adds a random delay before each send, independent of the RateLimiter's own pacing.
	// Nil adds no delay.
	Jitter *Jitter
	// ShuffleHeaderOrder randomizes header order per request when true.
	ShuffleHeaderOrder bool
	// headerRnd is the header-shuffle generator, guarded by mu because math/rand/v2's Rand is
	// not safe for concurrent use and the engine's sends run from concurrent goroutines. Kept
	// separate from Jitter's own generator so turning jitter on or off does not shift the
	// header-shuffle sequence a test might be asserting against, or vice versa.
	headerRnd *rand.Rand
	mu        sync.Mutex
}

// NewWAFEvasion builds a wrapper seeded for reproducible header shuffling. seed 0 is a seed like
// any other, not "unseeded" — the same convention DelayVariation.Seed documents in limit.go.
func NewWAFEvasion(seed uint64) *WAFEvasion {
	return &WAFEvasion{headerRnd: rand.New(rand.NewPCG(seed, seed^variationSeedStream))}
}

// Wrap returns send with every configured technique applied, in a fixed order: the jitter waits
// first (so the wait is charged before the request is even touched), then the User-Agent is
// rotated in, then headers are shuffled — each step working on the previous step's output so the
// final bytes reflect every technique that was configured.
func (w *WAFEvasion) Wrap(send SendFn) SendFn {
	return func(raw []byte) (Sent, error) {
		if w.Jitter != nil {
			w.Jitter.Sleep()
		}
		if w.UserAgents != nil {
			raw = ApplyUserAgent(raw, w.UserAgents.Next())
		}
		if w.ShuffleHeaderOrder {
			w.mu.Lock()
			raw = ShuffleHeaders(raw, w.headerRnd)
			w.mu.Unlock()
		}
		return send(raw)
	}
}

// wrapOrIdentity is Wrap with a nil receiver tolerated, for the one caller that holds an optional
// *WAFEvasion: Run, which wraps the SendFn it was handed exactly once.
//
// A nil-receiver method rather than an `if a.Evasion != nil` at the call site, because the call
// site is the thing that must not be able to get this wrong — a future second entry point that
// forgets the nil check would panic on every attack that configured no evasion, which is most of
// them. Returning the caller's own function unchanged (not a wrapper that does nothing) also keeps
// the unconfigured path free of an extra indirection per send.
func (w *WAFEvasion) wrapOrIdentity(send SendFn) SendFn {
	if w == nil {
		return send
	}
	return w.Wrap(send)
}
