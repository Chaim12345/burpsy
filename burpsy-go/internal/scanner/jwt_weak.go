// SCAN-02 — JWTs signed with a weak HMAC secret, proved by verifying the signature.
//
// A port of crates/scanner/src/jwt_weak.rs. Named divergences are at the bottom of this comment;
// everything else below is the Rust module's reasoning, which the port preserves.
//
// # The only finding this check will make
//
// A candidate secret from the wordlist recomputes the token's signature exactly. Nothing else
// counts. A short secret, a suspicious `kid`, a token that "looks" weak — none of those are findings
// here, because none of them is evidence that anyone can forge a token. That is why the confidence
// is always certain: the check has either reproduced the signature or it has not.
//
// # Scope: HMAC only, and the rest is counted
//
// HS256/HS384/HS512 are the algorithms whose signing key is a shared secret, so a wordlist attack is
// the relevant attack at all. RS*/ES*/PS* are asymmetric and `alg: none` is a different
// vulnerability with its own catalogued definition. Those tokens are **counted as skipped**, per
// algorithm, in JwtCoverage.OutOfScopeAlgorithms. Leaving them out of the report would let "no weak
// secrets found" cover tokens this check never attacked.
//
// # The bound, and why a truncated attack is not a clean result
//
// This is brute force, so the work is `distinct tokens × wordlist entries` HMAC computations.
// NewJwtWeakSecretCheckWithBudget caps that at maxHmacAttempts per response. When the cap stops a
// token part-way, the token is outcomeAbandoned: TokensAbandoned goes up, JwtCoverage.Truncated
// becomes true, and the token is **not** counted as exhausted. Only a token tested against every
// entry in the wordlist is TokensExhausted, and even that is a claim about the wordlist rather than
// about the secret — which is why JwtCoverage.Wordlist names the list and its exact size in every
// report. "No weak secrets found against 51 entries" and "…against 10 million entries" are different
// claims, and stating only the conclusion is how a truncated brute force gets read as a clean bill
// of health.
//
// # Deduplication
//
// Keyed on the signing input, so a session token seen on 200 pages is cracked once. Same insight as
// the finding store's insertion-time dedup and the audit ledger's already-covered verdict. The table
// is capped at MaxTrackedTokens: past that, tokens are still tested (never skipped) but no longer
// remembered, and JwtCoverage.DedupCapacityReached says so — the honest failure direction is
// repeated work, not unexamined tokens.
//
// # Where the wordlist comes from
//
// BundledJwtWordlist is 51 entries, each one verified present in Burp Suite 2026.7.1's shipped
// `resources/Scanner/jwt_secrets.txt` (sha256
// `0e451733b80f7cf722f6e33b82e4e6c7ca4b66c8407da0a7e92badd445d52fb2`, 103,975 entries) on
// 2026-07-28. Burp's whole list is deliberately *not* vendored: a megabyte of password dump for a
// check whose real hit rate comes from a few dozen framework defaults is a poor trade, and
// LoadJwtWordlist takes the full file — or any other — from an operator who wants it. The 51 entries
// below are transcribed from crates/scanner/src/jwt_weak.rs, which is where that verification was
// performed; this file did not re-derive the list and does not claim to have.
//
// # Named divergences from the Rust module
//
//  1. **`alg: none` no longer produces a finding here.** The Go check this replaces raised a
//     critical/certain "JWT Algorithm None" finding whenever it saw one in a response. That is an
//     overclaim: observing an unsigned token in traffic is not evidence that the server *accepts*
//     one, which is what Burp's catalogued "JWT none algorithm supported" issue asserts and what
//     proving it requires — re-sending a forged token and seeing it honoured, an active probe this
//     passive check does not perform. Following the Rust module, `none` is now counted as an
//     out-of-scope algorithm (visible by name and count in JwtCoverage.OutOfScopeAlgorithms) rather
//     than reported as a vulnerability.
//  2. **The dedup table is a plain map behind a mutex**, where Rust uses parking_lot's RwLock. Every
//     claim writes, so a read-write split would buy nothing.
//  3. **Base64url decoding uses encoding/base64's RawURLEncoding** rather than a hand-rolled decoder,
//     with the two explicit guards Rust's decoder has and the standard library does not: an empty
//     segment and a length that cannot be a base64 encoding at all are refusals, not empty decodes.
package scanner

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/burpsy-go/burpsy/internal/core"
)

// jwtIssue is the issue name, an exact match for Burp's catalogued issue (catalog_data.go, declared
// type index 2099459) so EnrichFinding attaches Burp's own remediation.
const jwtIssue = "JWT weak HMAC secret"

// DefaultMaxHmacAttempts is how many HMAC computations one response may cost. 200,000 short-input
// HMAC-SHA256 computations are affordable off the proxy hot path and nowhere near affordable on it —
// which is the other reason scanning does not run there.
const DefaultMaxHmacAttempts uint64 = 200_000

// MaxTrackedTokens is how many distinct signing inputs are remembered for deduplication. A cap
// rather than an unbounded map because this package's whole thesis is that nothing may grow without
// limit with traffic volume.
const MaxTrackedTokens = 65_536

// MaxTokenBytes is the longest token this check will hash. A token above this is refused *before*
// any HMAC work and counted: a multi-megabyte "token" is a denial of service against the scanner,
// not a credential.
const MaxTokenBytes = 8 * 1024

// bundledJwtSecrets are secrets that are documented framework defaults, canonical documentation
// examples, or the perennial placeholders. Every entry was verified present in Burp's shipped
// jwt_secrets.txt — see the file docs — so this list is a stated subset of a known corpus rather
// than a guess at what a weak secret looks like.
var bundledJwtSecrets = []string{
	"secret",
	"Secret",
	"SECRET",
	"secretkey",
	"secret_key",
	"secretKey",
	"mysecret",
	"my-secret",
	"supersecret",
	"super-secret",
	"topsecret",
	"changeme",
	"changeit",
	"password",
	"Password",
	"passw0rd",
	"123456",
	"qwerty",
	"admin",
	"test",
	"jwt",
	"jwtsecret",
	"jwt_secret",
	"jwtSecret",
	"jwt-secret",
	"your-256-bit-secret",
	"your_secret_key",
	"keyboard cat",
	"default",
	"dev",
	"development",
	"token",
	"shhhh",
	"s3cr3t",
	"letmein",
	"abc123",
	"1234567890",
	"null",
	"undefined",
	"example",
	"hello",
	"iloveyou",
	"root",
	"JWT_SECRET",
	"asdf",
	"foo",
	"bar",
	"secretsecret",
	"mySuperSecretKey",
	"your-secret-key",
	"thisisasecret",
}

// hmacAlg is one of the HMAC algorithms a wordlist attack applies to.
type hmacAlg int

const (
	hmacNotSupported hmacAlg = iota
	hmacHS256
	hmacHS384
	hmacHS512
)

func parseHmacAlg(alg string) (hmacAlg, bool) {
	switch alg {
	case "HS256":
		return hmacHS256, true
	case "HS384":
		return hmacHS384, true
	case "HS512":
		return hmacHS512, true
	}
	return hmacNotSupported, false
}

// verifies recomputes the signature and compares it in constant time. Any key length is accepted,
// which is what makes short weak secrets testable at all.
func (a hmacAlg) verifies(key, signingInput, signature []byte) bool {
	var h hash.Hash
	switch a {
	case hmacHS256:
		h = hmac.New(sha256.New, key)
	case hmacHS384:
		h = hmac.New(sha512.New384, key)
	case hmacHS512:
		h = hmac.New(sha512.New, key)
	default:
		return false
	}
	h.Write(signingInput)
	return hmac.Equal(h.Sum(nil), signature)
}

// JwtWordlist is a candidate-secret list, with the identity that has to appear beside any negative
// result.
type JwtWordlist struct {
	name    string
	source  string
	entries []string
}

// WordlistID is how a report names the wordlist. Without this, "no weak secrets found" is an
// unqualified claim.
type WordlistID struct {
	Name    string `json:"name"`
	Source  string `json:"source"`
	Entries int    `json:"entries"`
}

// BundledJwtWordlist is the compiled-in default. See the file docs for its provenance.
func BundledJwtWordlist() JwtWordlist {
	entries := make([]string, len(bundledJwtSecrets))
	copy(entries, bundledJwtSecrets)
	return JwtWordlist{
		name:    "burpsy bundled JWT secrets",
		source:  "subset of Burp Suite 2026.7.1 resources/Scanner/jwt_secrets.txt, verified 2026-07-28",
		entries: entries,
	}
}

// LoadJwtWordlist reads one secret per line, dropping blank lines. Duplicates are dropped too, so
// the reported entry count is the number of *distinct* secrets actually tried rather than the file's
// line count — the budget is spent on distinct work and the number beside a negative result should
// describe the same thing.
func LoadJwtWordlist(path string) (JwtWordlist, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return JwtWordlist{}, err
	}
	seen := make(map[string]struct{})
	var entries []string
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSuffix(line, "\r")
		if line == "" {
			continue
		}
		if _, dup := seen[line]; dup {
			continue
		}
		seen[line] = struct{}{}
		entries = append(entries, line)
	}
	if len(entries) == 0 {
		return JwtWordlist{}, fmt.Errorf("%s contains no candidate secrets", path)
	}
	name := path
	if i := strings.LastIndexAny(path, `/\`); i >= 0 && i+1 < len(path) {
		name = path[i+1:]
	}
	return JwtWordlist{name: name, source: path, entries: entries}, nil
}

// JwtWordlistFromEntries builds a list from explicit entries, for tests and for a caller assembling
// one in memory.
func JwtWordlistFromEntries(name, source string, entries []string) JwtWordlist {
	owned := make([]string, len(entries))
	copy(owned, entries)
	return JwtWordlist{name: name, source: source, entries: owned}
}

// ID returns how a report should name this list.
func (w JwtWordlist) ID() WordlistID {
	return WordlistID{Name: w.name, Source: w.source, Entries: len(w.entries)}
}

// Len reports how many distinct candidate secrets the list holds.
func (w JwtWordlist) Len() int { return len(w.entries) }

// IsEmpty reports whether there is nothing to try.
func (w JwtWordlist) IsEmpty() bool { return len(w.entries) == 0 }

// locationKind is where a token was found. Part of the finding detail because a token in a
// Set-Cookie and a token pasted into a response body are different mistakes.
type locationKind int

const (
	locResponseBody locationKind = iota
	locResponseHeader
	locRequestHeader
)

type tokenLocation struct {
	kind   locationKind
	header string
}

func (l tokenLocation) String() string {
	switch l.kind {
	case locResponseHeader:
		return "response header " + l.header
	case locRequestHeader:
		return "request header " + l.header
	default:
		return "the response body"
	}
}

// rawToken is a JWS-shaped string found in traffic, before its header has been looked at.
type rawToken struct {
	signingInput string
	signatureB64 string
	headerB64    string
	whereFound   tokenLocation
}

// tokenOutcome is what happened to one distinct token. Every token lands in exactly one of these,
// which is what makes the counters in JwtCoverage sum to TokensDistinct.
type tokenOutcome int

const (
	// outcomeCracked means a wordlist entry reproduced the signature.
	outcomeCracked tokenOutcome = iota
	// outcomeExhausted means the token was tested against every wordlist entry with no match.
	// Evidence, bounded by the wordlist.
	outcomeExhausted
	// outcomeAbandoned means the attempt hit the HMAC budget before the wordlist ran out. **Not** a
	// clean result.
	outcomeAbandoned
	// outcomeOutOfScope means it is not an HMAC algorithm: nothing here to attack with a wordlist.
	outcomeOutOfScope
	// outcomeRefused means the header would not decode, or the token was too large to hash. Refused,
	// not guessed at.
	outcomeRefused
)

// AlgCount is one out-of-scope algorithm and how many tokens used it.
type AlgCount struct {
	Alg   string `json:"alg"`
	Count uint64 `json:"count"`
}

// JwtCoverage is SCAN-02's record of what it attacked and what it declined to.
type JwtCoverage struct {
	// Wordlist names which list the negative results are relative to.
	Wordlist WordlistID `json:"wordlist"`
	// MaxHmacAttempts is the per-response HMAC cap in force.
	MaxHmacAttempts uint64 `json:"max_hmac_attempts"`
	Responses       uint64 `json:"responses"`
	// TokensSeen counts token-shaped strings seen, including repeats.
	TokensSeen uint64 `json:"tokens_seen"`
	// TokensDistinct counts distinct signing inputs actually considered.
	TokensDistinct uint64 `json:"tokens_distinct"`
	// TokensAlreadyCovered counts repeats collapsed by the dedup table.
	TokensAlreadyCovered uint64 `json:"tokens_already_covered"`
	TokensCracked        uint64 `json:"tokens_cracked"`
	// TokensExhausted counts tokens tested against the whole wordlist with no match.
	TokensExhausted uint64 `json:"tokens_exhausted"`
	// TokensAbandoned counts tokens given up on part-way through the wordlist. These are the tokens
	// a clean report must not cover.
	TokensAbandoned uint64 `json:"tokens_abandoned"`
	// TokensOutOfScope counts tokens that are not HMAC-signed, so out of this check's scope
	// entirely.
	TokensOutOfScope uint64 `json:"tokens_out_of_scope"`
	// TokensRefused counts tokens whose header would not decode, or which were larger than
	// MaxTokenBytes.
	TokensRefused uint64 `json:"tokens_refused"`
	// HmacAttempts counts HMAC computations performed.
	HmacAttempts uint64 `json:"hmac_attempts"`
	// Truncated is true once any token was abandoned mid-wordlist.
	Truncated bool `json:"truncated"`
	// DedupCapacityReached means the dedup table stopped remembering tokens, so some work may have
	// been repeated. Counted because the alternative reading — that tokens were skipped — would be
	// much worse and a reader cannot tell the two apart without being told.
	DedupCapacityReached bool `json:"dedup_capacity_reached"`
	// RequestsUnavailable counts responses scanned with no matching request message available, so
	// request-side tokens (`Authorization: Bearer …`) were not seen for them.
	RequestsUnavailable uint64 `json:"requests_unavailable"`
	// OutOfScopeAlgorithms names the algorithms seen and skipped, with counts — RS256, none, and
	// anything else asymmetric.
	OutOfScopeAlgorithms []AlgCount `json:"out_of_scope_algorithms"`
}

// Accounted sums the per-outcome counters. Every distinct token lands in exactly one outcome, so
// this must equal TokensDistinct. A tested invariant: a future outcome added without being counted
// here would otherwise silently shrink the denominator behind every claim this check makes.
func (c JwtCoverage) Accounted() uint64 {
	return c.TokensCracked + c.TokensExhausted + c.TokensAbandoned + c.TokensOutOfScope + c.TokensRefused
}

// Inconclusive reports whether a zero-finding result does not mean "no weak secrets".
func (c JwtCoverage) Inconclusive() bool {
	return c.Truncated || c.TokensRefused > 0 || c.TokensOutOfScope > 0
}

// Summary is one line an operator can act on, naming the wordlist and every give-up.
func (c JwtCoverage) Summary() string {
	return fmt.Sprintf(
		"%d distinct JWTs against %s (%d entries): %d cracked, %d exhausted, %d abandoned mid-wordlist, "+
			"%d out of scope (non-HMAC), %d refused; %d HMAC attempts",
		c.TokensDistinct,
		c.Wordlist.Name,
		c.Wordlist.Entries,
		c.TokensCracked,
		c.TokensExhausted,
		c.TokensAbandoned,
		c.TokensOutOfScope,
		c.TokensRefused,
		c.HmacAttempts,
	)
}

// JwtWeakSecretCheck is SCAN-02 as a passive check.
type JwtWeakSecretCheck struct {
	wordlist    JwtWordlist
	maxAttempts uint64

	// mu guards seen, the set of signing inputs already resolved, so a token seen again is not
	// re-attacked. Every claim writes, so there is no read-only path to split out.
	mu   sync.Mutex
	seen map[string]struct{}

	dedupFull           atomic.Bool
	truncated           atomic.Bool
	responses           atomic.Uint64
	tokensSeen          atomic.Uint64
	tokensDistinct      atomic.Uint64
	alreadyCovered      atomic.Uint64
	cracked             atomic.Uint64
	exhausted           atomic.Uint64
	abandoned           atomic.Uint64
	outOfScope          atomic.Uint64
	refused             atomic.Uint64
	attempts            atomic.Uint64
	requestsUnavailable atomic.Uint64

	algsMu sync.Mutex
	algs   map[string]uint64
}

// JwtWeakSecretCheckName is the check's name, as coverage and logs spell it.
const JwtWeakSecretCheckName = "JWT weak HMAC secret (SCAN-02)"

// BundledJwtWeakSecretCheck is the bundled wordlist at the default budget.
func BundledJwtWeakSecretCheck() *JwtWeakSecretCheck {
	return NewJwtWeakSecretCheckWithBudget(BundledJwtWordlist(), DefaultMaxHmacAttempts)
}

// NewJwtWeakSecretCheck runs one wordlist at the default budget.
func NewJwtWeakSecretCheck(wordlist JwtWordlist) *JwtWeakSecretCheck {
	return NewJwtWeakSecretCheckWithBudget(wordlist, DefaultMaxHmacAttempts)
}

// NewJwtWeakSecretCheckWithBudget sets an explicit HMAC budget per response. Zero means no token can
// be tested at all, and every token is then reported abandoned rather than clean.
func NewJwtWeakSecretCheckWithBudget(wordlist JwtWordlist, maxHmacAttempts uint64) *JwtWeakSecretCheck {
	return &JwtWeakSecretCheck{
		wordlist:    wordlist,
		maxAttempts: maxHmacAttempts,
		seen:        make(map[string]struct{}),
		algs:        make(map[string]uint64),
	}
}

// Coverage returns a point-in-time snapshot of what this check attacked and what it declined to.
func (c *JwtWeakSecretCheck) Coverage() JwtCoverage {
	c.algsMu.Lock()
	algs := make([]AlgCount, 0, len(c.algs))
	for alg, n := range c.algs {
		algs = append(algs, AlgCount{Alg: alg, Count: n})
	}
	c.algsMu.Unlock()
	// Sorted by algorithm name, matching the Rust BTreeMap, so two runs over the same traffic
	// produce the same report rather than one in Go map order.
	sort.Slice(algs, func(i, j int) bool { return algs[i].Alg < algs[j].Alg })

	return JwtCoverage{
		Wordlist:             c.wordlist.ID(),
		MaxHmacAttempts:      c.maxAttempts,
		Responses:            c.responses.Load(),
		TokensSeen:           c.tokensSeen.Load(),
		TokensDistinct:       c.tokensDistinct.Load(),
		TokensAlreadyCovered: c.alreadyCovered.Load(),
		TokensCracked:        c.cracked.Load(),
		TokensExhausted:      c.exhausted.Load(),
		TokensAbandoned:      c.abandoned.Load(),
		TokensOutOfScope:     c.outOfScope.Load(),
		TokensRefused:        c.refused.Load(),
		HmacAttempts:         c.attempts.Load(),
		Truncated:            c.truncated.Load(),
		DedupCapacityReached: c.dedupFull.Load(),
		RequestsUnavailable:  c.requestsUnavailable.Load(),
		OutOfScopeAlgorithms: algs,
	}
}

// Scan examines one response, plus the request that produced it when the caller has it.
//
// request may be nil because a passive caller is sometimes handed a response alone. That is
// legitimate, but it means Authorization headers were never looked at, so it increments
// JwtCoverage.RequestsUnavailable instead of passing silently.
func (c *JwtWeakSecretCheck) Scan(resp *core.StoredMessage, request *core.StoredMessage) []*Finding {
	c.responses.Add(1)
	if request == nil {
		c.requestsUnavailable.Add(1)
	}

	var raw []rawToken
	if resp != nil {
		raw = collectTokens(resp, false, raw)
	}
	if request != nil {
		raw = collectTokens(request, true, raw)
	}
	c.tokensSeen.Add(uint64(len(raw)))

	budget := c.maxAttempts
	var out []*Finding
	for _, t := range raw {
		if !c.claim(t) {
			c.alreadyCovered.Add(1)
			continue
		}
		c.tokensDistinct.Add(1)
		outcome, secret := c.attack(t, &budget)
		switch outcome {
		case outcomeCracked:
			c.cracked.Add(1)
			out = append(out, c.finding(t, secret))
		case outcomeExhausted:
			c.exhausted.Add(1)
		case outcomeAbandoned:
			c.abandoned.Add(1)
			c.truncated.Store(true)
		case outcomeOutOfScope:
			c.outOfScope.Add(1)
		default:
			c.refused.Add(1)
		}
	}
	return out
}

// claim claims a token for attack, returning false when it was already resolved.
//
// The key is the signing input AND the signature, not the signing input alone.
//
// Deduping on the signing input was one character short of correct and cost a real detection. Two
// tokens can carry byte-identical headers and payloads and differ only in their signature, which
// means they were signed with DIFFERENT KEYS - one of which may be weak. Keyed on the signing input,
// whichever token was seen first claimed the pair and the other was accounted "already covered"
// without ever being attacked, so a weak key sitting behind an identical payload was silently
// unreachable. A host rotating keys, or dev and prod signing the same claims, produces exactly that
// shape; so does internal/vulnapp, where /nt/session and /nt/safe/session issue the same claims
// under a wordlist secret and a random one, and whichever the harness audited first decided the
// verdict for both.
//
// The signature is the thing being attacked, so it belongs in the identity. The optimisation this
// table exists for is untouched: a session token seen on 200 pages has the same signing input and
// the same signature on all 200, so it is still cracked once.
//
// Past MaxTrackedTokens the table stops growing and every token is claimed — repeating work rather
// than skipping tokens, which is the failure direction that cannot produce a false negative.
func (c *JwtWeakSecretCheck) claim(t rawToken) bool {
	key := t.signingInput + "." + t.signatureB64
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.seen[key]; ok {
		return false
	}
	if len(c.seen) >= MaxTrackedTokens {
		c.dedupFull.Store(true)
		return true
	}
	c.seen[key] = struct{}{}
	return true
}

// attack runs the wordlist against one token, spending from budget.
func (c *JwtWeakSecretCheck) attack(t rawToken, budget *uint64) (tokenOutcome, string) {
	if len(t.signingInput)+len(t.signatureB64)+1 > MaxTokenBytes {
		return outcomeRefused, ""
	}
	headerBytes, ok := b64urlDecode(t.headerB64)
	if !ok {
		return outcomeRefused, ""
	}
	var header struct {
		Alg *string `json:"alg"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return outcomeRefused, ""
	}
	if header.Alg == nil {
		return outcomeRefused, ""
	}
	alg, supported := parseHmacAlg(*header.Alg)
	if !supported {
		c.algsMu.Lock()
		c.algs[*header.Alg]++
		c.algsMu.Unlock()
		return outcomeOutOfScope, ""
	}
	signature, ok := b64urlDecode(t.signatureB64)
	if !ok {
		return outcomeRefused, ""
	}

	for _, candidate := range c.wordlist.entries {
		if *budget == 0 {
			return outcomeAbandoned, ""
		}
		*budget--
		c.attempts.Add(1)
		if alg.verifies([]byte(candidate), []byte(t.signingInput), signature) {
			return outcomeCracked, candidate
		}
	}
	return outcomeExhausted, ""
}

func (c *JwtWeakSecretCheck) finding(t rawToken, secret string) *Finding {
	return &Finding{
		Name:       jwtIssue,
		Severity:   "high",
		Confidence: "certain",
		Description: fmt.Sprintf(
			"A JWT found in %s is signed with the secret %q, taken from %s (%d entries). The signature "+
				"was recomputed with that secret and matched, so anyone holding the wordlist can mint "+
				"tokens for this application. Signing input: %s.",
			t.whereFound, secret, c.wordlist.name, len(c.wordlist.entries), elideSigningInput(t.signingInput)),
		Evidence: secret,
		// Merge on the secret, not the target (burpsy-react-ui-7tc1). One weak key is one weakness
		// however many endpoints issue tokens under it: Burp's merger compares a fingerprint for
		// exactly this row (Zbvp.java:53-56), and keying on the target instead files the same proven
		// fact as a separate High per endpoint — a session cookie on /login, /api/session and every
		// other page that sets it, which is the shape a long crawl produces.
		//
		// The secret, not the signing input: two tokens signed with different keys can carry
		// byte-identical claims, so claims do not identify which key is weak. Only the recovered
		// secret does, and it is what the finding proved.
		MergeKey: secret,
		// Solution is left to EnrichFinding: Burp's catalogued definition for this exact issue name
		// carries the real remediation text.
		Timestamp: time.Now(),
	}
}

// elideSigningInput shortens a signing input for a finding detail. A finding is a report, not a copy
// of the traffic — the store already holds the bytes and the finding carries the exchange id.
func elideSigningInput(s string) string {
	if len(s) <= 96 {
		return s
	}
	return fmt.Sprintf("%s…%s (%d bytes)", s[:48], s[len(s)-16:], len(s))
}

// collectTokens pulls every JWS-shaped string out of one message's headers and body.
func collectTokens(msg *core.StoredMessage, isRequest bool, out []rawToken) []rawToken {
	for _, h := range msg.Shape.Headers {
		at := tokenLocation{kind: locResponseHeader, header: msg.Text(h.Name)}
		if isRequest {
			at.kind = locRequestHeader
		}
		out = scanTextForTokens(msg.Text(h.Value), at, out)
	}
	if !isRequest {
		out = scanTextForTokens(string(readableBody(msg)), tokenLocation{kind: locResponseBody}, out)
	}
	return out
}

// scanTextForTokens finds `header.payload.signature` triples.
//
// Anchored on `eyJ` — the base64url of `{"` — rather than on a general three-segment pattern,
// because "three dot-separated base64url runs" also describes plenty of filenames and version
// strings, and every one of those would cost a base64 decode and a JSON parse to reject.
//
// A candidate is refused rather than trimmed if its run does not have exactly three segments: a
// five-segment JWE is a different thing, and silently taking its first three parts would produce a
// signature check against bytes that are not a signature.
func scanTextForTokens(hay string, at tokenLocation, out []rawToken) []rawToken {
	for i := 0; i < len(hay); {
		rel := strings.Index(hay[i:], "eyJ")
		if rel < 0 {
			break
		}
		start := i + rel
		// Mid-token match: the byte before is part of the same base64url run, so this "eyJ" is not
		// the start of a header segment.
		if start > 0 && isSegmentBody(hay[start-1]) {
			i = start + 3
			continue
		}
		end := start
		for end < len(hay) && (isSegmentBody(hay[end]) || hay[end] == '.' || hay[end] == '=') {
			end++
		}
		run := strings.TrimRight(hay[start:end], ".")
		parts := strings.Split(run, ".")
		if len(parts) == 3 && parts[0] != "" && parts[1] != "" && parts[2] != "" {
			out = append(out, rawToken{
				signingInput: parts[0] + "." + parts[1],
				signatureB64: parts[2],
				headerB64:    parts[0],
				whereFound:   at,
			})
		}
		if next := start + 3; end > next {
			i = end
		} else {
			i = next
		}
	}
	return out
}

// isSegmentBody reports whether b is in the base64url alphabet proper.
//
// `=` is deliberately excluded: it is tolerated *inside* a segment as padding, but a `=` before
// `eyJ` is `cookie=eyJ…` or `token=eyJ…` — the most common way a token appears in real traffic — and
// treating it as part of a preceding token skipped every one of them.
func isSegmentBody(b byte) bool {
	return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') || b == '-' || b == '_'
}

// b64urlDecode decodes unpadded base64url, refusing anything that is not.
//
// Padding is tolerated because real deployments emit it despite RFC 7515 forbidding it, but a
// character outside the alphabet, or a length that cannot be a base64 encoding at all, is a refusal:
// a partial decode would hand a truncated signature to the comparison. The empty-string and
// length%4==1 guards are explicit because the standard library treats the first as a valid empty
// decode.
func b64urlDecode(s string) ([]byte, bool) {
	s = strings.TrimRight(s, "=")
	if s == "" || len(s)%4 == 1 {
		return nil, false
	}
	out, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, false
	}
	return out, true
}
