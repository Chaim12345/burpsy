package scanner

// Weak cryptography applied to user input, proven by computation (burpsy-react-ui-0vzb.28).
//
// A response that shows a 32-hex-digit string says nothing: it may be an ETag, a session id or a
// random token, and the "Potential Hash" posture row is exactly that guess. This check never guesses
// from a shape. It COMPUTES what a weak scheme would produce from a value the scanner chose and
// reports only when the response carries that exact output.
//
// # Hash of a fresh marker (active)
//
// Each probed parameter is set to a fresh random marker m1 (12 lower-case letters and digits). The
// check computes m1's digest under every unsalted scheme below, in lower- and upper-case hex and in
// standard, unpadded and URL-safe base64, and searches the answer. A digest found there must also be
// absent from the baseline answer and from the request. The check then sends a second fresh marker
// m2 and requires the SAME scheme's digest of m2 in that answer. Two independent random inputs
// mapping through the same function is proof that the server applies it to the parameter, unsalted
// (a salt or key would change the output), and discloses the result.
//
//   - Weak algorithms (CWE-328): MD4, MD5, SHA-1, NTLM (MD4 of UTF-16LE), LM (DES of "KGS!@#$%" under
//     the upper-cased, 14-byte-padded value) and MySQL 4.1 (SHA-1 of SHA-1). These report "Weak hash
//     algorithm applied to input".
//   - Fast general-purpose hashes (SHA-224/256/384/512) are not weak algorithms. Applied unsalted to
//     a PASSWORD-named parameter they, like the weak ones, report "Password hash with insufficient
//     computational effort" (CWE-916). Applied to any other parameter they report nothing.
//
// # The submitted value's own digest (valid credentials)
//
// A login replayed with working credentials can answer with the stored record. When the baseline
// answer (the captured request re-sent unchanged) carries the digest of the parameter's ORIGINAL value
// (at least 4 characters) under one of the schemes above, and the m1 answer does not carry it (so it
// is not text the page shows for every input), the server computed that digest of the submitted
// value. A bcrypt string in the baseline answer is verified against the original value (and in an m1
// answer against m1) with bcrypt itself; one that matches with a cost below 10 reports the
// insufficient-effort row. A bcrypt hash of cost 10 or more, or one that does not match, is quiet.
//
// # Plaintext password storage
//
// For a password-named parameter with working credentials: the baseline answer is JSON whose member
// under a key OTHER than the parameter's own name holds the original value verbatim, the m1 answer
// does not contain m1 (the field is not echoed) and does not contain the original value. The value
// came back from the server's own record only when it was the right one: "Password stored in
// plaintext" (CWE-256).
//
// # ECB mode (active)
//
// Run only when the m1 answer carries a new base64 or hex token of at least 12 bytes that no digest
// found above explains (something encrypted or encoded the input). The parameter is set to four copies of a random 16-letter block B1. In ECB
// mode identical plaintext blocks encrypt to identical ciphertext blocks, so a new token in the
// answer whose 16-byte (or 8-byte) blocks repeat shows it, whatever the key and whatever prefix the
// server adds. Required as well: a 64-letter non-periodic control produces a token with no repeated
// block, a second periodic probe with a fresh block B2 repeats again with a DIFFERENT repeated block,
// and no repeating token contains the plaintext block (an encoding of the input is not encryption).
// Reports "Block cipher in ECB mode applied to input" (CWE-327).
//
// # Safety and scope
//
// Markers are inert letters and digits. GET and POST only. Not re-sent: a request whose path names a
// destructive or account-changing operation (delete, change, update, register, signup, reset, ...)
// or one that sends mail or moves money, and a POST with a parameter that confirms, replaces or
// renews a password (confirm, new, old, current, repeat). At most four parameters, password-named
// first, and at most five requests each. A login form probed with markers records failed logins,
// which is why the check is off by default (check_weak_crypto).
//
// # Not done
//
// A cipher whose output for the input is never shown (only a stored secret's ciphertext is) cannot be
// proven without decrypting candidates against the server, which this check does not do. Salted or
// keyed schemes (HMAC, salted SHA) are correctly not reported: their output cannot be computed.
//
// # Catalogue rows
//
// Burp's catalogue has no row for any of these; they are burpsy's own (BurpsyNativeRows, native/
// b5003800-b5003830), reported by a check riding "Suspicious input transformation (reflected)" behind
// its own switch: each is a transformation of the input, proven by computing it.

import (
	"bytes"
	"context"
	"crypto/des"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"regexp"
	"sort"
	"strings"
	"unicode/utf16"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/md4"

	"github.com/burpsy-go/burpsy/internal/bcheck"
)

// burpsy's own row names; see BurpsyNativeRows.
const (
	IssueWeakHashOfInput        = "Weak hash algorithm applied to input"
	IssueWeakPasswordHash       = "Password hash with insufficient computational effort"
	IssueECBEncryptionOfInput   = "Block cipher in ECB mode applied to input"
	IssuePlaintextPasswordStore = "Password stored in plaintext"
)

// weakCryptoEnabled is the check's own switch.
func weakCryptoEnabled(c *ScanConfig) bool { return c != nil && c.CheckWeakCrypto }

const (
	weakCryptoMaxPoints  = 4
	weakCryptoMinOrig    = 4
	weakCryptoBcryptCost = 10
)

// weakCryptoTrace, when set (tests only), receives each probed parameter's outcome, so a test can
// assert which guard kept a safe twin quiet.
var weakCryptoTrace func(target, param, outcome string)

// suspiciousOrWeakCrypto runs the "Suspicious input transformation (reflected)" row's own check
// (behind CheckExtendedActive) and this check (behind CheckWeakCrypto). A proven finding is returned
// even when the sibling's run was undecided.
func suspiciousOrWeakCrypto(sit CheckRunner) CheckRunner {
	return func(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
		if cc == nil {
			return nil, nil
		}
		var sf []*Finding
		var serr error
		if finalChecksEnabled(cc.Config) || !weakCryptoEnabled(cc.Config) {
			sf, serr = sit(ctx, cc)
		}
		var wf []*Finding
		var werr error
		if weakCryptoEnabled(cc.Config) {
			wf, werr = checkWeakCrypto(ctx, cc)
		}
		switch {
		case len(wf) > 0:
			return append(sf, wf...), nil
		case serr != nil:
			return sf, serr
		case werr != nil:
			return sf, werr
		}
		return sf, nil
	}
}

// ---------------------------------------------------------------------------
// digests
// ---------------------------------------------------------------------------

// wcScheme is one unsalted scheme the check can compute.
type wcScheme struct {
	name string
	// weak marks an algorithm that is broken in itself (CWE-328), not merely fast.
	weak bool
	sum  func(string) []byte
}

var wcSchemes = []wcScheme{
	{"MD4", true, func(s string) []byte { h := md4.New(); h.Write([]byte(s)); return h.Sum(nil) }},
	{"MD5", true, func(s string) []byte { b := md5.Sum([]byte(s)); return b[:] }},
	{"SHA-1", true, func(s string) []byte { b := sha1.Sum([]byte(s)); return b[:] }},
	{"NTLM", true, wcNTLM},
	{"LM", true, wcLM},
	{"MySQL 4.1 (SHA-1 of SHA-1)", true, func(s string) []byte {
		a := sha1.Sum([]byte(s))
		b := sha1.Sum(a[:])
		return b[:]
	}},
	{"SHA-224", false, func(s string) []byte { b := sha256.Sum224([]byte(s)); return b[:] }},
	{"SHA-256", false, func(s string) []byte { b := sha256.Sum256([]byte(s)); return b[:] }},
	{"SHA-384", false, func(s string) []byte { b := sha512.Sum384([]byte(s)); return b[:] }},
	{"SHA-512", false, func(s string) []byte { b := sha512.Sum512([]byte(s)); return b[:] }},
}

// wcNTLM is MD4 of the UTF-16LE value.
func wcNTLM(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 0, 2*len(u))
	for _, c := range u {
		b = append(b, byte(c), byte(c>>8))
	}
	h := md4.New()
	h.Write(b)
	return h.Sum(nil)
}

// wcLM is the LAN Manager hash. It is defined for ASCII only (other characters go through an OEM code
// page this check does not model), so a non-ASCII value has no LM digest.
func wcLM(s string) []byte {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return nil
		}
	}
	pw := make([]byte, 14)
	copy(pw, strings.ToUpper(s))
	magic := []byte("KGS!@#$%")
	out := make([]byte, 0, 16)
	for _, half := range [][]byte{pw[:7], pw[7:]} {
		c, err := des.NewCipher(wcDESKey(half))
		if err != nil {
			return nil
		}
		blk := make([]byte, 8)
		c.Encrypt(blk, magic)
		out = append(out, blk...)
	}
	return out
}

// wcDESKey spreads 7 key bytes over 8, seven bits each, leaving the parity bit clear.
func wcDESKey(k []byte) []byte {
	return []byte{
		k[0] & 0xfe,
		(k[0]<<7 | k[1]>>1) & 0xfe,
		(k[1]<<6 | k[2]>>2) & 0xfe,
		(k[2]<<5 | k[3]>>3) & 0xfe,
		(k[3]<<4 | k[4]>>4) & 0xfe,
		(k[4]<<3 | k[5]>>5) & 0xfe,
		(k[5]<<2 | k[6]>>6) & 0xfe,
		k[6] << 1,
	}
}

// wcSpellings are the spellings a digest is searched for, with their names.
func wcSpellings(d []byte) [][2]string {
	if len(d) == 0 {
		return nil
	}
	h := hex.EncodeToString(d)
	return [][2]string{
		{"hex", h},
		{"upper-case hex", strings.ToUpper(h)},
		{"base64", base64.StdEncoding.EncodeToString(d)},
		{"unpadded base64", base64.RawStdEncoding.EncodeToString(d)},
		{"URL-safe base64", base64.RawURLEncoding.EncodeToString(d)},
	}
}

// wcHit is one scheme's digest of one value found in one answer.
type wcHit struct {
	scheme   wcScheme
	spelling string
	digest   string
}

// wcView is the text a digest is searched in: the whole raw response, plus its JSON-escaped slashes
// undone so a base64 digest written as `a\/b` is still found.
func wcView(r ProbeResponse) string {
	s := string(r.Raw)
	if s == "" {
		s = r.Body
	}
	return s + "\n" + strings.ReplaceAll(s, `\/`, "/")
}

// wcDigestsIn returns the schemes whose digest of value is in the answer, at most one spelling each.
func wcDigestsIn(view, value string) []wcHit {
	var out []wcHit
	for _, sc := range wcSchemes {
		for _, sp := range wcSpellings(sc.sum(value)) {
			if strings.Contains(view, sp[1]) {
				out = append(out, wcHit{scheme: sc, spelling: sp[0], digest: sp[1]})
				break
			}
		}
	}
	return out
}

// wcConfirmed reports whether the second marker's answer carries the same scheme's digest of m2, and
// no longer carries the first marker's digest (a page that keeps showing one value is not hashing
// each input).
func wcConfirmed(hit wcHit, view2, m2 string) (wcHit, bool) {
	if strings.Contains(view2, hit.digest) {
		return wcHit{}, false
	}
	for _, s := range wcDigestsIn(view2, m2) {
		if s.scheme.name == hit.scheme.name {
			return s, true
		}
	}
	return wcHit{}, false
}

var wcBcrypt = regexp.MustCompile(`\$2[abxy]?\$(\d\d)\$[./A-Za-z0-9]{53}`)

// wcBcryptOf returns a bcrypt hash in view that verifies against value, and its cost. Hashes of cost
// weakCryptoBcryptCost or more are not verified: they would report nothing, and each costs real CPU.
func wcBcryptOf(view, value string) (string, int, bool) {
	seen := map[string]bool{}
	for _, m := range wcBcrypt.FindAllStringSubmatch(view, 8) {
		if seen[m[0]] {
			continue
		}
		seen[m[0]] = true
		cost := int(m[1][0]-'0')*10 + int(m[1][1]-'0')
		if cost >= weakCryptoBcryptCost {
			continue
		}
		if bcrypt.CompareHashAndPassword([]byte(m[0]), []byte(value)) == nil {
			return m[0], cost, true
		}
	}
	return "", 0, false
}

// ---------------------------------------------------------------------------
// which requests and parameters
// ---------------------------------------------------------------------------

// wcPathSkip are path words naming an operation that must not be repeated with an invented value:
// destructive ones, ones that create or change an account or a password, and ones that send a message
// or move money.
var wcPathSkip = map[string]bool{
	"reset": true, "forgot": true, "change": true, "update": true, "edit": true, "set": true,
	"register": true, "registration": true, "signup": true, "create": true, "new": true, "add": true,
	"mail": true, "email": true, "notify": true, "notification": true, "invite": true, "invitation": true,
	"sms": true, "otp": true, "subscribe": true, "contact": true, "comment": true, "order": true,
	"checkout": true, "pay": true, "payment": true, "transfer": true, "purchase": true,
}

// wcNameSkip are parameter-name words of a POST that confirms, replaces or renews a password: a form
// that changes a password or creates an account, never a login.
var wcNameSkip = map[string]bool{
	"confirm": true, "confirmation": true, "new": true, "old": true, "current": true, "repeat": true,
	"retype": true, "verify": true,
}

// wcProbeable reports whether the captured request may be re-sent with markers.
func wcProbeable(raw string) bool {
	line, _, _ := strings.Cut(raw, "\r\n")
	method, _, _ := strings.Cut(line, " ")
	method = strings.ToUpper(method)
	if method != "GET" && method != "POST" {
		return false
	}
	for _, w := range nosqliPathWords(raw) {
		if ssppDestructive[w] || wcPathSkip[w] {
			return false
		}
	}
	if method == "POST" {
		pts, _ := bcheck.Enumerate([]byte(raw), []string{"query", "body"})
		for _, pt := range pts {
			for _, w := range ssppNameWords(pt.Name) {
				if wcNameSkip[w] {
					return false
				}
			}
		}
	}
	return true
}

// wcPasswordName reports whether a parameter name says it carries a password.
func wcPasswordName(name string) bool {
	for _, w := range ssppNameWords(name) {
		switch w {
		case "password", "passwd", "pass", "pwd", "passphrase", "passcode", "pin", "secret":
			return true
		}
	}
	return false
}

type wcCandidate struct {
	pt       bcheck.InsertionPoint
	value    string
	password bool
}

func wcCandidates(pts []bcheck.InsertionPoint) []wcCandidate {
	var out []wcCandidate
	for _, pt := range pts {
		if pt.Kind != bcheck.IpQuery && pt.Kind != bcheck.IpBody {
			continue
		}
		v, ok := ssppDecodedValue(pt)
		if !ok {
			continue
		}
		out = append(out, wcCandidate{pt: pt, value: v, password: wcPasswordName(pt.Name)})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].password && !out[j].password })
	if len(out) > weakCryptoMaxPoints {
		out = out[:weakCryptoMaxPoints]
	}
	return out
}

// ---------------------------------------------------------------------------
// the check
// ---------------------------------------------------------------------------

func checkWeakCrypto(ctx context.Context, cc *CheckContext) ([]*Finding, error) {
	if cc == nil || cc.Scanner == nil || cc.Exchange == nil {
		return nil, fmt.Errorf("weak crypto: no scanner or exchange: %w", errCapabilityMissing)
	}
	if cc.Scanner.sender == nil {
		return nil, fmt.Errorf("weak crypto: no sender; an active probe cannot be sent: %w", errCapabilityMissing)
	}
	raw := requestRaw(cc.Scanner, cc.Exchange)
	if raw == "" || !wcProbeable(raw) {
		return nil, nil
	}
	var kinds []string
	for _, k := range cc.ProbeInsertionKinds() {
		if k == "query" || k == "body" {
			kinds = append(kinds, k)
		}
	}
	if len(kinds) == 0 {
		return nil, nil
	}
	if pre, _ := bcheck.EnumerateWith([]byte(raw), kinds, cc.ProbeEnumerateOptions()); len(pre) == 0 {
		return nil, nil
	}
	h, err := NewProbeHarness(ctx, cc, kinds)
	if err != nil {
		return nil, fmt.Errorf("weak crypto: %w", err)
	}
	p := &wcProber{cc: cc, h: h, raw: raw, rows: map[string]*Finding{}}
	var failures []string
	for _, c := range wcCandidates(h.Points()) {
		outcome, err := p.point(ctx, c)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s %q: %v", c.pt.Kind, c.pt.Name, err))
			outcome = "failed: " + err.Error()
		}
		if weakCryptoTrace != nil {
			weakCryptoTrace(exchangeURL(cc.Exchange), c.pt.Name, outcome)
		}
	}
	var out []*Finding
	for _, name := range []string{IssueWeakHashOfInput, IssueWeakPasswordHash, IssueECBEncryptionOfInput, IssuePlaintextPasswordStore} {
		if f := p.rows[name]; f != nil {
			out = append(out, f)
		}
	}
	if len(out) > 0 {
		return out, nil
	}
	if len(failures) > 0 {
		return nil, fmt.Errorf("weak crypto: %s", strings.Join(failures, "; "))
	}
	return nil, nil
}

type wcProber struct {
	cc   *CheckContext
	h    *ProbeHarness
	raw  string
	rows map[string]*Finding
}

// wcMarker is n random characters from alphabet, starting with a letter.
func wcMarker(n int, alphabet string) string {
	b := make([]byte, n)
	for i := range b {
		set := alphabet
		if i == 0 {
			set = "abcdefghijklmnopqrstuvwxyz"
		}
		k, err := rand.Int(rand.Reader, big.NewInt(int64(len(set))))
		if err != nil {
			panic(err)
		}
		b[i] = set[k.Int64()]
	}
	return string(b)
}

func (p *wcProber) sendWith(ctx context.Context, c wcCandidate, value string) ([]byte, ProbeResponse, error) {
	req, err := c.pt.Apply([]byte(p.raw), value, false)
	if err != nil {
		return nil, ProbeResponse{}, err
	}
	resp, err := p.h.send(ctx, req)
	return req, resp, err
}

// point probes one parameter and returns a one-line outcome for the trace.
func (p *wcProber) point(ctx context.Context, c wcCandidate) (string, error) {
	const alnum = "abcdefghijklmnopqrstuvwxyz0123456789"
	base := p.h.Baseline()
	baseView := wcView(base)
	reqView := p.raw + "\n" + strings.ReplaceAll(p.raw, `\/`, "/")

	m1 := wcMarker(12, alnum)
	req1, r1, err := p.sendWith(ctx, c, m1)
	if err != nil {
		return "", err
	}
	view1 := wcView(r1)
	var outcomes []string

	// 1. The submitted value's own digest (a replayed request with working credentials).
	if len(c.value) >= weakCryptoMinOrig {
		for _, hit := range wcDigestsIn(baseView, c.value) {
			switch {
			case strings.Contains(view1, hit.digest):
				outcomes = append(outcomes, "original "+hit.scheme.name+": also in the marker answer (static text)")
			case strings.Contains(reqView, hit.digest):
				outcomes = append(outcomes, "original "+hit.scheme.name+": the request carries it")
			default:
				p.reportHash(c, hit, "original", c.value, "", wcHit{}, base, r1)
				outcomes = append(outcomes, "original "+hit.scheme.name+": held")
			}
		}
		if bh, cost, ok := wcBcryptOf(baseView, c.value); ok && c.password {
			if strings.Contains(view1, bh) {
				outcomes = append(outcomes, "original bcrypt: also in the marker answer")
			} else {
				p.reportBcrypt(c, bh, cost, "original", c.value, base)
				outcomes = append(outcomes, fmt.Sprintf("original bcrypt cost %d: held", cost))
			}
		}
		if c.password {
			if key, ok := wcPlaintextMember(base.Body, c.value, c.pt.Name); ok {
				switch {
				case strings.Contains(r1.Body, m1):
					outcomes = append(outcomes, "plaintext: the field is echoed")
				case strings.Contains(r1.Body, c.value):
					outcomes = append(outcomes, "plaintext: the value is in the marker answer too")
				default:
					p.reportPlaintext(c, key, base, r1, m1)
					outcomes = append(outcomes, "plaintext: held")
				}
			}
		}
	}

	// 2. Fresh markers.
	hits := wcDigestsIn(view1, m1)
	var fresh []wcHit
	for _, hit := range hits {
		if strings.Contains(baseView, hit.digest) || bytes.Contains(req1, []byte(hit.digest)) {
			outcomes = append(outcomes, "marker "+hit.scheme.name+": in the baseline or request")
			continue
		}
		if !hit.scheme.weak && !c.password {
			outcomes = append(outcomes, "marker "+hit.scheme.name+": a strong hash of a non-password value")
			continue
		}
		fresh = append(fresh, hit)
	}
	if len(fresh) > 0 {
		m2 := wcMarker(12, alnum)
		_, r2, err := p.sendWith(ctx, c, m2)
		if err != nil {
			return "", err
		}
		view2 := wcView(r2)
		for _, hit := range fresh {
			confirm, ok := wcConfirmed(hit, view2, m2)
			if !ok {
				outcomes = append(outcomes, "marker "+hit.scheme.name+": the second marker did not map the same way")
				continue
			}
			p.reportHash(c, hit, "marker", m1, m2, confirm, r1, r2)
			outcomes = append(outcomes, "marker "+hit.scheme.name+": held")
		}
	}
	if bh, cost, ok := wcBcryptOf(view1, m1); ok && c.password && !strings.Contains(baseView, bh) {
		p.reportBcrypt(c, bh, cost, "marker", m1, r1)
		outcomes = append(outcomes, fmt.Sprintf("marker bcrypt cost %d: held", cost))
	}

	// 3. ECB, only when the marker answer carries a new cipher-sized token that no digest above explains.
	if len(fresh) == 0 && len(wcNewTokens(r1.Body, base.Body)) > 0 {
		o, err := p.ecb(ctx, c, base)
		if err != nil {
			return "", err
		}
		outcomes = append(outcomes, "ecb: "+o)
	}
	if len(outcomes) == 0 {
		return "nothing computed was found", nil
	}
	return strings.Join(outcomes, "; "), nil
}

// ---------------------------------------------------------------------------
// ECB
// ---------------------------------------------------------------------------

var (
	wcB64Token = regexp.MustCompile(`[A-Za-z0-9+/_-]{16,}={0,2}`)
	wcHexToken = regexp.MustCompile(`[0-9A-Fa-f]{24,}`)
)

// wcToken is a decoded candidate ciphertext.
type wcToken struct {
	text string
	data []byte
}

// wcTokens are the base64 and hex runs in body that decode to at least 12 bytes. Only a token whose
// length is a multiple of the block size can show repeated blocks (wcRepeat); any token gates the ECB
// probes, so an encoding of the input is probed too and then refused by the plaintext guard.
func wcTokens(body string) []wcToken {
	body = strings.ReplaceAll(body, `\/`, "/")
	var out []wcToken
	seen := map[string]bool{}
	add := func(t string, d []byte) {
		if len(d) >= 12 && !seen[t] {
			seen[t] = true
			out = append(out, wcToken{text: t, data: d})
		}
	}
	for _, t := range wcHexToken.FindAllString(body, 32) {
		if len(t)%2 == 0 {
			if d, err := hex.DecodeString(t); err == nil {
				add(t, d)
			}
		}
	}
	for _, t := range wcB64Token.FindAllString(body, 32) {
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
			if d, err := enc.DecodeString(t); err == nil {
				add(t, d)
				break
			}
		}
	}
	return out
}

// wcNewTokens are the tokens of body that the baseline body does not carry.
func wcNewTokens(body, baseline string) []wcToken {
	var out []wcToken
	for _, t := range wcTokens(body) {
		if !strings.Contains(baseline, t.text) {
			out = append(out, t)
		}
	}
	return out
}

// wcRepeat returns the first repeated block of data at block size 16, then 8.
func wcRepeat(data []byte) (int, []byte, bool) {
	for _, bs := range []int{16, 8} {
		if len(data)%bs != 0 || len(data)/bs < 2 {
			continue
		}
		seen := map[string]bool{}
		for i := 0; i+bs <= len(data); i += bs {
			b := string(data[i : i+bs])
			if seen[b] {
				return bs, []byte(b), true
			}
			seen[b] = true
		}
	}
	return 0, nil, false
}

// wcRepeating is the first new token of an answer whose blocks repeat and which does not contain the
// plaintext block (an encoding of the input, not a cipher, would).
func wcRepeating(r ProbeResponse, baseline, block string, req []byte) (wcToken, int, []byte, string) {
	reason := "no repeating token"
	for _, t := range wcNewTokens(r.Body, baseline) {
		bs, rep, ok := wcRepeat(t.data)
		if !ok {
			continue
		}
		if bytes.Contains(t.data, []byte(block)) || bytes.Contains(bytes.ToLower(t.data), []byte(block)) {
			reason = "a repeating token contains the plaintext (an encoding, not a cipher)"
			continue
		}
		if bytes.Contains(req, []byte(t.text)) {
			reason = "a repeating token is in the request"
			continue
		}
		return t, bs, rep, ""
	}
	return wcToken{}, 0, nil, reason
}

func (p *wcProber) ecb(ctx context.Context, c wcCandidate, base ProbeResponse) (string, error) {
	const letters = "abcdefghijklmnopqrstuvwxyz"
	b1 := wcMarker(16, letters)
	reqP1, p1, err := p.sendWith(ctx, c, strings.Repeat(b1, 4))
	if err != nil {
		return "", err
	}
	t1, bs1, rep1, why := wcRepeating(p1, base.Body, b1, reqP1)
	if why != "" {
		return why, nil
	}
	ctl := wcMarker(64, letters)
	_, pc, err := p.sendWith(ctx, c, ctl)
	if err != nil {
		return "", err
	}
	ctoks := wcNewTokens(pc.Body, base.Body)
	if len(ctoks) == 0 {
		return "the non-periodic control answered with no token", nil
	}
	for _, t := range ctoks {
		if _, _, ok := wcRepeat(t.data); ok {
			return "the non-periodic control's token repeats too", nil
		}
	}
	b2 := wcMarker(16, letters)
	reqP2, p2, err := p.sendWith(ctx, c, strings.Repeat(b2, 4))
	if err != nil {
		return "", err
	}
	t2, bs2, rep2, why := wcRepeating(p2, base.Body, b2, reqP2)
	if why != "" {
		return "second periodic probe: " + why, nil
	}
	if bytes.Equal(rep1, rep2) {
		return "both periodic probes repeat the same block (not a function of the input)", nil
	}
	p.reportECB(c, b1, t1, bs1, rep1, ctl, ctoks[0], b2, t2, bs2, rep2, p1)
	return "held", nil
}

// ---------------------------------------------------------------------------
// plaintext
// ---------------------------------------------------------------------------

// wcPlaintextMember returns the key of a JSON member (at any depth) other than param whose string
// value is exactly value.
func wcPlaintextMember(body, value, param string) (string, bool) {
	var doc any
	if json.Unmarshal([]byte(strings.TrimSpace(body)), &doc) != nil {
		return "", false
	}
	pname := strings.ToLower(param)
	if i := strings.LastIndexAny(pname, ".[]"); i >= 0 {
		pname = strings.Trim(pname[i:], ".[]")
	}
	var walk func(v any) (string, bool)
	walk = func(v any) (string, bool) {
		switch x := v.(type) {
		case map[string]any:
			keys := make([]string, 0, len(x))
			for k := range x {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				if s, ok := x[k].(string); ok && s == value && strings.ToLower(k) != pname {
					return k, true
				}
				if k2, ok := walk(x[k]); ok {
					return k2, true
				}
			}
		case []any:
			for _, e := range x {
				if k, ok := walk(e); ok {
					return k, true
				}
			}
		}
		return "", false
	}
	return walk(doc)
}

// ---------------------------------------------------------------------------
// findings
// ---------------------------------------------------------------------------

func (p *wcProber) add(name, severity string, c wcCandidate, evidence, detail string) {
	if p.rows[name] != nil {
		p.rows[name].Evidence += "\n" + evidence
		return
	}
	f := buildHeaderFinding(p.cc, name, severity, "firm", evidence, detail)
	f.Param = c.pt.Name
	p.rows[name] = f
}

func wcExcerpt(body, needle string) string {
	i := strings.Index(body, needle)
	if i < 0 {
		return needle
	}
	return excerpt(body, i, len(needle))
}

func (p *wcProber) reportHash(c wcCandidate, hit wcHit, mode, v1, v2 string, hit2 wcHit, r1, r2 ProbeResponse) {
	var ev string
	if mode == "marker" {
		ev = fmt.Sprintf("%s %q set to the random marker %q: the answer (HTTP %d) carries its unsalted %s digest "+
			"in %s, %s (%q). A second marker %q answered (HTTP %d) with its own %s digest %s. Neither digest is in "+
			"the baseline answer or the request.",
			c.pt.Kind, c.pt.Name, v1, r1.Status, hit.scheme.name, hit.spelling, hit.digest,
			wcExcerpt(string(r1.Raw), hit.digest), v2, r2.Status, hit2.scheme.name, hit2.digest)
	} else {
		ev = fmt.Sprintf("%s %q carried its original value (%d characters): the answer to the unchanged request "+
			"(HTTP %d) carries that value's unsalted %s digest in %s, %s (%q); the answer to the random marker "+
			"(HTTP %d) does not, and the request does not carry it.",
			c.pt.Kind, c.pt.Name, len(v1), r1.Status, hit.scheme.name, hit.spelling, hit.digest,
			wcExcerpt(string(r1.Raw), hit.digest), r2.Status)
	}
	if hit.scheme.weak {
		detail := fmt.Sprintf("The server hashes the value of %s %q with %s, without a salt or key, and returns "+
			"the digest: the scanner computed %s of the value it sent and found exactly that in the answer. %s is "+
			"a broken hash algorithm: it is fast to compute and to look up in precomputed tables, and an unsalted "+
			"digest of a guessable value is reversed by a lookup.", c.pt.Kind, c.pt.Name, hit.scheme.name,
			hit.scheme.name, hit.scheme.name)
		p.add(IssueWeakHashOfInput, "medium", c, ev, detail)
	}
	if c.password {
		detail := fmt.Sprintf("The password parameter %s %q is hashed with %s, a fast general-purpose hash, "+
			"without a salt or work factor: the scanner computed %s of the password it sent and found exactly that "+
			"in the answer. A stolen digest of this kind is cracked at billions of guesses per second, and "+
			"identical passwords share a digest.", c.pt.Kind, c.pt.Name, hit.scheme.name, hit.scheme.name)
		p.add(IssueWeakPasswordHash, "medium", c, ev, detail)
	}
}

func (p *wcProber) reportBcrypt(c wcCandidate, hash string, cost int, mode, value string, r ProbeResponse) {
	what := "its original value"
	if mode == "marker" {
		what = fmt.Sprintf("the random marker %q", value)
	}
	ev := fmt.Sprintf("%s %q carried %s: the answer (HTTP %d) carries the bcrypt hash %s, which bcrypt verifies "+
		"against that value, with cost factor %d (2^%d rounds); at least %d is recommended.",
		c.pt.Kind, c.pt.Name, what, r.Status, hash, cost, cost, weakCryptoBcryptCost)
	detail := fmt.Sprintf("The password parameter %s %q is hashed with bcrypt at cost %d, below the recommended "+
		"minimum of %d: each guess against a stolen hash costs %d times less work than at cost %d.",
		c.pt.Kind, c.pt.Name, cost, weakCryptoBcryptCost, 1<<(weakCryptoBcryptCost-cost), weakCryptoBcryptCost)
	p.add(IssueWeakPasswordHash, "medium", c, ev, detail)
}

func (p *wcProber) reportPlaintext(c wcCandidate, key string, base, r1 ProbeResponse, m1 string) {
	ev := fmt.Sprintf("%s %q carried its original value (%d characters): the answer to the unchanged request "+
		"(HTTP %d) returns it verbatim as the JSON member %q, not the parameter's own name. With the random "+
		"marker %q in its place the answer (HTTP %d) carries neither the marker nor the original value, so the "+
		"field is not echoed: the value came from the server's record.",
		c.pt.Kind, c.pt.Name, len(c.value), base.Status, key, m1, r1.Status)
	detail := fmt.Sprintf("The server keeps the password submitted in %s %q in a recoverable form and returns it "+
		"in its own record (member %q) when the right password is sent. A password must be stored only as a "+
		"salted, deliberately slow hash.", c.pt.Kind, c.pt.Name, key)
	p.add(IssuePlaintextPasswordStore, "high", c, ev, detail)
}

func (p *wcProber) reportECB(c wcCandidate, b1 string, t1 wcToken, bs1 int, rep1 []byte, ctl string, ct wcToken,
	b2 string, t2 wcToken, bs2 int, rep2 []byte, r1 ProbeResponse) {
	ev := fmt.Sprintf("%s %q set to four copies of the random block %q: the answer (HTTP %d) carries the new "+
		"token %q, whose %d-byte block %s repeats. The non-periodic control %q answered with the token %q, "+
		"which has no repeated block. Four copies of a second block %q answered with %q, repeating the "+
		"%d-byte block %s. No token contains the plaintext.",
		c.pt.Kind, c.pt.Name, b1, r1.Status, t1.text, bs1, hex.EncodeToString(rep1), ctl, ct.text, b2, t2.text,
		bs2, hex.EncodeToString(rep2))
	detail := fmt.Sprintf("The server encrypts the value of %s %q with a block cipher in ECB mode (or another "+
		"deterministic, IV-less mode): identical plaintext blocks become identical ciphertext blocks, so the "+
		"ciphertext shows the structure of the plaintext, equal values encrypt equally, and blocks can be cut "+
		"and pasted between ciphertexts.", c.pt.Kind, c.pt.Name)
	p.add(IssueECBEncryptionOfInput, "medium", c, ev, detail)
}
