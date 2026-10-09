package session

// TOTP for recorded login sequences (burpsy-react-ui-xhtk).
//
// Burp's recorded-login editor has a TOTP step kind beside click, type, key press, go-to and wait
// (Zf50 in the 2026.7.1 teardown). The step carries a Base32 secret, an HMAC algorithm, a period and
// a digit count (Zrsy's "TOTP Secret", "Period (seconds)", "Digits", "HMAC algorithm for TOTP code
// generation"), validated by Zhfe against ^[A-Za-z2-7]+=*$, period > 0 and digits > 0, and the code
// is RFC 6238 computed by Zxf1.ZI: the 8-byte big-endian time-step counter, HMAC under the decoded
// secret, dynamic truncation, modulo 10^digits, zero-padded. Zxf1 treats digits <= 0 as 6; this does
// the same rather than refusing at generation time, because validation already refused it at save.

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"regexp"
	"strings"
	"time"
)

// TOTPAlgorithm is the HMAC hash a TOTP code is computed with. The three RFC 6238 names, under the
// spelling Burp's selector offers.
type TOTPAlgorithm string

const (
	TOTPSHA1   TOTPAlgorithm = "SHA1"
	TOTPSHA256 TOTPAlgorithm = "SHA256"
	TOTPSHA512 TOTPAlgorithm = "SHA512"
)

// TOTPConfig is one TOTP step's generator settings.
type TOTPConfig struct {
	// Secret is the Base32 shared secret. Never marshalled from a view; see RecordedLoginView.
	Secret    string        `json:"secret,omitempty"`
	Algorithm TOTPAlgorithm `json:"algorithm"`
	// Period is the code's lifetime in seconds. 30 is RFC 6238's default and every authenticator's.
	Period int `json:"period"`
	// Digits is the code length. 6 is the default.
	Digits int `json:"digits"`
}

// base32Secret is Burp's own acceptance pattern (Zhfe): letters of either case, 2-7, then padding.
var base32Secret = regexp.MustCompile(`^[A-Za-z2-7]+=*$`)

// normaliseSecret strips the spaces authenticator apps print secrets with and upper-cases it, so a
// secret copied from a QR enrolment page as "jbsw y3dp ehpk 3pxp" is accepted.
func normaliseSecret(s string) string {
	return strings.ToUpper(strings.Join(strings.Fields(s), ""))
}

// Validate refuses a configuration that could never produce a code, with Burp's own messages.
func (c TOTPConfig) Validate() error {
	secret := normaliseSecret(c.Secret)
	switch {
	case secret == "":
		return errors.New("TOTP secret cannot be empty")
	case !base32Secret.MatchString(secret):
		return errors.New("TOTP secret must be valid Base32 (A-Z, a-z, 2-7)")
	case c.Period <= 0:
		return errors.New("TOTP period must be greater than 0")
	case c.Digits <= 0:
		return errors.New("TOTP digits must be greater than 0")
	case c.Digits > 10:
		// Not a Burp message: 31 bits of truncated HMAC cannot fill more than 10 decimal digits, so
		// a longer code would be zero-padded noise no server issues.
		return errors.New("TOTP digits must be 10 or fewer")
	}
	if _, err := c.hash(); err != nil {
		return err
	}
	return nil
}

func (c TOTPConfig) hash() (func() hash.Hash, error) {
	switch strings.ToUpper(strings.ReplaceAll(string(c.Algorithm), "-", "")) {
	case "", "SHA1":
		return sha1.New, nil
	case "SHA256":
		return sha256.New, nil
	case "SHA512":
		return sha512.New, nil
	}
	return nil, fmt.Errorf("TOTP algorithm %q is not one of SHA1, SHA256, SHA512", c.Algorithm)
}

// Counter is the RFC 6238 time step at t.
func (c TOTPConfig) Counter(t time.Time) uint64 {
	period := c.Period
	if period <= 0 {
		period = 30
	}
	return uint64(t.Unix()) / uint64(period)
}

// CodeAt computes the code for time t.
func (c TOTPConfig) CodeAt(t time.Time) (string, error) {
	return c.CodeForCounter(c.Counter(t))
}

// CodeForCounter computes the code for an explicit time step — the RFC 4226 HOTP core.
func (c TOTPConfig) CodeForCounter(counter uint64) (string, error) {
	newHash, err := c.hash()
	if err != nil {
		return "", err
	}
	secret := strings.TrimRight(normaliseSecret(c.Secret), "=")
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil || len(key) == 0 {
		return "", errors.New("the TOTP secret is not valid Base32-encoded data")
	}
	digits := c.Digits
	if digits <= 0 {
		digits = 6
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	mac := hmac.New(newHash, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	bin := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	mod := uint64(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, uint64(bin)%mod), nil
}

// UntilNextPeriod is how long until the code at t rotates — Zxf1.ZM. A replay that has just used the
// code for this time step waits this long before typing another, because most servers refuse a code
// that has already been accepted once (RFC 6238 section 5.2).
func (c TOTPConfig) UntilNextPeriod(t time.Time) time.Duration {
	period := c.Period
	if period <= 0 {
		period = 30
	}
	p := time.Duration(period) * time.Second
	return p - time.Duration(t.UnixNano()%int64(p))
}
