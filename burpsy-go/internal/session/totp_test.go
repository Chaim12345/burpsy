package session

import (
	"encoding/base32"
	"strings"
	"testing"
	"time"
)

// RFC 6238 Appendix B. Each algorithm has its OWN seed length — 20, 32 and 64 bytes — and reusing the
// SHA1 seed for the other two is the classic way a TOTP test passes against a broken HMAC key.
func TestTOTPMatchesTheRFC6238Vectors(t *testing.T) {
	seeds := map[TOTPAlgorithm]string{
		TOTPSHA1:   "12345678901234567890",
		TOTPSHA256: "12345678901234567890123456789012",
		TOTPSHA512: "1234567890123456789012345678901234567890123456789012345678901234",
	}
	vectors := []struct {
		unix int64
		want map[TOTPAlgorithm]string
	}{
		{59, map[TOTPAlgorithm]string{TOTPSHA1: "94287082", TOTPSHA256: "46119246", TOTPSHA512: "90693936"}},
		{1111111109, map[TOTPAlgorithm]string{TOTPSHA1: "07081804", TOTPSHA256: "68084774", TOTPSHA512: "25091201"}},
		{1111111111, map[TOTPAlgorithm]string{TOTPSHA1: "14050471", TOTPSHA256: "67062674", TOTPSHA512: "99943326"}},
		{1234567890, map[TOTPAlgorithm]string{TOTPSHA1: "89005924", TOTPSHA256: "91819424", TOTPSHA512: "93441116"}},
		{2000000000, map[TOTPAlgorithm]string{TOTPSHA1: "69279037", TOTPSHA256: "90698825", TOTPSHA512: "38618901"}},
		{20000000000, map[TOTPAlgorithm]string{TOTPSHA1: "65353130", TOTPSHA256: "77737706", TOTPSHA512: "47863826"}},
	}
	for alg, seed := range seeds {
		cfg := TOTPConfig{
			Secret:    base32.StdEncoding.EncodeToString([]byte(seed)),
			Algorithm: alg, Period: 30, Digits: 8,
		}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("%s: valid config refused: %v", alg, err)
		}
		for _, v := range vectors {
			got, err := cfg.CodeAt(time.Unix(v.unix, 0))
			if err != nil {
				t.Fatalf("%s at %d: %v", alg, v.unix, err)
			}
			if got != v.want[alg] {
				t.Errorf("%s at %d: got %s, want %s", alg, v.unix, got, v.want[alg])
			}
		}
	}
}

// Six digits is the default, and the code is the low six digits of the same truncated value — so
// the RFC's 8-digit vector truncates to its own last six.
func TestTOTPDefaultsToSixDigitsAndAcceptsAuthenticatorSpelling(t *testing.T) {
	secret := base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))
	// Lower case, spaced in fours, padding kept: how an enrolment page prints it. Burp's pattern
	// (^[A-Za-z2-7]+=*$) accepts case and padding; the spaces are stripped first.
	var spaced strings.Builder
	for i, r := range strings.ToLower(secret) {
		if i > 0 && i%4 == 0 {
			spaced.WriteByte(' ')
		}
		spaced.WriteRune(r)
	}
	cfg := TOTPConfig{Secret: spaced.String(), Period: 30}
	got, err := cfg.CodeAt(time.Unix(59, 0))
	if err != nil {
		t.Fatal(err)
	}
	if got != "287082" {
		t.Fatalf("got %s, want 287082", got)
	}
}

func TestTOTPValidationUsesBurpsMessages(t *testing.T) {
	for _, c := range []struct {
		cfg  TOTPConfig
		want string
	}{
		{TOTPConfig{Secret: "", Period: 30, Digits: 6}, "TOTP secret cannot be empty"},
		{TOTPConfig{Secret: "NOT-BASE32!", Period: 30, Digits: 6}, "TOTP secret must be valid Base32 (A-Z, a-z, 2-7)"},
		{TOTPConfig{Secret: "JBSWY3DPEHPK3PXP", Period: 0, Digits: 6}, "TOTP period must be greater than 0"},
		{TOTPConfig{Secret: "JBSWY3DPEHPK3PXP", Period: 30, Digits: 0}, "TOTP digits must be greater than 0"},
		{TOTPConfig{Secret: "JBSWY3DPEHPK3PXP", Period: 30, Digits: 6, Algorithm: "MD5"}, `TOTP algorithm "MD5" is not one of SHA1, SHA256, SHA512`},
	} {
		err := c.cfg.Validate()
		if err == nil || err.Error() != c.want {
			t.Errorf("%+v: got %v, want %q", c.cfg, err, c.want)
		}
	}
}

func TestTOTPUntilNextPeriod(t *testing.T) {
	cfg := TOTPConfig{Period: 30}
	if got := cfg.UntilNextPeriod(time.Unix(59, 0)); got != time.Second {
		t.Fatalf("at 59s the 30s code rotates in 1s, got %s", got)
	}
	if got := cfg.UntilNextPeriod(time.Unix(60, 0)); got != 30*time.Second {
		t.Fatalf("at a boundary the next rotation is a full period away, got %s", got)
	}
}
