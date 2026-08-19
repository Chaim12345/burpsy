package scanner

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"testing"
)

// Two tokens carrying identical claims and signed with different keys are two different tokens, and
// the weak one must be cracked whichever is scanned first.
//
// Deduping on the signing input alone made that impossible: the strong token claimed the pair and
// the weak one was accounted "already covered" without ever being attacked, so a weak key sitting
// behind an identical payload was unreachable. internal/vulnapp reproduces the shape exactly -
// /nt/session and /nt/safe/session issue the same claims under a wordlist secret and a random one -
// and the runtime coverage harness passed or failed that row according to which endpoint it happened
// to audit first, which is how the defect surfaced.
func TestAWeakKeyIsFoundEvenBehindAnIdenticalPayloadSignedStrongly(t *testing.T) {
	const signingInput = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"
	sign := func(secret string) string {
		m := hmac.New(sha256.New, []byte(secret))
		m.Write([]byte(signingInput))
		return signingInput + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil))
	}
	weak := sign("secret")
	strong := sign("P4yyvPlLU1Qn2b800elAv5e7kQ-maqNcKKP0IvTkzg=")
	if weak == strong {
		t.Fatal("fixture is wrong: the two tokens must differ")
	}

	body := func(tok string) string { return fmt.Sprintf(`{"token":%q}`, tok) }

	// Strong first, so it is the one that would have claimed the shared signing input.
	c := BundledJwtWeakSecretCheck()
	if got := c.Scan(storedResponse(t, body(strong)), nil); len(got) != 0 {
		t.Fatalf("the strongly signed token was reported as weak: %s", got[0].Evidence)
	}
	if got := c.Scan(storedResponse(t, body(weak)), nil); len(got) == 0 {
		t.Fatal("the weak key was not found: scanning a strongly signed token carrying the SAME " +
			"claims first consumed the dedup entry, so the weak token was never attacked. The key " +
			"has to include the signature, which is the thing being attacked.")
	}

	// The optimisation the table exists for still holds: the same token again is not re-cracked.
	before := c.Coverage().TokensAlreadyCovered
	if again := c.Scan(storedResponse(t, body(weak)), nil); len(again) != 0 {
		t.Errorf("the same token was reported twice; dedup stopped working: %s", again[0].Evidence)
	}
	if c.Coverage().TokensAlreadyCovered <= before {
		t.Error("a repeat of an already-resolved token was not accounted as already covered")
	}
}
