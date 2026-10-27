package scanner

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// A server that runs the kid through a shell and keys HMAC with its stdout accepts one of the
// forgeries; a server that uses the kid literally as the key accepts none.
func TestKidCommandForgeriesVerifyOnlyWhereTheKidIsExecuted(t *testing.T) {
	tok := ParseJWT("eyJhbGciOiJIUzI1NiIsImtpZCI6ImsxIn0.eyJzdWIiOiJ1In0.c2ln")
	arith := regexp.MustCompile(`\$\(\((\d+)\*(\d+)\)\)`)
	verify := func(f jwtForgery, key func(kid string) string) bool {
		parts := strings.Split(f.tok, ".")
		raw, _ := base64.RawURLEncoding.DecodeString(parts[0])
		var h map[string]any
		_ = json.Unmarshal(raw, &h)
		m := hmac.New(sha256.New, []byte(key(h["kid"].(string))))
		m.Write([]byte(parts[0] + "." + parts[1]))
		return base64.RawURLEncoding.EncodeToString(m.Sum(nil)) == parts[2]
	}
	shell := func(kid string) string {
		g := arith.FindStringSubmatch(kid)
		a, _ := strconv.Atoi(g[1])
		b, _ := strconv.Atoi(g[2])
		return strconv.Itoa(a * b)
	}
	var executed, literal int
	for _, f := range jwtKidCommandForgeries(tok) {
		if verify(f, shell) {
			executed++
		}
		if verify(f, func(kid string) string { return kid }) {
			literal++
		}
	}
	if executed == 0 || literal != 0 {
		t.Fatalf("forgeries accepted by an executing server: %d (want >0); by a literal-kid server: %d (want 0)", executed, literal)
	}
}
