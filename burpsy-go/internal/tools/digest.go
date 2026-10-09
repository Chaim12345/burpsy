package tools

// The Decoder's hash step (burpsy-react-ui-wi55, burpsy-react-ui-7tgt).
//
// Burp's CryptoUtils.generateDigest names 60 DigestAlgorithm values and its Decoder offers a
// keyed HMAC; burpsy offered four bare digests with hex output, so a JWT HS256 signature, an
// NTLM (MD4) hash or a SHA3/BLAKE2-signed token could not be recomputed from the console.
//
// One table is the whole vocabulary. Every entry is computable with the standard library or
// golang.org/x/crypto, which the module already carries; algorithms that would need a new
// third-party dependency (BLAKE3, Whirlpool, SM3, GOST, MD2, Tiger, …) are not in the table, so
// the handler refuses them by name instead of guessing — gaps.md records which and why.

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"hash"
	"strings"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/md4"       //nolint:staticcheck // NTLM hashes are MD4; recomputing them is the point
	"golang.org/x/crypto/ripemd160" //nolint:staticcheck // offered for parity with Burp's digest list
	"golang.org/x/crypto/sha3"
)

// DigestAlgorithm is one hash the console can compute. Keyed is true for the HMAC family: those
// take a key and refuse to run without one, and the bare digests refuse a key, because a key the
// caller supplied and the server silently ignored would produce a digest the caller misreads.
type DigestAlgorithm struct {
	Name  string
	Keyed bool
	New   func() hash.Hash
	// Sum is set instead of New for an extendable-output function (SHAKE), which has no fixed-size
	// hash.Hash; the name fixes the output length, as Burp's SHAKE_128_256 / SHAKE_256_512 do.
	Sum func(data []byte) []byte
}

func mustBlake2b(size int) func() hash.Hash {
	return func() hash.Hash {
		h, err := blake2b.New(size, nil)
		if err != nil {
			panic(err) // sizes are constants below; an error is a programming mistake
		}
		return h
	}
}

func mustBlake2s256() hash.Hash {
	h, err := blake2s.New256(nil)
	if err != nil {
		panic(err)
	}
	return h
}

func shake(size int, sum func(out, data []byte)) func([]byte) []byte {
	return func(data []byte) []byte {
		out := make([]byte, size)
		sum(out, data)
		return out
	}
}

// digestAlgorithms is ordered weakest-first within each family, the order the UI lists them in.
var digestAlgorithms = []DigestAlgorithm{
	{Name: "md4", New: md4.New},
	{Name: "md5", New: md5.New},
	{Name: "sha1", New: sha1.New},
	{Name: "ripemd160", New: ripemd160.New},
	{Name: "sha224", New: sha256.New224},
	{Name: "sha256", New: sha256.New},
	{Name: "sha384", New: sha512.New384},
	{Name: "sha512", New: sha512.New},
	{Name: "sha512-224", New: sha512.New512_224},
	{Name: "sha512-256", New: sha512.New512_256},
	{Name: "sha3-224", New: sha3.New224},
	{Name: "sha3-256", New: sha3.New256},
	{Name: "sha3-384", New: sha3.New384},
	{Name: "sha3-512", New: sha3.New512},
	{Name: "keccak-256", New: sha3.NewLegacyKeccak256},
	{Name: "keccak-512", New: sha3.NewLegacyKeccak512},
	{Name: "shake128-256", Sum: shake(32, sha3.ShakeSum128)},
	{Name: "shake256-512", Sum: shake(64, sha3.ShakeSum256)},
	{Name: "blake2b-160", New: mustBlake2b(20)},
	{Name: "blake2b-256", New: mustBlake2b(32)},
	{Name: "blake2b-384", New: mustBlake2b(48)},
	{Name: "blake2b-512", New: mustBlake2b(64)},
	{Name: "blake2s-256", New: mustBlake2s256},
	{Name: "hmac-md5", Keyed: true, New: md5.New},
	{Name: "hmac-sha1", Keyed: true, New: sha1.New},
	{Name: "hmac-sha224", Keyed: true, New: sha256.New224},
	{Name: "hmac-sha256", Keyed: true, New: sha256.New},
	{Name: "hmac-sha384", Keyed: true, New: sha512.New384},
	{Name: "hmac-sha512", Keyed: true, New: sha512.New},
	{Name: "hmac-sha3-256", Keyed: true, New: sha3.New256},
	{Name: "hmac-sha3-512", Keyed: true, New: sha3.New512},
}

// DigestAlgorithmNames lists every accepted algorithm name in table order. The UI's
// HASH_ALGORITHMS constant must equal it; a web test reads both and fails if they drift.
func DigestAlgorithmNames() []string {
	out := make([]string, 0, len(digestAlgorithms))
	for _, a := range digestAlgorithms {
		out = append(out, a.Name)
	}
	return out
}

// LookupDigest resolves a name case-insensitively. "" is the documented default, SHA-256, kept
// because every caller that predates this table omits the field.
func LookupDigest(name string) (DigestAlgorithm, bool) {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" {
		n = "sha256"
	}
	for _, a := range digestAlgorithms {
		if a.Name == n {
			return a, true
		}
	}
	return DigestAlgorithm{}, false
}

// ComputeDigest hashes data with alg. A keyed algorithm needs a non-empty key; an unkeyed one
// refuses a key.
func ComputeDigest(alg DigestAlgorithm, data, key []byte) ([]byte, error) {
	if alg.Keyed {
		if len(key) == 0 {
			return nil, fmt.Errorf("%s needs a key", alg.Name)
		}
		m := hmac.New(alg.New, key)
		m.Write(data)
		return m.Sum(nil), nil
	}
	if len(key) > 0 {
		return nil, fmt.Errorf("%s is not keyed; send no key, or choose an hmac-* algorithm", alg.Name)
	}
	if alg.Sum != nil {
		return alg.Sum(data), nil
	}
	h := alg.New()
	h.Write(data)
	return h.Sum(nil), nil
}

// DecodeDigestInput reads an input or a key in the stated encoding: utf8 (the default), hex, or
// base64. base64 accepts the standard and URL-safe alphabets, padded or not, because the keys an
// operator pastes come from JWKs (unpadded base64url) as often as from config files.
func DecodeDigestInput(s, encoding string) ([]byte, error) {
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "", "utf8", "utf-8", "text":
		return []byte(s), nil
	case "hex":
		b, err := hex.DecodeString(strings.Join(strings.Fields(s), ""))
		if err != nil {
			return nil, fmt.Errorf("not hex: %w", err)
		}
		return b, nil
	case "base64":
		t := strings.Join(strings.Fields(s), "")
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
			if b, err := enc.DecodeString(t); err == nil {
				return b, nil
			}
		}
		return nil, fmt.Errorf("not base64 in the standard or URL-safe alphabet")
	default:
		return nil, fmt.Errorf("unknown encoding %q: expected utf8, hex or base64", encoding)
	}
}

// EncodeDigest renders a digest as hex (the default), base64, or base64url — unpadded, which is
// how a JWS signature is written (RFC 7515 §2).
func EncodeDigest(sum []byte, format string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", "hex":
		return hex.EncodeToString(sum), nil
	case "base64":
		return base64.StdEncoding.EncodeToString(sum), nil
	case "base64url":
		return base64.RawURLEncoding.EncodeToString(sum), nil
	default:
		return "", fmt.Errorf("unknown output %q: expected hex, base64 or base64url", format)
	}
}
