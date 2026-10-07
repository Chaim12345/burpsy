package tools

import (
	"encoding/hex"
	"strings"
	"testing"
)

// Known-answer vectors. The bare digests of "abc" and the HMAC vectors (RFC 4231 test case 1:
// key = 20 × 0x0b, data = "Hi There") were computed with Python's hashlib/hmac — an
// implementation independent of the Go packages under test — and the SHA-256 HMAC equals RFC
// 4231's published value. keccak-256 of the empty string is the well-known Ethereum value.
var digestKAT = map[string]string{
	"md4":         "a448017aaf21d8525fc10ae87aa6729d",
	"md5":         "900150983cd24fb0d6963f7d28e17f72",
	"sha1":        "a9993e364706816aba3e25717850c26c9cd0d89d",
	"ripemd160":   "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc",
	"sha224":      "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7",
	"sha256":      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
	"sha384":      "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
	"sha512":      "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
	"sha512-224":  "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa",
	"sha512-256":  "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23",
	"sha3-224":    "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf",
	"sha3-256":    "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
	"sha3-384":    "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25",
	"sha3-512":    "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0",
	"blake2b-256": "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319",
	"blake2b-384": "6f56a82c8e7ef526dfe182eb5212f7db9df1317e57815dbda46083fc30f54ee6c66ba83be64b302d7cba6ce15bb556f4",
	"blake2b-512": "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923",
	"blake2s-256": "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982",
}

var hmacKAT = map[string]string{
	"hmac-md5":    "5ccec34ea9656392457fa1ac27f08fbc",
	"hmac-sha1":   "b617318655057264e28bc0b6fb378c8ef146be00",
	"hmac-sha224": "896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22",
	"hmac-sha256": "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
	"hmac-sha384": "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6",
	"hmac-sha512": "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
}

func TestEveryBareDigestMatchesItsKnownAnswer(t *testing.T) {
	for name, want := range digestKAT {
		alg, ok := LookupDigest(name)
		if !ok {
			t.Fatalf("%s is not in the table", name)
		}
		sum, err := ComputeDigest(alg, []byte("abc"), nil)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := hex.EncodeToString(sum); got != want {
			t.Errorf("%s(abc) = %s, want %s", name, got, want)
		}
	}
	keccak, _ := LookupDigest("keccak-256")
	sum, _ := ComputeDigest(keccak, nil, nil)
	if got := hex.EncodeToString(sum); got != "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470" {
		t.Errorf("keccak-256('') = %s, want the Ethereum empty hash — legacy Keccak, not SHA3-256", got)
	}
	keccak512, _ := LookupDigest("keccak-512")
	sha3512, _ := LookupDigest("sha3-512")
	a, _ := ComputeDigest(keccak512, []byte("abc"), nil)
	b, _ := ComputeDigest(sha3512, []byte("abc"), nil)
	if len(a) != 64 || hex.EncodeToString(a) == hex.EncodeToString(b) {
		t.Errorf("keccak-512 must be 64 bytes and differ from sha3-512 (different padding), got %x", a)
	}
}

func TestEveryHMACMatchesRFC4231TestCase1(t *testing.T) {
	key := []byte(strings.Repeat("\x0b", 20))
	for name, want := range hmacKAT {
		alg, ok := LookupDigest(name)
		if !ok || !alg.Keyed {
			t.Fatalf("%s missing or not keyed", name)
		}
		sum, err := ComputeDigest(alg, []byte("Hi There"), key)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := hex.EncodeToString(sum); got != want {
			t.Errorf("%s = %s, want %s", name, got, want)
		}
	}
}

// RFC 7515 Appendix A.1: the JWS HS256 example. The key is the JWK "k" value (unpadded base64url),
// the input is the JWS signing input, and the expected signature is the RFC's own.
func TestTheRFC7515HS256ExampleSignatureIsReproduced(t *testing.T) {
	key, err := DecodeDigestInput("AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow", "base64")
	if err != nil {
		t.Fatal(err)
	}
	alg, _ := LookupDigest("HMAC-SHA256")
	sum, err := ComputeDigest(alg, []byte("eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"), key)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := EncodeDigest(sum, "base64url")
	if got != "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" {
		t.Errorf("signature = %s, want RFC 7515 A.1's dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", got)
	}
}

func TestKeysAreRequiredExactlyWhereTheyMeanSomething(t *testing.T) {
	hm, _ := LookupDigest("hmac-sha256")
	if _, err := ComputeDigest(hm, []byte("x"), nil); err == nil {
		t.Error("an HMAC with no key must be refused, not computed with an empty key")
	}
	sha, _ := LookupDigest("sha256")
	if _, err := ComputeDigest(sha, []byte("x"), []byte("k")); err == nil {
		t.Error("a key sent to an unkeyed digest must be refused, not silently ignored")
	}
}

func TestUnknownNamesAndEncodingsAreRefusedByName(t *testing.T) {
	for _, n := range []string{"blake3", "whirlpool", "sm3", "sha265"} {
		if _, ok := LookupDigest(n); ok {
			t.Errorf("%q should not resolve", n)
		}
	}
	if a, ok := LookupDigest(""); !ok || a.Name != "sha256" {
		t.Errorf("empty name must default to sha256, got %+v %v", a, ok)
	}
	if _, err := DecodeDigestInput("zz", "hex"); err == nil {
		t.Error("bad hex must be refused")
	}
	if _, err := DecodeDigestInput("x", "rot13"); err == nil {
		t.Error("unknown input encoding must be refused")
	}
	if _, err := EncodeDigest([]byte{1}, "base32"); err == nil {
		t.Error("unknown output must be refused")
	}
}
