package vulnapp

// The weak-cryptography family (burpsy-react-ui-0vzb.28): a hash or cipher applied to user input and
// shown in the answer, and passwords stored in recoverable or cheaply-hashed form.
//
// Vulnerable:
//
//   - GET /crypto/digest?token=... answers the unsalted MD5 of token (a non-password value): weak hash;
//   - GET /crypto/fingerprint?code=... answers the NTLM hash (MD4 of UTF-16LE) of code in upper-case hex;
//   - GET /crypto/check?password=... answers the unsalted SHA-256 of the password: a fast password hash;
//   - POST /crypto/account/login with alice's working password answers her profile with its stored
//     unsalted SHA-1 password hash; a wrong password answers "Invalid credentials";
//   - POST /crypto/account/login-legacy does the same with a bcrypt hash of cost 4;
//   - POST /crypto/account/login-plain answers bob's profile with his stored plaintext password;
//   - GET /crypto/seal?data=... encrypts data with AES-128 in ECB mode under a fixed key (base64).
//
// Safe twins and negative controls:
//
//   - /crypto/safe/digest answers HMAC-SHA-256 of token under a server secret: keyed, not computable;
//   - /crypto/safe/strong answers the unsalted SHA-256 of a non-password value: a strong hash, not a
//     password, so no row applies;
//   - /crypto/safe/static answers a fixed page with a 32-hex-digit request id and the MD5 of a constant
//     that happens to be the captured token value: the digest of the ORIGINAL value is in every answer,
//     so it is page text, not a hash of what was sent;
//   - /crypto/safe/check answers a salted SHA-256 (fresh random salt per request) of the password;
//   - POST /crypto/safe/account/login answers a profile with a bcrypt hash of cost 12;
//   - POST /crypto/safe/account/login-echo answers {"youTyped": password} for every input: an echo;
//   - /crypto/safe/seal encrypts with AES-128-GCM under a fresh random nonce;
//   - /crypto/safe/encode answers base64 of data: periodic, but an encoding of the plaintext;
//   - /crypto/safe/receipt answers a token holding a fresh random 16-byte id three times, whatever it
//     is sent: its blocks repeat, but for the non-periodic control too.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"unicode/utf16"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/md4"
)

const (
	rowWeakHash       = "Weak hash algorithm applied to input"
	rowWeakPwHash     = "Password hash with insufficient computational effort"
	rowECB            = "Block cipher in ECB mode applied to input"
	rowPlaintextPwd   = "Password stored in plaintext"
	wcAlicePassword   = "Correct-Horse-9"
	wcBobPassword     = "Tr0ub4dor&3x"
	wcLoginContent    = "application/x-www-form-urlencoded"
	wcAliceLoginBody  = "username=alice&password=Correct-Horse-9"
	wcBobLoginBody    = "username=bob&password=Tr0ub4dor%263x"
	wcSecretHMACKey   = "vulnapp-weakcrypto-hmac-key"
	wcFixedAESKeyText = "0123456789abcdef"
)

func weakCryptoEndpoints() []Endpoint {
	form := func(path, row, body, note string, safe bool) Endpoint {
		return Endpoint{Path: path, Method: http.MethodPost, Row: row, Body: body, ContentType: wcLoginContent,
			Safe: safe, Note: note}
	}
	return []Endpoint{
		{Path: "/crypto/digest?token=report-2024", Row: rowWeakHash,
			Note: "answers the unsalted MD5 of token"},
		{Path: "/crypto/fingerprint?code=device-7", Row: rowWeakHash,
			Note: "answers the NTLM hash (MD4 of UTF-16LE) of code, in upper-case hex"},
		{Path: "/crypto/check?password=letmein", Row: rowWeakPwHash,
			Note: "answers the unsalted SHA-256 of the password"},
		form("/crypto/account/login", rowWeakPwHash, wcAliceLoginBody,
			"a working login answers the profile with its stored unsalted SHA-1 password hash", false),
		form("/crypto/account/login-legacy", rowWeakPwHash, wcAliceLoginBody,
			"a working login answers the profile with its bcrypt hash of cost 4", false),
		form("/crypto/account/login-plain", rowPlaintextPwd, wcBobLoginBody,
			"a working login answers the profile with the stored plaintext password", false),
		{Path: "/crypto/seal?data=hello", Row: rowECB,
			Note: "encrypts data with AES-128-ECB under a fixed key and answers it in base64"},

		{Path: "/crypto/safe/digest?token=report-2024", Row: rowWeakHash, Safe: true,
			Note: "answers HMAC-SHA-256 of token under a server secret"},
		{Path: "/crypto/safe/strong?token=report-2024", Row: rowWeakHash, Safe: true,
			Note: "answers the unsalted SHA-256 of a non-password value: no row applies"},
		{Path: "/crypto/safe/static?token=report-2024", Row: rowWeakHash, Safe: true,
			Note: "answers a fixed id and the MD5 of a constant equal to the captured token, whatever it is sent"},
		{Path: "/crypto/safe/check?password=letmein", Row: rowWeakPwHash, Safe: true,
			Note: "answers a salted SHA-256 of the password, with a fresh random salt each time"},
		form("/crypto/safe/account/login", rowWeakPwHash, wcAliceLoginBody,
			"a working login answers the profile with a bcrypt hash of cost 12", true),
		form("/crypto/safe/account/login-echo", rowPlaintextPwd, wcBobLoginBody,
			"answers the submitted password back under another key for every input: an echo", true),
		{Path: "/crypto/safe/seal?data=hello", Row: rowECB, Safe: true,
			Note: "encrypts data with AES-128-GCM under a fresh random nonce"},
		{Path: "/crypto/safe/encode?data=hello", Row: rowECB, Safe: true,
			Note: "answers base64 of data: an encoding whose blocks repeat with the plaintext"},
		{Path: "/crypto/safe/receipt?data=hello", Row: rowECB, Safe: true,
			Note: "answers a fresh random 16-byte id written three times in one token, whatever it is sent"},
	}
}

func wcJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func wcNTLM(s string) string {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 0, 2*len(u))
	for _, c := range u {
		b = append(b, byte(c), byte(c>>8))
	}
	h := md4.New()
	h.Write(b)
	return strings.ToUpper(hex.EncodeToString(h.Sum(nil)))
}

func wcHex(b []byte) string { return hex.EncodeToString(b) }

var (
	wcBcryptOnce          sync.Once
	wcBcrypt4, wcBcrypt12 []byte
)

func wcBcrypts() {
	wcBcryptOnce.Do(func() {
		wcBcrypt4, _ = bcrypt.GenerateFromPassword([]byte(wcAlicePassword), 4)
		wcBcrypt12, _ = bcrypt.GenerateFromPassword([]byte(wcAlicePassword), 12)
	})
}

// wcLogin answers alice's (or bob's) profile with extra members when the password is right.
func wcLogin(w http.ResponseWriter, r *http.Request, user, password string, extra func() map[string]any) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST a login form", http.StatusMethodNotAllowed)
		return
	}
	if r.FormValue("username") != user || r.FormValue("password") != password {
		wcJSON(w, map[string]any{"content": "Invalid credentials", "isValid": false})
		return
	}
	profile := map[string]any{"userId": 7, "username": user, "role": "USER"}
	for k, v := range extra() {
		profile[k] = v
	}
	wcJSON(w, map[string]any{"content": profile, "isValid": true})
}

func registerWeakCrypto(mux *http.ServeMux) {
	mux.HandleFunc("/crypto/digest", func(w http.ResponseWriter, r *http.Request) {
		s := md5.Sum([]byte(r.FormValue("token")))
		wcJSON(w, map[string]string{"content": "Your token's checksum is " + wcHex(s[:])})
	})
	mux.HandleFunc("/crypto/fingerprint", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, "<html><body><p>Device fingerprint: <code>%s</code></p></body></html>", wcNTLM(r.FormValue("code")))
	})
	mux.HandleFunc("/crypto/check", func(w http.ResponseWriter, r *http.Request) {
		s := sha256.Sum256([]byte(r.FormValue("password")))
		wcJSON(w, map[string]string{"content": "Incorrect. Your input hashed to: " + wcHex(s[:])})
	})
	mux.HandleFunc("/crypto/account/login", func(w http.ResponseWriter, r *http.Request) {
		wcLogin(w, r, "alice", wcAlicePassword, func() map[string]any {
			s := sha1.Sum([]byte(wcAlicePassword))
			return map[string]any{"passwordHash": wcHex(s[:]), "algorithm": "SHA-1"}
		})
	})
	mux.HandleFunc("/crypto/account/login-legacy", func(w http.ResponseWriter, r *http.Request) {
		wcBcrypts()
		wcLogin(w, r, "alice", wcAlicePassword, func() map[string]any {
			return map[string]any{"passwordHash": string(wcBcrypt4)}
		})
	})
	mux.HandleFunc("/crypto/account/login-plain", func(w http.ResponseWriter, r *http.Request) {
		wcLogin(w, r, "bob", wcBobPassword, func() map[string]any {
			return map[string]any{"passwordInDB": wcBobPassword}
		})
	})
	mux.HandleFunc("/crypto/seal", func(w http.ResponseWriter, r *http.Request) {
		blk, _ := aes.NewCipher([]byte(wcFixedAESKeyText))
		pt := []byte(r.FormValue("data"))
		pad := aes.BlockSize - len(pt)%aes.BlockSize
		for i := 0; i < pad; i++ {
			pt = append(pt, byte(pad))
		}
		ct := make([]byte, len(pt))
		for i := 0; i < len(pt); i += aes.BlockSize {
			blk.Encrypt(ct[i:i+aes.BlockSize], pt[i:i+aes.BlockSize])
		}
		wcJSON(w, map[string]string{"content": "Sealed: " + base64.StdEncoding.EncodeToString(ct)})
	})

	mux.HandleFunc("/crypto/safe/digest", func(w http.ResponseWriter, r *http.Request) {
		m := hmac.New(sha256.New, []byte(wcSecretHMACKey))
		m.Write([]byte(r.FormValue("token")))
		wcJSON(w, map[string]string{"content": "Your token's signature is " + wcHex(m.Sum(nil))})
	})
	mux.HandleFunc("/crypto/safe/strong", func(w http.ResponseWriter, r *http.Request) {
		s := sha256.Sum256([]byte(r.FormValue("token")))
		wcJSON(w, map[string]string{"content": "Your token's checksum is " + wcHex(s[:])})
	})
	mux.HandleFunc("/crypto/safe/static", func(w http.ResponseWriter, r *http.Request) {
		s := md5.Sum([]byte("report-2024"))
		wcJSON(w, map[string]string{"requestId": "9f86d081884c7d659a2feaa0c55ad015", "build": wcHex(s[:]),
			"content": "Thanks, your token was recorded."})
	})
	mux.HandleFunc("/crypto/safe/check", func(w http.ResponseWriter, r *http.Request) {
		salt := make([]byte, 16)
		_, _ = rand.Read(salt)
		s := sha256.Sum256(append(salt, r.FormValue("password")...))
		wcJSON(w, map[string]string{"content": "Incorrect. Your salted input hashed to: " + wcHex(salt) + "$" + wcHex(s[:])})
	})
	mux.HandleFunc("/crypto/safe/account/login", func(w http.ResponseWriter, r *http.Request) {
		wcBcrypts()
		wcLogin(w, r, "alice", wcAlicePassword, func() map[string]any {
			return map[string]any{"passwordHash": string(wcBcrypt12)}
		})
	})
	mux.HandleFunc("/crypto/safe/account/login-echo", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST a login form", http.StatusMethodNotAllowed)
			return
		}
		ok := r.FormValue("username") == "bob" && r.FormValue("password") == wcBobPassword
		wcJSON(w, map[string]any{"youTyped": r.FormValue("password"), "isValid": ok})
	})
	mux.HandleFunc("/crypto/safe/seal", func(w http.ResponseWriter, r *http.Request) {
		blk, _ := aes.NewCipher([]byte(wcFixedAESKeyText))
		g, _ := cipher.NewGCM(blk)
		nonce := make([]byte, g.NonceSize())
		_, _ = rand.Read(nonce)
		ct := g.Seal(nonce, nonce, []byte(r.FormValue("data")), nil)
		wcJSON(w, map[string]string{"content": "Sealed: " + base64.StdEncoding.EncodeToString(ct)})
	})
	mux.HandleFunc("/crypto/safe/receipt", func(w http.ResponseWriter, r *http.Request) {
		id := make([]byte, 16)
		_, _ = rand.Read(id)
		tok := append(append(append([]byte(nil), id...), id...), id...)
		wcJSON(w, map[string]string{"content": "Receipt " + base64.StdEncoding.EncodeToString(tok)})
	})
	mux.HandleFunc("/crypto/safe/encode", func(w http.ResponseWriter, r *http.Request) {
		wcJSON(w, map[string]string{"content": "Encoded: " + base64.StdEncoding.EncodeToString([]byte(r.FormValue("data")))})
	})
}
