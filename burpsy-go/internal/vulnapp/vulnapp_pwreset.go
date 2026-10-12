package vulnapp

// The password-reset family (checks_pwreset.go): reset flows with one weakness each, and safe twins.
//
// Every variant serves the same three routes under /pwreset/<variant>/:
//
//	POST request  {"email": "<variant>@pwreset.test"}  -> mails a link to the identity's inbox
//	GET  page?token=T                                    -> the reset page: a form posting token+password
//	POST confirm  token=T&password=P                     -> sets the password if the token is valid
//
// and the shared test inbox is GET /pwreset/mailbox?to=<address>, which is what the scanner's
// ResetMailboxURL points at in the runtime test. Each variant has its own identity so that variants
// audited in parallel never read each other's messages.
//
// Links are built from the LISTENER's address (http.LocalAddrContextKey), never from the Host header,
// except in the poisonable variant, so a canary Host is reflected only where the defect is planted.
// Nothing here is stored outside this process's memory.

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// PwresetIdentities are the test identities of the reset variants, one per variant.
func PwresetIdentities() []string {
	out := make([]string, 0, len(pwVariants))
	for name := range pwVariants {
		out = append(out, name+"@pwreset.test")
	}
	return out
}

// PwresetMailboxPath is the inbox route; "{identity}" is the scanner's placeholder.
const PwresetMailboxPath = "/pwreset/mailbox?to={identity}"

type pwVariant struct {
	token      func(email string) string
	echo       bool   // the request's response carries the token
	decoy      bool   // the request's response carries an unrelated random csrfToken
	reusable   bool   // a used token stays valid
	httpLink   bool   // the link is http:// whatever the request came over
	poisonable bool   // the link's host comes from X-Forwarded-Host / Host
	reflectXFH bool   // the response echoes X-Forwarded-Host as plain text (not a link)
	policy     string // Referrer-Policy header on the page ("" = none)
	metaPolicy string // <meta name="referrer"> on the page
	staticImg  bool   // the page embeds a third-party image in its markup
	scriptImg  bool   // the page's script adds a third-party image
}

func pwRandomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func pwDigits(n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		k, _ := rand.Int(rand.Reader, big.NewInt(10))
		b.WriteString(k.String())
	}
	return b.String()
}

func pwJWT(exp bool) func(string) string {
	return func(email string) string {
		claims := map[string]any{"sub": email, "purpose": "password-reset", "jti": pwRandomHex(8)}
		if exp {
			claims["exp"] = time.Now().Add(15 * time.Minute).Unix()
		}
		h := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
		c, _ := json.Marshal(claims)
		p := base64.RawURLEncoding.EncodeToString(c)
		mac := hmac.New(sha256.New, jwSecret)
		mac.Write([]byte(h + "." + p))
		return h + "." + p + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	}
}

func pwStrong(string) string { return pwRandomHex(16) }

var pwVariants = map[string]pwVariant{
	// Vulnerable, one defect each (plus the http:// link every cleartext variant has).
	"leak": {token: pwStrong, echo: true},
	"clock": {token: func(string) string {
		return base64.RawURLEncoding.EncodeToString([]byte("u7:" + strconv.FormatInt(time.Now().Unix(), 10)))
	}},
	"weak":           {token: func(string) string { return "rst-" + pwDigits(5) }},
	"reuse":          {token: pwStrong, reusable: true},
	"jwt":            {token: pwJWT(false)},
	"poison":         {token: pwStrong, poisonable: true},
	"plain":          {token: pwStrong, httpLink: true}, // served over TLS, links over http://
	"referer":        {token: pwStrong, policy: "unsafe-url", staticImg: true},
	"referer-script": {token: pwStrong, metaPolicy: "unsafe-url", scriptImg: true},

	// Safe twins.
	"safe-leak":           {token: pwStrong, decoy: true},
	"safe-pred":           {token: pwStrong},
	"safe-entropy":        {token: pwStrong},
	"safe-reuse":          {token: pwStrong},
	"safe-jwt":            {token: pwJWT(true)},
	"safe-poison":         {token: pwStrong, reflectXFH: true},
	"safe-plain":          {token: pwStrong}, // served over TLS, links over https://
	"safe-referer":        {token: pwStrong, policy: "no-referrer", staticImg: true, scriptImg: true},
	"safe-referer-script": {token: pwStrong, metaPolicy: "no-referrer", scriptImg: true},
}

type pwTok struct {
	email string
	used  bool
}

var pw = struct {
	sync.Mutex
	inbox  map[string][]map[string]any
	tokens map[string]map[string]*pwTok // variant -> token -> state
	seq    int
}{inbox: map[string][]map[string]any{}, tokens: map[string]map[string]*pwTok{}}

func pwresetEndpoints() []Endpoint {
	req := func(v, row string, safe bool, note string) Endpoint {
		return Endpoint{Path: "/pwreset/" + v + "/request", Row: row, Safe: safe, Method: http.MethodPost,
			Body: `{"email":"` + v + `@pwreset.test"}`, ContentType: "application/json", Note: note}
	}
	const (
		inResp   = "Password reset token disclosed in response"
		pred     = "Predictable password reset token"
		entropy  = "Password reset token with insufficient entropy"
		reuse    = "Reusable password reset token"
		noExp    = "Password reset token without expiry"
		insecure = "Password reset link over unencrypted HTTP"
		referer  = "Password reset token leaked via Referer"
		poison   = "Password reset poisoning"
	)
	plain := req("plain", insecure, false, "served over https, but the mailed reset link is http://")
	plain.TLS = true
	safePlain := req("safe-plain", insecure, true, "served over https with an https:// reset link")
	safePlain.TLS = true
	refScript := req("referer-script", referer, false, "the reset page's meta referrer is unsafe-url and its "+
		"script adds a third-party image, so the browser sends the token-bearing URL to that origin")
	refScript.DOM = true
	safeRefScript := req("safe-referer-script", referer, true, "the reset page's script adds a third-party image, "+
		"but its meta referrer is no-referrer, so the browser sends no Referer")
	safeRefScript.DOM = true
	return []Endpoint{
		req("leak", inResp, false, "returns the reset token in the JSON response to the reset request"),
		req("clock", pred, false, "the token is base64url(\"u7:\" + server epoch seconds)"),
		req("weak", entropy, false, "the token is rst- followed by five random digits"),
		req("reuse", reuse, false, "tokens are never marked used"),
		req("jwt", noExp, false, "the token is a JWT without an exp claim"),
		req("poison", poison, false, "the link's host is taken from X-Forwarded-Host, else Host"),
		plain,
		req("referer", referer, false, "the reset page sends Referrer-Policy: unsafe-url and embeds a third-party image"),
		refScript,

		req("safe-leak", inResp, true, "the response carries only an unrelated random csrfToken, which is not a reset token"),
		req("safe-pred", pred, true, "128-bit random tokens"),
		req("safe-entropy", entropy, true, "128-bit random tokens"),
		req("safe-reuse", reuse, true, "a token is invalid once used"),
		req("safe-jwt", noExp, true, "a JWT token that expires in 15 minutes"),
		req("safe-poison", poison, true, "the link's host is the listener's; X-Forwarded-Host is only echoed as text"),
		safePlain,
		req("safe-referer", referer, true, "the reset page embeds and scripts a third-party image but sends Referrer-Policy: no-referrer"),
		safeRefScript,
	}
}

func registerPwreset(mux *http.ServeMux) {
	mux.HandleFunc("/pwreset/", func(w http.ResponseWriter, r *http.Request) {
		rest := strings.TrimPrefix(r.URL.Path, "/pwreset/")
		if rest == "mailbox" {
			to := strings.ToLower(r.URL.Query().Get("to"))
			pw.Lock()
			msgs := append([]map[string]any{}, pw.inbox[to]...)
			pw.Unlock()
			idorJSON(w, http.StatusOK, map[string]any{"messages": msgs})
			return
		}
		name, action, ok := strings.Cut(rest, "/")
		v, known := pwVariants[name]
		if !ok || !known {
			http.NotFound(w, r)
			return
		}
		switch action {
		case "request":
			pwRequest(w, r, name, v)
		case "page":
			pwPage(w, r, name, v)
		case "confirm":
			pwConfirm(w, r, name, v)
		default:
			http.NotFound(w, r)
		}
	})
}

func pwRequest(w http.ResponseWriter, r *http.Request, name string, v pwVariant) {
	var body struct {
		Email string `json:"email"`
	}
	if r.Method != http.MethodPost || json.NewDecoder(r.Body).Decode(&body) != nil || body.Email == "" {
		idorJSON(w, http.StatusBadRequest, map[string]string{"error": "email is required"})
		return
	}
	email := strings.ToLower(strings.TrimSpace(body.Email))
	resp := map[string]any{"message": "If the account exists, a reset link has been sent."}
	if email != name+"@pwreset.test" {
		idorJSON(w, http.StatusOK, resp)
		return
	}
	tok := v.token(email)
	scheme := "http"
	if r.TLS != nil && !v.httpLink {
		scheme = "https"
	}
	host := ""
	if a, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr); ok {
		host = a.String()
	}
	if v.poisonable {
		host = r.Host
		if x := r.Header.Get("X-Forwarded-Host"); x != "" {
			host = x
		}
	}
	link := fmt.Sprintf("%s://%s/pwreset/%s/page?token=%s", scheme, host, name, url.QueryEscape(tok))
	pw.Lock()
	if pw.tokens[name] == nil {
		pw.tokens[name] = map[string]*pwTok{}
	}
	pw.tokens[name][tok] = &pwTok{email: email}
	pw.seq++
	pw.inbox[email] = append(pw.inbox[email], map[string]any{"n": pw.seq, "to": email, "subject": "Reset your password",
		"body": `<p>Someone asked to reset your password. <a href="` + html.EscapeString(link) + `">Reset it here</a>.</p>`})
	if len(pw.inbox[email]) > 200 {
		pw.inbox[email] = pw.inbox[email][len(pw.inbox[email])-200:]
	}
	pw.Unlock()
	if v.echo {
		resp["resetToken"] = tok
	}
	if v.decoy {
		resp["csrfToken"] = pwRandomHex(16)
	}
	if v.reflectXFH {
		resp["forwardedFor"] = r.Header.Get("X-Forwarded-Host")
	}
	idorJSON(w, http.StatusOK, resp)
}

func pwPage(w http.ResponseWriter, r *http.Request, name string, v pwVariant) {
	tok := r.URL.Query().Get("token")
	if v.policy != "" {
		w.Header().Set("Referrer-Policy", v.policy)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	var b strings.Builder
	b.WriteString("<!doctype html><html><head><title>Reset password</title>")
	if v.metaPolicy != "" {
		b.WriteString(`<meta name="referrer" content="` + v.metaPolicy + `">`)
	}
	b.WriteString("</head><body><h1>Choose a new password</h1>")
	b.WriteString(`<form method="POST" action="/pwreset/` + name + `/confirm">`)
	b.WriteString(`<input type="hidden" name="token" value="` + html.EscapeString(tok) + `">`)
	b.WriteString(`<input type="password" name="password"><button type="submit">Reset</button></form>`)
	if v.staticImg {
		b.WriteString(`<img src="http://cdn.pwreset-thirdparty.test/pixel.png" alt="">`)
	}
	if v.scriptImg {
		b.WriteString(`<script>var i=new Image();i.src="http://cdn.pwreset-thirdparty.test/beacon.png";document.body.appendChild(i);</script>`)
	}
	b.WriteString("</body></html>")
	_, _ = w.Write([]byte(b.String()))
}

func pwConfirm(w http.ResponseWriter, r *http.Request, name string, v pwVariant) {
	if r.Method != http.MethodPost || r.ParseForm() != nil {
		idorJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	tok, pass := r.PostForm.Get("token"), r.PostForm.Get("password")
	pw.Lock()
	st := pw.tokens[name][tok]
	ok := st != nil && pass != "" && (!st.used || v.reusable)
	if ok {
		st.used = true
	}
	pw.Unlock()
	if !ok {
		idorJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid or expired reset token"})
		return
	}
	idorJSON(w, http.StatusOK, map[string]string{"status": "Your password has been reset successfully"})
}
