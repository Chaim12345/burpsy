package vulnapp

// Host header injection, HTTP response header injection (CRLF) and SMTP header injection.
//
// Every response that has to carry a line break the application did not sanitise is written through
// writeRaw (a hijacked connection), because net/http replaces CR and LF in header values and so cannot
// be made vulnerable the obvious way — see echo in vulnapp.go. Nothing unsafe happens to the host:
// the bytes go to a test client on a loopback listener, and no mail is ever sent (the "mailer" below
// only parses the message it would have handed to one).
//
// Corresponding scanner checks: checkHostHeaderInjection (checks_host_header.go),
// checkResponseHeaderInjection (checks_crlf.go), checkSMTPHeaderInjection (checks_remaining.go).

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/mail"
	"net/textproto"
	"net/url"
	"strings"
)

// canonicalHost is the host the safe twins are configured to serve.
const canonicalHost = "app.example.test"

func hostCRLFEndpoints() []Endpoint {
	const host = "Host header injection"
	const crlf = "HTTP response header injection"
	const smtp = "SMTP header injection"
	return []Endpoint{
		// --- Host header injection ---
		{Path: "/hh/home", Row: host,
			Note: "builds its absolute links and script src from the Host header"},
		{Path: "/hh/redirect", Row: host,
			Note: "redirects to http://<Host header>/hh/home"},
		{Path: "/hh/fwd", Row: host,
			Note: "trusts X-Forwarded-Host for its asset URLs"},
		{Path: "/hh/safe/home", Row: host, Safe: true,
			Note: "links use the configured host; the Host header is only printed as text and inside another URL's query"},
		{Path: "/hh/safe/redirect", Row: host, Safe: true,
			Note: "redirects to a relative path; the Host header is only printed as text"},
		{Path: "/hh/safe/fwd", Row: host, Safe: true,
			Note: "honours X-Forwarded-Host only for an allow-listed host"},

		// --- HTTP response header injection: path, request header, Unicode narrowing ---
		{Path: "/crlf/r/home", Row: crlf,
			Note: "redirects /crlf/r/<path> to <decoded path>/ with the path written raw into Location"},
		{Path: "/crlf/ref", Row: crlf, RequestHeaders: map[string]string{"Referer": "http://127.0.0.1/start"},
			Note: "URL-decodes the Referer and writes it raw into an X-Ref response header"},
		{Path: "/crlf/unicode?msg=seed", Row: crlf,
			Note: "strips CR/LF, THEN narrows each character to its low byte, so U+560D U+560A become CR LF"},
		{Path: "/crlf/safe/r/home", Row: crlf, Safe: true,
			Note: "the same redirect through net/http, which removes line breaks from the path"},
		{Path: "/crlf/safe/ref", Row: crlf, Safe: true, RequestHeaders: map[string]string{"Referer": "http://127.0.0.1/start"},
			Note: "echoes every request header back as a response header; a header the client sends is echoed, not split"},
		{Path: "/crlf/safe/unicode?msg=seed", Row: crlf, Safe: true,
			Note: "narrows first and strips CR/LF after, so no separator survives"},
		{Path: "/crlf/safe/body?msg=seed", Row: crlf, Safe: true,
			Note: "prints msg verbatim into a text/plain body and a stripped copy into a header: header lines as body text only"},

		// --- SMTP header injection ---
		{Path: "/mail/contact?subject=hello", Row: smtp,
			Note: "writes subject unsanitised into a Subject header; the mailer takes recipients from To/Cc/Bcc and its relay refuses .invalid domains with smtplib's SMTPRecipientsRefused"},
		{Path: "/mail/safe/contact?subject=hello", Row: smtp, Safe: true,
			Note: "removes CR and LF from the subject before composing"},
		{Path: "/mail/safe/validate?email=hello@example.test", Row: smtp, Safe: true,
			Note: "rejects ANY character outside an address alphabet with javax.mail's AddressException, line break or not"},
		{Path: "/mail/safe/dynamic?subject=hello", Row: smtp, Safe: true,
			Note: "sends no mail; the page carries a per-request nonce and echoes the User-Agent, so every probe differs from the baseline (j1mk.41)"},
	}
}

func registerHostCRLF(mux *http.ServeMux) {
	mux.HandleFunc("/hh/home", hhHome)
	mux.HandleFunc("/hh/redirect", hhRedirect)
	mux.HandleFunc("/hh/fwd", hhForwarded)
	mux.HandleFunc("/hh/safe/home", hhSafeHome)
	mux.HandleFunc("/hh/safe/redirect", hhSafeRedirect)
	mux.HandleFunc("/hh/safe/fwd", hhSafeForwarded)
	mux.HandleFunc("/hh/route", hhRoute)

	mux.HandleFunc("/crlf/r/", crlfPathRedirect)
	mux.HandleFunc("/crlf/ref", crlfReferer)
	mux.HandleFunc("/crlf/unicode", crlfUnicode)
	mux.HandleFunc("/crlf/safe/r/", crlfSafePathRedirect)
	mux.HandleFunc("/crlf/safe/ref", crlfSafeEchoHeaders)
	mux.HandleFunc("/crlf/safe/unicode", crlfSafeUnicode)
	mux.HandleFunc("/crlf/safe/body", crlfSafeBody)

	mux.HandleFunc("/mail/contact", mailContact)
	mux.HandleFunc("/mail/safe/contact", mailSafeContact)
	mux.HandleFunc("/mail/safe/validate", mailSafeValidate)
	mux.HandleFunc("/mail/safe/dynamic", mailSafeDynamic)
}

// writeRaw writes a whole HTTP/1.1 response over the hijacked connection, header lines unsanitised.
func writeRaw(w http.ResponseWriter, status string, headers []string, body string) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusNotImplemented)
		fmt.Fprint(w, "this endpoint needs a hijackable connection to be vulnerable")
		return
	}
	conn, buf, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()
	var b strings.Builder
	b.WriteString("HTTP/1.1 " + status + "\r\n")
	for _, h := range headers {
		b.WriteString(h + "\r\n")
	}
	fmt.Fprintf(&b, "Content-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
	_, _ = buf.WriteString(b.String())
	_ = buf.Flush()
}

// --- Host header ---

func hhPage(w http.ResponseWriter, linkHost, note string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	h := htmlEscape(linkHost)
	fmt.Fprintf(w, `<html><head><script src="//%s/static/app.js"></script></head><body>`+
		`<a href="http://%s/hh/account">Your account</a> <p>%s</p></body></html>`, h, h, note)
}

func hhHome(w http.ResponseWriter, r *http.Request) { hhPage(w, r.Host, "welcome") }

func hhRedirect(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Location", "http://"+r.Host+"/hh/home")
	w.WriteHeader(http.StatusFound)
}

func hhForwarded(w http.ResponseWriter, r *http.Request) {
	host := r.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = canonicalHost
	}
	hhPage(w, host, "assets")
}

func hhSafeHome(w http.ResponseWriter, r *http.Request) {
	h := htmlEscape(r.Host)
	hhPage(w, canonicalHost, "Served for host "+h+`. <a href="https://`+canonicalHost+`/login?next=//`+h+`/hh/home">Sign in</a>`)
}

func hhSafeRedirect(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Location", "/hh/home")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusFound)
	fmt.Fprintf(w, `<p>Redirecting (requested host %s). See <a href="https://%s/hh/home">home</a>.</p>`,
		htmlEscape(r.Host), canonicalHost)
}

func hhSafeForwarded(w http.ResponseWriter, r *http.Request) {
	host := canonicalHost
	if fwd := r.Header.Get("X-Forwarded-Host"); fwd == "cdn.example.test" {
		host = fwd
	}
	hhPage(w, host, "assets")
}

// hhRoute is a front end that routes by the Host header: a host that is not a loopback address is
// "forwarded to" (recorded as a DNS lookup and an HTTP request, never actually contacted), the way a
// reverse proxy that resolves the Host header would. Out-of-band fixture only, outside the manifest:
// the runtime suite has no collaborator.
func hhRoute(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if i := strings.LastIndexByte(host, ':'); i >= 0 && !strings.HasSuffix(host, "]") {
		host = host[:i]
	}
	if host != "127.0.0.1" && host != "localhost" && host != "[::1]" {
		recordContact("dns", host)
		recordContact("http", host)
		http.Error(w, "upstream "+host+" did not answer", http.StatusBadGateway)
		return
	}
	fmt.Fprint(w, "routed locally")
}

// --- HTTP response header injection ---

func crlfPathRedirect(w http.ResponseWriter, r *http.Request) {
	if strings.HasSuffix(r.URL.Path, "/") {
		fmt.Fprint(w, "directory")
		return
	}
	// r.URL.Path is already percent-decoded, so %0d%0a in the request target is a CR LF here.
	writeRaw(w, "301 Moved Permanently", []string{"Location: " + r.URL.Path + "/"}, "moved")
}

func crlfSafePathRedirect(w http.ResponseWriter, r *http.Request) {
	if strings.HasSuffix(r.URL.Path, "/") {
		fmt.Fprint(w, "directory")
		return
	}
	http.Redirect(w, r, strings.NewReplacer("\r", "", "\n", "").Replace(r.URL.Path)+"/", http.StatusMovedPermanently)
}

func crlfReferer(w http.ResponseWriter, r *http.Request) {
	ref, err := url.PathUnescape(r.Header.Get("Referer"))
	if err != nil {
		ref = r.Header.Get("Referer")
	}
	writeRaw(w, "200 OK", []string{"Content-Type: text/plain", "X-Ref: " + ref}, "noted")
}

func crlfSafeEchoHeaders(w http.ResponseWriter, r *http.Request) {
	for name, values := range r.Header {
		w.Header().Set(name, strings.Join(values, ", "))
	}
	fmt.Fprint(w, "echoed")
}

// narrow keeps each character's low byte, the way a writer that casts a UTF-16 char to a byte does.
func narrow(s string) string {
	var b strings.Builder
	for _, c := range s {
		b.WriteByte(byte(c))
	}
	return b.String()
}

func stripCRLF(s string) string { return strings.NewReplacer("\r", "", "\n", "").Replace(s) }

func crlfUnicode(w http.ResponseWriter, r *http.Request) {
	writeRaw(w, "200 OK", []string{"Content-Type: text/plain", "X-Msg: " + narrow(stripCRLF(r.URL.Query().Get("msg")))}, "ok")
}

func crlfSafeUnicode(w http.ResponseWriter, r *http.Request) {
	writeRaw(w, "200 OK", []string{"Content-Type: text/plain", "X-Msg: " + stripCRLF(narrow(r.URL.Query().Get("msg")))}, "ok")
}

func crlfSafeBody(w http.ResponseWriter, r *http.Request) {
	msg := r.URL.Query().Get("msg")
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("X-Msg", stripCRLF(msg))
	fmt.Fprint(w, "you sent:\r\n"+msg)
}

// --- SMTP header injection ---

// sendMail composes a message with subject in its Subject header and hands it to the "relay": the
// recipients are read back out of the composed To, Cc and Bcc headers (the way Python's
// smtplib.send_message does), and the relay refuses any recipient under the reserved .invalid TLD, as
// a real one would. The error is surfaced the way an unhandled smtplib exception is.
func sendMail(w http.ResponseWriter, subject string) {
	msg := "From: site@example.test\r\nTo: support@example.test\r\nSubject: " + subject + "\r\n\r\nhello\r\n"
	hdr, err := textproto.NewReader(bufio.NewReader(strings.NewReader(msg))).ReadMIMEHeader()
	if err != nil {
		http.Error(w, "could not compose the message", http.StatusBadRequest)
		return
	}
	for _, field := range []string{"To", "Cc", "Bcc"} {
		for _, v := range hdr.Values(field) {
			list, err := mail.ParseAddressList(v)
			if err != nil {
				continue
			}
			for _, a := range list {
				if strings.HasSuffix(strings.ToLower(a.Address), ".invalid") {
					http.Error(w, fmt.Sprintf("Traceback (most recent call last):\n  ...\n"+
						"smtplib.SMTPRecipientsRefused: {'%s': (550, b'5.1.2 Bad destination host')}", a.Address),
						http.StatusInternalServerError)
					return
				}
			}
		}
	}
	fmt.Fprint(w, "Thanks, your message was sent.")
}

func mailContact(w http.ResponseWriter, r *http.Request) { sendMail(w, r.URL.Query().Get("subject")) }

func mailSafeContact(w http.ResponseWriter, r *http.Request) {
	sendMail(w, stripCRLF(r.URL.Query().Get("subject")))
}

func mailSafeValidate(w http.ResponseWriter, r *http.Request) {
	email := r.URL.Query().Get("email")
	for _, c := range email {
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("@._+-", c)
		if !ok {
			http.Error(w, "javax.mail.internet.AddressException: Illegal character in string ``"+htmlEscape(email)+"''",
				http.StatusBadRequest)
			return
		}
	}
	fmt.Fprint(w, "subscribed")
}

func mailSafeDynamic(w http.ResponseWriter, r *http.Request) {
	nonce := make([]byte, 8)
	_, _ = rand.Read(nonce)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, "<p>Draft saved: %s</p><p>nonce %s</p><p>client %s</p>",
		htmlEscape(r.URL.Query().Get("subject")), hex.EncodeToString(nonce), htmlEscape(r.UserAgent()))
}
