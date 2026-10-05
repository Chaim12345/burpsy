package web

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"strings"

	"go.uber.org/zap"
	"software.sslmate.com/src/go-pkcs12"
)

// ---- CA export (burpsy-react-ui-j92x) ------------------------------------------------------------
//
// Burp's CA dialog exports the certificate, the private key and a PKCS#12 keystore (Zraj.java:48,57,
// 64). burpsy served /ca.crt and accepted an imported pair, and offered no way out for the key — so an
// operator could not point another tool (ZAP, a scanner, a mobile proxy) at the CA burpsy is already
// intercepting with, which is the documented way to make two tools agree about what is being
// intercepted.
//
// # Why this route is riskDestructive, and what that buys
//
// The key is the secret that lets whoever holds it mint a certificate every client that trusts this CA
// will accept. Handing it out is irreversible in the way handleCARegenerate's rotation is: once a copy
// exists elsewhere, nothing in this process can take it back. So the route carries the same class, and
// the confirmation gate in front of every riskDestructive route refuses an unattended call (428) until
// a one-time confirmation is minted and spent. The certificate export goes through the same gate even
// though the certificate is public, because one route with one rule is easier to reason about than a
// kind-dependent gate that a caller could talk past by naming the cheap kind first.
//
// # What never happens to the key
//
// It is never logged, never echoed in an error, and never served with a cacheable response. Every
// refusal below names the problem and the accepted values and nothing else — a 4xx that carried key
// material would be a second way out that skipped the gate.

// caExportKinds is the accepted set, in the order a refusal names them.
var caExportKinds = []string{"cert", "key", "pkcs12"}

// maxCAExportRequestBytes bounds the request body: it carries a kind and a password and nothing else.
const maxCAExportRequestBytes = 4 * 1024

type caExportRequest struct {
	// Kind is cert (PEM certificate), key (PKCS#8 PEM private key) or pkcs12 (a password-protected
	// keystore carrying both).
	Kind string `json:"kind"`
	// Password protects a pkcs12 export and is required for it: a keystore with no password opens for
	// anyone who has the file, and the file's whole purpose is to be carried to another machine.
	Password string `json:"password,omitempty"`
}

// handleCAExport serves POST /api/proxy/ca/export.
func (s *Server) handleCAExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req caExportRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxCAExportRequestBytes)).Decode(&req); err != nil {
		http.Error(w, `the body must be a JSON object such as {"kind":"cert"}`, http.StatusBadRequest)
		return
	}
	kind := strings.ToLower(strings.TrimSpace(req.Kind))
	if !isCAExportKind(kind) {
		// Names the accepted set, not the request: an unknown kind is refused by name rather than guessed
		// at, because the guess would be the difference between exporting the certificate and the key.
		http.Error(w, "unknown export kind; the kinds are "+strings.Join(caExportKinds, ", "), http.StatusBadRequest)
		return
	}
	if kind == "pkcs12" && req.Password == "" {
		http.Error(w, "a PKCS#12 export needs a password: a keystore with no password opens for anyone "+
			"who obtains the file", http.StatusBadRequest)
		return
	}

	if kind == "cert" {
		certPEM := s.currentCACertPEM()
		if len(certPEM) == 0 {
			s.refuseCAExportWithoutCA(w)
			return
		}
		s.logCAExport(kind, certPEM)
		writeCAExport(w, "application/x-pem-file", "burpsy-ca.crt", certPEM)
		return
	}

	// key and pkcs12 need the private key, which only the live engine holds.
	if s.tlsEngine == nil {
		s.refuseCAExportWithoutCA(w)
		return
	}
	cert, key, ok := s.tlsEngine.ExportCA()
	if !ok {
		s.refuseCAExportWithoutCA(w)
		return
	}

	switch kind {
	case "key":
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			// The marshal error describes the key type, never the key; the message is fixed anyway.
			http.Error(w, "the CA key could not be encoded", http.StatusInternalServerError)
			return
		}
		s.logCAExport(kind, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
		writeCAExport(w, "application/x-pem-file", "burpsy-ca.key",
			pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	case "pkcs12":
		// Modern (AES-256 / PBKDF2) rather than the legacy RC2/3DES encoding: every current consumer —
		// Java 11+, OpenSSL 3, browsers, mobile trust stores — reads it, and the legacy ciphers are the
		// reason a "protected" keystore can be cracked offline.
		p12, err := pkcs12.Modern.Encode(key, cert, nil, req.Password)
		if err != nil {
			http.Error(w, "the PKCS#12 keystore could not be built", http.StatusInternalServerError)
			return
		}
		s.logCAExport(kind, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
		writeCAExport(w, "application/x-pkcs12", "burpsy-ca.p12", p12)
	}
}

func isCAExportKind(kind string) bool {
	for _, k := range caExportKinds {
		if k == kind {
			return true
		}
	}
	return false
}

// refuseCAExportWithoutCA answers an export with no CA to export, saying why rather than returning an
// empty file — the distinction handleCACert draws at /ca.crt, for the same reason: an operator who
// downloaded an empty file would go looking for the fault in their other tool.
func (s *Server) refuseCAExportWithoutCA(w http.ResponseWriter) {
	http.Error(w, "TLS interception is off, so there is no signing CA to export; start burpsy with "+
		"-intercept-tls", http.StatusServiceUnavailable)
}

// logCAExport records that an export happened — kind and CA subject only. Exporting the key has
// consequences outside this process (whoever holds it can mint trusted leaves), so it is worth a line
// in the log; the line never carries the key, the password, or the PEM.
func (s *Server) logCAExport(kind string, certPEM []byte) {
	subject := ""
	if blk, _ := pem.Decode(certPEM); blk != nil {
		if cert, err := x509.ParseCertificate(blk.Bytes); err == nil {
			subject = cert.Subject.CommonName
		}
	}
	s.logger.Info("CA exported", zap.String("kind", kind), zap.String("subject", subject))
}

// writeCAExport sends an export as a download that no cache along the way keeps.
func writeCAExport(w http.ResponseWriter, contentType, filename string, body []byte) {
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	// no-store: a private key in a browser or proxy cache is a copy nobody decided to make.
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}
