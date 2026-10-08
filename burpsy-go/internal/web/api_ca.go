package web

// Importing an operator's own CA — Burp's `configPanelCustomCACertificates`.
//
// The capability was real and filesystem-only. LoadOrGenerateCA reads ca.crt/ca.key from -ca-dir at
// startup, so using your own CA meant stopping burpsy, placing two files, and starting again — which
// costs the operator every exchange captured so far. The console's certificate section could only
// download the generated CA. W6 #10 recorded it at state 3 for exactly that reason: capability
// present, no path to it from the UI.
//
// # Why this route is careful
//
// It accepts a private key. Three consequences shape the code below.
//
// First, validation happens before anything is replaced: TlsEngine.ImportCA runs the pair through
// the same loadCA/validateCA path the startup loader uses, on a throwaway engine, so a certificate
// that is not a CA, a mismatched key or an expired pair leaves the running CA untouched. Installing
// a CA that cannot sign would take TLS interception down entirely, which is strictly worse than
// refusing the import.
//
// Second, the key is never echoed. Not in the response, not in an error, not in a log line. The
// reply describes the *certificate* — subject and expiry — and says nothing about the key beyond
// whether it matched.
//
// Third, what is written to disk is written with the permissions the startup loader uses: 0644 for
// the certificate, which is public, and 0600 for the key, which is not.

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"go.uber.org/zap"
)

// caImportRequest carries a PEM pair. Field names match the two files the startup loader reads, so
// an operator scripting this against their existing ca.crt/ca.key has nothing to translate.
type caImportRequest struct {
	CertPEM string `json:"cert_pem"`
	KeyPEM  string `json:"key_pem"`
}

// caStatusResponse describes the CA now in force. Deliberately says nothing about the private key.
type caStatusResponse struct {
	Configured bool   `json:"configured"`
	Subject    string `json:"subject,omitempty"`
	NotAfter   string `json:"not_after,omitempty"`
	// Persisted reports whether the imported pair was written to -ca-dir. False means the CA is in
	// force for this process only and a restart returns to the previous one — a materially different
	// situation for an operator who has just installed it in a trust store, so it is stated rather
	// than left to be discovered.
	Persisted bool `json:"persisted"`
	// PersistError is why persistence failed, when it did. The import still succeeded; reporting
	// success with a silent partial failure is the shape this codebase treats as a defect.
	PersistError string `json:"persist_error,omitempty"`
	Hint         string `json:"hint,omitempty"`
	// Directory is where burpsy keeps the signing CA on disk (burpsy-react-ui-fyua), so an operator
	// can answer the operational question "where does my state live". Empty when no -ca-dir is set
	// (the CA is in force for this process only). Read-only: relocating it is a restart-time choice
	// (-ca-dir), not a runtime one, because the live engine has already loaded the CA from here and
	// moving it under the running process would desync the two.
	Directory string `json:"directory,omitempty"`
}

func (s *Server) caStatus() caStatusResponse {
	if s.tlsEngine == nil {
		return caStatusResponse{
			Hint: "TLS interception is off, so there is no signing CA. Start burpsy with " +
				"-intercept-tls to enable it.",
		}
	}
	subject, notAfter, ok := s.tlsEngine.CADescription()
	if !ok {
		return caStatusResponse{Hint: "the TLS engine holds no CA certificate"}
	}
	return caStatusResponse{
		Configured: true,
		Subject:    subject,
		NotAfter:   notAfter.UTC().Format(time.RFC3339),
		Directory:  s.caDir,
	}
}

// handleCAStatus serves GET /api/proxy/ca: which CA is signing, and until when.
func (s *Server) handleCAStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, s.caStatus())
}

// handleCAImport serves POST /api/proxy/ca/import.
//
// On success the leaf-certificate cache has been emptied by ImportCA — every cached leaf was signed
// by the CA just replaced, and clients are about to be told to trust the new one. See ImportCA for
// why that matters and for the one race it cannot close.
func (s *Server) handleCAImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Decoded before the engine check so the schema sweep reaches it (burpsy-react-ui-3zw0); a
	// malformed body is a 400 whatever this process carries.
	var req caImportRequest
	if err := requestJSON(w, r, nil).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if s.tlsEngine == nil {
		// Nothing would consult an imported CA, so accepting it would store a value that changes
		// nothing.
		http.Error(w, "TLS interception is off, so there is no signing CA to replace; start burpsy "+
			"with -intercept-tls", http.StatusServiceUnavailable)
		return
	}
	if req.CertPEM == "" || req.KeyPEM == "" {
		http.Error(w, "both cert_pem and key_pem are required", http.StatusBadRequest)
		return
	}

	// Validates first and replaces nothing on failure.
	if err := s.tlsEngine.ImportCA([]byte(req.CertPEM), []byte(req.KeyPEM)); err != nil {
		// err comes from loadCA/validateCA and describes the certificate or the key's *shape* —
		// "is not a certificate authority", "do not match". It never contains key material.
		http.Error(w, "CA import refused: "+err.Error(), http.StatusBadRequest)
		return
	}

	status := s.caStatus()
	status.Persisted, status.PersistError = s.persistCA(req)

	// Logged because replacing the signing CA is an operator action with consequences beyond this
	// process — every client trusting the old CA must be updated. Subject only; no key, no PEM.
	s.logger.Info("CA certificate imported; leaf cache cleared",
		zap.String("subject", status.Subject),
		zap.String("not_after", status.NotAfter),
		zap.Bool("persisted", status.Persisted))

	if !status.Persisted {
		status.Hint = "This CA is in force for this process only — it was not written to disk, so a " +
			"restart returns to the previous CA. Clients must be told to trust the new certificate " +
			"either way; download it from /ca.crt."
	} else {
		status.Hint = "Clients must now be told to trust this certificate — the previous one signs " +
			"nothing. Download it from /ca.crt."
	}
	writeJSON(w, http.StatusOK, status)
}

// handleCARegenerate serves POST /api/proxy/ca/regenerate — Burp's "Regenerate CA
// certificate", beside import/export in BurpClass9617.
//
// It mints a brand-new self-signed CA and installs it as the signing CA, discarding
// the previous one. Unlike import it takes nothing from the caller: the new key is
// generated inside the process and, like the imported one, never leaves it except as
// the public certificate at /ca.crt — not in this response, not in a log line.
//
// It is deliberately destructive and, once persisted, irreversible. The previous CA
// stops signing the moment RegenerateCA returns, every cached leaf is discarded, and
// persisting the new pair overwrites the old signing key on disk with no way back.
// Every client that trusted the old CA must be given the new one — the old
// certificate signs nothing from here on. That is why the manifest classifies this
// route riskDestructive and an unattended caller must confirm before invoking it.
func (s *Server) handleCARegenerate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.tlsEngine == nil {
		// Nothing would sign with a regenerated CA, so minting one would change nothing.
		http.Error(w, "TLS interception is off, so there is no signing CA to regenerate; start burpsy "+
			"with -intercept-tls", http.StatusServiceUnavailable)
		return
	}

	// RegenerateCA validates the minted pair before swapping, so on the (near-impossible)
	// failure path the running CA and the leaf cache are untouched. The error never carries
	// key material.
	certPEM, keyPEM, err := s.tlsEngine.RegenerateCA()
	if err != nil {
		http.Error(w, "CA regeneration failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	status := s.caStatus()
	// Reuses the import path's persistence: same directory, same modes, same
	// in-force-but-not-durable reporting when the write cannot complete.
	status.Persisted, status.PersistError = s.persistCA(caImportRequest{
		CertPEM: string(certPEM),
		KeyPEM:  string(keyPEM),
	})

	// Logged because rotating the signing CA has consequences beyond this process —
	// every client trusting the old CA must be updated. Subject only; no key, no PEM.
	s.logger.Info("CA certificate regenerated; leaf cache cleared",
		zap.String("subject", status.Subject),
		zap.String("not_after", status.NotAfter),
		zap.Bool("persisted", status.Persisted))

	if !status.Persisted {
		status.Hint = "A new CA is in force for this process only — it was not written to disk, so a " +
			"restart returns to the previous CA. Either way, every client that trusted the old CA must " +
			"now be given the new one; download it from /ca.crt."
	} else {
		status.Hint = "A new CA is now signing and the previous one is gone. Every client that trusted " +
			"the old certificate must now be given the new one — the previous certificate signs nothing. " +
			"Download it from /ca.crt."
	}
	writeJSON(w, http.StatusOK, status)
}

// persistCA writes the imported pair to -ca-dir so it survives a restart.
//
// Returns (false, reason) rather than failing the request: the CA is already installed and signing by
// the time this runs, so reporting an error would tell the operator the import failed when it did
// not. The distinction — in force but not durable — is carried in the response instead.
//
// Writes the certificate first. The order is deliberate — a key on disk with no certificate is key
// material lying around for a CA nobody can identify — but its consequence differs by what was there
// before. On a first import into an empty directory a failed key write leaves a lone certificate, and
// LoadOrGenerateCA requires *both* files before it will load a pair, so the next start mints a fresh
// CA. When a previous ca.key is already present (every regenerate, and any re-import), a failed key
// write leaves the NEW certificate beside the OLD key: LoadOrGenerateCA finds both files, loadCA runs
// them through validateCA, the keys do not match, and the next start REFUSES to load rather than
// falling through to generate. Both outcomes are reported honestly by the message below; neither is
// silently papered over.
func (s *Server) persistCA(req caImportRequest) (bool, string) {
	if s.caDir == "" {
		return false, "no CA directory is configured"
	}
	if err := os.MkdirAll(s.caDir, 0o700); err != nil {
		return false, fmt.Sprintf("could not create %s: %v", s.caDir, err)
	}
	certPath := filepath.Join(s.caDir, "ca.crt")
	keyPath := filepath.Join(s.caDir, "ca.key")

	// 0644: the certificate is public by design — it is served at /ca.crt and installed in trust
	// stores.
	if err := os.WriteFile(certPath, []byte(req.CertPEM), 0o644); err != nil {
		return false, fmt.Sprintf("could not write %s: %v", certPath, err)
	}
	// 0600: the key is not. Same mode the startup loader uses.
	if err := os.WriteFile(keyPath, []byte(req.KeyPEM), 0o600); err != nil {
		// Leave the certificate in place and say so. Removing it would be a second write that can
		// also fail, and LoadOrGenerateCA needs both files, so a lone certificate is already inert.
		return false, fmt.Sprintf("the certificate was written but the key was not (%v); the pair in %s "+
			"is now inconsistent — if a previous key is still present it will not match the new "+
			"certificate and the next start will refuse to load it; remove ca.crt and ca.key from %s to "+
			"force a fresh CA", err, s.caDir, s.caDir)
	}
	return true, ""
}
