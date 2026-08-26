package netauth

import (
	"crypto"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"software.sslmate.com/src/go-pkcs12"
)

// PKCS#12 client identities.
//
// # Why PKCS#12 and only PKCS#12
//
// Burp offers two sources for a client certificate: a PKCS#12 file and a PKCS#11
// hardware token. This build implements the file and **does not implement PKCS#11**.
// That is a declared limitation, not an oversight, and it is declared rather than
// stubbed because a token option that cannot open a token is worse than no option:
// the operator selects it, nothing loads, and the handshake fails for a reason the
// panel does not explain.
//
// The reason PKCS#11 is out of scope: it needs a cgo binding to a vendor `.so`
// (opensc-pkcs11, a vendor middleware), which makes the driver an install-time
// dependency of a tool that is currently a single static binary, and the signing
// operation has to happen inside the token — so it cannot reuse the tls.Certificate
// path below at all, it needs a crypto.Signer that marshals to the token per
// handshake. That is a separate piece of work with its own failure modes, and
// pretending otherwise on the panel would be dishonest.
//
// # Why the parsed certificate is held rather than the file
//
// A PKCS#12 file is encrypted with a passphrase-derived key, and the derivation is
// deliberately expensive. Re-reading and re-deriving per dial would put tens of
// milliseconds of PBKDF on every TLS connection the tool makes. The file is read
// once, at the moment the operator binds it, which is also when a bad passphrase or
// an unreadable file should be reported — the failure belongs at the point the
// operator can still fix it, not on a handshake three tabs away.

// LoadClientCert reads a PKCS#12 file and binds the identity in it to a host pattern.
//
// # Errors are the point of this function
//
// Every failure mode here is one an operator can act on, so each is named
// separately: a missing file, a wrong passphrase, a file that is not PKCS#12 at all,
// and a PKCS#12 that parses but carries no usable key pair. A single "could not load
// certificate" would leave the operator guessing which of four things to change.
//
// The chain matters. DecodeChain, not Decode: a client certificate issued by an
// intermediate must present leaf-plus-intermediates or the server cannot build a
// path to its trust anchor and rejects the handshake with an unknown-CA alert. That
// failure surfaces at the server, minutes later, and looks nothing like a missing
// intermediate — which is why the chain is assembled here rather than hoped for.
func LoadClientCert(host, path, passphrase string) (ClientCert, error) {
	host = strings.TrimSpace(host)
	if host == "" {
		return ClientCert{}, errors.New("a client-certificate binding needs a host pattern, for example example.com or *.example.com")
	}
	path = strings.TrimSpace(path)
	if path == "" {
		return ClientCert{}, errors.New("a client-certificate binding needs the path to a PKCS#12 file (.p12 or .pfx)")
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return ClientCert{}, fmt.Errorf("no PKCS#12 file at %s", path)
		}
		return ClientCert{}, fmt.Errorf("reading %s: %w", path, err)
	}
	if len(raw) == 0 {
		return ClientCert{}, fmt.Errorf("%s is empty, so it carries no certificate", path)
	}

	key, leaf, intermediates, err := pkcs12.DecodeChain(raw, passphrase)
	if err != nil {
		// The library reports a bad passphrase and a malformed file through the same error
		// type, so the message is the only signal. Distinguished here because the operator's
		// next action is completely different: retype the passphrase, or find the right file.
		if isPassphraseFailure(err) {
			return ClientCert{}, fmt.Errorf("the passphrase for %s was rejected: %w", path, err)
		}
		return ClientCert{}, fmt.Errorf("%s is not a PKCS#12 file this build can read: %w", path, err)
	}
	if leaf == nil {
		return ClientCert{}, fmt.Errorf("%s carries no end-entity certificate, so there is no identity to present", path)
	}
	if key == nil {
		return ClientCert{}, fmt.Errorf("%s carries a certificate but no private key, so it cannot sign a handshake", path)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return ClientCert{}, fmt.Errorf("the private key in %s is a %T, which cannot sign a TLS handshake", path, key)
	}

	// Leaf first, then intermediates, which is the order crypto/tls writes the
	// Certificate message in and the order a server expects to build a path from.
	chain := [][]byte{leaf.Raw}
	for _, ca := range intermediates {
		if ca == nil {
			continue
		}
		chain = append(chain, ca.Raw)
	}

	fingerprint := sha256.Sum256(leaf.Raw)
	return ClientCert{
		Host:        host,
		Subject:     leaf.Subject.String(),
		Issuer:      leaf.Issuer.String(),
		NotAfter:    leaf.NotAfter.UTC().Format(time.RFC3339),
		Fingerprint: hex.EncodeToString(fingerprint[:]),
		Path:        path,
		cert: &tls.Certificate{
			Certificate: chain,
			PrivateKey:  signer,
			Leaf:        leaf,
		},
		passphrase: passphrase,
	}, nil
}

// isPassphraseFailure reports whether a decode error is a rejected passphrase rather
// than a malformed file.
//
// String matching, because go-pkcs12 returns an unexported error value for the MAC
// check and errors.Is has nothing exported to compare against. Kept narrow and
// documented so that a library change makes this fall back to the generic message —
// a less specific error, never a wrong one.
func isPassphraseFailure(err error) bool {
	if errors.Is(err, pkcs12.ErrIncorrectPassword) {
		return true
	}
	text := strings.ToLower(err.Error())
	return strings.Contains(text, "incorrect password") || strings.Contains(text, "decryption password incorrect")
}

// RestoreClientCerts rebuilds bindings from persisted rows, returning the bindings it
// could load and one error per row it could not.
//
// Both halves are returned because both are true and the caller has to report both:
// a certificate whose file was deleted between sessions is a binding the operator
// still has on the panel and that will not be presented. Silently dropping it would
// make the panel claim an identity is bound when no handshake will ever carry it —
// the exact "partial result looking complete" failure this codebase treats as a bug.
//
// The rows are re-loaded, not trusted: a restored binding that skipped validation
// would present a certificate nobody had checked was still readable, and the first
// evidence of that would be a failed handshake mid-engagement.
func RestoreClientCerts(rows []ClientCertRow) (*ClientCerts, []error) {
	store := NewClientCerts()
	var failures []error
	for _, row := range rows {
		entry, err := LoadClientCert(row.Host, row.Path, row.Passphrase)
		if err != nil {
			failures = append(failures, fmt.Errorf("client certificate for %s: %w", row.Host, err))
			continue
		}
		store.Add(entry)
	}
	return store, failures
}

// RestoreCredentials rebuilds the platform-authentication list from persisted rows,
// returning the rules it could rebuild and one error per row it could not.
//
// A row whose scheme no longer parses is dropped and named rather than coerced: if a
// future build removes a scheme — or if a row was written by a build that had one this
// one does not — the credentials stored under it must not silently become Basic. That
// would send the operator's password to a host under a scheme they never chose.
func RestoreCredentials(rows []CredentialRow) (*Credentials, []error) {
	store := NewCredentials()
	var failures []error
	for _, row := range rows {
		scheme, err := ParseScheme(row.Scheme)
		if err != nil {
			failures = append(failures, fmt.Errorf("platform-authentication rule for %s: %w", row.Host, err))
			continue
		}
		rule, err := NewCredential(row.Host, scheme, row.Username, row.Password, row.Realm)
		if err != nil {
			failures = append(failures, fmt.Errorf("platform-authentication rule for %s: %w", row.Host, err))
			continue
		}
		store.Add(rule)
	}
	return store, failures
}

// ClientCerts satisfies alpn.ClientCertSource through its For method, which is the
// only thing the dial path needs from this package. The adapter is deliberately not
// written here: alpn.Dialer holds the decline-or-present policy (an empty
// tls.Certificate rather than an error) in one place, and a second copy of that
// policy in this package would be free to drift from it.
