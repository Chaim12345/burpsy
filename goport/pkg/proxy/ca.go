package proxy

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type CertAuthority struct {
	caCert    *x509.Certificate
	caPrivKey *rsa.PrivateKey
	mu        sync.RWMutex
	cache     map[string]*tls.Certificate
	leafKey   *rsa.PrivateKey // Cache a single RSA key for all leaf certificates to avoid expensive key gen
}

func LoadOrGenerateCA(caDir string) (*CertAuthority, error) {
	certPath := filepath.Join(caDir, "ca.crt")
	keyPath := filepath.Join(caDir, "ca.key")

	var caCertBytes, caKeyBytes []byte
	var err error

	if _, err = os.Stat(certPath); err == nil {
		caCertBytes, err = os.ReadFile(certPath)
		if err != nil {
			return nil, err
		}
		caKeyBytes, err = os.ReadFile(keyPath)
		if err != nil {
			return nil, err
		}
	} else {
		// Generate new CA
		if err = os.MkdirAll(caDir, 0755); err != nil {
			return nil, err
		}
		caCertBytes, caKeyBytes, err = generateCAFiles(certPath, keyPath)
		if err != nil {
			return nil, err
		}
	}

	caBlock, _ := pem.Decode(caCertBytes)
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return nil, err
	}

	keyBlock, _ := pem.Decode(caKeyBytes)
	caPrivKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, err
	}

	// Pre-generate a single leaf key to make TLS handshake lightning fast!
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	return &CertAuthority{
		caCert:    caCert,
		caPrivKey: caPrivKey,
		cache:     make(map[string]*tls.Certificate),
		leafKey:   leafKey,
	}, nil
}

func generateCAFiles(certPath, keyPath string) ([]byte, []byte, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"burpsy Go Port Certificate Authority"},
			CommonName:   "burpsy Root CA",
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}

	certPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPem := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	err = os.WriteFile(certPath, certPem, 0644)
	if err != nil {
		return nil, nil, err
	}
	err = os.WriteFile(keyPath, keyPem, 0600)
	if err != nil {
		return nil, nil, err
	}

	return certPem, keyPem, nil
}

func (ca *CertAuthority) SignCertificate(domain string) (*tls.Certificate, error) {
	ca.mu.RLock()
	if cert, ok := ca.cache[domain]; ok {
		ca.mu.RUnlock()
		return cert, nil
	}
	ca.mu.RUnlock()

	ca.mu.Lock()
	defer ca.mu.Unlock()

	// Check again in case of concurrent generation
	if cert, ok := ca.cache[domain]; ok {
		return cert, nil
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}

	// Standard dynamic certificate matching hostname or IP SANs
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   domain,
			Organization: []string{"burpsy Port Decrypted Traffic"},
		},
		NotBefore:   time.Now().Add(-1 * time.Hour),
		NotAfter:    time.Now().AddDate(1, 0, 0),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	if ip := net.ParseIP(domain); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{domain}
	}

	// SHA1 fingerprint of SubjectPublicKeyInfo is standard for AuthorityKeyId
	pubBytes, err := x509.MarshalPKIXPublicKey(&ca.leafKey.PublicKey)
	if err == nil {
		h := sha1.New()
		h.Write(pubBytes)
		template.SubjectKeyId = h.Sum(nil)
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, ca.caCert, &ca.leafKey.PublicKey, ca.caPrivKey)
	if err != nil {
		return nil, err
	}

	certPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPem := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(ca.leafKey)})

	cert, err := tls.X509KeyPair(certPem, keyPem)
	if err != nil {
		return nil, err
	}

	ca.cache[domain] = &cert
	return &cert, nil
}
