package security

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"time"
)

// TLSConfig creates a fresh in-memory server identity and a mandatory TLS1.3
// client-key pin policy. Standard adb authenticates the controller to us but
// does not pin our server certificate; Headscale peer identity is separately
// required. This does not pretend to provide stock-adb server-certificate PKI.
// No private controller key is read, and no server private key is written.
func (k *Keys) TLSConfig() (*tls.Config, error) {
	if k == nil || len(k.allowed) == 0 {
		return nil, errors.New("no authorized controller keys")
	}
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "private-adbd"}, NotBefore: now.Add(-24 * time.Hour), NotAfter: now.AddDate(2, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &private.PublicKey, private)
	if err != nil {
		return nil, err
	}
	// ADB uses these subject names to select an already-loaded host key. They
	// are hints only: neither CA signatures nor names grant authorization.
	hints := x509.NewCertPool()
	for _, fp := range k.Fingerprints() {
		hint := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{Organization: []string{"AdbKey-0"}, CommonName: fp}, NotBefore: template.NotBefore, NotAfter: template.NotAfter, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
		hintDER, e := x509.CreateCertificate(rand.Reader, hint, hint, &private.PublicKey, private)
		if e != nil {
			return nil, e
		}
		parsed, e := x509.ParseCertificate(hintDER)
		if e != nil {
			return nil, e
		}
		hints.AddCert(parsed)
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: private}},
		ClientAuth:   tls.RequireAnyClientCert, ClientCAs: hints, SessionTicketsDisabled: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if cs.Version != tls.VersionTLS13 || len(cs.PeerCertificates) != 1 || !k.Allows(cs.PeerCertificates[0].PublicKey) {
				return errors.New("controller key is not authorized")
			}
			// crypto/tls verifies CertificateVerify against this leaf's public key.
			// This exact-SPKI check never substitutes for proof of private-key possession.
			return nil
		},
	}, nil
}
