package security

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

func fixtureCert(t *testing.T, advertised crypto.PublicKey, signer crypto.Signer) tls.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(17), Subject: pkix.Name{CommonName: "adb-fixture"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, advertised, signer)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: signer}
}
func handshakeResult(t *testing.T, serverConf, clientConf *tls.Config) error {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	outcome := make(chan error, 1)
	go func() {
		c, e := ln.Accept()
		if e != nil {
			outcome <- e
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(3 * time.Second))
		outcome <- tls.Server(c, serverConf).Handshake()
	}()
	c, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	client := tls.Client(c, clientConf)
	_ = client.Handshake()
	_ = client.Close()
	return <-outcome
}
func TestTLSRequiresKnownKeyAndPossession(t *testing.T) {
	allowed, _ := rsa.GenerateKey(rand.Reader, 2048)
	unknown, _ := rsa.GenerateKey(rand.Reader, 2048)
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keys, err := ParseKeys([]byte(androidKey(t, &allowed.PublicKey)))
	if err != nil {
		t.Fatal(err)
	}
	conf, err := keys.TLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	if conf.MinVersion != tls.VersionTLS13 || conf.ClientAuth != tls.RequireAnyClientCert || !conf.SessionTicketsDisabled {
		t.Fatal("unsafe TLS settings")
	}
	cases := []struct {
		name string
		cert *tls.Certificate
		max  uint16
		want bool
	}{
		{"known", nil, tls.VersionTLS13, true}, {"unknown", nil, tls.VersionTLS13, false}, {"no_certificate", nil, tls.VersionTLS13, false}, {"wrong_signature", nil, tls.VersionTLS13, false}, {"wrong_key_type", nil, tls.VersionTLS13, false}, {"tls12", nil, tls.VersionTLS12, false},
	}
	good := fixtureCert(t, &allowed.PublicKey, allowed)
	bad := fixtureCert(t, &unknown.PublicKey, unknown)
	forged := fixtureCert(t, &allowed.PublicKey, unknown)
	ecc := fixtureCert(t, &ec.PublicKey, ec)
	cases[0].cert = &good
	cases[1].cert = &bad
	cases[3].cert = &forged
	cases[4].cert = &ecc
	cases[5].cert = &good
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Test client intentionally skips server PKI validation, as stock adb does.
			cc := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12, MaxVersion: tc.max}
			if tc.cert != nil {
				cc.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return tc.cert, nil }
			}
			err := handshakeResult(t, conf, cc)
			if (err == nil) != tc.want {
				t.Fatalf("server handshake result = %v; want success=%v", err, tc.want)
			}
		})
	}
}
