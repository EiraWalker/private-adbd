package security

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"
)

func TestADBCertificateRequestIncludesBothExactKeyHints(t *testing.T) {
	a, _ := rsa.GenerateKey(rand.Reader, 2048)
	b, _ := rsa.GenerateKey(rand.Reader, 2048)
	keys, err := ParseKeys([]byte(androidKey(t, &a.PublicKey) + "\n" + androidKey(t, &b.PublicKey)))
	if err != nil {
		t.Fatal(err)
	}
	config, err := keys.TLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	expected := map[string]bool{}
	for _, fp := range keys.Fingerprints() {
		expected[fp] = true
	}
	cert := fixtureCert(t, &a.PublicKey, a)
	seen := false
	client := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13, GetClientCertificate: func(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
		seen = true
		if len(info.AcceptableCAs) != 2 {
			t.Errorf("got %d CA hints; require both existing controller keys", len(info.AcceptableCAs))
		}
		for _, der := range info.AcceptableCAs {
			var rdn pkix.RDNSequence
			rest, e := asn1.Unmarshal(der, &rdn)
			if e != nil || len(rest) != 0 {
				t.Errorf("invalid CA subject DER")
				continue
			}
			var name pkix.Name
			name.FillFromRDNSequence(&rdn)
			if len(name.Organization) != 1 || name.Organization[0] != "AdbKey-0" || !expected[name.CommonName] {
				t.Errorf("bad ADB hint: %+v", name)
			}
			delete(expected, name.CommonName)
		}
		return &cert, nil
	}}
	if err := handshakeResult(t, config, client); err != nil {
		t.Fatal(err)
	}
	if !seen || len(expected) != 0 {
		t.Fatalf("key hints incomplete: callback=%v remaining=%d", seen, len(expected))
	}
}
