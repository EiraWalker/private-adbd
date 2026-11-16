package security

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"math/big"
	"strings"
	"testing"
)

func androidKey(t *testing.T, k *rsa.PublicKey) string {
	t.Helper()
	b := make([]byte, 524)
	binary.LittleEndian.PutUint32(b, 64)
	n := k.N.Bytes()
	for i := range n {
		b[8+i] = n[len(n)-1-i]
	}
	low := new(big.Int).SetUint64(uint64(binary.LittleEndian.Uint32(b[8:])))
	inv := new(big.Int).ModInverse(low, new(big.Int).Lsh(big.NewInt(1), 32))
	binary.LittleEndian.PutUint32(b[4:], uint32(-inv.Int64()))
	rr := new(big.Int).Exp(big.NewInt(2), big.NewInt(4096), k.N).Bytes()
	for i := range rr {
		b[264+i] = rr[len(rr)-1-i]
	}
	binary.LittleEndian.PutUint32(b[520:], uint32(k.E))
	return base64.StdEncoding.EncodeToString(b) + " test@fixture"
}
func TestParseOnlyExactAndroidRSAKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pub := androidKey(t, &key.PublicKey)
	keys, err := ParseKeys([]byte(pub + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !keys.Allows(&key.PublicKey) {
		t.Fatal("authorized RSA key rejected")
	}
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	if keys.Allows(&other.PublicKey) {
		t.Fatal("unknown RSA accepted")
	}
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if len(keys.Fingerprints()) != 1 || len(der) == 0 {
		t.Fatal("fingerprint inventory missing")
	}
	for _, bad := range []string{"", "\n", "junk", pub + "\n" + pub, strings.Repeat("A", 100000)} {
		if _, err := ParseKeys([]byte(bad)); err == nil {
			t.Fatalf("bad key input accepted, length %d", len(bad))
		}
	}
	blob, _ := base64.StdEncoding.DecodeString(strings.Fields(pub)[0])
	blob[0] = 63
	if _, err := ParseKeys([]byte(base64.StdEncoding.EncodeToString(blob))); err == nil {
		t.Fatal("bad modulus word count accepted")
	}
}
