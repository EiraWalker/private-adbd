// Package security owns the fail-closed, immutable controller public-key policy.
package security

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math/big"
	"sort"
	"strings"
)

// Keys is an immutable set of exact RSA SubjectPublicKeyInfo hashes. No key is
// enrolled by a network request, and comments have no authorization meaning.
type Keys struct{ allowed map[[32]byte]struct{} }

// ParseKeys accepts Android adbkey.pub lines, not SSH keys or certificates.
// Broken and duplicate entries abort startup; an empty store never allows all.
func ParseKeys(data []byte) (*Keys, error) {
	if len(data) > 8192 {
		return nil, errors.New("public-key store too large")
	}
	k := &Keys{allowed: make(map[[32]byte]struct{})}
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}
		b, err := base64.StdEncoding.Strict().DecodeString(parts[0])
		if err != nil || len(b) != 524 || binary.LittleEndian.Uint32(b) != 64 {
			return nil, errors.New("invalid Android RSA public key")
		}
		nbytes := bytes.Clone(b[8:264])
		for i, j := 0, len(nbytes)-1; i < j; i, j = i+1, j-1 {
			nbytes[i], nbytes[j] = nbytes[j], nbytes[i]
		}
		n := new(big.Int).SetBytes(nbytes)
		e := binary.LittleEndian.Uint32(b[520:])
		if n.BitLen() != 2048 || n.Bit(0) != 1 || e != 65537 {
			return nil, errors.New("requires 2048-bit RSA, exponent 65537")
		}
		pk := &rsa.PublicKey{N: n, E: int(e)}
		der, err := x509.MarshalPKIXPublicKey(pk)
		if err != nil {
			return nil, err
		}
		fp := sha256.Sum256(der)
		if _, ok := k.allowed[fp]; ok {
			return nil, errors.New("duplicate controller public key")
		}
		k.allowed[fp] = struct{}{}
		if len(k.allowed) > 2 {
			return nil, errors.New("at most two controller keys are allowed")
		}
	}
	if len(k.allowed) == 0 {
		return nil, errors.New("no authorized controller keys")
	}
	return k, nil
}

// Allows matches only the full RSA public key, never subject names, dates,
// certificate signatures alone, modulus size alone, or parsing error codes.
func (k *Keys) Allows(key crypto.PublicKey) bool {
	rsaKey, ok := key.(*rsa.PublicKey)
	if !ok || k == nil {
		return false
	}
	if rsaKey == nil || rsaKey.N == nil || rsaKey.N.BitLen() != 2048 || rsaKey.E != 65537 {
		return false
	}
	der, err := x509.MarshalPKIXPublicKey(rsaKey)
	if err != nil {
		return false
	}
	_, ok = k.allowed[sha256.Sum256(der)]
	return ok
}
func (k *Keys) Fingerprints() []string {
	out := make([]string, 0, len(k.allowed))
	for fp := range k.allowed {
		out = append(out, hex.EncodeToString(fp[:]))
	}
	sort.Strings(out)
	return out
}
