package transport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"net"
	"testing"
	"time"
)

const (
	tCNXN    = 0x4e584e43
	tSTLS    = 0x534c5453
	tOPEN    = 0x4e45504f
	tOKAY    = 0x59414b4f
	tWRTE    = 0x45545257
	tCLSE    = 0x45534c43
	tAUTH    = 0x48545541
	tVersion = 0x01000001
)

type frame struct {
	cmd, a, b uint32
	data      []byte
}

func put(w io.Writer, p frame) error {
	h := make([]byte, 24)
	words := []uint32{p.cmd, p.a, p.b, uint32(len(p.data)), 0, ^p.cmd}
	for _, b := range p.data {
		words[4] += uint32(b)
	}
	for i, v := range words {
		binary.LittleEndian.PutUint32(h[i*4:], v)
	}
	_, e := w.Write(append(h, p.data...))
	return e
}
func get(r io.Reader) (frame, error) {
	h := make([]byte, 24)
	if _, e := io.ReadFull(r, h); e != nil {
		return frame{}, e
	}
	p := frame{cmd: binary.LittleEndian.Uint32(h), a: binary.LittleEndian.Uint32(h[4:]), b: binary.LittleEndian.Uint32(h[8:])}
	n := binary.LittleEndian.Uint32(h[12:])
	if n > 65536 {
		return p, errors.New("oversize server packet")
	}
	if binary.LittleEndian.Uint32(h[20:]) != ^p.cmd {
		return p, errors.New("magic")
	}
	p.data = make([]byte, n)
	_, e := io.ReadFull(r, p.data)
	return p, e
}
func cert(t *testing.T) tls.Certificate {
	t.Helper()
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}, DNSNames: []string{"localhost"}}
	der, e := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, key)
	if e != nil {
		t.Fatal(e)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
func fixture(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	server, client := cert(t), cert(t)
	sc := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{server}, ClientAuth: tls.RequireAnyClientCert, VerifyConnection: func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) != 1 || !bytes.Equal(cs.PeerCertificates[0].Raw, client.Certificate[0]) {
			return errors.New("not authorized")
		}
		return nil
	}}
	cc := &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true, Certificates: []tls.Certificate{client}}
	return sc, cc
}
func launch(t *testing.T, s *Server) (string, context.CancelFunc, <-chan error) {
	t.Helper()
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, l) }()
	t.Cleanup(func() {
		cancel()
		l.Close()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("Serve leaked during shutdown")
		}
	})
	return l.Addr().String(), cancel, done
}
func raw(t *testing.T, addr string) net.Conn {
	t.Helper()
	c, e := net.DialTimeout("tcp", addr, time.Second)
	if e != nil {
		t.Fatal(e)
	}
	c.SetDeadline(time.Now().Add(3 * time.Second))
	t.Cleanup(func() { c.Close() })
	return c
}
func upgrade(t *testing.T, c net.Conn, cfg *tls.Config) *tls.Conn {
	t.Helper()
	if e := put(c, frame{tCNXN, tVersion, 1024 * 1024, []byte("host::features=shell_v2,cmd,delayed_ack")}); e != nil {
		t.Fatal(e)
	}
	p, e := get(c)
	if e != nil {
		t.Fatalf("STLS request missing: %v", e)
	}
	if p.cmd != tSTLS || p.a != 0x01000000 || p.b != 0 || len(p.data) != 0 {
		t.Fatalf("bad STLS: %+v", p)
	}
	if e := put(c, frame{cmd: tSTLS, a: 0x01000000}); e != nil {
		t.Fatal(e)
	}
	tc := tls.Client(c, cfg)
	if e := tc.Handshake(); e != nil {
		t.Fatal(e)
	}
	return tc
}
func connected(t *testing.T, addr string, cc *tls.Config) *tls.Conn {
	t.Helper()
	c := upgrade(t, raw(t, addr), cc)
	p, e := get(c)
	if e != nil {
		t.Fatal(e)
	}
	if p.cmd != tCNXN || p.a != tVersion || p.b != 65536 || string(p.data) != "device::features=shell_v2" {
		t.Fatalf("bad CNXN: %+v", p)
	}
	return c
}
func TestTLSUpgradeOrder(t *testing.T) {
	sc, cc := fixture(t)
	s := &Server{TLSConfig: sc, Banner: "device::features=shell_v2", Handler: func(context.Context, string, io.ReadWriteCloser) error { return nil }}
	addr, _, _ := launch(t, s)
	c := connected(t, addr, cc)
	if c.ConnectionState().Version != tls.VersionTLS13 {
		t.Fatal("not TLS1.3")
	}
}
