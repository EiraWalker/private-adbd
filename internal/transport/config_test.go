package transport

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"
)

func TestRefuseUnauthenticatedTLSConfig(t *testing.T) {
	sc, _ := fixture(t)
	sc.ClientAuth = tls.NoClientCert
	sc.VerifyConnection = nil
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	s := &Server{TLSConfig: sc, Banner: "device::features=shell_v2", Handler: func(context.Context, string, io.ReadWriteCloser) error { return nil }}
	if e = s.Serve(ctx, l); e == nil {
		t.Fatal("unsafe TLS config accepted")
	}
}
