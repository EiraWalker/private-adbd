package transport

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"testing"
)

func tlsClient(t *testing.T, c net.Conn, cc *tls.Config) *tls.Conn {
	t.Helper()
	tc := tls.Client(c, cc)
	if e := tc.Handshake(); e != nil {
		t.Fatal(e)
	}
	return tc
}
func TestPeerPayloadLimitSplitsWrites(t *testing.T) {
	sc, cc := fixture(t)
	s := &Server{TLSConfig: sc, Banner: "device::features=shell_v2", Handler: func(_ context.Context, _ string, rw io.ReadWriteCloser) error {
		_, e := rw.Write(make([]byte, 2049))
		return e
	}}
	addr, _, _ := launch(t, s)
	c := raw(t, addr)
	put(c, frame{tCNXN, tVersion, 1024, []byte("host::")})
	if _, e := get(c); e != nil {
		t.Fatal(e)
	}
	put(c, frame{cmd: tSTLS, a: 0x01000000})
	tc := tlsClient(t, c, cc)
	if _, e := get(tc); e != nil {
		t.Fatal(e)
	}
	put(tc, frame{tOPEN, 7, 0, []byte("output:")})
	p, e := get(tc)
	if e != nil {
		t.Fatal(e)
	}
	id := p.a
	for _, want := range []int{1024, 1024, 1} {
		p, e = get(tc)
		if e != nil || p.cmd != tWRTE || len(p.data) != want {
			t.Fatalf("payload got=%d want=%d err=%v", len(p.data), want, e)
		}
		put(tc, frame{cmd: tOKAY, a: 7, b: id})
	}
	if p, e = get(tc); e != nil || p.cmd != tCLSE {
		t.Fatalf("close %v %v", p, e)
	}
}
