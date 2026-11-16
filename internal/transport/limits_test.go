package transport

import (
	"context"
	"io"
	"testing"
	"time"
)

func TestConnectionLimitRejectsExcess(t *testing.T) {
	sc, _ := fixture(t)
	s := &Server{TLSConfig: sc, Banner: "device::features=shell_v2", MaxConnections: 1, Handler: func(context.Context, string, io.ReadWriteCloser) error { return nil }}
	addr, _, _ := launch(t, s)
	first := raw(t, addr)
	put(first, frame{tCNXN, tVersion, 65536, []byte("host::")})
	if _, e := get(first); e != nil {
		t.Fatal(e)
	}
	second := raw(t, addr)
	second.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	put(second, frame{tCNXN, tVersion, 65536, []byte("host::")})
	if p, e := get(second); e == nil {
		t.Fatalf("excess connection accepted: %x", p.cmd)
	} else if isTimeout(e) {
		t.Fatal("excess connection not closed")
	}
}
func isTimeout(e error) bool { x, ok := e.(interface{ Timeout() bool }); return ok && x.Timeout() }
