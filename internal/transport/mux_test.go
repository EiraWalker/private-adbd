package transport

import (
	"bytes"
	"context"
	"io"
	"testing"
	"time"
)

func TestMuxEcho64KiBAndClose(t *testing.T) {
	sc, cc := fixture(t)
	called := make(chan string, 1)
	s := &Server{TLSConfig: sc, Banner: "device::features=shell_v2", Handler: func(ctx context.Context, service string, rw io.ReadWriteCloser) error {
		called <- service
		buf := make([]byte, 65536)
		_, e := io.ReadFull(rw, buf)
		if e != nil {
			return e
		}
		_, e = rw.Write(buf)
		return e
	}}
	addr, _, _ := launch(t, s)
	c := connected(t, addr, cc)
	put(c, frame{tOPEN, 41, 0, []byte("echo:\x00")})
	p, e := get(c)
	if e != nil {
		t.Fatalf("OPEN not acknowledged: %v", e)
	}
	if p.cmd != tOKAY || p.a == 0 || p.b != 41 {
		t.Fatalf("bad OPEN ack: %+v", p)
	}
	local := p.a
	data := bytes.Repeat([]byte{0x9b}, 65536)
	put(c, frame{tWRTE, 41, local, data})
	p, e = get(c)
	if e != nil || p.cmd != tOKAY {
		t.Fatalf("WRTE not acknowledged: %+v %v", p, e)
	}
	p, e = get(c)
	if e != nil || p.cmd != tWRTE || p.a != local || p.b != 41 || !bytes.Equal(p.data, data) {
		t.Fatalf("echo mismatch: cmd=%x len=%d err=%v", p.cmd, len(p.data), e)
	}
	put(c, frame{cmd: tOKAY, a: 41, b: local})
	p, e = get(c)
	if e != nil || p.cmd != tCLSE {
		t.Fatalf("missing close: %+v %v", p, e)
	}
	put(c, frame{cmd: tCLSE, a: 41, b: local})
	select {
	case service := <-called:
		if service != "echo:" {
			t.Fatalf("service %q", service)
		}
	case <-time.After(time.Second):
		t.Fatal("handler missing")
	}
}
