package transport

import (
	"context"
	"io"
	"testing"
	"time"
)

func TestStreamLimitIncludesCancelingHandlers(t *testing.T) {
	sc, cc := fixture(t)
	release := make(chan struct{})
	started := make(chan struct{}, 1)
	s := &Server{TLSConfig: sc, Banner: "device::features=shell_v2", MaxStreams: 1, Handler: func(ctx context.Context, _ string, _ io.ReadWriteCloser) error {
		started <- struct{}{}
		<-ctx.Done()
		<-release
		return nil
	}}
	addr, _, _ := launch(t, s)
	defer close(release)
	c := connected(t, addr, cc)
	put(c, frame{tOPEN, 1, 0, []byte("wait:")})
	p, e := get(c)
	if e != nil {
		t.Fatal(e)
	}
	id := p.a
	<-started
	put(c, frame{tOPEN, 2, 0, []byte("wait:")})
	p, e = get(c)
	if e != nil || p.cmd != tCLSE || p.a != 0 || p.b != 2 {
		t.Fatalf("active stream limit: %+v %v", p, e)
	}
	put(c, frame{cmd: tCLSE, a: 1, b: id})
	p, e = get(c)
	if e != nil || p.cmd != tCLSE {
		t.Fatal("no close")
	}
	put(c, frame{tOPEN, 3, 0, []byte("wait:")})
	p, e = get(c)
	if e != nil || p.cmd != tCLSE || p.a != 0 || p.b != 3 {
		t.Fatalf("canceling handler bypassed stream limit: %+v %v", p, e)
	}
}
func TestBackpressureAndIndependentStreams(t *testing.T) {
	sc, cc := fixture(t)
	readGate := make(chan struct{})
	defer close(readGate)
	s := &Server{TLSConfig: sc, Banner: "device::features=shell_v2", Handler: func(ctx context.Context, service string, rw io.ReadWriteCloser) error {
		if service == "slow:" {
			select {
			case <-readGate:
			case <-ctx.Done():
				return ctx.Err()
			}
			b := make([]byte, 3)
			_, e := io.ReadFull(rw, b)
			return e
		}
		_, e := rw.Write([]byte("fast"))
		return e
	}}
	addr, _, _ := launch(t, s)
	c := connected(t, addr, cc)
	put(c, frame{tOPEN, 1, 0, []byte("slow:")})
	p, _ := get(c)
	slow := p.a
	put(c, frame{tWRTE, 1, slow, []byte("abc")})
	put(c, frame{tOPEN, 2, 0, []byte("fast:")})
	p, e := get(c)
	if e != nil || p.cmd != tOKAY || p.b != 2 {
		t.Fatalf("slow stream blocked fast: %+v %v", p, e)
	}
	fast := p.a
	p, e = get(c)
	if e != nil || p.cmd != tWRTE || string(p.data) != "fast" {
		t.Fatalf("fast write: %+v %v", p, e)
	}
	c.SetReadDeadline(time.Now().Add(80 * time.Millisecond))
	if p, e = get(c); !isTimeout(e) {
		t.Fatalf("unconsumed WRTE or unacknowledged write progressed: %+v %v", p, e)
	}
	c.SetReadDeadline(time.Now().Add(time.Second))
	put(c, frame{cmd: tOKAY, a: 2, b: fast})
	if p, e = get(c); e != nil || p.cmd != tCLSE || p.b != 2 {
		t.Fatalf("fast close: %+v %v", p, e)
	}
}
func TestCancellationUnblocksStreamIO(t *testing.T) {
	for _, mode := range []string{"read", "write"} {
		t.Run(mode, func(t *testing.T) {
			sc, cc := fixture(t)
			started := make(chan struct{})
			finished := make(chan struct{})
			s := &Server{TLSConfig: sc, Banner: "device::features=shell_v2", Handler: func(_ context.Context, _ string, rw io.ReadWriteCloser) error {
				defer close(finished)
				close(started)
				if mode == "read" {
					_, e := rw.Read(make([]byte, 1))
					return e
				}
				_, e := rw.Write([]byte("unacked"))
				return e
			}}
			addr, cancel, _ := launch(t, s)
			c := connected(t, addr, cc)
			put(c, frame{tOPEN, 1, 0, []byte("io:")})
			if _, e := get(c); e != nil {
				t.Fatal(e)
			}
			<-started
			if mode == "write" {
				if _, e := get(c); e != nil {
					t.Fatal(e)
				}
			}
			cancel()
			select {
			case <-finished:
			case <-time.After(time.Second):
				t.Fatal("stream IO leaked on cancellation")
			}
		})
	}
}
func TestHandshakeReadDeadline(t *testing.T) {
	if testing.Short() {
		t.Skip("real 10 second deadline")
	}
	sc, _ := fixture(t)
	s := &Server{TLSConfig: sc, Banner: "device::features=shell_v2", Handler: func(context.Context, string, io.ReadWriteCloser) error { return nil }}
	addr, _, _ := launch(t, s)
	c := raw(t, addr)
	c.SetDeadline(time.Now().Add(12 * time.Second))
	start := time.Now()
	var b [1]byte
	_, e := c.Read(b[:])
	elapsed := time.Since(start)
	if e == nil || isTimeout(e) || elapsed < 9*time.Second || elapsed > 12*time.Second {
		t.Fatalf("deadline elapsed=%s err=%v", elapsed, e)
	}
}
