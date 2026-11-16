package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"sync/atomic"
	"testing"
	"time"
)

func TestInvalidInitialVersionRejected(t *testing.T) {
	sc, _ := fixture(t)
	s := &Server{TLSConfig: sc, Banner: "device::features=shell_v2", Handler: func(context.Context, string, io.ReadWriteCloser) error { return nil }}
	addr, _, _ := launch(t, s)
	c := raw(t, addr)
	put(c, frame{tCNXN, 7, 65536, []byte("host::")})
	if p, e := get(c); e == nil {
		t.Fatalf("invalid version accepted: %x", p.cmd)
	}
}
func TestUnauthorizedOpenNeverDispatched(t *testing.T) {
	for _, mode := range []string{"plain-open", "auth-fallback", "after-stls", "unknown-certificate", "no-certificate", "tls12"} {
		t.Run(mode, func(t *testing.T) {
			sc, cc := fixture(t)
			var calls atomic.Int32
			s := &Server{TLSConfig: sc, Banner: "device::features=shell_v2", Handler: func(context.Context, string, io.ReadWriteCloser) error { calls.Add(1); return nil }}
			addr, _, _ := launch(t, s)
			c := raw(t, addr)
			switch mode {
			case "plain-open":
				put(c, frame{tOPEN, 1, 0, []byte("shell:id\x00")})
			case "auth-fallback":
				put(c, frame{tAUTH, 3, 0, []byte("untrusted")})
			default:
				put(c, frame{tCNXN, tVersion, 65536, []byte("host::")})
				p, e := get(c)
				if e != nil || p.cmd != tSTLS {
					t.Fatalf("no stls: %v", e)
				}
				if mode == "after-stls" {
					put(c, frame{tOPEN, 1, 0, []byte("shell:id\x00")})
					break
				}
				put(c, frame{cmd: tSTLS, a: 0x01000000})
				if mode == "unknown-certificate" {
					cc.Certificates = []tls.Certificate{cert(t)}
				}
				if mode == "no-certificate" {
					cc.Certificates = nil
				}
				if mode == "tls12" {
					cc.MinVersion = tls.VersionTLS12
					cc.MaxVersion = tls.VersionTLS12
				}
				tc := tls.Client(c, cc)
				if e := tc.Handshake(); e == nil {
					put(tc, frame{tOPEN, 1, 0, []byte("shell:id\x00")})
					if p, e := get(tc); e == nil {
						t.Fatalf("unauthorized response: %x", p.cmd)
					}
				}
			}
			c.SetReadDeadline(time.Now().Add(time.Second))
			if _, e := get(c); e == nil || isTimeout(e) {
				t.Fatalf("connection not rejected: %v", e)
			}
			if calls.Load() != 0 {
				t.Fatal("unauthorized dispatch")
			}
		})
	}
}
func TestMalformedPacketsFailClosed(t *testing.T) {
	for _, mode := range []string{"magic", "oversize", "unknown", "wrong-id", "okay-data", "open-zero", "open-credit", "open-nul", "duplicate-open", "double-write"} {
		t.Run(mode, func(t *testing.T) {
			sc, cc := fixture(t)
			s := &Server{TLSConfig: sc, Banner: "device::features=shell_v2", Handler: func(ctx context.Context, _ string, _ io.ReadWriteCloser) error { <-ctx.Done(); return ctx.Err() }}
			addr, _, _ := launch(t, s)
			c := connected(t, addr, cc)
			put(c, frame{tOPEN, 3, 0, []byte("wait:")})
			p, e := get(c)
			if e != nil {
				t.Fatal(e)
			}
			id := p.a
			switch mode {
			case "magic", "oversize":
				var b bytes.Buffer
				put(&b, frame{cmd: tWRTE, a: 3, b: id})
				h := b.Bytes()
				if mode == "magic" {
					h[20] ^= 1
				} else {
					binary.LittleEndian.PutUint32(h[12:], 65537)
				}
				c.Write(h)
			case "unknown":
				put(c, frame{cmd: 0x99999999})
			case "wrong-id":
				put(c, frame{tWRTE, 9, id, []byte("x")})
			case "okay-data":
				put(c, frame{tOKAY, 3, id, []byte("x")})
			case "open-zero":
				put(c, frame{tOPEN, 0, 0, []byte("wait:")})
			case "open-credit":
				put(c, frame{tOPEN, 4, 1024, []byte("wait:")})
			case "open-nul":
				put(c, frame{tOPEN, 4, 0, []byte("wait:\x00bad")})
			case "duplicate-open":
				put(c, frame{tOPEN, 3, 0, []byte("wait:")})
			case "double-write":
				put(c, frame{tWRTE, 3, id, []byte("a")})
				put(c, frame{tWRTE, 3, id, []byte("b")})
			}
			c.SetReadDeadline(time.Now().Add(time.Second))
			if _, e = get(c); e == nil || isTimeout(e) {
				t.Fatalf("malformed input not closed: %v", e)
			}
		})
	}
}
