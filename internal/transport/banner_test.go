package transport

import (
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestRefuseUnsafeBanner(t *testing.T) {
	for _, banner := range []string{"", "host::features=shell_v2", "device::features=delayed_ack", "device::features=shell_v2,delayed_ack", "device::x=\x00bad", "device::" + strings.Repeat("x", 4096)} {
		t.Run("invalid-banner", func(t *testing.T) {
			sc, _ := fixture(t)
			s := &Server{TLSConfig: sc, Banner: banner, Handler: func(context.Context, string, io.ReadWriteCloser) error { return nil }}
			l, e := net.Listen("tcp4", "127.0.0.1:0")
			if e != nil {
				t.Fatal(e)
			}
			defer l.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			defer cancel()
			if e = s.Serve(ctx, l); e == nil {
				t.Fatal("unsafe banner accepted")
			}
		})
	}
}
