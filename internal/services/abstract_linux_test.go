//go:build linux

package services

import (
	"fmt"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

func TestAbstractSocketActualBidirectionalDial(t *testing.T) {
	name := fmt.Sprintf("scrcpy_test_%d_%d", os.Getpid(), time.Now().UnixNano())
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: "\x00" + name, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan error, 1)
	go func() {
		conn, err := listener.AcceptUnix()
		if err != nil {
			accepted <- err
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		p := make([]byte, 4)
		_, err = io.ReadFull(conn, p)
		if err == nil && string(p) != "ping" {
			err = fmt.Errorf("got %q", p)
		}
		if err == nil {
			_, err = conn.Write([]byte("pong"))
		}
		accepted <- err
	}()
	s, done, _ := startService(t, hostConfig(t), "localabstract:"+name)
	if _, err = s.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	if p := readExact(t, s, 4); string(p) != "pong" {
		t.Fatalf("got %q", p)
	}
	if err = <-accepted; err != nil {
		t.Fatal(err)
	}
	if err = await(t, done); err != nil {
		t.Fatal(err)
	}
}
