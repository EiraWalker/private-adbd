//go:build linux

package services

import (
	"context"
	"io"
	"net"
)

func runAbstract(ctx context.Context, name string, stream io.ReadWriteCloser) error {
	if err := validateAbstractName(name); err != nil {
		return err
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", "\x00"+name)
	if err != nil {
		return err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close(); stream.Close() })
	defer stop()
	done := make(chan error, 2)
	go func() { _, e := io.Copy(conn, stream); done <- e }()
	go func() { _, e := io.Copy(stream, conn); done <- e }()
	err = <-done
	conn.Close()
	stream.Close()
	<-done
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}
