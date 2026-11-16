//go:build !linux

package services

import (
	"context"
	"errors"
	"io"
)

func runAbstract(_ context.Context, name string, _ io.ReadWriteCloser) error {
	if err := validateAbstractName(name); err != nil {
		return err
	}
	return errors.New("Unix abstract sockets require Linux/Android")
}
