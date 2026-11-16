//go:build !linux

package services

import "os"

func openSyncRead(path string, directory bool) (*os.File, error) {
	return os.Open(path)
}
