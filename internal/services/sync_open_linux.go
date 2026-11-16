//go:build linux

package services

import (
	"os"
	"syscall"
)

// Follow symlinks, but never wait for a FIFO peer before inspecting the fd.
// RECV checks that the opened fd is regular; LIST enforces directory at open.
func openSyncRead(path string, directory bool) (*os.File, error) {
	flags := os.O_RDONLY | syscall.O_NONBLOCK
	if directory {
		flags |= syscall.O_DIRECTORY
	}
	return os.OpenFile(path, flags, 0)
}
