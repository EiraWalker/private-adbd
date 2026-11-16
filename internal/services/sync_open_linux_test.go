//go:build linux

package services

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestSyncSpecialFileOpenDoesNotBlock(t *testing.T) {
	for _, operation := range []string{"RECV", "LIST"} {
		for _, link := range []bool{false, true} {
			name := operation + "/fifo"
			if link {
				name += "-symlink"
			}
			t.Run(name, func(t *testing.T) {
				fifo := filepath.Join(t.TempDir(), "fifo")
				if err := syscall.Mkfifo(fifo, 0600); err != nil {
					if _, android := os.Stat("/system/bin/getprop"); android == nil && (err == syscall.EACCES || err == syscall.EPERM) {
						t.Skipf("namedFIFO creation forbidden on Android: %v (product path not exercised)", err)
					}
					t.Fatal(err)
				}
				path := fifo
				if link {
					path += "-link"
					if err := os.Symlink(fifo, path); err != nil {
						t.Fatal(err)
					}
				}
				type result struct {
					wire []byte
					err  error
				}
				done := make(chan result, 1)
				go func() {
					var wire bytes.Buffer
					var err error
					if operation == "RECV" {
						err = syncRecv(context.Background(), &wire, path)
					} else {
						err = syncList(&wire, path)
					}
					done <- result{wire.Bytes(), err}
				}()
				select {
				case got := <-done:
					if operation == "RECV" {
						if got.err == nil || !bytes.HasPrefix(got.wire, []byte("FAIL")) {
							t.Fatalf("special RECV accepted: %q %v", got.wire, got.err)
						}
					} else {
						var want bytes.Buffer
						syncWords(&want, "DONE", 0, 0, 0, 0)
						if got.err != nil || !bytes.Equal(got.wire, want.Bytes()) {
							t.Fatalf("LIST non-directory response: %q %v", got.wire, got.err)
						}
					}
				case <-time.After(300 * time.Millisecond):
					// Release the buggy blocking open, then reap it before reporting RED.
					fd, err := syscall.Open(fifo, syscall.O_RDWR|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
					if err != nil {
						t.Fatal(err)
					}
					defer syscall.Close(fd)
					select {
					case <-done:
					case <-time.After(time.Second):
						t.Fatal("FIFO cleanup did not finish")
					}
					t.Fatal("opening FIFO blocked without a writer")
				}
			})
		}
	}
}

func TestSyncReadFollowsRegularAndDirectorySymlinks(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, []byte("payload"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{file, dir} {
		link := filepath.Join(t.TempDir(), "link")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		var got, want bytes.Buffer
		if target == file {
			if err := syncRecv(context.Background(), &got, link); err != nil {
				t.Fatal(err)
			}
			syncWords(&want, "DATA", 7)
			want.WriteString("payload")
			syncWords(&want, "DONE", 0)
		} else {
			if err := syncList(&got, link); err != nil {
				t.Fatal(err)
			}
			if err := syncList(&want, dir); err != nil {
				t.Fatal(err)
			}
			if !bytes.HasPrefix(got.Bytes(), []byte("DENT")) {
				t.Fatal("directory symlink lost its entries")
			}
		}
		if !bytes.Equal(got.Bytes(), want.Bytes()) {
			t.Fatalf("symlink read mismatch: %q != %q", got.Bytes(), want.Bytes())
		}
	}
}
