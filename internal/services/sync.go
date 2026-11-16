package services

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const maxSyncPath = 1024
const maxSyncName = 255

func syncWords(w io.Writer, id string, words ...uint32) error {
	p := make([]byte, 4+4*len(words))
	copy(p, id)
	for i, n := range words {
		binary.LittleEndian.PutUint32(p[4+i*4:], n)
	}
	return writeAll(w, p)
}
func syncFail(w io.Writer, err error) error {
	msg := err.Error()
	if len(msg) > 1024 {
		msg = msg[:1024]
	}
	if e := syncWords(w, "FAIL", uint32(len(msg))); e != nil {
		return e
	}
	if e := writeAll(w, []byte(msg)); e != nil {
		return e
	}
	return err
}
func syncReadHeader(r io.Reader) (string, uint32, error) {
	var h [8]byte
	_, err := io.ReadFull(r, h[:])
	return string(h[:4]), binary.LittleEndian.Uint32(h[4:]), err
}
func syncMode(info os.FileInfo) uint32 {
	m := uint32(info.Mode().Perm())
	switch {
	case info.Mode().IsRegular():
		m |= 0100000
	case info.IsDir():
		m |= 0040000
	case info.Mode()&os.ModeSymlink != 0:
		m |= 0120000
	case info.Mode()&os.ModeNamedPipe != 0:
		m |= 0010000
	case info.Mode()&os.ModeSocket != 0:
		m |= 0140000
	case info.Mode()&os.ModeDevice != 0:
		if info.Mode()&os.ModeCharDevice != 0 {
			m |= 0020000
		} else {
			m |= 0060000
		}
	}
	return m
}
func syncPath(c Config, path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(c.WorkingDir, path)
}

func runSync(ctx context.Context, c Config, stream io.ReadWriteCloser) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		id, n, err := syncReadHeader(stream)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if n > maxSyncPath {
			return syncFail(stream, errors.New("sync path exceeds 1024 bytes"))
		}
		p := make([]byte, n)
		if _, err = io.ReadFull(stream, p); err != nil {
			return err
		}
		path := string(p)
		if strings.ContainsRune(path, 0) {
			return syncFail(stream, errors.New("NUL in sync path"))
		}
		if id == "QUIT" {
			if n != 0 {
				return syncFail(stream, errors.New("QUIT path must be empty"))
			}
			return nil
		}
		pathSpec := path
		path = syncPath(c, path)
		switch id {
		case "SEND":
			err = syncSend(ctx, c, stream, pathSpec)
		case "RECV":
			err = syncRecv(ctx, stream, path)
		case "STAT":
			info, e := os.Lstat(path)
			if e != nil {
				err = syncWords(stream, "STAT", 0, 0, 0)
			} else {
				err = syncWords(stream, "STAT", syncMode(info), uint32(info.Size()), uint32(info.ModTime().Unix()))
			}
		case "LIST":
			err = syncList(stream, path)
		default:
			return syncFail(stream, fmt.Errorf("unsupported sync command %q", id))
		}
		if err != nil {
			return err
		}
	}
}
func syncList(w io.Writer, path string) error {
	f, err := openSyncRead(path, true)
	if err == nil {
		defer f.Close()
		for {
			entries, e := f.ReadDir(64)
			for _, entry := range entries {
				if len(entry.Name()) > maxSyncName {
					return syncFail(w, errors.New("directory name exceeds 255 bytes"))
				}
				info, e := entry.Info()
				if e != nil {
					continue
				}
				if e = syncWords(w, "DENT", syncMode(info), uint32(info.Size()), uint32(info.ModTime().Unix()), uint32(len(entry.Name()))); e != nil {
					return e
				}
				if e = writeAll(w, []byte(entry.Name())); e != nil {
					return e
				}
			}
			if e != nil {
				if !errors.Is(e, io.EOF) {
					return syncFail(w, e)
				}
				break
			}
		}
	}
	return syncWords(w, "DONE", 0, 0, 0, 0)
}
