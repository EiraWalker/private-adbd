package services

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// SEND stages in the destination directory. Incomplete uploads never truncate or
// remove an old destination; only our unique temporary file is cleaned up.
func syncSend(ctx context.Context, c Config, s io.ReadWriter, spec string) error {
	comma := strings.LastIndexByte(spec, ',')
	if comma <= 0 {
		return syncFail(s, errors.New("SEND requires path,mode"))
	}
	path := syncPath(c, spec[:comma])
	mode, err := strconv.ParseUint(spec[comma+1:], 0, 32)
	if err != nil {
		return syncFail(s, errors.New("invalid SEND mode"))
	}
	if kind := mode & 0170000; kind != 0 && kind != 0100000 {
		return syncFail(s, errors.New("SEND supports regular files only"))
	}
	if len(filepath.Base(path)) > maxSyncName {
		return syncFail(s, errors.New("filename exceeds 255 bytes"))
	}
	if info, e := os.Lstat(path); e == nil {
		if !info.Mode().IsRegular() {
			return syncFail(s, errors.New("SEND destination is not a regular file"))
		}
		// Do not use writable directory permissions to bypass a read-only file.
		f, e := os.OpenFile(path, os.O_WRONLY, 0)
		if e != nil {
			return syncFail(s, e)
		}
		f.Close()
	} else if !errors.Is(e, os.ErrNotExist) {
		return syncFail(s, e)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// Directory creation uses only the daemon's shell credentials and umask.
	// Never remove these directories on cancellation: other uploads/users may
	// already own entries in them. Only our unique staged file is disposable.
	if err := os.MkdirAll(filepath.Dir(path), 0775); err != nil {
		return syncFail(s, err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".privateadb-upload-*")
	if err != nil {
		return syncFail(s, err)
	}
	temp := f.Name()
	defer func() { f.Close(); os.Remove(temp) }()
	var buf [maxChunk]byte
	for {
		if err = ctx.Err(); err != nil {
			return err
		}
		id, n, e := syncReadHeader(s)
		if e != nil {
			return e
		}
		if id == "DONE" {
			if e = f.Chmod(os.FileMode(mode) & 0777); e != nil {
				return syncFail(s, e)
			}
			stamp := time.Unix(int64(n), 0)
			if e = os.Chtimes(temp, stamp, stamp); e != nil {
				return syncFail(s, e)
			}
			if e = f.Close(); e != nil {
				return syncFail(s, e)
			}
			if e = ctx.Err(); e != nil {
				return e
			}
			if e = os.Rename(temp, path); e != nil {
				return syncFail(s, e)
			}
			return syncWords(s, "OKAY", 0)
		}
		if id != "DATA" || n > maxChunk {
			return syncFail(s, errors.New("invalid or oversized SEND DATA"))
		}
		if _, e = io.ReadFull(s, buf[:n]); e != nil {
			return e
		}
		if e = writeAll(f, buf[:n]); e != nil {
			return syncFail(s, e)
		}
	}
}
func syncRecv(ctx context.Context, s io.Writer, path string) error {
	f, err := openSyncRead(path, false)
	if err != nil {
		return syncFail(s, err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return syncFail(s, err)
	}
	if !info.Mode().IsRegular() {
		return syncFail(s, errors.New("RECV supports regular files only"))
	}
	var buf [maxChunk]byte
	for {
		if err = ctx.Err(); err != nil {
			return err
		}
		n, e := f.Read(buf[:])
		if n > 0 {
			if err = syncWords(s, "DATA", uint32(n)); err != nil {
				return err
			}
			if err = writeAll(s, buf[:n]); err != nil {
				return err
			}
		}
		if errors.Is(e, io.EOF) {
			return syncWords(s, "DONE", 0)
		}
		if e != nil {
			return syncFail(s, e)
		}
	}
}
