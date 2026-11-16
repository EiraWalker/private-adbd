package services

import (
	"bytes"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestSyncCanceledUploadPreservesDestinationAndCleansPartial(t *testing.T) {
	for _, existing := range []bool{false, true} {
		t.Run(map[bool]string{true: "old-file", false: "new-file"}[existing], func(t *testing.T) {
			c := hostConfig(t)
			path := filepath.Join(c.WorkingDir, "target")
			old := []byte("untouched original")
			if existing {
				if err := os.WriteFile(path, old, 0600); err != nil {
					t.Fatal(err)
				}
			}
			s, done, cancel := startService(t, c, "sync:")
			syncRequest(t, s, "SEND", path+",33152")
			syncRequest(t, s, "DATA", "new partial")
			cancel()
			await(t, done)
			actual, err := os.ReadFile(path)
			if existing {
				if err != nil || !bytes.Equal(actual, old) {
					t.Fatalf("old data damaged: %q %v", actual, err)
				}
			} else if !os.IsNotExist(err) {
				t.Fatalf("partial destination survived: %v", err)
			}
			entries, err := os.ReadDir(c.WorkingDir)
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				if entry.Name() != "target" {
					t.Fatalf("owned partial leaked: %s", entry.Name())
				}
			}
		})
	}
}
func TestSyncOversizePathRejectedWithoutBody(t *testing.T) {
	s, done, _ := startService(t, hostConfig(t), "sync:")
	var h [8]byte
	copy(h[:], "STAT")
	binary.LittleEndian.PutUint32(h[4:], 1025)
	if _, err := s.Write(h[:]); err != nil {
		t.Fatal(err)
	}
	id, n := syncHeader(t, s)
	if id != "FAIL" || n > 1024 {
		t.Fatalf("bad response %s %d", id, n)
	}
	readExact(t, s, int(n))
	if await(t, done) == nil {
		t.Fatal("oversize path accepted")
	}
}
func TestShellV2ConcurrentFramesStayAtomic(t *testing.T) {
	s, done, _ := startService(t, hostConfig(t), "shell,v2,raw:(i=0; while [ $i -lt 32 ]; do printf O; i=$((i+1)); done) & i=0; while [ $i -lt 32 ]; do printf E >&2; i=$((i+1)); done; wait")
	out, stderr, exit := 0, 0, false
	for {
		id, p, err := readShellFrame(s)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		switch id {
		case 1:
			for _, b := range p {
				if b != 'O' {
					t.Fatalf("corrupt stdout %x", p)
				}
			}
			out += len(p)
		case 2:
			for _, b := range p {
				if b != 'E' {
					t.Fatalf("corrupt stderr %x", p)
				}
			}
			stderr += len(p)
		case 3:
			exit = bytes.Equal(p, []byte{0})
		default:
			t.Fatalf("corrupt frame %d", id)
		}
	}
	if out != 32 || stderr != 32 || !exit {
		t.Fatalf("out=%d err=%d exit=%v", out, stderr, exit)
	}
	if err := await(t, done); err != nil {
		t.Fatal(err)
	}
}
func TestMalformedShellFrameCancelsRealChild(t *testing.T) {
	s, done, _ := startService(t, hostConfig(t), "shell,v2,raw:read x")
	if err := writeShellFrame(s, 7, nil); err != nil {
		t.Fatal(err)
	}
	if await(t, done) == nil {
		t.Fatal("malformed shell frame accepted")
	}
}
