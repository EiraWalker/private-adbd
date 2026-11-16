package services

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func syncRequest(t *testing.T, w io.Writer, id, path string) {
	t.Helper()
	h := make([]byte, 8+len(path))
	copy(h, id)
	binary.LittleEndian.PutUint32(h[4:], uint32(len(path)))
	copy(h[8:], path)
	if _, err := w.Write(h); err != nil {
		t.Fatal(err)
	}
}
func readExact(t *testing.T, r io.Reader, n int) []byte {
	t.Helper()
	p := make([]byte, n)
	if _, err := io.ReadFull(r, p); err != nil {
		t.Fatal(err)
	}
	return p
}
func syncHeader(t *testing.T, r io.Reader) (string, uint32) {
	p := readExact(t, r, 8)
	return string(p[:4]), binary.LittleEndian.Uint32(p[4:])
}
func TestSyncStatListActualFilesystem(t *testing.T) {
	c := hostConfig(t)
	path := filepath.Join(c.WorkingDir, "hello.bin")
	if err := os.WriteFile(path, []byte("abc"), 0600); err != nil {
		t.Fatal(err)
	}
	s, done, _ := startService(t, c, "sync:")
	syncRequest(t, s, "STAT", path)
	p := readExact(t, s, 16)
	if string(p[:4]) != "STAT" || binary.LittleEndian.Uint32(p[8:12]) != 3 || binary.LittleEndian.Uint32(p[4:8])&0170000 != 0100000 {
		t.Fatalf("bad stat %x", p)
	}
	syncRequest(t, s, "STAT", path+".missing")
	p = readExact(t, s, 16)
	for _, b := range p[4:] {
		if b != 0 {
			t.Fatalf("missing STAT must be zero: %x", p)
		}
	}
	syncRequest(t, s, "LIST", c.WorkingDir)
	found := false
	for {
		p = readExact(t, s, 20)
		id := string(p[:4])
		if id == "DONE" {
			break
		}
		if id != "DENT" {
			t.Fatalf("LIST id %q", id)
		}
		n := binary.LittleEndian.Uint32(p[16:])
		if n > 255 {
			t.Fatal("oversize name")
		}
		name := string(readExact(t, s, int(n)))
		if name == "hello.bin" {
			found = true
		}
	}
	if !found {
		t.Fatal("LIST omitted real file")
	}
	syncRequest(t, s, "QUIT", "")
	if err := await(t, done); err != nil {
		t.Fatal(err)
	}
}

func TestSyncSendRecvBinaryHashAndTruncate(t *testing.T) {
	c := hostConfig(t)
	path := filepath.Join(c.WorkingDir, "binary.dat")
	data := make([]byte, 2*1024*1024+17)
	for i := range data {
		data[i] = byte(i*37 + 11)
	}
	if err := os.WriteFile(path, bytes.Repeat([]byte{255}, len(data)+8192), 0600); err != nil {
		t.Fatal(err)
	}
	s, done, _ := startService(t, c, "sync:")
	syncRequest(t, s, "SEND", fmt.Sprintf("%s,%d", path, 0100640))
	for offset := 0; offset < len(data); {
		end := offset + 65536
		if end > len(data) {
			end = len(data)
		}
		syncRequest(t, s, "DATA", string(data[offset:end]))
		offset = end
	}
	var h [8]byte
	copy(h[:], "DONE")
	binary.LittleEndian.PutUint32(h[4:], 1700000000)
	if _, err := s.Write(h[:]); err != nil {
		t.Fatal(err)
	}
	id, n := syncHeader(t, s)
	if id != "OKAY" || n != 0 {
		msg := readExact(t, s, int(n))
		t.Fatalf("SEND %s %q", id, msg)
	}
	actual, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, actual) {
		t.Fatalf("SEND not truncated/hash mismatch: got %d want %d", len(actual), len(data))
	}
	syncRequest(t, s, "RECV", path)
	hash := sha256.New()
	var size int64
	for {
		id, n = syncHeader(t, s)
		if id == "DONE" {
			if n != 0 {
				t.Fatal("DONE size")
			}
			break
		}
		if id != "DATA" || n > 65536 {
			t.Fatalf("RECV header %s %d", id, n)
		}
		p := readExact(t, s, int(n))
		hash.Write(p)
		size += int64(n)
	}
	want := sha256.Sum256(data)
	if !bytes.Equal(hash.Sum(nil), want[:]) || size != int64(len(data)) {
		t.Fatalf("RECV hash/size mismatch")
	}
	t.Logf("actual binary SEND/RECV: bytes=%d sha256=%x", size, hash.Sum(nil))
	syncRequest(t, s, "QUIT", "")
	if err := await(t, done); err != nil {
		t.Fatal(err)
	}
}
