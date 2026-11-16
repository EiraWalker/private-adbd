package services

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type reviewSyncBuffer struct {
	*bytes.Reader
	bytes.Buffer
}

func (b *reviewSyncBuffer) Read(p []byte) (int, error)  { return b.Reader.Read(p) }
func (b *reviewSyncBuffer) Write(p []byte) (int, error) { return b.Buffer.Write(p) }
func reviewSend(ctx context.Context, c Config, path string) (string, error) {
	var input bytes.Buffer
	syncWords(&input, "DATA", 3)
	input.WriteString("abc")
	syncWords(&input, "DONE", 1700000000)
	rw := &reviewSyncBuffer{Reader: bytes.NewReader(input.Bytes())}
	err := syncSend(ctx, c, rw, path+",33188")
	return rw.Buffer.String(), err
}
func TestReviewSendCreatesMissingParents(t *testing.T) {
	c := hostConfig(t)
	path := filepath.Join(c.WorkingDir, "missing", "nested", "file.bin")
	response, err := reviewSend(context.Background(), c, path)
	if err != nil || len(response) < 4 || response[:4] != "OKAY" {
		t.Fatalf("nested SEND: %q %v", response, err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "abc" {
		t.Fatalf("payload %q %v", got, err)
	}
}
func TestReviewConcurrentSendParentsAndPathError(t *testing.T) {
	c := hostConfig(t)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			path := filepath.Join(c.WorkingDir, "shared", "nested", fmt.Sprint(i))
			response, err := reviewSend(context.Background(), c, path)
			if err != nil || len(response) < 4 || response[:4] != "OKAY" {
				t.Errorf("concurrent SEND %q %v", response, err)
			}
		}(i)
	}
	wg.Wait()
	blocker := filepath.Join(c.WorkingDir, "blocker")
	if err := os.WriteFile(blocker, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	response, _ := reviewSend(context.Background(), c, filepath.Join(blocker, "nested", "file"))
	if len(response) < 4 || response[:4] != "FAIL" {
		t.Fatalf("path error %q", response)
	}
	got, _ := os.ReadFile(blocker)
	if string(got) != "keep" {
		t.Fatalf("user file changed: %q", got)
	}
}
func TestReviewSendTimeoutKeepsDirectories(t *testing.T) {
	c := hostConfig(t)
	path := filepath.Join(c.WorkingDir, "missing", "nested", "file.bin")
	s, done, cancel := startService(t, c, "sync:")
	defer cancel()
	syncRequest(t, s, "SEND", path+",33188")
	syncRequest(t, s, "DATA", "partial")
	timer := time.AfterFunc(50*time.Millisecond, cancel)
	defer timer.Stop()
	if err := await(t, done); err == nil {
		t.Fatal("timeout not reported")
	}
	if _, err := os.Stat(filepath.Dir(path)); err != nil {
		t.Fatalf("created user directory removed: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("partial destination exists: %v", err)
	}
	files, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".privateadb-upload-*"))
	if len(files) != 0 {
		t.Fatalf("owned partials: %v", files)
	}
}
