//go:build linux

package services

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestReviewLeaderExitCleansDescendants(t *testing.T) {
	for _, cancelled := range []bool{true, false} {
		t.Run(fmt.Sprintf("cancel=%v", cancelled), func(t *testing.T) {
			s, done, cancel := startService(t, hostConfig(t), "shell,v2,raw:sleep 5 & printf '%s\\n' \"$!\"; exit 0")
			id, data, err := readShellFrame(s)
			if err != nil || id != 1 {
				t.Fatalf("pid frame %d %q %v", id, data, err)
			}
			pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
			if err != nil {
				t.Fatal(err)
			}
			// The RED fixture is self-expiring. Never kill a child via a PID read
			// from stdout: it could already have exited and been reused.
			go io.Copy(io.Discard, s)
			time.Sleep(200 * time.Millisecond)
			if cancelled {
				cancel()
			}
			result := await(t, done)
			if !cancelled && result != nil {
				t.Errorf("normal leader exit: %v", result)
			}
			deadline := time.Now().Add(time.Second)
			for {
				raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
				if os.IsNotExist(err) || errors.Is(err, syscall.ESRCH) {
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				fields := strings.Fields(string(raw)[strings.LastIndexByte(string(raw), ')')+1:])
				if fields[0] == "Z" {
					return
				}
				if time.Now().After(deadline) {
					t.Fatalf("descendant %d survived leader exit (cancel=%v): %s", pid, cancelled, raw)
				}
				time.Sleep(10 * time.Millisecond)
			}
		})
	}
}
