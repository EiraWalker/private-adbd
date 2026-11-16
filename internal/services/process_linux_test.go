//go:build linux

package services

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestCancellationKillsShellProcessGroup(t *testing.T) {
	s, done, cancel := startService(t, hostConfig(t), "shell,v2,raw:sleep 30 & printf '%s\\n' \"$!\"; wait")
	id, p, err := readShellFrame(s)
	if err != nil || id != 1 {
		t.Fatalf("pid frame %d %q %v", id, p, err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(p)))
	if err != nil {
		t.Fatal(err)
	}
	// Capture the Linux process handle before cancellation; never send cleanup
	// signals to a numeric PID that may already have been recycled.
	child, err := os.FindProcess(pid)
	if err != nil {
		t.Fatal(err)
	}
	defer child.Release()
	// FindProcess can fall back to a numeric PID on unsupported kernels. Only
	// arm teardown if Go confirms a stable Linux pidfd handle is available.
	withHandle, available := any(child).(interface{ WithHandle(func(uintptr)) error })
	if available && withHandle.WithHandle(func(uintptr) {}) == nil {
		defer child.Kill()
	} else {
		t.Log("no pidfd cleanup available; fixture self-expires")
	}
	cancel()
	if err := await(t, done); err == nil {
		t.Fatal("cancellation was not reported")
	}
	deadline := time.Now().Add(time.Second)
	for {
		p, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		if os.IsNotExist(err) || errors.Is(err, syscall.ESRCH) {
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		fields := strings.Fields(string(p))
		if len(fields) > 2 && fields[2] == "Z" {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("child process %d survived cancellation: %s", pid, p)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
