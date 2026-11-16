//go:build linux

package services

import (
	"fmt"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"unsafe"
)

// The unreaped leader reserves its PID/PGID. Never signal a numeric group after
// reaping it: neither checking /proc nor holding a pidfd makes that safe.
// Normal leader exit ends this service's entire process group. Descendants that
// deliberately escape with setsid/setpgid are outside this lifecycle guarantee.
func configureProcess(cmd *exec.Cmd) func() error {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	var mu sync.Mutex
	owned := true
	kill := func() error {
		if !owned || cmd.Process == nil {
			return os.ErrProcessDone
		}
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if err == syscall.ESRCH {
			return os.ErrProcessDone
		}
		return err
	}
	cmd.Cancel = func() error { mu.Lock(); defer mu.Unlock(); return kill() }
	return func() error {
		// Observe death without reaping, retaining the identity anchor while
		// descendants can still hold the service's stdout/stderr pipes.
		var info [16]uint64 // Linux siginfo_t: 128 bytes with sufficient alignment.
		var errno syscall.Errno
		for {
			_, _, errno = syscall.Syscall6(syscall.SYS_WAITID, 1 /* P_PID */, uintptr(cmd.Process.Pid), uintptr(unsafe.Pointer(&info[0])), syscall.WEXITED|syscall.WNOWAIT, 0, 0)
			if errno != syscall.EINTR {
				break
			}
		}
		mu.Lock()
		var cleanup error
		if errno == 0 {
			cleanup = kill()
		}
		owned = false // disarm Cmd.Cancel BEFORE cmd.Wait may release the PID
		mu.Unlock()
		if errno != 0 {
			// Observation failed: never issue an unguarded numeric group signal.
			_ = cmd.Process.Kill()
			waited := cmd.Wait()
			return fmt.Errorf("observe shell exit: %v (wait: %v)", errno, waited)
		}
		waited := cmd.Wait()
		if cleanup != nil && cleanup != os.ErrProcessDone {
			return fmt.Errorf("clean shell group: %v (wait: %v)", cleanup, waited)
		}
		return waited
	}
}
