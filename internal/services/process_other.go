//go:build !linux

package services

import "os/exec"

// Non-Linux is a host-test path only; Android/Linux owns the process-group policy.
func configureProcess(cmd *exec.Cmd) func() error { return cmd.Wait }
