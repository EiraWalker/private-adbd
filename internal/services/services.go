// Package services implements the deliberately narrow authenticated ADB service set.
// The transport must authenticate the caller before invoking the returned handler.
package services

import (
	"context"
	"fmt"
	"io"
	"strings"
)

// Config selects the real shell, cwd and additional environment overrides.
// Empty Shell/WorkingDir use Android shell defaults. Env extends the inherited
// environment (including PATH); it never alters the process UID or privileges.
type Config struct {
	Shell      string
	WorkingDir string
	Env        []string
}

// New returns a handler which owns and closes each supplied stream. Cancellation
// must unblock stream reads/writes via Close, as net.Conn and transport streams do.
// PTYs are intentionally unsupported: use adb shell -T for raw interactive stdin.
func New(c Config) func(context.Context, string, io.ReadWriteCloser) error {
	if c.Shell == "" {
		c.Shell = "/system/bin/sh"
	}
	if c.WorkingDir == "" {
		c.WorkingDir = "/data/local/tmp"
	}
	c.Env = append([]string(nil), c.Env...)
	return func(ctx context.Context, service string, stream io.ReadWriteCloser) error {
		defer stream.Close()
		stop := context.AfterFunc(ctx, func() { stream.Close() })
		defer stop()
		if strings.HasPrefix(service, "localabstract:") {
			return runAbstract(ctx, strings.TrimPrefix(service, "localabstract:"), stream)
		}
		if service == "sync:" {
			return runSync(ctx, c, stream)
		}
		if strings.HasPrefix(service, "exec:") {
			return runShell(ctx, c, strings.TrimPrefix(service, "exec:"), stream, false)
		}
		if strings.HasPrefix(service, "shell:") {
			return runShell(ctx, c, strings.TrimPrefix(service, "shell:"), stream, false)
		}
		if strings.HasPrefix(service, "shell,") {
			options, command, ok := strings.Cut(service, ":")
			if !ok {
				return fmt.Errorf("shell service requires colon")
			}
			v2, raw := false, false
			local := c
			local.Env = append([]string(nil), c.Env...)
			for _, option := range strings.Split(strings.TrimPrefix(options, "shell,"), ",") {
				switch {
				case option == "v2":
					v2 = true
				case option == "raw":
					raw = true
				case strings.HasPrefix(option, "TERM=") && len(option) <= 128 && !strings.ContainsRune(option, 0):
					local.Env = append(local.Env, option)
				default:
					return fmt.Errorf("unsupported shell option (PTY disabled)")
				}
			}
			if !v2 || (!raw && command == "") {
				return fmt.Errorf("PTY disabled: use adb shell -T")
			}
			return runShell(ctx, local, command, stream, true)
		}
		return fmt.Errorf("unsupported service %q (PTY, reverse and TCP are disabled)", service)
	}
}
