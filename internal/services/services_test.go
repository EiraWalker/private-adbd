package services

import (
	"context"
	"io"
	"net"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func hostConfig(t *testing.T) Config {
	t.Helper()
	shell, err := exec.LookPath("bash")
	if err != nil {
		shell, err = exec.LookPath("sh")
	}
	if err != nil {
		t.Skip("real host bash/sh not available")
	}
	return Config{Shell: shell, WorkingDir: t.TempDir(), Env: []string{"PRIVATE_ADB_TEST=real-environment"}}
}

func startService(t *testing.T, c Config, service string) (net.Conn, <-chan error, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	client, server := net.Pipe()
	client.SetDeadline(time.Now().Add(4 * time.Second))
	done := make(chan error, 1)
	go func() { done <- New(c)(ctx, service, server); server.Close() }()
	t.Cleanup(func() { cancel(); client.Close() })
	return client, done, cancel
}

func await(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(3 * time.Second):
		t.Fatal("service did not terminate")
		return nil
	}
}

func TestShellV1RealExecution(t *testing.T) {
	c := hostConfig(t)
	s, done, _ := startService(t, c, "shell:printf '%s' \"$PRIVATE_ADB_TEST\"; printf stderr >&2")
	data, err := io.ReadAll(s)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "real-environment") || !strings.Contains(string(data), "stderr") {
		t.Fatalf("actual shell output %q", data)
	}
	if err := await(t, done); err != nil {
		t.Fatal(err)
	}
	t.Logf("actual shell output: %q", data)
}

func TestUnsupportedServicesRejected(t *testing.T) {
	for _, name := range []string{"tcp:80", "reverse:forward:tcp:1234;tcp:1234", "root:", "shell,v2,pty:", "localabstract:not_scrcpy"} {
		t.Run(name, func(t *testing.T) {
			s, done, _ := startService(t, hostConfig(t), name)
			s.Close()
			if err := await(t, done); err == nil {
				t.Fatal("unsupported service accepted")
			}
		})
	}
}
