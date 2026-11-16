package services

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const maxChunk = 64 * 1024

type shellOutput struct {
	mu     sync.Mutex
	stream io.Writer
	v2     bool
	cancel context.CancelFunc
}
type shellChannel struct {
	output *shellOutput
	id     byte
}

func (w shellChannel) Write(p []byte) (int, error) {
	w.output.mu.Lock()
	defer w.output.mu.Unlock()
	if w.output.v2 {
		var h [5]byte
		h[0] = w.id
		binary.LittleEndian.PutUint32(h[1:], uint32(len(p)))
		if err := writeAll(w.output.stream, h[:]); err != nil {
			w.output.cancel()
			return 0, err
		}
	}
	if err := writeAll(w.output.stream, p); err != nil {
		w.output.cancel()
		return 0, err
	}
	return len(p), nil
}
func writeAll(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		p = p[n:]
	}
	return nil
}

func shellInput(stream io.Reader, stdin io.WriteCloser, v2 bool) error {
	defer stdin.Close()
	if !v2 {
		_, err := io.Copy(stdin, stream)
		return err
	}
	var h [5]byte
	var data [maxChunk]byte
	closed := false
	for {
		if _, err := io.ReadFull(stream, h[:]); err != nil {
			return err
		}
		n := binary.LittleEndian.Uint32(h[1:])
		if n > maxChunk {
			return fmt.Errorf("shell frame exceeds %d bytes", maxChunk)
		}
		if h[0] != 0 && h[0] != 4 {
			return fmt.Errorf("unsupported raw shell input id %d", h[0])
		}
		if h[0] == 4 {
			if n != 0 {
				return errors.New("close-stdin payload must be empty")
			}
			stdin.Close()
			closed = true
			continue
		}
		if _, err := io.ReadFull(stream, data[:n]); err != nil {
			return err
		}
		if !closed {
			if err := writeAll(stdin, data[:n]); err != nil {
				stdin.Close()
				closed = true
			}
		}
	}
}

func runShell(ctx context.Context, c Config, command string, stream io.ReadWriteCloser, v2 bool) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { stream.Close() })
	defer stop()
	args := []string{"-c", command}
	if command == "" {
		args = nil
	}
	cmd := exec.CommandContext(ctx, c.Shell, args...)
	waitProcess := configureProcess(cmd)
	cmd.Dir = c.WorkingDir
	cmd.Env = append(os.Environ(), c.Env...)
	cmd.WaitDelay = time.Second
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	output := &shellOutput{stream: stream, v2: v2, cancel: cancel}
	cmd.Stdout = shellChannel{output, 1}
	cmd.Stderr = shellChannel{output, 2}
	if err = cmd.Start(); err != nil {
		stdin.Close()
		return err
	}
	inputDone := make(chan error, 1)
	var finished atomic.Bool
	go func() {
		err := shellInput(stream, stdin, v2)
		if err != nil && !finished.Load() && !errors.Is(err, io.EOF) {
			cancel()
		}
		inputDone <- err
	}()
	err = waitProcess()
	stdin.Close()
	exit := byte(0)
	var exited *exec.ExitError
	if errors.As(err, &exited) {
		exit = byte(exited.ExitCode())
		if status, ok := exited.Sys().(syscall.WaitStatus); ok && status.Signaled() {
			exit = 128 | byte(status.Signal())
		}
		err = nil
	}
	if err == nil && ctx.Err() == nil && v2 {
		_, err = (shellChannel{output, 3}).Write([]byte{exit})
	}
	// Child completion must unblock stdin readers; never wait on a peer to close.
	finished.Store(true)
	stream.Close()
	<-inputDone
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}
