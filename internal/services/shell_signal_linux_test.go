//go:build linux

package services

import (
	"io"
	"testing"
)

func TestShellV2SignalExitUses128OrSignal(t *testing.T) {
	s, done, _ := startService(t, hostConfig(t), "shell,v2,raw:kill -TERM $$")
	exits := 0
	for {
		id, p, err := readShellFrame(s)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if id == 3 {
			exits++
			if len(p) != 1 || p[0] != 143 {
				t.Errorf("TERM exit payload=%v, want [143] (128|SIGTERM)", p)
			}
		}
	}
	if exits != 1 {
		t.Fatalf("exit frame count=%d, want 1", exits)
	}
	if err := await(t, done); err != nil {
		t.Fatal(err)
	}
}
