package services

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
)

func writeShellFrame(w io.Writer, id byte, p []byte) error {
	b := make([]byte, 5+len(p))
	b[0] = id
	binary.LittleEndian.PutUint32(b[1:5], uint32(len(p)))
	copy(b[5:], p)
	_, err := w.Write(b)
	return err
}
func readShellFrame(r io.Reader) (byte, []byte, error) {
	var h [5]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return 0, nil, err
	}
	n := binary.LittleEndian.Uint32(h[1:])
	if n > 65536 {
		return 0, nil, io.ErrShortBuffer
	}
	p := make([]byte, n)
	_, err := io.ReadFull(r, p)
	return h[0], p, err
}
func TestShellV2StockTERMOption(t *testing.T) {
	s, done, _ := startService(t, hostConfig(t), "shell,v2,TERM=xterm-256color,raw:printf '%s' \"$TERM\"")
	var out bytes.Buffer
	for {
		id, p, err := readShellFrame(s)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if id == 1 {
			out.Write(p)
		}
	}
	if out.String() != "xterm-256color" {
		t.Fatalf("TERM output %q", out.String())
	}
	if err := await(t, done); err != nil {
		t.Fatal(err)
	}
}

func TestExecRealBinaryOutput(t *testing.T) {
	s, done, _ := startService(t, hostConfig(t), "exec:printf '\\000\\001\\377ABC'")
	p, err := io.ReadAll(s)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(p, []byte{0, 1, 255, 'A', 'B', 'C'}) {
		t.Fatalf("exec output %x", p)
	}
	if err := await(t, done); err != nil {
		t.Fatal(err)
	}
}

func TestShellV2RealStdinStdoutStderrExit(t *testing.T) {
	s, done, _ := startService(t, hostConfig(t), "shell,v2,raw:read x; printf 'out:%s' \"$x\"; printf err >&2; exit 7")
	sent := make(chan error, 1)
	go func() {
		if err := writeShellFrame(s, 0, []byte("hello\n")); err != nil {
			sent <- err
			return
		}
		sent <- writeShellFrame(s, 4, nil)
	}()
	var out, stderr bytes.Buffer
	exit := -1
	for {
		id, p, err := readShellFrame(s)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		switch id {
		case 1:
			out.Write(p)
		case 2:
			stderr.Write(p)
		case 3:
			if len(p) != 1 {
				t.Fatalf("exit payload %x", p)
			}
			exit = int(p[0])
		default:
			t.Fatalf("bad packet id %d", id)
		}
	}
	if err := <-sent; err != nil {
		t.Fatal(err)
	}
	if out.String() != "out:hello" || stderr.String() != "err" || exit != 7 {
		t.Fatalf("stdout=%q stderr=%q exit=%d", out.String(), stderr.String(), exit)
	}
	if err := await(t, done); err != nil {
		t.Fatal(err)
	}
	t.Logf("real shell: stdout=%q stderr=%q exit=%d", out.String(), stderr.String(), exit)
}
