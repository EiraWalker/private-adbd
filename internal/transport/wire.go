package transport

import (
	"encoding/binary"
	"errors"
	"io"
)

const (
	cmdCNXN       uint32 = 0x4e584e43
	cmdSTLS       uint32 = 0x534c5453
	cmdOPEN       uint32 = 0x4e45504f
	cmdOKAY       uint32 = 0x59414b4f
	cmdWRTE       uint32 = 0x45545257
	cmdCLSE       uint32 = 0x45534c43
	version       uint32 = 0x01000001
	legacyVersion uint32 = 0x01000000
	maxPayload           = 64 * 1024
)

var errProtocol = errors.New("invalid ADB protocol")

type packet struct {
	cmd, arg0, arg1 uint32
	payload         []byte
}

func readPacket(r io.Reader, checksum bool) (packet, error) {
	var h [24]byte
	if _, e := io.ReadFull(r, h[:]); e != nil {
		return packet{}, e
	}
	p := packet{cmd: binary.LittleEndian.Uint32(h[:]), arg0: binary.LittleEndian.Uint32(h[4:]), arg1: binary.LittleEndian.Uint32(h[8:])}
	n := binary.LittleEndian.Uint32(h[12:])
	if n > maxPayload || binary.LittleEndian.Uint32(h[20:]) != ^p.cmd {
		return p, errProtocol
	}
	p.payload = make([]byte, n)
	if _, e := io.ReadFull(r, p.payload); e != nil {
		return p, e
	}
	if checksum {
		var sum uint32
		for _, b := range p.payload {
			sum += uint32(b)
		}
		if sum != binary.LittleEndian.Uint32(h[16:]) {
			return p, errProtocol
		}
	}
	return p, nil
}
func writePacket(w io.Writer, p packet, checksum bool) error {
	var h [24]byte
	var sum uint32
	if checksum {
		for _, b := range p.payload {
			sum += uint32(b)
		}
	}
	for i, v := range []uint32{p.cmd, p.arg0, p.arg1, uint32(len(p.payload)), sum, ^p.cmd} {
		binary.LittleEndian.PutUint32(h[i*4:], v)
	}
	for _, b := range [][]byte{h[:], p.payload} {
		for len(b) > 0 {
			n, e := w.Write(b)
			if e != nil {
				return e
			}
			if n == 0 {
				return io.ErrShortWrite
			}
			b = b[n:]
		}
	}
	return nil
}
