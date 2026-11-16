package transport

import (
	"bytes"
	"testing"
)

func TestChecksumNegotiation(t *testing.T) {
	var buf bytes.Buffer
	put(&buf, frame{tCNXN, tVersion, 65536, []byte("host::")})
	b := buf.Bytes()
	b[16] ^= 1
	if _, e := readPacket(bytes.NewReader(b), true); e == nil {
		t.Fatal("bad legacy checksum accepted")
	}
	if _, e := readPacket(bytes.NewReader(b), false); e != nil {
		t.Fatalf("negotiated skip-checksum rejected: %v", e)
	}
}
