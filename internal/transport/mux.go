package transport

import (
	"bytes"
	"context"
	"io"
	"net"
	"sync"
	"time"
)

// The connection reader never waits for a service: each stream owns exactly one
// inbound packet. Credit is returned only after the application consumes it.
// Writers serialize per stream and wait for a peer OKAY for every packet.
type mux struct {
	ctx        context.Context
	cancel     context.CancelFunc
	conn       net.Conn
	checksum   bool
	payload    int
	maxStreams int
	handler    Handler
	sendMu     sync.Mutex
	workers    sync.WaitGroup
}

func (m *mux) send(p packet) error {
	m.sendMu.Lock()
	defer m.sendMu.Unlock()
	m.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	e := writePacket(m.conn, p, m.checksum)
	m.conn.SetWriteDeadline(time.Time{})
	if e != nil {
		m.conn.Close()
	}
	return e
}
func (m *mux) run() {
	streams := make(map[uint32]*stream)
	active := make(chan struct{}, m.maxStreams)
	var next uint32
	defer func() {
		m.cancel()
		m.conn.Close()
		for _, s := range streams {
			s.abort()
		}
		m.workers.Wait()
	}()
	for {
		p, e := readPacket(m.conn, m.checksum)
		if e != nil {
			return
		}
		if p.cmd == cmdOPEN {
			if p.arg0 == 0 || p.arg1 != 0 {
				return
			}
			name := bytes.TrimRight(p.payload, "\x00")
			if len(name) == 0 || bytes.IndexByte(name, 0) >= 0 {
				return
			}
			for _, s := range streams {
				if s.remote == p.arg0 {
					return
				}
			}
			if len(streams) >= m.maxStreams || len(active) >= m.maxStreams {
				if m.send(packet{cmd: cmdCLSE, arg1: p.arg0}) != nil {
					return
				}
				continue
			}
			next++
			if next == 0 {
				return
			}
			ctx, cancel := context.WithCancel(m.ctx)
			s := &stream{m: m, local: next, remote: p.arg0, ctx: ctx, cancel: cancel, in: make(chan []byte, 1), ack: make(chan struct{}, 1), done: make(chan struct{})}
			streams[next] = s
			if m.send(packet{cmd: cmdOKAY, arg0: s.local, arg1: s.remote}) != nil {
				return
			}
			active <- struct{}{}
			m.workers.Add(1)
			go func() {
				defer m.workers.Done()
				defer func() { <-active }()
				defer s.Close()
				_ = m.handler(s.ctx, string(name), s)
			}()
			continue
		}
		if p.cmd != cmdOKAY && p.cmd != cmdWRTE && p.cmd != cmdCLSE {
			return
		}
		s := streams[p.arg1]
		if s == nil || p.arg1 == 0 || (p.arg0 != s.remote && (p.cmd != cmdCLSE || p.arg0 != 0)) {
			return
		}
		switch p.cmd {
		case cmdCLSE:
			if len(p.payload) != 0 {
				return
			}
			already := s.abort()
			if !already {
				if m.send(packet{cmd: cmdCLSE, arg0: s.local, arg1: s.remote}) != nil {
					return
				}
			}
			delete(streams, s.local)
		case cmdOKAY:
			if len(p.payload) != 0 {
				return
			}
			s.mu.Lock()
			if s.closed {
				s.mu.Unlock()
				continue
			}
			if !s.waiting {
				s.mu.Unlock()
				return
			}
			s.waiting = false
			s.ack <- struct{}{}
			s.mu.Unlock()
		case cmdWRTE:
			s.mu.Lock()
			if s.closed {
				s.mu.Unlock()
				continue
			}
			if s.pending {
				s.mu.Unlock()
				return
			}
			s.pending = true
			s.in <- p.payload
			s.mu.Unlock()
		}
	}
}

type stream struct {
	m                        *mux
	local, remote            uint32
	ctx                      context.Context
	cancel                   context.CancelFunc
	mu, readMu, writeMu      sync.Mutex
	closed, pending, waiting bool
	in                       chan []byte
	ack                      chan struct{}
	done                     chan struct{}
	buf                      []byte
}

// abort is idempotent and returns whether the stream was already closed.
func (s *stream) abort() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	was := s.closed
	if !was {
		s.closed = true
		s.cancel()
		close(s.done)
	}
	return was
}
func (s *stream) Close() error {
	if s.abort() {
		return nil
	}
	return s.m.send(packet{cmd: cmdCLSE, arg0: s.local, arg1: s.remote})
}
func (s *stream) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	s.readMu.Lock()
	defer s.readMu.Unlock()
	for len(s.buf) == 0 {
		select {
		case <-s.done:
			return 0, io.EOF
		default:
		}
		select {
		case <-s.done:
			return 0, io.EOF
		case s.buf = <-s.in:
		}
		if len(s.buf) == 0 {
			if e := s.consumed(); e != nil {
				return 0, e
			}
		}
	}
	n := copy(p, s.buf)
	s.buf = s.buf[n:]
	if len(s.buf) == 0 {
		if e := s.consumed(); e != nil {
			return n, e
		}
	}
	return n, nil
}
func (s *stream) consumed() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return io.EOF
	}
	s.pending = false
	return s.m.send(packet{cmd: cmdOKAY, arg0: s.local, arg1: s.remote})
}
func (s *stream) Write(p []byte) (int, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	written := 0
	for len(p) > 0 {
		n := len(p)
		if n > s.m.payload {
			n = s.m.payload
		}
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			return written, io.ErrClosedPipe
		}
		s.waiting = true
		s.mu.Unlock()
		if e := s.m.send(packet{cmd: cmdWRTE, arg0: s.local, arg1: s.remote, payload: p[:n]}); e != nil {
			return written, e
		}
		select {
		case <-s.done:
			return written, io.ErrClosedPipe
		case <-s.ack:
		}
		written += n
		p = p[n:]
	}
	return written, nil
}
