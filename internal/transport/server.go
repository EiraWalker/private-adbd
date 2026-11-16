// Package transport implements the TLS-only ADB wire transport.
package transport

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

type Handler func(context.Context, string, io.ReadWriteCloser) error
type Server struct {
	TLSConfig      *tls.Config
	Banner         string
	Handler        Handler
	MaxConnections int
	MaxStreams     int
}

// Serve closes the listener and accepted sockets on cancellation. Handlers must
// respect context cancellation; arbitrary user code cannot be forcibly stopped.
func (s *Server) Serve(ctx context.Context, l net.Listener) error {
	if s.TLSConfig == nil || s.Handler == nil {
		return errors.New("TLS config and handler required")
	}
	if !strings.HasPrefix(s.Banner, "device::") || len(s.Banner) > 4096 || strings.ContainsAny(s.Banner, "\x00\r\n") {
		return errors.New("invalid device banner")
	}
	for _, prop := range strings.Split(strings.TrimPrefix(s.Banner, "device::"), ";") {
		if strings.HasPrefix(prop, "features=") {
			for _, feature := range strings.Split(strings.TrimPrefix(prop, "features="), ",") {
				if feature == "delayed_ack" {
					return errors.New("delayed_ack is not supported")
				}
			}
		}
	}
	cfg := s.TLSConfig
	if cfg.GetConfigForClient != nil || (cfg.ClientAuth != tls.RequireAndVerifyClientCert && (cfg.ClientAuth != tls.RequireAnyClientCert || (cfg.VerifyConnection == nil && cfg.VerifyPeerCertificate == nil))) {
		return errors.New("authenticated TLS client configuration required")
	}
	owned := *s
	owned.TLSConfig = cfg.Clone()
	owned.TLSConfig.MinVersion = tls.VersionTLS13
	owned.TLSConfig.MaxVersion = tls.VersionTLS13
	owned.TLSConfig.SessionTicketsDisabled = true
	s = &owned

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { l.Close() })
	defer stop()
	limit := s.MaxConnections
	if limit <= 0 {
		limit = 4
	}
	slots := make(chan struct{}, limit)
	var wg sync.WaitGroup
	defer func() { cancel(); l.Close(); wg.Wait() }()
	for {
		raw, e := l.Accept()
		if e != nil {
			if ctx.Err() != nil {
				return nil
			}
			return e
		}
		select {
		case slots <- struct{}{}:
		default:
			raw.Close()
			continue
		}
		wg.Add(1)
		go func() {
			defer func() { <-slots }()
			defer wg.Done()
			defer raw.Close()
			stop := context.AfterFunc(ctx, func() { raw.Close() })
			defer stop()
			s.serveConnection(ctx, raw)
		}()
	}
}
func (s *Server) serveConnection(ctx context.Context, raw net.Conn) {
	raw.SetDeadline(time.Now().Add(10 * time.Second))
	p, e := readPacket(raw, true)
	if e != nil || p.cmd != cmdCNXN || (p.arg0 != legacyVersion && p.arg0 != version) {
		return
	}
	peerPayload := int(p.arg1)
	if peerPayload == 0 {
		return
	}
	if peerPayload > maxPayload {
		peerPayload = maxPayload
	}
	checksum := p.arg0 < version
	if e = writePacket(raw, packet{cmd: cmdSTLS, arg0: legacyVersion}, checksum); e != nil {
		return
	}
	p, e = readPacket(raw, checksum)
	if e != nil || p.cmd != cmdSTLS || p.arg0 != legacyVersion || p.arg1 != 0 || len(p.payload) != 0 {
		return
	}
	cfg := s.TLSConfig.Clone()
	cfg.MinVersion = tls.VersionTLS13
	cfg.MaxVersion = tls.VersionTLS13
	conn := tls.Server(raw, cfg)
	if e = conn.HandshakeContext(ctx); e != nil {
		return
	}
	if e = writePacket(conn, packet{cmd: cmdCNXN, arg0: version, arg1: maxPayload, payload: []byte(s.Banner)}, checksum); e != nil {
		return
	}
	raw.SetDeadline(time.Time{})
	child, cancel := context.WithCancel(ctx)
	limit := s.MaxStreams
	if limit <= 0 {
		limit = 16
	}
	m := &mux{ctx: child, cancel: cancel, conn: conn, checksum: checksum, payload: peerPayload, maxStreams: limit, handler: s.Handler}
	m.run()
}
