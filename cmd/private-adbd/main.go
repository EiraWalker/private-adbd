// private-adbd is a deliberately scoped Android shell-only ADB TLS endpoint.
package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"

	"privateadb/internal/runtimecfg"
	"privateadb/internal/security"
	"privateadb/internal/services"
	"privateadb/internal/transport"
)

var version = "0.1.0"

const listenAddress = "127.0.0.1:27184"

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.LUTC)
	keysPath := flag.String("keys", "/data/local/tmp/private-adbd/authorized_keys", "owner-only Android controller public-key file")
	expected := flag.String("serial", "", "required target device serial (must match ro.serialno)")
	flag.Parse()
	if *expected == "" {
		log.Print("explicit --serial is required")
		os.Exit(2)
	}
	if flag.NArg() != 0 {
		log.Print("unexpected arguments")
		os.Exit(2)
	}
	// Fail before reading properties/files or creating listeners on non-shell UID.
	if os.Geteuid() != 2000 {
		log.Print("requires existing Android shell UID 2000; no privilege escalation")
		os.Exit(2)
	}
	prop := func(name string) (string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		b, e := exec.CommandContext(ctx, "/system/bin/getprop", name).Output()
		return strings.TrimSpace(string(b)), e
	}
	actual, err := prop("ro.serialno")
	if err != nil {
		log.Print("could not read device identity")
		os.Exit(2)
	}
	if err = runtimecfg.ValidateIdentity(os.Geteuid(), actual, *expected); err != nil {
		log.Print(err)
		os.Exit(2)
	}
	contextLabel, err := os.ReadFile("/proc/self/attr/current")
	if err != nil || strings.Trim(string(contextLabel), "\x00\r\n ") != "u:r:shell:s0" {
		log.Print("requires existing enforcing Android shell context")
		os.Exit(2)
	}
	enforce, err := os.ReadFile("/sys/fs/selinux/enforce")
	if err != nil || strings.TrimSpace(string(enforce)) != "1" {
		log.Print("requires SELinux enforcing")
		os.Exit(2)
	}
	data, err := runtimecfg.ReadKeys(*keysPath)
	if err != nil {
		log.Printf("key-store validation: %v", err)
		os.Exit(2)
	}
	keys, err := security.ParseKeys(data)
	if err != nil {
		log.Print(err)
		os.Exit(2)
	}
	conf, err := keys.TLSConfig()
	if err != nil {
		log.Print("TLS initialization failed")
		os.Exit(2)
	}
	banner := "device::"
	safeProp := regexp.MustCompile(`^[A-Za-z0-9_. -]{1,80}$`)
	for _, name := range []string{"ro.product.name", "ro.product.model", "ro.product.device"} {
		v, e := prop(name)
		if e != nil || !safeProp.MatchString(v) {
			log.Print("invalid device property for ADB banner")
			os.Exit(2)
		}
		banner += name + "=" + v + ";"
	}
	banner += "features=shell_v2;"
	listener, err := net.Listen("tcp4", listenAddress)
	if err != nil {
		log.Printf("loopback bind failed: %v", err)
		os.Exit(1)
	}
	defer listener.Close()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	// Any allowlist change closes ALL current sessions. A supervisor may restart
	// with the replacement; deletion/invalid replacement fails closed on startup.
	original := sha256.Sum256(data)
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				latest, e := runtimecfg.ReadKeys(*keysPath)
				if e != nil || sha256.Sum256(latest) != original {
					log.Print("controller policy changed; closing sessions")
					cancel()
					return
				}
			}
		}
	}()
	handler := services.New(services.Config{Shell: "/system/bin/sh", WorkingDir: "/data/local/tmp", Env: os.Environ()})
	s := transport.Server{TLSConfig: conf, Banner: banner, Handler: func(c context.Context, service string, stream io.ReadWriteCloser) error {
		// Do not log command arguments, screen content, paths or transmitted data.
		return handler(c, service, stream)
	}, MaxConnections: 8, MaxStreams: 16}
	log.Printf("private-adbd=%s serial=%s uid=%d bind=%s tls=1.3 controllers=%d", version, actual, os.Geteuid(), listener.Addr(), len(keys.Fingerprints()))
	err = s.Serve(ctx, listener)
	if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, net.ErrClosed) {
		fmt.Fprintln(os.Stderr, "ADB transport ended:", err)
		os.Exit(1)
	}
	log.Print("private-adbd stopped; streams cancelled")
}
