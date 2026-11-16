// Package runtimecfg owns target and key-file startup gates.
package runtimecfg

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
)

var identityPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

func ValidateIdentity(uid int, actual, expected string) error {
	if uid != 2000 {
		return errors.New("requires existing Android shell UID 2000; no privilege escalation")
	}
	if !identityPattern.MatchString(expected) || actual != expected {
		return errors.New("target serial does not match configured tablet")
	}
	return nil
}

// ReadKeys rejects symlinks, mutable-by-others stores, empty/oversize stores,
// and concurrent replacements. Deployment separately verifies owner UID 2000.
func ReadKeys(path string) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("key-store path must be absolute")
	}
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || before.Size() < 1 || before.Size() > 8192 {
		return nil, errors.New("invalid key-store file type or size")
	}
	if runtime.GOOS != "windows" && before.Mode().Perm()&0077 != 0 {
		return nil, errors.New("key-store permissions must be owner-only")
	}
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	if !parent.IsDir() || parent.Mode()&os.ModeSymlink != 0 || (runtime.GOOS != "windows" && parent.Mode().Perm()&0022 != 0) {
		return nil, errors.New("unsafe key-store parent directory")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(before, opened) {
		return nil, errors.New("key-store file changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(f, 8193))
	if err != nil {
		return nil, err
	}
	after, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if len(data) > 8192 || len(data) == 0 || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
		return nil, errors.New("key-store file changed while reading")
	}
	return data, nil
}
