package runtimecfg

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRequireExactTabletShellIdentity(t *testing.T) {
	for _, tc := range []struct {
		uid              int
		actual, expected string
		ok               bool
	}{
		{2000, "FIXTURE-SERIAL-001", "FIXTURE-SERIAL-001", true}, {0, "FIXTURE-SERIAL-001", "FIXTURE-SERIAL-001", false}, {10001, "FIXTURE-SERIAL-001", "FIXTURE-SERIAL-001", false}, {2000, "FIXTURE-OTHER-002", "FIXTURE-SERIAL-001", false}, {2000, "FIXTURE-SERIAL-001", "", false}, {2000, "", "", false}, {2000, "FIXTURE-SERIAL-001;features=x", "FIXTURE-SERIAL-001;features=x", false},
	} {
		if err := ValidateIdentity(tc.uid, tc.actual, tc.expected); (err == nil) != tc.ok {
			t.Errorf("identity %+v error %v", tc, err)
		}
	}
}
func TestKeyFileMustBePrivateRegularAndBounded(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "keys")
	if err := os.WriteFile(path, []byte("public-test"), 0600); err != nil {
		t.Fatal(err)
	}
	data, err := ReadKeys(path)
	if err != nil || string(data) != "public-test" {
		t.Fatalf("%q %v", data, err)
	}
	if _, err := ReadKeys(dir); err == nil {
		t.Fatal("directory accepted")
	}
	if _, err := ReadKeys("relative/keys"); err == nil {
		t.Fatal("relative path accepted")
	}
	if err := os.WriteFile(path, make([]byte, 8193), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadKeys(path); err == nil {
		t.Fatal("oversized key store accepted")
	}
}
