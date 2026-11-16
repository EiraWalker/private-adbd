package services

import "testing"

func TestOnlyScrcpyAbstractNamesAccepted(t *testing.T) {
	for _, name := range []string{"scrcpy_12345678", "scrcpy_demo"} {
		if err := validateAbstractName(name); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"scrcpy", "scrcpy_", "scrcpy_/path", "scrcpy_\x00hidden", "other", "scrcpy_../x"} {
		if validateAbstractName(name) == nil {
			t.Fatalf("accepted %q", name)
		}
	}
}
