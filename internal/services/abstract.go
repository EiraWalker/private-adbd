package services

import (
	"errors"
	"strings"
)

func validateAbstractName(name string) error {
	if !strings.HasPrefix(name, "scrcpy_") || len(name) <= len("scrcpy_") || len(name) > 107 {
		return errors.New("only bounded scrcpy_* abstract sockets are permitted")
	}
	for _, b := range []byte(name) {
		if (b < 'a' || b > 'z') && (b < 'A' || b > 'Z') && (b < '0' || b > '9') && b != '_' && b != '-' {
			return errors.New("invalid scrcpy abstract socket name")
		}
	}
	return nil
}
