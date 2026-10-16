package utils

import (
	"errors"
	"os"
)

// Create directory if not exists.
func CheckAndCreateDir(path string) {
	if _, err := os.Stat(path); err == nil {
		return
	} else if errors.Is(err, os.ErrNotExist) {
		os.MkdirAll(path, 0755)
	}
}
