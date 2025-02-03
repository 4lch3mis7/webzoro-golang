package utils

import (
	"errors"
	"fmt"
	"os"
)

// Create directory if not exists.
func CheckAndCreateDir(path string) {
	if _, err := os.Stat(path); err == nil {
		fmt.Println("[i] Existing path:", path)
	} else if errors.Is(err, os.ErrNotExist) {
		os.MkdirAll(path, 0755)
	}
}
