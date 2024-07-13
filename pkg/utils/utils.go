package utils

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
)

// CmdExec executes a command and returns the output as a string.
// If the command fails, it returns the error.
func CmdExec(cmd *exec.Cmd) (string, error) {
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// Get Domain from URL
func GetDomainFromUrl(url string) string {
	return strings.Split(strings.Split(url, "://")[1], "/")[0]
}

// Create directory if not exists
func CreateDirIfNotExists(path string) {
	if _, err := os.Stat(path); err == nil {
		fmt.Println("[i] Existing path:", path)
	} else if errors.Is(err, os.ErrNotExist) {
		os.MkdirAll(path, 0755)
	}
}

// Read a file line-by-line
func ReadLines(filePath string) []string {
	var lines []string
	file, err := os.Open(filePath)
	if err != nil {
		log.Fatal(err)
	}
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		lines = append(lines, strings.TrimSpace(scanner.Text()))
	}
	file.Close()
	return lines
}
