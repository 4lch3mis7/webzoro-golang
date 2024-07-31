package utils

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
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

// Read a local file line-by-line
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

// Read a remote file line-by-line
func ReadLinesRemote(url string) []string {
	resp, err := http.Get(url)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	body := strings.TrimSpace(string(bodyBytes))
	return strings.Split(body, "\n")
}

// Read a local or remote file line-by-line into a channel of string
func ReadLinesCh(path string, ch chan<- string) {
	if strings.HasPrefix(path, "http") {
		for _, line := range ReadLinesRemote(path) {
			ch <- line
		}
	} else {
		for _, line := range ReadLines(path) {
			ch <- line
		}
	}
	close(ch)
}

// Remove duplicate items from a slice
func Unique[T comparable](items []T) []T {
	keys := make(map[T]bool)
	result := []T{}
	for _, e := range items {
		if !keys[e] {
			keys[e] = true
			result = append(result, e)
		}
	}
	return result
}
