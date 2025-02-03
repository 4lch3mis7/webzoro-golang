package utils

import (
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

// Unique returns a slice with unique elements from the input slice.
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

// Diff returns the difference between two slices of elements.
//
// It returns a slice with elements that are present in the first slice but not in the second slice.
func Diff[T comparable](a, b []T) []T {
	m := make(map[T]bool)
	for _, s := range b {
		m[s] = true
	}
	var diff []T
	for _, s := range a {
		if !m[s] {
			diff = append(diff, s)
		}
	}
	return diff
}
