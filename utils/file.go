package utils

import (
	"bufio"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
)

func SaveToFile(fileName string, text string) error {
	file, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = io.WriteString(file, text)
	if err != nil {
		return err
	}

	return file.Close()
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

// Read a local or remote file line-by-line into a channel of string.
// The channel is closed after all lines are read.
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
