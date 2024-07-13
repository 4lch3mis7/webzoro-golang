package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/alecthomas/kingpin/v2"
)

var (
	host = kingpin.Arg("host", "Host (Domain or IP)").String()
	// tls  = kingpin.Flag("tls", "SSL/TLS").Default("false").Bool()

	urlRegexp = regexp.MustCompile(`^(http:\/\/www\.|https:\/\/www\.|http:\/\/|https:\/\/|\/|\/\/)?[A-z0-9_-]*?[:]?[A-z0-9_-]*?[@]?[A-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}(:[0-9]{1,5})?(\/.*)?$`)
	ipRegexp  = regexp.MustCompile(`^(?:\d+\.){3}\d+$`)
)

var binariesRequired = []string{
	"nmap",
}

func main() {
	kingpin.Parse()
	fmt.Println("[i] Binaries required: ", binariesRequired)

	if !IsValidHost(*host) {
		fmt.Println("[!] Invalid host. Please provide an URL or IP Address")
		return
	}

	wd, _ := os.Getwd()
	CreateDirIfNotExists(wd + "/" + *host)
}

// Is Valid Host?
func IsValidHost(host string) bool {
	return urlRegexp.MatchString(host) || ipRegexp.MatchString(host)
}

// Get Domain From URL
func GetDomainFromUrl(url string) string {
	return strings.Split(strings.Split(url, "://")[1], "/")[0]
}

// Create Domain If Not Exists
func CreateDirIfNotExists(path string) {
	if _, err := os.Stat(path); err == nil {
		fmt.Println("[i] Existing path:", path)
	} else if errors.Is(err, os.ErrNotExist) {
		os.MkdirAll(path, 0755)
	}
}

// Check if the dependencies (binaries required) are installed or not
// and returns a list of dependencies that are not installed
func CheckDependencies() []string {
	var notInstalled = []string{}
	for _, bin := range binariesRequired {
		if _, err := exec.LookPath(bin); err != nil {
			notInstalled = append(notInstalled, bin)
		}
	}
	return notInstalled
}

// Run a nmap scan on the target (domain or IP)
func NmapScan(target string) {
	cmd := exec.Command("nmap", "-sT", "-sV", "-sC", "-A", "-Pn", "-oN ")
	out, _ := cmd.Output()
	fmt.Println(string(out))
}
