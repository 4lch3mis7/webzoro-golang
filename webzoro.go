package main

import (
	"fmt"
	"os/exec"
	"path"

	"github.com/4lch3mis7/webzoro-golang/pkg/scanner"
	"github.com/alecthomas/kingpin/v2"
)

var (
	host = kingpin.Arg("host", "Host (Domain or IP)").String()
	// tls  = kingpin.Flag("tls", "SSL/TLS").Default("false").Bool()
)

var binariesRequired = []string{
	"nmap",
	"sublist3r",
	"dirsearch",
}

func main() {
	kingpin.Parse()
	fmt.Println("[i] Binaries required: ", binariesRequired)

	target := scanner.Target{
		Target: *host,
	}

	if !target.IsValidHost() {
		fmt.Println("[!] Invalid host. Please provide a domain name or an IP Address")
		return
	}

	// Subdomain Enumeration
	if target.IsDomain() {
		wd := target.GetWorkingDir()
		scanner.EnumSubdomains(target.Target, path.Join(wd, "sublist3r.out"))
	}

	// Run Scan on a Target
	scanner.Scan(&target)

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
