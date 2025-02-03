package main

import (
	"fmt"
	"os/exec"

	"github.com/4lch3mis7/webzoro-golang/scanner"
	"github.com/alecthomas/kingpin/v2"
)

var (
	host = kingpin.Arg("host", "Host (domain or IP)").String()
	// tls  = kingpin.Flag("tls", "SSL/TLS").Default("false").Bool()
)

var binariesRequired = []string{
	"rustscan",
	"subfinder",
	"nuclei",
}

func main() {
	kingpin.Parse()
	fmt.Printf("[i] Binaries required (%d): %s\n", len(binariesRequired), binariesRequired)

	target := scanner.Target{
		Target: *host,
	}

	if !target.IsValidHost() {
		fmt.Println("[!] Invalid host. Please provide a domain name or an IP Address")
		return
	}

	if !target.IsDomain() {
		fmt.Println("[!] Only domain names are supported for now")
		return
	}

	scanner.Run(&target)
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
