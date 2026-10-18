package main

import (
	"os/exec"

	"github.com/4lch3mis7/webzoro-golang/scanner"
	"github.com/4lch3mis7/webzoro-golang/utils"
	"github.com/alecthomas/kingpin/v2"
)

var (
	host    = kingpin.Arg("host", "Host (domain or IP)").String()
	verbose = kingpin.Flag("verbose", "Verbose output").Short('v').Default("false").Bool()
	// tls  = kingpin.Flag("tls", "SSL/TLS").Default("false").Bool()
)

var binariesRequired = []string{
	"nmap",
	"subfinder",
	"nuclei",
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

func main() {
	kingpin.Parse()

	missing := CheckDependencies()
	if len(missing) > 0 {
		utils.LogWarn("Missing dependencies (%d): %v", len(missing), missing)
		return
	}

	utils.LogAction("All dependencies installed")

	target := scanner.Target{
		Target:  *host,
		Verbose: *verbose,
	}

	if !target.IsValidHost() {
		utils.LogWarn("Invalid host. Please provide a domain name or an IP Address")
		return
	}

	scanner.Run(&target)
}
