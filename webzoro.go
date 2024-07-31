package main

import (
	"fmt"
	"os/exec"

	"github.com/4lch3mis7/webzoro-golang/pkg/scanner"
	"github.com/4lch3mis7/webzoro-golang/pkg/utils"
	"github.com/alecthomas/kingpin/v2"
)

var (
	host = kingpin.Arg("host", "Host (domain or IP)").String()
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

	// DNS Lookup
	lines := utils.ReadLinesRemote("https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/namelist.txt")
	for _, i := range lines {
		fmt.Println(i)
	}
	// enumSubdomain.DNSBrute(target.Target, *subdomainWordlist)

	// wCh := make(chan string)
	// oCh := make(chan string)
	// utils.ReadLinesCh(*subdomainWordlist, wCh)
	// enum.DNSBruteConc(target.Target, wCh, oCh)

	// for i := range wCh {
	// 	fmt.Println(i)
	// }

	// // Subdomain Enumeration
	// if target.IsDomain() {
	// 	// wd := target.GetWorkingDir()
	// 	// scanner.EnumSubdomains(target.Target, path.Join(wd, "sublist3r.out"))
	// 	for i, s := range enum.EnumSubdomains(target.Target) {
	// 		fmt.Println(i, s)
	// 	}
	// }

	// // Run Scan on a Target
	// scanner.Scan(&target)

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
