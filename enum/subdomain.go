package enum

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os/exec"
	"regexp"
	"strings"

	"github.com/4lch3mis7/webzoro-golang/utils"
)

// Enumerate subdomains using Certificate Transparency logs and DNS lookup.
//
// This function takes a domain name as an argument and returns a list of
// subdomains found in the Certificate Transparency logs and via DNS lookup.
func EnumSubdomains(domain string) []string {
	// Enumerating subdomains via Certificate Transparency logs
	ctSubs := GetSubdomainsFromCT(domain)

	// Enumerating subdomains via subfinder
	subfinderSubs := GetSubdomainsFromSubfinder(domain)

	// Combine all subdomains
	allSubs := append(ctSubs, subfinderSubs...)
	allSubs = utils.Unique(allSubs)

	return allSubs
}

// Enumerate subdomains using Certificate Transparency logs.
//
// This function takes a domain name as an argument and returns a list of
// subdomains found in the Certificate Transparency logs.
//
// It fetches the CT logs from crt.sh and parses the JSON response to extract
// the subdomains.
func GetSubdomainsFromCT(domain string) []string {
	log.Println("[i] Enumerating subdomains from CT logs")
	result := []string{}
	resp, err := http.Get(fmt.Sprintf("https://crt.sh/?q=%s&output=json", domain))
	if err != nil || resp.StatusCode != 200 {
		log.Println("[!] Error: Unable to fetch CT Logs from crt.sh for", domain)
		return []string{}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Println(err)
		return []string{}
	}

	// Extract subdomains from the response
	re := regexp.MustCompile(fmt.Sprintf(`([a-z0-9]+\.%s)`, domain))
	result = append(result, re.FindAllString(string(body), -1)...)
	log.Println("[i] Found", len(result), "subdomains from CT logs")

	// Remove duplicates
	log.Println("[i] Removing duplicate subdomains")
	result = utils.Unique(result)
	log.Println("[i] Found", len(result), "unique subdomains from CT logs")

	return result
}

// Enumerate subdomains using subfinder.
//
// This function takes a domain name as an argument and returns a list of
// subdomains found using subfinder tool.
func GetSubdomainsFromSubfinder(domain string) []string {
	log.Println("[i] Enumerating subdomains from subfinder")
	cmd := exec.Command("subfinder", "-d", domain, "-silent")
	out, err := utils.CmdExec(cmd)
	if err != nil {
		log.Println("[!] Error: Unable to enumerate subdomains from subfinder for", domain)
		return []string{}
	}

	// Extract subdomains from the output
	out = strings.TrimSpace(out)
	result := strings.Split(out, "\n")
	log.Println("[i] Found", len(result), "unique subdomains from subfinder")

	return result
}
