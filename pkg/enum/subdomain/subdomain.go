package subdomain

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"regexp"
	"time"

	"github.com/4lch3mis7/webzoro-golang/pkg/utils"
)

// Enumerate subdomains via crt.sh (CT Logs)
func CrtSh(domain string) (subdomains []string) {
	resp, err := http.Get(fmt.Sprintf("https://crt.sh/?q=%s&output=json", domain))
	if err != nil || resp.StatusCode != 200 {
		log.Println("[!] Error: Unable to fetch CT Logs from crt.sh for", domain)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Println(err)
		return []string{}
	}
	re := regexp.MustCompile(fmt.Sprintf(`([a-z0-9]+\.%s)`, domain))
	subdomains = append(subdomains, re.FindAllString(string(body), -1)...)
	return utils.Unique(subdomains)
}

// Bruteforce subdomains via DNS lookup
func DNSBrute(domain string, wordlistPath string) []string {
	start := time.Now()
	result := []string{}
	in := make(chan string)
	out := make(chan string)

	go utils.ReadLinesCh(wordlistPath, in)
	go DNSBruteConc(domain, in, out, 200)

	for i := range out {
		result = append(result, fmt.Sprintf("%s.%s", i, domain))
		fmt.Printf("%s.%s\n", i, domain)
	}

	timeElapsed := time.Since(start)

	fmt.Println("Time taken:", timeElapsed)

	return result
}

// Bruteforce subdomains vis DNS lookup.
// domain: Target domain to enumerate subdomains of
// wCh: Channel of string containing subdomain list for bruteforce
// oCh: Output channel which holds discovered subdomains
// conc: Number of goroutines to run concurrently
func DNSBruteConc(domain string, wCh <-chan string, oCh chan<- string, conc int) {
	for i := 0; i < conc; i++ {
		go func() {
			for subdomain := range wCh {
				if _, err := net.LookupHost(fmt.Sprintf("%s.%s", subdomain, domain)); err == nil {
					oCh <- subdomain
				}
			}
		}()
	}
}

func DNSLookupConc(hosts <-chan string, out chan<- string, conc int) {
	for i := 0; i < conc; i++ {
		go func() {
			for host := range hosts {
				if _, err := net.LookupHost(host); err == nil {
					out <- host
				}
			}
		}()
	}
}

// Enumerate subdomains passively using
func Virustotal(domiain string) []string {
	return []string{}
}
