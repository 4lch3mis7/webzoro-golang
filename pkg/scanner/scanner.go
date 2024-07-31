package scanner

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"

	"github.com/4lch3mis7/webzoro-golang/pkg/enum/subdomain"
)

type Scanner struct {
	Target *Target
}

func Scan(t *Target) {
	// If the target is a domain or an IP
	if t.IsDomain() || t.IsIP() {
		// Nmap(t.Target, path.Join(t.Target, "nmap.out"))
		FFUF(t.Url(), t.GetWorkingDir()+"/ffuf.out")
		// Dirsearch(t.Url(), t.GetWorkingDir()+"/dirsearch.out")
	}
}

// Enumerates subdomain of a domain and return a list
func EnumSubdomains(domain string, outputFile string) []string {

	// Enumerate sudomains from CT logs
	ctDomains := subdomain.CrtSh(domain)

	// Enumerate subdomains via DNS lookup (brute force)

	return ctDomains

}

// Run a nmap scan on the target (domain or IP)
func Nmap(target string, outputFile string) {
	fmt.Println("[+] Nmap scan started")
	os.Create(outputFile)
	cmd := exec.Command("nmap", target, "-sT", "-sV", "-sC", "-A", "-Pn", "-oN", outputFile)
	_, err := cmd.CombinedOutput()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("[+] Nmap results:", outputFile)
}

// Enumerate web directories for the target URL using `dirsearch`
func Dirsearch(targetUrl string, outputFile string) {
	fmt.Println("[+] Enumerating directories via dirsearch")
	os.Create(outputFile)
	cmd := exec.Command("dirsearch", "-F", "-u", targetUrl, "-o", outputFile)
	if _, err := cmd.CombinedOutput(); err == nil {
		log.Fatal(err)
	}
	fmt.Println("[+] Dirsearch result:", outputFile)
}

// Enumerate web directories for the target URL using `ffuf`
func FFUF(targetUrl string, outputFile string) {
	fmt.Println("[+] Enumerating directories via FFUF")

	os.Create(outputFile)
	wordsFile, _ := os.Create(os.TempDir() + "/combined_words.txt")
	defer wordsFile.Close()

	resp, err := http.Get("https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/combined_words.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	if _, err := io.Copy(wordsFile, resp.Body); err != nil {
		log.Fatal(err)
	}

	cmd := exec.Command("ffuf", "-r", "-w", wordsFile.Name(), "-u", targetUrl+"/FUZZ", "-o", outputFile)
	if _, err := cmd.CombinedOutput(); err == nil {
		log.Fatal(err)
	}
	fmt.Println("[+] FFUF result:", outputFile)
}
