package scanner

import (
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"

	"github.com/4lch3mis7/webzoro-golang/utils"
)

// Enumerate subdomains using subfinder
func Subfinder(domain, outputFile string) []string {
	utils.LogInfo("Enumerating subdomains from Subfinder")
	os.Create(outputFile)
	cmd := exec.Command("subfinder", "-d", domain, "-o", outputFile)
	if _, err := cmd.CombinedOutput(); err != nil {
		log.Fatal(err)
	}
	utils.LogInfo("Subdomains enumerated via Subfinder")
	return utils.ReadLines(outputFile)
}

// Run a nuclei scan on the target.
func Nuclei(target, outputFile string) []string {
	utils.LogAction("Running Nuclei scan")
	os.Create(outputFile)
	cmd := exec.Command("nuclei", "-as", "-silent", "-target", target, "-o", outputFile)
	if _, err := cmd.CombinedOutput(); err != nil {
		log.Fatal(err)
	}
	utils.LogSuccess("Nuclei scan results: %s", outputFile)
	return utils.ReadLines(outputFile)
}

// Enumerate web directories for the target URL using `dirsearch`
func Dirsearch(targetUrl, outputFile string) {
	utils.LogAction("Enumerating directories via dirsearch")
	os.Create(outputFile)
	cmd := exec.Command("dirsearch", "-F", "-u", targetUrl, "-o", outputFile)
	if _, err := cmd.CombinedOutput(); err == nil {
		log.Fatal(err)
	}
	utils.LogSuccess("Dirsearch result: %s", outputFile)
}

// Enumerate web directories for the target URL using `ffuf`
func FFUF(targetUrl, outputFile string) {
	utils.LogAction("Enumerating directories via FFUF")

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
	utils.LogSuccess("FFUF result: %s", outputFile)
}
