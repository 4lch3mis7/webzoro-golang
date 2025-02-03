package scanner

import (
	"fmt"
	"strings"

	"github.com/4lch3mis7/webzoro-golang/enum"
	"github.com/4lch3mis7/webzoro-golang/utils"
)

type Scanner struct {
	Target    *Target
	OutputDir string
}

func Run(t *Target) {

	// Enumerate subdomains
	subdomains := enum.EnumSubdomains(t.Target)

	// Save subdomains to a file.
	if len(subdomains) > 0 {
		path := t.OutDir() + "/subdomains.txt"
		utils.SaveToFile(path, strings.Join(subdomains, "\n"))
		fmt.Println("[i] Subdomains saved to", path)
	}

	// Scan subdomains
	for _, subdomain := range subdomains {
		fmt.Println(subdomain)
	}

	// Nuclei scan
}
