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

func EnumSubdomains(t *Target) {

	// Enumerate subdomains
	subdomains := enum.EnumSubdomains(t.Target)

	// Save subdomains to a file.
	if len(subdomains) > 0 {
		path := t.OutDir() + "/subdomains.txt"
		utils.SaveToFile(path, strings.Join(subdomains, "\n"))
		fmt.Println("[i] Subdomains saved to", path)
	}

	// Run Nuclei on the subdomains
	for _, subdomain := range subdomains {
		outDir := t.OutDir() + "/nuclei"
		utils.CheckAndCreateDir(outDir)
		Nuclei(subdomain, outDir+"/"+subdomain+".stdout")
	}
	// var wg sync.WaitGroup
	// for _, subdomain := range subdomains {
	// 	wg.Add(1)
	// 	go func(wg *sync.WaitGroup, subdomain string) {
	// 		outDir := t.OutDir() + "/nuclei"
	// 		utils.CheckAndCreateDir(outDir)
	// 		Nuclei(subdomain, outDir+"/"+subdomain+".stdout")
	// 		wg.Done()
	// 	}(&wg, subdomain)
	// }
	// wg.Wait()
}

func Run(t *Target) {
	// Port scanning (Naabu) + Service and Version detection (Nmap)
	results := NaabuWithServiceScan(t)
	fmt.Println("[i] Scan results:\n", results)

	// Vulnerability lookup on discovered open services using ProjectDiscovery vulnx
	if len(results.Ports) > 0 {
		vulnReport := LookupServiceCVEs(t, results.Ports, "cves.json")
		fmt.Println(vulnReport)
	}
}

func Show(t *Target) {

}
