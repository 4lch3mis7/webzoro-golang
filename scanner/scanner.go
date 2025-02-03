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
