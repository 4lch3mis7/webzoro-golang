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
		utils.LogInfo("Subdomains saved to %s", path)
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
	utils.LogInfo("Scan results:\n%s", results)

	// Vulnerability lookup on discovered open services using ProjectDiscovery vulnx
	if len(results.Ports) > 0 {
		vulnReport := LookupServiceCVEs(t, results.Ports, "cves.json")
		fmt.Println(vulnReport)
	}

	// Specialized service audits (e.g. MySQL, HTTP/HTTPS security checks)
	for _, p := range results.Ports {
		if strings.Contains(strings.ToLower(p.Service), "mysql") || p.Port == 3306 {
			mysqlAudit := AuditMySQL(t, p)
			fmt.Println(mysqlAudit)
			// Enumerate MySQL if DefaultAccess is present
			if strings.Contains(mysqlAudit.DefaultAccess, "CRITICAL") {
				EnumerateMySQL(t)
			}
		}

		if isHTTPService(p) {
			httpAudit := AuditHTTP(t, p)
			fmt.Println(httpAudit)
		}
	}
}

// isHTTPService checks if a port is likely running an HTTP or HTTPS service.
func isHTTPService(p Port) bool {
	svc := strings.ToLower(p.Service)
	if strings.Contains(svc, "http") || strings.Contains(svc, "https") || svc == "ssl/http" || svc == "http-proxy" {
		return true
	}
	switch p.Port {
	case 80, 443, 8000, 8008, 8080, 8443, 8888, 9000, 9443:
		return true
	}
	for _, cpe := range p.CPEs {
		cpeLower := strings.ToLower(cpe)
		if strings.Contains(cpeLower, "http") || strings.Contains(cpeLower, "apache") || strings.Contains(cpeLower, "nginx") || strings.Contains(cpeLower, "coyote") {
			return true
		}
	}
	return false
}

func Show(t *Target) {

}
