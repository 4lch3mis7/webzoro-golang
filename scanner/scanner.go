package scanner

import (
	"fmt"

	"github.com/4lch3mis7/webzoro-golang/enum"
)

type Scanner struct {
	Target *Target
}

func Run(t *Target) {

	// Enumerate subdomains
	subCh := make(chan string)
	enum.EnumSubdomains(t.Target, subCh)

	for subdomain := range subCh {
		fmt.Println(subdomain)
	}

	// // If the target is a domain or an IP
	// if t.IsDomain() || t.IsIP() {
	// 	// Nmap(t.Target, path.Join(t.Target, "nmap.out"))
	// 	FFUF(t.Url(), t.GetWorkingDir()+"/ffuf.out")
	// 	// Dirsearch(t.Url(), t.GetWorkingDir()+"/dirsearch.out")
	// }
}
