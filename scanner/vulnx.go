package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"strings"
	"time"

	"github.com/4lch3mis7/webzoro-golang/utils"
	"github.com/projectdiscovery/vulnx/v2"
)

type ServiceVuln struct {
	Port            int                   `json:"port"`
	Service         string                `json:"service"`
	Product         string                `json:"product"`
	Version         string                `json:"version"`
	CPE             string                `json:"cpe,omitempty"`
	Vulnerabilities []vulnx.Vulnerability `json:"vulnerabilities"`
}

type VulnReport struct {
	Target   string        `json:"target"`
	Verbose  bool          `json:"-"`
	Services []ServiceVuln `json:"services"`
}

func (r VulnReport) String() string {
	if len(r.Services) == 0 {
		return "[i] No known vulnerabilities found for open services.\n"
	}

	var sb strings.Builder
	totalVulns := 0
	for _, s := range r.Services {
		totalVulns += len(s.Vulnerabilities)
	}

	sb.WriteString(fmt.Sprintf("\n[+] Found %d potential vulnerabilities across %d services:\n", totalVulns, len(r.Services)))

	for _, s := range r.Services {
		svcLabel := s.Service
		if s.Product != "" {
			svcLabel = s.Product
			if s.Version != "" {
				svcLabel += " " + s.Version
			}
		}

		sb.WriteString(fmt.Sprintf("\n  PORT %d (%s):\n", s.Port, svcLabel))
		if len(s.Vulnerabilities) == 0 {
			sb.WriteString("    (No CVEs matched)\n")
			continue
		}

		for _, v := range s.Vulnerabilities {
			// Formatting severity tag
			sev := strings.ToUpper(v.Severity)
			if sev == "" {
				sev = "UNKNOWN"
			}

			var tags []string
			if v.CvssScore > 0 {
				tags = append(tags, fmt.Sprintf("CVSS: %.1f", v.CvssScore))
			}
			if v.EpssScore > 0 {
				tags = append(tags, fmt.Sprintf("EPSS: %.2f%%", v.EpssScore*100))
			}
			if v.IsKev {
				tags = append(tags, "KEV: YES")
			}
			if v.IsPoc {
				tags = append(tags, "PoC: YES")
			}
			if v.IsTemplate {
				tags = append(tags, "Nuclei: YES")
			}

			tagStr := ""
			if len(tags) > 0 {
				tagStr = " [" + strings.Join(tags, " | ") + "]"
			}

			sb.WriteString(fmt.Sprintf("    * %-14s %-8s%s\n", v.CVEID, sev, tagStr))

			if r.Verbose && v.Description != "" {
				desc := strings.TrimSpace(v.Description)
				if len(desc) > 120 {
					desc = desc[:117] + "..."
				}
				sb.WriteString(fmt.Sprintf("        %s\n", desc))
			}
		}
	}

	return sb.String()
}

// LookupServiceCVEs queries the ProjectDiscovery vulnx API for CVEs matching open ports.
func LookupServiceCVEs(t *Target, ports []Port, outputFile string) VulnReport {
	reportFile := path.Join(t.OutDir(), outputFile)

	// Check cache first
	if utils.FileExists(reportFile) {
		data, err := os.ReadFile(reportFile)
		if err == nil && len(data) > 0 {
			var cached VulnReport
			if err := json.Unmarshal(data, &cached); err == nil && len(cached.Services) > 0 {
				cached.Verbose = t.Verbose
				fmt.Println("[+] Loaded cached CVE results from", reportFile)
				return cached
			}
		}
	}

	fmt.Println("[*] Checking for CVEs on open services via ProjectDiscovery vulnx...")

	client, err := vulnx.New(
		vulnx.WithKeyFromEnv(),
	)
	if err != nil {
		fmt.Printf("[!] Failed to initialize vulnx client: %v\n", err)
		return VulnReport{Target: t.Target, Verbose: t.Verbose}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	var services []ServiceVuln
	rateLimited := false

portsLoop:
	for _, p := range ports {
		if p.State != "open" && p.State != "" {
			continue
		}

		queries := buildSearchQueries(p)
		if len(queries) == 0 {
			continue
		}

		var matchedVulns []vulnx.Vulnerability
		seenCVEs := make(map[string]bool)

		for _, query := range queries {
			params := vulnx.SearchParams{
				Query: vulnx.Ptr(query),
				Limit: vulnx.Ptr(10),
			}

			resp, err := client.SearchVulnerabilities(ctx, params)
			if err != nil {
				if strings.Contains(err.Error(), "rate limit") || strings.Contains(err.Error(), "429") {
					fmt.Println("[!] Vulnx API rate limit reached. Set PDCP_API_KEY environment variable for higher limits.")
					rateLimited = true
					break portsLoop
				}
				continue
			}

			for _, v := range resp.Results {
				if !seenCVEs[v.CVEID] {
					seenCVEs[v.CVEID] = true
					matchedVulns = append(matchedVulns, v)
				}
			}

			// If we got good results from the primary query (e.g. CPE), no need to over-query
			if len(matchedVulns) > 0 {
				break
			}
		}

		if len(matchedVulns) > 0 {
			primaryCPE := ""
			if len(p.CPEs) > 0 {
				primaryCPE = p.CPEs[0]
			}
			services = append(services, ServiceVuln{
				Port:            p.Port,
				Service:         p.Service,
				Product:         p.Product,
				Version:         p.Version,
				CPE:             primaryCPE,
				Vulnerabilities: matchedVulns,
			})
		}
	}

	report := VulnReport{
		Target:   t.Target,
		Verbose:  t.Verbose,
		Services: services,
	}

	// Cache to file only if we found services and were not rate-limited
	if !rateLimited && len(services) > 0 {
		if data, err := json.MarshalIndent(report, "", "  "); err == nil {
			_ = os.WriteFile(reportFile, data, 0644)
		}
	}

	return report
}

// buildSearchQueries constructs prioritized queries for vulnx based on port metadata.
func buildSearchQueries(p Port) []string {
	var queries []string

	// 1. Try CPE first if available
	for _, cpe := range p.CPEs {
		if cpe != "" {
			queries = append(queries, fmt.Sprintf("cpe:\"%s\"", cpe))
		}
	}

	// 2. Try product and version
	if p.Product != "" {
		prod := strings.ToLower(p.Product)
		// Clean version: strip OS specific tags (e.g., "5.7.29-0ubuntu0.18.04.1" -> "5.7.29")
		ver := cleanVersion(p.Version)
		if ver != "" {
			queries = append(queries, fmt.Sprintf("%s %s", prod, ver))
		} else {
			queries = append(queries, prod)
		}
	}

	return queries
}

// cleanVersion extracts the base version string before any distro-specific dashes.
func cleanVersion(v string) string {
	v = strings.TrimSpace(v)
	if idx := strings.Index(v, "-"); idx != -1 {
		v = v[:idx]
	}
	return v
}
