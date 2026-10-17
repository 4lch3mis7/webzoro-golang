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
	totalExploits := 0
	for _, s := range r.Services {
		totalVulns += len(s.Vulnerabilities)
		for _, v := range s.Vulnerabilities {
			if v.IsKev || v.IsPoc || len(v.Pocs) > 0 || v.PocCount > 0 {
				totalExploits++
			}
		}
	}

	exploitTag := fmt.Sprintf("%d with public exploits/KEV", totalExploits)
	if totalExploits > 0 {
		exploitTag = utils.ColorCritical.Sprintf("%d with public exploits/KEV", totalExploits)
	}

	sb.WriteString(fmt.Sprintf("\n%s Found %s potential vulnerabilities across %s services (%s):\n",
		utils.TagSuccess(),
		utils.ColorHighlight.Sprintf("%d", totalVulns),
		utils.ColorHighlight.Sprintf("%d", len(r.Services)),
		exploitTag,
	))

	for _, s := range r.Services {
		svcLabel := s.Service
		if s.Product != "" {
			svcLabel = s.Product
			if s.Version != "" {
				svcLabel += " " + s.Version
			}
		}

		exploitCount := 0
		for _, v := range s.Vulnerabilities {
			if v.IsKev || v.IsPoc || len(v.Pocs) > 0 || v.PocCount > 0 {
				exploitCount++
			}
		}
		exploitSummary := ""
		if exploitCount > 0 {
			exploitSummary = utils.ColorCritical.Sprintf(" [%d exploitable]", exploitCount)
		}

		sb.WriteString(fmt.Sprintf("\n  %s %s (%s) - %s%s:\n",
			utils.ColorBold.Sprint("PORT"),
			utils.ColorPortNum.Sprintf("%d", s.Port),
			utils.ColorService.Sprint(svcLabel),
			utils.ColorHighlight.Sprintf("%d CVE(s)", len(s.Vulnerabilities)),
			exploitSummary,
		))
		if len(s.Vulnerabilities) == 0 {
			sb.WriteString(utils.ColorDim.Sprint("    (No CVEs matched)\n"))
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
				cvssStr := fmt.Sprintf("CVSS: %.1f", v.CvssScore)
				if v.CvssScore >= 9.0 {
					tags = append(tags, utils.ColorCritical.Sprint(cvssStr))
				} else if v.CvssScore >= 7.0 {
					tags = append(tags, utils.ColorWarn.Sprint(cvssStr))
				} else {
					tags = append(tags, utils.ColorInfo.Sprint(cvssStr))
				}
			}
			if v.EpssScore > 0 {
				tags = append(tags, fmt.Sprintf("EPSS: %.2f%%", v.EpssScore*100))
			}

			// Explicit exploit / PoC status
			hasExploit := v.IsPoc || len(v.Pocs) > 0 || v.PocCount > 0
			if v.IsKev {
				tags = append(tags, utils.ColorCritical.Sprint("Exploit: ACTIVE (KEV)"))
			} else if hasExploit {
				if v.PocCount > 0 {
					tags = append(tags, utils.ColorWarn.Sprintf("Exploit: YES (%d PoCs)", v.PocCount))
				} else if len(v.Pocs) > 0 {
					tags = append(tags, utils.ColorWarn.Sprintf("Exploit: YES (%d PoCs)", len(v.Pocs)))
				} else {
					tags = append(tags, utils.ColorWarn.Sprint("Exploit: YES"))
				}
			} else {
				tags = append(tags, utils.ColorDim.Sprint("Exploit: NO"))
			}

			if v.IsTemplate {
				tags = append(tags, utils.ColorVersion.Sprint("Nuclei: YES"))
			}

			tagStr := ""
			if len(tags) > 0 {
				tagStr = " [" + strings.Join(tags, " | ") + "]"
			}

			cveIDStr := utils.ColorBold.Sprint(v.CVEID)
			sevBadge := utils.ColorSeverity(sev)
			sb.WriteString(fmt.Sprintf("    * %-22s %-12s%s\n", cveIDStr, sevBadge, tagStr))

			if r.Verbose && v.Description != "" {
				desc := strings.TrimSpace(v.Description)
				if len(desc) > 120 {
					desc = desc[:117] + "..."
				}
				sb.WriteString(fmt.Sprintf("        %s\n", utils.ColorDim.Sprint(desc)))
			}

			if r.Verbose && len(v.Pocs) > 0 {
				sb.WriteString(fmt.Sprintf("        %s\n", utils.ColorBold.Sprint("PoCs:")))
				maxPocs := 5
				for i, poc := range v.Pocs {
					if i >= maxPocs {
						sb.WriteString(fmt.Sprintf("          ... and %d more PoC(s)\n", len(v.Pocs)-maxPocs))
						break
					}
					if poc == nil || poc.URL == "" {
						continue
					}
					source := poc.Source
					if source == "" {
						source = "Link"
					}
					sb.WriteString(fmt.Sprintf("          - [%s] %s\n", utils.ColorInfo.Sprint(source), poc.URL))
				}
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
				utils.LogSuccess("Loaded cached CVE results from %s", reportFile)
				return cached
			}
		}
	}

	utils.LogAction("Checking for CVEs on open services via ProjectDiscovery vulnx...")

	client, err := vulnx.New(
		vulnx.WithKeyFromEnv(),
	)
	if err != nil {
		utils.LogWarn("Failed to initialize vulnx client: %v", err)
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
					utils.LogWarn("Vulnx API rate limit reached. Set PDCP_API_KEY environment variable for higher limits.")
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
