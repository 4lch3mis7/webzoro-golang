package scanner

import (
	"context"
	"encoding/json"
	"log"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/4lch3mis7/webzoro-golang/utils"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/naabu/v2/pkg/result"
	"github.com/projectdiscovery/naabu/v2/pkg/runner"
)

type NaabuOutput struct {
	Host  string
	IP    string
	Ports []int
}

type naabuRecord struct {
	Host string `json:"host"`
	IP   string `json:"ip"`
	Port int    `json:"port"`
}

// Run a naabu scan natively using the Naabu Go runner
func Naabu(t *Target, outputFile string) NaabuOutput {
	utils.LogAction("Naabu scan started")
	if outputFile == "" {
		outputFile = path.Join(t.OutDir(), "naabu.json")
	} else if !strings.Contains(outputFile, "/") {
		outputFile = path.Join(t.OutDir(), outputFile)
	}

	output := NaabuOutput{
		Host:  t.Target,
		Ports: []int{},
	}

	if !utils.FileExists(outputFile) {
		options := runner.Options{
			Host:     goflags.StringSlice{t.Target},
			ScanType: "c",    // Connect scan (unprivileged; no root required)
			TopPorts: "full", // Scan all 65,535 ports (1-65535)

			// Throughput: push rate higher, fewer threads is fine for connect scan
			Rate:       3000, // packets/sec
			Threads:    25,   // connect scan is I/O bound, not CPU bound
			WarmUpTime: 1,    // seconds

			// Reliability vs speed: 1 retry is enough; 1500ms timeout was the main bottleneck
			Retries: 1,
			Timeout: 1500, // ms — sufficient for LAN/VPN; raise to 1500 for WAN targets

			Output:        outputFile,
			JSON:          true,
			Silent:        true,
			DisableStdout: true,
			OnResult: func(hr *result.HostResult) {
				if hr == nil {
					return
				}
				if output.IP == "" && hr.IP != "" {
					output.IP = hr.IP
				}
				if hr.Host != "" {
					output.Host = hr.Host
				}
				for _, p := range hr.Ports {
					if p != nil {
						output.Ports = append(output.Ports, p.Port)
					}
				}
			},
		}

		naabuRunner, err := runner.NewRunner(&options)
		if err != nil {
			log.Fatal(err)
		}
		defer naabuRunner.Close()

		if err := naabuRunner.RunEnumeration(context.Background()); err != nil {
			log.Fatal(err)
		}
	} else {
		// Read from existing cached output file
		lines := utils.ReadLines(outputFile)
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}

			var rec naabuRecord
			if err := json.Unmarshal([]byte(line), &rec); err == nil && rec.Port != 0 {
				if output.IP == "" && rec.IP != "" {
					output.IP = rec.IP
				}
				if rec.Host != "" {
					output.Host = rec.Host
				}
				output.Ports = append(output.Ports, rec.Port)
			} else if strings.Contains(line, ":") {
				parts := strings.Split(line, ":")
				if p, err := strconv.Atoi(parts[len(parts)-1]); err == nil {
					output.Ports = append(output.Ports, p)
				}
			}
		}
	}

	// Deduplicate and sort open ports
	portMap := make(map[int]bool)
	var uniquePorts []int
	for _, p := range output.Ports {
		if !portMap[p] && p > 0 {
			portMap[p] = true
			uniquePorts = append(uniquePorts, p)
		}
	}
	sort.Ints(uniquePorts)
	output.Ports = uniquePorts

	utils.LogSuccess("Naabu results: %s", outputFile)
	if len(output.Ports) > 0 {
		var portStrs []string
		for _, p := range output.Ports {
			portStrs = append(portStrs, utils.ColorPortNum.Sprintf("%d", p))
		}
		utils.LogSuccess("Open ports (%s): %s",
			utils.ColorHighlight.Sprintf("%d", len(output.Ports)),
			strings.Join(portStrs, ", "),
		)
	} else {
		utils.LogWarn("No open ports found on %s", output.Host)
	}

	if output.IP == "" && t.IsIP() {
		output.IP = t.Target
	}

	return output
}

// NaabuWithServiceScan runs Naabu for fast port discovery, then runs Nmap on the discovered ports for service & version detection
func NaabuWithServiceScan(t *Target) NmapOutput {
	naabuOut := Naabu(t, "")
	if len(naabuOut.Ports) == 0 {
		return NmapOutput{IPAddress: naabuOut.IP, Hostname: naabuOut.Host}
	}

	var portList []string
	for _, p := range naabuOut.Ports {
		portList = append(portList, strconv.Itoa(p))
	}
	portsArg := strings.Join(portList, ",")

	return Nmap(t, "nmap.xml", portsArg)
}
