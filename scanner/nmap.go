package scanner

import (
	"encoding/xml"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path"
	"strings"

	"github.com/4lch3mis7/webzoro-golang/utils"
)

type Script struct {
	ID     string
	Output string
}

type Port struct {
	Port      int
	Protocol  string
	State     string
	Service   string
	Product   string
	Version   string
	ExtraInfo string
	CPEs      []string
	Scripts   []Script
}

func (p Port) String() string {
	var version string
	if p.Product != "" {
		version = p.Product
		if p.Version != "" {
			version += " " + p.Version
		}
	} else if p.Version != "" {
		version = p.Version
	}
	if p.ExtraInfo != "" {
		if version != "" {
			version += " (" + p.ExtraInfo + ")"
		} else {
			version = p.ExtraInfo
		}
	}

	proto := p.Protocol
	if proto == "" {
		proto = "tcp"
	}
	state := p.State
	if state == "" {
		state = "open"
	}

	portPlain := fmt.Sprintf("%d/%s", p.Port, proto)
	portPadded := fmt.Sprintf("%-9s", portPlain)
	portColored := utils.ColorPortNum.Sprint(portPlain) + portPadded[len(portPlain):]

	statePadded := fmt.Sprintf("%-7s", state)
	stateColored := utils.ColorPortState(state) + statePadded[len(state):]

	svcPadded := fmt.Sprintf("%-10s", p.Service)
	svcColored := utils.ColorService.Sprint(p.Service) + svcPadded[len(p.Service):]

	res := fmt.Sprintf("%s %s %s", portColored, stateColored, svcColored)
	if version != "" {
		res += " " + utils.ColorVersion.Sprint(version)
	}

	for i, s := range p.Scripts {
		lines := strings.Split(strings.Trim(s.Output, "\r\n"), "\n")
		prefix := "|"
		if i == len(p.Scripts)-1 {
			prefix = "|_"
		}
		treePrefix := utils.ColorTree.Sprint(prefix)
		scriptID := utils.ColorBold.Sprint(s.ID)
		if len(lines) == 1 && lines[0] != "" {
			res += fmt.Sprintf("\n%s %s: %s", treePrefix, scriptID, lines[0])
		} else {
			res += fmt.Sprintf("\n%s %s: ", utils.ColorTree.Sprint("|"), scriptID)
			for j, line := range lines {
				subPrefix := "|"
				if i == len(p.Scripts)-1 && j == len(lines)-1 {
					subPrefix = "|_"
				}
				res += fmt.Sprintf("\n%s   %s", utils.ColorTree.Sprint(subPrefix), line)
			}
		}
	}

	return res
}

func (p Port) Summary() string {
	var version string
	if p.Product != "" {
		version = p.Product
		if p.Version != "" {
			version += " " + p.Version
		}
	} else if p.Version != "" {
		version = p.Version
	}
	if p.ExtraInfo != "" {
		if version != "" {
			version += " (" + p.ExtraInfo + ")"
		} else {
			version = p.ExtraInfo
		}
	}

	proto := p.Protocol
	if proto == "" {
		proto = "tcp"
	}
	state := p.State
	if state == "" {
		state = "open"
	}

	res := fmt.Sprintf("%s [%s] %s",
		utils.ColorPortNum.Sprintf("%d/%s", p.Port, proto),
		utils.ColorPortState(state),
		utils.ColorService.Sprint(p.Service),
	)
	if version != "" {
		res += " - " + utils.ColorVersion.Sprint(version)
	}
	return res
}

type NmapOutput struct {
	IPAddress string
	Hostname  string
	RawOutput string
	Verbose   bool
	Ports     []Port
}

func (n NmapOutput) String() string {
	if n.Verbose {
		if n.RawOutput != "" {
			return n.RawOutput
		}
		var sb strings.Builder
		sb.WriteString(utils.ColorHeader.Sprintf("Nmap scan report for %s", n.IPAddress))
		if n.Hostname != "" {
			sb.WriteString(utils.ColorHighlight.Sprintf(" (%s)", n.Hostname))
		}
		sb.WriteString("\n" + utils.ColorHeader.Sprint("PORT      STATE   SERVICE    VERSION") + "\n")
		for _, p := range n.Ports {
			sb.WriteString(p.String() + "\n")
		}
		return sb.String()
	}

	return n.Summary()
}

func (n NmapOutput) Summary() string {
	var sb strings.Builder
	target := n.IPAddress
	if n.Hostname != "" {
		if target != "" {
			target = fmt.Sprintf("%s (%s)", n.Hostname, n.IPAddress)
		} else {
			target = n.Hostname
		}
	}
	sb.WriteString(fmt.Sprintf("%s: %s\n", utils.ColorBold.Sprint("Target"), utils.ColorHighlight.Sprint(target)))
	sb.WriteString(fmt.Sprintf("  %s (%d):", utils.ColorHighlight.Sprint("Open Ports"), len(n.Ports)))
	for _, p := range n.Ports {
		sb.WriteString(fmt.Sprintf("\n    - %s", p.Summary()))
	}
	return sb.String()
}

type nmapXML struct {
	Host struct {
		Addresses []struct {
			Addr     string `xml:"addr,attr"`
			AddrType string `xml:"addrtype,attr"`
		} `xml:"address"`
		Hostnames []struct {
			Name string `xml:"name,attr"`
			Type string `xml:"type,attr"`
		} `xml:"hostnames>hostname"`
		Ports []struct {
			PortID   int    `xml:"portid,attr"`
			Protocol string `xml:"protocol,attr"`
			State    struct {
				State string `xml:"state,attr"`
			} `xml:"state"`
			Service struct {
				Name      string   `xml:"name,attr"`
				Product   string   `xml:"product,attr"`
				Version   string   `xml:"version,attr"`
				ExtraInfo string   `xml:"extrainfo,attr"`
				CPEs      []string `xml:"cpe"`
			} `xml:"service"`
			Scripts []struct {
				ID     string `xml:"id,attr"`
				Output string `xml:"output,attr"`
			} `xml:"script"`
		} `xml:"ports>port"`
	} `xml:"host"`
}

// Parse Nmap XML output and return NmapOutput
func ParseNmapXML(xmlData []byte) (NmapOutput, error) {
	var scan nmapXML
	if err := xml.Unmarshal(xmlData, &scan); err != nil {
		return NmapOutput{}, err
	}

	var output NmapOutput

	for _, addr := range scan.Host.Addresses {
		if addr.AddrType == "ipv4" || output.IPAddress == "" {
			output.IPAddress = addr.Addr
		}
	}

	for _, hn := range scan.Host.Hostnames {
		if hn.Type == "user" || output.Hostname == "" {
			output.Hostname = hn.Name
			if hn.Type == "user" {
				break
			}
		}
	}

	for _, p := range scan.Host.Ports {
		if p.State.State == "open" {
			var scripts []Script
			for _, s := range p.Scripts {
				scripts = append(scripts, Script{
					ID:     s.ID,
					Output: s.Output,
				})
			}

			output.Ports = append(output.Ports, Port{
				Port:      p.PortID,
				Protocol:  p.Protocol,
				State:     p.State.State,
				Service:   p.Service.Name,
				Product:   p.Service.Product,
				Version:   p.Service.Version,
				ExtraInfo: p.Service.ExtraInfo,
				CPEs:      p.Service.CPEs,
				Scripts:   scripts,
			})
		}
	}

	return output, nil
}

// Run a nmap scan on the target (domain or IP)
func Nmap(t *Target, outputFile string, ports ...string) NmapOutput {
	utils.LogAction("Nmap scan started")
	xmlOutFile := path.Join(t.OutDir(), "nmap.xml")
	stdOutFile := path.Join(t.OutDir(), "nmap.stdout")

	if outputFile != "" {
		if strings.HasSuffix(outputFile, ".xml") {
			xmlOutFile = path.Join(t.OutDir(), outputFile)
		} else {
			stdOutFile = path.Join(t.OutDir(), outputFile)
		}
	}

	if !utils.FileExists(xmlOutFile) || !utils.FileExists(stdOutFile) {
		args := []string{t.Target, "-sT", "-sV", "-sC", "-A", "-Pn"}
		if len(ports) > 0 && ports[0] != "" {
			args = []string{t.Target, "-sV", "-sC", "-A", "-Pn", "-p", ports[0]}
		}
		args = append(args, "-oN", stdOutFile, "-oX", xmlOutFile)

		cmd := exec.Command("nmap", args...)
		if _, err := cmd.CombinedOutput(); err != nil {
			log.Fatal(err)
		}
	}
	utils.LogSuccess("Nmap results: %s", stdOutFile)

	data, err := os.ReadFile(xmlOutFile)
	if err != nil {
		log.Fatal(err)
	}

	output, err := ParseNmapXML(data)
	if err != nil {
		log.Fatal(err)
	}

	if utils.FileExists(stdOutFile) {
		if raw, err := os.ReadFile(stdOutFile); err == nil {
			output.RawOutput = strings.TrimSpace(string(raw))
		}
	}

	if t != nil {
		output.Verbose = t.Verbose
		if output.IPAddress == "" && t.IsIP() {
			output.IPAddress = t.Target
		}
		if output.Hostname == "" && t.IsDomain() {
			output.Hostname = t.Target
		}
	}

	return output
}
