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

type NmapOutput struct {
	IPAddress string
	Hostname  string
	Ports     []Port
}

func (n NmapOutput) String() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Target: %s", n.IPAddress))
	if n.Hostname != "" {
		sb.WriteString(fmt.Sprintf(" (%s)", n.Hostname))
	}
	sb.WriteString(fmt.Sprintf("\n  Open Ports (%d):", len(n.Ports)))
	for _, p := range n.Ports {
		sb.WriteString(fmt.Sprintf("\n    - %s", p.String()))
	}
	return sb.String()
}

type Port struct {
	Port      int
	Protocol  string
	State     string
	Service   string
	Product   string
	Version   string
	ExtraInfo string
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

	res := fmt.Sprintf("%d/%s [%s] %s", p.Port, proto, state, p.Service)
	if version != "" {
		res += " - " + version
	}
	return res
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
				Name      string `xml:"name,attr"`
				Product   string `xml:"product,attr"`
				Version   string `xml:"version,attr"`
				ExtraInfo string `xml:"extrainfo,attr"`
			} `xml:"service"`
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
			output.Ports = append(output.Ports, Port{
				Port:      p.PortID,
				Protocol:  p.Protocol,
				State:     p.State.State,
				Service:   p.Service.Name,
				Product:   p.Service.Product,
				Version:   p.Service.Version,
				ExtraInfo: p.Service.ExtraInfo,
			})
		}
	}

	return output, nil
}

// Run a nmap scan on the target (domain or IP)
func Nmap(t *Target, outputFile string, ports ...string) NmapOutput {
	fmt.Println("[+] Nmap scan started")
	xmlOutFile := path.Join(t.OutDir(), "nmap.xml")
	if outputFile != "" && strings.HasSuffix(outputFile, ".xml") {
		xmlOutFile = path.Join(t.OutDir(), outputFile)
	}

	if !utils.FileExists(xmlOutFile) {
		args := []string{t.Target, "-sV", "-Pn"}
		if len(ports) > 0 && ports[0] != "" {
			args = append(args, "-p", ports[0])
		} else {
			args = append(args, "-sT", "-sC", "-A")
		}
		args = append(args, "-oX", xmlOutFile)

		cmd := exec.Command("nmap", args...)
		if _, err := cmd.CombinedOutput(); err != nil {
			log.Fatal(err)
		}
	}
	fmt.Println("[+] Nmap results:", xmlOutFile)

	data, err := os.ReadFile(xmlOutFile)
	if err != nil {
		log.Fatal(err)
	}

	output, err := ParseNmapXML(data)
	if err != nil {
		log.Fatal(err)
	}

	if output.IPAddress == "" && t.IsIP() {
		output.IPAddress = t.Target
	}
	if output.Hostname == "" && t.IsDomain() {
		output.Hostname = t.Target
	}

	return output
}
