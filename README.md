# Webzoro

Fast network reconnaissance, port scanning, service enumeration, and vulnerability scanner.

## Prerequisites

Ensure the following tools are in your `PATH`:
- [nmap](https://nmap.org/)
- [subfinder](https://github.com/projectdiscovery/subfinder)
- [nuclei](https://github.com/projectdiscovery/nuclei)
- [ffuf](https://github.com/ffuf/ffuf)

## Installation

```bash
go build -o webzoro main.go
```

## Usage

```bash
# Scan a domain or IP (scans all 65,535 ports)
./webzoro <host>

# Enable verbose mode
./webzoro <host> -v
```

## Terminal Colors

Webzoro includes colorized status badges and severity indicators:
- `[*]`: Action / in progress
- `[+]`: Discovered finding / success
- `[!]`: Warning or critical finding
- `[-]`: Error / failure
- `[i]`: Informational notice

Vulnerability severities (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`) and exploit states (KEV / active PoCs) are highlighted automatically. The [`NO_COLOR`](https://no-color.org/) standard is respected.

