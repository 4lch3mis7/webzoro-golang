package utils

import (
	"fmt"
	"strings"

	"github.com/fatih/color"
)

var (
	// Prefix badges
	ColorInfo     = color.New(color.FgCyan, color.Bold)
	ColorAction   = color.New(color.FgCyan, color.Bold)
	ColorSuccess  = color.New(color.FgGreen, color.Bold)
	ColorWarn     = color.New(color.FgYellow, color.Bold)
	ColorCritical = color.New(color.FgHiRed, color.Bold)
	ColorError    = color.New(color.FgRed, color.Bold)

	// Text styling tokens
	ColorBold      = color.New(color.Bold)
	ColorDim       = color.New(color.Faint)
	ColorHighlight = color.New(color.FgHiWhite, color.Bold)
	ColorHeader    = color.New(color.FgHiCyan, color.Bold)
	ColorPortNum   = color.New(color.FgCyan)
	ColorService   = color.New(color.FgWhite, color.Bold)
	ColorVersion   = color.New(color.FgMagenta)
	ColorTree      = color.New(color.FgHiBlack)
)

// Log helpers with standard prefixes
func LogInfo(format string, a ...any) {
	fmt.Println(ColorInfo.Sprint("[i] ") + fmt.Sprintf(format, a...))
}

func LogAction(format string, a ...any) {
	fmt.Println(ColorAction.Sprint("[*] ") + fmt.Sprintf(format, a...))
}

func LogSuccess(format string, a ...any) {
	fmt.Println(ColorSuccess.Sprint("[+] ") + fmt.Sprintf(format, a...))
}

func LogWarn(format string, a ...any) {
	fmt.Println(ColorWarn.Sprint("[!] ") + fmt.Sprintf(format, a...))
}

func LogError(format string, a ...any) {
	fmt.Println(ColorError.Sprint("[-] ") + fmt.Sprintf(format, a...))
}

// Prefix tag string getters
func TagInfo() string     { return ColorInfo.Sprint("[i]") }
func TagAction() string   { return ColorAction.Sprint("[*]") }
func TagSuccess() string  { return ColorSuccess.Sprint("[+]") }
func TagWarn() string     { return ColorWarn.Sprint("[!]") }
func TagError() string    { return ColorError.Sprint("[-]") }
func TagCritical() string { return ColorCritical.Sprint("[!]") }

// ColorSeverity returns a colored badge for vulnerability severities.
func ColorSeverity(sev string) string {
	s := strings.ToUpper(strings.TrimSpace(sev))
	switch s {
	case "CRITICAL":
		return color.New(color.FgHiWhite, color.BgRed, color.Bold).Sprintf(" %s ", s)
	case "HIGH":
		return color.New(color.FgHiRed, color.Bold).Sprint(s)
	case "MEDIUM":
		return color.New(color.FgYellow, color.Bold).Sprint(s)
	case "LOW":
		return color.New(color.FgCyan).Sprint(s)
	case "INFO":
		return color.New(color.FgBlue).Sprint(s)
	default:
		return color.New(color.FgWhite, color.Faint).Sprint(s)
	}
}

// ColorPortState colors port status ("open", "filtered", "closed").
func ColorPortState(state string) string {
	switch strings.ToLower(strings.TrimSpace(state)) {
	case "open":
		return color.New(color.FgGreen, color.Bold).Sprint(state)
	case "filtered":
		return color.New(color.FgYellow).Sprint(state)
	case "closed":
		return color.New(color.FgRed).Sprint(state)
	default:
		return state
	}
}

// ColorRiskText highlights security evaluation tags like [SECURE], [!] CRITICAL:, [!] WARNING:.
func ColorRiskText(text string) string {
	if strings.Contains(text, "[!] CRITICAL:") {
		return strings.Replace(text, "[!] CRITICAL:", color.New(color.FgHiRed, color.Bold).Sprint("[!] CRITICAL:"), 1)
	}
	if strings.Contains(text, "[!] WARNING:") {
		return strings.Replace(text, "[!] WARNING:", color.New(color.FgYellow, color.Bold).Sprint("[!] WARNING:"), 1)
	}
	if strings.Contains(text, "[SECURE]") {
		return strings.Replace(text, "[SECURE]", color.New(color.FgGreen, color.Bold).Sprint("[SECURE]"), 1)
	}
	if strings.Contains(text, "[i]") {
		return strings.Replace(text, "[i]", color.New(color.FgCyan).Sprint("[i]"), 1)
	}
	return text
}
