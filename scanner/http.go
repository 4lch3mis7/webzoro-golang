package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/4lch3mis7/webzoro-golang/utils"
)

// HTTPAuditResult stores the comprehensive security audit findings for an HTTP/HTTPS service.
type HTTPAuditResult struct {
	Target          string   `json:"target"`
	Port            int      `json:"port"`
	Scheme          string   `json:"scheme"`
	URL             string   `json:"url"`
	StatusCode      int      `json:"status_code"`
	StatusText      string   `json:"status_text,omitempty"`
	Title           string   `json:"title,omitempty"`
	ServerHeader    string   `json:"server_header,omitempty"`
	Technologies    []string `json:"technologies,omitempty"`
	TLSFindings     []string `json:"tls_findings,omitempty"`
	HeaderFindings  []string `json:"header_findings,omitempty"`
	AllowedMethods  string   `json:"allowed_methods,omitempty"`
	MethodFindings  []string `json:"method_findings,omitempty"`
	CORSFindings    []string `json:"cors_findings,omitempty"`
	CookieFindings  []string `json:"cookie_findings,omitempty"`
	ExposedPaths    []string `json:"exposed_paths,omitempty"`
	Recommendations []string `json:"recommendations,omitempty"`
}

var titleRegex = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

func (r HTTPAuditResult) String() string {
	var sb strings.Builder

	targetStr := fmt.Sprintf(" (%s:%d - %s)", r.Target, r.Port, strings.ToUpper(r.Scheme))
	sb.WriteString(fmt.Sprintf("\n%s %s%s:\n",
		utils.TagSuccess(),
		utils.ColorHeader.Sprint("HTTP Service Security Audit"),
		utils.ColorHighlight.Sprint(targetStr),
	))

	// General Information
	if r.URL != "" {
		statusStr := fmt.Sprintf("%d %s", r.StatusCode, r.StatusText)
		if r.StatusCode >= 200 && r.StatusCode < 300 {
			statusStr = utils.ColorSuccess.Sprint(statusStr)
		} else if r.StatusCode >= 300 && r.StatusCode < 400 {
			statusStr = utils.ColorInfo.Sprint(statusStr)
		} else if r.StatusCode >= 400 && r.StatusCode < 500 {
			statusStr = utils.ColorWarn.Sprint(statusStr)
		} else {
			statusStr = utils.ColorError.Sprint(statusStr)
		}
		sb.WriteString(fmt.Sprintf("    %-20s: %s [%s]\n",
			utils.ColorBold.Sprint("Endpoint"),
			utils.ColorHighlight.Sprint(r.URL),
			statusStr,
		))
	}

	if r.Title != "" {
		sb.WriteString(fmt.Sprintf("    %-20s: %s\n",
			utils.ColorBold.Sprint("Title"),
			utils.ColorHighlight.Sprint(r.Title),
		))
	} else {
		sb.WriteString(fmt.Sprintf("    %-20s: %s\n",
			utils.ColorBold.Sprint("Title"),
			utils.ColorDim.Sprint("(No title)"),
		))
	}

	if r.ServerHeader != "" {
		sb.WriteString(fmt.Sprintf("    %-20s: %s\n",
			utils.ColorBold.Sprint("Server Banner"),
			utils.ColorVersion.Sprint(r.ServerHeader),
		))
	}

	if len(r.Technologies) > 0 {
		sb.WriteString(fmt.Sprintf("    %-20s: %s\n",
			utils.ColorBold.Sprint("Technologies"),
			strings.Join(r.Technologies, ", "),
		))
	}

	// TLS / SSL Findings
	if len(r.TLSFindings) > 0 {
		sb.WriteString(fmt.Sprintf("    %s\n", utils.ColorBold.Sprint("TLS / SSL Configuration:")))
		for _, f := range r.TLSFindings {
			sb.WriteString(fmt.Sprintf("      - %s\n", utils.ColorRiskText(f)))
		}
	}

	// Security Headers Findings
	if len(r.HeaderFindings) > 0 {
		sb.WriteString(fmt.Sprintf("    %s\n", utils.ColorBold.Sprint("Security Headers:")))
		for _, f := range r.HeaderFindings {
			sb.WriteString(fmt.Sprintf("      - %s\n", utils.ColorRiskText(f)))
		}
	}

	// HTTP Methods Findings
	if r.AllowedMethods != "" || len(r.MethodFindings) > 0 {
		sb.WriteString(fmt.Sprintf("    %s\n", utils.ColorBold.Sprint("HTTP Methods:")))
		if r.AllowedMethods != "" {
			sb.WriteString(fmt.Sprintf("      - Allowed: %s\n", utils.ColorHighlight.Sprint(r.AllowedMethods)))
		}
		for _, f := range r.MethodFindings {
			sb.WriteString(fmt.Sprintf("      - %s\n", utils.ColorRiskText(f)))
		}
	}

	// CORS & Cookies Findings
	if len(r.CORSFindings) > 0 || len(r.CookieFindings) > 0 {
		sb.WriteString(fmt.Sprintf("    %s\n", utils.ColorBold.Sprint("CORS & Session Security:")))
		for _, f := range r.CORSFindings {
			sb.WriteString(fmt.Sprintf("      - %s\n", utils.ColorRiskText(f)))
		}
		for _, f := range r.CookieFindings {
			sb.WriteString(fmt.Sprintf("      - %s\n", utils.ColorRiskText(f)))
		}
	}

	// Exposed Sensitive Files & Paths
	if len(r.ExposedPaths) > 0 {
		sb.WriteString(fmt.Sprintf("    %s\n", utils.ColorBold.Sprint("Exposed Endpoints & Files:")))
		for _, f := range r.ExposedPaths {
			sb.WriteString(fmt.Sprintf("      - %s\n", utils.ColorRiskText(f)))
		}
	}

	// Hardening Recommendations
	if len(r.Recommendations) > 0 {
		sb.WriteString(fmt.Sprintf("    %s\n", utils.ColorBold.Sprint("Hardening Recommendations:")))
		for _, rec := range r.Recommendations {
			sb.WriteString(fmt.Sprintf("      - %s\n", utils.ColorRiskText(rec)))
		}
	}

	return sb.String()
}

// AuditHTTP performs a comprehensive security assessment of an HTTP or HTTPS service.
func AuditHTTP(t *Target, p Port) HTTPAuditResult {
	res := HTTPAuditResult{
		Target: t.Target,
		Port:   p.Port,
	}

	scheme := detectScheme(t.Target, p)
	res.Scheme = scheme
	baseURL := fmt.Sprintf("%s://%s:%d", scheme, t.Target, p.Port)
	if (scheme == "http" && p.Port == 80) || (scheme == "https" && p.Port == 443) {
		baseURL = fmt.Sprintf("%s://%s", scheme, t.Target)
	}
	res.URL = baseURL

	// HTTP client with custom timeouts and TLS configuration
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		DialContext: (&net.Dialer{
			Timeout: 4 * time.Second,
		}).DialContext,
		ResponseHeaderTimeout: 5 * time.Second,
	}

	client := &http.Client{
		Transport: tr,
		Timeout:   6 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 4 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	// 1. TLS/SSL Audit (if HTTPS)
	if scheme == "https" {
		auditTLS(t.Target, p.Port, &res)
	} else {
		res.TLSFindings = append(res.TLSFindings,
			"[!] WARNING: Unencrypted HTTP transmission (Sensitive data, credentials, and cookies sent in plaintext)",
		)
		res.Recommendations = append(res.Recommendations,
			"Enforce HTTPS (TLS 1.2+) across all web endpoints and redirect HTTP traffic to HTTPS",
		)
	}

	// 2. Base Request & Header Hardening Audit
	req, err := http.NewRequestWithContext(context.Background(), "GET", baseURL+"/", nil)
	if err != nil {
		return res
	}
	req.Header.Set("User-Agent", "Webzoro-Security-Audit/1.0")

	resp, err := client.Do(req)
	if err != nil {
		res.HeaderFindings = append(res.HeaderFindings,
			fmt.Sprintf("[!] WARNING: Initial HTTP probe failed: %v", err),
		)
		return res
	}
	defer resp.Body.Close()

	res.StatusCode = resp.StatusCode
	res.StatusText = http.StatusText(resp.StatusCode)

	// Extract Title from HTML body (first 64KB)
	bodyPreview, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if matches := titleRegex.FindSubmatch(bodyPreview); len(matches) > 1 {
		rawTitle := strings.TrimSpace(string(matches[1]))
		rawTitle = html.UnescapeString(rawTitle)
		res.Title = strings.Join(strings.Fields(rawTitle), " ")
	}

	// Fallback to Nmap http-title script output if HTML <title> was not present
	if res.Title == "" {
		for _, s := range p.Scripts {
			if strings.EqualFold(s.ID, "http-title") && s.Output != "" {
				res.Title = strings.TrimSpace(s.Output)
				break
			}
		}
	}

	// Server banner & technology disclosures
	auditBannersAndTech(resp.Header, &res)

	// Security Headers audit
	auditSecurityHeaders(resp.Header, scheme, &res)

	// Cookies Audit
	auditCookies(resp.Cookies(), scheme, &res)

	// 3. HTTP Methods Audit (OPTIONS probe)
	auditHTTPMethods(client, baseURL, &res)

	// 4. CORS Misconfiguration Audit
	auditCORS(client, baseURL, &res)

	// 5. Sensitive Endpoints & File Probes
	auditSensitiveEndpoints(client, baseURL, &res)

	return res
}

// detectScheme determines whether the service is running HTTP or HTTPS.
func detectScheme(host string, p Port) string {
	svc := strings.ToLower(p.Service)
	if svc == "https" || svc == "ssl/http" || p.Port == 443 || p.Port == 8443 {
		return "https"
	}
	for _, cpe := range p.CPEs {
		if strings.Contains(strings.ToLower(cpe), "https") {
			return "https"
		}
	}

	// Fast probe for TLS handshake
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", p.Port))
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err == nil {
		_ = conn.Close()
		return "https"
	}

	return "http"
}

// auditTLS evaluates certificate validity, expiration, and protocol version.
func auditTLS(host string, port int, res *HTTPAuditResult) {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 4 * time.Second}, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		res.TLSFindings = append(res.TLSFindings, fmt.Sprintf("[!] WARNING: TLS handshake error: %v", err))
		return
	}
	defer conn.Close()

	state := conn.ConnectionState()

	// TLS Version check
	switch state.Version {
	case tls.VersionTLS10:
		res.TLSFindings = append(res.TLSFindings, "[!] CRITICAL: Obsolete TLS 1.0 protocol enabled (vulnerable to POODLE/BEAST)")
		res.Recommendations = append(res.Recommendations, "Disable TLS 1.0 and TLS 1.1; enforce TLS 1.2 or TLS 1.3")
	case tls.VersionTLS11:
		res.TLSFindings = append(res.TLSFindings, "[!] WARNING: Deprecated TLS 1.1 protocol enabled")
		res.Recommendations = append(res.Recommendations, "Disable TLS 1.1; enforce TLS 1.2 or TLS 1.3")
	case tls.VersionTLS12:
		res.TLSFindings = append(res.TLSFindings, "[SECURE] TLS 1.2 negotiated")
	case tls.VersionTLS13:
		res.TLSFindings = append(res.TLSFindings, "[SECURE] Modern TLS 1.3 negotiated")
	}

	// Certificates validation
	if len(state.PeerCertificates) == 0 {
		res.TLSFindings = append(res.TLSFindings, "[!] WARNING: No peer certificate supplied by server")
		return
	}

	cert := state.PeerCertificates[0]
	now := time.Now()

	// Expiration check
	if now.After(cert.NotAfter) {
		res.TLSFindings = append(res.TLSFindings,
			fmt.Sprintf("[!] CRITICAL: Certificate EXPIRED on %s", cert.NotAfter.Format("2006-01-02")),
		)
		res.Recommendations = append(res.Recommendations, "Renew and replace expired TLS certificate immediately")
	} else if cert.NotAfter.Sub(now) < 14*24*time.Hour {
		daysLeft := int(cert.NotAfter.Sub(now).Hours() / 24)
		res.TLSFindings = append(res.TLSFindings,
			fmt.Sprintf("[!] WARNING: Certificate expires soon in %d day(s) (%s)", daysLeft, cert.NotAfter.Format("2006-01-02")),
		)
	} else {
		res.TLSFindings = append(res.TLSFindings,
			fmt.Sprintf("[SECURE] Certificate valid until %s (Subject: %s)", cert.NotAfter.Format("2006-01-02"), cert.Subject.CommonName),
		)
	}

	// Self-signed check
	if cert.Issuer.CommonName == cert.Subject.CommonName && cert.Issuer.CommonName != "" {
		res.TLSFindings = append(res.TLSFindings,
			fmt.Sprintf("[!] WARNING: Self-signed certificate detected (Issuer: %s)", cert.Issuer.CommonName),
		)
		res.Recommendations = append(res.Recommendations, "Replace self-signed certificate with one issued by a trusted public Certificate Authority")
	}
}

// auditBannersAndTech checks for detailed version disclosures in headers.
func auditBannersAndTech(headers http.Header, res *HTTPAuditResult) {
	server := headers.Get("Server")
	if server != "" {
		res.ServerHeader = server
		if regexp.MustCompile(`[0-9]+\.[0-9]+`).MatchString(server) {
			res.HeaderFindings = append(res.HeaderFindings,
				fmt.Sprintf("[!] WARNING: Server banner exposes granular version: %s", server),
			)
			res.Recommendations = append(res.Recommendations, "Configure web server tokens to minimal/off (e.g., ServerTokens Prod / server_tokens off)")
		} else {
			res.HeaderFindings = append(res.HeaderFindings,
				fmt.Sprintf("[i] Server token: %s", server),
			)
		}
	} else {
		res.HeaderFindings = append(res.HeaderFindings, "[SECURE] Server banner is hidden/masked")
	}

	// Common tech disclosure headers
	techHeaders := []string{"X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator", "X-Runtime"}
	for _, th := range techHeaders {
		if val := headers.Get(th); val != "" {
			res.Technologies = append(res.Technologies, fmt.Sprintf("%s: %s", th, val))
			res.HeaderFindings = append(res.HeaderFindings,
				fmt.Sprintf("[!] WARNING: Technology disclosure: %s: %s", th, val),
			)
			res.Recommendations = append(res.Recommendations, fmt.Sprintf("Remove or disable the '%s' HTTP response header", th))
		}
	}
}

// auditSecurityHeaders checks for standard defensive HTTP headers.
func auditSecurityHeaders(headers http.Header, scheme string, res *HTTPAuditResult) {
	// Strict-Transport-Security (HSTS)
	hsts := headers.Get("Strict-Transport-Security")
	if scheme == "https" {
		if hsts != "" {
			res.HeaderFindings = append(res.HeaderFindings, fmt.Sprintf("[SECURE] Strict-Transport-Security (HSTS): %s", hsts))
		} else {
			res.HeaderFindings = append(res.HeaderFindings, "[!] WARNING: Strict-Transport-Security (HSTS) missing")
			res.Recommendations = append(res.Recommendations, "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to enforce encrypted connections")
		}
	}

	// Content-Security-Policy (CSP)
	csp := headers.Get("Content-Security-Policy")
	if csp != "" {
		if strings.Contains(csp, "'unsafe-inline'") || strings.Contains(csp, "'unsafe-eval'") {
			res.HeaderFindings = append(res.HeaderFindings, "[!] WARNING: Content-Security-Policy contains 'unsafe-inline' or 'unsafe-eval'")
			res.Recommendations = append(res.Recommendations, "Refactor scripts to use CSP nonces or hashes rather than 'unsafe-inline'/'unsafe-eval'")
		} else {
			res.HeaderFindings = append(res.HeaderFindings, "[SECURE] Content-Security-Policy (CSP) configured")
		}
	} else {
		res.HeaderFindings = append(res.HeaderFindings, "[!] WARNING: Content-Security-Policy (CSP) missing")
		res.Recommendations = append(res.Recommendations, "Implement a robust Content-Security-Policy to mitigate Cross-Site Scripting (XSS)")
	}

	// X-Frame-Options
	xfo := headers.Get("X-Frame-Options")
	if xfo != "" {
		res.HeaderFindings = append(res.HeaderFindings, fmt.Sprintf("[SECURE] X-Frame-Options: %s (Clickjacking protected)", xfo))
	} else if csp == "" || !strings.Contains(csp, "frame-ancestors") {
		res.HeaderFindings = append(res.HeaderFindings, "[!] WARNING: X-Frame-Options missing (Clickjacking vulnerability risk)")
		res.Recommendations = append(res.Recommendations, "Set 'X-Frame-Options: DENY' or 'SAMEORIGIN' to protect against UI redressing/clickjacking")
	}

	// X-Content-Type-Options
	xcto := headers.Get("X-Content-Type-Options")
	if strings.EqualFold(strings.TrimSpace(xcto), "nosniff") {
		res.HeaderFindings = append(res.HeaderFindings, "[SECURE] X-Content-Type-Options: nosniff")
	} else {
		res.HeaderFindings = append(res.HeaderFindings, "[!] WARNING: X-Content-Type-Options missing or invalid (MIME-sniffing risk)")
		res.Recommendations = append(res.Recommendations, "Set 'X-Content-Type-Options: nosniff' to prevent browsers from MIME-sniffing responses")
	}

	// Referrer-Policy
	rp := headers.Get("Referrer-Policy")
	if rp != "" {
		res.HeaderFindings = append(res.HeaderFindings, fmt.Sprintf("[SECURE] Referrer-Policy: %s", rp))
	} else {
		res.HeaderFindings = append(res.HeaderFindings, "[i] Referrer-Policy not explicitly set (defaults to browser policy)")
	}
}

// auditHTTPMethods sends an OPTIONS request to identify allowed and dangerous methods.
func auditHTTPMethods(client *http.Client, baseURL string, res *HTTPAuditResult) {
	req, err := http.NewRequestWithContext(context.Background(), "OPTIONS", baseURL+"/", nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", "Webzoro-Security-Audit/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	allow := resp.Header.Get("Allow")
	if allow == "" {
		allow = resp.Header.Get("Public")
	}

	if allow != "" {
		res.AllowedMethods = allow
		allowUpper := strings.ToUpper(allow)

		hasDangerous := false
		if strings.Contains(allowUpper, "TRACE") || strings.Contains(allowUpper, "TRACK") {
			res.MethodFindings = append(res.MethodFindings,
				"[!] WARNING: TRACE/TRACK method enabled (Cross-Site Tracing / XST vulnerability)",
			)
			res.Recommendations = append(res.Recommendations, "Disable TRACE and TRACK HTTP methods in web server configuration")
			hasDangerous = true
		}
		if strings.Contains(allowUpper, "PUT") {
			res.MethodFindings = append(res.MethodFindings,
				"[!] WARNING: PUT method exposed (Potential unauthorized file upload risk)",
			)
			hasDangerous = true
		}
		if strings.Contains(allowUpper, "DELETE") {
			res.MethodFindings = append(res.MethodFindings,
				"[!] WARNING: DELETE method exposed",
			)
			hasDangerous = true
		}
		if strings.Contains(allowUpper, "PROPFIND") || resp.Header.Get("DAV") != "" {
			res.MethodFindings = append(res.MethodFindings,
				"[i] WebDAV extensions enabled on server",
			)
		}

		if !hasDangerous {
			res.MethodFindings = append(res.MethodFindings,
				"[SECURE] No dangerous HTTP methods (PUT, DELETE, TRACE) exposed",
			)
		}
	}
}

// auditCORS tests for permissive CORS and Origin reflection with credentials.
func auditCORS(client *http.Client, baseURL string, res *HTTPAuditResult) {
	testOrigin := "https://evil-scanner-test.com"
	req, err := http.NewRequestWithContext(context.Background(), "GET", baseURL+"/", nil)
	if err != nil {
		return
	}
	req.Header.Set("Origin", testOrigin)
	req.Header.Set("User-Agent", "Webzoro-Security-Audit/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	acao := resp.Header.Get("Access-Control-Allow-Origin")
	acac := resp.Header.Get("Access-Control-Allow-Credentials")

	if acao == testOrigin {
		if strings.EqualFold(acac, "true") {
			res.CORSFindings = append(res.CORSFindings,
				"[!] CRITICAL: Permissive CORS with credentials enabled (Arbitrary Origin reflected with Allow-Credentials: true)",
			)
			res.Recommendations = append(res.Recommendations, "Remove dynamic Origin reflection when Access-Control-Allow-Credentials is true")
		} else {
			res.CORSFindings = append(res.CORSFindings,
				fmt.Sprintf("[!] WARNING: Permissive CORS dynamically reflects arbitrary Origin (%s)", acao),
			)
		}
	} else if acao == "*" {
		res.CORSFindings = append(res.CORSFindings,
			"[i] Wildcard CORS enabled (Access-Control-Allow-Origin: *)",
		)
	} else {
		res.CORSFindings = append(res.CORSFindings,
			"[SECURE] CORS does not reflect arbitrary untrusted origins",
		)
	}
}

// auditCookies checks cookie flags: Secure, HttpOnly, and SameSite.
func auditCookies(cookies []*http.Cookie, scheme string, res *HTTPAuditResult) {
	if len(cookies) == 0 {
		return
	}

	allSecure := true
	for _, c := range cookies {
		var issues []string
		if scheme == "https" && !c.Secure {
			issues = append(issues, "missing Secure flag")
			allSecure = false
		}
		if !c.HttpOnly {
			issues = append(issues, "missing HttpOnly flag (XSS theft risk)")
			allSecure = false
		}
		if c.SameSite == http.SameSiteNoneMode || c.SameSite == 0 {
			issues = append(issues, "missing or permissive SameSite attribute (CSRF risk)")
			allSecure = false
		}

		if len(issues) > 0 {
			res.CookieFindings = append(res.CookieFindings,
				fmt.Sprintf("[!] WARNING: Cookie '%s': %s", c.Name, strings.Join(issues, ", ")),
			)
			res.Recommendations = append(res.Recommendations,
				fmt.Sprintf("Configure cookie '%s' with Secure, HttpOnly, and SameSite=Lax/Strict flags", c.Name),
			)
		}
	}

	if allSecure {
		res.CookieFindings = append(res.CookieFindings,
			fmt.Sprintf("[SECURE] All %d session cookie(s) properly flagged (Secure, HttpOnly)", len(cookies)),
		)
	}
}

// auditSensitiveEndpoints probes for high-risk files (robots.txt, .git, .env, Swagger, etc.).
func auditSensitiveEndpoints(client *http.Client, baseURL string, res *HTTPAuditResult) {
	probes := []struct {
		path        string
		matcher     func(status int, body []byte) (bool, string)
	}{
		{
			path: "/robots.txt",
			matcher: func(status int, body []byte) (bool, string) {
				if status == http.StatusOK && strings.Contains(strings.ToLower(string(body)), "user-agent") {
					var disallows []string
					for _, line := range strings.Split(string(body), "\n") {
						line = strings.TrimSpace(line)
						if strings.HasPrefix(strings.ToLower(line), "disallow:") {
							parts := strings.SplitN(line, ":", 2)
							if len(parts) == 2 && strings.TrimSpace(parts[1]) != "" {
								disallows = append(disallows, strings.TrimSpace(parts[1]))
							}
						}
					}
					if len(disallows) > 0 {
						preview := strings.Join(disallows, ", ")
						if len(disallows) > 4 {
							preview = strings.Join(disallows[:4], ", ") + ", ..."
						}
						return true, fmt.Sprintf("[i] robots.txt found (%d disallowed paths: %s)", len(disallows), preview)
					}
					return true, "[i] robots.txt found"
				}
				return false, ""
			},
		},
		{
			path: "/.git/HEAD",
			matcher: func(status int, body []byte) (bool, string) {
				if status == http.StatusOK && strings.HasPrefix(strings.TrimSpace(string(body)), "ref: refs/") {
					return true, "[!] CRITICAL: Git repository exposed (/.git/HEAD found with source code leak)"
				}
				return false, ""
			},
		},
		{
			path: "/.env",
			matcher: func(status int, body []byte) (bool, string) {
				if status == http.StatusOK {
					b := string(body)
					if strings.Contains(b, "DB_") || strings.Contains(b, "APP_") || strings.Contains(b, "SECRET") || strings.Contains(b, "PASSWORD") {
						return true, "[!] CRITICAL: Environment configuration exposed (/.env found with credentials/secrets)"
					}
				}
				return false, ""
			},
		},
		{
			path: "/.well-known/security.txt",
			matcher: func(status int, body []byte) (bool, string) {
				if status == http.StatusOK && strings.Contains(strings.ToLower(string(body)), "contact:") {
					return true, "[i] Security disclosure policy published (/.well-known/security.txt)"
				}
				return false, ""
			},
		},
		{
			path: "/swagger/index.html",
			matcher: func(status int, body []byte) (bool, string) {
				if status == http.StatusOK && strings.Contains(strings.ToLower(string(body)), "swagger") {
					return true, "[!] WARNING: Interactive Swagger API documentation exposed (/swagger/index.html)"
				}
				return false, ""
			},
		},
		{
			path: "/openapi.json",
			matcher: func(status int, body []byte) (bool, string) {
				if status == http.StatusOK && strings.Contains(strings.ToLower(string(body)), "openapi") {
					return true, "[!] WARNING: OpenAPI schema definition exposed (/openapi.json)"
				}
				return false, ""
			},
		},
	}

	for _, p := range probes {
		probeURL, err := url.JoinPath(baseURL, p.path)
		if err != nil {
			continue
		}

		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		req, err := http.NewRequestWithContext(ctx, "GET", probeURL, nil)
		if err != nil {
			cancel()
			continue
		}
		req.Header.Set("User-Agent", "Webzoro-Security-Audit/1.0")

		resp, err := client.Do(req)
		if err != nil {
			cancel()
			continue
		}

		bodySnippet, _ := io.ReadAll(io.LimitReader(resp.Body, 8*1024))
		resp.Body.Close()
		cancel()

		if matched, msg := p.matcher(resp.StatusCode, bodySnippet); matched {
			res.ExposedPaths = append(res.ExposedPaths, msg)
			if strings.Contains(msg, "CRITICAL") {
				res.Recommendations = append(res.Recommendations, fmt.Sprintf("Block public web access to sensitive path '%s' immediately", p.path))
			}
		}
	}
}
