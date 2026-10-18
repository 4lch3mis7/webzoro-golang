package scanner

import (
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// AuthWorkflowType denotes the specific type of authentication surface.
type AuthWorkflowType string

const (
	AuthTypeReset    AuthWorkflowType = "password_reset"
	AuthTypeLogin    AuthWorkflowType = "login"
	AuthTypeRegister AuthWorkflowType = "registration"
	AuthTypeMFA      AuthWorkflowType = "mfa_verify"
)

// AuthSmellSeverity indicates the severity level of a discovered weakness or leak.
type AuthSmellSeverity string

const (
	SeverityCritical AuthSmellSeverity = "CRITICAL"
	SeverityHigh     AuthSmellSeverity = "HIGH"
	SeverityMedium   AuthSmellSeverity = "MEDIUM"
	SeverityLow      AuthSmellSeverity = "LOW"
	SeverityInfo     AuthSmellSeverity = "INFO"
)

// AuthSmell represents a passive security observation, defect, or sensitive data leak.
type AuthSmell struct {
	Severity    AuthSmellSeverity `json:"severity"`
	Description string            `json:"description"`
	Evidence    string            `json:"evidence,omitempty"`
}

// AuthSurface represents a discovered authentication or password recovery workflow.
type AuthSurface struct {
	Type         AuthWorkflowType  `json:"type"`                    // password_reset, login, registration, mfa_verify
	URL          string            `json:"url"`                     // Form action URL or endpoint URL
	Method       string            `json:"method"`                  // POST, GET, etc.
	Source       string            `json:"source"`                  // html_form, js_route, link
	Inputs       []string          `json:"inputs"`                  // Form field names or parameters
	HiddenFields map[string]string `json:"hidden_fields,omitempty"` // Hidden form inputs name -> value
	Smells       []AuthSmell       `json:"smells,omitempty"`        // Passive findings or leakage
}

var (
	// Form boundary extraction
	formTagRegex     = regexp.MustCompile(`(?is)<form([^>]*)>(.*?)</form>`)
	formActionAttr   = regexp.MustCompile(`(?i)\baction\s*=\s*["']([^"']*)["']`)
	formMethodAttr   = regexp.MustCompile(`(?i)\bmethod\s*=\s*["']([^"']*)["']`)
	formIdNameAttr   = regexp.MustCompile(`(?i)\b(?:id|name|class)\s*=\s*["']([^"']*)["']`)
	buttonSubmitText = regexp.MustCompile(`(?is)<(?:button|input)[^>]*(?:value|type)\s*=\s*["']?([^"'>\s]+)`)

	// Keywords indicating password reset / recovery flows
	resetKeywordRegex = regexp.MustCompile(`(?i)(?:reset|forgot|recover|change[-_]pass|lost[-_]pass|magic[-_]link)`)
	loginKeywordRegex = regexp.MustCompile(`(?i)(?:login|signin|sign[-_]in|authenticate)`)
	regKeywordRegex   = regexp.MustCompile(`(?i)(?:register|signup|sign[-_]up|join|create[-_]account)`)

	// Client-side JS leakage patterns
	jsClientTokenLeakRegex = regexp.MustCompile(`(?i)(?:res|response|data|json)\s*\.\s*(token|otp|code|reset_url|reset_link|temp_pass(?:word)?)`)
	jsDestructTokenRegex   = regexp.MustCompile(`(?:const|let|var)\s*\{\s*[^}]*(?:token|otp|code|resetUrl|resetLink)[^}]*\}\s*=\s*(?:res|response|data)`)
	jsClientOTPGenRegex    = regexp.MustCompile(`(?i)Math\.random\(\)\s*[\*\/].*?(?:otp|token|code)`)
	jsAuthRouteRegex       = regexp.MustCompile(`(?i)["'](/(?:api/)?(?:v\d+/)?(?:auth/)?(?:reset|forgot|recover)[a-zA-Z0-9_/\-]*)["']`)

	// URL token leak regex
	urlResetTokenRegex = regexp.MustCompile(`(?i)/(?:reset|recover|verify|confirm|password)[^?\s]*\?(?:[^&\s]*&)*(?:token|key|code|hash|otp)=([a-zA-Z0-9_\-]{4,})`)

	// Sensitive comment leaks
	htmlCommentRegex = regexp.MustCompile(`(?is)<!--(.*?)-->`)
	sensitiveComment = regexp.MustCompile(`(?i)(?:token|otp|code|reset[-_]url|temp[-_]pass|password)\s*[:=]\s*([a-zA-Z0-9_\-\.]{4,})`)
)

// ExtractAuthFromHTML parses HTML content to passively identify auth & recovery forms, pre-seeded tokens, and leaks.
func ExtractAuthFromHTML(body []byte, baseURL *url.URL) []AuthSurface {
	var surfaces []AuthSurface
	bodyStr := string(body)

	// 1. Scan for <form> tags
	formMatches := formTagRegex.FindAllStringSubmatch(bodyStr, -1)
	for _, match := range formMatches {
		if len(match) < 3 {
			continue
		}
		attrs := match[1]
		inner := match[2]

		// Extract action and resolve URL
		action := ""
		if actMatch := formActionAttr.FindStringSubmatch(attrs); len(actMatch) > 1 {
			action = strings.TrimSpace(actMatch[1])
		}
		resolvedURL := baseURL.String()
		if action != "" {
			if strings.HasPrefix(action, "http://") || strings.HasPrefix(action, "https://") {
				resolvedURL = action
			} else {
				resolvedURL = baseURL.ResolveReference(&url.URL{Path: action}).String()
			}
		}

		// Extract method (default to GET if unspecified)
		method := "GET"
		if methMatch := formMethodAttr.FindStringSubmatch(attrs); len(methMatch) > 1 {
			method = strings.ToUpper(strings.TrimSpace(methMatch[1]))
		}

		// Collect form fields and hidden fields
		var inputNames []string
		hiddenFields := make(map[string]string)
		hasPassword := false
		hasConfirmPassword := false
		hasIdentifier := false

		for _, inputTag := range formInputTagRegex.FindAllString(inner, -1) {
			nameMatch := attrNameRegex.FindStringSubmatch(inputTag)
			if len(nameMatch) <= 1 {
				continue
			}
			name := strings.TrimSpace(nameMatch[1])
			if !isValidParam(name) {
				continue
			}
			inputNames = append(inputNames, name)

			typeVal := "text"
			if typeMatch := attrTypeRegex.FindStringSubmatch(inputTag); len(typeMatch) > 1 {
				typeVal = strings.ToLower(strings.TrimSpace(typeMatch[1]))
			}

			val := ""
			if valMatch := attrValueRegex.FindStringSubmatch(inputTag); len(valMatch) > 1 {
				val = strings.TrimSpace(valMatch[1])
			}

			nameLower := strings.ToLower(name)
			if typeVal == "password" || strings.Contains(nameLower, "password") || strings.Contains(nameLower, "pass") {
				if strings.Contains(nameLower, "confirm") || strings.Contains(nameLower, "retype") || strings.Contains(nameLower, "repeat") {
					hasConfirmPassword = true
				} else {
					hasPassword = true
				}
			}

			if strings.Contains(nameLower, "email") || strings.Contains(nameLower, "user") || strings.Contains(nameLower, "login") || strings.Contains(nameLower, "account") || strings.Contains(nameLower, "phone") {
				hasIdentifier = true
			}

			if typeVal == "hidden" {
				hiddenFields[name] = val
			}
		}

		// Check context signals (attrs, URL, inner text)
		pageContext := strings.ToLower(resolvedURL + " " + attrs + " " + inner)
		isResetMatch := resetKeywordRegex.MatchString(pageContext)
		isLoginMatch := loginKeywordRegex.MatchString(pageContext)
		isRegMatch := regKeywordRegex.MatchString(pageContext)

		var wfType AuthWorkflowType
		if isResetMatch || (!hasPassword && hasIdentifier && resetKeywordRegex.MatchString(resolvedURL)) {
			wfType = AuthTypeReset
		} else if isRegMatch || hasConfirmPassword {
			wfType = AuthTypeRegister
		} else if isLoginMatch || (hasPassword && hasIdentifier) {
			wfType = AuthTypeLogin
		} else {
			continue // Not an auth form
		}

		var smells []AuthSmell

		// Evaluate security smells on form
		if wfType == AuthTypeReset {
			// Check for pre-seeded tokens or OTP in hidden fields
			for k, v := range hiddenFields {
				kLower := strings.ToLower(k)
				if (strings.Contains(kLower, "token") || strings.Contains(kLower, "otp") || strings.Contains(kLower, "code") || strings.Contains(kLower, "key") || strings.Contains(kLower, "hash")) && len(v) >= 4 {
					smells = append(smells, AuthSmell{
						Severity:    SeverityHigh,
						Description: fmt.Sprintf("Pre-seeded reset token/OTP found in hidden field '%s'", k),
						Evidence:    fmt.Sprintf("%s=%s", k, v),
					})
				}
			}

			// Check for missing anti-CSRF token on POST form
			if method == "POST" {
				hasCSRF := false
				for k := range hiddenFields {
					kLower := strings.ToLower(k)
					if strings.Contains(kLower, "csrf") || strings.Contains(kLower, "xsrf") || strings.Contains(kLower, "token") || strings.Contains(kLower, "nonce") {
						hasCSRF = true
						break
					}
				}
				if !hasCSRF {
					smells = append(smells, AuthSmell{
						Severity:    SeverityMedium,
						Description: "Missing anti-CSRF token on password recovery form",
					})
				}
			}
		}

		// Insecure transport smell
		if strings.HasPrefix(strings.ToLower(resolvedURL), "http://") {
			smells = append(smells, AuthSmell{
				Severity:    SeverityMedium,
				Description: "Form submits over unencrypted HTTP",
				Evidence:    resolvedURL,
			})
		}

		surfaces = append(surfaces, AuthSurface{
			Type:         wfType,
			URL:          resolvedURL,
			Method:       method,
			Source:       "html_form",
			Inputs:       deduplicateAndSort(inputNames),
			HiddenFields: hiddenFields,
			Smells:       smells,
		})
	}

	// 2. Scan for sensitive HTML comments (e.g. debug tokens, leaked reset credentials)
	for _, m := range htmlCommentRegex.FindAllStringSubmatch(bodyStr, -1) {
		commentText := m[1]
		if sub := sensitiveComment.FindStringSubmatch(commentText); len(sub) > 1 {
			surfaces = append(surfaces, AuthSurface{
				Type:   AuthTypeReset,
				URL:    baseURL.String(),
				Method: "GET",
				Source: "html_comment",
				Smells: []AuthSmell{
					{
						Severity:    SeverityHigh,
						Description: "HTML comment discloses sensitive auth keyword or token",
						Evidence:    strings.TrimSpace(m[0]),
					},
				},
			})
		}
	}

	return surfaces
}

// AnalyzeAuthFromJS scans JavaScript code for auth endpoints, client-side token extraction, and weak logic.
func AnalyzeAuthFromJS(jsBody []byte, jsURL string, baseURL *url.URL) []AuthSurface {
	var surfaces []AuthSurface
	jsStr := string(jsBody)

	var smells []AuthSmell

	// 1. Detect client-side inspection of reset responses (like the CTF scenario: response leaks token/otp/reset_url)
	for _, m := range jsClientTokenLeakRegex.FindAllStringSubmatch(jsStr, -1) {
		smells = append(smells, AuthSmell{
			Severity:    SeverityHigh,
			Description: fmt.Sprintf("Client-side JS reads token/OTP/reset_url directly from API response ('%s')", m[0]),
			Evidence:    fmt.Sprintf("Found in %s: %s", jsURL, m[0]),
		})
	}
	for _, m := range jsDestructTokenRegex.FindAllStringSubmatch(jsStr, -1) {
		smells = append(smells, AuthSmell{
			Severity:    SeverityHigh,
			Description: fmt.Sprintf("Client-side JS destructures token/OTP from response object ('%s')", m[0]),
			Evidence:    fmt.Sprintf("Found in %s: %s", jsURL, m[0]),
		})
	}

	// 2. Detect client-side OTP / token generation
	for _, m := range jsClientOTPGenRegex.FindAllString(jsStr, -1) {
		smells = append(smells, AuthSmell{
			Severity:    SeverityHigh,
			Description: "Client-side OTP / token generation logic detected in JavaScript",
			Evidence:    fmt.Sprintf("Found in %s: %s", jsURL, m),
		})
	}

	// 3. Extract hardcoded auth / reset routes from JS
	for _, m := range jsAuthRouteRegex.FindAllStringSubmatch(jsStr, -1) {
		route := m[1]
		resolved := route
		if strings.HasPrefix(route, "/") {
			resolved = baseURL.ResolveReference(&url.URL{Path: route}).String()
		}
		surfaces = append(surfaces, AuthSurface{
			Type:   AuthTypeReset,
			URL:    resolved,
			Method: "POST",
			Source: "js_route",
			Smells: smells,
		})
	}

	// If smells were detected but no explicit route was matched, attach to the JS file context
	if len(smells) > 0 && len(surfaces) == 0 {
		surfaces = append(surfaces, AuthSurface{
			Type:   AuthTypeReset,
			URL:    jsURL,
			Method: "GET",
			Source: "js_analysis",
			Smells: smells,
		})
	}

	return surfaces
}

// DetectLeakedResetLinks scans discovered links for exposed reset tokens or active links.
func DetectLeakedResetLinks(links []string) []AuthSurface {
	var surfaces []AuthSurface
	for _, l := range links {
		if m := urlResetTokenRegex.FindStringSubmatch(l); len(m) > 1 {
			surfaces = append(surfaces, AuthSurface{
				Type:   AuthTypeReset,
				URL:    l,
				Method: "GET",
				Source: "link_token_leak",
				Smells: []AuthSmell{
					{
						Severity:    SeverityCritical,
						Description: "Discovered URL exposes active or pre-generated password reset token",
						Evidence:    fmt.Sprintf("token=%s", m[1]),
					},
				},
			})
		}
	}
	return surfaces
}

// DeduplicateAuthSurfaces merges duplicate auth surfaces by URL and Type, combining their smells and inputs.
func DeduplicateAuthSurfaces(surfaces []AuthSurface) []AuthSurface {
	type key struct {
		wfType AuthWorkflowType
		url    string
		method string
	}

	m := make(map[key]*AuthSurface)
	for _, s := range surfaces {
		k := key{wfType: s.Type, url: s.URL, method: s.Method}
		existing, ok := m[k]
		if !ok {
			copySurface := s
			m[k] = &copySurface
			continue
		}

		// Merge inputs
		inputMap := make(map[string]bool)
		for _, inp := range existing.Inputs {
			inputMap[inp] = true
		}
		for _, inp := range s.Inputs {
			inputMap[inp] = true
		}
		existing.Inputs = setToSlice(inputMap)

		// Merge smells (deduplicate by description)
		seenSmells := make(map[string]bool)
		for _, sm := range existing.Smells {
			seenSmells[sm.Description] = true
		}
		for _, sm := range s.Smells {
			if !seenSmells[sm.Description] {
				seenSmells[sm.Description] = true
				existing.Smells = append(existing.Smells, sm)
			}
		}
	}

	var result []AuthSurface
	for _, s := range m {
		result = append(result, *s)
	}

	// Sort by workflow type, then URL
	sort.Slice(result, func(i, j int) bool {
		if result[i].Type != result[j].Type {
			return result[i].Type < result[j].Type
		}
		return result[i].URL < result[j].URL
	})

	return result
}
