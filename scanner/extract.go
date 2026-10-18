package scanner

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/4lch3mis7/webzoro-golang/utils"
)

// IDORCandidate represents an endpoint that references a resource or accepts an identifier.
type IDORCandidate struct {
	URL             string   `json:"url"`
	Method          string   `json:"method,omitempty"`
	Source          string   `json:"source"` // "path_id", "js_template", "js_concat", "form_hidden", "query_param"
	Entity          string   `json:"entity,omitempty"`
	DetectedID      string   `json:"detected_id,omitempty"`
	IDType          string   `json:"id_type,omitempty"` // "numeric", "uuid", "hash/slug", "template_var"
	CandidateParams []string `json:"candidate_params"`
	FuzzURLs        []string `json:"fuzz_urls,omitempty"`
}

// JSAnalysisReport captures the detailed analysis results for an individual JavaScript asset.
type JSAnalysisReport struct {
	URL        string   `json:"url"`
	LocalPath  string   `json:"local_path,omitempty"`
	Status     string   `json:"status"` // "downloaded", "cached", "404/failed", "external CDN"
	Endpoints  []string `json:"endpoints,omitempty"`
	Params     []string `json:"params,omitempty"`
	IDORs      []string `json:"idor_templates,omitempty"`
	AuthSmells []string `json:"auth_smells,omitempty"`
}

// ExtractedAssets stores deduplicated endpoints, parameters, inferred candidates, and JS files.
type ExtractedAssets struct {
	TargetURL      string             `json:"target_url"`
	Port           int                `json:"port"`
	Links          []string           `json:"links"`
	Parameters     []string           `json:"parameters"`
	InferredParams []string           `json:"inferred_parameters"`
	VerifiedParams []VerifiedParam    `json:"verified_parameters,omitempty"`
	IDORCandidates []IDORCandidate    `json:"idor_candidates"`
	JSFiles        []string           `json:"js_files"`
	AuthSurfaces   []AuthSurface      `json:"auth_surfaces,omitempty"`
	JSReports      []JSAnalysisReport `json:"js_analysis,omitempty"`
}

var (
	// Link & Asset regexes
	hrefSrcActionRegex = regexp.MustCompile(`(?i)(?:href|src|action|data-url)\s*=\s*["']([^"'#\s>]+)["']`)
	scriptSrcRegex     = regexp.MustCompile(`(?i)<script[^>]+src\s*=\s*["']([^"'#\s>]+)["']`)

	// Form input regexes (captures hidden and state fields)
	formInputTagRegex = regexp.MustCompile(`(?i)<(?:input|textarea|select)[^>]*>`)
	attrNameRegex     = regexp.MustCompile(`(?i)\bname\s*=\s*["']([^"'#\s>]+)["']`)
	attrTypeRegex     = regexp.MustCompile(`(?i)\btype\s*=\s*["']([^"'#\s>]+)["']`)
	attrValueRegex    = regexp.MustCompile(`(?i)\bvalue\s*=\s*["']([^"']*)["']`)

	// JS Endpoint calls & literals (handles single quote, double quote, and backtick template literals)
	jsEndpointRegex        = regexp.MustCompile(`(?i)(?:fetch|axios\.(?:get|post|put|delete|patch)|open)\s*\(\s*["'` + "`" + `]([^"'` + "`" + `\s]+)["'` + "`" + `]`)
	jsPathStringRegex      = regexp.MustCompile(`["'](/[a-zA-Z0-9_\-\./?=&%#]{2,120})["']`)
	jsTemplateLiteralRegex = regexp.MustCompile("`([^`\\n]*\\$\\{[a-zA-Z0-9_\\.\\s]+\\}[^`\\n]*)`")
	jsTemplateVarRegex     = regexp.MustCompile(`\$\{([a-zA-Z0-9_\.\s]+)\}`)
	jsConcatRegex          = regexp.MustCompile(`["'](/[a-zA-Z0-9_\-\./]+/)["']\s*\+\s*([a-zA-Z0-9_\.]{1,40})`)
	jsDestructRegex        = regexp.MustCompile(`(?:const|let|var)\s*\{\s*([a-zA-Z0-9_,\s]+)\s*\}\s*=\s*(?:req|res|data|body|params|response)`)

	// Parameter extraction regexes
	paramQueryRegex = regexp.MustCompile(`[?&]([a-zA-Z0-9_\-\.]{1,64})=`)
	jsParamRegex    = regexp.MustCompile(`(?:params\.(?:append|get|set)|data\s*:\s*\{)\s*["']?([a-zA-Z0-9_]{1,64})["']?`)
	jsonKeyRegex    = regexp.MustCompile(`"([a-zA-Z0-9_\-]{2,64})"\s*:`)

	// Path segment identifier patterns
	numericPathRegex  = regexp.MustCompile(`^(\d{1,16})$`)
	uuidPathRegex     = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	hashSlugPathRegex = regexp.MustCompile(`(?i)^([a-z]{2,8}[_-][a-z0-9_-]{3,32}|[0-9a-f]{16,64})$`)

	// Semantic Knowledge Base: Common web application entities and action verbs
	knownEntities = map[string]bool{
		"user": true, "account": true, "profile": true, "member": true, "customer": true, "client": true,
		"order": true, "cart": true, "item": true, "product": true, "transaction": true, "payment": true, "bill": true, "invoice": true, "receipt": true,
		"document": true, "doc": true, "file": true, "attachment": true, "report": true, "upload": true, "image": true, "photo": true, "video": true,
		"ticket": true, "message": true, "chat": true, "comment": true, "post": true, "article": true, "thread": true,
		"tenant": true, "org": true, "organization": true, "company": true, "team": true, "group": true, "role": true, "project": true, "workspace": true,
		"subscription": true, "plan": true, "contract": true, "booking": true, "reservation": true,
		"patient": true, "claim": true, "policy": true, "token": true, "session": true, "device": true, "lead": true,
	}

	knownVerbs = map[string][]string{
		"download": {"file", "path", "filename", "doc_id", "attachment_id", "id"},
		"export":   {"file", "format", "type", "id", "report_id"},
		"view":     {"id", "item_id", "view", "ref"},
		"show":     {"id", "ref", "view"},
		"read":     {"id", "doc_id"},
		"fetch":    {"id", "key", "ref"},
		"get":      {"id", "ref"},
		"edit":     {"id", "item_id", "target"},
		"update":   {"id", "item_id"},
		"delete":   {"id", "item_id", "target", "uid"},
		"remove":   {"id", "item_id"},
		"cancel":   {"id", "order_id", "txn_id"},
		"search":   {"q", "query", "search", "keyword", "term", "filter", "by"},
		"find":     {"q", "query", "keyword", "term"},
		"filter":   {"filter", "by", "category", "status", "type"},
		"list":     {"page", "limit", "offset", "sort", "order", "status"},
		"redirect": {"url", "redirect", "redirect_url", "return_url", "next", "dest"},
		"forward":  {"url", "dest", "to"},
		"goto":     {"url", "target", "next"},
		"return":   {"return_url", "url", "next"},
		"auth":     {"token", "code", "key", "user_id", "session_id", "auth"},
		"verify":   {"token", "code", "key", "id", "hash"},
		"reset":    {"token", "code", "key", "email", "id"},
		"login":    {"username", "user", "email", "password", "redirect"},
		"register": {"username", "user", "email", "role", "plan"},
	}
)

// SanitizeFilename cleans paths to create safe filesystem filenames.
func SanitizeFilename(s string) string {
	s = strings.TrimPrefix(s, "/")
	if s == "" {
		s = "index"
	}
	reg := regexp.MustCompile(`[^a-zA-Z0-9_\-\.]`)
	clean := reg.ReplaceAllString(s, "_")
	if len(clean) > 80 {
		clean = clean[:80]
	}
	return clean
}

// SaveHTTPResponse writes full HTTP response (status, headers, body) to disk.
func SaveHTTPResponse(responsesDir string, port int, rawURL string, statusCode int, headers http.Header, body []byte) string {
	utils.CheckAndCreateDir(responsesDir)

	u, err := url.Parse(rawURL)
	name := "response"
	if err == nil {
		name = SanitizeFilename(u.Path)
		if u.RawQuery != "" {
			name += "_" + SanitizeFilename(u.RawQuery)
		}
	}

	filename := fmt.Sprintf("%d_%d_%s.resp", port, statusCode, name)
	filePath := filepath.Join(responsesDir, filename)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("HTTP/1.1 %d %s\n", statusCode, http.StatusText(statusCode)))
	sb.WriteString(fmt.Sprintf("URL: %s\n", rawURL))
	for k, v := range headers {
		sb.WriteString(fmt.Sprintf("%s: %s\n", k, strings.Join(v, ", ")))
	}
	sb.WriteString("\n")
	sb.Write(body)

	_ = os.WriteFile(filePath, []byte(sb.String()), 0644)
	return filePath
}

// singularizeEntity strips plurals from English nouns (e.g., "users" -> "user", "categories" -> "category").
func singularizeEntity(noun string) string {
	noun = strings.ToLower(strings.TrimSpace(noun))
	if strings.HasSuffix(noun, "ies") && len(noun) > 4 {
		return noun[:len(noun)-3] + "y"
	}
	if strings.HasSuffix(noun, "ses") && len(noun) > 4 {
		return noun[:len(noun)-2]
	}
	if strings.HasSuffix(noun, "s") && !strings.HasSuffix(noun, "ss") && len(noun) > 2 {
		return noun[:len(noun)-1]
	}
	return noun
}

// generateEntityParams synthesizes intuitive parameter permutations for a given resource entity.
func generateEntityParams(entity string) []string {
	entity = singularizeEntity(entity)
	if entity == "" {
		return []string{"id"}
	}

	camelCase := entity + "Id"
	if strings.Contains(entity, "_") {
		parts := strings.Split(entity, "_")
		var sb strings.Builder
		sb.WriteString(parts[0])
		for i := 1; i < len(parts); i++ {
			if len(parts[i]) > 0 {
				sb.WriteString(strings.ToUpper(parts[i][:1]) + parts[i][1:])
			}
		}
		sb.WriteString("Id")
		camelCase = sb.String()
	}

	params := []string{
		"id",
		entity + "_id",
		camelCase,
		entity,
		entity + "_no",
		entity + "_uuid",
		"uuid",
	}

	switch entity {
	case "user", "member", "customer", "client", "account":
		params = append(params, "uid", "account_id", "accountId", "username")
	case "order", "invoice", "receipt", "bill", "payment":
		params = append(params, "order_no", "inv_id", "inv_no", "txn_id", "ref")
	case "document", "doc", "file", "attachment", "report":
		params = append(params, "doc_id", "docId", "file_id", "fileId", "file", "path", "filename")
	case "tenant", "org", "organization", "company", "workspace":
		params = append(params, "tenant_id", "tenantId", "org_id", "orgId", "company_id")
	}

	return deduplicateAndSort(params)
}

// IsIDORParam checks if a parameter name is commonly used for direct object referencing or access control.
func IsIDORParam(name string) bool {
	lower := strings.ToLower(strings.TrimSpace(name))
	if lower == "id" || lower == "uid" || lower == "uuid" || lower == "guid" {
		return true
	}
	if strings.HasSuffix(lower, "_id") || (strings.HasSuffix(lower, "id") && len(lower) > 2) {
		return true
	}
	if strings.HasSuffix(lower, "_no") || strings.HasSuffix(lower, "_num") || strings.HasSuffix(lower, "_number") {
		return true
	}
	switch lower {
	case "user", "account", "member", "order", "invoice", "file", "doc", "ticket", "profile",
		"tenant", "org", "role", "role_id", "group", "group_id", "email", "username", "token", "session":
		return true
	}
	return false
}

func isNumeric(s string) bool {
	return s != "" && numericPathRegex.MatchString(s)
}

func isUUID(s string) bool {
	return s != "" && uuidPathRegex.MatchString(s)
}

func detectIDType(s string) string {
	s = strings.TrimSpace(s)
	if isNumeric(s) {
		return "numeric"
	}
	if isUUID(s) {
		return "uuid"
	}
	if hashSlugPathRegex.MatchString(s) {
		return "hash/slug"
	}
	if strings.HasPrefix(s, "${") {
		return "template_var"
	}
	return "identifier"
}

func isSameTargetHost(h1, h2 string) bool {
	h1 = strings.ToLower(strings.TrimSpace(h1))
	h2 = strings.ToLower(strings.TrimSpace(h2))
	if h1 == "" || h2 == "" {
		return false
	}
	if h1 == h2 {
		return true
	}
	if strings.HasSuffix(h1, "."+h2) || strings.HasSuffix(h2, "."+h1) {
		return true
	}
	return false
}

func isHTML(data []byte) bool {
	sample := strings.ToLower(strings.TrimSpace(string(data)))
	if len(sample) > 512 {
		sample = sample[:512]
	}
	return strings.HasPrefix(sample, "<!doctype") ||
		strings.HasPrefix(sample, "<html") ||
		strings.Contains(sample, "<head>") ||
		strings.Contains(sample, "<body>") ||
		strings.Contains(sample, "<title>404") ||
		strings.Contains(sample, "not found")
}

// DetectPathIDOR analyzes a URL's path and query string for direct object references.
func DetectPathIDOR(rawURL string) *IDORCandidate {
	u, err := url.Parse(rawURL)
	if err != nil || u.Path == "" {
		return nil
	}

	cleanPath := strings.Trim(u.Path, "/")
	if cleanPath == "" {
		return nil
	}
	segments := strings.Split(cleanPath, "/")

	// 1. Check REST path segments for numeric IDs, UUIDs, or identifier hashes
	for i, seg := range segments {
		idType := ""
		if isNumeric(seg) {
			idType = "numeric"
		} else if isUUID(seg) {
			idType = "uuid"
		} else if i > 0 && hashSlugPathRegex.MatchString(seg) {
			idType = "hash/slug"
		}

		if idType != "" {
			entity := "item"
			if i > 0 {
				entity = singularizeEntity(segments[i-1])
			}

			// Construct candidate fuzz URLs
			fuzzSegments := make([]string, len(segments))
			copy(fuzzSegments, segments)
			fuzzSegments[i] = "FUZZ"
			fuzzPathURL := fmt.Sprintf("%s://%s/%s", u.Scheme, u.Host, strings.Join(fuzzSegments, "/"))

			candParams := generateEntityParams(entity)
			var fuzzURLs []string
			fuzzURLs = append(fuzzURLs, fuzzPathURL)

			// Query parameter alternatives
			if i > 0 {
				baseResourceURL := fmt.Sprintf("%s://%s/%s", u.Scheme, u.Host, strings.Join(segments[:i], "/"))
				fuzzURLs = append(fuzzURLs, fmt.Sprintf("%s?id=FUZZ", baseResourceURL))
				fuzzURLs = append(fuzzURLs, fmt.Sprintf("%s?%s_id=FUZZ", baseResourceURL, entity))
			}

			return &IDORCandidate{
				URL:             rawURL,
				Method:          "GET",
				Source:          "path_id",
				Entity:          entity,
				DetectedID:      seg,
				IDType:          idType,
				CandidateParams: candParams,
				FuzzURLs:        fuzzURLs,
			}
		}
	}

	// 2. Check query parameters for direct object reference values
	for k, vals := range u.Query() {
		if IsIDORParam(k) {
			val := ""
			if len(vals) > 0 {
				val = vals[0]
			}
			entity := singularizeEntity(strings.TrimSuffix(strings.TrimSuffix(strings.ToLower(k), "_id"), "id"))
			if entity == "" {
				entity = "item"
			}

			// Create fuzz URL by replacing parameter value with FUZZ
			q := u.Query()
			q.Set(k, "FUZZ")
			uCopy := *u
			uCopy.RawQuery = q.Encode()

			return &IDORCandidate{
				URL:             rawURL,
				Method:          "GET",
				Source:          "query_param",
				Entity:          entity,
				DetectedID:      val,
				IDType:          detectIDType(val),
				CandidateParams: generateEntityParams(k),
				FuzzURLs:        []string{uCopy.String()},
			}
		}
	}

	return nil
}

// InferContextualParams deduces probable query or body parameters based on route nouns and action verbs.
func InferContextualParams(rawURL string) []string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Path == "" {
		return nil
	}

	// Split path into individual semantic words
	cleanPath := strings.ToLower(u.Path)
	tokens := regexp.MustCompile(`[^a-zA-Z0-9]+`).Split(cleanPath, -1)

	paramMap := make(map[string]bool)

	for _, token := range tokens {
		if token == "" || len(token) < 2 {
			continue
		}
		singular := singularizeEntity(token)

		// Check if token represents an entity
		if knownEntities[singular] || knownEntities[token] {
			for _, p := range generateEntityParams(singular) {
				paramMap[p] = true
			}
		}

		// Check if token represents an action verb
		if params, exists := knownVerbs[token]; exists {
			for _, p := range params {
				paramMap[p] = true
			}
		}
	}

	return deduplicateAndSort(setToSlice(paramMap))
}

// ExtractFormIDORCandidates parses HTML form hidden fields to uncover object references and state parameters.
func ExtractFormIDORCandidates(body []byte, baseURL *url.URL) []IDORCandidate {
	var candidates []IDORCandidate
	bodyStr := string(body)

	for _, inputTag := range formInputTagRegex.FindAllString(bodyStr, -1) {
		nameMatch := attrNameRegex.FindStringSubmatch(inputTag)
		if len(nameMatch) <= 1 {
			continue
		}
		name := strings.TrimSpace(nameMatch[1])
		if !isValidParam(name) {
			continue
		}

		typeMatch := attrTypeRegex.FindStringSubmatch(inputTag)
		typeVal := ""
		if len(typeMatch) > 1 {
			typeVal = strings.ToLower(strings.TrimSpace(typeMatch[1]))
		}

		valMatch := attrValueRegex.FindStringSubmatch(inputTag)
		val := ""
		if len(valMatch) > 1 {
			val = strings.TrimSpace(valMatch[1])
		}

		// Prioritize hidden input fields containing IDs, tokens, or resource names
		if typeVal == "hidden" && (IsIDORParam(name) || isNumeric(val) || isUUID(val)) {
			entity := singularizeEntity(strings.TrimSuffix(strings.TrimSuffix(strings.ToLower(name), "_id"), "id"))
			if entity == "" {
				entity = name
			}
			candidates = append(candidates, IDORCandidate{
				URL:             baseURL.String(),
				Method:          "POST",
				Source:          "form_hidden",
				Entity:          entity,
				DetectedID:      val,
				IDType:          detectIDType(val),
				CandidateParams: generateEntityParams(name),
				FuzzURLs:        []string{fmt.Sprintf("%s?%s=FUZZ", baseURL.String(), name)},
			})
		}
	}

	return candidates
}

// isStaticAssetPath returns true if a path points to static or media assets rather than API resources.
func isStaticAssetPath(p string) bool {
	pLower := strings.ToLower(p)
	staticDirs := []string{"/css/", "/js/", "/images/", "/image/", "/img/", "/fonts/", "/font/", "/assets/", "/static/", "/dist/", "/vendor/", "/locales/", "/media/"}
	for _, d := range staticDirs {
		if strings.HasPrefix(pLower, d) || strings.Contains(pLower, d) {
			return true
		}
	}
	return false
}

// extractPrecedingEntity finds the resource noun immediately preceding a variable in a URL path.
// e.g. "/api/v1/users/${id}" -> "user", "/orders/" + id -> "order"
func extractPrecedingEntity(pathStr, varPlaceholder string) string {
	idx := len(pathStr)
	if varPlaceholder != "" {
		if i := strings.Index(pathStr, varPlaceholder); i >= 0 {
			idx = i
		}
	}
	sub := pathStr[:idx]
	if qIdx := strings.Index(sub, "?"); qIdx >= 0 {
		sub = sub[:qIdx]
	}
	sub = strings.TrimRight(sub, "/")
	parts := strings.Split(sub, "/")
	if len(parts) == 0 {
		return ""
	}
	lastSegment := strings.ToLower(strings.TrimSpace(parts[len(parts)-1]))
	reg := regexp.MustCompile(`[^a-zA-Z0-9_-]`)
	clean := reg.ReplaceAllString(lastSegment, "")
	return singularizeEntity(clean)
}

// isValidJSRouteTemplate checks if a JS template literal resembles an HTTP route or API endpoint.
// Eliminates false positives from DOM event handlers, CSS selectors, style measurements, and error strings.
func isValidJSRouteTemplate(literal string) bool {
	literal = strings.TrimSpace(literal)
	if len(literal) < 3 {
		return false
	}

	// Must contain at least one template variable ${...}
	if !jsTemplateVarRegex.MatchString(literal) {
		return false
	}

	// Replace template variables ${...} with a dummy token to inspect the URL structure
	skeleton := jsTemplateVarRegex.ReplaceAllString(literal, "X")

	// Must start with a path separator or URL scheme: "/", "http://", "https://", "./", "../"
	if !strings.HasPrefix(skeleton, "/") && !strings.HasPrefix(skeleton, "http://") && !strings.HasPrefix(skeleton, "https://") && !strings.HasPrefix(skeleton, "./") && !strings.HasPrefix(skeleton, "../") {
		return false
	}

	// Must contain a forward slash
	if !strings.Contains(skeleton, "/") {
		return false
	}

	// Must NOT contain whitespace, newlines, quotes, or HTML/CSS selector syntax
	if strings.ContainsAny(skeleton, " \t\r\n\"'`<>[]{}();,^!*~|#") {
		return false
	}

	skeletonLower := strings.ToLower(skeleton)

	// Reject CSS pseudo-classes, units, or styling
	if strings.Contains(skeletonLower, ":not") || strings.Contains(skeletonLower, "::") {
		return false
	}
	if strings.HasSuffix(skeletonLower, "px") || strings.HasSuffix(skeletonLower, "em") || strings.HasSuffix(skeletonLower, "rem") || strings.HasSuffix(skeletonLower, "%") {
		return false
	}

	// Reject common DOM events and framework noise
	if strings.Contains(skeletonLower, "data-bs") || strings.Contains(skeletonLower, "data-api") || strings.Contains(skeletonLower, "event") {
		return false
	}

	// Reject static asset prefixes
	if isStaticAssetPath(skeletonLower) {
		return false
	}

	return true
}

// ExtractJSTemplateIDORCandidates scans JavaScript code for backtick template literals and concatenations.
func ExtractJSTemplateIDORCandidates(jsBody []byte, baseURL *url.URL) []IDORCandidate {
	var candidates []IDORCandidate
	jsStr := string(jsBody)

	// 1. Template literal routes: `/api/users/${userId}` or `/orders/${order.id}`
	for _, m := range jsTemplateLiteralRegex.FindAllStringSubmatch(jsStr, -1) {
		literal := strings.TrimSpace(m[1])
		if !isValidJSRouteTemplate(literal) {
			continue
		}

		varMatches := jsTemplateVarRegex.FindAllStringSubmatch(literal, -1)
		for _, vm := range varMatches {
			rawVar := strings.TrimSpace(vm[1])
			varName := rawVar
			if strings.Contains(rawVar, ".") {
				parts := strings.Split(rawVar, ".")
				varName = parts[len(parts)-1]
			}
			if !isValidParam(varName) {
				continue
			}

			precedingEntity := extractPrecedingEntity(literal, vm[0])

			// If varName is a minified single letter (e.g. 'e', 't', 'n'),
			// only accept if the preceding path segment is a known resource entity.
			if len(varName) <= 1 {
				if precedingEntity == "" || !knownEntities[precedingEntity] {
					continue
				}
			}

			entity := precedingEntity
			if entity == "" || !knownEntities[entity] {
				entity = singularizeEntity(varName)
			}
			if entity == "" {
				entity = "item"
			}

			// Clean route for fuzz URL
			cleanRoute := jsTemplateVarRegex.ReplaceAllString(literal, "FUZZ")
			resolvedFuzzURL := cleanRoute
			if strings.HasPrefix(cleanRoute, "/") {
				resolvedFuzzURL = baseURL.ResolveReference(&url.URL{Path: cleanRoute}).String()
			}

			candidates = append(candidates, IDORCandidate{
				URL:             literal,
				Method:          "GET",
				Source:          "js_template",
				Entity:          entity,
				DetectedID:      "${" + rawVar + "}",
				IDType:          "template_var",
				CandidateParams: generateEntityParams(varName),
				FuzzURLs:        []string{resolvedFuzzURL, fmt.Sprintf("%s?%s=FUZZ", resolvedFuzzURL, varName)},
			})
		}
	}

	// 2. JavaScript concatenations: "/api/orders/" + orderId
	for _, m := range jsConcatRegex.FindAllStringSubmatch(jsStr, -1) {
		routePrefix := m[1]
		if isStaticAssetPath(routePrefix) {
			continue
		}

		rawVar := strings.TrimSpace(m[2])
		varName := rawVar
		if strings.Contains(rawVar, ".") {
			parts := strings.Split(rawVar, ".")
			varName = parts[len(parts)-1]
		}
		if !isValidParam(varName) {
			continue
		}

		precedingEntity := extractPrecedingEntity(routePrefix, "")
		if len(varName) <= 1 {
			if precedingEntity == "" || !knownEntities[precedingEntity] {
				continue
			}
		}

		entity := precedingEntity
		if entity == "" || !knownEntities[entity] {
			entity = singularizeEntity(varName)
		}
		if entity == "" {
			entity = "item"
		}

		resolvedFuzzURL := baseURL.ResolveReference(&url.URL{Path: routePrefix + "FUZZ"}).String()
		candidates = append(candidates, IDORCandidate{
			URL:             routePrefix + "+ " + rawVar,
			Method:          "GET",
			Source:          "js_concat",
			Entity:          entity,
			DetectedID:      rawVar,
			IDType:          "concat_var",
			CandidateParams: generateEntityParams(varName),
			FuzzURLs:        []string{resolvedFuzzURL, fmt.Sprintf("%s?%s=FUZZ", resolvedFuzzURL, varName)},
		})
	}

	return candidates
}

// ExtractFromHTML parses an HTML/text body and extracts links, parameters, and JS files.
func ExtractFromHTML(body []byte, baseURL *url.URL) ([]string, []string, []string) {
	linkMap := make(map[string]bool)
	paramMap := make(map[string]bool)
	jsMap := make(map[string]bool)

	bodyStr := string(body)

	// 1. Extract href, src, action, data-url
	for _, m := range hrefSrcActionRegex.FindAllStringSubmatch(bodyStr, -1) {
		if len(m) > 1 {
			raw := strings.TrimSpace(m[1])
			processLink(raw, baseURL, linkMap, paramMap, jsMap)
		}
	}

	// 2. Extract <script src="..."> specifically
	for _, m := range scriptSrcRegex.FindAllStringSubmatch(bodyStr, -1) {
		if len(m) > 1 {
			raw := strings.TrimSpace(m[1])
			processLink(raw, baseURL, linkMap, paramMap, jsMap)
		}
	}

	// 3. Extract form inputs (names and attributes)
	for _, inputTag := range formInputTagRegex.FindAllString(bodyStr, -1) {
		nameMatch := attrNameRegex.FindStringSubmatch(inputTag)
		if len(nameMatch) > 1 {
			name := strings.TrimSpace(nameMatch[1])
			if isValidParam(name) {
				paramMap[name] = true
			}
		}
	}

	// 4. Extract JS string paths from embedded scripts
	for _, m := range jsPathStringRegex.FindAllStringSubmatch(bodyStr, -1) {
		if len(m) > 1 {
			raw := strings.TrimSpace(m[1])
			processLink(raw, baseURL, linkMap, paramMap, jsMap)
		}
	}

	// 5. Extract JSON keys if response contains JSON
	for _, m := range jsonKeyRegex.FindAllStringSubmatch(bodyStr, -1) {
		if len(m) > 1 {
			key := strings.TrimSpace(m[1])
			if isValidParam(key) {
				paramMap[key] = true
			}
		}
	}

	return setToSlice(linkMap), setToSlice(paramMap), setToSlice(jsMap)
}

// isVendorJSLibrary detects third-party UI/utility libraries that should not have their internal object keys mined.
func isVendorJSLibrary(filenameOrURL string) bool {
	lower := strings.ToLower(filenameOrURL)
	vendors := []string{
		"bootstrap", "jquery", "popper", "react", "vue", "angular",
		"lodash", "moment", "fontawesome", "swiper", "select2",
		"chart.min.js", "chart.js", "core-js", "polyfill", "modernizr",
		"materialize", "semantic", "foundation", "uikit", "alpine",
	}
	for _, v := range vendors {
		if strings.Contains(lower, v) {
			return true
		}
	}
	return false
}

// ExtractFromJS parses JavaScript content for endpoints, API paths, and parameters.
func ExtractFromJS(jsBody []byte, baseURL *url.URL, isVendor bool) ([]string, []string, []string) {
	linkMap := make(map[string]bool)
	paramMap := make(map[string]bool)
	jsMap := make(map[string]bool)

	jsStr := string(jsBody)

	// 1. Extract API calls (fetch, axios, open)
	for _, m := range jsEndpointRegex.FindAllStringSubmatch(jsStr, -1) {
		if len(m) > 1 {
			raw := strings.TrimSpace(m[1])
			processLink(raw, baseURL, linkMap, paramMap, jsMap)
		}
	}

	// 2. Extract quoted path literals: "/api/v1/..."
	for _, m := range jsPathStringRegex.FindAllStringSubmatch(jsStr, -1) {
		if len(m) > 1 {
			raw := strings.TrimSpace(m[1])
			processLink(raw, baseURL, linkMap, paramMap, jsMap)
		}
	}

	// 3. Extract query parameters from paths and strings
	for _, m := range paramQueryRegex.FindAllStringSubmatch(jsStr, -1) {
		if len(m) > 1 {
			p := strings.TrimSpace(m[1])
			if isValidParam(p) {
				paramMap[p] = true
			}
		}
	}

	// 4. Extract JS parameter references: params.append("user", ...)
	for _, m := range jsParamRegex.FindAllStringSubmatch(jsStr, -1) {
		if len(m) > 1 {
			p := strings.TrimSpace(m[1])
			if isValidParam(p) {
				paramMap[p] = true
			}
		}
	}

	// 5. Extract JSON keys in JS objects (skipped on vendor libraries to prevent UI state noise)
	if !isVendor {
		for _, m := range jsonKeyRegex.FindAllStringSubmatch(jsStr, -1) {
			if len(m) > 1 {
				p := strings.TrimSpace(m[1])
				if isValidParam(p) {
					paramMap[p] = true
				}
			}
		}
	}

	// 6. Extract template variables inside template literals
	for _, m := range jsTemplateLiteralRegex.FindAllStringSubmatch(jsStr, -1) {
		literal := m[1]
		if !isValidJSRouteTemplate(literal) {
			continue
		}
		varMatches := jsTemplateVarRegex.FindAllStringSubmatch(literal, -1)
		for _, vm := range varMatches {
			rawVar := strings.TrimSpace(vm[1])
			varName := rawVar
			if strings.Contains(rawVar, ".") {
				parts := strings.Split(rawVar, ".")
				varName = parts[len(parts)-1]
			}
			if isValidParam(varName) && len(varName) > 1 {
				paramMap[varName] = true
			}
		}
	}

	// 7. Extract variables from JS string concatenations
	for _, m := range jsConcatRegex.FindAllStringSubmatch(jsStr, -1) {
		routePrefix := m[1]
		if isStaticAssetPath(routePrefix) {
			continue
		}
		rawVar := strings.TrimSpace(m[2])
		varName := rawVar
		if strings.Contains(rawVar, ".") {
			parts := strings.Split(rawVar, ".")
			varName = parts[len(parts)-1]
		}
		if isValidParam(varName) && len(varName) > 1 {
			paramMap[varName] = true
		}
	}

	// 8. Extract object destructuring in JS: const { userId, role } = req.body
	for _, m := range jsDestructRegex.FindAllStringSubmatch(jsStr, -1) {
		vars := strings.Split(m[1], ",")
		for _, v := range vars {
			v = strings.TrimSpace(v)
			if isValidParam(v) {
				paramMap[v] = true
			}
		}
	}

	return setToSlice(linkMap), setToSlice(paramMap), setToSlice(jsMap)
}

// processLink normalizes a raw link, extracts parameters, and categorizes JS files.
func processLink(raw string, baseURL *url.URL, linkMap, paramMap, jsMap map[string]bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.HasPrefix(raw, "#") || strings.HasPrefix(raw, "javascript:") || strings.HasPrefix(raw, "mailto:") || strings.HasPrefix(raw, "tel:") || strings.HasPrefix(raw, "data:") {
		return
	}

	parsedRef, err := url.Parse(raw)
	if err != nil {
		return
	}

	resolved := baseURL.ResolveReference(parsedRef)
	resolvedStr := resolved.String()

	// Extract query parameters
	for k := range resolved.Query() {
		if isValidParam(k) {
			paramMap[k] = true
		}
	}

	// Categorize JavaScript file or page link
	cleanPath := strings.ToLower(resolved.Path)
	if strings.HasSuffix(cleanPath, ".js") || strings.Contains(cleanPath, ".js?") {
		jsMap[resolvedStr] = true
	} else {
		linkMap[resolvedStr] = true
	}
}

func isValidParam(p string) bool {
	p = strings.TrimSpace(p)
	if len(p) <= 1 || len(p) > 64 {
		if len(p) == 1 {
			switch strings.ToLower(p) {
			case "q", "p", "s", "v", "t", "id":
				return true
			}
		}
		return false
	}
	pLower := strings.ToLower(p)
	switch pLower {
	case "true", "false", "null", "undefined", "string", "number", "object", "function":
		return false
	}
	// Filter out common CSS classes, Popper placements, and layout tokens
	if strings.HasPrefix(pLower, "carousel-") || strings.HasPrefix(pLower, "data-popper") ||
		strings.HasPrefix(pLower, "bottom-") || strings.HasPrefix(pLower, "top-") ||
		strings.HasPrefix(pLower, "left-") || strings.HasPrefix(pLower, "right-") ||
		strings.HasPrefix(pLower, "_") {
		return false
	}
	return true
}

func setToSlice(m map[string]bool) []string {
	var s []string
	for k := range m {
		if k != "" {
			s = append(s, k)
		}
	}
	sort.Strings(s)
	return s
}

func deduplicateAndSort(items []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item != "" && !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}
	sort.Strings(result)
	return result
}

// ProcessAndExtractAssets saves responses from probed endpoints, downloads and analyzes JS files,
// discovers links and parameters, synthesizes contextual parameters, and flags IDOR candidate endpoints.
func ProcessAndExtractAssets(t *Target, port int, baseURLStr string, hits []DirHit) ExtractedAssets {
	baseU, err := url.Parse(baseURLStr)
	if err != nil {
		return ExtractedAssets{}
	}

	responsesDir := filepath.Join(t.OutDir(), "responses")
	jsResponsesDir := filepath.Join(responsesDir, "js")
	utils.CheckAndCreateDir(responsesDir)
	utils.CheckAndCreateDir(jsResponsesDir)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			DialContext: (&net.Dialer{
				Timeout: 4 * time.Second,
			}).DialContext,
			MaxIdleConns:        50,
			MaxIdleConnsPerHost: 20,
		},
		Timeout: 5 * time.Second,
	}

	masterLinks := make(map[string]bool)
	masterParams := make(map[string]bool)
	masterInferred := make(map[string]bool)
	masterJS := make(map[string]bool)

	var idorCandidates []IDORCandidate
	seenIDOR := make(map[string]bool)
	var allAuthSurfaces []AuthSurface

	addIDOR := func(c IDORCandidate) {
		key := fmt.Sprintf("%s|%s|%s", c.URL, c.Source, c.DetectedID)
		if !seenIDOR[key] {
			seenIDOR[key] = true
			idorCandidates = append(idorCandidates, c)
		}
	}

	// Combine endpoints: base URL "/" + discovered directory hits
	var probeURLs []string
	probeURLs = append(probeURLs, baseURLStr+"/")
	for _, h := range hits {
		if h.URL != "" && h.StatusCode != 404 && h.StatusCode != 400 {
			probeURLs = append(probeURLs, h.URL)
		}
		for _, j := range h.JSFiles {
			masterJS[j] = true
		}
		for _, p := range h.Params {
			masterParams[p] = true
		}
		for _, l := range h.Links {
			masterLinks[l] = true
		}
	}

	// Deduplicate probe URLs
	uniqueProbes := make(map[string]bool)
	for _, u := range probeURLs {
		uniqueProbes[u] = true
	}

	savedResponsesCount := 0

	// 1. Process each probed endpoint: save response, extract assets & IDOR candidates
	for uStr := range uniqueProbes {
		// Detect REST path IDOR patterns
		if cand := DetectPathIDOR(uStr); cand != nil {
			addIDOR(*cand)
		}

		// Infer contextual parameters based on endpoint path semantics
		for _, p := range InferContextualParams(uStr) {
			masterInferred[p] = true
		}

		req, err := http.NewRequestWithContext(context.Background(), "GET", uStr, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Webzoro-Recon/1.0")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		body, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
		resp.Body.Close()
		if err != nil {
			continue
		}

		// Save response file
		SaveHTTPResponse(responsesDir, port, uStr, resp.StatusCode, resp.Header, body)
		savedResponsesCount++

		uParsed, _ := url.Parse(uStr)
		if resp.Request != nil && resp.Request.URL != nil {
			uParsed = resp.Request.URL
		} else if uParsed == nil {
			uParsed = baseU
		}

		// Extract from HTML response body
		links, params, jsFiles := ExtractFromHTML(body, uParsed)
		for _, l := range links {
			masterLinks[l] = true
		}
		for _, p := range params {
			masterParams[p] = true
		}
		for _, j := range jsFiles {
			masterJS[j] = true
		}

		// Extract hidden form inputs as IDOR candidates
		for _, cand := range ExtractFormIDORCandidates(body, uParsed) {
			addIDOR(cand)
		}

		// Passively extract auth surfaces and recovery workflows from HTML
		allAuthSurfaces = append(allAuthSurfaces, ExtractAuthFromHTML(body, uParsed)...)
	}

	// 2. Download and analyze discovered JavaScript files
	downloadedJSCount := 0
	cachedJSCount := 0
	analyzedJSCount := 0
	failedJSCount := 0
	externalJSCount := 0
	var jsReports []JSAnalysisReport

	sortedJS := setToSlice(masterJS)
	for _, jsURL := range sortedJS {
		jsParsed, err := url.Parse(jsURL)
		if err != nil {
			continue
		}

		// Only download target-origin or subdomain JS files
		if !isSameTargetHost(jsParsed.Hostname(), baseU.Hostname()) {
			externalJSCount++
			jsReports = append(jsReports, JSAnalysisReport{
				URL:    jsURL,
				Status: "external CDN",
			})
			continue
		}

		cleanPath := SanitizeFilename(jsParsed.Path)
		if !strings.HasSuffix(strings.ToLower(cleanPath), ".js") {
			cleanPath += ".js"
		}
		localJSPath := filepath.Join(jsResponsesDir, fmt.Sprintf("%d_%s", port, cleanPath))

		// Check for legacy double-.js.js file and migrate or clean up
		doubleJSPath := filepath.Join(jsResponsesDir, fmt.Sprintf("%d_%s.js", port, cleanPath))
		if utils.FileExists(doubleJSPath) && !utils.FileExists(localJSPath) {
			data, err := os.ReadFile(doubleJSPath)
			if err == nil && len(data) > 0 && !isHTML(data) {
				_ = os.Rename(doubleJSPath, localJSPath)
			} else {
				_ = os.Remove(doubleJSPath)
			}
		}

		var jsBody []byte
		status := "downloaded"
		if utils.FileExists(localJSPath) {
			data, err := os.ReadFile(localJSPath)
			if err == nil && len(data) > 0 {
				if isHTML(data) {
					// Stale cached 404 HTML page: remove it
					_ = os.Remove(localJSPath)
				} else {
					jsBody = data
					cachedJSCount++
					analyzedJSCount++
					status = "cached"
				}
			}
		}

		if len(jsBody) == 0 {
			req, err := http.NewRequestWithContext(context.Background(), "GET", jsURL, nil)
			if err != nil {
				failedJSCount++
				jsReports = append(jsReports, JSAnalysisReport{
					URL:    jsURL,
					Status: "404/failed",
				})
				continue
			}
			req.Header.Set("User-Agent", "Webzoro-Recon/1.0")

			resp, err := client.Do(req)
			if err != nil {
				failedJSCount++
				jsReports = append(jsReports, JSAnalysisReport{
					URL:    jsURL,
					Status: "404/failed",
				})
				continue
			}

			// Reject 404 or non-200 responses
			if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				resp.Body.Close()
				failedJSCount++
				jsReports = append(jsReports, JSAnalysisReport{
					URL:    jsURL,
					Status: "404/failed",
				})
				continue
			}

			data, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
			resp.Body.Close()

			if err == nil && len(data) > 0 && !isHTML(data) {
				jsBody = data
				_ = os.WriteFile(localJSPath, jsBody, 0644)
				downloadedJSCount++
				analyzedJSCount++
				status = "downloaded"
			} else {
				failedJSCount++
				jsReports = append(jsReports, JSAnalysisReport{
					URL:    jsURL,
					Status: "404/failed",
				})
				continue
			}
		}

		isVendor := isVendorJSLibrary(jsURL)
		if isVendor {
			status += ", vendor"
		}

		report := JSAnalysisReport{
			URL:       jsURL,
			LocalPath: localJSPath,
			Status:    status,
		}

		if len(jsBody) > 0 {
			// Extract endpoints, routes, and parameters from JS code
			links, params, extraJS := ExtractFromJS(jsBody, baseU, isVendor)
			for _, l := range links {
				masterLinks[l] = true
			}
			for _, p := range params {
				masterParams[p] = true
			}
			for _, j := range extraJS {
				masterJS[j] = true
			}

			// Extract template literal and concatenation IDOR candidates from JS
			for _, cand := range ExtractJSTemplateIDORCandidates(jsBody, baseU) {
				addIDOR(cand)
				report.IDORs = append(report.IDORs, cand.URL)
			}

			// Passively analyze JS code for auth endpoints, token leaks, and client-side logic
			authSurfs := AnalyzeAuthFromJS(jsBody, jsURL, baseU)
			allAuthSurfaces = append(allAuthSurfaces, authSurfs...)
			for _, a := range authSurfs {
				for _, smell := range a.Smells {
					report.AuthSmells = append(report.AuthSmells, smell.Description)
				}
			}

			report.Endpoints = deduplicateAndSort(links)
			report.Params = deduplicateAndSort(params)
			report.IDORs = deduplicateAndSort(report.IDORs)
			report.AuthSmells = deduplicateAndSort(report.AuthSmells)
		}
		jsReports = append(jsReports, report)
	}

	// 3. Scan all discovered links for REST Path IDOR patterns & contextual parameters
	for l := range masterLinks {
		if cand := DetectPathIDOR(l); cand != nil {
			addIDOR(*cand)
		}
		for _, p := range InferContextualParams(l) {
			masterInferred[p] = true
		}
	}

	// Also infer parameters from any detected IDOR candidates
	for _, cand := range idorCandidates {
		for _, p := range cand.CandidateParams {
			masterInferred[p] = true
		}
	}

	// Detect any leaked active/static reset tokens in discovered links
	allAuthSurfaces = append(allAuthSurfaces, DetectLeakedResetLinks(setToSlice(masterLinks))...)

	assets := ExtractedAssets{
		TargetURL:      baseURLStr,
		Port:           port,
		Links:          setToSlice(masterLinks),
		Parameters:     setToSlice(masterParams),
		InferredParams: setToSlice(masterInferred),
		IDORCandidates: idorCandidates,
		JSFiles:        setToSlice(masterJS),
		AuthSurfaces:   DeduplicateAuthSurfaces(allAuthSurfaces),
		JSReports:      jsReports,
	}

	// Active parameter verification (if --verify-params is enabled)
	if t.VerifyParams && (len(assets.InferredParams) > 0 || len(assets.Parameters) > 0) {
		utils.LogAction("Actively verifying candidate parameters against dynamic endpoints...")
		assets.VerifiedParams = VerifyParameters(t, port, baseURLStr, assets)
	}

	// 4. Persist lists to target output directory
	linksFile := filepath.Join(t.OutDir(), "links.txt")
	paramsFile := filepath.Join(t.OutDir(), "params.txt")
	paramsInferredFile := filepath.Join(t.OutDir(), "params_inferred.txt")
	idorJSONFile := filepath.Join(t.OutDir(), "idor_candidates.json")
	idorFuzzFile := filepath.Join(t.OutDir(), "idor_candidates.txt")
	jsFile := filepath.Join(t.OutDir(), "js_files.txt")
	assetsJSONFile := filepath.Join(t.OutDir(), fmt.Sprintf("assets_%d.json", port))

	if len(assets.Links) > 0 {
		_ = os.WriteFile(linksFile, []byte(strings.Join(assets.Links, "\n")+"\n"), 0644)
	}
	if len(assets.Parameters) > 0 {
		_ = os.WriteFile(paramsFile, []byte(strings.Join(assets.Parameters, "\n")+"\n"), 0644)
	}
	if len(assets.InferredParams) > 0 {
		_ = os.WriteFile(paramsInferredFile, []byte(strings.Join(assets.InferredParams, "\n")+"\n"), 0644)
	}
	if len(assets.JSFiles) > 0 {
		_ = os.WriteFile(jsFile, []byte(strings.Join(assets.JSFiles, "\n")+"\n"), 0644)
	}
	authJSONFile := filepath.Join(t.OutDir(), "auth_workflows.json")
	if len(assets.AuthSurfaces) > 0 {
		if data, err := json.MarshalIndent(assets.AuthSurfaces, "", "  "); err == nil {
			_ = os.WriteFile(authJSONFile, data, 0644)
		}
	}
	if len(assets.IDORCandidates) > 0 {
		if data, err := json.MarshalIndent(assets.IDORCandidates, "", "  "); err == nil {
			_ = os.WriteFile(idorJSONFile, data, 0644)
		}
		// Write unique fuzzable URLs for automated fuzzing (e.g. ffuf)
		seenFuzz := make(map[string]bool)
		var fuzzList []string
		for _, cand := range assets.IDORCandidates {
			for _, f := range cand.FuzzURLs {
				if !seenFuzz[f] {
					seenFuzz[f] = true
					fuzzList = append(fuzzList, f)
				}
			}
		}
		if len(fuzzList) > 0 {
			sort.Strings(fuzzList)
			_ = os.WriteFile(idorFuzzFile, []byte(strings.Join(fuzzList, "\n")+"\n"), 0644)
		}
	}
	if data, err := json.MarshalIndent(assets, "", "  "); err == nil {
		_ = os.WriteFile(assetsJSONFile, data, 0644)
	}

	// 5. Console display
	utils.LogSuccess("Asset & Parameter Mining complete on %s:%d:", t.Target, port)
	fmt.Printf("      - %-20s: %s (%s responses saved)\n",
		utils.ColorBold.Sprint("Saved Responses"),
		utils.ColorDim.Sprint(responsesDir),
		utils.ColorHighlight.Sprintf("%d", savedResponsesCount),
	)
	if len(assets.Links) > 0 {
		fmt.Printf("      - %-20s: %s unique link(s) -> %s\n",
			utils.ColorBold.Sprint("Discovered Links"),
			utils.ColorHighlight.Sprintf("%d", len(assets.Links)),
			utils.ColorDim.Sprint(linksFile),
		)
	}
	if len(assets.Parameters) > 0 {
		if t.Verbose {
			fmt.Printf("      - %-20s: %s observed param(s) -> %s\n",
				utils.ColorBold.Sprint("Observed Params"),
				utils.ColorHighlight.Sprintf("%d", len(assets.Parameters)),
				utils.ColorDim.Sprint(paramsFile),
			)
			for i := 0; i < len(assets.Parameters); i += 10 {
				end := i + 10
				if end > len(assets.Parameters) {
					end = len(assets.Parameters)
				}
				fmt.Printf("        %s\n", utils.ColorVersion.Sprint(strings.Join(assets.Parameters[i:end], ", ")))
			}
		} else {
			sampleParams := assets.Parameters
			if len(sampleParams) > 6 {
				sampleParams = sampleParams[:6]
			}
			fmt.Printf("      - %-20s: %s observed param(s) [%s...] -> %s\n",
				utils.ColorBold.Sprint("Observed Params"),
				utils.ColorHighlight.Sprintf("%d", len(assets.Parameters)),
				utils.ColorVersion.Sprint(strings.Join(sampleParams, ", ")),
				utils.ColorDim.Sprint(paramsFile),
			)
		}
	}
	if len(assets.InferredParams) > 0 {
		if t.Verbose {
			fmt.Printf("      - %-20s: %s inferred param(s) -> %s\n",
				utils.ColorBold.Sprint("Inferred Params"),
				utils.ColorHighlight.Sprintf("%d", len(assets.InferredParams)),
				utils.ColorDim.Sprint(paramsInferredFile),
			)
			for i := 0; i < len(assets.InferredParams); i += 10 {
				end := i + 10
				if end > len(assets.InferredParams) {
					end = len(assets.InferredParams)
				}
				fmt.Printf("        %s\n", utils.ColorVersion.Sprint(strings.Join(assets.InferredParams[i:end], ", ")))
			}
		} else {
			sampleInferred := assets.InferredParams
			if len(sampleInferred) > 6 {
				sampleInferred = sampleInferred[:6]
			}
			fmt.Printf("      - %-20s: %s inferred param(s) [%s...] -> %s\n",
				utils.ColorBold.Sprint("Inferred Params"),
				utils.ColorHighlight.Sprintf("%d", len(assets.InferredParams)),
				utils.ColorVersion.Sprint(strings.Join(sampleInferred, ", ")),
				utils.ColorDim.Sprint(paramsInferredFile),
			)
		}
	}
	if t.VerifyParams {
		verifiedJSONFile := filepath.Join(t.OutDir(), "params_verified.json")
		if len(assets.VerifiedParams) > 0 {
			fmt.Printf("      - %-20s: %s true positive parameter(s) confirmed -> %s\n",
				utils.ColorSuccess.Sprint("Verified Params"),
				utils.ColorHighlight.Sprintf("%d", len(assets.VerifiedParams)),
				utils.ColorDim.Sprint(verifiedJSONFile),
			)
			for _, v := range assets.VerifiedParams {
				fmt.Printf("        • %s -> [%s] (%s)\n",
					utils.ColorBold.Sprint(v.Endpoint),
					utils.ColorHighlight.Sprint(v.Param),
					utils.ColorVersion.Sprint(v.Description),
				)
			}
		} else {
			fmt.Printf("      - %-20s: %s\n",
				utils.ColorWarn.Sprint("Verified Params"),
				utils.ColorDim.Sprint("0 parameters responded differently than baseline"),
			)
		}
	} else if len(assets.InferredParams) > 0 {
		fmt.Printf("        %s\n", utils.ColorDim.Sprint("[Tip: Run with --verify-params to actively test inferred parameters on endpoints]"))
	}
	if len(assets.IDORCandidates) > 0 {
		fmt.Printf("      - %-20s: %s potential IDOR endpoint(s) flagged -> %s\n",
			utils.ColorWarn.Sprint("IDOR Candidates"),
			utils.ColorCritical.Sprintf("%d", len(assets.IDORCandidates)),
			utils.ColorDim.Sprint(idorJSONFile),
		)
		maxPreview := 3
		if len(assets.IDORCandidates) < maxPreview {
			maxPreview = len(assets.IDORCandidates)
		}
		for i := 0; i < maxPreview; i++ {
			c := assets.IDORCandidates[i]
			tag := "[" + strings.ToUpper(c.Source) + "]"
			fmt.Printf("        %s %s (entity: %s, id: %s) -> params: %s\n",
				utils.ColorWarn.Sprint(tag),
				utils.ColorBold.Sprint(c.URL),
				utils.ColorHighlight.Sprint(c.Entity),
				utils.ColorVersion.Sprint(c.DetectedID),
				utils.ColorDim.Sprint(strings.Join(c.CandidateParams, ", ")),
			)
		}
	}
	if len(assets.AuthSurfaces) > 0 {
		fmt.Printf("      - %-20s: %s auth/recovery workflow(s) mapped -> %s\n",
			utils.ColorWarn.Sprint("Auth Workflows"),
			utils.ColorHighlight.Sprintf("%d", len(assets.AuthSurfaces)),
			utils.ColorDim.Sprint(authJSONFile),
		)
		maxPreview := 3
		if len(assets.AuthSurfaces) < maxPreview {
			maxPreview = len(assets.AuthSurfaces)
		}
		for i := 0; i < maxPreview; i++ {
			s := assets.AuthSurfaces[i]
			tag := "[" + strings.ToUpper(string(s.Type)) + "]"
			inputsStr := strings.Join(s.Inputs, ", ")
			if inputsStr != "" {
				inputsStr = " [inputs: " + inputsStr + "]"
			}
			fmt.Printf("        %s %s %s%s\n",
				utils.ColorHeader.Sprint(tag),
				utils.ColorVersion.Sprint(s.Method),
				utils.ColorBold.Sprint(s.URL),
				utils.ColorDim.Sprint(inputsStr),
			)
			for _, smell := range s.Smells {
				sevBadge := utils.ColorSeverity(string(smell.Severity))
				fmt.Printf("          ! %s %s\n", sevBadge, smell.Description)
				if smell.Evidence != "" {
					fmt.Printf("            %s %s\n", utils.ColorDim.Sprint("Evidence:"), utils.ColorVersion.Sprint(smell.Evidence))
				}
			}
		}
	}
	if len(assets.JSFiles) > 0 {
		var detailParts []string
		if analyzedJSCount > 0 {
			if cachedJSCount > 0 && downloadedJSCount > 0 {
				detailParts = append(detailParts, fmt.Sprintf("%d analyzed (%d new, %d cached)", analyzedJSCount, downloadedJSCount, cachedJSCount))
			} else if cachedJSCount > 0 {
				detailParts = append(detailParts, fmt.Sprintf("%d analyzed from cache", analyzedJSCount))
			} else {
				detailParts = append(detailParts, fmt.Sprintf("%d downloaded & analyzed", analyzedJSCount))
			}
		} else {
			detailParts = append(detailParts, "0 analyzed")
		}
		if externalJSCount > 0 {
			detailParts = append(detailParts, fmt.Sprintf("%d external CDN", externalJSCount))
		}
		if failedJSCount > 0 {
			detailParts = append(detailParts, fmt.Sprintf("%d 404/failed", failedJSCount))
		}

		fmt.Printf("      - %-20s: %s JS file(s) (%s) -> %s\n",
			utils.ColorBold.Sprint("JavaScript Files"),
			utils.ColorHighlight.Sprintf("%d", len(assets.JSFiles)),
			strings.Join(detailParts, ", "),
			utils.ColorDim.Sprint(jsFile),
		)

		if t.Verbose {
			// Verbose Mode: detailed analysis breakdown per JS file
			for _, rep := range assets.JSReports {
				statusBadge := utils.ColorHighlight.Sprintf("[%s]", rep.Status)
				if rep.Status == "404/failed" {
					statusBadge = utils.ColorError.Sprintf("[%s]", rep.Status)
				} else if rep.Status == "external CDN" {
					statusBadge = utils.ColorDim.Sprintf("[%s]", rep.Status)
				}

				relPath := rep.LocalPath
				if relPath != "" {
					if rel, err := filepath.Rel(t.OutDir(), relPath); err == nil {
						relPath = " (" + rel + ")"
					} else {
						relPath = " (" + relPath + ")"
					}
				}

				fmt.Printf("        • %s %s%s\n",
					utils.ColorBold.Sprint(rep.URL),
					statusBadge,
					utils.ColorDim.Sprint(relPath),
				)

				if len(rep.Endpoints) > 0 {
					sample := rep.Endpoints
					if len(sample) > 5 {
						sample = sample[:5]
					}
					fmt.Printf("          - %s (%d): %s\n",
						utils.ColorInfo.Sprint("Endpoints"),
						len(rep.Endpoints),
						utils.ColorVersion.Sprint(strings.Join(sample, ", ")),
					)
				}
				if len(rep.Params) > 0 {
					sample := rep.Params
					if len(sample) > 8 {
						sample = sample[:8]
					}
					fmt.Printf("          - %s (%d): %s\n",
						utils.ColorInfo.Sprint("Parameters"),
						len(rep.Params),
						utils.ColorVersion.Sprint(strings.Join(sample, ", ")),
					)
				}
				if len(rep.IDORs) > 0 {
					fmt.Printf("          - %s (%d): %s\n",
						utils.ColorWarn.Sprint("IDOR Patterns"),
						len(rep.IDORs),
						utils.ColorCritical.Sprint(strings.Join(rep.IDORs, ", ")),
					)
				}
				if len(rep.AuthSmells) > 0 {
					for _, smell := range rep.AuthSmells {
						fmt.Printf("          - %s: %s\n",
							utils.ColorWarn.Sprint("Auth Finding"),
							utils.ColorCritical.Sprint(smell),
						)
					}
				}
				if len(rep.Endpoints) == 0 && len(rep.Params) == 0 && len(rep.IDORs) == 0 && len(rep.AuthSmells) == 0 && rep.Status != "404/failed" && rep.Status != "external CDN" {
					fmt.Printf("          - %s\n", utils.ColorDim.Sprint("No endpoints, parameters, or IDOR patterns detected in this script"))
				}
			}
		} else {
			// Standard Mode: clean preview of analyzed files and what was extracted
			maxPreview := 3
			analyzedCount := 0
			for _, rep := range assets.JSReports {
				if rep.Status == "downloaded" || rep.Status == "cached" {
					analyzedCount++
					if analyzedCount <= maxPreview {
						var findings []string
						if len(rep.Endpoints) > 0 {
							findings = append(findings, fmt.Sprintf("%d endpoint(s)", len(rep.Endpoints)))
						}
						if len(rep.Params) > 0 {
							findings = append(findings, fmt.Sprintf("%d param(s)", len(rep.Params)))
						}
						if len(rep.IDORs) > 0 {
							findings = append(findings, fmt.Sprintf("%d IDOR pattern(s)", len(rep.IDORs)))
						}
						if len(rep.AuthSmells) > 0 {
							findings = append(findings, fmt.Sprintf("%d auth smell(s)", len(rep.AuthSmells)))
						}
						findingStr := "no endpoints/params extracted"
						if len(findings) > 0 {
							findingStr = strings.Join(findings, ", ")
						}
						fmt.Printf("        • %s (%s)\n",
							utils.ColorBold.Sprint(rep.URL),
							utils.ColorVersion.Sprint(findingStr),
						)
					}
				}
			}
			if analyzedCount > maxPreview {
				fmt.Printf("        %s\n", utils.ColorDim.Sprintf("...and %d more JS file(s) (use --verbose to expand all)", analyzedCount-maxPreview))
			}
		}
	}
	fmt.Println()

	return assets
}
