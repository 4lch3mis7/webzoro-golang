package scanner

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/4lch3mis7/webzoro-golang/utils"
)

// DirHit represents an individual path discovered during directory enumeration.
type DirHit struct {
	Path            string   `json:"path"`
	URL             string   `json:"url"`
	StatusCode      int      `json:"status_code"`
	StatusText      string   `json:"status_text,omitempty"`
	ContentLen      int64    `json:"content_length"`
	Title           string   `json:"title,omitempty"`
	RedirectURL     string   `json:"redirect_url,omitempty"`
	ContentType     string   `json:"content_type,omitempty"`
	IsAPI           bool     `json:"is_api,omitempty"`
	Unauthenticated bool     `json:"unauthenticated,omitempty"`
	Links           []string `json:"links,omitempty"`
	Params          []string `json:"params,omitempty"`
	JSFiles         []string `json:"js_files,omitempty"`
}

// DirEnumResult contains all findings from the directory enumeration scan.
type DirEnumResult struct {
	TargetURL  string   `json:"target_url"`
	ScanType   string   `json:"scan_type,omitempty"`
	TotalWords int      `json:"total_words"`
	Hits       []DirHit `json:"hits"`
	Duration   string   `json:"duration"`
	Soft404    bool     `json:"soft_404_detected"`
}

var dirTitleRegex = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// formatSize converts bytes into a human-readable string (e.g. 1.2KB, 350B).
func formatSize(bytes int64) string {
	if bytes < 1024 {
		return fmt.Sprintf("%dB", bytes)
	} else if bytes < 1024*1024 {
		return fmt.Sprintf("%.1fKB", float64(bytes)/1024.0)
	}
	return fmt.Sprintf("%.1fMB", float64(bytes)/(1024.0*1024.0))
}

func (r DirEnumResult) String() string {
	var sb strings.Builder

	title := "Directory Enumeration Results"
	if r.ScanType != "" {
		title = r.ScanType + " Results"
	}

	header := fmt.Sprintf("\n%s %s (%s - %s words in %s):\n",
		utils.TagSuccess(),
		utils.ColorHeader.Sprint(title),
		utils.ColorHighlight.Sprint(r.TargetURL),
		utils.ColorHighlight.Sprintf("%d", r.TotalWords),
		r.Duration,
	)
	sb.WriteString(header)

	if len(r.Hits) == 0 {
		sb.WriteString("    " + utils.ColorDim.Sprint("No directories or files discovered.") + "\n")
		return sb.String()
	}

	for _, hit := range r.Hits {
		tag := utils.TagSuccess()
		statusColor := utils.ColorSuccess.Sprint(fmt.Sprintf("%-3d", hit.StatusCode))

		switch {
		case hit.StatusCode >= 300 && hit.StatusCode < 400:
			tag = utils.TagInfo()
			statusColor = utils.ColorInfo.Sprint(fmt.Sprintf("%-3d", hit.StatusCode))
		case hit.StatusCode >= 400 && hit.StatusCode < 500:
			tag = utils.TagWarn()
			statusColor = utils.ColorWarn.Sprint(fmt.Sprintf("%-3d", hit.StatusCode))
		case hit.StatusCode >= 500:
			tag = utils.TagError()
			statusColor = utils.ColorError.Sprint(fmt.Sprintf("%-3d", hit.StatusCode))
		}

		sizeStr := utils.ColorDim.Sprintf("%-8s", formatSize(hit.ContentLen))
		pathStr := utils.ColorHighlight.Sprintf("%-30s", hit.Path)

		extra := ""
		if hit.RedirectURL != "" {
			extra = fmt.Sprintf(" -> %s", utils.ColorInfo.Sprint(hit.RedirectURL))
		} else if hit.Title != "" {
			extra = fmt.Sprintf(" [%s]", utils.ColorBold.Sprint(hit.Title))
		}
		extra += formatHitBadge(hit)

		sb.WriteString(fmt.Sprintf("    %s %s %s %s%s\n",
			tag,
			statusColor,
			sizeStr,
			pathStr,
			extra,
		))
	}

	return sb.String()
}

// isAPIEndpoint checks whether a path or response represents an API endpoint.
func isAPIEndpoint(pathStr, contentType string) bool {
	lowerPath := strings.ToLower(pathStr)
	if strings.HasPrefix(lowerPath, "/api") ||
		strings.HasPrefix(lowerPath, "api/") ||
		strings.HasPrefix(lowerPath, "/v1") ||
		strings.HasPrefix(lowerPath, "v1/") ||
		strings.HasPrefix(lowerPath, "/v2") ||
		strings.HasPrefix(lowerPath, "v2/") ||
		strings.HasPrefix(lowerPath, "/v3") ||
		strings.HasPrefix(lowerPath, "v3/") ||
		strings.HasPrefix(lowerPath, "/rest") ||
		strings.HasPrefix(lowerPath, "rest/") ||
		strings.HasPrefix(lowerPath, "/graphql") ||
		strings.HasPrefix(lowerPath, "/swagger") ||
		strings.HasPrefix(lowerPath, "/openapi") {
		return true
	}
	ct := strings.ToLower(contentType)
	if strings.Contains(ct, "json") || strings.Contains(ct, "graphql") {
		return true
	}
	return false
}

// formatHitBadge returns contextual tags for API endpoints and unauthenticated discoveries.
func formatHitBadge(hit DirHit) string {
	if hit.IsAPI {
		switch hit.StatusCode {
		case http.StatusOK:
			return fmt.Sprintf(" %s", utils.ColorCritical.Sprint("[UNAUTHENTICATED API]"))
		case http.StatusUnauthorized, http.StatusForbidden:
			return fmt.Sprintf(" %s", utils.ColorWarn.Sprint("[Protected API]"))
		case http.StatusMethodNotAllowed:
			return fmt.Sprintf(" %s", utils.ColorInfo.Sprint("[Method Not Allowed]"))
		}
	}
	return ""
}

// DirEnum performs fast, concurrent native Go directory and file discovery on targetUrl using the common wordlist.
func DirEnum(targetURL string, outputFile string) DirEnumResult {
	words := loadCommonWordlist()
	return runDirEnum(targetURL, outputFile, words, "Directory Enumeration")
}

// DirEnumPHP performs PHP-specific directory and file discovery on targetUrl.
func DirEnumPHP(targetURL string, outputFile string) DirEnumResult {
	words := loadPHPWordlist()
	return runDirEnum(targetURL, outputFile, words, "PHP Directory Enumeration")
}

// DirEnumAPI performs API route and unauthenticated endpoint discovery on targetUrl.
func DirEnumAPI(targetURL string, outputFile string) DirEnumResult {
	words := loadAPIWordlist()
	return runDirEnum(targetURL, outputFile, words, "API Endpoint Enumeration")
}

// HasIndexPHP checks if /index.php was discovered during directory enumeration.
func HasIndexPHP(hits []DirHit) bool {
	for _, hit := range hits {
		p := strings.ToLower(strings.TrimSpace(hit.Path))
		if p == "/index.php" || p == "index.php" {
			if hit.StatusCode >= 200 && hit.StatusCode < 500 && hit.StatusCode != 404 {
				return true
			}
		}
	}
	return false
}

// runDirEnum executes concurrent directory enumeration with the given wordlist and scanType.
func runDirEnum(targetURL string, outputFile string, words []string, scanType string) DirEnumResult {
	// Check cached scan results first
	if outputFile != "" {
		if !strings.Contains(outputFile, "/") {
			outputFile = path.Join(".local", outputFile)
		}
		if utils.FileExists(outputFile) {
			data, err := os.ReadFile(outputFile)
			if err == nil && len(data) > 0 {
				var cached DirEnumResult
				if err := json.Unmarshal(data, &cached); err == nil && cached.TargetURL != "" {
					utils.LogSuccess("Loaded cached %s results from %s (%s hits)",
						scanType,
						outputFile,
						utils.ColorHighlight.Sprintf("%d", len(cached.Hits)),
					)
					return cached
				}
			}
		}
	}

	startTime := time.Now()
	utils.LogAction("Starting native %s on %s", scanType, targetURL)

	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		utils.LogError("Invalid target URL for directory enumeration: %v", err)
		return DirEnumResult{TargetURL: targetURL, ScanType: scanType}
	}

	if parsedURL.Scheme == "" {
		targetURL = "http://" + targetURL
	}
	targetURL = strings.TrimRight(targetURL, "/")

	// Setup connection-pooled HTTP client (do not follow redirects so we can record 301/302)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		DialContext: (&net.Dialer{
			Timeout:   3 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 30,
		IdleConnTimeout:     10 * time.Second,
	}

	client := &http.Client{
		Transport: tr,
		Timeout:   4 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Auto-Calibrate for Soft-404 detection
	calibrated404 := calibrateSoft404(client, targetURL)

	var responsesDir string
	if outputFile != "" {
		responsesDir = filepath.Join(filepath.Dir(outputFile), "responses")
	}

	// Worker Pool Execution
	concurrency := 25
	jobs := make(chan string, len(words))
	resultsChan := make(chan DirHit, len(words))

	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for w := range jobs {
				if hit, ok := probePath(client, targetURL, w, calibrated404, responsesDir); ok {
					resultsChan <- hit
				}
			}
		}()
	}

	// Enqueue words
	for _, w := range words {
		jobs <- w
	}
	close(jobs)

	// Wait in background and close results channel
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	var hits []DirHit
	for hit := range resultsChan {
		hits = append(hits, hit)
		printHitLive(hit)
	}

	duration := time.Since(startTime).Round(time.Millisecond).String()
	res := DirEnumResult{
		TargetURL:  targetURL,
		ScanType:   scanType,
		TotalWords: len(words),
		Hits:       hits,
		Duration:   duration,
		Soft404:    calibrated404.IsSoft404,
	}

	utils.LogSuccess("%s complete: %s hits in %s",
		scanType,
		utils.ColorHighlight.Sprintf("%d", len(hits)),
		duration,
	)

	// Persist to outputFile if specified
	if outputFile != "" {
		if !strings.Contains(outputFile, "/") {
			outputFile = path.Join(".local", outputFile)
		}
		if data, err := json.MarshalIndent(res, "", "  "); err == nil {
			_ = os.WriteFile(outputFile, data, 0644)
			utils.LogSuccess("Saved %s results to %s", scanType, outputFile)
		}
	}

	return res
}

type soft404Signature struct {
	IsSoft404   bool
	StatusCode  int
	ContentLen  int64
	BodySnippet string
	Title       string
}

// calibrateSoft404 probes non-existent random URLs to detect servers returning 200 for missing pages.
func calibrateSoft404(client *http.Client, baseURL string) soft404Signature {
	randBytes := make([]byte, 8)
	_, _ = rand.Read(randBytes)
	randomPath := fmt.Sprintf("/wz_probe_404_%s", hex.EncodeToString(randBytes))

	req, err := http.NewRequestWithContext(context.Background(), "GET", baseURL+randomPath, nil)
	if err != nil {
		return soft404Signature{}
	}
	req.Header.Set("User-Agent", "Webzoro-Directory-Scanner/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return soft404Signature{}
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
	title := extractTitle(body)

	// If random non-existent path returns 200 or 302, soft-404 is active
	if resp.StatusCode == http.StatusOK {
		utils.LogWarn("Soft-404 detected on %s (server returns 200 OK for missing paths, calibrating filters...)", baseURL)
		return soft404Signature{
			IsSoft404:   true,
			StatusCode:  resp.StatusCode,
			ContentLen:  int64(len(body)),
			BodySnippet: string(body),
			Title:       title,
		}
	}

	return soft404Signature{}
}

// probePath sends a request to a single endpoint and checks for a valid hit.
func probePath(client *http.Client, baseURL, word string, cal soft404Signature, responsesDir string) (DirHit, bool) {
	if !strings.HasPrefix(word, "/") {
		word = "/" + word
	}
	fullURL := baseURL + word

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", fullURL, nil)
	if err != nil {
		return DirHit{}, false
	}
	req.Header.Set("User-Agent", "Webzoro-Directory-Scanner/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return DirHit{}, false
	}
	defer resp.Body.Close()

	// Ignore 404 Not Found
	if resp.StatusCode == http.StatusNotFound {
		return DirHit{}, false
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	title := extractTitle(body)
	contentLen := int64(len(body))
	if resp.ContentLength > 0 {
		contentLen = resp.ContentLength
	}

	// Filter out calibrated soft-404s (do not discard valid JSON responses)
	contentType := resp.Header.Get("Content-Type")
	isJSON := strings.Contains(strings.ToLower(contentType), "json") ||
		strings.HasPrefix(strings.TrimSpace(string(body)), "{") ||
		strings.HasPrefix(strings.TrimSpace(string(body)), "[")

	if cal.IsSoft404 && resp.StatusCode == cal.StatusCode && !isJSON {
		// If response length is within +/- 5% or title matches soft-404, discard as false-positive
		diff := math.Abs(float64(contentLen - cal.ContentLen))
		if (cal.Title != "" && title == cal.Title) || (diff < 32 && diff < float64(cal.ContentLen)*0.05) {
			return DirHit{}, false
		}
	}

	hitURL, _ := url.Parse(fullURL)
	if resp.Request != nil && resp.Request.URL != nil {
		hitURL = resp.Request.URL
	}

	// Save response to responses/ directory
	if responsesDir != "" {
		port := 80
		if hitURL != nil {
			if p, err := strconv.Atoi(hitURL.Port()); err == nil {
				port = p
			} else if hitURL.Scheme == "https" {
				port = 443
			}
		}
		SaveHTTPResponse(responsesDir, port, fullURL, resp.StatusCode, resp.Header, body)
	}

	// Extract links, parameters, and JS files from response body
	var links, params, jsFiles []string
	if hitURL != nil {
		links, params, jsFiles = ExtractFromHTML(body, hitURL)
	}

	redirectLocation := resp.Header.Get("Location")
	isAPI := isAPIEndpoint(word, contentType)
	isUnauth := isAPI && resp.StatusCode == http.StatusOK

	hit := DirHit{
		Path:            word,
		URL:             fullURL,
		StatusCode:      resp.StatusCode,
		StatusText:      http.StatusText(resp.StatusCode),
		ContentLen:      contentLen,
		Title:           title,
		RedirectURL:     redirectLocation,
		ContentType:     contentType,
		IsAPI:           isAPI,
		Unauthenticated: isUnauth,
		Links:           links,
		Params:          params,
		JSFiles:         jsFiles,
	}

	return hit, true
}

func printHitLive(hit DirHit) {
	tag := utils.TagSuccess()
	statusColor := utils.ColorSuccess.Sprint(fmt.Sprintf("%-3d", hit.StatusCode))

	switch {
	case hit.Unauthenticated:
		tag = utils.TagCritical()
		statusColor = utils.ColorCritical.Sprint(fmt.Sprintf("%-3d", hit.StatusCode))
	case hit.StatusCode >= 300 && hit.StatusCode < 400:
		tag = utils.TagInfo()
		statusColor = utils.ColorInfo.Sprint(fmt.Sprintf("%-3d", hit.StatusCode))
	case hit.StatusCode >= 400 && hit.StatusCode < 500:
		tag = utils.TagWarn()
		statusColor = utils.ColorWarn.Sprint(fmt.Sprintf("%-3d", hit.StatusCode))
	case hit.StatusCode >= 500:
		tag = utils.TagError()
		statusColor = utils.ColorError.Sprint(fmt.Sprintf("%-3d", hit.StatusCode))
	}

	extra := ""
	if hit.RedirectURL != "" {
		extra = fmt.Sprintf(" -> %s", utils.ColorInfo.Sprint(hit.RedirectURL))
	} else if hit.Title != "" {
		extra = fmt.Sprintf(" [%s]", utils.ColorBold.Sprint(hit.Title))
	}
	extra += formatHitBadge(hit)
	var badges []string
	if len(hit.Links) > 0 {
		badges = append(badges, fmt.Sprintf("links: %d", len(hit.Links)))
	}
	if len(hit.Params) > 0 {
		badges = append(badges, fmt.Sprintf("params: %d", len(hit.Params)))
	}
	if len(hit.JSFiles) > 0 {
		badges = append(badges, fmt.Sprintf("js: %d", len(hit.JSFiles)))
	}
	if len(badges) > 0 {
		extra += fmt.Sprintf(" %s", utils.ColorDim.Sprintf("(%s)", strings.Join(badges, ", ")))
	}

	fmt.Printf("    %s %s %-8s %s%s\n",
		tag,
		statusColor,
		utils.ColorDim.Sprint(formatSize(hit.ContentLen)),
		utils.ColorHighlight.Sprint(hit.Path),
		extra,
	)
}

func extractTitle(body []byte) string {
	if matches := dirTitleRegex.FindSubmatch(body); len(matches) > 1 {
		rawTitle := strings.TrimSpace(string(matches[1]))
		rawTitle = html.UnescapeString(rawTitle)
		return strings.Join(strings.Fields(rawTitle), " ")
	}
	return ""
}

// loadCommonWordlist loads SecLists common.txt, caching it at $HOME/.local/wordlists/common.txt so it only downloads once.
func loadCommonWordlist() []string {
	home, _ := os.UserHomeDir()
	if home == "" {
		home = os.Getenv("HOME")
	}
	cacheFile := filepath.Join(home, ".local", "wordlists", "common.txt")
	if utils.FileExists(cacheFile) {
		lines := utils.ReadLines(cacheFile)
		if len(lines) > 0 {
			return lines
		}
	}

	// Fetch remote SecLists common.txt
	words := utils.ReadLinesRemote("https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Discovery/Web-Content/common.txt")
	if len(words) > 0 {
		utils.CheckAndCreateDir(filepath.Dir(cacheFile))
		_ = os.WriteFile(cacheFile, []byte(strings.Join(words, "\n")), 0644)
		return words
	}

	return defaultHighImpactWordlist
}

// loadPHPWordlist loads SecLists Common-PHP-Filenames.txt, caching it at $HOME/.local/wordlists/Common-PHP-Filenames.txt so it only downloads once.
func loadPHPWordlist() []string {
	home, _ := os.UserHomeDir()
	if home == "" {
		home = os.Getenv("HOME")
	}
	cacheFile := filepath.Join(home, ".local", "wordlists", "Common-PHP-Filenames.txt")
	if utils.FileExists(cacheFile) {
		lines := utils.ReadLines(cacheFile)
		if len(lines) > 0 {
			return lines
		}
	}

	// Fetch remote SecLists Common-PHP-Filenames.txt
	words := utils.ReadLinesRemote("https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Discovery/Web-Content/Programming-Language-Specific/Common-PHP-Filenames.txt")
	if len(words) > 0 {
		utils.CheckAndCreateDir(filepath.Dir(cacheFile))
		_ = os.WriteFile(cacheFile, []byte(strings.Join(words, "\n")), 0644)
		return words
	}

	return defaultPHPWordlist
}

// loadAPIWordlist loads SecLists api-endpoints.txt (cached locally at ~/.local/wordlists/api-endpoints.txt),
// and merges it with DefaultAPIWordlist and dynamic entity permutations to guarantee coverage of critical API endpoints.
func loadAPIWordlist() []string {
	var words []string
	seen := make(map[string]bool)

	addWord := func(w string) {
		w = strings.TrimSpace(w)
		if w != "" && !strings.HasPrefix(w, "#") && !seen[w] {
			seen[w] = true
			words = append(words, w)
		}
	}

	// 1. Always prioritize DefaultAPIWordlist (curated top routes)
	for _, w := range DefaultAPIWordlist {
		addWord(w)
	}

	// 2. Dynamic generation: combine API prefixes with KnownEntities
	prefixes := []string{"api", "api/v1", "v1", "rest"}
	for entity := range KnownEntities {
		singular := singularizeEntity(entity)
		plural := singular + "s"
		for _, prefix := range prefixes {
			addWord(prefix + "/" + plural)
			addWord(prefix + "/" + singular)
		}
	}

	// 3. Check local cache, local SecLists, or fetch remote
	home, _ := os.UserHomeDir()
	if home == "" {
		home = os.Getenv("HOME")
	}
	cacheFile := filepath.Join(home, ".local", "wordlists", "api-endpoints.txt")
	seclistsPath := "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt"

	var extraLines []string
	if utils.FileExists(cacheFile) {
		extraLines = utils.ReadLines(cacheFile)
	} else if utils.FileExists(seclistsPath) {
		extraLines = utils.ReadLines(seclistsPath)
		utils.CheckAndCreateDir(filepath.Dir(cacheFile))
		_ = os.WriteFile(cacheFile, []byte(strings.Join(extraLines, "\n")), 0644)
	} else {
		extraLines = utils.ReadLinesRemote("https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Discovery/Web-Content/api/api-endpoints.txt")
		if len(extraLines) > 0 {
			utils.CheckAndCreateDir(filepath.Dir(cacheFile))
			_ = os.WriteFile(cacheFile, []byte(strings.Join(extraLines, "\n")), 0644)
		}
	}

	for _, l := range extraLines {
		addWord(l)
	}

	return words
}

// loadWordlist returns user-supplied wordlist lines or the curated embedded wordlist.
func loadWordlist(filePath string) []string {
	if filePath != "" && utils.FileExists(filePath) {
		lines := utils.ReadLines(filePath)
		var cleaned []string
		for _, l := range lines {
			l = strings.TrimSpace(l)
			if l != "" && !strings.HasPrefix(l, "#") {
				cleaned = append(cleaned, l)
			}
		}
		if len(cleaned) > 0 {
			return cleaned
		}
	}

	return DefaultHighImpactWordlist
}
