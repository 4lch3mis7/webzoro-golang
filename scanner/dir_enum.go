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
	"strings"
	"sync"
	"time"

	"github.com/4lch3mis7/webzoro-golang/utils"
)

// DirHit represents an individual path discovered during directory enumeration.
type DirHit struct {
	Path        string `json:"path"`
	URL         string `json:"url"`
	StatusCode  int    `json:"status_code"`
	StatusText  string `json:"status_text,omitempty"`
	ContentLen  int64  `json:"content_length"`
	Title       string `json:"title,omitempty"`
	RedirectURL string `json:"redirect_url,omitempty"`
	ContentType string `json:"content_type,omitempty"`
}

// DirEnumResult contains all findings from the directory enumeration scan.
type DirEnumResult struct {
	TargetURL  string   `json:"target_url"`
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

	header := fmt.Sprintf("\n%s %s (%s - %s words in %s):\n",
		utils.TagSuccess(),
		utils.ColorHeader.Sprint("Directory Enumeration Results"),
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
		case hit.StatusCode == 401 || hit.StatusCode == 403:
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

// DirEnum performs fast, concurrent native Go directory and file discovery on targetUrl.
func DirEnum(targetURL string, outputFile string) DirEnumResult {
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
					utils.LogSuccess("Loaded cached directory enumeration results from %s (%s hits)",
						outputFile,
						utils.ColorHighlight.Sprintf("%d", len(cached.Hits)),
					)
					return cached
				}
			}
		}
	}

	startTime := time.Now()
	utils.LogAction("Starting native directory enumeration on %s", targetURL)

	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		utils.LogError("Invalid target URL for directory enumeration: %v", err)
		return DirEnumResult{TargetURL: targetURL}
	}

	if parsedURL.Scheme == "" {
		targetURL = "http://" + targetURL
	}
	targetURL = strings.TrimRight(targetURL, "/")

	// 1. Prepare wordlist (loads locally or downloads once from remote SecLists)
	words := loadCommonWordlist()

	// 2. Setup connection-pooled HTTP client (do not follow redirects so we can record 301/302)
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

	// 3. Auto-Calibrate for Soft-404 detection
	calibrated404 := calibrateSoft404(client, targetURL)

	// 4. Worker Pool Execution
	concurrency := 25
	jobs := make(chan string, len(words))
	resultsChan := make(chan DirHit, len(words))

	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for w := range jobs {
				if hit, ok := probePath(client, targetURL, w, calibrated404); ok {
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
		TotalWords: len(words),
		Hits:       hits,
		Duration:   duration,
		Soft404:    calibrated404.IsSoft404,
	}

	utils.LogSuccess("Directory enumeration complete: %s hits in %s",
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
			utils.LogSuccess("Saved directory enumeration results to %s", outputFile)
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
func probePath(client *http.Client, baseURL, word string, cal soft404Signature) (DirHit, bool) {
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

	// Ignore 404 Not Found, 400 Bad Request
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusBadRequest {
		return DirHit{}, false
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
	title := extractTitle(body)
	contentLen := int64(len(body))
	if resp.ContentLength > 0 {
		contentLen = resp.ContentLength
	}

	// Filter out calibrated soft-404s
	if cal.IsSoft404 && resp.StatusCode == cal.StatusCode {
		// If response length is within +/- 5% or title matches soft-404, discard as false-positive
		diff := math.Abs(float64(contentLen - cal.ContentLen))
		if (cal.Title != "" && title == cal.Title) || (diff < 32 && diff < float64(cal.ContentLen)*0.05) {
			return DirHit{}, false
		}
	}

	redirectLocation := resp.Header.Get("Location")

	hit := DirHit{
		Path:        word,
		URL:         fullURL,
		StatusCode:  resp.StatusCode,
		StatusText:  http.StatusText(resp.StatusCode),
		ContentLen:  contentLen,
		Title:       title,
		RedirectURL: redirectLocation,
		ContentType: resp.Header.Get("Content-Type"),
	}

	return hit, true
}

func printHitLive(hit DirHit) {
	tag := utils.TagSuccess()
	statusColor := utils.ColorSuccess.Sprint(fmt.Sprintf("%-3d", hit.StatusCode))

	switch {
	case hit.StatusCode >= 300 && hit.StatusCode < 400:
		tag = utils.TagInfo()
		statusColor = utils.ColorInfo.Sprint(fmt.Sprintf("%-3d", hit.StatusCode))
	case hit.StatusCode == 401 || hit.StatusCode == 403:
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

	return defaultHighImpactWordlist
}

// defaultHighImpactWordlist contains curated, high-priority routes and sensitive files for web enumeration.
var defaultHighImpactWordlist = []string{
	// Admin & Authentication
	"admin",
	"admin/",
	"admin/login",
	"admin/login.php",
	"admin/index.php",
	"administrator",
	"administrator/",
	"login",
	"login.php",
	"signin",
	"auth",
	"authenticate",
	"portal",
	"controlpanel",
	"cpanel",
	"dashboard",
	"manage",
	"management",
	"wp-admin",
	"wp-login.php",
	"user/login",
	"account/login",

	// Version Control & Repositories
	".git",
	".git/HEAD",
	".git/config",
	".git/index",
	".gitignore",
	".gitlab-ci.yml",
	".github",
	".svn",
	".svn/entries",
	".hg",
	".bzr",

	// Environment & Configuration Secrets
	".env",
	".env.local",
	".env.production",
	".env.development",
	".env.example",
	".env.bak",
	".env.save",
	"config.php",
	"config.php.bak",
	"config.json",
	"config.yml",
	"config.yaml",
	"configuration.php",
	"settings.py",
	"database.yml",
	"secrets.yml",
	"wp-config.php",
	"wp-config.php.bak",
	"wp-config.old",
	"web.config",
	"appsettings.json",
	"appsettings.Development.json",

	// APIs, Documentation & Schemas
	"api",
	"api/",
	"api/v1",
	"api/v2",
	"api/v3",
	"swagger",
	"swagger/",
	"swagger/index.html",
	"swagger-ui",
	"swagger-ui.html",
	"swagger.json",
	"swagger.yaml",
	"openapi.json",
	"openapi.yaml",
	"docs",
	"docs/",
	"api-docs",
	"api-docs/",
	"graphql",
	"graphiql",
	"v1",
	"v2",

	// Backups, Dumps & Archives
	"backup",
	"backup/",
	"backups",
	"backups/",
	"backup.zip",
	"backup.tar.gz",
	"backup.tar",
	"backup.sql",
	"backup.bak",
	"dump.sql",
	"db.sql",
	"data.sql",
	"database.sql",
	"site.zip",
	"site.tar.gz",
	"archive.zip",
	"www.zip",

	// Diagnostics, Health & Status
	"phpinfo.php",
	"info.php",
	"test.php",
	"health",
	"healthz",
	"live",
	"ready",
	"actuator",
	"actuator/health",
	"actuator/env",
	"actuator/info",
	"server-status",
	"status",
	"metrics",
	"debug",
	"trace",
	"console",

	// Common Sensitive Files & Policies
	"robots.txt",
	"sitemap.xml",
	".well-known/security.txt",
	"crossdomain.xml",
	"clientaccesspolicy.xml",
	"composer.json",
	"composer.lock",
	"package.json",
	"package-lock.json",
	"Dockerfile",
	"docker-compose.yml",
	"Makefile",

	// Common Directories
	"uploads",
	"uploads/",
	"upload",
	"files",
	"files/",
	"static",
	"static/",
	"assets",
	"assets/",
	"images",
	"images/",
	"media",
	"includes",
	"inc",
	"temp",
	"tmp",
	"test",
	"dev",
	"staging",
	"internal",
	"private",
	"secret",
	"keys",
	"certs",
	"logs",
	"log",
}
