package scanner

import (
	"bytes"
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
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/4lch3mis7/webzoro-golang/utils"
)

// SSTIFinding represents a confirmed Server-Side Template Injection vulnerability.
type SSTIFinding struct {
	Endpoint       string `json:"endpoint"`
	Param          string `json:"param"`
	Method         string `json:"method"`                     // "GET", "POST"
	PostFormat     string `json:"post_format,omitempty"`      // "form", "json"
	Engine         string `json:"engine"`                     // "Jinja2 (Flask/Python)", "Twig (PHP)", "Generic Template Engine"
	Severity       string `json:"severity"`                   // "CRITICAL"
	Syntax         string `json:"syntax"`                     // "{{...}}" or "${...}"
	TriggerPayload string `json:"trigger_payload"`            // e.g. {{491*13}}
	CanaryResult   string `json:"canary_result"`              // e.g. 6383
	Evidence       string `json:"evidence"`                   // Matched snippet from body
	SafePoC        string `json:"safe_poc,omitempty"`         // e.g. {{lipsum}} -> <function lipsum>
	ProbeURL       string `json:"probe_url"`
}

// SSTIProbeTemplate defines a probe expression and expected mathematical evaluation result.
type SSTIProbeTemplate struct {
	Syntax   string // "{{...}}", "${...}", "<%= ... %>"
	Payload  string // e.g. "{{491*13}}"
	Expected string // e.g. "6383"
	RawMath  string // e.g. "491*13"
}

// Standard non-destructive arithmetic probes with low probability of natural collision.
var defaultSSTIProbes = []SSTIProbeTemplate{
	{
		Syntax:   "{{...}}",
		Payload:  "{{491*13}}",
		Expected: "6383",
		RawMath:  "491*13",
	},
	{
		Syntax:   "${...}",
		Payload:  "${491*13}",
		Expected: "6383",
		RawMath:  "491*13",
	},
	{
		Syntax:   "<%= ... %>",
		Payload:  "<%= 491*13 %>",
		Expected: "6383",
		RawMath:  "491*13",
	},
}

// High-priority parameter names commonly passed to template renderers.
var sstiCandidateParamNames = map[string]bool{
	"q": true, "query": true, "search": true, "s": true,
	"name": true, "username": true, "user": true,
	"template": true, "tpl": true, "view": true, "page": true,
	"msg": true, "message": true, "text": true, "content": true,
	"input": true, "title": true, "greeting": true, "comment": true,
	"email": true, "id": true, "redirect": true, "error": true,
	"data": true, "pickle_data": true, "code": true, "render": true,
	"cmd": true, "payload": true, "format": true, "body": true, "prompt": true,
}

// createSSTIRequest generates the appropriate GET or POST (form/JSON) request for SSTI probing.
func createSSTIRequest(ctx context.Context, endpoint, param, payload, method, postFormat string) (*http.Request, string, error) {
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		method = "GET"
	}

	if method == "POST" {
		if postFormat == "json" {
			data := map[string]string{param: payload}
			jsonData, err := json.Marshal(data)
			if err != nil {
				return nil, "", err
			}
			req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(jsonData))
			if err != nil {
				return nil, "", err
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("User-Agent", "Webzoro-SSTI-Audit/1.0")
			probeDesc := fmt.Sprintf("[POST JSON] %s (%s=%s)", endpoint, param, payload)
			return req, probeDesc, nil
		}

		vals := url.Values{param: []string{payload}}
		req, err := http.NewRequestWithContext(ctx, "POST", endpoint, strings.NewReader(vals.Encode()))
		if err != nil {
			return nil, "", err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("User-Agent", "Webzoro-SSTI-Audit/1.0")
		probeDesc := fmt.Sprintf("[POST FORM] %s (%s=%s)", endpoint, param, payload)
		return req, probeDesc, nil
	}

	parsedURL, err := url.Parse(endpoint)
	if err != nil {
		return nil, "", err
	}
	q := parsedURL.Query()
	q.Set(param, payload)
	targetURL := *parsedURL
	targetURL.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, "GET", targetURL.String(), nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("User-Agent", "Webzoro-SSTI-Audit/1.0")
	return req, targetURL.String(), nil
}

// ProbeSSTI tests a specific endpoint and parameter for template injection across GET and POST methods.
func ProbeSSTI(client *http.Client, endpoint, param, method, postFormat, baselineBody string) *SSTIFinding {
	if method == "" {
		method = "GET"
	}

	for _, probe := range defaultSSTIProbes {
		// If baseline already contains the canary result, skip this probe to prevent false positives
		if strings.Contains(baselineBody, probe.Expected) {
			continue
		}

		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		req, probeURLDesc, err := createSSTIRequest(ctx, endpoint, param, probe.Payload, method, postFormat)
		if err != nil {
			cancel()
			continue
		}

		resp, err := client.Do(req)
		if err != nil {
			cancel()
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
		resp.Body.Close()
		cancel()

		bodyStr := string(body)

		// Verification: The computed answer (6383) MUST be present, and must not have been in the baseline
		if strings.Contains(bodyStr, probe.Expected) {
			evidence := extractEvidenceSnippet(bodyStr, probe.Expected, 60)

			engine := "Generic Template Engine"
			safePoC := ""

			// Stage 2: Disambiguate Engine (Jinja2 vs Twig vs Other) if syntax is {{...}}
			if probe.Syntax == "{{...}}" {
				engine, safePoC = fingerprintJinjaOrTwig(client, endpoint, param, method, postFormat)
			}

			return &SSTIFinding{
				Endpoint:       endpoint,
				Param:          param,
				Method:         method,
				PostFormat:     postFormat,
				Engine:         engine,
				Severity:       "CRITICAL",
				Syntax:         probe.Syntax,
				TriggerPayload: probe.Payload,
				CanaryResult:   probe.Expected,
				Evidence:       evidence,
				SafePoC:        safePoC,
				ProbeURL:       probeURLDesc,
			}
		}
	}

	return nil
}

// fingerprintJinjaOrTwig sends {{7*'7'}} via the target method to distinguish Jinja2 (7777777) from Twig (49).
func fingerprintJinjaOrTwig(client *http.Client, endpoint, param, method, postFormat string) (string, string) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	req, _, err := createSSTIRequest(ctx, endpoint, param, "{{7*'7'}}", method, postFormat)
	if err != nil {
		cancel()
		return "Generic Template Engine", ""
	}

	resp, err := client.Do(req)
	if err != nil {
		cancel()
		return "Generic Template Engine", ""
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	resp.Body.Close()
	cancel()

	bodyStr := string(body)

	if strings.Contains(bodyStr, "7777777") {
		// Jinja2 confirmed. Stage 3: Perform safe context verification ({{lipsum}} or {{config}})
		safePoC := testJinjaSafePoC(client, endpoint, param, method, postFormat)
		return "Jinja2 (Flask/Python)", safePoC
	} else if strings.Contains(bodyStr, "49") {
		return "Twig (PHP)", "{{7*'7'}} -> 49"
	}

	return "Jinja2 / Twig Compatible Engine", ""
}

// testJinjaSafePoC verifies access to Flask template globals non-destructively.
func testJinjaSafePoC(client *http.Client, endpoint, param, method, postFormat string) string {
	pocPayloads := []struct {
		payload string
		needle  string
	}{
		{"{{lipsum}}", "function"},
		{"{{cycler}}", "function"},
		{"{{config}}", "Config"},
	}

	for _, p := range pocPayloads {
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		req, _, err := createSSTIRequest(ctx, endpoint, param, p.payload, method, postFormat)
		if err != nil {
			cancel()
			continue
		}

		resp, err := client.Do(req)
		if err != nil {
			cancel()
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
		resp.Body.Close()
		cancel()

		bodyStr := string(body)
		if strings.Contains(bodyStr, p.needle) {
			return fmt.Sprintf("%s -> %s", p.payload, extractEvidenceSnippet(bodyStr, p.needle, 40))
		}
	}

	return "{{7*'7'}} -> 7777777"
}

func extractEvidenceSnippet(body, needle string, radius int) string {
	idx := strings.Index(body, needle)
	if idx == -1 {
		return needle
	}
	start := idx - radius
	if start < 0 {
		start = 0
	}
	end := idx + len(needle) + radius
	if end > len(body) {
		end = len(body)
	}
	snippet := strings.ReplaceAll(body[start:end], "\n", " ")
	snippet = strings.Join(strings.Fields(snippet), " ")
	return "..." + strings.TrimSpace(snippet) + "..."
}

// AuditSSTI tests discovered endpoints and candidate parameters for Server-Side Template Injection across GET and POST.
func AuditSSTI(t *Target, port int, baseURLStr string, assets ExtractedAssets) []SSTIFinding {
	baseU, err := url.Parse(baseURLStr)
	if err != nil {
		return nil
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			DialContext: (&net.Dialer{
				Timeout: 4 * time.Second,
			}).DialContext,
			MaxIdleConns:        40,
			MaxIdleConnsPerHost: 20,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 5 * time.Second,
	}

	type targetCandidate struct {
		endpoint   string
		param      string
		method     string
		postFormat string
	}

	var candidates []targetCandidate
	seen := make(map[string]bool)

	addCandidate := func(endpoint, param, method, postFormat string) {
		method = strings.ToUpper(strings.TrimSpace(method))
		if method == "" {
			method = "GET"
		}
		k := fmt.Sprintf("%s|%s|%s|%s", endpoint, method, postFormat, param)
		if !seen[k] {
			seen[k] = true
			candidates = append(candidates, targetCandidate{
				endpoint:   endpoint,
				param:      param,
				method:     method,
				postFormat: postFormat,
			})
		}
	}

	// 1. Highest priority: verified parameters (both GET and POST, all signals)
	for _, vp := range assets.VerifiedParams {
		if vp.Param != "" && vp.Endpoint != "" {
			addCandidate(vp.Endpoint, vp.Param, vp.Method, vp.PostFormat)
		}
	}

	// 2. Discovered HTML Forms (all forms: POST and GET)
	for _, f := range assets.FormSurfaces {
		method := strings.ToUpper(strings.TrimSpace(f.Method))
		if method == "" {
			method = "GET"
		}
		postFormat := ""
		if method == "POST" {
			postFormat = "form"
		}
		for _, p := range f.Inputs {
			addCandidate(f.Action, p, method, postFormat)
		}
	}

	// 3. Discovered Auth Forms (fallback/hidden fields)
	for _, s := range assets.AuthSurfaces {
		if strings.ToUpper(strings.TrimSpace(s.Method)) == "POST" && s.URL != "" {
			for _, p := range s.Inputs {
				if sstiCandidateParamNames[strings.ToLower(p)] {
					addCandidate(s.URL, p, "POST", "form")
				}
			}
		}
	}

	// 3. Discovered API endpoints (POST application/json)
	for _, cand := range assets.IDORCandidates {
		if strings.ToUpper(cand.Method) == "POST" || strings.Contains(cand.URL, "/api/") {
			for _, p := range cand.CandidateParams {
				if sstiCandidateParamNames[strings.ToLower(p)] {
					addCandidate(cand.URL, p, "POST", "json")
				}
			}
		}
	}

	// 4. Dynamic GET endpoints with recognized search/view/input parameter candidates
	dynamicEndpoints := SelectDynamicEndpoints(assets.Links, baseU)
	allParams := append(assets.Parameters, assets.InferredParams...)
	for _, ep := range dynamicEndpoints {
		for _, p := range allParams {
			if sstiCandidateParamNames[strings.ToLower(p)] {
				addCandidate(ep, p, "GET", "")
			}
		}
	}

	// Cap candidates to keep audit fast (top 25 candidates maximum)
	if len(candidates) > 25 {
		candidates = candidates[:25]
	}

	if len(candidates) == 0 {
		return nil
	}

	utils.LogAction("Auditing %s candidate parameter/endpoint pair(s) for SSTI (GET & POST)...", utils.ColorHighlight.Sprintf("%d", len(candidates)))

	// Measure baseline bodies for unique endpoints and methods
	baselineMap := make(map[string]string)
	for _, c := range candidates {
		baseKey := fmt.Sprintf("%s|%s|%s", c.endpoint, c.method, c.postFormat)
		if _, ok := baselineMap[baseKey]; !ok {
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			req, _, err := createSSTIRequest(ctx, c.endpoint, "", "", c.method, c.postFormat)
			if err == nil {
				resp, err := client.Do(req)
				if err == nil {
					body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
					resp.Body.Close()
					baselineMap[baseKey] = string(body)
				}
			}
			cancel()
		}
	}

	// Concurrently probe candidates
	var findings []SSTIFinding
	var mu sync.Mutex

	jobs := make(chan targetCandidate, len(candidates))
	var wg sync.WaitGroup
	concurrency := 10

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for cand := range jobs {
				baseKey := fmt.Sprintf("%s|%s|%s", cand.endpoint, cand.method, cand.postFormat)
				baseline := baselineMap[baseKey]
				if finding := ProbeSSTI(client, cand.endpoint, cand.param, cand.method, cand.postFormat, baseline); finding != nil {
					mu.Lock()
					findings = append(findings, *finding)
					printSSTIFindingLive(*finding)
					mu.Unlock()
				}
			}
		}()
	}

	for _, cand := range candidates {
		jobs <- cand
	}
	close(jobs)
	wg.Wait()

	// Persist findings
	if len(findings) > 0 {
		sort.Slice(findings, func(i, j int) bool {
			return findings[i].Endpoint < findings[j].Endpoint
		})

		sstiJSONFile := filepath.Join(t.OutDir(), "ssti_findings.json")
		if data, err := json.MarshalIndent(findings, "", "  "); err == nil {
			_ = os.WriteFile(sstiJSONFile, data, 0644)
			utils.LogSuccess("Saved %d SSTI finding(s) to %s", len(findings), sstiJSONFile)
		}

		sstiTxtFile := filepath.Join(t.OutDir(), "ssti_findings.txt")
		var lines []string
		for _, f := range findings {
			lines = append(lines, fmt.Sprintf("[%s] %s [%s - %s] -> %s", f.Method, f.ProbeURL, f.Engine, f.TriggerPayload, f.Evidence))
		}
		_ = os.WriteFile(sstiTxtFile, []byte(strings.Join(lines, "\n")+"\n"), 0644)
	}

	return findings
}

func printSSTIFindingLive(f SSTIFinding) {
	badge := utils.ColorSeverity(f.Severity)
	methodStr := f.Method
	if methodStr == "" {
		methodStr = "GET"
	}
	if f.PostFormat != "" {
		methodStr += " " + strings.ToUpper(f.PostFormat)
	}

	fmt.Printf("\n    %s %s Server-Side Template Injection (%s):\n",
		utils.TagCritical(),
		badge,
		utils.ColorHeader.Sprint(f.Engine),
	)
	fmt.Printf("        • %-16s: [%s] %s\n", utils.ColorBold.Sprint("Endpoint"), utils.ColorVersion.Sprint(methodStr), utils.ColorHighlight.Sprint(f.Endpoint))
	fmt.Printf("        • %-16s: %s\n", utils.ColorBold.Sprint("Parameter"), utils.ColorVersion.Sprint(f.Param))
	fmt.Printf("        • %-16s: %s (Evaluated: %s)\n", utils.ColorBold.Sprint("Trigger Payload"), utils.ColorCritical.Sprint(f.TriggerPayload), utils.ColorSuccess.Sprint(f.CanaryResult))
	if f.SafePoC != "" {
		fmt.Printf("        • %-16s: %s\n", utils.ColorBold.Sprint("Safe Context PoC"), utils.ColorInfo.Sprint(f.SafePoC))
	}
	fmt.Printf("        • %-16s: %s\n", utils.ColorBold.Sprint("Evidence"), utils.ColorDim.Sprint(f.Evidence))
	fmt.Printf("        • %-16s: %s\n\n", utils.ColorBold.Sprint("Proof URL"), utils.ColorHighlight.Sprint(f.ProbeURL))
}
