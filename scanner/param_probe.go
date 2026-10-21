package scanner

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// VerifiedParam represents a parameter that produced an observable behavioral change or reflection when probed.
type VerifiedParam struct {
	Param       string `json:"param"`
	Endpoint    string `json:"endpoint"`
	Method      string `json:"method"`                // "GET" or "POST"
	PostFormat  string `json:"post_format,omitempty"` // "form" or "json"
	Signal      string `json:"signal"`               // "reflection", "status_delta", "body_delta"
	Description string `json:"description"`          // Human-readable explanation of why this was verified
	ProbeURL    string `json:"probe_url"`
}

type endpointBaseline struct {
	Status   int
	Length   int
	Variance int
}

// ProbeEndpointTarget defines an endpoint and HTTP method configuration for active verification.
type ProbeEndpointTarget struct {
	URL        string
	Method     string // "GET" or "POST"
	PostFormat string // "form" (x-www-form-urlencoded) or "json" (application/json)
	Params     []string
}

// SelectDynamicEndpoints filters discovered links down to dynamic endpoints suitable for parameter probing.
func SelectDynamicEndpoints(links []string, baseU *url.URL) []string {
	seen := make(map[string]bool)
	var endpoints []string

	for _, l := range links {
		u, err := url.Parse(l)
		if err != nil {
			continue
		}

		// Keep only target host
		if !isSameTargetHost(u.Hostname(), baseU.Hostname()) {
			continue
		}

		cleanPath := strings.ToLower(u.Path)
		ext := filepath.Ext(cleanPath)
		if StaticFileExtensions[ext] {
			continue
		}

		// Strip query parameters to test the clean base endpoint
		uClean := *u
		uClean.RawQuery = ""
		uClean.Fragment = ""
		cleanURL := uClean.String()

		if !seen[cleanURL] {
			seen[cleanURL] = true
			endpoints = append(endpoints, cleanURL)
		}
	}

	// Prioritize endpoints with dynamic script extensions (.php, .jsp, .asp, etc.) or REST routes
	sort.Slice(endpoints, func(i, j int) bool {
		iExt := filepath.Ext(endpoints[i])
		jExt := filepath.Ext(endpoints[j])
		iIsDyn := iExt == ".php" || iExt == ".asp" || iExt == ".aspx" || iExt == ".jsp" || strings.Contains(endpoints[i], "/api/")
		jIsDyn := jExt == ".php" || jExt == ".asp" || jExt == ".aspx" || jExt == ".jsp" || strings.Contains(endpoints[j], "/api/")
		if iIsDyn && !jIsDyn {
			return true
		}
		if !iIsDyn && jIsDyn {
			return false
		}
		return endpoints[i] < endpoints[j]
	})

	// Cap at top 15 dynamic endpoints to keep verification fast and lightweight
	if len(endpoints) > 15 {
		endpoints = endpoints[:15]
	}

	return endpoints
}

// measureEndpointBaseline sends 2 unparameterized requests to compute the baseline status, length, and dynamic noise.
func measureEndpointBaseline(client *http.Client, endpoint, method, postFormat string) (*endpointBaseline, error) {
	createReq := func() (*http.Request, error) {
		ctx := context.Background()
		if method == "POST" {
			if postFormat == "json" {
				req, err := http.NewRequestWithContext(ctx, "POST", endpoint, strings.NewReader("{}"))
				if err != nil {
					return nil, err
				}
				req.Header.Set("Content-Type", "application/json")
				return req, nil
			}
			req, err := http.NewRequestWithContext(ctx, "POST", endpoint, strings.NewReader(""))
			if err != nil {
				return nil, err
			}
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			return req, nil
		}
		return http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	}

	req1, err := createReq()
	if err != nil {
		return nil, err
	}
	req1.Header.Set("User-Agent", "Webzoro-Recon/1.0")

	resp1, err := client.Do(req1)
	if err != nil {
		return nil, err
	}
	defer resp1.Body.Close()
	body1, _ := io.ReadAll(io.LimitReader(resp1.Body, 512*1024))

	req2, err := createReq()
	if err != nil {
		return &endpointBaseline{Status: resp1.StatusCode, Length: len(body1), Variance: 30}, nil
	}
	req2.Header.Set("User-Agent", "Webzoro-Recon/1.0")

	resp2, err := client.Do(req2)
	if err != nil {
		return &endpointBaseline{Status: resp1.StatusCode, Length: len(body1), Variance: 30}, nil
	}
	defer resp2.Body.Close()
	body2, _ := io.ReadAll(io.LimitReader(resp2.Body, 512*1024))

	variance := int(math.Abs(float64(len(body1) - len(body2))))
	if variance < 5 {
		variance = 5
	}

	return &endpointBaseline{
		Status:   resp1.StatusCode,
		Length:   len(body1),
		Variance: variance,
	}, nil
}

func measureBaselineSafe(client *http.Client, endpoint, method, postFormat string) (*endpointBaseline, error) {
	return measureEndpointBaseline(client, endpoint, method, postFormat)
}

// VerifyParameters actively tests inferred parameters against discovered endpoints using differential batching.
// Supports both GET query strings and POST form/JSON request bodies.
func VerifyParameters(t *Target, port int, baseURLStr string, assets ExtractedAssets) []VerifiedParam {
	baseU, err := url.Parse(baseURLStr)
	if err != nil {
		return nil
	}

	// 1. Build list of probe targets across GET and POST methods
	var probeTargets []ProbeEndpointTarget
	seenTargets := make(map[string]bool)

	// 1a. Dynamic GET endpoints (always includes base root endpoint)
	dynamicGET := SelectDynamicEndpoints(assets.Links, baseU)
	rootURL := baseURLStr
	if !strings.HasSuffix(rootURL, "/") {
		rootURL += "/"
	}
	hasRoot := false
	for _, ep := range dynamicGET {
		if ep == rootURL || ep == baseURLStr {
			hasRoot = true
			break
		}
	}
	if !hasRoot {
		dynamicGET = append([]string{rootURL}, dynamicGET...)
	}

	for _, ep := range dynamicGET {
		k := "GET|" + ep
		if !seenTargets[k] {
			seenTargets[k] = true
			probeTargets = append(probeTargets, ProbeEndpointTarget{
				URL:    ep,
				Method: "GET",
			})
		}
	}

	// 1b. Discovered HTML Forms (all forms: POST and GET)
	for _, f := range assets.FormSurfaces {
		method := strings.ToUpper(strings.TrimSpace(f.Method))
		if method == "" {
			method = "GET"
		}
		u, err := url.Parse(f.Action)
		if err == nil && isSameTargetHost(u.Hostname(), baseU.Hostname()) {
			postFormat := ""
			if method == "POST" {
				postFormat = "form"
			}
			k := fmt.Sprintf("%s|%s|%s", method, postFormat, f.Action)
			if !seenTargets[k] {
				seenTargets[k] = true
				probeTargets = append(probeTargets, ProbeEndpointTarget{
					URL:        f.Action,
					Method:     method,
					PostFormat: postFormat,
					Params:     f.Inputs,
				})
			} else {
				for idx := range probeTargets {
					if probeTargets[idx].URL == f.Action && probeTargets[idx].Method == method {
						probeTargets[idx].Params = deduplicateAndSort(append(probeTargets[idx].Params, f.Inputs...))
						break
					}
				}
			}
		}
	}

	// 1c. Discovered Auth Forms (fallback/hidden fields)
	for _, s := range assets.AuthSurfaces {
		method := strings.ToUpper(strings.TrimSpace(s.Method))
		if method == "" {
			method = "GET"
		}
		if s.URL != "" {
			u, err := url.Parse(s.URL)
			if err == nil && isSameTargetHost(u.Hostname(), baseU.Hostname()) {
				postFormat := ""
				if method == "POST" {
					postFormat = "form"
				}
				k := fmt.Sprintf("%s|%s|%s", method, postFormat, s.URL)
				if !seenTargets[k] {
					seenTargets[k] = true
					probeTargets = append(probeTargets, ProbeEndpointTarget{
						URL:        s.URL,
						Method:     method,
						PostFormat: postFormat,
						Params:     s.Inputs,
					})
				}
			}
		}
	}

	// 1d. Discovered API endpoints (POST application/json)
	for _, cand := range assets.IDORCandidates {
		method := strings.ToUpper(strings.TrimSpace(cand.Method))
		if method == "POST" || strings.Contains(cand.URL, "/api/") {
			u, err := url.Parse(cand.URL)
			if err == nil && isSameTargetHost(u.Hostname(), baseU.Hostname()) {
				k := "POST|json|" + cand.URL
				if !seenTargets[k] {
					seenTargets[k] = true
					probeTargets = append(probeTargets, ProbeEndpointTarget{
						URL:        cand.URL,
						Method:     "POST",
						PostFormat: "json",
						Params:     cand.CandidateParams,
					})
				}
			}
		}
	}

	// 2. Combine inferred parameters and observed parameters as verification candidates
	candidateMap := make(map[string]bool)
	for _, p := range assets.InferredParams {
		if isValidParam(p) {
			candidateMap[p] = true
		}
	}
	for _, p := range assets.Parameters {
		if isValidParam(p) {
			candidateMap[p] = true
		}
	}
	globalCandidates := setToSlice(candidateMap)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			DialContext: (&net.Dialer{
				Timeout: 4 * time.Second,
			}).DialContext,
			MaxIdleConns:        50,
			MaxIdleConnsPerHost: 20,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			if !isSameTargetHost(req.URL.Hostname(), baseU.Hostname()) {
				return http.ErrUseLastResponse
			}
			return nil
		},
		Timeout: 5 * time.Second,
	}

	var verifiedResults []VerifiedParam
	seenVerified := make(map[string]bool)

	addVerified := func(vp VerifiedParam) {
		k := fmt.Sprintf("%s|%s|%s", vp.Endpoint, vp.Method, vp.Param)
		if !seenVerified[k] {
			seenVerified[k] = true
			verifiedResults = append(verifiedResults, vp)
		}
	}

	batchSize := 15

	for _, target := range probeTargets {
		baseline, err := measureBaselineSafe(client, target.URL, target.Method, target.PostFormat)
		if err != nil || baseline.Status == 404 {
			continue // Skip offline or 404 dead endpoints
		}
		// Skip GET routes that hard error on baseline unparameterized request
		if target.Method == "GET" && baseline.Status >= 500 {
			continue
		}

		// Prioritize target-specific parameters (e.g. form fields) if present
		var targetCandidateList []string
		targetSeen := make(map[string]bool)

		// 1. Target-specific parameters (e.g. form inputs)
		for _, p := range target.Params {
			if isValidParam(p) && !targetSeen[p] {
				targetSeen[p] = true
				targetCandidateList = append(targetCandidateList, p)
			}
		}
		// 2. Discovered site parameters
		for _, p := range globalCandidates {
			if !targetSeen[p] {
				targetSeen[p] = true
				targetCandidateList = append(targetCandidateList, p)
			}
		}
		// 3. Fallback high-impact parameters
		for _, p := range DefaultHighImpactParams {
			if len(targetCandidateList) >= 40 {
				break
			}
			if !targetSeen[p] {
				targetSeen[p] = true
				targetCandidateList = append(targetCandidateList, p)
			}
		}

		// Probe candidates in batches
		for i := 0; i < len(targetCandidateList); i += batchSize {
			end := i + batchSize
			if end > len(targetCandidateList) {
				end = len(targetCandidateList)
			}
			batch := targetCandidateList[i:end]

			canaryMap := make(map[string]string)
			for _, p := range batch {
				canaryMap[p] = fmt.Sprintf("wz_%s", p)
			}

			// Build request depending on GET, POST form, or POST JSON
			var req *http.Request
			var probeDesc string
			ctx := context.Background()

			if target.Method == "POST" {
				if target.PostFormat == "json" {
					jsonData, _ := json.Marshal(canaryMap)
					req, err = http.NewRequestWithContext(ctx, "POST", target.URL, bytes.NewReader(jsonData))
					if err != nil {
						continue
					}
					req.Header.Set("Content-Type", "application/json")
					probeDesc = fmt.Sprintf("[POST JSON] %s", target.URL)
				} else {
					formVals := url.Values{}
					for p, val := range canaryMap {
						formVals.Set(p, val)
					}
					req, err = http.NewRequestWithContext(ctx, "POST", target.URL, strings.NewReader(formVals.Encode()))
					if err != nil {
						continue
					}
					req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
					probeDesc = fmt.Sprintf("[POST FORM] %s", target.URL)
				}
			} else {
				u, err := url.Parse(target.URL)
				if err != nil {
					continue
				}
				q := u.Query()
				for p, val := range canaryMap {
					q.Set(p, val)
				}
				u.RawQuery = q.Encode()
				req, err = http.NewRequestWithContext(ctx, "GET", u.String(), nil)
				if err != nil {
					continue
				}
				probeDesc = u.String()
			}

			req.Header.Set("User-Agent", "Webzoro-Recon/1.0")
			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
			resp.Body.Close()

			bodyStr := string(body)

			// 1. Reflection Check (Instant confirmation)
			for p, canaryVal := range canaryMap {
				if strings.Contains(bodyStr, canaryVal) {
					paramProbeURL := probeDesc
					if target.Method == "GET" {
						paramProbeURL = fmt.Sprintf("%s?%s=%s", target.URL, p, canaryVal)
					} else {
						paramProbeURL = fmt.Sprintf("%s (%s=%s)", probeDesc, p, canaryVal)
					}
					addVerified(VerifiedParam{
						Param:       p,
						Endpoint:    target.URL,
						Method:      target.Method,
						PostFormat:  target.PostFormat,
						Signal:      "reflection",
						Description: fmt.Sprintf("Canary value reflected in %s response body", target.Method),
						ProbeURL:    paramProbeURL,
					})
				}
			}

			// 2. Behavioral Delta (Status code shift or significant body length delta)
			statusDelta := resp.StatusCode != baseline.Status
			threshold := baseline.Variance*2 + 35
			if threshold < 35 {
				threshold = 35
			}
			lengthDelta := int(math.Abs(float64(len(body)-baseline.Length))) > threshold

			// If batch triggered a status or length delta, isolate individual parameters in the batch.
			// (Even if reflections occurred, remaining unreflected parameters in the batch should be isolated)
			if statusDelta || lengthDelta {
				for _, p := range batch {
					paramKey := fmt.Sprintf("%s|%s|%s", target.URL, target.Method, p)
					if seenVerified[paramKey] {
						continue // already confirmed via reflection
					}

					singleCanary := fmt.Sprintf("wz_%s", p)
					var sReq *http.Request
					var singleProbeURL string

					if target.Method == "POST" {
						if target.PostFormat == "json" {
							jsonData, _ := json.Marshal(map[string]string{p: singleCanary})
							sReq, err = http.NewRequestWithContext(ctx, "POST", target.URL, bytes.NewReader(jsonData))
							if err != nil {
								continue
							}
							sReq.Header.Set("Content-Type", "application/json")
							singleProbeURL = fmt.Sprintf("[POST JSON] %s (%s=%s)", target.URL, p, singleCanary)
						} else {
							vals := url.Values{p: []string{singleCanary}}
							sReq, err = http.NewRequestWithContext(ctx, "POST", target.URL, strings.NewReader(vals.Encode()))
							if err != nil {
								continue
							}
							sReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
							singleProbeURL = fmt.Sprintf("[POST FORM] %s (%s=%s)", target.URL, p, singleCanary)
						}
					} else {
						singleU, _ := url.Parse(target.URL)
						sq := singleU.Query()
						sq.Set(p, singleCanary)
						singleU.RawQuery = sq.Encode()
						sReq, err = http.NewRequestWithContext(ctx, "GET", singleU.String(), nil)
						if err != nil {
							continue
						}
						singleProbeURL = singleU.String()
					}

					sReq.Header.Set("User-Agent", "Webzoro-Recon/1.0")
					sResp, err := client.Do(sReq)
					if err != nil {
						continue
					}
					sBody, _ := io.ReadAll(io.LimitReader(sResp.Body, 512*1024))
					sResp.Body.Close()

					// Check reflection on single
					if strings.Contains(string(sBody), singleCanary) {
						addVerified(VerifiedParam{
							Param:       p,
							Endpoint:    target.URL,
							Method:      target.Method,
							PostFormat:  target.PostFormat,
							Signal:      "reflection",
							Description: fmt.Sprintf("Canary value reflected in %s response body", target.Method),
							ProbeURL:    singleProbeURL,
						})
						continue
					}

					// Check status delta on single
					if sResp.StatusCode != baseline.Status {
						addVerified(VerifiedParam{
							Param:       p,
							Endpoint:    target.URL,
							Method:      target.Method,
							PostFormat:  target.PostFormat,
							Signal:      "status_delta",
							Description: fmt.Sprintf("Status code shifted: %d -> %d (%s)", baseline.Status, sResp.StatusCode, target.Method),
							ProbeURL:    singleProbeURL,
						})
						continue
					}

					// Check length delta on single
					deltaBytes := len(sBody) - baseline.Length
					if int(math.Abs(float64(deltaBytes))) > threshold {
						addVerified(VerifiedParam{
							Param:       p,
							Endpoint:    target.URL,
							Method:      target.Method,
							PostFormat:  target.PostFormat,
							Signal:      "body_delta",
							Description: fmt.Sprintf("Response size delta: %+d bytes (%s)", deltaBytes, target.Method),
							ProbeURL:    singleProbeURL,
						})
					}
				}
			}
		}

		// 3. For declared HTML form parameters (target.Params), verify any unconfirmed inputs
		for _, p := range target.Params {
			paramKey := fmt.Sprintf("%s|%s|%s", target.URL, target.Method, p)
			if seenVerified[paramKey] {
				continue
			}

			singleCanary := fmt.Sprintf("wz_%s", p)
			var sReq *http.Request
			var singleProbeURL string
			ctx := context.Background()

			if target.Method == "POST" {
				if target.PostFormat == "json" {
					jsonData, _ := json.Marshal(map[string]string{p: singleCanary})
					sReq, err = http.NewRequestWithContext(ctx, "POST", target.URL, bytes.NewReader(jsonData))
					if err != nil {
						continue
					}
					sReq.Header.Set("Content-Type", "application/json")
					singleProbeURL = fmt.Sprintf("[POST JSON] %s (%s=%s)", target.URL, p, singleCanary)
				} else {
					vals := url.Values{p: []string{singleCanary}}
					sReq, err = http.NewRequestWithContext(ctx, "POST", target.URL, strings.NewReader(vals.Encode()))
					if err != nil {
						continue
					}
					sReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
					singleProbeURL = fmt.Sprintf("[POST FORM] %s (%s=%s)", target.URL, p, singleCanary)
				}
			} else {
				singleU, _ := url.Parse(target.URL)
				sq := singleU.Query()
				sq.Set(p, singleCanary)
				singleU.RawQuery = sq.Encode()
				sReq, err = http.NewRequestWithContext(ctx, "GET", singleU.String(), nil)
				if err != nil {
					continue
				}
				singleProbeURL = singleU.String()
			}

			sReq.Header.Set("User-Agent", "Webzoro-Recon/1.0")
			sResp, err := client.Do(sReq)
			if err != nil {
				continue
			}
			sBody, _ := io.ReadAll(io.LimitReader(sResp.Body, 512*1024))
			sResp.Body.Close()

			threshold := baseline.Variance*2 + 35
			if threshold < 35 {
				threshold = 35
			}

			if strings.Contains(string(sBody), singleCanary) {
				addVerified(VerifiedParam{
					Param:       p,
					Endpoint:    target.URL,
					Method:      target.Method,
					PostFormat:  target.PostFormat,
					Signal:      "reflection",
					Description: fmt.Sprintf("Canary value reflected in %s response body", target.Method),
					ProbeURL:    singleProbeURL,
				})
			} else if sResp.StatusCode != baseline.Status {
				addVerified(VerifiedParam{
					Param:       p,
					Endpoint:    target.URL,
					Method:      target.Method,
					PostFormat:  target.PostFormat,
					Signal:      "status_delta",
					Description: fmt.Sprintf("Status code shifted: %d -> %d (%s)", baseline.Status, sResp.StatusCode, target.Method),
					ProbeURL:    singleProbeURL,
				})
			} else if int(math.Abs(float64(len(sBody)-baseline.Length))) > threshold {
				deltaBytes := len(sBody) - baseline.Length
				addVerified(VerifiedParam{
					Param:       p,
					Endpoint:    target.URL,
					Method:      target.Method,
					PostFormat:  target.PostFormat,
					Signal:      "body_delta",
					Description: fmt.Sprintf("Response size delta: %+d bytes (%s)", deltaBytes, target.Method),
					ProbeURL:    singleProbeURL,
				})
			} else if sResp.StatusCode < 400 {
				addVerified(VerifiedParam{
					Param:       p,
					Endpoint:    target.URL,
					Method:      target.Method,
					PostFormat:  target.PostFormat,
					Signal:      "form_input",
					Description: fmt.Sprintf("Confirmed functional HTML form input (%s)", target.Method),
					ProbeURL:    singleProbeURL,
				})
			}
		}
	}

	// Persist verified parameters to target directory
	verifiedJSONFile := filepath.Join(t.OutDir(), "params_verified.json")
	verifiedTxtFile := filepath.Join(t.OutDir(), "params_verified.txt")

	if len(verifiedResults) > 0 {
		if data, err := json.MarshalIndent(verifiedResults, "", "  "); err == nil {
			_ = os.WriteFile(verifiedJSONFile, data, 0644)
		}
		var lines []string
		for _, v := range verifiedResults {
			method := v.Method
			if method == "" {
				method = "GET"
			}
			if method == "POST" {
				format := v.PostFormat
				if format == "" {
					format = "form"
				}
				lines = append(lines, fmt.Sprintf("[POST %s] %s (%s=FUZZ)", strings.ToUpper(format), v.Endpoint, v.Param))
			} else {
				lines = append(lines, fmt.Sprintf("%s?%s=FUZZ", v.Endpoint, v.Param))
			}
		}
		_ = os.WriteFile(verifiedTxtFile, []byte(strings.Join(deduplicateAndSort(lines), "\n")+"\n"), 0644)
	}

	return verifiedResults
}
