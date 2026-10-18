package scanner

import (
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
	Signal      string `json:"signal"`      // "reflection", "status_delta", "body_delta"
	Description string `json:"description"` // Human-readable explanation of why this was verified
	ProbeURL    string `json:"probe_url"`
}

type endpointBaseline struct {
	Status   int
	Length   int
	Variance int
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
func measureEndpointBaseline(client *http.Client, endpoint string) (*endpointBaseline, error) {
	req1, err := http.NewRequestWithContext(context.Background(), "GET", endpoint, nil)
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

	// Second request to calculate normal response variance (e.g. timestamps, CSRF tokens)
	req2, err := http.NewRequestWithContext(context.Background(), "GET", endpoint, nil)
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
	if variance < 25 {
		variance = 25
	}

	return &endpointBaseline{
		Status:   resp1.StatusCode,
		Length:   len(body1),
		Variance: variance,
	}, nil
}

// VerifyParameters actively tests inferred parameters against discovered endpoints using differential batching.
func VerifyParameters(t *Target, port int, baseURLStr string, assets ExtractedAssets) []VerifiedParam {
	baseU, err := url.Parse(baseURLStr)
	if err != nil {
		return nil
	}

	endpoints := SelectDynamicEndpoints(assets.Links, baseU)
	if len(endpoints) == 0 {
		endpoints = []string{baseURLStr + "/"}
	}

	// Combine inferred parameters and observed parameters as verification candidates
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
	candidates := setToSlice(candidateMap)
	if len(candidates) == 0 {
		return nil
	}

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

	var verifiedResults []VerifiedParam
	seenVerified := make(map[string]bool)

	addVerified := func(vp VerifiedParam) {
		k := fmt.Sprintf("%s|%s", vp.Endpoint, vp.Param)
		if !seenVerified[k] {
			seenVerified[k] = true
			verifiedResults = append(verifiedResults, vp)
		}
	}

	batchSize := 15

	for _, endpoint := range endpoints {
		baseline, err := measureBaselineSafe(client, endpoint)
		if err != nil || baseline.Status >= 500 || baseline.Status == 404 {
			continue // Skip offline or dead endpoints
		}

		// Probe candidates in batches
		for i := 0; i < len(candidates); i += batchSize {
			end := i + batchSize
			if end > len(candidates) {
				end = len(candidates)
			}
			batch := candidates[i:end]

			u, err := url.Parse(endpoint)
			if err != nil {
				continue
			}

			q := u.Query()
			canaryMap := make(map[string]string)
			for _, p := range batch {
				canaryVal := fmt.Sprintf("wz_%s", p)
				canaryMap[p] = canaryVal
				q.Set(p, canaryVal)
			}
			u.RawQuery = q.Encode()

			req, err := http.NewRequestWithContext(context.Background(), "GET", u.String(), nil)
			if err != nil {
				continue
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
			foundReflection := false
			for p, canaryVal := range canaryMap {
				if strings.Contains(bodyStr, canaryVal) {
					foundReflection = true
					addVerified(VerifiedParam{
						Param:       p,
						Endpoint:    endpoint,
						Signal:      "reflection",
						Description: "Canary value reflected in response body",
						ProbeURL:    fmt.Sprintf("%s?%s=%s", endpoint, p, canaryVal),
					})
				}
			}

			// 2. Behavioral Delta (Status code shift or significant body length delta)
			statusDelta := resp.StatusCode != baseline.Status
			lengthDelta := int(math.Abs(float64(len(body)-baseline.Length))) > (baseline.Variance*3 + 60)

			// If batch triggered a status or length delta (and wasn't already fully explained by reflections),
			// isolate individual parameters in the batch.
			if (statusDelta || lengthDelta) && !foundReflection {
				for _, p := range batch {
					singleU, _ := url.Parse(endpoint)
					sq := singleU.Query()
					singleCanary := fmt.Sprintf("wz_%s", p)
					sq.Set(p, singleCanary)
					singleU.RawQuery = sq.Encode()

					sReq, err := http.NewRequestWithContext(context.Background(), "GET", singleU.String(), nil)
					if err != nil {
						continue
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
							Endpoint:    endpoint,
							Signal:      "reflection",
							Description: "Canary value reflected in response body",
							ProbeURL:    singleU.String(),
						})
						continue
					}

					// Check status delta on single
					if sResp.StatusCode != baseline.Status {
						addVerified(VerifiedParam{
							Param:       p,
							Endpoint:    endpoint,
							Signal:      "status_delta",
							Description: fmt.Sprintf("Status code shifted: %d -> %d", baseline.Status, sResp.StatusCode),
							ProbeURL:    singleU.String(),
						})
						continue
					}

					// Check length delta on single
					deltaBytes := len(sBody) - baseline.Length
					if int(math.Abs(float64(deltaBytes))) > (baseline.Variance*3 + 50) {
						addVerified(VerifiedParam{
							Param:       p,
							Endpoint:    endpoint,
							Signal:      "body_delta",
							Description: fmt.Sprintf("Response size delta: %+d bytes", deltaBytes),
							ProbeURL:    singleU.String(),
						})
					}
				}
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
			lines = append(lines, fmt.Sprintf("%s?%s=FUZZ", v.Endpoint, v.Param))
		}
		_ = os.WriteFile(verifiedTxtFile, []byte(strings.Join(deduplicateAndSort(lines), "\n")+"\n"), 0644)
	}

	return verifiedResults
}

func measureBaselineSafe(client *http.Client, endpoint string) (*endpointBaseline, error) {
	return measureEndpointBaseline(client, endpoint)
}
