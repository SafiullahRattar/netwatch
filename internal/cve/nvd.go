// Package cve implements CVE lookup against the NIST National Vulnerability Database API.
package cve

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/SafiullahRattar/netwatch/internal/models"
)

const (
	nvdAPIBaseURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	apiKeyEnvVar  = "NVD_API_KEY"
)

// Client queries the NVD API for CVE information.
type Client struct {
	httpClient *http.Client
	apiKey     string
	baseURL    string
}

// NewClient creates a new NVD API client. It checks the NVD_API_KEY environment
// variable for an optional API key (increases rate limits from 5 to 50 req/30s).
func NewClient() *Client {
	return &Client{
		httpClient: &http.Client{Timeout: 30 * time.Second},
		apiKey:     os.Getenv(apiKeyEnvVar),
		baseURL:    nvdAPIBaseURL,
	}
}

// NewClientWithKey creates a new NVD API client with an explicit API key.
func NewClientWithKey(apiKey string) *Client {
	return &Client{
		httpClient: &http.Client{Timeout: 30 * time.Second},
		apiKey:     apiKey,
		baseURL:    nvdAPIBaseURL,
	}
}

// nvdResponse represents the NVD API 2.0 response structure.
type nvdResponse struct {
	ResultsPerPage  int              `json:"resultsPerPage"`
	StartIndex      int              `json:"startIndex"`
	TotalResults    int              `json:"totalResults"`
	Vulnerabilities []nvdVulnerability `json:"vulnerabilities"`
}

type nvdVulnerability struct {
	CVE nvdCVE `json:"cve"`
}

type nvdCVE struct {
	ID           string         `json:"id"`
	Published    string         `json:"published"`
	Descriptions []nvdLangValue `json:"descriptions"`
	Metrics      nvdMetrics     `json:"metrics"`
	References   []nvdReference `json:"references"`
}

type nvdLangValue struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type nvdMetrics struct {
	CvssMetricV31 []nvdCVSSMetric `json:"cvssMetricV31"`
	CvssMetricV30 []nvdCVSSMetric `json:"cvssMetricV30"`
	CvssMetricV2  []nvdCVSSMetricV2 `json:"cvssMetricV2"`
}

type nvdCVSSMetric struct {
	CVSSData struct {
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity"`
	} `json:"cvssData"`
}

type nvdCVSSMetricV2 struct {
	CVSSData struct {
		BaseScore float64 `json:"baseScore"`
	} `json:"cvssData"`
	BaseSeverity string `json:"baseSeverity"`
}

type nvdReference struct {
	URL string `json:"url"`
}

// SearchByKeyword searches the NVD for CVEs matching the given keyword
// (typically a product name and version).
func (c *Client) SearchByKeyword(ctx context.Context, keyword string) ([]models.CVE, error) {
	params := url.Values{}
	params.Set("keywordSearch", keyword)
	params.Set("resultsPerPage", "10")

	return c.query(ctx, params)
}

// SearchByProduct searches the NVD for CVEs matching a specific product and version
// using the CPE match criteria.
func (c *Client) SearchByProduct(ctx context.Context, product, version string) ([]models.CVE, error) {
	keyword := product
	if version != "" {
		keyword = fmt.Sprintf("%s %s", product, version)
	}
	return c.SearchByKeyword(ctx, keyword)
}

// GetCVE retrieves a specific CVE by its ID (e.g., "CVE-2021-44228").
func (c *Client) GetCVE(ctx context.Context, cveID string) (*models.CVE, error) {
	params := url.Values{}
	params.Set("cveId", cveID)

	results, err := c.query(ctx, params)
	if err != nil {
		return nil, err
	}

	if len(results) == 0 {
		return nil, fmt.Errorf("CVE %s not found", cveID)
	}

	return &results[0], nil
}

// query performs an HTTP request to the NVD API and parses the response.
func (c *Client) query(ctx context.Context, params url.Values) ([]models.CVE, error) {
	reqURL := fmt.Sprintf("%s?%s", c.baseURL, params.Encode())

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	if c.apiKey != "" {
		req.Header.Set("apiKey", c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("NVD API request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("NVD API rate limit exceeded (status %d). Set NVD_API_KEY env var for higher limits", resp.StatusCode)
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("NVD API returned status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var nvdResp nvdResponse
	if err := json.Unmarshal(body, &nvdResp); err != nil {
		return nil, fmt.Errorf("failed to parse NVD response: %w", err)
	}

	return convertNVDResults(nvdResp), nil
}

// convertNVDResults converts NVD API response to our internal CVE model.
func convertNVDResults(resp nvdResponse) []models.CVE {
	var cves []models.CVE

	for _, vuln := range resp.Vulnerabilities {
		cve := models.CVE{
			ID:        vuln.CVE.ID,
			Published: vuln.CVE.Published,
		}

		// Extract English description
		for _, desc := range vuln.CVE.Descriptions {
			if desc.Lang == "en" {
				cve.Description = desc.Value
				break
			}
		}

		// Extract CVSS score (prefer v3.1 > v3.0 > v2)
		if len(vuln.CVE.Metrics.CvssMetricV31) > 0 {
			m := vuln.CVE.Metrics.CvssMetricV31[0]
			cve.CVSS = m.CVSSData.BaseScore
			cve.Severity = m.CVSSData.BaseSeverity
		} else if len(vuln.CVE.Metrics.CvssMetricV30) > 0 {
			m := vuln.CVE.Metrics.CvssMetricV30[0]
			cve.CVSS = m.CVSSData.BaseScore
			cve.Severity = m.CVSSData.BaseSeverity
		} else if len(vuln.CVE.Metrics.CvssMetricV2) > 0 {
			m := vuln.CVE.Metrics.CvssMetricV2[0]
			cve.CVSS = m.CVSSData.BaseScore
			cve.Severity = strings.ToUpper(m.BaseSeverity)
		}

		// Extract references
		for _, ref := range vuln.CVE.References {
			cve.References = append(cve.References, ref.URL)
		}

		cves = append(cves, cve)
	}

	return cves
}

// SeverityFromCVSS returns a models.Severity based on a CVSS score.
func SeverityFromCVSS(score float64) models.Severity {
	switch {
	case score >= 9.0:
		return models.SeverityCritical
	case score >= 7.0:
		return models.SeverityHigh
	case score >= 4.0:
		return models.SeverityMedium
	case score > 0:
		return models.SeverityLow
	default:
		return models.SeverityInfo
	}
}
