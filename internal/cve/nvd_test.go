package cve

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/SafiullahRattar/netwatch/internal/models"
)

func TestSeverityFromCVSS(t *testing.T) {
	tests := []struct {
		score    float64
		expected models.Severity
	}{
		{10.0, models.SeverityCritical},
		{9.0, models.SeverityCritical},
		{8.5, models.SeverityHigh},
		{7.0, models.SeverityHigh},
		{6.5, models.SeverityMedium},
		{4.0, models.SeverityMedium},
		{3.5, models.SeverityLow},
		{0.1, models.SeverityLow},
		{0.0, models.SeverityInfo},
	}

	for _, tt := range tests {
		result := SeverityFromCVSS(tt.score)
		if result != tt.expected {
			t.Errorf("SeverityFromCVSS(%.1f) = %v, want %v", tt.score, result, tt.expected)
		}
	}
}

func TestConvertNVDResults(t *testing.T) {
	resp := nvdResponse{
		TotalResults: 1,
		Vulnerabilities: []nvdVulnerability{
			{
				CVE: nvdCVE{
					ID:        "CVE-2021-44228",
					Published: "2021-12-10T10:15Z",
					Descriptions: []nvdLangValue{
						{Lang: "en", Value: "Apache Log4j2 RCE vulnerability"},
					},
					Metrics: nvdMetrics{
						CvssMetricV31: []nvdCVSSMetric{
							{
								CVSSData: struct {
									BaseScore    float64 `json:"baseScore"`
									BaseSeverity string  `json:"baseSeverity"`
								}{
									BaseScore:    10.0,
									BaseSeverity: "CRITICAL",
								},
							},
						},
					},
					References: []nvdReference{
						{URL: "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"},
					},
				},
			},
		},
	}

	cves := convertNVDResults(resp)
	if len(cves) != 1 {
		t.Fatalf("expected 1 CVE, got %d", len(cves))
	}

	cve := cves[0]
	if cve.ID != "CVE-2021-44228" {
		t.Errorf("expected ID CVE-2021-44228, got %s", cve.ID)
	}
	if cve.CVSS != 10.0 {
		t.Errorf("expected CVSS 10.0, got %.1f", cve.CVSS)
	}
	if cve.Severity != "CRITICAL" {
		t.Errorf("expected severity CRITICAL, got %s", cve.Severity)
	}
	if cve.Description != "Apache Log4j2 RCE vulnerability" {
		t.Errorf("unexpected description: %s", cve.Description)
	}
	if len(cve.References) != 1 {
		t.Errorf("expected 1 reference, got %d", len(cve.References))
	}
}

func TestSearchByKeyword_MockServer(t *testing.T) {
	mockResp := nvdResponse{
		TotalResults: 1,
		Vulnerabilities: []nvdVulnerability{
			{
				CVE: nvdCVE{
					ID:        "CVE-2023-12345",
					Published: "2023-01-01T00:00Z",
					Descriptions: []nvdLangValue{
						{Lang: "en", Value: "Test vulnerability"},
					},
					Metrics: nvdMetrics{
						CvssMetricV31: []nvdCVSSMetric{
							{
								CVSSData: struct {
									BaseScore    float64 `json:"baseScore"`
									BaseSeverity string  `json:"baseSeverity"`
								}{
									BaseScore:    7.5,
									BaseSeverity: "HIGH",
								},
							},
						},
					},
				},
			},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request parameters
		if r.URL.Query().Get("keywordSearch") == "" {
			t.Error("expected keywordSearch parameter")
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(mockResp)
	}))
	defer server.Close()

	client := &Client{
		httpClient: server.Client(),
		baseURL:    server.URL,
	}

	cves, err := client.SearchByKeyword(context.Background(), "openssl 3.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(cves) != 1 {
		t.Fatalf("expected 1 CVE, got %d", len(cves))
	}

	if cves[0].ID != "CVE-2023-12345" {
		t.Errorf("expected CVE-2023-12345, got %s", cves[0].ID)
	}
}

func TestSearchByKeyword_RateLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()

	client := &Client{
		httpClient: server.Client(),
		baseURL:    server.URL,
	}

	_, err := client.SearchByKeyword(context.Background(), "test")
	if err == nil {
		t.Fatal("expected error for rate limit response")
	}
}

func TestSearchByKeyword_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal error"))
	}))
	defer server.Close()

	client := &Client{
		httpClient: server.Client(),
		baseURL:    server.URL,
	}

	_, err := client.SearchByKeyword(context.Background(), "test")
	if err == nil {
		t.Fatal("expected error for server error response")
	}
}

func TestNewClient(t *testing.T) {
	client := NewClient()
	if client == nil {
		t.Fatal("NewClient returned nil")
	}
	if client.baseURL != nvdAPIBaseURL {
		t.Errorf("expected base URL %s, got %s", nvdAPIBaseURL, client.baseURL)
	}
}

func TestNewClientWithKey(t *testing.T) {
	client := NewClientWithKey("test-key")
	if client.apiKey != "test-key" {
		t.Errorf("expected API key test-key, got %s", client.apiKey)
	}
}

func TestGetCVE_NotFound(t *testing.T) {
	mockResp := nvdResponse{
		TotalResults:    0,
		Vulnerabilities: []nvdVulnerability{},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(mockResp)
	}))
	defer server.Close()

	client := &Client{
		httpClient: server.Client(),
		baseURL:    server.URL,
	}

	_, err := client.GetCVE(context.Background(), "CVE-0000-00000")
	if err == nil {
		t.Fatal("expected error for missing CVE")
	}
}

func TestSearchByProduct(t *testing.T) {
	mockResp := nvdResponse{
		TotalResults:    0,
		Vulnerabilities: []nvdVulnerability{},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		keyword := r.URL.Query().Get("keywordSearch")
		if keyword != "nginx 1.18" {
			t.Errorf("expected keyword 'nginx 1.18', got %q", keyword)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(mockResp)
	}))
	defer server.Close()

	client := &Client{
		httpClient: server.Client(),
		baseURL:    server.URL,
	}

	_, err := client.SearchByProduct(context.Background(), "nginx", "1.18")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
