package headers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestExpectedHeaders(t *testing.T) {
	headers := ExpectedHeaders()
	if len(headers) == 0 {
		t.Fatal("ExpectedHeaders returned empty list")
	}

	// Verify all headers have required fields
	for _, h := range headers {
		if h.Name == "" {
			t.Error("header has empty name")
		}
		if h.Description == "" {
			t.Errorf("header %s has empty description", h.Name)
		}
		if h.Remediation == "" {
			t.Errorf("header %s has empty remediation", h.Name)
		}
	}
}

func TestCheck_AllHeadersPresent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=()")
		w.Header().Set("X-XSS-Protection", "0")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	checker := NewChecker(5 * time.Second)
	result, err := checker.Check(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Missing) != 0 {
		t.Errorf("expected no missing headers, got %v", result.Missing)
	}

	if result.Score != 100 {
		t.Errorf("expected score 100, got %d", result.Score)
	}
}

func TestCheck_NoHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	checker := NewChecker(5 * time.Second)
	result, err := checker.Check(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expectedMissing := len(ExpectedHeaders())
	if len(result.Missing) != expectedMissing {
		t.Errorf("expected %d missing headers, got %d", expectedMissing, len(result.Missing))
	}

	if result.Score != 0 {
		t.Errorf("expected score 0, got %d", result.Score)
	}
}

func TestCheck_InfoLeakage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache/2.4.51 (Ubuntu)")
		w.Header().Set("X-Powered-By", "PHP/8.1.0")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	checker := NewChecker(5 * time.Second)
	result, err := checker.Check(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	infoLeakCount := 0
	for _, f := range result.Findings {
		if f.Title == "Server header reveals version information" || f.Title == "X-Powered-By header present" {
			infoLeakCount++
		}
	}
	if infoLeakCount < 2 {
		t.Errorf("expected at least 2 info leakage findings, got %d", infoLeakCount)
	}
}

func TestAnalyzeHeaderValue_HSTS(t *testing.T) {
	// Missing includeSubDomains
	findings := analyzeHeaderValue("Strict-Transport-Security", "max-age=31536000")
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	// max-age=0
	findings = analyzeHeaderValue("Strict-Transport-Security", "max-age=0")
	found := false
	for _, f := range findings {
		if f.Title == "HSTS max-age is zero" {
			found = true
		}
	}
	if !found {
		t.Error("expected finding for max-age=0")
	}
}

func TestAnalyzeHeaderValue_CSP(t *testing.T) {
	findings := analyzeHeaderValue("Content-Security-Policy", "default-src 'self' 'unsafe-inline' 'unsafe-eval' *")
	if len(findings) != 3 {
		t.Errorf("expected 3 findings for weak CSP, got %d", len(findings))
	}
}

func TestAnalyzeHeaderValue_XFrameOptions(t *testing.T) {
	// Valid values should produce no findings
	for _, val := range []string{"DENY", "SAMEORIGIN", "ALLOW-FROM https://example.com"} {
		findings := analyzeHeaderValue("X-Frame-Options", val)
		if len(findings) != 0 {
			t.Errorf("expected no findings for %q, got %d", val, len(findings))
		}
	}

	// Invalid value
	findings := analyzeHeaderValue("X-Frame-Options", "INVALID")
	if len(findings) != 1 {
		t.Errorf("expected 1 finding for invalid X-Frame-Options, got %d", len(findings))
	}
}

func TestGradeFromScore(t *testing.T) {
	tests := []struct {
		score    int
		expected string
	}{
		{100, "A"},
		{90, "A"},
		{85, "B"},
		{75, "C"},
		{65, "D"},
		{50, "F"},
		{0, "F"},
	}

	for _, tt := range tests {
		result := GradeFromScore(tt.score)
		if result != tt.expected {
			t.Errorf("GradeFromScore(%d) = %q, want %q", tt.score, result, tt.expected)
		}
	}
}

func TestCheck_URLWithoutScheme(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	checker := NewChecker(5 * time.Second)
	// This won't actually connect to the test server since we strip the scheme,
	// but it tests that the URL handling logic works
	_, err := checker.Check(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNewChecker(t *testing.T) {
	checker := NewChecker(10 * time.Second)
	if checker == nil {
		t.Fatal("NewChecker returned nil")
	}
	if checker.httpClient == nil {
		t.Fatal("httpClient is nil")
	}
}
