package test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/SafiullahRattar/netwatch/internal/headers"
	"github.com/SafiullahRattar/netwatch/internal/models"
	"github.com/SafiullahRattar/netwatch/internal/report"
	"github.com/SafiullahRattar/netwatch/internal/scanner"
)

// TestFullScanWorkflow tests the complete scan-to-report pipeline.
func TestFullScanWorkflow(t *testing.T) {
	// Start a mock HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "TestServer/1.0")
		w.Header().Set("X-Frame-Options", "DENY")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "OK")
	}))
	defer server.Close()

	// Extract port from server URL
	_, portStr, _ := net.SplitHostPort(server.Listener.Addr().String())
	port, _ := strconv.Atoi(portStr)

	ctx := context.Background()

	// Phase 1: Port scan
	ps := scanner.NewPortScanner(2*time.Second, 4, 0)
	ports := []int{port, 59998, 59999}
	results, err := ps.Scan(ctx, "127.0.0.1", ports, nil)
	if err != nil {
		t.Fatalf("port scan failed: %v", err)
	}

	openCount := 0
	for _, r := range results {
		if r.State == models.PortOpen {
			openCount++
		}
	}
	if openCount < 1 {
		t.Fatalf("expected at least 1 open port, found %d", openCount)
	}

	// Phase 2: Service detection
	sd := scanner.NewServiceDetector(2 * time.Second)
	serviceResult := sd.DetectService(ctx, "127.0.0.1", port)
	if serviceResult.State != models.PortOpen {
		t.Fatal("expected service detection to find open port")
	}

	// Phase 3: HTTP header check
	checker := headers.NewChecker(5 * time.Second)
	headerResult, err := checker.Check(ctx, server.URL)
	if err != nil {
		t.Fatalf("header check failed: %v", err)
	}
	if headerResult.Score == 100 {
		t.Error("expected some missing headers from basic test server")
	}

	// Phase 4: Build report
	scanReport := &models.ScanReport{
		ID:        "test-001",
		StartTime: time.Now(),
		EndTime:   time.Now(),
		Duration:  "1s",
		Target:    "127.0.0.1",
		Ports:     results,
		Headers:   headerResult,
	}
	scanReport.Summary = report.ComputeSummary(scanReport)

	// Phase 5: JSON output
	var buf bytes.Buffer
	err = report.WriteJSON(&buf, scanReport)
	if err != nil {
		t.Fatalf("JSON report generation failed: %v", err)
	}

	// Verify JSON is valid
	var parsed models.ScanReport
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("generated JSON is invalid: %v", err)
	}
	if parsed.Target != "127.0.0.1" {
		t.Errorf("expected target 127.0.0.1, got %s", parsed.Target)
	}

	// Phase 6: HTML output
	var htmlBuf bytes.Buffer
	err = report.WriteHTML(&htmlBuf, scanReport)
	if err != nil {
		t.Fatalf("HTML report generation failed: %v", err)
	}
	if htmlBuf.Len() == 0 {
		t.Fatal("HTML report is empty")
	}

	t.Logf("Integration test passed: scanned %d ports, %d open, %d findings, JSON=%d bytes, HTML=%d bytes",
		len(results), openCount, scanReport.Summary.TotalFindings, buf.Len(), htmlBuf.Len())
}

// TestJSONReportRoundTrip tests saving and loading a JSON report.
func TestJSONReportRoundTrip(t *testing.T) {
	scanReport := &models.ScanReport{
		ID:        "roundtrip-test",
		StartTime: time.Now(),
		EndTime:   time.Now(),
		Duration:  "500ms",
		Target:    "192.168.1.1",
		Ports: []models.PortResult{
			{Port: 80, State: models.PortOpen, Service: "http"},
			{Port: 443, State: models.PortOpen, Service: "https"},
			{Port: 22, State: models.PortClosed},
		},
		Findings: []models.Finding{
			{
				Title:       "Test Finding",
				Description: "A test finding for the round-trip test",
				Severity:    models.SeverityMedium,
			},
		},
	}
	scanReport.Summary = report.ComputeSummary(scanReport)

	tmpFile := t.TempDir() + "/test-report.json"

	// Save
	err := report.SaveJSON(tmpFile, scanReport)
	if err != nil {
		t.Fatalf("SaveJSON failed: %v", err)
	}

	// Load
	loaded, err := report.LoadJSON(tmpFile)
	if err != nil {
		t.Fatalf("LoadJSON failed: %v", err)
	}

	if loaded.ID != scanReport.ID {
		t.Errorf("ID mismatch: got %s, want %s", loaded.ID, scanReport.ID)
	}
	if loaded.Target != scanReport.Target {
		t.Errorf("Target mismatch: got %s, want %s", loaded.Target, scanReport.Target)
	}
	if loaded.Summary.OpenPorts != 2 {
		t.Errorf("expected 2 open ports in summary, got %d", loaded.Summary.OpenPorts)
	}
}

// TestHTMLReportGeneration tests that an HTML report can be generated and saved.
func TestHTMLReportGeneration(t *testing.T) {
	scanReport := &models.ScanReport{
		ID:        "html-test",
		StartTime: time.Now(),
		EndTime:   time.Now(),
		Duration:  "1s",
		Target:    "example.com",
		Ports: []models.PortResult{
			{Port: 443, State: models.PortOpen, Service: "https", Version: "nginx/1.20"},
		},
		TLS: &models.TLSInfo{
			Host:            "example.com",
			Port:            443,
			Version:         "TLS 1.3",
			CipherSuite:     "TLS_AES_256_GCM_SHA384",
			CertSubject:     "CN=example.com",
			CertIssuer:      "CN=Let's Encrypt",
			CertExpiry:      time.Now().Add(90 * 24 * time.Hour),
			DaysUntilExpiry: 90,
		},
		Findings: []models.Finding{
			{Title: "Test Critical", Severity: models.SeverityCritical},
			{Title: "Test High", Severity: models.SeverityHigh},
			{Title: "Test Medium", Severity: models.SeverityMedium},
		},
	}
	scanReport.Summary = report.ComputeSummary(scanReport)

	tmpFile := t.TempDir() + "/test-report.html"
	err := report.SaveHTML(tmpFile, scanReport)
	if err != nil {
		t.Fatalf("SaveHTML failed: %v", err)
	}

	// Verify file exists and has content
	info, err := os.Stat(tmpFile)
	if err != nil {
		t.Fatalf("HTML file not found: %v", err)
	}
	if info.Size() == 0 {
		t.Fatal("HTML file is empty")
	}

	t.Logf("Generated HTML report: %d bytes", info.Size())
}
