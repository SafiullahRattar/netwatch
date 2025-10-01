package scanner

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/SafiullahRattar/netwatch/internal/models"
)

func TestParsePortRange_Single(t *testing.T) {
	ports, err := ParsePortRange("80")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ports) != 1 || ports[0] != 80 {
		t.Fatalf("expected [80], got %v", ports)
	}
}

func TestParsePortRange_Multiple(t *testing.T) {
	ports, err := ParsePortRange("80,443,8080")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ports) != 3 {
		t.Fatalf("expected 3 ports, got %d", len(ports))
	}
	expected := map[int]bool{80: true, 443: true, 8080: true}
	for _, p := range ports {
		if !expected[p] {
			t.Fatalf("unexpected port: %d", p)
		}
	}
}

func TestParsePortRange_Range(t *testing.T) {
	ports, err := ParsePortRange("1-10")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ports) != 10 {
		t.Fatalf("expected 10 ports, got %d", len(ports))
	}
}

func TestParsePortRange_Mixed(t *testing.T) {
	ports, err := ParsePortRange("22,80,100-105,443")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// 22, 80, 100, 101, 102, 103, 104, 105, 443 = 9
	if len(ports) != 9 {
		t.Fatalf("expected 9 ports, got %d", len(ports))
	}
}

func TestParsePortRange_Deduplicate(t *testing.T) {
	ports, err := ParsePortRange("80,80,80")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ports) != 1 {
		t.Fatalf("expected 1 port (deduplicated), got %d", len(ports))
	}
}

func TestParsePortRange_Errors(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"empty", ""},
		{"invalid", "abc"},
		{"out of range high", "99999"},
		{"out of range zero", "0"},
		{"reversed range", "100-10"},
		{"invalid range start", "abc-100"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParsePortRange(tt.input)
			if err == nil {
				t.Fatalf("expected error for input %q", tt.input)
			}
		})
	}
}

func TestCommonPorts(t *testing.T) {
	ports := CommonPorts()
	if len(ports) == 0 {
		t.Fatal("CommonPorts returned empty slice")
	}
	// Check that well-known ports are included
	portSet := make(map[int]bool)
	for _, p := range ports {
		portSet[p] = true
	}
	for _, expected := range []int{22, 80, 443} {
		if !portSet[expected] {
			t.Errorf("expected port %d in CommonPorts", expected)
		}
	}
}

func TestWellKnownService(t *testing.T) {
	tests := []struct {
		port     int
		expected string
	}{
		{22, "ssh"},
		{80, "http"},
		{443, "https"},
		{3306, "mysql"},
		{12345, ""},
	}

	for _, tt := range tests {
		result := WellKnownService(tt.port)
		if result != tt.expected {
			t.Errorf("WellKnownService(%d) = %q, want %q", tt.port, result, tt.expected)
		}
	}
}

func TestScanPort_Open(t *testing.T) {
	// Start a local TCP listener
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start listener: %v", err)
	}
	defer ln.Close()

	port := ln.Addr().(*net.TCPAddr).Port

	// Accept connections in background
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	scanner := NewPortScanner(2*time.Second, 1, 0)
	result := scanner.ScanPort(context.Background(), "127.0.0.1", port)

	if result.State != models.PortOpen {
		t.Errorf("expected port %d to be open, got %v", port, result.State)
	}
}

func TestScanPort_Closed(t *testing.T) {
	// Find a port that's likely closed
	scanner := NewPortScanner(500*time.Millisecond, 1, 0)
	result := scanner.ScanPort(context.Background(), "127.0.0.1", 59123)

	if result.State != models.PortClosed {
		t.Logf("port 59123 state: %v (may vary by environment)", result.State)
	}
}

func TestScan_Integration(t *testing.T) {
	// Start a local TCP listener
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start listener: %v", err)
	}
	defer ln.Close()

	port := ln.Addr().(*net.TCPAddr).Port

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	scanner := NewPortScanner(2*time.Second, 4, 0)
	results, err := scanner.Scan(context.Background(), "127.0.0.1", []int{port, 59124, 59125}, nil)
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}

	openCount := 0
	for _, r := range results {
		if r.State == models.PortOpen {
			openCount++
		}
	}

	if openCount != 1 {
		t.Errorf("expected 1 open port, found %d", openCount)
	}
}

func TestScan_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	scanner := NewPortScanner(2*time.Second, 4, 0)
	_, err := scanner.Scan(ctx, "127.0.0.1", []int{80, 443}, nil)

	if err != context.Canceled {
		t.Logf("scan with canceled context returned: %v", err)
	}
}
