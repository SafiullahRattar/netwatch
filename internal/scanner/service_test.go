package scanner

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/SafiullahRattar/netwatch/internal/models"
)

func TestServiceDetector_SSHBanner(t *testing.T) {
	// Start a mock SSH server
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
			fmt.Fprintf(conn, "SSH-2.0-OpenSSH_8.9p1\r\n")
			conn.Close()
		}
	}()

	detector := NewServiceDetector(2 * time.Second)
	result := detector.DetectService(context.Background(), "127.0.0.1", port)

	if result.State != models.PortOpen {
		t.Errorf("expected port to be open, got %v", result.State)
	}
	if result.Service != "ssh" {
		t.Errorf("expected service ssh, got %q", result.Service)
	}
	if result.Version != "OpenSSH_8.9p1" {
		t.Errorf("expected version OpenSSH_8.9p1, got %q", result.Version)
	}
}

func TestServiceDetector_FTPBanner(t *testing.T) {
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
			fmt.Fprintf(conn, "220 (vsFTPd 3.0.5)\r\n")
			conn.Close()
		}
	}()

	detector := NewServiceDetector(2 * time.Second)
	result := detector.DetectService(context.Background(), "127.0.0.1", port)

	if result.Service != "ftp" {
		t.Errorf("expected service ftp, got %q", result.Service)
	}
}

func TestServiceDetector_ClosedPort(t *testing.T) {
	detector := NewServiceDetector(500 * time.Millisecond)
	result := detector.DetectService(context.Background(), "127.0.0.1", 59199)

	if result.State == models.PortOpen {
		t.Error("expected port to not be open on unused port")
	}
}

func TestSanitizeBanner(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"clean", "SSH-2.0-OpenSSH", "SSH-2.0-OpenSSH"},
		{"with nulls", "SSH\x00-2.0", "SSH-2.0"},
		{"with whitespace", "  SSH-2.0  \n", "SSH-2.0"},
		{"empty", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizeBanner(tt.input)
			if result != tt.expected {
				t.Errorf("sanitizeBanner(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestParseBanner(t *testing.T) {
	sd := &ServiceDetector{}

	tests := []struct {
		name            string
		banner          string
		port            int
		expectedService string
		expectedVersion string
	}{
		{"ssh", "SSH-2.0-OpenSSH_8.9p1", 22, "ssh", "OpenSSH_8.9p1"},
		{"ftp", "220 (vsFTPd 3.0.5)", 21, "ftp", "(vsFTPd 3.0.5)"},
		{"smtp", "220 mail.example.com SMTP", 25, "smtp", "mail.example.com SMTP"},
		{"unknown", "some random banner", 12345, "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, version := sd.parseBanner(tt.banner, tt.port)
			if service != tt.expectedService {
				t.Errorf("service: got %q, want %q", service, tt.expectedService)
			}
			if tt.expectedVersion != "" && version != tt.expectedVersion {
				t.Errorf("version: got %q, want %q", version, tt.expectedVersion)
			}
		})
	}
}
