package tlsanalyzer

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"

	"github.com/SafiullahRattar/netwatch/internal/models"
)

func TestTLSVersionString(t *testing.T) {
	tests := []struct {
		version  uint16
		expected string
	}{
		{0x0301, "TLS 1.0"},
		{0x0302, "TLS 1.1"},
		{0x0303, "TLS 1.2"},
		{0x0304, "TLS 1.3"},
		{0x0000, "Unknown (0x0000)"},
	}

	for _, tt := range tests {
		result := tlsVersionString(tt.version)
		if result != tt.expected {
			t.Errorf("tlsVersionString(0x%04x) = %q, want %q", tt.version, result, tt.expected)
		}
	}
}

func TestIsSelfSigned(t *testing.T) {
	selfSigned := &x509.Certificate{
		Subject: pkix.Name{CommonName: "test.local"},
		Issuer:  pkix.Name{CommonName: "test.local"},
	}
	if !isSelfSigned(selfSigned) {
		t.Error("expected self-signed certificate to be detected")
	}

	caSigned := &x509.Certificate{
		Subject: pkix.Name{CommonName: "test.local"},
		Issuer:  pkix.Name{CommonName: "Some CA"},
	}
	if isSelfSigned(caSigned) {
		t.Error("expected CA-signed certificate to not be detected as self-signed")
	}
}

func TestIsWeakCipher(t *testing.T) {
	tests := []struct {
		name   string
		cipher string
		weak   bool
	}{
		{"RC4", "TLS_RSA_WITH_RC4_128_SHA", true},
		{"3DES", "TLS_RSA_WITH_3DES_EDE_CBC_SHA", true},
		{"NULL", "TLS_RSA_WITH_NULL_SHA", true},
		{"AES-GCM", "TLS_AES_256_GCM_SHA384", false},
		{"CHACHA20", "TLS_CHACHA20_POLY1305_SHA256", false},
		{"ECDHE-AES-GCM", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isWeakCipher(tt.cipher)
			if result != tt.weak {
				t.Errorf("isWeakCipher(%q) = %v, want %v", tt.cipher, result, tt.weak)
			}
		})
	}
}

func TestGenerateFindings_DeprecatedTLS(t *testing.T) {
	a := &Analyzer{}
	info := &models.TLSInfo{
		SupportedVersions: []string{"TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3"},
		CertExpiry:        time.Now().Add(365 * 24 * time.Hour),
		DaysUntilExpiry:   365,
	}

	findings := a.generateFindings(info)

	criticalCount := 0
	for _, f := range findings {
		if f.Severity == models.SeverityCritical {
			criticalCount++
		}
	}
	if criticalCount < 2 {
		t.Errorf("expected at least 2 critical findings for TLS 1.0 and 1.1, got %d", criticalCount)
	}
}

func TestGenerateFindings_ExpiredCert(t *testing.T) {
	a := &Analyzer{}
	info := &models.TLSInfo{
		Expired:         true,
		CertExpiry:      time.Now().Add(-24 * time.Hour),
		DaysUntilExpiry: -1,
	}

	findings := a.generateFindings(info)

	found := false
	for _, f := range findings {
		if f.Severity == models.SeverityHigh && f.Title == "SSL/TLS certificate has expired" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected finding for expired certificate")
	}
}

func TestGenerateFindings_ExpiringSoon(t *testing.T) {
	a := &Analyzer{}
	info := &models.TLSInfo{
		Expired:         false,
		CertExpiry:      time.Now().Add(15 * 24 * time.Hour),
		DaysUntilExpiry: 15,
	}

	findings := a.generateFindings(info)

	found := false
	for _, f := range findings {
		if f.Severity == models.SeverityMedium && f.Title == "SSL/TLS certificate expiring soon" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected finding for expiring certificate")
	}
}

func TestGenerateFindings_SelfSigned(t *testing.T) {
	a := &Analyzer{}
	info := &models.TLSInfo{
		SelfSigned:      true,
		CertExpiry:      time.Now().Add(365 * 24 * time.Hour),
		DaysUntilExpiry: 365,
	}

	findings := a.generateFindings(info)

	found := false
	for _, f := range findings {
		if f.Title == "Self-signed certificate detected" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected finding for self-signed certificate")
	}
}

func TestNewAnalyzer(t *testing.T) {
	a := NewAnalyzer(5 * time.Second)
	if a == nil {
		t.Fatal("NewAnalyzer returned nil")
	}
	if a.timeout != 5*time.Second {
		t.Errorf("expected timeout 5s, got %v", a.timeout)
	}
}
