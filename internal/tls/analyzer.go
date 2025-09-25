// Package tlsanalyzer implements TLS/SSL certificate and cipher suite analysis.
package tlsanalyzer

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/SafiullahRattar/netwatch/internal/models"
)

// Analyzer performs TLS/SSL security analysis on target hosts.
type Analyzer struct {
	timeout time.Duration
}

// NewAnalyzer creates a new TLS Analyzer with the given timeout.
func NewAnalyzer(timeout time.Duration) *Analyzer {
	return &Analyzer{timeout: timeout}
}

// Analyze performs a comprehensive TLS analysis of the given host and port.
func (a *Analyzer) Analyze(ctx context.Context, host string, port int) (*models.TLSInfo, error) {
	info := &models.TLSInfo{
		Host: host,
		Port: port,
	}

	address := net.JoinHostPort(host, strconv.Itoa(port))

	// Connect with TLS and collect certificate information
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: a.timeout},
		Config: &tls.Config{
			InsecureSkipVerify: true, // We verify manually for analysis
		},
	}

	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("TLS connection failed: %w", err)
	}
	defer conn.Close()

	tlsConn := conn.(*tls.Conn)
	state := tlsConn.ConnectionState()

	// Connection info
	info.Version = tlsVersionString(state.Version)
	info.CipherSuite = tls.CipherSuiteName(state.CipherSuite)

	// Certificate info
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		info.CertSubject = cert.Subject.String()
		info.CertIssuer = cert.Issuer.String()
		info.CertExpiry = cert.NotAfter
		info.CertNotBefore = cert.NotBefore
		info.DaysUntilExpiry = int(time.Until(cert.NotAfter).Hours() / 24)
		info.Expired = time.Now().After(cert.NotAfter)
		info.CertChainLength = len(state.PeerCertificates)
		info.SelfSigned = isSelfSigned(cert)

		// Subject Alternative Names
		for _, dns := range cert.DNSNames {
			info.SANs = append(info.SANs, dns)
		}
		for _, ip := range cert.IPAddresses {
			info.SANs = append(info.SANs, ip.String())
		}
	}

	// Test supported TLS versions
	info.SupportedVersions = a.checkSupportedVersions(ctx, host, port)

	// Enumerate cipher suites
	info.CipherSuites = a.enumerateCipherSuites(ctx, host, port)

	// Generate findings
	info.Findings = a.generateFindings(info)

	return info, nil
}

// checkSupportedVersions tests which TLS versions the server supports.
func (a *Analyzer) checkSupportedVersions(ctx context.Context, host string, port int) []string {
	versions := []struct {
		version uint16
		name    string
	}{
		{tls.VersionTLS10, "TLS 1.0"},
		{tls.VersionTLS11, "TLS 1.1"},
		{tls.VersionTLS12, "TLS 1.2"},
		{tls.VersionTLS13, "TLS 1.3"},
	}

	var supported []string
	address := net.JoinHostPort(host, strconv.Itoa(port))

	for _, v := range versions {
		select {
		case <-ctx.Done():
			return supported
		default:
		}

		dialer := &tls.Dialer{
			NetDialer: &net.Dialer{Timeout: a.timeout},
			Config: &tls.Config{
				InsecureSkipVerify: true,
				MinVersion:         v.version,
				MaxVersion:         v.version,
			},
		}

		conn, err := dialer.DialContext(ctx, "tcp", address)
		if err == nil {
			supported = append(supported, v.name)
			conn.Close()
		}
	}

	return supported
}

// enumerateCipherSuites returns the cipher suites supported by the server.
func (a *Analyzer) enumerateCipherSuites(ctx context.Context, host string, port int) []string {
	address := net.JoinHostPort(host, strconv.Itoa(port))

	// Collect unique cipher suites across TLS 1.2 and 1.3
	suiteSet := make(map[string]bool)

	// Test TLS 1.2 cipher suites
	for _, suite := range tls.CipherSuites() {
		select {
		case <-ctx.Done():
			break
		default:
		}

		dialer := &tls.Dialer{
			NetDialer: &net.Dialer{Timeout: a.timeout / 2},
			Config: &tls.Config{
				InsecureSkipVerify: true,
				MaxVersion:         tls.VersionTLS12,
				CipherSuites:       []uint16{suite.ID},
			},
		}

		conn, err := dialer.DialContext(ctx, "tcp", address)
		if err == nil {
			state := conn.(*tls.Conn).ConnectionState()
			name := tls.CipherSuiteName(state.CipherSuite)
			suiteSet[name] = true
			conn.Close()
		}
	}

	// Also test with TLS 1.3 (cipher suites are not configurable, but we capture what's negotiated)
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: a.timeout},
		Config: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS13,
		},
	}

	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err == nil {
		state := conn.(*tls.Conn).ConnectionState()
		name := tls.CipherSuiteName(state.CipherSuite)
		suiteSet[name] = true
		conn.Close()
	}

	var suites []string
	for s := range suiteSet {
		suites = append(suites, s)
	}
	return suites
}

// generateFindings produces security findings based on the TLS analysis.
func (a *Analyzer) generateFindings(info *models.TLSInfo) []models.Finding {
	var findings []models.Finding

	// Check for deprecated TLS versions
	for _, v := range info.SupportedVersions {
		if v == "TLS 1.0" || v == "TLS 1.1" {
			findings = append(findings, models.Finding{
				Title:       fmt.Sprintf("Deprecated TLS version supported: %s", v),
				Description: fmt.Sprintf("The server supports %s, which is deprecated and has known vulnerabilities. PCI DSS requires disabling TLS 1.0 and 1.1.", v),
				Severity:    models.SeverityCritical,
				Remediation: "Disable TLS 1.0 and TLS 1.1 on the server. Configure minimum TLS version to 1.2.",
				References:  []string{"https://datatracker.ietf.org/doc/rfc8996/"},
			})
		}
	}

	// Check for expired certificate
	if info.Expired {
		findings = append(findings, models.Finding{
			Title:       "SSL/TLS certificate has expired",
			Description: fmt.Sprintf("The certificate expired on %s.", info.CertExpiry.Format(time.RFC3339)),
			Severity:    models.SeverityHigh,
			Remediation: "Renew the SSL/TLS certificate immediately.",
		})
	}

	// Check for soon-to-expire certificate
	if !info.Expired && info.DaysUntilExpiry <= 30 {
		findings = append(findings, models.Finding{
			Title:       "SSL/TLS certificate expiring soon",
			Description: fmt.Sprintf("The certificate expires in %d days (on %s).", info.DaysUntilExpiry, info.CertExpiry.Format(time.RFC3339)),
			Severity:    models.SeverityMedium,
			Remediation: "Renew the SSL/TLS certificate before expiry.",
		})
	}

	// Check for self-signed certificate
	if info.SelfSigned {
		findings = append(findings, models.Finding{
			Title:       "Self-signed certificate detected",
			Description: "The server is using a self-signed certificate, which is not trusted by default by browsers and clients.",
			Severity:    models.SeverityMedium,
			Remediation: "Obtain a certificate from a trusted Certificate Authority (CA).",
		})
	}

	// Check for weak cipher suites
	for _, suite := range info.CipherSuites {
		if isWeakCipher(suite) {
			findings = append(findings, models.Finding{
				Title:       fmt.Sprintf("Weak cipher suite supported: %s", suite),
				Description: "The server supports a cipher suite that is considered weak or insecure.",
				Severity:    models.SeverityHigh,
				Remediation: "Disable weak cipher suites and configure the server to use only strong, modern ciphers.",
				References:  []string{"https://wiki.mozilla.org/Security/Server_Side_TLS"},
			})
			break // Report once to avoid duplicate noise
		}
	}

	return findings
}

// tlsVersionString converts a TLS version constant to a human-readable string.
func tlsVersionString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (0x%04x)", version)
	}
}

// isSelfSigned checks if a certificate is self-signed.
func isSelfSigned(cert *x509.Certificate) bool {
	return cert.Issuer.String() == cert.Subject.String()
}

// isWeakCipher checks if a cipher suite name indicates a weak cipher.
func isWeakCipher(name string) bool {
	weakIndicators := []string{
		"RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon",
		"CBC_SHA", // CBC mode ciphers with SHA-1 are considered weak
	}
	upper := strings.ToUpper(name)
	for _, indicator := range weakIndicators {
		if strings.Contains(upper, strings.ToUpper(indicator)) {
			return true
		}
	}
	return false
}
