// Package models defines the core data types used throughout the netwatch tool.
package models

import (
	"encoding/json"
	"fmt"
	"time"
)

// Severity represents the severity level of a finding.
type Severity int

const (
	SeverityInfo     Severity = iota // Informational
	SeverityLow                      // Low risk
	SeverityMedium                   // Medium risk
	SeverityHigh                     // High risk
	SeverityCritical                 // Critical risk
)

// String returns the human-readable name of a severity level.
func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "Info"
	case SeverityLow:
		return "Low"
	case SeverityMedium:
		return "Medium"
	case SeverityHigh:
		return "High"
	case SeverityCritical:
		return "Critical"
	default:
		return "Unknown"
	}
}

// MarshalJSON implements the json.Marshaler interface for Severity.
func (s Severity) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf("%q", s.String())), nil
}

// UnmarshalJSON implements the json.Unmarshaler interface for Severity.
func (s *Severity) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}
	switch str {
	case "Critical":
		*s = SeverityCritical
	case "High":
		*s = SeverityHigh
	case "Medium":
		*s = SeverityMedium
	case "Low":
		*s = SeverityLow
	case "Info":
		*s = SeverityInfo
	default:
		*s = SeverityInfo
	}
	return nil
}

// PortState represents the state of a scanned port.
type PortState int

const (
	PortClosed   PortState = iota // Port is closed
	PortOpen                      // Port is open
	PortFiltered                  // Port is filtered (no response)
)

// String returns the human-readable name of a port state.
func (p PortState) String() string {
	switch p {
	case PortClosed:
		return "closed"
	case PortOpen:
		return "open"
	case PortFiltered:
		return "filtered"
	default:
		return "unknown"
	}
}

// MarshalJSON implements the json.Marshaler interface for PortState.
func (p PortState) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf("%q", p.String())), nil
}

// UnmarshalJSON implements the json.Unmarshaler interface for PortState.
func (p *PortState) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	switch s {
	case "open":
		*p = PortOpen
	case "closed":
		*p = PortClosed
	case "filtered":
		*p = PortFiltered
	default:
		*p = PortClosed
	}
	return nil
}

// PortResult holds the result of scanning a single port.
type PortResult struct {
	Port    int       `json:"port"`
	State   PortState `json:"state"`
	Service string    `json:"service,omitempty"`
	Banner  string    `json:"banner,omitempty"`
	Version string    `json:"version,omitempty"`
}

// Host represents a discovered host on the network.
type Host struct {
	IP       string `json:"ip"`
	Hostname string `json:"hostname,omitempty"`
	MAC      string `json:"mac,omitempty"`
	Alive    bool   `json:"alive"`
	Latency  string `json:"latency,omitempty"`
}

// TLSInfo holds TLS/SSL analysis results for a host.
type TLSInfo struct {
	Host              string        `json:"host"`
	Port              int           `json:"port"`
	Version           string        `json:"version"`
	CipherSuite       string        `json:"cipher_suite"`
	CertSubject       string        `json:"cert_subject"`
	CertIssuer        string        `json:"cert_issuer"`
	CertExpiry        time.Time     `json:"cert_expiry"`
	CertNotBefore     time.Time     `json:"cert_not_before"`
	DaysUntilExpiry   int           `json:"days_until_expiry"`
	SelfSigned        bool          `json:"self_signed"`
	Expired           bool          `json:"expired"`
	CertChainLength   int           `json:"cert_chain_length"`
	SANs              []string      `json:"sans,omitempty"`
	SupportedVersions []string      `json:"supported_versions,omitempty"`
	CipherSuites      []string      `json:"cipher_suites,omitempty"`
	Findings          []Finding     `json:"findings,omitempty"`
}

// CVE represents a known vulnerability from the NVD.
type CVE struct {
	ID          string  `json:"id"`
	Description string  `json:"description"`
	CVSS        float64 `json:"cvss"`
	Severity    string  `json:"severity"`
	Published   string  `json:"published"`
	References  []string `json:"references,omitempty"`
}

// HeaderCheckResult holds HTTP security header analysis results.
type HeaderCheckResult struct {
	URL      string            `json:"url"`
	Headers  map[string]string `json:"headers"`
	Missing  []string          `json:"missing_headers"`
	Findings []Finding         `json:"findings"`
	Score    int               `json:"score"` // 0-100
}

// Finding represents a single security finding.
type Finding struct {
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Severity    Severity `json:"severity"`
	Remediation string   `json:"remediation,omitempty"`
	References  []string `json:"references,omitempty"`
}

// ScanTarget represents a target to be scanned.
type ScanTarget struct {
	Host      string `json:"host"`
	PortRange string `json:"port_range,omitempty"` // e.g., "1-1024", "80,443,8080"
}

// ScanConfig holds configuration for a scan operation.
type ScanConfig struct {
	Targets     []ScanTarget  `json:"targets"`
	Timeout     time.Duration `json:"timeout"`
	Workers     int           `json:"workers"`
	RateLimit   int           `json:"rate_limit"` // max requests per second, 0 = unlimited
	PortRange   string        `json:"port_range"`
	ServiceScan bool          `json:"service_scan"`
	TLSScan     bool          `json:"tls_scan"`
	CVELookup   bool          `json:"cve_lookup"`
	HeaderCheck bool          `json:"header_check"`
}

// ScanReport holds the full results of a scan.
type ScanReport struct {
	ID          string              `json:"id"`
	StartTime   time.Time           `json:"start_time"`
	EndTime     time.Time           `json:"end_time"`
	Duration    string              `json:"duration"`
	Target      string              `json:"target"`
	Ports       []PortResult        `json:"ports,omitempty"`
	TLS         *TLSInfo            `json:"tls,omitempty"`
	Hosts       []Host              `json:"hosts,omitempty"`
	Headers     *HeaderCheckResult  `json:"headers,omitempty"`
	CVEs        []CVE               `json:"cves,omitempty"`
	Findings    []Finding           `json:"findings,omitempty"`
	Summary     ReportSummary       `json:"summary"`
}

// ReportSummary provides a high-level overview of findings.
type ReportSummary struct {
	TotalPorts    int `json:"total_ports_scanned"`
	OpenPorts     int `json:"open_ports"`
	ClosedPorts   int `json:"closed_ports"`
	FilteredPorts int `json:"filtered_ports"`
	TotalFindings int `json:"total_findings"`
	Critical      int `json:"critical"`
	High          int `json:"high"`
	Medium        int `json:"medium"`
	Low           int `json:"low"`
	Info          int `json:"info"`
}
