// Package headers implements HTTP security header analysis.
package headers

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/SafiullahRattar/netwatch/internal/models"
)

// SecurityHeader defines an expected HTTP security header and its importance.
type SecurityHeader struct {
	Name        string
	Description string
	Severity    models.Severity
	Required    bool
	Remediation string
	Reference   string
}

// ExpectedHeaders returns the list of security headers to check.
func ExpectedHeaders() []SecurityHeader {
	return []SecurityHeader{
		{
			Name:        "Strict-Transport-Security",
			Description: "HTTP Strict Transport Security (HSTS) header forces browsers to use HTTPS.",
			Severity:    models.SeverityHigh,
			Required:    true,
			Remediation: "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header.",
			Reference:   "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
		},
		{
			Name:        "Content-Security-Policy",
			Description: "Content Security Policy (CSP) prevents XSS and data injection attacks.",
			Severity:    models.SeverityHigh,
			Required:    true,
			Remediation: "Add a Content-Security-Policy header with appropriate directives.",
			Reference:   "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
		},
		{
			Name:        "X-Frame-Options",
			Description: "X-Frame-Options prevents clickjacking by controlling iframe embedding.",
			Severity:    models.SeverityHigh,
			Required:    true,
			Remediation: "Add 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN' header.",
			Reference:   "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
		},
		{
			Name:        "X-Content-Type-Options",
			Description: "Prevents MIME-type sniffing, reducing drive-by download attacks.",
			Severity:    models.SeverityMedium,
			Required:    true,
			Remediation: "Add 'X-Content-Type-Options: nosniff' header.",
			Reference:   "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options",
		},
		{
			Name:        "Referrer-Policy",
			Description: "Controls how much referrer information is sent with requests.",
			Severity:    models.SeverityMedium,
			Required:    true,
			Remediation: "Add 'Referrer-Policy: strict-origin-when-cross-origin' header.",
			Reference:   "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy",
		},
		{
			Name:        "Permissions-Policy",
			Description: "Controls which browser features and APIs can be used (successor to Feature-Policy).",
			Severity:    models.SeverityMedium,
			Required:    false,
			Remediation: "Add a Permissions-Policy header to restrict browser features.",
			Reference:   "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy",
		},
		{
			Name:        "X-XSS-Protection",
			Description: "Legacy XSS filter header. While deprecated, its absence may indicate lack of security awareness.",
			Severity:    models.SeverityLow,
			Required:    false,
			Remediation: "Add 'X-XSS-Protection: 0' (modern recommendation) or rely on CSP.",
			Reference:   "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection",
		},
		{
			Name:        "Cross-Origin-Opener-Policy",
			Description: "Ensures a top-level document does not share a browsing context group with cross-origin documents.",
			Severity:    models.SeverityLow,
			Required:    false,
			Remediation: "Add 'Cross-Origin-Opener-Policy: same-origin' header.",
			Reference:   "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy",
		},
		{
			Name:        "Cross-Origin-Resource-Policy",
			Description: "Prevents other origins from reading the response of resources.",
			Severity:    models.SeverityLow,
			Required:    false,
			Remediation: "Add 'Cross-Origin-Resource-Policy: same-origin' header.",
			Reference:   "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy",
		},
	}
}

// Checker performs HTTP security header analysis.
type Checker struct {
	httpClient *http.Client
}

// NewChecker creates a new HTTP header Checker.
func NewChecker(timeout time.Duration) *Checker {
	return &Checker{
		httpClient: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
			// Don't follow redirects
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 3 {
					return fmt.Errorf("too many redirects")
				}
				return nil
			},
		},
	}
}

// Check performs an HTTP security header analysis on the given URL.
func (c *Checker) Check(ctx context.Context, targetURL string) (*models.HeaderCheckResult, error) {
	// Ensure URL has a scheme
	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		targetURL = "https://" + targetURL
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("User-Agent", "netwatch/1.0 (security-scanner)")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	result := &models.HeaderCheckResult{
		URL:     targetURL,
		Headers: make(map[string]string),
	}

	// Collect all response headers
	for name, values := range resp.Header {
		result.Headers[name] = strings.Join(values, "; ")
	}

	// Check for missing security headers
	expected := ExpectedHeaders()
	presentCount := 0

	for _, header := range expected {
		value := resp.Header.Get(header.Name)
		if value == "" {
			result.Missing = append(result.Missing, header.Name)
			result.Findings = append(result.Findings, models.Finding{
				Title:       fmt.Sprintf("Missing security header: %s", header.Name),
				Description: header.Description,
				Severity:    header.Severity,
				Remediation: header.Remediation,
				References:  []string{header.Reference},
			})
		} else {
			presentCount++
			// Analyze header values for common misconfigurations
			findings := analyzeHeaderValue(header.Name, value)
			result.Findings = append(result.Findings, findings...)
		}
	}

	// Check for information leakage headers
	leakageFindings := checkInfoLeakage(resp.Header)
	result.Findings = append(result.Findings, leakageFindings...)

	// Calculate score (percentage of required headers present)
	totalExpected := len(expected)
	if totalExpected > 0 {
		result.Score = (presentCount * 100) / totalExpected
	}

	return result, nil
}

// analyzeHeaderValue checks specific header values for misconfigurations.
func analyzeHeaderValue(name, value string) []models.Finding {
	var findings []models.Finding

	switch name {
	case "Strict-Transport-Security":
		if !strings.Contains(value, "includeSubDomains") {
			findings = append(findings, models.Finding{
				Title:       "HSTS missing includeSubDomains directive",
				Description: "The HSTS header does not include the includeSubDomains directive, leaving subdomains vulnerable to downgrade attacks.",
				Severity:    models.SeverityMedium,
				Remediation: "Add 'includeSubDomains' to the Strict-Transport-Security header value.",
			})
		}
		if strings.Contains(value, "max-age=0") {
			findings = append(findings, models.Finding{
				Title:       "HSTS max-age is zero",
				Description: "The HSTS max-age is set to 0, which effectively disables HSTS.",
				Severity:    models.SeverityHigh,
				Remediation: "Set max-age to at least 31536000 (1 year).",
			})
		}

	case "X-Frame-Options":
		upper := strings.ToUpper(value)
		if upper != "DENY" && upper != "SAMEORIGIN" && !strings.HasPrefix(upper, "ALLOW-FROM") {
			findings = append(findings, models.Finding{
				Title:       "Invalid X-Frame-Options value",
				Description: fmt.Sprintf("X-Frame-Options has an invalid value: %q. Valid values are DENY, SAMEORIGIN, or ALLOW-FROM.", value),
				Severity:    models.SeverityMedium,
				Remediation: "Set X-Frame-Options to 'DENY' or 'SAMEORIGIN'.",
			})
		}

	case "Content-Security-Policy":
		if strings.Contains(value, "'unsafe-inline'") {
			findings = append(findings, models.Finding{
				Title:       "CSP allows unsafe-inline scripts",
				Description: "The Content-Security-Policy allows 'unsafe-inline', which weakens XSS protection.",
				Severity:    models.SeverityMedium,
				Remediation: "Remove 'unsafe-inline' from CSP and use nonce or hash-based script loading.",
			})
		}
		if strings.Contains(value, "'unsafe-eval'") {
			findings = append(findings, models.Finding{
				Title:       "CSP allows unsafe-eval",
				Description: "The Content-Security-Policy allows 'unsafe-eval', enabling eval() and similar functions.",
				Severity:    models.SeverityMedium,
				Remediation: "Remove 'unsafe-eval' from CSP directives.",
			})
		}
		if strings.Contains(value, "*") {
			findings = append(findings, models.Finding{
				Title:       "CSP uses wildcard source",
				Description: "The Content-Security-Policy uses a wildcard (*) source, which is overly permissive.",
				Severity:    models.SeverityMedium,
				Remediation: "Replace wildcard sources with specific allowed origins.",
			})
		}
	}

	return findings
}

// checkInfoLeakage checks for headers that may leak sensitive information.
func checkInfoLeakage(headers http.Header) []models.Finding {
	var findings []models.Finding

	// Server header with version info
	server := headers.Get("Server")
	if server != "" && (strings.Contains(server, "/") || len(server) > 20) {
		findings = append(findings, models.Finding{
			Title:       "Server header reveals version information",
			Description: fmt.Sprintf("The Server header (%q) may reveal version information that could help attackers identify vulnerabilities.", server),
			Severity:    models.SeverityLow,
			Remediation: "Configure the server to send a generic Server header without version details.",
		})
	}

	// X-Powered-By header
	poweredBy := headers.Get("X-Powered-By")
	if poweredBy != "" {
		findings = append(findings, models.Finding{
			Title:       "X-Powered-By header present",
			Description: fmt.Sprintf("The X-Powered-By header (%q) reveals technology stack information.", poweredBy),
			Severity:    models.SeverityLow,
			Remediation: "Remove the X-Powered-By header from server responses.",
		})
	}

	// X-AspNet-Version header
	aspNet := headers.Get("X-AspNet-Version")
	if aspNet != "" {
		findings = append(findings, models.Finding{
			Title:       "X-AspNet-Version header present",
			Description: fmt.Sprintf("The X-AspNet-Version header (%q) reveals the ASP.NET version.", aspNet),
			Severity:    models.SeverityLow,
			Remediation: "Remove the X-AspNet-Version header from server responses.",
		})
	}

	return findings
}

// GradeFromScore converts a numeric score to a letter grade.
func GradeFromScore(score int) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 80:
		return "B"
	case score >= 70:
		return "C"
	case score >= 60:
		return "D"
	default:
		return "F"
	}
}
