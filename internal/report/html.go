package report

import (
	"embed"
	"fmt"
	"html/template"
	"io"
	"os"
	"strings"

	"github.com/SafiullahRattar/netwatch/internal/models"
)

//go:embed templates/report.html
var templateFS embed.FS

// templateFuncs provides helper functions for the HTML template.
var templateFuncs = template.FuncMap{
	"severityClass": func(s models.Severity) string {
		switch s {
		case models.SeverityCritical:
			return "critical"
		case models.SeverityHigh:
			return "high"
		case models.SeverityMedium:
			return "medium"
		case models.SeverityLow:
			return "low"
		default:
			return "info"
		}
	},
	"portStateClass": func(s models.PortState) string {
		switch s {
		case models.PortOpen:
			return "open"
		case models.PortClosed:
			return "closed"
		case models.PortFiltered:
			return "filtered"
		default:
			return ""
		}
	},
	"upper": strings.ToUpper,
	"lower": strings.ToLower,
	"join":  strings.Join,
}

// WriteHTML writes a scan report as an HTML document to the given writer.
func WriteHTML(w io.Writer, report *models.ScanReport) error {
	tmpl, err := template.New("report.html").Funcs(templateFuncs).ParseFS(templateFS, "templates/report.html")
	if err != nil {
		return fmt.Errorf("failed to parse HTML template: %w", err)
	}

	if err := tmpl.Execute(w, report); err != nil {
		return fmt.Errorf("failed to execute HTML template: %w", err)
	}

	return nil
}

// SaveHTML saves a scan report as an HTML file at the specified path.
func SaveHTML(path string, report *models.ScanReport) error {
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %w", path, err)
	}
	defer file.Close()

	return WriteHTML(file, report)
}
