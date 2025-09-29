// Package report implements report generation in JSON and HTML formats.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/SafiullahRattar/netwatch/internal/models"
)

// WriteJSON writes a scan report as formatted JSON to the given writer.
func WriteJSON(w io.Writer, report *models.ScanReport) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		return fmt.Errorf("failed to encode JSON report: %w", err)
	}
	return nil
}

// SaveJSON saves a scan report as a JSON file at the specified path.
func SaveJSON(path string, report *models.ScanReport) error {
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %w", path, err)
	}
	defer file.Close()

	return WriteJSON(file, report)
}

// LoadJSON loads a scan report from a JSON file.
func LoadJSON(path string) (*models.ScanReport, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open file %s: %w", path, err)
	}
	defer file.Close()

	var report models.ScanReport
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&report); err != nil {
		return nil, fmt.Errorf("failed to decode JSON report: %w", err)
	}

	return &report, nil
}

// ComputeSummary calculates the report summary from the collected data.
func ComputeSummary(report *models.ScanReport) models.ReportSummary {
	summary := models.ReportSummary{}

	for _, port := range report.Ports {
		summary.TotalPorts++
		switch port.State {
		case models.PortOpen:
			summary.OpenPorts++
		case models.PortClosed:
			summary.ClosedPorts++
		case models.PortFiltered:
			summary.FilteredPorts++
		}
	}

	allFindings := report.Findings
	if report.TLS != nil {
		allFindings = append(allFindings, report.TLS.Findings...)
	}
	if report.Headers != nil {
		allFindings = append(allFindings, report.Headers.Findings...)
	}

	for _, f := range allFindings {
		summary.TotalFindings++
		switch f.Severity {
		case models.SeverityCritical:
			summary.Critical++
		case models.SeverityHigh:
			summary.High++
		case models.SeverityMedium:
			summary.Medium++
		case models.SeverityLow:
			summary.Low++
		case models.SeverityInfo:
			summary.Info++
		}
	}

	return summary
}
