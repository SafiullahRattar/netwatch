package cmd

import (
	"fmt"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/SafiullahRattar/netwatch/internal/report"
)

var (
	reportInputJSON string
	reportOutputHTML string
)

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Generate or convert scan reports",
	Long: `Generate HTML reports from existing JSON scan results.

Examples:
  netwatch report --input scan.json --html report.html
  netwatch report -i scan.json --html report.html`,
	RunE: runReport,
}

func init() {
	reportCmd.Flags().StringVarP(&reportInputJSON, "input", "i", "", "input JSON report file (required)")
	reportCmd.Flags().StringVar(&reportOutputHTML, "html", "", "output HTML report file (required)")
	reportCmd.MarkFlagRequired("input")  //nolint:errcheck
	reportCmd.MarkFlagRequired("html")   //nolint:errcheck

	rootCmd.AddCommand(reportCmd)
}

func runReport(cmd *cobra.Command, args []string) error {
	color.Cyan("[*] Loading report from %s", reportInputJSON)

	scanReport, err := report.LoadJSON(reportInputJSON)
	if err != nil {
		return fmt.Errorf("failed to load JSON report: %w", err)
	}

	color.Cyan("[*] Generating HTML report...")

	if err := report.SaveHTML(reportOutputHTML, scanReport); err != nil {
		return fmt.Errorf("failed to generate HTML report: %w", err)
	}

	color.Green("[+] HTML report saved to %s", reportOutputHTML)
	color.Green("[+] Report for target: %s", scanReport.Target)
	color.Green("[+] Findings: %d total (%d critical, %d high, %d medium, %d low)",
		scanReport.Summary.TotalFindings,
		scanReport.Summary.Critical,
		scanReport.Summary.High,
		scanReport.Summary.Medium,
		scanReport.Summary.Low,
	)

	return nil
}
