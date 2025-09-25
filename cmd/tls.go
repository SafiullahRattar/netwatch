package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/SafiullahRattar/netwatch/internal/models"
	"github.com/SafiullahRattar/netwatch/internal/report"
	tlsanalyzer "github.com/SafiullahRattar/netwatch/internal/tls"
)

var (
	tlsPort       int
	tlsOutputJSON string
	tlsOutputHTML string
)

var tlsCmd = &cobra.Command{
	Use:   "tls [host]",
	Short: "Analyze TLS/SSL configuration of a host",
	Long: `Perform a detailed TLS/SSL security analysis of a target host.

Checks certificate validity, expiry, cipher suites, supported protocol
versions, and identifies security issues like deprecated TLS versions
or weak cipher suites.

Examples:
  netwatch tls example.com
  netwatch tls example.com --port 8443
  netwatch tls example.com -o tls-report.json`,
	Args: cobra.ExactArgs(1),
	RunE: runTLS,
}

func init() {
	tlsCmd.Flags().IntVar(&tlsPort, "port", 443, "TLS port to analyze")
	tlsCmd.Flags().StringVarP(&tlsOutputJSON, "output", "o", "", "save results to JSON file")
	tlsCmd.Flags().StringVar(&tlsOutputHTML, "html", "", "save results to HTML file")

	rootCmd.AddCommand(tlsCmd)
}

func runTLS(cmd *cobra.Command, args []string) error {
	host := args[0]
	start := time.Now()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		color.Yellow("\n[!] Analysis interrupted")
		cancel()
	}()

	fmt.Println(Banner())
	color.Cyan("[*] TLS/SSL Analysis: %s:%d", host, tlsPort)
	fmt.Println()

	analyzer := tlsanalyzer.NewAnalyzer(time.Duration(timeout) * time.Second)
	color.White("[+] Connecting and analyzing TLS configuration...")

	tlsInfo, err := analyzer.Analyze(ctx, host, tlsPort)
	if err != nil {
		return fmt.Errorf("TLS analysis failed: %w", err)
	}

	// Display results
	printTLSDetail(tlsInfo)

	// Build report if output requested
	if tlsOutputJSON != "" || tlsOutputHTML != "" {
		scanReport := &models.ScanReport{
			ID:        fmt.Sprintf("nw-tls-%d", time.Now().UnixNano()),
			StartTime: start,
			EndTime:   time.Now(),
			Duration:  time.Since(start).Round(time.Millisecond).String(),
			Target:    fmt.Sprintf("%s:%d", host, tlsPort),
			TLS:       tlsInfo,
		}
		scanReport.Summary = report.ComputeSummary(scanReport)

		if tlsOutputJSON != "" {
			if err := report.SaveJSON(tlsOutputJSON, scanReport); err != nil {
				color.Red("[!] Failed to save JSON: %v", err)
			} else {
				color.Green("[+] JSON report saved to %s", tlsOutputJSON)
			}
		}

		if tlsOutputHTML != "" {
			if err := report.SaveHTML(tlsOutputHTML, scanReport); err != nil {
				color.Red("[!] Failed to save HTML: %v", err)
			} else {
				color.Green("[+] HTML report saved to %s", tlsOutputHTML)
			}
		}
	}

	return nil
}

func printTLSDetail(info *models.TLSInfo) {
	bold := color.New(color.Bold)

	bold.Println("  Connection")
	fmt.Printf("    Protocol Version:   %s\n", info.Version)
	fmt.Printf("    Cipher Suite:       %s\n", info.CipherSuite)
	fmt.Println()

	bold.Println("  Certificate")
	fmt.Printf("    Subject:            %s\n", info.CertSubject)
	fmt.Printf("    Issuer:             %s\n", info.CertIssuer)
	fmt.Printf("    Not Before:         %s\n", info.CertNotBefore.Format("2006-01-02 15:04:05 MST"))

	if info.Expired {
		color.Red("    Not After:          %s (EXPIRED)", info.CertExpiry.Format("2006-01-02 15:04:05 MST"))
	} else if info.DaysUntilExpiry <= 30 {
		color.Yellow("    Not After:          %s (%d days remaining)",
			info.CertExpiry.Format("2006-01-02 15:04:05 MST"), info.DaysUntilExpiry)
	} else {
		color.Green("    Not After:          %s (%d days remaining)",
			info.CertExpiry.Format("2006-01-02 15:04:05 MST"), info.DaysUntilExpiry)
	}

	fmt.Printf("    Chain Length:       %d\n", info.CertChainLength)

	if info.SelfSigned {
		color.Yellow("    Self-Signed:        Yes")
	} else {
		color.Green("    Self-Signed:        No")
	}

	if len(info.SANs) > 0 {
		fmt.Printf("    SANs:               %s\n", strings.Join(info.SANs, ", "))
	}

	fmt.Println()
	bold.Println("  Protocol Support")
	for _, v := range info.SupportedVersions {
		if v == "TLS 1.0" || v == "TLS 1.1" {
			color.Red("    [!] %s (deprecated)", v)
		} else {
			color.Green("    [+] %s", v)
		}
	}

	if len(info.CipherSuites) > 0 {
		fmt.Println()
		bold.Println("  Cipher Suites")
		for _, cs := range info.CipherSuites {
			fmt.Printf("    - %s\n", cs)
		}
	}

	if len(info.Findings) > 0 {
		fmt.Println()
		bold.Println("  Findings")
		for _, f := range info.Findings {
			printFinding(f)
		}
	}

	fmt.Println()
}
