package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"

	"github.com/SafiullahRattar/netwatch/internal/cve"
	"github.com/SafiullahRattar/netwatch/internal/headers"
	"github.com/SafiullahRattar/netwatch/internal/models"
	"github.com/SafiullahRattar/netwatch/internal/report"
	"github.com/SafiullahRattar/netwatch/internal/scanner"
	tlsanalyzer "github.com/SafiullahRattar/netwatch/internal/tls"
)

var (
	portRange   string
	serviceScan bool
	tlsScan     bool
	cveLookup   bool
	headerCheck bool
	rateLimit   int
	outputJSON  string
	outputHTML  string
)

var scanCmd = &cobra.Command{
	Use:   "scan [host]",
	Short: "Scan a target host for open ports and vulnerabilities",
	Long: `Perform a comprehensive security scan of a target host.

This includes TCP port scanning, service detection via banner grabbing,
TLS/SSL certificate analysis, CVE lookup, and HTTP security header checks.

Examples:
  netwatch scan example.com
  netwatch scan 192.168.1.1 -p 1-1024
  netwatch scan example.com -p 80,443,8080 --service --tls
  netwatch scan example.com --all -o report.json --html report.html`,
	Args: cobra.ExactArgs(1),
	RunE: runScan,
}

func init() {
	scanCmd.Flags().StringVarP(&portRange, "ports", "p", "1-1024", "port range to scan (e.g., 80,443 or 1-1024)")
	scanCmd.Flags().BoolVarP(&serviceScan, "service", "s", false, "enable service detection (banner grabbing)")
	scanCmd.Flags().BoolVar(&tlsScan, "tls", false, "enable TLS/SSL analysis on HTTPS ports")
	scanCmd.Flags().BoolVar(&cveLookup, "cve", false, "enable CVE lookup for detected services")
	scanCmd.Flags().BoolVar(&headerCheck, "headers", false, "enable HTTP security header check")
	scanCmd.Flags().BoolVar(&headerCheck, "all", false, "enable all scan types")
	scanCmd.Flags().IntVar(&rateLimit, "rate-limit", 0, "max requests per second (0 = unlimited)")
	scanCmd.Flags().StringVarP(&outputJSON, "output", "o", "", "save results to JSON file")
	scanCmd.Flags().StringVar(&outputHTML, "html", "", "save results to HTML file")

	rootCmd.AddCommand(scanCmd)
}

func runScan(cmd *cobra.Command, args []string) error {
	host := args[0]
	start := time.Now()

	// Check for --all flag
	allFlag, _ := cmd.Flags().GetBool("all")
	if allFlag {
		serviceScan = true
		tlsScan = true
		cveLookup = true
		headerCheck = true
	}

	// Set up context with signal handling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		color.Yellow("\n[!] Scan interrupted, cleaning up...")
		cancel()
	}()

	fmt.Println(Banner())
	color.Cyan("[*] Target: %s", host)
	color.Cyan("[*] Port range: %s", portRange)
	color.Cyan("[*] Workers: %d", workers)
	fmt.Println()

	scanReport := &models.ScanReport{
		ID:        fmt.Sprintf("nw-%d", time.Now().UnixNano()),
		StartTime: start,
		Target:    host,
	}

	// Phase 1: Port scanning
	ports, err := scanner.ParsePortRange(portRange)
	if err != nil {
		return fmt.Errorf("invalid port range: %w", err)
	}

	color.White("[+] Phase 1: Port scanning (%d ports)", len(ports))

	bar := progressbar.NewOptions(len(ports),
		progressbar.OptionSetDescription("    Scanning ports"),
		progressbar.OptionSetTheme(progressbar.Theme{
			Saucer:        color.GreenString("="),
			SaucerHead:    color.GreenString(">"),
			SaucerPadding: " ",
			BarStart:      "[",
			BarEnd:        "]",
		}),
		progressbar.OptionShowCount(),
		progressbar.OptionSetWidth(40),
	)

	ps := scanner.NewPortScanner(time.Duration(timeout)*time.Second, workers, rateLimit)
	results, err := ps.Scan(ctx, host, ports, func(done int) {
		bar.Set(done) //nolint:errcheck
	})
	bar.Finish() //nolint:errcheck
	fmt.Println()

	if err != nil && ctx.Err() != nil {
		return fmt.Errorf("scan cancelled")
	}

	// Sort results by port
	sort.Slice(results, func(i, j int) bool {
		return results[i].Port < results[j].Port
	})

	// Filter to open ports for display
	var openPorts []models.PortResult
	for _, r := range results {
		if r.State == models.PortOpen {
			openPorts = append(openPorts, r)
		}
	}

	color.Green("[+] Found %d open ports out of %d scanned", len(openPorts), len(results))
	fmt.Println()

	if len(openPorts) > 0 {
		printPortTable(openPorts)
	}

	scanReport.Ports = results

	// Phase 2: Service detection
	if serviceScan && len(openPorts) > 0 {
		color.White("\n[+] Phase 2: Service detection")
		sd := scanner.NewServiceDetector(time.Duration(timeout) * time.Second)

		for i, p := range openPorts {
			result := sd.DetectService(ctx, host, p.Port)
			openPorts[i] = result

			// Update in full results too
			for j, r := range results {
				if r.Port == p.Port {
					results[j] = result
					break
				}
			}
		}

		scanReport.Ports = results
		fmt.Println()
		printPortTable(openPorts)
	}

	// Phase 3: TLS analysis
	if tlsScan {
		for _, p := range openPorts {
			if p.Port == 443 || p.Port == 8443 || p.Service == "https" {
				color.White("\n[+] Phase 3: TLS/SSL analysis on port %d", p.Port)
				analyzer := tlsanalyzer.NewAnalyzer(time.Duration(timeout) * time.Second)
				tlsInfo, err := analyzer.Analyze(ctx, host, p.Port)
				if err != nil {
					color.Red("    [!] TLS analysis failed: %v", err)
				} else {
					scanReport.TLS = tlsInfo
					printTLSInfo(tlsInfo)
				}
				break // Only analyze the first TLS port
			}
		}
	}

	// Phase 4: HTTP security headers
	if headerCheck {
		for _, p := range openPorts {
			if p.Port == 80 || p.Port == 443 || p.Port == 8080 || p.Port == 8443 || p.Service == "http" || p.Service == "https" {
				scheme := "http"
				if p.Port == 443 || p.Port == 8443 || p.Service == "https" {
					scheme = "https"
				}
				targetURL := fmt.Sprintf("%s://%s:%d", scheme, host, p.Port)

				color.White("\n[+] Phase 4: HTTP security header analysis (%s)", targetURL)
				checker := headers.NewChecker(time.Duration(timeout) * time.Second)
				headerResult, err := checker.Check(ctx, targetURL)
				if err != nil {
					color.Red("    [!] Header check failed: %v", err)
				} else {
					scanReport.Headers = headerResult
					printHeaderResults(headerResult)
				}
				break
			}
		}
	}

	// Phase 5: CVE lookup
	if cveLookup && serviceScan {
		color.White("\n[+] Phase 5: CVE lookup")
		nvdClient := cve.NewClient()

		for _, p := range openPorts {
			if p.Version == "" {
				continue
			}

			color.HiBlack("    Searching CVEs for %s %s...", p.Service, p.Version)
			cves, err := nvdClient.SearchByProduct(ctx, p.Service, p.Version)
			if err != nil {
				if verbose {
					color.Yellow("    [!] CVE lookup failed for %s: %v", p.Service, err)
				}
				continue
			}

			scanReport.CVEs = append(scanReport.CVEs, cves...)

			for _, c := range cves {
				sev := cve.SeverityFromCVSS(c.CVSS)
				scanReport.Findings = append(scanReport.Findings, models.Finding{
					Title:       fmt.Sprintf("%s (CVSS: %.1f)", c.ID, c.CVSS),
					Description: truncate(c.Description, 200),
					Severity:    sev,
					References:  c.References,
				})
			}

			if len(cves) > 0 {
				color.Yellow("    Found %d CVEs for %s %s", len(cves), p.Service, p.Version)
			}

			// Rate limit NVD requests
			time.Sleep(600 * time.Millisecond)
		}
	}

	// Finalize report
	scanReport.EndTime = time.Now()
	scanReport.Duration = scanReport.EndTime.Sub(scanReport.StartTime).Round(time.Millisecond).String()
	scanReport.Summary = report.ComputeSummary(scanReport)

	// Print summary
	printSummary(scanReport)

	// Save outputs
	if outputJSON != "" {
		if err := report.SaveJSON(outputJSON, scanReport); err != nil {
			color.Red("[!] Failed to save JSON report: %v", err)
		} else {
			color.Green("[+] JSON report saved to %s", outputJSON)
		}
	}

	if outputHTML != "" {
		if err := report.SaveHTML(outputHTML, scanReport); err != nil {
			color.Red("[!] Failed to save HTML report: %v", err)
		} else {
			color.Green("[+] HTML report saved to %s", outputHTML)
		}
	}

	return nil
}

func printPortTable(ports []models.PortResult) {
	bold := color.New(color.Bold)
	bold.Printf("    %-8s %-10s %-15s %-20s %s\n", "PORT", "STATE", "SERVICE", "VERSION", "BANNER")
	bold.Printf("    %-8s %-10s %-15s %-20s %s\n", "----", "-----", "-------", "-------", "------")

	for _, p := range ports {
		stateColor := color.GreenString("open")
		service := p.Service
		if service == "" {
			service = "-"
		}
		version := p.Version
		if version == "" {
			version = "-"
		}
		banner := truncate(p.Banner, 40)
		if banner == "" {
			banner = "-"
		}

		fmt.Printf("    %-8d %-10s %-15s %-20s %s\n",
			p.Port, stateColor, service, version, banner)
	}
}

func printTLSInfo(info *models.TLSInfo) {
	fmt.Println()
	color.White("    TLS Connection Info:")
	fmt.Printf("    Protocol:         %s\n", info.Version)
	fmt.Printf("    Cipher Suite:     %s\n", info.CipherSuite)
	fmt.Printf("    Certificate:      %s\n", info.CertSubject)
	fmt.Printf("    Issuer:           %s\n", info.CertIssuer)

	if info.Expired {
		color.Red("    Expiry:           %s (EXPIRED)", info.CertExpiry.Format("2006-01-02"))
	} else if info.DaysUntilExpiry <= 30 {
		color.Yellow("    Expiry:           %s (%d days)", info.CertExpiry.Format("2006-01-02"), info.DaysUntilExpiry)
	} else {
		fmt.Printf("    Expiry:           %s (%d days)\n", info.CertExpiry.Format("2006-01-02"), info.DaysUntilExpiry)
	}

	if info.SelfSigned {
		color.Yellow("    Self-Signed:      Yes")
	}

	if len(info.SupportedVersions) > 0 {
		fmt.Printf("    Supported:        %s\n", strings.Join(info.SupportedVersions, ", "))
	}

	if len(info.Findings) > 0 {
		fmt.Println()
		for _, f := range info.Findings {
			printFinding(f)
		}
	}
}

func printHeaderResults(result *models.HeaderCheckResult) {
	grade := headers.GradeFromScore(result.Score)
	gradeColor := color.GreenString
	if grade == "F" || grade == "D" {
		gradeColor = color.RedString
	} else if grade == "C" {
		gradeColor = color.YellowString
	}

	fmt.Printf("\n    Score: %s (%d/100)\n", gradeColor(grade), result.Score)

	if len(result.Missing) > 0 {
		color.Yellow("    Missing headers:")
		for _, h := range result.Missing {
			fmt.Printf("      - %s\n", h)
		}
	}
}

func printFinding(f models.Finding) {
	var sevStr string
	switch f.Severity {
	case models.SeverityCritical:
		sevStr = color.RedString("[CRITICAL]")
	case models.SeverityHigh:
		sevStr = color.HiRedString("[HIGH]")
	case models.SeverityMedium:
		sevStr = color.YellowString("[MEDIUM]")
	case models.SeverityLow:
		sevStr = color.GreenString("[LOW]")
	default:
		sevStr = color.CyanString("[INFO]")
	}

	fmt.Printf("    %s %s\n", sevStr, f.Title)
	if verbose && f.Description != "" {
		color.HiBlack("      %s", f.Description)
	}
}

func printSummary(r *models.ScanReport) {
	fmt.Println()
	color.Cyan("=" + strings.Repeat("=", 59))
	color.Cyan("  Scan Summary")
	color.Cyan("=" + strings.Repeat("=", 59))
	fmt.Printf("  Target:     %s\n", r.Target)
	fmt.Printf("  Duration:   %s\n", r.Duration)
	fmt.Printf("  Ports:      %d scanned, %d open, %d closed, %d filtered\n",
		r.Summary.TotalPorts, r.Summary.OpenPorts, r.Summary.ClosedPorts, r.Summary.FilteredPorts)

	if r.Summary.TotalFindings > 0 {
		fmt.Printf("  Findings:   %d total", r.Summary.TotalFindings)
		parts := []string{}
		if r.Summary.Critical > 0 {
			parts = append(parts, color.RedString("%d critical", r.Summary.Critical))
		}
		if r.Summary.High > 0 {
			parts = append(parts, color.HiRedString("%d high", r.Summary.High))
		}
		if r.Summary.Medium > 0 {
			parts = append(parts, color.YellowString("%d medium", r.Summary.Medium))
		}
		if r.Summary.Low > 0 {
			parts = append(parts, color.GreenString("%d low", r.Summary.Low))
		}
		if r.Summary.Info > 0 {
			parts = append(parts, color.CyanString("%d info", r.Summary.Info))
		}
		if len(parts) > 0 {
			fmt.Printf(" (%s)", strings.Join(parts, ", "))
		}
		fmt.Println()
	} else {
		fmt.Println("  Findings:   None")
	}

	color.Cyan("=" + strings.Repeat("=", 59))
	fmt.Println()
}

func truncate(s string, maxLen int) string {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", "")
	if len(s) > maxLen {
		return s[:maxLen-3] + "..."
	}
	return s
}
