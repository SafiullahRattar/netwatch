package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"

	"github.com/SafiullahRattar/netwatch/internal/discovery"
	"github.com/SafiullahRattar/netwatch/internal/models"
	"github.com/SafiullahRattar/netwatch/internal/report"
)

var (
	discoverInterface string
	discoverOutputJSON string
	discoverOutputHTML string
)

var discoverCmd = &cobra.Command{
	Use:   "discover [cidr]",
	Short: "Discover live hosts on a network",
	Long: `Perform network host discovery using TCP connect probes.

Scans a subnet (CIDR notation) to identify live hosts by attempting
TCP connections to common ports (80, 443, 22, 445, 139, 3389).

Examples:
  netwatch discover 192.168.1.0/24
  netwatch discover 10.0.0.0/24 -w 200
  netwatch discover --interface eth0`,
	Args: cobra.MaximumNArgs(1),
	RunE: runDiscover,
}

func init() {
	discoverCmd.Flags().StringVarP(&discoverInterface, "interface", "i", "", "network interface to detect subnet (auto-detect if empty)")
	discoverCmd.Flags().StringVarP(&discoverOutputJSON, "output", "o", "", "save results to JSON file")
	discoverCmd.Flags().StringVar(&discoverOutputHTML, "html", "", "save results to HTML file")

	rootCmd.AddCommand(discoverCmd)
}

func runDiscover(cmd *cobra.Command, args []string) error {
	start := time.Now()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		color.Yellow("\n[!] Discovery interrupted")
		cancel()
	}()

	fmt.Println(Banner())

	var cidr string
	if len(args) > 0 {
		cidr = args[0]
	} else {
		// Auto-detect from interface
		var err error
		cidr, err = discovery.SubnetFromInterface(discoverInterface)
		if err != nil {
			return fmt.Errorf("failed to detect subnet: %w\nSpecify a CIDR range manually, e.g., netwatch discover 192.168.1.0/24", err)
		}
		color.Cyan("[*] Auto-detected subnet: %s", cidr)
	}

	color.Cyan("[*] Network discovery: %s", cidr)
	color.Cyan("[*] Workers: %d", workers)
	fmt.Println()

	hd := discovery.NewHostDiscovery(time.Duration(timeout)*time.Second, workers)

	// We don't know the total count upfront without expanding, so use a spinner-style bar
	bar := progressbar.NewOptions(-1,
		progressbar.OptionSetDescription("    Discovering hosts"),
		progressbar.OptionSpinnerType(14),
		progressbar.OptionShowCount(),
	)

	hosts, err := hd.PingSweep(ctx, cidr, func(done int) {
		bar.Set(done) //nolint:errcheck
	})
	bar.Finish() //nolint:errcheck
	fmt.Println()

	if err != nil && ctx.Err() != nil {
		return fmt.Errorf("discovery cancelled")
	}

	color.Green("[+] Found %d live hosts", len(hosts))
	fmt.Println()

	if len(hosts) > 0 {
		printHostTable(hosts)
	}

	// Save outputs
	if discoverOutputJSON != "" || discoverOutputHTML != "" {
		scanReport := &models.ScanReport{
			ID:        fmt.Sprintf("nw-disc-%d", time.Now().UnixNano()),
			StartTime: start,
			EndTime:   time.Now(),
			Duration:  time.Since(start).Round(time.Millisecond).String(),
			Target:    cidr,
			Hosts:     hosts,
		}
		scanReport.Summary = report.ComputeSummary(scanReport)

		if discoverOutputJSON != "" {
			if err := report.SaveJSON(discoverOutputJSON, scanReport); err != nil {
				color.Red("[!] Failed to save JSON: %v", err)
			} else {
				color.Green("[+] JSON report saved to %s", discoverOutputJSON)
			}
		}

		if discoverOutputHTML != "" {
			if err := report.SaveHTML(discoverOutputHTML, scanReport); err != nil {
				color.Red("[!] Failed to save HTML: %v", err)
			} else {
				color.Green("[+] HTML report saved to %s", discoverOutputHTML)
			}
		}
	}

	return nil
}

func printHostTable(hosts []models.Host) {
	bold := color.New(color.Bold)
	bold.Printf("    %-18s %-30s %-15s\n", "IP ADDRESS", "HOSTNAME", "LATENCY")
	bold.Printf("    %-18s %-30s %-15s\n", "----------", "--------", "-------")

	for _, h := range hosts {
		hostname := h.Hostname
		if hostname == "" {
			hostname = "-"
		}
		latency := h.Latency
		if latency == "" {
			latency = "-"
		}
		fmt.Printf("    %-18s %-30s %-15s\n", h.IP, hostname, latency)
	}
}
