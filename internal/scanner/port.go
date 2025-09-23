// Package scanner implements TCP port scanning with configurable concurrency.
package scanner

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/SafiullahRattar/netwatch/internal/models"
)

// PortScanner performs TCP connect scanning on target hosts.
type PortScanner struct {
	timeout   time.Duration
	workers   int
	rateLimit time.Duration // minimum delay between connection attempts
}

// NewPortScanner creates a new PortScanner with the given configuration.
func NewPortScanner(timeout time.Duration, workers int, rateLimit int) *PortScanner {
	var rateDuration time.Duration
	if rateLimit > 0 {
		rateDuration = time.Second / time.Duration(rateLimit)
	}
	return &PortScanner{
		timeout:   timeout,
		workers:   workers,
		rateLimit: rateDuration,
	}
}

// ScanPort checks if a single port is open on the target host.
func (ps *PortScanner) ScanPort(ctx context.Context, host string, port int) models.PortResult {
	result := models.PortResult{
		Port:  port,
		State: models.PortClosed,
	}

	address := net.JoinHostPort(host, strconv.Itoa(port))

	dialer := &net.Dialer{Timeout: ps.timeout}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		if ctx.Err() != nil {
			result.State = models.PortFiltered
			return result
		}
		// Check for timeout / filtered
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			result.State = models.PortFiltered
		}
		return result
	}
	defer conn.Close()

	result.State = models.PortOpen
	result.Service = WellKnownService(port)

	return result
}

// Scan scans a range of ports on the target host using a worker pool.
func (ps *PortScanner) Scan(ctx context.Context, host string, ports []int, progressFn func(done int)) ([]models.PortResult, error) {
	var (
		results []models.PortResult
		mu      sync.Mutex
		wg      sync.WaitGroup
		done    int
	)

	portChan := make(chan int, len(ports))
	for _, p := range ports {
		portChan <- p
	}
	close(portChan)

	// Launch worker goroutines
	workerCount := ps.workers
	if workerCount > len(ports) {
		workerCount = len(ports)
	}

	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range portChan {
				select {
				case <-ctx.Done():
					return
				default:
				}

				result := ps.ScanPort(ctx, host, port)

				mu.Lock()
				results = append(results, result)
				done++
				if progressFn != nil {
					progressFn(done)
				}
				mu.Unlock()

				// Rate limiting
				if ps.rateLimit > 0 {
					time.Sleep(ps.rateLimit)
				}
			}
		}()
	}

	wg.Wait()

	return results, ctx.Err()
}

// ParsePortRange parses a port range string into a slice of port numbers.
// Supported formats: "80", "80,443", "1-1024", "80,443,8000-9000"
func ParsePortRange(portRange string) ([]int, error) {
	if portRange == "" {
		return nil, fmt.Errorf("empty port range")
	}

	var ports []int
	seen := make(map[int]bool)

	parts := strings.Split(portRange, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		if strings.Contains(part, "-") {
			rangeParts := strings.SplitN(part, "-", 2)
			start, err := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
			if err != nil {
				return nil, fmt.Errorf("invalid port number: %s", rangeParts[0])
			}
			end, err := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
			if err != nil {
				return nil, fmt.Errorf("invalid port number: %s", rangeParts[1])
			}

			if start < 1 || start > 65535 || end < 1 || end > 65535 {
				return nil, fmt.Errorf("port numbers must be between 1 and 65535")
			}
			if start > end {
				return nil, fmt.Errorf("invalid port range: start (%d) > end (%d)", start, end)
			}

			for p := start; p <= end; p++ {
				if !seen[p] {
					ports = append(ports, p)
					seen[p] = true
				}
			}
		} else {
			port, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("invalid port number: %s", part)
			}
			if port < 1 || port > 65535 {
				return nil, fmt.Errorf("port number %d out of range (1-65535)", port)
			}
			if !seen[port] {
				ports = append(ports, port)
				seen[port] = true
			}
		}
	}

	if len(ports) == 0 {
		return nil, fmt.Errorf("no valid ports specified")
	}

	return ports, nil
}

// CommonPorts returns a list of commonly used ports for quick scanning.
func CommonPorts() []int {
	return []int{
		21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
		143, 443, 445, 993, 995, 1723, 3306, 3389,
		5432, 5900, 6379, 8080, 8443, 8888, 9090, 27017,
	}
}

// WellKnownService returns the well-known service name for a port, if any.
func WellKnownService(port int) string {
	services := map[int]string{
		21:    "ftp",
		22:    "ssh",
		23:    "telnet",
		25:    "smtp",
		53:    "dns",
		80:    "http",
		110:   "pop3",
		111:   "rpcbind",
		135:   "msrpc",
		139:   "netbios-ssn",
		143:   "imap",
		443:   "https",
		445:   "microsoft-ds",
		993:   "imaps",
		995:   "pop3s",
		1723:  "pptp",
		3306:  "mysql",
		3389:  "ms-wbt-server",
		5432:  "postgresql",
		5900:  "vnc",
		6379:  "redis",
		8080:  "http-proxy",
		8443:  "https-alt",
		8888:  "http-alt",
		9090:  "zeus-admin",
		27017: "mongodb",
	}
	if s, ok := services[port]; ok {
		return s
	}
	return ""
}
