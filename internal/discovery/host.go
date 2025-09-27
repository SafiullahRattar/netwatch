// Package discovery implements network host discovery via ping sweep and ARP.
package discovery

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/SafiullahRattar/netwatch/internal/models"
)

// HostDiscovery performs network host discovery using TCP connect probes and ping sweeps.
type HostDiscovery struct {
	timeout time.Duration
	workers int
}

// NewHostDiscovery creates a new HostDiscovery instance.
func NewHostDiscovery(timeout time.Duration, workers int) *HostDiscovery {
	return &HostDiscovery{
		timeout: timeout,
		workers: workers,
	}
}

// PingSweep performs a TCP-based "ping sweep" by attempting to connect to common
// ports on each host in the given subnet. This does not require raw sockets or
// root privileges, unlike ICMP ping.
func (hd *HostDiscovery) PingSweep(ctx context.Context, cidr string, progressFn func(done int)) ([]models.Host, error) {
	ips, err := expandCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR: %w", err)
	}

	var (
		results []models.Host
		mu      sync.Mutex
		wg      sync.WaitGroup
		done    int
	)

	ipChan := make(chan string, len(ips))
	for _, ip := range ips {
		ipChan <- ip
	}
	close(ipChan)

	workerCount := hd.workers
	if workerCount > len(ips) {
		workerCount = len(ips)
	}

	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range ipChan {
				select {
				case <-ctx.Done():
					return
				default:
				}

				host := hd.probeHost(ctx, ip)

				mu.Lock()
				results = append(results, host)
				done++
				if progressFn != nil {
					progressFn(done)
				}
				mu.Unlock()
			}
		}()
	}

	wg.Wait()

	// Filter to only alive hosts
	var alive []models.Host
	for _, h := range results {
		if h.Alive {
			alive = append(alive, h)
		}
	}

	return alive, ctx.Err()
}

// probeHost checks if a host is alive by trying to connect to common ports.
func (hd *HostDiscovery) probeHost(ctx context.Context, ip string) models.Host {
	host := models.Host{
		IP:    ip,
		Alive: false,
	}

	// Try to resolve hostname
	names, err := net.LookupAddr(ip)
	if err == nil && len(names) > 0 {
		host.Hostname = names[0]
	}

	// TCP probe on common ports
	probePorts := []int{80, 443, 22, 445, 139, 3389}

	for _, port := range probePorts {
		select {
		case <-ctx.Done():
			return host
		default:
		}

		address := fmt.Sprintf("%s:%d", ip, port)
		start := time.Now()
		conn, err := net.DialTimeout("tcp", address, hd.timeout)
		if err == nil {
			host.Alive = true
			host.Latency = time.Since(start).Round(time.Microsecond).String()
			conn.Close()
			return host
		}
	}

	return host
}

// expandCIDR expands a CIDR notation string into a list of individual IP addresses.
func expandCIDR(cidr string) ([]string, error) {
	// Handle single IP address
	if !containsSlash(cidr) {
		if ip := net.ParseIP(cidr); ip != nil {
			return []string{cidr}, nil
		}
		return nil, fmt.Errorf("invalid IP address: %s", cidr)
	}

	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := ip.Mask(ipNet.Mask); ipNet.Contains(ip); incrementIP(ip) {
		ips = append(ips, ip.String())
	}

	if len(ips) <= 2 {
		return ips, nil
	}

	// Remove network and broadcast addresses for /24 and larger
	return ips[1 : len(ips)-1], nil
}

// incrementIP increments an IP address by one.
func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// containsSlash checks if a string contains a forward slash.
func containsSlash(s string) bool {
	for _, c := range s {
		if c == '/' {
			return true
		}
	}
	return false
}

// SubnetFromInterface returns the CIDR notation for the subnet of the given
// network interface, or the first non-loopback interface if name is empty.
func SubnetFromInterface(name string) (string, error) {
	var iface *net.Interface
	var err error

	if name != "" {
		iface, err = net.InterfaceByName(name)
		if err != nil {
			return "", fmt.Errorf("interface %q not found: %w", name, err)
		}
	} else {
		interfaces, err := net.Interfaces()
		if err != nil {
			return "", fmt.Errorf("failed to list interfaces: %w", err)
		}
		for i := range interfaces {
			if interfaces[i].Flags&net.FlagLoopback != 0 {
				continue
			}
			if interfaces[i].Flags&net.FlagUp == 0 {
				continue
			}
			iface = &interfaces[i]
			break
		}
	}

	if iface == nil {
		return "", fmt.Errorf("no suitable network interface found")
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return "", fmt.Errorf("failed to get addresses for %s: %w", iface.Name, err)
	}

	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok && ipNet.IP.To4() != nil {
			return addr.String(), nil
		}
	}

	return "", fmt.Errorf("no IPv4 address found on interface %s", iface.Name)
}
