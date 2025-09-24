package scanner

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/SafiullahRattar/netwatch/internal/models"
)

// ServiceDetector performs banner grabbing and service identification.
type ServiceDetector struct {
	timeout time.Duration
}

// NewServiceDetector creates a new ServiceDetector with the given timeout.
func NewServiceDetector(timeout time.Duration) *ServiceDetector {
	return &ServiceDetector{timeout: timeout}
}

// DetectService attempts to identify the service running on an open port
// by connecting and reading the service banner.
func (sd *ServiceDetector) DetectService(ctx context.Context, host string, port int) models.PortResult {
	result := models.PortResult{
		Port:    port,
		State:   models.PortOpen,
		Service: WellKnownService(port),
	}

	address := net.JoinHostPort(host, strconv.Itoa(port))
	dialer := &net.Dialer{Timeout: sd.timeout}

	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		result.State = models.PortClosed
		return result
	}
	defer conn.Close()

	// Set read deadline for banner grabbing
	if err := conn.SetReadDeadline(time.Now().Add(sd.timeout)); err != nil {
		return result
	}

	// Try to read a banner (many services send one upon connection)
	banner := sd.readBanner(conn)
	if banner != "" {
		result.Banner = banner
		service, version := sd.parseBanner(banner, port)
		if service != "" {
			result.Service = service
		}
		result.Version = version
	}

	// If no banner, try sending protocol-specific probes
	if banner == "" {
		result = sd.probeService(ctx, host, port, result)
	}

	return result
}

// readBanner reads the initial banner sent by a service upon connection.
func (sd *ServiceDetector) readBanner(conn net.Conn) string {
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		// Try reading whatever bytes are available
		buf := make([]byte, 1024)
		n, _ := reader.Read(buf)
		if n > 0 {
			return sanitizeBanner(string(buf[:n]))
		}
		return ""
	}
	return sanitizeBanner(line)
}

// parseBanner extracts service name and version from a banner string.
func (sd *ServiceDetector) parseBanner(banner string, port int) (service, version string) {
	lower := strings.ToLower(banner)

	// SSH detection
	if strings.HasPrefix(lower, "ssh-") {
		service = "ssh"
		re := regexp.MustCompile(`SSH-[\d.]+-([\w_.-]+)`)
		if matches := re.FindStringSubmatch(banner); len(matches) > 1 {
			version = matches[1]
		}
		return
	}

	// FTP detection
	if strings.HasPrefix(banner, "220") && (strings.Contains(lower, "ftp") || port == 21) {
		service = "ftp"
		re := regexp.MustCompile(`220[- ](.+)`)
		if matches := re.FindStringSubmatch(banner); len(matches) > 1 {
			version = strings.TrimSpace(matches[1])
		}
		return
	}

	// SMTP detection
	if strings.HasPrefix(banner, "220") && (strings.Contains(lower, "smtp") || strings.Contains(lower, "mail") || port == 25) {
		service = "smtp"
		re := regexp.MustCompile(`220[- ](.+)`)
		if matches := re.FindStringSubmatch(banner); len(matches) > 1 {
			version = strings.TrimSpace(matches[1])
		}
		return
	}

	// MySQL detection
	if port == 3306 || strings.Contains(lower, "mysql") || strings.Contains(lower, "mariadb") {
		service = "mysql"
		re := regexp.MustCompile(`([\d]+\.[\d]+\.[\d]+[\w.-]*)`)
		if matches := re.FindStringSubmatch(banner); len(matches) > 1 {
			version = matches[1]
		}
		return
	}

	// Redis detection
	if strings.Contains(lower, "redis") || port == 6379 {
		service = "redis"
		re := regexp.MustCompile(`redis_version:([\d.]+)`)
		if matches := re.FindStringSubmatch(banner); len(matches) > 1 {
			version = matches[1]
		}
		return
	}

	// PostgreSQL detection
	if port == 5432 || strings.Contains(lower, "postgresql") {
		service = "postgresql"
		return
	}

	// HTTP detection
	if strings.HasPrefix(lower, "http/") || strings.Contains(lower, "html") {
		service = "http"
		re := regexp.MustCompile(`Server:\s*(.+)`)
		if matches := re.FindStringSubmatch(banner); len(matches) > 1 {
			version = strings.TrimSpace(matches[1])
		}
		return
	}

	return "", ""
}

// probeService sends protocol-specific probes to identify the service.
func (sd *ServiceDetector) probeService(ctx context.Context, host string, port int, result models.PortResult) models.PortResult {
	address := net.JoinHostPort(host, strconv.Itoa(port))
	dialer := &net.Dialer{Timeout: sd.timeout}

	// Try HTTP probe
	if port == 80 || port == 8080 || port == 8443 || port == 443 || port == 8888 || port == 9090 {
		conn, err := dialer.DialContext(ctx, "tcp", address)
		if err != nil {
			return result
		}
		defer conn.Close()

		if err := conn.SetDeadline(time.Now().Add(sd.timeout)); err != nil {
			return result
		}

		httpReq := fmt.Sprintf("HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n", host)
		if _, err := conn.Write([]byte(httpReq)); err != nil {
			return result
		}

		reader := bufio.NewReader(conn)
		var headers []string
		for i := 0; i < 20; i++ {
			line, err := reader.ReadString('\n')
			if err != nil {
				break
			}
			headers = append(headers, strings.TrimSpace(line))
		}

		if len(headers) > 0 && strings.HasPrefix(headers[0], "HTTP/") {
			result.Service = "http"
			for _, h := range headers {
				if strings.HasPrefix(strings.ToLower(h), "server:") {
					result.Version = strings.TrimSpace(strings.SplitN(h, ":", 2)[1])
					break
				}
			}
			result.Banner = strings.Join(headers, "\n")
		}
	}

	return result
}

// sanitizeBanner cleans up a banner string by removing control characters.
func sanitizeBanner(banner string) string {
	banner = strings.TrimSpace(banner)
	// Remove null bytes and non-printable characters except newlines
	cleaned := strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return r
		}
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, banner)
	// Limit length
	if len(cleaned) > 512 {
		cleaned = cleaned[:512]
	}
	return cleaned
}
