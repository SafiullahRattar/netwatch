# Netwatch

A network security monitoring and vulnerability scanning tool written in Go, designed for authorized penetration testing, security audits, and infrastructure hardening.

> **DISCLAIMER:** This tool is intended for **authorized security testing only**. You must have explicit written permission from the system owner before scanning any network or host. Unauthorized scanning of computer systems is illegal under the Computer Fraud and Abuse Act (CFAA) and equivalent laws in other jurisdictions. The authors assume no liability for misuse of this software.

## Features

| Feature | Description |
|---|---|
| **Port Scanner** | TCP connect scanning with configurable concurrency, timeout, and port ranges. Supports single ports, ranges, and mixed notation. |
| **Service Detection** | Banner grabbing to identify services (SSH, FTP, SMTP, HTTP, MySQL, PostgreSQL, Redis) and extract version information. |
| **TLS/SSL Analysis** | Certificate chain validation, expiry checking, cipher suite enumeration, protocol version detection (TLS 1.0 through 1.3). |
| **CVE Lookup** | Query the NIST National Vulnerability Database (NVD) API for known vulnerabilities based on detected service versions. |
| **Network Discovery** | TCP-based host discovery via probe sweeps on common ports across subnets (CIDR notation). |
| **HTTP Security Headers** | Analyze web servers for missing security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, and more). |
| **Report Generation** | Export results as structured JSON or formatted HTML reports with severity ratings and remediation guidance. |
| **Concurrent Scanning** | Goroutine worker pool with configurable concurrency and rate limiting to avoid overwhelming targets. |

## Architecture

```
                              +------------------+
                              |    CLI (Cobra)   |
                              |  scan | tls |    |
                              | discover | report|
                              +--------+---------+
                                       |
                              +--------+---------+
                              |  Scanner Engine  |
                              +--------+---------+
                                       |
              +------------------------+------------------------+
              |            |           |           |            |
     +--------+--+ +------+------+ +--+-------+ +-+--------+ +-+----------+
     |   Port    | |   Service   | |   TLS    | |   CVE    | |   HTTP     |
     |  Scanner  | |  Detector   | | Analyzer | |  Lookup  | |  Headers   |
     +-----------+ +-------------+ +----------+ +----------+ +------------+
              |            |           |           |            |
              +------------------------+------------------------+
                                       |
                              +--------+---------+
                              | Report Generator |
                              |  JSON  |  HTML   |
                              +------------------+
```

## Installation

### From Source

```bash
go install github.com/SafiullahRattar/netwatch@latest
```

Or clone and build:

```bash
git clone https://github.com/SafiullahRattar/netwatch.git
cd netwatch
go build -o netwatch .
```

### Docker

```bash
docker build -t netwatch .
docker run --rm netwatch scan example.com -p 80,443
```

## Usage

### Port Scanning

```bash
# Scan common ports (1-1024)
netwatch scan example.com

# Scan specific ports
netwatch scan example.com -p 80,443,8080

# Scan a range with service detection
netwatch scan example.com -p 1-65535 --service -w 500

# Full scan with all checks, save reports
netwatch scan example.com --all -o report.json --html report.html
```

### TLS/SSL Analysis

```bash
# Analyze TLS configuration
netwatch tls example.com

# Analyze non-standard port
netwatch tls example.com --port 8443

# Save TLS analysis results
netwatch tls example.com -o tls-report.json
```

### Network Discovery

```bash
# Discover hosts on a subnet
netwatch discover 192.168.1.0/24

# Auto-detect local subnet
netwatch discover

# Specify network interface
netwatch discover --interface eth0

# Save discovery results
netwatch discover 10.0.0.0/24 -o hosts.json
```

### Report Generation

```bash
# Convert JSON report to HTML
netwatch report -i scan-results.json --html report.html
```

### Global Options

```
  -w, --workers int    Number of concurrent workers (default 100)
  -t, --timeout int    Connection timeout in seconds (default 3)
  -v, --verbose        Enable verbose output
```

## Sample Output

### Port Scan

```
  Netwatch - Network Security Monitor & Vulnerability Scanner

[*] Target: example.com
[*] Port range: 1-1024
[*] Workers: 100

[+] Phase 1: Port scanning (1024 ports)
    Scanning ports [========================================] 1024/1024

[+] Found 3 open ports out of 1024 scanned

    PORT     STATE      SERVICE         VERSION              BANNER
    ----     -----      -------         -------              ------
    22       open       ssh             OpenSSH_8.9p1        SSH-2.0-OpenSSH_8.9p1
    80       open       http            nginx/1.24.0         -
    443      open       https           nginx/1.24.0         -

============================================================
  Scan Summary
============================================================
  Target:     example.com
  Duration:   12.5s
  Ports:      1024 scanned, 3 open, 1021 closed, 0 filtered
  Findings:   3 total (0 critical, 1 high, 1 medium, 1 low)
============================================================
```

### TLS Analysis

```
  Connection
    Protocol Version:   TLS 1.3
    Cipher Suite:       TLS_AES_256_GCM_SHA384

  Certificate
    Subject:            CN=example.com
    Issuer:             CN=R3,O=Let's Encrypt,C=US
    Not After:          2024-05-27 (89 days remaining)
    Self-Signed:        No
    SANs:               example.com, www.example.com

  Protocol Support
    [+] TLS 1.2
    [+] TLS 1.3
```

## Severity Ratings

| Level | Criteria |
|---|---|
| **Critical** | Known CVEs with CVSS >= 9.0, deprecated TLS versions (1.0/1.1) |
| **High** | Missing critical security headers (HSTS, CSP, X-Frame-Options), weak ciphers, expired certificates |
| **Medium** | Self-signed certificates, missing recommended headers, CSP misconfigurations |
| **Low** | Informational findings, server version disclosure, optional headers |

## Configuration

### Environment Variables

| Variable | Description |
|---|---|
| `NVD_API_KEY` | Optional NVD API key for higher rate limits (50 req/30s vs 5 req/30s). Register at https://nvd.nist.gov/developers/request-an-api-key |

### Rate Limiting

Use the `--rate-limit` flag to cap the number of requests per second:

```bash
netwatch scan example.com --rate-limit 100
```

## Project Structure

```
netwatch/
├── main.go                          # Entry point
├── cmd/                             # CLI commands (Cobra)
│   ├── root.go                      # Root command and global flags
│   ├── scan.go                      # Port scan command
│   ├── tls.go                       # TLS analysis command
│   ├── discover.go                  # Network discovery command
│   └── report.go                    # Report generation command
├── internal/
│   ├── scanner/                     # Port scanning and service detection
│   │   ├── port.go                  # TCP connect scanner with worker pool
│   │   ├── port_test.go
│   │   ├── service.go               # Banner grabbing and service ID
│   │   └── service_test.go
│   ├── tls/                         # TLS/SSL analysis
│   │   ├── analyzer.go              # Certificate and cipher analysis
│   │   └── analyzer_test.go
│   ├── discovery/                   # Network host discovery
│   │   ├── host.go                  # TCP probe sweep
│   │   └── host_test.go
│   ├── cve/                         # CVE lookup
│   │   ├── nvd.go                   # NVD API client
│   │   └── nvd_test.go
│   ├── headers/                     # HTTP security headers
│   │   ├── checker.go               # Header analysis
│   │   └── checker_test.go
│   ├── report/                      # Report generation
│   │   ├── json.go                  # JSON output
│   │   ├── html.go                  # HTML output with embedded template
│   │   └── templates/
│   │       └── report.html          # HTML report template
│   └── models/
│       └── types.go                 # Core data types
├── test/
│   └── integration_test.go          # End-to-end integration tests
├── examples/
│   ├── scan_localhost.sh            # Example scan script
│   └── sample_report.json           # Sample JSON report output
├── Dockerfile                       # Multi-stage Docker build
├── go.mod
└── go.sum
```

## Development

```bash
# Run tests
go test ./...

# Build
go build -o netwatch .

# Run with race detector
go run -race . scan 127.0.0.1 -p 22,80,443
```

## License

MIT
