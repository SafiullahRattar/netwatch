#!/usr/bin/env bash
# Example: Scan localhost for common open ports
# This is a safe example that only scans your own machine.

set -euo pipefail

echo "=== Netwatch Example: Localhost Scan ==="
echo ""

# Basic port scan of common ports
echo "[1] Quick scan of common ports on localhost..."
netwatch scan 127.0.0.1 -p 22,80,443,3306,5432,6379,8080 -w 10

echo ""
echo "[2] Full scan with service detection..."
netwatch scan 127.0.0.1 -p 1-1024 --service -o localhost-scan.json

echo ""
echo "[3] Generate HTML report from JSON..."
netwatch report -i localhost-scan.json --html localhost-report.html

echo ""
echo "Done! Check localhost-scan.json and localhost-report.html"
