package discovery

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestExpandCIDR_SingleIP(t *testing.T) {
	ips, err := expandCIDR("192.168.1.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ips) != 1 || ips[0] != "192.168.1.1" {
		t.Fatalf("expected [192.168.1.1], got %v", ips)
	}
}

func TestExpandCIDR_Slash24(t *testing.T) {
	ips, err := expandCIDR("192.168.1.0/24")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// /24 = 256 addresses - 2 (network + broadcast) = 254
	if len(ips) != 254 {
		t.Fatalf("expected 254 IPs for /24, got %d", len(ips))
	}
	if ips[0] != "192.168.1.1" {
		t.Errorf("first IP should be 192.168.1.1, got %s", ips[0])
	}
	if ips[len(ips)-1] != "192.168.1.254" {
		t.Errorf("last IP should be 192.168.1.254, got %s", ips[len(ips)-1])
	}
}

func TestExpandCIDR_Slash30(t *testing.T) {
	ips, err := expandCIDR("10.0.0.0/30")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// /30 = 4 addresses - 2 = 2
	if len(ips) != 2 {
		t.Fatalf("expected 2 IPs for /30, got %d", len(ips))
	}
}

func TestExpandCIDR_Invalid(t *testing.T) {
	_, err := expandCIDR("not-an-ip")
	if err == nil {
		t.Fatal("expected error for invalid input")
	}
}

func TestExpandCIDR_InvalidCIDR(t *testing.T) {
	_, err := expandCIDR("192.168.1.0/99")
	if err == nil {
		t.Fatal("expected error for invalid CIDR")
	}
}

func TestContainsSlash(t *testing.T) {
	if !containsSlash("192.168.1.0/24") {
		t.Error("expected true for CIDR notation")
	}
	if containsSlash("192.168.1.1") {
		t.Error("expected false for plain IP")
	}
}

func TestIncrementIP(t *testing.T) {
	ip := net.ParseIP("192.168.1.1").To4()
	incrementIP(ip)
	if ip.String() != "192.168.1.2" {
		t.Errorf("expected 192.168.1.2, got %s", ip.String())
	}
}

func TestIncrementIP_Rollover(t *testing.T) {
	ip := net.ParseIP("192.168.1.255").To4()
	incrementIP(ip)
	if ip.String() != "192.168.2.0" {
		t.Errorf("expected 192.168.2.0, got %s", ip.String())
	}
}

func TestNewHostDiscovery(t *testing.T) {
	hd := NewHostDiscovery(2*time.Second, 10)
	if hd == nil {
		t.Fatal("NewHostDiscovery returned nil")
	}
	if hd.timeout != 2*time.Second {
		t.Errorf("expected timeout 2s, got %v", hd.timeout)
	}
	if hd.workers != 10 {
		t.Errorf("expected 10 workers, got %d", hd.workers)
	}
}

func TestProbeHost_Localhost(t *testing.T) {
	// Start a temporary TCP listener on localhost
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	hd := NewHostDiscovery(1*time.Second, 1)
	host := hd.probeHost(context.Background(), "127.0.0.1")

	// Localhost may or may not have common ports open depending on the system,
	// so we just verify the structure is correct
	if host.IP != "127.0.0.1" {
		t.Errorf("expected IP 127.0.0.1, got %s", host.IP)
	}
}

func TestPingSweep_CancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	hd := NewHostDiscovery(500*time.Millisecond, 4)
	hosts, _ := hd.PingSweep(ctx, "192.168.1.0/24", nil)

	// Should return quickly with no or few results
	t.Logf("got %d hosts with cancelled context", len(hosts))
}
