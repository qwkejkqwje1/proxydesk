package dns

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/proxydesk/proxydesk/internal/model"
	"github.com/proxydesk/proxydesk/internal/rules"
)

// buildMockDNSAnswer constructs a valid RFC 1035 DNS answer wire packet for testing.
func buildMockDNSAnswer(query []byte, rcode uint8, truncated bool, ip net.IP, ttl uint32) []byte {
	var buf bytes.Buffer
	hdr := make([]byte, 12)
	copy(hdr, query[:12])
	flags := uint16(0x8180) | uint16(rcode&0x0F)
	if truncated {
		flags |= 0x0200 // TC=1
	}
	binary.BigEndian.PutUint16(hdr[2:4], flags)
	if ip != nil {
		binary.BigEndian.PutUint16(hdr[6:8], 1) // ANCOUNT=1
	} else {
		binary.BigEndian.PutUint16(hdr[6:8], 0)
	}
	buf.Write(hdr)
	// Echo Question section
	buf.Write(query[12:])
	if ip4 := ip.To4(); ip4 != nil {
		// Name pointer 0xC00C, Type A(1), Class IN(1), TTL, RDLENGTH=4, RDATA
		ans := make([]byte, 16)
		binary.BigEndian.PutUint16(ans[0:2], 0xC00C)
		binary.BigEndian.PutUint16(ans[2:4], TypeA)
		binary.BigEndian.PutUint16(ans[4:6], 1)
		binary.BigEndian.PutUint32(ans[6:10], ttl)
		binary.BigEndian.PutUint16(ans[10:12], 4)
		copy(ans[12:16], ip4)
		buf.Write(ans)
	}
	return buf.Bytes()
}

func startMockUDPDNS(t *testing.T, handler func(q []byte) []byte) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			resp := handler(buf[:n])
			if resp != nil {
				_, _ = pc.WriteTo(resp, addr)
			}
		}
	}()
	return pc.LocalAddr().String()
}

func TestInvariant_DNSCacheIsolatedByPolicyAndNXDomainDoesNotTriggerFallback(t *testing.T) {
	clk := model.NewFakeClock(time.Date(2026, 10, 13, 16, 0, 0, 0, time.UTC))
	srv := NewServer(clk, 1024, true, nil)

	var fallbackHits atomic.Int32

	// Group 1 primary returns 10.10.10.1
	g1Addr := startMockUDPDNS(t, func(q []byte) []byte {
		return buildMockDNSAnswer(q, RcodeSuccess, false, net.ParseIP("10.10.10.1"), 120)
	})
	// Group 2 primary returns 203.0.113.200
	g2Addr := startMockUDPDNS(t, func(q []byte) []byte {
		return buildMockDNSAnswer(q, RcodeSuccess, false, net.ParseIP("203.0.113.200"), 120)
	})
	// NXDOMAIN primary + fallback upstream (to prove NXDOMAIN never triggers fallback!)
	nxPrimary := startMockUDPDNS(t, func(q []byte) []byte {
		return buildMockDNSAnswer(q, RcodeNXDomain, false, nil, 60)
	})
	nxFallback := startMockUDPDNS(t, func(q []byte) []byte {
		fallbackHits.Add(1)
		return buildMockDNSAnswer(q, RcodeSuccess, false, net.ParseIP("198.51.100.88"), 60)
	})

	groups := []DNSGroup{
		{ID: 1, Name: "Corp DNS", Upstreams: []UpstreamEndpoint{{Protocol: "udp", Address: g1Addr}}},
		{ID: 2, Name: "Public DNS", Upstreams: []UpstreamEndpoint{{Protocol: "udp", Address: g2Addr}}},
		{ID: 3, Name: "NX Test Group", Upstreams: []UpstreamEndpoint{
			{Protocol: "udp", Address: nxPrimary},
			{Protocol: "udp", Address: nxFallback},
		}},
	}
	dnsRules := []rules.DNSRule{
		{ID: 1, Priority: 10, Enabled: true, MatchType: rules.MatchExact, Pattern: "shared.example.com", Action: "group", DNSGroupID: 1},
	}
	srv.SetConfig(groups, 2, dnsRules, true)

	// 1. Resolve shared.example.com under Group 1 (gets 10.10.10.1 and caches under group:1)
	ips1, rcode1, _, err := srv.Resolve(context.Background(), "shared.example.com", TypeA)
	if err != nil || rcode1 != RcodeSuccess || len(ips1) != 1 || !ips1[0].Equal(net.ParseIP("10.10.10.1")) {
		t.Fatalf("expected 10.10.10.1 from group 1, got ips=%v rcode=%d err=%v", ips1, rcode1, err)
	}

	// 2. Switch rule to Group 2 for shared.example.com: MUST NOT return Group 1's cached 10.10.10.1 (INV-06!)
	dnsRules[0].DNSGroupID = 2
	srv.SetConfig(groups, 2, dnsRules, true)
	ips2, rcode2, _, err := srv.Resolve(context.Background(), "shared.example.com", TypeA)
	if err != nil || rcode2 != RcodeSuccess || len(ips2) != 1 || !ips2[0].Equal(net.ParseIP("203.0.113.200")) {
		t.Fatalf("INV-06 violated: expected 203.0.113.200 from group 2, got %v", ips2)
	}

	// 3. NXDOMAIN on Group 3 primary must NOT trigger nxFallback
	dnsRules[0].DNSGroupID = 3
	srv.SetConfig(groups, 2, dnsRules, true)
	_, rcodeNX, _, err := srv.Resolve(context.Background(), "shared.example.com", TypeA)
	if err != nil || rcodeNX != RcodeNXDomain {
		t.Fatalf("expected NXDOMAIN without error, got rcode=%d err=%v", rcodeNX, err)
	}
	if fallbackHits.Load() != 0 {
		t.Fatalf("NXDOMAIN triggered fallback upstream (%d hits)!", fallbackHits.Load())
	}

	// 4. Internal domain with dead upstream must refuse public fallback (ErrInternalDomainFallback)
	deadGroups := []DNSGroup{
		{ID: 4, Name: "Dead Internal", AllowPublicFallback: false, Upstreams: []UpstreamEndpoint{{Protocol: "udp", Address: "127.0.0.1:1"}}},
	}
	srv.SetConfig(deadGroups, 4, nil, true)
	_, _, _, errInt := srv.Resolve(context.Background(), "git.corp.local", TypeA)
	if !errors.Is(errInt, ErrInternalDomainFallback) {
		t.Fatalf("expected ErrInternalDomainFallback for internal domain, got %v", errInt)
	}
}
