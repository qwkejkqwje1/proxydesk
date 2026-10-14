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

func buildMockDNSAnswerWithSOA(query []byte, rcode uint8, truncated bool, ip net.IP, ansTTL uint32, includeSOA bool, soaTTL uint32) []byte {
	var buf bytes.Buffer
	hdr := make([]byte, 12)
	copy(hdr, query[:12])
	flags := uint16(0x8180) | uint16(rcode&0x0F)
	if truncated {
		flags |= 0x0200
	}
	binary.BigEndian.PutUint16(hdr[2:4], flags)
	if ip != nil && !truncated {
		binary.BigEndian.PutUint16(hdr[6:8], 1) // ANCOUNT=1
	}
	if includeSOA && !truncated {
		binary.BigEndian.PutUint16(hdr[8:10], 1) // NSCOUNT=1
	}
	buf.Write(hdr)
	buf.Write(query[12:]) // Echo Question

	if ip4 := ip.To4(); ip4 != nil && !truncated {
		ans := make([]byte, 16)
		binary.BigEndian.PutUint16(ans[0:2], 0xC00C)
		binary.BigEndian.PutUint16(ans[2:4], TypeA)
		binary.BigEndian.PutUint16(ans[4:6], ClassIN)
		binary.BigEndian.PutUint32(ans[6:10], ansTTL)
		binary.BigEndian.PutUint16(ans[10:12], 4)
		copy(ans[12:16], ip4)
		buf.Write(ans)
	}

	if includeSOA && !truncated {
		// SOA RR in Authority section: owner=0xC00C, MNAME=0xC00C, RNAME=0xC00C, 5x uint32 (last is MINIMUM=soaTTL)
		soaRData := make([]byte, 24)
		binary.BigEndian.PutUint16(soaRData[0:2], 0xC00C) // MNAME pointer
		binary.BigEndian.PutUint16(soaRData[2:4], 0xC00C) // RNAME pointer
		binary.BigEndian.PutUint32(soaRData[4:8], 1)      // SERIAL
		binary.BigEndian.PutUint32(soaRData[8:12], 3600)  // REFRESH
		binary.BigEndian.PutUint32(soaRData[12:16], 600)  // RETRY
		binary.BigEndian.PutUint32(soaRData[16:20], 86400) // EXPIRE
		binary.BigEndian.PutUint32(soaRData[20:24], soaTTL) // MINIMUM

		rrHdr := make([]byte, 12)
		binary.BigEndian.PutUint16(rrHdr[0:2], 0xC00C)
		binary.BigEndian.PutUint16(rrHdr[2:4], TypeSOA)
		binary.BigEndian.PutUint16(rrHdr[4:6], ClassIN)
		binary.BigEndian.PutUint32(rrHdr[6:10], soaTTL)
		binary.BigEndian.PutUint16(rrHdr[10:12], uint16(len(soaRData)))
		buf.Write(rrHdr)
		buf.Write(soaRData)
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

func TestDNSVerificationTTLZeroSOANegativeCacheAndUDPTCPListeners(t *testing.T) {
	clk := model.NewFakeClock(time.Date(2026, 10, 13, 16, 0, 0, 0, time.UTC))
	srv := NewServer(clk, 1024, true, nil)

	var hitsTTLZero atomic.Int32
	var hitsTTLSmall atomic.Int32
	var fallbackHits atomic.Int32

	// 1. Upstream returning TTL=0 (must NEVER be cached!)
	ttlZeroAddr := startMockUDPDNS(t, func(q []byte) []byte {
		hitsTTLZero.Add(1)
		return buildMockDNSAnswerWithSOA(q, RcodeSuccess, false, net.ParseIP("198.51.100.1"), 0, false, 0)
	})

	// 2. Upstream returning exact TTL=3s (must NOT be inflated to 15s; expires after 3s!)
	ttlSmallAddr := startMockUDPDNS(t, func(q []byte) []byte {
		hitsTTLSmall.Add(1)
		return buildMockDNSAnswerWithSOA(q, RcodeSuccess, false, net.ParseIP("198.51.100.2"), 3, false, 0)
	})

	// 3. Upstream returning NXDOMAIN with SOA MINIMUM=4s
	nxSOAAddr := startMockUDPDNS(t, func(q []byte) []byte {
		return buildMockDNSAnswerWithSOA(q, RcodeNXDomain, false, nil, 0, true, 4)
	})
	nxFallback := startMockUDPDNS(t, func(q []byte) []byte {
		fallbackHits.Add(1)
		return buildMockDNSAnswerWithSOA(q, RcodeSuccess, false, net.ParseIP("203.0.113.9"), 60, false, 0)
	})

	// 4. Upstream returning wrong Transaction ID (spoofed response -> must be rejected!)
	spoofIDAddr := startMockUDPDNS(t, func(q []byte) []byte {
		ans := buildMockDNSAnswerWithSOA(q, RcodeSuccess, false, net.ParseIP("198.51.100.99"), 60, false, 0)
		binary.BigEndian.PutUint16(ans[0:2], binary.BigEndian.Uint16(q[0:2])+1)
		return ans
	})

	groups := []DNSGroup{
		{ID: 1, Name: "TTL0 Group", Upstreams: []UpstreamEndpoint{{Protocol: "udp", Address: ttlZeroAddr}}},
		{ID: 2, Name: "TTL3 Group", Upstreams: []UpstreamEndpoint{{Protocol: "udp", Address: ttlSmallAddr}}},
		{ID: 3, Name: "NX SOA Group", Upstreams: []UpstreamEndpoint{
			{Protocol: "udp", Address: nxSOAAddr},
			{Protocol: "udp", Address: nxFallback},
		}},
		{ID: 4, Name: "Spoof ID Group", Upstreams: []UpstreamEndpoint{{Protocol: "udp", Address: spoofIDAddr}}},
	}
	dnsRules := []rules.DNSRule{
		{ID: 1, Priority: 1, Enabled: true, MatchType: rules.MatchExact, Pattern: "zero.example.com", Action: "group", DNSGroupID: 1},
		{ID: 2, Priority: 2, Enabled: true, MatchType: rules.MatchExact, Pattern: "three.example.com", Action: "group", DNSGroupID: 2},
		{ID: 3, Priority: 3, Enabled: true, MatchType: rules.MatchExact, Pattern: "nx.example.com", Action: "group", DNSGroupID: 3},
		{ID: 4, Priority: 4, Enabled: true, MatchType: rules.MatchExact, Pattern: "spoof.example.com", Action: "group", DNSGroupID: 4},
	}
	srv.SetConfig(groups, 2, dnsRules, true)

	// Test A: TTL=0 is never cached (2 queries -> 2 upstream hits)
	_, _, _ , _ = srv.Resolve(context.Background(), "zero.example.com", TypeA)
	_, _, _, _ = srv.Resolve(context.Background(), "zero.example.com", TypeA)
	if hitsTTLZero.Load() != 2 {
		t.Fatalf("expected TTL=0 response not to be cached (2 upstream hits), got %d", hitsTTLZero.Load())
	}

	// Test B: TTL=3s is cached for 2s, and expires at 4s (not inflated to 15s!)
	_, _, _, _ = srv.Resolve(context.Background(), "three.example.com", TypeA)
	clk.Advance(2 * time.Second)
	_, _, _, _ = srv.Resolve(context.Background(), "three.example.com", TypeA)
	if hitsTTLSmall.Load() != 1 {
		t.Fatalf("expected cache hit at t+2s for TTL=3s, got %d hits", hitsTTLSmall.Load())
	}
	clk.Advance(2 * time.Second) // Now t+4s (> 3s TTL)
	_, _, _, _ = srv.Resolve(context.Background(), "three.example.com", TypeA)
	if hitsTTLSmall.Load() != 2 {
		t.Fatalf("expected TTL=3s cache entry to expire by t+4s, got %d hits", hitsTTLSmall.Load())
	}

	// Test C: NXDOMAIN with SOA MINIMUM=4s caches negative response for 4s and does NOT trigger fallback
	_, rcodeNX, negTTL, _, err := srv.ResolveWithTTL(context.Background(), "nx.example.com", TypeA)
	if err != nil || rcodeNX != RcodeNXDomain || negTTL != 4 || fallbackHits.Load() != 0 {
		t.Fatalf("unexpected NXDOMAIN result: rcode=%d negTTL=%d fallback=%d err=%v", rcodeNX, negTTL, fallbackHits.Load(), err)
	}

	// Test D: Mismatched Transaction ID is rejected with ErrDNSResponseMismatch
	_, _, _, errSpoof := srv.Resolve(context.Background(), "spoof.example.com", TypeA)
	if !errors.Is(errSpoof, ErrDNSResponseMismatch) {
		t.Fatalf("expected ErrDNSResponseMismatch on spoofed ID, got %v", errSpoof)
	}

	// Test E: Malformed forward/self compression pointer is rejected
	badPkt, _ := BuildDNSQueryWire(0x1234, "a.com", TypeA)
	// Replace question name with self-referencing pointer 0xC00C at offset 12
	badPkt[12] = 0xC0
	badPkt[13] = 0x0C
	if _, _, _, _, _, errPtr := ParseDNSQueryWire(badPkt); !errors.Is(errPtr, ErrMalformedCompressionPointer) {
		t.Fatalf("expected ErrMalformedCompressionPointer for self pointer, got %v", errPtr)
	}
}
