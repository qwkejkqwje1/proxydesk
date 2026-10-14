package dns

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/proxydesk/proxydesk/internal/model"
	"github.com/proxydesk/proxydesk/internal/rules"
)

const (
	TypeA     uint16 = 1
	TypeCNAME uint16 = 5
	TypeAAAA  uint16 = 28

	RcodeSuccess  uint8 = 0
	RcodeFormat   uint8 = 1
	RcodeServFail uint8 = 2
	RcodeNXDomain uint8 = 3
	RcodeRefused  uint8 = 5
)

var (
	ErrNoUpstreamAvailable    = errors.New("all DNS upstreams in group failed transport check")
	ErrInternalDomainFallback = errors.New("refusing to leak internal domain to public fallback resolver")
)

type UpstreamEndpoint struct {
	Protocol string `json:"protocol"` // "udp", "tcp", "dot", "doh"
	Address  string `json:"address"`  // "1.1.1.1:53", "tls://dns.quad9.net:853", "https://cloudflare-dns.com/dns-query"
}

type DNSGroup struct {
	ID                  int                `json:"id"`
	Name                string             `json:"name"`
	Upstreams           []UpstreamEndpoint `json:"upstreams"`
	BootstrapIPs        []string           `json:"bootstrap_ips,omitempty"` // Used for DoH/DoT hostname bootstrap without circular dependency
	AllowPublicFallback bool               `json:"allow_public_fallback"`
}

type CachedDNSResponse struct {
	PolicyKey string
	QName     string
	QType     uint16
	Rcode     uint8
	IPs       []net.IP
	Wire      []byte
	ExpiresAt time.Time
	Negative  bool
}

type QueryLogEntry struct {
	Timestamp time.Time           `json:"timestamp"`
	QName     string              `json:"qname"`
	QType     uint16              `json:"qtype"`
	Rcode     uint8               `json:"rcode"`
	CacheHit  bool                `json:"cache_hit"`
	IPs       []string            `json:"ips,omitempty"`
	Trace     model.DecisionTrace `json:"trace"`
}

type Server struct {
	mu             sync.RWMutex
	clock          model.Clock
	maxCacheSize   int
	cache          map[string]CachedDNSResponse // Key: PolicyGroupID|qname|qtype (INV-06)
	groups         map[int]DNSGroup
	defaultGroupID int
	dnsRules       []rules.DNSRule
	enableQueryLog bool
	queryLog       []QueryLogEntry
	maxQueryLog    int
	rootCAs        *x509.CertPool
}

func NewServer(clock model.Clock, maxCacheSize int, enableQueryLog bool, customRootCAs *x509.CertPool) *Server {
	if clock == nil {
		clock = model.RealClock{}
	}
	if maxCacheSize <= 0 {
		maxCacheSize = 4096
	}
	return &Server{
		clock:          clock,
		maxCacheSize:   maxCacheSize,
		cache:          make(map[string]CachedDNSResponse),
		groups:         make(map[int]DNSGroup),
		defaultGroupID: 1,
		enableQueryLog: enableQueryLog,
		maxQueryLog:    200,
		rootCAs:        customRootCAs,
	}
}

func (s *Server) SetConfig(groups []DNSGroup, defaultGroupID int, dnsRules []rules.DNSRule, enableQueryLog bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.groups = make(map[int]DNSGroup, len(groups))
	for _, g := range groups {
		s.groups[g.ID] = g
	}
	s.defaultGroupID = defaultGroupID
	s.dnsRules = append([]rules.DNSRule(nil), dnsRules...)
	s.enableQueryLog = enableQueryLog
}

// CacheKey enforces INV-06: DNS responses cached under one policy group namespace
// can NEVER be returned to a query governed by another policy group.
func CacheKey(policyNamespace string, qname string, qtype uint16) string {
	return fmt.Sprintf("%s|%s|%d", policyNamespace, strings.ToLower(strings.TrimSuffix(strings.TrimSpace(qname), ".")), qtype)
}

// Resolve evaluates DNS rules, checks the policy-isolated TTL/negative cache,
// handles local_record/block actions, or queries the selected DNSGroup with UDP->TCP truncation retry
// and transport failover (without treating NXDOMAIN as a transport failure).
func (s *Server) Resolve(ctx context.Context, qname string, qtype uint16) ([]net.IP, uint8, model.DecisionTrace, error) {
	s.mu.RLock()
	rulesList := s.dnsRules
	defGroup := s.defaultGroupID
	groupsMap := s.groups
	s.mu.RUnlock()

	now := s.clock.Now()
	matchedRule, trace := rules.EvaluateDNS(qname, rulesList, defGroup, now)

	// 1. Action: block
	if matchedRule.Action == "block" {
		trace.SelectedCandidate = "block (NXDOMAIN)"
		s.recordQueryLog(qname, qtype, RcodeNXDomain, false, nil, trace)
		return nil, RcodeNXDomain, trace, nil
	}

	// 2. Action: local_record (hosts override)
	if matchedRule.Action == "local_record" {
		var ips []net.IP
		if qtype == TypeA && matchedRule.LocalIPv4 != "" {
			if ip := net.ParseIP(matchedRule.LocalIPv4); ip != nil {
				ips = append(ips, ip)
			}
		} else if qtype == TypeAAAA && matchedRule.LocalIPv6 != "" {
			if ip := net.ParseIP(matchedRule.LocalIPv6); ip != nil {
				ips = append(ips, ip)
			}
		}
		trace.SelectedCandidate = "local_record"
		s.recordQueryLog(qname, qtype, RcodeSuccess, false, ips, trace)
		return ips, RcodeSuccess, trace, nil
	}

	// 3. Action: group (check policy-isolated cache first — INV-06)
	policyNamespace := fmt.Sprintf("group:%d", matchedRule.DNSGroupID)
	cKey := CacheKey(policyNamespace, qname, qtype)

	if cached, ok := s.getCached(cKey, now); ok {
		trace.SelectedCandidate = fmt.Sprintf("cache_hit (%s)", policyNamespace)
		s.recordQueryLog(qname, qtype, cached.Rcode, true, cached.IPs, trace)
		return cached.IPs, cached.Rcode, trace, nil
	}

	grp, ok := groupsMap[matchedRule.DNSGroupID]
	if !ok || len(grp.Upstreams) == 0 {
		trace.SelectionReason = fmt.Sprintf("DNS group %d not found or has no upstreams", matchedRule.DNSGroupID)
		return nil, RcodeServFail, trace, ErrNoUpstreamAvailable
	}

	trace.CandidatesConsidered = len(grp.Upstreams)
	var lastErr error
	for idx, up := range grp.Upstreams {
		ips, rcode, ttlSec, err := s.queryUpstream(ctx, grp, up, qname, qtype)
		if err != nil {
			lastErr = err
			trace.Excluded = append(trace.Excluded, model.CandidateExclusion{
				Candidate: fmt.Sprintf("%s://%s", up.Protocol, up.Address),
				Reason:    "transport_error: " + err.Error(),
			})
			continue
		}

		// NXDOMAIN is a valid authoritative DNS response, NOT a transport error!
		// Do not trigger fallback to other resolvers on NXDOMAIN.
		if rcode == RcodeNXDomain {
			s.putCached(cKey, CachedDNSResponse{
				PolicyKey: policyNamespace,
				QName:     qname,
				QType:     qtype,
				Rcode:     RcodeNXDomain,
				ExpiresAt: now.Add(time.Duration(clampTTL(ttlSec, 10, 300)) * time.Second),
				Negative:  true,
			}, now)
			trace.SelectedCandidate = fmt.Sprintf("%s://%s", up.Protocol, up.Address)
			if idx > 0 {
				trace.FailoverReason = fmt.Sprintf("switched to upstream #%d after transport failure on primary", idx+1)
			}
			s.recordQueryLog(qname, qtype, RcodeNXDomain, false, nil, trace)
			return nil, RcodeNXDomain, trace, nil
		}

		if rcode == RcodeSuccess {
			s.putCached(cKey, CachedDNSResponse{
				PolicyKey: policyNamespace,
				QName:     qname,
				QType:     qtype,
				Rcode:     RcodeSuccess,
				IPs:       ips,
				ExpiresAt: now.Add(time.Duration(clampTTL(ttlSec, 15, 3600)) * time.Second),
				Negative:  false,
			}, now)
			trace.SelectedCandidate = fmt.Sprintf("%s://%s", up.Protocol, up.Address)
			if idx > 0 {
				trace.FailoverReason = fmt.Sprintf("switched to upstream #%d after transport failure on primary", idx+1)
			}
			s.recordQueryLog(qname, qtype, RcodeSuccess, false, ips, trace)
			return ips, RcodeSuccess, trace, nil
		}

		// SERVFAIL or REFUSED on upstream counts as upstream failure; try next upstream in group
		lastErr = fmt.Errorf("upstream returned rcode %d", rcode)
		trace.Excluded = append(trace.Excluded, model.CandidateExclusion{
			Candidate: fmt.Sprintf("%s://%s", up.Protocol, up.Address),
			Reason:    lastErr.Error(),
		})
	}

	// Guard internal domains from leaking to public fallback resolvers unless explicitly permitted
	if rules.IsInternalDomain(qname) && !grp.AllowPublicFallback {
		trace.SelectionReason = "all group upstreams failed; blocked fallback for internal domain"
		return nil, RcodeServFail, trace, ErrInternalDomainFallback
	}

	if lastErr == nil {
		lastErr = ErrNoUpstreamAvailable
	}
	return nil, RcodeServFail, trace, lastErr
}

func (s *Server) getCached(key string, now time.Time) (CachedDNSResponse, bool) {
	s.mu.RLock()
	item, ok := s.cache[key]
	s.mu.RUnlock()
	if !ok {
		return CachedDNSResponse{}, false
	}
	if !now.Before(item.ExpiresAt) {
		s.mu.Lock()
		delete(s.cache, key)
		s.mu.Unlock()
		return CachedDNSResponse{}, false
	}
	return item, true
}

func (s *Server) putCached(key string, entry CachedDNSResponse, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.cache) >= s.maxCacheSize {
		// Evict expired first, otherwise evict one arbitrary oldest entry
		evicted := false
		for k, v := range s.cache {
			if !now.Before(v.ExpiresAt) {
				delete(s.cache, k)
				evicted = true
				break
			}
		}
		if !evicted {
			for k := range s.cache {
				delete(s.cache, k)
				break
			}
		}
	}
	s.cache[key] = entry
}

func (s *Server) recordQueryLog(qname string, qtype uint16, rcode uint8, cacheHit bool, ips []net.IP, trace model.DecisionTrace) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.enableQueryLog {
		return
	}
	var ipStrs []string
	for _, ip := range ips {
		ipStrs = append(ipStrs, ip.String())
	}
	entry := QueryLogEntry{
		Timestamp: s.clock.Now(),
		QName:     qname,
		QType:     qtype,
		Rcode:     rcode,
		CacheHit:  cacheHit,
		IPs:       ipStrs,
		Trace:     trace,
	}
	if len(s.queryLog) >= s.maxQueryLog {
		copy(s.queryLog, s.queryLog[1:])
		s.queryLog[len(s.queryLog)-1] = entry
	} else {
		s.queryLog = append(s.queryLog, entry)
	}
}

func (s *Server) QueryLogs() []QueryLogEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]QueryLogEntry, len(s.queryLog))
	copy(out, s.queryLog)
	return out
}

func (s *Server) queryUpstream(ctx context.Context, grp DNSGroup, up UpstreamEndpoint, qname string, qtype uint16) ([]net.IP, uint8, uint32, error) {
	wireQuery, err := BuildDNSQueryWire(0x4242, qname, qtype)
	if err != nil {
		return nil, RcodeFormat, 0, err
	}

	proto := strings.ToLower(strings.TrimSpace(up.Protocol))
	switch proto {
	case "udp", "":
		respWire, truncated, err := queryUDPRaw(ctx, up.Address, wireQuery)
		if err != nil {
			return nil, RcodeServFail, 0, err
		}
		if truncated {
			// Automatic TCP retry on UDP TC=1 truncation (Increment F requirement)
			respWire, err = queryTCPRaw(ctx, up.Address, wireQuery)
			if err != nil {
				return nil, RcodeServFail, 0, err
			}
		}
		return ParseDNSResponseWire(respWire, qtype)

	case "tcp":
		respWire, err := queryTCPRaw(ctx, up.Address, wireQuery)
		if err != nil {
			return nil, RcodeServFail, 0, err
		}
		return ParseDNSResponseWire(respWire, qtype)

	case "dot":
		respWire, err := s.queryDoTRaw(ctx, grp, up.Address, wireQuery)
		if err != nil {
			return nil, RcodeServFail, 0, err
		}
		return ParseDNSResponseWire(respWire, qtype)

	case "doh":
		respWire, err := s.queryDoHRaw(ctx, grp, up.Address, wireQuery)
		if err != nil {
			return nil, RcodeServFail, 0, err
		}
		return ParseDNSResponseWire(respWire, qtype)

	default:
		return nil, RcodeServFail, 0, fmt.Errorf("unsupported DNS upstream protocol %q", up.Protocol)
	}
}

func queryUDPRaw(ctx context.Context, addr string, query []byte) ([]byte, bool, error) {
	d := net.Dialer{Timeout: 2 * time.Second}
	conn, err := d.DialContext(ctx, "udp", addr)
	if err != nil {
		return nil, false, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write(query); err != nil {
		return nil, false, err
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, false, err
	}
	if n < 12 {
		return nil, false, errors.New("short DNS UDP packet")
	}
	tc := (buf[2] & 0x02) != 0
	return buf[:n], tc, nil
}

func queryTCPRaw(ctx context.Context, addr string, query []byte) ([]byte, error) {
	d := net.Dialer{Timeout: 3 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	return exchangeDNSTCPConn(conn, query)
}

func (s *Server) queryDoTRaw(ctx context.Context, grp DNSGroup, endpoint string, query []byte) ([]byte, error) {
	clean := strings.TrimPrefix(endpoint, "tls://")
	host, port, err := net.SplitHostPort(clean)
	if err != nil {
		host = clean
		port = "853"
	}
	dialHost := host
	if net.ParseIP(host) == nil && len(grp.BootstrapIPs) > 0 {
		dialHost = grp.BootstrapIPs[0]
	}
	d := net.Dialer{Timeout: 3 * time.Second}
	rawConn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(dialHost, port))
	if err != nil {
		return nil, err
	}
	defer rawConn.Close()
	_ = rawConn.SetDeadline(time.Now().Add(3 * time.Second))

	// Certificate strictly validated against original endpoint hostname (never InsecureSkipVerify)
	tlsConn := tls.Client(rawConn, &tls.Config{
		ServerName:         host,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: false,
		RootCAs:            s.rootCAs,
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	return exchangeDNSTCPConn(tlsConn, query)
}

func (s *Server) queryDoHRaw(ctx context.Context, grp DNSGroup, endpointURL string, query []byte) ([]byte, error) {
	u, err := url.Parse(endpointURL)
	if err != nil {
		return nil, err
	}
	origHost := u.Hostname()
	tr := &http.Transport{
		Proxy: nil,
		TLSClientConfig: &tls.Config{
			ServerName:         origHost,
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: false,
			RootCAs:            s.rootCAs,
		},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			h, p, err := net.SplitHostPort(addr)
			if err == nil && net.ParseIP(h) == nil && len(grp.BootstrapIPs) > 0 {
				addr = net.JoinHostPort(grp.BootstrapIPs[0], p)
			}
			d := net.Dialer{Timeout: 3 * time.Second}
			return d.DialContext(ctx, network, addr)
		},
		DisableKeepAlives: true,
	}
	client := &http.Client{Transport: tr, Timeout: 4 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpointURL, bytes.NewReader(query))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH HTTP status %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 65535))
}

func exchangeDNSTCPConn(conn net.Conn, query []byte) ([]byte, error) {
	frame := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(query)))
	copy(frame[2:], query)
	if _, err := conn.Write(frame); err != nil {
		return nil, err
	}
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return nil, err
	}
	respLen := int(binary.BigEndian.Uint16(lenBuf))
	resp := make([]byte, respLen)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// BuildDNSQueryWire encodes a minimal RFC 1035 DNS query message with EDNS0 (4096 payload, no ECS).
func BuildDNSQueryWire(id uint16, qname string, qtype uint16) ([]byte, error) {
	var buf bytes.Buffer
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[0:2], id)
	binary.BigEndian.PutUint16(hdr[2:4], 0x0100) // RD=1
	binary.BigEndian.PutUint16(hdr[4:6], 1)      // QDCOUNT=1
	buf.Write(hdr)

	clean := strings.TrimSuffix(strings.TrimSpace(qname), ".")
	if clean != "" {
		for _, label := range strings.Split(clean, ".") {
			if len(label) == 0 || len(label) > 63 {
				return nil, errors.New("invalid DNS label length")
			}
			buf.WriteByte(byte(len(label)))
			buf.WriteString(label)
		}
	}
	buf.WriteByte(0x00)
	tail := make([]byte, 4)
	binary.BigEndian.PutUint16(tail[0:2], qtype)
	binary.BigEndian.PutUint16(tail[2:4], 1) // QCLASS=IN
	buf.Write(tail)
	return buf.Bytes(), nil
}

// ParseDNSResponseWire parses an RFC 1035 DNS response packet, skips CNAME hops, and extracts A/AAAA records and minimum TTL.
func ParseDNSResponseWire(pkt []byte, wantType uint16) ([]net.IP, uint8, uint32, error) {
	if len(pkt) < 12 {
		return nil, RcodeFormat, 0, errors.New("DNS response shorter than 12 bytes")
	}
	rcode := pkt[3] & 0x0F
	qdCount := int(binary.BigEndian.Uint16(pkt[4:6]))
	anCount := int(binary.BigEndian.Uint16(pkt[6:8]))

	offset := 12
	for i := 0; i < qdCount; i++ {
		next, err := skipDNSName(pkt, offset)
		if err != nil || next+4 > len(pkt) {
			return nil, RcodeFormat, 0, errors.New("malformed DNS question section")
		}
		offset = next + 4
	}

	var ips []net.IP
	var minTTL uint32 = 300
	for i := 0; i < anCount; i++ {
		next, err := skipDNSName(pkt, offset)
		if err != nil || next+10 > len(pkt) {
			return nil, RcodeFormat, 0, errors.New("malformed DNS answer RR header")
		}
		rrType := binary.BigEndian.Uint16(pkt[next : next+2])
		ttl := binary.BigEndian.Uint32(pkt[next+4 : next+8])
		rdLen := int(binary.BigEndian.Uint16(pkt[next+8 : next+10]))
		rdataStart := next + 10
		if rdataStart+rdLen > len(pkt) {
			return nil, RcodeFormat, 0, errors.New("malformed DNS answer RDATA")
		}
		if ttl < minTTL {
			minTTL = ttl
		}
		if rrType == TypeA && wantType == TypeA && rdLen == 4 {
			ip := make(net.IP, 4)
			copy(ip, pkt[rdataStart:rdataStart+4])
			ips = append(ips, ip)
		} else if rrType == TypeAAAA && wantType == TypeAAAA && rdLen == 16 {
			ip := make(net.IP, 16)
			copy(ip, pkt[rdataStart:rdataStart+16])
			ips = append(ips, ip)
		}
		// CNAME records (rrType == TypeCNAME) are naturally traversed as we collect terminal A/AAAA RRs in the answer section.
		offset = rdataStart + rdLen
	}
	return ips, rcode, minTTL, nil
}

func skipDNSName(pkt []byte, offset int) (int, error) {
	jumps := 0
	for {
		if offset >= len(pkt) {
			return 0, errors.New("DNS name out of bounds")
		}
		b := pkt[offset]
		if b == 0x00 {
			return offset + 1, nil
		}
		if (b & 0xC0) == 0xC0 {
			if offset+1 >= len(pkt) {
				return 0, errors.New("truncated DNS compression pointer")
			}
			return offset + 2, nil
		}
		labelLen := int(b)
		offset += 1 + labelLen
		jumps++
		if jumps > 128 {
			return 0, errors.New("DNS name loop detected")
		}
	}
}

func clampTTL(ttl, minV, maxV uint32) uint32 {
	if ttl < minV {
		return minV
	}
	if ttl > maxV {
		return maxV
	}
	return ttl
}
