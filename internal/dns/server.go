package dns

import (
	"bytes"
	"context"
	"crypto/rand"
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
	TypeSOA   uint16 = 6
	TypeAAAA  uint16 = 28

	ClassIN uint16 = 1

	RcodeSuccess  uint8 = 0
	RcodeFormat   uint8 = 1
	RcodeServFail uint8 = 2
	RcodeNXDomain uint8 = 3
	RcodeRefused  uint8 = 5

	maxCapTTLSeconds uint32 = 604800 // 7 days max cap; never artificially increase small TTLs
)

var (
	ErrNoUpstreamAvailable         = errors.New("all DNS upstreams in group failed transport check")
	ErrInternalDomainFallback      = errors.New("refusing to leak internal domain to public fallback resolver")
	ErrDNSResponseMismatch         = errors.New("DNS response failed ID, QR, Opcode, or Question verification")
	ErrMalformedCompressionPointer = errors.New("malformed or cyclic DNS name compression pointer")
	ErrMalformedDNSPacket          = errors.New("malformed DNS packet")
)

type UpstreamEndpoint struct {
	Protocol string `json:"protocol"` // "udp", "tcp", "dot", "doh"
	Address  string `json:"address"`
}

type DNSGroup struct {
	ID                  int                `json:"id"`
	Name                string             `json:"name"`
	Upstreams           []UpstreamEndpoint `json:"upstreams"`
	BootstrapIPs        []string           `json:"bootstrap_ips,omitempty"`
	AllowPublicFallback bool               `json:"allow_public_fallback"`
}

type CachedDNSResponse struct {
	PolicyKey string
	QName     string
	QType     uint16
	Rcode     uint8
	IPs       []net.IP
	TTLSec    uint32
	CachedAt  time.Time
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

type parsedDNSResponse struct {
	ID          uint16
	Truncated   bool
	Rcode       uint8
	QuestionName string
	QuestionType uint16
	IPs         []net.IP
	AnswerTTL   uint32
	HasAnswerTTL bool
	NegativeTTL uint32 // Derived strictly from Authority SOA record per RFC 2308
	HasSOA      bool
}

type Server struct {
	mu             sync.RWMutex
	clock          model.Clock
	maxCacheSize   int
	cache          map[string]CachedDNSResponse
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

// SetConfig updates DNS groups and rules and immediately invalidates the DNS cache
// so stale entries from previous policy configurations cannot persist (STABILIZATION-01 Section 5).
func (s *Server) SetConfig(groups []DNSGroup, defaultGroupID int, dnsRules []rules.DNSRule, enableQueryLog bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.groups = make(map[int]DNSGroup, len(groups))
	for _, g := range groups {
		s.groups[g.ID] = g
	}
	if defaultGroupID > 0 {
		s.defaultGroupID = defaultGroupID
	}
	s.dnsRules = append([]rules.DNSRule(nil), dnsRules...)
	s.enableQueryLog = enableQueryLog
	s.cache = make(map[string]CachedDNSResponse)
}

func (s *Server) ClearCache() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cache = make(map[string]CachedDNSResponse)
}

// CacheKey enforces INV-06: DNS responses cached under one policy group namespace
// can NEVER be returned to a query governed by another policy group.
func CacheKey(policyNamespace string, qname string, qtype uint16) string {
	return fmt.Sprintf("%s|%s|%d", policyNamespace, canonicalDNSName(qname), qtype)
}

func canonicalDNSName(name string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
}

func randomTxID() uint16 {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return uint16(time.Now().UnixNano() & 0xFFFF)
	}
	id := binary.BigEndian.Uint16(b[:])
	if id == 0 {
		return 1
	}
	return id
}

// Resolve evaluates DNS rules, checks the policy-isolated cache, and queries the selected upstream group.
func (s *Server) Resolve(ctx context.Context, qname string, qtype uint16) ([]net.IP, uint8, model.DecisionTrace, error) {
	ips, rcode, _, trace, err := s.ResolveWithTTL(ctx, qname, qtype)
	return ips, rcode, trace, err
}

func (s *Server) ResolveWithTTL(ctx context.Context, qname string, qtype uint16) ([]net.IP, uint8, uint32, model.DecisionTrace, error) {
	s.mu.RLock()
	rulesList := s.dnsRules
	defGroup := s.defaultGroupID
	groupsMap := s.groups
	s.mu.RUnlock()

	now := s.clock.Now()
	matchedRule, trace := rules.EvaluateDNS(qname, rulesList, defGroup, now)

	if matchedRule.Action == "block" {
		trace.SelectedCandidate = "block (NXDOMAIN)"
		s.recordQueryLog(qname, qtype, RcodeNXDomain, false, nil, trace)
		return nil, RcodeNXDomain, 0, trace, nil
	}

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
		return ips, RcodeSuccess, 60, trace, nil
	}

	policyNamespace := fmt.Sprintf("group:%d", matchedRule.DNSGroupID)
	cKey := CacheKey(policyNamespace, qname, qtype)

	if cached, remainingTTL, ok := s.getCached(cKey, now); ok {
		trace.SelectedCandidate = fmt.Sprintf("cache_hit (%s)", policyNamespace)
		s.recordQueryLog(qname, qtype, cached.Rcode, true, cached.IPs, trace)
		return cached.IPs, cached.Rcode, remainingTTL, trace, nil
	}

	grp, ok := groupsMap[matchedRule.DNSGroupID]
	if !ok || len(grp.Upstreams) == 0 {
		trace.SelectionReason = fmt.Sprintf("DNS group %d not found or has no upstreams", matchedRule.DNSGroupID)
		return nil, RcodeServFail, 0, trace, ErrNoUpstreamAvailable
	}

	trace.CandidatesConsidered = len(grp.Upstreams)
	var lastErr error
	for idx, up := range grp.Upstreams {
		parsed, err := s.queryUpstream(ctx, grp, up, qname, qtype)
		if err != nil {
			lastErr = err
			trace.Excluded = append(trace.Excluded, model.CandidateExclusion{
				Candidate: fmt.Sprintf("%s://%s", up.Protocol, up.Address),
				Reason:    "transport_error: " + err.Error(),
			})
			continue
		}

		// NXDOMAIN is an authoritative DNS response, NOT a transport failure.
		// Cache ONLY if Authority section provided an SOA record with NegativeTTL > 0 (RFC 2308).
		if parsed.Rcode == RcodeNXDomain {
			if parsed.HasSOA && parsed.NegativeTTL > 0 {
				ttl := capMaxTTL(parsed.NegativeTTL)
				s.putCached(cKey, CachedDNSResponse{
					PolicyKey: policyNamespace,
					QName:     qname,
					QType:     qtype,
					Rcode:     RcodeNXDomain,
					TTLSec:    ttl,
					CachedAt:  now,
					ExpiresAt: now.Add(time.Duration(ttl) * time.Second),
					Negative:  true,
				}, now)
			}
			trace.SelectedCandidate = fmt.Sprintf("%s://%s", up.Protocol, up.Address)
			if idx > 0 {
				trace.FailoverReason = fmt.Sprintf("switched to upstream #%d after transport failure on primary", idx+1)
			}
			s.recordQueryLog(qname, qtype, RcodeNXDomain, false, nil, trace)
			return nil, RcodeNXDomain, parsed.NegativeTTL, trace, nil
		}

		if parsed.Rcode == RcodeSuccess {
			var effectiveTTL uint32
			if len(parsed.IPs) > 0 && parsed.HasAnswerTTL {
				effectiveTTL = capMaxTTL(parsed.AnswerTTL)
				// Strictly honor TTL=0: NEVER cache when TTL is 0!
				if effectiveTTL > 0 {
					s.putCached(cKey, CachedDNSResponse{
						PolicyKey: policyNamespace,
						QName:     qname,
						QType:     qtype,
						Rcode:     RcodeSuccess,
						IPs:       parsed.IPs,
						TTLSec:    effectiveTTL,
						CachedAt:  now,
						ExpiresAt: now.Add(time.Duration(effectiveTTL) * time.Second),
						Negative:  false,
					}, now)
				}
			} else if len(parsed.IPs) == 0 && parsed.HasSOA && parsed.NegativeTTL > 0 {
				// NODATA negative caching per RFC 2308
				effectiveTTL = capMaxTTL(parsed.NegativeTTL)
				s.putCached(cKey, CachedDNSResponse{
					PolicyKey: policyNamespace,
					QName:     qname,
					QType:     qtype,
					Rcode:     RcodeSuccess,
					IPs:       nil,
					TTLSec:    effectiveTTL,
					CachedAt:  now,
					ExpiresAt: now.Add(time.Duration(effectiveTTL) * time.Second),
					Negative:  true,
				}, now)
			}

			trace.SelectedCandidate = fmt.Sprintf("%s://%s", up.Protocol, up.Address)
			if idx > 0 {
				trace.FailoverReason = fmt.Sprintf("switched to upstream #%d after transport failure on primary", idx+1)
			}
			s.recordQueryLog(qname, qtype, RcodeSuccess, false, parsed.IPs, trace)
			return parsed.IPs, RcodeSuccess, effectiveTTL, trace, nil
		}

		lastErr = fmt.Errorf("upstream returned rcode %d", parsed.Rcode)
		trace.Excluded = append(trace.Excluded, model.CandidateExclusion{
			Candidate: fmt.Sprintf("%s://%s", up.Protocol, up.Address),
			Reason:    lastErr.Error(),
		})
	}

	if rules.IsInternalDomain(qname) && !grp.AllowPublicFallback {
		trace.SelectionReason = "all group upstreams failed; blocked fallback for internal domain"
		return nil, RcodeServFail, 0, trace, ErrInternalDomainFallback
	}

	if lastErr == nil {
		lastErr = ErrNoUpstreamAvailable
	}
	return nil, RcodeServFail, 0, trace, lastErr
}

// ServeUDP runs the local user-mode UDP DNS listener (STABILIZATION-01 Section 2 & 5).
func (s *Server) ServeUDP(ctx context.Context, pc net.PacketConn) error {
	buf := make([]byte, 4096)
	for {
		n, clientAddr, err := pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			continue
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		go func(queryPkt []byte, addr net.Addr) {
			respWire := s.HandleWireQuery(ctx, queryPkt, true)
			if len(respWire) > 0 {
				_, _ = pc.WriteTo(respWire, addr)
			}
		}(pkt, clientAddr)
	}
}

// ServeTCP runs the local user-mode TCP DNS listener (STABILIZATION-01 Section 2 & 5).
func (s *Server) ServeTCP(ctx context.Context, ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			continue
		}
		go func(c net.Conn) {
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))
			lenBuf := make([]byte, 2)
			if _, err := io.ReadFull(c, lenBuf); err != nil {
				return
			}
			qLen := int(binary.BigEndian.Uint16(lenBuf))
			if qLen < 12 || qLen > 16384 {
				return
			}
			queryPkt := make([]byte, qLen)
			if _, err := io.ReadFull(c, queryPkt); err != nil {
				return
			}
			respWire := s.HandleWireQuery(ctx, queryPkt, false)
			if len(respWire) == 0 {
				return
			}
			out := make([]byte, 2+len(respWire))
			binary.BigEndian.PutUint16(out[:2], uint16(len(respWire)))
			copy(out[2:], respWire)
			_, _ = c.Write(out)
		}(conn)
	}
}

// HandleWireQuery parses a client's DNS wire request, resolves it via ResolveWithTTL,
// and encodes a compliant RFC 1035 DNS wire response with matching Transaction ID and Question.
func (s *Server) HandleWireQuery(ctx context.Context, queryPkt []byte, isUDP bool) []byte {
	txID, opcode, qname, qtype, qclass, err := ParseDNSQueryWire(queryPkt)
	if err != nil {
		if len(queryPkt) >= 12 {
			return BuildDNSResponseWire(binary.BigEndian.Uint16(queryPkt[:2]), "", 0, RcodeFormat, false, nil, 0)
		}
		return nil
	}
	if opcode != 0 || qclass != ClassIN {
		return BuildDNSResponseWire(txID, qname, qtype, RcodeRefused, false, nil, 0)
	}
	ips, rcode, ttl, _, err := s.ResolveWithTTL(ctx, qname, qtype)
	if err != nil && rcode == 0 {
		rcode = RcodeServFail
	}
	resp := BuildDNSResponseWire(txID, qname, qtype, rcode, false, ips, ttl)
	if isUDP && len(resp) > 512 {
		// Mark truncated (TC=1) so UDP client retries over TCP
		return BuildDNSResponseWire(txID, qname, qtype, rcode, true, nil, ttl)
	}
	return resp
}

func (s *Server) getCached(key string, now time.Time) (CachedDNSResponse, uint32, bool) {
	s.mu.RLock()
	item, ok := s.cache[key]
	s.mu.RUnlock()
	if !ok {
		return CachedDNSResponse{}, 0, false
	}
	if !now.Before(item.ExpiresAt) {
		s.mu.Lock()
		delete(s.cache, key)
		s.mu.Unlock()
		return CachedDNSResponse{}, 0, false
	}
	rem := uint32(item.ExpiresAt.Sub(now).Seconds())
	return item, rem, true
}

func (s *Server) putCached(key string, entry CachedDNSResponse, now time.Time) {
	if entry.TTLSec == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.cache) >= s.maxCacheSize {
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

func (s *Server) queryUpstream(ctx context.Context, grp DNSGroup, up UpstreamEndpoint, qname string, qtype uint16) (parsedDNSResponse, error) {
	txID := randomTxID()
	wireQuery, err := BuildDNSQueryWire(txID, qname, qtype)
	if err != nil {
		return parsedDNSResponse{}, err
	}

	proto := strings.ToLower(strings.TrimSpace(up.Protocol))
	switch proto {
	case "udp", "":
		respWire, err := queryUDPRaw(ctx, up.Address, wireQuery)
		if err != nil {
			return parsedDNSResponse{}, err
		}
		parsed, err := ParseAndValidateDNSResponseWire(respWire, txID, qname, qtype)
		if err != nil {
			return parsedDNSResponse{}, err
		}
		if parsed.Truncated {
			// Automatic TCP retry with a fresh transaction ID when UDP response has TC=1
			tcpTxID := randomTxID()
			tcpQuery, _ := BuildDNSQueryWire(tcpTxID, qname, qtype)
			tcpWire, tcpErr := queryTCPRaw(ctx, up.Address, tcpQuery)
			if tcpErr != nil {
				return parsedDNSResponse{}, tcpErr
			}
			return ParseAndValidateDNSResponseWire(tcpWire, tcpTxID, qname, qtype)
		}
		return parsed, nil

	case "tcp":
		respWire, err := queryTCPRaw(ctx, up.Address, wireQuery)
		if err != nil {
			return parsedDNSResponse{}, err
		}
		return ParseAndValidateDNSResponseWire(respWire, txID, qname, qtype)

	case "dot":
		respWire, err := s.queryDoTRaw(ctx, grp, up.Address, wireQuery)
		if err != nil {
			return parsedDNSResponse{}, err
		}
		return ParseAndValidateDNSResponseWire(respWire, txID, qname, qtype)

	case "doh":
		respWire, err := s.queryDoHRaw(ctx, grp, up.Address, wireQuery)
		if err != nil {
			return parsedDNSResponse{}, err
		}
		return ParseAndValidateDNSResponseWire(respWire, txID, qname, qtype)

	default:
		return parsedDNSResponse{}, fmt.Errorf("unsupported DNS upstream protocol %q", up.Protocol)
	}
}

func queryUDPRaw(ctx context.Context, addr string, query []byte) ([]byte, error) {
	d := net.Dialer{Timeout: 2 * time.Second}
	conn, err := d.DialContext(ctx, "udp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	if n < 12 {
		return nil, ErrMalformedDNSPacket
	}
	return buf[:n], nil
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
	if respLen < 12 {
		return nil, ErrMalformedDNSPacket
	}
	resp := make([]byte, respLen)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// BuildDNSQueryWire encodes an RFC 1035 DNS query message.
func BuildDNSQueryWire(id uint16, qname string, qtype uint16) ([]byte, error) {
	var buf bytes.Buffer
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[0:2], id)
	binary.BigEndian.PutUint16(hdr[2:4], 0x0100) // QR=0, Opcode=0, RD=1
	binary.BigEndian.PutUint16(hdr[4:6], 1)      // QDCOUNT=1
	buf.Write(hdr)

	if err := writeDNSName(&buf, qname); err != nil {
		return nil, err
	}
	tail := make([]byte, 4)
	binary.BigEndian.PutUint16(tail[0:2], qtype)
	binary.BigEndian.PutUint16(tail[2:4], ClassIN)
	buf.Write(tail)
	return buf.Bytes(), nil
}

// BuildDNSResponseWire encodes an RFC 1035 DNS response packet for local UDP/TCP clients.
func BuildDNSResponseWire(id uint16, qname string, qtype uint16, rcode uint8, truncated bool, ips []net.IP, ttl uint32) []byte {
	var buf bytes.Buffer
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[0:2], id)
	flags := uint16(0x8180) | uint16(rcode&0x0F) // QR=1, RD=1, RA=1
	if truncated {
		flags |= 0x0200 // TC=1
	}
	binary.BigEndian.PutUint16(hdr[2:4], flags)
	if qname != "" {
		binary.BigEndian.PutUint16(hdr[4:6], 1)
	}
	var validIPs [][]byte
	for _, ip := range ips {
		if qtype == TypeA {
			if ip4 := ip.To4(); ip4 != nil {
				validIPs = append(validIPs, ip4)
			}
		} else if qtype == TypeAAAA {
			if ip.To4() == nil && len(ip.To16()) == 16 {
				validIPs = append(validIPs, ip.To16())
			}
		}
	}
	if !truncated {
		binary.BigEndian.PutUint16(hdr[6:8], uint16(len(validIPs)))
	}
	buf.Write(hdr)

	if qname != "" {
		_ = writeDNSName(&buf, qname)
		qTail := make([]byte, 4)
		binary.BigEndian.PutUint16(qTail[0:2], qtype)
		binary.BigEndian.PutUint16(qTail[2:4], ClassIN)
		buf.Write(qTail)
	}

	if !truncated {
		for _, rdata := range validIPs {
			ans := make([]byte, 12+len(rdata))
			binary.BigEndian.PutUint16(ans[0:2], 0xC00C) // Pointer to Question name at offset 12
			binary.BigEndian.PutUint16(ans[2:4], qtype)
			binary.BigEndian.PutUint16(ans[4:6], ClassIN)
			binary.BigEndian.PutUint32(ans[6:10], ttl)
			binary.BigEndian.PutUint16(ans[10:12], uint16(len(rdata)))
			copy(ans[12:], rdata)
			buf.Write(ans)
		}
	}
	return buf.Bytes()
}

func writeDNSName(buf *bytes.Buffer, qname string) error {
	clean := strings.TrimSuffix(strings.TrimSpace(qname), ".")
	if len(clean) > 253 {
		return errors.New("DNS name exceeds 253 bytes")
	}
	if clean != "" {
		for _, label := range strings.Split(clean, ".") {
			if len(label) == 0 || len(label) > 63 {
				return errors.New("invalid DNS label length")
			}
			buf.WriteByte(byte(len(label)))
			buf.WriteString(label)
		}
	}
	buf.WriteByte(0x00)
	return nil
}

// ParseDNSQueryWire parses an incoming client DNS query packet.
func ParseDNSQueryWire(pkt []byte) (txID uint16, opcode uint8, qname string, qtype uint16, qclass uint16, err error) {
	if len(pkt) < 12 {
		return 0, 0, "", 0, 0, ErrMalformedDNSPacket
	}
	txID = binary.BigEndian.Uint16(pkt[0:2])
	flags := binary.BigEndian.Uint16(pkt[2:4])
	if (flags & 0x8000) != 0 {
		return 0, 0, "", 0, 0, errors.New("expected DNS query (QR=0), got response")
	}
	opcode = uint8((flags >> 11) & 0x0F)
	qdCount := int(binary.BigEndian.Uint16(pkt[4:6]))
	if qdCount < 1 {
		return 0, 0, "", 0, 0, ErrMalformedDNSPacket
	}
	name, nextOffset, err := readDNSName(pkt, 12)
	if err != nil || nextOffset+4 > len(pkt) {
		return 0, 0, "", 0, 0, ErrMalformedDNSPacket
	}
	qtype = binary.BigEndian.Uint16(pkt[nextOffset : nextOffset+2])
	qclass = binary.BigEndian.Uint16(pkt[nextOffset+2 : nextOffset+4])
	return txID, opcode, name, qtype, qclass, nil
}

// ParseAndValidateDNSResponseWire validates ID, QR=1, Opcode=0, and Question (name/type/class),
// follows CNAME chains in Answer section, and extracts RFC 2308 negative TTL from Authority SOA RRs.
func ParseAndValidateDNSResponseWire(pkt []byte, expectedID uint16, expectedQName string, expectedQType uint16) (parsedDNSResponse, error) {
	if len(pkt) < 12 {
		return parsedDNSResponse{}, ErrMalformedDNSPacket
	}
	respID := binary.BigEndian.Uint16(pkt[0:2])
	if respID != expectedID {
		return parsedDNSResponse{}, fmt.Errorf("%w: ID mismatch (got %d, want %d)", ErrDNSResponseMismatch, respID, expectedID)
	}
	flags := binary.BigEndian.Uint16(pkt[2:4])
	qr := (flags & 0x8000) != 0
	opcode := (flags >> 11) & 0x0F
	tc := (flags & 0x0200) != 0
	rcode := uint8(flags & 0x000F)

	if !qr || opcode != 0 {
		return parsedDNSResponse{}, fmt.Errorf("%w: invalid QR=%v or Opcode=%d", ErrDNSResponseMismatch, qr, opcode)
	}

	qdCount := int(binary.BigEndian.Uint16(pkt[4:6]))
	anCount := int(binary.BigEndian.Uint16(pkt[6:8]))
	nsCount := int(binary.BigEndian.Uint16(pkt[8:10]))

	if qdCount != 1 {
		return parsedDNSResponse{}, fmt.Errorf("%w: expected QDCOUNT=1, got %d", ErrDNSResponseMismatch, qdCount)
	}

	qName, offset, err := readDNSName(pkt, 12)
	if err != nil {
		return parsedDNSResponse{}, err
	}
	if offset+4 > len(pkt) {
		return parsedDNSResponse{}, ErrMalformedDNSPacket
	}
	qType := binary.BigEndian.Uint16(pkt[offset : offset+2])
	qClass := binary.BigEndian.Uint16(pkt[offset+2 : offset+4])
	offset += 4

	if canonicalDNSName(qName) != canonicalDNSName(expectedQName) || qType != expectedQType || qClass != ClassIN {
		return parsedDNSResponse{}, fmt.Errorf("%w: question mismatch (got %s/%d/%d, want %s/%d/1)", ErrDNSResponseMismatch, qName, qType, qClass, expectedQName, expectedQType)
	}

	out := parsedDNSResponse{
		ID:           respID,
		Truncated:    tc,
		Rcode:        rcode,
		QuestionName: qName,
		QuestionType: qType,
	}
	if tc {
		return out, nil
	}

	// Parse Answer section with CNAME chain resolution
	type answerRR struct {
		owner string
		rtype uint16
		ttl   uint32
		cname string
		ip    net.IP
	}
	var answers []answerRR
	for i := 0; i < anCount; i++ {
		owner, next, err := readDNSName(pkt, offset)
		if err != nil {
			return parsedDNSResponse{}, err
		}
		if next+10 > len(pkt) {
			return parsedDNSResponse{}, ErrMalformedDNSPacket
		}
		rrType := binary.BigEndian.Uint16(pkt[next : next+2])
		rrClass := binary.BigEndian.Uint16(pkt[next+2 : next+4])
		ttl := binary.BigEndian.Uint32(pkt[next+4 : next+8])
		rdLen := int(binary.BigEndian.Uint16(pkt[next+8 : next+10]))
		rdataStart := next + 10
		if rdataStart+rdLen > len(pkt) {
			return parsedDNSResponse{}, ErrMalformedDNSPacket
		}

		if rrClass == ClassIN {
			switch rrType {
			case TypeCNAME:
				cnameTarget, endOff, err := readDNSName(pkt, rdataStart)
				if err != nil || endOff > rdataStart+rdLen {
					return parsedDNSResponse{}, ErrMalformedDNSPacket
				}
				answers = append(answers, answerRR{
					owner: canonicalDNSName(owner),
					rtype: TypeCNAME,
					ttl:   ttl,
					cname: canonicalDNSName(cnameTarget),
				})
			case TypeA:
				if rdLen != 4 {
					return parsedDNSResponse{}, ErrMalformedDNSPacket
				}
				ip := make(net.IP, 4)
				copy(ip, pkt[rdataStart:rdataStart+4])
				answers = append(answers, answerRR{
					owner: canonicalDNSName(owner),
					rtype: TypeA,
					ttl:   ttl,
					ip:    ip,
				})
			case TypeAAAA:
				if rdLen != 16 {
					return parsedDNSResponse{}, ErrMalformedDNSPacket
				}
				ip := make(net.IP, 16)
				copy(ip, pkt[rdataStart:rdataStart+16])
				answers = append(answers, answerRR{
					owner: canonicalDNSName(owner),
					rtype: TypeAAAA,
					ttl:   ttl,
					ip:    ip,
				})
			}
		}
		offset = rdataStart + rdLen
	}

	// Follow CNAME chain starting from expectedQName (up to 8 CNAME hops)
	targetName := canonicalDNSName(expectedQName)
	var minTTL uint32
	hasTTL := false
	for hop := 0; hop < 8; hop++ {
		advanced := false
		for _, rr := range answers {
			if rr.rtype == TypeCNAME && rr.owner == targetName && rr.cname != "" && rr.cname != targetName {
				targetName = rr.cname
				if !hasTTL || rr.ttl < minTTL {
					minTTL = rr.ttl
					hasTTL = true
				}
				advanced = true
				break
			}
		}
		if !advanced {
			break
		}
	}

	for _, rr := range answers {
		if rr.rtype == expectedQType && (rr.owner == targetName || rr.owner == canonicalDNSName(expectedQName)) {
			out.IPs = append(out.IPs, rr.ip)
			if !hasTTL || rr.ttl < minTTL {
				minTTL = rr.ttl
				hasTTL = true
			}
		}
	}
	out.AnswerTTL = minTTL
	out.HasAnswerTTL = hasTTL

	// Parse Authority section for SOA record to compute RFC 2308 Negative Caching TTL
	for i := 0; i < nsCount; i++ {
		_, next, err := readDNSName(pkt, offset)
		if err != nil {
			return parsedDNSResponse{}, err
		}
		if next+10 > len(pkt) {
			return parsedDNSResponse{}, ErrMalformedDNSPacket
		}
		rrType := binary.BigEndian.Uint16(pkt[next : next+2])
		rrClass := binary.BigEndian.Uint16(pkt[next+2 : next+4])
		soaHeaderTTL := binary.BigEndian.Uint32(pkt[next+4 : next+8])
		rdLen := int(binary.BigEndian.Uint16(pkt[next+8 : next+10]))
		rdataStart := next + 10
		if rdataStart+rdLen > len(pkt) {
			return parsedDNSResponse{}, ErrMalformedDNSPacket
		}

		if rrType == TypeSOA && rrClass == ClassIN {
			// SOA RDATA: MNAME (domain), RNAME (domain), SERIAL(4), REFRESH(4), RETRY(4), EXPIRE(4), MINIMUM(4)
			_, rnameOff, err := readDNSName(pkt, rdataStart)
			if err != nil {
				return parsedDNSResponse{}, err
			}
			_, numsOff, err := readDNSName(pkt, rnameOff)
			if err != nil || numsOff+20 > rdataStart+rdLen {
				return parsedDNSResponse{}, ErrMalformedDNSPacket
			}
			soaMinimum := binary.BigEndian.Uint32(pkt[numsOff+16 : numsOff+20])
			negTTL := soaHeaderTTL
			if soaMinimum < negTTL {
				negTTL = soaMinimum
			}
			out.NegativeTTL = negTTL
			out.HasSOA = true
		}
		offset = rdataStart + rdLen
	}

	return out, nil
}

// readDNSName decompresses an RFC 1035 domain name starting at offset.
// Strictly rejects forward pointers, self-pointers, out-of-bounds pointers, or >64 pointer jumps.
func readDNSName(pkt []byte, offset int) (string, int, error) {
	if offset < 0 || offset >= len(pkt) {
		return "", 0, ErrMalformedDNSPacket
	}
	var labels []string
	cur := offset
	nextOffset := -1
	jumps := 0
	totalLen := 0

	for {
		if cur >= len(pkt) {
			return "", 0, ErrMalformedDNSPacket
		}
		b := pkt[cur]
		if b == 0x00 {
			if nextOffset == -1 {
				nextOffset = cur + 1
			}
			break
		}
		// Compression pointer (top two bits 11)
		if (b & 0xC0) == 0xC0 {
			if cur+1 >= len(pkt) {
				return "", 0, ErrMalformedCompressionPointer
			}
			ptr := ((int(b) & 0x3F) << 8) | int(pkt[cur+1])
			// Pointer must strictly point backward to an earlier offset in the packet (>= 12 and < cur)
			if ptr < 12 || ptr >= cur || ptr >= len(pkt) {
				return "", 0, ErrMalformedCompressionPointer
			}
			if nextOffset == -1 {
				nextOffset = cur + 2
			}
			cur = ptr
			jumps++
			if jumps > 64 {
				return "", 0, ErrMalformedCompressionPointer
			}
			continue
		}
		if (b & 0xC0) != 0 {
			// Reserved label type bits 01 or 10 are invalid in standard RFC 1035 names
			return "", 0, ErrMalformedCompressionPointer
		}
		labelLen := int(b)
		cur++
		if cur+labelLen > len(pkt) {
			return "", 0, ErrMalformedDNSPacket
		}
		totalLen += labelLen + 1
		if totalLen > 255 {
			return "", 0, ErrMalformedDNSPacket
		}
		labels = append(labels, string(pkt[cur:cur+labelLen]))
		cur += labelLen
	}
	return strings.Join(labels, "."), nextOffset, nil
}

func capMaxTTL(ttl uint32) uint32 {
	if ttl > maxCapTTLSeconds {
		return maxCapTTLSeconds
	}
	return ttl
}
