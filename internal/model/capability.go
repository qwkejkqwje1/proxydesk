package model

import (
	"sync"
	"time"
)

// CapabilityState represents the 5-state unified capability model (Engineering Bar Section 6).
type CapabilityState string

const (
	CapabilityUnknown        CapabilityState = "unknown"
	CapabilityConfirmed      CapabilityState = "confirmed"
	CapabilityUnsupported    CapabilityState = "unsupported"
	CapabilityTransientError CapabilityState = "transient_error"
	CapabilityStale          CapabilityState = "stale"
)

type CapabilityRecord struct {
	State      CapabilityState `json:"state"`
	VerifiedAt *time.Time      `json:"verified_at,omitempty"`
	Detail     string          `json:"detail,omitempty"`
}

// EffectiveState computes whether a confirmed capability has become stale relative to now and ttl.
func (c CapabilityRecord) EffectiveState(now time.Time, ttl time.Duration) CapabilityState {
	switch c.State {
	case CapabilityConfirmed:
		if c.VerifiedAt == nil {
			return CapabilityUnknown
		}
		if ttl > 0 && now.Sub(*c.VerifiedAt) > ttl {
			return CapabilityStale
		}
		return CapabilityConfirmed
	case CapabilityUnsupported, CapabilityTransientError, CapabilityStale, CapabilityUnknown:
		return c.State
	default:
		return CapabilityUnknown
	}
}

// IsUsable enforces INV-08: only CapabilityConfirmed within TTL is considered usable.
func (c CapabilityRecord) IsUsable(now time.Time, ttl time.Duration) bool {
	return c.EffectiveState(now, ttl) == CapabilityConfirmed
}

type ProxyCapabilities struct {
	Connect    CapabilityRecord `json:"connect"`
	Auth       CapabilityRecord `json:"auth"`
	RemoteDNS  CapabilityRecord `json:"remote_dns"`
	UDP        CapabilityRecord `json:"udp"`
	TLSToProxy CapabilityRecord `json:"tls_to_proxy"`
}

func DefaultCapabilities() ProxyCapabilities {
	return ProxyCapabilities{
		Connect:    CapabilityRecord{State: CapabilityUnknown},
		Auth:       CapabilityRecord{State: CapabilityUnknown},
		RemoteDNS:  CapabilityRecord{State: CapabilityUnknown},
		UDP:        CapabilityRecord{State: CapabilityUnknown},
		TLSToProxy: CapabilityRecord{State: CapabilityUnknown},
	}
}

type ProxyStatus string

const (
	StatusUnknown     ProxyStatus = "unknown"
	StatusChecking    ProxyStatus = "checking"
	StatusHealthy     ProxyStatus = "healthy"
	StatusDegraded    ProxyStatus = "degraded"
	StatusQuarantined ProxyStatus = "quarantined"
)

// DecisionTrace provides a bounded structured explanation for every routing/pool/DNS choice
// without storing traffic payloads (Engineering Bar Section 2).
type CandidateExclusion struct {
	Candidate string `json:"candidate"`
	Reason    string `json:"reason"`
}

type DecisionTrace struct {
	Timestamp            time.Time            `json:"timestamp"`
	Component            string               `json:"component"` // "pool", "gateway", "dns"
	RuleMatched          string               `json:"rule_matched"`
	DNSPolicy            string               `json:"dns_policy,omitempty"`
	ResolutionMode       string               `json:"resolution_mode,omitempty"` // "remote_dns" or "managed_dns"
	RouteAction          string               `json:"route_action,omitempty"`    // "proxy", "pool", "block", "direct"
	CandidatesConsidered int                  `json:"candidates_considered"`
	Excluded             []CandidateExclusion `json:"excluded,omitempty"`
	SelectedCandidate    string               `json:"selected_candidate,omitempty"`
	SelectionReason      string               `json:"selection_reason"`
	FailoverReason       string               `json:"failover_reason,omitempty"`
}

// Clock abstracts time for deterministic zero-sleep testing (Engineering Bar Section 4).
type Clock interface {
	Now() time.Time
}

type RealClock struct{}

func (RealClock) Now() time.Time { return time.Now().UTC() }

type FakeClock struct {
	mu  sync.Mutex
	cur time.Time
}

func NewFakeClock(initial time.Time) *FakeClock {
	return &FakeClock{cur: initial.UTC()}
}

func (f *FakeClock) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.cur
}

func (f *FakeClock) Advance(d time.Duration) time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cur = f.cur.Add(d)
	return f.cur
}

// CredentialStore holds proxy credentials strictly in process memory (ADR-003).
type Credentials struct {
	Username string
	Password string
}

type CredentialStore struct {
	mu    sync.RWMutex
	items map[string]Credentials // keyed by dedup_key
}

func NewCredentialStore() *CredentialStore {
	return &CredentialStore{items: make(map[string]Credentials)}
}

func (s *CredentialStore) Set(dedupKey, username, password string) {
	if username == "" && password == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items[dedupKey] = Credentials{Username: username, Password: password}
}

func (s *CredentialStore) Get(dedupKey string) (Credentials, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.items[dedupKey]
	return c, ok
}
