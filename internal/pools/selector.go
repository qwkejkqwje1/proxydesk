package pools

import (
	"errors"
	"fmt"
	"math/rand"
	"sort"
	"sync"
	"time"

	"github.com/proxydesk/proxydesk/internal/model"
	"github.com/proxydesk/proxydesk/internal/storage"
)

var ErrNoMatchingCandidate = errors.New("no healthy proxy candidate satisfies pool and capability requirements")

type PoolConfig struct {
	ID               int     `json:"id"`
	Name             string  `json:"name"`
	Kind             string  `json:"kind"`     // "manual", "reliable", "fast", "protocol", "custom"
	Strategy         string  `json:"strategy"` // "fixed", "failover", "best_score", "round_robin", "weighted"
	RequiredProtocol string  `json:"required_protocol,omitempty"`
	RequireConnect   bool    `json:"require_connect"`
	RequireRemoteDNS bool    `json:"require_remote_dns"`
	MinScore         float64 `json:"min_score"`
	CountryCode      string  `json:"country_code,omitempty"`
	HysteresisDelta  float64 `json:"hysteresis_delta"`
	ActiveProxyID    *int    `json:"active_proxy_id,omitempty"`
}

type SelectionRequest struct {
	RequireConnect   bool
	RequireRemoteDNS bool
	CapabilityTTL    time.Duration
	ExcludeProxyIDs  map[int]string // proxyID -> reason (e.g. failed during current failover attempt)
}

type Selector struct {
	mu      sync.Mutex
	clock   model.Clock
	rng     *rand.Rand
	rrIndex map[int]int // poolID -> round-robin cursor
}

func NewSelector(clock model.Clock, seed int64) *Selector {
	if clock == nil {
		clock = model.RealClock{}
	}
	return &Selector{
		clock:   clock,
		rng:     rand.New(rand.NewSource(seed)),
		rrIndex: make(map[int]int),
	}
}

// Select chooses a proxy from candidates according to pool rules, required capabilities (INV-08),
// strategy, and hysteresis, returning both the chosen ProxyRecord and a structured DecisionTrace.
func (s *Selector) Select(pool PoolConfig, candidates []storage.ProxyRecord, req SelectionRequest) (*storage.ProxyRecord, model.DecisionTrace, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.clock.Now()
	trace := model.DecisionTrace{
		Timestamp:            now,
		Component:            "pool",
		RuleMatched:          fmt.Sprintf("pool:%s (kind=%s, strategy=%s)", pool.Name, pool.Kind, pool.Strategy),
		CandidatesConsidered: len(candidates),
	}

	needConnect := pool.RequireConnect || req.RequireConnect
	needRemoteDNS := pool.RequireRemoteDNS || req.RequireRemoteDNS

	var eligible []storage.ProxyRecord
	var activeProxy *storage.ProxyRecord

	for _, c := range candidates {
		label := fmt.Sprintf("%s://%s:%d (id=%d)", c.Protocol, c.Host, c.Port, c.ID)
		if reason, excluded := req.ExcludeProxyIDs[c.ID]; excluded {
			trace.Excluded = append(trace.Excluded, model.CandidateExclusion{Candidate: label, Reason: "failover_excluded: " + reason})
			continue
		}
		if c.Status == model.StatusQuarantined {
			if c.QuarantineUntil != "" {
				if qTime, err := time.Parse(time.RFC3339, c.QuarantineUntil); err == nil && now.Before(qTime) {
					trace.Excluded = append(trace.Excluded, model.CandidateExclusion{Candidate: label, Reason: "quarantined until " + c.QuarantineUntil})
					continue
				}
			}
			trace.Excluded = append(trace.Excluded, model.CandidateExclusion{Candidate: label, Reason: "status is quarantined"})
			continue
		}
		if c.Status != model.StatusHealthy && c.Status != model.StatusDegraded {
			trace.Excluded = append(trace.Excluded, model.CandidateExclusion{Candidate: label, Reason: fmt.Sprintf("status is %s (requires healthy/degraded)", c.Status)})
			continue
		}
		if pool.RequiredProtocol != "" && c.Protocol != pool.RequiredProtocol {
			trace.Excluded = append(trace.Excluded, model.CandidateExclusion{Candidate: label, Reason: fmt.Sprintf("protocol mismatch (%s != %s)", c.Protocol, pool.RequiredProtocol)})
			continue
		}
		if pool.CountryCode != "" && c.CountryCode != pool.CountryCode {
			trace.Excluded = append(trace.Excluded, model.CandidateExclusion{Candidate: label, Reason: fmt.Sprintf("country mismatch (%q != %q)", c.CountryCode, pool.CountryCode)})
			continue
		}
		if pool.MinScore > 0 && c.Score < pool.MinScore {
			trace.Excluded = append(trace.Excluded, model.CandidateExclusion{Candidate: label, Reason: fmt.Sprintf("score %.1f < min_score %.1f", c.Score, pool.MinScore)})
			continue
		}
		// Enforce INV-08: only confirmed & fresh capabilities are usable
		if needConnect && !c.Capabilities.Connect.IsUsable(now, req.CapabilityTTL) {
			st := c.Capabilities.Connect.EffectiveState(now, req.CapabilityTTL)
			trace.Excluded = append(trace.Excluded, model.CandidateExclusion{Candidate: label, Reason: fmt.Sprintf("capability connect is %s (requires confirmed)", st)})
			continue
		}
		if needRemoteDNS && !c.Capabilities.RemoteDNS.IsUsable(now, req.CapabilityTTL) {
			st := c.Capabilities.RemoteDNS.EffectiveState(now, req.CapabilityTTL)
			trace.Excluded = append(trace.Excluded, model.CandidateExclusion{Candidate: label, Reason: fmt.Sprintf("capability remote_dns is %s (requires confirmed)", st)})
			continue
		}

		cCopy := c
		if pool.ActiveProxyID != nil && c.ID == *pool.ActiveProxyID {
			activeProxy = &cCopy
		}
		eligible = append(eligible, cCopy)
	}

	if len(eligible) == 0 {
		trace.SelectionReason = "no candidate passed status, filter, and capability checks"
		return nil, trace, ErrNoMatchingCandidate
	}

	// Sort eligible candidates according to pool Kind (fast sorts by AvgTotalMs asc, others by Score desc)
	sort.SliceStable(eligible, func(i, j int) bool {
		if pool.Kind == "fast" {
			msI := 999999
			if eligible[i].AvgTotalMs != nil {
				msI = *eligible[i].AvgTotalMs
			}
			msJ := 999999
			if eligible[j].AvgTotalMs != nil {
				msJ = *eligible[j].AvgTotalMs
			}
			if msI != msJ {
				return msI < msJ
			}
		}
		if eligible[i].Score != eligible[j].Score {
			return eligible[i].Score > eligible[j].Score
		}
		return eligible[i].ID < eligible[j].ID
	})

	var chosen storage.ProxyRecord
	switch pool.Strategy {
	case "fixed":
		if activeProxy != nil {
			chosen = *activeProxy
			trace.SelectionReason = "fixed strategy retained configured active proxy"
		} else {
			trace.SelectionReason = "fixed proxy is unavailable or unhealthy"
			return nil, trace, ErrNoMatchingCandidate
		}

	case "round_robin":
		idx := s.rrIndex[pool.ID] % len(eligible)
		chosen = eligible[idx]
		s.rrIndex[pool.ID] = (idx + 1) % len(eligible)
		trace.SelectionReason = fmt.Sprintf("round_robin selected slot %d of %d eligible candidates", idx, len(eligible))

	case "weighted":
		totalScore := 0.0
		for _, e := range eligible {
			w := e.Score
			if w < 1.0 {
				w = 1.0
			}
			totalScore += w
		}
		pick := s.rng.Float64() * totalScore
		accum := 0.0
		chosen = eligible[0]
		for _, e := range eligible {
			w := e.Score
			if w < 1.0 {
				w = 1.0
			}
			accum += w
			if pick <= accum {
				chosen = e
				break
			}
		}
		trace.SelectionReason = fmt.Sprintf("weighted strategy selected candidate (score=%.1f)", chosen.Score)

	case "failover", "best_score":
		fallthrough
	default:
		top := eligible[0]
		delta := pool.HysteresisDelta
		if delta <= 0 {
			delta = 5.0
		}
		if activeProxy != nil && activeProxy.Status == model.StatusHealthy {
			if activeProxy.ID == top.ID {
				chosen = *activeProxy
				trace.SelectionReason = fmt.Sprintf("retained active healthy proxy (top score %.1f)", chosen.Score)
			} else if top.Score < activeProxy.Score+delta {
				chosen = *activeProxy
				trace.SelectionReason = fmt.Sprintf("hysteresis retained active proxy (score %.1f; challenger %.1f did not exceed delta +%.1f)", activeProxy.Score, top.Score, delta)
			} else {
				chosen = top
				trace.FailoverReason = fmt.Sprintf("switched from proxy id=%d (score %.1f) to id=%d (score %.1f >= %.1f + %.1f)", activeProxy.ID, activeProxy.Score, top.ID, top.Score, activeProxy.Score, delta)
				trace.SelectionReason = "challenger exceeded hysteresis threshold"
			}
		} else {
			chosen = top
			if pool.ActiveProxyID != nil && (activeProxy == nil || activeProxy.Status != model.StatusHealthy) {
				trace.FailoverReason = fmt.Sprintf("previous active proxy id=%d became unavailable or degraded", *pool.ActiveProxyID)
			}
			trace.SelectionReason = fmt.Sprintf("selected highest-ranked eligible candidate (score=%.1f)", chosen.Score)
		}
	}

	trace.SelectedCandidate = fmt.Sprintf("%s://%s:%d (id=%d)", chosen.Protocol, chosen.Host, chosen.Port, chosen.ID)
	return &chosen, trace, nil
}
