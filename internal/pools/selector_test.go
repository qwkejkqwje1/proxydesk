package pools

import (
	"errors"
	"testing"
	"time"

	"github.com/proxydesk/proxydesk/internal/model"
	"github.com/proxydesk/proxydesk/internal/storage"
)

func TestInvariant_UnsupportedOrUnknownCapabilityRejectedAndHysteresisWorks(t *testing.T) {
	t0 := time.Date(2026, 10, 13, 14, 0, 0, 0, time.UTC)
	clk := model.NewFakeClock(t0)
	sel := NewSelector(clk, 100)

	confirmedCap := model.CapabilityRecord{State: model.CapabilityConfirmed, VerifiedAt: &t0}
	unknownCap := model.CapabilityRecord{State: model.CapabilityUnknown}
	unsupportedCap := model.CapabilityRecord{State: model.CapabilityUnsupported}

	activeID := 2
	pool := PoolConfig{
		ID:              1,
		Name:            "HTTPS Pool",
		Kind:            "reliable",
		Strategy:        "best_score",
		RequireConnect:  true,
		HysteresisDelta: 5.0,
		ActiveProxyID:   &activeID,
	}

	candidates := []storage.ProxyRecord{
		{
			ID: 1, Protocol: "http", Host: "198.51.100.1", Port: 8080,
			Status: model.StatusHealthy, Score: 95.0,
			Capabilities: model.ProxyCapabilities{Connect: unknownCap}, // High score, but CONNECT is unknown!
		},
		{
			ID: 2, Protocol: "http", Host: "198.51.100.2", Port: 8080,
			Status: model.StatusHealthy, Score: 80.0,
			Capabilities: model.ProxyCapabilities{Connect: confirmedCap}, // Active proxy
		},
		{
			ID: 3, Protocol: "http", Host: "198.51.100.3", Port: 8080,
			Status: model.StatusHealthy, Score: 83.0,
			Capabilities: model.ProxyCapabilities{Connect: confirmedCap}, // Challenger within +5.0 hysteresis delta
		},
		{
			ID: 4, Protocol: "http", Host: "198.51.100.4", Port: 8080,
			Status: model.StatusHealthy, Score: 99.0,
			Capabilities: model.ProxyCapabilities{Connect: unsupportedCap},
		},
	}

	// 1. Proxy 1 (unknown connect) and Proxy 4 (unsupported connect) must be rejected (INV-08).
	// Proxy 2 (score 80.0) must be retained over Proxy 3 (score 83.0) due to 5.0 hysteresis delta.
	chosen, trace, err := sel.Select(pool, candidates, SelectionRequest{RequireConnect: true, CapabilityTTL: 30 * time.Minute})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if chosen.ID != 2 {
		t.Fatalf("expected hysteresis to retain proxy ID=2, got ID=%d (trace=%+v)", chosen.ID, trace)
	}
	if len(trace.Excluded) != 2 {
		t.Fatalf("expected 2 excluded candidates in DecisionTrace, got %d: %+v", len(trace.Excluded), trace.Excluded)
	}

	// 2. When Proxy 3's score rises to 86.0 (>= 80.0 + 5.0), selector switches and records FailoverReason
	candidates[2].Score = 86.0
	chosen2, trace2, err := sel.Select(pool, candidates, SelectionRequest{RequireConnect: true, CapabilityTTL: 30 * time.Minute})
	if err != nil || chosen2.ID != 3 || trace2.FailoverReason == "" {
		t.Fatalf("expected switch to proxy ID=3 with failover reason, got chosen=%+v trace=%+v", chosen2, trace2)
	}

	// 3. When TTL expires (31m later), confirmed capability becomes stale and pool returns ErrNoMatchingCandidate
	clk.Advance(31 * time.Minute)
	_, _, errStale := sel.Select(pool, candidates, SelectionRequest{RequireConnect: true, CapabilityTTL: 30 * time.Minute})
	if !errors.Is(errStale, ErrNoMatchingCandidate) {
		t.Fatalf("expected ErrNoMatchingCandidate when capabilities are stale, got %v", errStale)
	}
}
