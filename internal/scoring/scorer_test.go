package scoring

import (
	"testing"
	"time"

	"github.com/proxydesk/proxydesk/internal/checker"
	"github.com/proxydesk/proxydesk/internal/config"
	"github.com/proxydesk/proxydesk/internal/model"
	"github.com/proxydesk/proxydesk/internal/storage"
)

func TestNewcomerLowConfidenceAndVeteranOutranksNewcomer(t *testing.T) {
	cfg := config.DefaultConfig()
	clk := model.NewFakeClock(time.Date(2026, 10, 13, 10, 0, 0, 0, time.UTC))
	scorer := NewScorer(&cfg, nil, clk)

	// 1. Newcomer with 1 very fast check (80ms)
	fastMs := 80
	newcomer := storage.ProxyRecord{ID: 1, Status: model.StatusUnknown, Capabilities: model.DefaultCapabilities()}
	newcomer, bdNew := scorer.ApplyCycleResult(newcomer, checker.CycleResult{
		ProxyID: 1, CheckedAt: clk.Now(), Outcome: checker.OutcomeSuccess,
		TargetsTested: 3, TargetsSucceeded: 3, TotalMs: &fastMs, ExitIP: "198.51.100.1",
	})

	if newcomer.CyclesCount != 1 {
		t.Fatalf("3 targets in 1 cycle must count as 1 cycle, got %d", newcomer.CyclesCount)
	}
	if newcomer.Confidence > 0.20 {
		t.Fatalf("newcomer with 1 check must have low confidence (<=0.20), got %v", newcomer.Confidence)
	}

	// 2. Veteran with 15 consistent checks across 24 hours at 220ms
	vetMs := 220
	veteran := storage.ProxyRecord{ID: 2, Status: model.StatusUnknown, Capabilities: model.DefaultCapabilities()}
	for i := 0; i < 15; i++ {
		veteran, _ = scorer.ApplyCycleResult(veteran, checker.CycleResult{
			ProxyID: 2, CheckedAt: clk.Now(), Outcome: checker.OutcomeSuccess,
			TargetsTested: 2, TargetsSucceeded: 2, TotalMs: &vetMs, ExitIP: "203.0.113.5",
		})
		clk.Advance(2 * time.Hour)
	}

	if veteran.Score <= newcomer.Score {
		t.Fatalf("veteran score (%v) must exceed 1-check newcomer score (%v); bdNew=%+v", veteran.Score, newcomer.Score, bdNew)
	}
}

func TestInvariant_InconclusiveAndCancelledDoNotPenalizeAndQuarantineRecovers(t *testing.T) {
	cfg := config.DefaultConfig()
	clk := model.NewFakeClock(time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC))
	scorer := NewScorer(&cfg, nil, clk)

	ms := 150
	p := storage.ProxyRecord{ID: 10, Status: model.StatusUnknown}
	p, _ = scorer.ApplyCycleResult(p, checker.CycleResult{
		ProxyID: 10, CheckedAt: clk.Now(), Outcome: checker.OutcomeSuccess, TotalMs: &ms, ExitIP: "198.51.100.10",
	})
	scoreBefore := p.Score

	// Inconclusive and Cancelled must not increment consecutive_failures or degrade status (INV-04)
	p, _ = scorer.ApplyCycleResult(p, checker.CycleResult{
		ProxyID: 10, CheckedAt: clk.Now(), Outcome: checker.OutcomeInconclusive,
	})
	p, _ = scorer.ApplyCycleResult(p, checker.CycleResult{
		ProxyID: 10, CheckedAt: clk.Now(), Outcome: checker.OutcomeCancelled,
	})
	if p.Status != model.StatusHealthy || p.ConsecutiveFailures != 0 || p.Score != scoreBefore {
		t.Fatalf("inconclusive/cancelled mutated healthy state: %+v", p)
	}

	// 3 consecutive real failures transition proxy to quarantined with 5m cooldown
	for i := 0; i < 3; i++ {
		clk.Advance(1 * time.Minute)
		p, _ = scorer.ApplyCycleResult(p, checker.CycleResult{
			ProxyID: 10, CheckedAt: clk.Now(), Outcome: checker.OutcomeFailure,
		})
	}
	if p.Status != model.StatusQuarantined || p.QuarantineUntil == "" {
		t.Fatalf("expected StatusQuarantined after 3 failures, got %s", p.Status)
	}

	// Trial recovery after cooldown restores StatusHealthy and tracks rotating ExitIP without penalty
	clk.Advance(6 * time.Minute)
	p, _ = scorer.ApplyCycleResult(p, checker.CycleResult{
		ProxyID: 10, CheckedAt: clk.Now(), Outcome: checker.OutcomeSuccess, TotalMs: &ms, ExitIP: "198.51.100.99",
	})
	if p.Status != model.StatusHealthy || !p.RotatingExitIP || p.ExitIPChanges != 1 {
		t.Fatalf("expected recovery to StatusHealthy and RotatingExitIP=true, got %+v", p)
	}
}
