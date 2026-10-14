package model

import (
	"testing"
	"time"
)

func TestCapabilityStateTransitionsAndUsability(t *testing.T) {
	t0 := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	clk := NewFakeClock(t0)
	ttl := 30 * time.Minute

	// 1. Unknown is not usable
	rec := CapabilityRecord{State: CapabilityUnknown}
	if rec.IsUsable(clk.Now(), ttl) {
		t.Fatal("unknown capability must not be usable")
	}

	// 2. Unsupported is not usable
	rec.State = CapabilityUnsupported
	if rec.IsUsable(clk.Now(), ttl) {
		t.Fatal("unsupported capability must not be usable")
	}

	// 3. TransientError is not usable
	rec.State = CapabilityTransientError
	if rec.IsUsable(clk.Now(), ttl) {
		t.Fatal("transient_error capability must not be usable")
	}

	// 4. Confirmed within TTL is usable
	verifiedAt := clk.Now()
	rec = CapabilityRecord{State: CapabilityConfirmed, VerifiedAt: &verifiedAt}
	if !rec.IsUsable(clk.Now(), ttl) {
		t.Fatal("confirmed fresh capability must be usable")
	}

	// 5. Confirmed past TTL transitions to stale and is not usable
	clk.Advance(31 * time.Minute)
	if got := rec.EffectiveState(clk.Now(), ttl); got != CapabilityStale {
		t.Fatalf("expected CapabilityStale after TTL, got %s", got)
	}
	if rec.IsUsable(clk.Now(), ttl) {
		t.Fatal("stale capability must not be usable")
	}
}
