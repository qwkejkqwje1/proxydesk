package scoring

import (
	"encoding/json"
	"math"
	"time"

	"github.com/proxydesk/proxydesk/internal/checker"
	"github.com/proxydesk/proxydesk/internal/config"
	"github.com/proxydesk/proxydesk/internal/model"
	"github.com/proxydesk/proxydesk/internal/storage"
)

type ScoreBreakdown struct {
	ReliabilityComponent float64 `json:"reliability_component"`
	LatencyComponent     float64 `json:"latency_component"`
	StabilityComponent   float64 `json:"stability_component"`
	FreshnessComponent   float64 `json:"freshness_component"`
	RawWeightedScore     float64 `json:"raw_weighted_score"`
	HeuristicConfidence  float64 `json:"heuristic_confidence"`
	ConfidenceNote       string  `json:"confidence_note"`
	FinalScore           float64 `json:"final_score"`
	RotatingExitIP       bool    `json:"rotating_exit_ip"`
}

type Scorer struct {
	cfg   *config.Config
	store *storage.Store
	clock model.Clock
}

func NewScorer(cfg *config.Config, store *storage.Store, clock model.Clock) *Scorer {
	if clock == nil {
		clock = model.RealClock{}
	}
	return &Scorer{cfg: cfg, store: store, clock: clock}
}

// ApplyCycleResult updates a proxy record in memory (and optionally persists to SQLite)
// based on an aggregated check cycle outcome.
// Enforces INV-04: inconclusive and cancelled outcomes never penalize reliability or status.
func (s *Scorer) ApplyCycleResult(p storage.ProxyRecord, cycle checker.CycleResult) (storage.ProxyRecord, ScoreBreakdown) {
	now := cycle.CheckedAt
	if now.IsZero() {
		now = s.clock.Now()
	}
	nowStr := now.UTC().Format(time.RFC3339)

	// Inconclusive or Cancelled: do not penalize reliability, consecutive_failures, or status (INV-04)
	if cycle.Outcome == checker.OutcomeInconclusive || cycle.Outcome == checker.OutcomeCancelled {
		p.LastCheckedAt = nowStr
		bd := s.RecomputeScore(p, now)
		p.Score = bd.FinalScore
		p.Confidence = bd.HeuristicConfidence
		return p, bd
	}

	if p.FirstCheckedAt == "" {
		p.FirstCheckedAt = nowStr
	}
	p.LastCheckedAt = nowStr
	p.Capabilities = cycle.Capabilities

	prevCycles := p.CyclesCount
	p.CyclesCount = prevCycles + 1

	if cycle.Outcome == checker.OutcomeSuccess {
		// Update EWMA / cumulative success rate across independent cycles
		if prevCycles == 0 {
			p.SuccessRate = 1.0
		} else {
			p.SuccessRate = (p.SuccessRate*float64(prevCycles)*0.85 + 1.0) / (float64(prevCycles)*0.85 + 1.0)
		}
		p.ConsecutiveFailures = 0
		p.QuarantineUntil = ""
		p.LastHealthyAt = nowStr
		p.Status = model.StatusHealthy

		// Update timings without replacing nil with 0 when unmeasured
		p.AvgConnectMs = blendTiming(p.AvgConnectMs, cycle.ConnectMs)
		p.AvgHandshakeMs = blendTiming(p.AvgHandshakeMs, cycle.HandshakeMs)
		p.AvgTTFBMs = blendTiming(p.AvgTTFBMs, cycle.TTFBMs)
		p.AvgTotalMs = blendTiming(p.AvgTotalMs, cycle.TotalMs)

		// Track exit IP changes as an informational attribute (not a reliability penalty)
		if cycle.ExitIP != "" {
			if p.ExitIP != "" && p.ExitIP != cycle.ExitIP {
				p.ExitIPChanges++
				p.RotatingExitIP = true
			}
			p.ExitIP = cycle.ExitIP
		}
		p.NextCheckAt = now.Add(15 * time.Minute).UTC().Format(time.RFC3339)
	} else {
		// OutcomeFailure
		if prevCycles == 0 {
			p.SuccessRate = 0.0
		} else {
			p.SuccessRate = (p.SuccessRate * float64(prevCycles) * 0.85) / (float64(prevCycles)*0.85 + 1.0)
		}
		p.ConsecutiveFailures++

		if p.ConsecutiveFailures >= 3 {
			p.Status = model.StatusQuarantined
			cooldown := ComputeQuarantineCooldown(p.ConsecutiveFailures)
			qUntil := now.Add(cooldown).UTC().Format(time.RFC3339)
			p.QuarantineUntil = qUntil
			p.NextCheckAt = qUntil // Trial recovery probe scheduled after cooldown
		} else {
			p.Status = model.StatusDegraded
			p.NextCheckAt = now.Add(2 * time.Minute).UTC().Format(time.RFC3339)
		}
	}

	bd := s.RecomputeScore(p, now)
	p.Score = bd.FinalScore
	p.Confidence = bd.HeuristicConfidence
	rawBD, _ := json.Marshal(bd)
	_ = json.Unmarshal(rawBD, &p.ScoreBreakdown)
	return p, bd
}

// ComputeQuarantineCooldown calculates deterministic exponential cooldown for quarantined proxies.
func ComputeQuarantineCooldown(consecutiveFailures int) time.Duration {
	shift := consecutiveFailures - 3
	if shift < 0 {
		shift = 0
	}
	if shift > 5 {
		shift = 5
	}
	return time.Duration(5*(1<<shift)) * time.Minute // 5m, 10m, 20m, 40m, 80m, 160m
}

// RecomputeScore calculates the 0-100 score and heuristic observation confidence.
// Note: HeuristicConfidence is explicitly labeled as an observation heuristic combining
// independent cycle count and temporal span, not a statistical confidence interval.
func (s *Scorer) RecomputeScore(p storage.ProxyRecord, now time.Time) ScoreBreakdown {
	if p.CyclesCount == 0 {
		return ScoreBreakdown{
			ConfidenceNote: "Эвристика полноты наблюдений: 0 проверок (статус unknown)",
			RotatingExitIP: p.RotatingExitIP,
		}
	}

	// 1. Heuristic Confidence (0.0 .. 1.0): combines cycle count factor (70%) and temporal span factor (30%)
	countFactor := 1.0 - math.Exp(-float64(p.CyclesCount)/5.0)
	spanFactor := 0.0
	if p.FirstCheckedAt != "" && p.LastCheckedAt != "" {
		tFirst, err1 := time.Parse(time.RFC3339, p.FirstCheckedAt)
		tLast, err2 := time.Parse(time.RFC3339, p.LastCheckedAt)
		if err1 == nil && err2 == nil && tLast.After(tFirst) {
			hours := tLast.Sub(tFirst).Hours()
			spanFactor = math.Min(1.0, hours/24.0) // Full temporal span credit after 24h of observation
		}
	}
	confidence := round2(0.70*countFactor + 0.30*spanFactor)

	// 2. Reliability component (0..100)
	relComp := p.SuccessRate * 100.0
	if p.ConsecutiveFailures > 0 {
		penalty := math.Min(60.0, float64(p.ConsecutiveFailures)*18.0)
		relComp = math.Max(0.0, relComp-penalty)
	}

	// 3. Latency component (0..100): never treat nil latency as 0ms!
	latComp := 0.0
	if p.AvgTotalMs != nil && *p.AvgTotalMs > 0 {
		ms := float64(*p.AvgTotalMs)
		if ms <= 150 {
			latComp = 100.0
		} else if ms >= 5000 {
			latComp = 0.0
		} else {
			latComp = 100.0 * (1.0 - math.Log10(ms/150.0)/math.Log10(5000.0/150.0))
		}
	}

	// 4. Stability component (0..100): based on low consecutive failures and consistent timings
	stabComp := 100.0
	if p.ConsecutiveFailures == 1 {
		stabComp = 65.0
	} else if p.ConsecutiveFailures == 2 {
		stabComp = 35.0
	} else if p.ConsecutiveFailures >= 3 {
		stabComp = 5.0
	}

	// 5. Freshness component (0..100): strictly based on last_healthy_at (Increment D requirement)
	freshComp := 0.0
	if p.LastHealthyAt != "" {
		if tHealthy, err := time.Parse(time.RFC3339, p.LastHealthyAt); err == nil {
			ageMin := math.Max(0.0, now.Sub(tHealthy).Minutes())
			// Half-life of 60 minutes
			freshComp = 100.0 * math.Exp(-ageMin/90.0)
		}
	}

	w := s.cfg.Weights
	rawScore := w.Reliability*relComp + w.Latency*latComp + w.Stability*stabComp + w.Freshness*freshComp
	// Damping factor ensures a brand-new proxy with 1 check (confidence ~0.13) cannot outrank a proven proxy
	finalScore := rawScore * (0.35 + 0.65*confidence)
	if p.Status == model.StatusQuarantined {
		finalScore = math.Min(finalScore, 15.0)
	}

	return ScoreBreakdown{
		ReliabilityComponent: round2(relComp),
		LatencyComponent:     round2(latComp),
		StabilityComponent:   round2(stabComp),
		FreshnessComponent:   round2(freshComp),
		RawWeightedScore:     round2(rawScore),
		HeuristicConfidence:  confidence,
		ConfidenceNote:       "Эвристика полноты наблюдений (число независимых циклов и временной охват, не стат. доверительный интервал)",
		FinalScore:           round2(finalScore),
		RotatingExitIP:       p.RotatingExitIP,
	}
}

// SaveCycleAndPrune persists the cycle and target results and enforces storage retention limits.
func (s *Scorer) SaveCycleAndPrune(p storage.ProxyRecord, cycle checker.CycleResult) (storage.ProxyRecord, ScoreBreakdown, error) {
	updated, bd := s.ApplyCycleResult(p, cycle)
	if s.store == nil {
		return updated, bd, nil
	}
	db := s.store.DB()
	nowStr := cycle.CheckedAt.UTC().Format(time.RFC3339)

	res, err := db.Exec(`
		INSERT INTO check_cycles (
			proxy_id, checked_at, outcome, targets_tested, targets_succeeded,
			connect_ms, handshake_ms, ttfb_ms, total_ms, exit_ip, summary_error
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		updated.ID, nowStr, string(cycle.Outcome), cycle.TargetsTested, cycle.TargetsSucceeded,
		cycle.ConnectMs, cycle.HandshakeMs, cycle.TTFBMs, cycle.TotalMs, cycle.ExitIP, cycle.SummaryError,
	)
	if err != nil {
		return updated, bd, err
	}
	cycleID, _ := res.LastInsertId()

	for _, tr := range cycle.TargetResults {
		_, _ = db.Exec(`
			INSERT INTO check_target_results (
				cycle_id, proxy_id, target_url, checked_at, outcome, stage_failed,
				connect_ms, handshake_ms, ttfb_ms, total_ms, exit_ip, error_detail
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			cycleID, updated.ID, tr.TargetURL, nowStr, string(tr.Outcome), tr.StageFailed,
			tr.ConnectMs, tr.HandshakeMs, tr.TTFBMs, tr.TotalMs, tr.ExitIP, tr.ErrorDetail,
		)
	}

	capJSON, _ := json.Marshal(updated.Capabilities)
	bdJSON, _ := json.Marshal(bd)
	_, err = db.Exec(`
		UPDATE proxies SET
			status = ?, score = ?, confidence = ?, cycles_count = ?, success_rate = ?,
			avg_connect_ms = ?, avg_handshake_ms = ?, avg_ttfb_ms = ?, avg_total_ms = ?,
			exit_ip = ?, rotating_exit_ip = ?, exit_ip_changes = ?,
			capabilities_json = ?, score_breakdown_json = ?,
			consecutive_failures = ?, quarantine_until = ?,
			first_checked_at = ?, last_checked_at = ?, last_healthy_at = ?, next_check_at = ?
		WHERE id = ?`,
		string(updated.Status), updated.Score, updated.Confidence, updated.CyclesCount, updated.SuccessRate,
		updated.AvgConnectMs, updated.AvgHandshakeMs, updated.AvgTTFBMs, updated.AvgTotalMs,
		updated.ExitIP, boolToInt(updated.RotatingExitIP), updated.ExitIPChanges,
		string(capJSON), string(bdJSON),
		updated.ConsecutiveFailures, updated.QuarantineUntil,
		updated.FirstCheckedAt, updated.LastCheckedAt, updated.LastHealthyAt, updated.NextCheckAt,
		updated.ID,
	)
	if err != nil {
		return updated, bd, err
	}

	// Enforce history budget per proxy (default 50 cycles) and retention days (default 14 days)
	maxHistory := s.cfg.Budgets.MaxHistoryPerProxy
	if maxHistory <= 0 {
		maxHistory = 50
	}
	cutoff := cycle.CheckedAt.AddDate(0, 0, -s.cfg.Budgets.HistoryRetentionDays).UTC().Format(time.RFC3339)
	_, _ = db.Exec(`
		DELETE FROM check_cycles
		WHERE proxy_id = ? AND (
			checked_at < ? OR id NOT IN (
				SELECT id FROM check_cycles WHERE proxy_id = ? ORDER BY checked_at DESC, id DESC LIMIT ?
			)
		)`, updated.ID, cutoff, updated.ID, maxHistory)

	return updated, bd, nil
}

func blendTiming(prev *int, cur *int) *int {
	if cur == nil {
		return prev
	}
	if prev == nil {
		v := *cur
		return &v
	}
	blended := int(math.Round(float64(*prev)*0.7 + float64(*cur)*0.3))
	return &blended
}

func round2(v float64) float64 {
	return math.Round(v*100) / 100
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
