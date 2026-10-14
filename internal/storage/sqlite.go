package storage

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/proxydesk/proxydesk/internal/model"
	"github.com/proxydesk/proxydesk/internal/parsers"
	"github.com/proxydesk/proxydesk/internal/rules"
	_ "modernc.org/sqlite"
)

//go:embed migrations/001_init.sql
var migration001SQL string

const CurrentSchemaVersion = 1

var (
	ErrIncompatibleBackupVersion = errors.New("backup database schema version is incompatible")
	ErrRecordNotFound            = errors.New("record not found")
)

type Store struct {
	mu     sync.RWMutex
	db     *sql.DB
	dbPath string
}

type ProxyRecord struct {
	ID                  int                     `json:"id"`
	DedupKey            string                  `json:"dedup_key"`
	Protocol            string                  `json:"protocol"`
	Host                string                  `json:"host"`
	Port                int                     `json:"port"`
	HasAuth             bool                    `json:"has_auth"`
	Status              model.ProxyStatus       `json:"status"`
	Score               float64                 `json:"score"`
	Confidence          float64                 `json:"confidence"`
	CyclesCount         int                     `json:"cycles_count"`
	SuccessRate         float64                 `json:"success_rate"`
	AvgConnectMs        *int                    `json:"avg_connect_ms"`
	AvgHandshakeMs      *int                    `json:"avg_handshake_ms"`
	AvgTTFBMs           *int                    `json:"avg_ttfb_ms"`
	AvgTotalMs          *int                    `json:"avg_total_ms"`
	ExitIP              string                  `json:"exit_ip"`
	RotatingExitIP      bool                    `json:"rotating_exit_ip"`
	ExitIPChanges       int                     `json:"exit_ip_changes"`
	CountryCode         string                  `json:"country_code"`
	ASN                 int                     `json:"asn"`
	ASNOrg              string                  `json:"asn_org"`
	Capabilities        model.ProxyCapabilities `json:"capabilities"`
	ScoreBreakdown      map[string]any          `json:"score_breakdown"`
	ConsecutiveFailures int                     `json:"consecutive_failures"`
	QuarantineUntil     string                  `json:"quarantine_until"`
	FirstCheckedAt      string                  `json:"first_checked_at"`
	LastCheckedAt       string                  `json:"last_checked_at"`
	LastHealthyAt       string                  `json:"last_healthy_at"`
	NextCheckAt         string                  `json:"next_check_at"`
	CreatedAt           string                  `json:"created_at"`
	SourcesCount        int                     `json:"sources_count"`
}

type SourceRecord struct {
	ID                  int    `json:"id"`
	Name                string `json:"name"`
	Kind                string `json:"kind"`
	Location            string `json:"location"`
	Format              string `json:"format"`
	DefaultProtocol     string `json:"default_protocol"`
	AllowPrivate        bool   `json:"allow_private"`
	UpdateIntervalSec   int    `json:"update_interval_sec"`
	TimeoutSec          int    `json:"timeout_sec"`
	Enabled             bool   `json:"enabled"`
	ETag                string `json:"etag"`
	LastModified        string `json:"last_modified"`
	BackoffUntil        string `json:"backoff_until"`
	ConsecutiveFailures int    `json:"consecutive_failures"`
	LastRunAt           string `json:"last_run_at"`
	LastStatus          string `json:"last_status"`
	LastError           string `json:"last_error"`
	TotalParsed         int    `json:"total_parsed"`
	TotalUnique         int    `json:"total_unique"`
	TotalErrors         int    `json:"total_errors"`
	VerifiedDate        string `json:"verified_date"`
	CreatedAt           string `json:"created_at"`
}

type PoolRecord struct {
	ID               int     `json:"id"`
	Name             string  `json:"name"`
	Kind             string  `json:"kind"`
	Strategy         string  `json:"strategy"`
	RequiredProtocol string  `json:"required_protocol,omitempty"`
	RequireConnect   bool    `json:"require_connect"`
	RequireRemoteDNS bool    `json:"require_remote_dns"`
	MinScore         float64 `json:"min_score"`
	CountryCode      string  `json:"country_code,omitempty"`
	HysteresisDelta  float64 `json:"hysteresis_delta"`
	ActiveProxyID    *int    `json:"active_proxy_id,omitempty"`
	IsDefault        bool    `json:"is_default"`
	MemberProxyIDs   []int   `json:"member_proxy_ids,omitempty"`
	CreatedAt        string  `json:"created_at"`
}

type DNSUpstreamEndpoint struct {
	Protocol string `json:"protocol"`
	Address  string `json:"address"`
}

type DNSGroupRecord struct {
	ID                  int                   `json:"id"`
	Name                string                `json:"name"`
	Upstreams           []DNSUpstreamEndpoint `json:"upstreams"`
	BootstrapIPs        []string              `json:"bootstrap_ips,omitempty"`
	AllowPublicFallback bool                  `json:"allow_public_fallback"`
	IsDefault           bool                  `json:"is_default"`
	CreatedAt           string                `json:"created_at"`
}

func Open(dataDir string) (*Store, error) {
	dbPath := filepath.Join(dataDir, "proxydesk.db")
	db, err := openSQLiteDB(dbPath)
	if err != nil {
		return nil, err
	}
	s := &Store{db: db, dbPath: dbPath}
	if err := s.Migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func openSQLiteDB(dbPath string) (*sql.DB, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(ON)", filepath.ToSlash(dbPath))
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1)
	return db, nil
}

func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return nil
	}
	_, _ = s.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE);`)
	err := s.db.Close()
	s.db = nil
	return err
}

func (s *Store) DB() *sql.DB {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.db
}

func (s *Store) Migrate() error {
	db := s.DB()
	if _, err := db.Exec(migration001SQL); err != nil {
		return fmt.Errorf("apply migration 001: %w", err)
	}
	var maxVer sql.NullInt64
	if err := db.QueryRow(`SELECT MAX(version) FROM schema_migrations`).Scan(&maxVer); err != nil {
		return fmt.Errorf("check schema_migrations: %w", err)
	}
	if maxVer.Valid && maxVer.Int64 > CurrentSchemaVersion {
		return fmt.Errorf("%w: database has schema version %d, supported %d", ErrIncompatibleBackupVersion, maxVer.Int64, CurrentSchemaVersion)
	}
	if !maxVer.Valid || maxVer.Int64 < 1 {
		_, err := db.Exec(`INSERT INTO schema_migrations(version, applied_at) VALUES (1, ?)`, time.Now().UTC().Format(time.RFC3339))
		if err != nil {
			return fmt.Errorf("record migration version: %w", err)
		}
	}
	return s.SeedDefaultsIfEmpty()
}

func (s *Store) SeedDefaultsIfEmpty() error {
	db := s.DB()
	now := time.Now().UTC().Format(time.RFC3339)

	// 1. Seed verified preset sources (disabled auto-run until user triggers or schedule elapses)
	var srcCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sources`).Scan(&srcCount); err != nil {
		return err
	}
	if srcCount == 0 {
		presets := []SourceRecord{
			{
				Name:              "monosans/proxy-list (All TXT)",
				Kind:              "url",
				Location:          "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/all.txt",
				Format:            "txt",
				DefaultProtocol:   "http",
				UpdateIntervalSec: 3600,
				TimeoutSec:        15,
				Enabled:           true,
				VerifiedDate:      "2026-10-13",
				CreatedAt:         now,
			},
			{
				Name:              "monosans/proxy-list (SOCKS5 TXT)",
				Kind:              "url",
				Location:          "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
				Format:            "txt",
				DefaultProtocol:   "socks5",
				UpdateIntervalSec: 3600,
				TimeoutSec:        15,
				Enabled:           true,
				VerifiedDate:      "2026-10-13",
				CreatedAt:         now,
			},
			{
				Name:              "monosans/proxy-list (Metadata JSON)",
				Kind:              "url",
				Location:          "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies.json",
				Format:            "json",
				DefaultProtocol:   "http",
				UpdateIntervalSec: 3600,
				TimeoutSec:        15,
				Enabled:           false,
				VerifiedDate:      "2026-10-13",
				CreatedAt:         now,
			},
		}
		for _, p := range presets {
			if _, err := s.CreateSource(p); err != nil {
				return err
			}
		}
	}

	// 2. Seed default Pool if empty
	var poolCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM pools`).Scan(&poolCount); err != nil {
		return err
	}
	if poolCount == 0 {
		_, err := s.CreatePool(PoolRecord{
			Name:            "Default Reliable Pool",
			Kind:            "reliable",
			Strategy:        "failover",
			RequireConnect:  true,
			HysteresisDelta: 5.0,
			IsDefault:       true,
			CreatedAt:       now,
		})
		if err != nil {
			return err
		}
	}

	// 3. Seed default DNS Group if empty
	var dnsGrpCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM dns_groups`).Scan(&dnsGrpCount); err != nil {
		return err
	}
	if dnsGrpCount == 0 {
		_, err := s.CreateDNSGroup(DNSGroupRecord{
			Name: "Default Public DNS",
			Upstreams: []DNSUpstreamEndpoint{
				{Protocol: "udp", Address: "1.1.1.1:53"},
				{Protocol: "tcp", Address: "1.0.0.1:53"},
			},
			BootstrapIPs:        []string{"1.1.1.1"},
			AllowPublicFallback: true,
			IsDefault:           true,
			CreatedAt:           now,
		})
		if err != nil {
			return err
		}
	}

	return nil
}

// --- Sources CRUD ---

func (s *Store) CreateSource(src SourceRecord) (int64, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	if src.CreatedAt == "" {
		src.CreatedAt = now
	}
	if src.Format == "" {
		src.Format = "txt"
	}
	if src.DefaultProtocol == "" {
		src.DefaultProtocol = "http"
	}
	if src.UpdateIntervalSec <= 0 {
		src.UpdateIntervalSec = 3600
	}
	if src.TimeoutSec <= 0 {
		src.TimeoutSec = 15
	}
	res, err := s.DB().Exec(`
		INSERT INTO sources (
			name, kind, location, format, default_protocol, allow_private,
			update_interval_sec, timeout_sec, enabled, verified_date, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		src.Name, src.Kind, src.Location, src.Format, src.DefaultProtocol, boolToInt(src.AllowPrivate),
		src.UpdateIntervalSec, src.TimeoutSec, boolToInt(src.Enabled), src.VerifiedDate, src.CreatedAt,
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) UpdateSource(src SourceRecord) error {
	if src.UpdateIntervalSec <= 0 {
		src.UpdateIntervalSec = 3600
	}
	if src.TimeoutSec <= 0 {
		src.TimeoutSec = 15
	}
	res, err := s.DB().Exec(`
		UPDATE sources SET
			name = ?, kind = ?, location = ?, format = ?, default_protocol = ?,
			allow_private = ?, update_interval_sec = ?, timeout_sec = ?, enabled = ?
		WHERE id = ?`,
		src.Name, src.Kind, src.Location, src.Format, src.DefaultProtocol,
		boolToInt(src.AllowPrivate), src.UpdateIntervalSec, src.TimeoutSec, boolToInt(src.Enabled),
		src.ID,
	)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrRecordNotFound
	}
	return nil
}

func (s *Store) DeleteSource(id int) error {
	res, err := s.DB().Exec(`DELETE FROM sources WHERE id = ?`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrRecordNotFound
	}
	return nil
}

func (s *Store) GetSource(id int) (SourceRecord, error) {
	list, err := s.ListSources()
	if err != nil {
		return SourceRecord{}, err
	}
	for _, item := range list {
		if item.ID == id {
			return item, nil
		}
	}
	return SourceRecord{}, ErrRecordNotFound
}

func (s *Store) ListSources() ([]SourceRecord, error) {
	rows, err := s.DB().Query(`
		SELECT id, name, kind, location, format, default_protocol, allow_private,
		       update_interval_sec, timeout_sec, enabled, etag, last_modified,
		       backoff_until, consecutive_failures, last_run_at, last_status,
		       last_error, total_parsed, total_unique, total_errors, verified_date, created_at
		FROM sources ORDER BY id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []SourceRecord
	for rows.Next() {
		var r SourceRecord
		var allowPriv, en int
		if err := rows.Scan(
			&r.ID, &r.Name, &r.Kind, &r.Location, &r.Format, &r.DefaultProtocol, &allowPriv,
			&r.UpdateIntervalSec, &r.TimeoutSec, &en, &r.ETag, &r.LastModified,
			&r.BackoffUntil, &r.ConsecutiveFailures, &r.LastRunAt, &r.LastStatus,
			&r.LastError, &r.TotalParsed, &r.TotalUnique, &r.TotalErrors, &r.VerifiedDate, &r.CreatedAt,
		); err != nil {
			return nil, err
		}
		r.AllowPrivate = allowPriv != 0
		r.Enabled = en != 0
		list = append(list, r)
	}
	return list, rows.Err()
}

// --- Pools CRUD & Activation ---

func (s *Store) CreatePool(p PoolRecord) (int64, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	if p.CreatedAt == "" {
		p.CreatedAt = now
	}
	if p.Kind == "" {
		p.Kind = "reliable"
	}
	if p.Strategy == "" {
		p.Strategy = "failover"
	}
	if p.HysteresisDelta <= 0 {
		p.HysteresisDelta = 5.0
	}
	db := s.DB()
	if p.IsDefault {
		_, _ = db.Exec(`UPDATE pools SET is_default = 0`)
	}
	res, err := db.Exec(`
		INSERT INTO pools (
			name, kind, strategy, required_protocol, require_connect, require_remote_dns,
			min_score, country_code, hysteresis_delta, active_proxy_id, is_default, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		p.Name, p.Kind, p.Strategy, p.RequiredProtocol, boolToInt(p.RequireConnect), boolToInt(p.RequireRemoteDNS),
		p.MinScore, p.CountryCode, p.HysteresisDelta, p.ActiveProxyID, boolToInt(p.IsDefault), p.CreatedAt,
	)
	if err != nil {
		return 0, err
	}
	poolID, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	for _, pid := range p.MemberProxyIDs {
		_, _ = db.Exec(`INSERT OR IGNORE INTO pool_members(pool_id, proxy_id, weight) VALUES (?, ?, 1)`, poolID, pid)
	}
	return poolID, nil
}

func (s *Store) UpdatePool(p PoolRecord) error {
	db := s.DB()
	if p.IsDefault {
		_, _ = db.Exec(`UPDATE pools SET is_default = 0`)
	}
	res, err := db.Exec(`
		UPDATE pools SET
			name = ?, kind = ?, strategy = ?, required_protocol = ?,
			require_connect = ?, require_remote_dns = ?, min_score = ?,
			country_code = ?, hysteresis_delta = ?, active_proxy_id = ?, is_default = ?
		WHERE id = ?`,
		p.Name, p.Kind, p.Strategy, p.RequiredProtocol,
		boolToInt(p.RequireConnect), boolToInt(p.RequireRemoteDNS), p.MinScore,
		p.CountryCode, p.HysteresisDelta, p.ActiveProxyID, boolToInt(p.IsDefault), p.ID,
	)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrRecordNotFound
	}
	if p.MemberProxyIDs != nil {
		_, _ = db.Exec(`DELETE FROM pool_members WHERE pool_id = ?`, p.ID)
		for _, pid := range p.MemberProxyIDs {
			_, _ = db.Exec(`INSERT OR IGNORE INTO pool_members(pool_id, proxy_id, weight) VALUES (?, ?, 1)`, p.ID, pid)
		}
	}
	return nil
}

func (s *Store) SetActivePool(poolID int, activeProxyID *int) error {
	db := s.DB()
	_, _ = db.Exec(`UPDATE pools SET is_default = 0`)
	res, err := db.Exec(`UPDATE pools SET is_default = 1, active_proxy_id = COALESCE(?, active_proxy_id) WHERE id = ?`, activeProxyID, poolID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrRecordNotFound
	}
	return nil
}

func (s *Store) DeletePool(id int) error {
	res, err := s.DB().Exec(`DELETE FROM pools WHERE id = ?`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrRecordNotFound
	}
	return nil
}

func (s *Store) ListPools() ([]PoolRecord, error) {
	db := s.DB()
	rows, err := db.Query(`
		SELECT id, name, kind, strategy, required_protocol, require_connect, require_remote_dns,
		       min_score, country_code, hysteresis_delta, active_proxy_id, is_default, created_at
		FROM pools ORDER BY is_default DESC, id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []PoolRecord
	for rows.Next() {
		var p PoolRecord
		var reqConn, reqRDNS, isDef int
		var activeID sql.NullInt64
		if err := rows.Scan(
			&p.ID, &p.Name, &p.Kind, &p.Strategy, &p.RequiredProtocol, &reqConn, &reqRDNS,
			&p.MinScore, &p.CountryCode, &p.HysteresisDelta, &activeID, &isDef, &p.CreatedAt,
		); err != nil {
			return nil, err
		}
		p.RequireConnect = reqConn != 0
		p.RequireRemoteDNS = reqRDNS != 0
		p.IsDefault = isDef != 0
		p.ActiveProxyID = nullIntToPtr(activeID)
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		mRows, err := db.Query(`SELECT proxy_id FROM pool_members WHERE pool_id = ? ORDER BY proxy_id ASC`, out[i].ID)
		if err == nil {
			for mRows.Next() {
				var pid int
				if mRows.Scan(&pid) == nil {
					out[i].MemberProxyIDs = append(out[i].MemberProxyIDs, pid)
				}
			}
			_ = mRows.Close()
		}
	}
	return out, nil
}

// --- DNS Groups CRUD ---

func (s *Store) CreateDNSGroup(g DNSGroupRecord) (int64, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	if g.CreatedAt == "" {
		g.CreatedAt = now
	}
	upJSON, err := json.Marshal(g.Upstreams)
	if err != nil {
		return 0, err
	}
	bootJSON, err := json.Marshal(g.BootstrapIPs)
	if err != nil {
		return 0, err
	}
	db := s.DB()
	if g.IsDefault {
		_, _ = db.Exec(`UPDATE dns_groups SET is_default = 0`)
	}
	res, err := db.Exec(`
		INSERT INTO dns_groups (name, upstreams_json, bootstrap_ips_json, allow_public_fallback, is_default, created_at)
		VALUES (?, ?, ?, ?, ?, ?)`,
		g.Name, string(upJSON), string(bootJSON), boolToInt(g.AllowPublicFallback), boolToInt(g.IsDefault), g.CreatedAt,
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) UpdateDNSGroup(g DNSGroupRecord) error {
	upJSON, err := json.Marshal(g.Upstreams)
	if err != nil {
		return err
	}
	bootJSON, err := json.Marshal(g.BootstrapIPs)
	if err != nil {
		return err
	}
	db := s.DB()
	if g.IsDefault {
		_, _ = db.Exec(`UPDATE dns_groups SET is_default = 0`)
	}
	res, err := db.Exec(`
		UPDATE dns_groups SET
			name = ?, upstreams_json = ?, bootstrap_ips_json = ?, allow_public_fallback = ?, is_default = ?
		WHERE id = ?`,
		g.Name, string(upJSON), string(bootJSON), boolToInt(g.AllowPublicFallback), boolToInt(g.IsDefault), g.ID,
	)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrRecordNotFound
	}
	return nil
}

func (s *Store) DeleteDNSGroup(id int) error {
	res, err := s.DB().Exec(`DELETE FROM dns_groups WHERE id = ?`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrRecordNotFound
	}
	return nil
}

func (s *Store) ListDNSGroups() ([]DNSGroupRecord, error) {
	rows, err := s.DB().Query(`
		SELECT id, name, upstreams_json, bootstrap_ips_json, allow_public_fallback, is_default, created_at
		FROM dns_groups ORDER BY is_default DESC, id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []DNSGroupRecord
	for rows.Next() {
		var g DNSGroupRecord
		var upStr, bootStr string
		var allowPub, isDef int
		if err := rows.Scan(&g.ID, &g.Name, &upStr, &bootStr, &allowPub, &isDef, &g.CreatedAt); err != nil {
			return nil, err
		}
		g.AllowPublicFallback = allowPub != 0
		g.IsDefault = isDef != 0
		_ = json.Unmarshal([]byte(upStr), &g.Upstreams)
		_ = json.Unmarshal([]byte(bootStr), &g.BootstrapIPs)
		out = append(out, g)
	}
	return out, rows.Err()
}

// --- DNS Rules & Routing Rules CRUD ---

func (s *Store) SaveDNSRule(r rules.DNSRule) (int64, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	if r.ID > 0 {
		_, err := s.DB().Exec(`
			UPDATE dns_rules SET
				priority = ?, enabled = ?, match_type = ?, pattern = ?,
				action = ?, dns_group_id = ?, local_ipv4 = ?, local_ipv6 = ?
			WHERE id = ?`,
			r.Priority, boolToInt(r.Enabled), string(r.MatchType), r.Pattern,
			r.Action, r.DNSGroupID, r.LocalIPv4, r.LocalIPv6, r.ID,
		)
		return int64(r.ID), err
	}
	res, err := s.DB().Exec(`
		INSERT INTO dns_rules (priority, enabled, match_type, pattern, action, dns_group_id, local_ipv4, local_ipv6, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.Priority, boolToInt(r.Enabled), string(r.MatchType), r.Pattern,
		r.Action, r.DNSGroupID, r.LocalIPv4, r.LocalIPv6, now,
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) DeleteDNSRule(id int) error {
	_, err := s.DB().Exec(`DELETE FROM dns_rules WHERE id = ?`, id)
	return err
}

func (s *Store) ListDNSRules() ([]rules.DNSRule, error) {
	rows, err := s.DB().Query(`
		SELECT id, priority, enabled, match_type, pattern, action, COALESCE(dns_group_id, 0), local_ipv4, local_ipv6
		FROM dns_rules ORDER BY priority ASC, id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []rules.DNSRule
	for rows.Next() {
		var r rules.DNSRule
		var en int
		var mt string
		if err := rows.Scan(&r.ID, &r.Priority, &en, &mt, &r.Pattern, &r.Action, &r.DNSGroupID, &r.LocalIPv4, &r.LocalIPv6); err != nil {
			return nil, err
		}
		r.Enabled = en != 0
		r.MatchType = rules.MatchType(mt)
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) SaveRoutingRule(r rules.RoutingRule) (int64, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	if r.ResolutionMode == "" {
		r.ResolutionMode = "remote_dns"
	}
	if r.ID > 0 {
		_, err := s.DB().Exec(`
			UPDATE routing_rules SET
				priority = ?, enabled = ?, match_type = ?, pattern = ?,
				action = ?, target_proxy_id = ?, target_pool_id = ?,
				resolution_mode = ?, dns_group_id = ?
			WHERE id = ?`,
			r.Priority, boolToInt(r.Enabled), string(r.MatchType), r.Pattern,
			r.Action, r.TargetProxyID, r.TargetPoolID, r.ResolutionMode, r.DNSGroupID, r.ID,
		)
		return int64(r.ID), err
	}
	res, err := s.DB().Exec(`
		INSERT INTO routing_rules (
			priority, enabled, match_type, pattern, action,
			target_proxy_id, target_pool_id, resolution_mode, dns_group_id, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.Priority, boolToInt(r.Enabled), string(r.MatchType), r.Pattern, r.Action,
		r.TargetProxyID, r.TargetPoolID, r.ResolutionMode, r.DNSGroupID, now,
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) DeleteRoutingRule(id int) error {
	_, err := s.DB().Exec(`DELETE FROM routing_rules WHERE id = ?`, id)
	return err
}

func (s *Store) ListRoutingRules() ([]rules.RoutingRule, error) {
	rows, err := s.DB().Query(`
		SELECT id, priority, enabled, match_type, pattern, action,
		       target_proxy_id, target_pool_id, resolution_mode, dns_group_id
		FROM routing_rules ORDER BY priority ASC, id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []rules.RoutingRule
	for rows.Next() {
		var r rules.RoutingRule
		var en int
		var mt string
		var tProxy, tPool, dGrp sql.NullInt64
		if err := rows.Scan(&r.ID, &r.Priority, &en, &mt, &r.Pattern, &r.Action, &tProxy, &tPool, &r.ResolutionMode, &dGrp); err != nil {
			return nil, err
		}
		r.Enabled = en != 0
		r.MatchType = rules.MatchType(mt)
		r.TargetProxyID = nullIntToPtr(tProxy)
		r.TargetPoolID = nullIntToPtr(tPool)
		r.DNSGroupID = nullIntToPtr(dGrp)
		out = append(out, r)
	}
	return out, rows.Err()
}

// --- Candidates & Proxies ---

func (s *Store) UpsertCandidates(ctx context.Context, sourceID int64, candidates []parsers.NormalizedCandidate, credStore *model.CredentialStore, now time.Time) (int, error) {
	db := s.DB()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	nowStr := now.UTC().Format(time.RFC3339)
	capJSON, _ := json.Marshal(model.DefaultCapabilities())
	upserted := 0

	for _, c := range candidates {
		if err := ctx.Err(); err != nil {
			return upserted, err
		}
		if c.HasAuth && credStore != nil {
			credStore.Set(c.DedupKey, c.Username, c.Password)
		}
		_, err := tx.ExecContext(ctx, `
			INSERT INTO proxies (
				dedup_key, protocol, host, port, has_auth, status, capabilities_json, created_at
			) VALUES (?, ?, ?, ?, ?, 'unknown', ?, ?)
			ON CONFLICT(dedup_key) DO UPDATE SET
				has_auth = excluded.has_auth`,
			c.DedupKey, c.Protocol, c.Host, c.Port, boolToInt(c.HasAuth), string(capJSON), nowStr,
		)
		if err != nil {
			return upserted, err
		}
		var proxyID int64
		if err := tx.QueryRowContext(ctx, `SELECT id FROM proxies WHERE dedup_key = ?`, c.DedupKey).Scan(&proxyID); err != nil {
			return upserted, err
		}
		if sourceID > 0 {
			_, err = tx.ExecContext(ctx, `
				INSERT INTO proxy_sources (proxy_id, source_id, first_seen_at, last_seen_at, sanitized_raw_line)
				VALUES (?, ?, ?, ?, ?)
				ON CONFLICT(proxy_id, source_id) DO UPDATE SET
					last_seen_at = excluded.last_seen_at,
					sanitized_raw_line = excluded.sanitized_raw_line`,
				proxyID, sourceID, nowStr, nowStr, c.SanitizedRaw,
			)
			if err != nil {
				return upserted, err
			}
		}
		upserted++
	}
	if err := tx.Commit(); err != nil {
		return upserted, err
	}
	return upserted, nil
}

type ProxyQueryFilter struct {
	Search   string
	Protocol string
	Status   string
	SortBy   string
	SortDesc bool
	Limit    int
	Offset   int
}

func (s *Store) ListProxies(filter ProxyQueryFilter) ([]ProxyRecord, int, error) {
	db := s.DB()
	var where []string
	var args []any

	if strings.TrimSpace(filter.Search) != "" {
		q := "%" + strings.ToLower(strings.TrimSpace(filter.Search)) + "%"
		where = append(where, "(LOWER(p.host) LIKE ? OR CAST(p.port AS TEXT) LIKE ? OR LOWER(p.exit_ip) LIKE ?)")
		args = append(args, q, q, q)
	}
	if filter.Protocol != "" {
		where = append(where, "p.protocol = ?")
		args = append(args, filter.Protocol)
	}
	if filter.Status != "" {
		where = append(where, "p.status = ?")
		args = append(args, filter.Status)
	}

	whereClause := ""
	if len(where) > 0 {
		whereClause = "WHERE " + strings.Join(where, " AND ")
	}

	var total int
	countSQL := fmt.Sprintf("SELECT COUNT(*) FROM proxies p %s", whereClause)
	if err := db.QueryRow(countSQL, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	orderCol := "p.score"
	switch filter.SortBy {
	case "latency":
		orderCol = "COALESCE(p.avg_total_ms, 999999)"
	case "created_at":
		orderCol = "p.id"
	case "host":
		orderCol = "p.host"
	}
	dir := "ASC"
	if filter.SortDesc {
		dir = "DESC"
	}
	limit := filter.Limit
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}

	query := fmt.Sprintf(`
		SELECT p.id, p.dedup_key, p.protocol, p.host, p.port, p.has_auth, p.status,
		       p.score, p.confidence, p.cycles_count, p.success_rate,
		       p.avg_connect_ms, p.avg_handshake_ms, p.avg_ttfb_ms, p.avg_total_ms,
		       p.exit_ip, p.rotating_exit_ip, p.exit_ip_changes, p.country_code, p.asn, p.asn_org,
		       p.capabilities_json, p.score_breakdown_json, p.consecutive_failures,
		       p.quarantine_until, p.first_checked_at, p.last_checked_at, p.last_healthy_at,
		       p.next_check_at, p.created_at,
		       (SELECT COUNT(*) FROM proxy_sources ps WHERE ps.proxy_id = p.id) AS sources_count
		FROM proxies p
		%s
		ORDER BY %s %s, p.id ASC
		LIMIT ? OFFSET ?`, whereClause, orderCol, dir)

	argsWithPage := append(append([]any{}, args...), limit, offset)
	rows, err := db.Query(query, argsWithPage...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var result []ProxyRecord
	for rows.Next() {
		r, err := scanProxyRow(rows)
		if err != nil {
			return nil, 0, err
		}
		result = append(result, r)
	}
	return result, total, rows.Err()
}

// DueProxiesForRecheck returns proxies whose next_check_at or quarantine_until cooldown has elapsed.
func (s *Store) DueProxiesForRecheck(now time.Time, limit int) ([]ProxyRecord, error) {
	if limit <= 0 {
		limit = 64
	}
	nowStr := now.UTC().Format(time.RFC3339)
	rows, err := s.DB().Query(`
		SELECT p.id, p.dedup_key, p.protocol, p.host, p.port, p.has_auth, p.status,
		       p.score, p.confidence, p.cycles_count, p.success_rate,
		       p.avg_connect_ms, p.avg_handshake_ms, p.avg_ttfb_ms, p.avg_total_ms,
		       p.exit_ip, p.rotating_exit_ip, p.exit_ip_changes, p.country_code, p.asn, p.asn_org,
		       p.capabilities_json, p.score_breakdown_json, p.consecutive_failures,
		       p.quarantine_until, p.first_checked_at, p.last_checked_at, p.last_healthy_at,
		       p.next_check_at, p.created_at,
		       (SELECT COUNT(*) FROM proxy_sources ps WHERE ps.proxy_id = p.id) AS sources_count
		FROM proxies p
		WHERE (p.next_check_at != '' AND p.next_check_at <= ?)
		   OR (p.status = 'quarantined' AND p.quarantine_until != '' AND p.quarantine_until <= ?)
		ORDER BY p.next_check_at ASC
		LIMIT ?`, nowStr, nowStr, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []ProxyRecord
	for rows.Next() {
		r, err := scanProxyRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func scanProxyRow(rows *sql.Rows) (ProxyRecord, error) {
	var r ProxyRecord
	var hasAuth, rotExit int
	var capStr, breakdownStr string
	var connMs, hsMs, ttfbMs, totMs sql.NullInt64
	if err := rows.Scan(
		&r.ID, &r.DedupKey, &r.Protocol, &r.Host, &r.Port, &hasAuth, &r.Status,
		&r.Score, &r.Confidence, &r.CyclesCount, &r.SuccessRate,
		&connMs, &hsMs, &ttfbMs, &totMs,
		&r.ExitIP, &rotExit, &r.ExitIPChanges, &r.CountryCode, &r.ASN, &r.ASNOrg,
		&capStr, &breakdownStr, &r.ConsecutiveFailures,
		&r.QuarantineUntil, &r.FirstCheckedAt, &r.LastCheckedAt, &r.LastHealthyAt,
		&r.NextCheckAt, &r.CreatedAt, &r.SourcesCount,
	); err != nil {
		return ProxyRecord{}, err
	}
	r.HasAuth = hasAuth != 0
	r.RotatingExitIP = rotExit != 0
	r.AvgConnectMs = nullIntToPtr(connMs)
	r.AvgHandshakeMs = nullIntToPtr(hsMs)
	r.AvgTTFBMs = nullIntToPtr(ttfbMs)
	r.AvgTotalMs = nullIntToPtr(totMs)
	_ = json.Unmarshal([]byte(capStr), &r.Capabilities)
	_ = json.Unmarshal([]byte(breakdownStr), &r.ScoreBreakdown)
	return r, nil
}

// --- Backup & Restore ---

func (s *Store) CreateBackup(destPath string) error {
	_ = os.Remove(destPath)
	_, err := s.DB().Exec(`VACUUM INTO ?`, destPath)
	return err
}

func ValidateBackupVersion(backupPath string) error {
	dsn := fmt.Sprintf("file:%s?mode=ro", filepath.ToSlash(backupPath))
	bDB, err := sql.Open("sqlite", dsn)
	if err != nil {
		return err
	}
	defer bDB.Close()

	var maxVer sql.NullInt64
	if err := bDB.QueryRow(`SELECT MAX(version) FROM schema_migrations`).Scan(&maxVer); err != nil {
		return fmt.Errorf("%w: missing or corrupt schema_migrations table: %v", ErrIncompatibleBackupVersion, err)
	}
	if !maxVer.Valid || maxVer.Int64 < 1 || maxVer.Int64 > CurrentSchemaVersion {
		return fmt.Errorf("%w: backup version %d (supported 1..%d)", ErrIncompatibleBackupVersion, maxVer.Int64, CurrentSchemaVersion)
	}
	return nil
}

// RestoreFromBackup validates the backup schema version, closes the active DB connection,
// replaces proxydesk.db atomically, and reopens the Store.
func (s *Store) RestoreFromBackup(backupPath string) error {
	if err := ValidateBackupVersion(backupPath); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.db != nil {
		_, _ = s.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE);`)
		_ = s.db.Close()
		s.db = nil
	}

	_ = os.Remove(s.dbPath + "-wal")
	_ = os.Remove(s.dbPath + "-shm")

	srcFile, err := os.Open(backupPath)
	if err != nil {
		reopenDB, _ := openSQLiteDB(s.dbPath)
		s.db = reopenDB
		return err
	}
	defer srcFile.Close()

	tmpDest := s.dbPath + ".restore.tmp"
	dstFile, err := os.OpenFile(tmpDest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		reopenDB, _ := openSQLiteDB(s.dbPath)
		s.db = reopenDB
		return err
	}
	if _, err := io.Copy(dstFile, srcFile); err != nil {
		_ = dstFile.Close()
		_ = os.Remove(tmpDest)
		reopenDB, _ := openSQLiteDB(s.dbPath)
		s.db = reopenDB
		return err
	}
	_ = dstFile.Close()

	if err := os.Rename(tmpDest, s.dbPath); err != nil {
		_ = os.Remove(tmpDest)
		reopenDB, _ := openSQLiteDB(s.dbPath)
		s.db = reopenDB
		return err
	}

	newDB, err := openSQLiteDB(s.dbPath)
	if err != nil {
		return err
	}
	s.db = newDB
	return nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func nullIntToPtr(n sql.NullInt64) *int {
	if !n.Valid {
		return nil
	}
	v := int(n.Int64)
	return &v
}
