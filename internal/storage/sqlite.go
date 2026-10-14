package storage

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/proxydesk/proxydesk/internal/model"
	"github.com/proxydesk/proxydesk/internal/parsers"
	_ "modernc.org/sqlite"
)

//go:embed migrations/001_init.sql
var migration001SQL string

const CurrentSchemaVersion = 1

var (
	ErrIncompatibleBackupVersion = errors.New("backup database schema version is incompatible")
	ErrSourceAlreadyExists       = errors.New("source already exists")
)

type Store struct {
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

func Open(dataDir string) (*Store, error) {
	dbPath := filepath.Join(dataDir, "proxydesk.db")
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(ON)", filepath.ToSlash(dbPath))
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1) // Serializes writes safely in pure-Go SQLite WAL mode
	s := &Store{db: db, dbPath: dbPath}
	if err := s.Migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	_, _ = s.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE);`)
	return s.db.Close()
}

func (s *Store) DB() *sql.DB {
	return s.db
}

func (s *Store) Migrate() error {
	if _, err := s.db.Exec(migration001SQL); err != nil {
		return fmt.Errorf("apply migration 001: %w", err)
	}
	var maxVer sql.NullInt64
	if err := s.db.QueryRow(`SELECT MAX(version) FROM schema_migrations`).Scan(&maxVer); err != nil {
		return fmt.Errorf("check schema_migrations: %w", err)
	}
	if maxVer.Valid && maxVer.Int64 > CurrentSchemaVersion {
		return fmt.Errorf("%w: database has schema version %d, supported %d", ErrIncompatibleBackupVersion, maxVer.Int64, CurrentSchemaVersion)
	}
	if !maxVer.Valid || maxVer.Int64 < 1 {
		_, err := s.db.Exec(`INSERT INTO schema_migrations(version, applied_at) VALUES (1, ?)`, time.Now().UTC().Format(time.RFC3339))
		if err != nil {
			return fmt.Errorf("record migration version: %w", err)
		}
	}
	return s.SeedVerifiedPresetsIfEmpty()
}

// SeedVerifiedPresetsIfEmpty populates the preset sources verified on 2026-10-13 (Increment B).
// Note: It does NOT automatically trigger network scraping on install.
func (s *Store) SeedVerifiedPresetsIfEmpty() error {
	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM sources`).Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return nil
	}
	now := time.Now().UTC().Format(time.RFC3339)
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
		_, err := s.CreateSource(p)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) CreateSource(src SourceRecord) (int64, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	if src.CreatedAt == "" {
		src.CreatedAt = now
	}
	if src.UpdateIntervalSec <= 0 {
		src.UpdateIntervalSec = 3600
	}
	if src.TimeoutSec <= 0 {
		src.TimeoutSec = 15
	}
	res, err := s.db.Exec(`
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

func (s *Store) ListSources() ([]SourceRecord, error) {
	rows, err := s.db.Query(`
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

// UpsertCandidates inserts or updates normalized proxy candidates and links their provenance
// in proxy_sources without overwriting existing proxy health status or duplicating records.
func (s *Store) UpsertCandidates(ctx context.Context, sourceID int64, candidates []parsers.NormalizedCandidate, credStore *model.CredentialStore, now time.Time) (int, error) {
	tx, err := s.db.BeginTx(ctx, nil)
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
	SortBy   string // "score", "latency", "created_at", "host"
	SortDesc bool
	Limit    int
	Offset   int
}

func (s *Store) ListProxies(filter ProxyQueryFilter) ([]ProxyRecord, int, error) {
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
	if err := s.db.QueryRow(countSQL, args...).Scan(&total); err != nil {
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
	rows, err := s.db.Query(query, argsWithPage...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var result []ProxyRecord
	for rows.Next() {
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
			return nil, 0, err
		}
		r.HasAuth = hasAuth != 0
		r.RotatingExitIP = rotExit != 0
		r.AvgConnectMs = nullIntToPtr(connMs)
		r.AvgHandshakeMs = nullIntToPtr(hsMs)
		r.AvgTTFBMs = nullIntToPtr(ttfbMs)
		r.AvgTotalMs = nullIntToPtr(totMs)
		_ = json.Unmarshal([]byte(capStr), &r.Capabilities)
		_ = json.Unmarshal([]byte(breakdownStr), &r.ScoreBreakdown)
		result = append(result, r)
	}
	return result, total, rows.Err()
}

// CreateBackup safely creates a consistent SQLite snapshot using VACUUM INTO (Increment H).
func (s *Store) CreateBackup(destPath string) error {
	_ = os.Remove(destPath)
	_, err := s.db.Exec(`VACUUM INTO ?`, destPath)
	return err
}

// ValidateBackupVersion verifies that a backup SQLite file has a compatible schema_migrations version
// before restoring it (Engineering Bar Section 7 & Increment H).
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
