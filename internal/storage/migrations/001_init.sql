-- Migration 001: Initial schema for ProxyDesk (Increments A through H)

CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('url', 'file', 'manual', 'html')),
    location TEXT NOT NULL,
    format TEXT NOT NULL DEFAULT 'txt' CHECK (format IN ('txt', 'csv', 'json', 'html')),
    default_protocol TEXT NOT NULL DEFAULT 'http' CHECK (default_protocol IN ('http', 'socks5')),
    allow_private INTEGER NOT NULL DEFAULT 0,
    update_interval_sec INTEGER NOT NULL DEFAULT 3600,
    timeout_sec INTEGER NOT NULL DEFAULT 15,
    enabled INTEGER NOT NULL DEFAULT 1,
    etag TEXT NOT NULL DEFAULT '',
    last_modified TEXT NOT NULL DEFAULT '',
    backoff_until TEXT NOT NULL DEFAULT '',
    consecutive_failures INTEGER NOT NULL DEFAULT 0,
    last_run_at TEXT NOT NULL DEFAULT '',
    last_status TEXT NOT NULL DEFAULT 'never',
    last_error TEXT NOT NULL DEFAULT '',
    total_parsed INTEGER NOT NULL DEFAULT 0,
    total_unique INTEGER NOT NULL DEFAULT 0,
    total_errors INTEGER NOT NULL DEFAULT 0,
    verified_date TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS proxies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    dedup_key TEXT NOT NULL UNIQUE,
    protocol TEXT NOT NULL CHECK (protocol IN ('http', 'socks5')),
    host TEXT NOT NULL,
    port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    has_auth INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'unknown' CHECK (status IN ('unknown', 'checking', 'healthy', 'degraded', 'quarantined')),
    score REAL NOT NULL DEFAULT 0.0,
    confidence REAL NOT NULL DEFAULT 0.0,
    cycles_count INTEGER NOT NULL DEFAULT 0,
    success_rate REAL NOT NULL DEFAULT 0.0,
    avg_connect_ms INTEGER,
    avg_handshake_ms INTEGER,
    avg_ttfb_ms INTEGER,
    avg_total_ms INTEGER,
    exit_ip TEXT NOT NULL DEFAULT '',
    rotating_exit_ip INTEGER NOT NULL DEFAULT 0,
    exit_ip_changes INTEGER NOT NULL DEFAULT 0,
    country_code TEXT NOT NULL DEFAULT '',
    asn INTEGER NOT NULL DEFAULT 0,
    asn_org TEXT NOT NULL DEFAULT '',
    capabilities_json TEXT NOT NULL DEFAULT '{}',
    score_breakdown_json TEXT NOT NULL DEFAULT '{}',
    consecutive_failures INTEGER NOT NULL DEFAULT 0,
    quarantine_until TEXT NOT NULL DEFAULT '',
    first_checked_at TEXT NOT NULL DEFAULT '',
    last_checked_at TEXT NOT NULL DEFAULT '',
    last_healthy_at TEXT NOT NULL DEFAULT '',
    next_check_at TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_proxies_status_score ON proxies(status, score DESC);
CREATE INDEX IF NOT EXISTS idx_proxies_protocol ON proxies(protocol);
CREATE INDEX IF NOT EXISTS idx_proxies_host_port ON proxies(host, port);

CREATE TABLE IF NOT EXISTS proxy_sources (
    proxy_id INTEGER NOT NULL,
    source_id INTEGER NOT NULL,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    sanitized_raw_line TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (proxy_id, source_id),
    FOREIGN KEY (proxy_id) REFERENCES proxies(id) ON DELETE CASCADE,
    FOREIGN KEY (source_id) REFERENCES sources(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS check_cycles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    proxy_id INTEGER NOT NULL,
    checked_at TEXT NOT NULL,
    outcome TEXT NOT NULL CHECK (outcome IN ('success', 'failure', 'inconclusive', 'cancelled')),
    targets_tested INTEGER NOT NULL DEFAULT 0,
    targets_succeeded INTEGER NOT NULL DEFAULT 0,
    connect_ms INTEGER,
    handshake_ms INTEGER,
    ttfb_ms INTEGER,
    total_ms INTEGER,
    exit_ip TEXT NOT NULL DEFAULT '',
    summary_error TEXT NOT NULL DEFAULT '',
    FOREIGN KEY (proxy_id) REFERENCES proxies(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_check_cycles_proxy_time ON check_cycles(proxy_id, checked_at DESC);

CREATE TABLE IF NOT EXISTS check_target_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cycle_id INTEGER NOT NULL,
    proxy_id INTEGER NOT NULL,
    target_url TEXT NOT NULL,
    checked_at TEXT NOT NULL,
    outcome TEXT NOT NULL CHECK (outcome IN ('success', 'failure', 'inconclusive', 'cancelled')),
    stage_failed TEXT NOT NULL DEFAULT '',
    connect_ms INTEGER,
    handshake_ms INTEGER,
    ttfb_ms INTEGER,
    total_ms INTEGER,
    exit_ip TEXT NOT NULL DEFAULT '',
    error_detail TEXT NOT NULL DEFAULT '',
    FOREIGN KEY (cycle_id) REFERENCES check_cycles(id) ON DELETE CASCADE,
    FOREIGN KEY (proxy_id) REFERENCES proxies(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS pools (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    kind TEXT NOT NULL CHECK (kind IN ('manual', 'reliable', 'fast', 'protocol', 'custom')),
    strategy TEXT NOT NULL CHECK (strategy IN ('fixed', 'failover', 'best_score', 'round_robin', 'weighted')),
    required_protocol TEXT NOT NULL DEFAULT '',
    require_connect INTEGER NOT NULL DEFAULT 0,
    require_remote_dns INTEGER NOT NULL DEFAULT 0,
    min_score REAL NOT NULL DEFAULT 0.0,
    country_code TEXT NOT NULL DEFAULT '',
    hysteresis_delta REAL NOT NULL DEFAULT 5.0,
    active_proxy_id INTEGER,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS pool_members (
    pool_id INTEGER NOT NULL,
    proxy_id INTEGER NOT NULL,
    weight INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (pool_id, proxy_id),
    FOREIGN KEY (pool_id) REFERENCES pools(id) ON DELETE CASCADE,
    FOREIGN KEY (proxy_id) REFERENCES proxies(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS dns_groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    upstreams_json TEXT NOT NULL,
    bootstrap_ips_json TEXT NOT NULL DEFAULT '[]',
    allow_public_fallback INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS dns_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    priority INTEGER NOT NULL DEFAULT 100,
    enabled INTEGER NOT NULL DEFAULT 1,
    match_type TEXT NOT NULL CHECK (match_type IN ('exact', 'suffix', 'list', 'all')),
    pattern TEXT NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('group', 'block', 'local_record')),
    dns_group_id INTEGER,
    local_ipv4 TEXT NOT NULL DEFAULT '',
    local_ipv6 TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS routing_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    priority INTEGER NOT NULL DEFAULT 100,
    enabled INTEGER NOT NULL DEFAULT 1,
    match_type TEXT NOT NULL CHECK (match_type IN ('exact', 'suffix', 'list', 'all')),
    pattern TEXT NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('proxy', 'pool', 'block', 'direct')),
    target_proxy_id INTEGER,
    target_pool_id INTEGER,
    resolution_mode TEXT NOT NULL DEFAULT 'remote_dns' CHECK (resolution_mode IN ('remote_dns', 'managed_dns')),
    dns_group_id INTEGER,
    created_at TEXT NOT NULL
);
