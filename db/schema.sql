-- Prowler Security Dashboard Schema
-- Run via: wrangler d1 execute prowler-db --file=db/schema.sql

CREATE TABLE IF NOT EXISTS scan_runs (
  id TEXT PRIMARY KEY,
  provider TEXT NOT NULL,
  scanned_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  total_checks INTEGER DEFAULT 0,
  passed INTEGER DEFAULT 0,
  failed INTEGER DEFAULT 0,
  critical INTEGER DEFAULT 0,
  high INTEGER DEFAULT 0,
  medium INTEGER DEFAULT 0,
  low INTEGER DEFAULT 0,
  score REAL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS findings (
  id TEXT PRIMARY KEY,
  scan_run_id TEXT,
  provider TEXT NOT NULL,
  service TEXT,
  check_id TEXT,
  check_title TEXT,
  status TEXT,
  severity TEXT,
  resource_uid TEXT,
  resource_name TEXT,
  resource_type TEXT,
  region TEXT,
  description TEXT,
  remediation TEXT,
  scanned_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (scan_run_id) REFERENCES scan_runs(id)
);

CREATE TABLE IF NOT EXISTS resources (
  id TEXT PRIMARY KEY,
  provider TEXT,
  service TEXT,
  resource_type TEXT,
  resource_uid TEXT,
  resource_name TEXT,
  region TEXT,
  risk_score INTEGER DEFAULT 0,
  last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS graph_edges (
  id TEXT PRIMARY KEY,
  source_id TEXT,
  target_id TEXT,
  source_label TEXT,
  target_label TEXT,
  relationship TEXT,
  severity TEXT
);

CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_provider ON findings(provider);
CREATE INDEX IF NOT EXISTS idx_findings_scanned_at ON findings(scanned_at);
CREATE INDEX IF NOT EXISTS idx_scan_runs_scanned_at ON scan_runs(scanned_at);
