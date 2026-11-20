CREATE TABLE library_version (
  version TEXT PRIMARY KEY, source_file TEXT NOT NULL, source_sha256 TEXT NOT NULL,
  dataset_version TEXT, imported_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE framework (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, control_count INTEGER NOT NULL DEFAULT 0
);
-- Grouping used for cross-framework de-duplication. Currently domain-level PLACEHOLDERS (see gap report).
CREATE TABLE unified_control (
  id TEXT PRIMARY KEY, domain TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'domain_level_placeholder'
);
CREATE TABLE control (
  id TEXT PRIMARY KEY, framework_id TEXT NOT NULL REFERENCES framework(id),
  ref TEXT NOT NULL, title TEXT NOT NULL, requirement TEXT, domain TEXT NOT NULL,
  evidence_hint TEXT, unified_control_id TEXT REFERENCES unified_control(id),
  -- B7 applicability metadata. NULL means "not authored yet": treated as applies-to-all + flagged.
  applies_if TEXT, depth_tier TEXT CHECK (depth_tier IN ('basic','standard','enhanced')),
  risk_weight INTEGER, owner_function TEXT, mandatory INTEGER,
  metadata_status TEXT NOT NULL DEFAULT 'needs_content_review',
  library_version TEXT NOT NULL REFERENCES library_version(version)
);
CREATE INDEX control_framework ON control(framework_id);
CREATE TABLE library_gap (
  control_id TEXT NOT NULL REFERENCES control(id), missing_field TEXT NOT NULL, note TEXT,
  PRIMARY KEY (control_id, missing_field)
);
