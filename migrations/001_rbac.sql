CREATE TABLE principal (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE client (
  id TEXT PRIMARY KEY, principal_id TEXT NOT NULL REFERENCES principal(id),
  name TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'invited'
    CHECK (status IN ('invited','onboarded','scoping','frameworks_pending_approval','active','archived')),
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE department (
  id TEXT PRIMARY KEY, client_id TEXT NOT NULL REFERENCES client(id), name TEXT NOT NULL
);
-- A user belongs to exactly ONE organisation (A2): platform, one principal, or one client.
CREATE TABLE user (
  id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE,
  org_type TEXT NOT NULL CHECK (org_type IN ('platform','principal','client')),
  org_id TEXT, active INTEGER NOT NULL DEFAULT 1,
  CHECK ((org_type = 'platform' AND org_id IS NULL) OR (org_type <> 'platform' AND org_id IS NOT NULL))
);
CREATE TABLE role (
  name TEXT PRIMARY KEY, tier TEXT NOT NULL CHECK (tier IN ('platform','principal','client')),
  description TEXT NOT NULL, requires_mfa INTEGER NOT NULL DEFAULT 0, default_scope TEXT NOT NULL
);
CREATE TABLE permission (
  name TEXT PRIMARY KEY, resource TEXT NOT NULL, action TEXT NOT NULL
);
-- Data-driven grants. Roles do NOT inherit; every role lists its permissions explicitly (A2).
CREATE TABLE role_permission (
  role TEXT NOT NULL REFERENCES role(name), permission TEXT NOT NULL REFERENCES permission(name),
  scope TEXT NOT NULL CHECK (scope IN ('platform','principal','asg','own','dept','task','content')),
  qualifier TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (role, permission, qualifier)
);
-- Scope attributes live on the assignment, not the role (A1/A5).
CREATE TABLE role_assignment (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT NOT NULL REFERENCES user(id), role TEXT NOT NULL REFERENCES role(name),
  org_id TEXT, client_ids TEXT NOT NULL DEFAULT '[]', framework_ids TEXT NOT NULL DEFAULT '[]',
  department_ids TEXT NOT NULL DEFAULT '[]',
  valid_from TEXT, valid_to TEXT, granted_by TEXT, created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE break_glass (
  id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT NOT NULL REFERENCES user(id),
  client_id TEXT NOT NULL REFERENCES client(id), reason TEXT NOT NULL CHECK (length(reason) > 0),
  approved_by TEXT, expires_at TEXT NOT NULL, principal_notified INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE policy_decision_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL DEFAULT (datetime('now')),
  user_id TEXT, action TEXT NOT NULL, resource_type TEXT, resource_id TEXT, client_id TEXT,
  allowed INTEGER NOT NULL, layer TEXT NOT NULL, reason TEXT NOT NULL
);
CREATE TABLE schema_migrations (name TEXT PRIMARY KEY, applied_at TEXT NOT NULL DEFAULT (datetime('now')));
