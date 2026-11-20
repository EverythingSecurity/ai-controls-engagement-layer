import { DatabaseSync } from 'node:sqlite';
import { readdirSync, readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

export type Db = DatabaseSync;
const root = join(dirname(fileURLToPath(import.meta.url)), '..');

export function openDb(path = ':memory:'): Db {
  const db = new DatabaseSync(path);
  db.exec('PRAGMA foreign_keys = ON');
  return db;
}

/** Applies migrations/*.sql in name order, once each. */
export function migrate(db: Db, dir = join(root, 'migrations')): string[] {
  db.exec(`CREATE TABLE IF NOT EXISTS schema_migrations (name TEXT PRIMARY KEY, applied_at TEXT NOT NULL DEFAULT (datetime('now')))`);
  const done = new Set(db.prepare('SELECT name FROM schema_migrations').all().map((r: any) => r.name));
  const applied: string[] = [];
  for (const f of readdirSync(dir).filter((f) => f.endsWith('.sql')).sort()) {
    if (done.has(f)) continue;
    let sql = readFileSync(join(dir, f), 'utf8');
    sql = sql.replace(/CREATE TABLE schema_migrations[^;]*;/, ''); // created above
    db.exec('BEGIN');
    try { db.exec(sql); db.prepare('INSERT INTO schema_migrations(name) VALUES (?)').run(f); db.exec('COMMIT'); }
    catch (e) { db.exec('ROLLBACK'); throw e; }
    applied.push(f);
  }
  return applied;
}
export { root };
