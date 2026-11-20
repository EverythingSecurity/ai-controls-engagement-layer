import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { root, type Db } from '../db.ts';

export interface Grant { resource: string; action: string; scope?: string; qualifier: string }

export function parseGrant(s: string): Grant {
  const m = /^([a-z_]+):([a-z_]+)(?:@([a-z]+))?(?:#([a-z]+))?$/.exec(s);
  if (!m) throw new Error(`Bad grant syntax: ${s}`);
  return { resource: m[1], action: m[2], scope: m[3], qualifier: m[4] ?? '' };
}

const load = (f: string) => JSON.parse(readFileSync(join(root, 'data/rbac', f), 'utf8'));

/** Seeds roles, permissions and role_permission from data files (idempotent). Permissions are data, not code. */
export function seedRbac(db: Db): { roles: number; grants: number } {
  const roles = load('roles.json');
  const matrix = load('matrix.json');
  db.exec('BEGIN');
  try {
    db.exec('DELETE FROM role_permission');
    const insRole = db.prepare('INSERT OR REPLACE INTO role(name,tier,description,requires_mfa,default_scope) VALUES (?,?,?,?,?)');
    const insPerm = db.prepare('INSERT OR IGNORE INTO permission(name,resource,action) VALUES (?,?,?)');
    const insRp = db.prepare('INSERT INTO role_permission(role,permission,scope,qualifier) VALUES (?,?,?,?)');
    let grants = 0;
    for (const r of roles) insRole.run(r.name, r.tier, r.description, r.requires_mfa ? 1 : 0, r.default_scope);
    for (const r of roles) {
      for (const g of (matrix[r.name] ?? []).map(parseGrant)) {
        const perm = `${g.resource}:${g.action}`;
        insPerm.run(perm, g.resource, g.action);
        insRp.run(r.name, perm, g.scope ?? r.default_scope, g.qualifier);
        grants++;
      }
    }
    db.exec('COMMIT');
    return { roles: roles.length, grants };
  } catch (e) { db.exec('ROLLBACK'); throw e; }
}
