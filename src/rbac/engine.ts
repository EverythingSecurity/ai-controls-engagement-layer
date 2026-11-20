import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { root, type Db } from '../db.ts';
import { decide, type Ctx, type Resource, type Decision, type Model } from './core.ts';
export type { User, Assignment, Ctx, Resource, Layer, Decision } from './core.ts';

const stateRules: Model['state_rules'] = JSON.parse(readFileSync(join(root, 'data/rbac/state_rules.json'), 'utf8'));
delete (stateRules as any)._doc;
const SENSITIVE_READS = new Set(['audit_log', 'user', 'config_history']);

export function authorize(db: Db, ctx: Ctx, permission: string, res: Resource = {}, opts: { log?: boolean } = {}): Decision {
  const d = decide(buildModel(db, ctx, res), ctx, permission, res);
  if (opts.log !== false) logDecision(db, ctx, permission, res, d);
  return d;
}

/** Loads only what this decision needs from the DB; the decision itself is the shared pure core. */
function buildModel(db: Db, ctx: Ctx, res: Resource): Model {
  const roles = [...new Set(ctx.assignments.map((a) => a.role))];
  const c = res.client_id ? (db.prepare('SELECT principal_id FROM client WHERE id = ?').get(res.client_id) as any) : null;
  return {
    clients: c ? { [res.client_id!]: { principal_id: c.principal_id } } : {},
    grants: roles.length
      ? db.prepare(`SELECT role, permission, scope, qualifier FROM role_permission WHERE role IN (${roles.map(() => '?').join(',')})`).all(...roles) as any
      : [],
    mfa_roles: (db.prepare('SELECT name FROM role WHERE requires_mfa = 1').all() as any[]).map((r) => r.name),
    state_rules: stateRules,
    break_glass: ctx.user ? db.prepare('SELECT user_id, client_id, approved_by, principal_notified, expires_at FROM break_glass WHERE user_id = ?').all(ctx.user.id) as any : [],
  };
}

function logDecision(db: Db, ctx: Ctx, permission: string, res: Resource, d: Decision) {
  const [rt, action] = permission.split(':');
  if (d.allowed && action === 'read' && !SENSITIVE_READS.has(rt)) return;
  db.prepare(`INSERT INTO policy_decision_log(user_id,action,resource_type,resource_id,client_id,allowed,layer,reason) VALUES (?,?,?,?,?,?,?,?)`)
    .run(ctx.user?.id ?? null, permission, rt, res.id ?? null, res.client_id ?? null, d.allowed ? 1 : 0, d.layer, d.reason);
}

/** Loads a user's context (active assignments) from the DB. */
export function loadCtx(db: Db, userId: string, mfa_verified: boolean, now = new Date()): Ctx {
  const u = db.prepare('SELECT id, org_type, org_id, active FROM user WHERE id = ?').get(userId) as any;
  const rows = db.prepare('SELECT * FROM role_assignment WHERE user_id = ?').all(userId) as any[];
  return {
    user: u ? { ...u, active: !!u.active } : (undefined as any), mfa_verified, now,
    assignments: rows.map((r) => ({
      role: r.role, org_id: r.org_id, valid_from: r.valid_from, valid_to: r.valid_to,
      client_ids: JSON.parse(r.client_ids), framework_ids: JSON.parse(r.framework_ids), department_ids: JSON.parse(r.department_ids),
    })),
  };
}
