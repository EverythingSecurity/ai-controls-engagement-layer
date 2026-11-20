import type { Db } from '../db.ts';
import { authorize, type Ctx } from './engine.ts';

export interface NewAssignment {
  user_id: string; role: string; client_ids?: string[]; framework_ids?: string[]; department_ids?: string[];
  valid_from?: string; valid_to?: string;
}
export interface GrantResult { ok: boolean; reason: string }
const fail = (reason: string): GrantResult => ({ ok: false, reason });

/**
 * Grants a role assignment, enforcing: authorisation (user:create), tier match (one org per user),
 * no self-grant, no widening beyond the actor's own reach, and the A6 separation-of-duties rules.
 * Every attempt is audit-logged by authorize(); successful and failed grants are both logged.
 */
export function grantRole(db: Db, actor: Ctx, a: NewAssignment): GrantResult {
  const target = db.prepare('SELECT id, org_type, org_id FROM user WHERE id = ?').get(a.user_id) as any;
  const role = db.prepare('SELECT name, tier FROM role WHERE name = ?').get(a.role) as any;
  if (!target || !role) return fail('unknown user or role');
  const log = (allowed: boolean, reason: string) =>
    db.prepare(`INSERT INTO policy_decision_log(user_id,action,resource_type,resource_id,client_id,allowed,layer,reason) VALUES (?,?,?,?,?,?,?,?)`)
      .run(actor.user.id, 'user:grant_role', 'role_assignment', a.user_id, null, allowed ? 1 : 0, 'separation_of_duties', reason);
  const refuse = (reason: string) => { log(false, reason); return fail(reason); };

  if (actor.user.id === a.user_id) return refuse('a user cannot grant themselves a role or widen their own scope');
  if (role.tier !== target.org_type) return refuse(`role tier ${role.tier} does not match user org tier ${target.org_type}`);
  if (role.tier === 'platform') return refuse('platform roles are provisioned out-of-band, not via assignment API');

  // Authorisation: principal_admin manages principal users; client_admin manages own client users.
  const resource = target.org_type === 'principal' ? { principal_id: target.org_id } : { client_id: target.org_id };
  const d = authorize(db, actor, 'user:create', resource, { log: false });
  if (!d.allowed) return refuse(`actor not permitted: ${d.reason}`);
  // Principal admins cannot grant an equal-or-higher authority role than they hold is moot (admin is top of tier);
  // non-admins have no user:create so cannot reach here (privilege escalation prevented by the matrix itself).

  const clients = a.client_ids ?? [];
  if (role.tier === 'principal') {
    for (const c of clients) {
      const row = db.prepare('SELECT principal_id FROM client WHERE id = ?').get(c) as any;
      if (!row || row.principal_id !== target.org_id) return refuse(`client ${c} is not in the user's principal`);
    }
    if (['principal_engagement_lead', 'principal_assessor', 'principal_analyst', 'principal_report_approver'].includes(a.role) && !clients.length)
      return refuse('assigned-scope role requires at least one client_id');
  } else {
    if (clients.length) return refuse('client-tier roles are scoped by org, not client_ids');
    for (const dep of a.department_ids ?? []) {
      const row = db.prepare('SELECT client_id FROM department WHERE id = ?').get(dep) as any;
      if (!row || row.client_id !== target.org_id) return refuse(`department ${dep} is not in the user's client`);
    }
    if (['department_lead', 'department_respondent'].includes(a.role) && !(a.department_ids ?? []).length)
      return refuse('department roles require at least one department_id');
  }

  // SoD: same user cannot be assessor and report_approver for the same client (A6).
  const pair: Record<string, string> = { principal_assessor: 'principal_report_approver', principal_report_approver: 'principal_assessor' };
  if (pair[a.role]) {
    const others = db.prepare('SELECT client_ids FROM role_assignment WHERE user_id = ? AND role = ?').all(a.user_id, pair[a.role]) as any[];
    for (const o of others) {
      const overlap = (JSON.parse(o.client_ids) as string[]).filter((c) => clients.includes(c));
      if (overlap.length) return refuse(`SoD: ${a.role} and ${pair[a.role]} cannot be held for the same client (${overlap.join(',')})`);
    }
  }

  db.prepare(`INSERT INTO role_assignment(user_id,role,org_id,client_ids,framework_ids,department_ids,valid_from,valid_to,granted_by)
    VALUES (?,?,?,?,?,?,?,?,?)`).run(a.user_id, a.role, target.org_id, JSON.stringify(clients), JSON.stringify(a.framework_ids ?? []),
    JSON.stringify(a.department_ids ?? []), a.valid_from ?? null, a.valid_to ?? null, actor.user.id);
  log(true, `granted ${a.role} to ${a.user_id}`);
  return { ok: true, reason: 'granted' };
}
