// PURE policy core: no Node APIs, no DB. Shared by the server engine and the browser demo (compiled by scripts/build-site.ts).
export interface User { id: string; org_type: 'platform' | 'principal' | 'client'; org_id: string | null; active: boolean }
export interface Assignment {
  role: string; org_id: string | null;
  client_ids: string[]; framework_ids: string[]; department_ids: string[];
  valid_from?: string | null; valid_to?: string | null;
}
export interface Ctx { user: User; assignments: Assignment[]; mfa_verified: boolean; now?: Date }
export interface Resource {
  id?: string; client_id?: string; principal_id?: string; framework_id?: string; department_id?: string;
  assigned_to?: string; status?: string; view?: string; change?: string;
  scored_by?: string[]; transition?: string; dept_has_lead_or_reviewer?: boolean; dept_approved?: boolean;
  [k: string]: unknown;
}
export type Layer = 'authentication' | 'organisation' | 'role' | 'resource_scope' | 'state' | 'separation_of_duties' | 'allow';
export interface Decision { allowed: boolean; status: 200 | 403 | 404; layer: Layer; reason: string }
export interface GrantRow { role: string; permission: string; scope: string; qualifier: string }
export interface BreakGlass { user_id: string; client_id: string; approved_by: string | null; principal_notified: number | boolean; expires_at: string }
export interface Model {
  clients: Record<string, { principal_id: string }>;
  grants: GrantRow[];
  mfa_roles: string[];
  state_rules: Record<string, { attr: string; allowed: string[] }>;
  break_glass: BreakGlass[];
}

const QUALIFIERS: Record<string, [string, string]> = {
  draft: ['status', 'draft'], final: ['status', 'final'], released: ['status', 'released'],
  summary: ['view', 'summary'], reply: ['change', 'reply'],
};
const rank: Record<Layer, number> = { authentication: 0, organisation: 1, role: 2, resource_scope: 3, state: 4, separation_of_duties: 5, allow: 6 };
const deny = (layer: Layer, reason: string, status: 403 | 404 = 403): Decision => ({ allowed: false, status, layer, reason });

export function decide(m: Model, ctx: Ctx, permission: string, res: Resource): Decision {
  const now = ctx.now ?? new Date();
  const { user } = ctx;
  if (!user || !user.active) return deny('authentication', 'user inactive or unknown');

  let principalId = res.principal_id;
  if (res.client_id) {
    const c = m.clients[res.client_id];
    if (!c) return deny('organisation', 'client not found', 404);
    principalId = c.principal_id;
    if (user.org_type === 'client' && user.org_id !== res.client_id) return deny('organisation', 'cross-tenant access', 404);
    if (user.org_type === 'principal' && user.org_id !== principalId) return deny('organisation', 'cross-tenant access', 404);
  } else if (principalId && user.org_type === 'client') return deny('organisation', 'cross-tenant access', 404);
  else if (principalId && user.org_type === 'principal' && user.org_id !== principalId) return deny('organisation', 'cross-tenant access', 404);

  const action = permission.split(':')[1];
  const valid = ctx.assignments.filter((a) => inTime(a, now) && (a.org_id ?? null) === (user.org_id ?? null));
  if (!valid.length) return deny('role', 'no active role assignment (expired, not yet valid or wrong org)');

  if (valid.some((a) => a.role === 'platform_super_admin') && res.client_id) {
    if (action !== 'read') return deny('role', 'super admin is read-only even under break-glass');
    const t = now.toISOString();
    const bg = m.break_glass.some((b) => b.user_id === user.id && b.client_id === res.client_id && b.approved_by && b.principal_notified && b.expires_at > t);
    return bg ? { allowed: true, status: 200, layer: 'allow', reason: 'break-glass (time-boxed, reason recorded, principal notified)' }
              : deny('role', 'client content requires approved break-glass', 404);
  }

  const mfaRoles = new Set(m.mfa_roles);
  let best: Decision | null = null;
  for (const a of valid) {
    for (const g of m.grants.filter((g) => g.role === a.role && g.permission === permission)) {
      const d = check(m, ctx, a, g, permission, res, principalId, mfaRoles);
      if (d.allowed) return d;
      if (!best || rank[d.layer] > rank[best.layer]) best = d;
    }
  }
  return best ?? deny('role', `no role grants ${permission} (default deny)`);
}

function check(m: Model, ctx: Ctx, a: Assignment, g: GrantRow, permission: string, res: Resource, principalId: string | undefined, mfaRoles: Set<string>): Decision {
  const { user } = ctx;
  if (mfaRoles.has(a.role) && !ctx.mfa_verified) return deny('authentication', `MFA required for ${a.role}`);
  switch (g.scope) {
    case 'platform': if (user.org_type !== 'platform') return deny('resource_scope', 'platform scope only'); break;
    case 'principal':
      if (user.org_type !== 'principal' || !principalId || user.org_id !== principalId) return deny('resource_scope', 'outside own principal'); break;
    case 'asg':
      if (!res.client_id || !a.client_ids.includes(res.client_id)) return deny('resource_scope', 'client not assigned');
      if (a.framework_ids.length && res.framework_id && !a.framework_ids.includes(res.framework_id)) return deny('resource_scope', 'framework not assigned');
      break;
    case 'own': if (user.org_type !== 'client' || res.client_id !== user.org_id) return deny('resource_scope', 'outside own client'); break;
    case 'dept':
      if (user.org_type !== 'client' || res.client_id !== user.org_id) return deny('resource_scope', 'outside own client');
      if (!res.department_id || !a.department_ids.includes(res.department_id)) return deny('resource_scope', 'outside own department'); break;
    case 'task':
      if (user.org_type !== 'client' || res.client_id !== user.org_id) return deny('resource_scope', 'outside own client');
      if (!res.assigned_to || res.assigned_to !== user.id) return deny('resource_scope', 'task not assigned to user'); break;
    case 'content': if (res.client_id) return deny('resource_scope', 'content roles have no client data access'); break;
    default: return deny('resource_scope', `unknown scope ${g.scope}`);
  }
  if (g.qualifier) {
    const [attr, val] = QUALIFIERS[g.qualifier] ?? [];
    if (!attr || res[attr] !== val) return deny('resource_scope', `grant limited to ${g.qualifier} records`);
  }
  const sr = m.state_rules[permission];
  if (sr) {
    const v = res[sr.attr];
    if (typeof v !== 'string' || !sr.allowed.includes(v)) return deny('state', `${permission} not allowed when ${sr.attr}=${String(v)}`);
  }
  if (permission === 'report:approve' && res.scored_by?.includes(user.id)) return deny('separation_of_duties', 'scorer cannot approve a report containing their scores');
  if (permission === 'task_delegation:update' && res.transition === 'approved_by_contributor' && a.role === 'client_contributor'
      && res.dept_has_lead_or_reviewer && !res.dept_approved)
    return deny('separation_of_duties', 'department answers need department_lead/client_reviewer approval; contributor cannot be sole approver');
  return { allowed: true, status: 200, layer: 'allow', reason: `granted to ${a.role}` };
}

function inTime(a: Assignment, now: Date): boolean {
  const t = now.toISOString();
  return (!a.valid_from || a.valid_from <= t) && (!a.valid_to || a.valid_to > t);
}
