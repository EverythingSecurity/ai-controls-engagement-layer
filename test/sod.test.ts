import { test } from 'node:test';
import assert from 'node:assert/strict';
import { authorize } from '../src/rbac/engine.ts';
import { grantRole } from '../src/rbac/assignments.ts';
import { world, ROLE_USER } from './helpers.ts';

test('SoD: scorer cannot approve a report containing their scores', () => {
  const w = world();
  const ap = w.ctx(ROLE_USER('principal_report_approver'));
  const rep = { client_id: 'C1', report_state: 'assessor_complete' };
  assert.equal(authorize(w.db, ap, 'report:approve', { ...rep, scored_by: ['someone_else'] }).allowed, true);
  const d = authorize(w.db, ap, 'report:approve', { ...rep, scored_by: [ROLE_USER('principal_report_approver')] });
  assert.deepEqual([d.allowed, d.layer], [false, 'separation_of_duties']);
  assert.equal(authorize(w.db, ap, 'report:approve', { client_id: 'C1', report_state: 'draft' }).layer, 'state');
});

test('SoD: same user cannot be assessor and report_approver for the same client', () => {
  const w = world();
  const admin = w.ctx(ROLE_USER('principal_admin'));
  // u_assessor_c2 is assessor on C2: approver on C2 refused, on C1 allowed
  assert.equal(grantRole(w.db, admin, { user_id: 'u_assessor_c2', role: 'principal_report_approver', client_ids: ['C2'] }).ok, false);
  assert.equal(grantRole(w.db, admin, { user_id: 'u_assessor_c2', role: 'principal_report_approver', client_ids: ['C1'] }).ok, true);
  // and the reverse direction, now that they hold approver on C1
  assert.equal(grantRole(w.db, admin, { user_id: 'u_assessor_c2', role: 'principal_assessor', client_ids: ['C1'] }).ok, false);
});

test('SoD: contributor cannot be sole approver of a department that has a lead/reviewer', () => {
  const w = world();
  const co = w.ctx(ROLE_USER('client_contributor')), lead = w.ctx(ROLE_USER('department_lead'));
  const t = { client_id: 'C1', department_id: 'D1', package_state: 'in_fulfilment', transition: 'approved_by_contributor' };
  assert.equal(authorize(w.db, co, 'task_delegation:update', { ...t, dept_has_lead_or_reviewer: true }).layer, 'separation_of_duties');
  assert.equal(authorize(w.db, co, 'task_delegation:update', { ...t, dept_has_lead_or_reviewer: true, dept_approved: true }).allowed, true);
  assert.equal(authorize(w.db, co, 'task_delegation:update', { ...t, dept_has_lead_or_reviewer: false }).allowed, true);
  assert.equal(authorize(w.db, lead, 'task_delegation:update', { ...t, dept_has_lead_or_reviewer: true }).allowed, true);
});

test('SoD: super admin reads client content only via approved, notified, unexpired break-glass', () => {
  const w = world();
  const sa = () => w.ctx(ROLE_USER('platform_super_admin'));
  const p = () => authorize(w.db, sa(), 'response:read', { client_id: 'C1' });
  assert.equal(p().allowed, false);
  const ins = (approved: string | null, notified: number, exp: string) =>
    w.db.prepare('INSERT INTO break_glass(user_id,client_id,reason,approved_by,principal_notified,expires_at) VALUES (?,?,?,?,?,?)')
      .run(ROLE_USER('platform_super_admin'), 'C1', 'incident 42', approved, notified, exp);
  ins(null, 1, '2999-01-01T00:00:00.000Z'); assert.equal(p().allowed, false, 'unapproved');
  w.db.exec('DELETE FROM break_glass');
  ins('principal_admin', 0, '2999-01-01T00:00:00.000Z'); assert.equal(p().allowed, false, 'principal not notified');
  w.db.exec('DELETE FROM break_glass');
  ins('principal_admin', 1, '2000-01-01T00:00:00.000Z'); assert.equal(p().allowed, false, 'expired');
  w.db.exec('DELETE FROM break_glass');
  ins('principal_admin', 1, '2999-01-01T00:00:00.000Z'); assert.equal(p().allowed, true);
  assert.equal(authorize(w.db, sa(), 'response:update', { client_id: 'C1', package_state: 'in_fulfilment' }).allowed, false, 'read-only');
  assert.equal(authorize(w.db, sa(), 'response:read', { client_id: 'C2' }).allowed, false, 'grant is per-client');
  assert.throws(() => w.db.prepare("INSERT INTO break_glass(user_id,client_id,reason,expires_at) VALUES ('u','C1','','x')").run());
});

test('privilege escalation: no self-grant, no widening, no role above own, no cross-org grants', () => {
  const w = world();
  const admin = w.ctx(ROLE_USER('principal_admin'));
  const g = (actor: any, a: any) => grantRole(w.db, actor, a);
  assert.equal(g(admin, { user_id: ROLE_USER('principal_admin'), role: 'principal_admin' }).ok, false, 'self-grant');
  assert.equal(g(w.ctx(ROLE_USER('principal_assessor')), { user_id: 'u_assessor_new', role: 'principal_assessor', client_ids: ['C1'] }).ok, false, 'assessor cannot grant');
  assert.equal(g(w.ctx(ROLE_USER('principal_engagement_lead')), { user_id: ROLE_USER('principal_analyst'), role: 'principal_assessor', client_ids: ['C1'] }).ok, false);
  assert.equal(g(w.ctx(ROLE_USER('client_contributor')), { user_id: ROLE_USER('department_respondent'), role: 'client_admin' }).ok, false, 'contributor cannot make admin');
  const ca = w.ctx(ROLE_USER('client_admin'));
  assert.equal(g(ca, { user_id: ROLE_USER('client_admin'), role: 'client_admin' }).ok, false, 'client_admin self-grant');
  assert.equal(g(ca, { user_id: ROLE_USER('client_contributor'), role: 'principal_admin' }).ok, false, 'tier mismatch');
  assert.equal(g(ca, { user_id: 'u_c2_contrib', role: 'department_lead', department_ids: ['D1'] }).ok, false, 'other client user');
  assert.equal(g(ca, { user_id: ROLE_USER('client_contributor'), role: 'department_lead', department_ids: ['D3'] }).ok, false, 'dept of another client');
  assert.equal(g(ca, { user_id: ROLE_USER('client_contributor'), role: 'department_lead', department_ids: ['D2'] }).ok, true);
  assert.equal(g(admin, { user_id: 'u_assessor_new', role: 'principal_assessor', client_ids: ['C3'] }).ok, false, 'client in another principal');
  assert.equal(g(w.ctx('u_p2_admin'), { user_id: 'u_assessor_new', role: 'principal_assessor', client_ids: ['C1'] }).ok, false, 'other principal admin');
  assert.equal(g(admin, { user_id: ROLE_USER('platform_auditor'), role: 'platform_super_admin' }).ok, false, 'platform role');
  assert.equal(g(admin, { user_id: 'u_assessor_new', role: 'principal_assessor', client_ids: [] }).ok, false, 'assigned role needs clients');
  assert.equal(g(admin, { user_id: 'u_assessor_new', role: 'principal_assessor', client_ids: ['C2'] }).ok, true);
});

test('every grant attempt is audit-logged and denials are logged by authorize()', () => {
  const w = world();
  const before = (w.db.prepare('SELECT count(*) n FROM policy_decision_log').get() as any).n;
  grantRole(w.db, w.ctx(ROLE_USER('principal_admin')), { user_id: ROLE_USER('principal_admin'), role: 'principal_admin' });
  authorize(w.db, w.ctx(ROLE_USER('client_exec_viewer')), 'response:update', { client_id: 'C1' });
  const rows = w.db.prepare('SELECT allowed, reason FROM policy_decision_log ORDER BY id DESC LIMIT 2').all() as any[];
  assert.equal((w.db.prepare('SELECT count(*) n FROM policy_decision_log').get() as any).n, before + 2);
  assert.ok(rows.every((r) => r.allowed === 0 && r.reason));
});
