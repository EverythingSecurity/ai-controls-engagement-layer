import { test } from 'node:test';
import assert from 'node:assert/strict';
import { authorize } from '../src/rbac/engine.ts';
import { scopedList } from '../src/rbac/tenant.ts';
import { world, ROLE_USER } from './helpers.ts';

test('cross-tenant: client C1 users get 404 (not 403) on every C2 resource and action', () => {
  const w = world();
  for (const role of ['client_admin', 'client_contributor', 'department_lead', 'department_respondent', 'client_reviewer', 'client_exec_viewer']) {
    const ctx = w.ctx(ROLE_USER(role));
    for (const perm of ['response:read', 'response:update', 'evidence:read', 'report:read', 'department:read', 'user:read', 'client_tenant:read']) {
      const d = authorize(w.db, ctx, perm, { client_id: 'C2', department_id: 'D1', assigned_to: ctx.user.id, status: 'released' });
      assert.deepEqual([d.allowed, d.status], [false, 404], `${role} ${perm}`);
    }
  }
});

test('cross-tenant: principal P2 admin cannot touch P1 clients; P1 admin cannot touch C3', () => {
  const w = world();
  assert.equal(authorize(w.db, w.ctx('u_p2_admin'), 'client_tenant:read', { client_id: 'C1' }).status, 404);
  assert.equal(authorize(w.db, w.ctx(ROLE_USER('principal_admin')), 'client_tenant:read', { client_id: 'C3' }).status, 404);
  assert.equal(authorize(w.db, w.ctx(ROLE_USER('principal_admin')), 'client_tenant:read', { client_id: 'C2' }).allowed, true);
  assert.equal(authorize(w.db, w.ctx('u_p2_admin'), 'user:read', { principal_id: 'P1' }).status, 404);
});

test('listing is tenant-filtered by default (search/export path)', () => {
  const w = world();
  const names = (u: string) => scopedList(w.db, w.ctx(u), 'department').map((d) => d.id).sort();
  assert.deepEqual(names(ROLE_USER('client_contributor')), ['D1', 'D2']);
  assert.deepEqual(names('u_c2_admin'), ['D3']);
  assert.deepEqual(names(ROLE_USER('principal_admin')), ['D1', 'D2', 'D3']);
  assert.deepEqual(names(ROLE_USER('principal_assessor')), ['D1', 'D2']); // assigned C1 only
  assert.deepEqual(names('u_assessor_c2'), ['D3']);
  assert.deepEqual(names('u_p2_admin'), []);
  assert.deepEqual(names(ROLE_USER('principal_content_manager')), []);
  assert.deepEqual(names(ROLE_USER('platform_super_admin')), []);
  assert.throws(() => scopedList(w.db, w.ctx(ROLE_USER('principal_admin')), 'user'), /not a registered/);
});

test('assignment scope: assessor on C1 cannot access C2; framework restriction applies', () => {
  const w = world();
  const a = w.ctx(ROLE_USER('principal_assessor'));
  assert.equal(authorize(w.db, a, 'control_assessment:update', { client_id: 'C1', package_state: 'in_assessment' }).allowed, true);
  const d = authorize(w.db, a, 'control_assessment:update', { client_id: 'C2', package_state: 'in_assessment' });
  assert.equal(d.allowed, false); assert.equal(d.layer, 'resource_scope');
  w.db.prepare(`UPDATE role_assignment SET framework_ids='["iso27001"]' WHERE user_id=?`).run(ROLE_USER('principal_assessor'));
  const a2 = w.ctx(ROLE_USER('principal_assessor'));
  assert.equal(authorize(w.db, a2, 'control_assessment:update', { client_id: 'C1', framework_id: 'iso27001', package_state: 'in_assessment' }).allowed, true);
  assert.equal(authorize(w.db, a2, 'control_assessment:update', { client_id: 'C1', framework_id: 'dora', package_state: 'in_assessment' }).allowed, false);
});

test('department and task rules', () => {
  const w = world();
  const lead = w.ctx(ROLE_USER('department_lead')), r1 = w.ctx(ROLE_USER('department_respondent')), r2 = w.ctx('u_resp2');
  assert.equal(authorize(w.db, lead, 'task_delegation:read', { client_id: 'C1', department_id: 'D1' }).allowed, true);
  assert.equal(authorize(w.db, lead, 'task_delegation:read', { client_id: 'C1', department_id: 'D2' }).allowed, false);
  const task = { client_id: 'C1', department_id: 'D1', assigned_to: ROLE_USER('department_respondent'), package_state: 'in_fulfilment' };
  assert.equal(authorize(w.db, r1, 'response:update', task).allowed, true);
  assert.equal(authorize(w.db, r2, 'response:update', task).allowed, false, 'respondent cannot see another respondent task');
  assert.equal(authorize(w.db, r1, 'response:update', { ...task, assigned_to: undefined }).allowed, false);
});

test('qualifiers: analyst draft-only, contributor final/released/summary-only', () => {
  const w = world();
  const an = w.ctx(ROLE_USER('principal_analyst')), co = w.ctx(ROLE_USER('client_contributor'));
  const ca = { client_id: 'C1', package_state: 'in_assessment' };
  assert.equal(authorize(w.db, an, 'control_assessment:update', { ...ca, status: 'draft' }).allowed, true);
  assert.equal(authorize(w.db, an, 'control_assessment:update', { ...ca, status: 'final' }).allowed, false, 'analyst cannot finalise');
  assert.equal(authorize(w.db, co, 'report:read', { client_id: 'C1', status: 'draft' }).allowed, false);
  assert.equal(authorize(w.db, co, 'report:read', { client_id: 'C1', status: 'released' }).allowed, true);
  assert.equal(authorize(w.db, co, 'control_assessment:read', { client_id: 'C1', status: 'draft' }).allowed, false);
  assert.equal(authorize(w.db, co, 'framework_recommendation:read', { client_id: 'C1', view: 'summary' }).allowed, true);
  assert.equal(authorize(w.db, co, 'framework_recommendation:read', { client_id: 'C1' }).allowed, false, 'contributor sees summary only');
});

test('content manager has no client data access', () => {
  const w = world();
  const cm = w.ctx(ROLE_USER('principal_content_manager'));
  for (const p of ['response:read', 'framework_recommendation:read', 'generated_question_set:read', 'scoping_response:read'])
    assert.equal(authorize(w.db, cm, p, { client_id: 'C1' }).allowed, false, p);
  assert.equal(authorize(w.db, cm, 'applicability_rule:approve', {}).allowed, true);
});

test('time rule: expired and not-yet-valid assignments grant nothing', () => {
  const w = world();
  const u = ROLE_USER('principal_assessor');
  w.db.prepare(`UPDATE role_assignment SET valid_to='2020-01-01T00:00:00.000Z' WHERE user_id=?`).run(u);
  assert.equal(authorize(w.db, w.ctx(u), 'response:read', { client_id: 'C1' }).allowed, false);
  w.db.prepare(`UPDATE role_assignment SET valid_from='2999-01-01T00:00:00.000Z', valid_to=NULL WHERE user_id=?`).run(u);
  assert.equal(authorize(w.db, w.ctx(u), 'response:read', { client_id: 'C1' }).allowed, false);
});

test('inactive user and MFA enforcement', () => {
  const w = world();
  assert.equal(authorize(w.db, w.ctx(ROLE_USER('principal_assessor'), false), 'response:read', { client_id: 'C1' }).layer, 'authentication');
  assert.equal(authorize(w.db, w.ctx(ROLE_USER('client_admin'), false), 'department:read', { client_id: 'C1' }).allowed, false);
  assert.equal(authorize(w.db, w.ctx(ROLE_USER('client_contributor'), false), 'department:read', { client_id: 'C1' }).allowed, true);
  w.db.prepare(`UPDATE user SET active=0 WHERE id=?`).run(ROLE_USER('client_contributor'));
  assert.equal(authorize(w.db, w.ctx(ROLE_USER('client_contributor')), 'department:read', { client_id: 'C1' }).allowed, false);
});

test('state rule: answers locked after submitted_locked; no scoring before it', () => {
  const w = world();
  const co = w.ctx(ROLE_USER('client_contributor')), as = w.ctx(ROLE_USER('principal_assessor'));
  for (const s of ['submitted_locked', 'in_assessment', 'assessed', 'reported'])
    assert.equal(authorize(w.db, co, 'response:update', { client_id: 'C1', package_state: s }).layer, 'state', s);
  assert.equal(authorize(w.db, co, 'response:update', { client_id: 'C1', package_state: 'in_fulfilment' }).allowed, true);
  for (const s of ['released', 'in_fulfilment'])
    assert.equal(authorize(w.db, as, 'control_assessment:create', { client_id: 'C1', package_state: s }).layer, 'state', s);
  assert.equal(authorize(w.db, as, 'control_assessment:create', { client_id: 'C1' }).allowed, false, 'missing state fails closed');
  assert.equal(authorize(w.db, as, 'control_assessment:create', { client_id: 'C1', package_state: 'submitted_locked' }).allowed, true);
});
