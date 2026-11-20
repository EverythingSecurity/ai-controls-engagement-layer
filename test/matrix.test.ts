import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { authorize, type Resource } from '../src/rbac/engine.ts';
import { world, ROLE_USER } from './helpers.ts';
import { root } from '../src/db.ts';

// Independent transcription of spec section A4 (C create R read U update D delete A approve S submit G assign).
// Qualifiers/scopes are exercised in scope.test.ts; here we assert the role x resource x action allow/deny set.
const A4: Record<string, string> = {
  principal_admin: 'client_tenant:CRUD user:CRUD scoping_template:R scoping_response:R applicability_rule:R framework_recommendation:R framework_assignment:R generated_question_set:R assessment_package:R control_assessment:R finding:R clarification:R report:R remediation:R scoring_config:CRUA audit_log:R',
  principal_engagement_lead: 'client_tenant:RU scoping_template:R scoping_response:R applicability_rule:R framework_recommendation:RA framework_assignment:CUA generated_question_set:RA assessment_package:CRUG submission:R control_assessment:R finding:RA clarification:R report:R remediation:R scoring_config:R audit_log:R',
  principal_assessor: 'client_tenant:R scoping_template:R scoping_response:R applicability_rule:R framework_recommendation:R framework_assignment:R generated_question_set:RU assessment_package:R response:R evidence:R submission:R control_assessment:CRU finding:CRU clarification:CRU report:R remediation:R scoring_config:R',
  principal_analyst: 'client_tenant:R scoping_template:R scoping_response:R applicability_rule:R framework_recommendation:R framework_assignment:R generated_question_set:R assessment_package:R response:R evidence:R submission:R control_assessment:CRU finding:CRU clarification:CRU report:R remediation:R scoring_config:R',
  principal_content_manager: 'scoping_template:CRUA applicability_rule:CRUA framework_recommendation:R generated_question_set:R scoring_config:R',
  principal_report_approver: 'client_tenant:R control_assessment:R finding:R report:RA scoring_config:R',
  client_admin: 'client_tenant:RU user:CRUD department:CRUD scoping_response:R response:R evidence:R task_delegation:R remediation:R audit_log:R',
  client_contributor: 'client_tenant:R user:R department:R scoping_response:CRUS framework_recommendation:R framework_assignment:R generated_question_set:R assessment_package:R task_delegation:CRUD response:CRUS evidence:CRUD submission:S control_assessment:R finding:R clarification:RU report:R remediation:CRU',
  department_lead: 'user:R department:R scoping_response:U generated_question_set:R assessment_package:R task_delegation:CRU response:CRUS evidence:CRUD finding:R clarification:RU remediation:CRU',
  department_respondent: 'scoping_response:U generated_question_set:R assessment_package:R task_delegation:R response:CRU evidence:CRU remediation:RU',
  client_reviewer: 'scoping_response:R generated_question_set:R assessment_package:R task_delegation:R response:R evidence:R remediation:R',
  client_exec_viewer: 'scoping_response:R framework_assignment:R assessment_package:R control_assessment:R finding:R report:R remediation:R',
};
const ACT: Record<string, string> = { C: 'create', R: 'read', U: 'update', D: 'delete', A: 'approve', S: 'submit', G: 'assign' };
const RESOURCES = ['client_tenant','user','department','scoping_template','scoping_response','applicability_rule','framework_recommendation','framework_assignment','generated_question_set','assessment_package','task_delegation','response','evidence','submission','control_assessment','finding','clarification','report','remediation','scoring_config','audit_log'];
const ACTIONS = Object.values(ACT);
const states: Record<string, { attr: string; allowed: string[] }> = JSON.parse(readFileSync(`${root}/data/rbac/state_rules.json`, 'utf8'));
// Every qualifier context; a permission is "granted" if ANY satisfies it (qualifiers are tested separately).
const QCTX: Resource[] = [{}, { status: 'draft' }, { status: 'final' }, { status: 'released' }, { view: 'summary' }, { change: 'reply' }];

const tierOf = (role: string) => role.startsWith('principal') ? 'principal' : 'client';

test('A4 matrix: every role x resource x action is allowed/denied exactly as specified', () => {
  const w = world();
  let checked = 0;
  for (const [role, spec] of Object.entries(A4)) {
    const expected = new Set<string>();
    for (const part of spec.split(' ')) { const [r, letters] = part.split(':'); for (const l of letters) expected.add(`${r}:${ACT[l]}`); }
    const ctx = w.ctx(ROLE_USER(role));
    for (const r of RESOURCES) for (const a of ACTIONS) {
      const perm = `${r}:${a}`;
      const base: Resource = { id: 'x' };
      if (role !== 'principal_content_manager') base.client_id = 'C1';
      if (['department_lead', 'department_respondent'].includes(role)) base.department_id = 'D1';
      base.assigned_to = ROLE_USER(role);
      const st = states[perm]; if (st) base[st.attr] = st.allowed[0];
      const granted = QCTX.some((q) => authorize(w.db, ctx, perm, { ...base, ...q }, { log: false }).allowed);
      assert.equal(granted, expected.has(perm), `${role} ${perm}: expected ${expected.has(perm) ? 'ALLOW' : 'DENY'}`);
      checked++;
    }
    void tierOf;
  }
  assert.ok(checked > 1000);
});

test('platform roles: only their listed permissions', () => {
  const w = world();
  const sa = w.ctx(ROLE_USER('platform_super_admin')), au = w.ctx(ROLE_USER('platform_auditor'));
  assert.ok(authorize(w.db, sa, 'principal:provision', {}).allowed);
  assert.ok(authorize(w.db, au, 'audit_log:read', {}).allowed);
  assert.ok(!authorize(w.db, au, 'audit_log:update', {}).allowed);
  assert.ok(!authorize(w.db, au, 'report:read', { client_id: 'C1', status: 'released' }).allowed);
  assert.ok(!authorize(w.db, sa, 'response:read', { client_id: 'C1' }).allowed);
});

test('default deny: unlisted action and unknown resource', () => {
  const w = world();
  for (const role of Object.keys(A4)) {
    const ctx = w.ctx(ROLE_USER(role));
    assert.equal(authorize(w.db, ctx, 'nonexistent:read', { client_id: 'C1' }).allowed, false);
    assert.equal(authorize(w.db, ctx, 'report:destroy', { client_id: 'C1' }).allowed, false);
  }
});
