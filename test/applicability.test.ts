import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { deriveProfile, findIssues, recommend, diffRecommendations, isVisible, type Question, type Rule } from '../src/applicability.ts';
import { FRAMEWORK_IDS } from '../src/library.ts';

const qs: Question[] = JSON.parse(readFileSync('data/scoping/demo_questionnaire.json', 'utf8')).questions;
const rules: Rule[] = JSON.parse(readFileSync('data/applicability/seed_rules.json', 'utf8')).rules;
const fws = Object.values(FRAMEWORK_IDS);
const run = (answers: Record<string, unknown>) => {
  const { attributes, source } = deriveProfile(qs, answers);
  return { attributes, issues: findIssues(qs, answers, attributes), recs: recommend(fws, rules, attributes, source) };
};
const out = (recs: any[], fw: string) => recs.find((r) => r.framework_id === fw);

test('every library framework gets a status and a rationale', () => {
  const { recs } = run({});
  assert.equal(recs.length, 18);
  assert.ok(recs.every((r) => r.outcome && r.rationale));
});

test('rule ids reference only frameworks that exist (no PDPPL etc.)', () => {
  for (const r of rules) if (!r.target_framework_id.startsWith('@')) assert.ok(fws.includes(r.target_framework_id), r.rule_id);
});

test('EU financial entity -> DORA required, with the exact answers and rule version cited', () => {
  const { recs } = run({ 'SCP-REG-001': true, 'SCP-GEO-001': ['EU'] });
  const d = out(recs, 'dora');
  assert.equal(d.outcome, 'required'); assert.deepEqual(d.rules, ['APP-DORA-001@1']);
  assert.deepEqual(d.because.map((b: any) => [b.attr, b.question_id]).sort(), [['geo.customer_countries', 'SCP-GEO-001'], ['reg.financial_entity', 'SCP-REG-001']]);
});

test('non-EU financial entity is not DORA-required (all-group enforced)', () => {
  assert.equal(out(run({ 'SCP-REG-001': true, 'SCP-GEO-001': ['QA'] }).recs, 'dora').outcome, 'optional');
});

test('AI answers drive ISO 42001, NIST AI RMF and EU AI Act', () => {
  const a = run({ 'SCP-AI-001': ['deploy', 'procure'], 'SCP-AI-004': 'high', 'SCP-AI-005': true });
  assert.equal(out(a.recs, 'iso42001').outcome, 'recommended');
  assert.equal(out(a.recs, 'nist_ai_rmf').outcome, 'recommended');
  assert.equal(out(a.recs, 'eu_ai_act').outcome, 'required');
  const lo = run({ 'SCP-AI-001': ['deploy'], 'SCP-AI-004': 'limited', 'SCP-AI-005': false });
  assert.equal(out(lo.recs, 'nist_ai_rmf').outcome, 'optional');
  assert.equal(out(lo.recs, 'eu_ai_act').outcome, 'optional');
});

test('strongest outcome wins when several rules hit; contract expands to named frameworks', () => {
  const a = run({ 'SCP-GOAL-001': 'certification', 'SCP-CERT-001': ['iso27001', 'dora', 'iso42001'] });
  assert.equal(out(a.recs, 'iso27001').outcome, 'required');
  assert.deepEqual(out(a.recs, 'iso27001').rules.sort(), ['APP-CONTRACT-001@1', 'APP-ISO27001-001@1']);
  assert.equal(out(a.recs, 'dora').outcome, 'required');
  assert.equal(out(a.recs, 'iso42001').outcome, 'required');
});

test('conditional display: hidden questions contribute nothing', () => {
  assert.equal(isVisible(qs.find((q) => q.id === 'SCP-DATA-002')!, {}), false);
  const a = run({ 'SCP-DATA-001': false, 'SCP-DATA-002': 'high' });
  assert.equal(a.attributes['data.volume_band'], undefined);
  assert.equal(out(a.recs, 'iso27701').outcome, 'optional');
});

test('conflicts and gaps are blockers', () => {
  const codes = (x: Record<string, unknown>) => run(x).issues.filter((i) => i.severity === 'blocker').map((i) => i.code);
  assert.ok(codes({ 'SCP-REG-001': true }).includes('FINENT_NO_JURISDICTION'));
  assert.ok(codes({ 'SCP-AI-001': ['none', 'deploy'] }).includes('CONFLICT_AI_NONE'));
  assert.ok(codes({}).includes('MISSING_REQUIRED'));
});

test('deterministic and diffable: same input same output; re-scoping shows added/removed frameworks', () => {
  const x = { 'SCP-AI-001': ['deploy'], 'SCP-AI-004': 'high', 'SCP-AI-005': true };
  assert.deepEqual(run(x).recs, run({ ...x }).recs);
  const diff = diffRecommendations(run(x).recs, run({ ...x, 'SCP-AI-001': ['procure'] }).recs);
  assert.deepEqual(diff.removed.sort(), ['iso42001', 'nist_ai_rmf']);
  assert.deepEqual(diff.added, []);
});
