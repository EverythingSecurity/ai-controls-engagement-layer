// Builds the static GitHub Pages demo into docs/. Compiles the SAME pure engines the tests exercise.
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { stripTypeScriptTypes } from 'node:module';
import { openDb, migrate } from '../src/db.ts';
import { seedRbac } from '../src/rbac/seed.ts';
import { importLibrary } from '../src/library.ts';
import { world } from '../test/helpers.ts';

mkdirSync('docs/assets', { recursive: true });
for (const [src, out] of [['src/rbac/core.ts', 'core.js'], ['src/applicability.ts', 'applicability.js']])
  writeFileSync(`docs/assets/${out}`, stripTypeScriptTypes(readFileSync(src, 'utf8'), { mode: 'strip' }));

const db = openDb(); migrate(db); seedRbac(db);
const lib = importLibrary(db, 'AI_Governance_Master_Checklist.json');
const all = (sql: string) => db.prepare(sql).all() as any[];
const w = world();
const stateRules = JSON.parse(readFileSync('data/rbac/state_rules.json', 'utf8')); delete stateRules._doc;
const users = (w.db.prepare('SELECT id, org_type, org_id FROM user ORDER BY id').all() as any[]).map((u) => ({
  ...u, active: true,
  assignments: (w.db.prepare('SELECT role, org_id, client_ids, framework_ids, department_ids FROM role_assignment WHERE user_id=?').all(u.id) as any[])
    .map((a) => ({ role: a.role, org_id: a.org_id, client_ids: JSON.parse(a.client_ids), framework_ids: JSON.parse(a.framework_ids), department_ids: JSON.parse(a.department_ids) })),
}));
const data = {
  built_from: { library_version: lib.version, controls: lib.controls, frameworks: lib.frameworks, gaps: lib.gaps, duplicate_refs: lib.duplicate_refs },
  roles: all('SELECT name, tier, description, requires_mfa FROM role'),
  grants: all('SELECT role, permission, scope, qualifier FROM role_permission ORDER BY role, permission'),
  state_rules: stateRules,
  world: {
    principals: w.db.prepare('SELECT id, name FROM principal').all(), clients: w.db.prepare('SELECT id, principal_id, name FROM client').all(),
    departments: w.db.prepare('SELECT id, client_id, name FROM department').all(), users,
  },
  frameworks: all('SELECT id, name, control_count FROM framework ORDER BY name'),
  controls: all('SELECT id, framework_id f, ref, title, domain d, requirement r, evidence_hint e FROM control'),
  questionnaire: JSON.parse(readFileSync('data/scoping/demo_questionnaire.json', 'utf8')),
  rules: JSON.parse(readFileSync('data/applicability/seed_rules.json', 'utf8')),
};
writeFileSync('docs/assets/data.json', JSON.stringify(data));
writeFileSync('docs/.nojekyll', '');
console.log(`site data: ${data.controls.length} controls, ${data.grants.length} grants, ${users.length} demo users`);
