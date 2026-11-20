import { decide } from './core.js';
import * as A from './applicability.js';

const D = await (await fetch('assets/data.json')).json();
const $ = (s, r = document) => r.querySelector(s);
const h = (tag, attrs = {}, ...kids) => {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k === 'class') e.className = v; else if (k.startsWith('on')) e[k] = v; else if (v === true) e.setAttribute(k, ''); else if (v !== false && v != null) e.setAttribute(k, v);
  }
  for (const c of kids.flat()) if (c != null && c !== false) e.append(c.nodeType ? c : document.createTextNode(String(c)));
  return e;
};
const pill = (o) => h('span', { class: `pill ${o}` }, o.replace('_', ' '));
const fwName = Object.fromEntries(D.frameworks.map((f) => [f.id, f.name]));
const ACT = { create: 'C', read: 'R', update: 'U', delete: 'D', approve: 'A', submit: 'S', assign: 'G', provision: 'P' };

const model = {
  clients: Object.fromEntries(D.world.clients.map((c) => [c.id, { principal_id: c.principal_id }])),
  grants: D.grants, mfa_roles: D.roles.filter((r) => r.requires_mfa).map((r) => r.name), state_rules: D.state_rules, break_glass: [],
};
$('#meta').textContent = `Library ${D.built_from.library_version}: ${D.built_from.controls} controls, ${D.built_from.frameworks} frameworks.`;

/* ---------------- tabs ---------------- */
const TABS = [['overview', 'Overview'], ['matrix', 'Roles & permissions'], ['sim', 'Permission simulator'], ['scoping', 'Scoping → frameworks'], ['controls', 'Controls in scope'], ['gaps', 'Library gaps']];
const state = { tab: 'overview', answers: {}, overrides: {}, baseline: null, approved: null };
function renderTabs() {
  const nav = $('#tabs'); nav.replaceChildren(...TABS.map(([id, label]) =>
    h('button', { role: 'tab', 'aria-selected': String(state.tab === id), onclick: () => { state.tab = id; location.hash = id; render(); } }, label)));
}
function render() { renderTabs(); const v = $('#view'); v.replaceChildren(({ overview, matrix, sim, scoping, controls, gaps })[state.tab]()); }

/* ---------------- overview ---------------- */
function overview() {
  return h('div', {},
    h('h2', {}, 'What this shows'),
    h('p', {}, 'A consulting principal assesses client companies against a library of compliance frameworks. Two things make that safe and useful: tight access control between tenants and roles, and a deterministic, explainable way to decide which frameworks (and controls) apply to which client.'),
    h('div', { class: 'grid two' },
      h('div', { class: 'card' }, h('h3', {}, '1. Role-based access control'), h('p', {}, `${D.roles.length} roles, ${D.grants.length} data-driven grants. Every decision passes authentication, organisation (tenant), role, resource scope, record state and separation-of-duties checks. Default deny; cross-tenant requests return 404.`),
        h('p', {}, h('a', { href: '#matrix' }, 'Browse the matrix'), ' or ', h('a', { href: '#sim' }, 'try to break it in the simulator'), '.')),
      h('div', { class: 'card' }, h('h3', {}, '2. Scoping → applicable frameworks'), h('p', {}, 'Answer a short scoping questionnaire. It becomes a client profile; versioned rules then give every framework a status (required / recommended / optional) with the exact answers and rule versions that caused it. Overrides need a written reason; changes show a diff.'),
        h('p', {}, h('a', { href: '#scoping' }, 'Run a scoping'), '.'))),
    h('h3', {}, 'What is real vs illustrative'),
    h('ul', {}, h('li', {}, 'Real: the policy core and applicability engine (the code under test), the 557-control library import.'),
      h('li', {}, 'Illustrative: the demo questionnaire and the seven seed rules (from the spec, not approved by a content manager or admin).'),
      h('li', {}, 'Not here: login, MFA provider, database, API, evidence upload, scoring, reporting. Those are later phases. See "Library gaps" for what content is still missing.')));
}

/* ---------------- matrix ---------------- */
function matrix() {
  const tierSel = h('select', { onchange: draw }, h('option', { value: '' }, 'All tiers'), ...['platform', 'principal', 'client'].map((t) => h('option', { value: t }, t)));
  const out = h('div');
  function draw() {
    const roles = D.roles.filter((r) => !tierSel.value || r.tier === tierSel.value);
    const resources = [...new Set(D.grants.map((g) => g.permission.split(':')[0]))];
    const cell = (role, res) => {
      const gs = D.grants.filter((g) => g.role === role && g.permission.startsWith(res + ':'));
      return h('td', { class: 'c', title: gs.map((g) => `${g.permission.split(':')[1]}@${g.scope}${g.qualifier ? '#' + g.qualifier : ''}`).join('\n') },
        [...new Set(gs.map((g) => ACT[g.permission.split(':')[1]] ?? '?'))].join(''));
    };
    out.replaceChildren(h('div', { class: 'wrap' }, h('table', {},
      h('thead', {}, h('tr', {}, h('th', {}, 'resource'), ...roles.map((r) => h('th', { title: r.description }, r.name.replace(/^(principal|client|platform|department)_/, '$1 ')))) ),
      h('tbody', {}, ...resources.map((res) => h('tr', {}, h('td', {}, res), ...roles.map((r) => cell(r.name, res))))))));
  }
  draw();
  return h('div', {}, h('h2', {}, 'Role × resource × action'),
    h('p', { class: 'mut' }, 'C create · R read · U update · D delete · A approve · S submit · G assign · P provision. Hover a cell for scope (own / asg = assigned clients / dept / task / principal) and qualifiers (#draft, #final, #released, #summary, #reply). Blank = denied. Roles never inherit; each lists its permissions explicitly.'),
    h('div', { class: 'row' }, h('label', {}, 'Tier ', tierSel)), out);
}

/* ---------------- simulator ---------------- */
const LAYERS = ['authentication', 'organisation', 'role', 'resource_scope', 'state', 'separation_of_duties'];
const LAYER_LABEL = { authentication: '1 Authentication (active user, MFA)', organisation: '2 Organisation / tenant scope', role: '3 Role permission', resource_scope: '4 Resource scope (assigned client, department, task, qualifier)', state: '5 Record state', separation_of_duties: '6 Separation of duties' };
function sim() {
  const sel = (opts, id) => h('select', { id }, ...opts.map(([v, l]) => h('option', { value: v }, l ?? v)));
  const users = D.world.users.map((u) => [u.id, `${u.id}  (${u.assignments.map((a) => a.role + (a.client_ids.length ? ' → ' + a.client_ids.join(',') : '') + (a.department_ids.length ? ' dept ' + a.department_ids.join(',') : '')).join('; ')})`]);
  const resources = [...new Set(D.grants.map((g) => g.permission.split(':')[0]))].sort();
  const none = ['', '(none)'];
  const f = {
    user: sel(users, 'f-user'), res: sel(resources.map((r) => [r]), 'f-res'), act: sel(Object.keys(ACT).map((a) => [a]), 'f-act'),
    client: sel([none, ...D.world.clients.map((c) => [c.id, `${c.id} ${c.name} (${c.principal_id})`])], 'f-client'),
    dept: sel([none, ...D.world.departments.map((d) => [d.id, `${d.id} ${d.name} (${d.client_id})`])], 'f-dept'),
    assigned: sel([none, ['self', 'the acting user'], ['other', 'someone else']], 'f-asg'),
    qual: sel([none, ['status=draft'], ['status=final'], ['status=released'], ['view=summary'], ['change=reply']], 'f-qual'),
    pkg: sel([none, ...['generated', 'principal_approved', 'released', 'in_fulfilment', 'submitted_locked', 'in_assessment', 'assessed', 'reported'].map((s) => [s])], 'f-pkg'),
    rep: sel([none, ...['draft', 'assessor_complete', 'approver_signed_off', 'released'].map((s) => [s])], 'f-rep'),
    scp: sel([none, ...['not_started', 'in_progress', 'submitted'].map((s) => [s])], 'f-scp'),
    fw: sel([none, ...D.frameworks.map((x) => [x.id, x.name])], 'f-fw'),
    mfa: h('input', { type: 'checkbox', checked: true, id: 'f-mfa' }), scorer: h('input', { type: 'checkbox', id: 'f-scorer' }),
    transition: h('input', { type: 'checkbox', id: 'f-tr' }), deptHas: h('input', { type: 'checkbox', id: 'f-dh' }),
    bg: h('input', { type: 'checkbox', id: 'f-bg' }),
  };
  const result = h('div', { class: 'card' });
  function compute() {
    const u = D.world.users.find((x) => x.id === f.user.value);
    const ctx = { user: { id: u.id, org_type: u.org_type, org_id: u.org_id, active: true }, assignments: u.assignments, mfa_verified: f.mfa.checked, now: new Date() };
    const res = { id: 'rec-1' };
    if (f.client.value) res.client_id = f.client.value; if (f.dept.value) res.department_id = f.dept.value;
    if (f.assigned.value) res.assigned_to = f.assigned.value === 'self' ? u.id : 'someone_else';
    if (f.qual.value) { const [k, v] = f.qual.value.split('='); res[k] = v; }
    if (f.pkg.value) res.package_state = f.pkg.value; if (f.rep.value) res.report_state = f.rep.value; if (f.scp.value) res.scoping_state = f.scp.value;
    if (f.fw.value) res.framework_id = f.fw.value;
    if (f.scorer.checked) res.scored_by = [u.id];
    if (f.transition.checked) { res.transition = 'approved_by_contributor'; res.dept_has_lead_or_reviewer = f.deptHas.checked; }
    model.break_glass = f.bg.checked && res.client_id
      ? [{ user_id: u.id, client_id: res.client_id, approved_by: 'principal_admin', principal_notified: 1, expires_at: '2999-01-01T00:00:00.000Z' }] : [];
    const perm = `${f.res.value}:${f.act.value}`;
    const d = decide(model, ctx, perm, res);
    const failIdx = d.allowed ? LAYERS.length : LAYERS.indexOf(d.layer);
    result.replaceChildren(
      h('div', { class: `verdict ${d.allowed ? 'allow' : 'deny'}` }, d.allowed ? `ALLOW (${d.status})` : `DENY (${d.status}${d.status === 404 ? ', hides existence' : ''})`),
      h('p', {}, h('strong', {}, perm), ' by ', h('strong', {}, u.id)), h('p', { class: 'mut' }, d.reason),
      h('ul', { class: 'layers' }, ...LAYERS.map((l, i) => h('li', { class: i < failIdx ? 'ok' : i === failIdx ? 'no' : 'skip' }, LAYER_LABEL[l]))),
      h('details', {}, h('summary', {}, 'Request passed to the policy core'), h('pre', {}, JSON.stringify({ permission: perm, user: ctx.user, assignments: ctx.assignments, resource: res, mfa_verified: ctx.mfa_verified }, null, 1))));
  }
  const field = (label, el) => h('label', {}, label, el);
  const chk = (label, el) => h('label', { class: 'opt' }, el, label);
  for (const el of Object.values(f)) el.onchange = compute;
  function preset(p) { for (const [k, v] of Object.entries(p)) { const el = f[k]; if (el.type === 'checkbox') el.checked = !!v; else el.value = v; } compute(); }
  const PRESETS = [
    ['Cross-tenant read', { user: 'u_client_contributor', res: 'response', act: 'read', client: 'C2', dept: '', assigned: '', qual: '', pkg: '', rep: '', scp: '', fw: '', mfa: 1 }],
    ['Answer after lock', { user: 'u_client_contributor', res: 'response', act: 'update', client: 'C1', pkg: 'submitted_locked', qual: '', dept: '', assigned: '' }],
    ['Analyst finalises score', { user: 'u_principal_analyst', res: 'control_assessment', act: 'update', client: 'C1', pkg: 'in_assessment', qual: 'status=final' }],
    ['Scorer approves own report', { user: 'u_principal_report_approver', res: 'report', act: 'approve', client: 'C1', rep: 'assessor_complete', scorer: 1, qual: '' }],
    ['Respondent, someone else\'s task', { user: 'u_department_respondent', res: 'response', act: 'update', client: 'C1', dept: 'D1', assigned: 'other', pkg: 'in_fulfilment', qual: '' }],
    ['Assessor, unassigned client', { user: 'u_principal_assessor', res: 'control_assessment', act: 'update', client: 'C2', pkg: 'in_assessment', qual: '' }],
    ['Super admin reads client data', { user: 'u_platform_super_admin', res: 'response', act: 'read', client: 'C1', bg: 0 }],
    ['Admin without MFA', { user: 'u_client_admin', res: 'department', act: 'read', client: 'C1', mfa: 0, assigned: '', qual: '', pkg: '' }],
  ];
  setTimeout(() => preset(PRESETS[0][1]));
  return h('div', {}, h('h2', {}, 'Permission simulator'),
    h('p', { class: 'mut' }, 'Pick a fictional user and a request; the real policy core decides and shows which layer stopped it. Fixture: Principal P1 owns clients C1 (Acme Bank) and C2; Principal P2 owns C3.'),
    h('div', { class: 'row' }, ...PRESETS.map(([n, p]) => h('button', { class: 'btn', onclick: () => preset(p) }, n))),
    h('div', { class: 'grid two' },
      h('div', { class: 'card' }, field('Acting user', f.user), field('Resource', f.res), field('Action', f.act), field('Record belongs to client', f.client), field('Department', f.dept), field('Assigned to', f.assigned), field('Record qualifier', f.qual),
        field('Framework', f.fw), field('Package state', f.pkg), field('Report state', f.rep), field('Scoping state', f.scp),
        h('div', { class: 'row' }, chk('MFA verified', f.mfa), chk('Acting user scored this', f.scorer), chk('Break-glass approved (super admin)', f.bg)),
        h('div', { class: 'row' }, chk('Task approval by contributor', f.transition), chk('Dept has lead/reviewer', f.deptHas))), result));
}

/* ---------------- scoping / applicability ---------------- */
const QS = D.questionnaire.questions, RULES = D.rules.rules, FW_IDS = D.frameworks.map((f) => f.id);
const SCENARIOS = {
  'EU bank using high-risk AI': { 'SCP-ORG-001': 'financial_services', 'SCP-REG-001': true, 'SCP-GEO-001': ['EU', 'QA'], 'SCP-DATA-001': true, 'SCP-DATA-002': 'high', 'SCP-AI-001': ['deploy', 'procure'], 'SCP-AI-004': 'high', 'SCP-AI-005': true, 'SCP-CERT-001': ['iso27001'], 'SCP-GOAL-001': 'regulatory' },
  'Qatar SaaS seeking ISO certification': { 'SCP-ORG-001': 'technology', 'SCP-REG-001': false, 'SCP-ICT-001': false, 'SCP-GEO-001': ['QA', 'GCC_OTHER'], 'SCP-DATA-001': true, 'SCP-DATA-002': 'medium', 'SCP-AI-001': ['none'], 'SCP-CERT-001': [], 'SCP-GOAL-001': 'certification' },
  'Inconsistent answers (blockers)': { 'SCP-ORG-001': 'financial_services', 'SCP-REG-001': true, 'SCP-AI-001': ['none', 'develop'] },
};
function analyse() {
  const { attributes, source } = A.deriveProfile(QS, state.answers);
  const issues = A.findIssues(QS, state.answers, attributes);
  const base = A.recommend(FW_IDS, RULES, attributes, source);
  const effective = base.map((r) => {
    const o = state.overrides[r.framework_id];
    return o && o.outcome && o.outcome !== r.outcome && o.why?.trim() ? { ...r, outcome: o.outcome, overridden: true } : r;
  });
  for (const [fw, o] of Object.entries(state.overrides)) if (o.outcome && o.outcome !== base.find((r) => r.framework_id === fw).outcome && !o.why?.trim())
    issues.push({ severity: 'blocker', code: 'OVERRIDE_NO_JUSTIFICATION', message: `Override of ${fwName[fw]} needs a written justification.` });
  return { attributes, source, issues, base, effective };
}
function scoping() {
  const root = h('div');
  const draw = () => {
    const a = analyse(); const blockers = a.issues.filter((i) => i.severity === 'blocker');
    const form = h('div', {}, ...QS.filter((q) => A.isVisible(q, a.attributes)).map((q) => {
      const v = state.answers[q.id]; const set = (x) => { state.answers[q.id] = x; draw(); };
      let input;
      if (q.answer_type === 'boolean') input = h('div', {}, ...[[true, 'Yes'], [false, 'No']].map(([val, l]) => h('label', { class: 'opt' }, h('input', { type: 'radio', name: q.id, checked: v === val, onchange: () => set(val) }), l)));
      else if (q.answer_type === 'single_select') input = h('select', { onchange: (e) => set(e.target.value || undefined) }, h('option', { value: '' }, '(select)'), ...q.options.map((o) => h('option', { value: o, selected: v === o }, o)));
      else input = h('div', {}, ...q.options.map((o) => h('label', { class: 'opt' }, h('input', { type: 'checkbox', checked: (v ?? []).includes(o), onchange: (e) => set(e.target.checked ? [...(v ?? []), o] : (v ?? []).filter((x) => x !== o)) }), o)));
      return h('div', { class: 'q' }, h('div', { class: 't' }, q.text, q.required ? ' *' : ''), h('div', { class: 'mut' }, `${q.id} → ${q.feeds_attributes.join(', ')}`), q.help_text && h('div', { class: 'mut' }, q.help_text), input);
    }));
    const diff = state.baseline ? A.diffRecommendations(state.baseline, a.effective) : null;
    const recs = [...a.effective].sort((x, y) => ['required', 'recommended', 'optional', 'not_applicable'].indexOf(x.outcome) - ['required', 'recommended', 'optional', 'not_applicable'].indexOf(y.outcome) || fwName[x.framework_id].localeCompare(fwName[y.framework_id]));
    const table = h('div', { class: 'wrap' }, h('table', {}, h('thead', {}, h('tr', {}, ...['Framework', 'Outcome', 'Because', 'Rule', 'Override (needs reason)'].map((t) => h('th', {}, t)))),
      h('tbody', {}, ...recs.map((r) => {
        const o = state.overrides[r.framework_id] ?? {};
        return h('tr', {}, h('td', {}, fwName[r.framework_id]), h('td', {}, pill(r.outcome), r.overridden ? ' (overridden)' : '', h('div', { class: 'mut' }, r.confidence !== 'n/a' ? `confidence ${r.confidence}` : '')),
          h('td', {}, r.because.length ? r.because.map((b) => h('div', {}, `${b.attr} = ${JSON.stringify(b.value)}`, b.question_id ? ` (${b.question_id})` : '')) : h('span', { class: 'mut' }, r.rationale), r.because.length ? h('div', { class: 'mut' }, r.rationale) : null),
          h('td', {}, r.rules.join(', ') || '–', r.authority_reference ? h('div', { class: 'mut' }, r.authority_reference) : null),
          h('td', {}, h('select', { onchange: (e) => { state.overrides[r.framework_id] = { ...o, outcome: e.target.value }; draw(); } }, ...['', 'required', 'recommended', 'optional', 'not_applicable'].map((x) => h('option', { value: x, selected: (o.outcome ?? '') === x }, x || 'no override'))),
            o.outcome ? h('input', { type: 'text', placeholder: 'justification', value: o.why ?? '', onchange: (e) => { state.overrides[r.framework_id] = { ...o, why: e.target.value }; draw(); } }) : null));
      }))));
    root.replaceChildren(h('h2', {}, 'Scoping → profile → applicable frameworks'),
      h('div', { class: 'row' }, h('span', { class: 'mut' }, 'Load scenario:'), ...Object.entries(SCENARIOS).map(([n, ans]) => h('button', { class: 'btn', onclick: () => { state.answers = structuredClone(ans); state.overrides = {}; draw(); } }, n)),
        h('button', { class: 'btn', onclick: () => { state.answers = {}; state.overrides = {}; state.baseline = null; state.approved = null; draw(); } }, 'Clear')),
      h('div', { class: 'grid two' },
        h('div', {}, h('h3', {}, `Scoping questionnaire (${D.questionnaire.version}, demo)`), form),
        h('div', {}, h('h3', {}, 'Client profile (derived attributes)'), h('pre', {}, JSON.stringify({ questionnaire_version: D.questionnaire.version, attributes: a.attributes }, null, 1)),
          h('h3', {}, 'Conflicts and gaps'), a.issues.length ? a.issues.map((i) => h('div', { class: `issue ${i.severity}` }, h('strong', {}, i.severity), ' ', i.message)) : h('p', { class: 'mut' }, 'None.'))),
      h('h3', {}, 'Framework recommendation report (every framework in the library)'), table,
      diff && h('div', { class: 'card' }, h('strong', {}, 'Diff vs baseline: '), `added ${JSON.stringify(diff.added.map((x) => fwName[x]))}, removed ${JSON.stringify(diff.removed.map((x) => fwName[x]))}, changed ${JSON.stringify(diff.changed.map((c) => `${fwName[c.framework_id]} ${c.from}→${c.to}`))}. A released package would not change until a principal approves.`),
      h('div', { class: 'row', style: 'margin-top:10px' },
        h('button', { class: 'btn', onclick: () => { state.baseline = structuredClone(a.effective); draw(); } }, 'Save as baseline (simulate released package)'),
        h('button', { class: 'btn p', disabled: blockers.length > 0, onclick: () => { state.approved = a; state.tab = 'controls'; location.hash = 'controls'; render(); } }, 'Approve framework set →'),
        blockers.length ? h('span', { class: 'deny' }, `Blocked: ${blockers.length} blocker(s)`) : null));
  };
  draw(); return root;
}

/* ---------------- controls in scope ---------------- */
function controls() {
  const ap = state.approved;
  if (!ap) return h('div', {}, h('h2', {}, 'Controls in scope'), h('p', {}, 'Approve a framework set first (', h('a', { href: '#scoping' }, 'Scoping → frameworks'), ').'));
  const inScope = ap.effective.filter((r) => r.outcome === 'required' || r.outcome === 'recommended');
  const trace = (c, r) => ({ control_id: c.id, framework_id: c.f, generated_because: { frameworks: [c.f], profile_attributes: r.because.map((b) => `${b.attr}=${JSON.stringify(b.value)}`), rule_versions: r.rules, outcome: r.outcome, depth_tier: null, mandatory: null }, applicability: 'applies_to_all (no applies_if authored: needs content review)', questions_generated: 0 });
  const sel = h('select', { onchange: draw }, ...inScope.map((r) => h('option', { value: r.framework_id }, `${fwName[r.framework_id]} (${r.outcome})`)));
  const out = h('div');
  function draw() {
    const r = inScope.find((x) => x.framework_id === sel.value); if (!r) return out.replaceChildren(h('p', {}, 'No required or recommended frameworks.'));
    const cs = D.controls.filter((c) => c.f === r.framework_id);
    out.replaceChildren(h('p', {}, `${cs.length} controls apply (all of them: no applicability metadata exists yet). Questions: 0 generated, because no question templates exist in the library. Below is the draft evidence request from the library's "Evidence to verify" column.`),
      h('div', { class: 'wrap' }, h('table', {}, h('thead', {}, h('tr', {}, ...['Ref', 'Title', 'Domain', 'Draft evidence request', 'Trace'].map((t) => h('th', {}, t)))),
        h('tbody', {}, ...cs.map((c) => h('tr', {}, h('td', {}, c.ref), h('td', {}, c.title), h('td', {}, c.d), h('td', {}, c.e ?? ''), h('td', {}, h('details', {}, h('summary', {}, 'why'), h('pre', {}, JSON.stringify(trace(c, r), null, 1))))))))));
  }
  draw();
  const total = inScope.reduce((n, r) => n + D.controls.filter((c) => c.f === r.framework_id).length, 0);
  const dl = () => { const blob = new Blob([JSON.stringify({ package_draft: true, questionnaire_version: D.questionnaire.version, library_version: D.built_from.library_version, profile: ap.attributes, frameworks: inScope.map((r) => ({ framework_id: r.framework_id, outcome: r.outcome, rules: r.rules, because: r.because, overridden: !!r.overridden, justification: state.overrides[r.framework_id]?.why ?? null })) }, null, 2)], { type: 'application/json' }); const a = h('a', { href: URL.createObjectURL(blob), download: 'package-draft.json' }); a.click(); };
  return h('div', {}, h('h2', {}, 'Controls in scope (draft package)'),
    h('p', { class: 'mut' }, `${inScope.length} approved frameworks, ${total} controls. This is as far as the library can go honestly: question generation, de-duplication and department routing need control metadata that has not been authored (see Library gaps).`),
    h('div', { class: 'row' }, h('label', {}, 'Framework ', sel), h('button', { class: 'btn', onclick: dl }, 'Download package-draft.json')), out);
}

/* ---------------- gaps ---------------- */
function gaps() {
  const g = D.built_from.gaps;
  return h('div', {}, h('h2', {}, 'Library gaps (nothing is invented)'),
    h('p', {}, `The source library provides ${D.built_from.controls} controls across ${D.built_from.frameworks} frameworks, but none of the metadata the engagement layer needs to tailor them to a client. Every control is imported as "needs content review" and treated as applying to all clients.`),
    h('div', { class: 'wrap' }, h('table', {}, h('thead', {}, h('tr', {}, h('th', {}, 'Missing field'), h('th', {}, 'Controls'))), h('tbody', {}, ...Object.entries(g).map(([k, n]) => h('tr', {}, h('td', {}, k), h('td', {}, n)))))),
    h('h3', {}, 'Also'), h('ul', {},
      h('li', {}, '"unified_control_id" is only a domain-level placeholder (32 groups). De-duplicating on it would collapse unrelated controls, so it is not used for question de-duplication.'),
      h('li', {}, `${D.built_from.duplicate_refs.length} ISO 27001 refs repeat (clause vs Annex A, e.g. 5.1): ${D.built_from.duplicate_refs.join(', ')}.`),
      h('li', {}, 'Qatar PDPPL is not in the library, so no rule can target it. No GDPR applicability rule is seeded either, to avoid inventing a legal claim.'),
      h('li', {}, 'Needed from the content owner: owner_function vocabulary, depth-tier rules, per-control applies_if, question templates, real cross-framework control mapping.')));
}

addEventListener('hashchange', () => { const t = location.hash.slice(1); if (TABS.some(([id]) => id === t) && t !== state.tab) { state.tab = t; render(); } });
const t0 = location.hash.slice(1); if (TABS.some(([id]) => id === t0)) state.tab = t0;
render();
