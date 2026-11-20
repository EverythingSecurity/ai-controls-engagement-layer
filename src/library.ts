import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import type { Db } from './db.ts';

// Canonical framework IDs, keyed by the "Framework" value used in the Master Control List.
export const FRAMEWORK_IDS: Record<string, string> = {
  'ISO/IEC 27001': 'iso27001', 'ISO/IEC 42001': 'iso42001', 'ISO/IEC 17021-1': 'iso17021', 'GDPR': 'gdpr',
  'EU AI Act': 'eu_ai_act', 'DORA': 'dora', 'ISO/IEC 31700-1/-2': 'iso31700', 'FAIR Risk Methodology': 'fair',
  'ISO/IEC 27701': 'iso27701', 'ISO/IEC 42005': 'iso42005', 'Privacy by Design (Cavoukian)': 'pbd',
  'NIST AI RMF': 'nist_ai_rmf', 'MITRE ATLAS': 'mitre_atlas', 'ISO/IEC 27090': 'iso27090',
  'OECD AI Principles': 'oecd_ai', 'NIST ARIA': 'nist_aria', 'ISO/IEC 5181': 'iso5181', 'OWASP LLM Top 10': 'owasp_llm',
};
// Per-framework sheets: used only to enrich controls with "Evidence to verify" (joined on Ref).
const EVIDENCE_SHEETS: Record<string, { sheet: string; ref: string; evidence: string }[]> = {
  'ISO/IEC 42001': [{ sheet: '1 CIA-Security Controls', ref: 'Ref', evidence: 'Evidence to verify' }, { sheet: '2 Non-CIA (Other) Controls', ref: 'Ref', evidence: 'Evidence to verify' }],
  'EU AI Act': [{ sheet: '3 EU AI Act', ref: 'Article/Annex', evidence: 'Evidence to verify' }],
  'OECD AI Principles': [{ sheet: '4 OECD AI Principles', ref: 'Ref', evidence: 'Evidence to verify' }],
  'NIST AI RMF': [{ sheet: '5 NIST AI RMF', ref: 'Ref', evidence: 'Evidence to verify' }],
  'ISO/IEC 42005': [{ sheet: '6 ISO 42005 Impact Assessment', ref: 'Ref', evidence: 'Evidence to verify' }],
  'ISO/IEC 27001': [{ sheet: '7 ISO 27001', ref: 'Ref', evidence: 'Evidence to verify' }],
  'GDPR': [{ sheet: '9 GDPR', ref: 'Article', evidence: 'Evidence to verify' }],
  'OWASP LLM Top 10': [{ sheet: '10 OWASP LLM Top 10', ref: 'Ref', evidence: 'Evidence to verify' }],
  'ISO/IEC 27701': [{ sheet: '11 ISO 27701 PIMS', ref: 'Ref', evidence: 'Evidence to verify' }],
  'Privacy by Design (Cavoukian)': [{ sheet: '14 Privacy by Design', ref: 'Ref', evidence: 'Evidence to verify' }],
  'ISO/IEC 31700-1/-2': [{ sheet: '15 ISO 31700 PbD (Consumer)', ref: 'Ref', evidence: 'Evidence to verify' }],
  'DORA': [{ sheet: '16 DORA', ref: 'Article', evidence: 'Evidence to verify' }],
  'NIST ARIA': [{ sheet: '17 NIST ARIA', ref: 'Ref', evidence: 'Evidence to verify' }],
  'FAIR Risk Methodology': [{ sheet: '18 FAIR Risk Methodology', ref: 'Ref', evidence: 'Evidence to verify' }],
  'ISO/IEC 5181': [{ sheet: '20 ISO 5181 Data Provenance', ref: 'Ref', evidence: 'Evidence to verify' }],
  'ISO/IEC 27090': [{ sheet: '21 ISO 27090 AI Threats', ref: 'Ref', evidence: 'Evidence to verify' }],
  'MITRE ATLAS': [{ sheet: '22 MITRE ATLAS', ref: 'Ref', evidence: 'Defensive evidence / test guidance' }],
  'ISO/IEC 17021-1': [{ sheet: '8 ISO 17021 Alignment', ref: 'Ref', evidence: 'Evidence to verify' }],
};
const norm = (s: unknown) => String(s ?? '').toLowerCase().replace(/\s+/g, ' ').trim();
const slug = (s: string) => s.toLowerCase().replace(/&/g, 'and').replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');

// Fields the B7 control model requires but the source library does not carry.
export const REQUIRED_METADATA = ['applies_if', 'depth_tier', 'risk_weight', 'owner_function', 'mandatory', 'unified_control_id', 'question_templates'] as const;

export interface ImportSummary {
  version: string; frameworks: number; controls: number; unified_placeholders: number;
  evidence_joined: number; duplicate_refs: string[]; gaps: Record<string, number>;
}

export function importLibrary(db: Db, file: string): ImportSummary {
  const raw = readFileSync(file);
  const sha = createHash('sha256').update(raw).digest('hex');
  const data = JSON.parse(raw.toString('utf8'));
  const version = `lib-${data._meta.dataset_version}-${sha.slice(0, 8)}`;
  if (db.prepare('SELECT 1 FROM library_version WHERE version = ?').get(version)) throw new Error(`library ${version} already imported`);

  const evidence = new Map<string, string>();
  for (const [fw, specs] of Object.entries(EVIDENCE_SHEETS)) for (const s of specs)
    for (const it of data[s.sheet]?.items ?? []) {
      const k = `${fw}|${String(it[s.ref]).trim()}|${norm(it['Title'])}`; const e = it[s.evidence];
      if (e && !evidence.has(k)) evidence.set(k, String(e));
    }

  db.exec('BEGIN');
  try {
    db.prepare('INSERT INTO library_version(version,source_file,source_sha256,dataset_version) VALUES (?,?,?,?)')
      .run(version, file.split('/').pop()!, sha, data._meta.dataset_version);
    const rows = data['12 Master Control List'].items as any[];
    const insFw = db.prepare('INSERT OR IGNORE INTO framework(id,name) VALUES (?,?)');
    const insUc = db.prepare('INSERT OR IGNORE INTO unified_control(id,domain) VALUES (?,?)');
    const insCtl = db.prepare(`INSERT INTO control(id,framework_id,ref,title,requirement,domain,evidence_hint,unified_control_id,library_version)
      VALUES (?,?,?,?,?,?,?,?,?)`);
    const insGap = db.prepare('INSERT INTO library_gap(control_id,missing_field,note) VALUES (?,?,?)');
    const seen = new Map<string, number>(); const dups: string[] = [];
    let joined = 0;
    const unknown = new Set<string>();
    for (const r of rows) {
      const fw = FRAMEWORK_IDS[r.Framework];
      if (!fw) { unknown.add(r.Framework); continue; }
      insFw.run(fw, r.Framework);
      const ucId = `UCF-DOMAIN-${slug(r.Domain)}`; insUc.run(ucId, r.Domain);
      const base = `${fw}:${String(r.Ref).trim()}`;
      const n = (seen.get(base) ?? 0) + 1; seen.set(base, n);
      if (n > 1) dups.push(base);
      const id = n > 1 ? `${base}#${n}` : base;
      const ev = evidence.get(`${r.Framework}|${String(r.Ref).trim()}|${norm(r.Title)}`)
        ?? evidence.get(`${r.Framework}|${String(r.Ref).trim()}|`) ?? null; // sheets without a Title column join on ref
      if (ev) joined++;
      insCtl.run(id, fw, String(r.Ref).trim(), r.Title, r['Requirement (condensed)'] ?? null, r.Domain, ev, ucId, version);
      for (const f of REQUIRED_METADATA) insGap.run(id, f,
        f === 'unified_control_id' ? 'domain-level placeholder only; needs a real unified control mapping'
        : f === 'question_templates' ? 'no question templates authored in source library' : 'not present in source library; defaults to applies-to-all');
    }
    if (unknown.size) throw new Error(`Unmapped framework names in master list: ${[...unknown].join(', ')}`);
    db.exec(`UPDATE framework SET control_count = (SELECT count(*) FROM control WHERE framework_id = framework.id)`);
    db.exec('COMMIT');
    const gaps: Record<string, number> = {};
    for (const g of db.prepare('SELECT missing_field f, count(*) n FROM library_gap GROUP BY missing_field').all() as any[]) gaps[g.f] = g.n;
    return {
      version, frameworks: (db.prepare('SELECT count(*) n FROM framework').get() as any).n,
      controls: (db.prepare('SELECT count(*) n FROM control').get() as any).n,
      unified_placeholders: (db.prepare('SELECT count(*) n FROM unified_control').get() as any).n,
      evidence_joined: joined, duplicate_refs: dups, gaps,
    };
  } catch (e) { db.exec('ROLLBACK'); throw e; }
}
