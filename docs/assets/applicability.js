// PURE applicability engine (no Node APIs). Shared by tests and the browser demo.
                                                                 
                                                               
                                                         
                                                                                                                                                                         
                                                                                                                                                                                                   
                                                                                 
                                            
                                                                                      
                                 
                                                                                                                                                   
 
                                                                                         

const arr = (v         )            => (Array.isArray(v) ? v : v === undefined || v === null ? [] : [v]);

export function evalCond(c      , a       )          {
  const v = a[c.attr];
  switch (c.op) {
    case 'eq': return v === c.value;
    case 'neq': return v !== undefined && v !== c.value;      // unknown never satisfies neq
    case 'in': return arr(c.value).includes(v);
    case 'contains_any': return arr(v).some((x) => arr(c.value).includes(x));
    case 'exists': return v !== undefined && arr(v).length > 0;
    default: return false;
  }
}
/** B4 semantics: if both groups exist, (any satisfied) AND (all satisfied). Absent group = true. */
export function evalCondition(c                  , a       )          {
  if (!c) return true;
  const anyOk = !c.any?.length || c.any.some((x) => evalCond(x, a));
  const allOk = !c.all?.length || c.all.every((x) => evalCond(x, a));
  return anyOk && allOk;
}
export const isVisible = (q          , a       ) => evalCondition(q.show_if, a);

/** Normalises answers (by question id) into the flat Client Profile. Hidden questions contribute nothing. */
export function deriveProfile(questions            , answers                         )                                                        {
  const attributes        = {}; const source                         = {};
  // iterate to a fixed point so show_if can depend on attributes derived from earlier questions
  for (const q of questions) {
    if (!isVisible(q, attributes)) continue;
    let v = answers[q.id];
    if (v === undefined || v === '' || (Array.isArray(v) && v.length === 0 && q.required)) continue;
    if (q.id === 'SCP-AI-001' && Array.isArray(v)) v = v.filter((x) => x !== 'none');
    attributes[q.feeds_attributes[0]] = v; source[q.feeds_attributes[0]] = q.id;
  }
  return { attributes, source };
}

export function findIssues(questions            , answers                         , attrs       )          {
  const out          = [];
  for (const q of questions)
    if (q.required && isVisible(q, attrs) && !attrs[q.feeds_attributes[0]] && attrs[q.feeds_attributes[0]] !== false)
      out.push({ severity: 'blocker', code: 'MISSING_REQUIRED', message: `${q.id} is unanswered: ${q.text}` });
  const aiNone = arr(answers['SCP-AI-001']).includes('none');
  if (aiNone && arr(answers['SCP-AI-001']).length > 1)
    out.push({ severity: 'blocker', code: 'CONFLICT_AI_NONE', message: "SCP-AI-001: 'none' selected together with other AI roles." });
  if (attrs['reg.financial_entity'] === true && !arr(attrs['geo.customer_countries']).length)
    out.push({ severity: 'blocker', code: 'FINENT_NO_JURISDICTION', message: 'Financial entity stated but no customer jurisdiction given.' });
  if (answers['SCP-ORG-001'] === 'financial_services' && attrs['reg.financial_entity'] === false)
    out.push({ severity: 'warning', code: 'SECTOR_VS_LICENCE', message: 'Sector is financial services but not a licensed financial entity: confirm.' });
  return out;
}

const STRENGTH                          = { required: 3, recommended: 2, optional: 1, not_applicable: 4 }; // explicit exclusion wins

/** Every framework gets a status; nothing is silently omitted (B5). */
export function recommend(frameworkIds          , rules        , attrs       , source                        )                   {
  const hits = new Map                                                ();
  for (const r of rules) {
    if (!evalCondition(r.condition, attrs)) continue;
    const targets = r.target_framework_id.startsWith('@') ? arr(attrs[r.target_framework_id.slice(1)]).map(String) : [r.target_framework_id];
    const attrNames = [...new Set([...(r.condition.any ?? []), ...(r.condition.all ?? [])].map((c) => c.attr))];
    for (const t of targets) {
      if (!frameworkIds.includes(t)) continue;
      const evidence = attrNames.filter((n) => attrs[n] !== undefined).map((n) => ({ attr: n, value: attrs[n], question_id: source[n] ?? null }));
      (hits.get(t) ?? hits.set(t, []).get(t) ).push({ rule: r, evidence });
    }
  }
  return frameworkIds.map((fw) => {
    const h = hits.get(fw);
    if (!h) return { framework_id: fw, outcome: 'optional'           , confidence: 'n/a', because: [], rules: [], authority_reference: '', rationale: 'No applicability rule was triggered by the scoping answers; available on request.' };
    const top = h.reduce((a, b) => (STRENGTH[b.rule.outcome] > STRENGTH[a.rule.outcome] ? b : a));
    return {
      framework_id: fw, outcome: top.rule.outcome, confidence: top.rule.confidence, rationale: top.rule.rationale,
      authority_reference: top.rule.authority_reference, rules: h.map((x) => `${x.rule.rule_id}@${x.rule.version}`),
      because: h.flatMap((x) => x.evidence).filter((e, i, l) => l.findIndex((o) => o.attr === e.attr) === i),
    };
  });
}

                                                                                                                                
const inSet = (o         ) => o === 'required' || o === 'recommended';
/** Re-scoping diff (B6): frameworks entering/leaving the applicable set and outcome changes. */
export function diffRecommendations(before                  , after                  )          {
  const b = new Map(before.map((r) => [r.framework_id, r.outcome]));
  const d          = { added: [], removed: [], changed: [] };
  for (const r of after) {
    const o = b.get(r.framework_id);
    if (o === undefined || o === r.outcome) continue;
    if (!inSet(o) && inSet(r.outcome)) d.added.push(r.framework_id);
    else if (inSet(o) && !inSet(r.outcome)) d.removed.push(r.framework_id);
    else d.changed.push({ framework_id: r.framework_id, from: o, to: r.outcome });
  }
  return d;
}
