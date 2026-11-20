# Engagement Layer Plan (Phase 0 + 1 delivered)

## Reused
`AI_Governance_Master_Checklist.json` v0.2.1 (Apache-2.0). The **Master Control List** (557 controls, 18 frameworks, 32 domains) is the uniform source; per-framework sheets are joined only to supply `evidence_hint`.

## Stack (needs confirmation)
Node 24+/TypeScript run natively, `node:sqlite`, `node:test`. **Zero dependencies.** SQLite stands in for Postgres because none is installed locally; SQL is plain and the engine sits behind `Db`. Moving to Postgres adds RLS as a second tenant-isolation layer.

## Added
- `migrations/001_rbac.sql`: principal, client, department, user (one org per user, CHECK-enforced), role, permission, role_permission, role_assignment (scope attributes), break_glass, policy_decision_log.
- `migrations/002_library.sql`: library_version, framework, unified_control, control (B7 metadata columns), library_gap.
- `data/rbac/*.json`: roles, A4 matrix, state rules. Permissions are data, seeded into tables.
- `src/rbac/engine.ts`: `authorize(db, ctx, "resource:action", resource)`; layers authn -> org -> role -> resource scope -> state -> SoD; default deny; 404 on cross-tenant; MFA; time rule; break-glass; decision log.
- `src/rbac/assignments.ts`: `grantRole` (no self-grant, no widening, tier match, SoD assessor/approver).
- `src/rbac/tenant.ts`: `scopedList`, the only sanctioned client-owned read path.
- `src/library.ts`: importer + gap report.

## Deviations from the spec (decide)
1. `assessment_package:assign` granted to engagement_lead (B10 names it; A4 omits it).
2. A4 gives content_manager R on framework_recommendation / generated_question_set, but A6 forbids client data. Granted at scope `content`, so it applies to library-level objects and never matches a client row.
3. department_lead `scoping_response:update` scoped to dept, not task.
4. Cross-tenant returns 404; same-tenant out-of-scope returns 403.
5. Break-glass requires approver + principal_notified + unexpired; it is read-only.

## Library gaps (block later phases; nothing invented)
All 557 controls: no `applies_if`, `depth_tier`, `risk_weight`, `owner_function`, `mandatory`, question templates. Imported as NULL, `metadata_status = needs_content_review`, treated as applies-to-all.
- `unified_control_id` is a **domain-level placeholder** (32 groups). Deduplicating on it would wrongly collapse unrelated controls. A real control-to-control mapping is needed before Phase 5.
- 12 ISO 27001 refs repeat (clause vs Annex A, e.g. 5.1). Stored as `iso27001:5.1` and `iso27001:5.1#2`; need distinct canonical refs.
- No Qatar PDPPL framework in the library, so no PDPPL rule can be seeded.
- Not controls: sheets 13 Domain Crosswalk and 19 Data Governance Register are not imported.

## Open decisions for you
Stack confirmation (Postgres + framework for Phase 2+); `owner_function` vocabulary; depth-tier rules; who authors question templates; self-select frameworks (assumed principal-controlled); first-release framework scope; white-labelling (deferred).
