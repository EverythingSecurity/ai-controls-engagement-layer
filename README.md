# AI Controls: Client Compliance Assessment Layer

Engagement layer around the AI Controls Framework library: role-based access control, and a deterministic scoping → applicable-frameworks pipeline. Spec: [CLIENT_COMPLIANCE_LAYER_V2.md](CLIENT_COMPLIANCE_LAYER_V2.md). Plan and open decisions: [docs/ENGAGEMENT_LAYER_PLAN.md](docs/ENGAGEMENT_LAYER_PLAN.md).

**Live demo (simulator):** see the repository's GitHub Pages site. It runs the same policy and applicability code as the tests, in the browser, with fictional tenants. It is not the secure product: a static site cannot enforce authorization.

## Status
| Phase | State |
|---|---|
| 0 Library import (557 controls, 18 frameworks, gap report) | done |
| 1 RBAC foundation (policy engine, matrix tests, SoD, audit log) | done |
| 4 (part) Applicability engine, seed rules, conflict detection, diff | engine + demo, rules are illustrative |
| 2, 3, 5-9 (onboarding, scoping app, question generation, fulfilment, scoring, reporting) | not started; blocked partly on library content (see plan) |

## Develop
Requires Node 24+. No dependencies.
```
npm test            # 29 tests
npm run migrate     # creates data/engagement.db, applies migrations, seeds RBAC
npm run import-library
npm run build-site  # regenerates docs/ (Pages demo) from the same source
```
Code: `src/rbac/core.ts` (pure policy), `src/rbac/engine.ts` (DB wrapper), `src/applicability.ts` (pure rules engine), `src/library.ts` (importer), `data/` (matrix, rules, questionnaire), `docs/` (Pages site).

## Licence
The library data is Apache-2.0 (see its `_meta`).
