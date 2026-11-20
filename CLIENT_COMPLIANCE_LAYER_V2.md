# Client Compliance Assessment Layer: Build Spec v2 (RBAC + Applicability-Driven Questionnaires)

> Supersedes `CLIENT_COMPLIANCE_LAYER.md`. This version defines (A) a layered, explicit RBAC model and (B) a deterministic pipeline that turns scoping answers into an applicable framework set and a generated, traceable question set per client.

## 0. Instructions for Claude Code

The framework library (DORA, data governance, ISO 27001, ISO 42001, etc.) already exists. **Do not rebuild it.** Add the engagement layer around it.

**Before coding:**
1. Explore the repo: stack, DB/ORM, auth, API style, frontend, tests, conventions.
2. Locate existing: frameworks, controls, questionnaires/questions, cross-framework mappings, scoring.
3. Write `docs/ENGAGEMENT_LAYER_PLAN.md` listing what you will reuse, what you will add, and any gaps in the existing library that block this spec (for example controls with no questions, or no mapping). Ask me before proceeding if there is a conflict.
4. Follow existing conventions. Ask before adding dependencies.

**Two non-negotiable principles:**
- **Authorization is enforced server-side on every request**, never only in the UI.
- **Nothing is generated without a recorded reason.** Every recommended framework, every applicable control and every generated question must trace back to the scoping answers or rules that caused it.

---

## PART A: ROLE-BASED ACCESS CONTROL

### A1. Layered model

Access is evaluated in four layers. A request must pass all of them.

| Layer | Question it answers | Example |
|---|---|---|
| 1. Authentication | Who are you? | SSO/MFA login |
| 2. Organisation scope | Which org's data? | Principal vs Client X |
| 3. Role permission | What actions does your role allow? | `assessment:score` |
| 4. Resource scope (ABAC) | On which specific records? | Only assigned clients / own department / assigned framework |

Permissions are named `resource:action` (for example `package:assign`). Roles are bundles of permissions. Scope constraints are attached to the **role assignment**, not the role.

### A2. Organisation tiers and role hierarchy

```
PLATFORM TIER
  platform_super_admin        (system operator, no client data by default)
  platform_auditor            (read-only audit logs and config history)

PRINCIPAL TIER (consulting company)
  principal_admin
    principal_engagement_lead      (owns a set of clients)
      principal_assessor           (scores and reviews)
      principal_analyst            (prepares, cannot finalise)
  principal_content_manager        (frameworks, rules, templates)
  principal_report_approver        (signs off reports)

CLIENT TIER (one tenant per client company)
  client_admin                     (client org setup, user management)
  client_contributor               (single accountable point of contact)
    department_lead                (owns a department's tasks)
      department_respondent        (answers and uploads)
  client_exec_viewer               (read-only)
  client_reviewer                  (internal QA before submission, optional)
```

Rules:
- A user belongs to **exactly one organisation tier** (platform, principal, or one client). No user spans a principal and a client.
- A user may hold multiple roles within their own org.
- Hierarchy is for delegation only. **Roles do not inherit permissions implicitly**; each role lists its permissions explicitly.

### A3. Role catalog

| Role | Tier | Purpose | Scope constraint |
|---|---|---|---|
| `platform_super_admin` | Platform | Provision principals, system config, break-glass | No access to client content unless break-glass approved and logged |
| `platform_auditor` | Platform | Read-only audit and config history | Read-only everywhere |
| `principal_admin` | Principal | Manage principal org, clients, users, scoring config | All clients of own principal |
| `principal_engagement_lead` | Principal | Run engagements for assigned clients, approve framework assignment | Assigned clients only |
| `principal_assessor` | Principal | Review responses and evidence, score controls, raise findings | Assigned clients and assigned frameworks |
| `principal_analyst` | Principal | Prepare assessments, draft findings (cannot finalise or score as final) | Assigned clients |
| `principal_content_manager` | Principal | Maintain rules, questionnaires, templates, mappings | Content only, no client data |
| `principal_report_approver` | Principal | Sign off and release reports | Assigned clients; cannot be the scoring assessor |
| `client_admin` | Client | Manage own org users, departments, role assignments | Own client only |
| `client_contributor` | Client | Complete scoping, delegate, review, submit | Own client only |
| `department_lead` | Client | Receive tasks for department, reassign inside department, approve department input | Own department only |
| `department_respondent` | Client | Answer assigned questions, upload evidence | Only tasks assigned to them |
| `client_reviewer` | Client | Quality-check before submission | Own client; no edit of answers |
| `client_exec_viewer` | Client | Read dashboards and final reports | Own client, read-only |

### A4. Permission matrix

Legend: **C** create, **R** read, **U** update, **D** delete, **A** approve/finalise, **S** submit, **X** execute, `-` none. Scope in parentheses: `own` = own org, `asg` = assigned, `dept` = own department, `task` = assigned tasks only.

| Resource / action | principal_admin | engagement_lead | assessor | analyst | content_manager | report_approver | client_admin | contributor | dept_lead | respondent | reviewer | exec_viewer |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Client tenant | C R U D (own) | R U (asg) | R (asg) | R (asg) | - | R (asg) | R U (own) | R (own) | - | - | - | - |
| Users and role assignments | C R U D (principal) | - | - | - | - | - | C R U D (client) | R (own) | R (dept) | - | - | - |
| Departments | - | - | - | - | - | - | C R U D | R | R (dept) | - | - | - |
| Scoping questionnaire (template) | R | R | R | R | C R U A | - | - | - | - | - | - | - |
| Scoping response | R (own) | R (asg) | R (asg) | R (asg) | - | - | R | C R U S | U (task) | U (task) | R | R |
| Applicability rules | R | R | R | R | C R U A | - | - | - | - | - | - | - |
| Framework recommendation | R | R A (asg) | R | R | R | - | - | R (summary) | - | - | - | - |
| Framework assignment | R | C U A (asg) | R | R | - | - | - | R | - | - | - | R |
| Generated question set | R | R A (asg) | R U (asg) | R (asg) | R | - | - | R | R (dept) | R (task) | R | - |
| Assessment package | R | C R U (asg) | R | R | - | - | - | R | R (dept) | R (task) | R | R (summary) |
| Task delegation | - | - | - | - | - | - | R | C R U D | C R U (dept) | R (task) | R | - |
| Response / answer | - | - | R | R | - | - | R | C R U S | C R U S (dept) | C R U (task) | R | - |
| Evidence upload | - | - | R | R | - | - | R | C R U D | C R U D (dept) | C R U (task) | R | - |
| Contributor submission (lock) | - | R | R | R | - | - | - | S | - | - | - | - |
| Control assessment (score) | R | R | C R U (asg) | C R U draft | - | R | - | R (final) | - | - | - | R (final) |
| Findings | R | R A | C R U | C R U draft | - | R | - | R (own) | R (dept) | - | - | R |
| Clarification query | R | R | C R U | C R U | - | - | - | R U (reply) | R U (dept) | - | - | - |
| Report | R | R | R | R draft | - | R A (release) | - | R (released) | - | - | - | R (released) |
| Remediation actions | R | R | R | R | - | - | R | C R U | C R U (dept) | R U (task) | R | R |
| Scoring configuration | C R U A | R | R | R | R | R | - | - | - | - | - | - |
| Audit log | R | R (asg) | - | - | - | - | R (own) | - | - | - | - | - |

Anything not listed is denied (**default deny**).

### A5. Scope and attribute rules (Layer 4)

Role assignments carry scope attributes. Evaluate them on every read and write:

```
RoleAssignment {
  user_id, role, org_id,
  client_ids[]        // principal roles: clients they may act on
  framework_ids[]     // optional: restrict assessors to certain frameworks
  department_ids[]    // client roles: departments they belong to
  valid_from, valid_to
}
```

Policy rules:
1. **Tenant rule:** every client-owned row has `client_id`. A client-tier user's `org_id` must equal it.
2. **Assignment rule:** principal non-admin roles act only on clients in `client_ids` (and frameworks in `framework_ids` if set).
3. **Department rule:** `department_lead` and `department_respondent` see only tasks tagged to their `department_ids`; respondents only tasks assigned to them.
4. **State rule:** actions depend on status. For example, answers are not editable after `submitted_locked`; scoring is not possible before `submitted_locked`.
5. **Time rule:** assignments can expire.

### A6. Separation of duties (hard constraints)

- The user who scores a control cannot approve the report that includes it.
- The same user cannot be both `principal_assessor` and `principal_report_approver` for the same client.
- A `client_contributor` cannot also be the sole approver of their own department's answers (requires `department_lead` or `client_reviewer` when those roles exist for that department).
- A user cannot grant themselves a role or widen their own scope.
- `principal_content_manager` cannot access client responses.
- `platform_super_admin` cannot read client content except via break-glass: time-boxed, reason recorded, principal notified.

### A7. Delegation rules

- Contributor delegates to departments and individuals within own client only.
- Delegation is a **task assignment**, not a role grant. Assignees get access to exactly the assigned tasks.
- Re-delegation is allowed only within the same department unless Contributor performs it.
- Delegations are recorded with delegator, assignee, due date, and are revocable.

### A8. Enforcement requirements

- Central policy engine (for example a single `authorize(user, action, resource)` function or policy library) used by every endpoint, background job and export.
- Middleware injects tenant context; ORM-level default filters scope every query by `client_id`.
- Do not rely on hidden UI. Return **403** (or 404 to avoid existence leaks across tenants) server-side.
- Permissions are data-driven (tables), not scattered `if role ==` checks.
- File downloads use signed, short-lived URLs checked against the same policy.
- Every permission decision on sensitive actions is audit-logged (who, what, resource, allowed/denied, reason).
- MFA mandatory for all principal tier roles and `client_admin`.

### A9. RBAC tests (required)

- Matrix-driven test: for each role x resource x action, assert allow/deny exactly as A4.
- Cross-tenant tests: client A user cannot read, list, update or download anything from client B (including via IDs in URLs, search, exports, reports).
- Scope tests: assessor assigned to client 1 cannot access client 2; respondent cannot see other respondents' tasks.
- SoD tests for each rule in A6.
- Privilege escalation tests: cannot assign roles above own, cannot edit own scope.
- Default-deny test: unlisted action returns denied.

---

## PART B: SCOPING, APPLICABILITY AND QUESTION GENERATION

### B1. Pipeline overview

```
Scoping answers
   -> Client Profile Attributes (normalised facts)
   -> Applicability Rules  -> Applicable Frameworks (with rationale)
   -> Principal review / override  -> Approved Framework Set
   -> Control Applicability (per framework, per client profile)
   -> Question Generation (per applicable control)
   -> De-duplication via cross-framework mapping
   -> Routing (department, owner function) and evidence requirements
   -> Assessment Package (generated, traceable, versioned)
```

Everything is **deterministic and data-driven**: same inputs and same rule version produce the same output.

### B2. Scoping questionnaire design

Each scoping question is a structured record, not free text:

```json
{
  "id": "SCP-AI-001",
  "domain": "ai_usage",
  "text": "Does your organisation develop, deploy or procure AI systems?",
  "answer_type": "multi_select",
  "options": ["develop", "deploy", "procure", "none"],
  "required": true,
  "show_if": null,
  "feeds_attributes": ["ai.role"],
  "help_text": "Include embedded AI in vendor products.",
  "evidence_hint": null
}
```

Rules:
- Answer types: single_select, multi_select, boolean, number, country_list, free_text (free text never drives rules directly; it is mapped to an attribute by the assessor or AI suggestion plus approval).
- Conditional display via `show_if` so clients only see relevant follow-ups.
- Every question declares `feeds_attributes` so it is clear what it determines.
- Questionnaire is versioned; responses store the version.

**Required scoping domains and the attributes they produce:**

| Domain | Example questions | Attributes produced |
|---|---|---|
| Organisation | Legal entity type, sector, size, public/private | `org.sector`, `org.size_band`, `org.type` |
| Jurisdiction | Countries of operation, where customers are, data hosting locations | `geo.operating_countries[]`, `geo.customer_countries[]`, `geo.data_residency[]` |
| Regulatory status | Licensed financial entity? Essential service operator? Regulated by which authority? | `reg.financial_entity`, `reg.essential_service`, `reg.regulators[]` |
| Personal data | Processes personal data? Special category? Volumes? Cross-border transfers? | `data.personal`, `data.special_category`, `data.volume_band`, `data.cross_border` |
| Payment data | Stores/processes/transmits card data? | `data.payment` |
| AI usage | Develop/deploy/procure AI, risk level of use cases, GPAI use, automated decisions, EU market | `ai.role[]`, `ai.risk_level`, `ai.gpai`, `ai.automated_decisions`, `ai.eu_market` |
| ICT and third parties | Cloud use, critical ICT providers, outsourcing, SaaS | `ict.cloud`, `ict.critical_third_parties`, `ict.outsourcing` |
| Certifications and contracts | Current ISO certs, customer-mandated standards | `cert.held[]`, `contract.required_standards[]` |
| Maturity | Security team, GRC tooling, policies in place | `maturity.band` |
| Objective | Why are you engaging us (certification, regulatory, customer demand)? | `goal.type` |

### B3. Client Profile Attributes

After scoping submission, the system normalises answers into a **Client Profile**: a flat set of typed attributes. This profile is the single input to rules.

```json
{
  "client_id": "c_123",
  "questionnaire_version": "scp-2026.1",
  "attributes": {
    "org.sector": "financial_services",
    "geo.customer_countries": ["QA", "DE"],
    "reg.financial_entity": true,
    "data.personal": true,
    "data.cross_border": true,
    "ai.role": ["deploy", "procure"],
    "ai.risk_level": "high",
    "ai.eu_market": true,
    "cert.held": [],
    "goal.type": "certification"
  }
}
```

The Contributor submits answers; the principal can view the derived profile and correct an attribute with a recorded justification.

### B4. Applicability rules (framework level)

Rules are versioned records in the database, editable only by `principal_content_manager` (approved by `principal_admin`).

```json
{
  "rule_id": "APP-DORA-001",
  "version": 3,
  "target_framework_id": "dora",
  "condition": {
    "any": [
      { "attr": "reg.financial_entity", "op": "eq", "value": true },
      { "attr": "ict.provides_to_financial_entities", "op": "eq", "value": true }
    ],
    "all": [
      { "attr": "geo.customer_countries", "op": "contains_any", "value": ["EU"] }
    ]
  },
  "outcome": "required",
  "confidence": "high",
  "rationale": "DORA applies to EU financial entities and their ICT third-party providers.",
  "authority_reference": "Regulation (EU) 2022/2554"
}
```

Outcome types:
- `required`: legally or contractually mandated.
- `recommended`: good fit based on profile.
- `optional`: available but not triggered.
- `not_applicable`: explicitly excluded, with reason.

Seed rules (only create for frameworks that exist in the library; match by framework ID):

| Condition (summary) | Framework | Outcome |
|---|---|---|
| EU financial entity, or ICT provider to one | DORA | required |
| Personal data of Qatar residents | Qatar PDPPL | required |
| `ai.role` includes develop/deploy | ISO 42001 | recommended |
| `ai.role` includes develop/deploy and AI risk is high | NIST AI RMF | recommended |
| `ai.eu_market` and AI use present | EU AI Act | required |
| `goal.type` = certification or contract requires it | ISO 27001 | required |
| `data.personal` true and volume above threshold | Data governance and privacy framework | recommended |
| `contract.required_standards` contains X | X | required |

### B5. Recommendation output (explicit and explainable)

For each client the system produces a **Framework Recommendation Report** shown to the principal and, in summary, to the Contributor:

```
Framework: ISO 42001            Outcome: recommended        Confidence: high
Because:
  - ai.role = [deploy, procure]           (from SCP-AI-001)
  - ai.risk_level = high                  (from SCP-AI-004)
Rule: APP-ISO42001-002 v2
Authority/reason: AI management system best practice for deployers of high-risk AI.
```

Rules for the output:
- Show **every framework in the library** with a status (`required`, `recommended`, `optional`, `not_applicable`) so nothing is silently omitted.
- Show the exact answers and rule versions that led to each status.
- Flag **conflicts and gaps**, for example a client states they are a financial entity but gave no jurisdiction; or an answer conflicts with another answer. These are blockers for finalisation.

### B6. Principal review and approval

- `principal_engagement_lead` (or assessor, per matrix) reviews, can **add, remove or change outcome** of a framework.
- Any override requires a written justification and is audit-logged.
- On approval, a **FrameworkAssignment** is created per framework with: client, framework, outcome basis (rule or override), approver, timestamp, rule versions used.
- The client sees the **approved applicable framework set and why**, in plain language. This is the "clearly defined working framework" the engagement runs on.
- Re-scoping: if the client later changes a scoping answer, the system recomputes, shows a **diff** (frameworks added/removed), and requires principal approval before the package changes.

### B7. Control-level applicability

Not every control in an applicable framework applies to every client. The library's controls need applicability metadata. For each control (extend the existing model if missing):

```json
{
  "control_id": "ISO42001-A.6.2.6",
  "framework_id": "iso42001",
  "unified_control_id": "UCF-AI-DATA-014",
  "applies_if": {
    "all": [
      { "attr": "ai.role", "op": "contains_any", "value": ["develop"] }
    ]
  },
  "depth_tier": "standard",
  "risk_weight": 3,
  "owner_function": ["data_science", "risk"],
  "mandatory": true
}
```

Rules:
- `applies_if` is evaluated against the client profile. Controls that do not apply are marked `not_applicable` **with a recorded reason** (visible to the assessor, not silently dropped).
- `depth_tier` supports proportionality: `basic`, `standard`, `enhanced`. The tier selected for the client comes from attributes such as `org.size_band`, `ai.risk_level`, `maturity.band`, or an explicit principal choice. Higher tiers include all questions from lower tiers.
- `mandatory` controls are always included for a `required` framework regardless of tier.
- `owner_function` drives department routing (B9).

**Gap handling:** if the existing library has controls without `applies_if`, `owner_function` or questions, list them in `docs/ENGAGEMENT_LAYER_PLAN.md` and default them to "applies to all" with a flag for content review. Do not invent compliance content silently.

### B8. Question generation

For each applicable control, generate the compliance questions and evidence requests from templates attached to the control:

```json
{
  "question_id": "Q-ISO42001-A.6.2.6-01",
  "control_id": "ISO42001-A.6.2.6",
  "unified_control_id": "UCF-AI-DATA-014",
  "text": "Is there a documented process for data quality management for AI training data?",
  "answer_type": "maturity_choice",
  "answer_options": ["not_implemented", "partial", "largely", "implemented", "not_applicable"],
  "depth_tier": "standard",
  "evidence_required": [
    { "type": "policy", "description": "Data quality management procedure", "max_age_months": 24 }
  ],
  "owner_function": ["data_science"],
  "conditions": { "attr": "ai.role", "op": "contains_any", "value": ["develop"] }
}
```

Generation algorithm:
1. Take the approved framework set.
2. For each framework, take controls where `applies_if` is true (and mandatory ones for required frameworks).
3. For each control, take question templates whose `depth_tier` is at or below the client's tier and whose own `conditions` pass.
4. Resolve text variables with client context (for example client name, named systems from scoping).
5. **De-duplicate** using `unified_control_id`: if two frameworks map to the same unified control, create **one question** and link it to every framework control it satisfies. Keep the strictest evidence requirement.
6. Attach evidence requests and answer options.
7. Route to department(s) by `owner_function` mapped to the client's departments (B9).
8. Order by framework, domain, then control.

**Traceability record per generated question** (mandatory):

```json
{
  "generated_question_id": "gq_9f2",
  "client_id": "c_123",
  "question_id": "Q-ISO42001-A.6.2.6-01",
  "satisfies": ["ISO42001-A.6.2.6", "NIST-AI-RMF-MAP-2.3"],
  "generated_because": {
    "frameworks": ["iso42001", "nist_ai_rmf"],
    "profile_attributes": ["ai.role=develop"],
    "rule_versions": ["APP-ISO42001-002@2"],
    "depth_tier": "standard",
    "mandatory": true
  },
  "package_version": 1
}
```

**Coverage guarantee:** after generation run a coverage check. For every applicable control in every approved framework there must be at least one generated question (or a recorded reason for exclusion). Report coverage % per framework. Block package release below 100 percent unless the principal records exceptions.

### B9. Routing to departments

- Map `owner_function` values (for example `iam`, `hr`, `legal`, `risk`, `procurement`, `data_science`, `it_ops`, `security`) to the client's departments during client setup (`client_admin`).
- Generated questions are auto-grouped into **work packets per department**, shown to the Contributor as a proposed delegation plan.
- Contributor can accept, reassign, split or merge packets. Unmapped functions are flagged for Contributor to resolve before delegation.

### B10. Package and versioning

- `AssessmentPackage` per client per framework, plus a **unified view** across frameworks.
- Package is versioned. If rules, scoping answers or approved frameworks change, a new version is generated with a **diff** (questions added, removed, changed) and answered questions are carried forward where the underlying control is unchanged.
- Principal approves the package before release to the Contributor (`package:assign`).
- Package records: scoping questionnaire version, rule versions, library content version, depth tier, generation timestamp.

### B11. Optional AI assistance (feature-flagged, last)

- Suggest attribute values from free-text scoping answers: assessor must confirm.
- Suggest likely framework gaps in rules or flag inconsistent answers.
- AI never changes framework assignment or question sets without human approval. Label AI output clearly and log prompts/outputs.

---

## PART C: DATA MODEL ADDITIONS

Reuse existing Framework, Control, Mapping entities. Add or extend:

- `Principal`, `Client`, `Department`, `User`
- `Role`, `Permission`, `RolePermission`, `RoleAssignment` (with scope attributes), `PolicyDecisionLog`
- `ScopingQuestionnaire` (versioned), `ScopingQuestion`, `ScopingResponse`
- `ClientProfile`, `ClientProfileAttribute` (with source and override justification)
- `ApplicabilityRule` (versioned), `FrameworkRecommendation`, `FrameworkAssignment`
- `ControlApplicability` (extension to Control: `applies_if`, `depth_tier`, `owner_function`, `mandatory`)
- `QuestionTemplate`, `GeneratedQuestion` (with traceability fields), `CoverageReport`
- `AssessmentPackage` (versioned), `PackageDiff`, `WorkPacket`, `Task`
- `Response`, `Evidence`, `ControlAssessment`, `Finding`, `RemediationAction`, `Report`, `AuditEvent`

All client-owned tables include `client_id` and default query scoping.

---

## PART D: WORKFLOW STATES

```
Client:        invited -> onboarded -> scoping -> frameworks_pending_approval -> active -> archived
Scoping:       not_started -> in_progress -> submitted -> profile_confirmed
Frameworks:    recommended -> under_review -> approved
Package:       generated -> principal_approved -> released -> in_fulfilment -> submitted_locked -> in_assessment -> assessed -> reported
Task:          assigned -> in_progress -> submitted_by_dept -> returned | approved_by_contributor
Report:        draft -> assessor_complete -> approver_signed_off -> released
```

State transitions are guarded by role permissions (Part A) and logged.

---

## PART E: ASSESSMENT, SCORING AND REPORTING (unchanged intent, summarised)

- Completeness and evidence checks, then control rating: compliant 100, largely compliant 75, partially compliant 50, non-compliant 0, not applicable excluded.
- Weighted roll-up control -> domain -> framework %. Readiness bands: <40 Initial, 40-69 Developing, 70-89 Established, 90+ Certification Ready. Gating controls cap the band.
- One assessed unified control updates every mapped framework.
- Scoring configuration versioned and recorded on each report.
- Reports: per-framework and consolidated per client; principal portfolio dashboard; remediation tracking and reassessment.
- Report shows **which framework applied and why** (from B5/B6) so scores are read in context.

---

## PART F: DELIVERY PHASES

Stop for review after each phase. Each ships with migrations and tests.

1. **RBAC foundation:** tenancy, role/permission tables, role assignments with scope, policy engine, audit log, SoD constraints, full RBAC test matrix (A9).
2. **Client onboarding:** client tenants, departments, Contributor invitation, user management by `client_admin`.
3. **Scoping:** structured scoping questionnaire, conditional logic, profile attribute derivation, profile review.
4. **Applicability engine:** rules store and editor, recommendation report with rationale, conflict detection, principal review and approval, assignment records.
5. **Control applicability and question generation:** control metadata extension, generation algorithm, de-duplication, traceability records, coverage check, department routing and work packets, package versioning and diffs.
6. **Fulfilment workspace:** delegation, respondent task view, evidence upload, progress dashboards.
7. **Assessment engine and findings.**
8. **Reporting and remediation.**
9. **AI assist and hardening.**

---

## PART G: ACCEPTANCE CRITERIA

**RBAC**
- Role x resource x action matrix test passes exactly as Section A4; unlisted actions are denied.
- No cross-tenant read, write, search, export or file download is possible.
- Every SoD rule in A6 is enforced and tested.
- No user can grant themselves or widen their own role or scope.

**Applicability**
- Every framework in the library appears in the recommendation report with a status and a rationale.
- Each `required` or `recommended` framework cites the rule version and the specific scoping answers behind it.
- Overrides require justification and are audit-logged.
- Changing a scoping answer produces a visible diff and does not alter the released package until approved.

**Question generation**
- Every generated question has a traceability record (framework, control, attributes, rule versions, tier).
- A control marked not applicable has a recorded reason.
- Coverage is 100 percent of applicable controls per approved framework, or exceptions are recorded.
- Shared unified controls produce a single question mapped to all relevant frameworks.
- Same inputs and rule versions always produce the same question set (deterministic).
- Questions are routed to departments, and unmapped functions block delegation until resolved.

---

## PART H: CONSTRAINTS AND WORKING AGREEMENTS

- Reuse the existing library. Extend models, do not duplicate them.
- Rules, weights, tiers, bands and questionnaires are data/config, versioned, never hard-coded.
- No compliance content is invented silently. If control metadata is missing, flag it and ask.
- Small reviewable commits with migrations and tests. Follow existing conventions.
- Ask before adding dependencies, changing the stack, or when a requirement conflicts with the code.

## PART I: OPEN QUESTIONS (confirm before Phase 1)

1. Is there already an auth system and user table to extend, or must RBAC be introduced from scratch?
2. Do existing controls already carry any applicability, owner or tier metadata?
3. Does the cross-framework mapping already provide a `unified_control_id` equivalent?
4. Can clients self-select any framework, or is it always principal-controlled?
5. Which frameworks beyond the current library are needed next, and which regulators matter most (Qatar, EU, other GCC)?
6. Is white-labelling of the client portal required?
