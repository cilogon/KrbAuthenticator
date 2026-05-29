---
title: "feat: KrbAuthenticator REST API V1"
type: feat
status: active
date: 2026-05-28
deepened: 2026-05-28
origin: docs/brainstorms/2026-05-28-krbauthenticator-rest-api-requirements.md
---

# feat: KrbAuthenticator REST API V1

## Summary

Add a working REST API surface to the `KrbAuthenticator` plugin so a privileged Registry API user can set and change a CoPerson's Kerberos principal password via REST, with the password actually committed in the KDC. V1 ships GET (index/view, metadata only), POST (set), PUT (change), and DELETE → 405 — mirroring `PasswordAuthenticator`'s shape but routing POST/PUT through `KrbAuthenticator::manage()` so the KDC is touched on every write.

## Problem Frame

A tester at access-ci.org is building a custom UI against the Registry data model and reported that `GET /registry/krb_authenticator/krbs.json?copersonid=104269` returns `404 CO Not Found`. The plugin already declares `Router::mapResources('KrbAuthenticator.krbs')` and `KrbsController` extends `SAMController`, but the inherited REST `add/edit` path goes directly to `Krb::saveAll()` — it never calls `KrbAuthenticator::manage()`, which is the only entry point that talks to the KDC. A plain inherited REST `POST` would write a `Krb` linkage row and silently leave the KDC unchanged — a contract violation. `KrbAuthenticator` needs an explicit REST branch that routes writes through `manage()`, plus an actor==target guard, sanitized errors, layered rate limiting, and a HistoryRecord trail that survives KDC-success/Registry-fail divergence.

## Requirements

### Endpoint surface

- **R1.** `GET /registry/krb_authenticator/krbs.json?krbauthid=N` returns a list of `Krb` rows scoped to that KrbAuthenticator instance, metadata-only. (see origin: `docs/brainstorms/2026-05-28-krbauthenticator-rest-api-requirements.md`)
- **R2.** `GET /registry/krb_authenticator/krbs.json?krbauthid=N&copersonid=M` returns the `Krb` row for that CO Person under that KrbAuthenticator instance, or an empty list.
- **R3.** `GET /registry/krb_authenticator/krbs/{id}.json` returns one `Krb` row's metadata (`id`, `co_person_id`, `krb_authenticator_id`, `created`, `modified`). No password material is ever returned.
- **R4.** `POST /registry/krb_authenticator/krbs.json` sets the Kerberos password for the given `(krb_authenticator_id, co_person_id)`, touching the KDC. Returns `201 Created` on success. Returns `409 Conflict` with a `Location` header pointing at the existing resource if a `Krb` row already exists for the pair (caller should `PUT` instead).
- **R5.** `PUT /registry/krb_authenticator/krbs/{id}.json` changes the Kerberos password for an existing `Krb` record, touching the KDC. Returns `200 OK` on success and `404 Not Found` if the row does not exist.
- **R6.** `DELETE /registry/krb_authenticator/krbs/{id}.json` returns `405 Method Not Allowed` with an `Allow: GET, POST, PUT` header. No DB or KDC change. The UI delete path (non-restful) is unaffected.

### Validation, permissions, and guards

- **R7.** POST/PUT payloads must include both `password` and `password2` where `password2 == password`. Enforced server-side; mismatch returns `422`.
- **R8.** Password length is bounded by the KrbAuthenticator instance's configured `min_length` / `max_length` (defaults 8 / 64); failures return `422` with a sanitized message before any KDC call.
- **R9.** REST mode is restricted to `cmadmin` or `coadmin` for the CO that owns the KrbAuthenticator instance — the existing `SAMController::calculateParentPermissions` default. Other roles receive `403`.
- **R9a.** The controller MUST resolve the owning CO of the target `KrbAuthenticator` instance from its persisted record and verify that the API user holds `cmadmin` (any CO) or `coadmin` for *that* CO. The CO derived from `parseCOID` or query parameters MUST be cross-checked against the KrbAuthenticator instance's owning CO; a mismatch returns `403`, not a CO-resolution error. (Defense against a coadmin of CO X reaching a CO Y resource via crafted `coid=X`.)
- **R10.** The controller MUST reject the request with `403` if the API user has any `cmadmin` or `coadmin` role bound to a CoPerson whose `co_person_id` equals the target. The check MUST evaluate against role records (`cm_co_person_roles`), not only against `Auth->User('co_person_id')`. If the API user has no CoPerson record at all, the guard is documented as inert — the substantive protection in that case is R9/R9a plus R16/R17/R17a.
- **R11.** The `passwordc` (current-password) check that `manage()` enforces when actor == CoPerson does NOT apply on the REST path — the REST caller is an API user, never the CoPerson themselves.

### KDC interaction and idempotency

- **R12.** POST and PUT route through `KrbAuthenticator::manage()` so the principal's password is actually set in the configured KDC.
- **R12a.** Principal name resolution MUST happen server-side from the persisted `(KrbAuthenticator instance, CoPerson)` pair only. The controller MUST re-load the `Krb` row (PUT) or the `(KrbAuthenticator instance, CoPerson)` identifiers (POST) from the database and ignore any principal-bearing fields supplied in the request body. For PUT, the loaded row's `co_person_id` and `krb_authenticator_id` are authoritative; any payload override is a 422, not a silent backfill. (Defense against payload-driven principal hijack.)
- **R13.** On POST success, both the KDC commit AND a `Krb` linkage row insert must occur. The GET index must list the row after a successful POST.
- **R14.** KDC failures (KDC unreachable, principal missing, KDC-policy rejection) return an appropriate 4xx/5xx with a sanitized message that does not echo the supplied password or any principal-bearing exception text. No `Krb` row is written or modified on KDC failure.
- **R14a.** The REST response body for any 4xx/5xx MUST contain only `_txt()`-keyed strings defined in `Lib/lang.php`. The controller MUST NOT include `$e->getMessage()`, an exception trace, the principal name, the KDC hostname, the realm, or any fragment of the supplied password or `password2` in the response body or in any dynamically-constructed response header. Fixed-value headers (`Allow: GET, POST, PUT` on 405; `Location: /registry/krb_authenticator/krbs/{id}.json` constructed from an opaque DB ID on 201/409) are exempt — their values are not derived from exception state, principal identity, or request payload. The response body MUST NOT include `$model->validationErrors`, `$model->invalidFields()`, or any per-field error structure composed from request payload values. (Hardens R14 as a testable invariant, not only a KTD aspiration.)
- **R14b.** The `comment` field of any HistoryRecord written by the REST path MUST contain only `_txt()`-keyed strings and opaque numeric IDs. Password material, principal names, KDC hostnames, realm strings, and exception message fragments are prohibited. Tested by querying `SELECT comment FROM cm_history_records WHERE action IN ('pKKI','pKKS','pKKF','pKKD')` after each test scenario and verifying no row contains the supplied password value or any substring of the KDC exception text. (Promotes a System-Wide Impact constraint to a testable requirement because `cm_history_records.comment` persists indefinitely, appears in backup snapshots, and is readable by any account with `SELECT` on the table — a larger blast radius than a transient response body leak.)
- **R15.** On KDC-success-then-Registry-fail (KDC `changePassword` succeeded but a subsequent Registry-side write fails), the KDC change is not rolled back. The same `(krb_authenticator_id, co_person_id, password)` POST/PUT replayed by the caller is accepted and produces the same end state. A distinct HistoryRecord marker is written when divergence is detected.

### Rate limiting

- **R16.** POST/PUT enforce a per-API-credential rate limit (default 5 requests/minute, configurable per KrbAuthenticator instance).
- **R17.** POST/PUT enforce a per-target rate limit keyed on `(krb_authenticator_id, co_person_id)` (default 2 requests/hour, configurable per KrbAuthenticator instance).
- **R17a.** POST/PUT enforce a per-KrbAuthenticator-instance global rate limit across all credentials and targets (default 20 requests/hour, configurable per instance). This bounds the blast radius if a single API credential is compromised or several credentials are colluding to bypass the per-credential limit. Breach returns `429` with `Retry-After`.
- **R18.** Breach of any of the three limits returns `429 Too Many Requests` with a `Retry-After` header naming the seconds until the relevant window expires.

### Audit (HistoryRecord)

- **R19.** Every REST POST and PUT writes a HistoryRecord attributed to the calling API user via `actor_api_user_id`. The recorded action is one of: `pKKI` (intent marker written before the KDC call), `pKKS` (KDC-change succeeded), `pKKF` (KDC-change failed), or `pKKD` (KDC-success/Registry-fail divergence detected).
- **R20.** A `pre-KDC` intent HistoryRecord is written immediately before the KDC call so the audit trail is never empty when divergence occurs; the post-KDC record updates intent → outcome.

### Documentation deliverable

- **R21.** Plugin documentation (README section) states the working URL patterns (`?krbauthid=N` and `?krbauthid=N&copersonid=M`), the 405-on-DELETE behavior, the security assumptions (TLS enforced at deploy, request bodies not logged), and the rate-limit defaults. The tester's originally-reported failing URL is named and the working alternative is shown.

---

## Key Technical Decisions

- **KTD-1: POST/PUT route through `KrbAuthenticator::manage()` rather than reusing the inherited StandardController path.** Rationale: the inherited path calls `Krb->saveAll()` directly and never touches the KDC. `manage()` is the only entry point that talks to the configured KDC. Adding an explicit REST branch in the controller — `is('restful')` checks paralleling `PasswordsController::generate()` / `ssr()` — is consistent with how PasswordAuthenticator handles its `manage()`-style flows.
- **KTD-2: Re-signature `KrbAuthenticator::manage()` to `manage($data, $actorCoPersonId, $actorApiUserId = null, $initialPasswordEvent = false)`.** Rationale: matches `PasswordAuthenticator::manage()`'s parameter order so anyone reading both plugins side-by-side sees the same shape, and so the Deferred-Work shared-base extraction does not have to bridge two divergent signatures. Search confirms zero callers pass a non-default third arg today: `KrbsController::ssr` at `Plugin/KrbAuthenticator/Controller/KrbsController.php:200` and `SAMController::manage` at upstream `app/Controller/SAMController.php:603-604` both pass exactly two args. The new third-slot `$actorApiUserId` defaults to `null` and is read by `Password::manage()`'s caller pattern at `app/AvailablePlugin/PasswordAuthenticator/Model/Password.php:102` (the canonical 3-arg call site). *Rejected: append `$actorApiUserId` to slot 4, keep `$initialPasswordEvent` in slot 3.* Strictly non-breaking even for hypothetical out-of-tree positional callers and would avoid the U1 mechanical signature change. Rejected because (a) the property being preserved is parameter-order alignment with the sibling plugin, not abstract backward compatibility against callers that do not exist; (b) once divergent, the two `manage()` signatures will drift further on every future change; and (c) the shared-base extraction listed under Deferred Work is materially harder if the two signatures disagree on what slot 3 means.
- **KTD-3: Fix the 11-arg `HistoryRecord->record` calls at `Model/KrbAuthenticator.php:411-420` and `:535-545` as part of this PR, not deferred.** Rationale: `HistoryRecord->record` takes 10 args; the two existing call sites pass 11 (one extra trailing `null`). PHP silently discards the extra, which is harmless today because no current code path passes a non-`null` `$actorApiUserId` to either `manage()` or `reset()` — the bug is latent rather than actively dropping data. But once U1 threads `$actorApiUserId` through `manage()` (KTD-2), the 11th-position `null` will silently shadow the new attribution unless the arg count is corrected first. This is a one-line correction at each site and is a precondition for U3/U4's REST attribution to work.
- **KTD-4: POST creates a `Krb` linkage row in addition to calling `manage()`.** Rationale: research found nothing currently writes `Krb` rows — neither the UI manage flow nor any test fixture. A POST that only touches the KDC would leave GET-index permanently empty, defeating R1/R2. The row insert runs after `manage()` succeeds; the controller wraps both in a single transaction.
- **KTD-5: New plugin-local ActionEnum codes `pKKI`/`pKKS`/`pKKF`/`pKKD` defined in a new `Lib/enum.php`.** Rationale: `app/Lib/enum.php:31` documents the `p`-prefix convention for plugin-defined actions, and PasswordAuthenticator already ships its own `Lib/enum.php`. Four distinct constants — intent (`pKKI`), success (`pKKS`), failure (`pKKF`), divergence (`pKKD`) — give the audit log queryable categories without a downstream consumer having to parse the free-text comment column. *Rejected: hybrid (reuse `AuthenticatorEdited` for success and failure, new code only for divergence).* Cheapest to define but breaks the audit-query invariant in a non-obvious way: a routine `WHERE action = 'AuthenticatorEdited'` query mixes REST-attributed and UI-attributed rows while only divergence is distinguishable, so every query consumer has to special-case the rare arm. *Rejected: pure reuse with marker change-strings only.* Forces every audit-log query to substring-match the `comment` column to distinguish KDC-touching events from Registry-only events, pushing parsing logic into every consumer. Plugin-local file means no upstream PR coupling; collision risk against other plugins' `p`-prefix codes is captured in Risks.
- **KTD-6: HistoryRecord intent-then-outcome pattern around the KDC call.** Rationale: the KDC `changePassword` call is irreversible from Registry's perspective — once it commits, the only "undo" is another `changePassword` to a different value, which itself can fail. The observable property V1 must preserve is: *for every POST/PUT that reaches the KDC, the audit log contains a durable record attributable to a specific API user, written before the irreversible commit, that survives any subsequent failure of the controller, the DB connection, or the worker process.* The intent record (pKKI) written immediately before the KDC call and the outcome record (pKKS / pKKF / pKKD) written immediately after preserve this property. *Rejected: PasswordAuthenticator's after-the-fact pattern (one record after the credential write).* Appropriate for PasswordAuthenticator because its credential write is a hash insert in Registry's own DB — same transaction as the HistoryRecord write, atomically succeeding or failing together. Inappropriate for KrbAuthenticator because KDC commit and Registry write are in two different systems with no two-phase commit between them; an after-the-fact single record can be lost when the KDC succeeds and the Registry write (including the record itself) fails, leaving an undetectable credential change. *Rejected: write-ahead-log with reconciliation worker.* Doubles the moving parts (queue table, worker, retry-budget tunables) for a V1 surface without automated tests; the worker's "re-attempt" arm cannot safely re-run a KDC `changePassword` without the original cleartext, which V1 declines to persist. *Rejected: no audit on failure (write outcome record only on success).* Loses the property that every reachable-the-KDC attempt is auditable — a compromised API credential exercising failed POSTs across many CoPersons would leave no trail. *Rejected: synchronous double-write inside `manage()`.* Moves both writes inside `manage()` rather than splitting between controller (intent) and `manage()`-caller (outcome). Rejected because UI flow callers do not need REST-attributable intent records and would have to either no-op or accept an extra arg. Reconciliation tooling (a future deliverable, not V1) identifies dangling pKKI records as candidates for human investigation against KDC logs.
- **KTD-7: Rate limiting via a new plugin-local DB table `cm_krb_rate_limit_counters` using a `save → catch PDOException with SQLSTATE filter → updateAll(column-relative) → find` pattern.** Rationale: the counter must be correct under multi-worker Apache, survive worker restart, be ownable end-to-end by the plugin without deployment-topology change, AND be DB-flavor portable across MySQL and Postgres (both shipped in Registry's container per `container/registry/base/Dockerfile:42`). The closest in-tree precedent is `app/Model/Lock.php:102-134`, which uses save-then-catch-`PDOException`-then-find — but its polarity is fail-closed (lock acquisition failure rethrows). The rate-limiter inverts the polarity to grant access on collision-recovery, so the controller path is genuinely new code that adapts the Lock pattern rather than directly mirroring it; this KTD documents that adaptation rather than claiming a direct precedent. The atomic-increment idiom — `updateAll(array('Model.count' => 'Model.count + 1'), $conditions)` — uses Cake 2's column-relative update syntax (DboSource at `lib/Cake/Model/Datasource/DboSource.php:2217` emits `quoted_field = value` and treats the value as a SQL snippet when conditions are non-empty) that translates correctly to both MySQL and Postgres without flavor-specific SQL. The `PDOException` catch is SQLSTATE-filtered to `23000`/`23505` (integrity constraint violations); other SQLSTATE codes (deadlock `40001`, lock-wait-timeout `HY000`, connection reset) rethrow and fail-closed so transient DB errors during a burst cannot silently bypass the limiter. Window arithmetic is done in PHP; storage is `(scope, key, window_start_epoch, count)` with a unique compound index on `(scope, key, window_start_epoch)` patterned after `cm_locks` index `locks_i1`. Three scopes are tracked: `per_credential` (key = `api_user_id`), `per_target` (key = `{krb_authenticator_id}:{co_person_id}`), and `per_instance` (key = `krb_authenticator_id`, supporting R17a). *Rejected: CakePHP 2 File cache.* Per-worker storage under multi-worker Apache means each worker maintains its own counter and the effective limit becomes `limit × worker_count`. Disqualified on correctness. *Rejected: add a new `Cache::config` block (Memcached, Redis) from the plugin's `Config/bootstrap.php`.* Commits the deployment to running an infrastructure component the plugin cannot itself provision; makes correctness depend on cross-plugin bootstrap load order; silently overrides any application-level `Cache::config` with the same name (action at a distance). Switching to Redis is a Deferred follow-on an operator opts into via deployment config, not a plugin install side-effect. *Rejected: raw atomic-upsert SQL (`INSERT ... ON DUPLICATE KEY UPDATE` for MySQL, `INSERT ... ON CONFLICT ... DO UPDATE` for Postgres) selected at runtime from the datasource flavor.* The earlier draft of this KTD; rejected because (a) no in-tree precedent — `grep` across `app/` returns zero matches for either form; (b) the Lock pattern is the canonical in-tree solution to the same problem and is already understood by Registry maintainers; (c) flavor-detection branches in plugin SQL invite drift when a third backend is introduced. *Rejected: token-bucket counter.* The brainstorm contract is fixed-window ("5/minute, 2/hour"); a token-bucket approximates that with two tunables where the contract asks for one, and its failure modes interact with clock skew across workers in ways fixed-window does not. Revisit if tuning needs require smoothing.
- **KTD-8: 422 and 429 status codes via raw integer literal to `ApiComponent::restResultHeader($code, $text)`.** Rationale: `HttpStatusCodesEnum` is missing both. `restResultHeader` registers the code dynamically via `httpCodes()` before setting status, so the integer-literal path works without an upstream PR. Upstream enum extension is a follow-on, not V1.
- **KTD-9: JSON view templates copied into `View/Krbs/json/` rather than symlinked, generated, or referenced by absolute path.** Rationale: the plugin is its own git repo separate from upstream `comanage-registry`. The chosen path keeps the plugin self-contained, makes its behavior reproducible in environments that fetch only the plugin tarball, and leaves a seam for V1 to ship sanitized error envelopes without an upstream PR. *Rejected: symlink across repos.* Either broken on plugin-only deploys or requires a sibling-layout convention the plugin cannot enforce. *Rejected: generate views from a template at deploy time.* Introduces a runtime dependency on upstream view paths that the plugin's manifest does not declare; plugins should not write into their own `View/` tree at runtime (file-permission and atomicity hazards). *Rejected: absolute-path view config (`App::build(array('View' => ...))`) pointing at upstream's Standard view directory.* Mutates global view-search state from `Config/bootstrap.php` for an effect that should be local; commits the plugin to whatever upstream's view contract happens to be at any given Registry version, removing the seam mentioned above. Cost of the chosen path: five short view files of duplication that are functionally identical to upstream; an upstream refactor consolidating the JSON views into a shared partial would eliminate the duplication and is not foreclosed.
- **KTD-10: "Idempotent retry" in R15 means natural idempotency, not Idempotency-Key infrastructure.** Rationale: the brainstorm's contract is that the same `(krb_authenticator_id, co_person_id, password)` replayed produces the same KDC end state. Writing the same password to the KDC twice produces an idempotent observable outcome; no per-request key store or replay-detection table is needed. *Failure modes natural idempotency DOES cover:* caller receives 5xx after KDC commit and re-sends identical request (second commit is no-op observable); network mid-flight cases (same); Registry-side write failure followed by replay after operator restores DB-side capability (second attempt completes Registry write while KDC is already correct). *Failure modes natural idempotency does NOT cover:* (a) **replay with a different password** — caller, believing the call failed after a divergence, retries with `POST(password=B)` when the previous attempt was `POST(password=A)`; KDC ends at B with no Registry row referencing A; HistoryRecord shows two pKKI then one pKKD then one pKKS, sufficient for forensic reconstruction but not for automatic reconciliation; (b) **two distinct concurrent requests for the same target** — both pass existence checks, both write pKKI, KDC sees two `changePassword` calls in race-order, one Registry row insert succeeds and the other fails on the unique constraint; KDC final state is determined by KDC-side serialization; bounded but not eliminated by the per-target rate limit within one window; (c) **caller retry after operator manually rolled back the KDC** — natural idempotency cannot distinguish "caller retry" from "caller second wish." V1 accepts these because (a) requires a malformed-client retry contract; (b) is observable in the HistoryRecord trail and bounded by R17/R17a; (c) is an operator-vs-caller race no idempotency layer resolves. A hardening gate (see OQ7) revisits Idempotency-Key infrastructure if operational data shows any of these failure modes in practice.
- **KTD-11: Error sanitization at the controller layer, not inside `manage()`.** Rationale: `manage()`'s exception messages contain principal-bearing strings useful for server-side logging (e.g., `Plugin/KrbAuthenticator/Model/KrbAuthenticator.php:399-404` wraps the KDC exception with the principal name). The REST controller catches the exception, logs the raw text via `$this->log()` for ops, and returns a fixed sanitized `_txt()` key in the response per R14a. This avoids weakening `manage()`'s internal error reporting for UI callers. Outer try/finally also clears `$this->request->data['Krb']['password']` and `password2` before any exception can propagate to Cake 2's default error logger, preventing the case where an uncaught fatal serializes the request body into the error log.
- **KTD-12: Transaction shape is intent-autocommit / KDC-uncommitted / outcome-transactional.** Rationale: the irreversibility of the KDC commit, plus the R20 invariant that the intent record always survives, forces a non-PasswordAuthenticator transaction shape. (a) The intent HistoryRecord (pKKI) is written in autocommit mode, before any transaction boundary, so it is durable even if the worker crashes mid-KDC-call. The controller MUST assert that no transaction is open on `$this->KrbAuthenticator->getDataSource()` at the pKKI write site (Cake 2's `_transactionStarted` flag); if a parent `beforeFilter`, behavior, or wrapper has opened one, the controller fails closed with a 500 rather than enrolling the intent record in a transaction that may roll back. (b) The KDC `changePassword` runs with no DB transaction open, so a slow KDC round-trip does not hold a DB connection or row locks. (c) After the KDC call returns, `_begin()` opens a transaction wrapping the `Krb` row insert (POST only) and the outcome HistoryRecord write (pKKS); `_commit()` on success. (d) On `_rollback()` of that transaction (divergence), the pKKD outcome record is written on the same DataSource — which is now no longer in a transaction and so reverts to autocommit — so the divergence is recorded even when the wrapping transaction failed. (No second `ConnectionManager::create()` is needed; "fresh autocommit connection" earlier wording is replaced with this clarification.) PasswordAuthenticator's `_begin/_commit/_rollback` pattern (referenced at upstream `app/AvailablePlugin/PasswordAuthenticator/Model/PasswordAuthenticator.php:213, 235, 240, 305-308, 325`) is not adopted because a transaction spanning the KDC call cannot honor the KDC's irreversibility. *Risk if misread:* a maintainer who reads KTD-6 alone may "wrap the whole thing in a transaction" and accidentally hold a connection across the KDC round-trip, breaking R20. This KTD is the authoritative shape. *Changelog behavior interaction* (see OQ8): `Krb` `actsAs Changelog` opens its own transaction inside `beforeSave/afterSave`. When the controller's `_begin()` is already open, Cake 2 uses SAVEPOINTs for the nested behavior transaction; the controller MUST detect ChangelogBehavior-driven `$dataSource->rollback()` calls (which would roll back the controller's outer transaction wholesale) and route into the pKKD branch on detection.

---

## High-Level Technical Design

The POST flow shows the ordering constraints that make divergence recoverable. The PUT flow is identical except for the precondition check (Krb row must exist) and no row-insert step.

```mermaid
sequenceDiagram
    autonumber
    participant C as API Client
    participant Ctl as KrbsController
    participant RL as KrbRateLimiter
    participant M as KrbAuthenticator::manage()
    participant K as KDC
    participant DB as Registry DB
    participant H as HistoryRecord

    C->>Ctl: POST /krbs.json {password, password2, krb_authenticator_id, co_person_id}
    Ctl->>Ctl: AppController auth: ApiUser HTTP basic, CO resolution
    Ctl->>Ctl: calculateParentPermissions (cmadmin || coadmin)
    Ctl->>Ctl: actor==target guard (403 if matches)
    Ctl->>Ctl: length validation (422 on failure, no KDC call)
    Ctl->>RL: check & increment per-credential, per-target, and per-instance
    alt rate limit exceeded
        RL-->>Ctl: limit breached
        Ctl-->>C: 429 + Retry-After
    end
    Ctl->>DB: existing Krb row? (409 if yes for POST; 404 if no for PUT)
    Ctl->>H: write intent record (pre-KDC marker)
    Ctl->>M: manage(data, null, actorApiUserId)
    M->>K: changePassword (irreversible)
    alt KDC failure
        K-->>M: exception
        M-->>Ctl: throw
        Ctl->>H: write pKKF outcome record
        Ctl-->>C: 4xx/5xx sanitized
    else KDC success
        K-->>M: ok
        M-->>Ctl: ok
        Ctl->>DB: insert Krb linkage row (POST only)
        alt Registry write succeeds
            Ctl->>H: write pKKS outcome record
            Ctl-->>C: 201 (POST) / 200 (PUT)
        else Registry write fails (divergence)
            Ctl->>H: write pKKD outcome record
            Ctl-->>C: 5xx sanitized; KDC NOT rolled back
        end
    end
```

The audit log invariant is: every POST/PUT produces at least one HistoryRecord (the intent record); the outcome record (pKKS, pKKF, or pKKD) is written whenever the controller can still write to the DB. If the controller crashes between the KDC commit and the outcome record, the intent record stays in the log as a dangling marker — reconciliation tooling identifies these and they correspond exactly to the divergence cases R15 commits to.

---

## Scope Boundaries

In scope for V1:

- The seven endpoints described in R1-R6 (GET index/view + POST + PUT + DELETE → 405) under the `?krbauthid=N[&copersonid=M]` URL pattern.
- The actor==target guard, sanitized errors, two-layer rate limiting, intent+outcome HistoryRecord pattern, and natural-idempotency retry contract.
- A precursor that adds `$actorApiUserId` to `KrbAuthenticator::manage()` and fixes the 11-arg `HistoryRecord->record` bug at two sites.
- A README section documenting the working URL patterns, expected error responses, and security assumptions.

### Deferred to Follow-Up Work

- **`issue-reset-token` REST endpoint.** Authenticated REST call that triggers `KrbResetToken::generateRequest()` server-side without exposing the token to the caller. V1 design must not foreclose this — see KTD-1's controller shape, which leaves room for a sibling action.
- **REST credential-removal endpoint.** Because V1 rejects DELETE, deprovisioning continues through the Registry UI. A future endpoint will need to decide between deleting the KDC principal, expiring it, or removing only the Registry linkage row.
- **Upstream PR to add `422` and `429` to `HttpStatusCodesEnum`.** V1 uses integer literals; the enum extension lands separately.
- **Switching the rate-limit backend to Redis.** A correctness-equivalent option that becomes attractive if the DB-counter table proves a hot spot. Operator-opt-in via deployment config, not a plugin install side-effect.
- **PasswordAuthenticator / KrbAuthenticator REST shared base class.** Extracting common REST-branch boilerplate is a refactor not justified by two callers.
- **Idempotency-Key header and replay-detection store.** Natural idempotency (KTD-10) covers the contract; explicit key infrastructure is a hardening pass gated on OQ7's operational signal.
- **Test harness setup.** The plugin and its PasswordAuthenticator sibling have no existing tests today; introducing CakePHP 2 PHPUnit harness for V1 is out of scope. Test scenarios in this plan are functional/manual-verification specs.
- **Counter-table garbage collection task.** A periodic shell command (Cake 2 shell or cron-driven script) that deletes rows from `cm_krb_rate_limit_counters` where `window_start_epoch < (now - max_window)`. Reduces growth from unbounded-over-years to bounded by max-window × active-key cardinality. **Required before sustained production load** — create a follow-on plan unit (U8 standalone) at the time V1 merges, gated on a concrete trigger: row count > 1M in `cm_krb_rate_limit_counters`, or row age > 24h × max-configured-window-multiplier, or `updateAll` latency on the per-credential window > 50ms p99. Operators monitoring DB size should add the table to their watch list at V1 deploy time; if the trigger fires before U8 lands, fall back to a manual cleanup query.
- **Per-CO rate-limit tunables.** Per-instance tunability suffices for V1; per-CO would require a different table layout. Gated on OQ6's answer.
- **`KrbAuthenticator::manage()` distinguishing principal-not-found-in-KDC as 404 not 500.** U3/U4 currently map `RuntimeException` coarsely to 500; the principal-missing case at `Plugin/KrbAuthenticator/Model/KrbAuthenticator.php:341` is arguably a 404. Refinement deferred — coarse mapping is fine for V1.
- **`Krb.modified` timestamp coarsening.** Reduces precision in REST responses to mitigate the timing-attack side channel named in Residual Risks.

Outside this product's identity:

- Modifying `SAMController::index()` REST branch or `StandardController` write helpers in upstream Registry. The plugin works around their constraints rather than changing them.
- Changing the Registry UI flows for `manage`, `ssr`, or `remind`. They remain unchanged in behavior.

---

## Implementation Units

### U1. Precursor: actorApiUserId plumbing and HistoryRecord arg fix

**Goal:** Make `KrbAuthenticator::manage()` accept and propagate an API-user attribution, and fix the silently-broken `HistoryRecord->record` calls at two existing sites so attribution actually persists. Also introduce the plugin-local `ActionEnum` constants that U3-U6 will reference.

**Requirements:** R19, R20 (enables attribution and intent/outcome write patterns).

**Dependencies:** none.

**Files:**

- `Plugin/KrbAuthenticator/Lib/enum.php` (new — adds `KrbAuthenticatorActionEnum` with `KrbKdcChangeSucceeded = 'pKKS'`, `KrbKdcChangeFailed = 'pKKF'`, `KrbKdcRegistryDivergence = 'pKKD'`, `KrbKdcChangeIntent = 'pKKI'`)
- `Plugin/KrbAuthenticator/Model/KrbAuthenticator.php` (modify — re-signature `manage()` lines around `:270`; fix 11-arg `HistoryRecord->record` call at `:411-420` and `:535-545`; thread `$actorApiUserId` into both calls)
- `Plugin/KrbAuthenticator/Controller/KrbAuthenticatorAppController.php` (modify — `App::uses('KrbAuthenticatorActionEnum', 'KrbAuthenticator.Lib')` if a global include point is needed)

**Approach:**

- New constants live in `Lib/enum.php` as a single `KrbAuthenticatorActionEnum` class, mirroring how `PasswordAuthenticator/Lib/enum.php` defines its enums.
- `manage()` signature becomes `manage($data, $actorCoPersonId, $actorApiUserId = null, $initialPasswordEvent = false)`. Search for existing positional callers (UI flow: `KrbsController::ssr` at `:200`, `SAMController::manage` at upstream `app/Controller/SAMController.php:603-604`) and confirm they pass only the first two args; no change required at call sites.
- `HistoryRecord->record` takes 10 args (`$coPersonID, $coPersonRoleID, $orgIdentityId, $actorCoPersonID, $action, $comment, $coGroupID, $coEmailListId, $coServiceId, $actorApiUserId`). The two existing call sites pass 11 — drop the extra trailing `null` and put `$actorApiUserId` in slot 10. Without this fix, U1's threaded `$actorApiUserId` would silently shadow against the trailing extra `null` and never reach the DB.
- **Suppress `manage()`'s internal `AuthenticatorEdited` HistoryRecord write when invoked from REST.** `Plugin/KrbAuthenticator/Model/KrbAuthenticator.php:411-420` unconditionally writes a `HistoryRecord` with `ActionEnum::AuthenticatorEdited` at the end of `manage()`'s success path. For UI callers that record is the audit trail. For REST callers, the controller writes its own pKKI/pKKS/pKKF/pKKD records (R19/R20), so the internal `AuthenticatorEdited` write would produce a three-record trail `{pKKI, AuthenticatorEdited, pKKS}` and break KTD-5's audit-query invariant (the rejected hybrid is back). Guard the internal write with `if ($actorApiUserId === null) { ... }` — UI callers (where `$actorApiUserId` is null) still get `AuthenticatorEdited`; REST callers (where `$actorApiUserId` is the API user's id) do not. The same guard applies at the `:535-545` `reset()` site.
- This unit changes no externally observable behavior for UI flows: `$actorApiUserId` defaults to `null`, the HistoryRecord shape is unchanged for UI calls. The 11-arg → 10-arg correction is structurally invisible to current code because no caller passes a non-`null` `$actorApiUserId` today; it becomes load-bearing the moment U3/U4 land.

**Patterns to follow:**

- `app/AvailablePlugin/PasswordAuthenticator/Lib/enum.php` for the enum class shape.
- `app/AvailablePlugin/PasswordAuthenticator/Model/PasswordAuthenticator.php:144` for `manage()` parameter order.
- `app/Model/HistoryRecord.php:223-264` for the canonical 10-arg signature.

**Test scenarios:**

- *Functional, no harness.* Invoke the UI manage flow (browser POST to `/registry/krb_authenticator/krbs/manage`) for a CoPerson and confirm a HistoryRecord row is created with `actor_co_person_id` populated, `actor_api_user_id` NULL, and `action = ActionEnum::AuthenticatorEdited` (the internal write fires because the actor==null guard sees a UI caller). Inspect with `SELECT * FROM cm_history_records ORDER BY id DESC LIMIT 1;`.
- *Regression.* The `$initialPasswordEvent` arg, when omitted, must continue to behave as `false` — verify by reading the conditional branch in `manage()` and confirming it does not enter the initial-password branch.
- *Internal-write suppression.* Call `KrbAuthenticator::manage($data, null, $someApiUserId)` directly (or via a U3 POST in dry-run mode). Confirm NO `AuthenticatorEdited` row is created — only the U3-written pKKI/pKKS pair appears, attributed via `actor_api_user_id`. This validates the U1 guard that prevents the three-record `{pKKI, AuthenticatorEdited, pKKS}` trail.

**Verification:** UI manage and ssr flows continue to work end-to-end. `cm_history_records` rows after a UI manage have correct `actor_co_person_id`. The `manage()` signature in `Model/KrbAuthenticator.php` matches `PasswordAuthenticator::manage()`'s shape.

---

### U2. REST GET endpoints (index and view)

**Goal:** Make `GET /krbs.json?krbauthid=N` and `GET /krbs/{id}.json` return well-formed JSON without writing any new controller code beyond what `SAMController` / `StandardController` already provide.

**Requirements:** R1, R2, R3.

**Dependencies:** U1 (for the ActionEnum reference if logging is added, otherwise none).

**Files:**

- `Plugin/KrbAuthenticator/View/Krbs/json/index.ctp` (new — copy from `app/View/Standard/json/index.ctp`)
- `Plugin/KrbAuthenticator/View/Krbs/json/view.ctp` (new — copy from `app/View/Standard/json/view.ctp`)
- `Plugin/KrbAuthenticator/View/Krbs/json/add.ctp` (new — copy from `app/View/Standard/json/add.ctp`, used as the response template for POST success and 4xx errors)
- `Plugin/KrbAuthenticator/View/Krbs/json/edit.ctp` (new — copy from `app/View/Standard/json/edit.ctp`)
- `Plugin/KrbAuthenticator/View/Krbs/json/delete.ctp` (new — copy from `app/View/Standard/json/delete.ctp`)
- `Plugin/KrbAuthenticator/Model/Krb.php` (modify — add `public $permittedApiFilters = array('krb_authenticator_id' => 'KrbAuthenticator.KrbAuthenticator')` so `?krb_authenticator_id=N` works through the generic StandardController filter as a documented alternative to `?krbauthid=N`)
- `Plugin/KrbAuthenticator/Controller/KrbsController.php` (modify — add `index()` override that delegates to `parent::index()` and converts the empty-result 404 path into 200 + empty `Krbs` array; see Approach)

**Approach:**

- JSON views are copied verbatim from upstream `app/View/Standard/json/` rather than symlinked — see KTD-9.
- `KrbsController::index()` override: `SAMController::index()` at upstream `:517-520` returns 404 Not Found when `find()` returns empty (with an XXX comment in upstream code acknowledging the behavior is wrong but not fixed). R1/R2 promise 200 + empty `Krbs` array. The override wraps `parent::index()`; when the parent set status to 404 with no rows AND `?krbauthid=N` was supplied (i.e., the parent flag matched a real instance but no Krb rows exist for the scope), rewrite the status to 200 and emit an empty `Krbs` array. Preserve the 404 path only when the parent flag itself resolves to nothing (e.g., `?krbauthid=99999` against a non-existent KrbAuthenticator).
- `StandardController::view()` handles `/krbs/{id}.json` for single-row lookup; no override needed there (404 is correct for a missing ID).
- `permittedApiFilters` lets `?krb_authenticator_id=N` work as an alternate filter for callers who prefer the model-attribute naming.
- **URL-disambiguation gotcha (documented in U7).** `?krbauthid=N` and `?krb_authenticator_id=N` are NOT aliases at the same code path. They fire in different branches: `?krbauthid=N` triggers SAMController's custom REST branch at `:506-525` (which composes with `&copersonid=M` to scope by both); `?krb_authenticator_id=N` falls through to `StandardController::index()`'s `permittedApiFilters` branch at `:929-942`, which filters ONLY on `krb_authenticator_id` and does NOT compose with `?copersonid=M`. If both query params are supplied, `?krbauthid=N` wins. The canonical V1 form for "list rows for one CoPerson under one KrbAuthenticator instance" is `?krbauthid=N&copersonid=M`.

**Patterns to follow:**

- `app/AvailablePlugin/UnixCluster/Model/UnixClusterAccount.php:37-39` for the `permittedApiFilters` shape.
- `app/View/Standard/json/index.ctp` / `view.ctp` for the response envelope shape: `{"ResponseType":"Krbs","Version":"1.0","Krbs":[{"Version":"1.0","Id":N,"Person":{"Type":"CO","Id":M},"KrbAuthenticatorId":K,"Created":"...","Modified":"..."}]}`.

**Test scenarios:**

- *Functional.* `GET /registry/krb_authenticator/krbs.json?krbauthid=N` with valid API credentials returns 200 and a `Krbs` array (possibly empty). Verify Content-Type is `application/json` and the envelope matches the standard shape.
- *Functional.* `GET /registry/krb_authenticator/krbs.json?krbauthid=N&copersonid=M` returns 200 and a `Krbs` array containing at most one entry for that CoPerson.
- *Functional.* `GET /registry/krb_authenticator/krbs/{id}.json` for an existing row returns 200 with a single-element `Krbs` array.
- *Functional.* `GET /registry/krb_authenticator/krbs/999999.json` (nonexistent ID) returns 404 with the standard ErrorResponse envelope.
- *Documented behavior.* `GET /registry/krb_authenticator/krbs.json?copersonid=M` (no `krbauthid`) — current behavior is the StandardController fallback path, which the brainstorm documents as the originally-reported failure case. Verify behavior with and without the deployment patch; capture the actual response in U7 documentation.
- *Negative permission.* Same calls with a non-cmadmin/coadmin API user return 401 or 403.

**Verification:** A privileged API user can list Krb rows under a given KrbAuthenticator instance and read a single row by ID. JSON response shape matches the standard envelope. No password material appears in any response.

---

### U3. REST POST: set Kerberos credential

**Goal:** A `POST /krbs.json` from a privileged API user sets the Kerberos password in the KDC AND creates the `Krb` linkage row, returning 201 with the new row's `Location`. All guards, sanitized errors, rate limiting, and HistoryRecord intent+outcome writes apply.

**Requirements:** R4, R7, R8, R9, R9a, R10, R11, R12, R12a, R13, R14, R14a, R15, R16, R17, R17a, R18, R19, R20.

**Dependencies:** U1 (manage signature and HistoryRecord fix), U2 (JSON views), U6 (rate limiter).

**Files:**

- `Plugin/KrbAuthenticator/Controller/KrbsController.php` (modify — add `add()` override with `is('restful')` branch)
- `Plugin/KrbAuthenticator/Lib/lang.php` (modify — add sanitized error keys)

**Approach:**

- New `add()` override at the top of `KrbsController.php` follows the canonical REST-branch shape from `PasswordsController::generate()` (`app/AvailablePlugin/PasswordAuthenticator/Controller/PasswordsController.php:125-153`) and `PasswordsController::ssr()` (`:161-245`):

  ```
  public function add() {
      if (!$this->request->is('restful')) {
          return parent::add();  // UI form post unchanged
      }
      // Outer try wraps the entire REST branch ONLY for the password-scrub
      // belt-and-suspenders defense (R14a). It does not write audit records.
      try {
          // --- Pre-KDC phase (no audit side effects on failure) ---
          // 1. Resolve actor (Auth->User('id') -> actorApiUserId)
          // 2. U6 schema preflight (in this branch, not in beforeFilter, so UI
          //    flows are unaffected): a cheap query against cm_krb_rate_limit_counters;
          //    503 + er.krbauthenticator.rest.ratelimiter.unavailable on failure
          // 3. Parse $this->Api->getData() into snake_case
          // 4. Validate presence of password, password2, krb_authenticator_id, co_person_id
          // 5. Confirm password == password2 (422 on mismatch)
          // 6. Length validation against the KrbAuthenticator instance's min/max_length
          // 7. Load the KrbAuthenticator instance row and derive its owning CO
          //    Cross-check against parseCOID / query CO; mismatch -> 403 (R9a)
          // 8. R10 role-based actor==target guard via cm_co_person_roles
          // 9. Existing Krb row check by (krb_authenticator_id, co_person_id) -> 409 with Location
          // 10. Rate limiter check & increment per-credential, per-target, per-instance
          //     -> 429 + Retry-After on breach
          //     Note: pre-KDC failures (steps 4-9) do NOT increment the counter; only
          //     this step's check + KDC-success/Registry-* outcomes do (per KTD-7
          //     "recovery is privileged" — pKKF/pKKD attempts are not counted toward
          //     the per-target budget so a legitimate replay after divergence does
          //     not exhaust the window)
          // (Pre-KDC failures return their sanitized 4xx/5xx and exit; NO pKKF is
          //  written because the request never reached the KDC, preserving KTD-6's
          //  "every reachable-the-KDC attempt is auditable" framing without
          //  producing orphan pKKF records for validation errors.)

          // --- KDC + audit phase (inner try ensures pKKI/pKKF/pKKD ordering) ---
          //
          // KTD-12 (a) assertion: assert no parent transaction is open on the
          // KrbAuthenticator->getDataSource() before writing pKKI. If a future
          // beforeFilter, behavior, or wrapper opened one, fail 500 with
          // er.krbauthenticator.rest.audit.preflight rather than enrolling pKKI
          // in a parent transaction that may roll back and silently violate R20.
          //
          // 11. Write intent HistoryRecord (pKKI) — autocommit, no open transaction
          //     comment string composed from fixed _txt() keys + IDs only (R14b);
          //     never from password fields, exception text, or derivatives
          try {
              // 12. Call $this->Krb->KrbAuthenticator->manage($data, null, $actorApiUserId)
              //     - KDC call runs with NO DB transaction open (KTD-12 (b))
              //     - Principal name resolved server-side from loaded KrbAuthenticator
              //       and verified co_person_id, NOT from request payload (R12a)
              //     - manage()'s internal AuthenticatorEdited write is suppressed
              //       when $actorApiUserId is non-null (U1 guard)
              // 13. _begin() — transaction wraps ONLY the post-KDC Registry writes:
              //     a. Insert Krb linkage row (Provisioner fires here, intended)
              //        Catch ChangelogBehavior-driven $dataSource->rollback() and
              //        route into the pKKD branch (see KTD-12 Changelog interaction note)
              //     b. Write outcome HistoryRecord (pKKS)
              //     c. _commit()
              // 14. On success, set Location header and return 201
          } catch (InvalidArgumentException $kdcPolicy) {
              // KDC policy rejection (e.g., dictionary-word check failed)
              $this->log($kdcPolicy->getMessage());
              // Write pKKF outcome record on the autocommit DataSource
              // (intent pKKI is already durable; outcome closes the trail)
              $this->Api->restResultHeader(422, "Unprocessable Entity");
              $this->set('vv_error', _txt('er.krbauthenticator.rest.kdc.policy'));
              return;
          } catch (RuntimeException $kdcFailure) {
              // KDC unreachable, principal missing, or changePassword threw
              $this->log($kdcFailure->getMessage());
              // Write pKKF outcome record on the autocommit DataSource
              $this->Api->restResultHeader(500, "Internal Server Error");
              $this->set('vv_error', _txt('er.krbauthenticator.rest.kdc.failed'));
              return;
          } catch (\Throwable $postKdc) {
              // Krb row insert / outcome write failed AFTER KDC commit (divergence).
              // _rollback() the controller's transaction if open. KDC password
              // remains committed. After rollback, the DataSource is no longer in
              // a transaction and subsequent writes auto-commit.
              if ($this->KrbAuthenticator->getDataSource()->_transactionStarted) {
                  $this->_rollback();
              }
              $this->log($postKdc->getMessage());
              // Write pKKD outcome record on the post-rollback (autocommit) DataSource
              $this->Api->restResultHeader(500, "Internal Server Error");
              $this->set('vv_error', _txt('er.krbauthenticator.rest.kdc.divergence'));
              return;
          }
      } finally {
          // Belt-and-suspenders: scrub password material before any exception can
          // propagate to Cake's default error logger (R14a). Runs on every exit
          // path — success, handled error, uncaught fatal.
          unset($this->request->data['Krb']['password']);
          unset($this->request->data['Krb']['password2']);
      }
  }
  ```

- **Transaction shape follows KTD-12 strictly.** Intent record at step 10 is autocommit. KDC call at step 11 runs with no transaction open. Post-KDC `_begin/_commit/_rollback` wraps steps 12a-c. The pKKD divergence record at step 13 is written via a fresh autocommit connection so it is durable even when the wrapping transaction was rolled back.
- **Principal resolution at step 11 (R12a).** `manage()` is invoked with `$data` reshaped so the principal-bearing fields come from the loaded `KrbAuthenticator` instance row and the loaded Krb-row's (or POST-supplied + verified) `co_person_id`. Any payload field that purports to override the principal is dropped before the call. The controller's input parsing extracts ONLY `password`, `password2`, `krb_authenticator_id`, `co_person_id` from the request body; all other fields are ignored.
- **Sanitized errors (R14a).** Map exception class to a `_txt()` key in the response. `InvalidArgumentException` → 422 `er.krbauthenticator.rest.validation`; `RuntimeException` → 500 `er.krbauthenticator.rest.kdc.failed` (coarse; see follow-on note about distinguishing principal-not-found-in-KDC as 404). Raw `$e->getMessage()` reaches only `$this->log()`. The outer `try { ... } catch (\Throwable $e) { unset password fields; ... }` is the belt-and-suspenders defense against Cake 2's default error handler serializing `$this->request->data` into a log on an uncaught fatal.
- The `Krb` row insert at step 12a uses `$this->Krb->save(array('Krb' => array('krb_authenticator_id' => ..., 'co_person_id' => ...)))`. The `Provisioner` behavior on the Krb model fires here — confirmed by research that `manage()` does NOT call `Krb->save()` and `KrbAuthenticator` is not itself `Provisioner`-decorated, so there is no double-fire. The UI flow's `SAMController::manage()` at upstream `:607` does an explicit `$this->Authenticator->provision()` after `manage()` returns; U3's `Krb->save()` provides the equivalent provisioning trigger for the REST path.
- **Provisioner timing on the divergence-replay path.** If the first POST diverged (KDC committed, row insert failed → pKKD, no row), a replay completes the row insert on the second attempt. The `Provisioner` behavior fires on the REPLAY, not on the original KDC commit, so a provisioner that timestamps "first observed" records the replay time rather than the actual credential-change time. Documented in U7 so provisioner targets needing event-time accuracy consult the HistoryRecord trail instead.

**Patterns to follow:**

- `app/AvailablePlugin/PasswordAuthenticator/Controller/PasswordsController.php:125-153, 161-245` for the `is('restful')` branch structure.
- `app/Controller/SAMController.php:440-441` for the `$actorApiUserId = $this->request->is('restful') ? $this->Auth->User('id') : null;` pattern.
- `app/Controller/Component/ApiComponent.php:502-510` for `restResultHeader($code, $text)` and `:202-252` for `convertRestResponse`.

**Test scenarios:**

- *Happy path.* `POST /krbs.json` with valid `{krb_authenticator_id, co_person_id, password, password2}` returns 201 with `Location: /registry/krb_authenticator/krbs/{newId}.json`. `SELECT * FROM cm_krbs WHERE co_person_id = M` returns one row. `kinit user@REALM` against the new password succeeds. `SELECT * FROM cm_history_records WHERE actor_api_user_id = X ORDER BY id DESC LIMIT 2` returns two rows (intent pKKI then outcome pKKS).
- *Conflict (already exists).* `POST` for a CoPerson who already has a `Krb` row returns 409 with `Location: /registry/krb_authenticator/krbs/{existingId}.json`. No HistoryRecord written, no KDC call.
- *Length too short.* `POST` with a 4-character password against `min_length=8` returns 422 with `er.krbauthenticator.rest.validation` text. No HistoryRecord, no KDC call.
- *Length too long.* `POST` with a 100-character password against `max_length=64` returns 422. No KDC call.
- *Password mismatch.* `POST` with `password != password2` returns 422. No KDC call.
- *Actor == target.* `POST` from an API user whose `co_person_id` equals the target `co_person_id` returns 403 with `er.krbauthenticator.rest.actor.target.forbidden`. No KDC call. (Rare in practice — most API users have no `co_person_id`.)
- *Insufficient role.* `POST` from an API user who is neither `cmadmin` nor `coadmin` returns 401 or 403 from the existing SAMController permission gate. No KDC call.
- *KDC unreachable.* With the KDC stopped, `POST` returns 500 with `er.krbauthenticator.rest.kdc.failed`. A `pKKF` HistoryRecord is written. No `Krb` row is created.
- *KDC policy reject.* `POST` with a password that the KDC rejects (e.g., dictionary word against a KDC enforcing strength) returns 422 with sanitized text. A `pKKF` HistoryRecord is written. No `Krb` row.
- *Divergence simulation.* Force a DB write failure (e.g., temporarily revoke insert privilege on `cm_krbs`) and `POST` valid input. Verify: KDC commit observable via `kinit`; response is 5xx sanitized; HistoryRecord shows pKKI followed by pKKD. Replay the same `POST` after restoring privilege — verify it succeeds (natural idempotency: same password value re-committed in KDC, Krb row now inserted).
- *Sanitized error.* Trigger any failure and confirm the response body contains no fragments of the supplied password.
- *Error-text leak audit (R14a).* For each negative test, regex the response body against the supplied password and against principal-bearing strings (the principal name as it would appear in `Plugin/KrbAuthenticator/Model/KrbAuthenticator.php:399-404`'s exception text); assert no match.
- *Manual verification only — no in-tree test harness.* Registry has no test pattern for asserting `cm_history_records` state programmatically; `app/Test/Case/Model/CoGroupTest.php` is the existing template and only uses `Model->find()` against fixtures. These scenarios are exercised by hand or by an integration script written against the deployment.
- *Rate limit (per credential).* Issue 6 valid `POST`s within 60 seconds from one API credential against 6 different CoPersons. The 6th returns 429 with `Retry-After` ≤ 60. (Defaults: 5/minute per credential.)
- *Rate limit (per target).* Issue 3 valid `POST`s within 1 hour against the same `(krb_authenticator_id, co_person_id)` pair. The 3rd returns 429 with `Retry-After`. (Defaults: 2/hour per target — note these end up as 409s after the first, so the rate-limit case is contrived; verify by `DELETE` of the Krb row between attempts via UI or by manually clearing.)

**Verification:** Successful POST results in a `Krb` row and a KDC password change verified by `kinit`. Failure responses are sanitized. HistoryRecord trail has either {pKKI, pKKS} or {pKKI, pKKF} or {pKKI, pKKD} per attempt.

---

### U4. REST PUT: change Kerberos credential

**Goal:** A `PUT /krbs/{id}.json` from a privileged API user changes the Kerberos password in the KDC for the existing principal, returning 200. The `Krb` row is not modified (no fields to change); only the KDC is touched.

**Requirements:** R5, R7, R8, R9, R9a, R10, R11, R12, R12a, R14, R14a, R15, R16, R17, R17a, R18, R19, R20.

**Dependencies:** U1, U2, U6. Independent of U3 (no shared row-insert logic).

**Files:**

- `Plugin/KrbAuthenticator/Controller/KrbsController.php` (modify — add `edit()` override with `is('restful')` branch)

**Approach:**

- New `edit($id)` override parallels U3's `add()` but:
  - Looks up the `Krb` row by `$id`; 404 if missing.
  - Skips the 409 conflict check (the row is expected to exist).
  - Skips the row-insert step in the success path (only KDC + HistoryRecord).
  - **Per R12a, the loaded row's `co_person_id` and `krb_authenticator_id` are authoritative.** If the payload supplies values that conflict with the loaded row, return 422 — do NOT silently back-fill or accept the payload override. Principal name resolution happens server-side from the loaded row only.
- **Transaction shape follows KTD-12.** Intent pKKI is autocommit-before-KDC; KDC call has no transaction open; post-KDC `_begin/_commit/_rollback` wraps the outcome HistoryRecord write (the row is unchanged, so the transaction wraps only the outcome record). On rollback, the pKKD record is written via a fresh autocommit connection.
- **Sanitized errors and password-field scrub** apply identically to U3's `try { ... } catch (\Throwable $e) { unset($this->request->data['Krb']['password']); unset($this->request->data['Krb']['password2']); ... }` pattern. See U3 for the canonical shape.

**Patterns to follow:** same as U3.

**Test scenarios:**

- *Happy path.* `PUT /krbs/{id}.json` for an existing row with a new password returns 200. `kinit` with the old password fails; `kinit` with the new password succeeds. HistoryRecord trail shows pKKI then pKKS attributed to the API user.
- *Not found.* `PUT /krbs/999999.json` returns 404 with sanitized text. No KDC call.
- *Length / mismatch / actor==target / role.* Same negative cases as U3, mapped to 422 / 403 / 401.
- *KDC failure.* Same negative cases as U3 — return 500 sanitized with pKKF HistoryRecord. Stored `Krb` row is unchanged.
- *Replay (natural idempotency).* Two `PUT`s with the same password against the same row both succeed; the second is a no-op in observable behavior (same KDC end state). HistoryRecord shows two intent+success pairs. This validates R15.
- *Cross-field tampering (R12a).* `PUT /krbs/{id}.json` with a payload whose `co_person_id` or `krb_authenticator_id` does not match the loaded row returns 422. No silent back-fill. No KDC call. Confirms the principal is resolved from the persisted row, not the payload.
- *Rate limit (per credential, per target, per instance).* Same patterns as U3.
- *Error-text leak audit (R14a).* Same regex sweep as U3.
- *Manual verification only — no in-tree test harness.* Same caveat as U3.

**Verification:** Successful PUT changes the principal's password in the KDC without modifying the `Krb` row. `kinit` confirms the new password works. HistoryRecord captures the change with `actor_api_user_id` populated.

---

### U5. REST DELETE returns 405

**Goal:** A `DELETE /krbs/{id}.json` from any REST caller returns 405 with `Allow: GET, POST, PUT` and changes nothing. The UI delete path (if any) is unaffected.

**Requirements:** R6.

**Dependencies:** none.

**Files:**

- `Plugin/KrbAuthenticator/Controller/KrbsController.php` (modify — add `delete($id)` override)

**Approach:**

- Small override: `if ($this->request->is('restful')) { $this->Api->restResultHeader(405, 'Method Not Allowed'); $this->response->header('Allow', 'GET, POST, PUT'); return; } return parent::delete($id);`
- No route-layer change; `Router::mapResources` still routes DELETE to the controller, the controller intercepts.

**Patterns to follow:**

- `app/Controller/Component/ApiComponent.php:502-510` for `restResultHeader`.

**Test scenarios:**

- *Reject path.* `DELETE /registry/krb_authenticator/krbs/{id}.json` returns 405 with `Allow: GET, POST, PUT`. The `Krb` row in `cm_krbs` is unchanged. No KDC change. No HistoryRecord written.
- *UI path unchanged.* If a UI flow exercises the controller's `delete($id)` non-restfully, parent behavior is preserved (the plugin's existing UI delete continues to work). Browser-driven test against the legacy delete URL confirms.

**Verification:** A REST DELETE never deletes a row and never touches the KDC. The 405 response is well-formed.

---

### U6. Layered rate limiting

**Goal:** A library and DB-backed counter table that the REST POST/PUT branches in U3 and U4 call before any KDC interaction, returning 429 + `Retry-After` when any of three layered windows (per-credential, per-target, per-instance) is exceeded.

**Requirements:** R16, R17, R17a, R18.

**Dependencies:** none from this plan, but U3 and U4 call into the library.

**Files:**

- `Plugin/KrbAuthenticator/Config/Schema/schema.xml` (modify — add `krb_rate_limit_counters` table with unique compound index on `(scope, key, window_start_epoch)`; add `rest_rate_limit_per_credential_per_minute`, `rest_rate_limit_per_target_per_hour`, and `rest_rate_limit_per_instance_per_hour` columns on `krb_authenticators` — NULL-allowed, no DB-level defaults, code-side defaults applied at read time; add a unique compound index `krbs_i3` on `cm_krbs(krb_authenticator_id, co_person_id)` — see "cm_krbs unique constraint" below)
- `Plugin/KrbAuthenticator/Model/KrbRateLimitCounter.php` (new — minimal model with `checkAndIncrement()` method; see Approach)
- `Plugin/KrbAuthenticator/Model/KrbAuthenticator.php` (modify — add validation for the three new tunables; code-side defaults: 5/minute, 2/hour, 20/hour)

**Approach:**

- Schema: `cm_krb_rate_limit_counters` columns `(id, scope VARCHAR(32), key VARCHAR(128), window_start_epoch BIGINT, count INT)` with a unique compound index on `(scope, key, window_start_epoch)` patterned after `cm_locks` index `locks_i1`. Three `scope` values are recognized: `per_credential` (key = `api_user_id`), `per_target` (key = `{krb_authenticator_id}:{co_person_id}`), and `per_instance` (key = `krb_authenticator_id`, supporting R17a).
- **cm_krbs unique constraint.** Add a unique compound index `krbs_i3` on `cm_krbs(krb_authenticator_id, co_person_id)` (with the Changelog behavior's `deleted` column factored in if the deployment uses soft-delete-then-re-create semantics for Krb rows). Without this constraint, two concurrent POSTs to the same target can both pass U3's 409 existence check (a SELECT-then-INSERT TOCTOU) and both insert duplicate Krb linkage rows. With it: the second insert raises a catchable `PDOException` with SQLSTATE 23000/23505, which U3 routes into the pKKD divergence branch (or, on the per-target-rate-limit path, never gets that far). Existing deployments with pre-existing duplicate rows must be deduplicated as part of the migration; document the `SELECT krb_authenticator_id, co_person_id, COUNT(*) FROM cm_krbs GROUP BY 1,2 HAVING COUNT(*) > 1` check as a deploy-time precondition.
- `KrbRateLimitCounter::checkAndIncrement($scope, $key, $windowSeconds, $limit)`:
  1. Computes `$windowStart = floor(time() / $windowSeconds) * $windowSeconds`.
  2. Attempts `$this->save(array('scope' => $scope, 'key' => $key, 'window_start_epoch' => $windowStart, 'count' => 1))`.
  3. On `PDOException`, inspect SQLSTATE via `$e->errorInfo[0]` (or `$e->getCode()`):
     - **`23000` (MySQL) or `23505` (Postgres)** — integrity-constraint violation indicating a row already exists for this window. Fall through to step 4 (the recovery path).
     - **Any other SQLSTATE** (deadlock `40001`, lock-wait-timeout `HY000`, connection reset, etc.) — rethrow. The Lock.php pattern fails CLOSED on lock acquisition failure; the rate limiter must do the same — transient DB errors must NOT silently bypass the limit. The controller catches the rethrown exception and surfaces a 5xx, fail-closed.
  4. Recovery path: `$this->updateAll(array('KrbRateLimitCounter.count' => 'KrbRateLimitCounter.count + 1'), array('KrbRateLimitCounter.scope' => $scope, 'KrbRateLimitCounter.key' => $key, 'KrbRateLimitCounter.window_start_epoch' => $windowStart))`. Note the keyed-array form (DboSource iterates `foreach ($fields as $field => $value)` at `lib/Cake/Model/Datasource/DboSource.php:2197-2233`; a flat array like `array('count = count + 1')` produces invalid SQL). The model-prefixed field references make the column-relative SQL snippet survive ORM quoting.
  5. `find('first', array('conditions' => array('scope' => ..., 'key' => ..., 'window_start_epoch' => ...)))` to read the post-increment count.
  6. Returns `(boolean $allowed, int $retryAfterSeconds)`. If the resulting count exceeds `$limit`, return `(false, $windowStart + $windowSeconds - time())`; otherwise `(true, 0)`.
- The check-and-increment method lives on the model itself rather than in a separate `Lib/` helper, mirroring `app/Model/Lock.php`'s single-file shape. The two controller callers (`KrbsController::add` and `KrbsController::edit`) invoke `$this->Krb->KrbRateLimitCounter->checkAndIncrement(...)` directly.
- Tunables come from the KrbAuthenticator instance row (per-instance configuration). Code-side defaults — 5/minute per credential, 2/hour per target, 20/hour per instance — are applied at read time when the column value is NULL, so existing `cm_krb_authenticators` rows inherit V1 defaults transparently on migration with no backfill SQL.
- **Fail-closed schema preflight in the REST branches (NOT in beforeFilter).** Before any rate-limit check, the REST POST/PUT branches in `add()` and `edit()` verify `cm_krb_rate_limit_counters` is reachable via a single inexpensive query (cached in process memory for the request's lifetime). If the table is missing or the query throws, those branches return `503 Service Unavailable` with `_txt('er.krbauthenticator.rest.ratelimiter.unavailable')`. The check runs only when `$this->request->is('restful') && in_array($this->request->method(), array('POST','PUT'))` — moving the preflight out of `beforeFilter` ensures UI flows (`manage`, `ssr`, `remind`) continue to work end-to-end during the deploy-window when the migration hasn't yet run, preserving the "No Registry UI flows change" claim in System-Wide Impact.
- **Recovery is privileged: do not count pKKF/pKKD attempts toward the per-target budget.** The natural-idempotency contract in R15 promises that the same `(krb_authenticator_id, co_person_id, password)` replay produces the same end state. If the per-target counter (R17) increments on the divergent attempt, a legitimate replay to converge state can be the call that pushes the counter past the limit — locking the operator out of further recovery on M for the remainder of the window. U3/U4's flow therefore: increment per-credential and per-instance on every accepted request (these are blast-radius controls); increment per-target only on pre-KDC validation failures (the validation work IS the attempt) and on successful KDC+Registry outcomes. Skip the per-target increment on pKKF (KDC failure) and pKKD (divergence) attempts — those are recovery candidates and the caller will replay.
- GET endpoints are not rate-limited at this layer; Registry's API-wide controls (whatever the deployment uses for ApiUser throttling) apply globally.
- The rate limiter runs *after* authentication and authorization (R9, R9a) so an unauthenticated attacker cannot grow the counter table by hammering the endpoint with arbitrary credentials. This guards against table-as-DoS-surface.
- Garbage collection of old counter rows is deferred to follow-on work — see Scope Boundaries. Documented expected growth: at one row per scope-key-window, a busy credential produces ~1440 rows/day at the per-credential scope.

**Patterns to follow:**

- `app/Model/Lock.php:102-134` — canonical save → catch `PDOException` → recover pattern, the in-tree primitive this unit mirrors. DO NOT invent flavor-specific upsert SQL.
- `app/Config/Schema/schema.xml` — `cm_locks` index `locks_i1` and `cm_cous` index `cous_i3` for multi-column `<unique/>` index syntax in ADOdb-XML.
- `app/Model/AppModel.php:54-89` — `_begin()`/`_commit()`/`_rollback()` transaction primitives, used by U3/U4 around the post-KDC row+outcome writes (per KTD-12) but NOT around the rate-limit check.
- `app/AvailablePlugin/SshKeyAuthenticator/Model/SshKey.php:301-313` and `app/Controller/CoExtendedAttributesController.php:322` — DB-flavor detection idiom (`explode("/", $db->config['datasource'], 2)[1]`) if any future hardening needs it; not used by V1.

**Test scenarios:**

- *Single hit.* Call `$this->Krb->KrbRateLimitCounter->checkAndIncrement('per_credential', '42', 60, 5)`. Returns `(true, 0)`. `SELECT count FROM cm_krb_rate_limit_counters WHERE scope='per_credential' AND key='42'` returns 1.
- *Within limit.* Five sequential calls within a 60-second window all return `(true, 0)`.
- *Limit breached.* The sixth call within the window returns `(false, retryAfter)` where `retryAfter` is between 1 and 60.
- *Window roll-over.* After the window expires, a new call lands on a new `window_start_epoch` row and returns `(true, 0)` regardless of prior counts.
- *Concurrency (canonical primitive).* Two parallel `php -r` invocations call `checkAndIncrement` against the same scope+key in the same window. Expected: both succeed (or both succeed eventually after the catch-and-recover), final count = 2. Reproduce on both MySQL and Postgres deployments.
- *Transient PDOException fails closed.* Simulate a deadlock (SQLSTATE `40001`) or lock-wait-timeout (`HY000`) during a `save()` (e.g., introduce contention via a held write lock on the counter row from another session). `checkAndIncrement` MUST rethrow rather than recover. The controller returns 5xx. Confirms transient errors do not silently bypass the limiter.
- *Per-target scope.* The `per_target` scope behaves identically with a longer window and different key format. Verify by issuing 3 calls within an hour and confirming the 3rd is rejected.
- *Per-instance scope (R17a).* The `per_instance` scope rate-limits ALL credentials/targets against one KrbAuthenticator instance. Verify by issuing 20 valid POSTs within an hour from a mix of API credentials against a mix of CoPersons under instance N. The 21st (from any credential, any target) returns 429.
- *Recovery is privileged.* Force a divergence (transient row-insert failure post-KDC) so U3 writes pKKD. Inspect the per-target counter: it MUST NOT have incremented for the pKKD attempt. Replay the same POST after restoring DB capability; the replay succeeds and the per-target counter increments once (for the successful outcome). Total: one counter row at count=1, not 2. Confirms the per-target budget does not punish recovery.
- *Schema preflight fail-closed in REST only.* With the `cm_krb_rate_limit_counters` table dropped: a POST returns 503 with `er.krbauthenticator.rest.ratelimiter.unavailable` — not 5xx with a SQL error, not 201 with rate limiting silently bypassed. Simultaneously, the UI `manage`, `ssr`, and `remind` flows continue to work end-to-end (browser submit succeeds), confirming the preflight is scoped to the REST branches of `add()`/`edit()` only and does NOT run in `beforeFilter`.
- *Auth-before-limiter ordering.* An unauthenticated POST does NOT cause a row to be written to the counter table; the controller's auth gate runs first.
- *Integration.* Through the U3/U4 endpoints, a 6th valid `POST` within 60s returns 429 with a `Retry-After` header between 1 and 60. Confirm no HistoryRecord is written when the rate limit fires (the limiter runs before the intent write).

**Verification:** A burst of POST/PUT requests beyond any configured limit gets 429 responses with sensible `Retry-After` values, and the counter table reflects what was sent. The Lock.php-pattern check-and-increment is concurrency-correct on both MySQL and Postgres without flavor-specific SQL.

---

### U7. Lang strings and plugin documentation

**Goal:** Add sanitized error message keys for every 4xx/5xx response shape, and add a README section that documents the V1 REST API surface so the tester (and future integrators) have a single reference.

**Requirements:** R21.

**Dependencies:** U3, U4, U5, U6 (so the documented behaviors match what shipped).

**Files:**

- `Plugin/KrbAuthenticator/Lib/lang.php` (modify — add `er.krbauthenticator.rest.*` keys)
- `Plugin/KrbAuthenticator/README.md` (modify or create — add "REST API (V1)" section)
- `Plugin/KrbAuthenticator/docs/rest-api.md` (new — longer-form reference if README would grow too long)

**Approach:**

- New lang keys (all under `er.krbauthenticator.rest.*`):
  - `validation` — generic 422 "The supplied data did not meet the validation requirements."
  - `kdc.failed` — generic 500 "The Kerberos key distribution center could not commit the password change. Contact your administrator."
  - `kdc.policy` — 422 "The Kerberos key distribution center rejected the password under its policy."
  - `actor.target.forbidden` — 403 "An API user may not set or change their own Kerberos credential via REST."
  - `co.mismatch` — 403 "The KrbAuthenticator instance does not belong to the resolved CO."
  - `row.exists` — 409 "A Krb record already exists for this CO Person under this KrbAuthenticator; use PUT to change the password."
  - `row.missing` — 404 "No Krb record found at the requested location."
  - `rate.limited` — 429 "Rate limit exceeded. Retry after the indicated interval."
  - `ratelimiter.unavailable` — 503 "The rate limiter is unavailable. Please retry."
  - `audit.preflight` — 500 "The audit preflight check failed." (KTD-12 (a) parent-transaction assertion)
  - `kdc.divergence` — 500 "The Kerberos credential change is in an inconsistent state. Replay the request to converge." (pKKD branch — caller-facing)
- README "REST API (V1)" section documents:
  - The five endpoints from R1-R6 with their canonical URL patterns.
  - The required POST/PUT payload shape `{ "Krbs": [{ "Version": "1.0", "KrbAuthenticatorId": N, "Person": {"Type":"CO","Id":M}, "Password": "...", "Password2": "..." }] }`.
  - The mapping of error class → status code → sanitized message.
  - The default rate limits (5/min per credential, 2/hour per target, 20/hour per instance) and their configurability per KrbAuthenticator instance.
  - The four new ActionEnum codes (`pKKI` intent, `pKKS` success, `pKKF` failure, `pKKD` divergence) so audit-log consumers and dashboards can recognize them.
  - The URL-disambiguation gotcha: `?krbauthid=N` and `?krb_authenticator_id=N` fire in DIFFERENT code paths inside Registry (`SAMController::index()` REST branch vs `StandardController::index()` `permittedApiFilters` branch). `?krbauthid=N&copersonid=M` scopes by both; `?krb_authenticator_id=N&copersonid=M` does NOT scope by `copersonid` (the latter only filters via `permittedApiFilters` on `krb_authenticator_id`). Document the working URL form unambiguously.
  - **Deployment security checklist (R21 expanded):**
    - TLS enforced on the REST endpoint at the web-server layer.
    - DebugKit plugin disabled in production (it caches request data when Cake's `Configure debug >= 1`).
    - Cake 2's default exception handler does NOT serialize `$this->request->data` into the error log; if a custom handler is installed, it MUST scrub `Krb.password` and `Krb.password2` before logging.
    - Apache `LogLevel` not raised to `debug`; `mod_dumpio` off.
    - Nginx `access_log` does not capture request bodies.
    - APM agents (NewRelic, Datadog, Sentry) configured to suppress request bodies on POST/PUT to `/registry/krb_authenticator/krbs.json`.
    - Reverse proxy or WAF body-capture rules off for this endpoint.
    - PHP `log_errors=On` with `display_errors` off (default) prevents request bodies from landing in PHP's `error_log` on fatals; verify before enabling REST writes.
    - NTP keeps host clocks synchronized — the rate-limit window arithmetic assumes clock-drift across multi-worker hosts is smaller than the smallest configured window (60s).
    - Web-server / load-balancer access logs MUST record HTTP 401 responses against `/registry/krb_authenticator/krbs.json` with source IP and timestamp. Failed-authentication attempts (HTTP Basic against the ApiUser layer) produce neither a HistoryRecord (the actor was never resolved) nor a rate-limit counter increment (the limiter runs post-auth). Without web-server-layer 401 logging, credential-stuffing attempts against the REST endpoint are forensically invisible.
  - **Fixed-window rate-limit boundary effect (operator-calibration note).** The rate limits in R16/R17/R17a are fixed-window: counters reset at window boundaries computed as `floor(time() / window_seconds) * window_seconds`. An attacker who knows wallclock can issue a burst that straddles the boundary and effectively double the configured rate (e.g., 5 hits at 14:59:55 plus 5 hits at 15:00:00 = 10 commits in 5 seconds against a 5/minute cap). Operators choosing defaults should treat the effective cap as `configured / 2` for blast-radius bounding. Sliding-window arithmetic is a follow-on hardening; V1's fixed-window choice was made because the brainstorm's contract is naturally fixed-window.
  - **Audit-log integrity caveat:** HistoryRecord rows are not signed or hash-chained. Tamper-resistance is bounded by database access control. This is the standard Registry posture — V1 does not change it but the new intent/outcome pattern relies on the audit trail to detect divergence, so DB write access should be treated as a tier-1 security boundary.
  - **Dangling pKKI guidance for reconciliation:** an intent record (pKKI) with no matching outcome (pKKS / pKKF / pKKD) means "outcome unknown — manual review required," not "divergence confirmed." Expected steady-state rate is zero; under PHP fatal errors, one per fatal. Operators should treat any dangling pKKI as a triage event.
  - **HistoryRecord backfill: none.** Pre-V1 rows written by the 11-arg bug at `Plugin/KrbAuthenticator/Model/KrbAuthenticator.php:535-545` have NULL `actor_api_user_id` even when an API user invoked `reset()`. The original actor identity is not recoverable from the row, so no backfill is performed. Analytics consumers should treat pre-V1 NULL `actor_api_user_id` as "unknown" rather than "no API user."
  - **GROUP BY action will see four new distinct codes** (`pKKI`, `pKKS`, `pKKF`, `pKKD`) appear at V1 deploy time. Dashboards keyed on a fixed code list — including any filtering on `ActionEnum::AuthenticatorEdited` — will UNDERCOUNT V1 REST writes unless updated to UNION-in the new codes.
  - The tester's originally-reported URL pattern (`?copersonid=104269`) and the working alternative (`?krbauthid=N&copersonid=M`).
  - **No in-tree precedent for plugin REST API documentation.** Closest style match for the technical-reference doc shape is `app/AvailablePlugin/ConfigurationHandler/README.md`; the new V1 README extends rather than mirrors it.

**Patterns to follow:**

- `Plugin/KrbAuthenticator/Lib/lang.php` existing `er.*` and `pl.*` key structure.

**Test scenarios:**

- *Doc parity.* Render the README locally; confirm each documented response code appears in U3/U4/U5/U6 test scenarios above. Any divergence is a bug in either the doc or the code.
- *Lang key coverage.* Grep the controller for every `_txt('er.krbauthenticator.rest.*')` invocation and confirm each key is defined in `Lib/lang.php`. Confirm no controller code constructs response messages by string-concatenating exception text.
- *Walkthrough.* A reader following only the README can issue a successful `POST` against a staging KrbAuthenticator instance and verify the Kerberos password with `kinit`.

**Verification:** The README is the canonical reference for an external integrator. All documented endpoints work as described. All documented error responses match the controller's actual output.

---

## System-Wide Impact

- **`KrbAuthenticator::manage()` signature change** is plugin-internal but observable to any future plugin code that depends on positional arguments. The `$initialPasswordEvent` arg moves from position 3 to position 4. Search confirms no current callers set it; future callers must use named-style positional convention.
- **HistoryRecord 11-arg fix at two existing call sites** changes observable audit behavior for the legacy `reset()` path: `actor_api_user_id` will now be populated where it previously was silently dropped. This is the correct behavior, but audit-log consumers that distinguished "old style" rows by absence of this column will need to re-baseline.
- **New `cm_krb_rate_limit_counters` table** requires a Registry database migration. The plugin's existing schema-XML mechanism handles this on next deployment install/upgrade.
- **New columns on `cm_krb_authenticators`** for rate-limit tunables similarly require migration.
- **No Registry UI flows change.** `manage`, `ssr`, and `remind` paths in `KrbsController` continue to render and behave identically. The new REST branches are guarded by `is('restful')`.
- **The `Provisioner` behavior on `Krb`** fires when U3 inserts a new linkage row. Downstream provisioner targets configured for the KrbAuthenticator instance will see the new row and run their provisioning hooks. This is the intended behavior, but a deployment with active provisioners should be informed.
- **Provisioner fan-out frequency increases relative to V0.** Before V1, `Krb` rows were never written by any code path (confirmed by exhaustive grep across the upstream + plugin trees for `Krb->save`, `Krb->saveAll`, `Krb']->save`); downstream Provisioner targets registered against the `Krb` model effectively never fired. After V1, every successful POST fires `ProvisionerBehavior::afterSave` on row insert. Deployments with LDAP-password-sync or similar credential-bearing provisioners will see new traffic. Coordinate with deployers before enabling REST writes on a deployment with active Krb-attached provisioners.
- **Audit dashboards counting `ActionEnum::AuthenticatorEdited` will undercount REST writes.** The four new codes `pKKI`/`pKKS`/`pKKF`/`pKKD` are distinct from `AuthenticatorEdited`. Any deployment dashboard, alerting rule, or compliance query that filters on `AuthenticatorEdited` MUST be updated to UNION-in the new codes. U7 documentation calls this out explicitly.
- **HistoryRecord audit trail is not signed or hash-chained.** Consistent with the rest of Registry, audit rows can be tampered with by anyone with DB write access. V1 does not change this posture but does increase reliance on the audit trail (the intent/outcome pattern is meaningless if the trail can be silently edited). Treat the DB connection as a tier-1 security boundary.
- **The intent record (`pKKI`) without a matching outcome record is a documented audit state, not an error.** Reconciliation tooling that flags every dangling `pKKI` as a divergence will false-positive on controller crashes between the intent write and any DB-side write, including transient PHP fatals. U7 documents the interpretation rule: dangling `pKKI` is "outcome unknown — manual review required," not "divergence confirmed."
- **The pre-KDC intent record's `comment` field MUST be password-free.** HistoryRecord `comment` is plain text persisted alongside the audit row. U3 and U4 compose the comment from fixed `_txt()` keys plus IDs only — never from `$data['Krb']['password']`, `$data['Krb']['password2']`, or any derivative (length, hash prefix, character class). Without this constraint, a "more helpful" comment refactor could land a password fragment in `cm_history_records.comment`.
- **Request-body password exposure depends on more than the web stack.** The "request bodies not logged" deploy-time assumption covers: Apache `LogLevel debug` and `mod_dumpio`, Nginx `access_log` body capture, Cake 2 `DebugKit` plugin (logs request data when `Configure debug >= 1`), Cake's default `ExceptionRenderer` which can serialize `$this->request->data` into the error log on uncaught 500s, APM agents (NewRelic, Datadog, Sentry), reverse-proxy or WAF body-capture rules, and PHP `error_log` when `log_errors=On` with `display_errors` not redirected. U7 documents each as a deployment gate item. U3/U4 add belt-and-suspenders by clearing the password fields from `$this->request->data` inside the outer try/catch before any exception propagates.
- **Replay risk of logged request bodies.** If the no-body-logging assumption fails at any layer above, a captured POST body is a fully-replayable credential-set operation (TLS prevents network interception, but a logged body bypasses TLS). U7 frames "operators MUST audit their log pipelines for body capture before enabling REST writes" as a deployment-gate checklist item rather than a soft assumption.
- **Headroom for the SSR follow-on.** KTD-1's "leaves room for a sibling action" claim is true only if the follow-on `issue-reset-token` lives at a different route than `add()`. The plan documents the intended route as `POST /registry/krb_authenticator/krbs/{id}/reset_token.json` (or a sibling controller action) so V1's `Router::mapResources` choice does not foreclose it; the new route is configured explicitly in `Config/routes.php` when the follow-on lands.
- **Rate-limit counter table as a DoS surface, mitigated by ordering.** `cm_krb_rate_limit_counters` is upserted on every REST write attempt that passes auth. U6's approach explicitly runs the limiter *after* authentication and authorization gates (R9, R9a, R10) so an unauthenticated attacker cannot grow the table by hammering the endpoint. The table-growth bound is therefore `authenticated requests/sec × window_seconds`, not unbounded.

## Risks and Dependencies

- **No existing test harness in the plugin or in PasswordAuthenticator.** Test scenarios in this plan are functional/manual specs. CI cannot enforce regression on the V1 surface until a harness exists, which is deferred. Mitigation: run the documented test scenarios manually against a staging deployment before shipping. The closest in-tree assertion-style template is `app/Test/Case/Model/CoGroupTest.php`, which uses only `Model->find()` against fixtures — there is no precedent for raw-SQL state assertions, so the plan's `SELECT * FROM cm_history_records ...` checks are manual-verification-only.
- **KDC reachability is a deployment property.** The plugin's failure modes for KDC unreachable, principal missing, and policy rejection are surfaced as 500 / 5xx. A flaky KDC under load will produce false positives at the REST layer; the rate-limit defaults try to bound thrashing but cannot prevent it.
- **The Krb-rows-not-currently-written observation needs deployment validation.** Research found that nothing in current code writes `Krb` rows (exhaustive grep across upstream + plugin for `Krb->save`, `Krb->saveAll`, `Krb']->save` returned nothing except this plan document). If a deployment has rows from earlier Registry versions or external scripts, GET-index will return them and U3's 409-conflict path will fire on POST attempts against existing CoPersons. Verify before the tester exercises the API: `SELECT COUNT(*) FROM cm_krbs` on the access-ci.org deployment.
- **The originally-reported 404 may be a Registry version skew.** Research showed that `ApiComponent::requestedCOID()` at upstream HEAD already accepts `?copersonid=` for any model whose `belongsTo` includes `CoPerson`, which `Krb` does. If the tester's deployment is at upstream HEAD, the 404 is a different bug (probably empty `cm_krbs` for that CoPerson combined with a misleading error message); if it's an older version, V1's documented URL pattern resolves it. Confirm with the tester before V1 closes Goal 3.
- **The new ActionEnum constants (`pKKI`/`pKKS`/`pKKF`/`pKKD`) must not collide with codes used by other plugins.** The 4-char `p`-prefix convention has no central registry. Mitigation: grep the available plugins for existing `p`-prefix codes; pick alternatives if collision is found.
- **The `Provisioner` behavior firing on a new `Krb` row** may trigger downstream side effects (e.g., posting to a provisioning target's API). On a deployment with mis-configured provisioners, this can cascade. Mitigation: deploy on a staging instance first.
- **Coadmin cross-CO escalation.** `SAMController::calculateParentPermissions` resolves CO from request context (`parseCOID` and query parameters), not from the target resource. Without the R9a cross-check against the loaded KrbAuthenticator instance's owning CO, a coadmin of CO X could operate against a KrbAuthenticator instance owned by CO Y via a forged `coid=X` query string. R9a closes this; verifying the cross-check fires on every path is on the U3/U4 implementer.
- **Inert actor==target guard for typical ApiUsers.** Most ApiUsers have no CoPerson record, so the R10 guard evaluates `null === $target` → never fires for the typical case. R10 protects only the edge case of an ApiUser bound to a CoPerson role. The substantive protection against cmadmin-credential-theft is R9/R9a (role gate) plus R16/R17/R17a (rate limits) plus R19/R20 (audit). U7 documents this honestly so deployers do not over-rely on R10.
- **Multi-credential coordinated attack against a single target.** R16 (per-credential) and R17 (per-target) do not catch "5 different cmadmin credentials each hit target M once in 60 seconds." R17 catches the 3rd hit but the first two complete. R17a (per-instance, 20/hour default) bounds the totalwithin one KrbAuthenticator instance. Residual risk: two colluding credentials can still achieve two password changes per target per hour before R17 fires.
- **`actor_api_user_id` integrity inherits upstream ApiUser auth security.** The plan attributes REST writes from `$this->Auth->User('id')`. This is set during AppController's HTTP Basic auth flow and is not caller-supplied, so it cannot be spoofed by request payload. Residual: V1 inherits the security of upstream's ApiUser authentication wholesale; a session-fixation or auth-component bug in upstream propagates here.
- **DebugKit / CakeLog / Apache as silent password-leak vectors.** U3/U4's outer try/catch unsets `Krb.password` and `Krb.password2` before any exception can propagate to Cake's default error logger, but multiple layers above the framework can capture request bodies independently. U7's deployment security checklist names each layer; this risk is residual because a misconfigured deployment can land plaintext passwords in logs despite the plugin's defenses.
- **Schema migration is one-way and requires operator attention.** U6 adds `cm_krb_rate_limit_counters` and three columns on `cm_krb_authenticators`. New columns are NULL-allowed with code-side defaults applied at read time (no DB-level default) so existing rows inherit V1 defaults transparently with no backfill SQL. The migration runs through the plugin's `setup()` / re-enable hook; sites using the manual `db_acl.php` path must run it before V1 code begins serving REST traffic. Rollback to V0 leaves the new table and columns in place (Cake 2 schema-XML does not auto-drop) and leaves the new `pKKI`/`pKKS`/`pKKF`/`pKKD` HistoryRecord rows present but unrendered by older UI code; both are acceptable residual states.
- **Counter-table growth is unbounded in V1.** `cm_krb_rate_limit_counters` accumulates one row per `(scope, key, window)` with no GC in V1. At the per-credential scope (60-second window), a busy credential produces ~1440 rows/day. The index on `(scope, key, window_start_epoch)` is sized accordingly. A periodic prune task (delete rows where `window_start_epoch < now - max_window`) is captured under Scope Boundaries as follow-on hardening. Operators monitoring DB size should add `cm_krb_rate_limit_counters` to their watch list.
- **Counter-table truncation or restore-from-stale-backup fails open.** A wipe of `cm_krb_rate_limit_counters` resets all counts to zero; subsequent requests pass until counters rebuild. Accepted residual consistent with the layered-defense intent (R17a per-instance limit protects against the worst case even when per-credential and per-target counts reset).
- **PHP `Throwable` reaching outer scope does not bypass the password scrub.** U3/U4's outer `try { ... } catch (\Throwable $e) { unset password fields; ... }` catches all PHP exceptions including `Error` (which a fatal converts to in PHP 7+). A true PHP segfault would bypass the catch, but at that point the worker has died and Cake's error handler is not invoked. Residual.
- **Clock skew across multi-worker hosts.** The rate-limit window arithmetic uses `floor(time() / $windowSeconds) * $windowSeconds`; clock skew larger than the smallest window (60s) causes per-credential window boundaries to drift across workers. NTP-managed hosts are fine; container hosts with paused clocks (suspended VMs) are not. Documented as an NTP deployment assumption in U7.
- **Multi-master DB / async replicas.** On a multi-master MySQL or async-replica Postgres setup, the counter table's atomic-update holds on the writer but read-after-write from a replica can briefly under-report. The rate limiter MUST read from the writer; document this in U6 and U7 if the deployment uses replicas.
- **`HttpStatusCodesEnum` missing 422/429/503.** KTD-8 captures the integer-literal workaround for 422/429; the new 503 from U6's fail-closed preflight follows the same pattern. Audit tooling that scans for hardcoded HTTP codes will flag these as smells; document the upstream-PR-deferred decision in code comments at the call sites so a reviewer doesn't try to "fix" them.
- **Unit grouping for the V1 PR matters.** U1 may ship as a standalone precursor PR — the `manage()` signature change is backward-compatible (default arg) and the HistoryRecord arg-count fix is independently correct. U2 may ship as a standalone PR — GET endpoints are inert side-effect-free additions and JSON views are copies. U3, U4, and U6 MUST ship together in a single PR: U3 and U4 hard-depend on U6's `KrbRateLimiter` class and schema; without U6 the limiter call is a fatal PHP error and every POST/PUT returns 500. U5 (DELETE → 405) and U7 (lang/README) may ship in the U3/U4/U6 PR or as follow-ons. Mitigation: name this grouping in the V1 PR description so a reviewer who suggests "split this PR" knows where the seams are.

### Residual Risks (unlikely-but-worth-naming)

- HistoryRecord rows not being hash-chained is the Registry-wide posture and predates V1.
- The actor==target guard being mostly inert for typical ApiUsers is acceptable IF R9a and R17a land — the role gate plus per-instance global rate limit are the substantive protection.
- A Postgres deployment whose Postgres version predates Cake 2's portable `updateAll` semantics (pre-9.x) is unsupported by U6. Upstream Registry's minimum Postgres is well past this, but a frozen-version site could hit it.
- `Krb.modified` exposes credential-change timing at second precision via GET. This is a side channel against a target whose other state is partially known. V1 does not coarsen the timestamp; a future hardening could reduce precision in the REST response if a deployment requires it.

## Open Questions

Carried forward from the requirements doc's "Deferred / Open Questions" section. None block V1 implementation, but all should be answered before the PR merges or with the tester's response on the requirements PR.

- **OQ1. Premise check (P1, chain root): is direct REST POST/PUT actually the right V1 shape?** The requirements doc captures this as the root question. User confirmed "plan POST/PUT as drafted" at planning time; tester confirmation on the requirements PR is the durable answer. If the answer comes back "no, documentation + SSR-trigger is enough," this plan retires in favor of a smaller V1.
- **OQ2. Goal 3 vs. Success Criteria mismatch on the 404 fix (P2).** Cascades from OQ1. If POST/PUT stays, the 404 fix is the documentation deliverable in U7 plus the working URL pattern; if POST/PUT goes, the criterion needs to be re-stated.
- **OQ3. Should `?copersonid=X` alone (without `krbauthid`) be accepted as an index filter (P2)?** Cascades from OQ1. Research shows it likely already works at upstream HEAD via `StandardController` fallback. If it works, U2's verification scenarios already document the behavior; if not, V1's `?krbauthid=N&copersonid=M` is the documented form.
- **OQ4. Validate the SSR follow-on as actual near-term demand (P2).** Cascades from OQ1. Affects whether the issue-reset-token endpoint is genuinely deferred or should be folded into V1.
- **OQ5. (Plan-time.) Does the access-ci.org deployment have any pre-existing rows in `cm_krbs`?** If yes, U3's POST against those CoPersons returns 409 immediately. If no, the GET-index returns `[]` until the first successful POST. A `SELECT COUNT(*) FROM cm_krbs` on the deployment resolves it; not a blocker.
- **OQ6. (Plan-time.) Should the rate-limit defaults (5/min, 2/hour, 20/hour) be tunable per CO or only per KrbAuthenticator instance?** This plan picks per-instance, which is consistent with other KrbAuthenticator tunables. Per-CO would require a different table layout. Defer unless the tester reports a multi-CO use case.
- **OQ7. (Operational hardening gate.) Has the reconciliation tooling reported a non-trivial rate of the three "natural idempotency does not cover" failure modes named in KTD-10 (replay with different password, two distinct concurrent requests for the same target, caller retry after operator KDC rollback)?** Answered by the first quarter of operational data after V1 ships. If yes, V2 includes Idempotency-Key infrastructure (replay-detection table keyed on `(api_user_id, idempotency_key)` with a stored response body and TTL); if no, the V1 contract is sufficient. This explicit gate prevents the plan from pre-emptively building infrastructure to cover failure modes that may never appear.

### From 2026-05-29 plan review

The following questions were deferred during interactive document review of this plan. Both involve genuine tradeoffs the plan author should resolve before U3/U6 implementation lands.

- **OQ8. (Implementation tradeoff.) Changelog behavior on `Krb` opens its own transaction inside `beforeSave/afterSave` (`app/Model/Behavior/ChangelogBehavior.php:37-43, 79`). How should this interact with KTD-12's controller-managed `_begin/_commit/_rollback` wrapping the `Krb` row insert in U3?** Two paths: (a) pass `'callbacks' => false` to `$this->Krb->save(...)` from the controller to bypass Changelog, accepting the loss of revision tracking for REST-created Krb rows (audit trail is on `cm_history_records` anyway, but the per-row revision column drifts); or (b) accept the nested-SAVEPOINT semantics Cake 2 produces when the outer transaction is open, and add explicit detection of Changelog-driven `$dataSource->rollback()` that would roll back the controller's outer transaction wholesale. Path (a) is simpler; path (b) preserves revision history at the cost of more controller code. Decide before U3 lands.
- **OQ9. (Tester input.) Does the access-ci.org tester's anticipated request volume against the deployment fit within R17a's 20/hour per-instance default, or should the default be calibrated to their bulk-onboarding rate before V1 ships?** A custom UI doing initial onboarding of many CoPersons could plausibly need more than 20 credential operations per hour. OQ6 asks per-CO-vs-per-instance but does not ask whether the rate itself fits the named use case. Ask the tester on the requirements PR. If their pattern is bursty (initial-load then steady-state), consider either a higher default or a per-instance escape hatch for the bulk-load window.

## Sources and Research

Origin requirements: `docs/brainstorms/2026-05-28-krbauthenticator-rest-api-requirements.md`.

Plugin code touched by V1:

- `Plugin/KrbAuthenticator/Config/routes.php` — `Router::mapResources('KrbAuthenticator.krbs')` is already declared.
- `Plugin/KrbAuthenticator/Controller/KrbsController.php` — existing `ssr()`, `remind()`, `beforeFilter()`, `calculateImpliedCoId()`, `isAuthorized()`.
- `Plugin/KrbAuthenticator/Model/KrbAuthenticator.php` — `manage()` at `:270`, `reset()` at `:447`, HistoryRecord calls at `:411-420` and `:535-545` (the 11-arg bug).
- `Plugin/KrbAuthenticator/Model/Krb.php` — linkage-only model; no credential fields. `actsAs Provisioner` fires on row insert.
- `Plugin/KrbAuthenticator/Lib/lang.php` — `er.*` and `pl.*` key namespaces.

Upstream Registry references (read-only — V1 does not modify these):

- `app/Controller/Component/ApiComponent.php:202-252, 320-380, 393-490, 502-510` — REST request/response shape, `restResultHeader`, `getData`.
- `app/Controller/AppController.php:117-326` — REST auth flow, ApiUser HTTP basic, CO resolution via `parseCOID`.
- `app/Controller/SAMController.php:65-126, 165-376, 433-486, 496-535` — `beforeFilter`, `calculateParentPermissions` REST branch at `:306-318`, `generateHistory`, REST-aware `index()`.
- `app/Controller/StandardController.php` — generic REST add/edit/delete/view used as fallback; `permittedApiFilters` is consulted in `index()`.
- `app/Model/HistoryRecord.php:223-264` — `record()` 10-arg signature.
- `app/Lib/enum.php:28-132, 371-399` — `ActionEnum`, `HttpStatusCodesEnum` (missing 422 and 429), `p`-prefix-for-plugins convention at `:31`.
- `app/AvailablePlugin/PasswordAuthenticator/Controller/PasswordsController.php:125-153, 161-245` — canonical `is('restful')` branch shape.
- `app/AvailablePlugin/PasswordAuthenticator/Model/PasswordAuthenticator.php:144-328` — reference `manage($data, $actorCoPersonId, $actorApiUserId)` signature; `_begin/_commit/_rollback` transaction pattern.
- `app/AvailablePlugin/UnixCluster/Model/UnixClusterAccount.php:37-39` — `permittedApiFilters` example.
- `app/View/Standard/json/{index,view,add,edit,delete}.ctp` — shared REST view templates, copied verbatim into U2.

Versions confirmed by research: CakePHP 2.10.24 (`lib/Cake/VERSION.txt:20`); PHP 8.3.24 in upstream container (`container/registry/base/Dockerfile:19`); PECL `krb5` extension required.
