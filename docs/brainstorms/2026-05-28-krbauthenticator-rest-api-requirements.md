# KrbAuthenticator REST API — Requirements

**Date:** 2026-05-28
**Status:** Draft (reviewed 2026-05-28)
**Scope:** Standard

## Context

The `KrbAuthenticator` plugin (COmanage Registry v4.x) was forked from `PasswordAuthenticator` to let users and admins manage a Kerberos principal password instead of a simple in-database password. `PasswordAuthenticator` exposes a REST API so a privileged Registry API user can manage simple passwords for a CoPerson; `KrbAuthenticator` does not currently provide a working REST surface.

An external tester at access-ci.org attempted to call the plugin via REST and reported:

> `GET https://registry.access-ci.org/registry/krb_authenticator/krbs.json?copersonid=104269`
> `Client error '404 CO Not Found'`
>
> Adding `&coid=2` produced the same result. The tester was using production COmanage API credentials that work against other Registry REST endpoints.

The tester is building a custom UI on top of Registry's data model and only leveraging Registry for storage and credential operations — they will not use the Registry UI for routine flows. They will likely also want, in a near-term follow-on, to trigger the existing self-service password reset (SSR) email mechanism programmatically.

### What already exists

- `Config/routes.php` already declares `Router::mapResources('KrbAuthenticator.krbs')`, so REST routing is wired.
- `Controller/KrbsController.php` extends `SAMController`, which provides REST-aware `index`/`add`/`edit`/`delete`/`view` via the inherited `StandardController`.
- `Model/KrbAuthenticator.php::manage()` is the existing entry point that talks to the KDC (`$principalObj->changePassword()`); it is invoked from the UI's `manage` and `ssr` flows. It is **not** called from the inherited REST add/edit path.
- `Model/KrbResetToken.php::generateRequest()` is the existing entry point that issues an SSR token and dispatches the email; today it is invoked from the UI `ssr`/`remind` paths only.

### Why the reported call fails

`SAMController::index()` enters its REST branch only when a parent-flag query string is present (e.g., `?krbauthid=N`); otherwise it falls through to `parent::index()`, which requires a determinable CO. `?copersonid=104269` alone satisfies neither path. `&coid=2` interacts with the CO-determination chain but not with the controller's restful filter. This is a URL-pattern / surface-area problem, not a routing problem.

### Why a straight "mirror PasswordAuthenticator" is not enough

`Password` rows store the hashed credential — the row IS the credential, so the inherited REST write path is correct for that plugin. `Krb` rows store only `(co_person_id, krb_authenticator_id)` linkage; the actual credential lives in the KDC and is set by `KrbAuthenticator::manage()`. A plain inherited REST `POST /krbs.json` would write a Krb row and never touch the KDC, silently breaking the contract.

## Goals

1. A privileged Registry API user can set and change a CoPerson's Kerberos principal password via REST, with the password actually being changed in the KDC.
2. A privileged Registry API user can read which CoPersons have Krb records under a given KrbAuthenticator instance, enough to drive a custom UI's "set vs. change" decision.
3. The reported `404 CO Not Found` case has a documented, working URL pattern.
4. REST-driven removal of Kerberos credentials is deferred to a follow-on with explicit lifecycle semantics, rather than implemented in V1.

## Non-Goals (V1)

- Auto-generated passwords (`generate()` parity). `KrbAuthenticator` has no auto-generate code path today; adding one is a feature, not REST plumbing.
- A distinct `status()` endpoint. Whatever metadata `status()` would return is folded into the GET (view) response.
- DELETE over REST. Removal of a Krb record (and any KDC-side cleanup) continues to go through the Registry UI in V1.
- Refactoring shared REST behavior between `PasswordsController` and `KrbsController`.

## Users

- **Privileged Registry API user** (`cmadmin` or `coadmin` for the relevant CO) — the only role that may invoke these endpoints. Matches `SAMController::calculateParentPermissions()` defaults in REST mode.
- **CoPerson whose credential is being managed** — affected but not the caller. Self-service flows continue to go through the UI / SSR for V1.

## Success Criteria

- The tester at access-ci.org can issue a REST call from their custom UI that:
  1. Reads whether a given CoPerson has a Krb record (GET).
  2. Sets a new Kerberos password (POST), and verifies via `kinit` that the new password works against the configured KDC.
  3. Changes an existing Kerberos password (PUT), with the same `kinit` verification.
- A REST `DELETE` against a Krb resource returns `405 Method Not Allowed`; existing Krb row and KDC principal are unchanged.
- The Registry UI flows (`manage`, `ssr`, `remind`) are unchanged in behavior.
- The tester's originally-reported URL produces a clear error or documented redirect to the correct URL pattern (not a confusing `404 CO Not Found`).

## V1 Behavior

### Endpoints

| Verb   | Path                                                | Behavior                                                                                  |
|--------|-----------------------------------------------------|-------------------------------------------------------------------------------------------|
| GET    | `/registry/krb_authenticator/krbs.json`             | Index Krb rows scoped by `krbauthid` (and optionally `copersonid`). Metadata only.        |
| GET    | `/registry/krb_authenticator/krbs/{id}.json`        | View a single Krb row. Metadata only.                                                     |
| POST   | `/registry/krb_authenticator/krbs.json`             | Set the Kerberos password for the given `(krb_authenticator_id, co_person_id)`. Touches the KDC. Returns `409 Conflict` with a `Location` header if a Krb row already exists for that pair (caller should `PUT` instead). |
| PUT    | `/registry/krb_authenticator/krbs/{id}.json`        | Change the Kerberos password for an existing Krb record. Touches the KDC. Returns `404 Not Found` if the row does not exist. |
| DELETE | `/registry/krb_authenticator/krbs/{id}.json`        | `405 Method Not Allowed`. No DB or KDC change.                                            |

### Request payload (POST / PUT)

REST POST and PUT payloads must include both `password` and `password2` (where `password2 == password`). This preserves parity with `KrbAuthenticator::manage()`'s existing validation at `Model/KrbAuthenticator.php:316` so the REST path can route through `manage()` without modifying its signature or branching its validation logic on caller context — keeping the no-refactor non-goal intact. Callers should treat `password2` as a fixed duplication of `password` for API ergonomics; the field is required for transport, not as an independent secret.

### Request-side validation

REST POST and PUT apply the same `min_length` / `max_length` constraints `KrbAuthenticator::manage()` already enforces at `Model/KrbAuthenticator.php:302–313` (sourced from the KrbAuthenticator instance's configured `min_length` / `max_length`, defaults 8 / 64). Length failures return `422 Unprocessable Entity` with a sanitized message before any KDC call. KDC-policy rejections (KDC returns "password too weak" or equivalent) also surface as `422` with a sanitized message — see KDC interaction below.

### KDC interaction

- POST and PUT route through `KrbAuthenticator::manage()` (or a REST-context-aware equivalent of its KDC-changing logic) so the principal's password is actually set in the configured KDC.
- The `passwordc` (current-password) check that `manage()` enforces when actor == CoPerson does not apply — the REST caller is an API user, never the CoPerson themselves.
- **Actor / target guard.** If the resolved actor CO Person ID equals the target `co_person_id` on the REST POST or PUT, the request is rejected with `403 Forbidden` before any KDC call. A `cmadmin` or `coadmin` who is also a CO Person in the same CO must not use REST to change their own Kerberos password (the UI's `passwordc` defense is the path for that case). This guard runs even though `passwordc` is otherwise skipped on REST.
- **KDC failure (KDC unreachable, principal missing, KDC-policy rejection, etc.):** the REST response is an appropriate 4xx/5xx with a **sanitized** message. Sanitization is required — KDC error strings must not echo the supplied password value or any principal-bearing exception text that could include credential fragments. No Krb row is written or modified on KDC failure.
- **KDC-success-then-Registry-failure (the harder direction):** if the KDC `changePassword` call succeeds and a subsequent Registry-side write or response then fails (DB exception, transient error, HistoryRecord failure, client disconnect after KDC commit), the KDC password change is **not** rolled back (it is not reversible without the prior password, which the caller already discarded). V1 commits to an **idempotent-retry contract**: the same `(krb_authenticator_id, co_person_id, password)` POST/PUT replayed by the caller produces either a fresh successful KDC change (the principal now has the same password as the prior intent) or a no-op success path. The Registry layer must record a compensating HistoryRecord entry of a distinct action type when this divergence is detected, so post-incident reconciliation has a forensic trace.

### Read responses

GET responses return Krb row metadata only — `id`, `co_person_id`, `krb_authenticator_id`, created/modified timestamps as appropriate to Registry's standard REST envelope. No password material is ever returned (and none exists on the row).

### Permissions

REST mode is restricted to `cmadmin` or `coadmin` for the CO that owns the KrbAuthenticator instance. This is the existing `SAMController` default and is not relaxed.

### Rate limiting

REST POST and PUT enforce two layered rate limits:

- **Per-API-credential:** at most N requests/minute across all targets (initial value: 5/minute; tune per deployment in `KrbAuthenticator` configuration).
- **Per-target principal** (keyed on `(krb_authenticator_id, co_person_id)`): at most M requests/hour (initial value: 2/hour).

A breach of either limit returns `429 Too Many Requests` with a `Retry-After` header. The intent is to bound damage from a compromised `cmadmin` API token and to keep programmatic callers from thrashing the KDC. GET endpoints are not rate-limited beyond Registry's existing API-wide controls.

### Audit (HistoryRecord)

Every REST POST and PUT — successful or failed — produces a `HistoryRecord` entry attributed to the calling API user (`actor_api_user_id`, parallel to how `SAMController::generateHistory()` attributes REST callers):

- **Successful KDC change:** `ActionEnum::AuthenticatorEdited` with a change string identifying the KrbAuthenticator instance and the target CO Person.
- **KDC failure:** a distinct action type (e.g., `ActionEnum::AuthenticatorEditFailed` if available, or `ActionEnum::AuthenticatorEdited` with a failure-marker change string if not) so the failure trail is queryable.
- **KDC-success / Registry-fail divergence (per the compensating-action requirement above):** a third distinct marker so reconciliation tooling can detect this case specifically.

This commitment resolves the prior "audit trail on KDC failure" deferral.

### URL pattern / CO resolution

The expected REST index URL pattern matches `PasswordAuthenticator`: `?krbauthid=N` (the per-instance KrbAuthenticator ID), optionally with `&copersonid=M`. Documentation of this pattern is part of V1's deliverable so the tester's reported failure has a working URL. Whether the bare `?copersonid=X` form (without `krbauthid`) should also be accepted is captured in Open Questions below — its resolution is tied to the V1-scope question raised in review.

## Anticipated Follow-On (not built in V1)

- **`issue-reset-token` endpoint.** Authenticated REST call that causes `KrbResetToken::generateRequest()` to issue a token and dispatch the existing reset email to the CoPerson, without the API caller ever seeing the token. V1 design must not make this harder to add later (do not name the controller, request shapes, or auth model in ways that exclude a future explicit action). Single-use, expiry, and storage requirements for the token will be captured when this is planned.
- **Credential-removal endpoint with explicit lifecycle semantics.** Because V1 rejects REST DELETE and the tester does not use the Registry UI for routine flows, an integration-driven deprovisioning path is needed. The follow-on must answer: does removal delete the KDC principal, only expire it, or only remove the Registry linkage row? Each choice has different implications for `kadmin`-managed environments vs. Registry-managed environments.

## Deferred Decisions (for planning, not for this document)

- Exact JSON envelope and field set for GET responses (defer to Registry REST conventions; if PasswordAuthenticator's REST envelope is documented, adopt by reference).
- Exact body content for the 405 returned on DELETE (status code alone satisfies the success criterion).

## Dependencies and Assumptions

- Registry's REST authentication and `SAMController` REST permission model are unchanged.
- The configured KDC server (`Server::KdcServer`) is reachable from the Registry host when REST set/change operations run; the existing `KrbAuthenticator::manage()` failure modes are acceptable as REST failure modes.
- The tester's API credential is a Registry API user with `cmadmin` or `coadmin` role for the relevant CO. (The original 404 is consistent with role/scoping issues being secondary to the URL-pattern problem; both must hold.)
- Registry UI flows (`manage`, `ssr`, `remind`) remain the sole path for credential removal and for SSR initiation in V1.
- **Transport security:** the Registry deployment enforces TLS on the REST endpoint. The plugin assumes and does not re-verify transport security. If a deployment runs without TLS, plaintext Kerberos passwords transit in POST/PUT bodies — V1 considers that an unsupported configuration.
- **Logging hygiene:** the Registry application stack (web server, framework, error reporters) does not capture POST/PUT request bodies for `/krb_authenticator/krbs.json`. V1 assumes this at deploy time. If the deployment logs request bodies, plaintext Kerberos passwords land in logs — also an unsupported configuration.

## References

- `Config/routes.php`
- `Controller/KrbsController.php`
- `Controller/KrbAuthenticatorsController.php`
- `Model/Krb.php`
- `Model/KrbAuthenticator.php` — see `manage()`, `reset()`, `status()`
- `Model/KrbResetToken.php` — see `generateRequest()`, `validateToken()`
- COmanage Registry: `app/Controller/SAMController.php` — see `index()`, `calculateImpliedCoId()`, `calculateParentPermissions()`, `generateHistory()`
- COmanage Registry: `app/AvailablePlugin/PasswordAuthenticator/Controller/PasswordsController.php` — reference REST shape
- COmanage Registry: `app/AvailablePlugin/PasswordAuthenticator/Model/PasswordAuthenticator.php` — reference `manage()` REST handling

## Deferred / Open Questions

### From 2026-05-28 review

The following questions surfaced during ce-doc-review and have been deferred for resolution outside this document. They are not implementation details — each requires either external input (the tester) or a product judgment that should land before planning commits to V1's endpoint shape.

- **[P1, chain root] Premise check: is direct REST POST/PUT actually the right V1 shape?**
  The Context section itself concludes the original failure was a URL-pattern problem ("not a routing problem"), yet V1 has expanded to a full POST/PUT credential-mutating REST surface that is inferred from "the tester is building a custom UI," not from a stated POST/PUT failure. A documentation-only V1 (publish the working URL pattern + bring the `issue-reset-token` follow-on into V1) may meet Goals 1, 3, and 4 with no new credential-handling code path and a smaller security surface.
  *Action:* confirm directly with the tester whether they explicitly want direct POST/PUT credential-setting in V1, or whether documented URL + accelerated SSR-trigger would meet their integration need. Record the answer in Context and adjust Goals and V1 Behavior if the scope shifts. The three questions below cascade from this one — they resolve automatically if this premise is rejected.

- **[P2, cascades from premise check] Goal 3 vs. Success Criteria mismatch on the 404 fix.**
  Goal 3 promises "a documented, working URL pattern" for the originally-reported 404 case, but the Success Criteria softens this to "a clear error or documented redirect" — two different commitments. If V1 keeps full POST/PUT, this needs a single clear bar; if V1 narrows to documentation+SSR, it dissolves.

- **[P2, cascades from premise check] Should `?copersonid=X` alone (without `krbauthid`) be accepted as an index filter?**
  This is what the tester actually tried. If V1 keeps full POST/PUT, this is the lowest-cost way to make their original URL work; if V1 narrows, it can be a documentation-only fix ("use `?krbauthid=N&copersonid=M` instead").

- **[P2, cascades from premise check] Validate the SSR follow-on as actual near-term demand.**
  The doc treats the `issue-reset-token` endpoint as anticipated but doesn't record whether the tester confirmed it. If they did confirm and they don't actually need POST/PUT in V1, bringing SSR-trigger into V1 (and dropping POST/PUT) is a cleaner integration. If they didn't confirm, the V1 design constraint to "not preclude" it should be dropped.
