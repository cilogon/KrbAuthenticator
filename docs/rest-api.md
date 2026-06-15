# KrbAuthenticator REST API (V1)

This document is the integrator's reference for the REST surface added
by V1 of the KrbAuthenticator plugin. It mirrors the implementation
contract in `docs/plans/2026-05-28-001-feat-krbauthenticator-rest-api-plan.md`;
the plan is the source of truth and this document tracks what shipped.

## Endpoints

All endpoints are versioned through the existing Registry API path. The
authenticated caller is an `ApiUser` whose role must be `cmadmin` or
`coadmin` for the CO that owns the targeted `KrbAuthenticator` instance.

| Method | Path                                                          | Behavior                                                                      |
| ------ | ------------------------------------------------------------- | ------------------------------------------------------------------------------ |
| GET    | `/registry/krb_authenticator/krbs.json?krbauthid=N`           | List rows under one `KrbAuthenticator`. 200 with empty `Krbs` if none.        |
| GET    | `/registry/krb_authenticator/krbs.json?krbauthid=N&copersonid=M` | Same, scoped to one CO Person.                                                |
| GET    | `/registry/krb_authenticator/krbs.json?krb_authenticator_id=N` | Same listing via the `permittedApiFilters` route. See the gotcha below.       |
| GET    | `/registry/krb_authenticator/krbs/{id}.json`                  | Read one Krb row by ID.                                                       |
| POST   | `/registry/krb_authenticator/krbs.json`                       | Set the Kerberos password AND insert the linkage row. 201 + `Location`.       |
| PUT    | `/registry/krb_authenticator/krbs/{id}.json`                  | Change the Kerberos password for an existing row. 200.                        |
| DELETE | `/registry/krb_authenticator/krbs/{id}.json`                  | 405 `Method Not Allowed` with `Allow: GET, POST, PUT`. No state change.       |

V1 does not expose credential removal via REST. Deprovisioning continues
through the Registry UI; a follow-up endpoint will decide between
deleting the KDC principal, expiring it, or removing only the linkage
row.

### URL disambiguation gotcha

`?krbauthid=N` and `?krb_authenticator_id=N` look like aliases but fire
in **different** code paths inside Registry:

- `?krbauthid=N` is handled by `SAMController::index()`'s REST branch
  (overridden by `KrbsController::index()` so an empty result is 200
  with an empty `Krbs` array instead of 404). The form composes with
  `?copersonid=M` to scope by both.
- `?krb_authenticator_id=N` is handled by `StandardController::index()`
  via `Krb::$permittedApiFilters`. This form does **not** compose with
  `?copersonid=M` — `copersonid` is silently ignored on this branch.

Prefer `?krbauthid=N[&copersonid=M]` for new integrations.

## Expected workflow

A typical integration follows the lifecycle below. Read this section
before the endpoint reference if you are building against the API for
the first time — the GET-returns-empty starting state surprises most
new integrators.

1. **GET** the targeted CO Person's existing rows:

   ```
   GET /registry/krb_authenticator/krbs.json?krbauthid=N&copersonid=M
   ```

   On a fresh integration the response is `200 OK` with an empty
   `Krbs` array. This is the expected initial state: the `cm_krbs`
   table was effectively unused in V0 (no UI form or controller path
   wrote rows to it), so a deployment that has only ever set passwords
   via the Registry UI has no rows to return. The KDC principal can
   still exist and the CO Person's authenticator status can still be
   `Set` — the empty list does not contradict either fact. It just
   means no caller has explicitly created a `cm_krbs` linkage record
   yet.

2. **POST** to create the linkage row and set the KDC password in one
   call:

   ```
   POST /registry/krb_authenticator/krbs.json
   ```

   The request body carries `KrbAuthenticatorId`, `Person.Id`, and the
   matched `Password`/`Password2` pair. On success the response is
   `201 Created` with a `Location` header pointing at the new row
   (e.g. `Location: /registry/krb_authenticator/krbs/42.json`). The
   KDC `changePassword` call and the `cm_krbs` row insert are
   committed together; the audit log records `pKKI` (intent) and
   `pKKS` (success) attributed to the calling API user. A subsequent
   GET against the same `krbauthid` + `copersonid` now returns the
   row.

   POSTing for a CO Person who already has a row returns `409
   Conflict` with `Location` pointing at the existing row — the
   integrator should switch to PUT against that ID rather than retry
   the POST.

3. **PUT** to change the password on an existing row:

   ```
   PUT /registry/krb_authenticator/krbs/{id}.json
   ```

   The `cm_krbs` row is not modified — only the KDC's password state
   changes. The audit log records another `pKKI`/`pKKS` pair. The
   same POST or PUT replayed with the same password is naturally
   idempotent per R15: the KDC end state is identical, no duplicate
   row is created on POST (409 instead), and the integrator can
   safely retry on a transient failure.

4. **DELETE** returns `405 Method Not Allowed` (R6). V1 does not
   expose credential removal via REST; deprovisioning continues
   through the Registry UI.

## Request payload (POST and PUT)

The wire format matches the Registry-wide REST convention:

```json
{
  "Krbs": [
    {
      "Version": "1.0",
      "KrbAuthenticatorId": 1,
      "Person": {"Type": "CO", "Id": 104269},
      "Password": "...",
      "Password2": "..."
    }
  ]
}
```

`Person.Type` must be `CO`. Both `Password` and `Password2` are
required and must be equal — a mismatch returns 422 before any KDC
interaction. The server ignores any other field in the payload, in
particular any field that purports to set the principal name directly.
The principal is always resolved server-side from the persisted
`(KrbAuthenticator, CoPerson)` pair.

For PUT, the loaded `cm_krbs` row's `krb_authenticator_id` and
`co_person_id` are authoritative. A payload that names a different
`KrbAuthenticatorId` or `Person.Id` returns 422 rather than silently
rerouting the KDC change.

## Example requests

Both examples authenticate the caller as an `ApiUser` using HTTP Basic
(`-u USERNAME:PASSWORD`). The ApiUser must hold `cmadmin` or `coadmin`
for the CO that owns the targeted `KrbAuthenticator` instance. Replace
`registry.example.org`, the credentials, and the numeric IDs with
deployment-specific values.

### GET — list Krb rows under a KrbAuthenticator + CoPerson

```
curl -sS -i \
  -u 'USERNAME:PASSWORD' \
  -H 'Accept: application/json' \
  'https://registry.example.org/registry/krb_authenticator/krbs.json?krbauthid=N&copersonid=M'
```

Successful response is `200 OK` with a body of
`{"ResponseType":"Krbs","Version":"1.0","Krbs":[ ... ]}`. An empty
`Krbs` array (rather than 404) indicates no matching rows; this is the
intentional V1 behavior. The `.json` URL suffix is what flags the
request as REST to `ApiComponent` (it adds a `restful` detector keyed on
the URL extension); without it Registry would attempt to render the UI
view. The `Accept: application/json` header is good practice for
proxies and observability but is not what triggers the REST branch.

### POST — set the Kerberos password and create the linkage row

```
curl -sS -i \
  -u 'USERNAME:PASSWORD' \
  -X POST \
  -H 'Accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{"Krbs":[{"Version":"1.0","KrbAuthenticatorId":1,"Person":{"Type":"CO","Id":34567},"Password":"new-password-here","Password2":"new-password-here"}]}' \
  'https://registry.example.org/registry/krb_authenticator/krbs.json'
```

`KrbAuthenticatorId: 1` matches what most single-tenant deployments
end up with (the table is small and the first row's auto-increment ID
is 1), but it is NOT a synonym for `cm_authenticators.id`. The two are
different tables — see the URL-disambiguation gotcha above for the
same trap on the GET path. Confirm against the deployment with
`SELECT id, authenticator_id FROM cm_krb_authenticators;` before
running this in production. Replace `34567` with the target CO Person
ID and the password values with the credential to set. `Password` and
`Password2` must both be present and equal.

Successful response is `201 Created` with a `Location` header pointing
at the newly created row, e.g.
`Location: /registry/krb_authenticator/krbs/42.json`. On `409 Conflict`
a `cm_krbs` row already exists for this `(KrbAuthenticator, CoPerson)`
pair and the `Location` header points at it — switch to PUT against
that ID to change the password.

### PUT — change the Kerberos password on an existing Krb row

```
curl -sS -i \
  -u 'USERNAME:PASSWORD' \
  -X PUT \
  -H 'Accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{"Krbs":[{"Version":"1.0","Password":"new-password-here","Password2":"new-password-here"}]}' \
  'https://registry.example.org/registry/krb_authenticator/krbs/ID.json'
```

(The `-d '...'` form is preferred over a heredoc because it survives
copy-paste across editors and terminals without depending on the
heredoc terminator landing on its own line. The JSON contains no single
quotes, so wrapping it in single quotes for the shell is safe.)

Successful response is `200 OK` and an empty body. Both `Password` and
`Password2` must be present and equal; mismatch returns `422`. The
loaded `cm_krbs` row's `krb_authenticator_id` and `co_person_id` are
authoritative — supplying matching `KrbAuthenticatorId` and
`Person:{Type:"CO",Id:M}` fields in the body is accepted but optional;
supplying values that disagree with the loaded row returns `422` rather
than silently rerouting the change to a different principal.

`Content-Type: application/json` is required so Registry parses the
body as JSON. The REST branch is selected by the `.json` URL suffix,
not by the `Accept` header, but sending `Accept: application/json` is
still good practice.

## Response status codes

| Status | When                                                                                  | Body key                                          |
| ------ | ------------------------------------------------------------------------------------- | ------------------------------------------------- |
| 200    | GET success; PUT success                                                              | (none, or `Krbs` array for GET)                   |
| 201    | POST success                                                                          | (none; `Location` header points at the new row)   |
| 403    | Authorization (`cmadmin`/`coadmin` for the right CO) failed, or actor==target         | `actor.target.forbidden` / `co.mismatch`          |
| 404    | PUT against a non-existent `Krb` row                                                  | `row.missing`                                     |
| 405    | DELETE                                                                                | `method.not.allowed`                              |
| 409    | POST when a `Krb` row already exists for the `(authenticator, person)` pair           | `row.exists` (with `Location: ...{id}.json`)      |
| 422    | Missing/mismatched/length-violating payload; KDC policy reject; tampered IDs (PUT)    | `validation` / `kdc.policy` / `kdc.policy.reuse`  |
| 429    | One of the three rate-limit windows breached                                          | `rate.limited` (with `Retry-After: N` header)     |
| 500    | KDC unreachable / changePassword failed; audit preflight assertion failed             | `kdc.failed` / `audit.preflight` / `kdc.divergence` |
| 503    | `cm_krb_rate_limit_counters` migration not yet applied                                | `ratelimiter.unavailable`                         |

Body keys are the `er.krbauthenticator.rest.<key>` suffix from
`Lib/lang.php`. Response bodies are intentionally minimal so no
principal name, KDC hostname, exception fragment, or payload material
appears in the wire response (R14a). Raw exception text reaches only
the Registry's PHP error log via `$this->log()`.

The `kdc.policy` and `kdc.policy.reuse` keys differentiate KDC-side
password rejections from KDC infrastructure failures. The classifier
in `KrbsController::restClassifyKdcRuntime()` inspects the kadm5 error
string surfaced by PECL krb5 and matches known substrings (e.g.
`reuse`, `password history`, `too short`, `dictionary`,
`character class`). Recognized reuse messages route to
`kdc.policy.reuse`; other recognized policy rejections route to
`kdc.policy`; anything unrecognized stays at `500 + kdc.failed` so the
default response is unchanged for true KDC failures.

## Rate limits

Three layered fixed-window limits gate every accepted POST/PUT. Defaults
are set in `KrbAuthenticator::$restRateLimitDefaults`; per-instance
overrides live on the `cm_krb_authenticators` columns
`rest_rate_limit_per_credential_per_minute`,
`rest_rate_limit_per_target_per_hour`, and
`rest_rate_limit_per_instance_per_hour` (NULL means "use the default").

| Scope          | Key                                                | Window  | Default | Override column                                    |
| -------------- | -------------------------------------------------- | ------- | ------- | -------------------------------------------------- |
| per_credential | ApiUser ID                                         | 60 s    | 5       | `rest_rate_limit_per_credential_per_minute`        |
| per_target     | `{krb_authenticator_id}:{co_person_id}`            | 3600 s  | 2       | `rest_rate_limit_per_target_per_hour`              |
| per_instance   | `krb_authenticator_id`                             | 3600 s  | 20      | `rest_rate_limit_per_instance_per_hour`            |

Breach returns 429 with `Retry-After` set to the wall-clock seconds
until the relevant window expires. Recovery is privileged: the
per-target counter is NOT incremented when an attempt routes through
the `pKKF` (KDC failure) or `pKKD` (divergence) branches, so a
legitimate replay after a transient failure cannot exhaust the budget.

Per-instance defaults are operator-tunable from the KrbAuthenticator
edit view in the Registry UI. The three form rows are labeled "REST
API Per-Credential Limit (per minute)", "REST API Per-Target Limit
(per hour)", and "REST API Per-Instance Limit (per hour)" and accept
any integer in the range 0–100000. Leaving a field blank preserves
the code-side default. Setting any of the three to `0` immediately
rejects REST API password changes against that instance — a documented
kill-switch state surfaced in the form's help text and visible in the
read-only view as a plain `0` (an unset field renders as `5 (default)`
/ `2 (default)` / `20 (default)` instead).

### Fixed-window boundary effect

The windows are fixed (`floor(time() / window) * window`), not sliding.
An attacker who knows wall-clock can issue a burst that straddles the
boundary and effectively double the configured rate (e.g., 5 hits at
14:59:55 + 5 hits at 15:00:00 against a 5/minute cap = 10 commits in
5 seconds). Operators choosing defaults should treat the effective cap
as `configured / 2` for blast-radius bounding. Sliding-window
arithmetic is a follow-on hardening.

### Counter table growth

`cm_krb_rate_limit_counters` accumulates one row per
`(scope, key, window_start_epoch)` and has no GC in V1. Expected steady
state: ~1440 rows/day at the per-credential scope for one busy
credential. A periodic prune job (delete rows where
`window_start_epoch < now - max_window`) is required before sustained
production load. Operators should add the table to their DB-size watch
list at V1 deploy time. The plan documents the trigger thresholds for
the prune-task follow-on.

## Audit (HistoryRecord) action codes

Every POST and PUT writes at least one `cm_history_records` row
attributed to the calling ApiUser via `actor_api_user_id`. The four new
action codes follow the documented plugin-prefix convention `p`:

| Code   | Constant                                              | Written when                                                                   |
| ------ | ----------------------------------------------------- | ------------------------------------------------------------------------------ |
| `pKKI` | `KrbAuthenticatorActionEnum::KrbKdcChangeIntent`      | Immediately before the KDC `changePassword` call. Autocommit; durable on crash. |
| `pKKS` | `KrbAuthenticatorActionEnum::KrbKdcChangeSucceeded`   | KDC succeeded AND the Registry-side write committed.                            |
| `pKKF` | `KrbAuthenticatorActionEnum::KrbKdcChangeFailed`      | KDC call threw before any state change.                                         |
| `pKKD` | `KrbAuthenticatorActionEnum::KrbKdcRegistryDivergence`| KDC committed but the Registry-side write failed; reconciliation may be needed. |

The `comment` column contains only `_txt()`-keyed strings and opaque
numeric IDs. Password material, principal names, KDC hostnames, and
exception text are never written there (R14b).

### GROUP BY queries

Dashboards or audit queries that GROUP BY `action` will see four new
distinct codes appear at V1 deploy time. Existing dashboards keyed on a
fixed code list — including any filter on `ActionEnum::AuthenticatorEdited`
— will undercount V1 REST writes unless updated to UNION-in `pKKI`,
`pKKS`, `pKKF`, and `pKKD`.

### Dangling pKKI

A `pKKI` row with no matching `pKKS`/`pKKF`/`pKKD` for the same
`(co_person_id, krb_authenticator_id)` within the same request window
means "outcome unknown — manual review required," NOT "divergence
confirmed." The expected steady-state rate is zero; under PHP fatal
errors the rate is one per fatal. Operators should treat any dangling
pKKI as a triage event.

### Audit-log integrity caveat

`cm_history_records` rows are not signed or hash-chained. Tamper
resistance is bounded by database access control. V1 does not change
this posture, but the new intent/outcome pattern relies on the audit
trail to detect divergence — DB write access should be treated as a
tier-1 security boundary.

### HistoryRecord pre-V1 NULL `actor_api_user_id`

Rows written by the pre-V1 11-arg bug at
`Plugin/KrbAuthenticator/Model/KrbAuthenticator.php:535-545` have NULL
`actor_api_user_id` even when an API user invoked `reset()`. The
original actor identity is not recoverable from those rows; no backfill
is performed. Treat pre-V1 NULL `actor_api_user_id` as "unknown" rather
than "no API user."

## Idempotency and divergence handling

POST and PUT are naturally idempotent at the credential-set
contract: the same `(krb_authenticator_id, co_person_id, password)`
re-sent produces the same observable end state (R15). After a `pKKD`
(KDC committed, Registry write failed) outcome, the caller can replay
the same POST/PUT to converge state — the per-target rate limit will
not punish the replay (the divergent attempt did not increment the
per-target counter).

V1 does not implement explicit `Idempotency-Key` header handling;
natural idempotency covers the contract. Explicit key infrastructure
is a follow-on if operational signal warrants it.

### Provisioner timing on the divergence-replay path

If the first POST diverged (KDC committed, row insert failed → `pKKD`,
no row), a replay completes the row insert on the second attempt. The
`Provisioner` behavior fires on the REPLAY, not on the original KDC
commit, so a provisioner that timestamps "first observed" records the
replay time rather than the actual credential-change time. Provisioner
targets needing event-time accuracy should consult the HistoryRecord
trail instead.

## Deployment security checklist

The REST surface is meaningful at the response-body sanitization layer
only if the deployment also closes the surrounding ambient-leakage
vectors. Verify before enabling REST writes:

- TLS enforced on the REST endpoint at the web-server layer.
- DebugKit plugin disabled in production (it caches request data when
  Cake's `Configure debug >= 1`).
- Cake 2's default exception handler does NOT serialize
  `$this->request->data` into the error log; if a custom handler is
  installed, it MUST scrub `Krb.password` and `Krb.password2` before
  logging.
- Apache `LogLevel` not raised to `debug`; `mod_dumpio` off.
- Nginx `access_log` does not capture request bodies.
- APM agents (NewRelic, Datadog, Sentry) configured to suppress
  request bodies on POST/PUT to `/registry/krb_authenticator/krbs.json`.
- Reverse proxy or WAF body-capture rules off for this endpoint.
- PHP `log_errors=On` with `display_errors=Off` (default) prevents
  request bodies from landing in PHP's `error_log` on fatals; verify
  before enabling REST writes.
- NTP keeps host clocks synchronized — the rate-limit window arithmetic
  assumes clock-drift across multi-worker hosts is smaller than the
  smallest configured window (60 s).
- Web-server / load-balancer access logs MUST record HTTP 401 responses
  against `/registry/krb_authenticator/krbs.json` with source IP and
  timestamp. Failed-authentication attempts (HTTP Basic against the
  ApiUser layer) produce neither a HistoryRecord (the actor was never
  resolved) nor a rate-limit counter increment (the limiter runs
  post-auth). Without web-server-layer 401 logging, credential-stuffing
  attempts against the REST endpoint are forensically invisible.

## Migration prerequisites

V1 adds:

- A new table `cm_krb_rate_limit_counters`.
- Three NULL-allowed columns on `cm_krb_authenticators`:
  `rest_rate_limit_per_credential_per_minute`,
  `rest_rate_limit_per_target_per_hour`,
  `rest_rate_limit_per_instance_per_hour`. No backfill SQL is required;
  the code-side defaults apply at read time when the column is NULL.
- A unique compound index `krbs_i3` on
  `cm_krbs(krb_authenticator_id, co_person_id)`. **Pre-existing
  duplicate rows must be deduplicated before this migration runs.**
  Check with:

  ```sql
  SELECT krb_authenticator_id, co_person_id, COUNT(*)
    FROM cm_krbs
   GROUP BY 1, 2
   HAVING COUNT(*) > 1;
  ```

**After the migration runs, clear Cake's model schema cache.** Cake 2
caches each model's column metadata in `app/tmp/cache/models/cake_model_default_*`.
If anything left a stale cache for `cm_krb_authenticators` or
`cm_krb_rate_limit_counters` — for instance, the file was created when
the table or column was missing earlier in the deploy cycle — the REST
preflight returns 503 and the edit-view form silently no-ops on the
new fields, even though the schema is now correct. The fix is one
command:

```
rm -f app/tmp/cache/models/cake_model_default_*
```

Cake regenerates the cache on the next request. Required on TEST
2026-06-11 deploy; expect to be required on every fresh deploy with
new columns or new tables.

Rollback to V0 leaves the new table and columns in place (Cake 2
schema-XML does not auto-drop) and leaves the new `pKKI`/`pKKS`/`pKKF`/
`pKKD` HistoryRecord rows present but unrendered by older UI code. Both
are acceptable residual states.

If the deployment uses the manual `db_acl.php` path rather than the
plugin's `setup()` / re-enable hook, the migration must run before V1
code begins serving REST traffic — the schema preflight in the REST
POST/PUT branches will return 503 until then.
