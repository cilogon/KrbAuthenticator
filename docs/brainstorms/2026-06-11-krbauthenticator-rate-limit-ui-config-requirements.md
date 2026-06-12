# KrbAuthenticator REST Rate-Limit UI Configurability — Requirements

**Date:** 2026-06-11
**Type:** Feature brainstorm
**Status:** Ready for planning
**Predecessor:** `docs/brainstorms/2026-05-28-krbauthenticator-rest-api-requirements.md`
**Predecessor plan:** `docs/plans/2026-05-28-001-feat-krbauthenticator-rest-api-plan.md` (V1, shipped)

---

## Context

V1 of the KrbAuthenticator REST API (shipped on branch `fix/rest-api-manage`, deployed to TEST 2026-06-10) added three rate-limit tunables to the `cm_krb_authenticators` table:

- `rest_rate_limit_per_credential_per_minute` (default 5)
- `rest_rate_limit_per_target_per_hour` (default 2)
- `rest_rate_limit_per_instance_per_hour` (default 20)

The columns are NULL-allowed; code-side defaults are applied at read time by `KrbAuthenticator::restRateLimits($id)` and consumed by `KrbsController::restAdd()` / `restEdit()` per request. Validation is `range(0, 100000)`.

V1 shipped without a UI surface for the three new columns. An operator who wants to override a default on a specific instance has to edit the database directly (`UPDATE cm_krb_authenticators SET ...`). This brainstorm captures the requirements for surfacing those three columns in the existing KrbAuthenticator edit/add view so the override is a normal operator action.

## Goals

1. A `cmadmin` / `coadmin` who can already edit a KrbAuthenticator instance can also set, change, or clear each of the three rate-limit values from the same form, with no DB shell required.
2. The V1 "NULL means use code-side default at read time" property is preserved in the UI: a blank input round-trips as NULL in the database, not as the default integer.
3. The kill-switch behavior already inherent in the model (any of the three set to `0` causes the very first matching request to exceed the window count and return 429) is documented in the form's help text and becomes an operator-facing feature rather than an implementation accident.

## Non-Goals

- Per-CO or per-API-credential tunables. The per-instance row remains the only configuration surface. (Already deferred in the V1 plan's Scope Boundaries.)
- A distinct "no limit / unlimited" sentinel separate from a high integer. `100000` is effectively unlimited at any realistic traffic; doubling the validation surface for an unobservable user gain is not justified.
- A separate read-only-for-coadmin / writable-only-for-cmadmin permission split on these fields. Existing `permissions['edit']` for KrbAuthenticator gates the whole form; the rate-limit fields inherit that gate uniformly.
- Visual grouping (subheading row, collapsible "Advanced" section, tabs). The existing form is flat; new fields slot into the existing flow with no chrome.
- Backend or model changes. The schema columns, validation rules, defaults, and `restRateLimits()` accessor were all delivered in V1 unit U6 and are already correct.
- A "reset to defaults" button. Leaving a field blank already produces that effect via the NULL semantics.

## Users

The acting user is a `cmadmin` (platform-wide admin) or `coadmin` (CO admin for the CO that owns the KrbAuthenticator instance). They are the same role-holders who can edit any other KrbAuthenticator configuration today.

Secondary user: the operator reading the form months later trying to understand why a particular CO sees more 429s than expected. The desc text under each field is the primary documentation surface for that user.

## Success Criteria

A cmadmin/coadmin who has never read the REST API documentation can:

1. Open the KrbAuthenticator edit form for an existing instance, see three new rows for rate limits with their defaults documented in the desc text, understand the units from the field titles alone, leave the inputs blank, and save — producing zero net change to the database.
2. Type `10` into the per-credential field, save, and observe that subsequent REST POST/PUT against that instance allow up to 10 requests/minute per API user.
3. Type `0` into any of the three fields, save, and observe that subsequent REST POST/PUT against that instance return 429 immediately, with the existing UI flows (`manage`, `ssr`, `remind`) still working end-to-end.
4. Clear the value in any field (back to blank), save, and observe behavior reverts to the code-side default without manual DB intervention.
5. Repeat all of the above on the add form for a brand-new KrbAuthenticator instance (no row in `cm_krb_authenticators` yet).

## Behavior

### Form layout

Three new field rows appear in `View/KrbAuthenticators/fields.inc`, placed after the existing `max_length` row and before the existing `enable_ssr` row. Display order:

1. REST API Per-Credential Limit (per minute) — default 5
2. REST API Per-Target Limit (per hour) — default 2
3. REST API Per-Instance Limit (per hour) — default 20

The rationale for placement: rate limits are authentication-mechanism configuration (like min/max length), not feature toggles (like SSR / username reminder), so they sit with the auth-mechanism block.

### Field shape

Each row follows the `min_length` / `max_length` precedent from the same file:

- `<div class="field-title">` — the title, drawn from a new `pl.krbauthenticator.rest.ratelimit.<key>` lang string.
- `<div class="field-desc">` — the desc line, drawn from a new `pl.krbauthenticator.rest.ratelimit.<key>.desc` lang string.
- `<div class="field-info">` — the input, rendered via `$this->Form->input('rest_rate_limit_*')` with NO `default` attribute. A blank input round-trips as NULL (or empty string; the model's `restRateLimits()` accessor treats both as "use default" at read time, so the operator-observable behavior is identical).

The seven lang strings shipped with this work (six titles + descs, plus one shared range-validation error message) are:

| Key | Value |
|-----|-------|
| `pl.krbauthenticator.rest.ratelimit.per_credential` | `REST API Per-Credential Limit (per minute)` |
| `pl.krbauthenticator.rest.ratelimit.per_credential.desc` | `Maximum REST API password-change requests per API user per minute. Default is 5. Set to 0 to immediately reject all REST API password changes against this instance.` |
| `pl.krbauthenticator.rest.ratelimit.per_target` | `REST API Per-Target Limit (per hour)` |
| `pl.krbauthenticator.rest.ratelimit.per_target.desc` | `Maximum REST API password-change requests per CO Person per KrbAuthenticator instance per hour. Default is 2. Set to 0 to immediately reject all REST API password changes against this instance.` |
| `pl.krbauthenticator.rest.ratelimit.per_instance` | `REST API Per-Instance Limit (per hour)` |
| `pl.krbauthenticator.rest.ratelimit.per_instance.desc` | `Maximum REST API password-change requests against this KrbAuthenticator instance per hour, across all API users and CO People. Default is 20. Set to 0 to immediately reject all REST API password changes against this instance.` |
| `er.krbauthenticator.rest.ratelimit.range` | `Must be an integer between 0 and 100000.` |

The desc strings encode the kill-switch disclosure inline, so the operator who reads any field's desc sees both the default and the `0`-as-disable semantic without needing to read external documentation.

### View (non-edit) mode rendering

When the row column is NOT NULL, the field-info renders the integer value via `filter_var(..., FILTER_SANITIZE_SPECIAL_CHARS)` — same as the input fields above it.

When the row column IS NULL (no operator override), the field-info renders the code-side default with a trailing `(default)` label: `5 (default)`, `2 (default)`, `20 (default)`. This distinguishes "no override, default applies" from "operator explicitly set this value" for the secondary-user persona (the operator reading the form months later trying to understand why a CO sees the 429 rate it does).

When the row column is explicitly `0`, the field-info renders `0` (no `(default)` label, no chrome). The kill-switch disclosure is in the desc text on the same row, which renders adjacent — the operator who reads the form sees the configured `0` and the disclosure together.

### Blank-input semantics

A blank input round-trips as NULL in `cm_krb_authenticators`. `restRateLimits($id)` applies the code-side default at read time, exactly as V1 already does. Operators do not see a number in the input unless they explicitly typed one. A future release that bumps any default automatically applies to every row whose operator never set an explicit value.

### Zero-input semantics

A `0` in any of the three inputs is a documented operator feature: the very first matching REST POST/PUT request will see `count = 1 > limit = 0` and return 429. The field's desc text names this explicitly so the operator who sets `0` knows what they are doing.

The kill switch is per-window, not permanent. If the operator clears the field, the next request lands in a fresh window with the code-side default. UI flows (`manage`, `ssr`, `remind`) are unaffected per the V1 "no UI flow change" guarantee — they do not hit the rate limiter.

### Validation

The existing `range(0, 100000)` validation in `Model/KrbAuthenticator.php` covers this surface unchanged. A non-integer or out-of-range input renders via `$this->Form->error(...)` in the same shape as `min_length` / `max_length` errors. Each of the three rate-limit fields' range rule is updated to carry the shared `er.krbauthenticator.rest.ratelimit.range` message key (Cake 2's `'message' => _txt('er.krbauthenticator.rest.ratelimit.range')` on the rule definition) so the operator sees the explicit allowed-range text rather than Cake's generic stock string.

### Permissions

Existing `permissions['edit']` on KrbAuthenticator gates the rate-limit fields the same way it gates `min_length`, `max_length`, `enable_ssr`, etc. No new permission tier.

## Files Affected

- `Plugin/KrbAuthenticator/View/KrbAuthenticators/fields.inc` — three new `<li>` rows.
- `Plugin/KrbAuthenticator/Lib/lang.php` — seven new keys: six title + desc pairs under `pl.krbauthenticator.rest.ratelimit.*` (verbatim strings in the Field shape section above) plus one shared range-validation error message under `er.krbauthenticator.rest.ratelimit.range`.
- `Plugin/KrbAuthenticator/Model/KrbAuthenticator.php` — the three rate-limit `range` validation rules grow a `'message' => _txt('er.krbauthenticator.rest.ratelimit.range')` so the validation error renders the new lang string rather than Cake's stock text.
- `Plugin/KrbAuthenticator/docs/rest-api.md` — short addition to the existing "Rate limits" section noting per-instance defaults are now operator-tunable via the edit view; cross-reference the form fields by their title strings so an integrator who reads the doc can map between the wire-format consequence and the UI control.

No schema or controller changes.

## Dependencies and Assumptions

- The deployment has run the V1 schema migration (`cm_krb_authenticators` has the three new columns) AND cleared Cake's model schema cache so the form reflects the new schema. Both of these were confirmed on TEST during V1 deploy; documenting here so a fresh PROD deploy gets the same treatment.
- Operators reading the form understand the time-unit naming convention used in the field titles ("per minute" / "per hour"). No time-unit dropdown is provided.
- The `Form->input()` Cake helper renders a NULL row column as a blank input when no `default` attribute is set (verified by reading the existing `min_length` / `max_length` rendering in the same file — both have no default and render blank when the column is NULL).
- The model's `restRateLimits()` accessor already treats both `null` and empty-string `''` as "use code-side default" (`Model/KrbAuthenticator.php` lines 208/211/214), so the operator-observable "NULL means default" property holds regardless of whether Cake's save path stores the empty input as `NULL` or as `''`. The doc's wording uses "NULL" for both cases.

## Anticipated Follow-On (not built here)

- Per-CO rate-limit tunables. Different table layout, different surface area. Track separately.
- Per-credential overrides on the `ApiUser` row. Lets a deployment grant unusually high limits to a vetted automation while keeping the instance default low. Different model.
- A "rate-limit observability" panel — current per-instance counter table contents, recent 429 rate, top breached scope-key tuples. Different feature, different brainstorm.
- A migration shell that bulk-edits rate limits across all KrbAuthenticator rows in a CO (deferred until there is a deployment with enough instances to need it).

## Open Questions (for planning, not blocking this brainstorm)

- Should the new fields appear inside the existing SSR-controlled `fields_update_gadgets()` JS block? They are unrelated to SSR, so no. Confirm during planning that the JS does not accidentally show/hide them.
- Should `docs/rest-api.md`'s "Migration prerequisites" section mention the model-schema-cache clear required after the V1 migration ran (separately confirmed on TEST 2026-06-11)? Likely yes; tracking in this brainstorm rather than spawning a separate doc PR.

## References

- V1 brainstorm: `docs/brainstorms/2026-05-28-krbauthenticator-rest-api-requirements.md`
- V1 plan: `docs/plans/2026-05-28-001-feat-krbauthenticator-rest-api-plan.md`
- V1 integrator reference: `docs/rest-api.md` (post-V1)
- Existing form precedent: `View/KrbAuthenticators/fields.inc` rows for `min_length`, `max_length`, `ssr_validity`
- Model defaults and validation: `Model/KrbAuthenticator.php` `$restRateLimitDefaults` and `$validate`
- Limit consumer: `Controller/KrbsController.php` `restAdd()` / `restEdit()` via `restRateLimits($krbAuthId)`
