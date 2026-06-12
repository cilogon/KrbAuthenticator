---
type: feat
origin: Plugin/KrbAuthenticator/docs/brainstorms/2026-06-11-krbauthenticator-rate-limit-ui-config-requirements.md
status: active
created: 2026-06-11
---

# feat: Surface KrbAuthenticator REST rate-limit tunables in UI

## Summary

V1 of the KrbAuthenticator REST API added three rate-limit tunable columns to `cm_krb_authenticators` (`rest_rate_limit_per_credential_per_minute`, `rest_rate_limit_per_target_per_hour`, `rest_rate_limit_per_instance_per_hour`) but shipped no UI surface for them — operators have to edit the database directly to override the code-side defaults of 5/min, 2/hour, 20/hour. This plan exposes the three columns in the existing KrbAuthenticator edit/add view as three integer input rows, with eight new lang strings (six titles+descs, one shared range-error message, one view-mode default label), one model change to attach the new error message to the existing `range` validation rules, and a short integrator-doc addition.

The work preserves V1's "NULL means use code-side default at read time" semantics: blank input round-trips as NULL (or empty-string; `restRateLimits()` already treats both identically), no `default` attribute on the Form helper, no pre-fill. View (non-edit) mode renders NULL as `5 (default)` / `2 (default)` / `20 (default)` so the secondary-user persona ("operator reading the form months later trying to understand why a particular CO sees the 429 rate it does") can tell "no override set, default applies" from "explicitly set to 5". Each field's desc string encodes the `0`-as-kill-switch disclosure inline.

---

## Problem Frame

**Current state:** V1's three rate-limit columns are tunable per-instance but only via SQL. The plan's exhaustive `UPDATE cm_krb_authenticators ...` workaround is well within an operator's skill set, but it has three real costs: (1) it bypasses any audit surface the UI gives, (2) it requires the operator to know the column names verbatim, and (3) the V1 deploy on TEST 2026-06-10 already revealed that the model schema cache must be cleared for fresh columns to be visible — an operator who shells into the DB without knowing this loses an afternoon to a phantom no-op.

**Desired state:** A `cmadmin` or `coadmin` who can edit a KrbAuthenticator instance can also tune its three rate limits from the same form. The form makes the V1 model semantics (NULL = default, 0 = kill switch) discoverable through field titles and desc text alone — no out-of-band documentation required.

**Why now:** TEST exercised V1 end-to-end on 2026-06-10. The next operator-facing question after "does it work?" is "how do I tune it?" — answering it with a UI surface costs three small file edits and prevents the next deploy from sliding into a DB-shell workflow as the supported path.

---

## Requirements

Carrying from origin (`docs/brainstorms/2026-06-11-krbauthenticator-rate-limit-ui-config-requirements.md`):

- **R1.** A `cmadmin`/`coadmin` who can edit a KrbAuthenticator instance can set, change, or clear each of the three rate-limit values from the same form, with no DB shell required. (Origin Goal 1)
- **R2.** "NULL means use code-side default at read time" is preserved in the UI: a blank input round-trips as NULL (or empty-string; the V1 model accessor treats both identically). The UI does not pre-fill the input with the default value. (Origin Goal 2)
- **R3.** The kill-switch behavior already inherent in the model (any of the three set to `0` makes the very first matching request exceed the window count → 429) is documented in the form's desc text and becomes an operator-facing feature. (Origin Goal 3)
- **R4.** View (non-edit) mode renders a NULL row column as `<default> (default)` — `5 (default)`, `2 (default)`, `20 (default)`. An explicitly-set `0` renders as plain `0` (no `(default)` label). (Origin Behavior § View (non-edit) mode rendering)
- **R5.** The six title+desc lang strings shipped with this work appear verbatim as drafted in the origin doc's Field shape table. Each desc encodes the kill-switch disclosure inline. (Origin Behavior § Field shape, D2 and D3 resolutions)
- **R6.** The three `range(0, 100000)` validation rules carry a shared `er.krbauthenticator.rest.ratelimit.range` message so the operator sees the explicit allowed-range text rather than Cake's generic stock string. (Origin Behavior § Validation, D4 resolution)
- **R7.** No new permission tier. Existing `permissions['edit']` gates the rate-limit fields the same way it gates `min_length`, `max_length`, `enable_ssr`. (Origin Behavior § Permissions; inherited constraint — no unit-level work required, verified by the existing permission gate covering the new field rows alongside the rest of the form.)
- **R8.** UI flows (`manage`, `ssr`, `remind`) are unaffected. Adding form rows must not break the JS gadgets that show/hide SSR-dependent fields. (Origin success criterion #3, Open Question 1)

---

## Scope Boundaries

### In scope

- Three new form rows in `Plugin/KrbAuthenticator/View/KrbAuthenticators/fields.inc`, placed after `max_length` and before `enable_ssr`.
- Eight new lang strings in `Plugin/KrbAuthenticator/Lib/lang.php` — six title/desc strings under the `pl.krbauthenticator.rest.ratelimit.*` namespace, one shared error under `er.krbauthenticator.rest.ratelimit.range`, and one view-mode default-label format string under `pl.krbauthenticator.rest.ratelimit.default_label`.
- One model change to attach the shared error message to the three existing `range` validation rules.
- One paragraph addition to `Plugin/KrbAuthenticator/docs/rest-api.md` cross-referencing the new UI surface, plus a Migration prerequisites note about clearing the model schema cache (carrying from V1 TEST deploy).

### Deferred to Follow-Up Work

- Per-CO rate-limit tunables. (Origin Anticipated Follow-On)
- Per-credential overrides on the `ApiUser` row. (Origin Anticipated Follow-On)
- Rate-limit observability panel. (Origin Anticipated Follow-On)
- Bulk-edit shell across all instances in a CO. (Origin Anticipated Follow-On)

### Outside this product's identity

None — the brainstorm did not declare a product-identity boundary distinct from the V1 plan, and this work strictly extends V1's existing operator-configuration surface.

---

## Key Technical Decisions

**KTD-1: The form rows use the `min_length` / `max_length` precedent, not the `ssr_validity` precedent.** Both patterns live in the same file. `min_length` / `max_length` render via `$this->Form->input(...)` with no `default` attribute — a NULL row column renders as a blank input and a blank submit round-trips back. `ssr_validity` uses `array('default' => 10)`, which pre-fills the input with the default value on first add. The brainstorm explicitly chose the no-default semantics (R2) so the V1 "NULL means use default at read time" property survives. Three form rows + zero `default` attributes is the entirety of this decision.

**KTD-2: View-mode `(default)` label is a controller-side decision, not a Cake-builtin.** The existing pattern `print filter_var($krb_authenticators[0]['KrbAuthenticator']['min_length'], FILTER_SANITIZE_SPECIAL_CHARS)` would render a NULL column as the empty string. R4 requires `5 (default)` / `2 (default)` / `20 (default)` instead. The view file synthesizes the label inline by reading the column value, testing against null/empty, and falling back to a `_txt('pl.krbauthenticator.rest.ratelimit.default_label', [default])` string. The lang-string layer carries the format `%s (default)`; the view computes which default applies per row via the same defaults the model already exposes (`$restRateLimitDefaults`).

**KTD-3: One shared range-error message, not three.** Cake 2's `range(0, 100000)` rule with `'message' => _txt('er.krbauthenticator.rest.ratelimit.range')` produces the same output for any of the three fields. D4's resolution explicitly preferred the one-key design over three field-specific messages — three messages would only restate the range in three different framings without naming anything that varies per field beyond what the field title already says. One key keeps `Lib/lang.php` editable without a search-and-replace cascade.

**KTD-4: No JS gadgets visibility-toggle integration.** The existing `fields_update_gadgets()` function in `fields.inc` only manipulates `#KrbAuthenticatorEnableSsr`, `#KrbAuthenticatorRedirectOnSuccessSsr`, `#KrbAuthenticatorSsrValidity`, `#KrbAuthenticatorCoMessageTemplateId`, and `#KrbAuthenticatorUsernameReminderMessageTemplateId` by ID. The three new fields will have new IDs not referenced anywhere in that JS, so they sit outside the show/hide block by construction. Verification: read the function after the form change lands; confirm no new element IDs appear in any `.show('fade')` / `.hide('fade')` selector.

**KTD-5: No new model accessor, no schema change.** V1 already shipped `KrbAuthenticator::restRateLimits($id)`, `$restRateLimitDefaults`, and the three schema columns with `range(0, 100000)` validation marked `allowEmpty => true`. This plan adds zero columns, zero accessors, and zero new validation rules — only the `'message' =>` attribute on each of three existing rule definitions. The blank-input round-trip semantics for nullable integer columns in Cake 2 are inherited from the V1 work; the brainstorm's Dependencies and Assumptions section explicitly confirms `restRateLimits()` treats both `null` and `''` as "use default", so the operator-observable behavior is identical regardless of how Cake's save path stores the empty input.

---

## High-Level Technical Design

Skipped. The plan is a four-file, dependency-ordered increment with no multi-component architecture, no state machine, no protocol sequence, no decision-branching gates. The unit-level prose covers the shape directly.

---

## Implementation Units

### U1. Add lang strings

**Goal:** Land the eight new lang strings in `Lib/lang.php` so subsequent units can reference them via `_txt()`.

**Requirements:** R5, R6.

**Dependencies:** None.

**Files:**

- `Plugin/KrbAuthenticator/Lib/lang.php` (modify)

**Approach:**

- Add to the `$cm_krb_authenticator_texts['en_US']` array, alphabetically slotted near existing `er.krbauthenticator.rest.*` and `pl.krbauthenticator.*` keys.
- The seven strings are verbatim from the origin's Field shape table:
  - `pl.krbauthenticator.rest.ratelimit.per_credential` → `REST API Per-Credential Limit (per minute)`
  - `pl.krbauthenticator.rest.ratelimit.per_credential.desc` → `Maximum REST API password-change requests per API user per minute. Default is 5. Set to 0 to immediately reject all REST API password changes against this instance.`
  - `pl.krbauthenticator.rest.ratelimit.per_target` → `REST API Per-Target Limit (per hour)`
  - `pl.krbauthenticator.rest.ratelimit.per_target.desc` → `Maximum REST API password-change requests per CO Person per KrbAuthenticator instance per hour. Default is 2. Set to 0 to immediately reject all REST API password changes against this instance.`
  - `pl.krbauthenticator.rest.ratelimit.per_instance` → `REST API Per-Instance Limit (per hour)`
  - `pl.krbauthenticator.rest.ratelimit.per_instance.desc` → `Maximum REST API password-change requests against this KrbAuthenticator instance per hour, across all API users and CO People. Default is 20. Set to 0 to immediately reject all REST API password changes against this instance.`
  - `er.krbauthenticator.rest.ratelimit.range` → `Must be an integer between 0 and 100000.`
- Add one additional string for the view-mode default label per KTD-2:
  - `pl.krbauthenticator.rest.ratelimit.default_label` → `%s (default)`

**Patterns to follow:**

- `Plugin/KrbAuthenticator/Lib/lang.php` existing entries under `er.krbauthenticator.rest.*` (added during V1 U7) and `pl.krbauthenticator.*`.

**Test scenarios:**

Test expectation: none — pure lang-string addition. Verification is via the units that consume the keys (U2 reads `er.*` for validation messages; U3 reads `pl.*` for form rendering and view-mode default labels). A typo or missing key surfaces as the literal key string appearing in the UI under U3's smoke test.

**Verification:** `grep` for each of the eight new keys in `Lib/lang.php` returns exactly one definition per key.

---

### U2. Attach shared error message to model validation rules

**Goal:** Each of the three rate-limit `range` validation rules on `Model/KrbAuthenticator.php` renders the new `er.krbauthenticator.rest.ratelimit.range` message instead of Cake's stock text.

**Requirements:** R6.

**Dependencies:** U1.

**Files:**

- `Plugin/KrbAuthenticator/Model/KrbAuthenticator.php` (modify)

**Approach:**

- The existing `$validate` block defines three rules of the shape `'rule' => array('range', 0, 100000), 'required' => false, 'allowEmpty' => true` for `rest_rate_limit_per_credential_per_minute`, `rest_rate_limit_per_target_per_hour`, and `rest_rate_limit_per_instance_per_hour`.
- Keep each rule definition's flat structure. Cake 2's `ModelValidator` accepts `'message' =>` as a sibling of `'rule' =>` on a flat single-rule entry — no `'content' =>` nesting is required (that idiom is only needed when adding a second named rule under another key, which `principal_type` does because it has multiple constraints). Add `'message' => _txt('er.krbauthenticator.rest.ratelimit.range')` alongside the existing `'rule'`, `'required'`, `'allowEmpty'` keys on each of the three rate-limit rules.
- Leave the `range(0, 100000)` arguments, `required`, and `allowEmpty` flags unchanged. `allowEmpty => true` ensures a blank input bypasses the rule entirely (R2 round-trip semantics).

**Patterns to follow:**

- `Plugin/KrbAuthenticator/Model/KrbAuthenticator.php` existing flat-form rules for `min_length`, `max_length`, `ssr_validity` — same shape this unit produces (`'rule' =>`, `'required' =>`, `'allowEmpty' =>`, optionally `'message' =>`, all as siblings).
- Upstream `app/Model/AppModel.php` or any Cake 2 model in the registry for a flat-form `'rule'` + `'message'` example.

**Test scenarios:**

- *Range error message renders the new string.* Manually: edit a KrbAuthenticator via the UI form, type `-1` into the per-credential field, save. The error rendered next to the field reads `Must be an integer between 0 and 100000.` (not Cake's generic "must be between 0 and 100000").
- *Above-range value renders the new string.* Manually: type `100001` into the per-target field, save. Same error message renders.
- *Blank input bypasses validation.* Manually: edit a KrbAuthenticator, leave all three rate-limit fields blank, save. Form submits cleanly; `SELECT rest_rate_limit_per_credential_per_minute, rest_rate_limit_per_target_per_hour, rest_rate_limit_per_instance_per_hour FROM cm_krb_authenticators WHERE id = <id>;` returns NULL or empty string for each.
- *Integer in range passes validation.* Manually: type `10` into per-credential, save. Form submits cleanly; the column now reads `10`.

**Verification:** The four manual scenarios above all produce the expected outcomes. No other validation rules in the file regressed (the principal_type, min_length, max_length, etc. rules still fire as before — verified by saving the form with each of those in turn deliberately invalid).

---

### U3. Add the three form rows to the UI view

**Goal:** Add three integer-input form rows to `View/KrbAuthenticators/fields.inc` immediately after `max_length` and before `enable_ssr`. Edit mode renders blank when the column is NULL and the typed value otherwise; view mode renders `%s (default)` for NULL and the typed integer otherwise.

**Requirements:** R1, R2, R3, R4, R8.

**Dependencies:** U1.

**Files:**

- `Plugin/KrbAuthenticator/View/KrbAuthenticators/fields.inc` (modify)

**Approach:**

- Three new `<li>` blocks following the `min_length` precedent exactly:
  - `<div class="field-name">` with a `<div class="field-title">` printing the `pl.krbauthenticator.rest.ratelimit.<key>` title string and a `<div class="field-desc">` printing the `.desc` string.
  - `<div class="field-info">` with PHP logic branching on `$e` (the editable flag).
- **Edit mode (`$e === true`):** Follow the `principal_type` precedent for the input + error pairing, not `min_length`. `min_length` has no error-rendering branch — copying it verbatim would leave validation errors invisible. The shape is: `print $this->Form->input('rest_rate_limit_per_credential_per_minute', array('label' => false));` (`label => false` suppresses Cake's auto-generated `Rest Rate Limit Per Credential Per Minute` label, which would otherwise duplicate the field-title div above the input — same hide-the-auto-label pattern `principal_type` uses by virtue of `select()` not generating a wrapping label). Immediately after, render the error inside the same `field-info` div with an `isFieldError` guard: `if($this->Form->isFieldError('rest_rate_limit_per_credential_per_minute')) { print $this->Form->error('rest_rate_limit_per_credential_per_minute'); }` — exact `principal_type` shape (`fields.inc` line ~137-138). Repeat for the two other column names. The guard prevents an empty error div from emitting on page load when validation hasn't fired yet.
- **View mode (`$e === false`):** Branch on `isset($krb_authenticators[0]['KrbAuthenticator']['rest_rate_limit_per_credential_per_minute']) && $krb_authenticators[0]['KrbAuthenticator']['rest_rate_limit_per_credential_per_minute'] !== null && $krb_authenticators[0]['KrbAuthenticator']['rest_rate_limit_per_credential_per_minute'] !== ''`:
  - True: `print filter_var($krb_authenticators[0]['KrbAuthenticator']['rest_rate_limit_per_credential_per_minute'], FILTER_SANITIZE_SPECIAL_CHARS);` — exact `min_length` view-mode shape. An explicit `0` falls into this branch (because `0 !== null && 0 !== ''`) and renders as plain `0`, satisfying R4's "no `(default)` suffix on a saved zero" requirement.
  - False: `print _txt('pl.krbauthenticator.rest.ratelimit.default_label', array(5));` — the `%s (default)` template with the per-credential default literal substituted. Use inline literal constants `5` / `2` / `20` in the view (the model's `$restRateLimitDefaults` array is not currently exposed to the view via any viewVar set by `KrbAuthenticatorsController::beforeRender`, and adding a viewVar for one literal-substitution site is over-engineering). Add a code comment in each occurrence cross-referencing `Model/KrbAuthenticator.php` `$restRateLimitDefaults` so a future maintainer who bumps a default updates both places.
- **Add-form null safety:** On the add path, `$krb_authenticators[0]['KrbAuthenticator']` is a stub array set by `StandardController::add()` before the form renders. Rate-limit column keys may be absent (not present at all) or present-and-null. `isset(...)` returns false for both "key absent" and "key set to null", which falls through to the default-label branch — which is the right outcome for add mode regardless of whether the form is rendered editable or read-only. The conditional handles add-mode correctly by construction.
- **Why `isset() && !== null && !== ''` instead of `!empty()`:** `!empty('0')` and `!empty(0)` both evaluate to false, which would route an explicit zero into the "render default label" branch and break R4. Document this gotcha as a code comment in the view so a maintainer doesn't refactor the conditional back to `!empty()`.

**KTD-4 verification (Open Question 1 from brainstorm):**

- After the new rows land, re-read `fields_update_gadgets()` and confirm no `.show('fade')` / `.hide('fade')` call references any of the three new field IDs (`#KrbAuthenticatorRestRateLimitPerCredentialPerMinute`, `#KrbAuthenticatorRestRateLimitPerTargetPerHour`, `#KrbAuthenticatorRestRateLimitPerInstancePerHour`). They should not — but this verification step closes the brainstorm's Open Question 1.

**Patterns to follow:**

- `Plugin/KrbAuthenticator/View/KrbAuthenticators/fields.inc` `principal_type` row — the canonical "input + isFieldError-guarded error render inside field-info" precedent. Use this for the input + error block.
- The same file's `min_length` row — the "blank-when-null view-mode" rendering shape this unit's view-mode branch extends.

**Test scenarios:**

- *Add form, blank state.* Manually: navigate to the KrbAuthenticator add form. Three new rows appear after `max_length` with empty inputs and the title/desc text rendered correctly. The page does not throw a PHP warning about missing lang keys.
- *Edit form on a row with all NULL columns.* Manually: edit an existing KrbAuthenticator whose rate-limit columns are NULL. All three inputs render blank. The title/desc text shows the kill-switch disclosure for each.
- *Edit form on a row with explicit values.* Manually: pre-populate one row with `rest_rate_limit_per_credential_per_minute = 10` via SQL. Edit it; the per-credential input renders `10`. Other two inputs render blank.
- *Edit form on a row with an explicit `0`.* Manually: pre-populate `rest_rate_limit_per_target_per_hour = 0` via SQL. Edit it; the per-target input renders `0` (not blank). Save without other changes; the column still reads `0` after save.
- *View mode for an authenticator with all NULL columns.* Manually: navigate to the read-only view (the `info` action or wherever the form renders with `$e === false`). The three rows render `5 (default)`, `2 (default)`, `20 (default)`.
- *View mode for an authenticator with an explicit `0`.* Manually: with `rest_rate_limit_per_target_per_hour = 0` persisted, view the read-only form. The per-target row renders `0` (no `(default)` suffix).
- *View mode for an authenticator with an explicit `10`.* As above with `10`. Renders `10`.
- *UI flows unchanged (R8).* Manually: navigate to `/registry/krb_authenticator/krbs/manage/authenticatorid:N/copersonid:M` and confirm the existing UI password-change flow returns 200 and renders correctly. Repeat for `ssr` and `remind`. Confirms the form additions did not regress unrelated paths.
- *SSR JS gadgets unaffected.* Toggle the `enable_ssr` checkbox; the SSR-dependent rows still show/hide correctly and none of the three new rate-limit rows are affected by the toggle (KTD-4 verification).
- *REST API still rate-limits.* Issue a POST through the curl recipe in `docs/rest-api.md` and observe the appropriate 201/422/429. Confirms the model accessor still reads the values written by the form. (Light-touch: this is V1 territory, not new code.)

**Verification:** The nine manual scenarios above all produce the expected outcomes. The brainstorm's Success Criteria (5 numbered items) are all observable end-to-end via this set.

---

### U4. Update integrator reference doc

**Goal:** `docs/rest-api.md` reflects two facts: (1) per-instance defaults are now operator-tunable via the edit view, and (2) a fresh deploy must clear Cake's model schema cache after the V1 migration runs (separately confirmed on TEST 2026-06-11).

**Requirements:** Brainstorm Open Question 2 closure; brainstorm Files Affected line 3.

**Dependencies:** U3.

**Files:**

- `Plugin/KrbAuthenticator/docs/rest-api.md` (modify)

**Approach:**

- In the "Rate limits" section, after the table of three scopes, add a one-paragraph note:
  > Per-instance defaults are operator-tunable from the KrbAuthenticator edit view in the Registry UI. The fields are labeled "REST API Per-Credential Limit (per minute)", "REST API Per-Target Limit (per hour)", and "REST API Per-Instance Limit (per hour)". Setting any to `0` immediately rejects REST API password changes against the instance — a documented kill-switch state.
- In the "Migration prerequisites" section, add a bullet to the existing list:
  > **Clear Cake's model schema cache after the migration runs.** Cake 2 caches each model's column metadata in `app/tmp/cache/models/cake_model_default_*`. If anything left a stale cache for `cm_krb_authenticators` or `cm_krb_rate_limit_counters` — for instance, the file was created when the table was missing — the schema preflight on POST returns 503 even though the table exists. Run `rm -f app/tmp/cache/models/cake_model_default_*` after the migration; Cake regenerates on the next request. Required on TEST 2026-06-11 deploy; expect to be required on every fresh deploy.

**Patterns to follow:**

- `Plugin/KrbAuthenticator/docs/rest-api.md` existing "Rate limits" and "Migration prerequisites" section structure.

**Test scenarios:**

Test expectation: none — pure doc update. The content is verifiable by reading the rendered markdown.

**Verification:** Both additions land in the expected sections without disrupting surrounding prose. The UI control names match the lang strings shipped in U1.

---

## System-Wide Impact

- **UI:** Three new rows in one form. No impact on other forms, no impact on UI rendering of other authenticator plugins.
- **REST API:** No behavior change. The same `restRateLimits($id)` accessor and rate-limit columns are read in exactly the same shape — operators can now influence the values without DB shell access.
- **DB:** No schema changes. Existing NULL-allowed columns inherit their V1 semantics.
- **Audit:** No new HistoryRecord codes. UI form saves continue to produce `AuthenticatorEdited` records via the upstream `SAMController::generateHistory` path. The new field values are part of the `vv_authenticator` snapshot serialized into that record.
- **Provisioner:** No impact. The form save doesn't trigger Provisioner (KrbAuthenticator is not Provisioner-decorated; the V1 plan confirms this).
- **Deploy:** A new lang.php means PHP opcache should be invalidated alongside any Cake model cache clear. The Migration prerequisites bullet in U4 covers operator-facing guidance; PHP opcache invalidation is whatever the operator already does for plugin-touching deploys.

---

## Dependencies and Assumptions

- **V1 must be deployed.** The three rate-limit columns must exist on `cm_krb_authenticators` and the V1 lang.php strings added under U7 must be present. Without V1 in place, the new form rows would attempt to read columns that don't exist; Cake would silently skip them and the form would render empty inputs with no warning.
- **Cake's model schema cache must be cleared after the migration runs.** Confirmed on TEST 2026-06-11. U4 documents this for the next deploy.
- **The `min_length` form precedent's rendering behavior is stable.** A NULL row column with no `default` attribute on `Form->input()` renders blank; a blank input saved via the standard StandardController path round-trips back to NULL or empty string, both of which `restRateLimits()` treats as "use default". Verified by the brainstorm's feasibility review (origin Dependencies and Assumptions section).
- **No new translations.** English-only deployment is assumed. Lang keys add to `en_US` only.

---

## Open Questions

None blocking. The two Open Questions in the origin brainstorm are addressed:
- *SSR JS gadgets check* → U3's KTD-4 verification step.
- *`docs/rest-api.md` cache-clear note* → U4.

---

## References

- **Origin requirements:** `Plugin/KrbAuthenticator/docs/brainstorms/2026-06-11-krbauthenticator-rate-limit-ui-config-requirements.md`
- **V1 plan (predecessor):** `Plugin/KrbAuthenticator/docs/plans/2026-05-28-001-feat-krbauthenticator-rest-api-plan.md`
- **V1 brainstorm (predecessor):** `Plugin/KrbAuthenticator/docs/brainstorms/2026-05-28-krbauthenticator-rest-api-requirements.md`
- **V1 integrator reference:** `Plugin/KrbAuthenticator/docs/rest-api.md`
- **Form precedent:** `Plugin/KrbAuthenticator/View/KrbAuthenticators/fields.inc` rows for `min_length`, `max_length`, `ssr_validity`, `principal_type` (validation error pairing)
- **Model defaults and validation:** `Plugin/KrbAuthenticator/Model/KrbAuthenticator.php` `$restRateLimitDefaults` property and `$validate` array
- **Limit consumer:** `Plugin/KrbAuthenticator/Controller/KrbsController.php` `restAdd()` / `restEdit()` via `restRateLimits($krbAuthId)`
- **Cake 2 schema cache behavior:** `app/tmp/cache/models/cake_model_default_*` — file-based per-DataSource cache; cleared by `rm -f`, regenerated on next request
