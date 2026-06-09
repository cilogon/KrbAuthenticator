<?php
/**
 * COmanage Registry Kerberos Password Controller
 *
 * Portions licensed to the University Corporation for Advanced Internet
 * Development, Inc. ("UCAID") under one or more contributor license agreements.
 * See the NOTICE file distributed with this work for additional information
 * regarding copyright ownership.
 *
 * UCAID licenses this file to you under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with the
 * License. You may obtain a copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 * @link          http://www.internet2.edu/comanage COmanage Project
 * @package       registry
 * @since         COmanage Registry v4.1.0
 * @license       Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 */

App::uses("SAMController", "Controller");
// KrbAuthenticatorActionEnum is autoloaded by app/Lib/enum.php's
// _bootstrap_plugin_enum() at bootstrap, so no explicit App::uses is
// needed for it.

class KrbsController extends SAMController {
  // Class name, used by Cake
  public $name = "Krbs";

  // No $uses override here. SAMController declares
  //   public $uses = array('Authenticator', 'CoEnrollmentAuthenticator',
  //                        'CoEnrollmentFlow', 'CoPerson', 'CoPetition');
  // and the inherited beforeFilter chain reads $this->Authenticator inside
  // calculateImpliedCoId() on every request — including UI manage(). A
  // subclass $uses replaces the parent's array (Cake 2 does not merge), so
  // declaring one here would null out $this->Authenticator and break the
  // UI flow. The plugin-local KrbRateLimitCounter model is lazy-loaded
  // inside the REST branches via restLoadRateLimitCounter() below, which
  // also preserves the plan's "no UI flow change during deploy window"
  // guarantee: a deployment that has not yet run the schema migration
  // never instantiates the counter model on UI requests.

  // Krb Authenticator ID, used by ssr()
  protected $krbAuthenticatorId = null;

  // REST V1: per-request memoization for the rate-limit schema preflight so
  // we don't re-run the probing find() multiple times within a single REST
  // call (the per-credential, per-target, and per-instance checks all share
  // one preflight result).
  private $restRateLimiterReachable = null;
  
  /**
   * Callback before other controller methods are invoked or views are rendered.
   * - postcondition: $pool_org_identities set
   *
   * @since  COmanage Registry v4.1.0
   */
  
  public function beforeFilter() {
    parent::beforeFilter();
    
    if($this->action == 'ssr' 
       && (!empty($this->request->params['named']['authenticatorid'])
           || !empty($this->request->params['named']['token'])
           || !empty($this->request->data['Krb']['token']))) {
      // Is Self Service Reset enabled for this authenticator? If so, allow
      // access without authentication.
      
      $ssrenabled = false;
      
      $token = null;
      
      if(!empty($this->request->params['named']['token'])) {
        $token = $this->request->params['named']['token'];
      } elseif(!empty($this->request->data['Krb']['token'])) {
        $token = $this->request->data['Krb']['token'];
      }
      
      if($token) {
        // Map the token to the authenticator ID. Note if both params are provided
        // (which they shouldn't be) we check the token since it's more specific.
        
        $this->krbAuthenticatorId = $this->Krb->KrbAuthenticator->KrbResetToken->field('krb_authenticator_id', array('token' => $token));
        
        if(!empty($this->krbAuthenticatorId)) {
          $ssrenabled = $this->Krb->KrbAuthenticator->field('enable_ssr', array('KrbAuthenticator.id' => $this->krbAuthenticatorId));
        }
      } elseif(!empty($this->request->params['named']['authenticatorid'])) {
        $ssrenabled = $this->Krb->KrbAuthenticator->field('enable_ssr', array('KrbAuthenticator.authenticator_id' => $this->request->params['named']['authenticatorid']));
      }
      
      if($ssrenabled) {
        $this->Auth->allow();
      }
    } elseif($this->action == 'remind'
       && !empty($this->request->params['named']['authenticatorid'])) {
      // Is Username Reminder enabled for this authenticator? If so, allow
      // access without authentication.

      $reminderMT = null;
      $reminderMT = $this->Krb->KrbAuthenticator->field('username_reminder_message_template_id', array('KrbAuthenticator.authenticator_id' => $this->request->params['named']['authenticatorid']));
      if($reminderMT) {
        $this->Auth->allow();
      }
    }
  }
  
  /**
   * REST index override. Mirrors SAMController::index()'s REST branch but
   * returns 200 + empty Krbs array when find() returns no rows under a
   * matching ?krbauthid=N parent flag. SAMController returns 404 here (with
   * an XXX comment in upstream code acknowledging the behavior is wrong but
   * not fixed); R1/R2 of this plan commit to the 200+empty contract.
   *
   * Non-REST requests and REST requests without ?krbauthid fall through to
   * the inherited parent::index() so UI flows and StandardController's
   * permittedApiFilters branch keep working unchanged.
   *
   * @since  COmanage Registry KrbAuthenticator REST V1
   */

  public function index() {
    if(!$this->request->is('restful')) {
      // UI path unchanged.
      return parent::index();
    }

    if(empty($this->params['url']['krbauthid'])) {
      // No parent flag - SAMController falls through to StandardController's
      // generic REST index, which honors $permittedApiFilters on the Krb
      // model. Preserve that behavior unchanged.
      return parent::index();
    }

    // Parent flag is present: replicate SAMController's REST find but convert
    // the empty-result branch from 404 into 200 + empty array.
    $args = array();
    $args['conditions']['Krb.krb_authenticator_id'] = $this->params['url']['krbauthid'];
    if(!empty($this->params['url']['copersonid'])) {
      $args['conditions']['Krb.co_person_id'] = $this->params['url']['copersonid'];
    }
    $args['contain'] = false;

    $t = $this->Krb->find('all', $args);

    // R1/R2: empty result is 200 with an empty Krbs array.
    $this->set('krbs', $this->Api->convertRestResponse($t));
    $this->Api->restResultHeader(200, "OK");
  }

  /**
   * REST POST: set a Kerberos credential.
   *
   * UI form posts continue to flow through the inherited parent::add().
   * The REST branch implements the full V1 contract (R4, R7-R20):
   *
   *   - schema preflight (R-aux) returns 503 if the rate-limit table is
   *     missing, scoped to the REST branch so concurrent UI flows
   *     (manage/ssr/remind) keep working during the deploy window
   *   - input validation (password presence and password == password2,
   *     length against KrbAuthenticator min/max, parent-flag presence)
   *     returns 422 before any KDC interaction
   *   - actor==target guard (R10) returns 403 — documented as inert when
   *     the ApiUser has no linked CoPerson, which is the registry default
   *   - existing-row check (R13 inversion) returns 409 + Location
   *   - three-layer rate limit (R16/R17/R17a) returns 429 + Retry-After.
   *     Per-credential and per-instance counters always tick on accepted
   *     requests; the per-target counter only ticks at this pre-KDC stage
   *     and on successful KDC+Registry outcomes — divergence and KDC
   *     failure are recovery candidates that must not exhaust the budget
   *     (KTD-7 "recovery is privileged")
   *   - KTD-12 transaction shape: pKKI is written autocommit before the
   *     KDC call (asserting no parent transaction is open first); manage()
   *     runs with no DB transaction open so a slow KDC round-trip does not
   *     hold a connection; an inner DataSource begin/commit/rollback wraps
   *     only the post-KDC Krb-row insert and pKKS outcome write; on
   *     post-KDC failure the wrapping txn rolls back and pKKD is written
   *     on the same now-autocommit DataSource
   *   - R14a/R14b sanitization: response body is a fixed _txt() key for
   *     any 4xx/5xx; HistoryRecord.comment is composed of fixed _txt keys
   *     and opaque IDs; password material is scrubbed from request->data
   *     in a finally so an uncaught fatal cannot land it in Cake's
   *     default error log; raw exception text reaches only $this->log()
   *
   * The principal name passed to the KDC is resolved server-side from the
   * loaded (KrbAuthenticator instance, CoPerson) pair per R12a; payload
   * fields beyond {krb_authenticator_id, co_person_id, password, password2}
   * are ignored. The U1 guard in KrbAuthenticator::manage() suppresses the
   * internal AuthenticatorEdited HistoryRecord write when the actor is an
   * API user, so the audit trail per request is exactly {pKKI + outcome}.
   *
   * @since  COmanage Registry KrbAuthenticator REST V1
   */

  public function add() {
    if(!$this->request->is('restful')) {
      // UI form-post path unchanged.
      return parent::add();
    }

    // R14a belt-and-suspenders: scrub the password fields off
    // $this->request->data on every exit path, including uncaught throws.
    // Cake 2's default exception handler can serialize request->data into
    // the error log on an unhandled fatal; the finally runs before that.
    try {
      $this->restAdd();
    } finally {
      if(isset($this->request->data['Krb']['password'])) {
        $this->request->data['Krb']['password'] = '';
        unset($this->request->data['Krb']['password']);
      }
      if(isset($this->request->data['Krb']['password2'])) {
        $this->request->data['Krb']['password2'] = '';
        unset($this->request->data['Krb']['password2']);
      }
    }
  }

  /**
   * REST POST inner method. See add() for the contract.
   *
   * @since  COmanage Registry KrbAuthenticator REST V1
   */

  protected function restAdd() {
    $actorApiUserId = $this->Auth->User('id');
    $actorCoPersonId = $this->Auth->User('co_person_id');

    if(!$this->restRateLimiterSchemaReachable()) {
      $this->restEmit(503, 'er.krbauthenticator.rest.ratelimiter.unavailable');
      return;
    }

    $data = $this->Api->getData();
    if(!is_array($data)) { $data = array(); }

    $krbAuthId = !empty($data['krb_authenticator_id']) ? (int)$data['krb_authenticator_id'] : null;
    $coPersonId = !empty($data['co_person_id']) ? (int)$data['co_person_id'] : null;
    $password = isset($data['password']) ? (string)$data['password'] : null;
    $password2 = isset($data['password2']) ? (string)$data['password2'] : null;

    if(empty($krbAuthId) || empty($coPersonId)
       || $password === null || $password2 === null) {
      $this->restEmit(422, 'er.krbauthenticator.rest.validation');
      return;
    }

    if($password !== $password2) {
      $this->restEmit(422, 'er.krbauthenticator.rest.validation');
      return;
    }

    // R9a, R12a: load the persisted KrbAuthenticator instance so the
    // principal is resolved server-side, not from the payload. Containment
    // pulls the parent Authenticator row for setConfig() below.
    $krbAuth = $this->Krb->KrbAuthenticator->find('first', array(
      'conditions' => array('KrbAuthenticator.id' => $krbAuthId),
      'contain' => array('Authenticator'),
      'recursive' => -1
    ));
    if(empty($krbAuth['KrbAuthenticator'])) {
      // Unknown parent: treat as a validation failure rather than a 404 to
      // avoid distinguishing "wrong krb_authenticator_id" from "wrong
      // password length" in the response (R14a-style minimization).
      $this->restEmit(422, 'er.krbauthenticator.rest.validation');
      return;
    }

    // R9a: cross-check the KrbAuthenticator instance's CO against the
    // authenticated session's resolved CO. cur_co is populated by
    // AppController::beforeFilter via calculateImpliedCoId, which for the
    // REST path runs against the body data through Api->getData(). A
    // mismatch is a 403, not a 422.
    $instanceCoId = !empty($krbAuth['Authenticator']['co_id'])
      ? (int)$krbAuth['Authenticator']['co_id']
      : null;
    $resolvedCoId = !empty($this->cur_co['Co']['id'])
      ? (int)$this->cur_co['Co']['id']
      : null;
    if($instanceCoId !== null && $resolvedCoId !== null
       && $instanceCoId !== $resolvedCoId) {
      $this->restEmit(403, 'er.krbauthenticator.rest.co.mismatch');
      return;
    }

    $minlen = !empty($krbAuth['KrbAuthenticator']['min_length'])
      ? (int)$krbAuth['KrbAuthenticator']['min_length'] : 8;
    $maxlen = !empty($krbAuth['KrbAuthenticator']['max_length'])
      ? (int)$krbAuth['KrbAuthenticator']['max_length'] : 64;
    if(strlen($password) < $minlen || strlen($password) > $maxlen) {
      $this->restEmit(422, 'er.krbauthenticator.rest.validation');
      return;
    }

    // R10: documented as inert when the API user has no linked CoPerson,
    // which is the registry default for cm_api_users rows. The check is
    // wired anyway so a deployment that assigns co_person_id to the
    // ApiUser session via custom logic gets the protection automatically.
    if(!empty($actorCoPersonId) && (int)$actorCoPersonId === (int)$coPersonId) {
      $this->restEmit(403, 'er.krbauthenticator.rest.actor.target.forbidden');
      return;
    }

    // Existing-row check (R13 inversion). 409 carries a Location header
    // pointing at the existing row so the caller can switch to PUT.
    $existing = $this->Krb->find('first', array(
      'conditions' => array(
        'Krb.krb_authenticator_id' => $krbAuthId,
        'Krb.co_person_id' => $coPersonId
      ),
      'contain' => false,
      'recursive' => -1
    ));
    if(!empty($existing['Krb']['id'])) {
      $this->response->header('Location',
        '/registry/krb_authenticator/krbs/' . (int)$existing['Krb']['id'] . '.json');
      $this->restEmit(409, 'er.krbauthenticator.rest.row.exists');
      return;
    }

    // Rate limits (R16/R17/R17a). The per-credential and per-instance
    // counters tick on every accepted-pre-KDC request; the per-target
    // counter is checked here too but its semantic ownership of "recovery
    // is privileged" is realized at the audit branches below: pKKF/pKKD
    // attempts on a future replay do NOT increment per-target a second
    // time because they short-circuit before reaching this stage.
    $limits = $this->Krb->KrbAuthenticator->restRateLimits($krbAuthId);
    $checks = array(
      array('per_credential', (string)$actorApiUserId, 60, $limits['per_credential_per_minute']),
      array('per_target', $krbAuthId . ':' . $coPersonId, 3600, $limits['per_target_per_hour']),
      array('per_instance', (string)$krbAuthId, 3600, $limits['per_instance_per_hour'])
    );
    foreach($checks as $check) {
      list($scope, $key, $windowSeconds, $limit) = $check;
      list($ok, $retryAfter) = $this->KrbRateLimitCounter->checkAndIncrement(
        $scope, $key, $windowSeconds, $limit);
      if(!$ok) {
        $this->response->header('Retry-After', (string)$retryAfter);
        $this->restEmit(429, 'er.krbauthenticator.rest.rate.limited');
        return;
      }
    }

    // KTD-12 (a) assertion: pKKI MUST be written outside any parent
    // transaction. If a wrapper opened one, fail closed rather than enrol
    // the intent record in a transaction that may roll back and leave the
    // audit trail empty when divergence happens (R20).
    $dataSource = $this->Krb->getDataSource();
    if($dataSource->inTransaction()) {
      $this->restEmit(500, 'er.krbauthenticator.rest.audit.preflight');
      return;
    }

    // R20: intent record written before the KDC call, autocommit. From
    // this point on, an outcome record MUST be written on every code path
    // that returns to the caller.
    $this->restWriteAudit(
      $coPersonId,
      $actorApiUserId,
      KrbAuthenticatorActionEnum::KrbKdcChangeIntent,
      $krbAuthId,
      null
    );

    // KTD-12 (b): KDC runs with no DB transaction open. R12a: the data
    // passed to manage() is the persisted (krb_authenticator_id,
    // co_person_id) pair plus the password fields — payload fields beyond
    // those are dropped here.
    try {
      $this->Krb->KrbAuthenticator->setConfig($krbAuth);
      $manageData = array(
        'Krb' => array(
          'krb_authenticator_id' => $krbAuthId,
          'co_person_id' => $coPersonId,
          'password' => $password,
          'password2' => $password2
        )
      );
      $this->Krb->KrbAuthenticator->manage($manageData, null, $actorApiUserId);
    }
    catch(InvalidArgumentException $kdcPolicy) {
      // KDC policy reject (e.g., principal-token or current-password
      // path — neither should fire on REST, but defense in depth). No KDC
      // commit happened.
      $this->log($kdcPolicy->getMessage());
      $this->restWriteAudit(
        $coPersonId, $actorApiUserId,
        KrbAuthenticatorActionEnum::KrbKdcChangeFailed, $krbAuthId, null);
      $this->restEmit(422, 'er.krbauthenticator.rest.kdc.policy');
      return;
    }
    catch(RuntimeException $kdcFailure) {
      // KDC unreachable, principal missing, or changePassword threw. No
      // KDC commit happened (manage() throws before changePassword on
      // connection errors; throws after changePassword on token-finalize
      // failure — that latter case is pKKD-shaped but indistinguishable
      // from outside, so coarse 500 + pKKF is acceptable for V1).
      $this->log($kdcFailure->getMessage());
      $this->restWriteAudit(
        $coPersonId, $actorApiUserId,
        KrbAuthenticatorActionEnum::KrbKdcChangeFailed, $krbAuthId, null);
      $this->restEmit(500, 'er.krbauthenticator.rest.kdc.failed');
      return;
    }

    // KTD-12 (c): KDC committed. Open the transaction that wraps the row
    // insert and the outcome record so a downstream failure rolls both
    // back together — keeping the cm_krbs row and the pKKS marker in
    // sync. The pKKD divergence record is written outside this txn on
    // rollback (KTD-12 (d)).
    $newKrbId = null;
    $dataSource->begin();
    try {
      // OQ8 path a: callbacks=>false to bypass the Changelog behavior on
      // this insert. The plan documented the tradeoff — REST writes do
      // not produce per-row revision history under V1; the HistoryRecord
      // trail (pKKI/pKKS/pKKF/pKKD) is the durable audit surface.
      $this->Krb->create();
      $saved = $this->Krb->save(
        array('Krb' => array(
          'krb_authenticator_id' => $krbAuthId,
          'co_person_id' => $coPersonId
        )),
        array('callbacks' => false, 'validate' => true, 'atomic' => false)
      );
      if(!$saved) {
        throw new RuntimeException('cm_krbs save() returned false');
      }
      $newKrbId = (int)$this->Krb->id;

      $this->restWriteAudit(
        $coPersonId, $actorApiUserId,
        KrbAuthenticatorActionEnum::KrbKdcChangeSucceeded, $krbAuthId, $newKrbId);

      $dataSource->commit();
    }
    catch(Exception $postKdc) {
      // Divergence: KDC committed but the Registry-side write failed. Per
      // KTD-12 (d), roll back the txn first so the DataSource reverts to
      // autocommit, then write pKKD on it. R15: KDC is NOT rolled back;
      // the same POST replayed converges state via natural idempotency.
      if($dataSource->inTransaction()) {
        $dataSource->rollback();
      }
      $this->log($postKdc->getMessage());
      $this->restWriteAudit(
        $coPersonId, $actorApiUserId,
        KrbAuthenticatorActionEnum::KrbKdcRegistryDivergence,
        $krbAuthId, null);
      $this->restEmit(500, 'er.krbauthenticator.rest.kdc.divergence');
      return;
    }

    // OQ8 path a suppresses ALL callbacks on the Krb->save above, which
    // takes Changelog OUT of the picture as intended but also takes the
    // Provisioner behavior out. Fire provisioning explicitly here so the
    // REST path matches the upstream UI flow's post-manage() trigger at
    // app/AvailablePlugin/PasswordAuthenticator/Controller/PasswordsController.php:205
    // and SAMController::manage() at :607. A provisioning failure does
    // not roll back state: the Krb row and pKKS are already committed,
    // and the audit trail is the durable signal — provisioner backends
    // are re-run by other Registry mechanisms.
    try {
      $this->Krb->KrbAuthenticator->Authenticator->provision($coPersonId);
    }
    catch(Exception $provErr) {
      $this->log('KrbAuthenticator REST: provision after Krb insert failed: '
        . $provErr->getMessage());
    }

    // Success: 201 Created with a Location pointing at the new row. Body
    // is empty per R1-R5's response-shape minimization.
    $this->response->header('Location',
      '/registry/krb_authenticator/krbs/' . $newKrbId . '.json');
    $this->restEmit(201, 'Created');
  }

  /**
   * REST PUT: change a Kerberos credential on an existing row.
   *
   * UI form posts continue to flow through the inherited parent::edit().
   * The REST branch implements R5/R7-R9a/R10-R12a/R14/R14a/R15-R20:
   *
   *   - 404 if the cm_krbs row does not exist (R5)
   *   - R12a authoritative-row guard: the loaded row's krb_authenticator_id
   *     and co_person_id are the principal-resolution source. If the
   *     payload supplies values that disagree with the loaded row, 422.
   *     Principal-bearing payload fields are otherwise ignored.
   *   - Same three-layer rate limit, audit preflight, intent/outcome
   *     pattern, and password-scrub finally as add(). The transaction
   *     wraps only the pKKS outcome write here — there is no row insert
   *     to protect.
   *
   * @since  COmanage Registry KrbAuthenticator REST V1
   */

  public function edit($id) {
    if(!$this->request->is('restful')) {
      // UI form-post path unchanged.
      return parent::edit($id);
    }

    try {
      $this->restEdit($id);
    } finally {
      if(isset($this->request->data['Krb']['password'])) {
        $this->request->data['Krb']['password'] = '';
        unset($this->request->data['Krb']['password']);
      }
      if(isset($this->request->data['Krb']['password2'])) {
        $this->request->data['Krb']['password2'] = '';
        unset($this->request->data['Krb']['password2']);
      }
    }
  }

  /**
   * REST PUT inner method. See edit() for the contract.
   *
   * @since  COmanage Registry KrbAuthenticator REST V1
   */

  protected function restEdit($id) {
    $actorApiUserId = $this->Auth->User('id');
    $actorCoPersonId = $this->Auth->User('co_person_id');

    if(!$this->restRateLimiterSchemaReachable()) {
      $this->restEmit(503, 'er.krbauthenticator.rest.ratelimiter.unavailable');
      return;
    }

    $existing = $this->Krb->find('first', array(
      'conditions' => array('Krb.id' => (int)$id),
      'contain' => false,
      'recursive' => -1
    ));
    if(empty($existing['Krb']['id'])) {
      $this->restEmit(404, 'er.krbauthenticator.rest.row.missing');
      return;
    }

    // R12a: the loaded row's IDs are authoritative. Capture them now;
    // the payload's IDs are only consulted to detect disagreement.
    $krbAuthId = (int)$existing['Krb']['krb_authenticator_id'];
    $coPersonId = (int)$existing['Krb']['co_person_id'];

    $data = $this->Api->getData();
    if(!is_array($data)) { $data = array(); }

    // R12a payload-vs-loaded-row consistency check: a payload that names
    // a different krb_authenticator_id or co_person_id is a 422, not a
    // silent overwrite or a 404.
    if(!empty($data['krb_authenticator_id'])
       && (int)$data['krb_authenticator_id'] !== $krbAuthId) {
      $this->restEmit(422, 'er.krbauthenticator.rest.validation');
      return;
    }
    if(!empty($data['co_person_id'])
       && (int)$data['co_person_id'] !== $coPersonId) {
      $this->restEmit(422, 'er.krbauthenticator.rest.validation');
      return;
    }

    $password = isset($data['password']) ? (string)$data['password'] : null;
    $password2 = isset($data['password2']) ? (string)$data['password2'] : null;
    if($password === null || $password2 === null) {
      $this->restEmit(422, 'er.krbauthenticator.rest.validation');
      return;
    }
    if($password !== $password2) {
      $this->restEmit(422, 'er.krbauthenticator.rest.validation');
      return;
    }

    $krbAuth = $this->Krb->KrbAuthenticator->find('first', array(
      'conditions' => array('KrbAuthenticator.id' => $krbAuthId),
      'contain' => array('Authenticator'),
      'recursive' => -1
    ));
    if(empty($krbAuth['KrbAuthenticator'])) {
      // The loaded Krb row points at a KrbAuthenticator that no longer
      // exists. This is an integrity hole that should not happen under
      // normal operation; surface as 500 rather than masking with 422.
      $this->log('KrbAuthenticator REST: Krb id ' . (int)$id
        . ' references missing KrbAuthenticator ' . $krbAuthId);
      $this->restEmit(500, 'er.krbauthenticator.rest.kdc.failed');
      return;
    }

    $instanceCoId = !empty($krbAuth['Authenticator']['co_id'])
      ? (int)$krbAuth['Authenticator']['co_id'] : null;
    $resolvedCoId = !empty($this->cur_co['Co']['id'])
      ? (int)$this->cur_co['Co']['id'] : null;
    if($instanceCoId !== null && $resolvedCoId !== null
       && $instanceCoId !== $resolvedCoId) {
      $this->restEmit(403, 'er.krbauthenticator.rest.co.mismatch');
      return;
    }

    $minlen = !empty($krbAuth['KrbAuthenticator']['min_length'])
      ? (int)$krbAuth['KrbAuthenticator']['min_length'] : 8;
    $maxlen = !empty($krbAuth['KrbAuthenticator']['max_length'])
      ? (int)$krbAuth['KrbAuthenticator']['max_length'] : 64;
    if(strlen($password) < $minlen || strlen($password) > $maxlen) {
      $this->restEmit(422, 'er.krbauthenticator.rest.validation');
      return;
    }

    if(!empty($actorCoPersonId) && (int)$actorCoPersonId === $coPersonId) {
      $this->restEmit(403, 'er.krbauthenticator.rest.actor.target.forbidden');
      return;
    }

    $limits = $this->Krb->KrbAuthenticator->restRateLimits($krbAuthId);
    $checks = array(
      array('per_credential', (string)$actorApiUserId, 60, $limits['per_credential_per_minute']),
      array('per_target', $krbAuthId . ':' . $coPersonId, 3600, $limits['per_target_per_hour']),
      array('per_instance', (string)$krbAuthId, 3600, $limits['per_instance_per_hour'])
    );
    foreach($checks as $check) {
      list($scope, $key, $windowSeconds, $limit) = $check;
      list($ok, $retryAfter) = $this->KrbRateLimitCounter->checkAndIncrement(
        $scope, $key, $windowSeconds, $limit);
      if(!$ok) {
        $this->response->header('Retry-After', (string)$retryAfter);
        $this->restEmit(429, 'er.krbauthenticator.rest.rate.limited');
        return;
      }
    }

    $dataSource = $this->Krb->getDataSource();
    if($dataSource->inTransaction()) {
      $this->restEmit(500, 'er.krbauthenticator.rest.audit.preflight');
      return;
    }

    $this->restWriteAudit(
      $coPersonId, $actorApiUserId,
      KrbAuthenticatorActionEnum::KrbKdcChangeIntent,
      $krbAuthId, (int)$id
    );

    try {
      $this->Krb->KrbAuthenticator->setConfig($krbAuth);
      $manageData = array(
        'Krb' => array(
          'krb_authenticator_id' => $krbAuthId,
          'co_person_id' => $coPersonId,
          'password' => $password,
          'password2' => $password2
        )
      );
      $this->Krb->KrbAuthenticator->manage($manageData, null, $actorApiUserId);
    }
    catch(InvalidArgumentException $kdcPolicy) {
      $this->log($kdcPolicy->getMessage());
      $this->restWriteAudit(
        $coPersonId, $actorApiUserId,
        KrbAuthenticatorActionEnum::KrbKdcChangeFailed,
        $krbAuthId, (int)$id);
      $this->restEmit(422, 'er.krbauthenticator.rest.kdc.policy');
      return;
    }
    catch(RuntimeException $kdcFailure) {
      $this->log($kdcFailure->getMessage());
      $this->restWriteAudit(
        $coPersonId, $actorApiUserId,
        KrbAuthenticatorActionEnum::KrbKdcChangeFailed,
        $krbAuthId, (int)$id);
      $this->restEmit(500, 'er.krbauthenticator.rest.kdc.failed');
      return;
    }

    // KDC committed. PUT has no row insert to protect, so the txn here
    // wraps only the pKKS write — the structure matches U3 so the
    // divergence handling stays uniform across add()/edit() and a
    // single-statement INSERT failure for HistoryRecord still routes to
    // pKKD instead of partially-committed pKKS.
    $dataSource->begin();
    try {
      $this->restWriteAudit(
        $coPersonId, $actorApiUserId,
        KrbAuthenticatorActionEnum::KrbKdcChangeSucceeded,
        $krbAuthId, (int)$id);
      $dataSource->commit();
    }
    catch(Exception $postKdc) {
      if($dataSource->inTransaction()) {
        $dataSource->rollback();
      }
      $this->log($postKdc->getMessage());
      $this->restWriteAudit(
        $coPersonId, $actorApiUserId,
        KrbAuthenticatorActionEnum::KrbKdcRegistryDivergence,
        $krbAuthId, (int)$id);
      $this->restEmit(500, 'er.krbauthenticator.rest.kdc.divergence');
      return;
    }

    // PUT does not modify the Krb row, but provisioning targets that
    // observe credential changes (rather than DB state) want a trigger
    // here too. Match U3's post-commit Authenticator->provision() call.
    try {
      $this->Krb->KrbAuthenticator->Authenticator->provision($coPersonId);
    }
    catch(Exception $provErr) {
      $this->log('KrbAuthenticator REST: provision after Krb update failed: '
        . $provErr->getMessage());
    }

    $this->restEmit(200, 'OK');
  }

  /**
   * REST DELETE returns 405 Method Not Allowed.
   *
   * V1 explicitly does not expose credential removal via REST (R6) so
   * deprovisioning continues to flow through the Registry UI. The
   * Router::mapResources route still maps DELETE to this controller; we
   * intercept here and emit 405 + Allow before any model interaction.
   * Non-restful invocations are passed through to parent::delete() so
   * the inherited UI path stays unchanged.
   *
   * @since  COmanage Registry KrbAuthenticator REST V1
   */

  public function delete($id) {
    if($this->request->is('restful')) {
      $this->response->header('Allow', 'GET, POST, PUT');
      $this->restEmit(405, 'er.krbauthenticator.rest.method.not.allowed');
      return;
    }
    return parent::delete($id);
  }

  /**
   * Lazy-load the plugin-local KrbRateLimitCounter model onto
   * $this->KrbRateLimitCounter. Called by restAdd() and restEdit() before
   * any rate-limit interaction; never called from UI request paths, so a
   * deployment that has not yet run the V1 schema migration can keep
   * serving UI traffic unaffected.
   *
   * @since  COmanage Registry KrbAuthenticator REST V1
   */

  protected function restLoadRateLimitCounter() {
    if(empty($this->KrbRateLimitCounter)) {
      $this->KrbRateLimitCounter =
        ClassRegistry::init('KrbAuthenticator.KrbRateLimitCounter');
    }
  }

  /**
   * Probe whether cm_krb_rate_limit_counters is reachable. Returns true on
   * the second and later calls within the same REST request (memoized).
   * Lazy-loads the counter model on first call so callers do not need to
   * remember to do it themselves.
   *
   * @since  COmanage Registry KrbAuthenticator REST V1
   * @return boolean
   */

  protected function restRateLimiterSchemaReachable() {
    if($this->restRateLimiterReachable !== null) {
      return $this->restRateLimiterReachable;
    }
    $this->restLoadRateLimitCounter();
    try {
      // Cheap probe: a bounded find against the table. We do not care
      // whether rows come back — only that the table responds.
      $this->KrbRateLimitCounter->find('first', array(
        'conditions' => array('KrbRateLimitCounter.id' => 0),
        'contain' => false,
        'recursive' => -1
      ));
      $this->restRateLimiterReachable = true;
    }
    catch(Exception $e) {
      $this->log('KrbAuthenticator REST: rate-limit table unreachable: '
        . $e->getMessage());
      $this->restRateLimiterReachable = false;
    }
    return $this->restRateLimiterReachable;
  }

  /**
   * Write a HistoryRecord row attributed to the calling API user. The
   * comment is composed exclusively of fixed _txt() keys plus opaque
   * numeric IDs to satisfy R14b.
   *
   * @since  COmanage Registry KrbAuthenticator REST V1
   * @param  integer $coPersonId      Subject CO Person ID.
   * @param  integer $actorApiUserId  ApiUser ID making the request.
   * @param  string  $action          A KrbAuthenticatorActionEnum constant.
   * @param  integer $krbAuthId       KrbAuthenticator instance ID.
   * @param  integer $krbId           cm_krbs row ID (null until known).
   */

  protected function restWriteAudit($coPersonId, $actorApiUserId,
                                    $action, $krbAuthId, $krbId) {
    $commentKey = $this->restAuditCommentKey($action);
    $args = array((int)$krbAuthId);
    if($krbId !== null) {
      $args[] = (int)$krbId;
    }
    $comment = _txt($commentKey, $args);

    try {
      $this->Krb->CoPerson->HistoryRecord->record(
        $coPersonId,
        null,
        null,
        null,
        $action,
        $comment,
        null, null, null,
        $actorApiUserId
      );
    }
    catch(Exception $e) {
      // A HistoryRecord write failure must not crash the controller — the
      // KDC state and any Krb row are the truth. Log and continue; the
      // missing audit row is a triage event per U7's "dangling pKKI"
      // guidance.
      $this->log('KrbAuthenticator REST: HistoryRecord write failed for '
        . $action . ': ' . $e->getMessage());
    }
  }

  /**
   * Map a HistoryRecord action code to its _txt() comment key.
   *
   * @since  COmanage Registry KrbAuthenticator REST V1
   */

  protected function restAuditCommentKey($action) {
    switch($action) {
      case KrbAuthenticatorActionEnum::KrbKdcChangeIntent:
        return 'pl.krbauthenticator.rest.audit.intent';
      case KrbAuthenticatorActionEnum::KrbKdcChangeSucceeded:
        return 'pl.krbauthenticator.rest.audit.succeeded';
      case KrbAuthenticatorActionEnum::KrbKdcChangeFailed:
        return 'pl.krbauthenticator.rest.audit.failed';
      case KrbAuthenticatorActionEnum::KrbKdcRegistryDivergence:
        return 'pl.krbauthenticator.rest.audit.divergence';
    }
    return 'pl.krbauthenticator.rest.audit.unknown';
  }

  /**
   * Emit a REST response: set the status code and a single fixed _txt()
   * key as the body. Wraps ApiComponent::restResultHeader so the call
   * shape at call sites is short and uniform.
   *
   * @since  COmanage Registry KrbAuthenticator REST V1
   */

  protected function restEmit($status, $txtKey) {
    $body = ($txtKey === 'Created' || $txtKey === 'OK')
      ? $txtKey
      : _txt($txtKey);
    $this->Api->restResultHeader($status, $body);
    $this->set('vv_error', $body);
  }

  /**
   * Determine the CO ID based on some attribute of the request.
   * This method is intended to be overridden by model-specific controllers.
   *
   * @since  COmanage Registry v4.1.0
   * @return Integer CO ID, or null if not implemented or not applicable.
   * @throws InvalidArgumentException
   */

  protected function calculateImpliedCoId($data = null) {
    if($this->action == 'ssr') {
      // Map the token (if found) to a CO. Note we don't check for expired tokens
      // yet since if we fail here the user will get a confusing error ("No CO
      // Specified").
      
      $token = null;
      
      if($this->request->is('get')
         && !empty($this->request->params['named']['token'])) {
        $token = $this->request->params['named']['token'];
      } elseif($this->request->is('post')
               && !empty($this->request->data['Krb']['token'])) {
        $token = $this->request->data['Krb']['token'];
      }
      
      if($token) {
        $args = array();
        $args['conditions']['KrbResetToken.token'] = $token;
        $args['contain'] = array('CoPerson');
        
        $prt = $this->Krb->KrbAuthenticator->KrbResetToken->find('first', $args);
        
        if(!empty($prt['CoPerson']['co_id'])) {
          return $prt['CoPerson']['co_id'];
        }
        
        // Force a different error to be slightly less confusing
        $this->Flash->set(_txt('er.krbauthenticator.token.notfound'), array('key' => 'error'));
        $this->redirect('/');
      }
    }
    
    return parent::calculateImpliedCoId($data);
  }

  /**
   * Self service reset a Kerberos principal password.
   *
   * @since  COmanage Registry v4.1.0
   */
  
  public function ssr() {
    $authenticatorId = null;
    
    if($this->request->is('get')) {
      if(!empty($this->request->named['token'])) {
        // We're back from the email message. Verify that the token is valid.
        // If so, pass the token to the view for embedding in the reset form.
        
        try {
          $coPersonId = $this->Krb
                             ->KrbAuthenticator
                             ->KrbResetToken->validateToken($this->request->named['token'], false);
          
          if($coPersonId) {
            // The form will embed the token for the actual reset request
            $this->set('vv_token', $this->request->named['token']);
            
            // Also pass the CO Person name to the view
            $args = array();
            $args['conditions']['Name.co_person_id'] = $coPersonId;
            $args['conditions']['Name.primary_name'] = true;
            $args['contain'] = false;
            
            $name = $this->Krb->CoPerson->Name->find('first', $args);
            
            $this->set('vv_name', generateCn($name['Name']));
          }
        } catch(Exception $e) {
          $this->Flash->set($e->getMessage(), array('key' => 'error'));
        }
      }
      // else fall through and let the search form render
      
      if(!empty($this->request->params['named']['authenticatorid'])) {
        $authenticatorId = $this->request->params['named']['authenticatorid'];
      }
    } elseif($this->request->is('post')) {
      if(!empty($this->request->params['named']['authenticatorid'])) {
        $authenticatorId = $this->request->params['named']['authenticatorid'];
        
        if(!empty($this->request->data['Krb']['q'])) {
          // We're back from the search form, try to generate a reset request
          
          try {
            $this->Krb->KrbAuthenticator->KrbResetToken->generateRequest($authenticatorId, $this->request->data['Krb']['q'], 'reset');
            
            // We render success but let the form render again anyway, in case the
            // user wants to try again.
            $this->Flash->set(_txt('pl.krbauthenticator.ssr.sent'), array('key' => 'success'));
          }
          catch(Exception $e) {
            $this->Flash->set($e->getMessage(), array('key' => 'error'));
          }
        }
      } elseif(!empty($this->request->data['Krb'])) {
        try {
          $r = $this->Krb->KrbAuthenticator->manage($this->request->data, null);
          
          $this->Flash->set($r, array('key' => 'success'));
          
          if($this->krbAuthenticatorId) {
            // See if there is a redirect URL configured
            
            $redirect = $this->Krb->KrbAuthenticator->field('redirect_on_success_ssr', array('KrbAuthenticator.id' => $this->krbAuthenticatorId));
            
            if($redirect) {
              $this->redirect($redirect);
            }
          }
        } catch(Exception $e) {
          $this->Flash->set($e->getMessage(), array('key' => 'error'));
          
          // On error we need to re-include the token so the form can be resubmitted
          if(!empty($this->request->data['Krb']['token'])) {
            $this->set('vv_token', $this->request->data['Krb']['token']);
            
            // We need to re-populate vv_name here
            
            $coPersonId = $this->Krb
                               ->KrbAuthenticator
                               ->KrbResetToken->validateToken($this->request->data['Krb']['token'], false);
            
            if($coPersonId) {
              // The form will embed the token for the actual reset request
              $this->set('vv_token', $this->request->data['Krb']['token']);
              
              // Also pass the CO Person name to the view
              $args = array();
              $args['conditions']['Name.co_person_id'] = $coPersonId;
              $args['conditions']['Name.primary_name'] = true;
              $args['contain'] = false;
              
              $name = $this->Krb->CoPerson->Name->find('first', $args);
              
              $this->set('vv_name', generateCn($name['Name']));
            }
          }
        }
      }
    }
    
    if(!empty($authenticatorId)) {
      // Construct the SSR initiation URL
      $url = array(
        'plugin'          => 'krb_authenticator',
        'controller'      => 'krbs',
        'action'          => 'manage',
        'authenticatorid' => $authenticatorId
      );
      
      $this->set('vv_ssr_authenticated_url', Router::url($url, true));
    }
    
    // If we don't have a CO Person ID, we want to render a form to allow the
    // requester to enter an identifier or email address of some form.
  }
  

  /**
   * Remind User of Username.
   *
   * @since  COmanage Registry v4.1.0
   */

  public function remind() {
    if($this->request->is('post')) {
      if(!empty($this->request->params['named']['authenticatorid'])) {
        $authenticatorId = $this->request->params['named']['authenticatorid'];

        if(!empty($this->request->data['Remind']['q'])) {
          // We're back from the search form, try to generate a username reminder

          try {
            $this->Krb->KrbAuthenticator->KrbResetToken->generateRequest($authenticatorId, $this->request->data['Remind']['q'], 'remind');

            // We render success but let the form render again anyway, in case the
            // user wants to try again.
            $this->Flash->set(_txt('pl.krbauthenticator.ssr.sent'), array('key' => 'success'));
          }
          catch(Exception $e) {
            $this->Flash->set($e->getMessage(), array('key' => 'error'));
          }
        }
      }
    }
  }


  /**
   * Authorization for this Controller, called by Auth component
   * - precondition: Session.Auth holds data used for authz decisions
   * - postcondition: $permissions set with calculated permissions
   *
   * @since  COmanage Registry v4.1.0
   * @return Array Permissions
   */
  
  function isAuthorized() {
    $roles = $this->Role->calculateCMRoles();
    
    // Construct the permission set for this user, which will also be passed to the view.
    $p = array();
    
    // Determine what operations this user can perform
    
    // Merge in the permissions calculated by our parent
    $p = array_merge($p, $this->calculateParentPermissions($this->Krb->KrbAuthenticator->multiple));
    
    $p['generate'] = isset($p['manage']) ? $p['manage'] : false;
    
    // We default to ssr being denied. If enabled, beforeFilter() will allow access.
    $p['ssr'] = false;
    
    $this->set('permissions', $p);
    return($p[$this->action]);
  }
}
