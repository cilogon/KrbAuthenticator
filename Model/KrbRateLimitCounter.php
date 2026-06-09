<?php
/**
 * COmanage Registry Kerberos Authenticator Rate Limit Counter Model
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
 * @package       registry-plugin
 * @since         COmanage Registry KrbAuthenticator REST V1
 * @license       Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 */

class KrbRateLimitCounter extends AppModel {
  // Define class name for cake
  public $name = "KrbRateLimitCounter";

  // Current schema version for API
  public $version = "1.0";

  // No belongsTo: this model is a primitive whose rows are keyed by an
  // opaque (scope, rl_key, window_start_epoch) tuple. The scope+rl_key pair
  // encodes the referent (api_user_id, krb_authenticator_id, or composite
  // krb_authenticator_id:co_person_id) and is interpreted only by callers.
  public $belongsTo = array();

  public $hasOne = array();

  // No Changelog: counters are transient and the audit value of revision
  // history is zero. Containable is added defensively so callers using
  // 'contain' => false don't trip an "unknown behavior" warning.
  public $actsAs = array('Containable');

  // Default display field for cake generated views
  public $displayField = "rl_key";

  // Validation rules for table elements
  public $validate = array(
    'scope' => array(
      'rule' => array('inList', array('per_credential', 'per_target', 'per_instance')),
      'required' => true,
      'allowEmpty' => false
    ),
    'rl_key' => array(
      'rule' => array('maxLength', 128),
      'required' => true,
      'allowEmpty' => false
    ),
    'window_start_epoch' => array(
      'rule' => 'numeric',
      'required' => true,
      'allowEmpty' => false
    ),
    'count' => array(
      'rule' => 'numeric',
      'required' => true,
      'allowEmpty' => false
    )
  );

  /**
   * Atomically increment a rate-limit counter for the (scope, key, window)
   * tuple and return whether the caller is still within the limit.
   *
   * The implementation mirrors app/Model/Lock.php:102-134's canonical
   * "save then catch PDOException then recover" pattern, with the polarity
   * inverted from "lock acquisition" to "counter increment":
   *
   *   1. Compute the fixed-window bucket for the current wall-clock time.
   *   2. Optimistically save() a fresh row (scope, key, window, count=1).
   *   3. On PDOException, inspect SQLSTATE: 23000 (MySQL) or 23505
   *      (Postgres) indicates the row already exists — fall through to the
   *      recovery path. ANY OTHER SQLSTATE — deadlock 40001, lock-wait
   *      HY000, connection reset, etc. — is rethrown. Transient DB errors
   *      MUST NOT silently bypass the limiter; fail closed so the REST
   *      controller surfaces a 5xx and the request is denied.
   *   4. Recovery: column-relative updateAll() to atomically bump the
   *      existing row's count, then find() to read the post-increment
   *      value. The keyed-array form (field => SQL snippet) is required;
   *      a flat-string array like array('count = count + 1') is misparsed
   *      by DboSource as a single field assignment.
   *   5. Return (allowed, retryAfter). If the post-increment count exceeds
   *      $limit, retryAfter is the wall-clock seconds remaining in the
   *      current bucket; otherwise it is 0.
   *
   * GC of expired counter rows is a separate concern; see Scope Boundaries
   * in the V1 plan.
   *
   * @since  COmanage Registry KrbAuthenticator REST V1
   * @param  string  $scope         One of 'per_credential', 'per_target',
   *                                'per_instance'.
   * @param  string  $key           Scope-dependent key (api_user_id,
   *                                "krb_authenticator_id:co_person_id", or
   *                                krb_authenticator_id). Length <= 128.
   * @param  integer $windowSeconds Fixed-window width in seconds.
   * @param  integer $limit         Max increments allowed in one window.
   * @return array                  array($allowed, $retryAfterSeconds).
   * @throws PDOException           Rethrown unchanged for any SQLSTATE
   *                                outside the integrity-constraint set,
   *                                so callers fail closed on transient
   *                                DB faults.
   */

  public function checkAndIncrement($scope, $key, $windowSeconds, $limit) {
    $now = time();
    $windowStart = (int)floor($now / $windowSeconds) * $windowSeconds;

    $row = array(
      'KrbRateLimitCounter' => array(
        'scope' => $scope,
        'rl_key' => $key,
        'window_start_epoch' => $windowStart,
        'count' => 1
      )
    );

    $this->create();

    try {
      // Force a fresh save: clear $this->id from any prior call so save()
      // never silently updates an unrelated row.
      $this->save($row, array('callbacks' => false));
      $count = 1;
    }
    catch(PDOException $e) {
      // SQLSTATE is the first element of $e->errorInfo for the PDO driver;
      // $e->getCode() returns the same string in current PHP. Compare both
      // to be resilient to driver-specific quirks.
      $sqlState = null;
      if(is_array($e->errorInfo) && isset($e->errorInfo[0])) {
        $sqlState = $e->errorInfo[0];
      }
      if($sqlState === null) {
        $sqlState = $e->getCode();
      }

      // 23000: MySQL/SQLite integrity-constraint violation.
      // 23505: Postgres unique_violation.
      // Anything else (40001 deadlock, HY000 lock-wait, connection reset)
      // fails closed — the limiter must not silently leak under load.
      if($sqlState !== '23000' && $sqlState !== '23505') {
        throw $e;
      }

      $conditions = array(
        'KrbRateLimitCounter.scope' => $scope,
        'KrbRateLimitCounter.rl_key' => $key,
        'KrbRateLimitCounter.window_start_epoch' => $windowStart
      );

      // Atomic column-relative bump. The keyed-array form is required so
      // DboSource emits "count = count + 1" rather than treating the value
      // as a placeholder. See DboSource::update() at
      // lib/Cake/Model/Datasource/DboSource.php:2197-2233.
      $this->updateAll(
        array('KrbRateLimitCounter.count' => 'KrbRateLimitCounter.count + 1'),
        $conditions
      );

      $existing = $this->find('first', array(
        'conditions' => $conditions,
        'contain' => false,
        'recursive' => -1
      ));

      // Defensive: if the row vanished between updateAll and find (e.g.,
      // a GC task interleaved) treat the increment as having raced ahead
      // of GC; report count=1 so the caller is not erroneously locked out.
      $count = !empty($existing['KrbRateLimitCounter']['count'])
        ? (int)$existing['KrbRateLimitCounter']['count']
        : 1;
    }

    if($count > $limit) {
      $retryAfter = ($windowStart + $windowSeconds) - $now;
      // Floor at 1 second so callers never advertise Retry-After: 0.
      if($retryAfter < 1) {
        $retryAfter = 1;
      }
      return array(false, $retryAfter);
    }

    return array(true, 0);
  }
}
