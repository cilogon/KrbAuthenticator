<?php
/**
 * COmanage Registry Kerberos Authenticator Enumerations
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

// HistoryRecord action codes attributed to KrbAuthenticator REST writes. The
// 'p' prefix follows the plugin convention documented at
// app/Lib/enum.php:31 ("Codes beginning with a lowercase `p` (eg: `pABC`) are
// reserved for plugin use").
class KrbAuthenticatorActionEnum
{
  // Intent record written immediately before the KDC changePassword() call.
  // Durable in autocommit mode so the audit trail is never empty even when
  // the KDC commits and a subsequent Registry write fails.
  const KrbKdcChangeIntent      = 'pKKI';

  // KDC change succeeded and the Registry-side outcome record was written.
  const KrbKdcChangeSucceeded   = 'pKKS';

  // KDC change failed before commit (KDC unreachable, principal missing,
  // KDC-policy rejection, etc.). No KDC state change occurred.
  const KrbKdcChangeFailed      = 'pKKF';

  // KDC change committed but the post-KDC Registry write failed (divergence).
  // Reconciliation may be required.
  const KrbKdcRegistryDivergence = 'pKKD';
}
