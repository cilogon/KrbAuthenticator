<?php
/**
 * COmanage Registry Kerberos Authenticator Model
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
 * @since         COmanage Registry v4.1.0
 * @license       Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 */

App::uses("AuthenticatorBackend", "Model");

class KrbAuthenticator extends AuthenticatorBackend {
  // Define class name for cake
  public $name = "KrbAuthenticator";

  // Required by COmanage Plugins
  public $cmPluginType = "authenticator";

  // Add behaviors
  public $actsAs = array('Containable');

  // Document foreign keys
  public $cmPluginHasMany = array(
    "CoPerson" => array("Krb"),
    "CoMessageTemplate" => array("KrbAuthenticator")
  );

  // Association rules from this model to other models
  public $belongsTo = array(
    "Authenticator",
    "CoMessageTemplate"
  );

  public $hasMany = array(
    "KrbAuthenticator.Krb",
    "KrbAuthenticator.KrbResetToken"
  );

  // Default display field for cake generated views
  public $displayField = "server_id";

  // Request KDC servers
  public $cmServerType = ServerEnum::KdcServer;

  // Validation rules for table elements
  public $validate = array(
    'authenticator_id' => array(
      'rule' => 'numeric',
      'required' => true,
      'allowEmpty' => false
    ),
    'server_id' => array(
      'rule' => 'numeric',
      'required' => true,
      'allowEmpty' => false
    ),
    'principal_type' => array(
      'content' => array(
        'rule' => array('validateExtendedType',
                        array('attribute' => 'Identifier.type',
                              'default' => array(IdentifierEnum::ePPN,
                                                 IdentifierEnum::ePTID,
                                                 IdentifierEnum::Mail,
                                                 IdentifierEnum::OIDCsub,
                                                 IdentifierEnum::OpenID,
                                                 IdentifierEnum::SamlPairwise,
                                                 IdentifierEnum::SamlSubject,
                                                 IdentifierEnum::UID))),
        'required' => true,
        'allowEmpty' => false
      )
    ),
    'min_length' => array(
      'rule' => 'numeric',
      'required' => false,
      'allowEmpty' => true
    ),
    'max_length' => array(
      'rule' => 'numeric',
      'required' => false,
      'allowEmpty' => true
    ),
    'enable_ssr' => array(
      'rule' => array('boolean'),
      'required' => false,
      'allowEmpty' => true
    ),
    'ssr_validity' => array(
      'rule' => 'numeric',
      'required' => true,
      'allowEmpty' => false
    ),
    // XXX This should be required if enable_ssr is true, but for now we don't
    // have a conditional validation rule
    'co_message_template_id' => array(
      'rule' => 'numeric',
      'required' => false,
      'allowEmpty' => true
    ),
    'redirect_on_success_ssr' => array(
      'rule' => array('url', true),
      'required' => false,
      'allowEmpty' => true
    )
  );

  // Do we support multiple authenticators per instantiation?
  public $multiple = false;
  
  /**
   * Expose menu items.
   * 
   * @ since COmanage Registry v4.1.0
   * @ return Array with menu location type as key and array of labels, controllers, actions as values.
   */

  public function cmPluginMenus() {
    return array();
  }

  /**
   * Obtain current data suitable for passing to manage().
   *
   * @since  COmanage Registry v4.1.0
   * @param  integer $id         Authenticator ID
   * @param  integer $backendId  Authenticator Backend ID
   * @param  integer $coPersonId CO Person ID
   * @return Array 
   * @throws RuntimeException
   */

  public function current($id, $backendId, $coPersonId) {
    // Since Kerberos principal passwords are only stored in the KDC
    // and not in a database table we need to overload this method from
    // the parent AuthenticatorBackend model.

    $data = array();
    $data['Krb']['co_person_id'] = $coPersonId;

    return $data;
  }

  /**
   * Lock Authenticator.
   *
   * @since  COmanage Registry v4.1.0
   * @param  integer $id         Authenticator ID
   * @param  integer $coPersonId CO Person ID
   * @return Boolean             true on success
   * @throws RuntimeException
   */
  
  public function lock($id, $coPersonId) {
    return $this->lockOrUnlock($id, $coPersonId, true);
  }

  /**
   * Lock or unlock Authenticator.
   *
   * @since  COmanage Registry v4.1.0
   * @param  integer $id         Authenticator ID
   * @param  integer $coPersonId CO Person ID
   * @param  Boolean $lock true to disable principal or false to enable
   * @return Boolean             true on success
   * @throws RuntimeException
   */
  
  private function lockOrUnlock($id, $coPersonId, $lock=true) {
    $args = array();
    $args['conditions']['Authenticator.id'] = $id;
    $args['contain'] = 'KrbAuthenticator';

    $authenticator = $this->Authenticator->find('first', $args);

    $kdcServerId = $authenticator['KrbAuthenticator']['server_id'];
    $principalType = $authenticator['KrbAuthenticator']['principal_type'];

    // Find the principal from the CO Person record.

    $args = array();
    $args['conditions']['Identifier.co_person_id'] = $coPersonId;
    $args['conditions']['Identifier.type'] = $principalType;
    $args['contain'] = false;

    $identifier = $this->Authenticator->Co->CoPerson->Identifier->find('first', $args);

    if(empty($identifier)) {
      $msg = _txt('pl.krbauthenticator.principal_type.not.found', array($principalType));
      $this->log($msg);
      throw new RuntimeException($msg);
    }

    $principal = $identifier['Identifier']['identifier'];

    // Open a connection to the KDC.
    try {
      $kdc = $this->Authenticator->Co->Server->KdcServer->connect($kdcServerId);
    } catch (Exception $e) {
      $msg = "Unable to connect to KDC: ";
      $msg = $msg . print_r($e->getMessage(), true);
      $this->log($msg);

      throw new RuntimeException($msg);
    }

    // Find the principal object.
    try {
      $principalObj = $kdc->getPrincipal($principal);
    } catch (Exception $e) {
      $principalObj = null;
    }

    if(empty($principalObj)) {
      $msg = _txt('pl.krbauthenticator.principal.not.found', array($principal));
      $this->log($msg);
      throw new RuntimeException($msg);
    }

    // Disable the principal.
    try {
      $currentAttributes = $principalObj->getAttributes();

      if($lock) {
        $newAttributes = $currentAttributes | 64;
      } else {
        $newAttributes = $currentAttributes ^ 64;
      }
      $principalObj->setAttributes($newAttributes);
      $principalObj->save();
    } catch (Exception $e) {
      $msg = "Unable to disable or enable principal: ";
      $msg = $msg . print_r($e->getMessage(), true);
      $this->log($msg);
      throw new RuntimeException($msg);
    }

    return true;
  }
  
  /**
   * Manage Authenticator data, as submitted from the view.
   *
   * @since  COmanage Registry v4.1.0
   * @param  Array   $data            Array of Authenticator data submitted from the view
   * @param  integer $actorCoPersonId Actor CO Person ID
   * @return string Human readable (localized) result comment
   * @throws InvalidArgumentException
   * @throws RuntimeException
   */

  public function manage($data, $actorCoPersonId, $actorApiUserId=null) {
    if(!empty($data['Krb']['token'])) {
      // Me're here from a Self Service Password Reset operation (ssr), which
      // means all we have are the token and the new password. First, we'll need
      // to pull our own configuration, by looking up the token. 
      
      $args = array();
      $args['conditions']['KrbResetToken.token'] = $data['Krb']['token'];
      $args['contain'] = array('KrbAuthenticator' => 'Authenticator');
      
      $token = $this->KrbResetToken->find('first', $args);
      
      if(empty($token)) {
        throw new InvalidArgumentException(_txt('er.krbauthenticator.token.notfound'));
      }
      
      // We can set our configuration based on $token, though note the containable
      // result will be a slightly different structure than we normally get so
      // we have to fix that here.
      
      $this->pluginCfg['KrbAuthenticator'] = $token['KrbAuthenticator'];
      $this->pluginCfg['Authenticator'] = $token['KrbAuthenticator']['Authenticator'];
      unset($this->pluginCfg['KrbAuthenticator']['Authenticator']);
      
      // Stuff additional info we need into $data
      $data['Krb']['co_person_id'] = $token['KrbResetToken']['co_person_id'];
      $data['Krb']['krb_authenticator_id'] = $this->pluginCfg['KrbAuthenticator']['id'];
      
      // Force the $actorCoPersonId to be the CO Person ID associated with the token.
      $actorCoPersonId = $token['KrbResetToken']['co_person_id'];
    }
    
    $minlen = $this->pluginCfg['KrbAuthenticator']['min_length'] ?: 8;
    $maxlen = $this->pluginCfg['KrbAuthenticator']['max_length'] ?: 64;

    // Check minimum length
    if(strlen($data['Krb']['password']) < $minlen) {
      throw new InvalidArgumentException(_txt('er.krbauthenticator.len.min', array($minlen)));
    }

    // Check maximum length
    if(strlen($data['Krb']['password']) > $maxlen) {
      throw new InvalidArgumentException(_txt('er.krbauthenticator.len.max', array($maxlen)));
    }

    // Check that passwords match
    if($data['Krb']['password'] != $data['Krb']['password2']) {
      throw new InvalidArgumentException(_txt('er.krbauthenticator.match'));
    }
    
    // Make sure we have a CO Person ID to operate over
    if(empty($data['Krb']['co_person_id'])) {
      throw new InvalidArgumentException(_txt('er.notprov.id', array(_txt('ct.co_people.1'))));
    }

    $coPersonId = $data['Krb']['co_person_id'];

    // Find the principal from the CO Person record.

    $principalType = $this->pluginCfg['KrbAuthenticator']['principal_type'];

    $args = array();
    $args['conditions']['Identifier.co_person_id'] = $coPersonId;
    $args['conditions']['Identifier.type'] = $principalType;
    $args['contain'] = false;

    $identifier = $this->Authenticator->Co->CoPerson->Identifier->find('first', $args);

    if(empty($identifier)) {
      $msg = _txt('pl.krbauthenticator.principal_type.not.found', array($principalType));
      $this->log($msg);
      throw new RuntimeException($msg);
    }

    $principal = $identifier['Identifier']['identifier'];

    // Open a connection to the KDC.
    $kdcServerId = $this->pluginCfg['KrbAuthenticator']['server_id'];

    try {
      $kdc = $this->Authenticator->Co->Server->KdcServer->connect($kdcServerId);
    } catch (Exception $e) {
      $msg = "Unable to connect to KDC: ";
      $msg = $msg . print_r($e->getMessage(), true);
      $this->log($msg);

      throw new RuntimeException($msg);
    }

    if(!empty($data['Krb']['token'])) {
      // If we have a token, validate it before processing anything
      
      // This will throw InvalidArgumentException on error
      $this->KrbResetToken->validateToken($data['Krb']['token'], false);
    } else {
      // If the actor is the CO Person then the current password is
      // required, so test that it is valid.
      if($coPersonId == $actorCoPersonId) {

        try {
          $ticket = new KRB5CCache();
          $ticket->initPassword($principal, $data['Krb']['passwordc']);
        } catch (Exception $e) {
          throw new InvalidArgumentException(_txt('er.krbauthenticator.current'));
        }
      }
    }

    // Find the principal object.
    try {
      $principalObj = $kdc->getPrincipal($principal);
    } catch (Exception $e) {
      $principalObj = null;
    }

    if(empty($principalObj)) {
      $msg = _txt('pl.krbauthenticator.principal.not.found', array($principal));
      $this->log($msg);
      throw new RuntimeException($msg);
    }

    // Change the password.
    try {
      $principalObj->changePassword($data['Krb']['password']);

      // Success so now invalidate the token if we had one.
      if(!empty($data['Krb']['token'])) {
        $this->KrbResetToken->validateToken($data['Krb']['token'], true);
      }

    } catch (Exception $e) {
      $msg = "Unable to set password for principal $principal: ";
      $msg = $msg . print_r($e->getMessage(), true);
      $this->log($msg);
      throw new RuntimeException($msg);
    }

    // Compute comment used for flash and for history record.
    $comment = _txt('pl.krbauthenticator.saved',
                    array($this->pluginCfg['Authenticator']['description']));

    // Write a history record for the CO Person.
    $this->Authenticator
         ->Co
         ->CoPerson
         ->HistoryRecord->record($coPersonId,
                                 null,
                                 null,
                                 $actorCoPersonId,
                                 ActionEnum::AuthenticatorEdited,
                                 $comment,
                                 null, null, null, null,
                                 $actorApiUserId);

    return $comment;
  }

  /**
   * Generate a random string, using a cryptographically secure 
   * pseudorandom number generator (random_int)
   *
   * This function requires PHP 7+.
   * 
   * @param int $length      How many characters do we want?
   * @param string $keyspace A string of all possible characters to select from
   * @return string
   */

  function random_str(int $length = 64, string $keyspace = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ') {
      if ($length < 1) {
          throw new RangeException("Length must be a positive integer");
      }

      $pieces = [];

      $max = mb_strlen($keyspace, '8bit') - 1;

      for ($i = 0; $i < $length; ++$i) {
          $pieces []= $keyspace[random_int(0, $max)];
      }

      return implode('', $pieces);
  }

  /**
   * Reset Authenticator data for a CO Person.
   *
   * @since  COmanage Registry v4.1.0
   * @param  integer $coPersonId      CO Person ID
   * @param  integer $actorCoPersonId Actor CO Person ID
   * @param  integer $actorApiUserId  Actor API User ID
   * @return boolean true on success
   */
  
  public function reset($coPersonId, $actorCoPersonId, $actorApiUserId=null) {
    // Perform the reset by reseting the password to a long random string.

    $args = array();
    $args['conditions']['Krb.krb_authenticator_id'] = $this->pluginCfg['KrbAuthenticator']['id'];
    $args['conditions']['Krb.co_person_id'] = $coPersonId;

    // Find the principal.
    $principalType = $this->pluginCfg['KrbAuthenticator']['principal_type'];

    $args = array();
    $args['conditions']['Identifier.co_person_id'] = $coPersonId;
    $args['conditions']['Identifier.type'] = $principalType;
    $args['contain'] = false;

    $identifier = $this->Authenticator->Co->CoPerson->Identifier->find('first', $args);

    if(empty($identifier)) {
      $msg = _txt('pl.krbauthenticator.principal_type.not.found', array($principalType));
      $this->log($msg);
      throw new RuntimeException($msg);
    }

    $principal = $identifier['Identifier']['identifier'];

    // Open a connection to the KDC.
    $kdcServerId = $this->pluginCfg['KrbAuthenticator']['server_id'];

    try {
      $kdc = $this->Authenticator->Co->Server->KdcServer->connect($kdcServerId);
    } catch (Exception $e) {
      $msg = "Unable to connect to KDC: ";
      $msg = $msg . print_r($e->getMessage(), true);
      $this->log($msg);

      throw new RuntimeException($msg);
    }

    // Find the principal object.
    try {
      $principalObj = $kdc->getPrincipal($principal);
    } catch (Exception $e) {
      $principalObj = null;
    }

    if(empty($principalObj)) {
      $msg = _txt('pl.krbauthenticator.principal.not.found', array($principal));
      $this->log($msg);
      throw new RuntimeException($msg);
    }

    $newRandomPassword = $this->random_str();

    // Change the password.
    try {
      $principalObj->changePassword($newRandomPassword);
    } catch (Exception $e) {
      $msg = "Unable to set password for principal $principal: ";
      $msg = $msg . print_r($e->getMessage(), true);
      $this->log($msg);
      throw new RuntimeException($msg);
    }
    
    // And record some history

    $comment = _txt('pl.krbauthenticator.reset',
                    array($this->pluginCfg['Authenticator']['description']));

    $this->Authenticator
         ->Co
         ->CoPerson
         ->HistoryRecord->record($coPersonId,
                                 null,
                                 null,
                                 $actorCoPersonId,
                                 ActionEnum::AuthenticatorDeleted,
                                 $comment,
                                 null, null, null, null,
                                 $actorApiUserId);

    // We always return true
    return true;
  }

  /**
   * Obtain the current Authenticator status for a CO Person.
   *
   * @since  COmanage Registry v4.1.0
   * @param  integer $coPersonId   CO Person ID
   * @return Array Array with values
   *               status: AuthenticatorStatusEnum
   *               comment: Human readable string, visible to the CO Person
   * @throws RuntimeException if unable to connect to KDC
   */

  public function status($coPersonId) {
    // Is there a password for this person?
    $principalType = $this->pluginCfg['KrbAuthenticator']['principal_type'];

    // Find the principal.
    $args = array();
    $args['conditions']['Identifier.co_person_id'] = $coPersonId;
    $args['conditions']['Identifier.type'] = $principalType;
    $args['contain'] = false;

    $identifier = $this->Authenticator->Co->CoPerson->Identifier->find('first', $args);

    if(empty($identifier)) {
      return array(
        'status' => AuthenticatorStatusEnum::NotSet,
        'comment' => _txt('pl.krbauthenticator.principal_type.not.found', array($principalType))
      );
    }

    $principal = $identifier['Identifier']['identifier'];

    $kdcServerId = $this->pluginCfg['KrbAuthenticator']['server_id'];

    try {
      $kdc = $this->Authenticator->Co->Server->KdcServer->connect($kdcServerId);
    } catch (Exception $e) {
      $msg = "Unable to connect to KDC: ";
      $msg = $msg . print_r($e->getMessage(), true);
      $this->log($msg);

      throw new RuntimeException($msg);
    }

    try {
      $principalObj = $kdc->getPrincipal($principal);
    } catch (Exception $e) {
      $principalObj = null;
    }

    if(empty($principalObj)) {
      return array(
        'status' => AuthenticatorStatusEnum::NotSet,
        'comment' => _txt('pl.krbauthenticator.principal.not.found', array($principal))
      );
    }

    $currentAttributes = $principalObj->getAttributes();
    $principalIsDisabled = $currentAttributes & 64;

    if($principalIsDisabled) {
      return array(
        'status' => AuthenticatorStatusEnum::Locked,
        'comment' => _txt('pl.krbauthenticator.principal.disabled', array($principal))
      );
    } else {
      $lastModificationTime = $principalObj->getLastPasswordChange();
      $lastModificationDateTime = new DateTime("@$lastModificationTime");
      $lastModificationString = $lastModificationDateTime->format('Y-m-d H:i:s');
      return array(
        'status' => AuthenticatorStatusEnum::Active,
        'comment' => _txt('pl.krbauthenticator.mod', array($lastModificationString))
      );
    }
  }

  /**
   * Unlock Authenticator
   *
   * @since  COmanage Registry v4.1.0
   * @param  integer $id         Authenticator ID
   * @param  integer $coPersonId CO Person ID
   * @return Boolean             true on success
   * @throws RuntimeException
   */
  
  public function unlock($id, $coPersonId) {
    return $this->lockOrUnlock($id, $coPersonId, false);
  }
}
