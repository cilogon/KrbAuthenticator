<?php
/**
 * COmanage Registry Krb Reset Token Model
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
 * @since         COmanage Registry v4.0.0
 * @license       Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 */

class KrbResetToken extends AppModel {
  // Define class name for cake
  public $name = "KrbResetToken";

  // Current schema version for API
  public $version = "1.0";
  
  // Add behaviors
  public $actsAs = array('Containable',
                         'Changelog' => array('priority' => 5));

  // Association rules from this model to other models
  public $belongsTo = array(
    "KrbAuthenticator.KrbAuthenticator",
    "CoPerson"
  );

  // Default display field for cake generated views
  public $displayField = "co_person_id";

  // Validation rules for table elements
  public $validate = array(
    'krb_authenticator_id' => array(
      'rule' => 'numeric',
      'required' => true,
      'allowEmpty' => false
    ),
    'co_person_id' => array(
      'rule' => 'numeric',
      'required' => true,
      'allowEmpty' => false
    ),
    'token' => array(
      'rule' => 'notBlank',
      'required' => true,
      'allowEmpty' => false
    ),
    'expires' => array(
      'rule' => '/.*/',  // The 'date' rule is too constraining
      'required' => true,
      'allowEmpty' => false
    )
  );
  
  /**
   * Generate a Krb Reset Token.
   *
   * @since  COmanage Registry v4.1.0
   * @param  int    $krbAuthenticatorId Krb Authenticator ID
   * @param  int    $coPersonId              CO Person ID
   * @return string                          Service Token
   * @throws InvalidArgumentException
   * @throws RuntimeException
   */

  protected function generate($krbAuthenticatorId, $coPersonId) {
    // Toss any previous reset tokens. We need to fire callbacks for ChangelogBehavior.
    $args = array(
      'KrbResetToken.krb_authenticator_id' => $krbAuthenticatorId,
      'KrbResetToken.co_person_id' => $coPersonId
    );
    
    $this->deleteAll($args, true, true);

    // We need the token validity configuration
    $tokenValidity = $this->KrbAuthenticator->field('ssr_validity', array('KrbAuthenticator.id' => $krbAuthenticatorId));
    
    if(!$tokenValidity) {
      throw new InvalidArgumentException(_txt('er.notfound', array(_txt('ct.krb_authenticators.1'), $krbAuthenticatorId)));
    }
    
    $token = generateRandomToken();
    
    $data = array(
      'KrbResetToken' => array(
        'krb_authenticator_id' => $krbAuthenticatorId,
        'co_person_id'              => $coPersonId,
        'token'                     => $token,
        'expires'                   => date('Y-m-d H:i:s', strtotime('+' . $tokenValidity . ' minutes'))
      )
    );

    $this->clear();
    
    if(!$this->save($data)) {
      throw new RuntimeException(_txt('er.db.save-a', array('KrbResetToken::generate')));
    }
    
    return $token;
  }
  
  /**
   * Attempt to generate (and send) a Kerberos Reset Token request or UserName Reminder
   *
   * @since  COmanage Registry v4.1.0
   * @param  int    $authenticatorId Authenticator ID
   * @param  string $q               Search query (email or identifier)
   * @param  string $mode	     'reset' for ssr or 'remind' for username reminder
   * @return bool                    True on success
   * @throws InvalidArgumentException
   */
  
  public function generateRequest($authenticatorId, $q, $mode='reset') {
    // First, search for a CO Person record that matches $q. Note that both
    // EmailAddress and Identifier implement exact searching only, so we don't
    // need to handle that specially here. We do need to know the CO to search
    // within, though.
    
    $coId = $this->KrbAuthenticator->Authenticator->field('co_id', array('Authenticator.id' => $authenticatorId));
    
    if(!$coId) {
      throw new InvalidArgumentException(_txt('er.notfound', array(_txt('ct.authenticators.1'), $authenticatorId)));
    }
    
    // Next, try to find a CO Person ID. We need to find exactly one, but we'll
    // run both searches regardless in case we somehow have an ambiguous string.
    
    $coPersonId = null;
    
    foreach(array('EmailAddress', 'Identifier') as $model) {
      // Note this search will match _unverified_ email addresses, but we only
      // want to match verified email addresses. We'll filter those below.
      $matches = $this->CoPerson->$model->search($coId, $q, 25);
      
      if(!empty($matches)) {
        foreach($matches as $m) {
          // If this is an EmailAddress, make sure it is verified
          if(isset($m['EmailAddress']['verified']) && !$m['EmailAddress']['verified']) {
            continue;
          }
          
          if(!$coPersonId) {
            $coPersonId = $m['CoPerson']['id'];
          } elseif($coPersonId != $m['CoPerson']['id']) {
            // We found at least two different CO People, so throw an error
            throw new InvalidArgumentException(_txt('er.krbauthenticator.ssr.multiple', $q));
          }
        }
      }
    }
    
    if(!$coPersonId) {
      throw new InvalidArgumentException(_txt('er.krbauthenticator.ssr.notfound', array($q)));
    }
    
    // Take the CO Person and look for associated verified email addresses.
    // This could match the search query, but we'll walk the path to make sure.
    
    $args = array();
    $args['conditions']['CoPerson.id'] = $coPersonId;
    $args['contain'] = array('EmailAddress', 'Identifier');

    $coPerson = $this->CoPerson->find('first', $args);
    
    // We could try prioritizing on type or something, but instead we'll just
    // send the message to however many verified addresses we find.
    $verifiedEmails = array();
    
    if(!empty($coPerson['EmailAddress'])) {
      foreach($coPerson['EmailAddress'] as $ea) {
        if($ea['verified']) {
          $verifiedEmails[] = $ea['mail'];
        }
      }
    }
    
    if(empty($verifiedEmails)) {
      throw new InvalidArgumentException(_txt('er.krbauthenticator.ssr.notfound', array($q)));
    }
    
    // Map the Authenticator ID to a Kerberos Authenticator ID
    $args = array();
    $args['conditions']['KrbAuthenticator.authenticator_id'] = $authenticatorId;
    $args['contain'] = false;
    
    $krbAuthenticator = $this->KrbAuthenticator->find('first', $args);
    
    if(!$krbAuthenticator) {
      throw new InvalidArgumentException(_txt('er.notfound', array(_txt('ct.authenticators.1'), $authenticatorId)));
    }
    
    // Use $mode to determine whether we're sending Reset Token Request or Username Reminder
    // and send the message
    if( $mode == 'reset') {
      //  generate a token in order to send it
      $token = $this->generate($krbAuthenticator['KrbAuthenticator']['id'], $coPersonId);
    
      $this->sendRequest($krbAuthenticator, $coPerson, $token, $verifiedEmails, $coPersonId);
    } elseif( $mode == 'remind') {
      $this->send($krbAuthenticator, $coPerson, $verifiedEmails, $coPersonId, null, 'remind');
    }
    return true;
  }
  
  /**
   * Send a Kerberos Reset Token.
   *
   * @since  COmanage Registry v4.1.0
   * @param  KrbAuthenticator $krbAuthenticator Kerberos Authenticator configuration
   * @param  array                 $coPerson              CO Person with associated email addresses and identifiers
   * @param  string                $token                 Kerberos Reset Token
   * @param  array                 $recipients            Array of email addresses to send token to
   * @param  int                   $actorCoPersonId       Actor CO Person ID
   * @throws InvalidArgumentException
   */
  
  protected function sendRequest($krbAuthenticator, $coPerson, $token, $recipients, $actorCoPersonId) {

    // get the expiration time
    $expiry = $this->field('expires', array('KrbResetToken.token' => $token));
    
    // set substitutions
    $rurl = array(
      'plugin'      => 'krb_authenticator',
      'controller'  => 'krbs',
      'action'      => 'ssr',
      'token'       => $token
    );

    $substitutions = array(
      'RESET_URL'         => Router::url($rurl, true),
      'LINK_EXPIRY'       => $expiry
    );

    $this->send($krbAuthenticator, $coPerson, $recipients, $actorCoPersonId, $substitutions, 'reset');

    // Also store the recipient list in the token
    $this->clear();
    $this->updateAll(
      array('KrbResetToken.recipients' => "'" . substr(implode(',', $recipients), 0, 256) . "'"),
      array('KrbResetToken.token' => "'" . $token . "'")
    );
  }

  /**
   * Send a Kerberos Reset  or Username Reminder
   *
   * @since  COmanage Registry v4.1.0
   * @param  KrbAuthenticator $krbAuthenticator Kerberos Authenticator configuration
   * @param  array                 $coPerson              CO Person with associated email addresses and identifiers
   * @param  array                 $recipients            Array of email addresses to send token to
   * @param  int                   $actorCoPersonId       Actor CO Person ID
   * @param  array		   $substitutions	  substitutions for the message template
   * @param  string		   $mode		  'reset' for ssr or 'remind' for username reminder
   * @throws InvalidArgumentException
   */
  protected function send($krbAuthenticator, $coPerson, $recipients, $actorCoPersonId, $substitutions=null, $mode='reset') {

    // Use the value of $mode to set the message template type and text for history record
    $mtType = null;
    $historyText = null;

    if ($mode == 'remind') {
      $mtType = 'username_reminder_message_template_id';
      $historyText = 'pl.krbauthenticator.usernamereminder.hr.sent';
    } elseif($mode == 'reset') {
      $mtType = 'co_message_template_id';
      $historyText = 'pl.krbauthenticator.ssr.hr.sent';
    }

    // Pull the message template
    $mt = null;

    if(!empty($krbAuthenticator['KrbAuthenticator'][$mtType])) {
      $args = array();
      $args['conditions']['CoMessageTemplate.id'] = $krbAuthenticator['KrbAuthenticator'][$mtType];
      $args['conditions']['CoMessageTemplate.status'] = SuspendableStatusEnum::Active;
      $args['contain'] = false;

      $mt = $this->KrbAuthenticator->CoMessageTemplate->find('first', $args);
    }

    if(empty($mt)) {
      throw new InvalidArgumentException(_txt('er.notfound', array(_txt('ct.co_message_templates.1'), $krbAuthenticator['KrbAuthenticator'][$mtType])));
    }

    // pull out the identifiers from the coPerson

    $ids = null;
    $ids = $coPerson['Identifier'];

    $msgSubject = processTemplate($mt['CoMessageTemplate']['message_subject'], $substitutions, $ids);
    $format = $mt['CoMessageTemplate']['format'];
    
    // We don't try/catch, but instead let any exceptions bubble up.
    $email = new CakeEmail('default');

      // If a from address was provided, use it
/*
      if($fromAddress) {
        $email->from($fromAddress);
      }*/

    // Add cc and bcc if specified
    if($mt['CoMessageTemplate']['cc']) {
      $email->cc(explode(',', $mt['CoMessageTemplate']['cc']));
    }

    if($mt['CoMessageTemplate']['bcc']) {
      $email->bcc(explode(',', $mt['CoMessageTemplate']['bcc']));
    }
    
    $msgBody = array();
    
    if($format != MessageFormatEnum::Plaintext
       && !empty($mt['CoMessageTemplate']['message_body_html'])) {
      $msgBody[MessageFormatEnum::HTML] = processTemplate($mt['CoMessageTemplate']['message_body_html'], $substitutions, $ids);
    }
    if($format != MessageFormatEnum::HTML
       && !empty($mt['CoMessageTemplate']['message_body'])) {
      $msgBody[MessageFormatEnum::Plaintext] = processTemplate($mt['CoMessageTemplate']['message_body'], $substitutions, $ids);
    }
    if(empty($msgBody[MessageFormatEnum::Plaintext])) {
      $msgBody[MessageFormatEnum::Plaintext] = "unknown message";
    }
    
    $email->template('custom', 'basic')
      ->emailFormat($format)
      ->to($recipients)
      ->viewVars($msgBody)
      ->subject($msgSubject);
    $email->send();
    
    // Record a HistoryRecord
    $this->CoPerson->HistoryRecord->record($coPerson['CoPerson']['id'],
                                           null,
                                           null,
                                           $actorCoPersonId,
                                           ActionEnum::AuthenticatorEdited,
                                           _txt($historyText, array(implode(",", $recipients))));
  }
  
  /**
   * Validate a Kerberos Reset Token.
   *
   * @since  COmanage Registry v4.1.0
   * @param  string  $token      Kerberos Reset Token
   * @param  boolean $invalidate If true, invalidate the token (otherwise just test it)
   * @return int                 CO Person ID
   * @throws InvalidArgumentException
   */
  
  public function validateToken($token, $invalidate=true) {
    if(!$token) {
      throw new InvalidArgumentException(_txt('er.krbauthenticator.token.notfound'));
    }
    
    $args = array();
    $args['conditions']['KrbResetToken.token'] = $token;
    $args['contain'] = array('CoPerson', 'KrbAuthenticator');
    
    $token = $this->find('first', $args);

    if(empty($token) || empty($token['KrbResetToken']['co_person_id'])) {
      throw new InvalidArgumentException(_txt('er.krbauthenticator.token.notfound'));
    }
    
    if(time() > strtotime($token['KrbResetToken']['expires'])) {
      throw new InvalidArgumentException(_txt('er.krbauthenticator.token.expired'));
    }
    
    // We only accept validation requests for Active or Grace Period CO People.
    if(!in_array($token['CoPerson']['status'], array(StatusEnum::Active, StatusEnum::GracePeriod))) {
      throw new InvalidArgumentException(_txt('er.krbauthenticator.ssr.inactive'));
    }
    
    // We won't validate locked tokens, so check the Authenticator Status
    $args = array();
    $args['conditions']['AuthenticatorStatus.co_person_id'] = $token['KrbResetToken']['co_person_id'];
    $args['conditions']['AuthenticatorStatus.authenticator_id'] = $token['KrbAuthenticator']['authenticator_id'];
    $args['contain'] = false;
    
    $locked = $this->CoPerson->AuthenticatorStatus->field('locked', $args['conditions']);
    
    if($locked) {
      throw new InvalidArgumentException(_txt('er.krbauthenticator.ssr.locked'));
    }
    
    if($invalidate) {
      // We could also delete the token if it was expired, but that might cause
      // user confusion when their error changes from "expired" to "notfound",
      // and deleting the token doesn't actually remove the row from the table.
      
      $this->delete($token['KrbResetToken']['id']);
    }
    
    return $token['KrbResetToken']['co_person_id'];
  }
}
