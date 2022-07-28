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

class KrbsController extends SAMController {
  // Class name, used by Cake
  public $name = "Krbs";
  
  // Krb Authenticator ID, used by ssr()
  protected $krbAuthenticatorId = null;
  
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
