<!--
/**
 * COmanage Registry Kerberos Authenticator Plugin Fields
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
 * @since         COmanage Registry v3.1.0
 * @license       Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 */
-->
<?php
  // Determine if fields are editable
  $e = false;
  
  if(($this->action == "add" && $permissions['add']) || ($this->action == "edit" && $permissions['edit']))
    $e = true;
    
  // We shouldn't get here if we don't have at least read permission, but check just in case
  
  if(!$e && !$permissions['view'])
    return false;
  
  print $this->Form->hidden('authenticator_id', array('default' => $vv_authid)) . "\n";

?>
<script type="text/javascript">
  function fields_update_gadgets() {
    // Hide or show gadgets according to current state
    $("#KrbAuthenticatorEnableSsr").closest("li").show('fade');
    $("#KrbAuthenticatorRedirectOnSuccessSsr").closest("li").hide('fade');
    $("#KrbAuthenticatorSsrValidity").closest("li").hide('fade');
    $("#KrbAuthenticatorCoMessageTemplateId").closest("li").hide('fade');
    
    var ssr = document.getElementById('KrbAuthenticatorEnableSsr').checked;
    
    if(ssr) {
      $("#ssr-url").show('fade');
      $("#KrbAuthenticatorRedirectOnSuccessSsr").closest("li").show('fade');
      $("#KrbAuthenticatorSsrValidity").closest("li").show('fade');
      $("#KrbAuthenticatorCoMessageTemplateId").closest("li").show('fade');
    } else {
      $("#ssr-url").hide('fade');
      $("#KrbAuthenticatorRedirectOnSuccessSsr").closest("li").hide('fade');
      $("#KrbAuthenticatorSsrValidity").closest("li").hide('fade');
      $("#KrbAuthenticatorCoMessageTemplateId").closest("li").hide('fade');
    }

    var remindMT = document.getElementById('KrbAuthenticatorUsernameReminderMessageTemplateId').value;

    if(remindMT) {
      $("#username-reminder-url").show('fade');
    } else {
      $("#username-reminder-url").hide('fade');
    }
  }
  
  function js_local_onload() {
    fields_update_gadgets();
  }
</script>

<?php if(empty($vv_servers)): ?>
<div class="co-info-topbox">
  <i class="material-icons">info</i>
  <?php print _txt('er.server.none', array(_txt('en.server', null, ServerEnum::KdcServer))); ?>
</div>
<?php else: // vv_servers ?>
<ul id="<?php print $this->action; ?>_krb_authenticator" class="fields form-list form-list-admin">
  <li>
    <div class="field-name">
      <?php print ($e ? $this->Form->label('server_id', _txt('fd.server')) : _txt('fd.server')); ?>
      <span class="required">*</span>
    </div>
    <div class="field-info">
      <?php
        $attrs = array();
        $attrs['value'] = (isset($krb_authenticators[0]['KrbAuthenticator']['server_id'])
                           ? $krb_authenticators[0]['KrbAuthenticator']['server_id']
                           : null);
        // Since required=true, this will render blank by default but not allow save until a server is selected
        $attrs['empty'] = true;

        if($e) {
          print $this->Form->select('server_id',
                                    $vv_servers,
                                    $attrs);

          if($this->Form->isFieldError('server_id')) {
            print $this->Form->error('server_id');
          }
        } else {
          if(!empty($krb_authenticators[0]['KrbAuthenticator']['server_id'])) {
            print filter_var($vv_servers[ $krb_authenticators[0]['KrbAuthenticator']['server_id'] ], FILTER_SANITIZE_SPECIAL_CHARS);
          }
        }
      ?>
    </div>
  </li>
  <li>
    <div class="field-name">
      <div class="field-title">
        <?php print _txt('pl.krbauthenticator.principal_type'); ?>
        <span class="required">*</span>
      </div>
      <div class="field-desc"><?php print _txt('pl.krbauthenticator.principal_type.desc'); ?></div>
    </div>
    <div class="field-info">
      <?php
        $attrs = array();
        $attrs['value'] = (isset($krb_authenticators[0]['KrbAuthenticator']['principal_type'])
                           ? $krb_authenticators[0]['KrbAuthenticator']['principal_type']
                           : "");
        $attrs['empty'] = true;

        if($e) {
          print $this->Form->select('principal_type',
                                    $vv_identifiers_types,
                                    $attrs);

          if($this->Form->isFieldError('principal_type')) {
            print $this->Form->error('principal_type');
          }
        } else {
          print _txt('en.identifier.type', null, filter_var($krb_authenticators[0]['KrbAuthenticator']['principal_type'],FILTER_SANITIZE_SPECIAL_CHARS));
        }
      ?>
    </div>
  </li>
  <li>
    <div class="field-name">
      <div class="field-title"><?php print _txt('pl.krbauthenticator.minlen'); ?></div>
      <div class="field-desc"><?php print _txt('pl.krbauthenticator.minlen.desc'); ?></div>
    </div>
    <div class="field-info">
      <?php print ($e ? $this->Form->input('min_length') : filter_var($krb_authenticators[0]['KrbAuthenticator']['min_length'],FILTER_SANITIZE_SPECIAL_CHARS)); ?>
    </div>
  </li>
  <li>
    <div class="field-name">
      <div class="field-title"><?php print _txt('pl.krbauthenticator.maxlen'); ?></div>
      <div class="field-desc"><?php print _txt('pl.krbauthenticator.maxlen.desc'); ?></div>
    </div>
    <div class="field-info">
      <?php print ($e ? $this->Form->input('max_length') : filter_var($krb_authenticators[0]['KrbAuthenticator']['max_length'],FILTER_SANITIZE_SPECIAL_CHARS)); ?>
    </div>
  </li>
  <li>
    <div class="field-name">
      <div class="field-title"><?php print _txt('pl.krbauthenticator.ssr'); ?></div>
      <div class="field-desc"><?php print _txt('pl.krbauthenticator.ssr.desc'); ?></div>
    </div>
    <div class="field-info">
      <?php if($e) print $this->Form->input('enable_ssr', array('onChange' => 'fields_update_gadgets()')); ?>
    </div>
  </li>
  <li id="ssr-url">
    <div class="field-name">
      <div class="field-title"><?php print _txt('pl.krbauthenticator.ssr.url'); ?></div>
    </div>
    <div class="field-info">
      <?php if(!empty($vv_ssr_initiation_url)) print $this->Html->link($vv_ssr_initiation_url, $vv_ssr_initiation_url); ?>
    </div>
  </li>
  <li>
    <div class="field-name">
      <div class="field-title"><?php print _txt('pl.krbauthenticator.ssr.validity'); ?></div>
      <div class="field-desc"><?php print _txt('pl.krbauthenticator.ssr.validity.desc'); ?></div>
    </div>
    <div class="field-info">
      <?php print ($e ? $this->Form->input('ssr_validity', array('default' => 10)) : filter_var($krb_authenticators[0]['KrbAuthenticator']['ssr_validity'],FILTER_SANITIZE_SPECIAL_CHARS)); ?>
    </div>
  </li>
  <li>
    <div class="field-name">
      <div class="field-title">
        <?php print _txt('pl.krbauthenticator.ssr.mt'); ?>
        <span class="required">*</span>
      </div>
      <div class="field-desc"><?php print _txt('pl.krbauthenticator.ssr.mt.desc'); ?></div>
    </div>
    <div class="field-info">
      <?php
        $attrs = array();
        $attrs['value'] = (!empty($krb_authenticators[0]['KrbAuthenticator']['co_message_template_id'])
                          ? $krb_authenticators[0]['KrbAuthenticator']['co_message_template_id']
                          : null);
        // This should be true, but since we don't validate based on multiple
        // fields yet (required only if SSR is enabled) this will prevent an
        // empty value
        $attrs['empty'] = false;
        
        if($e) {
          print $this->Form->select('co_message_template_id',
            (!empty($vv_message_templates[MessageTemplateEnum::Authenticator])
                    ? $vv_message_templates[MessageTemplateEnum::Authenticator]
                    : array()),
            $attrs);
          
          if($this->Form->isFieldError('co_message_template_id')) {
            print $this->Form->error('co_message_template_id');
          }
        }
      ?>
    </div>
  </li>
  <li>
    <div class="field-name">
      <div class="field-title"><?php print _txt('pl.krbauthenticator.ssr.redirect'); ?></div>
      <div class="field-desc"><?php print _txt('pl.krbauthenticator.ssr.redirect.desc'); ?></div>
    </div>
    <div class="field-info">
      <?php print ($e ? $this->Form->input('redirect_on_success_ssr') : filter_var($krb_authenticators[0]['KrbAuthenticator']['redirect_on_success_ssr'],FILTER_SANITIZE_SPECIAL_CHARS)); ?>
    </div>
  </li>
  <li>
    <div class="field-name">
      <div class="field-title">
        <?php print _txt('pl.krbauthenticator.usernamereminder.mt'); ?>
      </div>
      <div class="field-desc"><?php print _txt('pl.krbauthenticator.usernamereminder.mt.desc'); ?></div>
    </div>
    <div class="field-info">
      <?php
        $rattrs = array();
        $rattrs['value'] = (!empty($krb_authenticators[0]['KrbAuthenticator']['username_reminder_message_template_id'])
                          ? $krb_authenticators[0]['KrbAuthenticator']['username_reminder_message_template_id']
                          : null);
        $rattrs['empty'] = true;
        $rattrs['onChange'] = "fields_update_gadgets();";

        if($e) {
          print $this->Form->select('username_reminder_message_template_id',
            (!empty($vv_message_templates[MessageTemplateEnum::Authenticator])
                    ? $vv_message_templates[MessageTemplateEnum::Authenticator]
                    : array()),
            $rattrs);

          if($this->Form->isFieldError('username_reminder_message_template_id')) {
            print $this->Form->error('username_reminder_message_template_id');
          }
        }
      ?>
    </div>
  </li>
  <li id="username-reminder-url">
    <div class="field-name">
      <div class="field-title"><?php print _txt('pl.krbauthenticator.usernamereminder.url'); ?></div>
    </div>
    <div class="field-info">
      <?php if(!empty($vv_username_reminder_url)) print $this->Html->link($vv_username_reminder_url, $vv_username_reminder_url); ?>
    </div>
  </li>
  <?php if($e): ?>
    <li class="fields-submit">
      <div class="field-name">
        <span class="required"><?php print _txt('fd.req'); ?></span>
      </div>
      <div class="field-info">
        <?php print $this->Form->submit($submit_label); ?>
      </div>
    </li>
  <?php endif; ?>
</ul>
<?php endif; // vv_servers ?>
