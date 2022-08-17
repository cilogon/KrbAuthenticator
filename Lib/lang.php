<?php
/**
 * COmanage Registry Kerberos Authenticator Plugin Language File
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
  
global $cm_lang, $cm_texts;

// When localizing, the number in format specifications (eg: %1$s) indicates the argument
// position as passed to _txt.  This can be used to process the arguments in
// a different order than they were passed.

$cm_krb_authenticator_texts['en_US'] = array(
  // Titles, per-controller
  'ct.krb_authenticators.1'  => 'Krb Authenticator',
  'ct.krb_authenticators.pl' => 'Password Authenticators',
  'ct.passwords.1'           => 'Password',
  'ct.passwords.pl'          => 'Passwords',
  
  // Error messages
  'er.krbauthenticator.current'   => 'Current password is not valid',
  'er.krbauthenticator.match'     => 'New passwords do not match',
  'er.krbauthenticator.len.max'   => 'Password cannot be more than %1$s characters',
  'er.krbauthenticator.len.min'   => 'Password must be at least %1$s characters',
  'er.krbauthenticator.ssr.cfg'   => 'Configuration not supported for Self Service Reset',
  'er.krbauthenticator.ssr.inactive'   => 'CO Person is not active and Authenticator cannot be reset',
  'er.krbauthenticator.ssr.locked'     => 'Authenticator is locked and cannot be reset',
  'er.krbauthenticator.ssr.multiple'   => 'Could not resolve a single CO Person for "%1$s"',
  'er.krbauthenticator.ssr.notfound'   => 'No verified email address was found for "%1$s"',
  'er.krbauthenticator.token.expired'  => 'Reset token expired',
  'er.krbauthenticator.token.notfound' => 'Reset token not found',
  
  // Plugin texts
  'pl.krbauthenticator.principal_type' => 'Principal Identifier Type',
  'pl.krbauthenticator.principal_type.desc' => 'Identifier type used for Kerberos principal',
  'pl.krbauthenticator.principal_type.not.found' => 'Principal Identifier type %1$s not found',
  'pl.krbauthenticator.principal.not.found' => 'Principal %1$s not provisioned',
  'pl.krbauthenticator.principal.disabled' => 'Principal %1$s is disabled',
  'pl.krbauthenticator.generate'       => 'To generate a new token, click the <b>Generate</b> button below. This will replace the existing token, if one was already set.',
  'pl.krbauthenticator.info'           => 'Your new password must be between %1$s and %2$s characters in length, and include characters from three of the following: lowercase letters, uppercase letters, numbers, and symbols.',
  'pl.krbauthenticator.maxlen'         => 'Maximum Password Length',
  'pl.krbauthenticator.maxlen.desc'    => 'Must be between 8 and 64 characters (inclusive), default is 64',
  'pl.krbauthenticator.minlen'         => 'Minimum Password Length',
  'pl.krbauthenticator.minlen.desc'    => 'Must be between 8 and 64 characters (inclusive), default is 12',
  'pl.krbauthenticator.mod'            => 'Password last changed %1$s UTC',
  'pl.krbauthenticator.noedit'         => 'This password cannot be edited via this interface.',
  'pl.krbauthenticator.password.again' => 'New Password Again',
  'pl.krbauthenticator.password.current' => 'Current Password',
  'pl.krbauthenticator.password.info'  => 'This newly generated password cannot be recovered. If it is lost a new password must be generated. ',
  'pl.krbauthenticator.password.new'   => 'New Password',
  'pl.krbauthenticator.password_source' => 'Password Source',
  'pl.krbauthenticator.remind.q'       => 'Email Address',
  'pl.krbauthenticator.reset'          => 'Password "%1$s" Reset',
  'pl.krbauthenticator.saved'          => 'Password "%1$s" Set',
  'pl.krbauthenticator.ssr'            => 'Enable Self Service Reset',
  'pl.krbauthenticator.ssr.desc'       => 'Allow self service reset via single use tokens sent to a verified email address',
  'pl.krbauthenticator.ssr.for'        => 'Select a new password for %1$s.',
  'pl.krbauthenticator.ssr.hr.sent'    => 'Password reset request sent to "%1$s"',
  'pl.krbauthenticator.ssr.info'       => 'Enter a verified email address or your ACCESS ID to proceed.</p>If you still know your password, click <a href="%1$s">here</a> to directly select a new password.',
  'pl.krbauthenticator.ssr.mt'         => 'Reset Message Template',
  'pl.krbauthenticator.ssr.mt.desc'    => 'Message template used for email to send reset instructions to',
  'pl.krbauthenticator.ssr.q'          => 'Email Address or ACCESS ID',
  'pl.krbauthenticator.ssr.redirect'   => 'Redirect on Self Service Reset',
  'pl.krbauthenticator.ssr.redirect.desc' => 'URL to redirect to on successful self service reset',
  'pl.krbauthenticator.ssr.sent'       => 'An email with further instructions has been sent to the address on record',
  'pl.krbauthenticator.ssr.url'        => 'Self Service Reset Initiation URL',
  'pl.krbauthenticator.ssr.validity'   => 'Self Service Reset Token Validity',
  'pl.krbauthenticator.ssr.validity.desc' => 'Time in minutes the reset token is valid for',
  'pl.krbauthenticator.token.confirm'  => 'Are you sure you wish to generate a new token?',
  'pl.krbauthenticator.token.gen'      => 'Generate Token',
  'pl.krbauthenticator.token.ssr'      => 'Self Service Password Reset',
  'pl.krbauthenticator.token.usernamereminder' => 'ACCESS ID Reminder',
  'pl.krbauthenticator.usernamereminder.info' => 'Enter a verified email address to proceed.',
  'pl.krbauthenticator.usernamereminder.mt' => 'Username Reminder Message Template',
  'pl.krbauthenticator.usernamereminder.mt.desc' => 'Message template used for email to send username reminder to',
  'pl.krbauthenticator.usernamereminder.hr.sent' => 'Username Reminder sent to "%1$s"',
  'pl.krbauthenticator.usernamereminder.url' => 'Username Reminder URL'
);
