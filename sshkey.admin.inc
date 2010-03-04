<?php

function sshkey_settings_form() {
  $form = array();

  $form['sshkey_key_directory'] = array(
    '#type' => 'textfield',
    '#title' => t('Key directory'),
    '#description' => t('The directory in the filesystem that is used to store public keys.'),
    '#size' => 40,
    '#maxlength' => 255,
    '#required' => TRUE,
    '#default_value' => sshkey_get_key_directory(),
  );

  $form['sshkey_ssh_vulnkey'] = array(
    '#type' => 'textfield',
    '#title' => t('Vulnerable key check'),
    '#description' => t('The path to ssh-vulnkey that can check a key against a blacklist of compromised keys, make sure that you\'ve installed openssh-blacklist.'),
    '#size' => 40,
    '#maxlength' => 255,
    '#default_value' => variable_get('sshkey_ssh_vulnkey', ''),
  );

  $form['save'] = array(
    '#type' => 'submit',
    '#value' => t('Save'),
  );

  return $form;
}

function sshkey_settings_form_validate(&$form, $form_state) {
  $values = $form_state['values'];

  if (file_exists($values['sshkey_key_directory'])) {
    if (!is_writable($values['sshkey_key_directory'])) {
      form_set_error('sshkey_key_directory', t('The key directory is not writeable'));
    }
  }
  else {
    if (!mkdir($values['sshkey_key_directory'])) {
      form_set_error('sshkey_key_directory', t('The key directory doesn\'t exist and cannot be created automatically.'));
    }
    else {
      drupal_set_message(t('The directory @dir has been created', array(
        '@dir' => $values['sshkey_key_directory'],
      )));
    }
  }

  if (!empty($values['sshkey_ssh_vulnkey'])) {
    if (!file_exists($values['sshkey_ssh_vulnkey'])) {
      form_set_error('sshkey_ssh_vulnkey', t('The ssh-vulnkey executable doesn\'t exist'));
    }
    else if (!is_executable($values['sshkey_ssh_vulnkey'])) {
      form_set_error('sshkey_ssh_vulnkey', t('The ssh-vulnkey executable isn\'t executable'));
    }
  }
}

function sshkey_settings_form_submit($form, $form_state) {
  $values = $form_state['values'];

  variable_set('sshkey_ssh_vulnkey', $values['sshkey_ssh_vulnkey']);
  variable_set('sshkey_key_directory', $values['sshkey_key_directory']);
}
