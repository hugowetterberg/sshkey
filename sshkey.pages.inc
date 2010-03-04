<?php

function sshkey_page_list_public_keys($user=NULL) {
  drupal_add_css(drupal_get_path('module', 'sshkey') . '/css/sshkey.css');

  $keys = sshkey_user_public_keys_list($user->uid);

  $header = array(
    array('data' => t('Fingerprint'), 'class' => 'sshkey-public-key-fingerprint'),
    array('data' => t('Name'),        'class' => 'sshkey-public-key-name'),
    array('data' => t('Created'),     'class' => 'sshkey-public-key-created'),
    array('data' => t('Operations'),  'class' => 'sshkey-public-key-operations'),
  );
  $rows = array();

  foreach ($keys as $key) {
    $segmented = '';
    for ($i=0; $i<8; $i+=2) {
      $segmented .= substr($key['fingerprint'], $i, 2) . ':';
    }

    $data = array(
      'fingerprint' => array(
        'data'  => $segmented . '...',
        'class' => 'sshkey-public-key-key',
      ),
      'name' => array(
        'data'  => $key['name'],
        'class' => 'sshkey-public-key-name',
      ),
      'created' => array(
        'data'  => format_date($key['created']),
        'class' => 'sshkey-public-key-created',
      ),
    );

    $operations = array();
    $operations[] = array(
      'title' => t('Edit'),
      'href'  => sprintf('user/%d/sshkeys/%s/edit', $key['uid'], $key['fingerprint']),
      'query' => drupal_get_destination(),
    );
    $operations[] = array(
      'title' => t('Delete'),
      'href'  => sprintf('user/%d/sshkeys/%s/delete', $key['uid'], $key['fingerprint']),
      'query' => drupal_get_destination(),
    );

    $rows[] = array(
      'data' => $data + array(
        'operations' => array(
          'data'  => theme('links', $operations),
          'class' => 'sshkey-public-key-operations',
        ),
      ),
      'class' => 'sshkey-public-key-operations',
    );
  }

  $table = theme('sshkey_table', $header, $rows, array('id' => 'sshkey-public-list-key'));
  $form = drupal_get_form('sshkey_add_public_key_form', $user);
  return theme('sshkey_public_key_list_page', $table, $form);
}

function sshkey_add_public_key_form($form_state, $account) {
  $form = array();

  $form['user_object'] = array(
    '#type' => 'value',
    '#value' => $account,
  );

  $form['name'] = array(
    '#type' => 'textfield',
    '#title' => t('Name'),
    '#description' => t('The name of the public key. Will be filled in from the key comment if omitted.'),
    '#size' => 40,
    '#maxlength' => 255,
  );
  
  $form['public_key'] = array(
    '#type' => 'textarea',
    '#title' => t('Public key'),
    '#description' => t('The contents of your public key file.'),
    '#cols' => 40,
    '#rows' => 5,
    '#required' => TRUE,
  );

  $form['save'] = array(
    '#type' => 'submit',
    '#value' => t('Save'),
  );

  return $form;
}

function sshkey_add_public_key_form_validate($form, $form_state) {
  module_load_include('inc', 'sshkey');
  $values = $form_state['values'];
  $user = $values['user_object'];

  try {
    // Parse the key
    $pubkey = sshkey_public_key_parse($values['public_key']);

    // Check if the key is blacklisted.
    if (sshkey_public_key_blacklisted($pubkey['pubkey'])) {
      form_set_error('public_key', t('The key you have used is blacklisted'));
    }

    // Check if the key exists
    $exists = sshkey_public_key_load($pubkey['fingerprint']);
    if ($exists) {
      // Be a bit helpful and tell the user if the key has been added by herself,
      // or if it's been added by someone else. Not sure how to treat the double-
      // add scenario.
      if ($exists['uid'] == $user->uid) {
        form_set_error('public_key', t('You have already added this public key.'));
      }
      else {
        form_set_error('public_key', t('This public key has already been added by someone else, contact the webmaster at @email if you have any questions or suspect malicious intent.', array(
          '@email' => variable_get('site_mail', ''),
        )));
      }
    }
  }
  catch (Exception $e) {
    form_set_error('public_key', t('There was a problem with the key: !message', array(
      '!message' => $e->getMessage(),
    )));
  }
}

function sshkey_add_public_key_form_submit($form, $form_state) {
  $values = $form_state['values'];
  $user = $values['user_object'];

  try {
    sshkey_public_key_save($user->uid, $values['public_key'], $values['name']);
  }
  catch (Exception $e) {
    drupal_set_message(t('There was a problem saving your key: !message', array(
      '!message' => $e->getMessage(),
    )), 'error');
  }
}

function sshkey_page_edit_public_key($key) {
  return drupal_get_form('sshkey_edit_public_key_form', $key);
}

function sshkey_edit_public_key_form($form_state, $key) {
  $form = array();
  return $form;
}

function sshkey_page_delete_public_key($key) {
  return drupal_get_form('sshkey_delete_public_key_form', $key);
}

function sshkey_delete_public_key_form($form_state, $key) {
  $form['key_object'] = array(
    '#type' => 'value',
    '#value' => $key
  );

  $form['warning'] = array(
    '#type' => 'item',
    '#title' => t('Warning'),
    '#value' => t('Your\'e about to delete a public key, effectively disabling access for any services that use it. Are you sure that you want to do this?'),
  );

  $destination = 'user/' . $key->uid . '/sshkeys';
  if (isset($_REQUEST['destination'])) {
    $destination = $_REQUEST['destination'];
  }
  $form['cancel'] = array(
    '#type' => 'item',
    '#title' => t('Cancel'),
    '#value' => l('Click here to cancel the deletion of the key', $destination),
  );
  
  $form['delete'] = array(
    '#type' => 'submit',
    '#value' => t('Delete'),
  );

  return $form;
}

function sshkey_delete_public_key_form_submit($form, $form_state) {
  $key = $form_state['values']['key_object'];
  sshkey_public_key_delete($key['fingerprint']);
}