<?php

/**
 * Parses a public key.
 *
 * @param string $pubkey
 * @return array
 *  An array containing the algo, key, comment, fingerprint, decoded key data as data and the sanitized
 *  public key as pubkey.
 * @throws Exception
 *  A exception is thrown if the public key can't be parsed (error code
 *  SSHKEY_PARSE_ERROR).
 */
function sshkey_public_key_parse($pubkey) {
  // Be tolerant of linebreaks and extra spaces.
  $pubkey = preg_replace('/\n|\r/', '', $pubkey);
  $pubkey = preg_replace('/\s{2,}/', ' ', $pubkey);
  $pubkey = trim($pubkey);

  // Explode the key into it's components.
  $parts = explode(' ', $pubkey, 3);
  if (count($parts) < 2) {
    throw new Exception(t('Could not parse the public key'), SSHKEY_PARSE_ERROR);
  }

  // Shift out the parts of the public key.
  $key = array(
    'algo' => array_shift($parts),
    'key' => array_shift($parts),
    'comment' => '',
    'pubkey' => $pubkey,
  );
  if (!empty($parts)) {
    $key['comment'] = array_shift($parts);
  }

  // Decode the key data so that we can create a fingerprint.
  $key['data'] = base64_decode($key['key']);
  if ($key['data'] === FALSE) {
    throw new Exception(t('Could not decode the key data'), SSHKEY_PARSE_ERROR);
  }
  $key['fingerprint'] = hash('md5', $key['data']);

  return $key;
}

/**
 * Checks a key against the ubuntu/debian blacklist using ssh-vulnkey.
 *
 * @param string $pubkey
 * @return bool|object
 *  Returns TRUE if the key is blacklisted. FALSE if the key has been verified
 *  as non-blacklisted. Or NULL if we couldn't verify the key.
 */
function sshkey_public_key_blacklisted($pubkey) {
  $vulnkey = variable_get('sshkey_ssh_vulnkey', '');
  $blacklisted = NULL;

  if (!empty($vulnkey) && is_executable($vulnkey)) {
    $descriptorspec = array(
       0 => array("pipe", "r"), // stdin
       1 => array("pipe", "w"), // stdout
    );
    // Open ssh-vulnkey in verbose mode so that we get output
    // even when the key isn't blacklisted.
    $process = proc_open(sprintf('%s -v -', $vulnkey), $descriptorspec, $pipes);

    // Write the public key to stdin
    fwrite($pipes[0], $pubkey);
    fclose($pipes[0]);

    // Get result from stdout
    $result = stream_get_contents($pipes[1]);
    fclose($pipes[1]);

    // Close process handle and get the return code
    $retcode = proc_close($process);
    // Retcode 0 means that the code is blacklisted
    if ($retcode == 0) {
      $blacklisted = TRUE;
    }
    else {
      // Check response so that we know if the key really has been checked
      // we're looking for the response message 'Not blacklisted' as it could
      // also be 'Unknown (blacklist file not installed)' and in that case
      // we'll just let the response ($blacklisted) remain as NULL.
      list($line) = explode("\n", $result);
      list($file, $line_num, $message, $key) = explode(':', $line, 4);
      if (trim($message) == 'Not blacklisted') {
        $blacklisted = FALSE;
      }
    }
  }
  return $blacklisted;
}

/**
 * Migrates key files to a new directory.
 *
 * @param string $directory
 * @return void
 * @throws Exception
 *  Throws a exception if: the current directory isn't readable (error code
 *  SSHKEY_ACCESS_DENIED); all keys couldn't be copied to the new
 *  directory (error code SSHKEY_IO_FAILURE).
 */
function sshkey_migrate_key_files($directory) {
  $current_directory = sshkey_get_key_directory();
  // Check if keys should be moved. If the current directory doesn't exist
  // we can safely ignore the move parameter.
  if (file_exists($current_directory)) {
    if (!is_readable($current_directory)) {
      throw new Exception(t('Move keys was specified but the current directory cannot be read from'), SSHKEY_ACCESS_DENIED);
    }
    $remove = array();

    // Copy all public key files to the new directory.
    $dh = opendir($current_directory);
    while ($file = readdir($dh)) {
      if (substr($file, -3) === '.pub') {
        if (!copy($current_directory . '/' . $file, $directory . '/' . $file)) {
          throw new Exception(t('Could not copy all keys from the current directory'), SSHKEY_IO_FAILURE);
        }
        $remove[] = $current_directory . '/' . $file;
      }
    }
    // Remove all the public keys that we've moved.
    // Failure to remove a public key is a strictly non-fatal error.
    foreach ($remove as $file) {
      if (is_writable($file)) {
        unlink($file);
      }
    }
  }
}
