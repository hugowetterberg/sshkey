SSH Key
====================

Manages OpenSSH public keys for Drupal accounts.

* Allow associating more than one key to a user.
* Disallow adding the same key twice by calculating and using the key fingerprint.
* Validates the key format.
* Checks keys against the openssh-blacklist using ssh-vulnkey.
