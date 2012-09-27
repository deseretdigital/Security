# DDM Security

DDM Security provides classes to simplify the creation of nonces and signatures
needed to work with DDM API's. These classes can also be used to verify nonces
and signatures.

## Basic Usage

### Generating Nonces and Signatures

```php
<?php

use DDM\Security;

$nonce = Security\Nonce::generateNonce();
$signature = Security\Signature::generateSignature($token, $nonce, $secret);
```

### Validating Nonces and Signatures

```php
<?php

use DDM\Security;

$nonceParts = Security\Nonce::splitNonce($nonce);
list($nonceTimestamp, $nonceSalt) = $nonceParts
$isNonceTimeValid = Security\Nonce::validateNonceTime($nonceTimestamp);
// Code to check if nonce has not yet been used.
// Could check database, memcache, etc. for usage of nonce

$isSignatureValid = Security\Signature::validateSignature(
    $token,
    $nonce,
    $secret,
    $memberId,
    $untrustedSignature
);
```

