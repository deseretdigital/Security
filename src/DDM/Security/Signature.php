<?php

/**
 * Creates and verifies signatures
 */

namespace DDM\Security;

class Signature
{
    /**
     * Generates a signature
     *
     * @param string $token
     * @param string $nonce
     * @param string $secret
     * @param string $memberId OPTIONAL
     * @param string $hash OPTIONAL
     *
     * @return string
     */
    public static function generateSignature($token, $nonce, $secret, $memberId = 0, $hash = 'sha1')
    {
        $data = $token . $memberId . $nonce;
        $hmac = hash_hmac($hash, $data, $secret);
        return $hmac;
    }

    /**
     * Validates a signature using token, nonce, and secret
     *
     * @param string $token
     * @param string $nonce
     * @param string $secret
     * @param string $memberId
     * @param string $signature
     * @param string $hash OPTIONAL
     *
     * @return boolean
     */
    public static function validateSignature($token, $nonce, $secret, $memberId, $signature, $hash = 'sha1')
    {
        $testHmac = self::generateSignature($token, $nonce, $secret, $memberId, $hash);
        return $testHmac == $signature;
    }
}

