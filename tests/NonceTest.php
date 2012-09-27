<?php

use DDM\Security;

class NonceTest extends PHPUnit_Framework_TestCase
{
    /**
     * @test
     */
    public function generateNonce()
    {
        $nonce = Security\Nonce::generateNonce();
        $this->assertInternalType('string', $nonce);

        $followsRegex = preg_match(Security\Nonce::NONCE_REGEX, $nonce);
        $this->assertEquals($followsRegex, 1);

        return $nonce;
    }

    /**
     * @test
     * @depends generateNonce
     */
    public function splitNonce($nonce)
    {
        $nonceParts = Security\Nonce::splitNonce($nonce);
        $this->assertInternalType('array', $nonceParts);
        $this->assertCount(2, $nonceParts);
        $this->assertInternalType('int', $nonceParts[0], 'Nonce timestamp is not an int');
        $this->assertInternalType('string', $nonceParts[1], 'Nonce salt is not a string');
    }

    /**
     * @test
     */
    public function splitNonceKsl()
    {
        $nonce = Security\Nonce::generateNonce(16);
        $nonceParts = Security\Nonce::splitNonce($nonce);
        $this->assertInternalType('array', $nonceParts);
        $this->assertCount(2, $nonceParts);
        $this->assertInternalType('int', $nonceParts[0], 'Nonce timestamp is not an int');
        $this->assertInternalType('string', $nonceParts[1], 'Nonce salt is not a string');
    }

    /**
     * @test
     */
    public function validateNonceTimeValid()
    {;
        $time = time();
        $isValid = Security\Nonce::validateNonceTime($time);

        $this->assertTrue($isValid);
    }

    /**
     * @test
     */
    public function validateNonceTimeInvalidPast()
    {
        $time = strtotime('-' . Security\Nonce::ALLOWED_TIME_SKEW . ' seconds');
        $time = strtotime('-1 second', $time);
        $isValid = Security\Nonce::validateNonceTime($time);

        $this->assertFalse($isValid);
    }

    /**
     * @test
     */
    public function validateNonceTimeInvalidFuture()
    {
        $time = strtotime('+' . Security\Nonce::ALLOWED_TIME_SKEW . ' seconds');
        $time = strtotime('+1 second', $time);
        $isValid = Security\Nonce::validateNonceTime($time);

        $this->assertFalse($isValid);
    }

    /**
     * @test
     */
    public function getExpiredTime()
    {
        $time = time();
        $expiredTime = strtotime('-' . Security\Nonce::ALLOWED_TIME_SKEW . ' seconds', $time);
        $testExpiredTime = Security\Nonce::getExpiredTime(null, $time);

        $this->assertEquals($testExpiredTime, $expiredTime);
    }

    /**
     * @test
     */
    public function getExpiredTimestamp()
    {
        $time = time();
        $expiredTime = strtotime('-' . Security\Nonce::ALLOWED_TIME_SKEW . ' seconds', $time);
        $timestamp = gmstrftime(Security\Nonce::NONCE_DATEFORMAT, $expiredTime);
        $testTimestamp = Security\Nonce::getExpiredTimestamp($time);

        $this->assertEquals($testTimestamp, $timestamp);
    }
}

