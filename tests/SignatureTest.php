<?php

use \DDM\Security;

class SignatureTest extends PHPUnit_Framework_TestCase
{
    /**
     * @test
     */
    public function generateSignature()
    {
        $token = 'token';
        $nonce = Security\Nonce::generateNonce();
        $secret = 'secret';

        $signature = Security\Signature::generateSignature(
            $token,
            $nonce,
            $secret
        );

        $this->assertInternalType('string', $signature);

        return array(
            'token' => $token,
            'nonce' => $nonce,
            'secret' => $secret,
            'memberId' => 0,
            'signature' => $signature,
        );
    }

    /**
     * @test
     * @depends generateSignature
     */
    public function validateSignatureValid($request)
    {
        $isSignatureValid = Security\Signature::validateSignature(
            $request['token'],
            $request['nonce'],
            $request['secret'],
            $request['memberId'],
            $request['signature']
        );

        $this->assertTrue($isSignatureValid);
    }

    /**
     * @test
     * @depends generateSignature
     */
    public function validateSignatureInvalidToken($request)
    {
        $isSignatureValid = Security\Signature::validateSignature(
            'invalid',
            $request['nonce'],
            $request['secret'],
            $request['memberId'],
            $request['signature']
        );

        $this->assertFalse($isSignatureValid);
    }

    /**
     * @test
     * @depends generateSignature
     */
    public function validateSignatureInvalidNonce($request)
    {
        $isSignatureValid = Security\Signature::validateSignature(
            $request['token'],
            'invalid',
            $request['secret'],
            $request['memberId'],
            $request['signature']
        );

        $this->assertFalse($isSignatureValid);
    }

    /**
     * @test
     * @depends generateSignature
     */
    public function validateSignatureInvalidSecret($request)
    {
        $isSignatureValid = Security\Signature::validateSignature(
            $request['token'],
            $request['nonce'],
            'invalid',
            $request['memberId'],
            $request['signature']
        );

        $this->assertFalse($isSignatureValid);
    }

    /**
     * @test
     * @depends generateSignature
     */
    public function validateSignatureInvalidMemberId($request)
    {
        $isSignatureValid = Security\Signature::validateSignature(
            $request['token'],
            $request['nonce'],
            $request['secret'],
            'invalid',
            $request['signature']
        );

        $this->assertFalse($isSignatureValid);
    }

    /**
     * @test
     * @depends generateSignature
     */
    public function validateSignatureInvalidSignature($request)
    {
        $isSignatureValid = Security\Signature::validateSignature(
            $request['token'],
            $request['nonce'],
            $request['secret'],
            $request['memberId'],
            'invalid'
        );

        $this->assertFalse($isSignatureValid);
    }
}

