<?php

use Firebase\JWT\BeforeValidException;
use Firebase\JWT\ExpiredException;
use Kirby\Cms\App;
use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use PHPUnit\Framework\TestCase;
use PhilippTrenz\KFMConnector\JWTCertificate;

final class JWTCertificateTest extends TestCase {

    private App $kirby;
    private string $audience;
    private string $issuer;

    protected function setUp() : void
    {        
        $this->kirby    = kirby();
        $this->audience = $this->kirby->site()->url();
        $this->issuer   = $this->kirby->option('philipptrenz.kirby-fleet-manager-connector.issuer', null);
    }

    public function testJwtIssuing() : void
    {
        // Server side part
        $cert = new JWTCertificate();
        $jwt = $cert->issueJWT($this->issuer, $this->audience);
        $jwks = JWTCertificate::toJWKS($cert);

        // Client part
        $keyset = JWK::parseKeySet($jwks);
        $payload = JWT::decode($jwt, $keyset);

        $this->assertEquals($payload->iss, $this->issuer);
        $this->assertEquals($payload->aud, $this->audience);
    }

    public function testJwtIssuingWith2048BitRsa() : void
    {
        $cert = new JWTCertificate(2048);
        $jwt = $cert->issueJWT($this->issuer, $this->audience);
        $jwks = JWTCertificate::toJWKS($cert);

        $keyset = JWK::parseKeySet($jwks);
        $payload = JWT::decode($jwt, $keyset);

        $this->assertEquals($payload->iss, $this->issuer);
        $this->assertEquals($payload->aud, $this->audience);
    }

    public function testJwtBeforeValid() : void
    {
        $this->expectException(BeforeValidException::class);

        $cert = new JWTCertificate();
        $jwt = $cert->issueJWT($this->issuer, $this->audience, 5, 5);
        $jwks = JWTCertificate::toJWKS($cert);

        // Client part
        $keyset = JWK::parseKeySet($jwks);
        JWT::decode($jwt, $keyset);
    }

    public function testJwtExpired() : void
    {
        $this->expectException(ExpiredException::class);

        $cert = new JWTCertificate();
        $jwt = $cert->issueJWT($this->issuer, $this->audience, -5, 4);
        $jwks = JWTCertificate::toJWKS($cert);

        // Client part
        $keyset = JWK::parseKeySet($jwks);
        JWT::decode($jwt, $keyset);
    }

    public function testJwtMalformed() : void
    {
        $this->expectException(UnexpectedValueException::class);

        $cert = new JWTCertificate();
        $jwt = '1234';
        $jwks = JWTCertificate::toJWKS($cert);

        // Client part
        $keyset = JWK::parseKeySet($jwks);
        JWT::decode($jwt, $keyset);
    }

    public function testJwtMissingKidInJwks() : void
    {
        $this->expectException(UnexpectedValueException::class);

        $cert = new JWTCertificate();
        $jwt = $cert->issueJWT($this->issuer, $this->audience, -5, 4);
        $jwks = JWTCertificate::toJWKS($cert);
        $jwks['keys']['']['kid'] = 'unknown-kid';

        // Client part
        $keyset = JWK::parseKeySet($jwks);
        JWT::decode($jwt, $keyset);
    }
}