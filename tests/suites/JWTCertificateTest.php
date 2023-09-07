<?php

use Kirby\Cms\App;
use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use PHPUnit\Framework\TestCase;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\BeforeValidException;
use Firebase\JWT\SignatureInvalidException;
use PhilippTrenz\KFMConnector\JwtCertificate;

final class JwtCertificateTest extends TestCase {

    private App $kirby;
    private string $audience;
    private string $issuer;

    protected function setUp() : void
    {        
        $this->kirby    = kirby();
        $this->audience = $this->kirby->site()->url();
        $this->issuer   = $this->kirby->option('philipptrenz.kfm-connector.issuer');
    }

    public function testJwtIssuing() : void
    {        
        // Server side part
        $cert = new JwtCertificate();
        $jwt = $cert->issueJWT($this->issuer, $this->audience);
        $jwks = JwtCertificate::toJWKS($cert);

        // Client part
        $keyset = JWK::parseKeySet($jwks);
        $payload = JWT::decode($jwt, $keyset);

        $this->assertEquals($payload->iss, $this->issuer);
        $this->assertEquals($payload->aud, $this->audience);
    }

    public function testJwtIssuingWith2048BitRsa() : void
    {
        $cert = new JwtCertificate(2048);
        $jwt = $cert->issueJWT($this->issuer, $this->audience);
        $jwks = JwtCertificate::toJWKS($cert);

        $keyset = JWK::parseKeySet($jwks);
        $payload = JWT::decode($jwt, $keyset);

        $this->assertEquals($payload->iss, $this->issuer);
        $this->assertEquals($payload->aud, $this->audience);
    }

    public function testJwtBeforeValid() : void
    {
        $this->expectException(BeforeValidException::class);

        $cert = new JwtCertificate();
        $jwt = $cert->issueJWT($this->issuer, $this->audience, 5, 5);
        $jwks = JwtCertificate::toJWKS($cert);

        // Client part
        $keyset = JWK::parseKeySet($jwks);
        JWT::decode($jwt, $keyset);
    }

    public function testJwtSignatureInvalid() : void
    {
        $this->expectException(SignatureInvalidException::class);

        $cert = new JwtCertificate();
        $jwt = $cert->issueJWT($this->issuer, $this->audience, -5, 4);
        $jwks = JwtCertificate::toJWKS($cert);

        // Create JWKS with kid of signing cert, but different public key
        $cert2 = new JwtCertificate();
        $jwks = JwtCertificate::toJWKS($cert2);
        $jwks['keys'][0]['kid'] = $cert->kid();

        // Client part
        $keyset = JWK::parseKeySet($jwks);
        JWT::decode($jwt, $keyset);
    }

    public function testJwtExpired() : void
    {
        $this->expectException(ExpiredException::class);

        $cert = new JwtCertificate();
        $jwt = $cert->issueJWT($this->issuer, $this->audience, -5, 4);
        $jwks = JwtCertificate::toJWKS($cert);

        // Client part
        $keyset = JWK::parseKeySet($jwks);
        JWT::decode($jwt, $keyset);
    }

    public function testJwtMalformed() : void
    {
        $this->expectException(UnexpectedValueException::class);

        $cert = new JwtCertificate();
        $jwt = '1234';
        $jwks = JwtCertificate::toJWKS($cert);

        // Client part
        $keyset = JWK::parseKeySet($jwks);
        JWT::decode($jwt, $keyset);
    }

    public function testJwtMissingKidInJwks() : void
    {
        $this->expectException(UnexpectedValueException::class);

        $cert = new JwtCertificate();
        $jwt = $cert->issueJWT($this->issuer, $this->audience, -5, 4);
        $jwks = JwtCertificate::toJWKS($cert);
        $jwks['keys']['']['kid'] = 'unknown-kid';

        // Client part
        $keyset = JWK::parseKeySet($jwks);
        JWT::decode($jwt, $keyset);
    }
}