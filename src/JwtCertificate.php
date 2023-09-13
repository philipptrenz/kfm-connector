<?php declare(strict_types=1);

namespace PhilippTrenz\KFMConnector;

use Exception;
use Firebase\JWT\JWT;
use \OpenSSLAsymmetricKey;

/**
 * Create and use certificates for JWT signing
 * 
 * Note: Currently, only RSA is supported, ECDSA + P-256 + SHA256 might be added later
 * 
 * @author Philipp Trenz
 * @copyright (c) 2023
 */
class JwtCertificate
{

    protected OpenSSLAsymmetricKey $res;
    
    /**
     * Create a new certificate
     * @param int $bits
     * @throws \Exception
     */
    public function __construct(int $bits=4096)
    {
        $this->res = $this->createRsa($bits);
    }

    /**
     * Creates an RSA certificate with specified bit length
     * @param int $bits
     * @return \OpenSSLAsymmetricKey
     */
    private function createRsa(int $bits) : OpenSSLAsymmetricKey
    {
        return openssl_pkey_new([
            'private_key_bits' => $bits,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
            'default_md' => 'sha256'
        ]);
    }

    /**
     * Creates a key id from public key base and exponent
     * @param array $key
     * @return string
     */
    private function createKidFromDetails(array $key) : string
    {
        return sha1($key['rsa']['n'] . $key['rsa']['e']);
    }

    /**
     * Provides a key id for the certificate
     * @return string
     */
    public function kid() : string
    {
        $key = openssl_pkey_get_details($this->res);
        return $this->createKidFromDetails($key);    
    }

    /**
     * Provides the private key as PEM formatted string
     * @return string
     */
    private function getPrivateKey() : string
    {
        $privKey = null;
        openssl_pkey_export($this->res, $privKey);
        return $privKey;
    }

    /**
     * Creates a JSON Web Key after RFC7517
     * 
     * See: https://datatracker.ietf.org/doc/html/rfc7517
     * 
     * @return array
     */
    public function jwk() : array
    {
        $key = openssl_pkey_get_details($this->res);

        $kid = $this->createKidFromDetails($key);
        $modulus = $key['rsa']['n'];
        $exponent = $key['rsa']['e'];

        return [
            'kty' => 'RSA',
            'use' => 'sig',
            'alg' => 'RS256',
            'kid' => $kid,
            'n' => rtrim(str_replace(['+', '/'], ['-', '_'], base64_encode($modulus)), '='),
            'e' => rtrim(str_replace(['+', '/'], ['-', '_'], base64_encode($exponent)), '='),
        ];
    }

    /**
     * Encodes a payload array into a signed JWT token string
     * @param array $payload
     * @param array|null $headers
     * @return string
     */
    private function encodeJWT(array $payload, array|null $headers=null) : string
    {
        $privateKey = $this->getPrivateKey();
        return JWT::encode($payload, $privateKey, 'RS256', $this->kid(), $headers);
    }

    /**
     * Creates a JWT token string
     * @param string $issuer
     * @param string $audience
     * @param int $validInMinutes
     * @param int $validForMinutes
     * @return string
     */
    public function issueJWT(string $issuer, string $audience, int $validInMinutes=0, int $validForMinutes=20) : string
    {
        return $this->encodeJWT([
            'iss' => rtrim($issuer, '/'),
            'aud' => rtrim($audience, '/'),
            'iat' => time(),                                                    // time of issuing
            'nbf' => time() + (60 * $validInMinutes),                           // valid from
            'exp' => time() + (60 * ($validInMinutes + $validForMinutes)),      // valid to
        ]);
    }

    /**
     * Encodes JwtCertificate instances into a Json Web Key Set after RFC7517
     * 
     * See: https://datatracker.ietf.org/doc/html/rfc7517
     * 
     * @param \PhilippTrenz\KFMConnector\JwtCertificate|array $certificates
     * @return array
     */
    public static function toJWKS(JwtCertificate|array $certificates) : array
    {
        if($certificates instanceof JwtCertificate) return [
            'keys' => [ $certificates->jwk() ]
        ];
        else return [
            'keys' => array_map(
                fn (JwtCertificate $c) => $c->jwk(), 
                $certificates
            )
        ];
    }

}
