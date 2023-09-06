<?php declare(strict_types=1);

namespace PhilippTrenz\KFMConnector;

use Firebase\JWT\JWT;
use \OpenSSLAsymmetricKey;

class JWTCertificate
{

    protected OpenSSLAsymmetricKey $res;
    
    public function __construct(int|null $bits=4096)
    {
        $this->res = $this->createRsa($bits);
    }

    private function createRsa(int $bits) : OpenSSLAsymmetricKey
    {
        return openssl_pkey_new([
            'private_key_bits' => $bits,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);
    }

    private function createKidFromDetails($key) : string
    {
        return sha1($key['rsa']['n'] . $key['rsa']['e']);
    }

    public function kid() : string
    {
        $key = openssl_pkey_get_details($this->res);
        return $this->createKidFromDetails($key);    
    }

    private function getPrivateKey() : string
    {
        $privKey = null;
        openssl_pkey_export($this->res, $privKey);
        return $privKey;
    }

    // JWT related functions

    public function jwk() : array
    {
        $key = openssl_pkey_get_details($this->res);

        $kid = $this->createKidFromDetails($key);
        $modulus = $key['rsa']['n'];
        $exponent = $key['rsa']['e'];

        return [
            'kty' => 'RSA',
            'alg' => 'RS256',
            'use' => 'sig',
            'kid' => $kid,
            'n' => rtrim(str_replace(['+', '/'], ['-', '_'], base64_encode($modulus)), '='),
            'e' => rtrim(str_replace(['+', '/'], ['-', '_'], base64_encode($exponent)), '='),
        ];
    }

    private function encodeJWT($payload, $headers=null) : string
    {
        $privateKey = $this->getPrivateKey();
        return JWT::encode($payload, $privateKey, 'RS256', $this->kid(), $headers);
    }

    public function issueJWT($issuer, $audience, $validInMinutes=0, $validForMinutes=20) : string
    {
        return $this->encodeJWT([
            'iss' => $issuer,
            'aud' => $audience,
            'iat' => time(),                                                    // time of issuing
            'nbf' => time() + (60 * $validInMinutes),                           // valid from
            'exp' => time() + (60 * ($validInMinutes + $validForMinutes)),      // valid to
        ]);
    }

    /**
    * @param JWTCertificate|JWTCertificate[] $certificates
    */
    public static function toJWKS(JWTCertificate|array $certificates) : array
    {
        if($certificates instanceof JWTCertificate) {
            return [
                'keys' => [ $certificates->jwk() ]
            ];
        } else {
            return [
                'keys' => array_map(fn (JWTCertificate $c) => $c->jwk(), $certificates)
            ];
        }
    }

}
