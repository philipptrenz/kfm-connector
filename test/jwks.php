<?php

// Run from plugin folder using `php -S localhost:8000 test/jwks.php`

require __DIR__ . '/../vendor/autoload.php';
require 'certs.php';

$keyInfo = openssl_pkey_get_details(openssl_pkey_get_public($publicKey));

$rsaKey = [
    'kty' => 'RSA',
    'alg' => 'RS256',
    'use' => 'sig',
    'kid' => $keyId,
    'n' => rtrim(str_replace(['+', '/'], ['-', '_'], base64_encode($keyInfo['rsa']['n'])), '='),
    'e' => rtrim(str_replace(['+', '/'], ['-', '_'], base64_encode($keyInfo['rsa']['e'])), '='),
];

function returnJwks($keys) {
    $json = json_encode([
        'keys' => $keys
    ]);
    exit($json);
}

returnJwks([
    $rsaKey,
]);