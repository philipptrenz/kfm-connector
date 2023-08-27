<?php

// Run from plugin folder using `php test/test.php`

require __DIR__ . '/../vendor/autoload.php';

use Firebase\JWT\JWT;


require 'certs.php';

$options = include __DIR__ . '/../../../config/config.php';
$pluginOptions = $options['philipptrenz.kirby-fleet-manager-connector'];

$url = 'http://localhost:7000/kfm-api/v1';
$issuer = $pluginOptions['issuer'];
$audience = 'http://localhost:7000';


$payload = [
    'iss' => $issuer,
    'aud' => $audience,
    'iat' => time(),                // time of issuing
    'nbf' => time(),                // valid from
    'exp' => time() + (20 * 60),    // valid to (now + 20 minutes)
];
$jwt = JWT::encode($payload, $privateKey, 'RS256', $keyId);

$options = [
    'http' => [
        'header' => [
            "Accept: application/json",
            "Content-Type: application/json",
            "Authorization: Bearer " . $jwt,
        ],
        'method' => 'GET',
        'content' => '{}',
    ],
];
$context = stream_context_create($options);
$result = file_get_contents($url, false, $context);
if ($result === false) {
    /* Handle error */
    exit(500);
}


exit($result);