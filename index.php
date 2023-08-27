<?php

@include_once __DIR__ . '/vendor/autoload.php';

use Kirby\Cms\App;
use PhilippTrenz\KFMConnector\API;


App::plugin('philipptrenz/kirby-fleet-manager-connector', [

    'options' => [
        'cache' => true
    ],
	'routes' => [
        [
            'pattern' => 'kfm-api/v1',
            'method' => 'GET',
            'action'  => function() {
                return (new Api)->handleRequest();
            },
        ]
    ],

]);
