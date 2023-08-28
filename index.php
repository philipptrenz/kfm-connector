<?php

@include_once __DIR__ . '/vendor/autoload.php';

use Kirby\Cms\App;
use PhilippTrenz\KFMConnector\RequestHandler;


App::plugin('philipptrenz/kirby-fleet-manager-connector', [

    'options' => [
        'cache' => true
    ],
	'routes' => [
        [
            'pattern' => 'kfm-api/v1',
            'method' => 'GET',
            'action'  => function() {
                return RequestHandler::process();
            },
        ]
    ],

]);
