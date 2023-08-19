<?php

@include_once __DIR__ . '/vendor/autoload.php';

use Kirby\Cms\App;

Kirby::plugin('philipptrenz/kirby-fleet-manager-connector', [

	'routes' => [
        [
            'pattern' => 'teleinfo',
            'method' => 'POST',
            'action'  => function () {
                $token = get('token');
                if ($token !== option('philipptrenz.kirby-fleet-manager-connector.token')) {
                    return new Response([
                        'code' => 401,
                        'message' => 'Not authorized'
                    ]);
                }

                $kirby        = App::instance();
                $system       = $kirby->system();
                $updateStatus = $system->updateStatus();
                $license      = $system->license();
                $exceptions = $updateStatus?->exceptionMessages() ?? [];
                $plugins      = $system->plugins()->values(function ($plugin) use (&$exceptions) {
                    $authors       = $plugin->authorsNames();
                    $updateStatus  = $plugin->updateStatus();
                    $version       = $plugin->version() ?? null;
                    $latestVersion = $updateStatus?->toArray()['latestVersion'] ?? null;

                    if ($latestVersion == '?') $latestVersion = null;
                    if ($updateStatus !== null) {
                        $exceptions = array_merge($exceptions, $updateStatus->exceptionMessages());
                    }
    
                    return [
                        'author'        => empty($authors) ? null : $authors,
                        'license'       => $plugin->license() ?? null,
                        /*'name'        => [
                            'text' => $plugin->name() ?? '–',
                            'href' => $plugin->link(),
                        ],*/
                        'name'          => $plugin->name() ?? null,
                        'version'       => $version,
                        'latestVersion' => $latestVersion
                    ];
                });

                $latestVersion = $updateStatus?->toArray()['latestVersion'] ?? null;
                if ($latestVersion == '?') $latestVersion = null;
    
                $info = [
                    'url' => site()->url(),
                    'users' => $kirby->users()->count(),
                    'system' => [
                        'environment' => [
                            'license' => $license,
                            'version' => $kirby->version(),
                            'latestVersion' => $latestVersion,
                            'php' => phpversion(),
                            'server' => $system->serverSoftware() ?? null
                        ],
                        'security' => [
                            'debug' => $kirby->option('debug', false) === true,
                            'https' => $kirby->environment()->https() === true,
                        ],
                        'plugins' => $plugins,
                    ]
                ];
    
                return response::json($info);
            }
        ]
    ],

]);
