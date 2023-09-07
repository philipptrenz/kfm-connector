<?php declare(strict_types=1);

namespace PhilippTrenz\KFMConnector;

use Kirby\Cms\App;
use Kirby\Cms\System;

/**
 * Retrieve Status of Kirby instance
 * @author Philipp Trenz
 * @copyright (c) 2023
 */
final class KirbyStatus {

    private App $kirby;

    /**
     * Constructor
     * @param \Kirby\Cms\App|null $kirby
     */
    public function __construct(App|null $kirby=null) {
        $this->kirby = $kirby ?? App::instance();
    }

    /**
     * Get plugin information
     * @param \Kirby\Cms\System $system
     * @return array
     */
    private function getPlugins(System $system): array
    {
        return $system->plugins()->values(function ($plugin) {
            $authors       = $plugin->authorsNames();
            $updateStatus  = $plugin->updateStatus();
            $version       = $plugin->version() ?? null;
            $latestVersion = $updateStatus?->toArray()['latestVersion'] ?? null;

            $plugin = [
                'author'        => empty($authors) ? null : $authors,
                'license'       => $plugin->license() ?? null,
                'link'          => $plugin->link() ?? null,
                'name'          => $plugin->name() ?? null,
                'version'       => $version
            ];

            $latestVersion = $updateStatus?->toArray()['latestVersion'] ?? null;
            if ($latestVersion != '?') $plugin['latestVersion'] = $latestVersion;

            return $plugin;
        });
    }

    /**
     * Get system information
     * @param \Kirby\Cms\System $system
     * @return array
     */
    private function getSystem(System $system) : array
    {
        return [
            'environment' => [
                'license' => $system->license(),
                'version' => $this->kirby->version(),
                'php' => phpversion(),
                'server' => $system->serverSoftware() ?? null
            ],
            'security' => [
                'debug' => $this->kirby->option('debug', false) === true,
                'https' => $this->kirby->environment()->https() === true,
            ],
            'plugins' => $this->getPlugins($system),
        ];
    }

    /**
     * Retrieve status of Kirby instance
     * @return array
     */
    public function getStatus(): array
    {
        return [
            'url' => $this->kirby->site()->url(),
            'users' => $this->kirby->users()->count(),
            'system' => $this->getSystem($this->kirby->system())
        ];
    }

}