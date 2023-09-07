<?php declare(strict_types=1);

namespace PhilippTrenz\KFMConnector;

use Kirby\Cms\App;

final class KirbyStatus {

    private App $kirby;
    public function __construct(App $kirby=null) {
        $this->kirby = $kirby ?? App::instance();
    }

    private function getPlugins($system, $exceptions): array
    {
        return $system->plugins()->values(function ($plugin) use (&$exceptions) {
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
                'link'          => $plugin->link() ?? null,
                'name'          => $plugin->name() ?? null,
                'version'       => $version,
                'latestVersion' => $latestVersion
            ];
        });
    } 

    public function getStatus(): array
    {
        $system       = $this->kirby->system();
        $updateStatus = $system->updateStatus();
        $license      = $system->license();
        $exceptions   = $updateStatus?->exceptionMessages() ?? [];

        return [
            'url' => site()->url(),
            'users' => $this->kirby->users()->count(),
            'system' => [
                'environment' => [
                    'license' => $license,
                    'version' => $this->kirby->version(),
                    'php' => phpversion(),
                    'server' => $system->serverSoftware() ?? null
                ],
                'security' => [
                    'debug' => $this->kirby->option('debug', false) === true,
                    'https' => $this->kirby->environment()->https() === true,
                ],
                'plugins' => $this->getPlugins($system, $exceptions),
            ]
        ];
    }

}