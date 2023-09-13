# Kirby Fleet Manager Connector

This is the official Kirby plugin to connect your [Kirby](https://getkirby.com) website to the [Kirby Fleet Manager](https://github.com/philipptrenz/kirby-fleet-manager).

## Installation

### Download

Download and copy this repository to `/site/plugins/kfm-connector`.

### Git submodule

```
git submodule add https://github.com/philipptrenz/kfm-connector.git site/plugins/kfm-connector
```


### Composer

```
composer require philipptrenz/kfm-connector
```

## Setup

Add the base url to your Kirby Fleet Manager instance as issuer to `site/config/config.php` (make sure to use a secure SSL connection):

```php
<?php

return [
    # ...

    'philipptrenz.kfm-connector' => [
        'issuer' => 'https://my-kirby-fleet-manager-instance.com',#

        'jwks_cache_duration' => 4320,  // OPTIONAL; in minutes, defaults to 3 days
        'ip_whitelist' => [             // OPTIONAL; limits access to listed IPs, if set
            '::1',
            '127.0.0.1'
        ]
    ],

    # ...
];
```

## Test

```bash
./vendor/bin/phpunit --bootstrap ./tests/bootstrap.php --testdox ./tests/suites
```

## License

MIT

---

© 2023 Philipp Trenz
