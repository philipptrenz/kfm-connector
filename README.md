# Kirby Fleet Manager Connector

This is the official Kirby plugin to connect your [Kirby](https://getkirby.com) website to the [Kirby Fleet Manager](https://github.com/philipptrenz/kirby-fleet-manager).

## Installation

### Download

Download and copy this repository to `/site/plugins/kirby-fleet-manager-connector`.

### Git submodule

```
git submodule add philipptrenz/kirby-fleet-manager-connector.git site/plugins/kirby-fleet-manager-connector
```

### Composer

```
composer require philipptrenz/kirby-fleet-manager-connector
```

## Setup

Add the base url to your Kirby Fleet Manager instance as issuer to `site/config/config.php` (make sure to use a secure SSL connection):

```php
<?php

return [

    # ...

    'philipptrenz.kirby-fleet-manager-connector' => [
        'issuer' => 'https://example.com',
    ],

    # ...
];
```

## Test

```bash
./vendor/bin/phpunit --bootstrap ./tests/bootstrap.php --testdox ./tests/suites
```

## License

Proprietary

---

© 2023 Philipp Trenz
