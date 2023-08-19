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

Add your access token to `site/config/config.php`:

```php
<?php

return [

    # ...

    'philipptrenz.kirby-fleet-manager-connector' => [
        'token' => '<secret_token>'
    ],


    # ...
];
```

## License

Proprietary

## Credits

- [Philipp Trenz](https://github.com/philipptrenz)
