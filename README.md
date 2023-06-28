# kirby-teleinfo

A diagnostics API for Kirby

## Install

1. Add this repository to your Kirby installation:

```bash
git submodule add https://github.com/philipptrenz/kirby-teleinfo.git site/plugins/kirby-teleinfo
```

2. Add an access token to `site/config/config.php`:

```php
<?php

return [

    # ...

    'philipptrenz.kirby-teleinfo' => [
        'token' => '<secret_token>'
    ],


    # ...
];
```