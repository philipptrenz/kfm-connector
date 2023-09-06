<?php
require_once __DIR__ . '/../../../../kirby/bootstrap.php';

use Kirby\Cms\App;

new App([
    'roots' => [
      'config' => __DIR__ . '/kirby/config',
    ]
]);