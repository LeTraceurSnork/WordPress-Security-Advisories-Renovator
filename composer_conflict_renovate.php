<?php

require 'vendor/autoload.php';

use GuzzleHttp\Exception\GuzzleException;

define('GITHUB_TOKEN', getenv('GITHUB_TOKEN'));
define('GITHUB_REPO', getenv('GITHUB_REPO'));
define('COMPOSER_JSON_PATH', 'composer.json');

try {
//    (new WordfenceController())->getScannerFeed();
} catch (JsonException|GuzzleException $e) {

}