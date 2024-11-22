<?php

use Github\Client;
use LTS\WordpressSecurityAdvisoriesRenovator\Services\Renovator;

require 'vendor/autoload.php';

define('BOT_PERSONAL_ACCESS_TOKEN', getenv('BOT_PERSONAL_ACCESS_TOKEN'));
define('REPO_OWNER', getenv('REPO_OWNER'));
define('REPO_NAME', getenv('REPO_NAME'));

try {
    $client    = new Client();
    $reference = $client
        ->api('gitData')
        ->references()
        ->show('LeTraceurSnork', 'WordPress-Security-Advisories', 'heads/master');

    $renovator = new Renovator();
    $renovator->renovate(BOT_PERSONAL_ACCESS_TOKEN, REPO_OWNER, REPO_NAME);
} catch (Exception $e) {
    var_dump($e->getMessage());
}
