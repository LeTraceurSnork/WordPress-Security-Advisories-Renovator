<?php

use Github\Client;
use LTS\WordpressSecurityAdvisoriesRenovator\Services\Renovator;

require 'vendor/autoload.php';

define('GITHUB_TOKEN', getenv('GITHUB_TOKEN'));
define('GITHUB_REPO_OWNER', getenv('GITHUB_REPO_OWNER'));
define('GITHUB_REPO_NAME', getenv('GITHUB_REPO_NAME'));

try {
    $client    = new Client();
    $reference = $client
        ->api('gitData')
        ->references()
        ->show('LeTraceurSnork', 'WordPress-Security-Advisories', 'heads/master');

    $renovator = new Renovator();
    $renovator->renovate(GITHUB_TOKEN, GITHUB_REPO_OWNER, GITHUB_REPO_NAME);
} catch (Exception $e) {
    var_dump($e->getMessage());
}
