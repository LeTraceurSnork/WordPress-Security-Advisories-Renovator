<?php

use Github\AuthMethod;
use Github\Client;
use LTS\WordpressSecurityAdvisoriesRenovator\Controllers\GithubApiController;
use LTS\WordpressSecurityAdvisoriesRenovator\Services\ComposerConflictsRenovator;

require 'vendor/autoload.php';

define('BOT_PERSONAL_ACCESS_TOKEN', getenv('BOT_PERSONAL_ACCESS_TOKEN'));
define('REPO_OWNER', getenv('REPO_OWNER'));
define('REPO_NAME', getenv('REPO_NAME'));
define('API_PAUSE_BETWEEN_ACTIONS_SECONDS', getenv('API_PAUSE_BETWEEN_ACTIONS_SECONDS'));

try {
    $github_client = new Client();
    $github_client->authenticate(tokenOrLogin: BOT_PERSONAL_ACCESS_TOKEN, authMethod: AuthMethod::ACCESS_TOKEN);
    $controller = new GithubApiController($github_client, REPO_OWNER, REPO_NAME);

    $renovator = new ComposerConflictsRenovator($controller);
    $renovator->renovate(API_PAUSE_BETWEEN_ACTIONS_SECONDS);
} catch (Exception $e) {
    var_dump($e->getMessage());
}
