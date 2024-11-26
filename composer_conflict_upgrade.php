<?php

use Github\AuthMethod;
use Github\Client;
use LTS\WordpressSecurityAdvisoriesUpgrader\Controllers\GithubApiController;
use LTS\WordpressSecurityAdvisoriesUpgrader\Services\ComposerConflictsUpgrader;
use Monolog\Handler\StreamHandler;
use Monolog\Level;
use Monolog\Logger;

require 'vendor/autoload.php';

define('BOT_PERSONAL_ACCESS_TOKEN', getenv('BOT_PERSONAL_ACCESS_TOKEN'));
define('REPO_OWNER', getenv('REPO_OWNER'));
define('REPO_NAME', getenv('REPO_NAME'));
define('API_PAUSE_BETWEEN_ACTIONS_SECONDS', (int)getenv('API_PAUSE_BETWEEN_ACTIONS_SECONDS'));

$logger = new Logger('ci_logger');
$logger->pushHandler(new StreamHandler('php://stdout', Level::Debug));

try {
    $github_client = new Client();
    $github_client->authenticate(tokenOrLogin: BOT_PERSONAL_ACCESS_TOKEN, authMethod: AuthMethod::ACCESS_TOKEN);
    $controller = new GithubApiController($github_client, REPO_OWNER, REPO_NAME);

    $renovator = new ComposerConflictsUpgrader($controller, $logger);
    $renovator->renovate(API_PAUSE_BETWEEN_ACTIONS_SECONDS);
} catch (Exception $e) {
    $logger->error($e->getMessage());
}
