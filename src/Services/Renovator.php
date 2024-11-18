<?php

declare(strict_types=1);

namespace LTS\WordpressSecurityAdvisoriesRenovator\Services;

use Github\Client as GithubClient;
use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\Exception\GuzzleException;
use JsonException;
use Psr\Http\Client\ClientInterface;
use RuntimeException;

/**
 * Service to renovate dependencies
 */
class Renovator
{
    /**
     * Path to composer.json renovating file
     */
    public const COMPOSER_JSON_PATH = 'composer.json';

    /**
     * URL of Wordfence /scanner/ feed (short version of API list)
     */
    public const WORDFENCE_SCANNER_FEED_URL = 'https://www.wordfence.com/api/intelligence/v2/vulnerabilities/scanner/';

    /**
     * @var string Bot's GitHub Personal Access Token
     */
    protected string $token;

    /**
     * @var string Repository owner (format <OWNER>/<REPO>/)
     *             https://github.com/<OWNER>/<REPO>/
     */
    protected string $repo_owner;

    /**
     * @var string Repository name (format <OWNER>/<REPO>/)
     *             https://github.com/<OWNER>/<REPO>/
     */
    protected string $repo_name;

    /**
     * @var array Contents of composer.json file
     */
    protected array $composer_json_content;

    /**
     * @param ClientInterface $client
     * @param GithubClient    $github_client
     */
    public function __construct(
        protected readonly ClientInterface $client = new GuzzleClient(),
        protected readonly GithubClient $github_client = new GithubClient()
    ) {
    }

    /**
     * @param string $token      Bot's github personal access token
     * @param string $repo_owner Repository owner + next param
     * @param string $repo_name  Repository name that needs to be renovated
     *
     * @throws GuzzleException
     * @throws JsonException
     * @throws RuntimeException
     * @return void
     */
    public function renovate(string $token, string $repo_owner, string $repo_name): void
    {
        $this->token      = $token;
        $this->repo_owner = $repo_owner;
        $this->repo_name  = $repo_name;

        $composer_json_data = $this->github_client
            ->api('repo')
            ->contents()
            ->show($this->repo_owner, $this->repo_name, static::COMPOSER_JSON_PATH);
        if (!$composer_json_data || !isset($composer_json_data['content'])) {
            throw new RuntimeException('Missing composer.json content');
        }
        $this->composer_json_content = json_decode(
            base64_decode($composer_json_data['content']),
            associative: true,
            depth: 512,
            flags: JSON_THROW_ON_ERROR
        );

        $feed = $this->getScannerFeed();
        $file = file_get_contents('/renovator/Scanner_Feed-1731945545798.txt');
        $feed = json_decode($file,
            associative: true,
            depth: 512,
            flags: JSON_THROW_ON_ERROR);

        foreach ($feed as $entry) {
            $software = $entry['software'] ?? null;
            if (empty($software)) {
                continue;
            }

            foreach ($software as $item) {
                $this->updateConflictsForVulnerability($item);
            }
            die;
        }
    }

    /**
     * @throws GuzzleException
     * @throws JsonException
     * @return array{
     *     software: array{
     *         type: string,
     *         name: string,
     *         slug: string,
     *         affected_versions: array,
     *     }[]
     * }[]
     */
    protected function getScannerFeed(): array
    {
        $response = $this->client->get(static::WORDFENCE_SCANNER_FEED_URL);

        return json_decode(
            json: $response->getBody()->getContents(),
            associative: true,
            depth: 512,
            flags: JSON_THROW_ON_ERROR
        );
    }

    protected function updateConflictsForVulnerability(array $software)
    {
        if (!$software['patched']) {
            return;
        }

        $affectedVersions = $software['affected_versions'] ?? [];
        if (!is_array($affectedVersions)) {
            return;
        }

        $slug             = $software['slug'];
        $vulnerability_key        = sprintf('wpackagist-plugin/%1$s', $slug);
        foreach ($affectedVersions as $affected_version) {
            $conflict_versions_string = $this->getConflictStringForAffectedVersion($affected_version);
            if (isset($this->composer_json_content['conflict'][$vulnerability_key])) {
                var_dump('if');
                if (!str_contains($this->composer_json_content['conflict'][$vulnerability_key], $conflict_versions_string)) {
                    $this->composer_json_content['conflict'][$vulnerability_key] .= " || $conflict_versions_string";
                }
            } else {
                var_dump('else');
                $this->composer_json_content['conflict'][$vulnerability_key] = $conflict_versions_string;
            }
        }

        var_dump($this->composer_json_content);
    }

    /**
     * Gets the string of conflicts versions in format like:
     *  >2.0.0,<=2.0.3
     *  >=1.0.4,<2.0.0
     *  <=3.0.5
     *
     * @param array $affected_version
     *
     * @return string
     */
    protected function getConflictStringForAffectedVersion(array $affected_version): string
    {
        $to_version = $affected_version['to_version'] ?? null;
        if (!$to_version) {
            return '';
        }

        $from_symbol = ($affected_version['from_inclusive'] ?? null)
            ? '>='
            : '>';
        $to_symbol   = ($affected_version['to_inclusive'] ?? null)
            ? '<='
            : '<';

        $from_version = $affected_version['from_version'] ?? '*';
        $from_part    = $from_version === '*'
            ? ''
            : sprintf('%1$2%2$s', $from_symbol, $from_version);

        return $from_part
            ? sprintf('%1$s,%2$s%3$s', $from_part, $to_symbol, $to_version)
            : sprintf('%1$s%2$s', $to_symbol, $to_version);
    }

    /**
     * @return string|null
     */
    protected function getMasterSha(): ?string
    {
        $reference = $this->github_client
            ->api('gitData')
            ->references()
            ->show($this->repo_owner, $this->repo_name, 'heads/master');

        return $reference['object']['sha'] ?? null
            ? (string)$reference['object']['sha']
            : null;
    }
}
