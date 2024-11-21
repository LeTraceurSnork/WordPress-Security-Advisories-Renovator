<?php

declare(strict_types=1);

namespace LTS\WordpressSecurityAdvisoriesRenovator\Services;

use Composer\Semver\VersionParser;
use Exception;
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
     * @param VersionParser   $versionParser
     */
    public function __construct(
        protected readonly ClientInterface $client = new GuzzleClient(),
        protected readonly GithubClient $github_client = new GithubClient(),
        protected readonly VersionParser $versionParser = new VersionParser(),
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
        $this->token                 = $token;
        $this->repo_owner            = $repo_owner;
        $this->repo_name             = $repo_name;
        $this->composer_json_content = $this->getComposerJsonContent();

        $feed = $this->getScannerFeed();

        $time1 = time();
        foreach ($feed as $entry) {
            if (empty($entry['software'])) {
                continue;
            }

            $updated = $this->updateConflictsForVulnerability($entry);
        }
        $time2 = time();
        var_dump($time2 - $time1);

        $encoded = json_encode(value: $this->composer_json_content, flags: JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);

        file_put_contents('new_composer.txt', $encoded);
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
            flags: JSON_THROW_ON_ERROR
        );
    }

    /**
     * Updates composer.json conflict section for specified vulnerability.
     *
     * @param array $entry
     *
     * @return bool Whether composer.json was updated or not.
     */
    protected function updateConflictsForVulnerability(array $entry): bool
    {
        $updated  = false;
        $software = $entry['software'];
        if (empty($software)) {
            return false;
        }

        foreach ($software as $software_entry) {
            $affectedVersions = $software_entry['affected_versions'] ?? [];
            if (!is_array($affectedVersions) || empty($affectedVersions)) {
                continue;
            }

            $entry_type = $software_entry['type'];
            switch ($entry_type) {
                case 'plugin':
                case 'theme':
                    $vulnerability_key =
                        strtolower(sprintf('wpackagist-%1$s/%2$s', $entry_type, $software_entry['slug']));

                    break;

                case 'core':
                    if ($software_entry['slug'] !== 'wordpress') {
                        break;
                    }

                    $vulnerability_key = 'roots/wordpress';

                    break;

                default:
                    break;
            }

            if (!isset($vulnerability_key)) {
                continue;
            }

            foreach ($affectedVersions as $affected_version) {
                $conflict_versions_string = $this->getConflictStringForAffectedVersion($affected_version);
                if (!isset($conflict_versions_string)) {
                    continue;
                }

                if (!isset($this->composer_json_content['conflict'][$vulnerability_key])) {
                    $this->composer_json_content['conflict'][$vulnerability_key] = $conflict_versions_string;
                    $updated                                                     = true;
                    continue;
                }

                if (!str_contains(
                    $this->composer_json_content['conflict'][$vulnerability_key],
                    $conflict_versions_string
                )) {
                    $this->composer_json_content['conflict'][$vulnerability_key] .= " || $conflict_versions_string";
                    $updated                                                     = true;
                }
            }

            if ($updated) {
                ksort($this->composer_json_content['conflict']);
            }
        }

        return $updated;
    }

    /**
     * Gets the string of conflicts versions in format like:
     *  >2.0.0,<=2.0.3
     *  >=1.0.4,<2.0.0
     *  <=3.0.5
     *
     * @param array $affected_version
     *
     * @return string|null
     */
    protected function getConflictStringForAffectedVersion(array $affected_version): ?string
    {
        $to_version = $affected_version['to_version'] ?? null;
        if (!$to_version) {
            return null;
        }
        $from_version = $affected_version['from_version'] ?? '*';

        if (!$this->isValidComposerVersion($from_version) || !$this->isValidComposerVersion($to_version)) {
            return null;
        }

        $from_symbol = ($affected_version['from_inclusive'] ?? null)
            ? '>='
            : '>';
        $to_symbol   = ($affected_version['to_inclusive'] ?? null)
            ? '<='
            : '<';

        return match (true) {
            $from_version === $to_version => $from_version,
            $from_version === '*'         => sprintf('%1$s%2$s', $to_symbol, $to_version),
            default                       => sprintf(
                '%1$s%2$s,%3$s%4$s',
                $from_symbol,
                $from_version,
                $to_symbol,
                $to_version
            ),
        };
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

    /**
     * Retrieves remote repository's composer.json content
     *
     * @throws JsonException
     * @throws RuntimeException
     * @return array
     */
    private function getComposerJsonContent(): array
    {
        $composer_json_data = $this->github_client
            ->api('repo')
            ->contents()
            ->show($this->repo_owner, $this->repo_name, static::COMPOSER_JSON_PATH);
        if (!$composer_json_data || !isset($composer_json_data['content'])) {
            throw new RuntimeException('Missing composer.json content');
        }

        return json_decode(
            base64_decode($composer_json_data['content']),
            associative: true,
            flags: JSON_THROW_ON_ERROR
        );
    }

    /**
     * Whether passed string is a valid composer.json version of a package
     *
     * @param string $version
     *
     * @return bool
     */
    private function isValidComposerVersion(string $version): bool
    {
        try {
            $this->versionParser->parseConstraints($version);

            return true;
        } catch (Exception $e) {
            return false;
        }
    }
}
