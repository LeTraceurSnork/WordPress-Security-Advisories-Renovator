<?php

declare(strict_types=1);

namespace LTS\WordpressSecurityAdvisoriesRenovator\Services;

use Composer\Semver\VersionParser;
use Exception;
use GuzzleHttp\Exception\GuzzleException;
use JsonException;
use LTS\WordpressSecurityAdvisoriesRenovator\Controllers\GithubApiController;
use LTS\WordpressSecurityAdvisoriesRenovator\Controllers\WordfenceController;
use LTS\WordpressSecurityAdvisoriesRenovator\DTO\ConflictSectionUpdateResult;
use RuntimeException;

/**
 * Service to renovate dependencies
 */
class ComposerConflictsRenovator
{
    /**
     * Name of repository's default branch
     */
    public const REPO_DEFAULT_BRANCH_NAME = 'master';

    /**
     * Path to composer.json renovating file
     */
    public const COMPOSER_JSON_PATH = 'composer.json';

    /**
     * @var array Contents of composer.json file
     */
    protected array $composer_json_content;

    /**
     * @param GithubApiController $github_api_controller
     * @param VersionParser       $version_parser
     * @param WordfenceController $wordfence_controller
     */
    public function __construct(
        protected readonly GithubApiController $github_api_controller,
        protected readonly VersionParser $version_parser = new VersionParser(),
        protected readonly WordfenceController $wordfence_controller = new WordfenceController()
    ) {
    }

    /**
     * @param int $pause
     *
     * @throws GuzzleException
     * @throws JsonException
     * @throws RuntimeException
     * @return void
     */
    public function renovate(int $pause = 1): void
    {
        $file_content                = $this->github_api_controller->getFileContent(static::COMPOSER_JSON_PATH);
        $this->composer_json_content = json_decode($file_content, associative: true, flags: JSON_THROW_ON_ERROR);
        $feed                        = $this->wordfence_controller->getProductionFeed();

        foreach ($feed as $entry) {
            if (empty($entry['software'])) {
                continue;
            }
            $software      = $entry['software'];
            $software_type = $software[0]['type'] ?? 'unknown type';
            $software_name = $software[0]['name'] ?? 'unknown name';
            $cvss          = $entry['cvss']['score'] ?? 'unknown';

            $updated_result = $this->updateConflictsForVulnerability($entry, $this->composer_json_content);
            if ($updated_result?->isUpdated()) {
                try {
                    $new_composer_json_content = $updated_result->getComposerJsonContent();
                    $commit_message            = sprintf(
                        '%1$s %2$s | CVSS = %3$s | %4$s',
                        $software_type,
                        $software_name,
                        $cvss,
                        $updated_result->getConflictVersionsString() ?? '',
                    );

                    $encoded     = json_encode(
                        value: $new_composer_json_content,
                        flags: JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES
                    );
                    $branch_name = $entry['id'] ?? md5(json_encode($entry['software']));

                    $this->github_api_controller->createBranch($branch_name, static::REPO_DEFAULT_BRANCH_NAME);
                    $this->github_api_controller->updateFileContent(
                        static::COMPOSER_JSON_PATH,
                        $encoded,
                        $commit_message,
                        $this->github_api_controller->getFileSha(
                            static::COMPOSER_JSON_PATH,
                            static::REPO_DEFAULT_BRANCH_NAME
                        ),
                        $branch_name
                    );
                    $this->github_api_controller->createPullRequest(
                        static::REPO_DEFAULT_BRANCH_NAME,
                        $branch_name,
                        $commit_message,
                        sprintf(
                            "According to [Wordfence](https://www.wordfence.com/threat-intel/vulnerabilities/), %1\$s %2\$s has a %3\$s CVSS security vulnerability\n\nI'm bumping versions to %4\$s",
                            $software_type,
                            $software_name,
                            $cvss,
                            $updated_result->getConflictVersionsString() ?? '',
                        )
                    );
                } catch (Exception $e) {
                    continue;
                }
            }

            sleep($pause);
        }
    }

    /**
     * Updates composer.json conflict section for specified vulnerability.
     *
     * @param array $entry
     * @param array $composer_json_content
     *
     * @return ConflictSectionUpdateResult|null
     */
    protected function updateConflictsForVulnerability(
        array $entry,
        array $composer_json_content
    ): ?ConflictSectionUpdateResult {
        $updated  = false;
        $software = $entry['software'];
        if (empty($software)) {
            return null;
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

                if (!isset($composer_json_content['conflict'][$vulnerability_key])) {
                    $composer_json_content['conflict'][$vulnerability_key] = $conflict_versions_string;
                    $updated                                               = true;
                    continue;
                }

                if (!str_contains($composer_json_content['conflict'][$vulnerability_key], $conflict_versions_string)) {
                    $composer_json_content['conflict'][$vulnerability_key] .= " || $conflict_versions_string";
                    $updated                                               = true;
                }
            }

            if ($updated) {
                ksort($composer_json_content['conflict']);
            }
        }

        return new ConflictSectionUpdateResult($composer_json_content, $conflict_versions_string ?? '', $updated);
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
     * Whether passed string is a valid composer.json version of a package
     *
     * @param string $version
     *
     * @return bool
     */
    private function isValidComposerVersion(string $version): bool
    {
        try {
            $this->version_parser->parseConstraints($version);

            return true;
        } catch (Exception $e) {
            return false;
        }
    }
}
