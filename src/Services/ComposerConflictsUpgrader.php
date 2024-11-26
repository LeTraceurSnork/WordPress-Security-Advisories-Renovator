<?php

declare(strict_types=1);

namespace LTS\WordpressSecurityAdvisoriesUpgrader\Services;

use Composer\Semver\VersionParser;
use Exception;
use GuzzleHttp\Exception\GuzzleException;
use JsonException;
use LTS\WordpressSecurityAdvisoriesUpgrader\Controllers\GithubApiController;
use LTS\WordpressSecurityAdvisoriesUpgrader\Controllers\WordfenceController;
use LTS\WordpressSecurityAdvisoriesUpgrader\DTO\ConflictSectionUpgradeResult;
use RuntimeException;

/**
 * Service to upgrade dependencies
 */
class ComposerConflictsUpgrader
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

        echo "Got production feed!\n\n";

        foreach ($feed as $entry) {
            if (empty($entry['software'])) {
                continue;
            }

            $software      = $entry['software'];
            $software_type = (string)($software[0]['type'] ?? 'unknown type');
            $software_name = (string)($software[0]['name'] ?? 'unknown name');
            $cvss          = (string)($entry['cvss']['score'] ?? 'unknown');

            echo "Trying to renovate {$software_name}\n";

            $upgrade_result = $this->upgradeConflictsForVulnerability($entry, $this->composer_json_content);
            if ($upgrade_result?->isUpgraded()) {
                try {
                    $new_composer_json_content = $upgrade_result->getComposerJsonContent();
                    $commit_message            = sprintf(
                        '%1$s %2$s | CVSS = %3$s | %4$s',
                        $software_type,
                        $software_name,
                        $cvss,
                        $upgrade_result->getConflictVersionsString() ?? '',
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
                            "According to [Wordfence](https://www.wordfence.com/threat-intel/vulnerabilities/), %1\$s %2\$s has a %3\$s CVSS security vulnerability\n\nI'm bumping versions to %4\$s\n\nReferences: %5\$s",
                            $software_type,
                            $software_name,
                            $cvss,
                            $upgrade_result->getConflictVersionsString() ?? '',
                            implode(' , ', $software[0]['references'] ?? [])
                        )
                    );
                    echo "!!! === Pull Request created === !!!\n\n";
                } catch (Exception $e) {
                    echo "Something went wrong with this one, continuing\n\n";
                    continue;
                }
            }

            sleep($pause);
        }
    }

    /**
     * Upgrades composer.json conflict section for specified vulnerability.
     *
     * @param array $entry
     * @param array $composer_json_content
     *
     * @return ConflictSectionUpgradeResult|null
     */
    protected function upgradeConflictsForVulnerability(
        array $entry,
        array $composer_json_content
    ): ?ConflictSectionUpgradeResult {
        $software = $entry['software'];
        if (empty($software)) {
            return null;
        }

        foreach ($software as $software_entry) {
            $upgraded = false;
            $slug     = $software_entry['slug'];
            if (!is_string($slug) || $slug === '') {
                continue;
            }

            $affectedVersions = $software_entry['affected_versions'] ?? [];
            if (!is_array($affectedVersions) || empty($affectedVersions)) {
                continue;
            }

            $entry_type = $software_entry['type'];
            switch ($entry_type) {
                case 'plugin':
                case 'theme':
                    $vulnerability_key =
                        strtolower(sprintf('wpackagist-%1$s/%2$s', $entry_type, $slug));

                    break;

                case 'core':
                    if ($slug !== 'wordpress') {
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
                    $upgraded                                              = true;

                    continue;
                }

                if (!str_contains($composer_json_content['conflict'][$vulnerability_key], $conflict_versions_string)) {
                    $composer_json_content['conflict'][$vulnerability_key] .= " || {$conflict_versions_string}";
                    $upgraded                                              = true;
                }
            }

            if ($upgraded) {
                ksort($composer_json_content['conflict']);
            }
        }

        return new ConflictSectionUpgradeResult($composer_json_content, $conflict_versions_string ?? '', $upgraded);
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
