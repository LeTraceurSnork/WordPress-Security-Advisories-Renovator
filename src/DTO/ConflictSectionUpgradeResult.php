<?php

declare(strict_types=1);

namespace LTS\WordpressSecurityAdvisoriesUpgrader\DTO;

use LTS\WordpressSecurityAdvisoriesUpgrader\Services\ComposerConflictsUpgrader;

/**
 * DTO for result of method ComposerConflictsUpgrader::upgradeConflictsForVulnerability()
 *
 * @see ComposerConflictsUpgrader::upgradeConflictsForVulnerability()
 */
final readonly class ConflictSectionUpgradeResult
{
    /**
     * @param array  $composer_json_content
     * @param string $conflict_versions_string
     * @param bool   $is_upgraded
     */
    public function __construct(
        private array $composer_json_content,
        private string $conflict_versions_string,
        private bool $is_upgraded = false
    ) {
    }

    /**
     * @return array
     */
    public function getComposerJsonContent(): array
    {
        return $this->composer_json_content;
    }

    /**
     * @return string
     */
    public function getConflictVersionsString(): string
    {
        return $this->conflict_versions_string;
    }

    /**
     * @return bool
     */
    public function isUpgraded(): bool
    {
        return $this->is_upgraded;
    }
}
