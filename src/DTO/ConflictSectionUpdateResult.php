<?php

declare(strict_types=1);

namespace LTS\WordpressSecurityAdvisoriesRenovator\DTO;

use LTS\WordpressSecurityAdvisoriesRenovator\Services\ComposerConflictsRenovator;

/**
 * DTO for result of method Renovator::updateConflictsForVulnerability()
 *
 * @see ComposerConflictsRenovator::updateConflictsForVulnerability()
 */
final readonly class ConflictSectionUpdateResult
{
    /**
     * @param array  $composer_json_content
     * @param string $conflict_versions_string
     * @param bool   $is_updated
     */
    public function __construct(
        private array $composer_json_content,
        private string $conflict_versions_string,
        private bool $is_updated = false
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
    public function isUpdated(): bool
    {
        return $this->is_updated;
    }
}
