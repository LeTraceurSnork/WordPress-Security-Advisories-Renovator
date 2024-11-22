<?php

declare(strict_types=1);

namespace LTS\WordpressSecurityAdvisoriesRenovator\DTO;

use LTS\WordpressSecurityAdvisoriesRenovator\Services\Renovator;

/**
 * DTO for result of method Renovator::updateConflictsForVulnerability()
 *
 * @see Renovator::updateConflictsForVulnerability()
 */
final readonly class ConflictSectionUpdateResult
{
    /**
     * @param array $composer_json_content
     * @param bool  $is_updated
     */
    public function __construct(private array $composer_json_content, private bool $is_updated = false)
    {
    }

    /**
     * @return array
     */
    public function getComposerJsonContent(): array
    {
        return $this->composer_json_content;
    }

    /**
     * @return bool
     */
    public function isUpdated(): bool
    {
        return $this->is_updated;
    }
}
