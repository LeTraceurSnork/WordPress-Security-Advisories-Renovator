<?php

declare(strict_types=1);

namespace LTS\WordpressSecurityAdvisoriesUpgrader\Controllers\Wordfence;

use Exception;

/**
 * Interface of controller that should act like a Wordfence API proxy
 */
interface WordfenceControllerInterface
{
    /**
     * @throws Exception
     * @return array{
     *     software: array{
     *         type: string,
     *         name: string,
     *         slug: string,
     *         affected_versions: array,
     *     }[]
     * }[]
     */
    public function getScannerFeed(): array;

    /**
     * @throws Exception
     * @return array{
     *     software: array{
     *         type: string,
     *         name: string,
     *         slug: string,
     *         affected_versions: array,
     *     }[],
     *     references: string[],
     *     cvss: array{
     *          score: float|null,
     *     },
     * }[]
     */
    public function getProductionFeed(): array;
}
