<?php

declare(strict_types=1);

namespace LTS\WordpressSecurityAdvisoriesUpgrader\Controllers\Wordfence;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;
use JsonException;
use Psr\Http\Client\ClientInterface;

/**
 * Controller for Wordfence API
 */
class WordfenceController implements WordfenceControllerInterface
{
    /**
     * URL of Wordfence /scanner/ feed (short version of API list)
     */
    public const WORDFENCE_SCANNER_FEED_URL = 'https://www.wordfence.com/api/intelligence/v2/vulnerabilities/scanner/';

    /**
     * URL of Wordfence /production/ feed (full version of API list)
     */
    public const WORDFENCE_PRODUCTION_FEED_URL = 'https://www.wordfence.com/api/intelligence/v2/vulnerabilities/production/';

    /**
     * @param ClientInterface $client
     */
    public function __construct(protected readonly ClientInterface $client = new Client())
    {
    }

    /**
     * @throws GuzzleException
     * @throws JsonException
     * @inheritdoc
     */
    public function getProductionFeed(): array
    {
        return $this->getSelectedFeed(static::WORDFENCE_PRODUCTION_FEED_URL);
    }

    /**
     * @throws GuzzleException
     * @throws JsonException
     * @inheritdoc
     */
    public function getScannerFeed(): array
    {
        return $this->getSelectedFeed(static::WORDFENCE_SCANNER_FEED_URL);
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
    protected function getSelectedFeed(string $feed): array
    {
        $response = $this->client
            ->get($feed)
            ->getBody()
            ->getContents();

        return json_decode(
            json: $response,
            associative: true,
            flags: JSON_THROW_ON_ERROR
        );
    }
}
