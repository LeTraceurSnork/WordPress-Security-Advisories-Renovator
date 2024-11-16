<?php

declare(strict_types=1);

namespace Letraceursnork\WordpressSecurityAdvisoriesRenovator\Controllers;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;
use JsonException;
use Psr\Http\Client\ClientInterface;

/**
 * Controller to work with Wordfence API
 */
class WordfenceController
{
    /**
     * URL of Wordfence /scanner/ feed (short version of API list)
     */
    public const WORDFENCE_SCANNER_FEED_URL = 'https://www.wordfence.com/api/intelligence/v2/vulnerabilities/scanner/';

    public function __construct(protected readonly ClientInterface $client = new Client())
    {
    }

    /**
     * @throws GuzzleException
     * @throws JsonException
     * @return string[]
     */
    public function getScannerFeed(): array
    {
        $response = $this->client->get(static::WORDFENCE_SCANNER_FEED_URL);

        return json_decode(json: $response->getBody()->getContents(), associative: true, depth: 512, flags: JSON_THROW_ON_ERROR);
    }
}