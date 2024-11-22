<?php

declare(strict_types=1);

namespace LTS\WordpressSecurityAdvisoriesRenovator\Controllers;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;
use JsonException;
use Psr\Http\Client\ClientInterface;

/**
 * Controller for Wordfence API
 */
class WordfenceController
{
    /**
     * URL of Wordfence /scanner/ feed (short version of API list)
     */
    public const WORDFENCE_SCANNER_FEED_URL = 'https://www.wordfence.com/api/intelligence/v2/vulnerabilities/scanner/';

    /**
     * @param ClientInterface $client
     */
    public function __construct(protected readonly ClientInterface $client = new Client())
    {
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
    public function getScannerFeed(): array
    {
        //        $response = $this->client
        //            ->get(static::WORDFENCE_SCANNER_FEED_URL)
        //            ->getBody()
        //            ->getContents();

        $response = file_get_contents('./Scanner_Feed.txt');

        return json_decode(
            json: $response,
            associative: true,
            flags: JSON_THROW_ON_ERROR
        );
    }
}
