<?php

declare(strict_types=1);

namespace LTS\WordpressSecurityAdvisoriesUpgrader\Controllers;

use Exception;
use Github\Client;
use JsonException;
use RuntimeException;

/**
 * Class to fetch data from GitHub API via its Client
 */
final readonly class GithubApiController
{
    /**
     * @param string $repo_owner Repository owner + next param
     * @param string $repo_name  Repository name that needs to be renovated
     * @param Client $client     GitHub API client
     */
    public function __construct(protected Client $client, protected string $repo_owner, protected string $repo_name)
    {
    }

    /**
     * Tries to branch `$branch_name` and head it to `$from_branch`.
     * Throws a RuntimeException if unable to do so.
     *
     * @param string $branch_name
     * @param string $from_branch
     *
     * @throws RuntimeException
     * @return void
     */
    public function createBranch(string $branch_name, string $from_branch): void
    {
        $ref_name = sprintf('refs/heads/%1$s', $branch_name);
        $ref_data = [
            'ref' => $ref_name,
            'sha' => $this->getBranchSha($from_branch),
        ];

        $response = $this->client
            ->api('gitData')
            ->references()
            ->create($this->repo_owner, $this->repo_name, $ref_data);

        if (is_array($response) && $response['ref'] === $ref_name) {
            return;
        }

        throw new RuntimeException(sprintf('Unable to create branch, GitHub response was: %1$s', $response));
    }

    /**
     * Returns branch SHA
     *
     * @param string $branch_name
     *
     * @return string|null
     */
    public function getBranchSha(string $branch_name): ?string
    {
        try {
            $reference = $this->client
                ->api('gitData')
                ->references()
                ->show($this->repo_owner, $this->repo_name, sprintf('heads/%1$s', $branch_name));

            return is_array($reference)
                ? $reference['object']['sha'] ?? null
                : null;
        } catch (Exception $e) {
            return null;
        }
    }

    /**
     * Returns selected branch/file SHA
     *
     * @param string $path_to_file
     * @param string $branch
     *
     * @throws RuntimeException
     * @return string
     */
    public function getFileSha(string $path_to_file, string $branch): string
    {
        $response = $this->client
            ->api('repo')
            ->contents()
            ->show($this->repo_owner, $this->repo_name, $path_to_file, $branch);
        $sha      = $response['sha'] ?? null;
        if (is_string($sha)) {
            return $sha;
        }

        throw new RuntimeException(sprintf('Unable to retrieve file SHA: %1$s', $path_to_file));
    }

    /**
     * Retrieves remote repository's file content
     *
     * @param string $path_to_file Full path to the file
     *
     * @throws JsonException
     * @throws RuntimeException
     * @return string
     */
    public function getFileContent(string $path_to_file): string
    {
        $file_data = $this->client
            ->api('repo')
            ->contents()
            ->show($this->repo_owner, $this->repo_name, $path_to_file);
        if (!$file_data || !isset($file_data['content'])) {
            throw new RuntimeException(sprintf('Missing "%1$s" content', $path_to_file));
        }

        return base64_decode($file_data['content']);
    }

    /**
     * @param string $path_to_file
     * @param string $content
     * @param string $commit_message
     * @param string $old_sha
     * @param string $branch
     *
     * @return void
     */
    public function updateFileContent(
        string $path_to_file,
        string $content,
        string $commit_message,
        string $old_sha,
        string $branch
    ): void {
        $this->client
            ->api('repo')
            ->contents()
            ->update($this->repo_owner, $this->repo_name, $path_to_file, $content, $commit_message, $old_sha, $branch);
    }

    /**
     * Creates a pull request from `$head_branch` to `$base_branch`
     *
     * @param string $base_branch
     * @param string $head_branch
     * @param string $title
     * @param string $body
     *
     * @return void
     */
    public function createPullRequest(string $base_branch, string $head_branch, string $title, string $body = ''): void
    {
        $pullRequest = $this->client
            ->api('pull_request')
            ->create($this->repo_owner, $this->repo_name, [
                'base'  => $base_branch,
                'head'  => $head_branch,
                'title' => $title,
                'body'  => $body,
            ]);
    }
}
