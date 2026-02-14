<?php

declare(strict_types=1);

namespace Denosys\Auth\Authorization\Policy;

class PolicyLoader
{
    /** @var array<PolicySourceInterface> */
    private array $sources = [];

    /** @var array<Policy>|null Cached policies */
    private ?array $cache = null;

    /**
     * Add a policy source.
     */
    public function addSource(PolicySourceInterface $source): self
    {
        $this->sources[] = $source;
        $this->cache = null; // Invalidate cache
        return $this;
    }

    /**
     * Load all policies from all sources.
     * 
     * @return array<Policy>
     */
    public function load(): array
    {
        if ($this->cache !== null) {
            return $this->cache;
        }

        $policies = [];

        foreach ($this->sources as $source) {
            $policies = array_merge($policies, $source->load());
        }

        // Sort by priority (highest first)
        usort($policies, fn(Policy $a, Policy $b) => $b->priority <=> $a->priority);

        $this->cache = $policies;

        return $policies;
    }

    /**
     * Clear the policy cache.
     */
    public function clearCache(): void
    {
        $this->cache = null;
    }

    /**
     * Find policies matching the given criteria.
     *
     * @param array<string> $roles
     * @return array<Policy>
     */
    public function findMatching(
        string|int $userId,
        array $roles,
        string $action,
        string $resourceType
    ): array {
        $matching = [];

        foreach ($this->load() as $policy) {
            if (!$policy->matchesSubject('user', $userId, $roles)) {
                continue;
            }

            if (!$policy->matchesAction($action)) {
                continue;
            }

            if (!$policy->matchesResource($resourceType)) {
                continue;
            }

            $matching[] = $policy;
        }

        return $matching;
    }
}
