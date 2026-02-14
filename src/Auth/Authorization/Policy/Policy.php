<?php

declare(strict_types=1);

namespace CFXP\Core\Auth\Authorization\Policy;

class Policy
{
    /**
     * @param string $subject Pattern for who this applies to (e.g., 'role:admin', 'user:*')
     * @param string|array $action Action(s) this policy covers ('*' for all)
     * @param string $resource Resource type this policy covers ('*' for all)
     * @param string $effect 'allow' or 'deny'
     * @param \Closure|null $condition Optional condition callback
     * @param int $priority Higher priority rules are evaluated first
      * @param array<string, mixed> $action
     */
    public function __construct(
        /**
         * @param array<string, mixed> $action
         */
        public readonly string $subject,
        /**
         * @param array<string, mixed> $action
         */
        public readonly string|array $action,
        public readonly string $resource,
        public readonly string $effect = 'allow',
        public readonly ?\Closure $condition = null,
        public readonly int $priority = 0,
    ) {}

    /**
     * Create an allow policy.
     */
    public static function allow(string $subject): PolicyBuilder
    {
        return new PolicyBuilder($subject, 'allow');
    }

    /**
     * Create a deny policy.
     */
    public static function deny(string $subject): PolicyBuilder
    {
        return new PolicyBuilder($subject, 'deny');
    }

    /**
     * Create from array (e.g., from config file).
      * @param array<string, mixed> $data
     */
    public static function fromArray(array $data): self
    {
        return new self(
            subject: $data['subject'],
            action: $data['action'] ?? '*',
            resource: $data['resource'] ?? '*',
            effect: $data['effect'] ?? 'allow',
            condition: $data['condition'] ?? null,
            priority: $data['priority'] ?? 0,
        );
    }

    /**
     * Check if this policy matches the given subject pattern.
      * @param array<string> $roles
     */
    public function matchesSubject(string $subjectType, string|int $subjectId, array $roles): bool
    {
        // Parse policy subject (e.g., 'role:admin' or 'user:123' or 'user:*')
        if (str_starts_with($this->subject, 'role:')) {
            $requiredRole = substr($this->subject, 5);
            return $requiredRole === '*' || in_array($requiredRole, $roles, true);
        }

        if (str_starts_with($this->subject, 'user:')) {
            $requiredUser = substr($this->subject, 5);
            return $requiredUser === '*' || $requiredUser === (string) $subjectId;
        }

        // Wildcard matches all
        return $this->subject === '*';
    }

    /**
     * Check if this policy matches the given action.
     */
    public function matchesAction(string $action): bool
    {
        if ($this->action === '*') {
            return true;
        }

        if (is_array($this->action)) {
            return in_array($action, $this->action, true);
        }

        return $this->action === $action;
    }

    /**
     * Check if this policy matches the given resource type.
     */
    public function matchesResource(string $resourceType): bool
    {
        return $this->resource === '*' || $this->resource === $resourceType;
    }

    /**
     * Evaluate the condition if present.
     */
    public function evaluateCondition(object $subject, mixed $resource): bool
    {
        if ($this->condition === null) {
            return true;
        }

        return (bool) ($this->condition)($subject, $resource);
    }

    /**
     * Check if this is an allow policy.
     */
    public function isAllow(): bool
    {
        return $this->effect === 'allow';
    }

    /**
     * Check if this is a deny policy.
     */
    public function isDeny(): bool
    {
        return $this->effect === 'deny';
    }
}
