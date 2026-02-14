<?php

declare(strict_types=1);

namespace CFXP\Core\Auth\Authorization\Policy;

class PolicyBuilder
{
    /** @var string|array<string> */
    private string|array $action = '*';
    private string $resource = '*';
    private ?\Closure $condition = null;
    private int $priority = 0;

    public function __construct(
        private readonly string $subject,
        private readonly string $effect,
    ) {}

    /**
     * Set a single action.
     */
    public function action(string $action): self
    {
        $this->action = $action;
        return $this;
    }

    /**
     * Set multiple actions.
     */
    public function actions(string ...$actions): self
    {
        $this->action = $actions;
        return $this;
    }

    /**
     * Allow any action.
     */
    public function anyAction(): self
    {
        $this->action = '*';
        return $this;
    }

    /**
     * Set the resource type.
     */
    public function on(string $resource): self
    {
        $this->resource = $resource;
        return $this;
    }

    /**
     * Allow any resource.
     */
    public function anyResource(): self
    {
        $this->resource = '*';
        return $this;
    }

    /**
     * Add a condition callback.
     */
    public function when(\Closure $condition): self
    {
        $this->condition = $condition;
        return $this;
    }

    /**
     * Set the priority (higher = evaluated first).
     */
    public function withPriority(int $priority): self
    {
        $this->priority = $priority;
        return $this;
    }

    /**
     * Build the policy.
     */
    public function build(): Policy
    {
        return new Policy(
            subject: $this->subject,
            action: $this->action,
            resource: $this->resource,
            effect: $this->effect,
            condition: $this->condition,
            priority: $this->priority,
        );
    }

    /**
     * Implicitly build when used as Policy.
     */
    public function __destruct()
    {
        // Allow static collection in PolicyLoader
    }
}
