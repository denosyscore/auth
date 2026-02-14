<?php

declare(strict_types=1);

namespace Denosys\Auth\Identity;

interface IdentityInterface
{
    /**
     * Get the unique identifier for this identity.
     */
    public function getId(): string|int;

    /**
     * Get all claims (attributes) about this identity.
     * 
     * Claims describe "what the subject is" (e.g., roles, email, department)
     * rather than "what they can do" (which is authorization).
      * @return array<string, mixed>
     */
    public function getClaims(): array;

    /**
     * Check if this identity has a specific claim.
     */
    public function hasClaim(string $key): bool;

    /**
     * Get a specific claim value.
     */
    public function getClaim(string $key, mixed $default = null): mixed;

    /**
     * Check if this identity represents an authenticated user.
     */
    public function isAuthenticated(): bool;

    /**
     * Get roles assigned to this identity.
     * Convenience method - roles are typically stored as a claim.
      * @return array<string>
     */
    public function getRoles(): array;

    /**
     * Check if identity has a specific role.
     */
    public function hasRole(string $role): bool;
}
