<?php

declare(strict_types=1);

namespace CFXP\Core\Auth\Identity;

interface AuthenticatableInterface
{
    /**
     * Get the unique identifier for authentication (usually primary key).
     */
    public function getAuthIdentifier(): string|int;

    /**
     * Get the name of the unique identifier column.
     */
    public function getAuthIdentifierName(): string;

    /**
     * Get the hashed password for authentication.
     */
    public function getAuthPassword(): string;

    /**
     * Get the remember-me token value.
     */
    public function getRememberToken(): ?string;

    /**
     * Set the remember-me token value.
     */
    public function setRememberToken(string $token): void;

    /**
     * Get the column name for the remember token.
     */
    public function getRememberTokenName(): string;

    /**
     * Get claims to include in the identity.
     * Override to add custom claims like roles, permissions, etc.
      * @return array<string, mixed>
     */
    public function getAuthClaims(): array;
}
