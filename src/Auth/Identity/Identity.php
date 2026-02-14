<?php

declare(strict_types=1);

namespace Denosys\Auth\Identity;

final class Identity implements IdentityInterface
{
    /**
     * @param string|int $id The unique identifier
     * @param array<string, mixed> $claims Key-value pairs of identity claims
     */
    public function __construct(
        /**
         * @param array<string, mixed> $claims
         */
        private readonly string|int $id,
        /**
         * @param array<string, mixed> $claims
         */
        private readonly array $claims = [],
    ) {}

    /**
     * Create an identity from an authenticatable model.
     */
    public static function fromAuthenticatable(AuthenticatableInterface $user): self
    {
        return new self(
            $user->getAuthIdentifier(),
            $user->getAuthClaims()
        );
    }

    public function getId(): string|int
    {
        return $this->id;
    }

    /**

     * @return array<string, mixed>

     */

public function getClaims(): array

    {
        return $this->claims;
    }

    public function hasClaim(string $key): bool
    {
        return array_key_exists($key, $this->claims);
    }

    public function getClaim(string $key, mixed $default = null): mixed
    {
        return $this->claims[$key] ?? $default;
    }

    public function isAuthenticated(): bool
    {
        return true;
    }

    /**
     * @return array<string>
     */
    public function getRoles(): array
    {
        $roles = $this->getClaim('roles', []);
        return is_array($roles) ? $roles : [$roles];
    }

    public function hasRole(string $role): bool
    {
        return in_array($role, $this->getRoles(), true);
    }

    /**
     * Create a new identity with additional claims.
      * @param array<string, mixed> $additionalClaims
     */
    public function withClaims(array $additionalClaims): self
    {
        return new self(
            $this->id,
            array_merge($this->claims, $additionalClaims)
        );
    }
}
