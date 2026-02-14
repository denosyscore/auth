<?php

declare(strict_types=1);

namespace CFXP\Core\Auth\Identity;

final class AnonymousIdentity implements IdentityInterface
{
    public function getId(): string|int
    {
        return 0;
    }

    /**

     * @return array<string, mixed>

     */

public function getClaims(): array

    {
        return [];
    }

    public function hasClaim(string $key): bool
    {
        return false;
    }

    public function getClaim(string $key, mixed $default = null): mixed
    {
        return $default;
    }

    public function isAuthenticated(): bool
    {
        return false;
    }

    /**
     * @return array<string>
     */
    public function getRoles(): array
    {
        return ['guest'];
    }

    public function hasRole(string $role): bool
    {
        return $role === 'guest';
    }
}
