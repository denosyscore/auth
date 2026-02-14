<?php

declare(strict_types=1);

namespace Denosys\Auth\Authentication;

use Denosys\Auth\Identity\AuthenticatableInterface;

interface UserProviderInterface
{
    /**
     * Retrieve a user by their unique identifier.
     */
    public function findById(string|int $id): ?AuthenticatableInterface;

    /**
     * Retrieve a user by a unique field (e.g., email, username).
     */
    public function findByCredential(string $field, string $value): ?AuthenticatableInterface;

    /**
     * Retrieve a user by their remember-me token.
     */
    public function findByRememberToken(string|int $id, string $token): ?AuthenticatableInterface;

    /**
     * Update the remember-me token for a user.
     */
    public function updateRememberToken(AuthenticatableInterface $user, string $token): void;

    /**
     * Validate a user's password.
     */
    public function validatePassword(AuthenticatableInterface $user, string $password): bool;

    /**
     * Rehash the password if needed (e.g., when algorithm changes).
     */
    public function rehashPasswordIfRequired(AuthenticatableInterface $user, string $password): void;
}
