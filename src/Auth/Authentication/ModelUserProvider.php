<?php

declare(strict_types=1);

namespace CFXP\Core\Auth\Authentication;

use CFXP\Core\Auth\Identity\AuthenticatableInterface;
use CFXP\Core\Database\Model;

class ModelUserProvider implements UserProviderInterface
{
    /**
     * @param class-string<Model&AuthenticatableInterface> $modelClass
     * @param string $identifierField The field used for login (e.g., 'email')
     * @param array<string, mixed> $hashOptions Password hashing options
     */
    public function __construct(
        /**
         * @param array<string, mixed> $hashOptions
         */
        private readonly string $modelClass,
        /**
         * @param array<string, mixed> $hashOptions
         */
        private readonly string $identifierField = 'email',
        /**
         * @param array<string, mixed> $hashOptions
         */
        private readonly array $hashOptions = [],
    ) {}

    public function findById(string|int $id): ?AuthenticatableInterface
    {
        /** @var AuthenticatableInterface|null $result */
        $result = ($this->modelClass)::find($id);
        return $result;
    }

    public function findByCredential(string $field, string $value): ?AuthenticatableInterface
    {
        /** @var AuthenticatableInterface|null $result */
        $result = ($this->modelClass)::query()
            ->where($field, '=', $value)
            ->first();
        return $result;
    }

    public function findByRememberToken(string|int $id, string $token): ?AuthenticatableInterface
    {
        $user = $this->findById($id);

        if ($user === null) {
            return null;
        }

        $storedToken = $user->getRememberToken();

        if ($storedToken === null || !hash_equals($storedToken, $token)) {
            return null;
        }

        return $user;
    }

    public function updateRememberToken(AuthenticatableInterface $user, string $token): void
    {
        $user->setRememberToken($token);

        if ($user instanceof Model) {
            $user->save();
        }
    }

    public function validatePassword(AuthenticatableInterface $user, string $password): bool
    {
        return password_verify($password, $user->getAuthPassword());
    }

    public function rehashPasswordIfRequired(AuthenticatableInterface $user, string $password): void
    {
        if (!password_needs_rehash($user->getAuthPassword(), PASSWORD_DEFAULT, $this->hashOptions)) {
            return;
        }

        if ($user instanceof Model) {
            $user->setAttribute('password', password_hash($password, PASSWORD_DEFAULT, $this->hashOptions));
            $user->save();
        }
    }

    /**
     * Get the identifier field used for credentials lookup.
     */
    public function getIdentifierField(): string
    {
        return $this->identifierField;
    }

    /**
     * Hash a plain text password.
     */
    public function hashPassword(string $password): string
    {
        return password_hash($password, PASSWORD_DEFAULT, $this->hashOptions);
    }
}
