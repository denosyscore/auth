<?php

declare(strict_types=1);

namespace Denosys\Auth\Authentication;

use Denosys\Auth\Identity\AuthenticatableInterface;
use Denosys\Database\Record\Record;

/**
 * Finds users among the records of one class. The class implements both
 * Record and AuthenticatableInterface; its password is stored in the
 * `password` column.
 */
final readonly class RecordUserProvider implements UserProviderInterface
{
    /**
     * @param class-string<Record&AuthenticatableInterface> $userClass
     * @param string $identifierField The column used to log in, such as `email`.
     * @param array<string, mixed> $hashOptions Options for password_hash().
     */
    public function __construct(
        private string $userClass,
        private string $identifierField = 'email',
        private array $hashOptions = [],
    ) {
    }

    public function findById(string|int $id): ?AuthenticatableInterface
    {
        $user = ($this->userClass)::find($id);

        return $user instanceof AuthenticatableInterface ? $user : null;
    }

    public function findByCredential(string $field, string $value): ?AuthenticatableInterface
    {
        $user = ($this->userClass)::query()->where($field, '=', $value)->first();

        return $user instanceof AuthenticatableInterface ? $user : null;
    }

    public function findByRememberToken(string|int $id, string $token): ?AuthenticatableInterface
    {
        $user = $this->findById($id);
        $stored = $user?->getRememberToken();

        return $stored !== null && hash_equals($stored, $token) ? $user : null;
    }

    public function updateRememberToken(AuthenticatableInterface $user, string $token): void
    {
        $user->setRememberToken($token);
        if ($user instanceof Record) {
            $user->save();
        }
    }

    public function validatePassword(AuthenticatableInterface $user, string $password): bool
    {
        return password_verify($password, $user->getAuthPassword());
    }

    public function rehashPasswordIfRequired(AuthenticatableInterface $user, string $password): void
    {
        if (!$user instanceof Record || !password_needs_rehash($user->getAuthPassword(), PASSWORD_DEFAULT, $this->hashOptions)) {
            return;
        }

        // Only replace the hash that was just verified: if the password changed
        // meanwhile, the update matches no row and the new password stands.
        ($this->userClass)::query()
            ->where($user->getAuthIdentifierName(), '=', $user->getAuthIdentifier())
            ->where('password', '=', $user->getAuthPassword())
            ->update(['password' => $this->hashPassword($password)]);
        $user->refresh();
    }

    /** The column used to log in. */
    public function getIdentifierField(): string
    {
        return $this->identifierField;
    }

    public function hashPassword(string $password): string
    {
        return password_hash($password, PASSWORD_DEFAULT, $this->hashOptions);
    }
}
