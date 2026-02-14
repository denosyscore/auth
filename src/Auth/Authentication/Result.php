<?php

declare(strict_types=1);

namespace Denosys\Auth\Authentication;

use Denosys\Auth\Identity\IdentityInterface;
use Denosys\Auth\Identity\AuthenticatableInterface;

final class Result
{
    /**
     * @param array<string, mixed> $metadata
     */
    private function __construct(
        private readonly bool $success,
        private readonly ?IdentityInterface $identity,
        private readonly ?AuthenticatableInterface $user,
        private readonly ?string $error,
        private readonly array $metadata = [],
    ) {}

    /**
     * Create a successful authentication result.
     *
     * @param array<string, mixed> $metadata
     */
    public static function success(
        IdentityInterface $identity,
        AuthenticatableInterface $user,
        array $metadata = []
    ): self {
        return new self(
            success: true,
            identity: $identity,
            user: $user,
            error: null,
            metadata: $metadata,
        );
    }

    /**
     * Create a failed authentication result.
      * @param array<string, mixed> $metadata
     */
    public static function failure(string $error, array $metadata = []): self
    {
        return new self(
            success: false,
            identity: null,
            user: null,
            error: $error,
            metadata: $metadata,
        );
    }

    /**
     * Common failure: invalid credentials.
     */
    public static function invalidCredentials(): self
    {
        return self::failure('Invalid credentials');
    }

    /**
     * Common failure: user not found.
     */
    public static function userNotFound(): self
    {
        return self::failure('User not found');
    }

    /**
     * Common failure: account disabled.
     */
    public static function accountDisabled(): self
    {
        return self::failure('Account is disabled');
    }

    /**
     * Common failure: too many attempts.
     */
    public static function tooManyAttempts(int $retryAfter): self
    {
        return self::failure('Too many attempts', ['retry_after' => $retryAfter]);
    }

    public function isSuccess(): bool
    {
        return $this->success;
    }

    public function isFailure(): bool
    {
        return !$this->success;
    }

    public function getIdentity(): ?IdentityInterface
    {
        return $this->identity;
    }

    public function getUser(): ?AuthenticatableInterface
    {
        return $this->user;
    }

    public function getError(): ?string
    {
        return $this->error;
    }

    /**

     * @return array<string, mixed>

     */

public function getMetadata(): array

    {
        return $this->metadata;
    }

    public function getMetadataValue(string $key, mixed $default = null): mixed
    {
        return $this->metadata[$key] ?? $default;
    }
}
