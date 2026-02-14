<?php

declare(strict_types=1);

namespace Denosys\Auth\Authentication\Credential;

final readonly class PasswordCredential implements CredentialInterface
{
    public function __construct(
        public string $identifier,
        public string $password,
        public bool $remember = false,
    ) {}

    public function getType(): string
    {
        return 'password';
    }
}
