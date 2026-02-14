<?php

declare(strict_types=1);

namespace CFXP\Core\Auth\Authentication\Credential;

final readonly class TokenCredential implements CredentialInterface
{
    public function __construct(
        public string $token,
    ) {}

    public function getType(): string
    {
        return 'token';
    }
}
