<?php

declare(strict_types=1);

namespace Denosys\Auth\Authentication\Credential;

interface CredentialInterface
{
    /**
     * Get the credential type identifier.
     */
    public function getType(): string;
}
