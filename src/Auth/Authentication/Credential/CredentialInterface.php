<?php

declare(strict_types=1);

namespace CFXP\Core\Auth\Authentication\Credential;

interface CredentialInterface
{
    /**
     * Get the credential type identifier.
     */
    public function getType(): string;
}
