<?php

declare(strict_types=1);

namespace CFXP\Core\Auth\Authentication\Strategy;

use CFXP\Core\Auth\Authentication\Credential\CredentialInterface;
use CFXP\Core\Auth\Authentication\Result;

interface StrategyInterface
{
    /**
     * Get the strategy name/identifier.
     */
    public function getName(): string;

    /**
     * Check if this strategy supports the given credential type.
     */
    public function supports(CredentialInterface $credential): bool;

    /**
     * Attempt to authenticate using the provided credential.
     */
    public function authenticate(CredentialInterface $credential): Result;
}
