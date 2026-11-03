<?php

declare(strict_types=1);

namespace Denosys\Auth\Middleware;

use Denosys\Auth\Identity\AuthenticatableInterface;

interface RememberEligibilityInterface
{
    public function allows(AuthenticatableInterface $user): bool;
}
