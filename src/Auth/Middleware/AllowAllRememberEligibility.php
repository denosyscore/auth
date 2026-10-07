<?php

declare(strict_types=1);

namespace Denosys\Auth\Middleware;

use Denosys\Auth\Identity\AuthenticatableInterface;

final class AllowAllRememberEligibility implements RememberEligibilityInterface
{
    public function allows(AuthenticatableInterface $user): bool
    {
        return true;
    }
}
