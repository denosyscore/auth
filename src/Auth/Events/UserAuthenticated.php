<?php

declare(strict_types=1);

namespace CFXP\Core\Auth\Events;

use CFXP\Core\Auth\Identity\IdentityInterface;
use CFXP\Core\Auth\Identity\AuthenticatableInterface;

/**
 * Event dispatched when a user successfully authenticates.
 */
final readonly class UserAuthenticated
{
    public function __construct(
        public AuthenticatableInterface $user,
        public IdentityInterface $identity,
        public bool $remember = false,
    ) {}
}
