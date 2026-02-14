<?php

declare(strict_types=1);

namespace Denosys\Auth\Events;

use Denosys\Auth\Identity\IdentityInterface;
use Denosys\Auth\Identity\AuthenticatableInterface;

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
