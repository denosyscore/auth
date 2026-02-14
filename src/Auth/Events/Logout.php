<?php

declare(strict_types=1);

namespace Denosys\Auth\Events;

use Denosys\Auth\Identity\AuthenticatableInterface;

/**
 * Event dispatched when a user logs out.
 */
final readonly class Logout
{
    public function __construct(
        public AuthenticatableInterface $user,
    ) {}
}
