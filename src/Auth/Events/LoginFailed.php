<?php

declare(strict_types=1);

namespace Denosys\Auth\Events;

/**
 * Event dispatched when a login attempt fails.
 */
final readonly class LoginFailed
{
    public function __construct(
        public string $identifier,
        public string $reason = 'Invalid credentials',
        public ?string $ipAddress = null,
    ) {}
}
