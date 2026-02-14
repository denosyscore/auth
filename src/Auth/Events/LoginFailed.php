<?php

declare(strict_types=1);

namespace CFXP\Core\Auth\Events;

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
