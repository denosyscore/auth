<?php

declare(strict_types=1);

namespace Denosys\Auth\Middleware;

use InvalidArgumentException;

final readonly class RememberCookieOptions
{
    public function __construct(
        public string $cookieName = 'remember_auth',
        public int $lifetimeSeconds = 2592000,
        public ?bool $secure = null,
        public string $sameSite = 'Lax',
        public string $loginPath = '/login',
        public string $logoutPath = '/logout',
    ) {
        if (preg_match('/\A[A-Za-z_][A-Za-z0-9_-]*\z/', $cookieName) !== 1
            || $lifetimeSeconds < 1
            || !in_array($sameSite, ['Lax', 'Strict', 'None'], true)
            || ($sameSite === 'None' && $secure === false)
            || !self::validPath($loginPath)
            || !self::validPath($logoutPath)) {
            throw new InvalidArgumentException('Remember-cookie options are invalid.');
        }
    }

    private static function validPath(string $path): bool
    {
        return str_starts_with($path, '/') && !str_starts_with($path, '//')
            && !str_contains($path, '\\') && preg_match('/[\x00-\x1F\x7F]/', $path) !== 1;
    }
}
