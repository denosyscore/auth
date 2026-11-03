<?php

declare(strict_types=1);

namespace Denosys\Auth\Middleware;

use Closure;
use Denosys\Auth\Authentication\Authenticator;
use Denosys\Auth\Authentication\UserProviderInterface;
use Denosys\Auth\Identity\AuthenticatableInterface;
use Denosys\Auth\Identity\Identity;
use Denosys\Encryption\DecryptException;
use Denosys\Encryption\EncrypterInterface;
use Denosys\Session\SessionInterface;
use JsonException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Opt-in persistent authentication cookie lifecycle for the session authenticator.
 * Applications can supply an eligibility check for disabled or unverified users.
 */
final class RememberCookieMiddleware implements MiddlewareInterface
{
    private const TOKEN_KEY = '_auth_remember_token';
    private const ID_KEY = '_auth_remember_id';

    /** @var Closure(AuthenticatableInterface): bool */
    private readonly Closure $canRestore;
    private readonly RememberCookieOptions $options;

    /** @param callable(AuthenticatableInterface): bool|null $canRestore */
    public function __construct(
        private readonly Authenticator $authenticator,
        private readonly UserProviderInterface $users,
        private readonly SessionInterface $session,
        private readonly EncrypterInterface $encrypter,
        ?RememberCookieOptions $options = null,
        ?callable $canRestore = null,
    ) {
        $this->options = $options ?? new RememberCookieOptions();
        $this->canRestore = $canRestore === null
            ? static fn (AuthenticatableInterface $user): bool => true
            : Closure::fromCallable($canRestore);
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $cookie = $request->getCookieParams()[$this->options->cookieName] ?? null;
        $path = $request->getUri()->getPath();
        $method = strtoupper($request->getMethod());
        $invalidCookie = false;

        if (!($method === 'POST' && $path === $this->options->loginPath)
            && $this->authenticator->guest() && is_string($cookie) && $cookie !== '') {
            $user = $this->restore($cookie);
            if ($user === null) {
                $invalidCookie = true;
            } else {
                $this->authenticator->login(Identity::fromAuthenticatable($user), $user);
            }
        }

        $response = $handler->handle($request);

        if ($method === 'POST' && $path === $this->options->logoutPath && $this->authenticator->guest()) {
            $this->session->forgetMany([self::TOKEN_KEY, self::ID_KEY]);

            return $response->withAddedHeader('Set-Cookie', $this->cookieHeader('', 0, $request));
        }

        if ($method === 'POST' && $path === $this->options->loginPath && $this->authenticator->check()) {
            $token = $this->session->pull(self::TOKEN_KEY);
            $id = $this->session->pull(self::ID_KEY);
            $user = $this->authenticator->user();
            if ($user !== null && is_string($token) && preg_match('/\A[a-f0-9]{64}\z/', $token) === 1
                && (is_int($id) || is_string($id))
                && (string) $id === (string) $user->getAuthIdentifier()
                && $this->users->findByRememberToken($id, $token) !== null) {
                $expires = time() + $this->options->lifetimeSeconds;
                $payload = json_encode([
                    'id' => $id,
                    'token' => $token,
                    'password' => sha1($user->getAuthPassword()),
                    'expires' => $expires,
                ], JSON_THROW_ON_ERROR);
                $value = rtrim(strtr($this->encrypter->encryptString($payload), '+/', '-_'), '=');

                return $response->withAddedHeader('Set-Cookie', $this->cookieHeader($value, $expires, $request));
            }

            if (is_string($cookie) && $cookie !== '') {
                $rememberedUser = $this->restore($cookie);
                if ($rememberedUser !== null) {
                    $this->users->updateRememberToken($rememberedUser, '');
                }

                return $response->withAddedHeader('Set-Cookie', $this->cookieHeader('', 0, $request));
            }
        }

        return $invalidCookie
            ? $response->withAddedHeader('Set-Cookie', $this->cookieHeader('', 0, $request))
            : $response;
    }

    private function restore(string $cookie): ?AuthenticatableInterface
    {
        try {
            $encoded = strtr($cookie, '-_', '+/');
            $encoded .= str_repeat('=', (4 - strlen($encoded) % 4) % 4);
            $data = json_decode($this->encrypter->decryptString($encoded), true, flags: JSON_THROW_ON_ERROR);
        } catch (DecryptException|JsonException) {
            return null;
        }

        if (!is_array($data) || !(is_int($data['id'] ?? null) || is_string($data['id'] ?? null))
            || $data['id'] === '' || $data['id'] === 0
            || !is_string($data['token'] ?? null) || preg_match('/\A[a-f0-9]{64}\z/', $data['token']) !== 1
            || !is_string($data['password'] ?? null) || !is_int($data['expires'] ?? null)
            || $data['expires'] <= time()) {
            return null;
        }

        $user = $this->users->findByRememberToken($data['id'], $data['token']);

        return $user !== null && ($this->canRestore)($user)
            && hash_equals($data['password'], sha1($user->getAuthPassword()))
            ? $user
            : null;
    }

    private function cookieHeader(string $value, int $expires, ServerRequestInterface $request): string
    {
        $parts = [
            $this->options->cookieName . '=' . $value,
            'Path=/',
            'Expires=' . gmdate('D, d M Y H:i:s \G\M\T', $expires),
            'Max-Age=' . max(0, $expires - time()),
            'HttpOnly',
            'SameSite=' . $this->options->sameSite,
        ];

        if ($this->options->sameSite === 'None' || $this->options->secure === true
            || ($this->options->secure === null && $request->getUri()->getScheme() === 'https')) {
            $parts[] = 'Secure';
        }

        return implode('; ', $parts);
    }
}
