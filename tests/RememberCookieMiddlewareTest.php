<?php

declare(strict_types=1);

namespace Denosys\Auth\Tests;

use Denosys\Auth\Authentication\Authenticator;
use Denosys\Auth\AuthServiceProvider;
use Denosys\Auth\Authentication\UserProviderInterface;
use Denosys\Auth\Identity\AuthenticatableInterface;
use Denosys\Auth\Identity\Identity;
use Denosys\Auth\Middleware\RememberCookieMiddleware;
use Denosys\Auth\Middleware\RememberCookieOptions;
use Denosys\Encryption\Encrypter;
use Denosys\Encryption\EncrypterInterface;
use Denosys\Container\Container;
use Denosys\Session\SessionInterface;
use InvalidArgumentException;
use Denosys\Session\Handlers\ArraySessionHandler;
use Denosys\Session\Store;
use Laminas\Diactoros\Response\HtmlResponse;
use Laminas\Diactoros\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

final class RememberCookieMiddlewareTest extends TestCase
{
    public function testServiceProviderBindsOptInMiddlewareWithoutEnablingItGlobally(): void
    {
        $container = new Container();
        $container->instance('config', new class {
            public function get(string $key, mixed $default = null): mixed
            {
                return $key === 'auth.remember.cookie_name' ? 'custom_remember' : $default;
            }
        });
        $session = $this->session();
        $user = new RememberTestUser();
        $container->instance(SessionInterface::class, $session);
        $container->instance(EncrypterInterface::class, new Encrypter(base64_encode(random_bytes(32))));

        (new AuthServiceProvider())->register($container);
        $container->instance(UserProviderInterface::class, new RememberTestProvider($user));
        $guard = $container->get(Authenticator::class);
        $guard->login(Identity::fromAuthenticatable($user), $user);
        $session->put('_auth_remember_token', $user->getRememberToken());
        $session->put('_auth_remember_id', $user->getAuthIdentifier());

        $middleware = $container->get(RememberCookieMiddleware::class);
        self::assertInstanceOf(RememberCookieMiddleware::class, $middleware);
        $response = $middleware->process(new ServerRequest([], [], 'https://example.test/login', 'POST'), $this->handler());
        self::assertStringContainsString('custom_remember=', $response->getHeaderLine('Set-Cookie'));
    }

    public function testOptInCookieSurvivesSessionLossAndUsesSecureFlags(): void
    {
        self::assertTrue(class_exists(RememberCookieMiddleware::class));
        $user = new RememberTestUser();
        $provider = new RememberTestProvider($user);
        $session = $this->session();
        $guard = new Authenticator($session, $provider);
        $guard->login(Identity::fromAuthenticatable($user), $user);
        $session->put('_auth_remember_token', $user->getRememberToken());
        $session->put('_auth_remember_id', $user->getAuthIdentifier());
        $encrypter = new Encrypter(base64_encode(random_bytes(32)));
        $options = new RememberCookieOptions(cookieName: 'remember_auth', lifetimeSeconds: 3600);
        $middleware = new RememberCookieMiddleware($guard, $provider, $session, $encrypter, $options);

        $response = $middleware->process(new ServerRequest([], [], 'https://example.test/login', 'POST'), $this->handler());
        $header = $response->getHeaderLine('Set-Cookie');
        self::assertStringContainsString('remember_auth=', $header);
        self::assertStringContainsString('HttpOnly', $header);
        self::assertStringContainsString('SameSite=Lax', $header);
        self::assertStringContainsString('Secure', $header);
        preg_match('/remember_auth=([^;]+)/', $header, $matches);
        $cookie = $matches[1] ?? '';
        self::assertNotSame('', $cookie);

        $newSession = $this->session();
        $newGuard = new Authenticator($newSession, $provider);
        $restore = new RememberCookieMiddleware($newGuard, $provider, $newSession, $encrypter, $options);
        $restore->process(
            (new ServerRequest([], [], 'https://example.test/dashboard', 'GET'))->withCookieParams(['remember_auth' => $cookie]),
            $this->handler(),
        );

        self::assertSame(7, $newGuard->id());
    }

    public function testExpiredTamperedChangedPasswordAndDisallowedCookiesAreRejected(): void
    {
        $user = new RememberTestUser();
        $provider = new RememberTestProvider($user);
        $encrypter = new Encrypter(base64_encode(random_bytes(32)));
        $options = new RememberCookieOptions();
        $validCookie = $this->cookie($encrypter, $user, time() + 3600);
        $expiredCookie = $this->cookie($encrypter, $user, time() - 1);
        $user->passwordHash = 'changed-hash';

        foreach ([$validCookie, $expiredCookie, $validCookie . 'tampered'] as $cookie) {
            $session = $this->session();
            $guard = new Authenticator($session, $provider);
            $middleware = new RememberCookieMiddleware($guard, $provider, $session, $encrypter, $options);
            $response = $middleware->process(
                (new ServerRequest([], [], 'https://example.test/dashboard', 'GET'))->withCookieParams(['remember_auth' => $cookie]),
                $this->handler(),
            );

            self::assertTrue($guard->guest());
            self::assertStringContainsString('Max-Age=0', $response->getHeaderLine('Set-Cookie'));
        }

        $session = $this->session();
        $guard = new Authenticator($session, $provider);
        $cookie = $this->cookie($encrypter, $user, time() + 3600);
        $middleware = new RememberCookieMiddleware(
            $guard,
            $provider,
            $session,
            $encrypter,
            $options,
            static fn (AuthenticatableInterface $candidate): bool => false,
        );
        $response = $middleware->process(
            (new ServerRequest([], [], 'https://example.test/dashboard', 'GET'))->withCookieParams(['remember_auth' => $cookie]),
            $this->handler(),
        );

        self::assertTrue($guard->guest());
        self::assertStringContainsString('Max-Age=0', $response->getHeaderLine('Set-Cookie'));
    }

    public function testLogoutAndNonRememberLoginRevokeExistingToken(): void
    {
        foreach (['logout', 'login'] as $action) {
            $user = new RememberTestUser();
            $provider = new RememberTestProvider($user);
            $encrypter = new Encrypter(base64_encode(random_bytes(32)));
            $cookie = $this->cookie($encrypter, $user, time() + 3600);
            $session = $this->session();
            $guard = new Authenticator($session, $provider);
            $guard->login(Identity::fromAuthenticatable($user), $user);
            $handler = $action === 'logout' ? $this->logoutHandler($guard) : $this->handler();
            $response = (new RememberCookieMiddleware($guard, $provider, $session, $encrypter))->process(
                (new ServerRequest([], [], 'https://example.test/' . $action, 'POST'))
                    ->withCookieParams(['remember_auth' => $cookie]),
                $handler,
            );

            self::assertSame('', $user->getRememberToken());
            self::assertStringContainsString('Max-Age=0', $response->getHeaderLine('Set-Cookie'));
        }
    }

    public function testUnsafeCookieOptionsAreRejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        new RememberCookieOptions(cookieName: "remember\r\nInjected", lifetimeSeconds: 3600);
    }

    private function session(): Store
    {
        $session = new Store('auth-test', new ArraySessionHandler());
        $session->start();

        return $session;
    }

    private function cookie(Encrypter $encrypter, RememberTestUser $user, int $expires): string
    {
        $payload = json_encode([
            'id' => $user->getAuthIdentifier(),
            'token' => $user->getRememberToken(),
            'password' => sha1($user->getAuthPassword()),
            'expires' => $expires,
        ], JSON_THROW_ON_ERROR);

        return rtrim(strtr($encrypter->encryptString($payload), '+/', '-_'), '=');
    }

    private function handler(): RequestHandlerInterface
    {
        return new class implements RequestHandlerInterface {
            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                return new HtmlResponse('ok');
            }
        };
    }

    private function logoutHandler(Authenticator $guard): RequestHandlerInterface
    {
        return new class ($guard) implements RequestHandlerInterface {
            public function __construct(private Authenticator $guard)
            {
            }

            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                $this->guard->logout();

                return new HtmlResponse('ok');
            }
        };
    }
}

final class RememberTestUser implements AuthenticatableInterface
{
    public string $passwordHash = 'stored-hash';
    private string $rememberToken;

    public function __construct()
    {
        $this->rememberToken = str_repeat('a', 64);
    }

    public function getAuthIdentifier(): string|int { return 7; }
    public function getAuthIdentifierName(): string { return 'id'; }
    public function getAuthPassword(): string { return $this->passwordHash; }
    public function getRememberToken(): ?string { return $this->rememberToken; }
    public function setRememberToken(string $token): void { $this->rememberToken = $token; }
    public function getRememberTokenName(): string { return 'remember_token'; }
    public function getAuthClaims(): array { return []; }
}

final class RememberTestProvider implements UserProviderInterface
{
    public function __construct(private RememberTestUser $user)
    {
    }

    public function findById(string|int $id): ?AuthenticatableInterface
    {
        return (int) $id === 7 ? $this->user : null;
    }

    public function findByCredential(string $field, string $value): ?AuthenticatableInterface
    {
        return null;
    }

    public function findByRememberToken(string|int $id, string $token): ?AuthenticatableInterface
    {
        return (int) $id === 7 && hash_equals($this->user->getRememberToken() ?? '', $token)
            ? $this->user
            : null;
    }

    public function updateRememberToken(AuthenticatableInterface $user, string $token): void
    {
        $user->setRememberToken($token);
    }

    public function validatePassword(AuthenticatableInterface $user, string $password): bool
    {
        return false;
    }

    public function rehashPasswordIfRequired(AuthenticatableInterface $user, string $password): void
    {
    }
}
