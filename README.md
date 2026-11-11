# denosyscore/auth

Authentication and authorization components

## Installation

```bash
composer require denosyscore/auth
```

## Quick start

Log users in with a password strategy. Supply a user provider for your storage; the session keeps the login.

<!-- quickstart -->
```php
<?php

require __DIR__ . '/vendor/autoload.php';

use Denosys\Auth\Authentication\Authenticator;
use Denosys\Auth\Authentication\Credential\PasswordCredential;
use Denosys\Auth\Authentication\Strategy\PasswordStrategy;
use Denosys\Auth\Authentication\UserProviderInterface;
use Denosys\Auth\Identity\AuthenticatableInterface;
use Denosys\Session\Handlers\ArraySessionHandler;
use Denosys\Session\Store;

final class User implements AuthenticatableInterface
{
    public ?string $rememberToken = null;

    public function __construct(public int $id, public string $email, public string $passwordHash) {}

    public function getAuthIdentifier(): int { return $this->id; }
    public function getAuthIdentifierName(): string { return 'id'; }
    public function getAuthPassword(): string { return $this->passwordHash; }
    public function getRememberToken(): ?string { return $this->rememberToken; }
    public function setRememberToken(string $token): void { $this->rememberToken = $token; }
    public function getRememberTokenName(): string { return 'remember_token'; }
    public function getAuthClaims(): array { return ['id' => $this->id, 'email' => $this->email]; }
}

// Tell the authenticator how to find users; in an application this reads the database.
final class InMemoryUsers implements UserProviderInterface
{
    /** @param array<int, User> $users */
    public function __construct(private array $users) {}

    public function findById(string|int $id): ?AuthenticatableInterface { return $this->users[$id] ?? null; }

    public function findByCredential(string $field, string $value): ?AuthenticatableInterface
    {
        foreach ($this->users as $user) {
            if ($field === 'email' && $user->email === $value) {
                return $user;
            }
        }
        return null;
    }

    public function findByRememberToken(string|int $id, string $token): ?AuthenticatableInterface { return null; }
    public function updateRememberToken(AuthenticatableInterface $user, string $token): void {}
    public function validatePassword(AuthenticatableInterface $user, string $password): bool
    {
        return password_verify($password, $user->getAuthPassword());
    }
    public function rehashPasswordIfRequired(AuthenticatableInterface $user, string $password): void {}
}

$users = new InMemoryUsers([1 => new User(1, 'ada@example.com', password_hash('secret', PASSWORD_DEFAULT))]);
$session = new Store('app_session', new ArraySessionHandler());
$session->start();

$auth = new Authenticator($session, $users);
$auth->addStrategy(new PasswordStrategy($users, identifierField: 'email'));

var_dump($auth->attempt(new PasswordCredential('ada@example.com', 'wrong'))->isSuccess());  // bool(false)
var_dump($auth->attempt(new PasswordCredential('ada@example.com', 'secret'))->isSuccess()); // bool(true)
echo $auth->user()->getAuthClaims()['email'], "\n";  // ada@example.com

$auth->logout();
var_dump($auth->guest());  // bool(true)
```

## Included Modules

- src/Auth/*

## Authenticated requests

`AuthenticateMiddleware` accepts any PSR-7 server request. After successful
authentication it forwards a PSR-compatible `Denosys\Http\Request` containing
the authenticated user and rebinds that request under both HTTP request
contracts in the container. The original method, URI, attributes, parsed
body, and headers remain available. Unauthenticated requests keep the
configured redirect or JSON 401 behavior.

## Persistent login cookies

`RememberCookieMiddleware` is opt-in. The auth service provider binds it, but
does not add it to a route group. Add it after session startup in the web
middleware group when persistent login is wanted. It reads the remember-token
metadata written by `Authenticator::attempt()` after a successful credential
with `remember: true`, issues an encrypted cookie, restores a user after the
ordinary session expires, and clears the cookie on logout or invalid input.
The existing `UserProviderInterface` revokes the stored token.

Configure `auth.remember.cookie_name`, `lifetime_seconds`, `secure` (true,
false, or null to follow HTTPS), `same_site` (Lax, Strict, or None),
`login_path`, and `logout_path` before resolving the middleware. Defaults are
`remember_auth`, 30 days, null, Lax, `/login`, and `/logout`. Cookies are always
HttpOnly. `SameSite=None` always emits Secure. Paths must be local paths.

By default any valid authenticated user may be restored. Applications with
account status rules should bind `RememberEligibilityInterface` to an
implementation that checks those rules. The middleware remains disabled until
explicitly placed in a route or middleware group. Encryption is a declared
runtime dependency; configure its key before enabling persistent cookies.

## Development

composer validate --strict
find src tests -type f -name '*.php' -print0 | xargs -0 -n1 php -l
composer test

## CI Workflows

- CI: Composer validation, isolated installation, PHP syntax lint, and
  authentication regression tests on push and pull requests.
- Release: GitHub release publication on semantic version tags.
- Dependabot: weekly Composer dependency update checks.

## Releases

CI tests database 0.2, 0.3, and 0.4 with compatible HTTP and session
releases on PHP 8.2 and 8.5. After CI passes on `main`,
create an annotated semantic version tag from that reviewed commit and push
it. The Release workflow publishes a GitHub Release. Confirm the matching
version is available in the Composer package index before updating consumers.
