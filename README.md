# denosyscore/auth

Authentication and authorization components

## Status

Initial extraction snapshot from denosyscore monorepo as of 2026-02-14.

## Installation

composer require denosyscore/auth

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
