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

## Development

composer validate --strict
find src tests -type f -name '*.php' -print0 | xargs -0 -n1 php -l
composer test

## CI Workflows

- CI: Composer validation, isolated installation, PHP syntax lint, and
  authentication regression tests on push and pull requests.
- Release: GitHub release publication on semantic version tags.
- Dependabot: weekly Composer dependency update checks.
