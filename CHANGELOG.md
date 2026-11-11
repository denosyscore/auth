# Changelog

## 0.3.3 – 2026-11-11

- Accept `denosyscore/http` 0.4, which removes classes this package never used.
  CI tests it with database 0.5.0 and session 0.2.6.

## 0.3.2 – 2026-11-11

- Accept `denosyscore/database` 0.5. The test suite passes against 0.5.0, and CI
  tests it alongside the matching HTTP and dependent package releases.

## 0.3.1

- Accept database 0.4 while retaining the supported 0.2 and 0.3 lines.
- Test database 0.4 with compatible HTTP and session releases in CI.

## 0.3.0

- Accept database and HTTP 0.3 while retaining their supported 0.2 lines.
- Add opt-in encrypted remember-cookie middleware for issuance, restoration,
  revocation, and logout handling without changing the default web stack.

- Propagate the authenticated user through any PSR-7 request by forwarding a
  PSR-compatible HTTP request wrapper. Existing wrapped-request and
  unauthenticated behavior remains supported.
- Declare the container, contracts, and PSR interfaces used directly by the
  package; run authentication regression tests in CI.

This changes the concrete request class seen by handlers that supply another
PSR-7 implementation. Review for a compatible minor release under the 0.x
version policy.
