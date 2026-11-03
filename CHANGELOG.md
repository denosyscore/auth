# Changelog

## Unreleased (proposed 0.3.0)

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
