# Changelog

## Unreleased

- Propagate the authenticated user through any PSR-7 request by forwarding a
  PSR-compatible HTTP request wrapper. Existing wrapped-request and
  unauthenticated behavior remains supported.
- Declare the container, contracts, and PSR interfaces used directly by the
  package; run authentication regression tests in CI.

This changes the concrete request class seen by handlers that supply another
PSR-7 implementation. Review for a compatible minor release under the 0.x
version policy.
