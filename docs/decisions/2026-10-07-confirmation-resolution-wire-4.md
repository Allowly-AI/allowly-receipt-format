# Confirmation resolution: approved wire 4 exception

Date: 2026-10-07. Status: approved prelaunch exception, staged for release.

The maintainer explicitly approved adding one event to receipt wire `"4"`:
`confirmation.resolve`, paired only with `confirmation_approved` or
`confirmation_rejected`. Both reference verifier packages advance to `4.3.0`.
This one exception does not require the normal wire-major bump or 14-day RFC
window. It does not change the governance rules for future changes.

The top-level receipt fields, Ed25519 signatures, canonicalization, key trust,
workspace binding, and wire value remain unchanged. Resolution data stays in
the signed `context` object. Existing signed vectors and receipt bytes remain
unchanged and valid. A signature authenticates the issuer's recorded report;
it does not establish a named human's identity, approval, or action execution.

Published `4.2.0` artifacts remain immutable. They still reject
`confirmation.resolve` because their event allowlist does not contain it.
Verification of the new event requires `4.3.0` or a later compatible 4.x
release. Other unknown events and invalid event/decision pairs stay rejected.

## Release gate

This feature branch stages source, tests, package versions, and local-source
consumer locks. It does not publish packages or deploy an issuer.

1. Review and merge the receipt-format change through the release workflow.
2. Publish both `allowly-receipt-format==4.3.0` and `@allowly/verifier@4.3.0`.
3. Remove temporary local-source consumer overrides and regenerate registry
   locks. Update runtime, SDK, integration, dashboard, and site consumers.
4. Run contract lint and consumer tests against the published artifacts.
5. Deploy consumers that verify the event before enabling an issuer that
   emits it. Runtime, package, and site releases remain separate operations.

An old verifier rejecting the new event is expected fail-closed behavior.
The common wire value alone is not a claim that older consumers support it.
