# Governance

This document describes how decisions about the Allowly Receipt Format specification are made.

## Current state

The specification is maintained by Allowly. The current local receipt wire format is `"5"`, implemented by verifier packages 5.x. Final decisions on the spec text and verifier behavior rest with Allowly's maintainers while Allowly is the only serious implementer.

## Change process

Changes fall into three categories:

### 1. Editorial changes

Typos, clarifications that don't change normative behavior, improved examples, broken links. Handled via pull request with one maintainer approval. No RFC needed.

### 2. Non-breaking additions

New optional fields, new non-normative appendices, new test vectors covering existing behavior. Handled via pull request with:

- At least one maintainer approval.
- A 7-day comment window on GitHub Discussions before merge.
- Confirmation that existing verifiers continue to pass all test vectors.

### 3. Breaking changes

Any change that would cause a verifier for the current wire format to reject a previously valid receipt, or accept a previously invalid receipt. Examples: new required fields, changes to canonicalization rules, signature algorithm changes.

Breaking changes require a wire-version and verifier-major bump (for example, wire `"4"` / verifier 4.x to wire `"5"` / verifier 5.x) and go through an RFC process:

1. Open a GitHub Discussion titled `RFC: <short name>` with a written proposal: problem, proposed change, migration story, reference to affected spec sections.
2. **14-day minimum comment window.** Longer if discussion is active.
3. Maintainers summarize the discussion and announce a decision.
4. If accepted, a PR updates the spec, bumps the version, and adds a migration note to `CHANGELOG.md`.

Breaking changes never rewrite a released specification. A new wire-version specification lives alongside the historical text. Support for older verifier majors is governed by their published release and security-support policy; this document does not promise indefinite maintenance.

### Approved prelaunch exception: confirmation resolution

The [2026-10-07 decision](docs/decisions/2026-10-07-confirmation-resolution-wire-4.md)
permits only `confirmation.resolve` with `confirmation_approved` or
`confirmation_rejected` to extend wire `"4"` in verifier packages `4.3.0`.
For this one approved prelaunch change, the wire-major bump and 14-day RFC
window above do not apply. Published `4.2.0` artifacts remain unchanged and
continue to reject the new event. All other breaking changes follow the
normal rules above.

### Approved unpublished exception: policy-defined evidence

On 2026-10-18 the maintainer explicitly approved a breaking policy/evidence
revision without package, HTTP, policy/basic, assessment or receipt version
bumps because no external clients use this source contract. Optional approved
action evidence metadata and generic assessment facts replace named-use-case
branches. The ordinary wire-5 JWS fields and public receipt-verifier exports
remain unchanged. All active definition consumers and source assessment tools
must align in the same batch. Original signed assessments, historical vectors
and published policy definitions remain immutable. This exception authorizes
neither package publication nor production deployment/migrations; normal review,
checks and required approvals still apply. Other breaking changes retain the
normal rules above.

## Who are the maintainers

Listed in `MAINTAINERS.md`. Maintainers are added when they've made sustained contributions to the spec, verifiers, or test vectors, and are nominated by an existing maintainer. Removal happens when a maintainer is inactive for 12+ months or steps down.

## Longer-term intent

The goal is for the receipt format to be a neutral standard, not a single-vendor artifact. As the ecosystem matures, governance will evolve toward:

- A foundation or working group (CNCF, IETF, or similar) if adoption justifies it.
- Multi-organization maintainer representation.
- A formal RFC process modeled on IETF or W3C.

None of that makes sense before there are multiple serious implementers. Until then, the process above is the operating model.

## Security issues

Suspected vulnerabilities in the specification or reference verifiers should **not** be filed as GitHub issues. Email `security@allowly.ai` with details. We'll respond within 3 business days and coordinate disclosure.

## Questions

Open a GitHub Discussion. For private questions about process or licensing, email `spec@allowly.ai`.
