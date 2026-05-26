# Governance

This document describes how decisions about the Allowly Receipt Format specification are made.

## Current state

The specification is maintained by Allowly. During the v1 draft period, final decisions on the spec text and verifier behavior rest with Allowly's maintainers. This reflects the spec's early stage, not a long-term position.

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

Any change that would cause a v1.0-compliant verifier to reject a previously-valid receipt, or accept a previously-invalid receipt. Examples: new required fields, changes to canonicalization rules, signature algorithm changes.

Breaking changes require a version bump (v1 → v2) and go through an RFC process:

1. Open a GitHub Discussion titled `RFC: <short name>` with a written proposal: problem, proposed change, migration story, reference to affected spec sections.
2. **14-day minimum comment window.** Longer if discussion is active.
3. Maintainers summarize the discussion and announce a decision.
4. If accepted, a PR updates the spec, bumps the version, and adds a migration note to `CHANGELOG.md`.

Breaking changes never modify v1. A v2 spec lives alongside v1; v1 verifiers continue to work against v1 receipts indefinitely.

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
