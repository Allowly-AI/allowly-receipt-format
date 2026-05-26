# Contributing

Thanks for your interest in the Allowly Receipt Format. This document covers how to report problems, propose changes, and add new verifier implementations.

## Reporting bugs and ambiguities

Open a GitHub issue with:

- **For spec ambiguities:** quote the section and line, describe what's unclear, and say what you'd do if you had to implement it today.
- **For verifier bugs:** include a minimal receipt JSON that reproduces the issue, the expected result, the actual result, and your environment (Python/Node version, OS).
- **For test vector disagreements:** if two verifiers disagree on a vector, that's the most important kind of bug. Include both outputs.

## Proposing spec changes

See [GOVERNANCE.md](./GOVERNANCE.md) for the change process. In short:

- **Editorial:** just open a PR.
- **Non-breaking addition:** open a PR, allow 7 days for comment.
- **Breaking change:** open an RFC in GitHub Discussions first. Don't open a PR until the RFC is accepted.

## Adding a new verifier (Go, Rust, Ruby, etc.)

New-language verifiers are welcome. Requirements:

1. **Must pass every vector in `test-vectors.json`.** No exceptions. If a vector fails, either the spec is wrong (open an issue) or the verifier is wrong (fix it).
2. **Must implement the verification algorithm in §7 of the spec in the stated order.** The order matters for consistent rejection reasons across implementations.
3. **Must include a CLI** that takes a receipt path and a keys path and exits 0 for valid / 1 for invalid, matching the Python and TypeScript verifiers' behavior.
4. **Must be reasonably minimal.** The reference verifiers are single-file, zero-to-minimal dependency. A new verifier doesn't need to match that exactly, but shouldn't pull in a framework.
5. **Must have a README** explaining installation and CLI usage.

Open a PR with the new verifier under `verifiers/<language>/`. Include a GitHub Actions workflow that runs its test suite against `test-vectors.json`.

## Code style

- **Python:** standard library first, type hints, black-formatted.
- **TypeScript:** strict mode, no `any`, prettier-formatted.
- **All languages:** no hidden dependencies on the Allowly service. Verifiers must work entirely offline given a receipt and a public key.

## Test vector contributions

New test vectors are especially welcome if they cover edge cases the current set misses. When adding vectors:

- Add them to `test-vectors.json` with a clear description of what they test.
- Add expected behavior to the `should_verify` or `should_reject` group.
- Verify both the Python and TypeScript reference verifiers produce the expected result before opening the PR.

## Legal

By contributing, you agree your contributions are licensed under:

- **Apache 2.0** for code changes (verifiers, test harnesses, tooling).
- **CC-BY 4.0** for specification text changes.

You affirm you have the right to contribute the work. For employer-owned contributions, make sure your employer's contribution policy allows it.

## Code of conduct

Be respectful. Disagreements about technical decisions are fine and expected; personal attacks are not. Maintainers may remove comments or block contributors who repeatedly violate this.
