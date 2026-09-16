# Interoperability

Allowly returns a policy decision for one agent action and records a receipt of
that decision. The caller asks before running the tool and executes only an
`allow`; it stops on `deny`, pauses on `confirm` or `escalate`, and stops if the
check fails. A check can return a pending receipt, which the caller retrieves
after signing. The receipt signer never runs the tool.

The documented [AgentCore Gateway REQUEST interceptor](https://allowly.ai/docs/sdk/allowly-agentcore-interceptor/),
[Google ADK App plugin](https://allowly.ai/docs/sdk/google-adk/), and
[Semantic Kernel filter](https://allowly.ai/docs/sdk/allowly-semantic-kernel-filter/)
put the check and stopping behavior at the host's tool hook. They cover calls
routed through that configured hook. The host must prevent direct access that
bypasses it; with the plain API, the caller owns the check and enforcement.

## CSA AARM v1.0

This map describes how Allowly supports a host's implementation of the
[Autonomous Action Runtime Management requirements](https://aarm.dev/conformance),
reviewed on 2026-09-16. It is not a certification claim.

| AARM requirement | Allowly's part | Host responsibility or limit |
|---|---|---|
| R1 — intercept before execution | The caller, or a configured host hook, checks before the tool runs. | Only `allow` forwards. `deny`, `confirm`, `escalate`, and check failures keep the tool stopped. Coverage depends on routing and bypass prevention. |
| R2 — accumulate context | The receipt signs supplied `context` under the format's canonical serialization rules, preserving values and array order. | The host accumulates intent, prior actions, and other relevant context, and selects what to send. The signature does not establish that the context is true or complete. |
| R3 — evaluate policy and intent | Written policy is evaluated without a model in the decision path. Optional `policy_eval` can record the matched conditional clause and evaluated value. | The host supplies relevant intent and context; Allowly does not independently infer the user's intent. |
| R4 — five decision outcomes | Partial: `allow`, `deny`, `confirm` (roughly `STEP_UP`), and `escalate` (roughly `DEFER`). | There is no `MODIFY` outcome. The caller owns confirmation and escalation handling. |
| R5 — tamper-evident receipts | Signed action receipts include `action`, `decision`, `issued_at`, and `authorization_id`, with optional `policy_eval`. Ed25519 signatures verify offline with the open-source verifiers. | The verifier must authenticate the expected workspace and public key. A receipt records a decision, not downstream execution. |
| R6 — bind identity | Partial: receipts include opaque, customer-supplied `agent_id` and `user_id`. | The host or identity provider binds these identifiers to real identities. |

R7 semantic-distance and intent-drift tracking, R8 telemetry export, and R9
least-privilege credential scoping remain host responsibilities.

## ACTA draft, revision 03

As of 2026-09-16, wire-4 receipts are not envelopes defined by
[`draft-farley-acta-signed-receipts-03`](https://www.ietf.org/archive/id/draft-farley-acta-signed-receipts-03.html).
For a valid wire-4 receipt containing none of U+0008, U+0009, U+000A, U+000C,
or U+000D in any string value or member name, its canonical payload bytes
(the receipt with only `signature` removed) are byte-identical to
[RFC 8785 JCS](https://www.rfc-editor.org/rfc/rfc8785.html#section-3.2):
the decoded Ed25519 signature therefore verifies over those JCS bytes with the
pinned workspace key, but this byte-level check replaces neither ACTA envelope
validation nor the [full Allowly verification algorithm](./spec/receipt-format.md#7-verification-algorithm).
At the decision level, `confirm` corresponds to ACTA's `require_approval`, which
holds an action for human approval; `escalate` has no exact ACTA counterpart
([revision 03 §3.1.1](https://www.ietf.org/archive/id/draft-farley-acta-signed-receipts-03.html#section-3.1.1)).

## What verification does not prove

The following is reproduced verbatim from [specification §7.1](./spec/receipt-format.md#71-what-verification-does-not-prove);
section references below refer to that specification.

Verifiers and users of verified receipts **MUST NOT** assume the following:

1. **That the action actually happened.** An action receipt records what the agent *asked about*, not what the agent *did*. An `allow` decision followed by no action still produces a receipt.
2. **That a human approved.** An `authorization.create` receipt records that an authenticated customer client registered the authorization. If the client reports human approval, the receipt does not independently prove that input occurred, that the UI was clear, or that the user understood it.
3. **That the context is true.** Fields like `initiated_by` and `origin` reflect what the customer's system reported at the time. The issuer does not independently verify them.
4. **That `user_id` corresponds to any particular real-world person.** It is an opaque identifier the customer controls.
5. **That the issuer's registry or real-world history was complete.** Without a checkpoint, signatures prove only each presented receipt. A verified checkpoint proves equality to its signed member-set commitment, but without external anchoring it cannot prove the issuer registered or retained every receipt before constructing that commitment (§3.7.2).
6. **That a receipt was signed at `issued_at`.** The timestamp is a signed claim, not a proof of signing time; a compromised key can produce receipts bearing any `issued_at` (§10.1).
7. **That a workspace or key is authentic without an external trust decision.** A signature proves only that the holder of the selected private key signed the payload. The verifier still must authenticate the expected workspace and public key, or its fingerprint, as described in §7.

These limits are intentional. The receipt attests to what the issuer observed and recorded, not to ground truth about the world.

---

This page is licensed under [CC BY 4.0](./LICENSE-SPEC), like the specification.
