# Verify an Observe assessment

These source tools implement [assessment profile v1](../spec/profiles/allowly-assessment-v1.md).
They remain separate from ordinary receipt wire 5 and its public package API.
The approved 2026-10-18 policy/evidence revision keeps version labels unchanged;
new verification uses approved policy requirements rather than named use cases.

Install the maintained Python canonicalizer/key parser, then verify:

```sh
python -m pip install -e verifiers/python
python assessment/verify.py bundle.json trusted-keys.json \
  --workspace-id YOUR_WORKSPACE --project-id YOUR_PROJECT \
  --trusted-key-fingerprint sha256:YOUR_TRUSTED_FINGERPRINT
```

The Node tool uses the existing maintained TypeScript build:

```sh
cd verifiers/typescript && npm ci && npm run build
cd ../..
node assessment/verify.mjs bundle.json trusted-keys.json \
  YOUR_WORKSPACE YOUR_PROJECT sha256:YOUR_TRUSTED_FINGERPRINT
```

The bundle contains original `signed_assessment` JWS strings, `source_snapshot`,
`policy_definition`, and `mapping_snapshot`. Obtain expected workspace/project
IDs and trusted key fingerprints independently. Bundled keys do not establish
trust. Keep source data private; the fictional vectors are safe test inputs.

Both tools authenticate the frozen record, policy/mapping/source commitments,
exact citations, typed facts, derived context, reconstructed request and OPA
input commitments. No Langfuse connection is required. Success does not prove
AI interpretation, upstream truth, independent OPA replay, action execution,
enforcement, delivery, human identity or complete capture. Read the separate
application-reported execution claim independently of the policy result.

Shared pure Python helpers live in `allowly_receipt_format.evidence`; they use
no provider/network/OPA. Existing package exports and receipt semantics stay
unchanged. Historical `vectors.json` is immutable evidence, not a compatibility
parser target. Generate revised fixtures into `evidence-vectors.json` only.

```sh
PYTHONPATH=. python -m pytest -q assessment/test_assessment.py assessment/test_evidence.py
node assessment/test_assessment.mjs
python assessment/generate_vectors.py
```
