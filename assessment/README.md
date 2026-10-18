# Verify an Observe assessment

These source tools implement [assessment profile v1](../spec/profiles/allowly-assessment-v1.md).
They are separate from the public wire-5 receipt API. No package release or
receipt wire change is implied. Existing receipt parsers keep rejecting this
different artifact type.

Install the maintained Python canonicalizer/key parser, then verify:

```sh
python -m pip install -e verifiers/python
python assessment/verify.py bundle.json trusted-keys.json \
  --workspace-id YOUR_WORKSPACE --project-id YOUR_LANGFUSE_PROJECT \
  --trusted-key-fingerprint sha256:YOUR_TRUSTED_FINGERPRINT
```

The Node reference uses the existing maintained TypeScript build:

```sh
cd verifiers/typescript && npm ci && npm run build
cd ../..
node assessment/verify.mjs bundle.json trusted-keys.json \
  YOUR_WORKSPACE YOUR_LANGFUSE_PROJECT sha256:YOUR_TRUSTED_FINGERPRINT
```

`bundle.json` contains `signed_assessment` (the original JWS strings) and
`source_snapshot` (the exact captured source). Obtain trusted key fingerprints
and workspace/project settings independently. Keys bundled by an untrusted
sender are not trust anchors. Keep source data private; the fictional vectors
are safe demonstration inputs.

A success authenticates the frozen record, source digest and cited passages.
It does not establish that a model's interpretation is right or that an action
occurred. Read application-reported execution separately from the OPA result.

Run the shared signed-vector/negative-case checks:

```sh
PYTHONPATH=. python -m pytest -q assessment/test_assessment.py
node assessment/test_assessment.mjs
```
