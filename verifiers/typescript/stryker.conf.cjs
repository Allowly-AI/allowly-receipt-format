module.exports = {
  mutate: ["verifier.ts"],
  testRunner: "command",
  buildCommand: "npm run build",
  commandRunner: {
    // The gate separately runs the generated browser build before instrumentation.
    // Mutants exercise the same policy implementation through its Node vectors.
    command: "node dist/test_vectors.js ../../test-vectors.json && node dist/test_policy_evaluation.js ../../vectors/policy/profile-v1.json && node dist/test_pseudonym_refs.js && node dist/test_seal.js ../../vectors/seal/profile-v1.json ../../vectors/seal/verification-v1.json",
  },
  incremental: true,
  incrementalFile: "reports/mutation/incremental.json",
  reporters: ["clear-text"],
  coverageAnalysis: "off",
  inPlace: true,
  thresholds: {
    break: 100,
  },
};
