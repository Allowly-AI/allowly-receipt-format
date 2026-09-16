module.exports = {
  mutate: ["verifier.ts"],
  testRunner: "command",
  commandRunner: {
    command: "npm test",
  },
  reporters: ["clear-text"],
  coverageAnalysis: "off",
  thresholds: {
    break: 100,
  },
};
