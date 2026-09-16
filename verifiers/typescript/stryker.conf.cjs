module.exports = {
  mutate: ["verifier.ts"],
  testRunner: "command",
  commandRunner: {
    command: "npm test",
  },
  reporters: ["clear-text"],
  coverageAnalysis: "off",
  inPlace: true,
  thresholds: {
    break: 100,
  },
};
