/**
 * hmac-v1 pseudonym reference tests (spec Appendix A).
 *
 * Constants are the spec's Appendix A.3 published vectors — identical to the
 * Python test_pseudonym_refs.py, so the two reference helpers are pinned to the
 * same cross-language expected bytes.
 *
 * Usage: node --experimental-strip-types test_pseudonym_refs.ts
 *    or after build: node dist/test_pseudonym_refs.js
 */
import { matchesRef } from "./verifier.js";

const KEY = new Uint8Array(Array.from({ length: 32 }, (_, i) => i));
const RECORD_REF =
  "hmac-v1:ecfc67ffb7bac447c05df24d1a25d75ebe7e765320d0fb1b4d22be332341599e";
const FULL_TUPLE_REF =
  "hmac-v1:c5fa890e042ea330013bd07bcc47c3312136373493fe87a490907b0e93c5727a";

let failures = 0;
function check(name: string, cond: boolean): void {
  if (cond) {
    console.log(`  OK    ${name}`);
  } else {
    console.log(`  FAIL  ${name}`);
    failures++;
  }
}

// A.3 published record vector
check("matches_published_record_vector", matchesRef(KEY, "record", "MRN-48291", RECORD_REF));

// A.3 published full_tuple vector (five components joined by 0x1F)
const fullTuple = ["MRN-48291", "baseline_arm_1", "demographics", "demographics", "2"].join("\x1f");
check("matches_published_full_tuple_vector", matchesRef(KEY, "full_tuple", fullTuple, FULL_TUPLE_REF));

// Mismatches and non-canonical references return false (never throw)
for (const [fieldName, value, ref] of [
  ["record", "MRN-48292", RECORD_REF],
  ["actor", "MRN-48291", RECORD_REF],
  ["record", "MRN-48291", RECORD_REF.toUpperCase()],
  ["record", "MRN-48291", RECORD_REF.slice(0, -1)],
  ["record", "MRN-48291", "sha256:" + RECORD_REF.slice("hmac-v1:".length)],
] as const) {
  check(`mismatch_returns_false [${fieldName}/${value.slice(0, 9)}]`, !matchesRef(KEY, fieldName, value, ref));
}

// Value is NOT Unicode-normalized: composed U+00E9 matches, decomposed e+U+0301 does not.
const composed = "José";
const decomposed = "José";
const JOSE_REF = "hmac-v1:76eca5c20d6d5d1c60f48bcd8b891f757e21a030e92f3cac90bc2462997f43ab";
check("composed_value_matches", matchesRef(KEY, "actor", composed, JOSE_REF));
check("decomposed_value_does_not_match", !matchesRef(KEY, "actor", decomposed, JOSE_REF));

// Weak key and unknown field are rejected loudly
function throws(fn: () => void, needle: string): boolean {
  try {
    fn();
    return false;
  } catch (e) {
    return e instanceof Error && e.message.includes(needle);
  }
}
check("rejects_weak_key", throws(() => matchesRef(new Uint8Array(8), "record", "MRN-48291", RECORD_REF), "128 bits"));
check("rejects_unknown_field", throws(() => matchesRef(KEY, "unknown", "MRN-48291", RECORD_REF), "field name"));

if (failures) {
  console.log(`\n${failures} failure(s)`);
  process.exit(1);
}
console.log("\nhmac-v1 pseudonym reference vectors pass.");
