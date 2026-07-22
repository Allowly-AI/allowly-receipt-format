/**
 * Allowly Receipt Verifier (TypeScript reference implementation).
 *
 * Verifies Allowly receipts per receipt-format.md v2.0.0.
 *
 * Dependencies: Node.js 20+ (uses built-in node:crypto and the WebCrypto API).
 * No external runtime dependencies.
 *
 * Usage:
 *   import { verifyReceipt, VerificationError, loadKeysFromJson } from "./verifier.js";
 *
 *   try {
 *     await verifyReceipt(receipt, publicKeys);
 *     console.log("valid");
 *   } catch (e) {
 *     if (e instanceof VerificationError) console.log(`invalid: ${e.message}`);
 *     else throw e;
 *   }
 *
 * Spec: https://github.com/Allowly-AI/allowly-receipt-format
 * License: Apache 2.0
 */

import { webcrypto } from "node:crypto";

const SPEC_VERSION = "2.0.0";
const ACTION_DECISIONS = new Set(["allow", "deny", "confirm", "escalate"]);
const EVENT_DECISIONS: Record<string, Set<string>> = {
  "authorization.create": new Set(["authorization_granted"]),
  "authorization.revoke": new Set(["authorization_revoked"]),
  "budget.settle": new Set(["budget_settled"]),
  "escalation.resolve": new Set(["escalation_approved", "escalation_rejected"]),
};
const AUTHORIZATION_LIFECYCLE_EVENTS = new Set(["authorization.create", "authorization.revoke"]);
const EVENT_ONLY_DECISIONS = new Set(Object.values(EVENT_DECISIONS).flatMap((decisions) => [...decisions]));
const REQUIRED_FIELDS = new Set([
  "version", "receipt_id", "workspace_id", "issued_at", "decision", "reason",
  "user_id", "agent_id", "resource", "context",
  "authorization_id", "engine_version", "alg", "key_id", "signature",
]);
const OPTIONAL_FIELDS = new Set(["policy_eval"]);
const DISCRIMINATOR_FIELDS = new Set(["action", "event"]);
const ALL_TOP_LEVEL_FIELDS = new Set([
  ...REQUIRED_FIELDS,
  ...DISCRIMINATOR_FIELDS,
  ...OPTIONAL_FIELDS,
]);
const MAX_FUTURE_SKEW_MS = 5 * 60 * 1000;

export class VerificationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "VerificationError";
  }
}

export interface PublicKey {
  keyId: string;
  alg: "Ed25519";
  publicKeyBytes: Uint8Array;  // 32 raw bytes
  activeFrom: Date;
  activeUntil: Date | null;
}

interface ReceiptBase {
  receipt_id: string;
  workspace_id: string;
  issued_at: string;
  decision: string;
  reason: string;
  user_id: string;
  agent_id: string;
  action?: string;
  event?: string;
  resource: string | null;
  context: Record<string, unknown>;
  authorization_id: string | null;
  engine_version: string;
  policy_eval?: {
    matched_condition: {
      field: string;
      op: string;
      value: string | number | boolean | null | Array<string | number | boolean | null>;
    } | null;
    field_value: string | number | boolean | null;
  };
}

export interface Receipt extends ReceiptBase {
  version: "2.0.0";
  alg: string;
  key_id: string;
  signature: string;
}

// ---------------------------------------------------------------------------
// Base64url
// ---------------------------------------------------------------------------

const B64URL_RE = /^[A-Za-z0-9_-]*$/;

function b64urlDecode(s: string): Uint8Array {
  // Buffer.from(..., "base64") silently drops out-of-alphabet characters and
  // accepts padding / the standard alphabet, so we gate on the URL-safe,
  // unpadded form explicitly to enforce spec §5.1.
  if (!B64URL_RE.test(s)) {
    throw new VerificationError(`not unpadded base64url: ${JSON.stringify(s)}`);
  }
  const padded = s + "=".repeat((4 - (s.length % 4)) % 4);
  const standard = padded.replace(/-/g, "+").replace(/_/g, "/");
  const binary = Buffer.from(standard, "base64");
  if (binary.toString("base64url") !== s) {
    throw new VerificationError(`non-canonical base64url: ${JSON.stringify(s)}`);
  }
  return new Uint8Array(binary);
}

// ---------------------------------------------------------------------------
// Canonicalization (spec §4)
// ---------------------------------------------------------------------------

// Depth/node limits so hostile receipts fail with a VerificationError instead
// of blowing the call stack during canonicalization.
const MAX_PAYLOAD_DEPTH = 32;
const MAX_PAYLOAD_NODES = 50_000;

export function canonicalize(payload: unknown): Uint8Array {
  validateTree(payload);
  const s = stringify(payload);
  return new TextEncoder().encode(s);
}

function validateTree(payload: unknown): void {
  // Iterative pre-walk: bound depth/size, reject lone surrogates and
  // non-integer/unsafe numbers (spec §4.2 rules 1 and 6). Without the
  // well-formedness check, TextEncoder silently replaces an unpaired
  // surrogate with U+FFFD — so two *different* strings could canonicalize to
  // identical bytes and a tampered receipt would still verify.
  let nodes = 0;
  const stack: Array<[unknown, number]> = [[payload, 1]];
  while (stack.length > 0) {
    const [value, depth] = stack.pop()!;
    nodes += 1;
    if (depth > MAX_PAYLOAD_DEPTH) {
      throw new VerificationError(`payload nesting exceeds max depth ${MAX_PAYLOAD_DEPTH}`);
    }
    if (nodes > MAX_PAYLOAD_NODES) {
      throw new VerificationError(`payload exceeds max node count ${MAX_PAYLOAD_NODES}`);
    }
    if (typeof value === "number") {
      if (!Number.isInteger(value)) {
        throw new VerificationError("receipts must not contain non-integer numbers");
      }
      // Integers outside the I-JSON safe range (±(2^53-1)) lose precision in
      // doubles and would render with an exponent (e.g. "1e+21"), violating
      // §4.2 rule 6. Number.isSafeInteger excludes them.
      if (!Number.isSafeInteger(value)) {
        throw new VerificationError(
          "integer exceeds the safe range ±(2^53-1); receipts must not carry integers that lose precision in IEEE-754 doubles",
        );
      }
    } else if (typeof value === "string") {
      if (!value.isWellFormed()) {
        throw new VerificationError("string contains an unpaired Unicode surrogate");
      }
    } else if (Array.isArray(value)) {
      for (const item of value) stack.push([item, depth + 1]);
    } else if (value !== null && typeof value === "object") {
      for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
        if (!k.isWellFormed()) {
          throw new VerificationError("string contains an unpaired Unicode surrogate");
        }
        stack.push([v, depth + 1]);
      }
    }
  }
}

function stringify(v: unknown): string {
  if (v === null) return "null";
  if (typeof v === "boolean") return v ? "true" : "false";
  if (typeof v === "number") {
    // Integers already validated by assertNoFloats.
    return String(v);
  }
  if (typeof v === "string") return encodeString(v);
  if (Array.isArray(v)) {
    return "[" + v.map(stringify).join(",") + "]";
  }
  if (typeof v === "object") {
    const entries = Object.entries(v as Record<string, unknown>);
    // Lexicographic sort by UTF-16 code units (JS default).
    entries.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    return (
      "{" +
      entries.map(([k, val]) => encodeString(k) + ":" + stringify(val)).join(",") +
      "}"
    );
  }
  throw new VerificationError(`unsupported type in payload: ${typeof v}`);
}

function encodeString(s: string): string {
  let out = '"';
  for (const ch of s) {
    const code = ch.codePointAt(0)!;
    if (ch === '"') out += '\\"';
    else if (ch === "\\") out += "\\\\";
    else if (code < 0x20) {
      out += "\\u" + code.toString(16).padStart(4, "0");
    } else {
      // Non-ASCII passed through as UTF-8 per spec §4.2 rule 5.
      out += ch;
    }
  }
  out += '"';
  return out;
}

// ---------------------------------------------------------------------------
// Verification (spec §7)
// ---------------------------------------------------------------------------

export async function verifyReceipt(
  receipt: Record<string, unknown>,
  publicKeys: PublicKey[],
  opts: { now?: Date; expectedWorkspaceId?: string } = {},
): Promise<void> {
  const now = opts.now ?? new Date();

  // Step 1: version check
  if (receipt.version !== SPEC_VERSION) {
    throw new VerificationError(
      `unsupported version: ${JSON.stringify(receipt.version)} (want "${SPEC_VERSION}")`,
    );
  }

  // Key ids alone do not bind a receipt to a workspace. If the caller passes the
  // workspace the keys were published for, require the receipt to match it.
  if (
    opts.expectedWorkspaceId !== undefined &&
    receipt.workspace_id !== opts.expectedWorkspaceId
  ) {
    throw new VerificationError(
      `workspace_id mismatch: receipt has ${JSON.stringify(receipt.workspace_id)}, ` +
        `expected ${JSON.stringify(opts.expectedWorkspaceId)}`,
    );
  }

  // Step 2: schema check (includes signature shape — rejects placeholders)
  checkSchema(receipt);
  const r = receipt as unknown as Receipt;

  // Step 3: receipt kind and pairing
  const hasAction = "action" in receipt;
  const hasEvent = "event" in receipt;

  if (hasAction && hasEvent) {
    throw new VerificationError(
      "receipt has both 'action' and 'event'; exactly one must be present",
    );
  }
  if (!hasAction && !hasEvent) {
    throw new VerificationError(
      "receipt has neither 'action' nor 'event'; exactly one must be present",
    );
  }

  if (hasEvent) {
    const event = (receipt as Record<string, unknown>).event;
    if (typeof event !== "string") {
      throw new VerificationError("event must be a string");
    }
    if (!(event in EVENT_DECISIONS)) {
      throw new VerificationError(
        `event must be one of ["authorization.create","authorization.revoke","budget.settle","escalation.resolve"], got ${JSON.stringify(event)}`,
      );
    }
    const expectedDecisions = EVENT_DECISIONS[event];
    if (!expectedDecisions.has(r.decision)) {
      throw new VerificationError(
        `event receipt with event=${JSON.stringify(event)} must have ` +
          `decision in ${JSON.stringify([...expectedDecisions].sort())}, got ${JSON.stringify(r.decision)}`,
      );
    }
    if (r.authorization_id === null) {
      throw new VerificationError(
        `event receipt with event=${JSON.stringify(event)} must have non-null authorization_id`,
      );
    }
    if (AUTHORIZATION_LIFECYCLE_EVENTS.has(event) && r.resource !== null) {
      throw new VerificationError(
        `authorization lifecycle receipt with event=${JSON.stringify(event)} must have null resource`,
      );
    }
    if ("policy_eval" in receipt) {
      throw new VerificationError("policy_eval must be absent on event receipts");
    }
  } else {
    const action = (receipt as Record<string, unknown>).action;
    if (typeof action !== "string") {
      throw new VerificationError("action must be a string");
    }
    if (EVENT_ONLY_DECISIONS.has(r.decision)) {
      throw new VerificationError(
        `decision=${JSON.stringify(r.decision)} requires an event receipt (event field), ` +
          `got an action receipt with action=${JSON.stringify(action)}`,
      );
    }
    if (!ACTION_DECISIONS.has(r.decision)) {
      throw new VerificationError(
        `action receipt must have decision in ["allow","confirm","deny","escalate"], ` +
          `got ${JSON.stringify(r.decision)}`,
      );
    }
  }

  // Step 4: algorithm check
  if (r.alg !== "Ed25519") {
    throw new VerificationError(`unsupported signature alg: ${JSON.stringify(r.alg)}`);
  }

  // Step 5: timestamp sanity
  const issuedAt = parseRFC3339(r.issued_at);
  // Spec §3: issued_at is exactly UTC, millisecond precision, Z suffix.
  // (Key-document timestamps stay on the general RFC 3339 rule.)
  if (!ISSUED_AT_RE.test(r.issued_at)) {
    throw new VerificationError(
      `issued_at must be UTC millisecond precision YYYY-MM-DDTHH:MM:SS.sssZ, got ${JSON.stringify(r.issued_at)}`,
    );
  }
  if (issuedAt.getTime() > now.getTime() + MAX_FUTURE_SKEW_MS) {
    throw new VerificationError(
      `receipt issued in the future: ${issuedAt.toISOString()} > ${now.toISOString()}`,
    );
  }

  // Step 6: canonicalize
  const { signature, ...payload } = r;
  const canonical = canonicalize(payload);

  // Step 7: signature verification
  const key = findKey(publicKeys, r.key_id, issuedAt);
  const sigBytes = b64urlDecode(r.signature);  // length already validated in schema check

  const cryptoKey = await webcrypto.subtle.importKey(
    "raw",
    key.publicKeyBytes,
    { name: "Ed25519" },
    false,
    ["verify"],
  );

  const ok = await webcrypto.subtle.verify("Ed25519", cryptoKey, sigBytes, canonical);
  if (!ok) {
    throw new VerificationError("signature verification failed");
  }

  // Step 8: accept (implicit — no throw)
}

function checkSchema(receipt: Record<string, unknown>): void {
  const extra = Object.keys(receipt).filter((k) => !ALL_TOP_LEVEL_FIELDS.has(k));
  if (extra.length) {
    throw new VerificationError(`unknown top-level fields: ${JSON.stringify(extra.sort())}`);
  }
  const missing = [...REQUIRED_FIELDS].filter((k) => !(k in receipt));
  if (missing.length) {
    throw new VerificationError(`missing top-level fields: ${JSON.stringify(missing.sort())}`);
  }

  const stringFields = [
    "version", "receipt_id", "workspace_id", "issued_at", "decision", "reason",
    "user_id", "agent_id", "engine_version",
  ];
  for (const f of stringFields) {
    if (typeof receipt[f] !== "string") {
      throw new VerificationError(`${f} must be a string`);
    }
  }
  for (const f of ["resource", "authorization_id"]) {
    const v = receipt[f];
    if (v !== null && typeof v !== "string") {
      throw new VerificationError(`${f} must be string or null`);
    }
  }

  if (
    typeof receipt.context !== "object" ||
    receipt.context === null ||
    Array.isArray(receipt.context)
  ) {
    throw new VerificationError("context must be an object");
  }

  for (const f of ["alg", "key_id", "signature"]) {
    if (typeof receipt[f] !== "string") {
      throw new VerificationError(`${f} must be a string`);
    }
  }
  const sigValue = receipt.signature as string;

  // Signature text must be canonical base64url and decode to exactly 64 bytes.
  // This rejects placeholder strings ("pending", empty, anything malformed)
  // before the verification path even starts.
  let sigBytes: Uint8Array;
  try {
    sigBytes = b64urlDecode(sigValue);
  } catch {
    throw new VerificationError(`signature is not valid canonical base64url: ${JSON.stringify(sigValue)}`);
  }
  if (sigBytes.length !== 64) {
    throw new VerificationError(
      `signature must decode to 64 bytes (Ed25519), got ${sigBytes.length}`,
    );
  }

  if ("policy_eval" in receipt) {
    checkPolicyEval(receipt.policy_eval);
  }
}

function isPolicyScalar(value: unknown): boolean {
  return (
    value === null ||
    typeof value === "string" ||
    typeof value === "boolean" ||
    (typeof value === "number" && Number.isInteger(value))
  );
}

function isPolicyConditionValue(value: unknown): boolean {
  if (isPolicyScalar(value)) {
    return true;
  }
  return Array.isArray(value) && value.every((item) => isPolicyScalar(item));
}

function checkExactKeys(
  obj: Record<string, unknown>,
  expected: string[],
  prefix: string,
): void {
  const expectedSet = new Set(expected);
  const extra = Object.keys(obj).filter((key) => !expectedSet.has(key));
  const missing = expected.filter((key) => !(key in obj));
  if (extra.length) {
    throw new VerificationError(`${prefix} has unknown fields: ${JSON.stringify(extra.sort())}`);
  }
  if (missing.length) {
    throw new VerificationError(`${prefix} missing fields: ${JSON.stringify(missing.sort())}`);
  }
}

function checkPolicyEval(value: unknown): void {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new VerificationError("policy_eval must be an object");
  }
  const policyEval = value as Record<string, unknown>;
  checkExactKeys(policyEval, ["matched_condition", "field_value"], "policy_eval");

  const matched = policyEval.matched_condition;
  if (matched !== null) {
    if (typeof matched !== "object" || Array.isArray(matched)) {
      throw new VerificationError("policy_eval.matched_condition must be an object or null");
    }
    const condition = matched as Record<string, unknown>;
    checkExactKeys(condition, ["field", "op", "value"], "policy_eval.matched_condition");
    if (typeof condition.field !== "string") {
      throw new VerificationError("policy_eval.matched_condition.field must be a string");
    }
    if (typeof condition.op !== "string") {
      throw new VerificationError("policy_eval.matched_condition.op must be a string");
    }
    if (!isPolicyConditionValue(condition.value)) {
      throw new VerificationError(
        "policy_eval.matched_condition.value must be string, integer, boolean, null, or an array of those",
      );
    }
  }

  if (!isPolicyScalar(policyEval.field_value)) {
    throw new VerificationError("policy_eval.field_value must be string, integer, boolean, or null");
  }
}

const RFC3339_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;
// Receipt issued_at is stricter than key-document timestamps: spec §3 requires
// exactly UTC, millisecond precision, Z suffix.
const ISSUED_AT_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

function parseRFC3339(s: string): Date {
  // `new Date(s)` alone accepts timezone-less and date-only strings, parsing
  // them in *local* time — which makes the key-window check machine-dependent.
  // Require a full RFC 3339 instant with an explicit offset (Z or ±HH:MM).
  if (typeof s !== "string" || !RFC3339_RE.test(s)) {
    throw new VerificationError(`not an RFC 3339 timestamp with timezone: ${JSON.stringify(s)}`);
  }
  const d = new Date(s);
  if (isNaN(d.getTime())) {
    throw new VerificationError(`invalid RFC 3339 timestamp: ${s}`);
  }
  // `new Date` silently rolls shape-valid but impossible dates (Feb 30 → Mar 2),
  // so re-check the calendar day from the string's own components.
  const y = Number(s.slice(0, 4)), mo = Number(s.slice(5, 7)), day = Number(s.slice(8, 10));
  const utc = new Date(Date.UTC(y, mo - 1, day));
  if (utc.getUTCFullYear() !== y || utc.getUTCMonth() !== mo - 1 || utc.getUTCDate() !== day) {
    throw new VerificationError(`not a real calendar date/time: ${s}`);
  }
  return d;
}

function findKey(keys: PublicKey[], keyId: string, issuedAt: Date): PublicKey {
  for (const k of keys) {
    if (k.keyId !== keyId) continue;
    if (issuedAt < k.activeFrom) {
      throw new VerificationError(`key ${JSON.stringify(keyId)} not yet active at issued_at`);
    }
    if (k.activeUntil !== null && issuedAt >= k.activeUntil) {
      throw new VerificationError(`key ${JSON.stringify(keyId)} retired before issued_at`);
    }
    return k;
  }
  throw new VerificationError(`no public key found for key_id=${JSON.stringify(keyId)}`);
}

// ---------------------------------------------------------------------------
// Convenience loader
// ---------------------------------------------------------------------------

export interface KeyDocument {
  workspace_id: string;
  keys: Array<{
    key_id: string;
    alg: string;
    public_key: string;
    active_from: string;
    active_until: string | null;
  }>;
}

export function loadKeysFromJson(doc: KeyDocument): PublicKey[] {
  // Throws VerificationError (never a raw TypeError) on a malformed document,
  // and rejects duplicate key ids and duplicate public keys so key lookup is
  // unambiguous and one public key cannot carry conflicting active windows
  // (spec §10.1).
  if (typeof doc !== "object" || doc === null || !Array.isArray((doc as KeyDocument).keys)) {
    throw new VerificationError("keys document must be an object with a 'keys' array");
  }
  const seenIds = new Set<string>();
  const seenPubs = new Set<string>();
  return doc.keys.map((k, i) => {
    if (typeof k !== "object" || k === null) {
      throw new VerificationError(`keys[${i}] must be an object`);
    }
    for (const field of ["key_id", "alg", "public_key", "active_from"] as const) {
      if (typeof k[field] !== "string") {
        throw new VerificationError(`keys[${i}].${field} must be a string`);
      }
    }
    if (seenIds.has(k.key_id)) {
      throw new VerificationError(`duplicate key_id in keys document: ${JSON.stringify(k.key_id)}`);
    }
    if (seenPubs.has(k.public_key)) {
      throw new VerificationError(`duplicate public key in keys document: ${JSON.stringify(k.key_id)}`);
    }
    seenIds.add(k.key_id);
    seenPubs.add(k.public_key);
    const pub = b64urlDecode(k.public_key);
    if (pub.length !== 32) {
      throw new VerificationError(`keys[${i}].public_key must decode to 32 bytes, got ${pub.length}`);
    }
    return {
      keyId: k.key_id,
      alg: "Ed25519" as const,
      publicKeyBytes: pub,
      activeFrom: parseRFC3339(k.active_from),
      activeUntil: k.active_until ? parseRFC3339(k.active_until) : null,
    };
  });
}
