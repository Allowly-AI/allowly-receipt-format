/**
 * Allowly Receipt Verifier (TypeScript reference implementation).
 *
 * Verifies Allowly receipts per receipt-format.md wire version 4.
 *
 * Dependencies: Node.js 20+, RFC 8785 canonicalization, and strict JSON parsing.
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

import { createHash, createHmac, timingSafeEqual, webcrypto } from "node:crypto";
import jcsCanonicalize from "canonicalize";
import { isSafeNumber, parse as parseLosslessJson } from "lossless-json";

const SPEC_VERSION = "4";
const ACTION_DECISIONS = new Set(["allow", "deny", "confirm", "escalate"]);
const EVENT_DECISIONS: Record<string, Set<string>> = {
  "authorization.create": new Set(["authorization_granted"]),
  "authorization.revoke": new Set(["authorization_revoked"]),
  "budget.settle": new Set(["budget_settled"]),
  "escalation.resolve": new Set(["escalation_approved", "escalation_rejected"]),
  "receipt.checkpoint": new Set(["receipt_set_committed"]),
};
const AUTHORIZATION_LIFECYCLE_EVENTS = new Set(["authorization.create", "authorization.revoke"]);
const EVENT_ONLY_DECISIONS = new Set(Object.values(EVENT_DECISIONS).flatMap((decisions) => [...decisions]));
const REQUIRED_FIELDS = new Set([
  "schema_version", "receipt_id", "workspace_id", "issued_at", "decision", "reason",
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

export function publicKeyFingerprint(key: PublicKey): string {
  return "sha256:" + createHash("sha256").update(key.publicKeyBytes).digest("hex");
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
  schema_version: "4";
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
  const snapshot = snapshotJson(payload, "payload");
  const s = stringify(snapshot);
  return new TextEncoder().encode(s);
}

function snapshotJson(value: unknown, label: string, checkCanonicalNumbers = true): unknown {
  // Reject values that structuredClone would silently normalize, then clone
  // once so validation and serialization cannot observe different values.
  validateTree(value, checkCanonicalNumbers);
  let snapshot: unknown;
  try {
    snapshot = structuredClone(value);
  } catch {
    throw new VerificationError(`${label} must be structured-cloneable JSON data`);
  }
  validateTree(snapshot, checkCanonicalNumbers);
  return snapshot;
}

async function sha256(...parts: Uint8Array[]): Promise<Uint8Array> {
  const length = parts.reduce((total, part) => total + part.length, 0);
  const input = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    input.set(part, offset);
    offset += part.length;
  }
  return new Uint8Array(await webcrypto.subtle.digest("SHA-256", input));
}

function compareBytes(left: Uint8Array, right: Uint8Array): number {
  for (let i = 0; i < left.length; i++) {
    if (left[i] !== right[i]) return left[i] - right[i];
  }
  return left.length - right.length;
}

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export async function checkpointMerkleRoot(receipts: Array<Record<string, unknown>>): Promise<string> {
  const seenIds = new Set<string>();
  let level = await Promise.all(receipts.map(async (receipt) => {
    if (typeof receipt !== "object" || receipt === null || typeof receipt.receipt_id !== "string") {
      throw new VerificationError("checkpoint member must be a receipt object with receipt_id");
    }
    if (seenIds.has(receipt.receipt_id)) {
      throw new VerificationError(`duplicate checkpoint member receipt_id: ${JSON.stringify(receipt.receipt_id)}`);
    }
    seenIds.add(receipt.receipt_id);
    return sha256(new Uint8Array([0x00]), canonicalize(receipt));
  }));
  level.sort(compareBytes);
  if (level.length === 0) {
    return "sha256:" + hex(await sha256(new Uint8Array([0x02])));
  }
  while (level.length > 1) {
    if (level.length % 2 === 1) level.push(level[level.length - 1]);
    const next: Uint8Array[] = [];
    for (let i = 0; i < level.length; i += 2) {
      next.push(await sha256(new Uint8Array([0x01]), level[i], level[i + 1]));
    }
    level = next;
  }
  return "sha256:" + hex(level[0]);
}

function validateTree(payload: unknown, checkCanonicalNumbers = true): void {
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
      if (checkCanonicalNumbers && !Number.isInteger(value)) {
        throw new VerificationError("receipts must not contain non-integer numbers");
      }
      // Integers outside the I-JSON safe range (±(2^53-1)) lose precision in
      // doubles and would render with an exponent (e.g. "1e+21"), violating
      // §4.2 rule 6. Number.isSafeInteger excludes them.
      if (checkCanonicalNumbers && !Number.isSafeInteger(value)) {
        throw new VerificationError(
          "integer exceeds the safe range ±(2^53-1); receipts must not carry integers that lose precision in IEEE-754 doubles",
        );
      }
    } else if (typeof value === "string") {
      if (!value.isWellFormed()) {
        throw new VerificationError("string contains an unpaired Unicode surrogate");
      }
    } else if (Array.isArray(value)) {
      const keys = Object.keys(value);
      if (keys.length !== value.length || keys.some((key, index) => key !== String(index))) {
        throw new VerificationError("payload arrays must be dense JSON arrays without extra properties");
      }
      const descriptors = Object.getOwnPropertyDescriptors(value);
      for (const key of keys) {
        const descriptor = descriptors[key];
        if (!("value" in descriptor)) {
          throw new VerificationError("payload must not contain accessor properties");
        }
        stack.push([descriptor.value, depth + 1]);
      }
    } else if (value !== null && typeof value === "object") {
      const prototype = Object.getPrototypeOf(value);
      if (prototype !== Object.prototype && prototype !== null) {
        throw new VerificationError("payload objects must be plain JSON objects");
      }
      for (const [k, descriptor] of Object.entries(Object.getOwnPropertyDescriptors(value))) {
        if (!descriptor.enumerable) continue;
        if (!k.isWellFormed()) {
          throw new VerificationError("string contains an unpaired Unicode surrogate");
        }
        if (!("value" in descriptor)) {
          throw new VerificationError("payload must not contain accessor properties");
        }
        stack.push([descriptor.value, depth + 1]);
      }
    } else if (value !== null && !["boolean", "number", "string"].includes(typeof value)) {
      throw new VerificationError(`unsupported type in payload: ${typeof value}`);
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
  opts: {
    now?: Date;
    expectedWorkspaceId?: string;
    trustedKeyFingerprints?: ReadonlySet<string>;
  } = {},
): Promise<void> {
  if (typeof receipt !== "object" || receipt === null || Array.isArray(receipt)) {
    throw new VerificationError("receipt must be an object");
  }
  const ownReceipt = snapshotJson(receipt, "receipt", false) as Record<string, unknown>;
  if (!Array.isArray(publicKeys)) {
    throw new VerificationError("publicKeys must be an array");
  }
  let keySnapshots: PublicKey[];
  try {
    keySnapshots = structuredClone(publicKeys);
  } catch {
    throw new VerificationError("publicKeys must be structured-cloneable data");
  }
  const now = opts.now ?? new Date();
  let nowMs: number;
  try {
    nowMs = Date.prototype.getTime.call(now);
  } catch {
    throw new VerificationError("now must be a valid Date");
  }
  if (!Number.isFinite(nowMs)) {
    throw new VerificationError("now must be a valid Date");
  }

  // Step 1: version check
  if (ownReceipt.schema_version !== SPEC_VERSION) {
    throw new VerificationError(
      `unsupported schema_version: ${JSON.stringify(ownReceipt.schema_version)} (want "${SPEC_VERSION}")`,
    );
  }

  // Key ids alone do not bind a receipt to a workspace. If the caller passes the
  // workspace the keys were published for, require the receipt to match it.
  if (
    opts.expectedWorkspaceId !== undefined &&
    ownReceipt.workspace_id !== opts.expectedWorkspaceId
  ) {
    throw new VerificationError(
      `workspace_id mismatch: receipt has ${JSON.stringify(ownReceipt.workspace_id)}, ` +
        `expected ${JSON.stringify(opts.expectedWorkspaceId)}`,
    );
  }

  // Step 2: schema check (includes signature shape — rejects placeholders)
  checkSchema(ownReceipt);
  const r = ownReceipt as unknown as Receipt;

  // Step 3: receipt kind and pairing
  const hasAction = Object.hasOwn(ownReceipt, "action");
  const hasEvent = Object.hasOwn(ownReceipt, "event");

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
    const event = ownReceipt.event;
    if (typeof event !== "string") {
      throw new VerificationError("event must be a string");
    }
    if (!Object.hasOwn(EVENT_DECISIONS, event)) {
      throw new VerificationError(
        `event must be one of ["authorization.create","authorization.revoke","budget.settle","escalation.resolve","receipt.checkpoint"], got ${JSON.stringify(event)}`,
      );
    }
    const expectedDecisions = EVENT_DECISIONS[event];
    if (!expectedDecisions.has(r.decision)) {
      throw new VerificationError(
        `event receipt with event=${JSON.stringify(event)} must have ` +
          `decision in ${JSON.stringify([...expectedDecisions].sort())}, got ${JSON.stringify(r.decision)}`,
      );
    }
    if (event === "receipt.checkpoint") {
      if (r.authorization_id !== null) {
        throw new VerificationError("receipt.checkpoint must have null authorization_id");
      }
      if (r.resource !== null) {
        throw new VerificationError("receipt.checkpoint must have null resource");
      }
      checkCheckpointContext(r.context, r.issued_at);
    } else if (r.authorization_id === null) {
      throw new VerificationError(
        `event receipt with event=${JSON.stringify(event)} must have non-null authorization_id`,
      );
    }
    if (AUTHORIZATION_LIFECYCLE_EVENTS.has(event) && r.resource !== null) {
      throw new VerificationError(
        `authorization lifecycle receipt with event=${JSON.stringify(event)} must have null resource`,
      );
    }
    if (Object.hasOwn(ownReceipt, "policy_eval")) {
      throw new VerificationError("policy_eval must be absent on event receipts");
    }
  } else {
    const action = ownReceipt.action;
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
  if (issuedAt.getTime() > nowMs + MAX_FUTURE_SKEW_MS) {
    throw new VerificationError(
      `receipt issued in the future: ${issuedAt.toISOString()} > ${new Date(nowMs).toISOString()}`,
    );
  }

  // Step 6: canonicalize
  const { signature, ...payload } = r;
  const canonical = canonicalize(payload);

  // Step 7: signature verification
  const key = findKey(keySnapshots, r.key_id, issuedAt);
  const fingerprint = publicKeyFingerprint(key);
  if (
    opts.trustedKeyFingerprints !== undefined &&
    !opts.trustedKeyFingerprints.has(fingerprint)
  ) {
    throw new VerificationError(
      `public key fingerprint is not trusted: ${fingerprint}`,
    );
  }
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

// ---------------------------------------------------------------------------
// Allowly conditional policy evaluation profile
// ---------------------------------------------------------------------------

export const POLICY_EVALUATION_PROFILE = "allowly-conditional-evaluation-v1";
export const POLICY_EVALUATION_ENGINE_VERSION = "2026-09-27.1";
export const POLICY_EVALUATION_ENGINE_VERSIONS = [
  "2026-09-16.1",
  "2026-09-24.1",
  POLICY_EVALUATION_ENGINE_VERSION,
] as const;

export type PolicyEvaluationStatus = "matched" | "mismatch" | "not_checked";

export interface PolicyEvaluationResult {
  profile: typeof POLICY_EVALUATION_PROFILE;
  engine_version: string;
  receipt_id: string;
  authorization_receipt_id: string | null;
  status: PolicyEvaluationStatus;
  diagnostic: string;
  recorded_evaluation: Record<string, unknown> | null;
  calculated_evaluation: Record<string, unknown> | null;
}

interface NormalizedPolicyCondition {
  field: string;
  op: string;
  value: unknown;
}

interface PolicyConditionResult {
  kind: "deny" | "escalate" | "confirm" | "none";
  reason:
    | "deny_condition_matched"
    | "escalate_condition_matched"
    | "confirm_condition_matched"
    | "context_field_missing"
    | "policy_conditions_not_matched";
  policyEval: Record<string, unknown>;
}

const POLICY_CONDITION_KEYS = ["deny_when", "escalate_when", "confirm_when"] as const;
const POLICY_OPERATORS = new Set([
  "eq", "neq", "lt", "lte", "gt", "gte", "in", "nin",
  "contains_any", "contains_none", "empty", "exists",
]);
const MAX_POLICY_CONDITIONS = 10;
const BASE_REPLAY_CONTEXT_EXCLUSIONS = ["budget", "escalation", "session_id"] as const;
const CURRENT_REPLAY_CONTEXT_EXCLUSIONS = [
  ...BASE_REPLAY_CONTEXT_EXCLUSIONS,
  "client_timestamp",
  "client_timestamp_source",
  "execution",
  "identity_verification",
] as const;
const PUBLIC_KEY_FINGERPRINT_RE = /^sha256:[0-9a-f]{64}$/;

class UnsupportedPolicyError extends Error {}

/**
 * Authenticate an action receipt and supplied authorization evidence, then
 * repeat only its conditional policy calculation. This does not reproduce the
 * final allow/deny/confirm/escalate decision, which can depend on runtime state.
 */
export async function verifyPolicyEvaluation(
  receipt: Record<string, unknown>,
  authorizationReceipts: Record<string, unknown>[],
  publicKeys: PublicKey[],
  opts: {
    expectedWorkspaceId: string;
    trustedKeyFingerprints: ReadonlySet<string>;
    now?: Date;
  },
): Promise<PolicyEvaluationResult> {
  // Snapshot every caller-controlled input before the first await. In
  // particular, do not authenticate one object and later evaluate a mutated
  // version of it.
  if (typeof receipt !== "object" || receipt === null || Array.isArray(receipt)) {
    throw new VerificationError("receipt must be an object");
  }
  const ownReceipt = snapshotJson(receipt, "receipt", false) as Record<string, unknown>;
  if (!Array.isArray(authorizationReceipts)) {
    throw new VerificationError("authorizationReceipts must be an array");
  }
  const ownAuthorizationReceipts = snapshotJson(
    authorizationReceipts,
    "authorizationReceipts",
    false,
  ) as Record<string, unknown>[];
  if (!Array.isArray(publicKeys)) {
    throw new VerificationError("publicKeys must be an array");
  }
  let ownPublicKeys: PublicKey[];
  try {
    ownPublicKeys = structuredClone(publicKeys);
  } catch {
    throw new VerificationError("publicKeys must be structured-cloneable data");
  }
  if (
    typeof SharedArrayBuffer !== "undefined"
    && ownPublicKeys.some((key) => key?.publicKeyBytes?.buffer instanceof SharedArrayBuffer)
  ) {
    throw new VerificationError("publicKeyBytes must not use SharedArrayBuffer");
  }
  if (
    typeof opts !== "object"
    || opts === null
    || typeof opts.expectedWorkspaceId !== "string"
    || opts.expectedWorkspaceId.length === 0
  ) {
    throw new VerificationError("expectedWorkspaceId must be a non-empty string");
  }
  if (
    opts.trustedKeyFingerprints === null
    || typeof opts.trustedKeyFingerprints !== "object"
    || typeof opts.trustedKeyFingerprints.has !== "function"
    || typeof opts.trustedKeyFingerprints.size !== "number"
  ) {
    throw new VerificationError("trustedKeyFingerprints must be a non-empty set");
  }
  let trustedKeyFingerprints: Set<string>;
  try {
    trustedKeyFingerprints = new Set(opts.trustedKeyFingerprints);
  } catch {
    throw new VerificationError("trustedKeyFingerprints must be a non-empty set");
  }
  if (
    trustedKeyFingerprints.size === 0
    || [...trustedKeyFingerprints].some(
      (fingerprint) => typeof fingerprint !== "string" || !PUBLIC_KEY_FINGERPRINT_RE.test(fingerprint),
    )
  ) {
    throw new VerificationError(
      "trustedKeyFingerprints must contain at least one sha256:<64 lowercase hex> fingerprint",
    );
  }
  let ownNow = opts.now;
  if (ownNow !== undefined) {
    try {
      ownNow = new Date(Date.prototype.getTime.call(ownNow));
    } catch {
      throw new VerificationError("now must be a valid Date");
    }
  }
  const receiptOptions = {
    now: ownNow,
    expectedWorkspaceId: opts.expectedWorkspaceId,
    trustedKeyFingerprints,
  };

  await verifyReceipt(ownReceipt, ownPublicKeys, receiptOptions);
  for (const authorizationReceipt of ownAuthorizationReceipts) {
    await verifyReceipt(authorizationReceipt, ownPublicKeys, receiptOptions);
  }
  if (!Object.hasOwn(ownReceipt, "action")) {
    throw new VerificationError("policy evaluation requires an action receipt");
  }

  const engineVersion = ownReceipt.engine_version as string;
  const receiptId = ownReceipt.receipt_id as string;
  const recordedEvaluation = Object.hasOwn(ownReceipt, "policy_eval")
    ? ownReceipt.policy_eval as Record<string, unknown>
    : null;
  const result = (
    authorizationReceiptId: string | null,
    status: PolicyEvaluationStatus,
    diagnostic: string,
    calculatedEvaluation: Record<string, unknown> | null = null,
  ): PolicyEvaluationResult => ({
    profile: POLICY_EVALUATION_PROFILE,
    engine_version: engineVersion,
    receipt_id: receiptId,
    authorization_receipt_id: authorizationReceiptId,
    status,
    diagnostic,
    recorded_evaluation: recordedEvaluation,
    calculated_evaluation: calculatedEvaluation,
  });

  if (recordedEvaluation === null) {
    return result(null, "not_checked", "policy_evaluation_not_recorded");
  }
  if (!(POLICY_EVALUATION_ENGINE_VERSIONS as readonly string[]).includes(engineVersion)) {
    return result(null, "not_checked", "unsupported_engine_version");
  }

  const authorizationId = ownReceipt.authorization_id;
  if (typeof authorizationId !== "string" || authorizationId.length === 0) {
    return result(null, "not_checked", "authorization_receipt_not_found");
  }
  const matchingReceipts = ownAuthorizationReceipts.filter(
    (candidate) => candidate.event === "authorization.create"
      && candidate.authorization_id === authorizationId
      && candidate.workspace_id === ownReceipt.workspace_id,
  );
  const distinctMatchingReceipts = new Map<string, Record<string, unknown>>();
  for (const candidate of matchingReceipts) {
    distinctMatchingReceipts.set(new TextDecoder().decode(canonicalize(candidate)), candidate);
  }
  if (distinctMatchingReceipts.size === 0) {
    return result(null, "not_checked", "authorization_receipt_not_found");
  }
  if (distinctMatchingReceipts.size > 1) {
    return result(null, "not_checked", "conflicting_authorization_receipts");
  }

  const authorizationReceipt = distinctMatchingReceipts.values().next().value!;
  const authorizationReceiptId = authorizationReceipt.receipt_id as string;
  if (
    !(POLICY_EVALUATION_ENGINE_VERSIONS as readonly string[]).includes(
      authorizationReceipt.engine_version as string,
    )
    || parseRFC3339(authorizationReceipt.issued_at as string) > parseRFC3339(ownReceipt.issued_at as string)
  ) {
    return result(
      authorizationReceiptId,
      "not_checked",
      "unsupported_authorization_snapshot",
    );
  }
  if (
    authorizationReceipt.user_id !== ownReceipt.user_id
    || authorizationReceipt.agent_id !== ownReceipt.agent_id
  ) {
    return result(authorizationReceiptId, "not_checked", "authorization_subject_mismatch");
  }

  const snapshot = policyConstraintsFromAuthorization(
    authorizationReceipt,
    ownReceipt.action as string,
  );
  if (snapshot.diagnostic !== null) {
    return result(authorizationReceiptId, "not_checked", snapshot.diagnostic);
  }

  const replayContext = {
    ...(ownReceipt.context as Record<string, unknown>),
  };
  const replayContextExclusions = engineVersion !== "2026-09-16.1"
    ? CURRENT_REPLAY_CONTEXT_EXCLUSIONS
    : BASE_REPLAY_CONTEXT_EXCLUSIONS;
  for (const key of replayContextExclusions) delete replayContext[key];

  let calculatedEvaluation: Record<string, unknown> | null;
  try {
    calculatedEvaluation = evaluatePolicyConditions(snapshot.constraints!, replayContext)?.policyEval ?? null;
  } catch (error) {
    if (error instanceof UnsupportedPolicyError) {
      return result(authorizationReceiptId, "not_checked", "unsupported_policy");
    }
    throw error;
  }
  const status = policyEvaluationsEqual(recordedEvaluation, calculatedEvaluation)
    ? "matched"
    : "mismatch";
  return result(
    authorizationReceiptId,
    status,
    status === "matched" ? "matched" : "policy_evaluation_mismatch",
    calculatedEvaluation,
  );
}

function policyConstraintsFromAuthorization(
  authorizationReceipt: Record<string, unknown>,
  action: string,
): {
  constraints: Record<string, unknown> | null;
  diagnostic:
    | "unsupported_authorization_snapshot"
    | "authorization_action_not_found"
    | "authorization_action_ambiguous"
    | null;
} {
  const context = authorizationReceipt.context;
  if (!isPlainJsonObject(context)) {
    return { constraints: null, diagnostic: "unsupported_authorization_snapshot" };
  }
  const actions = context.actions;
  if (!Array.isArray(actions) || actions.length === 0) {
    return { constraints: null, diagnostic: "unsupported_authorization_snapshot" };
  }
  const parsedActions: Array<{ name: string; constraints: Record<string, unknown> }> = [];
  for (const entry of actions) {
    if (!isPlainJsonObject(entry) || !supportedActionShape(entry, authorizationReceipt.engine_version)) {
      return { constraints: null, diagnostic: "unsupported_authorization_snapshot" };
    }
    if (
      typeof entry.name !== "string"
      || entry.name.length === 0
      || !isPlainJsonObject(entry.constraints)
    ) {
      return { constraints: null, diagnostic: "unsupported_authorization_snapshot" };
    }
    parsedActions.push({
      name: entry.name,
      constraints: entry.constraints as Record<string, unknown>,
    });
  }
  const matchingActions = parsedActions.filter((entry) => entry.name === action);
  if (matchingActions.length === 0) {
    return { constraints: null, diagnostic: "authorization_action_not_found" };
  }
  if (matchingActions.length > 1) {
    return { constraints: null, diagnostic: "authorization_action_ambiguous" };
  }
  const unrelatedNames = parsedActions
    .filter((entry) => entry.name !== action)
    .map((entry) => entry.name);
  if (new Set(unrelatedNames).size !== unrelatedNames.length) {
    return { constraints: null, diagnostic: "unsupported_authorization_snapshot" };
  }
  return { constraints: matchingActions[0].constraints, diagnostic: null };
}

function supportedActionShape(entry: Record<string, unknown>, engine: unknown): boolean {
  if (hasExactKeys(entry, ["name", "constraints"])) return true;
  if (engine !== POLICY_EVALUATION_ENGINE_VERSION
      || !hasExactKeys(entry, ["name", "constraints", "executable_operations"])) return false;
  const grants = entry.executable_operations;
  const fields = ["enabled_executable_id", "provider_id", "operation_id", "catalog_revision", "definition_fingerprint", "minimum_evidence_mode"];
  return Array.isArray(grants) && grants.length <= 100 && grants.every((grant) =>
    isPlainJsonObject(grant) && hasExactKeys(grant, fields)
    && Object.values(grant).every((value) => typeof value === "string" && value.length > 0)
    && PUBLIC_KEY_FINGERPRINT_RE.test(grant.definition_fingerprint as string)
    && ["receipt", "witnessed"].includes(grant.minimum_evidence_mode as string));
}

function evaluatePolicyConditions(
  constraints: Record<string, unknown>,
  context: Record<string, unknown>,
): PolicyConditionResult | null {
  validatePolicyConditions(constraints);
  const denyResult = evaluateConditionList(
    "deny",
    "deny_condition_matched",
    constraints.deny_when,
    context,
    "confirm",
  );
  if (denyResult !== null && denyResult.reason === "deny_condition_matched") {
    return denyResult;
  }
  const denyMissingFallback = denyResult;

  const escalateResult = evaluateConditionList(
    "escalate",
    "escalate_condition_matched",
    constraints.escalate_when,
    context,
  );
  if (escalateResult !== null) return escalateResult;

  const confirmResult = evaluateConditionList(
    "confirm",
    "confirm_condition_matched",
    constraints.confirm_when,
    context,
  );
  if (confirmResult !== null) return confirmResult;
  if (denyMissingFallback !== null) return denyMissingFallback;

  if (hasPolicyConditions(constraints)) {
    return {
      kind: "none",
      reason: "policy_conditions_not_matched",
      policyEval: { matched_condition: null, field_value: null },
    };
  }
  return null;
}

function evaluateConditionList(
  kind: "deny" | "escalate" | "confirm",
  reason:
    | "deny_condition_matched"
    | "escalate_condition_matched"
    | "confirm_condition_matched",
  value: unknown,
  context: Record<string, unknown>,
  missingKind?: "confirm",
): PolicyConditionResult | null {
  if (!Array.isArray(value)) return null;
  let missingResult: PolicyConditionResult | null = null;
  for (const rawCondition of value) {
    const condition = normalizePolicyCondition(rawCondition);
    const present = Object.hasOwn(context, condition.field);
    const actual = context[condition.field];
    const policyEval = {
      matched_condition: {
        field: condition.field,
        op: condition.op,
        value: condition.value,
      },
      field_value: policyEvaluationFieldValue(
        condition.op,
        actual,
        condition.value,
        present,
      ),
    };
    if (condition.op === "exists") {
      if (present === condition.value) return { kind, reason, policyEval };
      continue;
    }
    const matched = present
      ? policyConditionMatches(condition.op, actual, condition.value)
      : null;
    if (matched === null) {
      const result: PolicyConditionResult = {
        kind: missingKind ?? kind,
        reason: "context_field_missing",
        policyEval,
      };
      if (missingKind === undefined) return result;
      missingResult ??= result;
      continue;
    }
    if (matched) return { kind, reason, policyEval };
  }
  return missingResult;
}

function validatePolicyConditions(constraints: Record<string, unknown>): void {
  let total = 0;
  for (const key of POLICY_CONDITION_KEYS) {
    const value = constraints[key];
    if (value === undefined || value === null) continue;
    if (!Array.isArray(value)) throw new UnsupportedPolicyError();
    total += value.length;
    if (total > MAX_POLICY_CONDITIONS) throw new UnsupportedPolicyError();
    for (const condition of value) normalizePolicyCondition(condition);
  }
}

function normalizePolicyCondition(value: unknown): NormalizedPolicyCondition {
  if (!isPlainJsonObject(value)) throw new UnsupportedPolicyError();
  const field = value.field;
  if (typeof field !== "string" || field.length === 0) throw new UnsupportedPolicyError();
  const keys = Object.keys(value);
  const operatorKeys = keys.filter((key) => POLICY_OPERATORS.has(key));
  if (
    keys.length !== 2
    || operatorKeys.length !== 1
    || keys.some((key) => key !== "field" && !POLICY_OPERATORS.has(key))
  ) {
    throw new UnsupportedPolicyError();
  }
  const op = operatorKeys[0];
  const expected = value[op];
  if (op === "exists" || op === "empty") {
    if (typeof expected !== "boolean") throw new UnsupportedPolicyError();
  } else if (["in", "nin", "contains_any", "contains_none"].includes(op)) {
    if (
      !Array.isArray(expected)
      || expected.length === 0
      || expected.some((item) => !isStrictPolicyScalar(item))
    ) {
      throw new UnsupportedPolicyError();
    }
  } else if (["lt", "lte", "gt", "gte"].includes(op)) {
    if (!isStrictPolicyInteger(expected)) throw new UnsupportedPolicyError();
  } else if (!isStrictPolicyScalar(expected)) {
    throw new UnsupportedPolicyError();
  }
  return { field, op, value: expected };
}

function policyConditionMatches(op: string, actual: unknown, expected: unknown): boolean | null {
  if (op === "eq" || op === "neq") {
    if (!samePolicyScalarType(actual, expected)) return null;
    return op === "eq" ? actual === expected : actual !== expected;
  }
  if (["lt", "lte", "gt", "gte"].includes(op)) {
    if (!isStrictPolicyInteger(actual) || !isStrictPolicyInteger(expected)) return null;
    if (op === "lt") return actual < expected;
    if (op === "lte") return actual <= expected;
    if (op === "gt") return actual > expected;
    return actual >= expected;
  }
  if (op === "in" || op === "nin") {
    if (!Array.isArray(expected)) return null;
    const comparable = expected.filter((item) => samePolicyScalarType(actual, item));
    if (comparable.length === 0) return null;
    const included = comparable.some((item) => item === actual);
    return op === "in" ? included : !included;
  }
  if (op === "contains_any" || op === "contains_none") {
    if (
      !Array.isArray(actual)
      || !Array.isArray(expected)
      || actual.some((item) => !isStrictPolicyScalar(item))
      || expected.some((item) => !isStrictPolicyScalar(item))
    ) {
      return null;
    }
    const expectedKeys = new Set(expected.map(typedPolicyScalarKey));
    const intersects = actual.some((item) => expectedKeys.has(typedPolicyScalarKey(item)));
    return op === "contains_any" ? intersects : !intersects;
  }
  if (op === "empty") {
    if (!Array.isArray(actual) || typeof expected !== "boolean") return null;
    return (actual.length === 0) === expected;
  }
  return false;
}

function policyEvaluationFieldValue(
  op: string,
  actual: unknown,
  expected: unknown,
  present: boolean,
): unknown {
  if (!present) return null;
  if (op === "contains_any" && Array.isArray(actual) && Array.isArray(expected)) {
    const expectedKeys = new Set(
      expected.filter(isStrictPolicyScalar).map(typedPolicyScalarKey),
    );
    for (const item of actual) {
      if (isStrictPolicyScalar(item) && expectedKeys.has(typedPolicyScalarKey(item))) {
        return item;
      }
    }
    return null;
  }
  if (op === "contains_none" || op === "empty") return null;
  return isStrictPolicyScalar(actual) ? actual : null;
}

function hasPolicyConditions(constraints: Record<string, unknown>): boolean {
  return POLICY_CONDITION_KEYS.some(
    (key) => Array.isArray(constraints[key]) && (constraints[key] as unknown[]).length > 0,
  );
}

function isStrictPolicyInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value);
}

function isStrictPolicyScalar(value: unknown): value is string | number | boolean | null {
  return value === null
    || typeof value === "string"
    || typeof value === "boolean"
    || isStrictPolicyInteger(value);
}

function samePolicyScalarType(left: unknown, right: unknown): boolean {
  if (!isStrictPolicyScalar(left) || !isStrictPolicyScalar(right)) return false;
  if (left === null || right === null) return left === null && right === null;
  return typeof left === typeof right;
}

function typedPolicyScalarKey(value: string | number | boolean | null): string {
  if (value === null) return "null:";
  if (typeof value === "string") return `string:${JSON.stringify(value)}`;
  if (typeof value === "boolean") return `boolean:${value ? "true" : "false"}`;
  return `integer:${String(value)}`;
}

function isPlainJsonObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasExactKeys(value: Record<string, unknown>, expected: string[]): boolean {
  const keys = Object.keys(value);
  return keys.length === expected.length && expected.every((key) => Object.hasOwn(value, key));
}

function policyEvaluationsEqual(
  recorded: Record<string, unknown>,
  calculated: Record<string, unknown> | null,
): boolean {
  if (calculated === null) return false;
  const left = canonicalize(recorded);
  const right = canonicalize(calculated);
  return left.length === right.length && left.every((byte, index) => byte === right[index]);
}

// ---------------------------------------------------------------------------
// SEAL profile (RFC 8785 / JCS record hashing)
// ---------------------------------------------------------------------------

export const SEAL_PROFILE = "allowly.seal.jcs-sha256.v1";
export const SEAL_ACTION = "record.seal";
export const SEAL_AGENT_ID = "allowly.seal";
export const SEAL_USER_ID = "allowly:seal";
export const SEAL_MAX_UTF8_BYTES = 1_048_576;
export const SEAL_MAX_DEPTH = 32;

export type SealInputFailure =
  | "invalid_type"
  | "invalid_utf8"
  | "size_limit"
  | "depth_limit"
  | "invalid_json"
  | "duplicate_key"
  | "invalid_unicode"
  | "number_overflow"
  | "number_underflow"
  | "unsafe_integer"
  | "number_precision"
  | "unsupported_value"
  | "canonicalization_failed";

export class SealInputError extends Error {
  constructor(
    readonly code: SealInputFailure,
    message: string,
  ) {
    super(message);
    this.name = "SealInputError";
  }
}

export type SealVerificationFailure =
  | "receipt_verification_failed"
  | "not_seal_receipt"
  | "seal_identity_mismatch"
  | "seal_profile_mismatch"
  | "invalid_record_digest"
  | "invalid_record"
  | "record_mismatch";

export interface SealVerificationResult {
  signatureVerified: boolean;
  recordMatches: boolean;
  failureReason: SealVerificationFailure | null;
}

export function hashSealJson(rawJson: string | Uint8Array): string {
  const { bytes, text } = decodeRawSealJson(rawJson);
  if (bytes.byteLength > SEAL_MAX_UTF8_BYTES) {
    throw new SealInputError(
      "size_limit",
      `record exceeds the ${SEAL_MAX_UTF8_BYTES}-byte SEAL limit`,
    );
  }
  checkRawSealDepth(text);

  let record: unknown;
  try {
    // lossless-json assigns object members through ordinary property writes,
    // so a decoded "__proto__" key would mutate its temporary object's
    // prototype instead of remaining data. Prefix every decoded object key in
    // the validation copy: the mapping is injective, duplicate detection is
    // preserved, and no customer key can invoke that legacy setter. Native
    // JSON.parse then builds the actual value with "__proto__" as an own data
    // property, as required by JSON semantics.
    parseLosslessJson(namespaceObjectKeysForValidation(text), undefined, {
      parseNumber: parseSealNumber,
    });
    record = JSON.parse(text);
  } catch (error) {
    if (error instanceof SealInputError) throw error;
    throw new SealInputError("invalid_json", "record must be valid JSON");
  }
  return hashSealSnapshot(record);
}

function namespaceObjectKeysForValidation(text: string): string {
  const chunks: string[] = [];
  const objectKeys: Set<string>[] = [];
  let chunkStart = 0;
  let index = 0;
  while (index < text.length) {
    if (text[index] !== '"') {
      if (text[index] === "{") objectKeys.push(new Set());
      else if (text[index] === "}") objectKeys.pop();
      index += 1;
      continue;
    }
    const tokenStart = index;
    index += 1;
    let escaped = false;
    while (index < text.length) {
      const char = text[index];
      if (escaped) escaped = false;
      else if (char === "\\") escaped = true;
      else if (char === '"') break;
      index += 1;
    }
    if (index >= text.length) break;
    const tokenEnd = index + 1;
    let next = tokenEnd;
    while (next < text.length && /\s/u.test(text[next])) next += 1;
    if (text[next] === ":") {
      try {
        const key = JSON.parse(text.slice(tokenStart, tokenEnd));
        const keys = objectKeys.at(-1);
        // lossless-json permits repeated keys when their values are equal.
        if (keys?.has(key)) {
          throw new SealInputError("duplicate_key", `duplicate decoded object key: ${JSON.stringify(key)}`);
        }
        keys?.add(key);
        chunks.push(text.slice(chunkStart, tokenStart), JSON.stringify(`\0${key}`));
        chunkStart = tokenEnd;
      } catch (error) {
        if (error instanceof SealInputError) throw error;
        // The strict parser below reports malformed string tokens uniformly.
      }
    }
    index = tokenEnd;
  }
  if (chunks.length === 0) return text;
  chunks.push(text.slice(chunkStart));
  return chunks.join("");
}

/**
 * Hash an already-parsed value. Parsing has already erased duplicate object
 * names and original number-token spellings; prefer hashSealJson for raw input.
 */
export function hashSealValue(record: unknown): string {
  return hashSealSnapshot(record);
}

export async function verifySealJson(
  rawJson: string | Uint8Array,
  receipt: Record<string, unknown>,
  publicKeys: PublicKey[],
  opts: {
    expectedWorkspaceId: string;
    trustedKeyFingerprints?: ReadonlySet<string>;
    now?: Date;
  },
): Promise<SealVerificationResult> {
  return verifySeal(
    () => hashSealJson(rawJson),
    receipt,
    publicKeys,
    opts,
  );
}

/** Verify a SEAL against a parsed value, subject to the parsed-value boundary. */
export async function verifySealValue(
  record: unknown,
  receipt: Record<string, unknown>,
  publicKeys: PublicKey[],
  opts: {
    expectedWorkspaceId: string;
    trustedKeyFingerprints?: ReadonlySet<string>;
    now?: Date;
  },
): Promise<SealVerificationResult> {
  return verifySeal(
    () => hashSealValue(record),
    receipt,
    publicKeys,
    opts,
  );
}

async function verifySeal(
  recordDigest: () => string,
  receipt: Record<string, unknown>,
  publicKeys: PublicKey[],
  opts: {
    expectedWorkspaceId: string;
    trustedKeyFingerprints?: ReadonlySet<string>;
    now?: Date;
  },
): Promise<SealVerificationResult> {
  if (
    !opts
    || typeof opts.expectedWorkspaceId !== "string"
    || opts.expectedWorkspaceId.length === 0
  ) {
    return sealResult(false, false, "receipt_verification_failed");
  }
  let ownReceipt: Record<string, unknown>;
  try {
    ownReceipt = snapshotJson(receipt, "receipt", false) as Record<string, unknown>;
    await verifyReceipt(ownReceipt, publicKeys, opts);
  } catch (error) {
    if (error instanceof VerificationError) {
      return sealResult(false, false, "receipt_verification_failed");
    }
    throw error;
  }

  if (ownReceipt.action !== SEAL_ACTION || ownReceipt.decision !== "allow") {
    return sealResult(true, false, "not_seal_receipt");
  }
  if (ownReceipt.agent_id !== SEAL_AGENT_ID || ownReceipt.user_id !== SEAL_USER_ID) {
    return sealResult(true, false, "seal_identity_mismatch");
  }
  const context = ownReceipt.context as Record<string, unknown>;
  if (context.seal_profile !== SEAL_PROFILE) {
    return sealResult(true, false, "seal_profile_mismatch");
  }
  const expectedDigest = context.record_sha256;
  if (typeof expectedDigest !== "string" || !/^[0-9a-f]{64}$/.test(expectedDigest)) {
    return sealResult(true, false, "invalid_record_digest");
  }

  let actualDigest: string;
  try {
    actualDigest = recordDigest();
  } catch (error) {
    if (error instanceof SealInputError) return sealResult(true, false, "invalid_record");
    throw error;
  }
  const matches = timingSafeEqual(Buffer.from(actualDigest, "hex"), Buffer.from(expectedDigest, "hex"));
  return matches
    ? sealResult(true, true, null)
    : sealResult(true, false, "record_mismatch");
}

function sealResult(
  signatureVerified: boolean,
  recordMatches: boolean,
  failureReason: SealVerificationFailure | null,
): SealVerificationResult {
  return { signatureVerified, recordMatches, failureReason };
}

function decodeRawSealJson(rawJson: string | Uint8Array): { bytes: Uint8Array; text: string } {
  if (typeof rawJson === "string") {
    if (!rawJson.isWellFormed()) {
      throw new SealInputError("invalid_unicode", "record contains an unpaired Unicode surrogate");
    }
    return { bytes: new TextEncoder().encode(rawJson), text: rawJson };
  }
  if (!(rawJson instanceof Uint8Array)) {
    throw new SealInputError("invalid_type", "rawJson must be a string or Uint8Array");
  }
  const bytes = new Uint8Array(rawJson);
  try {
    return { bytes, text: new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes) };
  } catch (error) {
    throw new SealInputError("invalid_utf8", "record must be well-formed UTF-8");
  }
}

function checkRawSealDepth(text: string): void {
  let depth = 0;
  let inString = false;
  let escaped = false;
  for (const char of text) {
    if (inString) {
      if (escaped) escaped = false;
      else if (char === "\\") escaped = true;
      else if (char === '"') inString = false;
      continue;
    }
    if (char === '"') inString = true;
    else if (char === "[" || char === "{") {
      depth += 1;
      if (depth > SEAL_MAX_DEPTH) {
        throw new SealInputError(
          "depth_limit",
          `record nesting exceeds the SEAL max depth ${SEAL_MAX_DEPTH}`,
        );
      }
    } else if (char === "]" || char === "}") depth -= 1;
  }
}

function parseSealNumber(token: string): number {
  const value = Number(token);
  if (!Number.isFinite(value)) {
    throw new SealInputError("number_overflow", "record contains a number outside binary64 range");
  }
  const significand = token.split(/[eE]/, 1)[0];
  if (value === 0 && /[1-9]/.test(significand)) {
    throw new SealInputError("number_underflow", "record number underflows binary64 to zero");
  }
  if (Number.isInteger(value) && !Number.isSafeInteger(value)) {
    throw new SealInputError("unsafe_integer", "record contains an integer outside ±(2^53-1)");
  }
  if (value !== 0 && !isSafeNumber(token)) {
    throw new SealInputError(
      "number_precision",
      "record number loses significant digits in the RFC 8785 binary64 model",
    );
  }
  return value;
}

function hashSealSnapshot(record: unknown): string {
  const snapshot = snapshotSealValue(record);
  let canonical: string | undefined;
  try {
    canonical = jcsCanonicalize(snapshot);
  } catch (error) {
    throw new SealInputError("canonicalization_failed", "record cannot be canonicalized as RFC 8785");
  }
  if (canonical === undefined) {
    throw new SealInputError("canonicalization_failed", "record cannot be canonicalized as RFC 8785");
  }
  const bytes = new TextEncoder().encode(canonical);
  if (bytes.byteLength > SEAL_MAX_UTF8_BYTES) {
    throw new SealInputError(
      "size_limit",
      `canonical record exceeds the ${SEAL_MAX_UTF8_BYTES}-byte SEAL limit`,
    );
  }
  return createHash("sha256").update(bytes).digest("hex");
}

function snapshotSealValue(record: unknown): unknown {
  validateSealTree(record);
  let snapshot: unknown;
  try {
    snapshot = structuredClone(record);
  } catch (error) {
    throw new SealInputError("unsupported_value", "record must be structured-cloneable JSON data");
  }
  validateSealTree(snapshot);
  return snapshot;
}

function validateSealTree(record: unknown): void {
  const stack: Array<[unknown, number]> = [[record, 1]];
  while (stack.length > 0) {
    const [value, depth] = stack.pop()!;
    if (depth > SEAL_MAX_DEPTH) {
      throw new SealInputError(
        "depth_limit",
        `record nesting exceeds the SEAL max depth ${SEAL_MAX_DEPTH}`,
      );
    }
    if (value === null || typeof value === "boolean") continue;
    if (typeof value === "number") {
      if (!Number.isFinite(value)) {
        throw new SealInputError("number_overflow", "record contains a non-finite number");
      }
      if (Number.isInteger(value) && !Number.isSafeInteger(value)) {
        throw new SealInputError("unsafe_integer", "record contains an integer outside ±(2^53-1)");
      }
    } else if (typeof value === "string") {
      if (!value.isWellFormed()) {
        throw new SealInputError("invalid_unicode", "record contains an unpaired Unicode surrogate");
      }
    } else if (Array.isArray(value)) {
      const keys = Object.keys(value);
      if (keys.length !== value.length || keys.some((key, index) => key !== String(index))) {
        throw new SealInputError("unsupported_value", "record arrays must be dense without extra properties");
      }
      const descriptors = Object.getOwnPropertyDescriptors(value);
      for (const key of keys) {
        const descriptor = descriptors[key];
        if (!("value" in descriptor)) {
          throw new SealInputError("unsupported_value", "record must not contain accessors");
        }
        stack.push([descriptor.value, depth + 1]);
      }
    } else if (typeof value === "object") {
      const prototype = Object.getPrototypeOf(value);
      if (prototype !== Object.prototype && prototype !== null) {
        throw new SealInputError("unsupported_value", "record objects must be plain JSON objects");
      }
      if (Object.getOwnPropertySymbols(value).length > 0) {
        throw new SealInputError("unsupported_value", "record must not contain symbol keys");
      }
      for (const [key, descriptor] of Object.entries(Object.getOwnPropertyDescriptors(value))) {
        if (!descriptor.enumerable || !("value" in descriptor)) {
          throw new SealInputError("unsupported_value", "record must contain enumerable data properties only");
        }
        if (!key.isWellFormed()) {
          throw new SealInputError("invalid_unicode", "record contains an unpaired Unicode surrogate");
        }
        stack.push([descriptor.value, depth + 1]);
      }
    } else {
      throw new SealInputError("unsupported_value", `record contains non-JSON type ${typeof value}`);
    }
  }
}

function checkSchema(receipt: Record<string, unknown>): void {
  const extra = Object.keys(receipt).filter((k) => !ALL_TOP_LEVEL_FIELDS.has(k));
  if (extra.length) {
    throw new VerificationError(`unknown top-level fields: ${JSON.stringify(extra.sort())}`);
  }
  const missing = [...REQUIRED_FIELDS].filter((k) => !Object.hasOwn(receipt, k));
  if (missing.length) {
    throw new VerificationError(`missing top-level fields: ${JSON.stringify(missing.sort())}`);
  }

  const stringFields = [
    "schema_version", "receipt_id", "workspace_id", "issued_at", "decision", "reason",
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

  if (Object.hasOwn(receipt, "policy_eval")) {
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
  const missing = expected.filter((key) => !Object.hasOwn(obj, key));
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

const CHECKPOINT_ROOT_RE = /^sha256:[0-9a-f]{64}$/;
const CHECKPOINT_CONTEXT_FIELDS = [
  "period_start",
  "period_end",
  "receipt_count",
  "merkle_root",
  "previous_checkpoint_id",
  "previous_merkle_root",
];

function checkCheckpointContext(value: unknown, issuedAt: string): void {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new VerificationError("receipt.checkpoint context must be an object");
  }
  const context = value as Record<string, unknown>;
  checkExactKeys(context, CHECKPOINT_CONTEXT_FIELDS, "receipt.checkpoint context");
  const periodStart = parseRFC3339(context.period_start as string);
  const periodEnd = parseRFC3339(context.period_end as string);
  const checkpointAt = parseRFC3339(issuedAt);
  if (periodEnd <= periodStart) {
    throw new VerificationError("receipt.checkpoint period_end must be after period_start");
  }
  if (
    !String(context.period_start).endsWith("T00:00:00.000Z") ||
    periodEnd.getTime() - periodStart.getTime() !== 24 * 60 * 60 * 1000
  ) {
    throw new VerificationError("receipt.checkpoint period must be one UTC calendar day");
  }
  if (checkpointAt < periodEnd) {
    throw new VerificationError("receipt.checkpoint issued_at must be at or after period_end");
  }
  if (!Number.isSafeInteger(context.receipt_count) || (context.receipt_count as number) < 0) {
    throw new VerificationError("receipt.checkpoint receipt_count must be a non-negative integer");
  }
  if (typeof context.merkle_root !== "string" || !CHECKPOINT_ROOT_RE.test(context.merkle_root)) {
    throw new VerificationError("receipt.checkpoint merkle_root must be sha256:<64 lowercase hex>");
  }
  const previousId = context.previous_checkpoint_id;
  const previousRoot = context.previous_merkle_root;
  if ((previousId === null) !== (previousRoot === null)) {
    throw new VerificationError("receipt.checkpoint previous id and root must both be null or strings");
  }
  if (previousId !== null && typeof previousId !== "string") {
    throw new VerificationError("receipt.checkpoint previous_checkpoint_id must be string or null");
  }
  if (previousRoot !== null && (typeof previousRoot !== "string" || !CHECKPOINT_ROOT_RE.test(previousRoot))) {
    throw new VerificationError(
      "receipt.checkpoint previous_merkle_root must be sha256:<64 lowercase hex> or null",
    );
  }
}

export async function verifyCheckpoint(
  checkpoint: Record<string, unknown>,
  receipts: Array<Record<string, unknown>>,
  publicKeys: PublicKey[],
  opts: {
    expectedWorkspaceId: string;
    previousCheckpoint?: Record<string, unknown>;
    now?: Date;
    trustedKeyFingerprints?: ReadonlySet<string>;
  },
): Promise<void> {
  const ownCheckpoint = snapshotJson(checkpoint, "checkpoint", false) as Record<string, unknown>;
  const ownReceipts = snapshotJson(receipts, "receipts", false) as Array<Record<string, unknown>>;
  const ownPreviousCheckpoint = opts.previousCheckpoint === undefined
    ? undefined
    : snapshotJson(opts.previousCheckpoint, "previous checkpoint", false) as Record<string, unknown>;
  let ownPublicKeys: PublicKey[];
  try {
    ownPublicKeys = structuredClone(publicKeys);
  } catch {
    throw new VerificationError("publicKeys must be structured-cloneable data");
  }
  if (
    typeof SharedArrayBuffer !== "undefined"
    && ownPublicKeys.some((key) => key?.publicKeyBytes?.buffer instanceof SharedArrayBuffer)
  ) {
    throw new VerificationError("publicKeyBytes must not use SharedArrayBuffer");
  }
  let ownNow = opts.now;
  if (ownNow !== undefined) {
    try {
      ownNow = new Date(Date.prototype.getTime.call(ownNow));
    } catch {
      throw new VerificationError("now must be a valid Date");
    }
  }
  const receiptOptions = {
    now: ownNow,
    expectedWorkspaceId: opts.expectedWorkspaceId,
    trustedKeyFingerprints: opts.trustedKeyFingerprints === undefined
      ? undefined
      : new Set(opts.trustedKeyFingerprints),
  };

  await verifyReceipt(ownCheckpoint, ownPublicKeys, receiptOptions);
  if (ownCheckpoint.event !== "receipt.checkpoint") {
    throw new VerificationError("checkpoint receipt must have event='receipt.checkpoint'");
  }
  const context = ownCheckpoint.context as Record<string, unknown>;
  const periodStart = parseRFC3339(context.period_start as string);
  const periodEnd = parseRFC3339(context.period_end as string);
  for (const receipt of ownReceipts) {
    await verifyReceipt(receipt, ownPublicKeys, receiptOptions);
    if (receipt.event === "receipt.checkpoint") {
      throw new VerificationError("receipt.checkpoint cannot be a checkpoint member");
    }
    const issuedAt = parseRFC3339(receipt.issued_at as string);
    if (issuedAt < periodStart || issuedAt >= periodEnd) {
      throw new VerificationError(
        `checkpoint member ${JSON.stringify(receipt.receipt_id)} falls outside checkpoint period`,
      );
    }
  }
  if (context.receipt_count !== ownReceipts.length) {
    throw new VerificationError(
      `checkpoint receipt_count mismatch: committed ${context.receipt_count}, got ${ownReceipts.length}`,
    );
  }
  const root = await checkpointMerkleRoot(ownReceipts);
  if (context.merkle_root !== root) {
    throw new VerificationError(
      `checkpoint merkle_root mismatch: committed ${context.merkle_root}, got ${root}`,
    );
  }
  if (ownPreviousCheckpoint !== undefined) {
    await verifyReceipt(ownPreviousCheckpoint, ownPublicKeys, receiptOptions);
    if (ownPreviousCheckpoint.event !== "receipt.checkpoint") {
      throw new VerificationError("previous checkpoint must have event='receipt.checkpoint'");
    }
    const previousContext = ownPreviousCheckpoint.context as Record<string, unknown>;
    if (context.previous_checkpoint_id !== ownPreviousCheckpoint.receipt_id) {
      throw new VerificationError("checkpoint previous_checkpoint_id mismatch");
    }
    if (context.previous_merkle_root !== previousContext.merkle_root) {
      throw new VerificationError("checkpoint previous_merkle_root mismatch");
    }
    if (String(previousContext.period_end) > String(context.period_start)) {
      throw new VerificationError("checkpoint periods overlap or are out of order");
    }
  }
}

const RFC3339_RE = /^(?!0000)[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$/;

function parseRFC3339(s: string): Date {
  if (typeof s !== "string" || !RFC3339_RE.test(s)) {
    throw new VerificationError(
      `timestamp must be UTC millisecond precision YYYY-MM-DDTHH:MM:SS.sssZ, got ${JSON.stringify(s)}`,
    );
  }
  const d = new Date(s);
  // `new Date` rolls impossible dates and hour 24; round-tripping also handles
  // years 0001–0099 without Date.UTC's two-digit-year remapping.
  if (isNaN(d.getTime()) || d.toISOString() !== s) {
    throw new VerificationError(`not a real calendar date/time: ${s}`);
  }
  return d;
}

function findKey(keys: PublicKey[], keyId: string, issuedAt: Date): PublicKey {
  for (const k of keys) {
    if (typeof k !== "object" || k === null) {
      throw new VerificationError("publicKeys entries must be objects");
    }
    if (k.keyId !== keyId) continue;
    if (k.alg !== "Ed25519") {
      throw new VerificationError(`unsupported public key alg: ${JSON.stringify(k.alg)}`);
    }
    if (!(k.publicKeyBytes instanceof Uint8Array) || k.publicKeyBytes.length !== 32) {
      throw new VerificationError("selected Ed25519 public key must contain 32 raw bytes");
    }
    if (!(k.activeFrom instanceof Date) || !Number.isFinite(k.activeFrom.getTime())) {
      throw new VerificationError("selected public key activeFrom must be a valid Date");
    }
    if (
      k.activeUntil !== null &&
      (!(k.activeUntil instanceof Date) || !Number.isFinite(k.activeUntil.getTime()))
    ) {
      throw new VerificationError("selected public key activeUntil must be a valid Date or null");
    }
    if (k.activeUntil !== null && k.activeUntil <= k.activeFrom) {
      throw new VerificationError("selected public key active window is empty");
    }
    if (issuedAt < k.activeFrom) {
      throw new VerificationError(`key ${JSON.stringify(keyId)} not yet active at issued_at`);
    }
    if (k.activeUntil !== null && issuedAt >= k.activeUntil) {
      throw new VerificationError(`key ${JSON.stringify(keyId)} retired before issued_at`);
    }
    return {
      keyId: k.keyId,
      alg: k.alg,
      publicKeyBytes: new Uint8Array(k.publicKeyBytes),
      activeFrom: new Date(k.activeFrom.getTime()),
      activeUntil: k.activeUntil === null ? null : new Date(k.activeUntil.getTime()),
    };
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
    public_key_fingerprint?: string;
    active_from: string;
    active_until: string | null;
  }>;
}

export function loadKeysFromJson(doc: KeyDocument): PublicKey[] {
  // Throws VerificationError (never a raw TypeError) on a malformed document,
  // and rejects duplicate key ids and duplicate public keys so key lookup is
  // unambiguous and one public key cannot carry conflicting active windows
  // (spec §10.1).
  if (
    typeof doc !== "object" ||
    doc === null ||
    !Object.hasOwn(doc, "workspace_id") ||
    typeof doc.workspace_id !== "string" ||
    doc.workspace_id.length === 0 ||
    !Object.hasOwn(doc, "keys") ||
    !Array.isArray(doc.keys)
  ) {
    throw new VerificationError(
      "keys document must be an object with a non-empty 'workspace_id' and a 'keys' array",
    );
  }
  const seenIds = new Set<string>();
  const seenPubs = new Set<string>();
  return doc.keys.map((k, i) => {
    if (typeof k !== "object" || k === null) {
      throw new VerificationError(`keys[${i}] must be an object`);
    }
    for (const field of ["key_id", "alg", "public_key", "active_from"] as const) {
      if (!Object.hasOwn(k, field) || typeof k[field] !== "string") {
        throw new VerificationError(`keys[${i}].${field} must be a string`);
      }
    }
    if (k.alg !== "Ed25519") {
      throw new VerificationError(`keys[${i}].alg must be "Ed25519"`);
    }
    if (!Object.hasOwn(k, "active_until") || (k.active_until !== null && typeof k.active_until !== "string")) {
      throw new VerificationError(`keys[${i}].active_until must be a string or null`);
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
    const key = {
      keyId: k.key_id,
      alg: "Ed25519" as const,
      publicKeyBytes: pub,
      activeFrom: parseRFC3339(k.active_from),
      activeUntil: k.active_until === null ? null : parseRFC3339(k.active_until),
    };
    if (
      Object.hasOwn(k, "public_key_fingerprint") &&
      k.public_key_fingerprint !== publicKeyFingerprint(key)
    ) {
      throw new VerificationError(
        `keys[${i}].public_key_fingerprint does not match public_key`,
      );
    }
    return key;
  });
}

// ---------------------------------------------------------------------------
// hmac-v1 keyed pseudonym references (spec Appendix A) — optional helper
// ---------------------------------------------------------------------------

const HMAC_REF_RE = /^hmac-v1:[0-9a-f]{64}$/;
const HMAC_REF_FIELDS = new Set(["project", "record", "actor", "full_tuple"]);

/**
 * Match an application `hmac-v1` reference without contacting Allowly
 * (spec Appendix A). `key` is the decoded per-integration pseudonym key.
 *
 * Inputs are used exactly as supplied: this helper does no trimming, case
 * folding, or Unicode normalization. It is unrelated to receipt signature
 * verification — the receipt schema, canonicalization, and wire version are
 * untouched by this convention.
 */
export function matchesRef(
  key: Uint8Array,
  fieldName: string,
  value: string,
  ref: string,
): boolean {
  if (!(key instanceof Uint8Array)) {
    throw new TypeError("key must be a Uint8Array");
  }
  if (key.length < 16) {
    throw new RangeError("key must contain at least 128 bits");
  }
  if (typeof fieldName !== "string" || !HMAC_REF_FIELDS.has(fieldName)) {
    throw new RangeError("unsupported hmac-v1 field name");
  }
  if (typeof value !== "string") {
    throw new TypeError("value must be a string");
  }
  if (!value.isWellFormed()) {
    throw new RangeError("value contains an unpaired Unicode surrogate");
  }
  if (typeof ref !== "string" || !HMAC_REF_RE.test(ref)) {
    return false;
  }
  // message = ASCII(field_name) || 0x00 || UTF8(value)  (spec §A.2)
  const message = Buffer.concat([
    Buffer.from(fieldName, "ascii"),
    Buffer.from([0x00]),
    Buffer.from(value, "utf-8"),
  ]);
  const expected = Buffer.from(
    "hmac-v1:" + createHmac("sha256", key).update(message).digest("hex"),
    "ascii",
  );
  const got = Buffer.from(ref, "ascii");
  // `ref` passed HMAC_REF_RE, so it is exactly `hmac-v1:` + 64 hex — same
  // length as `expected`; the guard keeps timingSafeEqual from throwing.
  return expected.length === got.length && timingSafeEqual(expected, got);
}
