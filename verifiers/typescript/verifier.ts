/**
 * Allowly Receipt Verifier (TypeScript reference implementation).
 *
 * Verifies Allowly receipts per receipt-format.md wire version 5.
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
import { base64url, compactVerify, importJWK } from "jose";

const SPEC_VERSION = "5";
const ACTION_DECISIONS = new Set(["allow", "deny", "confirm", "escalate"]);
const EVENT_DECISIONS: Record<string, Set<string>> = {
  "authorization.create": new Set(["authorization_granted"]),
  "authorization.revoke": new Set(["authorization_revoked"]),
  "budget.settle": new Set(["budget_settled"]),
  "confirmation.resolve": new Set(["confirmation_approved", "confirmation_rejected"]),
  "escalation.resolve": new Set(["escalation_approved", "escalation_rejected"]),
  "receipt.checkpoint": new Set(["receipt_set_committed"]),
};
const AUTHORIZATION_LIFECYCLE_EVENTS = new Set(["authorization.create", "authorization.revoke"]);
const EVENT_ONLY_DECISIONS = new Set(Object.values(EVENT_DECISIONS).flatMap((decisions) => [...decisions]));
const REQUIRED_FIELDS = new Set([
  "schema_version", "receipt_id", "workspace_id", "issued_at", "decision", "reason",
  "user_id", "agent_id", "resource", "context",
  "authorization_id", "policy_ref", "engine_version",
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
  policy_ref: { policy_id: string; policy_version: number; definition_sha256: string } | null;
  policy_eval?: {
    input_sha256: string;
    result: {
      profile: "allowly.basic.v1";
      status: "ok";
      decision: "allow" | "deny" | "confirm" | "escalate";
      target: string | null;
      matched_rule_id: string | null;
      evaluated_fields: Record<string, unknown>;
    };
  };
}

export interface ReceiptPayload extends ReceiptBase, Record<string, unknown> {
  schema_version: "5";
}

export interface JwsReceipt extends Record<string, unknown> {
  protected: string;
  payload: string;
  signature: string;
}
export type Receipt = JwsReceipt;

/** Standard JWS signing bytes for external Ed25519 signing (for example KMS). */
export function jwsSigningInput(payload: unknown, keyId: string): Uint8Array {
  if (typeof keyId !== "string" || !keyId) throw new VerificationError("JWS kid must be a nonempty string");
  const header = { alg: "EdDSA", kid: keyId, typ: "allowly-receipt+jws" };
  return new TextEncoder().encode([header, payload].map(value => base64url.encode(canonicalize(value))).join("."));
}

/** Package an external signature. This does not sign or verify the evidence. */
export function jwsReceipt(payload: unknown, keyId: string, signature: Uint8Array | string): JwsReceipt {
  const [protectedHeader, encoded] = new TextDecoder().decode(jwsSigningInput(payload, keyId)).split(".");
  const encodedSignature = typeof signature === "string" ? signature : base64url.encode(signature);
  if (b64urlDecode(encodedSignature).length !== 64) throw new VerificationError("signature must decode to 64 bytes (Ed25519)");
  return { protected: protectedHeader, payload: encoded, signature: encodedSignature };
}

function jwsParts(receipt: unknown): { envelope: JwsReceipt; header: { kid: string }; payload: ReceiptPayload } {
  const envelope = snapshotJson(receipt, "receipt") as Record<string, unknown>;
  if (typeof envelope !== "object" || envelope === null || Array.isArray(envelope)) throw new VerificationError("receipt must be an object");
  checkExactKeys(envelope, ["protected", "payload", "signature"], "JWS envelope");
  if (Object.values(envelope).some(value => typeof value !== "string")) throw new VerificationError("JWS segments must be strings");
  const wire = envelope as unknown as JwsReceipt;
  if (wire.protected.length + wire.payload.length + wire.signature.length > 8 * 1024 * 1024) throw new VerificationError("JWS exceeds size limit");
  const parse = (encoded: string): Record<string, unknown> => {
    try {
      const text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(b64urlDecode(encoded));
      parseLosslessJson(namespaceObjectKeysForValidation(text), undefined, { parseNumber: token => {
        if (!/^-?(?:0|[1-9][0-9]*)$/.test(token)) throw new VerificationError("receipts must not contain non-integer numbers");
        const number = Number(token);
        if (!Number.isSafeInteger(number)) throw new VerificationError("integer exceeds the safe range ±(2^53-1)");
        return number;
      }});
      const value = JSON.parse(text);
      validateTree(value);
      if (typeof value !== "object" || value === null || Array.isArray(value)) throw new VerificationError("JWS JSON must be an object");
      return value;
    } catch (error) {
      if (error instanceof VerificationError) throw error;
      throw new VerificationError(`invalid JWS strict UTF-8 JSON: ${error instanceof Error ? error.message : "invalid JSON"}`);
    }
  };
  const header = parse(wire.protected);
  checkExactKeys(header, ["alg", "kid", "typ"], "JWS protected header");
  if (header.alg !== "EdDSA" || header.typ !== "allowly-receipt+jws") throw new VerificationError("unsupported JWS algorithm or type");
  if (typeof header.kid !== "string" || !header.kid) throw new VerificationError("JWS kid must be a nonempty string");
  if (b64urlDecode(wire.signature).length !== 64) throw new VerificationError("signature must decode to 64 bytes (Ed25519)");
  const payload = parse(wire.payload);
  if (payload.schema_version !== SPEC_VERSION) throw new VerificationError(`unsupported schema_version: ${JSON.stringify(payload.schema_version)}`);
  checkSchema(payload);
  return { envelope: wire, header: header as { kid: string }, payload: payload as unknown as ReceiptPayload };
}

/** Strict UNVERIFIED decoding for display, never for authorization. */
export function decodeReceipt(receipt: unknown): ReceiptPayload {
  return jwsParts(receipt).payload;
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
    if (typeof receipt !== "object" || receipt === null || !Object.hasOwn(receipt, "protected")) {
      throw new VerificationError("checkpoint member must be a receipt object with receipt_id");
    }
    const payload = decodeReceipt(receipt);
    if (typeof payload.receipt_id !== "string") {
      throw new VerificationError("checkpoint member must be a receipt object with receipt_id");
    }
    if (seenIds.has(payload.receipt_id)) {
      throw new VerificationError(`duplicate checkpoint member receipt_id: ${JSON.stringify(payload.receipt_id)}`);
    }
    seenIds.add(payload.receipt_id);
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
): Promise<ReceiptPayload> {
  if (typeof receipt !== "object" || receipt === null || Array.isArray(receipt)) {
    throw new VerificationError("receipt must be an object");
  }
  const { envelope, header, payload: decoded } = jwsParts(receipt);
  const ownReceipt = decoded as unknown as Record<string, unknown>;
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

  const r = decoded;

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
        `event must be one of ${JSON.stringify(Object.keys(EVENT_DECISIONS).sort())}, got ${JSON.stringify(event)}`,
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

  if (hasEvent) {
    if (ownReceipt.event === "receipt.checkpoint") {
      if (ownReceipt.policy_ref !== null) throw new VerificationError("receipt.checkpoint must have null policy_ref");
    } else if (ownReceipt.policy_ref === null) {
      throw new VerificationError("authorization event must have non-null policy_ref");
    }
  } else if (r.authorization_id === null) {
    if (ownReceipt.policy_ref !== null) throw new VerificationError("unresolved authorization must have null policy_ref");
  } else if (ownReceipt.policy_ref === null && ownReceipt.action !== "record.seal") {
    throw new VerificationError("governed action must have non-null policy_ref");
  }

  // Step 5: timestamp sanity
  const issuedAt = parseRFC3339(r.issued_at);
  if (issuedAt.getTime() > nowMs + MAX_FUTURE_SKEW_MS) {
    throw new VerificationError(
      `receipt issued in the future: ${issuedAt.toISOString()} > ${new Date(nowMs).toISOString()}`,
    );
  }

  // Step 7: signature verification
  const key = findKey(keySnapshots, header.kid, issuedAt);
  const fingerprint = publicKeyFingerprint(key);
  if (
    opts.trustedKeyFingerprints !== undefined &&
    !opts.trustedKeyFingerprints.has(fingerprint)
  ) {
    throw new VerificationError(
      `public key fingerprint is not trusted: ${fingerprint}`,
    );
  }
  try {
    const cryptoKey = await importJWK({ kty: "OKP", crv: "Ed25519", x: base64url.encode(key.publicKeyBytes) }, "EdDSA");
    await compactVerify([envelope.protected, envelope.payload, envelope.signature].join("."), cryptoKey, { algorithms: ["EdDSA"] });
  } catch {
    throw new VerificationError("signature verification failed");
  }
  return decoded;
}

const PUBLIC_KEY_FINGERPRINT_RE = /^sha256:[0-9a-f]{64}$/;

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
    ownReceipt = await verifyReceipt(receipt, publicKeys, opts) as unknown as Record<string, unknown>;
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

  checkPolicyRef(receipt.policy_ref);
  if ((receipt.engine_version as string).length !== 71 || !PUBLIC_KEY_FINGERPRINT_RE.test(receipt.engine_version as string)) throw new VerificationError("engine_version must be sha256: followed by 64 lowercase hex characters");
  if (Object.hasOwn(receipt, "policy_eval")) {
    checkPolicyEval(receipt.policy_eval);
    if (receipt.policy_ref === null) throw new VerificationError("policy_eval requires non-null policy_ref");
  }
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

function checkPolicyRef(value: unknown): void {
  if (value === null) return;
  if (typeof value !== "object" || Array.isArray(value)) throw new VerificationError("policy_ref must be an object or null");
  const ref = value as Record<string, unknown>;
  checkExactKeys(ref, ["policy_id", "policy_version", "definition_sha256"], "policy_ref");
  if (typeof ref.policy_id !== "string" || !ref.policy_id) throw new VerificationError("policy_ref.policy_id must be a nonempty string");
  if (typeof ref.policy_version !== "number" || !Number.isSafeInteger(ref.policy_version) || ref.policy_version < 1) throw new VerificationError("policy_ref.policy_version must be a positive safe integer");
  if (typeof ref.definition_sha256 !== "string" || ref.definition_sha256.length !== 64 || !/^[0-9a-f]{64}$/.test(ref.definition_sha256)) throw new VerificationError("policy_ref.definition_sha256 must be 64 lowercase hex characters");
}

function checkPolicyEval(value: unknown): void {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new VerificationError("policy_eval must be an object");
  const evidence = value as Record<string, unknown>;
  checkExactKeys(evidence, ["input_sha256", "result"], "policy_eval");
  if (typeof evidence.input_sha256 !== "string" || evidence.input_sha256.length !== 64 || !/^[0-9a-f]{64}$/.test(evidence.input_sha256)) throw new VerificationError("policy_eval.input_sha256 must be 64 lowercase hex characters");
  const valueResult = evidence.result;
  if (typeof valueResult !== "object" || valueResult === null || Array.isArray(valueResult)) throw new VerificationError("policy_eval.result must be an object");
  const result = valueResult as Record<string, unknown>;
  checkExactKeys(result, ["profile", "status", "decision", "target", "matched_rule_id", "evaluated_fields"], "policy_eval.result");
  if (result.profile !== "allowly.basic.v1" || result.status !== "ok") throw new VerificationError("policy_eval.result requires allowly.basic.v1 successful status");
  if (typeof result.decision !== "string" || !ACTION_DECISIONS.has(result.decision)) throw new VerificationError("policy_eval.result.decision must be allow, deny, confirm, or escalate");
  const target = result.target;
  const validTarget = result.decision === "allow" || result.decision === "deny" ? target === null
    : result.decision === "confirm" ? target === "agent_owner"
    : typeof target === "string" && target.startsWith("member:") && target.length > 7 && [...target].length <= 256;
  if (!validTarget) throw new VerificationError("policy_eval.result.target does not match decision");
  const rule = result.matched_rule_id;
  if (rule !== null && (typeof rule !== "string" || !rule || [...rule].length > 128)) throw new VerificationError("policy_eval.result.matched_rule_id must be a bounded nonempty string or null");
  const fields = result.evaluated_fields;
  if (typeof fields !== "object" || fields === null || Array.isArray(fields) || Object.keys(fields).some(key => !key || [...key].length > 128)) throw new VerificationError("policy_eval.result.evaluated_fields must be an object with bounded nonempty field names");
  if (rule === null && Object.keys(fields).length) throw new VerificationError("policy_eval.result default requires empty evaluated_fields");
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

  const checkpointPayload = await verifyReceipt(ownCheckpoint, ownPublicKeys, receiptOptions);
  if (checkpointPayload.event !== "receipt.checkpoint") {
    throw new VerificationError("checkpoint receipt must have event='receipt.checkpoint'");
  }
  const context = checkpointPayload.context;
  const periodStart = parseRFC3339(context.period_start as string);
  const periodEnd = parseRFC3339(context.period_end as string);
  for (const receipt of ownReceipts) {
    const payload = await verifyReceipt(receipt, ownPublicKeys, receiptOptions);
    if (payload.event === "receipt.checkpoint") {
      throw new VerificationError("receipt.checkpoint cannot be a checkpoint member");
    }
    const issuedAt = parseRFC3339(payload.issued_at);
    if (issuedAt < periodStart || issuedAt >= periodEnd) {
      throw new VerificationError(
        `checkpoint member ${JSON.stringify(payload.receipt_id)} falls outside checkpoint period`,
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
    const previousPayload = await verifyReceipt(ownPreviousCheckpoint, ownPublicKeys, receiptOptions);
    if (previousPayload.event !== "receipt.checkpoint") {
      throw new VerificationError("previous checkpoint must have event='receipt.checkpoint'");
    }
    const previousContext = previousPayload.context;
    if (context.previous_checkpoint_id !== previousPayload.receipt_id) {
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
