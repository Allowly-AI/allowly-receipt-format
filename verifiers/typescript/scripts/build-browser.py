#!/usr/bin/env python3
"""Build self-hosted browser verifier and SEAL JSON files after npm run build.

Usage: build-browser.py RECEIPT_OUTPUT SEAL_JSON_OUTPUT [DECLARATION_OUTPUT]
"""
import json
import pathlib
import sys

SRC_DIR = pathlib.Path(__file__).resolve().parent.parent
SRC = SRC_DIR / "dist" / "verifier.js"

NODE_IMPORT = 'import { createHash, createHmac, timingSafeEqual, webcrypto } from "node:crypto";'
JCS_IMPORT = 'import jcsCanonicalize from "canonicalize";\n'
LOSSLESS_IMPORT = 'import { isSafeNumber, parse as parseLosslessJson } from "lossless-json";\n'
NODE_FINGERPRINT = '''export function publicKeyFingerprint(key) {
    return "sha256:" + createHash("sha256").update(key.publicKeyBytes).digest("hex");
}'''
BROWSER_FINGERPRINT = '''export async function publicKeyFingerprint(key) {
    const digest = new Uint8Array(await webcrypto.subtle.digest("SHA-256", key.publicKeyBytes));
    return "sha256:" + Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("");
}'''
NODE_B64 = '''    const padded = s + "=".repeat((4 - (s.length % 4)) % 4);
    const standard = padded.replace(/-/g, "+").replace(/_/g, "/");
    const binary = Buffer.from(standard, "base64");
    if (binary.toString("base64url") !== s) {
        throw new VerificationError(`non-canonical base64url: ${JSON.stringify(s)}`);
    }
    return new Uint8Array(binary);'''
BROWSER_B64 = '''    const padded = s + "=".repeat((4 - (s.length % 4)) % 4);
    const standard = padded.replace(/-/g, "+").replace(/_/g, "/");
    let bytes;
    try {
        const binary = atob(standard);
        bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
    }
    catch {
        throw new VerificationError(`not unpadded base64url: ${JSON.stringify(s)}`);
    }
    let binary = "";
    for (let i = 0; i < bytes.length; i += 0x8000) {
        binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
    }
    const reencoded = btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
    if (reencoded !== s) {
        throw new VerificationError(`non-canonical base64url: ${JSON.stringify(s)}`);
    }
    return bytes;'''


def main() -> int:
    if len(sys.argv) not in {3, 4}:
        print("usage: build-browser.py RECEIPT_OUTPUT SEAL_JSON_OUTPUT [DECLARATION_OUTPUT]", file=sys.stderr)
        return 2
    receipt_out, seal_out = map(pathlib.Path, sys.argv[1:3])
    seal_source = SRC_DIR / "dist" / "browser" / "sealJson.js"
    declaration_source = seal_source.with_suffix(".d.ts")
    inputs = [SRC, seal_source, *([declaration_source] if len(sys.argv) == 4 else [])]
    for path in inputs:
        if not path.exists():
            print(f"missing {path}\nBuild it first: cd {SRC_DIR} && npm run build", file=sys.stderr)
            return 1

    source = SRC.read_text()
    if NODE_IMPORT not in source:
        print(
            "node:crypto import not found — the reference verifier changed its imports.\n"
            "Re-read verifier.js and update this transform rather than guessing.",
            file=sys.stderr,
        )
        return 1

    version = json.loads((SRC_DIR / "package.json").read_text())["version"]
    shim = f"""// ---------------------------------------------------------------------------
// Vendored browser build of @allowly/verifier {version} (Apache-2.0).
// Generated from verifiers/typescript/dist/verifier.js — do not hand-edit.
// Generator: verifiers/typescript/scripts/build-browser.py
// Refresh in the app or site: python3 scripts/refresh-verifier.py
//
// Browser adapter: SHA-256 and key loading are async because WebCrypto has no
// synchronous digest API. Receipt verification is unchanged. The synchronous
// Node SEAL helpers are supplied by the generated browser/sealJson.js module;
// matchesRef() is intentionally unavailable in this browser build.
// ---------------------------------------------------------------------------
const webcrypto = globalThis.crypto;"""

    source = source.replace(NODE_IMPORT, shim, 1)
    seal_start = source.find("// SEAL profile (RFC 8785 / JCS record hashing)")
    seal_end = source.find("function checkSchema(", seal_start)
    if seal_start == -1 or seal_end == -1:
        print("SEAL section markers not found; update the browser adapter", file=sys.stderr)
        return 1
    section_start = source.rfind("// ---------------------------------------------------------------------------", 0, seal_start)
    source = source[:section_start] + source[seal_end:]
    source = source.replace(JCS_IMPORT, "", 1).replace(LOSSLESS_IMPORT, "", 1)
    source = source.replace(NODE_FINGERPRINT, BROWSER_FINGERPRINT, 1)
    source = source.replace(NODE_B64, BROWSER_B64, 1)
    source = source.replace(
        "export function loadKeysFromJson(doc) {",
        "export async function loadKeysFromJson(doc) {",
        1,
    )
    source = source.replace(
        "    return doc.keys.map((k, i) => {",
        "    return Promise.all(doc.keys.map(async (k, i) => {",
        1,
    )
    source = source.replace(
        "const fingerprint = publicKeyFingerprint(key);",
        "const fingerprint = await publicKeyFingerprint(key);",
        1,
    )
    source = source.replace(
        "k.public_key_fingerprint !== publicKeyFingerprint(key))",
        "k.public_key_fingerprint !== await publicKeyFingerprint(key))",
        1,
    )
    source = source.replace(
        "        return key;\n    });\n}\n// ---------------------------------------------------------------------------\n// hmac-v1",
        "        return key;\n    }));\n}\n// ---------------------------------------------------------------------------\n// hmac-v1",
        1,
    )
    matches_start = source.find("export function matchesRef")
    if matches_start == -1:
        print("matchesRef export not found; update the browser adapter", file=sys.stderr)
        return 1
    source = source[:matches_start] + '''export function matchesRef() {
    throw new Error("matchesRef() is Node-only in the browser build");
}
'''
    if "Buffer.from(standard" in source or "createHash(" in source:
        print("Node-only verification code remains after browser transform", file=sys.stderr)
        return 1

    header = f"""// Vendored browser SEAL helpers from @allowly/verifier {version} (Apache-2.0).
// Generated from verifiers/typescript/browser/sealJson.ts — do not hand-edit.
// Refresh in the app or site: python3 scripts/refresh-verifier.py
"""
    outputs = [(receipt_out, source), (seal_out, header + seal_source.read_text())]
    if len(sys.argv) == 4:
        outputs.append((pathlib.Path(sys.argv[3]), header + declaration_source.read_text()))
    for path, content in outputs:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        print(f"wrote {path} from @allowly/verifier {version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
