/**
 * Record and pack verification (TypeScript port). Same security model as Python:
 * issuer pinning + fail-closed, content-address recomputation, and never throws on
 * hostile input. A single record verifies on its own (portability).
 */

import { recordId, VERSION } from "./memory.ts";
import { unb64, verify as verifySig } from "./signing.ts";

export type TrustedKeys = string | Buffer | Array<string | Buffer>;

export interface RecordVerdict {
  valid: boolean;
  reason: string;
}

export interface PackVerdict {
  valid: boolean;
  count: number;
  broken_at: number | null;
  reason: string;
}

export interface VerifyOptions {
  trustedKeys?: TrustedKeys;
  allowUnverifiedIssuer?: boolean;
}

function normalizeTrusted(trustedKeys?: TrustedKeys): Set<string> | null {
  if (trustedKeys == null) return null;
  const arr = Array.isArray(trustedKeys) ? trustedKeys : [trustedKeys];
  return new Set(arr.map((k) => (Buffer.isBuffer(k) ? k.toString("base64") : k)));
}

export function verifyRecord(record: any, opts: VerifyOptions = {}): RecordVerdict {
  const trusted = normalizeTrusted(opts.trustedKeys);
  if (trusted === null && !opts.allowUnverifiedIssuer) {
    return { valid: false, reason: "no trusted issuer keys supplied: pass trustedKeys: [...] (recommended) or allowUnverifiedIssuer: true" };
  }
  try {
    if (!record || typeof record !== "object" || Array.isArray(record)) {
      return { valid: false, reason: "record is not an object" };
    }
    if (record.version !== VERSION) {
      return { valid: false, reason: `unsupported or mismatched record version: ${JSON.stringify(record.version)}` };
    }
    // Coerce every id-contributing field to null when absent, exactly as Python's
    // record.get(...) does. Without this the `canonicalize` package drops
    // undefined-valued keys, so an absent field hashes differently than Python's
    // null and the same signed record would verify in one SDK but not the other.
    const recomputed = recordId({
      subject: record.subject ?? null, agent: record.agent ?? null,
      kind: record.kind ?? null, scope: record.scope ?? null, consent: record.consent ?? null,
      content: record.content ?? null, timestamp: record.timestamp ?? null,
      supersedes: record.supersedes ?? null, revoked: record.revoked ?? false,
    });
    if (recomputed !== record.id) return { valid: false, reason: "content tampered: id does not match" };
    const sig = record.signature;
    if (!sig || typeof sig !== "object" || sig.alg !== "Ed25519") {
      return { valid: false, reason: "missing or unsupported signature" };
    }
    if (trusted !== null && !trusted.has(sig.public_key)) {
      return { valid: false, reason: "signer is not in the trusted-issuer set" };
    }
    if (!verifySig(unb64(sig.value ?? ""), unb64(record.id), unb64(sig.public_key ?? ""))) {
      return { valid: false, reason: "invalid signature" };
    }
    return { valid: true, reason: "record valid" };
  } catch (ex) {
    return { valid: false, reason: `malformed record: ${(ex as Error).name}` };
  }
}

export function verifyPack(pack: any, opts: VerifyOptions = {}): PackVerdict {
  let records: any;
  if (pack && Array.isArray(pack.records)) records = pack.records;
  else if (Array.isArray(pack)) records = pack;
  else if (pack && typeof pack === "object") records = pack.records;
  else return { valid: false, count: 0, broken_at: null, reason: "malformed: not a pack" };
  if (!Array.isArray(records)) return { valid: false, count: 0, broken_at: null, reason: "malformed: records is not a list" };

  const trusted = normalizeTrusted(opts.trustedKeys);
  if (trusted === null && !opts.allowUnverifiedIssuer) {
    return { valid: false, count: records.length, broken_at: null,
      reason: "no trusted issuer keys supplied: pass trustedKeys: [...] (recommended) or allowUnverifiedIssuer: true" };
  }

  for (let i = 0; i < records.length; i++) {
    const verdict = verifyRecord(records[i], opts);
    if (!verdict.valid) return { valid: false, count: records.length, broken_at: i, reason: verdict.reason };
  }
  return { valid: true, count: records.length, broken_at: null, reason: "pack intact" };
}
