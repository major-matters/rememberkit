/**
 * The memory record (TypeScript port). Mirrors the Python module: each record is
 * content-addressed (id = SHA-256 over its canonical content, RFC 8785) and signed,
 * so a single memory verifies on its own and can travel between agents.
 */

import { canonicalize } from "./canonical.ts";
import { b64, publicKeyFromSeed, sha256, sign, unb64 } from "./signing.ts";

export const VERSION = "rememberkit/v0";

// Recognized consent markers, least to most open.
export const CONSENT_LEVELS = ["private", "shareable", "public"] as const;

export interface Record {
  version: string;
  id: string;
  subject: string | null;
  agent: string | null;
  kind: string;
  scope: string | null;
  consent: string;
  content: unknown;
  timestamp: string;
  supersedes: string | null;
  revoked: boolean;
  signature: { alg: "Ed25519"; public_key: string; value: string };
}

function nowIso(): string {
  return new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
}

export function recordId(r: {
  subject: string | null;
  agent: string | null;
  kind: string | null;
  scope: string | null;
  consent: string | null;
  content: unknown;
  timestamp: string | null;
  supersedes: string | null;
  revoked: boolean;
}): string {
  const body = {
    version: VERSION,
    subject: r.subject,
    agent: r.agent,
    kind: r.kind,
    scope: r.scope,
    consent: r.consent,
    content: r.content,
    timestamp: r.timestamp,
    supersedes: r.supersedes,
    revoked: r.revoked,
  };
  return b64(sha256(canonicalize(body)));
}

export function buildRecord(opts: {
  subject: string | null;
  agent: string | null;
  kind: string;
  scope: string | null;
  consent: string;
  content: unknown;
  privateKey: Buffer;
  timestamp?: string;
  supersedes?: string | null;
  revoked?: boolean;
}): Record {
  const timestamp = opts.timestamp ?? nowIso();
  const supersedes = opts.supersedes ?? null;
  const revoked = opts.revoked ?? false;
  const id = recordId({
    subject: opts.subject, agent: opts.agent, kind: opts.kind, scope: opts.scope,
    consent: opts.consent, content: opts.content, timestamp, supersedes, revoked,
  });
  const signature = sign(unb64(id), opts.privateKey);
  return {
    version: VERSION,
    id,
    subject: opts.subject,
    agent: opts.agent,
    kind: opts.kind,
    scope: opts.scope,
    consent: opts.consent,
    content: opts.content,
    timestamp,
    supersedes,
    revoked,
    signature: {
      alg: "Ed25519",
      public_key: b64(publicKeyFromSeed(opts.privateKey)),
      value: b64(signature),
    },
  };
}

function isRecordObject(r: unknown): r is Record {
  return !!r && typeof r === "object" && !Array.isArray(r);
}

function liveIds(records: Record[]): Set<string> {
  const superseded = new Set<string>();
  for (const r of records) if (isRecordObject(r) && r.supersedes) superseded.add(r.supersedes);
  const live = new Set<string>();
  for (const r of records) {
    if (!isRecordObject(r)) continue;
    if (r.revoked) continue;
    if (superseded.has(r.id)) continue;
    live.add(r.id);
  }
  return live;
}

export interface Pack {
  version: string;
  agent: string | null;
  subject: string | null;
  records: Record[];
}

export class Memory {
  private key: Buffer | null;
  agent: string | null;
  subject: string | null;
  records: Record[];

  constructor(privateKey: Buffer | null, agent: string | null, subject: string | null = null, records: Record[] = []) {
    this.key = privateKey;
    this.agent = agent;
    this.subject = subject;
    this.records = [...records];
  }

  remember(content: unknown, opts: {
    kind?: string; scope?: string | null; consent?: string;
    subject?: string | null; supersedes?: string | null; timestamp?: string;
  } = {}): Record {
    if (this.key == null) throw new Error("Memory has no signing key; cannot remember");
    const record = buildRecord({
      subject: opts.subject !== undefined ? opts.subject : this.subject,
      agent: this.agent,
      kind: opts.kind ?? "fact",
      scope: opts.scope ?? null,
      consent: opts.consent ?? "private",
      content: content ?? {},
      privateKey: this.key,
      timestamp: opts.timestamp,
      supersedes: opts.supersedes ?? null,
    });
    this.records.push(record);
    return record;
  }

  forget(targetId: string, opts: { timestamp?: string } = {}): Record {
    if (this.key == null) throw new Error("Memory has no signing key; cannot forget");
    const record = buildRecord({
      subject: this.subject,
      agent: this.agent,
      kind: "tombstone",
      scope: null,
      consent: "private",
      content: { forgets: targetId },
      privateKey: this.key,
      timestamp: opts.timestamp,
      supersedes: targetId,
      revoked: true,
    });
    this.records.push(record);
    return record;
  }

  recall(opts: {
    scope?: string | null; kind?: string | null; subject?: string | null;
    minConsent?: string | null; includeRevoked?: boolean;
  } = {}): Record[] {
    // FAIL CLOSED: an unrecognized minConsent must not silently disable the
    // consent filter (which would leak private records). Throw instead.
    if (opts.minConsent != null && !(CONSENT_LEVELS as readonly string[]).includes(opts.minConsent)) {
      throw new Error(`unrecognized minConsent ${JSON.stringify(opts.minConsent)}; expected one of ${CONSENT_LEVELS.join(", ")}`);
    }
    const live = liveIds(this.records);
    const floor = opts.minConsent != null
      ? (CONSENT_LEVELS as readonly string[]).indexOf(opts.minConsent) : null;
    const out: Record[] = [];
    for (const r of this.records) {
      if (!isRecordObject(r)) continue;
      if (!opts.includeRevoked && !live.has(r.id)) continue;
      if (r.revoked && !opts.includeRevoked) continue;
      if (opts.scope != null && r.scope !== opts.scope) continue;
      if (opts.kind != null && r.kind !== opts.kind) continue;
      if (opts.subject != null && r.subject !== opts.subject) continue;
      if (floor != null) {
        const idx = (CONSENT_LEVELS as readonly string[]).indexOf(r.consent);
        if (idx < 0 || idx < floor) continue;
      }
      out.push(r);
    }
    return out;
  }

  toJSON(): Pack {
    return { version: VERSION, agent: this.agent, subject: this.subject, records: this.records };
  }

  share(opts: { scope?: string | null; minConsent?: string; subject?: string | null } = {}): Pack {
    // Default to this store's subject so a multi-subject store does not leak one
    // subject's records to another's peer. Pass subject: null to share across all.
    const subject = "subject" in opts ? (opts.subject ?? null) : this.subject;
    const records = this.recall({ scope: opts.scope ?? null, minConsent: opts.minConsent ?? "shareable", subject });
    return { version: VERSION, agent: this.agent, subject: this.subject, records };
  }

  static open(data: any, privateKey: Buffer | null = null, agent: string | null = null, subject: string | null = null): Memory {
    const records: Record[] = Array.isArray(data) ? data : (data?.records ?? []);
    let a = agent;
    let s = subject;
    if (data && !Array.isArray(data)) {
      if (a == null) a = data.agent ?? null;
      if (s == null) s = data.subject ?? null;
    }
    return new Memory(privateKey, a, s, records);
  }
}
