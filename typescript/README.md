# RememberKit · v0 (TypeScript)

**Governed, portable memory for AI agents.** The TypeScript SDK. Wire-compatible with
the Python package: a record signed in one verifies in the other.

```bash
npm install rememberkit
```

```ts
import { Memory, generateKeypair, verifyPack } from "rememberkit";

const { privateKey, publicKey } = generateKeypair();   // the signing key stays on-device
const mem = new Memory(privateKey, "agent-7", "user-123");

mem.remember({ seat: "aisle" }, { kind: "preference", scope: "travel", consent: "shareable" });
mem.remember({ homeCard: "**** 1234" }, { kind: "fact", scope: "payments", consent: "private" });

mem.recall({ scope: "travel" });                       // the live view, by topic
const pack = mem.share();                               // only consent >= "shareable" leaves
verifyPack(pack, { trustedKeys: [publicKey] }).valid;   // true
```

Correct a memory by superseding it, withdraw one with `forget` (a signed tombstone),
and hand a scoped, consent-filtered slice to another agent with `share`. Each record is
individually signed and content-addressed, so a single memory verifies on its own with
`verifyRecord` — memory moves with its provenance attached.

## Security model

A valid signature proves integrity, not authority. Pin the issuer with `trustedKeys`;
without it (and without `allowUnverifiedIssuer`) verification **fails closed** and never
throws on hostile input. Tamper-evident, not tamper-proof; consent is an advisory marker,
not access control. See [`../SECURITY.md`](../SECURITY.md).

Runs on Node 22.6+. License: MIT.
