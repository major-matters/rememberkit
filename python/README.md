# RememberKit · v0

**Governed, portable memory for AI agents.**

The fifth question an agent raises, after who it is (IdentityKit), what it may do
(MandateKit), what it spends (BudgetGuard), and what it did (WitnessKit): what does
it know and remember? RememberKit records memory as signed, scoped, content-addressed
records. Each one stands alone, so a memory can move from one agent to another and
still be verified. It is a governance layer for memory, not a vector database.

## Quick start

```python
from rememberkit import Memory, generate_keypair, verify_pack

key, public_key = generate_keypair()          # the signing key stays on-device
mem = Memory(key, agent="agent-7", subject="user-123")

mem.remember({"seat": "aisle"}, kind="preference", scope="travel", consent="shareable")
mem.remember({"home_card": "**** 1234"}, kind="fact", scope="payments", consent="private")

mem.recall(scope="travel")                     # the live view, by topic
pack = mem.share()                             # only consent >= "shareable" leaves
verify_pack(pack, trusted_keys=[public_key])["valid"]   # True
```

## What each piece does

- **`remember(content, *, kind, scope, consent, supersedes)`** writes a signed record.
- **`recall(*, scope, kind, subject, min_consent)`** returns the live view: latest,
  not superseded, not revoked. A correction is just a new record that `supersedes`
  an old id.
- **`forget(id)`** writes a signed tombstone that withdraws a memory. Revocation is
  itself a verifiable record.
- **`share(*, scope, min_consent)`** exports a portable pack of only the records
  cleared to leave (consent `shareable` or `public` by default; `private` stays).
- **`verify_record` / `verify_pack`** check integrity and a trusted issuer.

## Why "portable"

Every record is individually signed and content-addressed (its id is a SHA-256 over
its canonical content, RFC 8785). So a single memory carried to another agent verifies
on its own with `verify_record`, without trusting the transport or having the rest of
the store. Memory moves with its provenance attached.

## Security model

A valid signature proves **integrity, not authority**. You must pin the issuer: pass
`trusted_keys`. Without it (and without an explicit `allow_unverified_issuer=True`),
verification **fails closed**. Verification never throws on hostile input.

**Honest limitations (v0):**
- **Tamper-evident, not tamper-proof.** A holder of the signing key can rewrite or
  forge records under the same agent. External anchoring (a witness log) is the roadmap.
- **Consent is an advisory marker, not access control.** It tells a well-behaved reader
  how a memory may be used; it does not stop a hostile holder from reading content it
  already has.
- **Payloads must be JSON-safe** (numbers within 2⁵³), the limit of canonical JSON.

Full notes in [`../SECURITY.md`](../SECURITY.md).

## Install

```bash
pip install rememberkit
```

(Or run from source: `cd python && PYTHONPATH=. python3 ../demo.py`.)

## License

MIT.
