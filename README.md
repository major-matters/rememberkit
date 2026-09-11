# RememberKit · v0

[![MCP Surface Check: low surface](https://img.shields.io/badge/MCP_Surface_Check-low-4FA86A)](https://majorlabs.co/security)

[![CI](https://github.com/major-matters/rememberkit/actions/workflows/ci.yml/badge.svg)](https://github.com/major-matters/rememberkit/actions/workflows/ci.yml)

> ⚠️ **Experimental — unaudited, not for production.** A v0 research prototype with
> no third-party security audit. The on-the-wire format will change.

**Governed, portable memory for AI agents.**

An agent raises five questions every time it acts. Four already have a kit:
who it is (**IdentityKit**), what it may do (**MandateKit**), what it spends
(**BudgetGuard**), and what it did (**WitnessKit**). RememberKit answers the fifth:
**what does it know and remember?**

It records memory as **signed, scoped records**. Each record carries its content,
who it is about, which agent recorded it, what it is about, and how it may be used,
then signs that. Because every record is individually signed and content-addressed,
a single memory can travel from one agent to another and still be verified on its
own. That is the point: memory moves **with its provenance attached**, not as an
unverifiable blob inside one vendor's store.

It ships in **Python** and **TypeScript**, with byte-compatible records (a record
signed in one verifies in the other).

> v0 fills the **portable-agent-memory** gap: the part of the agentic stack where,
> today, commerce-relevant memory is locked inside whichever model holds it. This is
> a schema and a verifier, not a database.

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

Correct a memory by superseding it, withdraw one with `forget` (a signed tombstone),
and hand a scoped, consent-filtered slice to another agent with `share`. Tamper with
any record, or present one signed by an untrusted key, and verification returns
`valid: False` with the reason.

## How it works

Each record's id is a SHA-256 over its canonical content (RFC 8785), and the agent
signs that id with Ed25519. `recall` returns the live view: the latest record for a
thing, dropping anything superseded or revoked. Verification recomputes the id,
checks the signature, and confirms a **trusted issuer** signed it.

## Security model

A valid signature proves **integrity, not authority**. You must pin the issuer: pass
`trusted_keys` / `trustedKeys`. Without it (and without an explicit
`allow_unverified_issuer`), verification **fails closed**. (Borrowed from MandateKit
and WitnessKit's reviews.) Verification never throws on hostile input.

**Honest limitations (v0):**
- **Tamper-evident, not tamper-proof.** The signing key-holder can rewrite or forge
  records under the same agent. True append-only-ness needs external anchoring — a
  witness / transparency log — on the roadmap.
- **Consent is an advisory marker, not access control.** It signals how a memory may
  be used; it does not stop a holder from reading content it already possesses.
- **Payloads must be JSON-safe** (numbers within 2⁵³), the inherent limit of canonical
  JSON.

Full notes in [`SECURITY.md`](SECURITY.md).

## Layout

```
rememberkit/
  python/        # pip-installable package + tests
  typescript/    # npm package, runs on Node 22+
  LICENSE        # MIT
```

Try it: `cd python && PYTHONPATH=. python3 ../demo.py`

---

## The accountability stack, September 2026

This year's frontier launches arrived alongside rogue-agent incidents that investigators struggled to attribute, and a written admission from inside the labs that runtime monitoring is degrading. The accountability primitives those events call for are what this suite implements:

> **[IdentityKit](https://github.com/major-matters/identitykit)** says who the agent is. **[MandateKit](https://github.com/major-matters/mandatekit)** says what it may do. **[BudgetGuard](https://github.com/major-matters/budget-guard)** caps what it spends. **[WitnessKit](https://github.com/major-matters/witnesskit)** proves what it did. **[RememberKit](https://github.com/major-matters/rememberkit)** governs what it remembers.

The [MM Control Stack Compact](https://www.majormatters.co/p/open-letter-control-stack-compact) (September 2026) proposes six verifiable commitments for frontier-AI accountability. Attributable agents and contractually bounded authority need running code, not pledges. This suite is a working v0 of that layer.

## License

MIT.
