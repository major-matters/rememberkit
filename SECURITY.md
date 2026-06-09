# RememberKit — Security

## Threat model

RememberKit records what an AI agent knows and remembers, in a form that carries its
provenance and resists after-the-fact rewriting as it moves between agents. The
adversary wants to alter a remembered fact, forge one, pass off one agent's memory as
another's, present a withdrawn memory as still live, or use a memory in a way its
subject did not consent to.

## What it detects

| Attack | Caught by |
|---|---|
| Alter a record's content | id recomputation (content no longer matches its id) |
| Forge a record | issuer pinning (signer not in `trusted_keys`) |
| Pass off another agent's memory | the `agent` field is signed; the issuer key must be trusted |
| Present a stale, corrected memory | `recall` returns the live view; a superseding record wins |
| Replay a withdrawn memory | a signed tombstone (`forget`) marks it revoked |
| Malformed / hostile input | returns a verdict, never throws |

## Security posture (borrowed from MandateKit / WitnessKit reviews)

- **Issuer pinning, fail-closed.** A valid signature proves integrity, not authority.
  `verify_record` and `verify_pack` require `trusted_keys` and deny without it unless
  you explicitly pass `allow_unverified_issuer=True`.
- **Deterministic, cross-language hashing.** RFC 8785 (JCS) + SHA-256, byte-identical
  in Python and TypeScript, so a record signed in one verifies in the other.
- **Vetted crypto.** Constant-time Ed25519 via `cryptography` (Python) / Node's built-in
  crypto (TS); a pure-Python reference is a warned fallback only.
- **Never throws.** Property-based tests fuzz the verifier with arbitrary input; every
  path returns a verdict.

## Known limitations (by design, v0)

- **Tamper-evident, not tamper-proof.** The signing key-holder can re-sign rewritten
  records or forge new ones under the same agent. Preventing that requires external
  anchoring — periodically publishing state to a witness or transparency log. Roadmap.
- **Consent is advisory, not enforcement.** The `consent` marker tells a well-behaved
  reader how a memory may be used and lets `share` withhold private records. It does
  not stop a hostile holder from reading content it already possesses. Real enforcement
  belongs at the store/transport boundary, paired with MandateKit.
- **Dropping is not detectable from a pack alone.** An agent that controls a pack can
  omit a record (including a tombstone). Detecting omission needs an anchored set hash,
  the same roadmap item as WitnessKit truncation. A consequence: `verify_pack` on an
  **empty** pack returns `valid: true, count: 0` (nothing to verify is not a failure).
  Callers MUST check `count`, not `valid` alone, when completeness matters.
- **`recall` returns the non-superseded, non-revoked set, not a timestamp-ordered
  "latest".** A correction only wins if it explicitly `supersedes` the record it
  replaces; two un-chained records for the same thing both stay live.
- **Payloads must be JSON-safe** (numbers within 2⁵³), the limit of canonical JSON.
- **Not independently audited.** Automated tooling and property tests are not a
  substitute for a third-party audit.

## Hardening notes (v0 adversarial review)

A tier 1-2 adversarial review (multiple independent reviewers, each finding verified
against the code) was run before release. Fixed and regression-tested:

- **Cross-language id divergence (high).** The TS verifier left `kind`/`consent`/`content`/
  `timestamp` uncoerced, so a record with an absent field hashed differently than in
  Python (which maps absent to `null`), letting a hand-crafted record verify in one SDK
  and not the other (an equivocation primitive). Both verifiers now coerce every
  id-contributing field identically; a cross-language conformance vector locks it.
- **Consent boundary failing open (high).** `recall(min_consent=...)` silently disabled
  the consent filter on an unrecognized level, leaking `private` records on the export
  path. It now **fails closed** (raises) in both languages.
- **`version` was unsigned and unchecked.** Verifiers now reject a record whose
  top-level `version` does not match the supported schema version.
- **Verifier parity and robustness.** A records-less pack object is now malformed in both
  languages (was vacuously valid in Python); non-dict junk in a store is ignored rather
  than crashing `recall`; `share` is scoped to the store's subject by default so a
  multi-subject store does not leak one subject's records to another's peer.

## Reporting

This is a pre-release v0 prototype. Do not rely on it for anything that matters yet.

## Audit status (v0)

This is a v0 release. It has been hardened with property-based tests and static analysis,
and reuses the same Ed25519 + RFC 8785 core as the other Major Labs primitives, but it has
**not** had a third-party security audit. Treat it accordingly for anything high-stakes.

## Security review welcome

We actively want researcher eyes on this. If you find a fail-open, a signature bypass, a
way to pass off one agent's memory as another's, or any way to defeat a guarantee in this
document, please open an issue. Credit given. The shared crypto core (Ed25519 + RFC 8785
canonicalization) and the record/pack verification are the highest-value targets.
