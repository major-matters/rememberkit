"""
Record and pack verification.

A memory record is self-contained: recompute its id from its content, confirm the
id still matches, and confirm a trusted issuer signed it. Because records stand
alone, a single one carried between agents verifies with `verify_record` without
the rest of the store.

SECURITY MODEL (borrowed from MandateKit / WitnessKit):
  * A valid signature proves integrity, not authority. You MUST pin the issuer:
    pass `trusted_keys=[agent_public_key]`. Without it (and without an explicit
    `allow_unverified_issuer=True`), verification FAILS CLOSED.
  * Verification never raises. Malformed or hostile input returns a verdict.

LIMITATIONS (honest, v0):
  * Tamper-EVIDENT, not tamper-proof. A holder of the signing key can rewrite any
    record (re-sign it) or forge new ones under the same agent. Detecting that a
    record was withdrawn relies on the tombstone being present; an agent can drop
    a record from a pack it controls. Pinning state to an external anchor (a
    witness log) is the roadmap defense.
  * Consent is an advisory marker the writer asserts, not an access control. It
    tells a well-behaved reader how a memory may be used; it does not stop a
    hostile holder from reading content it already possesses.
"""

import base64
from typing import Dict, Iterable, Optional, Set, Union

from .memory import record_id, VERSION
from .signing import unb64, verify as _verify

TrustedKeys = Union[str, bytes, Iterable[Union[str, bytes]]]


def _normalize_trusted(trusted_keys: Optional[TrustedKeys]) -> Optional[Set[str]]:
    if trusted_keys is None:
        return None
    if isinstance(trusted_keys, (str, bytes, bytearray)):
        trusted_keys = [trusted_keys]
    out: Set[str] = set()
    for k in trusted_keys:
        out.add(base64.b64encode(k).decode("ascii") if isinstance(k, (bytes, bytearray)) else k)
    return out


def _record_result(valid: bool, reason: str) -> Dict:
    return {"valid": valid, "reason": reason}


def verify_record(
    record,
    *,
    trusted_keys: Optional[TrustedKeys] = None,
    allow_unverified_issuer: bool = False,
) -> Dict:
    """Verify a single memory record stands on its own and a trusted issuer signed it."""
    trusted = _normalize_trusted(trusted_keys)
    if trusted is None and not allow_unverified_issuer:
        return _record_result(False,
                              "no trusted issuer keys supplied: pass trusted_keys=[...] (recommended) "
                              "or allow_unverified_issuer=True")
    try:
        if not isinstance(record, dict):
            return _record_result(False, "record is not an object")
        if record.get("version") != VERSION:
            return _record_result(False, f"unsupported or mismatched record version: {record.get('version')!r}")
        recomputed = record_id(
            subject=record.get("subject"), agent=record.get("agent"),
            kind=record.get("kind"), scope=record.get("scope"),
            consent=record.get("consent"), content=record.get("content"),
            timestamp=record.get("timestamp"), supersedes=record.get("supersedes"),
            revoked=record.get("revoked", False),
        )
        if recomputed != record.get("id"):
            return _record_result(False, "content tampered: id does not match")
        sig = record.get("signature")
        if not isinstance(sig, dict) or sig.get("alg") != "Ed25519":
            return _record_result(False, "missing or unsupported signature")
        pub = sig.get("public_key")
        if trusted is not None and pub not in trusted:
            return _record_result(False, "signer is not in the trusted-issuer set")
        if not _verify(unb64(sig.get("value", "")), unb64(record["id"]), unb64(sig.get("public_key", ""))):
            return _record_result(False, "invalid signature")
        return _record_result(True, "record valid")
    except Exception as ex:  # hostile input must never crash verification
        return _record_result(False, f"malformed record: {type(ex).__name__}")


def verify_pack(
    pack,
    *,
    trusted_keys: Optional[TrustedKeys] = None,
    allow_unverified_issuer: bool = False,
) -> Dict:
    """Verify every record in an exported pack. Returns a verdict with counts.

    `valid` is True only if every record verifies. `broken_at` is the index of the
    first record that failed, or None."""
    if hasattr(pack, "records"):
        records = pack.records
    elif isinstance(pack, dict):
        records = pack.get("records")          # missing 'records' key is malformed, not empty-valid
    elif isinstance(pack, list):
        records = pack
    else:
        return {"valid": False, "count": 0, "broken_at": None, "reason": "malformed: not a pack"}
    if not isinstance(records, list):
        return {"valid": False, "count": 0, "broken_at": None, "reason": "malformed: records is not a list"}

    trusted = _normalize_trusted(trusted_keys)
    if trusted is None and not allow_unverified_issuer:
        return {"valid": False, "count": len(records), "broken_at": None,
                "reason": "no trusted issuer keys supplied: pass trusted_keys=[...] (recommended) "
                          "or allow_unverified_issuer=True"}

    for i, r in enumerate(records):
        verdict = verify_record(r, trusted_keys=trusted_keys,
                                allow_unverified_issuer=allow_unverified_issuer)
        if not verdict["valid"]:
            return {"valid": False, "count": len(records), "broken_at": i, "reason": verdict["reason"]}
    return {"valid": True, "count": len(records), "broken_at": None, "reason": "pack intact"}
