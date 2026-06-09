"""
The memory record: a signed, scoped, portable unit of agent memory.

Each record commits to its content, who it is about (subject), who recorded it
(agent), what it is about (scope/kind), and how it may be used (consent), then
signs that commitment. Because every record is individually signed and
content-addressed, a single memory can travel from one agent to another and still
be verified on its own (see `verify_record`). That is the portability guarantee:
memory moves without trusting the transport.

Record shape:

    {
      "version": "rememberkit/v0",
      "id": "base64 sha256 of the canonical content",   # content-addressed
      "subject": "user-123",          # whose memory this is (or null)
      "agent": "agent-7",             # which agent recorded it
      "kind": "preference",           # preference | fact | observation | note | ...
      "scope": "travel",              # topic/category, used to recall (or null)
      "consent": "private",           # private | shareable | public
      "content": { ... },             # arbitrary, JSON-serializable
      "timestamp": "2026-06-09T00:00:00Z",
      "supersedes": null,             # id of a record this replaces, or null
      "revoked": false,               # true = a tombstone that forgets `supersedes`
      "signature": {"alg": "Ed25519", "public_key": "...", "value": "..."}
    }

A correction is a new record with `supersedes` set to the old id. A `forget` is a
revoked record (a tombstone) whose `supersedes` points at what to drop. `recall`
returns the live view: latest, not superseded, not revoked.
"""

import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .canonical import canonicalize
from .signing import b64, public_from_seed, sign as _sign, unb64

VERSION = "rememberkit/v0"

# Recognized consent markers, least to most open. Free-form strings are allowed,
# but these are the ones `recall(max_consent=...)` understands as an ordering.
CONSENT_LEVELS = ("private", "shareable", "public")


def _now_iso() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def record_id(*, subject, agent, kind, scope, consent, content, timestamp, supersedes, revoked) -> str:
    """Deterministic base64 SHA-256 over a record's content.

    Uses RFC 8785 canonicalization so the id is identical across languages and
    re-serializations. The id is what gets signed."""
    body = {
        "version": VERSION,
        "subject": subject,
        "agent": agent,
        "kind": kind,
        "scope": scope,
        "consent": consent,
        "content": content,
        "timestamp": timestamp,
        "supersedes": supersedes,
        "revoked": revoked,
    }
    return b64(hashlib.sha256(canonicalize(body)).digest())


def build_record(*, subject, agent, kind, scope, consent, content, private_key,
                 timestamp=None, supersedes=None, revoked=False) -> Dict:
    timestamp = timestamp or _now_iso()
    rid = record_id(
        subject=subject, agent=agent, kind=kind, scope=scope, consent=consent,
        content=content, timestamp=timestamp, supersedes=supersedes, revoked=revoked,
    )
    signature = _sign(unb64(rid), private_key)  # sign the record's id
    return {
        "version": VERSION,
        "id": rid,
        "subject": subject,
        "agent": agent,
        "kind": kind,
        "scope": scope,
        "consent": consent,
        "content": content,
        "timestamp": timestamp,
        "supersedes": supersedes,
        "revoked": revoked,
        "signature": {
            "alg": "Ed25519",
            "public_key": b64(public_from_seed(private_key)),
            "value": b64(signature),
        },
    }


def _live_ids(records: List[Dict]) -> set:
    """Ids that are still in effect: not superseded by a later record, not revoked.

    A record is dropped if any record names it in `supersedes` (a correction or a
    tombstone replaces it), and a tombstone (revoked=True) is itself never live.
    Non-dict junk in the list is ignored rather than trusted."""
    superseded = {r.get("supersedes") for r in records
                  if isinstance(r, dict) and r.get("supersedes")}
    live = set()
    for r in records:
        if not isinstance(r, dict):
            continue
        if r.get("revoked"):
            continue
        if r.get("id") in superseded:
            continue
        live.add(r.get("id"))
    return live


class Memory:
    """A signed, portable memory store written by one agent.

    The signing key stays with the agent. Export with `to_json()` to move the
    store; each record carries its own signature so it survives the trip."""

    def __init__(self, private_key: Optional[bytes], agent: Optional[str],
                 subject: Optional[str] = None, records: Optional[List[Dict]] = None):
        self._key = private_key
        self.agent = agent
        self.subject = subject
        self.records: List[Dict] = list(records or [])

    def remember(self, content: Any, *, kind: str = "fact", scope: Optional[str] = None,
                 consent: str = "private", subject: Optional[str] = None,
                 supersedes: Optional[str] = None, timestamp: Optional[str] = None) -> Dict:
        """Record a new memory. Returns the signed record."""
        if self._key is None:
            raise ValueError("Memory has no signing key; cannot remember")
        record = build_record(
            subject=subject if subject is not None else self.subject,
            agent=self.agent,
            kind=kind,
            scope=scope,
            consent=consent,
            content=content if content is not None else {},
            private_key=self._key,
            timestamp=timestamp,
            supersedes=supersedes,
        )
        self.records.append(record)
        return record

    def forget(self, target_id: str, *, timestamp: Optional[str] = None) -> Dict:
        """Revoke a memory by id. Emits a signed tombstone that supersedes it.

        Revocation is itself a record, so it is portable and verifiable: a reader
        who has the tombstone can prove the memory was withdrawn."""
        if self._key is None:
            raise ValueError("Memory has no signing key; cannot forget")
        record = build_record(
            subject=self.subject,
            agent=self.agent,
            kind="tombstone",
            scope=None,
            consent="private",
            content={"forgets": target_id},
            private_key=self._key,
            timestamp=timestamp,
            supersedes=target_id,
            revoked=True,
        )
        self.records.append(record)
        return record

    def recall(self, *, scope: Optional[str] = None, kind: Optional[str] = None,
               subject: Optional[str] = None, min_consent: Optional[str] = None,
               include_revoked: bool = False) -> List[Dict]:
        """The records that are not superseded and not revoked, filtered.

        ("Latest" is not enforced by timestamp: a correction must explicitly
        `supersedes` the record it replaces. Two un-chained records for the same
        thing both stay live.)

        Filter by scope / kind / subject. `min_consent` keeps only records at or
        above a consent openness (e.g. min_consent='shareable' keeps 'shareable'
        and 'public', drops 'private'), for handing a scoped slice to another
        agent. A record whose own consent is not a recognized level is treated as
        the most private and dropped whenever `min_consent` is set.

        FAILS CLOSED: passing a `min_consent` that is not a recognized level
        raises ValueError rather than silently disabling the consent filter (which
        would leak private records). Non-dict junk in the store is ignored."""
        if min_consent is not None and min_consent not in CONSENT_LEVELS:
            raise ValueError(
                f"unrecognized min_consent {min_consent!r}; expected one of {CONSENT_LEVELS}")
        live = _live_ids(self.records)
        out = []
        floor = CONSENT_LEVELS.index(min_consent) if min_consent is not None else None
        for r in self.records:
            if not isinstance(r, dict):
                continue
            if not include_revoked and r.get("id") not in live:
                continue
            if r.get("revoked") and not include_revoked:
                continue
            if scope is not None and r.get("scope") != scope:
                continue
            if kind is not None and r.get("kind") != kind:
                continue
            if subject is not None and r.get("subject") != subject:
                continue
            if floor is not None:
                c = r.get("consent")
                if c not in CONSENT_LEVELS or CONSENT_LEVELS.index(c) < floor:
                    continue
            out.append(r)
        return out

    def to_json(self) -> Dict:
        """Export the portable memory pack (records only; no private key)."""
        return {"version": VERSION, "agent": self.agent, "subject": self.subject,
                "records": self.records}

    def share(self, *, scope: Optional[str] = None, min_consent: str = "shareable",
              subject: Optional[str] = "__store__") -> Dict:
        """A portable pack containing only the records cleared to leave this store.

        Defaults to consent 'shareable' or more open, so 'private' records stay
        behind. Optionally narrow to one scope. By default the pack is scoped to
        this store's `subject` (so a multi-subject store does not leak one
        subject's records to another's peer); pass `subject=None` to share across
        all subjects deliberately. The receiving agent can verify every record on
        its own."""
        subj = self.subject if subject == "__store__" else subject
        recs = self.recall(scope=scope, min_consent=min_consent, subject=subj)
        return {"version": VERSION, "agent": self.agent, "subject": self.subject, "records": recs}

    @classmethod
    def open(cls, data, private_key: Optional[bytes] = None,
             agent: Optional[str] = None, subject: Optional[str] = None) -> "Memory":
        """Re-open an exported pack. Pass private_key only if you intend to write."""
        records = data.get("records", []) if isinstance(data, dict) else list(data)
        if isinstance(data, dict):
            agent = agent if agent is not None else data.get("agent")
            subject = subject if subject is not None else data.get("subject")
        return cls(private_key, agent, subject, records)
