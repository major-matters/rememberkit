"""
RememberKit v0 - governed, portable memory for AI agents.

The fifth question an agent raises, after who it is, what it may do, what it
spends, and what it did: what does it know and remember? RememberKit records
memory as signed, scoped, content-addressed records. Each one stands alone, so a
memory can move from one agent to another and still be verified.

    from rememberkit import Memory, generate_keypair, verify_pack

    key, pub = generate_keypair()                 # the signing key stays on-device
    mem = Memory(key, agent="agent-7", subject="user-123")
    mem.remember({"seat": "aisle"}, kind="preference", scope="travel", consent="shareable")
    mem.remember({"card": "declined at Acme"}, kind="observation", scope="payments")

    mem.recall(scope="travel")                     # the live view, by topic
    pack = mem.share(scope="travel")               # only the shareable records
    verify_pack(pack, trusted_keys=[pub])["valid"]  # True

A correction supersedes an old record; `forget` writes a signed tombstone. v0,
experimental. Tamper-evident, not tamper-proof, and consent is an advisory marker,
not access control (see verify.py). Fills the portable-agent-memory gap.
"""

from .memory import Memory, VERSION, CONSENT_LEVELS, build_record, record_id
from .signing import generate_keypair, public_from_seed, b64
from .verify import verify_record, verify_pack

__version__ = "0.0.1"

__all__ = [
    "Memory",
    "verify_record",
    "verify_pack",
    "generate_keypair",
    "public_from_seed",
    "build_record",
    "record_id",
    "b64",
    "VERSION",
    "CONSENT_LEVELS",
    "__version__",
]
