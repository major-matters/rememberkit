#!/usr/bin/env python3
"""RememberKit demo: governed, portable agent memory.

    cd python && PYTHONPATH=. python3 ../demo.py
"""

from rememberkit import Memory, generate_keypair, verify_record, verify_pack


def line(s=""):
    print(s)


def main():
    key, pub = generate_keypair()
    mem = Memory(key, agent="agent-7", subject="user-123")

    line("1. Remember a few things, scoped and with a consent marker")
    mem.remember({"seat": "window"}, kind="preference", scope="travel", consent="shareable")
    mem.remember({"diet": "vegetarian"}, kind="preference", scope="food", consent="shareable")
    mem.remember({"home_card": "**** 1234"}, kind="fact", scope="payments", consent="private")
    for r in mem.recall():
        line(f"   [{r['scope']:>8} · {r['consent']:>9}] {r['content']}")

    line()
    line("2. Correct a memory (a new record supersedes the old one)")
    first = mem.recall(scope="travel")[0]
    mem.remember({"seat": "aisle"}, kind="preference", scope="travel",
                 consent="shareable", supersedes=first["id"])
    line(f"   travel is now: {mem.recall(scope='travel')[0]['content']}")

    line()
    line("3. Share a scoped slice with another agent (private stays behind)")
    pack = mem.share()  # min_consent='shareable' by default
    line(f"   shareable records leaving the store: {len(pack['records'])} of {len(mem.recall())}")
    line(f"   payments (private) included? {'payments' in [r['scope'] for r in pack['records']]}")

    line()
    line("4. The other agent verifies every shared record on its own")
    verdict = verify_pack(pack, trusted_keys=[pub])
    line(f"   pack valid: {verdict['valid']} ({verdict['count']} records)")
    one = pack["records"][0]
    line(f"   a single record verifies standalone: {verify_record(one, trusted_keys=[pub])['valid']}")

    line()
    line("5. Forget a memory (a signed tombstone withdraws it)")
    pay = mem.recall(scope="payments")[0]
    mem.forget(pay["id"])
    line(f"   payments after forget: {mem.recall(scope='payments')}")

    line()
    line("6. Tamper detection and fail-closed issuer pinning")
    rec = mem.recall(scope="travel")[0]
    tampered = dict(rec, content={"seat": "first class"})
    line(f"   tampered record valid?      {verify_record(tampered, trusted_keys=[pub])['valid']}")
    line(f"   no trusted_keys (deny)?     {verify_record(rec)['valid']}")
    line(f"   correct issuer pinned?      {verify_record(rec, trusted_keys=[pub])['valid']}")


if __name__ == "__main__":
    main()
