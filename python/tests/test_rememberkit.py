"""Unit tests for RememberKit: remember/recall, correction, forget, consent, verify."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from rememberkit import Memory, generate_keypair, verify_record, verify_pack, record_id


def make():
    key, pub = generate_keypair()
    return Memory(key, agent="agent-7", subject="user-123"), pub


def test_remember_and_recall():
    mem, _ = make()
    mem.remember({"seat": "aisle"}, kind="preference", scope="travel")
    mem.remember({"diet": "vegetarian"}, kind="preference", scope="food")
    assert len(mem.recall()) == 2
    travel = mem.recall(scope="travel")
    assert len(travel) == 1 and travel[0]["content"] == {"seat": "aisle"}
    assert mem.recall(kind="preference", scope="food")[0]["content"] == {"diet": "vegetarian"}


def test_correction_supersedes():
    mem, _ = make()
    first = mem.remember({"seat": "window"}, kind="preference", scope="travel")
    mem.remember({"seat": "aisle"}, kind="preference", scope="travel", supersedes=first["id"])
    live = mem.recall(scope="travel")
    assert len(live) == 1
    assert live[0]["content"] == {"seat": "aisle"}  # the correction wins


def test_forget_writes_tombstone_and_drops_record():
    mem, pub = make()
    r = mem.remember({"card": "1234"}, kind="observation", scope="payments")
    assert len(mem.recall(scope="payments")) == 1
    tomb = mem.forget(r["id"])
    assert tomb["revoked"] is True and tomb["supersedes"] == r["id"]
    assert mem.recall(scope="payments") == []          # forgotten
    # the tombstone itself is a real, verifiable record
    assert verify_record(tomb, trusted_keys=[pub])["valid"]


def test_share_filters_by_consent():
    mem, _ = make()
    mem.remember({"x": 1}, scope="travel", consent="private")
    mem.remember({"x": 2}, scope="travel", consent="shareable")
    mem.remember({"x": 3}, scope="travel", consent="public")
    shared = mem.share(scope="travel")                  # default min_consent="shareable"
    contents = sorted(r["content"]["x"] for r in shared["records"])
    assert contents == [2, 3]                           # private withheld


def test_portability_single_record_verifies_standalone():
    mem, pub = make()
    rec = mem.remember({"seat": "aisle"}, scope="travel", consent="shareable")
    # carry one record to another agent; it verifies without the rest of the store
    assert verify_record(rec, trusted_keys=[pub])["valid"]


def test_verify_pack_roundtrip():
    mem, pub = make()
    mem.remember({"a": 1}, scope="s1")
    mem.remember({"b": 2}, scope="s2")
    pack = mem.to_json()
    reopened = Memory.open(pack)
    assert verify_pack(reopened, trusted_keys=[pub])["valid"]
    assert verify_pack(pack, trusted_keys=[pub])["count"] == 2


def test_fail_closed_without_trusted_keys():
    mem, _ = make()
    rec = mem.remember({"a": 1})
    assert verify_record(rec)["valid"] is False          # no trusted_keys -> deny
    assert verify_pack(mem.to_json())["valid"] is False
    # explicit opt-out is honored
    assert verify_record(rec, allow_unverified_issuer=True)["valid"]


def test_tampered_content_detected():
    mem, pub = make()
    rec = mem.remember({"amount": 10}, scope="payments")
    rec["content"]["amount"] = 1000000                   # tamper after signing
    assert verify_record(rec, trusted_keys=[pub])["valid"] is False


def test_wrong_issuer_rejected():
    mem, _ = make()
    _, other_pub = generate_keypair()
    rec = mem.remember({"a": 1})
    assert verify_record(rec, trusted_keys=[other_pub])["valid"] is False


def test_hostile_input_never_raises():
    # Records: every junk shape is invalid (never a valid signed record).
    for junk in [None, 42, "str", [], {}, {"id": "x", "signature": 1}, {"signature": {"alg": "RSA"}}]:
        assert verify_record(junk, trusted_keys=["x"])["valid"] is False
    # Packs: non-container junk and a records-less object are malformed; an empty
    # list pack is validly empty. ({} has no 'records' key -> malformed, matching TS.)
    for junk in [None, 42, "str", {}]:
        assert verify_pack(junk, trusted_keys=["x"])["valid"] is False
    assert verify_pack([], trusted_keys=["x"])["valid"] is True
    assert verify_pack({"records": []}, trusted_keys=["x"])["valid"] is True


def test_recall_fails_closed_on_bad_min_consent():
    # Regression: an unrecognized min_consent must NOT disable the filter and leak
    # private records. It raises instead.
    mem, _ = make()
    mem.remember({"x": 1}, scope="s", consent="private")
    mem.remember({"x": 2}, scope="s", consent="shareable")
    for bad in ["Shareable", " public", "confidential", ""]:
        try:
            mem.recall(min_consent=bad)
            assert False, f"expected ValueError for min_consent={bad!r}"
        except ValueError:
            pass
    # share (which uses min_consent='shareable') still works and withholds private
    assert [r["content"]["x"] for r in mem.share(scope="s")["records"]] == [2]


def test_version_mismatch_rejected():
    mem, pub = make()
    rec = mem.remember({"a": 1})
    rec["version"] = "rememberkit/v999"            # claim a different schema version
    assert verify_record(rec, trusted_keys=[pub])["valid"] is False


def test_share_is_subject_scoped():
    key, pub = generate_keypair()
    mem = Memory(key, agent="agent-7", subject="user-A")
    mem.remember({"x": 1}, scope="s", consent="shareable")
    # a record about a different subject must not leave in user-A's share
    mem.remember({"x": 2}, scope="s", consent="shareable", subject="user-B")
    shared = mem.share(scope="s")                  # defaults to store subject user-A
    assert [r["subject"] for r in shared["records"]] == ["user-A"]
    # explicit cross-subject share is opt-in
    assert len(mem.share(scope="s", subject=None)["records"]) == 2


def test_non_dict_records_ignored_not_crashed():
    mem, pub = make()
    mem.remember({"a": 1}, scope="s")
    mem.records.append("junk")                     # hostile entry
    mem.records.append(None)
    assert len(mem.recall(scope="s")) == 1         # ignored, no crash


def test_id_is_deterministic():
    a = record_id(subject="u", agent="a", kind="fact", scope="s", consent="private",
                  content={"x": 1}, timestamp="2026-06-09T00:00:00Z", supersedes=None, revoked=False)
    b = record_id(subject="u", agent="a", kind="fact", scope="s", consent="private",
                  content={"x": 1}, timestamp="2026-06-09T00:00:00Z", supersedes=None, revoked=False)
    assert a == b


if __name__ == "__main__":
    import traceback
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    passed = 0
    for fn in fns:
        try:
            fn()
            print(f"  PASS {fn.__name__}")
            passed += 1
        except Exception:
            print(f"  FAIL {fn.__name__}")
            traceback.print_exc()
    print(f"\n{passed}/{len(fns)} passed")
    sys.exit(0 if passed == len(fns) else 1)
