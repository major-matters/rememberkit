"""
Property-based tests (Hypothesis) for RememberKit. Run:
    pip install hypothesis
    PYTHONPATH=. python3 tests/test_properties.py
"""

import copy

from hypothesis import given, settings, strategies as st

from rememberkit import Memory, verify_record, verify_pack
from rememberkit.memory import record_id
from rememberkit.signing import b64, public_from_seed

seeds = st.binary(min_size=32, max_size=32)
# Payloads must be JSON-safe (numbers within JS's 2**53 range) — the documented
# constraint of any RFC 8785 canonicalization.
SAFE_INT = st.integers(min_value=-(2 ** 53 - 1), max_value=2 ** 53 - 1)
contents = st.dictionaries(st.text(max_size=8), SAFE_INT | st.text(max_size=20), max_size=4)
items = st.lists(st.tuples(st.text(max_size=12), contents), max_size=6)
json_values = st.recursive(
    st.none() | st.booleans() | st.integers() | st.text(max_size=10),
    lambda c: st.lists(c, max_size=4) | st.dictionaries(st.text(max_size=6), c, max_size=4),
    max_leaves=30,
)


def _build(seed, its):
    m = Memory(seed, "agent", "subject")
    for i, (scope, content) in enumerate(its):
        m.remember(content, kind="fact", scope=scope, timestamp=f"2026-01-01T00:00:{i:02d}Z")
    return m


@given(seeds, items)
def test_roundtrip_any_pack(seed, its):
    pub = b64(public_from_seed(seed))
    assert verify_pack(_build(seed, its).to_json(), trusted_keys=[pub])["valid"] is True


@given(seeds, items.filter(lambda a: len(a) >= 1))
def test_any_content_tamper_breaks(seed, its):
    pub = b64(public_from_seed(seed))
    data = _build(seed, its).to_json()
    d = copy.deepcopy(data)
    d["records"][0]["scope"] = str(d["records"][0]["scope"]) + "_x"  # change without re-signing
    assert verify_pack(d, trusted_keys=[pub])["valid"] is False


@given(seeds, seeds, st.text(max_size=12))
def test_forgery_iff_same_key(signer, trusted, scope):
    m = Memory(signer, "a", "s"); rec = m.remember({}, scope=scope)
    same = public_from_seed(signer) == public_from_seed(trusted)
    v = verify_record(rec, trusted_keys=[b64(public_from_seed(trusted))])
    assert v["valid"] == same


@given(seeds, items)
def test_single_record_verifies_standalone(seed, its):
    pub = b64(public_from_seed(seed))
    m = _build(seed, its)
    for rec in m.records:  # every record verifies on its own (portability)
        assert verify_record(rec, trusted_keys=[pub])["valid"] is True


@settings(max_examples=200)
@given(json_values)
def test_never_throws_on_garbage(j):
    assert verify_record(j, trusted_keys=["AAAA"])["valid"] in (True, False)
    assert verify_pack(j, trusted_keys=["AAAA"])["valid"] in (True, False)
    wrapped = {"records": j if isinstance(j, list) else [j]}
    assert verify_pack(wrapped, trusted_keys=["AAAA"])["valid"] in (True, False)


@given(st.dictionaries(st.text(min_size=1, max_size=6),
                       st.integers(min_value=-(2 ** 53 - 1), max_value=2 ** 53 - 1), max_size=6))
def test_id_is_key_order_invariant(content):
    kw = dict(subject="u", agent="a", kind="fact", scope="s", consent="private",
              timestamp="t", supersedes=None, revoked=False)
    a = record_id(content=content, **kw)
    reordered = {k: content[k] for k in reversed(list(content))}
    assert a == record_id(content=reordered, **kw)


if __name__ == "__main__":
    import sys
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    fails = 0
    for t in tests:
        try:
            t(); print(f"  PASS  {t.__name__}")
        except Exception as e:
            fails += 1; print(f"  FAIL  {t.__name__}: {type(e).__name__}: {str(e)[:160]}")
    print(f"\n{len(tests)-fails}/{len(tests)} property tests passed")
    sys.exit(1 if fails else 0)
