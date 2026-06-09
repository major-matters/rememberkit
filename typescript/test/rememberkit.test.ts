import { test } from "node:test";
import assert from "node:assert/strict";
import { Memory, generateKeypair, verifyRecord, verifyPack } from "../src/index.ts";

function make() {
  const { privateKey, publicKey } = generateKeypair();
  return { mem: new Memory(privateKey, "agent-7", "user-123"), pub: publicKey };
}

test("remember and recall by scope", () => {
  const { mem } = make();
  mem.remember({ seat: "aisle" }, { kind: "preference", scope: "travel" });
  mem.remember({ diet: "vegetarian" }, { kind: "preference", scope: "food" });
  assert.equal(mem.recall().length, 2);
  const travel = mem.recall({ scope: "travel" });
  assert.equal(travel.length, 1);
  assert.deepEqual(travel[0].content, { seat: "aisle" });
});

test("correction supersedes the old record", () => {
  const { mem } = make();
  const first = mem.remember({ seat: "window" }, { scope: "travel" });
  mem.remember({ seat: "aisle" }, { scope: "travel", supersedes: first.id });
  const live = mem.recall({ scope: "travel" });
  assert.equal(live.length, 1);
  assert.deepEqual(live[0].content, { seat: "aisle" });
});

test("forget writes a verifiable tombstone and drops the record", () => {
  const { mem, pub } = make();
  const r = mem.remember({ card: "1234" }, { scope: "payments" });
  const tomb = mem.forget(r.id);
  assert.equal(tomb.revoked, true);
  assert.equal(tomb.supersedes, r.id);
  assert.equal(mem.recall({ scope: "payments" }).length, 0);
  assert.equal(verifyRecord(tomb, { trustedKeys: [pub] }).valid, true);
});

test("share withholds private records", () => {
  const { mem } = make();
  mem.remember({ x: 1 }, { scope: "travel", consent: "private" });
  mem.remember({ x: 2 }, { scope: "travel", consent: "shareable" });
  mem.remember({ x: 3 }, { scope: "travel", consent: "public" });
  const shared = mem.share({ scope: "travel" });
  const xs = shared.records.map((r) => (r.content as any).x).sort();
  assert.deepEqual(xs, [2, 3]);
});

test("a single record verifies standalone (portability)", () => {
  const { mem, pub } = make();
  const rec = mem.remember({ seat: "aisle" }, { scope: "travel", consent: "shareable" });
  assert.equal(verifyRecord(rec, { trustedKeys: [pub] }).valid, true);
});

test("fail-closed without trustedKeys", () => {
  const { mem } = make();
  const rec = mem.remember({ a: 1 });
  assert.equal(verifyRecord(rec).valid, false);
  assert.equal(verifyPack(mem.toJSON()).valid, false);
  assert.equal(verifyRecord(rec, { allowUnverifiedIssuer: true }).valid, true);
});

test("tampered content is detected", () => {
  const { mem, pub } = make();
  const rec = mem.remember({ amount: 10 }, { scope: "payments" });
  (rec.content as any).amount = 1000000;
  assert.equal(verifyRecord(rec, { trustedKeys: [pub] }).valid, false);
});

test("wrong issuer is rejected", () => {
  const { mem } = make();
  const { publicKey: otherPub } = generateKeypair();
  const rec = mem.remember({ a: 1 });
  assert.equal(verifyRecord(rec, { trustedKeys: [otherPub] }).valid, false);
});

test("hostile input never throws", () => {
  for (const junk of [null, 42, "str", [], {}, { signature: 1 }, { signature: { alg: "RSA" } }]) {
    assert.equal(typeof verifyRecord(junk, { trustedKeys: ["x"] }).valid, "boolean");
  }
  assert.equal(verifyPack([], { trustedKeys: ["x"] }).valid, true);  // empty list pack is validly empty
  assert.equal(verifyPack({ records: [] }, { trustedKeys: ["x"] }).valid, true);
  assert.equal(verifyPack({}, { trustedKeys: ["x"] }).valid, false); // no records key -> malformed (matches Python)
  assert.equal(verifyPack(null, { trustedKeys: ["x"] }).valid, false);
});

test("recall fails closed on an unrecognized minConsent", () => {
  const { mem } = make();
  mem.remember({ x: 1 }, { scope: "s", consent: "private" });
  mem.remember({ x: 2 }, { scope: "s", consent: "shareable" });
  for (const bad of ["Shareable", " public", "confidential", ""]) {
    assert.throws(() => mem.recall({ minConsent: bad }), /unrecognized minConsent/);
  }
  assert.deepEqual(mem.share({ scope: "s" }).records.map((r) => (r.content as any).x), [2]);
});

test("version mismatch is rejected", () => {
  const { mem, pub } = make();
  const rec = mem.remember({ a: 1 });
  (rec as any).version = "rememberkit/v999";
  assert.equal(verifyRecord(rec, { trustedKeys: [pub] }).valid, false);
});

test("cross-language: a Python record with an ABSENT field verifies in TS (fix for id divergence)", () => {
  // Built in Python with the `kind` key omitted and its id computed over kind=null.
  // Before the fix, TS dropped the undefined key and recomputed a different id (valid:false).
  const PUB = "A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=";
  const REC = { version: "rememberkit/v0", id: "4EmanimJ1/kdOeYHmbSs9tFFyCzCruPT1wCfpHCBpdw=", subject: null, agent: "a", scope: null, consent: "public", content: { x: 1 }, timestamp: "t", supersedes: null, revoked: false, signature: { alg: "Ed25519", public_key: "A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=", value: "Ho8bk+FZg0clRNjrWeRHcGghueMLkqf083T9mTpm9XOMrQPd4bBniHH5SfkrlCXh/JF7dnJ5eplwmgyhv/N/Ag==" } };
  assert.equal((REC as any).kind, undefined);  // the key really is absent
  assert.equal(verifyRecord(REC, { trustedKeys: [PUB] }).valid, true);
});

test("cross-language: a Python-signed pack verifies in TypeScript", () => {
  const PUB = "A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=";
  const PACK = {
    version: "rememberkit/v0", agent: "agent-7", subject: "user-123",
    records: [
      { version: "rememberkit/v0", id: "EHMLs6V7xlxCCjNL7hlucX6FAri7tVQwrpGPVntdTiM=", subject: "user-123", agent: "agent-7", kind: "preference", scope: "travel", consent: "shareable", content: { seat: "aisle" }, timestamp: "2026-06-09T00:00:00Z", supersedes: null, revoked: false, signature: { alg: "Ed25519", public_key: "A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=", value: "9snHu14d8QuloJrBToait3jdeTEdOt3EOWa09tj8FYuv41gNDTPuain6B/6wcYYG3rJfRy4qSNzzjh+dHK/jDg==" } },
      { version: "rememberkit/v0", id: "wyQyE/0OMcg7tJRu+E+DVaIl5dOY8oTbzjLRXG2qHzc=", subject: "user-123", agent: "agent-7", kind: "fact", scope: "food", consent: "public", content: { diet: "vegetarian" }, timestamp: "2026-06-09T00:00:01Z", supersedes: null, revoked: false, signature: { alg: "Ed25519", public_key: "A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=", value: "NRP4DkNKeSm/PwLMoxAFzSKND6j34yuqY5OVmbiLd8VZzOzsncGNhA1Lz86MP5FWcXxZxK7rT2lZqu2tpy3EDw==" } },
    ],
  };
  assert.equal(verifyPack(PACK, { trustedKeys: [PUB] }).valid, true);
});
