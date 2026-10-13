// V11(2026-10-12) 유도식 — C_s 재정의·토큰 메시지·auid/auid_s/arid_s·PPID 순서·생성원 13개. 외부 의존 없음(unit).
//   node tests/test_mode3_credential_v11.js
import assert from 'node:assert/strict';
import { buildBabyjub, buildPoseidon, buildPedersenHash } from 'circomlibjs';
import {
  userCommit, sessionCommit, credMessageV11, compressPoint, auidOf, auidSOf, aridSOf, ppid, normalizeAttrs,
  PEDERSEN_GENERATORS, SCALAR_MAX, PK_I_MAX, MAX_HEIGHT_MAX, ATTR_SLOTS,
  DOMAIN_MODE3_CRED_V11, DOMAIN_MODE3_AUID, DOMAIN_MODE3_AUIDS, DOMAIN_MODE3_ARIDS,
} from '../lib/mode3_credential.js';
import { sessionLeaf, TAG_MODE3_SESSION } from '../lib/mode3_revocation.js';

let failed = 0;
async function t(name, fn) {
  try { await fn(); console.log(`ok   ${name}`); }
  catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.message}`); }
}
const be = (s) => BigInt('0x' + Buffer.from(s).toString('hex'));
const bj = await buildBabyjub();
const ps = await buildPoseidon();
const H = (arr) => ps.F.toObject(ps(arr));
const mul = (g, e) => bj.mulPointEscalar([bj.F.e(g[0]), bj.F.e(g[1])], e);
const uid = 11n, s_u = 22n, blind_u = 33n, attrs = [19n, 410n, 0n, 0n, 0n, 0n], arid = 44n, pk_i = 0x1234n, max_height = 1789000000n, r_s = 55n, r_rp = 66n;

await t('도메인 상수는 ASCII 빅엔디언이다', () => {
  assert.equal(DOMAIN_MODE3_CRED_V11, be('MODE3CREDV11'));
  assert.equal(DOMAIN_MODE3_AUID, be('MODE3AUID'));
  assert.equal(DOMAIN_MODE3_AUIDS, be('MODE3AUIDS'));
  assert.equal(DOMAIN_MODE3_ARIDS, be('MODE3ARIDS'));
  assert.equal(PK_I_MAX, 1n << 160n);
});

await t('생성원 13개 — uid,arid,s_u,pk_i,blind,attr0..3 = getBasePoint(0..8), attr4·attr5 = 9·10, exp = 11, rs = 12; 전부 곡선 위·부분군 안', async () => {
  const ph = await buildPedersenHash();
  const F = ph.babyJub.F;
  assert.equal(Object.keys(PEDERSEN_GENERATORS).length, 13);
  const idx = { uid: 0, arid: 1, s_u: 2, pk_i: 3, blind: 4, attr0: 5, attr1: 6, attr2: 7, attr3: 8, attr4: 9, attr5: 10, exp: 11, rs: 12 };
  for (const [name, i] of Object.entries(idx)) {
    const P = ph.getBasePoint('blake', i);
    assert.deepEqual([...PEDERSEN_GENERATORS[name]], [F.toObject(P[0]), F.toObject(P[1])], name);
    const Q = [bj.F.e(PEDERSEN_GENERATORS[name][0]), bj.F.e(PEDERSEN_GENERATORS[name][1])];
    assert.ok(bj.inCurve(Q) && bj.inSubgroup(Q), `${name} 곡선·부분군`);
  }
});

await t('userCommit 은 불변 — uid·G_UID + s_u·G_SU + Σattr·G_ATTR + blind_u·H', async () => {
  const { Cx, Cy, Cf } = await userCommit({ uid, s_u, blind_u, attrs });
  let acc = mul(PEDERSEN_GENERATORS.uid, uid);
  acc = bj.addPoint(acc, mul(PEDERSEN_GENERATORS.s_u, s_u));
  for (let i = 0; i < ATTR_SLOTS; i++) acc = bj.addPoint(acc, mul(PEDERSEN_GENERATORS[`attr${i}`], attrs[i]));
  acc = bj.addPoint(acc, mul(PEDERSEN_GENERATORS.blind, blind_u));
  assert.equal(Cx, bj.F.toObject(acc[0])); assert.equal(Cy, bj.F.toObject(acc[1]));
  assert.equal(Cf, H([Cx, Cy])); assert.equal(await compressPoint({ x: Cx, y: Cy }), Cf);
});

await t('normalizeAttrs: 길이 6 으로 0 패딩, 생략은 전부 0, 7개·2^64 이상·음수·배열 아님은 throw (회로 Num2Bits(64) 와 같은 상한)', () => {
  assert.equal(ATTR_SLOTS, 6);
  assert.deepEqual(normalizeAttrs(['1990', '410', '2']), [1990n, 410n, 2n, 0n, 0n, 0n]);
  assert.deepEqual(normalizeAttrs(undefined), [0n, 0n, 0n, 0n, 0n, 0n]);
  assert.throws(() => normalizeAttrs([1n, 2n, 3n, 4n, 5n, 6n, 7n]), /최대 6개/);
  assert.throws(() => normalizeAttrs([1n << 64n]), /2\^64/);
  assert.throws(() => normalizeAttrs(['-1']), /2\^64/);
  assert.throws(() => normalizeAttrs('12345'));
});

await t('V11 sessionCommit = pk_i·G_PK + max_height·G_EXP + r_s·G_RS + r_rp·H (arid 항 없음)', async () => {
  const { Cx, Cy, Cf } = await sessionCommit({ pk_i, max_height, r_s, r_rp });
  let acc = mul(PEDERSEN_GENERATORS.pk_i, pk_i);
  acc = bj.addPoint(acc, mul(PEDERSEN_GENERATORS.exp, max_height));
  acc = bj.addPoint(acc, mul(PEDERSEN_GENERATORS.rs, r_s));
  acc = bj.addPoint(acc, mul(PEDERSEN_GENERATORS.blind, r_rp));
  assert.equal(Cx, bj.F.toObject(acc[0])); assert.equal(Cy, bj.F.toObject(acc[1]));
  assert.equal(Cf, H([Cx, Cy]));
  const other = await sessionCommit({ pk_i, max_height: max_height + 1n, r_s, r_rp });
  assert.notEqual(other.Cf, Cf, 'max_height 가 커밋에 실린다');
  assert.notEqual((await sessionCommit({ pk_i, max_height, r_s: r_s + 1n, r_rp })).Cf, Cf, 'r_s 가 커밋에 실린다');
});

await t('sessionCommit 상한: pk_i ≥ 2^160, max_height ≥ 2^64, r_s·r_rp ≥ 2^250 은 거부', async () => {
  await assert.rejects(() => sessionCommit({ pk_i: PK_I_MAX, max_height, r_s, r_rp }), /2\^160/);
  await assert.rejects(() => sessionCommit({ pk_i, max_height: MAX_HEIGHT_MAX, r_s, r_rp }), /2\^64/);
  await assert.rejects(() => sessionCommit({ pk_i, max_height, r_s: SCALAR_MAX, r_rp }), /2\^250/);
  await assert.rejects(() => sessionCommit({ pk_i, max_height, r_s, r_rp: SCALAR_MAX }), /2\^250/);
  await assert.rejects(() => sessionCommit({ pk_i, max_height, r_s }), /r_rp/);
});

await t('credMessageV11 = Poseidon(D_V11, auid_s, arid_s, Cf_u, Cf_s, chainid, allowAgent); allowAgent 2 는 거부', async () => {
  const m = await credMessageV11(1n, 2n, 3n, 4n, 31337n, 1n);
  assert.equal(m, H([DOMAIN_MODE3_CRED_V11, 1n, 2n, 3n, 4n, 31337n, 1n]));
  await assert.rejects(() => credMessageV11(1n, 2n, 3n, 4n, 31337n, 2n), /allowAgent/);
  await assert.rejects(() => credMessageV11('1', 2n, 3n, 4n, 31337n, 0n), /bigint/);
});

await t('auidOf·auidSOf·aridSOf 는 태그가 붙은 Poseidon 이고, 같은 r_rp 라도 arid 가 다르면 auid_s 가 다르다(D7)', async () => {
  const a = await auidOf({ uid, s_u });
  assert.equal(a, H([DOMAIN_MODE3_AUID, uid, s_u]));
  assert.equal(await auidSOf({ auid: a, arid, r_rp }), H([DOMAIN_MODE3_AUIDS, a, arid, r_rp]));
  assert.equal(await aridSOf({ arid, r_rp }), H([DOMAIN_MODE3_ARIDS, arid, r_rp]));
  assert.notEqual(await auidSOf({ auid: a, arid, r_rp }), await auidSOf({ auid: a, arid: arid + 1n, r_rp }));
  assert.notEqual(await aridSOf({ arid, r_rp }), await aridSOf({ arid, r_rp: r_rp + 1n }));
  await assert.rejects(() => auidOf({ uid: SCALAR_MAX, s_u }), /2\^250/);
});

await t('PPID = Poseidon(uid, s_u, arid, chainid) — 옛 순서(uid, s_u, chainid, arid)와 다르다(D13)', async () => {
  const p = await ppid({ uid, s_u, arid, chainid: 31337n });
  assert.equal(p, H([uid, s_u, arid, 31337n]));
  assert.notEqual(p, H([uid, s_u, 31337n, arid]));
  await assert.rejects(() => ppid({ uid, s_u, arid }), /chainid/);
});

await t('세션 리프는 불변 — Poseidon(5, Cf_s)', async () => {
  assert.equal(TAG_MODE3_SESSION, 5n);
  assert.equal(await sessionLeaf(77n), H([5n, 77n]));
});

process.exit(failed === 0 ? 0 : 1);
