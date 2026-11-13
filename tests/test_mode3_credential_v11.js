// V11(2026-10-12) 유도식 — C_s 재정의·토큰 메시지·auid/auid_s/arid_s·PPID 순서·생성원 13개. 외부 의존 없음(unit).
//   node tests/test_mode3_credential_v11.js
import assert from 'node:assert/strict';
import { buildBabyjub, buildPoseidon, buildPedersenHash } from 'circomlibjs';
import {
  userCommit, sessionCommit, credMessageV11, compressPoint, auidOf, auidSOf, aridSOf, ppid, normalizeAttrs,
  PEDERSEN_GENERATORS, SCALAR_MAX, PK_I_MAX, MAX_HEIGHT_MAX, ATTR_SLOTS,
  DOMAIN_MODE3_CRED_V11, DOMAIN_MODE3_AUID, DOMAIN_MODE3_AUIDS, DOMAIN_MODE3_ARIDS,
  DOMAIN_MODE3_TAG, DOMAIN_MODE3_CTX_ISSUE, DOMAIN_MODE3_CTX_REG, DOMAIN_MODE3_CTX_SLOT, DOMAIN_MODE3_CTX_REVOKE,
  issueCtx, registerCtx, slotCtx, revokeSessionCtx, tagOf,
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
  assert.equal(DOMAIN_MODE3_AUID, be('MODE3AUID2'));   // 2026-11-13: uid 를 뺀 새 정의
  assert.equal(DOMAIN_MODE3_AUIDS, be('MODE3AUIDS'));
  assert.equal(DOMAIN_MODE3_ARIDS, be('MODE3ARIDS'));
  assert.equal(PK_I_MAX, 1n << 160n);
});

// 2026-11-13(스펙 2026-11-12 no-pk-u §2·§3.1): 요청 인증은 π_IdP 의 ctx·tag — 용도마다 다른 도메인.
await t('ctx·tag 도메인 상수는 ASCII 빅엔디언이고 서로 다르다', () => {
  assert.equal(DOMAIN_MODE3_TAG, be('MODE3TAG'));
  assert.equal(DOMAIN_MODE3_CTX_ISSUE, be('MODE3CTXISSUE'));
  assert.equal(DOMAIN_MODE3_CTX_REG, be('MODE3CTXREG'));
  assert.equal(DOMAIN_MODE3_CTX_SLOT, be('MODE3CTXSLOT'));
  assert.equal(DOMAIN_MODE3_CTX_REVOKE, be('MODE3CTXREVOKE'));
  assert.equal(new Set([DOMAIN_MODE3_TAG, DOMAIN_MODE3_CTX_ISSUE, DOMAIN_MODE3_CTX_REG, DOMAIN_MODE3_CTX_SLOT, DOMAIN_MODE3_CTX_REVOKE]).size, 5);
});
await t('ctx 넷 = 도메인이 앞에 붙은 Poseidon — 같은 숫자라도 용도가 다르면 값이 다르다', async () => {
  assert.equal(await issueCtx({ arid_s: 7n, chainid: 31337n, allowAgent: 1n, n: 5n }), H([DOMAIN_MODE3_CTX_ISSUE, 7n, 31337n, 1n, 5n]));
  assert.equal(await registerCtx({ n: 7n }), H([DOMAIN_MODE3_CTX_REG, 7n]));
  assert.equal(await slotCtx({ nonce: 7n }), H([DOMAIN_MODE3_CTX_SLOT, 7n]));
  assert.equal(await revokeSessionCtx({ Cf_s: 7n, bound: 3n, nonce: 9n }), H([DOMAIN_MODE3_CTX_REVOKE, 7n, 3n, 9n]));
  assert.notEqual(await registerCtx({ n: 7n }), await slotCtx({ nonce: 7n }), '등록용과 슬롯용은 같은 난수라도 다르다');
  assert.notEqual(await issueCtx({ arid_s: 7n, chainid: 31337n, allowAgent: 0n, n: 5n }), await issueCtx({ arid_s: 7n, chainid: 31337n, allowAgent: 1n, n: 5n }), 'allowAgent 가 ctx 에 든다');
  // 2026-11-13(사용자 결정): 발급 ctx 에 지갑이 뽑는 난수 n — RP 가 r_rp 를 되풀이해도(같은 arid_s) 요청마다 ctx·tag 가 다르다
  assert.notEqual(await issueCtx({ arid_s: 7n, chainid: 31337n, allowAgent: 0n, n: 5n }), await issueCtx({ arid_s: 7n, chainid: 31337n, allowAgent: 0n, n: 6n }), 'n 이 ctx 에 든다');
  assert.notEqual(await revokeSessionCtx({ Cf_s: 7n, bound: 3n, nonce: 9n }), await revokeSessionCtx({ Cf_s: 7n, bound: 2n, nonce: 9n }), 'bound 가 ctx 에 든다');
});
await t('ctx·tag 입력 검사: bigint 아님·음수·p 이상·allowAgent 2·bound 2^32 는 throw', async () => {
  const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
  await assert.rejects(() => issueCtx({ arid_s: 7n, chainid: 31337n, allowAgent: 2n, n: 5n }), /allowAgent/);
  await assert.rejects(() => issueCtx({ arid_s: '7', chainid: 31337n, allowAgent: 0n, n: 5n }), /arid_s/);
  await assert.rejects(() => issueCtx({ arid_s: 7n, chainid: 31337n, allowAgent: 0n }), /n 는/, 'n 없이는 만들지 못한다');
  await assert.rejects(() => issueCtx({ arid_s: 7n, chainid: 31337n, allowAgent: 0n, n: P }), /n 는/);
  await assert.rejects(() => registerCtx({ n: P }), /n /);
  await assert.rejects(() => slotCtx({ nonce: -1n }), /nonce/);
  await assert.rejects(() => revokeSessionCtx({ Cf_s: 7n, bound: 1n << 32n, nonce: 9n }), /bound/);
  await assert.rejects(() => revokeSessionCtx({ Cf_s: 7n, bound: 3, nonce: 9n }), /bound/);
  await assert.rejects(() => tagOf({ s_u: 1n << 250n, ctx: 5n }), /s_u/);
  await assert.rejects(() => tagOf({ s_u: 5n, ctx: P }), /ctx/);
});
await t('tagOf = Poseidon(T_TAG, s_u, ctx) — s_u 나 ctx 가 다르면 다르다', async () => {
  assert.equal(await tagOf({ s_u: 22n, ctx: 5n }), H([DOMAIN_MODE3_TAG, 22n, 5n]));
  assert.notEqual(await tagOf({ s_u: 22n, ctx: 5n }), await tagOf({ s_u: 23n, ctx: 5n }));
  assert.notEqual(await tagOf({ s_u: 22n, ctx: 5n }), await tagOf({ s_u: 22n, ctx: 6n }));
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
  const a = await auidOf({ s_u });
  assert.equal(a, H([DOMAIN_MODE3_AUID, s_u]));   // 2026-11-13(스펙 random-salt R10): uid 가 식에 없다
  assert.equal(DOMAIN_MODE3_AUID, 365084431357309404922930n);   // ASCII "MODE3AUID2"
  assert.equal(DOMAIN_MODE3_AUID, BigInt('0x' + Buffer.from('MODE3AUID2').toString('hex')));
  assert.notEqual(await auidOf({ s_u: s_u + 1n }), a);
  assert.equal(await auidSOf({ auid: a, arid, r_rp }), H([DOMAIN_MODE3_AUIDS, a, arid, r_rp]));
  assert.equal(await aridSOf({ arid, r_rp }), H([DOMAIN_MODE3_ARIDS, arid, r_rp]));
  assert.notEqual(await auidSOf({ auid: a, arid, r_rp }), await auidSOf({ auid: a, arid: arid + 1n, r_rp }));
  assert.notEqual(await aridSOf({ arid, r_rp }), await aridSOf({ arid, r_rp: r_rp + 1n }));
  await assert.rejects(() => auidOf({ s_u: SCALAR_MAX }), /2\^250/);
});

await t('PPID = Poseidon(s_u, arid, chainid) — uid 가 식에 없다(2026-11-13 스펙 random-salt R9); arid·chainid 가 다르면 다르다', async () => {
  const p = await ppid({ s_u, arid, chainid: 31337n });
  assert.equal(p, H([s_u, arid, 31337n]));
  assert.notEqual(p, H([s_u, 31337n, arid]));
  assert.notEqual(p, await ppid({ s_u, arid: arid + 1n, chainid: 31337n }));
  assert.notEqual(p, await ppid({ s_u, arid, chainid: 1n }));
  assert.notEqual(p, await ppid({ s_u: s_u + 1n, arid, chainid: 31337n }));
  await assert.rejects(() => ppid({ s_u, arid }), /chainid/);
});

await t('세션 리프 = (Poseidon(5, Cf_s) mod 2^220)·2^32 + bound — 태그 5 는 불변', async () => {
  assert.equal(TAG_MODE3_SESSION, 5n);
  const hPrime = H([5n, 77n]) & ((1n << 220n) - 1n);
  assert.equal(await sessionLeaf(77n, 0n), hPrime << 32n);
  assert.equal(await sessionLeaf(77n, 3n), (hPrime << 32n) + 3n);
  await assert.rejects(() => sessionLeaf(77n), /bound/);   // 옛 한 인자 호출은 거부
});

process.exit(failed === 0 ? 0 : 1);
