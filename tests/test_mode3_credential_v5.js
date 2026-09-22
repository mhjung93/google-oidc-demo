// V5 커밋 둘·서명 메시지·리프 (설계 2026-09-21 §3). 외부 의존 없음(unit).
//   node tests/test_mode3_credential_v5.js
import assert from 'node:assert/strict';
import { buildBabyjub, buildPoseidon } from 'circomlibjs';
import {
  userCommit, sessionCommit, credMessageV5, compressPoint, normalizeAttrs,
  PEDERSEN_GENERATORS, SCALAR_MAX, DOMAIN_MODE3_CRED_V5, MAX_HEIGHT_MAX, ATTR_MAX,
} from '../lib/mode3_credential.js';
import { userLeaf, TAG_MODE3_USER } from '../lib/mode3_revocation.js';
import { TAG_SESSION, TAG_ACCOUNT, leafValue } from '../lib/imt_v2.js';

let failed = 0;
async function t(name, fn) {
  try { await fn(); console.log(`ok   ${name}`); }
  catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.message}`); }
}
const bj = await buildBabyjub();
const ps = await buildPoseidon();
const mul = (g, e) => bj.mulPointEscalar([bj.F.e(g[0]), bj.F.e(g[1])], e);
const uid = 11n, s_u = 22n, blind_u = 33n, attrs = [19n, 410n, 0n, 0n], arid = 44n, pk_i = 0x1234n, blind_s = 55n;

await t('userCommit = uid·G_UID + s_u·G_SU + Σattr·G_ATTR + blind_u·H (arid·pk_i 항 없음)', async () => {
  const { Cx, Cy, Cf } = await userCommit({ uid, s_u, blind_u, attrs });
  let acc = mul(PEDERSEN_GENERATORS.uid, uid);
  acc = bj.addPoint(acc, mul(PEDERSEN_GENERATORS.s_u, s_u));
  for (let i = 0; i < 4; i++) acc = bj.addPoint(acc, mul(PEDERSEN_GENERATORS[`attr${i}`], attrs[i]));
  acc = bj.addPoint(acc, mul(PEDERSEN_GENERATORS.blind, blind_u));
  assert.equal(Cx, bj.F.toObject(acc[0])); assert.equal(Cy, bj.F.toObject(acc[1]));
  assert.equal(Cf, ps.F.toObject(ps([Cx, Cy])));
  assert.equal(await compressPoint({ x: Cx, y: Cy }), Cf);
});

await t('sessionCommit = arid·G_ARID + pk_i·G_PKI + blind_s·H', async () => {
  const { Cx, Cy, Cf } = await sessionCommit({ arid, pk_i, blind_s });
  let acc = mul(PEDERSEN_GENERATORS.arid, arid);
  acc = bj.addPoint(acc, mul(PEDERSEN_GENERATORS.pk_i, pk_i));
  acc = bj.addPoint(acc, mul(PEDERSEN_GENERATORS.blind, blind_s));
  assert.equal(Cx, bj.F.toObject(acc[0])); assert.equal(Cy, bj.F.toObject(acc[1]));
  assert.equal(Cf, ps.F.toObject(ps([Cx, Cy])));
});

await t('blind_u 하나만 바꿔도 C_u 가 바뀐다; attrs 생략은 전부 0', async () => {
  const a = await userCommit({ uid, s_u, blind_u, attrs });
  const b = await userCommit({ uid, s_u, blind_u: blind_u + 1n, attrs });
  assert.notEqual(a.Cf, b.Cf);
  const c = await userCommit({ uid, s_u, blind_u });
  const d = await userCommit({ uid, s_u, blind_u, attrs: [0n, 0n, 0n, 0n] });
  assert.equal(c.Cf, d.Cf);
});

await t('범위: 스칼라가 2^250 이상이면 두 커밋 다 throw', async () => {
  await assert.rejects(() => userCommit({ uid, s_u: SCALAR_MAX, blind_u, attrs }), /2\^250/);
  await assert.rejects(() => sessionCommit({ arid, pk_i: SCALAR_MAX, blind_s }), /2\^250/);
  await assert.rejects(() => userCommit({ uid: 'x', s_u, blind_u, attrs }), /bigint/);
});

await t('normalizeAttrs: 2^64 이상은 throw, 2^64 − 1 은 통과 (스펙 2026-09-22 §4.1)', () => {
  assert.throws(() => normalizeAttrs([ATTR_MAX]), /attr0/);
  assert.deepEqual(normalizeAttrs([ATTR_MAX - 1n]), [ATTR_MAX - 1n, 0n, 0n, 0n]);
});

await t('credMessageV5 = Poseidon(D_V5, Cf_u, Cf_s, max_height, chainid, allowAgent); 도메인은 "MODE3CREDV5"', async () => {
  const m = await credMessageV5(1n, 2n, 1000n, 31337n, 0n);
  assert.equal(m, ps.F.toObject(ps([DOMAIN_MODE3_CRED_V5, 1n, 2n, 1000n, 31337n, 0n])));
  assert.equal(DOMAIN_MODE3_CRED_V5, 93461614427473393731524149n);
  assert.equal(DOMAIN_MODE3_CRED_V5, BigInt('0x' + Buffer.from('MODE3CREDV5').toString('hex')));
  assert.notEqual(m, await credMessageV5(2n, 1n, 1000n, 31337n, 0n), 'Cf_u 와 Cf_s 자리는 바뀌면 다른 메시지');
  assert.notEqual(m, await credMessageV5(1n, 2n, 1000n, 31337n, 1n));
  await assert.rejects(() => credMessageV5(1n, 2n, MAX_HEIGHT_MAX, 31337n, 0n), /2\^64/);
  await assert.rejects(() => credMessageV5(1n, 2n, 1000n, 31337n, 2n), /allowAgent/);
  await assert.rejects(() => credMessageV5(1n, 2n, 1000n, '31337', 0n), /bigint/);
});

await t('userLeaf = leafValue(4, Cf_u); 태그 4 는 Mode 2 의 1·2 와 다르다', async () => {
  const { Cf } = await userCommit({ uid, s_u, blind_u, attrs });
  assert.equal(TAG_MODE3_USER, 4n);
  assert.notEqual(TAG_MODE3_USER, TAG_SESSION); assert.notEqual(TAG_MODE3_USER, TAG_ACCOUNT);
  assert.equal(await userLeaf(Cf), await leafValue(4n, Cf));
  assert.ok((await userLeaf(Cf)) < (1n << 252n));
  assert.notEqual(await userLeaf(Cf), await userLeaf(Cf + 1n));
});

process.exit(failed === 0 ? 0 : 1);
