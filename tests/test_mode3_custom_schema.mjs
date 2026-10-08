// 사용자 정의 속성 스키마(CIA_ATTR_SCHEMA_FILE)로 띄운 격리 Mode 3 스택 — 최종 리뷰 I2(2026-10-07). (chain 그룹)
//   node tests/test_mode3_custom_schema.mjs
//
// 배경: 데모 계정 profile 은 기본 스키마의 이름(birthYear·country)으로 적혀 있어, 그 이름이 없거나 다른 스키마로 띄우면 CIA 가
// 처리되지 않은 rejection 으로 죽었다. 그래서 RP 의 AttrGate 가드(birthYear≠0 또는 country≠1 이면 배포 건너뜀)와 predicate_unavailable
// 경로가 실제로는 도달 불가였다. 여기서는 두 스키마로 스택을 띄워 그 경로를 끝까지 돌린다.
//   (가) country 를 슬롯 2 로 옮긴 스키마 — AttrGate 건너뜀, 집합 술어는 set.slot 2(d.sel 3)로 통과
//   (나) country 가 없는 스키마 — require.countrySet 은 predicate_unavailable
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { startIsolatedMode3Stack } from './helpers/isolated_mode3_stack.mjs';
import { startIsolatedCia } from './helpers/isolated_cia.mjs';
import { VKEY_PATH } from '../lib/mode3_wallet.js';
import { loadSchema } from '../lib/mode3_attr_schema.js';

const j = (o) => JSON.stringify(o);
let failed = 0;
async function t(name, fn) {
  try { await fn(); console.log(`ok   ${name}`); }
  catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.message}`); }
}

assert.ok(fs.existsSync(VKEY_PATH), `pi_cred vkey 없음: ${VKEY_PATH} (build/mode3 산출물 필요)`);

const UNUSED = { type: 'unused' };
// 데모 계정(testuser KR·alice US)이 인코딩되도록 US 를 넣는다 — 없으면 CIA 가 기동을 거부한다(아래 마지막 케이스).
const SCHEMA_A = { id: 'zkd-attrs-country2', version: 1, slots: [
  { name: 'birthYear', label: '출생연도', type: 'int', min: 1900, max: 2100 },
  { name: 'extra1', label: '예비 1', type: 'string' },
  { name: 'country', label: '국가', type: 'enum', values: { KR: 410, JP: 392, US: 840 } },
  UNUSED, UNUSED, UNUSED,
] };
const SCHEMA_B = { id: 'zkd-attrs-nocountry', version: 1, slots: [
  { name: 'birthYear', label: '출생연도', type: 'int', min: 1900, max: 2100 },
  { name: 'extra1', label: '예비 1', type: 'string' },
  { name: 'extra2', label: '예비 2', type: 'string' },
  UNUSED, UNUSED, UNUSED,
] };
const SCHEMA_C = { ...SCHEMA_A, id: 'zkd-attrs-nous', slots: SCHEMA_A.slots.map((s, i) => (i === 2 ? { ...s, values: { KR: 410, JP: 392 } } : s)) };

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mode3-custom-schema-'));
const fileOf = (name, schema) => { const f = path.join(dir, `${name}.json`); fs.writeFileSync(f, JSON.stringify(schema)); return f; };

/** 지갑 등록 → (술어를 실은) 지갑 로그인 → RP 로그인(require). 페이지가 보내는 본문과 같은 모양. */
async function loginWithRequire(stack, { disclose = null, set = null, require }) {
  const { wallet, rp } = stack;
  const info = (await rp.get('/api/mode3/rp_info')).body;
  const ch = (await rp.post('/api/mode3/challenge')).body;
  assert.ok(ch.r_s, j(ch));
  const w = await stack.withRelay(() => wallet.post('/wallet/login', { arid: info.arid, origin: info.origin, cert_s: info.cert_s, pk_trace: info.pk_trace, r_s: ch.r_s, allowAgent: '0', factoryAddress: ch.factoryAddress, attrGateAddress: ch.attrGateAddress, ...(disclose ? { disclose } : {}), ...(set ? { set } : {}) }, { Origin: rp.origin }));
  assert.equal(w.status, 200, j(w.body));
  const r = await rp.post('/api/mode3/login', { r_s: ch.r_s, proof: w.body.proof, publicSignals: w.body.publicSignals, sig: w.body.sig, require });
  return { wallet: w.body, rp: r.body, info };
}

try {
  await t('(가) country 를 슬롯 2 로 옮긴 스키마: CIA·지갑이 그 스키마를 공개, RP 는 AttrGate 를 건너뛰고(attrGateAddress null), set.slot 2 로그인은 require 를 통과', async () => {
    const want = loadSchema(SCHEMA_A).hash;
    const stack = await startIsolatedMode3Stack({ ciaEnv: { CIA_ATTR_SCHEMA_FILE: fileOf('a', SCHEMA_A) }, rpEnv: { MODE3_ALLOWED_COUNTRIES: 'KR,JP', MODE3_CHALLENGE_TTL_MS: '12000' } });
    try {
      const { cia, wallet, rp } = stack;
      const cs = (await cia.get('/cia/attr_schema')).body;
      assert.equal(cs.schema.id, 'zkd-attrs-country2'); assert.equal(cs.hash, want);
      const ws = await wallet.get('/wallet/attr_schema');
      assert.equal(ws.status, 200); assert.equal(ws.body.hash, want); assert.equal(ws.body.source, 'cia');
      assert.match(rp.log(), /AttrGate 배포를 건너뛴다/);
      const info = (await rp.get('/api/mode3/rp_info')).body;
      assert.equal(info.attrGateAddress, null);
      assert.deepEqual(info.predicates.attrSchema, { id: 'zkd-attrs-country2', version: 1, hash: want });
      assert.deepEqual(info.predicates.allowedCountries, ['410', '392']); assert.deepEqual(info.predicates.allowedCountryNames, ['KR', 'JP']);
      assert.equal(info.predicates.birthYearMin, '1900');
      const reg = await wallet.post('/wallet/register', { uid: '12345', pwd: 'password123' });
      assert.equal(reg.status, 201, j(reg.body));
      assert.deepEqual(reg.body.attrs, ['1990', '0', '410', '0', '0', '0'], '데모 profile 이 사용자 정의 스키마의 슬롯으로 인코딩됐다');
      assert.deepEqual(reg.body.profile, { birthYear: '1990', country: 'KR' });
      const year = new Date().getUTCFullYear();
      const r = await loginWithRequire(stack, {
        disclose: [{ lo: info.predicates.birthYearMin, hi: String(year - Number(info.predicates.minAge)) }, null, null, null],
        set: { slot: 2, members: info.predicates.allowedCountries },
        require: { countrySet: true, minAge: true },
      });
      assert.equal(r.wallet.disclosure.set.sel, '3', 'set.slot 2 → d.sel 3');
      assert.equal(r.rp.ok, true, j(r.rp));
      assert.equal(r.rp.disclosure.set.root, info.predicates.allowedCountriesRoot);
    } finally { await stack.stop(); }
  });

  await t('(나) country 가 없는 스키마: 지갑은 그 스키마를 돌려주고, require.countrySet 로그인은 predicate_unavailable', async () => {
    const want = loadSchema(SCHEMA_B).hash;
    const stack = await startIsolatedMode3Stack({ ciaEnv: { CIA_ATTR_SCHEMA_FILE: fileOf('b', SCHEMA_B) }, rpEnv: { MODE3_CHALLENGE_TTL_MS: '12000' } });
    try {
      const { cia, wallet, rp } = stack;
      assert.equal((await cia.get('/cia/attr_schema')).body.schema.id, 'zkd-attrs-nocountry');
      const ws = await wallet.get('/wallet/attr_schema');
      assert.equal(ws.status, 200); assert.equal(ws.body.hash, want); assert.equal(ws.body.source, 'cia');
      assert.match(rp.log(), /AttrGate 배포를 건너뛴다/);
      assert.equal((await rp.get('/api/mode3/rp_info')).body.attrGateAddress, null);
      const reg = await wallet.post('/wallet/register', { uid: '12345', pwd: 'password123' });
      assert.equal(reg.status, 201, j(reg.body));
      assert.deepEqual(reg.body.attrs, ['1990', '0', '0', '0', '0', '0']); assert.deepEqual(reg.body.profile, { birthYear: '1990' }, '스키마에 없는 country 는 버렸다');
      const r = await loginWithRequire(stack, { require: { countrySet: true } });
      assert.deepEqual(r.rp, { ok: false, reason: 'predicate_unavailable' });
    } finally { await stack.stop(); }
  });

  await t('데모 계정 profile 을 인코딩할 수 없는 스키마(US 없음 — alice)는 CIA 가 기동 거부(스택 트레이스가 아니라 사유 한 줄)', async () => {
    let cia;
    try { cia = await startIsolatedCia({ env: { CIA_ATTR_SCHEMA_FILE: fileOf('c', SCHEMA_C) } }); }
    catch (e) { assert.match(e.message, /기동 거부: 데모 계정 속성이 스키마와 맞지 않는다 — alice/, e.message); return; }
    await cia.stop();
    assert.fail('기동이 거부돼야 하는데 떠 버렸다');
  });
} finally {
  fs.rmSync(dir, { recursive: true, force: true });
}
process.exit(failed === 0 ? 0 : 1);
