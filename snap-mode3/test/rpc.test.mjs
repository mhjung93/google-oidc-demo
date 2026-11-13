// snap-mode3 단위 테스트 — 스펙 2026-09-22 metamask-snap §3.1 의 RPC 표·상태 모양이 정본이고,
// tests/helpers/snap_sim.mjs(시뮬레이터)와 같은 입출력을 지켜야 한다. MetaMask 없이 전역 `snap` 을 스텁으로 대신한다
// (`snap_manageState` 는 메모리 맵, `snap_dialog` 는 시나리오별 응답 큐).
//   node snap-mode3/test/rpc.test.mjs
// scripts/run_tests.sh 의 `snap` 그룹이 이 파일을 돌린다(2026-09-22 Ruling 9): `bash scripts/run_tests.sh snap`.
// 체인도 브라우저도 필요 없지만 snap-mode3/node_modules(@metamask/snaps-sdk)를 전제하므로 unit 이 아니라 별도 그룹이다.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { createHash } from 'node:crypto';
import { validateWitness } from '../../lib/mode3_secret_source.js';
import { auidOf } from '../../lib/mode3_credential.js';

const WALLET_ORIGIN = 'http://127.0.0.1:5100';
const WALLET_ORIGIN_ALT = 'http://localhost:5100';
const RP_ORIGIN = 'http://127.0.0.1:3000';
// 줄분리자(U+2028)·문단분리자(U+2029) — 소스에 그대로 쓰면 파서가 줄바꿈으로 읽는다.
const LS = String.fromCharCode(0x2028), PS = String.fromCharCode(0x2029);

let failed = 0;
async function t(name, fn) {
  try { await fn(); console.log(`ok   ${name}`); }
  catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.stack ?? e.message}`); }
}

// ---- 전역 snap 스텁 ----
const clone = (v) => (v === undefined ? undefined : JSON.parse(JSON.stringify(v)));
const store = { state: null };          // snap_manageState 의 암호화 저장소 대역
const entropy = { srp: 'srp-A' };        // snap_getEntropy 의 SRP 대역 — 테스트가 바꿔 "다른 SRP" 를 흉내 낸다(2026-11-12)
const dialogs = [];                     // 표시된 대화상자(내용 검사용)
const answers = [];                     // 다음 대화상자들이 돌려줄 값

globalThis.snap = {
  request: async ({ method, params }) => {
    if (method === 'snap_manageState') {
      const op = params?.operation;
      if (op === 'get') return clone(store.state) ?? null;
      if (op === 'update') { store.state = clone(params.newState); return null; }
      if (op === 'clear') { store.state = null; return null; }
      throw new Error(`stub: 모르는 operation ${op}`);
    }
    if (method === 'snap_dialog') {
      dialogs.push(clone(params));
      if (!answers.length) throw new Error('stub: 대화상자 응답 큐가 비었다');
      return answers.shift();
    }
    if (method === 'snap_getEntropy') {
      // MetaMask 는 (SRP, 스냅 ID, salt) 로 결정적 32바이트를 준다 — 스텁은 SRP 대역 문자열과 salt 의 SHA-256.
      if (params?.version !== 1 || typeof params?.salt !== 'string') throw new Error('stub: snap_getEntropy 는 { version: 1, salt }');
      return '0x' + createHash('sha256').update(`${entropy.srp}|${params.salt}`).digest('hex');
    }
    throw new Error(`stub: 모르는 method ${method}`);
  },
};

const { onRpcRequest } = await import('../src/index.js');
const call = (method, params, origin = WALLET_ORIGIN) => onRpcRequest({ origin, request: { method, params } });
const lastDialogText = () => JSON.stringify(dialogs[dialogs.length - 1]);
const stateJson = () => JSON.stringify(store.state);

const ATTRS = ['1990', '410', '2', '0', '0', '0'];
const SLOT = 3;
const USER_CRED = { C_u_pt: { x: '11', y: '22' }, Cf_u: '33', blind_u: '987654321098765432109876543210', issuedAt: '2026-09-22T00:00:00.000Z' };

// onRpcRequest 의 switch 에서 method 이름을 직접 뽑는다 — 목록을 손으로 적어 두면 새 RPC 가 늘어날 때
// 아래 검사에서 조용히 빠진다(2026-09-25 리뷰: 제목은 "모든 RPC" 인데 getPublicInfo 하나만 보고 있었다).
const RPC_METHODS = [...fs.readFileSync(new URL('../src/index.js', import.meta.url), 'utf8').matchAll(/^\s*case '([A-Za-z]+)':/gm)].map((m) => m[1]);

await t('다른 오리진은 모든 RPC 에서 거절된다', async () => {
  assert.ok(RPC_METHODS.length >= 9, `RPC 목록을 못 뽑았다: ${JSON.stringify(RPC_METHODS)}`);
  for (const must of ['register', 'getPublicInfo', 'consentLogin', 'consentDisclosure', 'selfRevoke', 'reset']) {
    assert.ok(RPC_METHODS.includes(must), `${must} 가 목록에 없다 — 정규식이 소스와 어긋났다`);
  }
  for (const bad of ['http://evil.example', 'http://127.0.0.1:3000', 'https://127.0.0.1:5100', 'metamask']) {
    for (const m of RPC_METHODS) {
      await assert.rejects(() => call(m, {}, bad), /origin/i, `거절해야 한다: ${m} @ ${bad}`);
    }
  }
  assert.equal(store.state, null, '거절된 호출은 상태를 만들지 않는다');
  assert.equal(dialogs.length, 0, '거절된 호출은 대화상자를 띄우지 않는다 — 오리진 검사가 맨 앞이어야 한다');
  console.log(`     (RPC ${RPC_METHODS.length}종: ${RPC_METHODS.join(', ')})`);
});

await t('지갑 오리진 두 철자(127.0.0.1·localhost)는 모두 허용된다', async () => {
  for (const ok of [WALLET_ORIGIN, WALLET_ORIGIN_ALT]) {
    const info = await call('getPublicInfo', {}, ok);
    assert.equal(info.registered, false);
  }
});

let registered = null;
let auid = null;

// V11 갱신(2026-10-23): register 는 더 이상 비밀번호를 프롬프트로 받지 않는다 — 지갑 페이지가 넘긴 uid 를 받는다.
// 2026-11-05: 확인 창도 뺐다(중복 확인 제거) — 어떤 register 호출도 대화상자를 띄우지 않는다.
await t('register: uid 가 10진 문자열이 아니면 bad_uid, 대화상자는 없다', async () => {
  const before = dialogs.length;
  await assert.rejects(() => call('register', { uid: 'abc' }), /bad_uid/);
  assert.equal(store.state, null, '검증 실패는 상태를 만들지 않는다');
  assert.equal(dialogs.length, before, '대화상자 없음');
});

await t('register({ uid }): 대화상자 없이 → { uid, s_u, index }(pwd·sk_u 없음), 상태에 s_u', async () => {
  const before = dialogs.length;
  registered = await call('register', { uid: '12345' });
  assert.equal(registered.uid, '12345');
  assert.equal('pwd' in registered, false, 'pwd 는 더 이상 없다');
  assert.match(registered.s_u, /^[0-9]+$/);
  assert.equal('sk_u' in registered, false, '등록 키는 없어졌다(0.4.0)');
  assert.equal(dialogs.length, before, '확인 창을 띄우지 않는다(2026-11-05)');
  const reg = store.state.registration;
  assert.equal(store.state.version, 1);
  assert.equal(reg.s_u, registered.s_u);
  assert.ok(BigInt(reg.s_u) < (1n << 250n), '스칼라는 2^250 미만');
  assert.equal('sk_u' in reg, false);
  assert.equal(reg.attrs, null);
  assert.equal('r_u' in reg, false, 'r_u 는 없어졌다');
  assert.equal('cm_u' in reg, false, 'cm_u 는 없어졌다');
  assert.ok(reg.registeredAt, 'registeredAt 기록');
});

await t('auid 는 에이전트가 계산한다 — storeRegistration 이 받은 auid 가 getPublicInfo 에 보인다', async () => {
  auid = (await auidOf({ uid: 12345n, s_u: BigInt(registered.s_u) })).toString();
  await call('storeRegistration', { attrs: ATTRS, slot: SLOT, auid });
  assert.equal((await call('getPublicInfo', {})).auid, auid);
});

await t('register 두 번째는 거절된다', async () => {
  await assert.rejects(() => call('register', {}), /already_registered|이미/);
});

await t('storeRegistration: attrs 는 6개(짧으면 bad_attrs)·slot 저장, auid 없으면 bad_auid, 비밀은 받지 않는다', async () => {
  await assert.rejects(() => call('storeRegistration', { attrs: ATTRS.slice(0, 4), slot: SLOT, auid }), /bad_attrs/);
  await assert.rejects(() => call('storeRegistration', { attrs: ATTRS, slot: SLOT }), /bad_auid/);
  assert.deepEqual(await call('storeRegistration', { attrs: ATTRS, slot: SLOT, auid }), { ok: true });
  assert.deepEqual(store.state.registration.attrs, ATTRS);
  assert.equal(store.state.registration.slot, SLOT);
  assert.equal(store.state.registration.auid, auid);
  assert.equal(store.state.registration.s_u, registered.s_u, 'storeRegistration 은 s_u 를 건드리지 않는다');
});

await t('storeRegistration: slot 은 음이 아닌 정수여야 한다 — 음수·문자열은 bad_slot, 정상 값은 저장된다', async () => {
  await assert.rejects(() => call('storeRegistration', { attrs: ATTRS, slot: -1, auid }), /bad_slot/);
  await assert.rejects(() => call('storeRegistration', { attrs: ATTRS, slot: '1', auid }), /bad_slot/);
  assert.deepEqual(await call('storeRegistration', { attrs: ATTRS, slot: 1, auid }), { ok: true });
  assert.equal((await call('getPublicInfo', {})).slot, 1);
  // 뒤따르는 테스트가 기대하는 slot=SLOT 으로 되돌려 둔다 — 이 케이스가 이후 상태에 흔적을 남기지 않게 한다.
  assert.deepEqual(await call('storeRegistration', { attrs: ATTRS, slot: SLOT, auid }), { ok: true });
});

// 리뷰 2026-10-13 U2: attrs 는 10진 문자열이면 받아 줬을 뿐 상한(2^64) 검사가 없었다(회로는 끝내 거절하지만, 오리진 제한을 뚫을 가치가 없다).
await t('storeRegistration: attrs 원소는 2^64 미만이어야 한다(ATTR_MAX, bad_attrs)', async () => {
  const tooBig = (1n << 64n).toString();
  await assert.rejects(() => call('storeRegistration', { attrs: [tooBig, '0', '0', '0', '0', '0'], slot: SLOT, auid }), /bad_attrs/);
  // 뒤따르는 테스트가 기대하는 attrs=ATTRS 로 되돌려 둔다.
  assert.deepEqual(await call('storeRegistration', { attrs: ATTRS, slot: SLOT, auid }), { ok: true });
});

await t('getPublicInfo 에는 비밀이 없다', async () => {
  const info = await call('getPublicInfo', {});
  assert.deepEqual(Object.keys(info).sort(), ['attrs', 'auid', 'consents', 'hasUserCred', 'index', 'nextIndex', 'pending', 'provider', 'registered', 'slot', 'uid']);
  assert.equal(info.registered, true);
  assert.equal(info.uid, '12345');
  assert.equal(info.auid, auid);
  assert.deepEqual(info.attrs, ATTRS);
  assert.equal(info.slot, SLOT);
  assert.equal(info.hasUserCred, false);
  const s = JSON.stringify(info);
  for (const secret of [store.state.registration.s_u]) {
    assert.ok(!s.includes(secret), `공개 정보에 비밀이 실렸다: ${secret.slice(0, 8)}…`);
  }
});

// 리뷰 2026-10-13 U3 의 자리: buildWitness 는 손상된 등록 비밀을 그대로 내보내지 않는다(0.4.0 부터 비밀은 s_u 하나 — 전에는 sk_u 의 16진 검사였다).
await t('buildWitness: s_u 가 10진이 아니면 registration_incomplete(상태는 건드리지 않는다)', async () => {
  const saved = store.state.registration.s_u;
  store.state.registration.s_u = 'zz';
  await assert.rejects(() => call('consentLogin', { origin: RP_ORIGIN, arid: '777', allowAgent: '0' }), /registration_incomplete/);
  store.state.registration.s_u = saved;
});

await t('consentLogin → 대화상자 없이 validateWitness 를 통과하는 증인, consents 기록', async () => {
  const before = dialogs.length;
  const w = await call('consentLogin', { origin: RP_ORIGIN, arid: '777', allowAgent: '1', serviceName: '데모 RP' });
  assert.equal(dialogs.length, before, '로그인 동의 창은 없다(2026-11-05)');
  // auid 까지 준다 — 증인의 s_u 가 register 가 낸 auid 와 실제로 묶였는지 본다(최종 리뷰 Minor 1 의 V11 판).
  await validateWitness(w, '12345', auid);
  assert.equal(w.uid, '12345');
  assert.equal('sk_u' in w, false, '증인에 sk_u 가 없다');
  assert.deepEqual(w.attrs, ATTRS);
  assert.equal(w.userCred, null);
  assert.equal(store.state.consents[RP_ORIGIN].arid, '777');
  assert.equal(store.state.consents[RP_ORIGIN].allowAgent, '1');
  assert.ok(store.state.consents[RP_ORIGIN].grantedAt);
});

await t('consentLogin: 다른 RP 오리진도 묻지 않고 증인·동의 기록(allowAgent 는 \'0\'/\'1\' 로 굳힌다)', async () => {
  const before = dialogs.length;
  const w = await call('consentLogin', { origin: 'http://127.0.0.1:3001', arid: '888', allowAgent: 0, serviceName: '다른 RP' });
  assert.equal(dialogs.length, before, '대화상자 없음');
  assert.equal(w.uid, '12345');
  assert.deepEqual(store.state.consents['http://127.0.0.1:3001'], { ...store.state.consents['http://127.0.0.1:3001'], arid: '888', allowAgent: '0' });
});

// 2026-11-05: consentDisclosure 는 RP 릴레이 출금({ relay: true })만 대화상자를 띄운다 — 지갑 페이지의 "보내기"(MetaMask 확인 창이 뒤따른다)는 묻지 않는다.
await t('consentDisclosure: relay 가 아니면 대화상자 없이 { ok: true }', async () => {
  const before = dialogs.length;
  const args = { arid: '777', origin: null, disclose: [{ lo: '0', hi: '2007' }, null, null, null], to: '0x1111111111111111111111111111111111111111', value: '0' };
  assert.deepEqual(await call('consentDisclosure', args), { ok: true });
  assert.equal(dialogs.length, before, '대화상자 없음');
});

await t('consentDisclosure(relay): 대화상자에 슬롯·구간·대상·금액, 승인/거절', async () => {
  answers.push(true);
  const args = { relay: true, arid: '777', origin: RP_ORIGIN, disclose: [{ lo: '0', hi: '2007' }, { lo: '410', hi: '410' }, null, null], to: '0x1111111111111111111111111111111111111111', value: '0' };
  assert.deepEqual(await call('consentDisclosure', args), { ok: true });
  const d = lastDialogText();
  for (const part of ['a₀', '출생연도', '2007', 'a₁', '국가', '410', '0x1111111111111111111111111111111111111111']) {
    assert.ok(d.includes(part), `대화상자에 ${part} 가 없다`);
  }
  assert.ok(!d.includes('a₂'), '공개하지 않는 슬롯은 표시하지 않는다');
  answers.push(false);
  assert.deepEqual(await call('consentDisclosure', args), { denied: true });
});

await t('consentDisclosure(V7, relay): set 이 있으면 "a₁(국가) ∈ {…} (N개)" 줄, 33개 이상이면 앞 8개 + "외 N개"', async () => {
  answers.push(true);
  const base = { relay: true, arid: '777', origin: RP_ORIGIN, disclose: [null, null, null, null], to: '0x1111111111111111111111111111111111111111', value: '0' };
  assert.deepEqual(await call('consentDisclosure', { ...base, set: { slot: 1, members: [410, 392, 840, 276, 250] } }), { ok: true });
  let d = lastDialogText();
  for (const part of ['a₁', '국가', '∈', '410', '250', '(5개)']) assert.ok(d.includes(part), `대화상자에 ${part} 가 없다`);
  answers.push(true);
  await call('consentDisclosure', { ...base, set: { slot: 2, members: Array.from({ length: 40 }, (_, i) => i + 1) } });
  d = lastDialogText();
  assert.ok(d.includes('… 외 32개') && d.includes('a₂') && !d.includes(' 40,') , d);
});

await t('updateUserCred(obj) 저장 → 증인에 실리고 getPublicInfo 는 hasUserCred 만 알린다', async () => {
  assert.deepEqual(await call('updateUserCred', USER_CRED), { ok: true });
  const info = await call('getPublicInfo', {});
  assert.equal(info.hasUserCred, true);
  assert.ok(!JSON.stringify(info).includes(USER_CRED.blind_u), 'blind_u 는 공개 정보에 없다');
  const w = await call('consentLogin', { origin: RP_ORIGIN, arid: '777', allowAgent: '1', serviceName: '데모 RP' });
  await validateWitness(w, '12345', auid);
  assert.deepEqual(w.userCred.C_u_pt, USER_CRED.C_u_pt);
  assert.equal(w.userCred.blind_u, USER_CRED.blind_u);
});

await t('updateUserCred(null) 은 저장된 C_u 를 버린다', async () => {
  assert.deepEqual(await call('updateUserCred', null), { ok: true });
  assert.equal((await call('getPublicInfo', {})).hasUserCred, false);
  assert.equal(store.state.userCred, null);
});

await t('updateUserCred: 인자가 아예 없으면 bad_params (조용한 폐기를 막는다 — T3 리뷰 Ruling 6)', async () => {
  await call('updateUserCred', USER_CRED);
  await assert.rejects(() => call('updateUserCred', undefined), /bad_params/);
  assert.equal((await call('getPublicInfo', {})).hasUserCred, true, '거절된 호출은 C_u 를 건드리지 않는다');
  assert.deepEqual(await call('updateUserCred', { userCred: null }), { ok: true }, '{ userCred: null } 은 폐기다');
  assert.equal((await call('getPublicInfo', {})).hasUserCred, false);
});

await t('syncAttrs: 같으면 changed=false, 바뀌면 true 와 C_u 폐기', async () => {
  await call('updateUserCred', USER_CRED);
  assert.deepEqual(await call('syncAttrs', { attrs: ATTRS }), { ok: true, changed: false });
  assert.equal((await call('getPublicInfo', {})).hasUserCred, true, '안 바뀌면 C_u 유지');
  assert.deepEqual(await call('syncAttrs', { attrs: ['1991', '410', '2', '0', '0', '0'] }), { ok: true, changed: true });
  assert.deepEqual(store.state.registration.attrs, ['1991', '410', '2', '0', '0', '0']);
  assert.equal((await call('getPublicInfo', {})).hasUserCred, false, '속성이 바뀌면 옛 C_u 는 물린다');
});

await t('selfRevoke: prompt(비밀번호) → { uid, pwd }, 거절은 denied', async () => {
  answers.push('password123');
  assert.deepEqual(await call('selfRevoke', {}), { uid: '12345', pwd: 'password123' });
  assert.equal(dialogs[dialogs.length - 1].type, 'prompt');
  assert.ok(!stateJson().includes('password123'), '비밀번호는 저장하지 않는다');
  answers.push(null);
  assert.deepEqual(await call('selfRevoke', {}), { denied: true });
});

// 2026-11-05: 세션 폐기 동의 창은 뺐다(지갑 페이지의 확인이 이미 있다) — 등록만 있으면 대화상자 없이 { ok: true }. bound 가 없어도 던지지 않는다.
await t('consentRevokeSession: 대화상자 없이 { ok: true }(bound 생략도 받는다)', async () => {
  const before = dialogs.length;
  assert.deepEqual(await call('consentRevokeSession', { arid: '777', issuedAt: '2026-09-24T00:00:00Z', maxHeight: '1000', bound: '3' }), { ok: true });
  assert.deepEqual(await call('consentRevokeSession', { arid: '777', issuedAt: '2026-09-24T00:00:00Z', maxHeight: '1000' }), { ok: true });
  assert.equal(dialogs.length, before, '대화상자 없음');
});

await t('showSalt: 대화상자 없이 { s_u }(저장된 값과 같다)', async () => {
  const savedSU = store.state.registration.s_u;
  const before = dialogs.length;
  assert.deepEqual(await call('showSalt', {}), { s_u: savedSU });
  assert.equal(dialogs.length, before, '확인 창을 띄우지 않는다(2026-11-05)');
});

// "내 계정"(2026-11-12 사용자 요청): zk 스냅 화면이 스냅에 저장된 값을 전부 보여 준다 — 비밀까지 싣는 유일한 조회 RPC.
await t('getStoredState: 대화상자 없이 저장 상태 전부(비밀 s_u·blind_u 포함)를 돌려주고 상태는 바꾸지 않는다', async () => {
  await call('updateUserCred', USER_CRED);
  const before = dialogs.length, saved = stateJson();
  const st = await call('getStoredState', {});
  assert.deepEqual(Object.keys(st).sort(), ['consents', 'nextIndex', 'registration', 'userCred', 'version']);
  assert.equal(st.version, 1);
  assert.deepEqual(st.registration, store.state.registration);
  assert.equal(st.registration.s_u, registered.s_u); assert.equal('sk_u' in st.registration, false);
  assert.deepEqual(st.userCred, USER_CRED);
  assert.deepEqual(st.consents, store.state.consents);
  assert.ok(Object.keys(st.consents).length >= 1, '동의 기록이 실려 있다');
  assert.equal(st.nextIndex, (await call('getPublicInfo', {})).nextIndex);
  assert.equal(dialogs.length, before, '확인 창 없음');
  assert.equal(stateJson(), saved, '읽기만 한다');
});

await t('모르는 method 는 거절', async () => {
  await assert.rejects(() => call('nope', {}), /nope/);
});

await t('reset: 확인 뒤 상태를 비운다(거절하면 그대로)', async () => {
  answers.push(false);
  assert.deepEqual(await call('reset', {}), { denied: true });
  assert.equal((await call('getPublicInfo', {})).registered, true);
  answers.push(true);
  assert.deepEqual(await call('reset', {}), { ok: true });
  const info = await call('getPublicInfo', {});
  assert.equal(info.registered, false);
  assert.equal(info.uid, null);
  assert.deepEqual(info.consents, {});
  assert.ok(!stateJson().includes(registered.s_u), '초기화 뒤 비밀이 남지 않는다');
  // 등록이 없을 때의 getStoredState — 빈 등록·빈 동의 기록과 남은 다음 가입 번호
  assert.deepEqual(await call('getStoredState', {}), { version: 1, registration: null, userCred: null, consents: {}, nextIndex: info.nextIndex });
});

await t('prepareRegister: 대화상자 없이 uid 없는 보류 등록 — registered=false, pending=true', async () => {
  const before = dialogs.length;
  const p = await call('prepareRegister', {});
  assert.match(p.s_u, /^[0-9]+$/); assert.equal('sk_u' in p, false);
  assert.equal(dialogs.length, before, '확인 창을 띄우지 않는다(2026-11-05)');
  const info = await call('getPublicInfo', {});
  assert.equal(info.registered, false); assert.equal(info.pending, true); assert.equal(info.uid, null); assert.equal(info.provider, null);
  // 다시 시도(Google 단계 실패 뒤) — 같은 비밀
  assert.deepEqual(await call('prepareRegister', {}), p);
});

await t('보류 등록에서는 비밀이 필요한 RPC 가 not_registered 로 거절된다(uid 없는 증인·프롬프트 금지)', async () => {
  for (const m of ['consentLogin', 'updateUserCred', 'syncAttrs', 'selfRevoke', 'consentRevokeSession', 'showSalt']) {
    await assert.rejects(() => call(m, { origin: RP_ORIGIN }), /not_registered/, `${m}`);
  }
});

await t('storeRegistration(보류): uid 가 없으면 bad_uid 이고 상태 그대로; uid·provider 를 주면 완성 등록', async () => {
  const before = stateJson();
  await assert.rejects(() => call('storeRegistration', { attrs: ATTRS, slot: SLOT, auid: '77' }), /bad_uid/);
  assert.equal(stateJson(), before, '거절은 상태를 바꾸지 않는다');
  await assert.rejects(() => call('storeRegistration', { attrs: ATTRS, slot: SLOT, auid: '77', uid: '5', provider: 'bad provider!' }), /bad_provider/);
  assert.equal(stateJson(), before);
  assert.deepEqual(await call('storeRegistration', { attrs: ATTRS, slot: SLOT, auid: '77', uid: '5', provider: 'google' }), { ok: true });
  const info = await call('getPublicInfo', {});
  assert.equal(info.registered, true); assert.equal(info.pending, false); assert.equal(info.uid, '5'); assert.equal(info.provider, 'google');
  // 완성 등록: 다른 uid 는 uid_mismatch, 같은 uid·uid 생략은 받는다
  await assert.rejects(() => call('storeRegistration', { attrs: ATTRS, slot: SLOT, auid: '77', uid: '6' }), /uid_mismatch/);
  assert.deepEqual(await call('storeRegistration', { attrs: ATTRS, slot: SLOT, auid: '77' }), { ok: true });
  // 완성 등록이면 prepareRegister 는 already_registered
  await assert.rejects(() => call('prepareRegister', {}), /already_registered/);
});

await t('register 는 보류 등록을 덮어쓴다(완성 등록만 already_registered); reset 은 보류도 지운다', async () => {
  answers.push(true); assert.deepEqual(await call('reset', {}), { ok: true });
  const p = await call('prepareRegister', {});
  const r = await call('register', { uid: '42' });
  assert.equal(r.uid, '42'); assert.equal(r.s_u, p.s_u, '2026-11-12: 비밀은 시드 유도라 보류 등록과 같다 — register 는 uid 를 채운 완성 등록으로 덮어쓴다');
  assert.equal((await call('getPublicInfo', {})).pending, false);
  answers.push(true); assert.deepEqual(await call('reset', {}), { ok: true });
  answers.push(true); const p2 = await call('prepareRegister', {});
  answers.push(true); assert.deepEqual(await call('reset', {}), { ok: true });
  assert.ok(!String(stateJson()).includes(p2.s_u), 'reset 뒤 보류 비밀이 남지 않는다');
  assert.equal(store.state?.registration ?? null, null, 'reset 뒤 등록이 없다(2026-11-12: 다음 가입 번호 nextIndex 만 남는다)');
});

await t('유도(2026-11-12): 같은 SRP 면 register·prepareRegister·getSalt 가 같은 s_u, 다른 SRP 면 다르다; reset 뒤에도 같다', async () => {
  entropy.srp = 'srp-A';
  const g = await call('getSalt', {});
  assert.match(g.s_u, /^[0-9]+$/); assert.ok(BigInt(g.s_u) >= 1n && BigInt(g.s_u) < (1n << 250n));
  assert.equal(store.state?.registration ?? null, null, 'getSalt 는 상태를 만들지 않는다');
  const r = await call('register', { uid: '7' });
  assert.equal(r.s_u, g.s_u);
  answers.push(true); assert.deepEqual(await call('reset', {}), { ok: true });
  const p = await call('prepareRegister', {});
  assert.equal(p.s_u, r.s_u, 'reset 뒤 보류 등록도 같은 s_u');
  answers.push(true); assert.deepEqual(await call('reset', {}), { ok: true });
  entropy.srp = 'srp-B';
  const b = await call('register', { uid: '7' });
  assert.notEqual(b.s_u, r.s_u, '다른 SRP 면 다른 s_u');
  assert.equal((await call('getSalt', {})).s_u, b.s_u, '등록 뒤에도 getSalt 는 같은 값');
  answers.push(true); assert.deepEqual(await call('reset', {}), { ok: true });
  entropy.srp = 'srp-A';
});

await t('register({ uid, s_u }): s_u 는 유도값과 같을 때만 받는다 — 다르면 salt_not_derived 이고 아무것도 저장하지 않는다', async () => {
  const { s_u } = await call('getSalt', {});
  await assert.rejects(() => call('register', { uid: '7', s_u: '123456789' }), /salt_not_derived/);
  await assert.rejects(() => call('register', { uid: '7', s_u: 'abc' }), /salt_not_derived/);
  assert.equal(store.state?.registration ?? null, null);
  const r = await call('register', { uid: '7', s_u: ` 0${s_u} ` });
  assert.equal(r.s_u, s_u, '공백·앞자리 0 은 정규화 뒤 비교');
  answers.push(true); assert.deepEqual(await call('reset', {}), { ok: true });
});

await t('saltFromEntropy: 경계값과 형식 오류', async () => {
  const { saltFromEntropy } = await import('../src/crypto.js');
  assert.equal(saltFromEntropy('0x' + '00'.repeat(32)), '1', '0 → 1(0 은 쓰지 않는다)');
  const max = (1n << 256n) - 1n; assert.equal(saltFromEntropy('0x' + 'ff'.repeat(32)), (1n + (max % ((1n << 250n) - 1n))).toString());
  for (const bad of ['', '0x', '0x1234', 'zz'.repeat(32), '0x' + 'g'.repeat(64)]) {
    assert.throws(() => saltFromEntropy(bad), /bad_entropy/);
  }
});

await t('등록 전에는 비밀이 필요한 RPC 가 거절된다', async () => {
  for (const m of ['storeRegistration', 'consentLogin', 'updateUserCred', 'syncAttrs', 'selfRevoke', 'consentRevokeSession', 'showSalt']) {
    await assert.rejects(() => call(m, {}), /not_registered|등록/, `${m} 은 등록을 요구한다`);
  }
});

// 2026-11-12(스펙 snap-account-index, 리뷰 I-3): 계정 번호 k 마다 다른 비밀. 번호는 기록이 들고 다니고, nextIndex 는 reset 을 넘어 남는다.
await t('계정 번호: 번호가 다르면 s_u 가 다르고 같은 번호면 같다; getSalt 기본은 등록 번호 → 없으면 nextIndex; storeRegistration 이 nextIndex 를 올리고 reset 뒤에도 남는다', async () => {
  entropy.srp = 'srp-A'; store.state = null;
  const g0 = await call('getSalt', {}); assert.equal(g0.index, 0, '처음엔 0번');
  const g1 = await call('getSalt', { index: 1 }); assert.equal(g1.index, 1);
  assert.notEqual(g1.s_u, g0.s_u, '번호가 다르면 salt 가 다르다');
  assert.equal((await call('getSalt', { index: 1 })).s_u, g1.s_u, '같은 번호면 같은 salt');
  const r = await call('register', { uid: '7', s_u: g1.s_u, index: 1 });
  assert.equal(r.index, 1); assert.equal(r.s_u, g1.s_u);
  assert.equal((await call('getSalt', {})).index, 1, '등록이 있으면 기본은 그 번호(Ruling P1)');
  await call('storeRegistration', { attrs: ATTRS, slot: 0, auid: '5' });
  const info = await call('getPublicInfo', {}); assert.equal(info.index, 1); assert.equal(info.nextIndex, 2);
  answers.push(true); assert.deepEqual(await call('reset', {}), { ok: true });
  assert.equal(store.state?.registration ?? null, null, 'reset 은 등록을 지운다');
  assert.equal((await call('getPublicInfo', {})).nextIndex, 2, 'reset 뒤에도 nextIndex 는 남는다');
  const p = await call('prepareRegister', {});
  assert.equal(p.index, 2, '보류 등록은 nextIndex'); assert.notEqual(p.s_u, r.s_u, '다른 번호 → 다른 s_u');
  assert.deepEqual(await call('prepareRegister', { index: 9 }), p, '보류가 있으면 그 비밀·번호 그대로');
  answers.push(true); await call('reset', {});
  store.state = null;
});

await t('계정 번호 검사: bad_index(범위·형식)·setNextIndex·번호와 어긋난 s_u 는 salt_not_derived; nextIndex 는 상한에서 넘치지 않는다', async () => {
  store.state = null;
  for (const bad of [-1, 1.5, '3', 2 ** 31]) {
    await assert.rejects(() => call('getSalt', { index: bad }), /bad_index/);
    await assert.rejects(() => call('setNextIndex', { index: bad }), /bad_index/);
    await assert.rejects(() => call('register', { uid: '7', index: bad }), /bad_index/);
  }
  await assert.rejects(() => call('setNextIndex', {}), /bad_index/);
  assert.deepEqual(await call('setNextIndex', { index: 5 }), { ok: true, nextIndex: 5 });
  assert.equal((await call('getSalt', {})).index, 5, '등록이 없으면 기본은 nextIndex');
  const s0 = (await call('getSalt', { index: 0 })).s_u;
  await assert.rejects(() => call('register', { uid: '7', s_u: s0, index: 4 }), /salt_not_derived/, '0번 salt 를 4번으로 등록할 수 없다');
  assert.equal(store.state?.registration ?? null, null, '거절은 등록을 만들지 않는다');
  await call('setNextIndex', { index: 2 ** 31 - 1 });
  await call('register', { uid: '7' }); await call('storeRegistration', { attrs: ATTRS, slot: 0, auid: '5' });
  assert.equal((await call('getPublicInfo', {})).nextIndex, 2 ** 31 - 1, '상한에서 멈춘다');
  answers.push(true); await call('reset', {});
  store.state = null;
});

// 0.4.0(2026-11-13, 스펙 2026-11-12 no-pk-u §4.1): 등록 키 sk_u 는 없다 — 유도하지도 저장하지도 내주지도 않는다.
await t('0.4.0: register·prepareRegister·getStoredState·증인 어디에도 sk_u 가 없고, s_u 는 0.3.x 와 같은 salt(zkd/mode3/s_u/v2/<k>)로 유도된다', async () => {
  store.state = null; entropy.srp = 'srp-A';
  const crypto = await import('../src/crypto.js');
  const { ENTROPY_SALT_S_U, saltFromEntropy } = crypto;
  assert.equal(ENTROPY_SALT_S_U, 'zkd/mode3/s_u/v2/');
  assert.equal('ENTROPY_SALT_SK_U' in crypto, false); assert.equal('skFromEntropy' in crypto, false);
  const p = await call('prepareRegister', {});
  assert.deepEqual(Object.keys(p).sort(), ['index', 's_u']);
  assert.equal(p.s_u, saltFromEntropy('0x' + createHash('sha256').update(`srp-A|zkd/mode3/s_u/v2/${p.index}`).digest('hex')));
  const r = await call('register', { uid: '4242' });
  assert.deepEqual(Object.keys(r).sort(), ['index', 's_u', 'uid']); assert.equal(r.s_u, p.s_u);
  await call('storeRegistration', { attrs: ATTRS, slot: SLOT, auid: (await auidOf({ uid: 4242n, s_u: BigInt(r.s_u) })).toString() });
  const st = await call('getStoredState', {});
  assert.equal('sk_u' in st.registration, false); assert.equal(stateJson().includes('sk_u'), false);
  const w = await call('consentLogin', { origin: RP_ORIGIN, arid: '777', allowAgent: '0' });
  assert.deepEqual(Object.keys(w).sort(), ['attrs', 's_u', 'uid', 'userCred']);
  await validateWitness(w, '4242');
});
await t('0.4.0: 0.3.x 상태(registration.sk_u 있음)를 재등록 없이 읽는다 — 증인·조회에 sk_u 가 나가지 않고 다음 저장 때 저장소에서도 사라진다', async () => {
  const old = JSON.parse(stateJson());
  old.registration.sk_u = 'ab'.repeat(32);                      // 0.3.x 가 저장해 둔 모양
  store.state = old;
  const w = await call('consentLogin', { origin: RP_ORIGIN, arid: '778', allowAgent: '0' });
  assert.equal('sk_u' in w, false); assert.equal(w.s_u, old.registration.s_u);
  assert.equal('sk_u' in (await call('getStoredState', {})).registration, false);
  assert.equal(stateJson().includes('ab'.repeat(32)), false, 'consentLogin 이 동의 기록을 저장하면서 sk_u 가 사라졌다');
  assert.equal((await call('getPublicInfo', {})).registered, true, '등록은 그대로다');
});

console.log(failed ? `\n${failed} failed` : '\nall passed');
process.exit(failed === 0 ? 0 : 1);
