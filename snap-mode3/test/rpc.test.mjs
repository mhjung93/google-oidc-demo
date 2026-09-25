// snap-mode3 단위 테스트 — 스펙 2026-09-22 metamask-snap §3.1 의 RPC 표·상태 모양이 정본이고,
// tests/helpers/snap_sim.mjs(시뮬레이터)와 같은 입출력을 지켜야 한다. MetaMask 없이 전역 `snap` 을 스텁으로 대신한다
// (`snap_manageState` 는 메모리 맵, `snap_dialog` 는 시나리오별 응답 큐).
//   node snap-mode3/test/rpc.test.mjs
// scripts/run_tests.sh 의 `snap` 그룹이 이 파일을 돌린다(2026-09-22 Ruling 9): `bash scripts/run_tests.sh snap`.
// 체인도 브라우저도 필요 없지만 snap-mode3/node_modules(@metamask/snaps-sdk)를 전제하므로 unit 이 아니라 별도 그룹이다.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { validateWitness } from '../../lib/mode3_secret_source.js';
import { registrationCommit } from '../../lib/mode3_issuance.js';

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
    throw new Error(`stub: 모르는 method ${method}`);
  },
};

const { onRpcRequest } = await import('../src/index.js');
const call = (method, params, origin = WALLET_ORIGIN) => onRpcRequest({ origin, request: { method, params } });
const lastDialogText = () => JSON.stringify(dialogs[dialogs.length - 1]);
const stateJson = () => JSON.stringify(store.state);

const SK_U = 'ab'.repeat(32);
const ATTRS = ['1990', '410', '2', '0'];
const USER_CRED = { C_u_pt: { x: '11', y: '22' }, Cf_u: '33', blind_u: '987654321098765432109876543210', leaf: '55', issuedAt: '2026-09-22T00:00:00.000Z' };

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
await t('register: prompt 두 번 → { uid, pwd, cm_u }, 상태에 s_u·r_u, 비밀번호는 저장 안 함', async () => {
  answers.push('12345', 'password123');
  registered = await call('register', {});
  assert.equal(registered.uid, '12345');
  assert.equal(registered.pwd, 'password123');
  assert.match(registered.cm_u.x, /^[0-9]+$/);
  assert.match(registered.cm_u.y, /^[0-9]+$/);
  assert.equal(dialogs.length, 2, '대화상자 두 번(uid, 비밀번호)');
  assert.equal(dialogs[0].type, 'prompt');
  assert.equal(dialogs[1].type, 'prompt');
  const reg = store.state.registration;
  assert.equal(store.state.version, 1);
  assert.match(reg.s_u, /^[0-9]+$/);
  assert.match(reg.r_u, /^[0-9]+$/);
  assert.ok(BigInt(reg.s_u) < (1n << 250n) && BigInt(reg.r_u) < (1n << 250n), '스칼라는 2^250 미만');
  assert.deepEqual(reg.cm_u, registered.cm_u);
  assert.equal(reg.sk_u, null);
  assert.equal(reg.attrs, null);
  assert.ok(reg.registeredAt, 'registeredAt 기록');
  assert.ok(!stateJson().includes('password123'), '비밀번호는 상태에 남지 않는다');
});

await t('cm_u 는 루트 lib 의 registrationCommit(s_u, r_u) 과 같은 점이다', async () => {
  const reg = store.state.registration;
  const expected = await registrationCommit(BigInt(reg.s_u), BigInt(reg.r_u));
  assert.equal(registered.cm_u.x, expected.x.toString());
  assert.equal(registered.cm_u.y, expected.y.toString());
});

await t('register 두 번째는 거절된다', async () => {
  await assert.rejects(() => call('register', {}), /already_registered|이미/);
});

await t('storeRegistration: sk_u·attrs 저장', async () => {
  assert.deepEqual(await call('storeRegistration', { sk_u: SK_U, attrs: ATTRS }), { ok: true });
  assert.equal(store.state.registration.sk_u, SK_U);
  assert.deepEqual(store.state.registration.attrs, ATTRS);
});

await t('getPublicInfo 에는 비밀이 없다', async () => {
  const info = await call('getPublicInfo', {});
  assert.deepEqual(Object.keys(info).sort(), ['attrs', 'cm_u', 'consents', 'hasUserCred', 'registered', 'uid']);
  assert.equal(info.registered, true);
  assert.equal(info.uid, '12345');
  assert.deepEqual(info.attrs, ATTRS);
  assert.equal(info.hasUserCred, false);
  const s = JSON.stringify(info);
  for (const secret of [store.state.registration.s_u, store.state.registration.r_u, SK_U]) {
    assert.ok(!s.includes(secret), `공개 정보에 비밀이 실렸다: ${secret.slice(0, 8)}…`);
  }
});

await t('consentLogin 승인 → validateWitness 를 통과하는 증인, consents 기록', async () => {
  answers.push(true);
  const w = await call('consentLogin', { origin: RP_ORIGIN, arid: '777', allowAgent: '1', serviceName: '데모 RP' });
  // cm_u 까지 준다 — 증인의 s_u·r_u 가 register 가 낸 cm_u 와 실제로 묶였는지 본다(최종 리뷰 Minor 1).
  await validateWitness(w, '12345', registered.cm_u);
  assert.equal(w.uid, '12345');
  assert.equal(w.sk_u, SK_U);
  assert.deepEqual(w.attrs, ATTRS);
  assert.equal(w.userCred, null);
  const d = lastDialogText();
  assert.equal(dialogs[dialogs.length - 1].type, 'confirmation');
  for (const part of ['데모 RP', RP_ORIGIN, '777', 'AI']) assert.ok(d.includes(part), `대화상자에 ${part} 가 없다`);
  assert.equal(store.state.consents[RP_ORIGIN].arid, '777');
  assert.equal(store.state.consents[RP_ORIGIN].allowAgent, '1');
  assert.ok(store.state.consents[RP_ORIGIN].grantedAt);
});

await t('consentLogin 거절 → { denied: true }, consents 는 그대로', async () => {
  answers.push(false);
  const r = await call('consentLogin', { origin: 'http://127.0.0.1:3001', arid: '888', allowAgent: '0', serviceName: '다른 RP' });
  assert.deepEqual(r, { denied: true });
  assert.ok(!store.state.consents['http://127.0.0.1:3001'], '거절은 기록하지 않는다');
});

await t('consentLogin(V7): disclose·set 이 있으면 공개 줄이 보인다', async () => {
  answers.push(true);
  await call('consentLogin', { origin: RP_ORIGIN, arid: '777', allowAgent: '0', serviceName: '데모 RP', disclose: [{ lo: '0', hi: '2007' }, null, null, null], set: { slot: 1, members: [410, 392] } });
  const d = lastDialogText();
  for (const part of ['a₀', '2007', 'a₁', '∈', '410', '(2개)']) assert.ok(d.includes(part), `대화상자에 ${part} 가 없다`);
});

// 2026-09-25 리뷰 D-2: serviceName 은 서비스가 준 임의의 문자열이다(인증서가 덮는 것은 origin 뿐).
// 개행으로 가짜 줄을 끼워 넣거나 긴 이름으로 창을 밀어내지 못해야 한다.
await t('consentLogin: 서비스 이름은 한 줄·48자로 잘린다(개행·제어문자 제거), 빈 이름은 오리진으로', async () => {
  answers.push(true);
  const evil = `가짜 은행\n${LS}오리진: http://real-bank.example${PS}\u0007 ${'가'.repeat(200)}`;
  await call('consentLogin', { origin: RP_ORIGIN, arid: '777', allowAgent: '0', serviceName: evil });
  const lines = dialogs[dialogs.length - 1].content.children.map((c) => c.value ?? '');
  const svc = lines.find((l) => l.startsWith('서비스: '));
  assert.ok(svc, `서비스 줄이 없다: ${JSON.stringify(lines)}`);
  assert.ok(!/[\u0000-\u001f\u007f]/.test(svc), `제어문자가 남았다: ${JSON.stringify(svc)}`);
  assert.ok(!svc.includes(LS) && !svc.includes(PS), `줄분리자가 남았다: ${JSON.stringify(svc)}`);
  assert.ok(svc.length <= '서비스: '.length + 48, `한 줄 48자를 넘었다(${svc.length}): ${JSON.stringify(svc)}`);
  assert.ok(lines.includes(`오리진: ${RP_ORIGIN}`), '진짜 오리진 줄은 그대로다');
  answers.push(true);
  await call('consentLogin', { origin: RP_ORIGIN, arid: '777', allowAgent: '0', serviceName: '   ' });
  const blank = dialogs[dialogs.length - 1].content.children.map((c) => c.value ?? '');
  assert.ok(blank.includes(`서비스: ${RP_ORIGIN}`), `빈 이름은 오리진으로 대체된다: ${JSON.stringify(blank)}`);
});

await t('consentDisclosure: 대화상자에 슬롯·구간·대상·금액, 승인/거절', async () => {
  answers.push(true);
  const args = { arid: '777', origin: RP_ORIGIN, disclose: [{ lo: '0', hi: '2007' }, { lo: '410', hi: '410' }, null, null], to: '0x1111111111111111111111111111111111111111', value: '0' };
  assert.deepEqual(await call('consentDisclosure', args), { ok: true });
  const d = lastDialogText();
  for (const part of ['a₀', '출생연도', '2007', 'a₁', '국가', '410', '0x1111111111111111111111111111111111111111']) {
    assert.ok(d.includes(part), `대화상자에 ${part} 가 없다`);
  }
  assert.ok(!d.includes('a₂'), '공개하지 않는 슬롯은 표시하지 않는다');
  answers.push(false);
  assert.deepEqual(await call('consentDisclosure', args), { denied: true });
});

await t('consentDisclosure(V7): set 이 있으면 "a₁(국가) ∈ {…} (N개)" 줄, 33개 이상이면 앞 8개 + "외 N개"', async () => {
  answers.push(true);
  const base = { arid: '777', origin: RP_ORIGIN, disclose: [null, null, null, null], to: '0x1111111111111111111111111111111111111111', value: '0' };
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
  answers.push(true);
  const w = await call('consentLogin', { origin: RP_ORIGIN, arid: '777', allowAgent: '1', serviceName: '데모 RP' });
  await validateWitness(w, '12345', registered.cm_u);
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
  assert.deepEqual(await call('syncAttrs', { attrs: ['1991', '410', '2', '0'] }), { ok: true, changed: true });
  assert.deepEqual(store.state.registration.attrs, ['1991', '410', '2', '0']);
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

await t('consentRevokeSession: 대화상자에 arid·발급 시각이 보이고 승인/거절', async () => {
  answers.push(true);
  assert.deepEqual(await call('consentRevokeSession', { arid: '777', issuedAt: '2026-09-24T00:00:00Z', maxHeight: '1000' }), { ok: true });
  const d = lastDialogText();
  for (const part of ['777', '2026-09-24', '폐기']) assert.ok(d.includes(part), `대화상자에 ${part} 가 없다`);
  answers.push(false);
  assert.deepEqual(await call('consentRevokeSession', { arid: '777', issuedAt: 'x', maxHeight: '1' }), { denied: true });
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
  assert.ok(!stateJson().includes(SK_U), '초기화 뒤 비밀이 남지 않는다');
});

await t('등록 전에는 비밀이 필요한 RPC 가 거절된다', async () => {
  for (const m of ['storeRegistration', 'consentLogin', 'updateUserCred', 'syncAttrs', 'selfRevoke', 'consentRevokeSession']) {
    await assert.rejects(() => call(m, {}), /not_registered|등록/, `${m} 은 등록을 요구한다`);
  }
});

console.log(failed ? `\n${failed} failed` : '\nall passed');
process.exit(failed === 0 ? 0 : 1);
