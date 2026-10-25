// snap-mode3 단위 테스트 — 스펙 2026-09-22 metamask-snap §3.1 의 RPC 표·상태 모양이 정본이고,
// tests/helpers/snap_sim.mjs(시뮬레이터)와 같은 입출력을 지켜야 한다. MetaMask 없이 전역 `snap` 을 스텁으로 대신한다
// (`snap_manageState` 는 메모리 맵, `snap_dialog` 는 시나리오별 응답 큐).
//   node snap-mode3/test/rpc.test.mjs
// scripts/run_tests.sh 의 `snap` 그룹이 이 파일을 돌린다(2026-09-22 Ruling 9): `bash scripts/run_tests.sh snap`.
// 체인도 브라우저도 필요 없지만 snap-mode3/node_modules(@metamask/snaps-sdk)를 전제하므로 unit 이 아니라 별도 그룹이다.
import assert from 'node:assert/strict';
import fs from 'node:fs';
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

// V11 갱신(2026-10-23): register 는 더 이상 비밀번호를 프롬프트로 받지 않는다 — 지갑 페이지가 넘긴 uid 를 받아
// 확인 창 하나만 띄운다. bad_uid 검사가 확인 창보다 먼저라 대화상자를 띄우지 않고 거절해야 한다.
await t('register: uid 가 10진 문자열이 아니면 bad_uid, 확인창은 뜨지 않는다', async () => {
  const before = dialogs.length;
  await assert.rejects(() => call('register', { uid: 'abc' }), /bad_uid/);
  assert.equal(store.state, null, '검증 실패는 상태를 만들지 않는다');
  assert.equal(dialogs.length, before, 'bad_uid 는 확인창을 띄우기 전에 거절된다');
});

await t('register({ uid }): 거절하면 { denied: true }, 상태는 그대로 null', async () => {
  const before = dialogs.length;
  answers.push(false);
  assert.deepEqual(await call('register', { uid: '12345' }), { denied: true });
  assert.equal(dialogs.length, before + 1, '확인창 한 번');
  assert.equal(dialogs[before].type, 'confirmation');
  assert.equal(store.state, null, '거절은 등록을 만들지 않는다');
});

await t('register({ uid }): 확인창 한 번 → { uid, s_u, sk_u }(pwd 없음), 상태에 s_u·sk_u, 대화상자에 uid 있고 비밀번호 문구 없음', async () => {
  const before = dialogs.length;
  answers.push(true);
  registered = await call('register', { uid: '12345' });
  assert.equal(registered.uid, '12345');
  assert.equal('pwd' in registered, false, 'pwd 는 더 이상 없다');
  assert.match(registered.s_u, /^[0-9]+$/);
  assert.match(registered.sk_u, /^[0-9a-fA-F]{64}$/);
  assert.equal(dialogs.length, before + 1, '확인창 한 번');
  assert.equal(dialogs[before].type, 'confirmation');
  const d = lastDialogText();
  assert.ok(d.includes('12345'), '대화상자에 uid 가 보인다');
  assert.ok(!d.includes('비밀번호'), '대화상자에 비밀번호 문구가 없다');
  const reg = store.state.registration;
  assert.equal(store.state.version, 1);
  assert.equal(reg.s_u, registered.s_u);
  assert.ok(BigInt(reg.s_u) < (1n << 250n), '스칼라는 2^250 미만');
  assert.equal(reg.sk_u, registered.sk_u);
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

await t('storeRegistration: attrs 는 6개(짧으면 bad_attrs)·slot 저장, auid 없으면 bad_auid, sk_u 는 받지 않는다', async () => {
  await assert.rejects(() => call('storeRegistration', { attrs: ATTRS.slice(0, 4), slot: SLOT, auid }), /bad_attrs/);
  await assert.rejects(() => call('storeRegistration', { attrs: ATTRS, slot: SLOT }), /bad_auid/);
  assert.deepEqual(await call('storeRegistration', { attrs: ATTRS, slot: SLOT, auid }), { ok: true });
  assert.deepEqual(store.state.registration.attrs, ATTRS);
  assert.equal(store.state.registration.slot, SLOT);
  assert.equal(store.state.registration.auid, auid);
  assert.equal(store.state.registration.sk_u, registered.sk_u, 'storeRegistration 은 sk_u 를 건드리지 않는다');
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
  assert.deepEqual(Object.keys(info).sort(), ['attrs', 'auid', 'consents', 'hasUserCred', 'pending', 'provider', 'registered', 'slot', 'uid']);
  assert.equal(info.registered, true);
  assert.equal(info.uid, '12345');
  assert.equal(info.auid, auid);
  assert.deepEqual(info.attrs, ATTRS);
  assert.equal(info.slot, SLOT);
  assert.equal(info.hasUserCred, false);
  const s = JSON.stringify(info);
  for (const secret of [store.state.registration.s_u, registered.sk_u]) {
    assert.ok(!s.includes(secret), `공개 정보에 비밀이 실렸다: ${secret.slice(0, 8)}…`);
  }
});

// 리뷰 2026-10-13 U3: buildWitness 가 sk_u 를 문자열이면 그대로 받아 줬다(64자 16진 검사 없음) — 손상된 상태라도
// 형식 검사를 통과해 그대로 지갑 페이지로 나갔다. 기존 사유(registration_incomplete)는 그대로 두고 검사만 좁힌다.
await t('buildWitness: sk_u 가 64자 16진이 아니면 registration_incomplete(상태는 건드리지 않는다)', async () => {
  const savedSkU = store.state.registration.sk_u;
  store.state.registration.sk_u = 'zz'.repeat(32);   // 길이는 64지만 16진이 아니다
  answers.push(true);
  await assert.rejects(() => call('consentLogin', { origin: RP_ORIGIN, arid: '777', allowAgent: '0' }), /registration_incomplete/);
  store.state.registration.sk_u = savedSkU;
});

await t('consentLogin 승인 → validateWitness 를 통과하는 증인, consents 기록', async () => {
  answers.push(true);
  const w = await call('consentLogin', { origin: RP_ORIGIN, arid: '777', allowAgent: '1', serviceName: '데모 RP' });
  // auid 까지 준다 — 증인의 s_u 가 register 가 낸 auid 와 실제로 묶였는지 본다(최종 리뷰 Minor 1 의 V11 판).
  await validateWitness(w, '12345', auid);
  assert.equal(w.uid, '12345');
  assert.equal(w.sk_u, registered.sk_u, 'buildWitness 의 sk_u 는 register 때 만든 것과 같다');
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

// 2026-09-25 리뷰 D-2: serviceName 은 RP 가 준 임의의 문자열이다(인증서가 덮는 것은 origin 뿐).
// 개행으로 가짜 줄을 끼워 넣거나 긴 이름으로 창을 밀어내지 못해야 한다.
await t('consentLogin: RP 이름은 한 줄·48자로 잘린다(개행·제어문자 제거), 빈 이름은 오리진으로', async () => {
  answers.push(true);
  const evil = `가짜 은행\n${LS}오리진: http://real-bank.example${PS}\u0007 ${'가'.repeat(200)}`;
  await call('consentLogin', { origin: RP_ORIGIN, arid: '777', allowAgent: '0', serviceName: evil });
  const lines = dialogs[dialogs.length - 1].content.children.map((c) => c.value ?? '');
  const svc = lines.find((l) => l.startsWith('RP: '));
  assert.ok(svc, `RP 줄이 없다: ${JSON.stringify(lines)}`);
  assert.ok(!/[\u0000-\u001f\u007f]/.test(svc), `제어문자가 남았다: ${JSON.stringify(svc)}`);
  assert.ok(!svc.includes(LS) && !svc.includes(PS), `줄분리자가 남았다: ${JSON.stringify(svc)}`);
  assert.ok(svc.length <= 'RP: '.length + 48, `한 줄 48자를 넘었다(${svc.length}): ${JSON.stringify(svc)}`);
  assert.ok(lines.includes(`오리진: ${RP_ORIGIN}`), '진짜 오리진 줄은 그대로다');
  answers.push(true);
  await call('consentLogin', { origin: RP_ORIGIN, arid: '777', allowAgent: '0', serviceName: '   ' });
  const blank = dialogs[dialogs.length - 1].content.children.map((c) => c.value ?? '');
  assert.ok(blank.includes(`RP: ${RP_ORIGIN}`), `빈 이름은 오리진으로 대체된다: ${JSON.stringify(blank)}`);
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

await t('consentRevokeSession: 대화상자에 arid·발급 시각·허용 거래 수가 보이고 승인/거절', async () => {
  answers.push(true);
  assert.deepEqual(await call('consentRevokeSession', { arid: '777', issuedAt: '2026-09-24T00:00:00Z', maxHeight: '1000', bound: '3' }), { ok: true });
  const d = lastDialogText();
  for (const part of ['777', '2026-09-24', '폐기', '허용 거래 수: 3', 'nonce < 3']) assert.ok(d.includes(part), `대화상자에 ${part} 가 없다`);
  answers.push(false);
  assert.deepEqual(await call('consentRevokeSession', { arid: '777', issuedAt: 'x', maxHeight: '1', bound: '3' }), { denied: true });
});

// bound 는 Task 9 이전 호출(있다면)과의 하위호환 — 없으면 0 으로 동작하고 던지지 않는다.
await t('consentRevokeSession: bound 가 없으면 0 으로 동작한다(하위호환)', async () => {
  answers.push(true);
  assert.deepEqual(await call('consentRevokeSession', { arid: '777', issuedAt: '2026-09-24T00:00:00Z', maxHeight: '1000' }), { ok: true });
  const d = lastDialogText();
  assert.ok(d.includes('허용 거래 수: 0'), `대화상자에 기본값이 없다: ${d}`);
});

await t('showSalt: 승인하면 { s_u }(저장된 값과 같다, 대화상자엔 실제 값이 없다), 거절하면 denied', async () => {
  const savedSU = store.state.registration.s_u;
  const before = dialogs.length;
  answers.push(true);
  const r = await call('showSalt', {});
  assert.deepEqual(r, { s_u: savedSU });
  assert.equal(dialogs.length, before + 1);
  assert.equal(dialogs[before].type, 'confirmation');
  assert.ok(!lastDialogText().includes(savedSU), '대화상자에 salt 값 자체는 보이지 않는다(경고문뿐)');
  answers.push(false);
  assert.deepEqual(await call('showSalt', {}), { denied: true });
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
  assert.ok(!stateJson().includes(registered.sk_u), '초기화 뒤 비밀이 남지 않는다');
});

await t('prepareRegister: 거절이면 { denied } 이고 상태가 없다; 승인이면 uid 없는 보류 등록 — registered=false, pending=true', async () => {
  answers.push(false);
  assert.deepEqual(await call('prepareRegister', {}), { denied: true });
  assert.equal(store.state, null, '거절은 상태를 만들지 않는다');
  answers.push(true);
  const p = await call('prepareRegister', {});
  assert.match(p.s_u, /^[0-9]+$/); assert.match(p.sk_u, /^[0-9a-f]{64}$/);
  assert.ok(/Google/.test(lastDialogText()), '확인 창 제목에 Google');
  assert.ok(!lastDialogText().includes(p.sk_u) && !lastDialogText().includes(p.s_u), '확인 창에 비밀 값은 없다');
  const info = await call('getPublicInfo', {});
  assert.equal(info.registered, false); assert.equal(info.pending, true); assert.equal(info.uid, null); assert.equal(info.provider, null);
  // 다시 시도(Google 단계 실패 뒤) — 같은 비밀(같은 pk_u → 같은 nonce)
  answers.push(true);
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
  answers.push(true); const p = await call('prepareRegister', {});
  answers.push(true); const r = await call('register', { uid: '42' });
  assert.equal(r.uid, '42'); assert.notEqual(r.sk_u, p.sk_u, 'register 는 새 비밀을 만든다');
  assert.equal((await call('getPublicInfo', {})).pending, false);
  answers.push(true); assert.deepEqual(await call('reset', {}), { ok: true });
  answers.push(true); const p2 = await call('prepareRegister', {});
  answers.push(true); assert.deepEqual(await call('reset', {}), { ok: true });
  assert.ok(!String(stateJson()).includes(p2.sk_u), 'reset 뒤 보류 비밀이 남지 않는다');
  assert.equal(store.state, null);
});

await t('등록 전에는 비밀이 필요한 RPC 가 거절된다', async () => {
  for (const m of ['storeRegistration', 'consentLogin', 'updateUserCred', 'syncAttrs', 'selfRevoke', 'consentRevokeSession', 'showSalt']) {
    await assert.rejects(() => call(m, {}), /not_registered|등록/, `${m} 은 등록을 요구한다`);
  }
});

console.log(failed ? `\n${failed} failed` : '\nall passed');
process.exit(failed === 0 ? 0 : 1);
