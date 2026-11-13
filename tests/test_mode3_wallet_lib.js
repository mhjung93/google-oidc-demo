// 지갑 라이브러리의 체인·zkey 없는 부분(V11) — 등록값·요청 인증 증명(스텁)·ProofCache. (unit)  node tests/test_mode3_wallet_lib.js
import assert from 'node:assert/strict';
import { createRegistration, registrationSecretsFromSeed, buildAuthProof, buildCredentialProof, ProofCache, chooseMaxHeight } from '../lib/mode3_wallet.js';
import { auidOf, auidSOf, userCommit, sessionCommit, registerCtx, issueCtx, aridSOf, tagOf, SCALAR_MAX } from '../lib/mode3_credential.js';
import * as walletLib from '../lib/mode3_wallet.js';
import { IDP_PUB_INDEX, idpPublicSignals, verifyIdp } from '../lib/mode3_idp_proof.js';

let fails = 0;
async function t(name, fn) { try { await fn(); console.log('ok   -', name); } catch (e) { fails++; console.log('FAIL -', name, '\n      ', e.message); } }

await t('createRegistration(uid) = { s_u, auid = Poseidon(T_AUID, uid, s_u), seed } — 등록 키(sk_u·pk_u)는 없다; uid 없이는 throw', async () => {
  const reg = await createRegistration(12345n);
  assert.deepEqual(Object.keys(reg).sort(), ['auid', 's_u', 'seed']);
  assert.ok(reg.s_u < SCALAR_MAX); assert.match(reg.seed, /^[0-9a-f]{64}$/);
  assert.equal(reg.auid, await auidOf({ uid: 12345n, s_u: reg.s_u }));
  await assert.rejects(() => createRegistration(), /uid/);
  assert.notEqual((await createRegistration(12345n)).auid, reg.auid, 's_u 가 매번 다르다');
});
await t('registrationSecretsFromSeed: 같은 시드 → 같은 s_u(유도 규칙 그대로), sk_u 는 돌려주지 않는다', () => {
  const seed = new Uint8Array(32).fill(7);
  const a = registrationSecretsFromSeed(seed);
  assert.deepEqual(Object.keys(a), ['s_u']);
  assert.ok(a.s_u < SCALAR_MAX);
  assert.equal(registrationSecretsFromSeed(new Uint8Array(32).fill(7)).s_u, a.s_u);
  assert.notEqual(registrationSecretsFromSeed(new Uint8Array(32).fill(8)).s_u, a.s_u);
});
await t('서명 함수는 없어졌다 — eddsaPubOf·signRegistration·signSlotRequest·signRevokeSession·signIssueRequest', () => {
  for (const k of ['eddsaPubOf', 'signRegistration', 'signSlotRequest', 'signRevokeSession', 'signIssueRequest']) assert.equal(k in walletLib, false, k);
});
await t('buildAuthProof: 버릴 값(attrs·arid·pk_i·max_height = 0, 새 blind·r_rp·r_s)으로 π_IdP 를 만들고 본문 조각을 10진 문자열로 돌려준다', async () => {
  const reg = await createRegistration(12345n);
  const ctx = await registerCtx({ n: 77n });
  const calls = [];
  const fullProve = async (input) => { calls.push(input); return { proof: { stub: true }, publicSignals: [] }; };
  const a = await buildAuthProof({ uid: 12345n, s_u: reg.s_u, ctx, fullProve });
  assert.deepEqual(Object.keys(a).sort(), ['C_s_pt', 'C_u_pt', 'auid_s', 'max_height', 'proof_idp', 'tag']);
  assert.deepEqual(a.proof_idp, { stub: true }); assert.equal(a.max_height, '0');
  assert.equal(a.tag, (await tagOf({ s_u: reg.s_u, ctx })).toString());
  const inp = calls[0];
  assert.equal(inp.uid, '12345'); assert.equal(inp.auid, reg.auid.toString()); assert.equal(inp.ctx, ctx.toString()); assert.equal(inp.tag, a.tag);
  assert.deepEqual(inp.attrs, ['0', '0', '0', '0', '0', '0']); assert.equal(inp.arid, '0'); assert.equal(inp.pk_i, '0'); assert.equal(inp.max_height, '0');
  // 공개값이 비밀과 맞는다: C_u·C_s·auid_s 를 입력의 비밀로 다시 계산
  const cu = await userCommit({ uid: 12345n, s_u: reg.s_u, blind_u: BigInt(inp.blind_u), attrs: [] });
  assert.deepEqual(a.C_u_pt, { x: cu.Cx.toString(), y: cu.Cy.toString() });
  const cs = await sessionCommit({ pk_i: 0n, max_height: 0n, r_s: BigInt(inp.r_s), r_rp: BigInt(inp.r_rp) });
  assert.deepEqual(a.C_s_pt, { x: cs.Cx.toString(), y: cs.Cy.toString() });
  assert.equal(a.auid_s, (await auidSOf({ auid: reg.auid, arid: 0n, r_rp: BigInt(inp.r_rp) })).toString());
  // blind 는 매번 새 난수다 — C_u 에 진짜 s_u 가 들어가므로 같은 blind 를 다시 쓰면 요청들이 서로 묶인다
  const b = await buildAuthProof({ uid: 12345n, s_u: reg.s_u, ctx, fullProve });
  assert.notDeepEqual(b.C_u_pt, a.C_u_pt); assert.notDeepEqual(b.C_s_pt, a.C_s_pt); assert.equal(b.tag, a.tag, 'tag 는 (s_u, ctx) 만으로 정해진다');
  await assert.rejects(() => buildAuthProof({ uid: 12345n, s_u: reg.s_u, ctx: '5', fullProve }), /ctx/);
});
// 리뷰 지적: counter 경계 가드(lib/mode3_wallet.js:243 부근)는 함수 초입이라 다른 무거운 일(증명·트리 조회) 전에 던져야 한다 —
// 다른 인자는 전부 트리비얼한 자리표시(bigint 1n·{x:1n,y:1n}·빈 registry·slot 0)만 채워 counter 검사까지만 도달시킨다.
await t('buildCredentialProof: counter 가 [0, 2^32) bigint 가 아니면(2^32·숫자형) 다른 무거운 일 전에 /counter/ 로 reject', async () => {
  const base = { uid: 1n, arid: 1n, s_u: 1n, auid: 1n, blind_u: 1n, r_rp: 1n, r_s: 1n, pk_i: 1n, pk_trace: { x: 1n, y: 1n }, registry: {}, slot: 0 };
  await assert.rejects(() => buildCredentialProof({ ...base, counter: 1n << 32n }), /counter/, '상한');
  await assert.rejects(() => buildCredentialProof({ ...base, counter: 5 }), /counter/, 'bigint 가 아닌 number');
});
await t('idpPublicSignals: 10개 10진 문자열, 순서 = IDP_PUB_INDEX; 범위 밖은 throw', () => {
  const pub = idpPublicSignals({ uid: 1n, auid: 2n, auid_s: 3n, C_u_pt: { x: 4n, y: 5n }, C_s_pt: { x: 6n, y: 7n }, max_height: 8n, ctx: 9n, tag: 10n });
  assert.deepEqual(pub, ['1', '2', '3', '4', '5', '6', '7', '8', '9', '10']); assert.equal(IDP_PUB_INDEX.COUNT, 10); assert.equal(pub[IDP_PUB_INDEX.MAX_HEIGHT], '8');
  assert.equal(pub[IDP_PUB_INDEX.CTX], '9'); assert.equal(pub[IDP_PUB_INDEX.TAG], '10');
  assert.throws(() => idpPublicSignals({ uid: SCALAR_MAX, auid: 2n, auid_s: 3n, C_u_pt: { x: 4n, y: 5n }, C_s_pt: { x: 6n, y: 7n }, max_height: 8n, ctx: 9n, tag: 10n }), /uid/);
  assert.throws(() => idpPublicSignals({ uid: 1n, auid: 2n, auid_s: 3n, C_u_pt: { x: 4n, y: 5n }, C_s_pt: { x: 6n, y: 7n }, max_height: 1n << 64n, ctx: 9n, tag: 10n }), /max_height/);
  assert.throws(() => idpPublicSignals({ uid: 1n, auid: 2n, auid_s: 3n, C_u_pt: { x: 4n, y: 5n }, C_s_pt: { x: 6n, y: 7n }, max_height: 8n, ctx: 9n }), /ctx·tag/);
});
// 리뷰(2026-10-13) 테스트 공백: verifyIdp 의 입력 검사 음성 케이스. vkey 는 접근을 기록하는 Proxy 다 — 형식 검사에서 거절되면 snarkjs 까지 가지
// 않으므로 touched 가 false 로 남는다(snarkjs 가 던져서 false 가 된 것과 구별된다). 대조군(정규 10개)은 snarkjs 까지 가서 vkey 를 읽는다.
await t('verifyIdp: 길이 8·9·11, 앞자리 0, 10진 아님(음수·0x·공백·숫자형)은 snarkjs 전에 false; 증명이 객체가 아니면 false', async () => {
  let touched = false;
  const vkey = new Proxy({}, { get: (o, k) => { touched = true; return undefined; }, ownKeys: () => { touched = true; return []; }, has: () => { touched = true; return false; } });
  const good = ['1', '2', '3', '4', '5', '6', '7', '8', '9', '10'];
  const proof = { pi_a: ['1', '2', '1'], pi_b: [['1', '2'], ['3', '4'], ['1', '0']], pi_c: ['1', '2', '1'], protocol: 'groth16', curve: 'bn128' };
  const bad = [
    ['길이 9', good.slice(0, 9)], ['길이 11', [...good, '11']], ['길이 8(옛 형식)', good.slice(0, 8)], ['배열 아님', '1,2,3,4,5,6,7,8,9,10'],
    ['앞자리 0', ['01', ...good.slice(1)]], ['앞자리 0(뒤쪽)', [...good.slice(0, 9), '007']],
    ['음수', ['-1', ...good.slice(1)]], ['0x', ['0x1', ...good.slice(1)]], ['공백', [' 1', ...good.slice(1)]], ['+', ['+1', ...good.slice(1)]],
    ['빈 문자열', ['', ...good.slice(1)]], ['숫자형', [1, ...good.slice(1)]], ['bigint', [1n, ...good.slice(1)]],
  ];
  for (const [label, pub] of bad) {
    touched = false;
    assert.equal(await verifyIdp(vkey, pub, proof), false, label);
    assert.equal(touched, false, `${label}: 형식 검사에서 거절돼 vkey 를 읽지 않아야 한다`);
  }
  for (const p of [null, undefined, 'proof', 7]) { touched = false; assert.equal(await verifyIdp(vkey, good, p), false, String(p)); assert.equal(touched, false, `proof=${String(p)}`); }
  // 대조군: 정규 10개·객체 증명은 형식 검사를 지나 snarkjs 가 vkey 를 읽는다(가짜 vkey 라 결과는 false — 예외는 삼킨다)
  touched = false;
  assert.equal(await verifyIdp(vkey, good, proof), false);
  assert.equal(touched, true, '정규 입력은 snarkjs 까지 가야 한다(위 거절들이 형식 검사 덕임을 보이는 대조군)');
});
await t('V10 ProofCache.rootKey(chainId, rev, reg) = "chainId:rev:reg", 2인자는 throw, deleteSession 은 세션만', () => {
  assert.equal(ProofCache.rootKey(31337n, 1n, 2n), '31337:1:2');
  assert.throws(() => ProofCache.rootKey(1n, 2n));
  assert.notEqual(ProofCache.rootKey(1n, 5n, 6n), ProofCache.rootKey(2n, 5n, 6n));
  const c = new ProofCache();
  c.set(ProofCache.rootKey(31337n, 1n, 2n), '77', 'a', '1:0,0:0,0:0:0'); c.set(ProofCache.rootKey(31337n, 1n, 2n), '88', 'b');
  c.deleteSession('77');
  assert.equal(c.get(ProofCache.rootKey(31337n, 1n, 2n), '77', '1:0,0:0,0:0:0'), null); assert.equal(c.get(ProofCache.rootKey(31337n, 1n, 2n), '88'), 'b');
});
await t('chooseMaxHeight 그리드', () => { assert.equal(chooseMaxHeight(1234n), 1600n); assert.equal(chooseMaxHeight(10n, { ttlBlocks: 5n, grid: 1n }), 15n); });
await t('R7: proveIdp 는 fullProve 를 주입받는다 — 회로 입력 전부를 넘기고 결과를 그대로 돌려준다', async () => {
  const { proveIdp } = await import('../lib/mode3_idp_proof.js');
  const calls = [];
  const stub = async (input, wasmPath, zkeyPath) => { calls.push({ input, wasmPath, zkeyPath }); return { proof: { pi_a: ['stub'] }, publicSignals: ['1', '2'] }; };
  const out = await proveIdp({ uid: 12345n, s_u: 7n, blind_u: 8n, attrs: [1990n, 410n], arid: 3n, r_rp: 4n, pk_i: 5n, r_s: 6n, auid: 9n, auid_s: 10n, C_u_pt: { x: 1n, y: 2n }, C_s_pt: { x: 3n, y: 4n }, max_height: 100n, ctx: 11n, tag: 12n, wasmPath: 'W', zkeyPath: 'Z', fullProve: stub });
  assert.deepEqual(out, { proof: { pi_a: ['stub'] }, publicSignals: ['1', '2'] });
  assert.equal(calls.length, 1); assert.equal(calls[0].wasmPath, 'W'); assert.equal(calls[0].zkeyPath, 'Z');
  assert.deepEqual(Object.keys(calls[0].input).sort(), ['C_s_x', 'C_s_y', 'C_u_x', 'C_u_y', 'arid', 'attrs', 'auid', 'auid_s', 'blind_u', 'ctx', 'max_height', 'pk_i', 'r_rp', 'r_s', 's_u', 'tag', 'uid']);
  assert.deepEqual(calls[0].input.attrs, ['1990', '410', '0', '0', '0', '0']);
});
await t('buildIssueRequest: sk_u 없이 — 본문에 sig_u 대신 tag·n, ctx = issueCtx(arid_s, chainid, allowAgent, n); fullProve 를 proveIdp 에 넘긴다', async () => {
  const { buildIssueRequest, createSessionKey } = await import('../lib/mode3_wallet.js');
  const reg = await createRegistration(12345n);
  let seen = null;
  const req = await buildIssueRequest({ uid: 12345n, s_u: reg.s_u, blind_u: 11n, attrs: [1990n, 410n], arid: 3n, r_rp: 4n, r_s: 6n, session: createSessionKey(), chainid: 31337n, allowAgent: 1n, max_height: 100n, fullProve: async (input) => { seen = input; return { proof: { stub: true }, publicSignals: [] }; } });
  assert.ok(seen && seen.uid === '12345', 'proveIdp 가 주입된 fullProve 로 돌았다');
  assert.deepEqual(req.body.proof_idp, { stub: true });
  assert.equal('sig_u' in req.body, false);
  assert.match(req.body.n, /^[0-9]+$/); assert.equal(req.n.toString(), req.body.n);
  const ctx = await issueCtx({ arid_s: await aridSOf({ arid: 3n, r_rp: 4n }), chainid: 31337n, allowAgent: 1n, n: req.n });
  assert.equal(req.body.tag, (await tagOf({ s_u: reg.s_u, ctx })).toString());
  assert.equal(req.tag.toString(), req.body.tag); assert.equal(seen.ctx, ctx.toString()); assert.equal(seen.tag, req.body.tag);
  assert.equal(req.body.auid_s, req.auid_s.toString());
});
// 2026-11-13(사용자 결정): 발급 ctx 의 난수 n 은 지갑이 요청마다 뽑는다. 한 스냅의 여러 계정이 같은 s_u 를 쓰게 돼도(스펙 초안 2026-11-13 snap-random-salt-backup R1),
// RP 가 r_rp 를 되풀이해 같은 tag 를 내게 만들어 IdP 가 두 계정을 묶는 길이 없다 — tag 가 (s_u, ctx) 만으로 정해지므로 ctx 가 요청마다 달라야 한다.
await t('buildIssueRequest: 같은 s_u·arid·r_rp·chainid·allowAgent 라도 요청마다 tag 가 다르다(uid 가 달라도, 같아도); n 을 주면 그 n 으로 — Google nonce 를 미리 계산한 요청이 같은 tag 를 낸다', async () => {
  const { buildIssueRequest, createSessionKey } = await import('../lib/mode3_wallet.js');
  const fullProve = async () => ({ proof: { stub: true }, publicSignals: [] });
  const base = { s_u: 777n, blind_u: 11n, attrs: [1990n, 410n], arid: 3n, r_rp: 4n, r_s: 6n, chainid: 31337n, allowAgent: 0n, max_height: 100n, fullProve };
  const a = await buildIssueRequest({ ...base, uid: 111n, session: createSessionKey() });
  const b = await buildIssueRequest({ ...base, uid: 222n, session: createSessionKey() });   // 다른 계정, 같은 s_u·같은 r_rp
  const a2 = await buildIssueRequest({ ...base, uid: 111n, session: createSessionKey() });
  assert.equal(a.arid_s, b.arid_s, 'r_rp 가 같으면 arid_s 는 같다(RP 가 되풀이한 상황)');
  assert.notEqual(a.tag, b.tag, '다른 계정의 tag 가 같으면 IdP 가 둘을 묶는다'); assert.notEqual(a.tag, a2.tag); assert.notEqual(a.n, b.n);
  const fixed = await buildIssueRequest({ ...base, uid: 111n, session: createSessionKey(), n: 42n });
  assert.equal(fixed.body.n, '42');
  assert.equal(fixed.tag, await tagOf({ s_u: 777n, ctx: await issueCtx({ arid_s: a.arid_s, chainid: 31337n, allowAgent: 0n, n: 42n }) }));
  await assert.rejects(() => buildIssueRequest({ ...base, uid: 111n, session: createSessionKey(), n: '42' }), /n/);
});
process.exit(fails ? 1 : 0);
