// tests/test_mode3_rp_relay.mjs — RP 릴레이(스펙 2026-10-15 §5.1, 계획 R6): 양성 1 + 음성 6(비활성·대상·셀렉터·arid·가스 상한·속도 제한)·CORS.
// 2026-10-26 리뷰 E2: 증명이 틀린 calldata 는 배포 전에 relay_bad_proof. E1: 로그인 proof 정규화(로그 줄 크기 상한·비정규 숫자 400).
// file 모드 에이전트의 /wallet/tx/prepare 가 만든 진짜 calldata 를 쓴다. :8545 와 build/mode3 필요. (chain)
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { ethers } from 'ethers';
import { startIsolatedMode3Stack } from './helpers/isolated_mode3_stack.mjs';
import { getProvider } from './helpers/mode3_chain.mjs';
import { walletInterface, decodeExecuteCalldata, parseExecuteReceipt, factoryAt, FACTORY_ABI } from '../lib/mode3_onchain.js';

const stack = await startIsolatedMode3Stack({ autoRelay: true });
const { wallet, rp, cia } = stack;
const provider = getProvider();
let fails = 0; async function t(n, f) { try { await f(); console.log('ok   -', n); } catch (e) { fails++; console.log('FAIL -', n, '\n      ', e.message); } }
const relay = (body, origin = wallet.origin) => rp.post('/api/mode3/relay', body, { Origin: origin });
const relayRaw = (body, headers = {}) => rp.raw('/api/mode3/relay', { method: 'POST', headers: { 'Content-Type': 'application/json', Origin: wallet.origin, ...headers }, body: JSON.stringify(body) });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function waitReceipt(hash) { for (let i = 0; i < 60; i++) { const r = await provider.getTransactionReceipt(hash); if (r) return r; await sleep(300); } throw new Error('영수증 없음 ' + hash); }
try {
  // 준비: 등록 → RP 챌린지 → 에이전트 로그인 → RP 로그인 → 세션 r_s. (test_mode3_demo_stack.mjs 의 로그인 각본과 같다)
  assert.equal((await wallet.post('/wallet/register', { uid: '12345', pwd: 'password123' })).status, 201);
  const info = (await rp.get('/api/mode3/rp_info')).body;
  const ch = (await rp.post('/api/mode3/challenge')).body;
  const lg = await wallet.post('/wallet/login', { arid: info.arid, origin: info.origin, cert_s: info.cert_s, pk_trace: info.pk_trace, r_s: ch.r_s, r_rp: ch.r_rp, factoryAddress: info.factoryAddress, attrGateAddress: info.attrGateAddress }, { Origin: rp.origin });
  assert.equal(lg.status, 200, JSON.stringify(lg.body));
  assert.equal((await rp.post('/api/mode3/login', { proof: lg.body.proof, publicSignals: lg.body.publicSignals, sig: lg.body.sig, r_s: ch.r_s })).body.ok, true);
  const prepare = (extra = {}) => wallet.post('/wallet/tx/prepare', { r_s: ch.r_s, to: '0x000000000000000000000000000000000000dEaD', value: '0', data: '0x', ...extra });
  const factory = factoryAt(info.factoryAddress, provider);
  const reencode = (dec, { a = dec.a, pub = dec.pub } = {}) => walletInterface.encodeFunctionData('execute', [dec.payload, dec.sig, a.map(BigInt), dec.b.map((row) => row.map(BigInt)), dec.c.map(BigInt), pub.map(BigInt)]);

  // 첫 양성보다 앞에 둔다 — 계정이 아직 배포되지 않은 상태에서만 "배포하지 않았다" 를 getCode 로 확인할 수 있다.
  await t('E2(2026-10-26): 증명이 틀린 calldata 는 배포 전에 400 relay_bad_proof — 계정 코드는 그대로 0x', async () => {
    const p = await prepare(); assert.equal(p.status, 200, JSON.stringify(p.body)); assert.equal(p.body.deployNeeded, true);
    const dec = decodeExecuteCalldata(p.body.calldata);
    const badA = [...dec.a]; badA[0] = (BigInt(badA[0]) + 1n).toString();
    let r = await relay({ to: p.body.walletAddr, data: reencode(dec, { a: badA }) });
    assert.equal(r.status, 400, JSON.stringify(r.body)); assert.equal(r.body.reason, 'relay_bad_proof');
    assert.equal(await provider.getCode(p.body.walletAddr), '0x', '증명 확인 전에 배포하면 안 된다');
    // 공격 각본: arid 는 공개(rp_info)이므로 PPID 만 바꾸고 to 를 그 PPID 의 주소로 맞추면 대상 검사·속도 제한(대상별)을 매번 통과한다.
    const pub = [...dec.pub]; pub[0] = (BigInt(pub[0]) + 1n).toString();
    const other = await factory.computeAddress(BigInt(pub[0]));
    r = await relay({ to: other, data: reencode(dec, { pub }) });
    assert.equal(r.status, 400, JSON.stringify(r.body)); assert.equal(r.body.reason, 'relay_bad_proof');
    assert.equal(await provider.getCode(other), '0x', '임의 PPID 계정을 배포하면 안 된다(릴레이어 가스 소모)');
  });

  await t('양성: 첫 execute — 릴레이어가 계정을 배포하고 보낸다, 영수증에 Executed·Mode3Auth', async () => {
    const p = await prepare(); assert.equal(p.status, 200, JSON.stringify(p.body)); assert.equal(p.body.deployNeeded, true);
    const r = await relay({ to: p.body.walletAddr, data: p.body.calldata });
    assert.equal(r.status, 200, JSON.stringify(r.body)); assert.equal(r.body.ok, true); assert.equal(r.body.deployed, true); assert.match(r.body.deployTxHash, /^0x[0-9a-f]{64}$/);
    const rc = await waitReceipt(r.body.txHash);
    assert.equal(rc.status, 1); const parsed = parseExecuteReceipt(rc, p.body.walletAddr); assert.equal(parsed.executed.success, true); assert.ok(parsed.auth);
    const st = (await rp.get(`/api/mode3/relay/${r.body.txHash}`)).body; assert.equal(st.pending, false); assert.equal(st.status, 1);
    assert.equal((await rp.get('/api/mode3/relay/0xzz')).status, 400);
    assert.equal((await rp.get(`/api/mode3/relay/0x${'11'.repeat(32)}`)).body.pending, true);
  });
  await t('양성 2: 두 번째 execute 는 배포 없이(deployed:false), 영수증 성공', async () => {
    const p = await prepare(); assert.equal(p.body.deployNeeded, false);
    const r = await relay({ to: p.body.walletAddr, data: p.body.calldata });
    assert.equal(r.status, 200, JSON.stringify(r.body)); assert.equal(r.body.deployed, false);
    assert.equal((await waitReceipt(r.body.txHash)).status, 1);
  });
  await t('기록(2026-10-21): GET /api/mode3/txs 가 릴레이한 두 건을 보낸 순서대로 담고, 영수증 뒤 상태가 success 다', async () => {
    let txs = []; const deadline = Date.now() + 10_000;
    while (Date.now() < deadline) { txs = (await rp.get('/api/mode3/txs')).body.txs; if (txs.length >= 2 && txs.slice(0, 2).every((x) => x.status !== 'pending')) break; await new Promise((r) => setTimeout(r, 200)); }
    assert.ok(txs.length >= 2, JSON.stringify(txs));
    for (const x of txs.slice(0, 2)) {
      assert.match(x.txHash, /^0x[0-9a-f]{64}$/); assert.match(x.account, /^0x[0-9a-fA-F]{40}$/); assert.match(x.PPID, /^[0-9]+$/);
      assert.equal(x.status, 'success', JSON.stringify(x)); assert.ok(['transfer', 'claim'].includes(x.kind)); assert.equal(typeof x.blockNumber, 'number');
    }
    assert.match(txs[0].deployTxHash, /^0x[0-9a-f]{64}$/, '첫 건은 계정 배포가 함께 있었다'); assert.equal(txs[1].deployTxHash, null);
  });
  await t('음성: value 가 0 이 아니면·to 가 주소가 아니면·data 가 hex 가 아니면 400 relay_bad_calldata', async () => {
    const p = (await prepare()).body;
    for (const b of [{ to: p.walletAddr, data: p.calldata, value: '1' }, { to: 'nope', data: p.calldata }, { to: p.walletAddr, data: 'zz' }]) { const r = await relay(b); assert.equal(r.status, 400, JSON.stringify(b).slice(0, 60)); assert.equal(r.body.reason, 'relay_bad_calldata'); }
  });
  await t('음성: execute 가 아닌 calldata(팩토리 deploy)·pub[1]≠arid 는 relay_bad_calldata', async () => {
    const p = (await prepare()).body;
    const deployData = new ethers.Interface(FACTORY_ABI).encodeFunctionData('deploy', [1n]);
    let r = await relay({ to: p.walletAddr, data: deployData }); assert.equal(r.status, 400); assert.equal(r.body.reason, 'relay_bad_calldata'); assert.equal(r.body.detail, 'selector');
    const dec = decodeExecuteCalldata(p.calldata);
    const pub = dec.pub.map(BigInt); pub[1] += 1n;
    const tampered = walletInterface.encodeFunctionData('execute', [dec.payload, dec.sig, dec.a.map(BigInt), dec.b.map((row) => row.map(BigInt)), dec.c.map(BigInt), pub]);
    r = await relay({ to: p.walletAddr, data: tampered }); assert.equal(r.status, 400); assert.equal(r.body.reason, 'relay_bad_calldata'); assert.equal(r.body.detail, 'arid');
  });
  await t('음성: to 가 pub[0](PPID) 의 계정 주소가 아니면 relay_bad_target', async () => {
    const p = (await prepare()).body;
    const other = await factory.computeAddress(BigInt(decodeExecuteCalldata(p.calldata).pub[0]) + 1n);
    const r = await relay({ to: other, data: p.calldata }); assert.equal(r.status, 400); assert.equal(r.body.reason, 'relay_bad_target');
  });
  await t('음성: 이미 쓴 nonce 의 calldata 를 다시 보내면 estimateGas 가 revert — 400 relay_gas, detail 에 NonceMismatch', async () => {
    const p = (await prepare()).body;
    const ok = await relay({ to: p.walletAddr, data: p.calldata }); assert.equal(ok.status, 200); await waitReceipt(ok.body.txHash);
    const again = await relay({ to: p.walletAddr, data: p.calldata }); assert.equal(again.status, 400); assert.equal(again.body.reason, 'relay_gas'); assert.match(String(again.body.detail), /NonceMismatch/);
  });
  await t('CORS: 사용자 오리진에만 ACAO(프리플라이트·실제), 다른 오리진은 없음', async () => {
    const pre = await rp.raw('/api/mode3/relay', { method: 'OPTIONS', headers: { Origin: wallet.origin, 'Access-Control-Request-Method': 'POST', 'Access-Control-Request-Headers': 'content-type' } });
    assert.equal(pre.headers.get('access-control-allow-origin'), wallet.origin);
    const real = await relayRaw({ to: 'x', data: 'y' }); assert.equal(real.headers.get('access-control-allow-origin'), wallet.origin);
    const bad = await relayRaw({ to: 'x', data: 'y' }, { Origin: 'http://evil.example' }); assert.equal(bad.headers.get('access-control-allow-origin'), null);
  });
  await t('음성: 가스 상한(MODE3_RELAY_GAS_CAP=100000) 아래로 재기동하면 relay_gas(cap)', async () => {
    await stack.restartRp({ MODE3_RELAY_GAS_CAP: '100000' });
    const p = (await prepare()).body;
    const r = await relay({ to: p.walletAddr, data: p.calldata }); assert.equal(r.status, 400); assert.equal(r.body.reason, 'relay_gas'); assert.match(String(r.body.detail), /cap/);
  });
  await t('음성: 속도 제한(MODE3_RELAY_RATE=1) — 같은 계정의 두 번째 호출은 429(1~4단계를 통과한 호출을 체인 작업 전에 센다)', async () => {
    await stack.restartRp({ MODE3_RELAY_GAS_CAP: '', MODE3_RELAY_RATE: '1' });
    const p = (await prepare()).body;
    const first = await relay({ to: p.walletAddr, data: p.calldata }); assert.equal(first.status, 200, JSON.stringify(first.body)); await waitReceipt(first.body.txHash);
    const second = await relay({ to: p.walletAddr, data: (await prepare()).body.calldata }); assert.equal(second.status, 429); assert.equal(second.body.reason, 'relay_rate_limited');
  });
  // E1(2026-10-26): 로그인 proof 는 정규형으로 다시 만들어 검증·기록한다 — 원문을 기록하면 패딩 proof 가 개봉 요청(IdP 256kb)을 413 으로 막는다.
  const LOGIN_LOG = path.join(stack.dir, 'mode3_rp_logins.jsonl');
  const freshLogin = async () => {
    const c = (await rp.post('/api/mode3/challenge')).body;
    const w = await wallet.post('/wallet/login', { arid: info.arid, origin: info.origin, cert_s: info.cert_s, pk_trace: info.pk_trace, r_s: c.r_s, r_rp: c.r_rp, factoryAddress: info.factoryAddress, attrGateAddress: info.attrGateAddress }, { Origin: rp.origin });
    assert.equal(w.status, 200, JSON.stringify(w.body));
    return { c, w: w.body };
  };
  await t('E1: 모르는 키로 200KB 를 덧댄 proof 도 정규 부분이 유효하면 로그인되고, 로그 줄에는 정규 proof 만 남는다; 개봉 요청은 413 이 아니다', async () => {
    const { c, w } = await freshLogin();
    const padded = { ...w.proof, pad: 'x'.repeat(200_000), pi_a: [...w.proof.pi_a] };
    const r = await rp.post('/api/mode3/login', { proof: padded, publicSignals: w.publicSignals, sig: w.sig, r_s: c.r_s });
    assert.equal(r.status, 200, JSON.stringify(r.body)); assert.equal(r.body.ok, true, JSON.stringify(r.body));
    const line = fs.readFileSync(LOGIN_LOG, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l)).reverse().find((l) => l.r_s === c.r_s);
    assert.ok(line, '로그 줄이 있어야 한다');
    assert.ok(JSON.stringify(line).length < 16_000, `로그 줄 크기 ${JSON.stringify(line).length}`);
    assert.deepEqual(Object.keys(line.proof).sort(), ['curve', 'pi_a', 'pi_b', 'pi_c', 'protocol']);
    assert.deepEqual(line.proof, { pi_a: w.proof.pi_a, pi_b: w.proof.pi_b, pi_c: w.proof.pi_c, protocol: 'groth16', curve: 'bn128' });
    const o = await rp.post('/api/mode3/open', { PPID: r.body.PPID });
    assert.notEqual(o.status, 413, JSON.stringify(o.body)); assert.ok(o.status < 300, JSON.stringify(o.body)); assert.ok(o.body.id, JSON.stringify(o.body));
  });
  await t('E1: 비정규 숫자 문자열(앞자리 0)·원소를 덧붙인 좌표·필드 밖 좌표가 든 proof 는 400 malformed', async () => {
    const q = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
    const variants = [
      (pr) => ({ ...pr, pi_a: ['0' + pr.pi_a[0], pr.pi_a[1], pr.pi_a[2]] }),
      (pr) => ({ ...pr, pi_c: [...pr.pi_c, '7'] }),
      (pr) => ({ ...pr, pi_b: [pr.pi_b[0], [(BigInt(pr.pi_b[1][0]) + q).toString(), pr.pi_b[1][1]], pr.pi_b[2]] }),
      (pr) => ({ ...pr, pi_a: [Number(1), pr.pi_a[1], pr.pi_a[2]] }),
    ];
    for (const [i, mk] of variants.entries()) {
      const { c, w } = await freshLogin();
      const r = await rp.post('/api/mode3/login', { proof: mk(w.proof), publicSignals: w.publicSignals, sig: w.sig, r_s: c.r_s });
      assert.equal(r.status, 400, `#${i} ${JSON.stringify(r.body)}`); assert.equal(r.body.reason, 'malformed', `#${i}`);
    }
  });
  await t('음성: 검증기가 없으면(팩토리 상수 조회 실패) 503 relay_inactive — 마지막 케이스(env 누적)', async () => {
    await stack.restartRp({ MODE3_RELAY_RATE: '', MODE3_RP_FACTORY_ADDRESS: cia.logAddress }, { waitActive: false });
    await sleep(1500);
    const r = await relay({ to: ethers.ZeroAddress, data: '0x' }); assert.equal(r.status, 503); assert.equal(r.body.reason, 'relay_inactive');
  });
} finally { await stack.stop(); }
process.exit(fails ? 1 : 0);
