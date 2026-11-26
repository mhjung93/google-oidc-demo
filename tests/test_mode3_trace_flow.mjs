// 추적 기록의 끝에서 끝(스펙 2026-11-26 ppid-account-trace §4·§5): 등록부 배포(scripts/mode3_trace_setup.mjs) → 사용자의 기록(실제 π_trace) → 개봉 요청 거래 →
// 감사자 프로세스(mode3_auditors.js)가 요청을 본 뒤 부분 복호 → 조합(openFromParts)으로 auid. :8545·build/mode3/pi_trace_*·artifacts 필요. (chain)
//   node tests/test_mode3_trace_flow.mjs
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn, execFileSync } from 'node:child_process';
import { ethers } from 'ethers';
import * as snarkjs from 'snarkjs';
import { traceWitness, openFromParts, partFromJson, ptFromJson } from '../lib/mode3_trace_record.js';
import http from 'node:http';
import { traceRegistryAt, registryPk, listOpenRequests, traceCtx } from '../lib/mode3_trace_chain.js';
import { proofToCalldata } from '../lib/mode3_onchain.js';
import { randomScalar } from '../lib/mode3_credential.js';

const RPC = 'http://127.0.0.1:8545', WASM = 'build/mode3/pi_trace_js/pi_trace.wasm', ZKEY = 'build/mode3/pi_trace_final.zkey';
if (!fs.existsSync(ZKEY)) { console.log('BLOCKED: build/mode3/pi_trace_* 가 없다 — bash scripts/build_mode3_circuit.sh pi_trace'); process.exit(1); }
let fails = 0; async function t(n, f) { try { await f(); console.log('ok   -', n); } catch (e) { fails++; console.log('FAIL -', n, '\n      ', e.stack ?? e.message); } }
const provider = new ethers.JsonRpcProvider(RPC);
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'zkd-aud-'));
const procs = [];
const TOKEN = 'test-auditor-token-0123456789abcdef0123456789abcdef';   // 테스트 고정값 — 감사자와 조합자가 나눠 갖는 토큰
const startAuditors = (env) => new Promise((resolve, reject) => {
  const p = spawn('node', ['mode3_auditors.js'], { env: { ...process.env, MODE3_AUDITOR_DIR: dir, MODE3_AUDITOR_RPC: RPC, MODE3_AUDITOR_POLL_MS: '300', MODE3_AUDITOR_TOKEN: TOKEN, ...env }, stdio: ['ignore', 'pipe', 'pipe'] });
  procs.push(p); let out = '';
  const on = (d) => { out += d; if (/up :\d+/.test(out)) resolve({ p, out: () => out }); };
  p.stdout.on('data', on); p.stderr.on('data', on); p.on('exit', (c) => reject(new Error(`감사자 프로세스가 끝났다(${c}): ${out}`)));
});
const getJson = async (u, headers = { 'X-Auditor-Token': TOKEN }) => { const r = await fetch(u, { headers }); return { status: r.status, body: await r.json().catch(() => null) }; };
const statusWithHost = (port, p, host) => new Promise((resolve, reject) => { http.get({ host: '127.0.0.1', port, path: p, headers: { Host: host, 'X-Auditor-Token': TOKEN } }, (r) => { r.resume(); resolve(r.statusCode); }).on('error', reject); });
const waitFor = async (fn, ms = 20_000) => { const t0 = Date.now(); for (;;) { const v = await fn(); if (v) return v; if (Date.now() - t0 > ms) throw new Error('기다리다 시간이 지났다'); await new Promise((r) => setTimeout(r, 200)); } };
try {
  const setup = execFileSync('node', ['scripts/mode3_trace_setup.mjs'], { env: { ...process.env, RPC, MODE3_AUDITOR_DIR: dir }, encoding: 'utf8' });
  const REG = /MODE3_TRACE_REGISTRY=(0x[0-9a-fA-F]{40})/.exec(setup)?.[1];
  const registry = traceRegistryAt(REG, provider), chainid = (await provider.getNetwork()).chainId, ARID = 9001n;
  const user = async () => { const s_u = randomScalar(); const w = await traceWitness({ s_u, arid: ARID, chainid, pk_aud: await registryPk(registry) }); const { proof, publicSignals } = await snarkjs.groth16.fullProve(w.input, WASM, ZKEY); const { a, b, c } = await proofToCalldata(proof, publicSignals); return { w, args: [w.PPID, ARID, w.c1.x, w.c1.y, w.c2, a, b, c] }; };
  const relayer = await provider.getSigner(3), service = await provider.getSigner(4);
  const alice = await user();

  await t('배포: 주소가 나오고 조각 파일은 0600, 출력에 조각 값이 없다 — 두 번째 실행은 같은 키로 새 등록부를 올린다', async () => {
    assert.match(REG ?? '', /^0x[0-9a-fA-F]{40}$/, setup);
    for (const i of [1, 2, 3]) { const f = path.join(dir, `auditor${i}.json`); assert.equal(fs.statSync(f).mode & 0o777, 0o600, f); assert.ok(!setup.includes(JSON.parse(fs.readFileSync(f, 'utf8')).x), '출력에 조각'); }
    const again = execFileSync('node', ['scripts/mode3_trace_setup.mjs'], { env: { ...process.env, RPC, MODE3_AUDITOR_DIR: dir }, encoding: 'utf8' });
    assert.ok(again.includes('이미 있다')); const reg2 = traceRegistryAt(/MODE3_TRACE_REGISTRY=(0x[0-9a-fA-F]{40})/.exec(again)[1], provider);
    assert.deepEqual(await registryPk(reg2), await registryPk(registry));
  });
  await t('기록: 중계자가 사용자의 증명으로 등록한다 → has, 같은 PPID 는 다시 안 된다', async () => {
    await (await registry.connect(relayer).register(...alice.args)).wait();
    assert.equal(await registry.has(alice.w.PPID), true);
    await assert.rejects(() => registry.connect(relayer).register.staticCall(...alice.args));
  });
  let aud;
  await t('감사자는 체인의 요청을 본 뒤에만 응답한다 — 요청 전에는 조각이 없고, 요청 뒤 둘(1·2번)이 내며 체인에 표시가 남는다', async () => {
    aud = await startAuditors({ MODE3_TRACE_REGISTRY: REG, MODE3_AUDITOR_PORT: '5391' });
    assert.equal((await getJson('http://127.0.0.1:5391/shares/0')).status, 404);
    assert.equal((await getJson('http://127.0.0.1:5391/respond/0')).status, 404, 'GET 으로는 응답시키지 못한다');
    await (await registry.connect(service).requestOpen(alice.w.PPID, ethers.id('테스트 사유'))).wait();
    const got = await waitFor(async () => { const r = await getJson('http://127.0.0.1:5391/shares/0'); return r.status === 200 && r.body.parts.length === 2 ? r.body : null; });
    assert.deepEqual(got.parts.map((p) => p.index).sort(), [1, 2]);
    const reqs = await listOpenRequests(registry); assert.equal(reqs.length, 1); assert.deepEqual(reqs[0].shares, [1, 2]); assert.equal(reqs[0].requester, await service.getAddress());
    assert.ok(!aud.out().includes(JSON.parse(fs.readFileSync(path.join(dir, 'auditor1.json'), 'utf8')).x), '로그에 조각');
  });
  await t('감사자 HTTP 는 토큰이 있어야 답한다(검토 I-3): 토큰 없이·틀린 토큰으로는 조각도 공개키도 승인도 안 되고, Host 가 다른 요청(이름 돌리기)은 받지 않는다 — /health 만 열려 있다', async () => {
    for (const h of [{}, { 'X-Auditor-Token': 'x'.repeat(TOKEN.length) }, { 'X-Auditor-Token': TOKEN.slice(1) }]) {
      for (const u of ['/shares/0', '/pk', '/requests']) assert.equal((await getJson(`http://127.0.0.1:5391${u}`, h)).status, 401, `${u} ${JSON.stringify(h)}`);
      assert.equal((await fetch('http://127.0.0.1:5391/respond/0', { method: 'POST', headers: h })).status, 401);
    }
    assert.equal(await statusWithHost(5391, '/shares/0', 'evil.example:5391'), 421);
    assert.equal((await getJson('http://127.0.0.1:5391/health', {})).status, 200);
    assert.ok(!aud.out().includes(TOKEN), '로그에 토큰');
  });
  await t('조합: 감사자가 낸 둘을 확인해 합치면 그 사용자의 auid — 하나뿐이면·하나를 바꾸면·다른 키의 조각 공개키면 열리지 않는다', async () => {
    const pkj = (await getJson('http://127.0.0.1:5391/pk')).body, sh = (await getJson('http://127.0.0.1:5391/shares/0')).body;
    assert.ok(!JSON.stringify(pkj).includes('"x":"' + JSON.parse(fs.readFileSync(path.join(dir, 'auditor2.json'), 'utf8')).x + '"'), '/pk 에 조각');
    const shareXs = Object.fromEntries(pkj.shares.map((s) => [s.index, ptFromJson(s.X)])), parts = sh.parts.map(partFromJson);
    const r = await registry.recordOf(alice.w.PPID), base = { pk: await registryPk(registry), shareXs, c1: { x: r.c1x, y: r.c1y }, c2: r.c2 };
    const ctx = traceCtx({ chainId: chainid, registry: REG, id: 0 }); base.ctx = ctx;
    const opened = await openFromParts({ ...base, parts });
    assert.equal(opened.auid, alice.w.auid); assert.deepEqual(opened.used.sort(), [1, 2]);
    await assert.rejects(() => openFromParts({ ...base, parts, ctx: traceCtx({ chainId: chainid, registry: REG, id: 1 }) }), (e) => e.reason === 'trace_share_bad', '다른 요청 번호의 문맥으로는 통과하지 않는다');
    await assert.rejects(() => openFromParts({ ...base, parts, ctx: 0n }), (e) => e.reason === 'trace_share_bad', '문맥 없이');
    await assert.rejects(() => openFromParts({ ...base, parts: [parts[0]] }), (e) => e.reason === 'trace_shares_short');
    await assert.rejects(() => openFromParts({ ...base, parts: [parts[0], { ...parts[1], D: parts[0].D }] }), (e) => e.reason === 'trace_share_bad');
    await assert.rejects(() => openFromParts({ ...base, parts: [parts[0], { ...parts[0] }] }), (e) => e.reason === 'trace_share_bad', '같은 조각 두 번');
    await assert.rejects(() => openFromParts({ ...base, pk: { x: base.pk.x, y: base.pk.y + 1n }, parts }), (e) => e.reason === 'trace_key_mismatch');
  });
  await t('기록이 없는 PPID 는 요청 자체가 되지 않고, 다른 사용자의 요청은 그 사람의 auid 로 열린다(서로 섞이지 않는다)', async () => {
    const bob = await user();
    await assert.rejects(() => registry.connect(service).requestOpen.staticCall(bob.w.PPID, ethers.ZeroHash));
    await (await registry.connect(relayer).register(...bob.args)).wait();
    await (await registry.connect(service).requestOpen(bob.w.PPID, ethers.ZeroHash)).wait();
    const sh = await waitFor(async () => { const r = await getJson('http://127.0.0.1:5391/shares/1'); return r.status === 200 && r.body.parts.length === 2 ? r.body : null; });
    const pkj = (await getJson('http://127.0.0.1:5391/pk')).body, r = await registry.recordOf(bob.w.PPID);
    const opened = await openFromParts({ pk: await registryPk(registry), shareXs: Object.fromEntries(pkj.shares.map((s) => [s.index, ptFromJson(s.X)])), c1: { x: r.c1x, y: r.c1y }, c2: r.c2, parts: sh.parts.map(partFromJson), ctx: traceCtx({ chainId: chainid, registry: REG, id: 1 }) });
    assert.equal(opened.auid, bob.w.auid); assert.notEqual(opened.auid, alice.w.auid);
  });
  await t('기동 검사: 등록부의 키가 디렉터리의 키와 다르면 뜨지 않는다 — 토큰이 없거나 짧아도, 조각 파일이 공개 기록과 짝이 아니어도 뜨지 않는다; 키 파일이 일부만 있으면 배포가 멈춘다', async () => {
    const other = fs.mkdtempSync(path.join(os.tmpdir(), 'zkd-aud2-'));
    const boot = (env) => new Promise((resolve) => { const p = spawn('node', ['mode3_auditors.js'], { env: { ...process.env, MODE3_AUDITOR_RPC: RPC, MODE3_TRACE_REGISTRY: REG, MODE3_AUDITOR_PORT: '5392', MODE3_AUDITOR_TOKEN: TOKEN, ...env }, stdio: ['ignore', 'pipe', 'pipe'] }); let o = ''; p.stderr.on('data', (d) => { o += d; }); const k = setTimeout(() => p.kill(), 15_000); p.on('exit', (c) => { clearTimeout(k); resolve({ c, o }); }); });
    try {
      for (const tok of ['', 'short']) { const r = await boot({ MODE3_AUDITOR_DIR: dir, MODE3_AUDITOR_TOKEN: tok }); assert.equal(r.c, 2, `token "${tok}"`); assert.ok(r.o.includes('MODE3_AUDITOR_TOKEN'), r.o); }
      execFileSync('node', ['scripts/mode3_trace_setup.mjs'], { env: { ...process.env, RPC, MODE3_AUDITOR_DIR: other }, encoding: 'utf8' });
      const r = await boot({ MODE3_AUDITOR_DIR: other });
      assert.equal(r.c, 2); assert.ok(r.o.includes('pk_aud'), r.o);
      // 조각 파일 하나가 다른 키의 것(공개 기록 pk.json 은 그대로) → 뜨지 않는다
      const mixed = fs.mkdtempSync(path.join(os.tmpdir(), 'zkd-aud3-'));
      try {
        for (const f of ['pk.json', 'auditor1.json', 'auditor3.json']) fs.copyFileSync(path.join(dir, f), path.join(mixed, f));
        fs.copyFileSync(path.join(other, 'auditor2.json'), path.join(mixed, 'auditor2.json'));
        const r2 = await boot({ MODE3_AUDITOR_DIR: mixed }); assert.equal(r2.c, 2); assert.ok(r2.o.includes('감사자 2'), r2.o);
        // 키 파일이 일부만 있으면(조각 하나를 잃음) 배포 스크립트가 새 키를 만들지 않고 멈춘다 — 남은 파일은 그대로다
        fs.rmSync(path.join(mixed, 'auditor3.json')); const before = fs.readFileSync(path.join(mixed, 'auditor1.json'), 'utf8');
        let code = 0, err = ''; try { execFileSync('node', ['scripts/mode3_trace_setup.mjs'], { env: { ...process.env, RPC, MODE3_AUDITOR_DIR: mixed }, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }); } catch (e) { code = e.status; err = String(e.stderr); }
        assert.equal(code, 2); assert.ok(err.includes('MODE3_AUDITOR_REDEAL'), err); assert.equal(fs.readFileSync(path.join(mixed, 'auditor1.json'), 'utf8'), before); assert.ok(!fs.existsSync(path.join(mixed, 'auditor3.json')));
      } finally { fs.rmSync(mixed, { recursive: true, force: true }); }
    } finally { fs.rmSync(other, { recursive: true, force: true }); }
  });
} finally { for (const p of procs) p.kill(); fs.rmSync(dir, { recursive: true, force: true }); }
console.log(fails ? `\n${fails} FAILED` : '\nall ok');
process.exit(fails ? 1 : 0);
