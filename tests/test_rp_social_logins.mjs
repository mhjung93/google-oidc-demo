// tests/test_rp_social_logins.mjs — RP 계정에 zkIdP·Google·네이버 로그인 연결(스펙 2026-11-10). 격리 스택(IdP·지갑·RP 둘) + 가짜 Google·네이버. (chain — :8545)
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { startIsolatedMode3Stack } from './helpers/isolated_mode3_stack.mjs';
import { startOidcIssuerStub } from './helpers/oidc_issuer_stub.mjs';
import { ethers } from 'ethers';

let failed = 0;
async function t(name, fn) { try { await fn(); console.log(`ok   ${name}`); } catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.stack ?? e.message}`); } }
const j = (v) => JSON.stringify(v);

const g = await startOidcIssuerStub({ clientId: 'rp-google-client', provider: 'google' });
const nv = await startOidcIssuerStub({ clientId: 'rp-naver-client', provider: 'naver', clientSecret: 'rp-naver-secret' });
const socialEnv = {
  MODE3_RP_GOOGLE_CLIENT_ID: g.clientId, MODE3_RP_GOOGLE_ISSUER: g.issuer, MODE3_RP_GOOGLE_JWKS_URL: g.jwksUrl,
  MODE3_RP_NAVER_CLIENT_ID: nv.clientId, MODE3_RP_NAVER_CLIENT_SECRET: nv.clientSecret, MODE3_RP_NAVER_ISSUER: nv.issuer, MODE3_RP_NAVER_JWKS_URL: nv.jwksUrl,
  MODE3_RP_NAVER_AUTHORIZE_URL: nv.authorizeUrl, MODE3_RP_NAVER_TOKEN_URL: nv.tokenUrl,
};
const stack = await startIsolatedMode3Stack({ rpEnv: { MODE3_RP_NAME: 'zkONE', ...socialEnv }, extraRps: [{ name: 'zkTWO', env: socialEnv }] });
const { wallet, rp } = stack, rp2 = stack.rps[1];
// 격리 스택은 체인 하나(RP 릴레이어가 보내는 곳). cacheTimeout -1 — 같은 요청을 250ms 캐시하면 출금 전후 잔액이 같게 읽힌다.
const provider = new ethers.JsonRpcProvider(process.env.CIA_RPC_URL || 'http://127.0.0.1:8545', undefined, { cacheTimeout: -1 });

/** 쿠키를 들고 다니는 RP 클라이언트(리다이렉트는 따라가지 않고 location 을 돌려준다). */
function jar(base) {
  const cookies = new Map();
  return {
    cookies,
    async req(method, p, body) {
      const r = await fetch(new URL(p, base), { method, redirect: 'manual', headers: { ...(cookies.size ? { Cookie: [...cookies].map(([k, v]) => `${k}=${v}`).join('; ') } : {}), ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}) }, body: body !== undefined ? j(body) : undefined });
      for (const c of r.headers.getSetCookie?.() ?? []) { const [kv] = c.split(';'); const i = kv.indexOf('='); cookies.set(kv.slice(0, i), kv.slice(i + 1)); }
      const text = await r.text(); let json = null; try { json = JSON.parse(text); } catch { /* HTML·빈 본문 */ }
      return { status: r.status, body: json, location: r.headers.get('location') };
    },
  };
}
async function googleLogin(u, sub, purpose = 'login') {
  const { nonce } = (await u.req('POST', '/api/rp/oidc/nonce', { purpose })).body;
  return u.req('POST', '/api/rp/google', { id_token: await g.mint({ sub, nonce }), purpose });
}
/** 네이버 다녀오기: start → (가짜 네이버가 바로 code 로 돌려보낸다) → callback → 돌아온 주소. */
async function naverRoundTrip(u, sub, purpose = 'login') {
  nv.setNextSub(sub);
  const s = await u.req('GET', `/api/rp/naver/start?purpose=${purpose}`);
  assert.equal(s.status, 302, j(s));
  const a = await fetch(s.location, { redirect: 'manual' });
  return u.req('GET', a.headers.get('location'));
}
async function zkLogin(u, target = rp, { link = false } = {}) {
  const info = (await target.get('/api/mode3/rp_info')).body;
  const ch = (await u.req('POST', '/api/mode3/challenge', {})).body;
  const w = await stack.withRelay(() => wallet.post('/wallet/login', { arid: info.arid, origin: info.origin, cert_s: info.cert_s, pk_trace: info.pk_trace, r_s: ch.r_s, r_rp: ch.r_rp, allowAgent: '0', factoryAddress: ch.factoryAddress, attrGateAddress: ch.attrGateAddress }, { Origin: target.origin }));
  assert.equal(w.status, 200, j(w.body));
  return u.req('POST', '/api/mode3/login', { proof: w.body.proof, publicSignals: w.body.publicSignals, sig: w.body.sig, r_s: ch.r_s, id_token: w.body.id_token ?? null, ...(link ? { link: true } : {}) });
}

try {
  // 지갑 등록(격리 IdP 의 데모 계정 testuser — test_mode3_demo_stack.mjs 의 "1. 등록" 과 같다). zkIdP 로그인 케이스가 쓴다.
  assert.equal((await wallet.post('/wallet/register', { uid: '12345', pwd: 'password123' })).status, 201, '지갑 등록');
  let B = null;
  await t('rp_info.social: 두 공급자 켜짐, Google 클라이언트 ID 만 싣는다(비밀 없음)', async () => {
    const s = (await rp.get('/api/mode3/rp_info')).body.social;
    // 2026-11-19: Google 의 리디렉션식 로그인 설정(인가 주소 — 공개값, 돌아올 주소 — 이 스택은 설정하지 않아 null)과 zkIdP 일반 OIDC 의 켜짐 여부(기본 꺼짐)가 더해졌다.
    assert.deepEqual(s, { google: { enabled: true, clientId: g.clientId, authorizeUrl: 'https://accounts.google.com/o/oauth2/v2/auth', redirectUri: null }, naver: { enabled: true }, zkoidc: { enabled: false } });
    assert.equal(j((await rp.get('/api/mode3/rp_info')).body).includes('rp-naver-secret'), false);
  });
  await t('Google 첫 로그인 → 새 계정·쿠키 세션(이름 zkone.sid), /api/rp/me 의 계정 보기(methods)에 sub 없음 — 받은 토큰은 seen 에(2026-11-19); nonce 재사용·다른 aud·purpose 불일치는 거절', async () => {
    const u = jar(rp.base);
    const r = await googleLogin(u, 'g-alice');
    assert.equal(r.status, 200, j(r.body)); assert.equal(r.body.created, true); assert.equal(r.body.via, 'google'); B = r.body.account;
    assert.ok(u.cookies.has('zkone.sid'), `쿠키: ${[...u.cookies.keys()]}`);
    const me = await u.req('GET', '/api/rp/me');
    assert.equal(me.body.account, B); assert.equal(me.body.via, 'google'); assert.equal(j(me.body.methods).includes('g-alice'), false, '계정 보기에는 sub 가 없다');
    // 2026-11-19(데모 시나리오 3 — "JWT 에 uid·rid 가 드러난다"): 로그인한 본인에게, 이 서비스가 Google 에서 받은 토큰의 sub·aud 와 본문을 보인다(서명 없음).
    assert.equal(me.body.seen.protocol, 'oidc'); assert.equal(me.body.seen.issuer, 'google'); assert.equal(me.body.seen.uid, 'g-alice'); assert.equal(me.body.seen.rid, g.clientId);
    assert.equal(me.body.seen.jwt.payload.sub, 'g-alice'); assert.equal(me.body.seen.jwt.payload.aud, g.clientId); assert.deepEqual(Object.keys(me.body.seen.jwt).sort(), ['header', 'payload']);
    const { nonce } = (await u.req('POST', '/api/rp/oidc/nonce', { purpose: 'login' })).body;
    const tok = await g.mint({ sub: 'g-x', nonce });
    assert.equal((await u.req('POST', '/api/rp/google', { id_token: tok, purpose: 'login' })).status, 200);
    assert.equal((await u.req('POST', '/api/rp/google', { id_token: tok, purpose: 'login' })).body.reason, 'bad_nonce', 'nonce 는 1회용');
    const { nonce: n2 } = (await u.req('POST', '/api/rp/oidc/nonce', { purpose: 'login' })).body;
    assert.equal((await u.req('POST', '/api/rp/google', { id_token: await g.mint({ sub: 'g-x', nonce: n2, aud: 'other' }), purpose: 'login' })).status, 401, '다른 aud');
    const { nonce: n3 } = (await u.req('POST', '/api/rp/oidc/nonce', { purpose: 'login' })).body;
    assert.equal((await u.req('POST', '/api/rp/google', { id_token: await g.mint({ sub: 'g-x', nonce: n3 }), purpose: 'link' })).status, 401, '로그인 nonce 로 연결 불가(접두어)');
    assert.equal((await jar(rp.base).req('POST', '/api/rp/oidc/nonce', { purpose: 'link' })).body.reason, 'no_rp_session');
    // 리뷰 2026-11-19(OIDC I-1): nonce 는 받아 간 브라우저(쿠키 세션)에 묶인다 — 다른 브라우저가 그 nonce 의 토큰을 내면 거절, 새로 받으면 앞의 nonce 는 못 쓴다
    const a = jar(rp.base), b = jar(rp.base);
    const { nonce: na } = (await a.req('POST', '/api/rp/oidc/nonce', { purpose: 'login' })).body;
    const other = await b.req('POST', '/api/rp/google', { id_token: await g.mint({ sub: 'g-y', nonce: na }), purpose: 'login' });
    assert.equal(other.status, 401, j(other.body)); assert.equal(other.body.reason, 'bad_nonce');
    assert.equal((await b.req('GET', '/api/rp/me')).status, 401);
    const { nonce: n4 } = (await a.req('POST', '/api/rp/oidc/nonce', { purpose: 'login' })).body;
    const { nonce: n5 } = (await a.req('POST', '/api/rp/oidc/nonce', { purpose: 'login' })).body;
    assert.equal((await a.req('POST', '/api/rp/google', { id_token: await g.mint({ sub: 'g-y', nonce: n4 }), purpose: 'login' })).body.reason, 'bad_nonce', '앞서 받은 nonce');
    assert.equal(n5.length > 0, true);
  });
  await t('Google 계정(B)에 zkIdP 연결(link:true) → B 에 PPID; 이어서 새 브라우저의 zkIdP 로그인은 B 로 들어간다', async () => {
    const u = jar(rp.base); await googleLogin(u, 'g-alice');
    const r = await zkLogin(u, rp, { link: true });
    assert.equal(r.body.ok, true, j(r.body)); assert.equal(r.body.account, B);
    assert.ok((await u.req('GET', '/api/rp/me')).body.methods.zkid.PPID);
    const v = jar(rp.base); const z = await zkLogin(v);
    assert.equal(z.body.ok, true, j(z.body)); assert.equal(z.body.account, B); assert.equal(z.body.via, 'zkid');
    assert.equal((await v.req('GET', '/api/rp/me')).body.via, 'zkid');
  });
  await t('다른 Google 계정(C)에 같은 PPID 를 zkIdP 로 연결하면 409 method_linked_elsewhere 이고 r_s 세션도 생기지 않는다', async () => {
    const u = jar(rp.base); const c = await googleLogin(u, 'g-carol');
    const before = (await rp.get('/api/mode3/sessions')).body.sessions.length;
    const r = await zkLogin(u, rp, { link: true });
    assert.equal(r.status, 409, j(r.body)); assert.equal(r.body.reason, 'method_linked_elsewhere');
    assert.equal((await rp.get('/api/mode3/sessions')).body.sessions.length, before, '세션이 늘지 않았다');
    assert.equal((await u.req('GET', '/api/rp/me')).body.account, c.body.account, '로그인이 다른 계정으로 바뀌지 않는다');
  });
  await t('네이버: 로그인 다녀오기 → 새 계정; B 에 네이버 연결(#account 로 돌아옴); 같은 네이버를 다른 계정에 연결하면 social_error', async () => {
    const u = jar(rp.base);
    const r = await naverRoundTrip(u, 'n-dave');
    assert.equal(r.status, 302); assert.match(r.location, /\/\?social=ok&via=naver$/);
    const D = (await u.req('GET', '/api/rp/me')).body.account; assert.notEqual(D, B);
    const ub = jar(rp.base); await googleLogin(ub, 'g-alice');
    const l = await naverRoundTrip(ub, 'n-alice', 'link');
    assert.match(l.location, /\/\?linked=naver#account$/);
    assert.ok((await ub.req('GET', '/api/rp/me')).body.methods.naver);
    const l2 = await naverRoundTrip(u, 'n-alice', 'link');
    assert.match(l2.location, /social_error=method_linked_elsewhere/);
  });
  await t('네이버 실패 경로: 사용자가 취소하면 naver_denied, 모르는 state 는 naver_state_invalid — 500 이 아니다', async () => {
    const u = jar(rp.base);
    const s = await u.req('GET', '/api/rp/naver/start?purpose=login');
    const st = new URL(s.location).searchParams.get('state');
    const d = await u.req('GET', `/api/rp/naver/callback?error=access_denied&state=${st}`);
    assert.equal(d.status, 302); assert.match(d.location, /social_error=naver_denied/);
    const x = await u.req('GET', '/api/rp/naver/callback?code=abc&state=nope');
    assert.match(x.location, /social_error=naver_state_invalid/);
  });
  await t('해제: 마지막 수단은 409 last_method; B 에서 Google 을 풀면 그 Google 로그인은 새 계정', async () => {
    const u = jar(rp.base); const d = await naverRoundTrip(u, 'n-erin');
    assert.equal((await u.req('POST', '/api/rp/unlink', { method: 'naver' })).body.reason, 'last_method');
    const ub = jar(rp.base); await googleLogin(ub, 'g-alice');
    const r = await ub.req('POST', '/api/rp/unlink', { method: 'google' });
    assert.equal(r.status, 200, j(r.body)); assert.equal(r.body.methods.google, null);
    const again = await googleLogin(jar(rp.base), 'g-alice');
    assert.equal(again.body.created, true); assert.notEqual(again.body.account, B);
  });
  // 2026-11-25(스펙 rp-custody-address): 보관 ETH 는 장부 숫자가 아니라 서비스가 키를 보관하는 주소의 체인 잔고다. 보내면 from 이 그 주소이고 가스도 거기서 나간다.
  let frank = null;
  await t('보관 계정: 구매는 그 계정 주소로 실제 송금, 보내기는 그 주소가 from — 초과·가스 부족·0·주소 오류는 400 이고 잔고 그대로', async () => {
    const u = jar(rp.base); await googleLogin(u, 'g-frank');
    const ts = () => Date.now();
    const b0 = (await u.req('POST', '/api/rp/ledger', { body: 'balance' })).body.balance;
    assert.match(b0.custodyAddress, /^0x[0-9a-fA-F]{40}$/); assert.equal(b0.ledger.ETH_CUSTODY, '0'); assert.equal(b0.custodyMaxEth, '0'); frank = b0.custodyAddress;
    assert.equal((await u.req('POST', '/api/rp/ledger', { body: `deposit:${ts()}` })).body.ok, true);
    const b = await u.req('POST', '/api/rp/ledger', { body: `buy:0.1:${ts()}` });
    assert.equal(b.body.ok, true, j(b.body)); assert.match(b.body.txHash, /^0x/); assert.equal(b.body.balance.ledger.ETH_CUSTODY, '0.1'); assert.equal(b.body.balance.ledger.ETH, '-', 'PPID 계정 없음');
    assert.equal(await provider.getBalance(frank), 10n ** 17n, '체인 잔고'); { const tx = await provider.getTransaction(b.body.txHash); assert.equal(tx.to, frank); assert.notEqual(tx.from, frank); }
    const to = '0x000000000000000000000000000000000000bEEF';
    const before = await provider.getBalance(to);
    for (const [body, reason] of [[`withdraw:${to}:${10n ** 18n}:${ts()}`, 'insufficient_custody'], [`withdraw:${to}:${10n ** 17n}:${ts()}`, 'insufficient_gas'], [`withdraw:${to}:0:${ts()}`, 'bad_amount'], [`withdraw:0x12:5:${ts()}`, 'bad_address']]) {
      const r = await u.req('POST', '/api/rp/ledger', { body });
      assert.equal(r.status, 400, j(r.body)); assert.equal(r.body.reason, reason);
      if (reason === 'insufficient_gas') { assert.ok(Number(r.body.detail.maxEth) > 0.09 && Number(r.body.detail.maxEth) < 0.1, j(r.body.detail)); assert.equal(r.body.balance.ledger.ETH_CUSTODY, '0.1'); }
    }
    assert.equal(await provider.getBalance(frank), 10n ** 17n, '거절인데 잔고가 줄었다');
    const w = await u.req('POST', '/api/rp/ledger', { body: `withdraw:${to}:${5n * 10n ** 16n}:${ts()}` });
    assert.equal(w.body.ok, true, j(w.body)); const tx = await provider.getTransaction(w.body.txHash), rc = await provider.getTransactionReceipt(w.body.txHash);
    assert.equal(tx.from, frank, 'from 이 내 주소가 아니다'); assert.equal((await provider.getBalance(to)) - before, 5n * 10n ** 16n);
    assert.equal(await provider.getBalance(frank), 10n ** 17n - 5n * 10n ** 16n - rc.gasUsed * rc.gasPrice, '금액 + 가스만큼 줄어야 한다');
    // "보낼 수 있는 최대" 만큼은 실제로 보내진다
    const max = (await u.req('POST', '/api/rp/ledger', { body: 'balance' })).body.balance.custodyMaxEth; assert.ok(Number(max) > 0.04 && Number(max) < 0.05, max);
    const m = await u.req('POST', '/api/rp/ledger', { body: `withdraw:${to}:${ethers.parseEther(max)}:${ts()}` }); assert.equal(m.body.ok, true, j(m.body));
    const rep = `deposit:${ts()}`; await u.req('POST', '/api/rp/ledger', { body: rep });
    assert.equal((await u.req('POST', '/api/rp/ledger', { body: rep })).body.reason, 'request_replayed');
    assert.equal((await jar(rp.base).req('POST', '/api/rp/ledger', { body: 'balance' })).body.reason, 'no_rp_session');
  });
  await t('RP 마다 따로: zkTWO 의 쿠키 이름은 zktwo.sid, zkONE 의 Google 계정은 zkTWO 에 없다(zkTWO 첫 로그인 = 새 계정)', async () => {
    const u = jar(rp2.base); const r = await googleLogin(u, 'g-frank');
    assert.equal(r.body.created, true); assert.ok(u.cookies.has('zktwo.sid'));
    const a2 = (await u.req('POST', '/api/rp/ledger', { body: 'balance' })).body.balance.custodyAddress; assert.match(a2, /^0x/); assert.notEqual(a2, frank, '서비스마다 시드가 달라 주소가 다르다');
  });
  await t('보관 계정: 동시에 누른 구매는 KRW 를 넘지 않고, 동시에 누른 보내기는 모두 나간다(nonce 가 겹치지 않는다) — 같은 본문은 한 번만', async () => {
    const u = jar(rp.base); await googleLogin(u, 'g-gina'); const ts = () => Date.now(), L = (body) => u.req('POST', '/api/rp/ledger', { body });
    await L(`deposit:${ts()}`); const addr = (await L('balance')).body.balance.custodyAddress;
    const t0 = ts(); const rs = await Promise.all([L(`buy:0.15:${t0}`), L(`buy:0.15:${t0 + 1}`)]);   // 100만원으로 0.15 ETH(63.15만원)는 한 번만 산다
    assert.deepEqual(rs.map((r) => r.body.ok).sort(), [false, true], j(rs.map((r) => r.body))); assert.equal(rs.find((r) => !r.body.ok).body.reason, 'insufficient_krw'); assert.equal(await provider.getBalance(addr), 15n * 10n ** 16n);
    const to = ethers.getAddress('0x000000000000000000000000000000000000cafe'), b0 = await provider.getBalance(to), t1 = ts();
    const ws = await Promise.all([0, 1, 2].map((i) => L(`withdraw:${to}:${10n ** 16n}:${t1 + i}`))); assert.ok(ws.every((r) => r.body.ok), j(ws.map((r) => r.body)));
    assert.equal((await provider.getBalance(to)) - b0, 3n * 10n ** 16n);
    const same = `withdraw:${to}:${10n ** 16n}:${ts()}`; const ds = await Promise.all([L(same), L(same)]); assert.deepEqual(ds.map((r) => r.body.ok).sort(), [false, true]); assert.equal(ds.find((r) => !r.body.ok).body.reason, 'request_replayed');
  });
  await t('시드는 어느 응답·로그에도 없고, 시드 파일은 서비스마다 따로 0600 이며 계정 파일에는 지문만 있다', async () => {
    const files = fs.readdirSync(stack.dir).filter((f) => /custody_seed\.json$/.test(f)); assert.ok(files.length >= 2, j(files));
    const seeds = files.map((f) => { const p = path.join(stack.dir, f); assert.equal(fs.statSync(p).mode & 0o777, 0o600); return JSON.parse(fs.readFileSync(p, 'utf8')).seed; });
    assert.equal(new Set(seeds).size, seeds.length, '시드를 나눠 쓴다');
    const u = jar(rp.base); await googleLogin(u, 'g-frank');
    const bodies = [await u.req('GET', '/api/rp/me'), await u.req('POST', '/api/rp/ledger', { body: 'balance' }), await u.req('GET', '/api/mode3/rp_info'), await u.req('GET', '/mode3/health')].map((r) => j(r.body));
    for (const f of fs.readdirSync(stack.dir).filter((f) => /accounts\.json$/.test(f))) { const x = fs.readFileSync(path.join(stack.dir, f), 'utf8'); assert.match(JSON.parse(x).custodyKey ?? '', /^0x[0-9a-fA-F]{40}$/); bodies.push(x); }
    for (const c of stack.rps) bodies.push(c.log());
    for (const s of seeds) for (const b of bodies) assert.ok(!b.includes(s), '시드가 새었다');
  });
  await t('RP 재기동: 쿠키 세션은 끝나도 계정·연결·KRW·보관 주소와 그 잔고는 남는다', async () => {
    const u = jar(rp.base); await googleLogin(u, 'g-frank');
    const bal = (await u.req('POST', '/api/rp/ledger', { body: 'balance' })).body.balance.ledger;
    await stack.restartRp();
    assert.equal((await u.req('GET', '/api/rp/me')).status, 401, '세션 비밀이 바뀌어 옛 쿠키는 무효');
    const v = jar(rp.base); await googleLogin(v, 'g-frank');
    assert.deepEqual((await v.req('POST', '/api/rp/ledger', { body: 'balance' })).body.balance.ledger, bal);
    assert.equal((await v.req('POST', '/api/rp/ledger', { body: 'balance' })).body.balance.custodyAddress, frank, '재기동 뒤 주소가 바뀌었다');
  });
  await t('zkIdP 로 만든 쿠키 세션은 그 r_s 세션이 끝나면(로그아웃·폐기) 함께 끝난다 — 소셜로 만든 세션은 그대로', async () => {
    const u = jar(rp.base); const z = await zkLogin(u);
    assert.equal(z.body.ok, true, j(z.body)); assert.equal((await u.req('GET', '/api/rp/me')).status, 200);
    await rp.post('/api/mode3/logout', { r_s: z.body.r_s });
    assert.equal((await u.req('GET', '/api/rp/me')).status, 401, 'r_s 세션이 끝났는데 쿠키 세션이 남으면 폐기를 우회한다');
    const v = jar(rp.base); await googleLogin(v, 'g-hana');
    assert.equal((await v.req('GET', '/api/rp/me')).status, 200);
  });
  await t('리뷰 I2: 네이버 state 는 시작한 브라우저에 묶인다 — 다른 브라우저가 콜백 URL 을 열면 naver_state_invalid 이고 로그인되지 않는다(로그인 CSRF)', async () => {
    const attacker = jar(rp.base); nv.setNextSub('n-attacker');
    const s = await attacker.req('GET', '/api/rp/naver/start?purpose=login');
    const a = await fetch(s.location, { redirect: 'manual' });
    const victim = jar(rp.base);
    const r = await victim.req('GET', a.headers.get('location'));
    assert.match(r.location, /social_error=naver_state_invalid/);
    assert.equal((await victim.req('GET', '/api/rp/me')).status, 401);
  });
  await t('리뷰 I3: 형식이 틀린 출금·입금·구매 본문은 400 malformed — 성공(ok:true)으로 빠지지 않는다', async () => {
    const u = jar(rp.base); await googleLogin(u, 'g-ivan');
    for (const body of [`withdraw::1000:${Date.now()}`, `withdraw:0x000000000000000000000000000000000000bEEF:${'9'.repeat(31)}:${Date.now()}`, 'deposit:abc', 'buy:x:1']) {
      const r = await u.req('POST', '/api/rp/ledger', { body });
      assert.equal(r.status, 400, `${body} → ${j(r.body)}`); assert.equal(r.body.reason, 'malformed');
    }
  });
  await t('로그아웃: /api/rp/logout 뒤 /api/rp/me 401; JSON 이 아닌 본문은 415 json_only', async () => {
    const u = jar(rp.base); await googleLogin(u, 'g-gina');
    await u.req('POST', '/api/rp/logout', {});
    assert.equal((await u.req('GET', '/api/rp/me')).status, 401);
    const r = await fetch(new URL('/api/rp/unlink', rp.base), { method: 'POST', headers: { 'Content-Type': 'text/plain' }, body: 'method=google' });
    assert.equal(r.status, 415);
  });
  // 맨 끝에 둔다 — 지갑의 testuser 계정을 폐기한다.
  await t('리뷰 I1: zkIdP 로 만든 쿠키 세션은 IdP 폐기(root 변경)로 r_s 세션이 재검증을 요구하면 함께 막힌다 — /api/rp/me·/api/rp/ledger 401', async () => {
    const u = jar(rp.base); const z = await zkLogin(u);
    assert.equal(z.body.ok, true, j(z.body)); assert.equal((await u.req('GET', '/api/rp/me')).status, 200);
    const rv = await stack.cia.adminPost('/cia/revoke', { uid: '12345', scope: 'account' });
    assert.equal(rv.status, 200, j(rv.body));
    await stack.relayIfBehind();   // 폐기 게시를 RP 가 읽는 거울에 싣는다
    assert.equal((await u.req('GET', '/api/rp/me')).status, 401, '폐기 뒤 쿠키 세션이 남으면 거래소 보관 출금까지 된다');
    assert.equal((await u.req('POST', '/api/rp/ledger', { body: 'balance' })).status, 401);
  });
} finally {
  await stack.stop(); await g.stop(); await nv.stop();
}
if (failed) { console.error(`${failed} failed`); process.exit(1); }
console.log('all passed');
