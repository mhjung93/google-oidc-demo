// tests/test_mode3_wallet_idp_return_parity.mjs — zk 스냅 화면(mode3/wallet.html)의 goIdpAuth·takeIdpReturn 사본이 공용 모듈 mode3/user/idp_return.js 와
// 같은 규칙인지 본다(2026-11-22, 11-18 리뷰 5번: 사본에는 "갈 때의 목적과 돌아온 목적 대조" 가 없었다). wallet.html 은 고전 스크립트라 모듈을 가져다 쓰지 않는다 —
// 두 곳을 같이 고치지 않으면 이 테스트가 깨진다. 외부 의존 없음(unit).
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import { webcrypto } from 'node:crypto';
import * as M from '../mode3/user/idp_return.js';

const html = fs.readFileSync(new URL('../mode3/wallet.html', import.meta.url), 'utf8');
const a = html.indexOf("const PENDING_KEY = 'mode3.authorize.pending';");
const b = html.indexOf('function takeIdpReturn()', a);
const end = html.indexOf('\n    }\n', b);
assert.ok(a > 0 && b > a && end > b, 'wallet.html 에서 goIdpAuth·takeIdpReturn 구간을 못 찾았다');
const SRC = html.slice(a, end + 6);

let fails = 0; async function t(n, f) { try { await f(); console.log('ok   -', n); } catch (e) { fails++; console.log('FAIL -', n, '\n      ', e.stack ?? e.message); } }
const store = () => { const m = new Map(); return { getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: (k) => m.delete(k) }; };
/** wallet.html 사본을 가짜 브라우저 전역으로 띄운다. 돌아오는 길은 return(search, now) 로 흉내 낸다. */
function walletCopy() {
  const ctx = { sessionStorage: store(), crypto: webcrypto, URL, URLSearchParams, JSON, Date, Array, Uint8Array, cfg: { ciaUrl: 'https://idp.example' },
    location: { origin: 'https://wallet.example', pathname: '/', search: '', assigned: null, assign(u) { this.assigned = u; } }, history: { replaceState() {} } };
  vm.createContext(ctx);
  vm.runInContext(`${SRC}\nthis.goIdpAuth = goIdpAuth; this.takeIdpReturn = takeIdpReturn; this.PENDING_MAX_AGE_MS = PENDING_MAX_AGE_MS;`, ctx);
  return {
    ctx,
    async go(req, origin, purpose) { await ctx.goIdpAuth(req, origin, { purpose }); return new URL(ctx.location.assigned).searchParams.get('nonce'); },
    back(search, now) { ctx.location.search = search; const realNow = Date.now; ctx.Date = { now: () => now }; try { vm.runInContext('this.__r = takeIdpReturn();', ctx); return ctx.__r; } finally { ctx.Date = Date; void realNow; } },
  };
}
/** 같은 상황을 공용 모듈로. */
function moduleTake(storage, search, now) { return M.takeIdpReturn({ search, storage, now }); }
const norm = (r) => (r === null ? null : r.req === null ? { req: null } : { req: r.req, origin: r.origin, code: r.code, purpose: r.purpose, uid: r.uid, auid: r.auid });

const REQ = { rid: '7', n: '42' }, ORIGIN = 'https://rp.example';
const cases = [
  ['issue 로 가서 issue 로 돌아옴', 'issue', (n) => `?authorize=1&idp_nonce=${n}&idp_code=c1`, 0],
  ['register 로 가서 register 로 돌아옴(uid·auid)', 'register', (n) => `?authorize=1&idp_nonce=${n}&idp_code=c2&idp_purpose=register&idp_uid=100001&idp_auid=55`, 0],
  ['issue 로 갔는데 register 로 돌아옴 — 거절', 'issue', (n) => `?authorize=1&idp_nonce=${n}&idp_code=c3&idp_purpose=register&idp_uid=100001`, 0],
  ['register 로 갔는데 issue 로 돌아옴 — 거절', 'register', (n) => `?authorize=1&idp_nonce=${n}&idp_code=c4`, 0],
  ['register 인데 uid 가 10진이 아님 — 거절', 'register', (n) => `?authorize=1&idp_nonce=${n}&idp_code=c5&idp_purpose=register&idp_uid=abc`, 0],
  ['nonce 가 다름 — 거절', 'issue', () => '?authorize=1&idp_nonce=other&idp_code=c6', 0],
  ['10분이 지남 — 거절', 'issue', (n) => `?authorize=1&idp_nonce=${n}&idp_code=c7`, 600_001],
  ['돌아온 길이 아님 — null', 'issue', () => '?authorize=1', 0],
];
for (const [name, purpose, search, late] of cases) {
  await t(`사본과 모듈이 같은 답: ${name}`, async () => {
    const w = walletCopy();
    const nonce = await w.go(REQ, ORIGIN, purpose);
    const saved = JSON.parse(w.ctx.sessionStorage.getItem(M.PENDING_KEY));
    const ms = store(); M.savePending(ms, { req: REQ, origin: ORIGIN, nonce, at: saved.at, purpose });
    assert.deepEqual(saved, JSON.parse(ms.getItem(M.PENDING_KEY)), '갈 때 남기는 대기분(목적 포함)이 같다');
    const now = saved.at + late, q = search(nonce);
    const got = norm(w.back(q, now)), want = norm(moduleTake(ms, q, now));
    assert.deepEqual(got, want);
    assert.equal(w.ctx.sessionStorage.getItem(M.PENDING_KEY) === null, ms.getItem(M.PENDING_KEY) === null, '저장분을 지우는 규칙도 같다');
  });
}
await t('대기 시간 상한이 같다', () => { assert.equal(walletCopy().ctx.PENDING_MAX_AGE_MS, M.PENDING_MAX_AGE_MS); });
console.log(fails ? `\n${fails} 실패` : '\n모두 통과');
process.exit(fails ? 1 : 0);
