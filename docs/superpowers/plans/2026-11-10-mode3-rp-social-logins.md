# RP 계정에 zkID·Google·네이버 로그인 연결 — 구현 계획

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** RP(zkONE·zkTWO)가 Google·네이버 OIDC 클라이언트가 되어 RP 계정(로그인 수단 세 칸: zkID=PPID·Google·네이버)에 로그인·연결하게 하고, 11-09 의 zkID(IdP) 쪽 연결을 걷어낸다.

**Architecture:** RP 계정 저장소(`lib/mode3_rp_accounts.js`, 파일 version 2)가 계정·수단 색인·KRW·거래소 보관 ETH 장부를 맡는다. RP 서버는 `express-session` 쿠키 세션(RP 마다 다른 이름)을 두고, 소셜 경로(`lib/mode3_rp_social.js`)와 기존 zkID 로그인이 같은 저장소·같은 장부 함수(`ledgerOp`)를 쓴다. 화면(`mode3/rp.html`)은 쿠키 세션(`/api/rp/me`)과 zkID r_s 세션 중 하나라도 있으면 로그인 상태다.

**Tech Stack:** Node ESM, express 4 + express-session(이미 의존성), jose(검증기 `lib/mode3_oidc.js`), ethers 6, Playwright(브라우저 테스트), hardhat 노드(:8545).

**Spec:** `docs/superpowers/specs/2026-11-10-mode3-rp-social-logins-design.md`

## Global Constraints

- 모든 주석·문구는 한국어, 기존 스타일(날짜 꼬리표 `2026-11-10`, 한 줄 주석 밀도)을 따른다.
- 새 의존성 금지(`express-session`·`jose`·`ethers` 는 이미 있다).
- 비밀(네이버 Client Secret·세션 비밀)은 응답·로그·화면·진행 줄에 싣지 않는다. `.env`·`role.env` 값은 읽거나 출력하지 않는다(스크립트가 옮길 뿐).
- 회로(`circuits/`)·컨트랙트(`contracts/`)·`npm run zk:*` 는 건드리지 않는다.
- `/api/rp/me` 등 API 응답에 Google·네이버 `sub` 을 싣지 않는다.
- 쿠키 이름: `<RP 이름 소문자에서 [a-z0-9_-] 만>.sid`(빈 값이면 `rp.sid`), `httpOnly`, `sameSite:'lax'`.
- 오류 사유 코드(정확한 문자열): `no_rp_session`, `bad_purpose`, `bad_nonce`, `provider_disabled`, `method_linked_elsewhere`, `method_already_linked`, `not_linked`, `last_method`, `bad_method`, `insufficient_krw`, `insufficient_custody`, `bad_amount`, `bad_address`, `withdraw_failed`, `request_replayed`, `json_only`, `naver_state_invalid`, `naver_denied`, `naver_token_failed`.
- nonce 접두어: 로그인 `rplogin:`, 연결 `rplink:`.
- 테스트 진입점은 `scripts/run_tests.sh`. 새 테스트는 해당 그룹(unit·chain·browser)에 넣는다. :8545 를 쓰는 테스트는 순서대로(동시에 돌리지 않는다). hardhat 은 스크래치 `chain/min.config.cjs` 로 띄우고, 끝나면 그 프로세스만(명령줄 확인 후) 내린다.
- `git add` 는 경로를 지정해서만. 커밋 꼬리말 `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>` · `Claude-Session: https://claude.ai/code/session_013qGSXZTftBJSB1M4XpPRHN`. **커밋은 사용자가 이 계획을 승인할 때 태스크별 커밋까지 승인한 경우에만.**

## Review Focus

1. 소셜 세션과 zkID r_s 세션이 한 화면에 섞일 때(예: zkID 로 로그인해 둔 탭에서 다른 브라우저 창의 Google 로그인) — 화면은 쿠키 세션의 계정(`/api/rp/me`)을 기준으로 보이고, 로그아웃은 둘 다 끝낸다. → Task 3 브라우저 케이스의 "로그아웃하면 /api/rp/me 401 이고 r_s 세션도 사라진다".
2. 네이버에서 사용자가 취소(`?error=access_denied&state=…`) — 500 이 아니라 `/?social_error=naver_denied` 로 돌아온다. → Task 2 테스트.
3. 거래소 보관 출금의 잘못된 입력(잔액 초과·0·주소 형식 오류)과 릴레이어 전송 실패 — 400 이고 장부가 그대로다(전송 실패면 되돌린다). → Task 2 테스트(잔액 초과·0·주소 오류). 전송 실패는 `ledgerOp` 의 되돌림 코드로 보장(테스트 생략 — 릴레이어 실패를 격리 스택에서 만들 수 없다).
4. 자기 계정이 이미 있는 PPID 를 다른 계정에 zkID 로 연결 — 409 `method_linked_elsewhere`, r_s 세션도 만들지 않는다(로그인이 몰래 다른 계정으로 바뀌지 않는다). → Task 2 테스트.
5. RP 재기동 — 쿠키 세션은 사라져도(세션 비밀이 기동마다 무작위) 계정·연결·KRW·거래소 보관 잔고는 남는다. → Task 2 테스트(`restartRp` 뒤 같은 수단으로 다시 로그인하면 같은 계정·같은 잔고).

---

## File Structure

| 파일 | 할 일 |
|---|---|
| `lib/mode3_rp_accounts.js` (새) | RP 계정 저장소: 수단 색인·연결·해제·속성 커밋먼트 고정·KRW·거래소 보관 장부, version 1→2 이전 |
| `lib/mode3_rp_social.js` (새) | RP 소셜 라우트(`/api/rp/*`), 설정 읽기, 쿠키 세션 묶기 |
| `mode3_rp.js` | 저장소·세션·소셜 라우트 연결, `/api/mode3/login` 의 쿠키 세션·`link:true`, 장부 함수 `ledgerOp`, `rp_info.social`, 로그인 기록 `via` |
| `tests/helpers/isolated_mode3_stack.mjs` | RP 계정 파일을 임시 디렉터리로(지금은 저장소 루트에 샌다) |
| `tests/test_mode3_rp_accounts.mjs` (새, unit) | 저장소 단위 |
| `tests/test_rp_social_logins.mjs` (새, chain) | RP 소셜·연결·장부 통합 |
| `mode3/rp.html`, `mode3/rp_admin.html`, `mode3/common/strings.js`, `mode3/common/rp.css` | 로그인 창 소셜 버튼, 내 계정 패널, 자산(거래소 보관·출금 출처), 기록의 수단 열 |
| `cia.js`, `lib/mode3_cia_state.js`, `lib/mode3_oidc_link.js`, `mode3/cia_login.html`, `mode3/cia_user.html`, `mode3/wallet.html`, `mode3/user/popup.js` | 11-09 zkID 쪽 연결 제거 |
| `tests/test_cia_linked_logins.mjs`(삭제), `tests/test_mode3_oidc_link.mjs`, `tests/test_cia_oidc_register.mjs`, `tests/test_mode3_cia_state.mjs`, `tests/test_mode3_wallet_snap_oidc_browser.mjs`, `tests/helpers/isolated_cia.mjs` | 제거에 맞춘 테스트 정리 |
| `scripts/demo_split_start.sh`, `docs/MODE3_DEMO.md`, `scripts/run_tests.sh` | RP 터널·키 전달, 런북, 테스트 등록 |

---

### Task 1: RP 계정 저장소

**Files:**
- Create: `lib/mode3_rp_accounts.js`
- Test: `tests/test_mode3_rp_accounts.mjs`
- Modify: `scripts/run_tests.sh`(unit 그룹에 추가)

**Interfaces:**
- Produces:
  - `METHODS = ['zkid','google','naver']`
  - `class AccountError extends Error { status: number; reason: string }`
  - `migrateAccounts(raw, { now: string, newId: () => string }) → { state, migrated: boolean }`
  - `openAccountStore({ file, now?: () => ISOString, newId?: () => string }) → store` 메서드:
    `get(id) → account|null`, `findBy(method, ref) → id|null`, `loginOrCreate(method, ref) → { id, created }`,
    `link(id, method, ref) → account`, `unlink(id, method) → account`, `view(id) → { account, methods:{zkid:{PPID,linkedAt}|null, google:{linkedAt}|null, naver:{linkedAt}|null}, attrCommit }`,
    `pinAttrCommit(id, commit|null) → { attrCommit, changed }`, `krw(id) → bigint`, `custody(id) → bigint`, `addKrw(id, delta) → bigint`, `addCustody(id, delta) → bigint`.
  - `ref` 는 zkid 면 `{ PPID: '<10진>' }`, google·naver 면 `{ sub: '<문자열>' }`.

- [ ] **Step 1: 실패하는 단위 테스트 작성** — `tests/test_mode3_rp_accounts.mjs`

```js
// tests/test_mode3_rp_accounts.mjs — RP 계정 저장소(lib/mode3_rp_accounts.js, 스펙 2026-11-10 §2) 단위. 외부 의존 없음. (unit)
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { openAccountStore, migrateAccounts, AccountError, METHODS } from '../lib/mode3_rp_accounts.js';

let failed = 0;
async function t(name, fn) { try { await fn(); console.log(`ok   ${name}`); } catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.stack ?? e.message}`); } }
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rp-accounts-'));
let n = 0;
const fresh = () => { const file = path.join(dir, `a${++n}.json`); let i = 0; return { file, store: openAccountStore({ file, now: () => '2026-11-10T00:00:00.000Z', newId: () => `acct_${n}_${++i}` }) }; };
const rejectsWith = (fn, status, reason) => assert.throws(fn, (e) => e instanceof AccountError && e.status === status && e.reason === reason);

await t('METHODS 는 zkid·google·naver', () => assert.deepEqual([...METHODS], ['zkid', 'google', 'naver']));
await t('loginOrCreate: 처음 보는 수단이면 그 칸만 채운 새 계정, 두 번째는 같은 계정', () => {
  const { store } = fresh();
  const a = store.loginOrCreate('google', { sub: 'g1' });
  assert.equal(a.created, true);
  assert.deepEqual(store.loginOrCreate('google', { sub: 'g1' }), { id: a.id, created: false });
  const acc = store.get(a.id);
  assert.equal(acc.google.sub, 'g1'); assert.equal(acc.zkid, null); assert.equal(acc.naver, null);
  assert.equal(store.findBy('google', { sub: 'g1' }), a.id); assert.equal(store.findBy('naver', { sub: 'g1' }), null, '수단마다 색인이 따로');
});
await t('link: 빈 칸에 붙인다; 다른 계정의 값이면 409 method_linked_elsewhere; 칸이 차 있으면 409 method_already_linked; 같은 값은 그대로', () => {
  const { store } = fresh();
  const A = store.loginOrCreate('zkid', { PPID: '111' }).id, B = store.loginOrCreate('google', { sub: 'g2' }).id;
  store.link(A, 'naver', { sub: 'n1' });
  assert.equal(store.findBy('naver', { sub: 'n1' }), A);
  rejectsWith(() => store.link(B, 'naver', { sub: 'n1' }), 409, 'method_linked_elsewhere');
  rejectsWith(() => store.link(B, 'zkid', { PPID: '111' }), 409, 'method_linked_elsewhere');
  rejectsWith(() => store.link(A, 'naver', { sub: 'n9' }), 409, 'method_already_linked');
  assert.equal(store.link(A, 'naver', { sub: 'n1' }).naver.sub, 'n1', '같은 값 재연결은 오류가 아니다');
  rejectsWith(() => store.link('acct_none', 'google', { sub: 'x' }), 404, 'no_account');
  rejectsWith(() => store.link(A, 'email', { sub: 'x' }), 400, 'bad_method');
  rejectsWith(() => store.link(A, 'google', { sub: '' }), 400, 'bad_sub');
});
await t('unlink: 마지막 수단은 409 last_method, 없는 칸은 409 not_linked; 풀면 색인도 지워져 다른 계정이 쓸 수 있다', () => {
  const { store } = fresh();
  const A = store.loginOrCreate('google', { sub: 'g3' }).id;
  rejectsWith(() => store.unlink(A, 'google'), 409, 'last_method');
  rejectsWith(() => store.unlink(A, 'naver'), 409, 'not_linked');
  store.link(A, 'naver', { sub: 'n3' });
  store.unlink(A, 'google');
  assert.equal(store.findBy('google', { sub: 'g3' }), null);
  const B = store.loginOrCreate('google', { sub: 'g3' });
  assert.equal(B.created, true, '풀린 Google 로 로그인하면 새 계정');
});
await t('view 는 sub 을 싣지 않는다', () => {
  const { store } = fresh();
  const A = store.loginOrCreate('google', { sub: 'secret-sub' }).id;
  store.link(A, 'zkid', { PPID: '222' });
  const v = store.view(A);
  assert.equal(v.account, A); assert.equal(v.methods.zkid.PPID, '222'); assert.ok(v.methods.google.linkedAt);
  assert.equal(JSON.stringify(v).includes('secret-sub'), false);
});
await t('pinAttrCommit: 처음 고정은 changed false, 다른 값이면 true + 기록, null 이면 그대로', () => {
  const { store } = fresh();
  const A = store.loginOrCreate('zkid', { PPID: '333' }).id;
  assert.deepEqual(store.pinAttrCommit(A, null), { attrCommit: null, changed: false });
  assert.deepEqual(store.pinAttrCommit(A, '5'), { attrCommit: '5', changed: false });
  assert.deepEqual(store.pinAttrCommit(A, '5'), { attrCommit: '5', changed: false });
  assert.deepEqual(store.pinAttrCommit(A, '6'), { attrCommit: '6', changed: true });
  assert.equal(store.get(A).attrHistory.at(-1).attrCommit, '5');
});
await t('장부: addKrw·addCustody 는 bigint, 음수가 되면 400 이고 바뀌지 않는다', () => {
  const { store } = fresh();
  const A = store.loginOrCreate('google', { sub: 'g4' }).id;
  assert.equal(store.addKrw(A, 1_000_000n), 1_000_000n);
  rejectsWith(() => store.addKrw(A, -2_000_000n), 400, 'insufficient_krw');
  assert.equal(store.krw(A), 1_000_000n);
  assert.equal(store.addCustody(A, 10n ** 17n), 10n ** 17n);
  rejectsWith(() => store.addCustody(A, -(10n ** 18n)), 400, 'insufficient_custody');
  assert.equal(store.custody(A), 10n ** 17n);
});
await t('파일: 다시 열어도 계정·색인·장부가 남는다(version 2, 권한 600)', () => {
  const { file, store } = fresh();
  const A = store.loginOrCreate('naver', { sub: 'n5' }).id;
  store.addKrw(A, 7n); store.addCustody(A, 9n);
  const again = openAccountStore({ file });
  assert.equal(again.findBy('naver', { sub: 'n5' }), A); assert.equal(again.krw(A), 7n); assert.equal(again.custody(A), 9n);
  assert.equal(JSON.parse(fs.readFileSync(file, 'utf8')).version, 2);
  assert.equal(fs.statSync(file).mode & 0o777, 0o600);
});
await t('version 1(byPPID → 속성 커밋먼트)은 PPID 계정으로 옮기고 파일을 version 2 로 다시 쓴다', () => {
  const file = path.join(dir, 'v1.json');
  fs.writeFileSync(file, JSON.stringify({ version: 1, byPPID: { '444': { attrCommit: '9', since: '2026-11-09T01:00:00.000Z', updatedAt: '2026-11-09T02:00:00.000Z', history: [] } } }));
  const store = openAccountStore({ file, newId: () => 'acct_v1' });
  assert.equal(store.findBy('zkid', { PPID: '444' }), 'acct_v1');
  assert.equal(store.get('acct_v1').attrCommit, '9');
  assert.equal(JSON.parse(fs.readFileSync(file, 'utf8')).version, 2);
});
await t('모르는 모양의 파일이면 연다고 덮어쓰지 않고 오류', () => {
  assert.throws(() => migrateAccounts({ version: 7 }, { now: 'x', newId: () => 'y' }), /모양을 모른다/);
});

fs.rmSync(dir, { recursive: true, force: true });
if (failed) { console.error(`${failed} failed`); process.exit(1); }
console.log('all passed');
```

- [ ] **Step 2: 실패 확인** — Run: `node tests/test_mode3_rp_accounts.mjs` → Expected: `Cannot find module '../lib/mode3_rp_accounts.js'`.

- [ ] **Step 3: 구현** — `lib/mode3_rp_accounts.js`

```js
// lib/mode3_rp_accounts.js — RP 계정 저장소(스펙 2026-11-10-mode3-rp-social-logins §2). RP(mode3_rp.js)만 쓴다.
// 계정 하나에 로그인 수단 세 칸(zkid=PPID · google · naver) — 수단 하나는 계정 하나에만(색인 byPPID·byGoogle·byNaver). KRW 장부와 거래소 보관 ETH(wei)도
// 계정 번호 기준이다(어느 수단으로 로그인해도 같은 잔고). 파일 version 2. version 1(byPPID → { attrCommit, since, updatedAt, history }, 11-09 Phase 1)은
// 열 때 PPID 계정으로 옮긴다. 모르는 모양이면 기동을 막는다 — 조용히 비우면 장부를 잃는다.
import { randomBytes } from 'node:crypto';
import { readJson, writeJsonAtomic } from './mode3_state.js';

export const METHODS = Object.freeze(['zkid', 'google', 'naver']);
const INDEX = Object.freeze({ zkid: 'byPPID', google: 'byGoogle', naver: 'byNaver' });
const isDec = (v) => typeof v === 'string' && /^[0-9]+$/.test(v);

export class AccountError extends Error {
  constructor(status, reason) { super(reason); this.status = status; this.reason = reason; }
}
const fail = (status, reason) => { throw new AccountError(status, reason); };
/** 수단의 색인 키 — zkid 는 PPID(10진), google·naver 는 sub. */
function keyOf(method, ref) {
  if (!METHODS.includes(method)) fail(400, 'bad_method');
  if (method === 'zkid') { if (!isDec(ref?.PPID) || ref.PPID.length > 80) fail(400, 'bad_ppid'); return ref.PPID; }
  if (typeof ref?.sub !== 'string' || !ref.sub || ref.sub.length > 256) fail(400, 'bad_sub');
  return ref.sub;
}
const slotOf = (method, k, at) => (method === 'zkid' ? { PPID: k, linkedAt: at } : { sub: k, linkedAt: at });
export const emptyAccountsState = () => ({ version: 2, accounts: {}, byPPID: {}, byGoogle: {}, byNaver: {}, krw: {}, custodyEth: {} });
const blankAccount = (id, at) => ({ id, createdAt: at, zkid: null, google: null, naver: null, attrCommit: null, attrSince: null, attrUpdatedAt: null, attrHistory: [] });

/** 파일 내용 → version 2 상태. migrated 면 호출자가 곧바로 다시 쓴다. */
export function migrateAccounts(raw, { now, newId }) {
  if (raw === null || raw === undefined) return { state: emptyAccountsState(), migrated: false };
  if (raw.version === 2 && raw.accounts && typeof raw.accounts === 'object') return { state: { ...emptyAccountsState(), ...raw }, migrated: false };
  if (raw.version === 1 && raw.byPPID && typeof raw.byPPID === 'object') {
    const s = emptyAccountsState();
    for (const [PPID, v] of Object.entries(raw.byPPID)) {
      if (!isDec(PPID)) continue;
      const id = newId(), at = v?.since ?? now;
      s.accounts[id] = { ...blankAccount(id, at), zkid: { PPID, linkedAt: at }, attrCommit: v?.attrCommit ?? null, attrSince: v?.since ?? null, attrUpdatedAt: v?.updatedAt ?? null, attrHistory: Array.isArray(v?.history) ? v.history : [] };
      s.byPPID[PPID] = id;
    }
    return { state: s, migrated: true };
  }
  throw new Error('RP 계정 파일의 모양을 모른다(version 1·2 가 아니다) — 지우지 말고 확인할 것');
}

export function openAccountStore({ file, now = () => new Date().toISOString(), newId = () => `acct_${randomBytes(8).toString('hex')}` }) {
  const { state, migrated } = migrateAccounts(readJson(file, null), { now: now(), newId });
  const save = () => writeJsonAtomic(file, state, 0o600);
  if (migrated) save();
  const acct = (id) => state.accounts[id] ?? fail(404, 'no_account');
  const clone = (v) => JSON.parse(JSON.stringify(v));
  const store = {
    get: (id) => (state.accounts[id] ? clone(state.accounts[id]) : null),
    findBy: (method, ref) => state[INDEX[method] ?? fail(400, 'bad_method')][keyOf(method, ref)] ?? null,
    /** 그 수단의 계정으로 로그인 — 없으면 그 칸만 채운 새 계정을 만든다(R4). */
    loginOrCreate(method, ref) {
      const k = keyOf(method, ref);
      const found = state[INDEX[method]][k];
      if (found) return { id: found, created: false };
      const id = newId(), at = now();
      state.accounts[id] = { ...blankAccount(id, at), [method]: slotOf(method, k, at) };
      state[INDEX[method]][k] = id;
      save();
      return { id, created: true };
    },
    /** 로그인한 계정의 빈 칸에 붙인다 — 병합은 하지 않는다. */
    link(id, method, ref) {
      const a = acct(id), k = keyOf(method, ref);
      const owner = state[INDEX[method]][k];
      if (owner === id) return clone(a);
      if (owner) fail(409, 'method_linked_elsewhere');
      if (a[method]) fail(409, 'method_already_linked');
      a[method] = slotOf(method, k, now());
      state[INDEX[method]][k] = id;
      save();
      return clone(a);
    },
    /** 수단이 하나 이상 남을 때만 푼다. */
    unlink(id, method) {
      const a = acct(id);
      if (!METHODS.includes(method)) fail(400, 'bad_method');
      if (!a[method]) fail(409, 'not_linked');
      if (METHODS.filter((m) => a[m]).length <= 1) fail(409, 'last_method');
      delete state[INDEX[method]][method === 'zkid' ? a.zkid.PPID : a[method].sub];
      a[method] = null;
      save();
      return clone(a);
    },
    /** 화면·API 용 — Google·네이버 sub 은 싣지 않는다. */
    view(id) {
      const a = acct(id);
      return { account: id, methods: { zkid: a.zkid ? { PPID: a.zkid.PPID, linkedAt: a.zkid.linkedAt } : null, google: a.google ? { linkedAt: a.google.linkedAt } : null, naver: a.naver ? { linkedAt: a.naver.linkedAt } : null }, attrCommit: a.attrCommit };
    },
    /** zkID ID 토큰의 name(C_attr)을 계정에 고정한다(11-09 Phase 1 의 pinAttrCommit 과 같은 규칙, 키만 계정 번호). */
    pinAttrCommit(id, commit) {
      const a = acct(id);
      if (!commit) return { attrCommit: a.attrCommit, changed: false };
      if (a.attrCommit === commit) return { attrCommit: commit, changed: false };
      const at = now(), had = a.attrCommit !== null;
      if (had) a.attrHistory = [...a.attrHistory, { attrCommit: a.attrCommit, until: at }].slice(-10); else a.attrSince = at;
      a.attrCommit = commit; a.attrUpdatedAt = at;
      save();
      return { attrCommit: commit, changed: had };
    },
    krw: (id) => BigInt(state.krw[id] ?? '0'),
    custody: (id) => BigInt(state.custodyEth[id] ?? '0'),
    /** 장부 증감 — 결과가 음수면 400 이고 아무것도 바꾸지 않는다. */
    addKrw(id, delta) { acct(id); const v = store.krw(id) + BigInt(delta); if (v < 0n) fail(400, 'insufficient_krw'); state.krw[id] = v.toString(); save(); return v; },
    addCustody(id, delta) { acct(id); const v = store.custody(id) + BigInt(delta); if (v < 0n) fail(400, 'insufficient_custody'); state.custodyEth[id] = v.toString(); save(); return v; },
  };
  return store;
}
```

- [ ] **Step 4: 통과 확인** — Run: `node tests/test_mode3_rp_accounts.mjs` → Expected: 모든 줄 `ok`, `all passed`.

- [ ] **Step 5: 테스트 등록** — `scripts/run_tests.sh` 의 unit 목록에서 `tests/test_mode3_attr_commit.mjs` 줄 바로 아래에 `tests/test_mode3_rp_accounts.mjs` 를 같은 형식으로 추가. Run: `bash scripts/run_tests.sh unit` → `실패 0`.

- [ ] **Step 6: 커밋**

```bash
git add lib/mode3_rp_accounts.js tests/test_mode3_rp_accounts.mjs scripts/run_tests.sh
git commit -m "feat(rp): RP 계정 저장소 — 로그인 수단 세 칸(zkid·google·naver)·KRW·거래소 보관 장부, version 1→2 이전" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -m "Claude-Session: https://claude.ai/code/session_013qGSXZTftBJSB1M4XpPRHN"
```

---

### Task 2: RP 서버 — 쿠키 세션·소셜 라우트·장부

**Files:**
- Create: `lib/mode3_rp_social.js`
- Modify: `mode3_rp.js` (계정 저장소 `113-127`, 앱 미들웨어 `~407`, `rp_info` `~452`, `/api/mode3/login` `~501-541`, 장부 `~570-666`)
- Modify: `tests/helpers/isolated_mode3_stack.mjs` (RP env 에 `MODE3_RP_ACCOUNTS_FILE`)
- Test: `tests/test_rp_social_logins.mjs` (새, chain) · `scripts/run_tests.sh`(chain 그룹)

**Interfaces:**
- Consumes (Task 1): `openAccountStore`, `AccountError`.
- Produces:
  - `lib/mode3_rp_social.js`: `RP_LOGIN_PREFIX='rplogin:'`, `RP_LINK_PREFIX='rplink:'`, `socialConfigFromEnv(env, { publicOrigin }) → { google:{enabled,clientId,issuer,jwksUrl}, naver:{enabled,clientId,clientSecret,issuer,jwksUrl,authorizeUrl,tokenUrl,redirectUri} }`, `setRpSession(req, account, via) → Promise`, `mountRpSocial(app, { store, cfg, ledgerOp, onLogin })`.
  - HTTP: `GET /api/rp/me`, `POST /api/rp/oidc/nonce {purpose}`, `POST /api/rp/google {id_token,purpose}`, `GET /api/rp/naver/start?purpose`, `GET /api/rp/naver/callback`, `POST /api/rp/unlink {method}`, `POST /api/rp/logout`, `POST /api/rp/ledger {body}`.
  - `/api/rp/ledger` 와 `/api/mode3/request` 가 같은 본문 문법을 받는다: `balance` · `deposit:<ms>` · `buy:<eth>:<ms>` · (쿠키 세션만) `withdraw:<0x주소>:<wei>:<ms>`.
  - 장부 응답 `balance.ledger` 키: `KRW`, `ETH`(PPID 계정, 없으면 `'-'`), `ETH_CUSTODY`(거래소 보관). `balance.custodyWei`(10진).
  - `rp_info.social = { google: { enabled, clientId }, naver: { enabled } }`.
  - `/api/mode3/login` 응답에 `account`, `via:'zkid'`; 본문 `link: true` 지원.

- [ ] **Step 1: 격리 스택의 계정 파일 누수 수정** — `tests/helpers/isolated_mode3_stack.mjs` 의 `rpSpawnFor` env 에서 `MODE3_RP_LOGIN_LOG` 줄 아래에 추가:

```js
        MODE3_RP_ACCOUNTS_FILE: path.join(dir, `mode3_${tag}_accounts.json`),   // 2026-11-10: 없으면 저장소 루트의 mode3_rp_accounts.json 에 썼다(테스트 누수)
```

그리고 같은 파일 `PINNED_ENV` 의 `MODE3_RP_LOGIN_LOG: '',` 뒤에 `MODE3_RP_ACCOUNTS_FILE: '', MODE3_RP_GOOGLE_CLIENT_ID: '', MODE3_RP_NAVER_CLIENT_ID: '', MODE3_RP_NAVER_CLIENT_SECRET: '', MODE3_RP_NAVER_REDIRECT_URI: '', MODE3_RP_SESSION_SECRET: '',` 를 넣는다(셸에 남은 데모 값이 새지 않게).

- [ ] **Step 2: 실패하는 통합 테스트 작성** — `tests/test_rp_social_logins.mjs`

```js
// tests/test_rp_social_logins.mjs — RP 계정에 zkID·Google·네이버 로그인 연결(스펙 2026-11-10). 격리 스택(IdP·지갑·RP 둘) + 가짜 Google·네이버. (chain — :8545)
import assert from 'node:assert/strict';
import { startIsolatedMode3Stack } from './helpers/isolated_mode3_stack.mjs';
import { startOidcIssuerStub } from './helpers/oidc_issuer_stub.mjs';

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
  let B = null;
  await t('rp_info.social: 두 공급자 켜짐, Google 클라이언트 ID 만 싣는다(비밀 없음)', async () => {
    const s = (await rp.get('/api/mode3/rp_info')).body.social;
    assert.deepEqual(s, { google: { enabled: true, clientId: g.clientId }, naver: { enabled: true } });
    assert.equal(j((await rp.get('/api/mode3/rp_info')).body).includes('rp-naver-secret'), false);
  });
  await t('Google 첫 로그인 → 새 계정·쿠키 세션(이름 zkone.sid), /api/rp/me 에 sub 없음; nonce 재사용·다른 aud·purpose 불일치는 거절', async () => {
    const u = jar(rp.base);
    const r = await googleLogin(u, 'g-alice');
    assert.equal(r.status, 200, j(r.body)); assert.equal(r.body.created, true); assert.equal(r.body.via, 'google'); B = r.body.account;
    assert.ok(u.cookies.has('zkone.sid'), `쿠키: ${[...u.cookies.keys()]}`);
    const me = await u.req('GET', '/api/rp/me');
    assert.equal(me.body.account, B); assert.equal(me.body.via, 'google'); assert.equal(j(me.body).includes('g-alice'), false);
    const { nonce } = (await u.req('POST', '/api/rp/oidc/nonce', { purpose: 'login' })).body;
    const tok = await g.mint({ sub: 'g-x', nonce });
    assert.equal((await u.req('POST', '/api/rp/google', { id_token: tok, purpose: 'login' })).status, 200);
    assert.equal((await u.req('POST', '/api/rp/google', { id_token: tok, purpose: 'login' })).body.reason, 'bad_nonce', 'nonce 는 1회용');
    const { nonce: n2 } = (await u.req('POST', '/api/rp/oidc/nonce', { purpose: 'login' })).body;
    assert.equal((await u.req('POST', '/api/rp/google', { id_token: await g.mint({ sub: 'g-x', nonce: n2, aud: 'other' }), purpose: 'login' })).status, 401, '다른 aud');
    const { nonce: n3 } = (await u.req('POST', '/api/rp/oidc/nonce', { purpose: 'login' })).body;
    assert.equal((await u.req('POST', '/api/rp/google', { id_token: await g.mint({ sub: 'g-x', nonce: n3 }), purpose: 'link' })).status, 401, '로그인 nonce 로 연결 불가(접두어)');
    assert.equal((await jar(rp.base).req('POST', '/api/rp/oidc/nonce', { purpose: 'link' })).body.reason, 'no_rp_session');
  });
  await t('Google 계정(B)에 zkID 연결(link:true) → B 에 PPID; 이어서 새 브라우저의 zkID 로그인은 B 로 들어간다', async () => {
    const u = jar(rp.base); await googleLogin(u, 'g-alice');
    const r = await zkLogin(u, rp, { link: true });
    assert.equal(r.body.ok, true, j(r.body)); assert.equal(r.body.account, B);
    assert.ok((await u.req('GET', '/api/rp/me')).body.methods.zkid.PPID);
    const v = jar(rp.base); const z = await zkLogin(v);
    assert.equal(z.body.ok, true, j(z.body)); assert.equal(z.body.account, B); assert.equal(z.body.via, 'zkid');
    assert.equal((await v.req('GET', '/api/rp/me')).body.via, 'zkid');
  });
  await t('다른 Google 계정(C)에 같은 PPID 를 zkID 로 연결하면 409 method_linked_elsewhere 이고 r_s 세션도 생기지 않는다', async () => {
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
  await t('거래소 보관: 쿠키 세션으로 입금·구매(거래소 보관 ETH 증가, 체인 거래 없음) → 출금은 릴레이어가 실제 ETH 를 보낸다; 초과·0·주소 오류는 400 이고 장부 그대로', async () => {
    const u = jar(rp.base); await googleLogin(u, 'g-frank');
    const ts = () => Date.now();
    assert.equal((await u.req('POST', '/api/rp/ledger', { body: `deposit:${ts()}` })).body.ok, true);
    const b = await u.req('POST', '/api/rp/ledger', { body: `buy:0.1:${ts()}` });
    assert.equal(b.body.ok, true, j(b.body)); assert.equal(b.body.balance.ledger.ETH_CUSTODY, '0.1'); assert.equal(b.body.balance.ledger.ETH, '-', 'PPID 계정 없음');
    const to = '0x000000000000000000000000000000000000bEEF';
    const before = await stack.provider.getBalance(to);
    for (const [body, reason] of [[`withdraw:${to}:${10n ** 18n}:${ts()}`, 'insufficient_custody'], [`withdraw:${to}:0:${ts()}`, 'bad_amount'], [`withdraw:0x12:5:${ts()}`, 'bad_address']]) {
      const r = await u.req('POST', '/api/rp/ledger', { body });
      assert.equal(r.status, 400, j(r.body)); assert.equal(r.body.reason, reason);
    }
    const w = await u.req('POST', '/api/rp/ledger', { body: `withdraw:${to}:${5n * 10n ** 16n}:${ts()}` });
    assert.equal(w.body.ok, true, j(w.body)); assert.match(w.body.txHash, /^0x/);
    assert.equal((await stack.provider.getBalance(to)) - before, 5n * 10n ** 16n);
    assert.equal(w.body.balance.ledger.ETH_CUSTODY, '0.05');
    const rep = `deposit:${ts()}`; await u.req('POST', '/api/rp/ledger', { body: rep });
    assert.equal((await u.req('POST', '/api/rp/ledger', { body: rep })).body.reason, 'request_replayed');
    assert.equal((await jar(rp.base).req('POST', '/api/rp/ledger', { body: 'balance' })).body.reason, 'no_rp_session');
  });
  await t('RP 마다 따로: zkTWO 의 쿠키 이름은 zktwo.sid, zkONE 의 Google 계정은 zkTWO 에 없다(zkTWO 첫 로그인 = 새 계정)', async () => {
    const u = jar(rp2.base); const r = await googleLogin(u, 'g-frank');
    assert.equal(r.body.created, true); assert.ok(u.cookies.has('zktwo.sid'));
  });
  await t('RP 재기동: 쿠키 세션은 끝나도 계정·연결·KRW·거래소 보관 잔고는 남는다', async () => {
    const u = jar(rp.base); await googleLogin(u, 'g-frank');
    const bal = (await u.req('POST', '/api/rp/ledger', { body: 'balance' })).body.balance.ledger;
    await stack.restartRp();
    assert.equal((await u.req('GET', '/api/rp/me')).status, 401, '세션 비밀이 바뀌어 옛 쿠키는 무효');
    const v = jar(rp.base); await googleLogin(v, 'g-frank');
    assert.deepEqual((await v.req('POST', '/api/rp/ledger', { body: 'balance' })).body.balance.ledger, bal);
  });
  await t('로그아웃: /api/rp/logout 뒤 /api/rp/me 401; JSON 이 아닌 본문은 415 json_only', async () => {
    const u = jar(rp.base); await googleLogin(u, 'g-gina');
    await u.req('POST', '/api/rp/logout', {});
    assert.equal((await u.req('GET', '/api/rp/me')).status, 401);
    const r = await fetch(new URL('/api/rp/unlink', rp.base), { method: 'POST', headers: { 'Content-Type': 'text/plain' }, body: 'method=google' });
    assert.equal(r.status, 415);
  });
} finally {
  await stack.stop(); await g.stop(); await nv.stop();
}
if (failed) { console.error(`${failed} failed`); process.exit(1); }
console.log('all passed');
```

  격리 스택이 `stack.provider`·`stack.rps` 를 돌려주지 않으면 `isolated_mode3_stack.mjs` 의 반환 객체에 `provider: new ethers.JsonRpcProvider(<RP 들이 쓰는 CIA_RPC_URL>)` 와 `rps`(이미 있다)를 확인해 추가한다. 이미 있는 이름을 쓰고 새로 만들지 않는다.

- [ ] **Step 3: 실패 확인** — 임시 hardhat(:8545)을 띄우고 Run: `node tests/test_rp_social_logins.mjs` → Expected: 첫 케이스부터 FAIL(`rp_info.social` 없음).

- [ ] **Step 4: `lib/mode3_rp_social.js` 구현**

```js
// lib/mode3_rp_social.js — RP 의 Google·네이버 로그인과 RP 계정 연결(스펙 2026-11-10-mode3-rp-social-logins §3). mode3_rp.js 가 mountRpSocial(app, …) 로 붙인다.
// 이 로그인은 zk-Delegation 을 거치지 않는다(§6) — RP 가 공급자의 OIDC 클라이언트다. 쿠키 세션은 { rpAccount, via } 만 든다. sub·비밀은 응답에 싣지 않는다.
import { createOidcVerifier, GOOGLE_DEFAULTS } from './mode3_oidc.js';
import { NAVER_DEFAULTS, createOnceStore, pkcePair, naverAuthorizeUrl, exchangeNaverCode, randomHex } from './mode3_oidc_link.js';
import { AccountError } from './mode3_rp_accounts.js';

export const RP_LOGIN_PREFIX = 'rplogin:';
export const RP_LINK_PREFIX = 'rplink:';
const prefixOf = (purpose) => (purpose === 'link' ? RP_LINK_PREFIX : RP_LOGIN_PREFIX);

/** env → 공급자 설정. Google 은 클라이언트 ID 만 있으면, 네이버는 ID·Secret 둘 다 있어야 켜진다. 콜백 기본값은 이 RP 의 공개 주소. */
export function socialConfigFromEnv(env, { publicOrigin }) {
  const gId = env.MODE3_RP_GOOGLE_CLIENT_ID || null, nId = env.MODE3_RP_NAVER_CLIENT_ID || null, nSec = env.MODE3_RP_NAVER_CLIENT_SECRET || null;
  return {
    google: { enabled: Boolean(gId), clientId: gId, issuer: env.MODE3_RP_GOOGLE_ISSUER || GOOGLE_DEFAULTS.issuer, jwksUrl: env.MODE3_RP_GOOGLE_JWKS_URL || GOOGLE_DEFAULTS.jwksUrl },
    naver: {
      enabled: Boolean(nId && nSec), clientId: nId, clientSecret: nSec,
      issuer: env.MODE3_RP_NAVER_ISSUER || NAVER_DEFAULTS.issuer, jwksUrl: env.MODE3_RP_NAVER_JWKS_URL || NAVER_DEFAULTS.jwksUrl,
      authorizeUrl: env.MODE3_RP_NAVER_AUTHORIZE_URL || NAVER_DEFAULTS.authorizeUrl, tokenUrl: env.MODE3_RP_NAVER_TOKEN_URL || NAVER_DEFAULTS.tokenUrl,
      redirectUri: env.MODE3_RP_NAVER_REDIRECT_URI || `${publicOrigin}/api/rp/naver/callback`,
    },
  };
}

/** 쿠키 세션을 계정에 묶는다 — 계정이 정해지는 로그인은 세션 id 를 새로 받는다(고정 공격 방지). */
export function setRpSession(req, account, via) {
  return new Promise((resolve, reject) => req.session.regenerate((e) => {
    if (e) return reject(e);
    req.session.rpAccount = account; req.session.via = via;
    req.session.save((e2) => (e2 ? reject(e2) : resolve()));
  }));
}

/** 네이버에서 돌아갈 곳 — 로그인은 첫 화면, 연결은 "내 계정" 패널. */
const backTo = (purpose, params) => `/?${new URLSearchParams(params)}${purpose === 'link' ? '#account' : ''}`;

export function mountRpSocial(app, { store, cfg, ledgerOp, onLogin = () => {} }) {
  const google = cfg.google.enabled ? createOidcVerifier({ issuer: cfg.google.issuer, jwksUrl: cfg.google.jwksUrl, clientId: cfg.google.clientId }) : null;
  const naver = cfg.naver.enabled ? createOidcVerifier({ issuer: cfg.naver.issuer, jwksUrl: cfg.naver.jwksUrl, clientId: cfg.naver.clientId }) : null;
  const once = createOnceStore({ max: 2000 });
  const jsonOnly = (req, res, next) => (req.is('application/json') ? next() : res.status(415).json({ ok: false, reason: 'json_only' }));
  const me = (req) => (req.session?.rpAccount && store.get(req.session.rpAccount) ? req.session.rpAccount : null);
  const fail = (res, e) => {
    if (e instanceof AccountError) return res.status(e.status).json({ ok: false, reason: e.reason });
    if (e?.reason === 'oidc_unavailable') return res.status(502).json({ ok: false, reason: e.reason });
    if (e?.reason) return res.status(401).json({ ok: false, reason: e.reason });
    return res.status(500).json({ ok: false, reason: 'internal', detail: e?.message });
  };
  /** login: 그 수단의 계정(없으면 새로)으로 세션. link: 시작 때의 계정과 지금 세션 계정이 같을 때 그 계정에 붙인다. */
  async function finish(req, { method, sub, purpose, account }) {
    if (purpose === 'link') {
      if (!account || me(req) !== account) throw new AccountError(401, 'no_rp_session');
      store.link(account, method, { sub });
      return { ok: true, linked: method, via: req.session.via, ...store.view(account) };
    }
    const { id, created } = store.loginOrCreate(method, { sub });
    await setRpSession(req, id, method);
    onLogin({ account: id, via: method, created });
    return { ok: true, created, via: method, ...store.view(id) };
  }

  app.get('/api/rp/me', (req, res) => {
    const id = me(req);
    if (!id) return res.status(401).json({ ok: false, reason: 'no_rp_session' });
    res.json({ ok: true, via: req.session.via, ...store.view(id) });
  });
  app.post('/api/rp/oidc/nonce', jsonOnly, (req, res) => {
    const purpose = req.body?.purpose;
    if (purpose !== 'login' && purpose !== 'link') return res.status(400).json({ ok: false, reason: 'bad_purpose' });
    const account = purpose === 'link' ? me(req) : null;
    if (purpose === 'link' && !account) return res.status(401).json({ ok: false, reason: 'no_rp_session' });
    const nonce = prefixOf(purpose) + randomHex();
    once.put(`nonce:${nonce}`, { purpose, account });
    res.json({ ok: true, nonce });
  });
  app.post('/api/rp/google', jsonOnly, async (req, res) => {
    try {
      if (!google) return res.status(503).json({ ok: false, reason: 'provider_disabled' });
      const { id_token, purpose } = req.body ?? {};
      if (purpose !== 'login' && purpose !== 'link') return res.status(400).json({ ok: false, reason: 'bad_purpose' });
      if (typeof id_token !== 'string' || id_token.length > 8192) return res.status(400).json({ ok: false, reason: 'malformed' });
      const v = await google.verify(id_token, { noncePrefix: prefixOf(purpose) });
      const n = once.take(`nonce:${v.nonce}`);
      if (!n || n.purpose !== purpose) return res.status(401).json({ ok: false, reason: 'bad_nonce' });
      res.json(await finish(req, { method: 'google', sub: v.sub, purpose, account: n.account }));
    } catch (e) { fail(res, e); }
  });
  app.get('/api/rp/naver/start', (req, res) => {
    const purpose = req.query.purpose === 'link' ? 'link' : 'login';
    if (!naver) return res.redirect(backTo(purpose, { social_error: 'provider_disabled' }));
    const account = purpose === 'link' ? me(req) : null;
    if (purpose === 'link' && !account) return res.redirect(backTo(purpose, { social_error: 'no_rp_session' }));
    const st = randomHex(), nonce = prefixOf(purpose) + randomHex(), { verifier, challenge } = pkcePair();
    once.put(`naver-state:${st}`, { purpose, nonce, verifier, account });
    res.redirect(naverAuthorizeUrl(cfg.naver, { state: st, nonce, challenge }));
  });
  app.get('/api/rp/naver/callback', async (req, res) => {
    const st = typeof req.query.state === 'string' ? req.query.state : '';
    const rec = st ? once.take(`naver-state:${st}`) : null;
    if (!rec) return res.redirect(backTo('login', { social_error: 'naver_state_invalid' }));
    if (typeof req.query.error === 'string') return res.redirect(backTo(rec.purpose, { social_error: 'naver_denied' }));
    try {
      const idToken = await exchangeNaverCode(cfg.naver, { code: String(req.query.code ?? ''), state: st, verifier: rec.verifier });
      const v = await naver.verify(idToken, { noncePrefix: prefixOf(rec.purpose) });
      if (v.nonce !== rec.nonce) return res.redirect(backTo(rec.purpose, { social_error: 'bad_nonce' }));
      await finish(req, { method: 'naver', sub: v.sub, purpose: rec.purpose, account: rec.account });
      res.redirect(backTo(rec.purpose, rec.purpose === 'link' ? { linked: 'naver' } : { social: 'ok', via: 'naver' }));
    } catch (e) {
      res.redirect(backTo(rec.purpose, { social_error: e?.reason ?? 'internal' }));
    }
  });
  app.post('/api/rp/unlink', jsonOnly, (req, res) => {
    const id = me(req);
    if (!id) return res.status(401).json({ ok: false, reason: 'no_rp_session' });
    try { store.unlink(id, req.body?.method); res.json({ ok: true, via: req.session.via, ...store.view(id) }); } catch (e) { fail(res, e); }
  });
  app.post('/api/rp/logout', (req, res) => { if (!req.session) return res.json({ ok: true }); req.session.destroy(() => res.json({ ok: true })); });
  app.post('/api/rp/ledger', jsonOnly, async (req, res) => {
    const id = me(req);
    if (!id) return res.status(401).json({ ok: false, reason: 'no_rp_session' });
    try { const r = await ledgerOp({ account: id, body: req.body?.body, channel: 'cookie' }); res.status(r.status ?? 200).json(r.body); } catch (e) { fail(res, e); }
  });
}
```

- [ ] **Step 5: `mode3_rp.js` 연결**

  5a. import 에 추가(파일 위쪽 import 묶음 끝):

```js
import session from 'express-session';
import { randomBytes } from 'node:crypto';   // 이미 있는 node:crypto import 줄에 randomBytes 를 합친다(줄을 새로 만들지 않는다)
import { openAccountStore, AccountError } from './lib/mode3_rp_accounts.js';
import { socialConfigFromEnv, mountRpSocial, setRpSession } from './lib/mode3_rp_social.js';
```

  5b. `113-127` 의 계정 저장 블록(`ACCOUNTS_FILE`·`accounts`·`pinAttrCommit`)을 다음으로 바꾼다:

```js
// RP 계정(2026-11-10 스펙 rp-social-logins §2): 계정 하나에 로그인 수단 세 칸(zkid=PPID·google·naver)·속성 커밋먼트·KRW·거래소 보관 ETH. 11-09 Phase 1 의
// byPPID 파일(version 1)은 열 때 옮긴다. 비밀은 없다(sub 은 파일에만).
const ACCOUNTS_FILE = process.env.MODE3_RP_ACCOUNTS_FILE || path.join(__dirname, 'mode3_rp_accounts.json');
const accountStore = openAccountStore({ file: ACCOUNTS_FILE });
const SOCIAL = socialConfigFromEnv(process.env, { publicOrigin: PUBLIC_ORIGIN });
```

  (`PUBLIC_ORIGIN` 은 93행에서 정의된다 — 이 블록이 그보다 위에 있으면 `SOCIAL` 줄만 `RP_KEY` 정의 아래로 옮긴다.)

  5c. `app.use(express.json(...))` 바로 아래에 쿠키 세션:

```js
// 쿠키 세션(2026-11-10): 소셜 로그인·zkID 로그인 모두 { rpAccount, via } 를 둔다. 이름을 RP 마다 다르게 — localhost 에서는 포트가 달라도
// 쿠키를 함께 쓰므로 같은 이름이면 zkONE·zkTWO·IdP(cia.sid) 세션이 서로 덮어쓴다. 비밀이 기동마다 바뀌면 재기동 뒤 옛 쿠키는 무효(계정·장부는 파일에 남는다).
const SESSION_COOKIE = `${RP_NAME.toLowerCase().replace(/[^a-z0-9_-]/g, '') || 'rp'}.sid`;
app.use(session({ name: SESSION_COOKIE, secret: process.env.MODE3_RP_SESSION_SECRET || randomBytes(32).toString('hex'), resave: false, saveUninitialized: false, cookie: { httpOnly: true, sameSite: 'lax' } }));
```

  5d. `rp_info` 응답 객체에 `social: { google: { enabled: SOCIAL.google.enabled, clientId: SOCIAL.google.clientId }, naver: { enabled: SOCIAL.naver.enabled } },` 를 `oidc: pkCIA.oidc` 앞에 넣는다.

  5e. `/api/mode3/login` — `const attr = pinAttrCommit(...)` 줄을 다음으로 바꾼다:

```js
    // RP 계정(2026-11-10): link:true 면 지금 쿠키 세션 계정의 zkID 칸에 이 PPID 를 붙이고(이미 다른 계정의 PPID 면 409 — r_s 세션도 만들지 않는다),
    // 아니면 PPID 의 계정으로 들어간다(없으면 새로). 어느 쪽이든 쿠키 세션은 그 계정(via zkid).
    const PPIDs = v.PPID.toString();
    let account;
    try {
      if (req.body.link === true) {
        account = req.session?.rpAccount && accountStore.get(req.session.rpAccount) ? req.session.rpAccount : null;
        if (!account) return res.status(401).json({ ok: false, reason: 'no_rp_session' });
        accountStore.link(account, 'zkid', { PPID: PPIDs });
      } else account = accountStore.loginOrCreate('zkid', { PPID: PPIDs }).id;
    } catch (e) { if (e instanceof AccountError) return res.status(e.status).json({ ok: false, reason: e.reason }); throw e; }
    const attr = accountStore.pinAttrCommit(account, tokenName !== undefined && isAttrCommit(tokenName) ? tokenName : null);
    if (req.body.link === true) req.session.via = 'zkid'; else await setRpSession(req, account, 'zkid');
```

  같은 핸들러의 `sessions.set(rsStr, { …` 객체에 `account,` 를 더하고, `logins.push({ …` 와 `fs.appendFileSync(LOGIN_LOG, …` 객체에 `via: 'zkid', account` 를 더하고, 응답 `res.json({ ok: true, …` 에 `account, via: 'zkid',` 를 더한다.

  5f. 장부: `krwLedger` 줄을 지우고, `ledgerView` 와 `freshLedgerBody` 를 계정 번호 기준으로 바꾸고, `/api/mode3/request` 안의 `balance`·`deposit`·`buy` 처리(지금 `if (body === 'balance')` 부터 마지막 `res.json({ ok: true, echo: body, PPID: s.PPID })` 앞까지)를 `ledgerOp` 호출로 바꾼다:

```js
/** 계정의 장부 보기 — KRW·거래소 보관 ETH 는 RP 장부, ETH 는 PPID 계정(있으면)의 실제 체인 잔액. */
async function ledgerView(acctId) {
  const PPID = accountStore.get(acctId)?.zkid?.PPID ?? null;
  const account = PPID ? await accountOf(PPID) : null;
  let wei = null;
  if (account) { try { wei = await provider.getBalance(account); } catch { wei = null; } }
  const custody = accountStore.custody(acctId);
  return { ledger: { KRW: fmtKrw(accountStore.krw(acctId)), ETH: wei === null ? '-' : fmtEth(wei), ETH_CUSTODY: fmtEth(custody) }, account, ethWei: wei === null ? null : wei.toString(), custodyWei: custody.toString(), priceKrw: ETH_PRICE_KRW.toString() };
}
/** 입금·구매·출금 본문의 재전송 방지 — 클라이언트 시각이 ±5분 안이고 같은 (계정, 본문) 을 아직 쓰지 않았을 때만 true. */
function freshLedgerBody(acctId, body, tsMs) {
  if (!Number.isFinite(tsMs) || Math.abs(Date.now() - tsMs) > LEDGER_TS_WINDOW_MS) return false;
  const key = `${acctId}|${body}`;
  if (usedLedgerBodies.has(key)) return false;
  usedLedgerBodies.add(key);
  if (usedLedgerBodies.size > 5000) usedLedgerBodies.delete(usedLedgerBodies.values().next().value);
  return true;
}
/**
 * 장부 요청 하나(2026-11-10) — channel 'signed' 는 zkID r_s 세션의 세션키 서명 요청(/api/mode3/request), 'cookie' 는 쿠키 세션(/api/rp/ledger).
 * 구매: signed 면 RP 릴레이어가 PPID 계정으로 실제 ETH 를 보내고(지금과 같다), cookie 면 거래소 보관 장부에 쌓는다(체인 거래 없음).
 * 출금(cookie 만): 거래소 보관에서 먼저 깎고 릴레이어가 보낸다 — 전송이 실패하면 되돌린다. 결과 { status?, body }.
 */
async function ledgerOp({ account, body, channel, PPID = null }) {
  const bad = (reason, extra = {}) => ({ status: 400, body: { ok: false, reason, ...extra } });
  if (typeof body !== 'string' || body.length > 200) return bad('malformed');
  if (body === 'balance') return { body: { ok: true, echo: body, balance: await ledgerView(account) } };
  const dep = /^deposit:([0-9]{10,16})$/.exec(body);
  if (dep) {
    if (!freshLedgerBody(account, body, Number(dep[1]))) return { status: 409, body: { ok: false, reason: 'request_replayed' } };
    accountStore.addKrw(account, DEMO_DEPOSIT_KRW);
    return { body: { ok: true, echo: body, depositedKrw: DEMO_DEPOSIT_KRW.toString(), balance: await ledgerView(account) } };
  }
  const buy = /^buy:([0-9]+(?:\.[0-9]{1,18})?):([0-9]{10,16})$/.exec(body);
  if (buy) {
    const wei = parseEth(buy[1]);
    if (wei === null || wei <= 0n) return bad('bad_amount');
    const cost = (wei * ETH_PRICE_KRW + 10n ** 18n - 1n) / 10n ** 18n;   // KRW 올림
    const have = accountStore.krw(account);
    if (have < cost) return bad('insufficient_krw', { detail: { needKrw: fmtKrw(cost), haveKrw: fmtKrw(have) } });
    if (!freshLedgerBody(account, body, Number(buy[2]))) return { status: 409, body: { ok: false, reason: 'request_replayed' } };
    let txHash = null;
    if (channel === 'signed') {
      if (!reg.factoryAddress) return { status: 503, body: { ok: false, reason: 'relay_inactive', detail: 'no_factory' } };
      const target = await accountOf(PPID);
      let tx, rc;
      try { tx = await (await provider.getSigner(RELAYER_INDEX)).sendTransaction({ to: target, value: wei }); rc = await tx.wait(); }
      catch (e) { return { status: 502, body: { ok: false, reason: 'buy_transfer_failed', detail: e.shortMessage ?? e.message } }; }
      txHash = tx.hash;
      relayedTxs.push({ at: new Date().toISOString(), txHash, account: target, PPID, kind: 'buy', target, value: wei.toString(), deployTxHash: null, status: rc?.status === 1 ? 'success' : 'failed', blockNumber: rc?.blockNumber ?? null });
    } else accountStore.addCustody(account, wei);
    accountStore.addKrw(account, -cost);
    return { body: { ok: true, echo: body, txHash, boughtWei: wei.toString(), costKrw: fmtKrw(cost), balance: await ledgerView(account) } };
  }
  const wd = /^withdraw:([^:]+):([0-9]{1,30}):([0-9]{10,16})$/.exec(body);
  if (wd) {
    if (channel !== 'cookie') return bad('malformed', { detail: '거래소 보관 출금은 /api/rp/ledger 로' });
    if (!/^0x[0-9a-fA-F]{40}$/.test(wd[1])) return bad('bad_address');
    const wei = BigInt(wd[2]);
    if (wei <= 0n) return bad('bad_amount');
    if (accountStore.custody(account) < wei) return bad('insufficient_custody');
    if (!freshLedgerBody(account, body, Number(wd[3]))) return { status: 409, body: { ok: false, reason: 'request_replayed' } };
    accountStore.addCustody(account, -wei);   // 먼저 깎는다 — 동시에 두 번 눌러도 잔고보다 많이 나가지 않게
    let tx, rc;
    try { tx = await (await provider.getSigner(RELAYER_INDEX)).sendTransaction({ to: wd[1], value: wei }); rc = await tx.wait(); }
    catch (e) { accountStore.addCustody(account, wei); return { status: 502, body: { ok: false, reason: 'withdraw_failed', detail: e.shortMessage ?? e.message } }; }
    relayedTxs.push({ at: new Date().toISOString(), txHash: tx.hash, account: null, PPID: null, kind: 'custody_withdraw', target: wd[1], value: wei.toString(), deployTxHash: null, status: rc?.status === 1 ? 'success' : 'failed', blockNumber: rc?.blockNumber ?? null });
    return { body: { ok: true, echo: body, txHash: tx.hash, balance: await ledgerView(account) } };
  }
  return { body: { ok: true, echo: body } };
}
```

  `/api/mode3/request` 안에서 서명 확인 뒤(`requestCount++;` 다음) 장부 분기 전체를 다음 세 줄로 바꾼다(기존 응답에 실리던 `PPID` 는 유지):

```js
    const acctId = s.account ?? accountStore.loginOrCreate('zkid', { PPID: s.PPID }).id;   // 2026-11-10 전에 만든 세션(account 없음)도 받는다
    const r = await ledgerOp({ account: acctId, body, channel: 'signed', PPID: s.PPID });
    return res.status(r.status ?? 200).json({ ...r.body, PPID: s.PPID });
```

  (기존 `buy` 의 `relayedTxs.push` 의 `blockNumber` 자리 값은 원래 코드의 것을 그대로 옮긴다 — 위 코드의 `rc?.blockNumber ?? null` 과 원래가 다르면 원래를 따른다.)

  5g. 앱 라우트 정의부(예: `/api/mode3/rp_info` 바로 위)에 소셜 라우트를 붙인다:

```js
// RP 소셜 로그인·계정 연결(2026-11-10) — lib/mode3_rp_social.js. 로그인 기록에 수단(via)을 남긴다.
mountRpSocial(app, { store: accountStore, cfg: SOCIAL, ledgerOp, onLogin: ({ account, via }) => {
  const at = new Date().toISOString();
  logins.push({ PPID: '', at, root: '', r_s: '', allowAgent: '0', disclosure: null, via, account });
  fs.appendFileSync(LOGIN_LOG, JSON.stringify({ at, via, account }) + '\n', { mode: 0o600 });
} });
if (SOCIAL.google.enabled || SOCIAL.naver.enabled) console.log(`[rp] 소셜 로그인: Google ${SOCIAL.google.enabled ? '켜짐' : '꺼짐'} · 네이버 ${SOCIAL.naver.enabled ? `켜짐(콜백 ${SOCIAL.naver.redirectUri})` : '꺼짐'}`);
```

  `readLoginLog()` 로 되살리는 `logins` 매핑(415행 근처)에 `via: l.via ?? 'zkid', account: l.account ?? null` 을 더하고, `PPID: String(l.PPID ?? '')`, `root: String(l.root ?? '')` 로 소셜 줄(PPID·root 없음)도 받게 한다. 개봉(`lastTranscriptOf`)이 로그 줄을 읽는 곳은 `l.r_s` 가 있는 줄만 보도록 `if (!l.r_s) continue;` 를 넣는다(소셜 줄에는 트랜스크립트가 없다).

- [ ] **Step 6: 통과 확인** — Run: `node tests/test_rp_social_logins.mjs` → Expected: 모두 `ok`. 이어서 기존 회귀: `node tests/test_mode3_demo_stack.mjs`(장부 응답 `balance.ledger.KRW`·`ETH` 키 유지, 입금 재생 409 유지) → 통과. 실패하면 기대값을 바꾸지 말고 구현을 고친다. 단 `balance.ledger` 에 `ETH_CUSTODY` 가 늘어 `deepEqual` 로 비교하는 곳이 있으면 그 기대값에 `ETH_CUSTODY: '0'` 을 더한다.

- [ ] **Step 7: 테스트 등록** — `scripts/run_tests.sh` chain 그룹에 `tests/test_rp_social_logins.mjs` 추가(`tests/test_cia_linked_logins.mjs` 줄 아래).

- [ ] **Step 8: 커밋**

```bash
git add lib/mode3_rp_social.js mode3_rp.js tests/helpers/isolated_mode3_stack.mjs tests/test_rp_social_logins.mjs scripts/run_tests.sh
git commit -m "feat(rp): RP 가 Google·네이버 로그인을 직접 — 쿠키 세션(RP 마다 이름), RP 계정에 수단 연결·해제, zkID 로그인 link:true, 거래소 보관 구매·출금; 격리 스택의 RP 계정 파일 누수 수정" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -m "Claude-Session: https://claude.ai/code/session_013qGSXZTftBJSB1M4XpPRHN"
```

---

### Task 3: RP 화면 — 소셜 버튼·내 계정·거래소 보관

**Files:**
- Modify: `mode3/rp.html`, `mode3/rp_admin.html`, `mode3/common/strings.js`, `mode3/common/rp.css`
- Test: `tests/test_mode3_wallet_snap_oidc_browser.mjs`

**Interfaces:**
- Consumes (Task 2): `rp_info.social`, `/api/rp/*`, `/api/mode3/login` 의 `link`·`account`·`via`, 장부 `ETH_CUSTODY`.
- Produces: 요소 id — `#loginGsiSlot`(모달 안 GIS 자리), `#navAccount`(메뉴 탭), `#account`(내 계정 절), 수단 줄 `#mState_zkid|google|naver`, 버튼 `#mLink_zkid|google|naver`·`#mUnlink_zkid|google|naver`, `#linkGsiSlot`, `#accountVerdict`, `#viaBadge`, 잔고 `li[data-asset="ETH_CUSTODY"]`, 출금 출처 `#txSource`(`account`|`custody`).

- [ ] **Step 1: 실패하는 브라우저 케이스로 교체** — `tests/test_mode3_wallet_snap_oidc_browser.mjs` 에서 11-09 의 RP 버튼 케이스 둘(`zkONE "Google 계정으로 로그인" + 미등록 지갑…`, `zkONE "네이버로 로그인" + 등록된 아이디 지갑…`)을 지우고, 스택 옵션에 RP 소셜 env(Task 2 테스트의 `socialEnv` 와 같은 모양 — 이 파일의 기존 Google 스텁 `stub` 과 네이버 스텁 `naverStub` 을 RP 쪽 클라이언트로 하나 더 띄워 쓴다: `startOidcIssuerStub({ clientId: 'rp-google-client', provider: 'google' })`, `startOidcIssuerStub({ clientId: 'rp-naver-client', provider: 'naver', clientSecret: 'rp-naver-secret' })`)와 `walletHost: 'localhost'` 를 유지한 채, RP 를 `http://localhost:<port>` 로 연다(GIS 는 localhost 원본에서만 그려진다 — 스택이 RP 를 127.0.0.1 로 띄우면 페이지 주소만 `localhost` 로 바꿔 연다). 새 케이스:

```js
  await t('RP 소셜(2026-11-10): 로그인 창 Google(GIS 흉내) → 새 RP 계정·via google 배지 → 내 계정에서 네이버 연결 → 자산에 거래소 보관 ETH·출금 출처; 로그아웃하면 /api/rp/me 401', async () => {
    const rpUi = rp.base.replace('127.0.0.1', 'localhost');
    const page = await context.newPage(); await page.goto(`${rpUi}/`);
    await page.click('#loginBtn'); await page.click('#googleLoginBtn');
    await page.waitForSelector('#loginGsiSlot .gsi-stub', { timeout: 30_000 });
    await page.evaluate(() => { window.__gsiSub = 'rp-g-user'; });
    await page.click('#loginGsiSlot .gsi-stub');
    await page.waitForSelector('#assetsLoggedIn:not([hidden])', { timeout: 30_000 });
    assert.match(await text(page, '#viaBadge'), /Google/);
    await page.click('#navAccount'); await page.waitForSelector('#account:not([hidden])');
    assert.match(await text(page, '#mState_google'), /연결됨/); assert.match(await text(page, '#mState_naver'), /연결 안 됨/);
    assert.equal(await page.isVisible('#mUnlink_google'), true);
    rpNaver.setNextSub('rp-n-user');
    await page.click('#mLink_naver');                                   // 네이버 흉내를 다녀와 /?linked=naver#account 로 돌아온다
    await page.waitForURL((u) => u.hash === '#account', { timeout: 30_000 });
    await waitText(page, '#accountVerdict', '네이버');
    assert.match(await text(page, '#mState_naver'), /연결됨/);
    assert.equal(await page.$eval('li[data-asset="ETH_CUSTODY"]', (el) => !el.hidden), true);
    assert.equal(await page.$eval('#txSource option[value="account"]', (o) => o.disabled), true, 'zkID 세션이 아니면 내 계정 출금 불가');
    await page.click('#logoutBtn'); await page.waitForSelector('#assetsLoggedOut:not([hidden])');
    assert.equal(await page.evaluate(() => fetch('/api/rp/me').then((r) => r.status)), 401);
    await page.close();
  });
```

  (`text`·`waitText` 는 이 파일에 이미 있는 도우미를 쓴다. 없으면 `test_mode3_browser.mjs` 의 같은 이름 도우미를 그대로 옮긴다. GIS 흉내(`.gsi-stub`, `window.__gsiSub`)는 이 파일의 기존 스텁을 RP 페이지에도 쓰도록 같은 `context` 에 걸린 것을 그대로 쓰되, 스텁이 `/mint` 를 부를 발급자를 페이지별로 고를 수 있어야 하면 RP 페이지에서는 `window.__gsiMintBase = <rp 용 Google 스텁 base>` 를 먼저 넣는 방식으로 스텁을 넓힌다.)

- [ ] **Step 2: 실패 확인** — 임시 hardhat 이 떠 있는 상태에서 Run: `node tests/test_mode3_wallet_snap_oidc_browser.mjs` → Expected: 새 케이스 FAIL(`#loginGsiSlot` 없음).

- [ ] **Step 3: HTML** — `mode3/rp.html`

  3a. `<head>` 의 공통 스크립트 뒤에 `<script src="/common/gsi.js"></script>   <!-- 2026-11-10: RP 의 Google 로그인·연결 -->`.

  3b. 메뉴: `.nav-menu` 안 `#assets` 링크 뒤에 `<a href="#account" class="nav-link" id="navAccount" hidden data-i18n="nav_account">내 계정</a>`. 계정 pill(`#accountPill`) 안 `<code id="accountAddr">` 앞에 `<span id="viaBadge" class="badge muted"></span>`.

  3c. 로그인 모달: `#googleLoginBtn` 바로 뒤에 `<div id="loginGsiSlot" class="gsi-slot" hidden></div>`. 모달의 `#loginModalNote` 는 그대로(설정이 없을 때 안내).

  3d. 잔고 목록: `<li data-asset="ETH">` 의 라벨을 `<span class="bal-label" data-i18n="rp_eth_account">ETH (내 계정)</span>` 로, 그 뒤에 `<li data-asset="ETH_CUSTODY"><span class="bal-label" data-i18n="rp_eth_custody">ETH (거래소 보관)</span><strong class="bal-amt">0</strong></li>`.

  3e. 온체인 출금 박스(`#onchain`)의 받는 주소 label 앞에:

```html
          <label class="withdraw-amount"><span data-i18n="rp_tx_source_label">출금 출처</span>
            <select id="txSource"><option value="account" data-i18n="rp_tx_source_account">내 계정(PPID — zkID 로그인 필요)</option><option value="custody" data-i18n="rp_tx_source_custody">거래소 보관</option></select></label>
```

  3f. `</aside>`(#assets 끝) 뒤, `#compliance` 절 앞에 내 계정 절:

```html
    <!-- 2026-11-10(스펙 rp-social-logins §4): 이 RP 계정의 로그인 수단 세 칸 — RP 마다 따로다(zkONE 의 연결은 zkTWO 와 무관). -->
    <section id="account" class="card account-panel" hidden>
      <h2 data-i18n="rp_account_title">내 계정</h2>
      <p class="desc" data-i18n="rp_account_desc">이 서비스 계정에 로그인 수단을 연결합니다. 연결한 어느 수단으로 로그인해도 같은 계정·같은 잔고입니다. 다른 서비스와는 따로입니다.</p>
      <dl class="kv method-list">
        <dt>zkID</dt><dd><span id="mState_zkid">-</span> <button type="button" id="mLink_zkid" class="btn-ghost" data-i18n="rp_link_btn">연결</button> <button type="button" id="mUnlink_zkid" class="btn-ghost" data-i18n="rp_unlink_btn">해제</button></dd>
        <dt>Google</dt><dd><span id="mState_google">-</span> <button type="button" id="mLink_google" class="btn-ghost" data-i18n="rp_link_btn">연결</button> <button type="button" id="mUnlink_google" class="btn-ghost" data-i18n="rp_unlink_btn">해제</button><div id="linkGsiSlot" class="gsi-slot" hidden></div></dd>
        <dt data-i18n="rp_naver_name">네이버</dt><dd><span id="mState_naver">-</span> <button type="button" id="mLink_naver" class="btn-ghost" data-i18n="rp_link_btn">연결</button> <button type="button" id="mUnlink_naver" class="btn-ghost" data-i18n="rp_unlink_btn">해제</button></dd>
      </dl>
      <div id="accountVerdict"></div>
    </section>
```

- [ ] **Step 4: 스크립트** — `mode3/rp.html`

  4a. 상태 변수(`let lastAttrCommit` 아래): `let rpMe = null;   // 2026-11-10: 쿠키 세션의 계정(/api/rp/me) — 소셜·zkID 로그인 모두. null 이면 쿠키 세션 없음`. 그리고 로그인 판정 함수 `const loggedIn = () => !!currentSession || !!rpMe;`.

  4b. `renderTitle`·`renderAccountView` 의 `currentSession` 로그인 판정을 `loggedIn()` 으로 바꾸고, `renderAccountView` 끝에 추가:

```js
      $('navAccount').hidden = !loggedIn();
      const via = rpMe?.via ?? (currentSession ? 'zkid' : null);
      $('viaBadge').textContent = via ? (tt(`rp_via_${via}`) || via) : ''; $('viaBadge').hidden = !via;
      // 내 자산의 PPID 계정 줄·출금 출처: PPID 가 없는 계정(소셜로만 가입)은 "내 계정" 잔액이 없고, zkID 세션이 아니면 PPID 계정에서 내보낼 수 없다(R5).
      $('txSource').querySelector('option[value="account"]').disabled = !currentSession;
      if (!currentSession) $('txSource').value = 'custody';
      renderMethods();
```

  `for (const a of document.querySelectorAll('.nav-link[href="#assets"], …'))` 의 `if (currentSession) return;` 를 `if (loggedIn()) return;` 로.

  4c. 쿠키 세션 읽기·수단 줄 그리기:

```js
    /** 쿠키 세션(2026-11-10) — /api/rp/me. 401 이면 null. 바뀌면 화면을 다시 그리고 잔액을 읽는다. */
    async function refreshMe() {
      let me = null;
      try { const r = await fetch('/api/rp/me'); if (r.ok) me = await r.json(); } catch { me = null; }
      const changed = (me?.account ?? null) !== (rpMe?.account ?? null);
      rpMe = me;
      if (me?.attrCommit) lastAttrCommit = me.attrCommit;
      if (me?.methods?.zkid?.PPID && !lastPPID) lastPPID = me.methods.zkid.PPID;
      renderAccountView(); renderGuide();
      if (changed && me) refreshLedger();
      return me;
    }
    const fmtDay = (iso) => String(iso ?? '').slice(0, 10);
    function renderMethods() {
      for (const m of ['zkid', 'google', 'naver']) {
        const s = rpMe?.methods?.[m] ?? null;
        const on = m === 'zkid' ? true : !!info?.social?.[m]?.enabled;
        $(`mState_${m}`).textContent = s ? (tt('rp_method_linked', { date: fmtDay(s.linkedAt) }) || `연결됨 · ${fmtDay(s.linkedAt)}`) : on ? (tt('rp_method_none') || '연결 안 됨') : (tt('rp_method_disabled') || '이 서비스에 설정되지 않음');
        $(`mLink_${m}`).hidden = !rpMe || !!s || !on;
        $(`mUnlink_${m}`).hidden = !rpMe || !s;
      }
    }
```

  4d. 소셜 로그인·연결(GIS·네이버). 기존 `$('googleLoginBtn')`·`$('naverLoginBtn')` 핸들러(지금 `startIdpLogin({ provider })` 를 부르는 것)를 지우고:

```js
    /** GIS 버튼을 slot 에 그리고, 토큰을 받으면 /api/rp/google 로. purpose 'login' | 'link'. */
    async function renderGoogle(slot, purpose, verdictEl) {
      const g = info?.social?.google;
      if (!g?.enabled) { setVerdict(verdictEl, false, 'social_failed', { reason: 'provider_disabled' }); return; }
      if (!Mode3Gsi.originOk()) { setVerdict(verdictEl, false, 'social_failed', { reason: 'origin_not_localhost', summary: tt('rp_google_localhost_only') || 'Google 로그인은 http://localhost 주소에서만 됩니다' }); return; }
      const n = await (await post('/api/rp/oidc/nonce', { purpose })).json();
      if (!n.ok) { setVerdict(verdictEl, false, 'social_failed', { reason: n.reason }); return; }
      slot.hidden = false;
      try {
        await Mode3Gsi.load();
        Mode3Gsi.render({ el: slot, clientId: g.clientId, nonce: n.nonce, onToken: async (id_token) => {
          const rb = await (await post('/api/rp/google', { id_token, purpose })).json();
          slot.hidden = true;
          if (!rb.ok) { setVerdict(verdictEl, false, 'social_failed', { reason: rb.reason, detail: rb }); return; }
          if (purpose === 'login') { closeLoginModal(); setVerdict($('verdict'), true, 'social_login_ok', () => ({ summary: tt(rb.created ? 'rp_social_new_account' : 'rp_social_same_account', { via: 'Google' }) })); }
          else setVerdict(verdictEl, true, 'social_link_ok', () => ({ summary: tt('rp_social_linked', { via: 'Google' }) }));
          await refreshMe();
        } });
      } catch (e) { slot.hidden = true; setVerdict(verdictEl, false, 'social_failed', { reason: 'gsi_unavailable', detail: e.message }); }
    }
    $('googleLoginBtn').addEventListener('click', async () => { if (!info) await loadInfo(); renderGoogle($('loginGsiSlot'), 'login', $('verdict')); });
    $('naverLoginBtn').addEventListener('click', async () => {
      if (!info) await loadInfo();
      if (!info?.social?.naver?.enabled) { setVerdict($('verdict'), false, 'social_failed', { reason: 'provider_disabled' }); return; }
      location.assign('/api/rp/naver/start?purpose=login');
    });
    $('mLink_google').addEventListener('click', () => renderGoogle($('linkGsiSlot'), 'link', $('accountVerdict')));
    $('mLink_naver').addEventListener('click', () => location.assign('/api/rp/naver/start?purpose=link'));
    $('mLink_zkid').addEventListener('click', () => startIdpLogin({ link: true }));
    for (const m of ['zkid', 'google', 'naver']) $(`mUnlink_${m}`).addEventListener('click', async () => {
      const rb = await (await post('/api/rp/unlink', { method: m })).json();
      setVerdict($('accountVerdict'), !!rb.ok, rb.ok ? 'social_unlink_ok' : 'social_failed', rb.ok ? {} : { reason: rb.reason });
      await refreshMe();
    });
```

  4e. `startIdpLogin(opts)`: `authorizeRequest({ … provider: opts.provider ?? null })` 의 `provider` 인자를 지우고(소셜은 지갑을 거치지 않는다), `/api/mode3/login` 본문에 `...(opts.link ? { link: true } : {})` 를 더한다. 성공(`rb.ok`)이면 `setSession(...)` 뒤에 `await refreshMe();`, `opts.link` 면 결과를 `#accountVerdict` 에도 `setVerdict($('accountVerdict'), rb.ok, rb.ok ? 'social_link_ok' : 'social_failed', rb.ok ? () => ({ summary: tt('rp_social_linked', { via: 'zkID' }) }) : { reason: rb.reason })`.

  4f. 장부: `sessionRequest` 를 감싸는 `ledgerRequest(body, opts)` — `currentSession` 이 있으면 `sessionRequest(body, opts)`, 없고 `rpMe` 면 쿠키로:

```js
    async function ledgerRequest(body, opts = {}) {
      if (currentSession) return sessionRequest(body, opts);
      const vEl = opts.verdictEl ?? $('ledgerVerdict');
      if (!rpMe) { if (!opts.quiet) setVerdict(vEl, false, 'request_failed', { reason: 'no_session' }); return null; }
      if (!opts.quiet) pendingVerdict(vEl, 'working');
      const rb = await (await post('/api/rp/ledger', { body })).json().catch(() => ({ ok: false, reason: 'internal' }));
      if (!rb.ok) { if (!opts.quiet) setVerdict(vEl, false, 'request_failed', { reason: rb.reason ?? 'internal', detail: rb }); return null; }
      if (rb.balance) applyLedger(rb.balance);
      if (!opts.quiet) setVerdict(vEl, true, opts.okTitle ?? 'request_ok', () => ({ summary: opts.okSummary ? opts.okSummary(rb) : undefined, detail: rb }));
      return rb;
    }
```

  `balanceBtn`·`depositBtn`·`buyBtn` 핸들러와 `refreshLedger` 의 `sessionRequest(` 를 `ledgerRequest(` 로 바꾸고, `refreshLedger` 의 `if (!info || !currentSession) return null;` 를 `if (!info || !loggedIn()) return null;` 로, `WEB()` 이면서 `currentSession` 일 때만 자동 조회를 건너뛰게 `if (WEB() && currentSession) return null;` 로 바꾼다.

  4g. 출금: `txBtn` 핸들러 맨 앞(`tourBusy` 검사 뒤)에 거래소 보관 분기:

```js
      if ($('txSource').value === 'custody') {
        const to = $('txTo').value.trim(), value = ethToWei($('txValue').value.trim() || '0');
        if (value === null) { setVerdict($('txVerdict'), false, 'tx_failed', { reason: 'bad_amount' }); return; }
        const rb = await ledgerRequestCookie(`withdraw:${to}:${value}:${Date.now()}`);
        if (!rb?.ok) { setVerdict($('txVerdict'), false, 'tx_failed', { reason: rb?.reason ?? 'internal', detail: rb }); return; }
        setVerdict($('txVerdict'), true, 'tx_ok', () => ({ summary: tt('rp_custody_withdraw_ok', { eth: $('txValue').value.trim() }) || `거래소 보관에서 ${$('txValue').value.trim()} ETH 를 보냈습니다.`, detail: rb }));
        lastTxHash = rb.txHash; $('txHashCode').textContent = `${String(rb.txHash).slice(0, 18)}…`; $('txHashCode').title = rb.txHash; $('txHashRow').hidden = false;
        if (rb.balance) applyLedger(rb.balance);
        return;
      }
```

  와 도우미 `const ledgerRequestCookie = async (body) => (await post('/api/rp/ledger', { body })).json().catch(() => null);`(거래소 보관 출금은 zkID 세션이어도 쿠키 세션으로 — zkID 로그인도 쿠키 세션을 만든다). 기존 `if (!currentSession) { … no_session }` 는 그 아래(내 계정 출금 경로)에 그대로 둔다.

  4h. 로그아웃: `logoutBtn` 핸들러에서 `setSession(null)` 뒤 `rpMe = null; try { await post('/api/rp/logout', {}); } catch { /* 화면은 이미 비웠다 */ }` 를 더하고 `renderAccountView()`.

  4i. 첫 로드: 맨 끝의 `loadInfo(); restoreSession();` 를 다음으로:

```js
    // 2026-11-10: 네이버에서 돌아온 길(?social=ok|social_error=…|linked=naver) — 결과를 보이고 주소를 정리한다.
    const q0 = new URLSearchParams(location.search);
    const socialBack = { ok: q0.get('social'), err: q0.get('social_error'), linked: q0.get('linked') };
    if (socialBack.ok || socialBack.err || socialBack.linked) history.replaceState(null, '', location.pathname + location.hash);
    loadInfo().then(() => { renderMethods(); if (location.hash === '#account') { $('account').hidden = false; $('account').scrollIntoView(); } });
    restoreSession();
    refreshMe().then(() => {
      if (socialBack.ok) setVerdict($('verdict'), true, 'social_login_ok', () => ({ summary: tt('rp_social_logged_in', { via: tt('rp_naver_name') || '네이버' }) }));
      else if (socialBack.linked) setVerdict($('accountVerdict'), true, 'social_link_ok', () => ({ summary: tt('rp_social_linked', { via: tt('rp_naver_name') || '네이버' }) || '네이버 계정을 연결했습니다' }));
      else if (socialBack.err) setVerdict(location.hash === '#account' ? $('accountVerdict') : $('verdict'), false, 'social_failed', { reason: socialBack.err });
    });
```

  `#account` 절 표시: `renderAccountView` 에서 `$('account').hidden = !loggedIn();`. 메뉴 `#navAccount` 클릭은 기본 앵커 이동이면 충분하다.

  4j. `renderGuide` 의 `login: !!currentSession` 판정과 `current` 계산에서 `currentSession` 을 `loggedIn()` 으로(소셜 로그인도 "로그인 단계 완료"). 세션 생존 확인(`checkSessionAlive`)은 r_s 전용 그대로.

- [ ] **Step 5: 문구·스타일** — `mode3/common/strings.js` 의 `ui` 에 추가(ko·en 둘 다):

```js
    // RP 소셜 로그인·내 계정(2026-11-10)
    nav_account: { ko: '내 계정', en: 'My account' },
    rp_account_title: { ko: '내 계정', en: 'My account' },
    rp_account_desc: { ko: '이 서비스 계정에 로그인 수단을 연결합니다. 연결한 어느 수단으로 로그인해도 같은 계정·같은 잔고입니다. 다른 서비스와는 따로입니다.', en: 'Link sign-in methods to this service account. Any linked method signs you into the same account and balances. Other services are separate.' },
    rp_link_btn: { ko: '연결', en: 'Link' }, rp_unlink_btn: { ko: '해제', en: 'Unlink' },
    rp_naver_name: { ko: '네이버', en: 'Naver' },
    rp_method_linked: { ko: '연결됨 · {date}', en: 'Linked · {date}' },
    rp_method_none: { ko: '연결 안 됨', en: 'Not linked' },
    rp_method_disabled: { ko: '이 서비스에 설정되지 않음', en: 'Not set up for this service' },
    rp_via_zkid: { ko: 'zkID', en: 'zkID' }, rp_via_google: { ko: 'Google', en: 'Google' }, rp_via_naver: { ko: '네이버', en: 'Naver' },
    rp_eth_account: { ko: 'ETH (내 계정)', en: 'ETH (my account)' },
    rp_eth_custody: { ko: 'ETH (거래소 보관)', en: 'ETH (held by exchange)' },
    rp_tx_source_label: { ko: '출금 출처', en: 'Withdraw from' },
    rp_tx_source_account: { ko: '내 계정(PPID — zkID 로그인 필요)', en: 'My account (PPID — needs zkID login)' },
    rp_tx_source_custody: { ko: '거래소 보관', en: 'Held by exchange' },
    rp_custody_withdraw_ok: { ko: '거래소 보관에서 {eth} ETH 를 보냈습니다.', en: 'Sent {eth} ETH from the exchange-held balance.' },
    rp_social_new_account: { ko: '{via} 로 새 계정을 만들어 로그인했습니다.', en: 'Created a new account with {via} and signed in.' },
    rp_social_same_account: { ko: '{via} 로 로그인했습니다.', en: 'Signed in with {via}.' },
    rp_social_logged_in: { ko: '{via} 로 로그인했습니다.', en: 'Signed in with {via}.' },
    rp_social_linked: { ko: '{via} 계정을 연결했습니다.', en: 'Linked your {via} account.' },
    rp_google_localhost_only: { ko: 'Google 로그인은 http://localhost 주소에서만 됩니다.', en: 'Google sign-in works only on http://localhost.' },
```

  `verdicts` 에 `social_login_ok: { ko: '로그인 성공', en: 'Signed in' }`, `social_link_ok: { ko: '연결 완료', en: 'Linked' }`, `social_unlink_ok: { ko: '해제 완료', en: 'Unlinked' }`, `social_failed: { ko: '로그인 수단 처리 실패', en: 'Sign-in method failed' }`.
  `reasons` 에(없는 것만) `no_rp_session`, `bad_purpose`, `bad_nonce`, `method_linked_elsewhere`(다른 계정에 이미 연결된 수단), `method_already_linked`, `not_linked`, `last_method`(마지막 로그인 수단은 해제할 수 없음), `insufficient_custody`, `bad_address`, `withdraw_failed`, `json_only`, `origin_not_localhost`, `gsi_unavailable` — 각각 이 파일 `reasons` 의 기존 항목과 같은 모양(`{ ko: { title, cause, action }, en: {…} }` — 기존 항목 하나를 열어 모양을 그대로 따른다).
  `mode3/common/rp.css` 끝에: `.account-panel .method-list dd { display:flex; flex-wrap:wrap; gap:6px 10px; align-items:center } .gsi-slot { margin-top:8px }`.

- [ ] **Step 6: RP 관리자 페이지** — `mode3/rp_admin.html` 로그인 기록 표에 "수단" 열: 머리 `<th data-i18n="rp_col_via">수단</th>`, 행 `td.textContent = tt(\`rp_via_${l.via ?? 'zkid'}\`) || l.via`. `strings.js` 에 `rp_col_via: { ko: '수단', en: 'Method' }`. `/api/mode3/logins` 응답의 각 항목은 Task 2 에서 `via` 를 싣는다(`logins` 배열 항목).

- [ ] **Step 7: 통과 확인** — Run: `node tests/test_mode3_wallet_snap_oidc_browser.mjs`, `node tests/test_mode3_browser.mjs` → 모두 통과(기존 zkID 로그인·잔액·출금 케이스 회귀 없음).

- [ ] **Step 8: 커밋**

```bash
git add mode3/rp.html mode3/rp_admin.html mode3/common/strings.js mode3/common/rp.css tests/test_mode3_wallet_snap_oidc_browser.mjs
git commit -m "feat(rp): RP 화면 — 로그인 창 Google(GIS)·네이버 직접, 내 계정 패널(수단 연결·해제), 거래소 보관 잔고·출금 출처, 관리자 로그인 기록에 수단" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -m "Claude-Session: https://claude.ai/code/session_013qGSXZTftBJSB1M4XpPRHN"
```

---

### Task 4: zkID 쪽 연결 제거 (45f3602 되돌리기)

**Files:**
- Modify: `cia.js`, `lib/mode3_cia_state.js`, `lib/mode3_oidc_link.js`, `mode3/cia_login.html`, `mode3/cia_user.html`, `mode3/wallet.html`, `mode3/user/popup.js`, `mode3/common/strings.js`
- Delete: `tests/test_cia_linked_logins.mjs`
- Modify tests: `tests/test_mode3_oidc_link.mjs`, `tests/test_cia_oidc_register.mjs`, `tests/test_mode3_cia_state.mjs`, `tests/test_mode3_wallet_snap_oidc_browser.mjs`, `tests/helpers/isolated_cia.mjs`, `tests/helpers/isolated_mode3_stack.mjs`, `scripts/run_tests.sh`

**Interfaces:**
- Consumes (Task 2): RP 가 `lib/mode3_oidc_link.js` 의 `NAVER_DEFAULTS`·`createOnceStore`·`pkcePair`·`naverAuthorizeUrl`·`exchangeNaverCode`·`randomHex` 를 쓴다 — 이것들은 남긴다.
- Produces: IdP `public_keys.oidc` 는 45f3602 이전 모양 `{ enabled, provider, clientId, issuer }`(providers 없음). `/cia/user/me` 에 `linked` 없음. `/cia/auth/code` 는 아이디·비밀번호만.

참조: 지울 것은 `git diff 81c1893 45f3602 -- <파일>` 에 보이는 추가분이다. 아래 "유지" 항목만 남긴다.

- [ ] **Step 1: 테스트부터 정리(실패하게)**
  - `git rm tests/test_cia_linked_logins.mjs`, `scripts/run_tests.sh` 에서 그 줄을 지운다.
  - `tests/test_mode3_oidc_link.mjs`: `LINK_SLOTS`·`sanitizeAuthCtx`·`LINK_PREFIX`·`AUTH_PREFIX` 케이스를 지운다(나머지 — once 저장소·PKCE·인가 URL·코드 교환 — 는 RP 가 쓰므로 남긴다).
  - `tests/test_cia_oidc_register.mjs`: `public_keys.oidc` 기대값에서 `providers` 를 지우고 `assert.equal('providers' in pk.oidc, false)` 를 더한다. "아이디 계정 + Google 토큰 → 400 use_auth_window" 는 유지.
  - `tests/test_mode3_cia_state.mjs`: `linkedOidc → linked.google` 이전·중복 제거 케이스를 "옛 `linked`·`linkedOidc` 는 기동 때 지워지고 노트가 남는다" 로 바꾼다:

```js
await t('2026-11-10: 계정의 linked·linkedOidc(11-09 zkID 쪽 연결)는 열 때 지운다', () => {
  const raw = validV(/* 이 파일의 기존 최신 버전 상태 생성 도우미를 쓴다 */);
  raw.accounts['1'].linked = { google: { sub: 'g', linkedAt: 'x' } }; raw.accounts['1'].linkedOidc = { provider: 'google', sub: 'g' };
  const { state, notes } = migrateCiaState(raw);   // 이 파일이 이미 쓰는 이전 함수 이름을 그대로 쓴다
  assert.equal('linked' in state.accounts['1'], false); assert.equal('linkedOidc' in state.accounts['1'], false);
  assert.ok(notes.some((n) => /linked/.test(n)));
});
```

    (`validV`·`migrateCiaState` 자리에는 이 테스트 파일이 지금 쓰는 실제 도우미·함수 이름을 넣는다 — 새 이름을 만들지 않는다.)
  - `tests/test_mode3_wallet_snap_oidc_browser.mjs`: `/user` 연결 케이스(`/user 에서 Google·네이버 연결…`)를 지운다. 스택 옵션의 IdP 쪽 `naver` 는 지운다(RP 쪽 스텁은 Task 3 것 유지). `ciaHost: 'localhost'` 는 IdP 의 Google 래퍼(`/account`) 케이스가 쓰면 유지, 아니면 지운다.
  - Run: `node tests/test_mode3_cia_state.mjs` → 새 케이스 FAIL.

- [ ] **Step 2: IdP 서버(`cia.js`)**
  - 지운다: 50행 import 를 `import { … } from './lib/mode3_oidc_link.js'` 째로; 101–146행(`NAVER_CLIENT_ID` 부터 `loginBack` 까지 — `NAVER`·`LINK_CFG`·`linkOnce`·`authOnce`·`onceFor`·`uidLinkedTo`·`linkAccount`·`verifyLinkToken`·`linkedView`·`loginBack`); 라우트 `/cia/oidc/nonce`·`/cia/user/link`·`/cia/user/unlink`·`/cia/oidc/naver/start`·`/cia/oidc/naver/callback`; `public_keys.oidc` 의 `providers` 줄(638); `/cia/user/me` 응답의 `linked: linkedView(a),`; 래퍼 등록 두 곳의 `if (uidLinkedTo('google', o.sub)) return res.status(409)…oidc_linked_elsewhere` 줄(1164·1271).
  - `/cia/auth/code`: `method` 처리를 45f3602 이전(`git show 81c1893:cia.js` 의 같은 라우트)으로 되돌린다 — 아이디·비밀번호만. 단 nonce·코드를 "코드를 내기 직전에만 소비"하는 순서와 `async` 는 지금 것을 유지해도 된다. 본문에 `method` 가 `password` 가 아닌 값으로 오면 400 `bad_method`.
  - **유지**: 아이디 계정이 `/cia/issue` 에 `id_token` 을 내면 400 `use_auth_window`(1261), `unlink_wallet` 이 연결을 건드리지 않는 것(이제 연결이 없다 — 관련 줄이 남아 있으면 지운다).
  - Run: `node --check cia.js`.

- [ ] **Step 3: IdP 상태(`lib/mode3_cia_state.js`)** — 45f3602 의 `linkedOidc → linked.google` 이전·`linked` 검증·`(slot|sub)` 중복 제거를 지우고, 대신 계정마다:

```js
    // 2026-11-10: 11-09 zkID 쪽 연결(linked·옛 linkedOidc)은 RP 로 옮겨 없앴다 — 남아 있으면 지운다(값은 IdP 가 더 쓰지 않는다).
    if ('linked' in a || 'linkedOidc' in a) { delete a.linked; delete a.linkedOidc; notes.push(`계정 ${uid}: 옛 linked·linkedOidc 를 지웠다(2026-11-10 RP 직접 연결로 대체)`); }
```

  (`a`·`uid`·`notes` 는 이 파일의 계정 순회 루프에서 쓰는 실제 이름으로.) Run: `node tests/test_mode3_cia_state.mjs` → 통과.

- [ ] **Step 4: 공용 lib(`lib/mode3_oidc_link.js`)** — `LINK_PREFIX`·`AUTH_PREFIX`·`LINK_SLOTS`·`sanitizeAuthCtx`(와 `CTX_KEYS`)를 지우고 머리 주석을 "RP 의 네이버 로그인(PKCE·코드 교환)과 1회용 저장소 — 2026-11-10 부터 RP(lib/mode3_rp_social.js)가 쓴다" 로 고친다. Run: `node tests/test_mode3_oidc_link.mjs` → 통과.

- [ ] **Step 5: 화면**
  - `mode3/cia_login.html`: 외부 인증 줄(`authExtRow`·`authGsiSlot`·`authNaverBtn`), `method`·`ticket`·`auth_error` 처리, `gsi.js` 로드(45f3602 에서 더한 것)를 지운다 — `git show 81c1893:mode3/cia_login.html` 과 비교해 그 사이 다른 커밋(b16d639 등록 모드, 10e3445 auid 직접 입력)의 변경은 남긴다.
  - `mode3/cia_user.html`: 연결 카드(`linksCard`)와 `renderLinks`·`LINK_ROWS`·`linkProviders`·`?linked`/`?link_error` 처리·`gsi.js` 로드(45f3602 추가분)를 지운다. 0bced51 의 하위 메뉴·배지 제거는 남긴다.
  - `mode3/wallet.html`: `processAuthorize` 의 `method` 분기(`req.provider === 'google' || 'naver'` → `goIdpAuth(…, { method })`, `provider_mismatch`)를 지우고 `goIdpAuth(req, evOrigin, { purpose })` 의 `method` 인자도 지운다. 미등록 지갑은 늘 등록 모드(`purpose:'register'`), 등록 지갑은 아이디·비밀번호 인증 창. Google 래퍼 지갑의 기존 경로(지갑 안 Google 버튼 발급)는 그대로.
  - `mode3/user/popup.js`: 네이버 `snap_mode_only` 응답을 지우고 `npm run user:build`.
  - `mode3/common/strings.js`: 45f3602 가 더한 IdP·지갑 쪽 키(`idp_links_*`, `idp_auth_google_*`, `idp_auth_naver_*`, `idp_auth_ext_*`, `idp_auth_continue`, `wallet_auth_to_idp_ext`)와 이제 아무도 안 쓰는 사유(`oidc_not_linked`, `oidc_already_linked`, `oidc_linked_elsewhere`, `oidc_has_own_account`, `link_not_allowed`, `bad_ticket`, `provider_mismatch`, `snap_mode_only`)를 지운다. RP 가 쓰는 `naver_state_invalid`·`naver_token_failed`·`naver_denied`·`provider_disabled`·`bad_method` 와 `use_auth_window` 는 남긴다. 지우기 전에 `grep -rn "<키>" mode3 cia.js mode3_rp.js mode3_wallet_agent.js lib` 로 남은 사용처가 없는지 확인한다.

- [ ] **Step 6: 테스트 도우미** — `tests/helpers/isolated_cia.mjs` 의 `naver`·`uiHost` 옵션과 `MODE3_NAVER_*` env 를 지우고, `isolated_mode3_stack.mjs` 의 `naver` 옵션·`naver: cia.naver` 반환을 지운다(`ciaHost`·`ciaUiBase` 는 다른 테스트가 쓰면 유지 — `grep -rn "ciaHost\|ciaUiBase" tests` 로 확인).

- [ ] **Step 7: 통과 확인(순서대로)** — Run: `bash scripts/run_tests.sh unit`; 임시 hardhat 위에서 `node tests/test_cia_oidc_register.mjs`, `node tests/test_cia_accounts.mjs`, `node tests/test_mode3_wallet_agent.mjs`, `node tests/test_rp_social_logins.mjs`, `node tests/test_mode3_browser.mjs`, `node tests/test_mode3_wallet_snap_oidc_browser.mjs`, `node tests/test_mode3_user_web.mjs` → 모두 통과. `grep -rn "linkedView\|LINK_SLOTS\|/cia/user/link\|/cia/oidc/naver\|method=naver\|authExtRow" cia.js mode3 lib tests` → 결과 없음.

- [ ] **Step 8: 커밋**

```bash
git add cia.js lib/mode3_cia_state.js lib/mode3_oidc_link.js mode3/cia_login.html mode3/cia_user.html mode3/wallet.html mode3/user/popup.js mode3/common/strings.js tests/test_mode3_oidc_link.mjs tests/test_cia_oidc_register.mjs tests/test_mode3_cia_state.mjs tests/test_mode3_wallet_snap_oidc_browser.mjs tests/helpers/isolated_cia.mjs tests/helpers/isolated_mode3_stack.mjs scripts/run_tests.sh
git commit -m "refactor(idp,wallet): 11-09 zkID 쪽 Google·네이버 연결 제거 — 연결은 RP 로(스펙 2026-11-10); 인증 창은 아이디·비밀번호만, 옛 linked 는 기동 때 지움" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -m "Claude-Session: https://claude.ai/code/session_013qGSXZTftBJSB1M4XpPRHN"
```

  (`git rm` 한 `tests/test_cia_linked_logins.mjs` 는 이미 스테이징돼 있다.)

---

### Task 5: 분리 데모 스크립트·런북

**Files:**
- Modify: `scripts/demo_split_start.sh`, `docs/MODE3_DEMO.md`

**Interfaces:**
- Consumes: RP env `MODE3_RP_GOOGLE_CLIENT_ID`, `MODE3_RP_NAVER_CLIENT_ID`, `MODE3_RP_NAVER_CLIENT_SECRET`, `MODE3_RP_NAVER_REDIRECT_URI`, `MODE3_RP_PUBLIC_ORIGIN`(Task 2).

- [ ] **Step 1: 스크립트** — `scripts/demo_split_start.sh`
  - 머리 주석의 11-09 "네이버 연결" 두 줄을 이렇게 바꾼다: `#        (2026-11-10 RP 소셜 로그인) snap 모드 기본 SPLIT_RP_TUNNEL=1 — 이 VM 에 localhost:3100→zkONE, localhost:3101→zkTWO 터널. RP 공개 주소·지갑의 RP 오리진이 localhost 가 된다(Google 은 http 원본으로 localhost 만). Google 클라이언트 ID 와 네이버 ID·Secret(환경변수 또는 .env 의 MODE3_NAVER_CLIENT_ID·_SECRET)은 RP role.env 에만, 출력은 on/off 만. 네이버 Callback: http://localhost:3100/api/rp/naver/callback, http://localhost:3101/api/rp/naver/callback. Google 콘솔 승인된 원본: http://localhost:3100, http://localhost:3101.`
  - 변수: `TUNNEL_SPEC` 아래에 `RP1_TUNNEL="-L 127.0.0.1:$RP1_PORT:127.0.0.1:$RP1_PORT"`, `RP2_TUNNEL="-L 127.0.0.1:$RP2_PORT:127.0.0.1:$RP2_PORT"`, `SPLIT_RP_TUNNEL="${SPLIT_RP_TUNNEL:-$([ "$WALLET_MODE" = snap ] && echo 1 || echo 0)}"`, `if [ "$SPLIT_RP_TUNNEL" != 0 ]; then RP1_UI="http://localhost:$RP1_PORT"; RP2_UI="http://localhost:$RP2_PORT"; else RP1_UI="http://$RP1:$RP1_PORT"; RP2_UI="http://$RP2:$RP2_PORT"; fi`.
  - `stop_local` 의 spec 목록에 `"$RP1_PORT:$RP1_TUNNEL" "$RP2_PORT:$RP2_TUNNEL"` 추가. 0단계 ABORT 검사에 RP 터널이 켜져 있으면 :3100·:3101 이 비어 있는지 확인(한 머신 데모 RP 와 충돌하면 중단).
  - IdP `role.env`: `NAVER_LINES` 를 IdP 에 쓰던 것을 지운다.
  - RP `role.env`: `MODE3_RP_PUBLIC_ORIGIN=$RP1_UI`·`$RP2_UI` 로 바꾸고, 각 RP 에 `${RP_GOOGLE_LINE:+"$RP_GOOGLE_LINE"}` 와 RP 별 네이버 줄을 더한다:

```bash
# RP 소셜(2026-11-10) — 값은 출력하지 않는다(on/off 만). Google 은 IdP 래퍼와 같은 클라이언트 ID 를 쓴다(OIDC_ID 를 구한 곳에서 같이).
RP_GOOGLE_LINE=""; [ -n "$OIDC_LINE" ] && RP_GOOGLE_LINE="MODE3_RP_GOOGLE_CLIENT_ID=${OIDC_LINE#MODE3_OIDC_CLIENT_ID=}"
NAVER_ID="$(env_or_dotenv MODE3_NAVER_CLIENT_ID)"; NAVER_SECRET="$(env_or_dotenv MODE3_NAVER_CLIENT_SECRET)"
rp_naver_lines() { [ -n "$NAVER_ID" ] && [ -n "$NAVER_SECRET" ] && printf '%s\n' "MODE3_RP_NAVER_CLIENT_ID=$NAVER_ID" "MODE3_RP_NAVER_CLIENT_SECRET=$NAVER_SECRET" "MODE3_RP_NAVER_REDIRECT_URI=$1/api/rp/naver/callback"; }
echo "  RP 소셜: Google $([ -n "$RP_GOOGLE_LINE" ] && echo on || echo off) · 네이버 $([ -n "$NAVER_ID" ] && [ -n "$NAVER_SECRET" ] && echo on || echo off)   RP 주소: $RP1_UI, $RP2_UI"
```

    RP 의 `printf … | put_env` 두 줄 끝에 `${RP_GOOGLE_LINE:+"$RP_GOOGLE_LINE"}` 를 넣고, 파이프 앞을 `{ printf '%s\n' …; rp_naver_lines "$RP1_UI"; } | put_env "$RP1"`(zkTWO 는 `$RP2_UI`·`$RP2`)로 감싼다. 끝에 `unset NAVER_ID NAVER_SECRET`.
  - 지갑 에이전트의 `MODE3_RP_ORIGIN="http://$RP1:$RP1_PORT,http://$RP2:$RP2_PORT"` 를 `"$RP1_UI,$RP2_UI"` 로(snap·web 두 줄 모두).
  - RP 기동(`start_remote`) 뒤 터널: `if [ "$SPLIT_RP_TUNNEL" != 0 ]; then for spec in "$RP1:$RP1_TUNNEL:$RP1_UI" "$RP2:$RP2_TUNNEL:$RP2_UI"; do …; done; fi` — 각 줄은 IdP 터널과 같은 `ssh -o BatchMode=yes -o ConnectTimeout=5 -o ExitOnForwardFailure=yes -f -N <터널> "$U@<RP IP>" && curl -s -m 3 -o /dev/null "<UI>/mode3/health" && echo "RP 터널 up: <UI>"`(셸에서 콜론 분해 대신 RP1·RP2 두 번 쓴다).
  - 7단계 안내문의 RP 주소(zkONE http://$RP1:…)를 `$RP1_UI`·`$RP2_UI` 로, 8단계 요약 `for u in` 의 RP 두 항목도 그대로 VM 주소(서버 확인용)로 둔다. 페이지 안내 줄의 zkONE·zkTWO 주소는 `$RP1_UI`·`$RP2_UI`.
  - Run: `bash -n scripts/demo_split_start.sh` → 문법 오류 없음. `grep -n "MODE3_NAVER" scripts/demo_split_start.sh` → IdP role.env 에 쓰는 줄이 없다.

- [ ] **Step 2: 런북** — `docs/MODE3_DEMO.md` 의 "zkID 계정에 Google·네이버 로그인 연결" 절 전체를 다음 내용의 절 "RP 계정에 Google·네이버 로그인 연결(2026-11-10)" 로 바꾼다(기존 문체):
  - 모델: RP 마다 계정, 로그인 수단 세 칸(zkID·Google·네이버), 처음 쓰는 수단이면 새 계정, "내 계정" 탭에서 연결·해제(마지막 수단은 못 푼다), 다른 계정에 붙은 수단은 거부.
  - zk 를 거치지 않는 지점(스펙 §6 다섯 줄).
  - 자산: KRW·ETH(내 계정)·ETH(거래소 보관), 출금 출처.
  - 분리 데모: 브라우저는 zkONE `http://localhost:3100`, zkTWO `http://localhost:3101`, IdP `http://localhost:4100` 로 연다(모두 이 VM 의 SSH 터널). 사용자 설정(Google 원본 두 개, 네이버 Callback 두 개, 키는 `.env` 의 `MODE3_NAVER_CLIENT_ID`·`_SECRET`).
  - 시연 순서: zkONE 에서 zkID 로그인 → 내 계정 → Google 연결 → 로그아웃 → Google 로 로그인(같은 계정·같은 잔고) → 네이버 연결 → zkTWO 에서 Google 로그인(새 계정 — RP 마다 따로).
  - 미확인: 실제 네이버의 localhost 콜백·`client_secret`+PKCE·콜백 여러 개 등록.

- [ ] **Step 3: 커밋**

```bash
git add scripts/demo_split_start.sh docs/MODE3_DEMO.md
git commit -m "chore(demo): 분리 데모 RP 터널(localhost:3100·3101)·RP 소셜 키를 RP role.env 로, 런북 RP 소셜 로그인 절" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -m "Claude-Session: https://claude.ai/code/session_013qGSXZTftBJSB1M4XpPRHN"
```

---

### Task 6: 전체 확인

- [ ] **Step 1:** `bash scripts/run_tests.sh unit` → 실패 0.
- [ ] **Step 2:** 임시 hardhat(:8545, 스크래치 `chain/min.config.cjs`)을 띄우고 `bash scripts/run_tests.sh chain` → 실패 0.
- [ ] **Step 3:** 같은 노드로 `bash scripts/run_tests.sh browser` → 실패 0. `bash scripts/run_tests.sh snap` → 실패 0.
- [ ] **Step 4:** 띄운 hardhat 을 명령줄 확인 후 내리고 :8545 가 빈 것을 확인.
- [ ] **Step 5:** 저장소 루트에 테스트가 새로 쓴 파일이 없는지: `git status --short` 에 새 `mode3_rp*_accounts*.json` 수정 시각이 이번 실행 이후로 바뀌지 않았는지(`ls -l --time-style=+%T mode3_rp_accounts.json`) 확인 — Task 2 Step 1 의 누수 수정 확인.
- [ ] **Step 6:** 최종 리뷰(Opus) — 전체 브랜치 diff(`git diff 0bced51..HEAD`)를 스펙과 대조.
