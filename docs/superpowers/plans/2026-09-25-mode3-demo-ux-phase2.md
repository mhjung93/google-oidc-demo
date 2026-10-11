# Mode 3 데모 UX 2차(health·상태 패널·체험 모드) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 세 서버에 민감정보 없는 `GET /mode3/health`를 두고, 공통 레이어가 그것을 폴링해 상단 바에 상태 점·패널을 그리며, 체험 모드가 같은 데이터로 앞 3단계를 잠그고 말풍선으로 다음 클릭을 안내한다.

**Architecture:** `lib/mode3_health.js`(순수 조립·허용 오리진 판정) → 서버 라우트 3개(헤더 직접 부착) → `Demo.stack()`(폴링·점·패널) → `Demo.tour`(스위치·판정·잠금·오버레이). 페이지는 주소를 넘기고 잠글 버튼을 등록할 뿐, 요청 본문·id·1차 안내 바는 그대로다.

**Tech Stack:** Node ESM(express), 순수 HTML/JS/CSS(빌드·의존성 없음), `t()` 러너 단위 테스트, 격리 스택(`tests/helpers/isolated_mode3_stack.mjs`), Playwright(Chrome `channel:'chrome'`).

**Spec:** `docs/superpowers/specs/2026-09-25-mode3-demo-ux-phase2-design.md`

## Global Constraints

- health 응답에 **uid·PPID·시크릿·개인키·pk 값·arid·r_s 없음**(단위 테스트가 어느 깊이에서도 `uid PPID secret sk_u pk_u pk_CIA arid r_s` 키가 없음을 강제). `Cache-Control: no-store`. 인증 없음.
- CORS: `Origin` 이 허용 목록에 있을 때만 `Access-Control-Allow-Origin: <origin>` + `Vary: Origin`. 서비스 = `WALLET_ORIGIN`·`CIA_URL`; 지갑 = `RP_ORIGIN`·`CIA_URL`; AA = 승인된 `state.rps[*].origin`(`status==='approved'`) + env `MODE3_WALLET_AGENT_ORIGIN`(기본 `http://127.0.0.1:5100`). `cors` 패키지는 새로 import 하지 않는다.
- 기존 라우트·요청 본문·페이지 id 불변. `tests/test_mode3_browser.mjs`·`tests/test_mode3_demo_stack.mjs` 무수정 통과(체험 모드 기본 꺼짐).
- 폴링 5초, 요청 타임아웃 2초(`AbortController`), 탭 숨김 시 정지. 실패는 콘솔에 남기지 않는다.
- 체험 모드: `localStorage` `mode3.tour`('1'|없음), 기본 꺼짐; `?tour=1|0` 로 켜고/끄고 `history.replaceState` 로 지움; health 없으면 잠그지 않음; 승인 팝업(`?authorize=1`)에는 표시 안 함.
- 문구는 전부 사전(ko+en). 파괴적 조작 규칙·`.expert`·`tte/tt` 헬퍼 등 1차 규약 유지. 새 의존성·빌드 없음. `.env`·`*_keys.json`·`*_state.json` 은 읽지 않는다. hardhat 노드는 스스로 띄우고 PID 로만 종료. 커밋 메시지 한글 + 트레일러 두 줄.

---

## 파일 구조

| 파일 | 책임 | 작업 |
|---|---|---|
| `lib/mode3_health.js` | `buildAaHealth/buildRpHealth/buildWalletHealth`, `allowOrigin`, `shortRoot`, `rootAge` (순수) | T1 |
| `tests/test_mode3_health_shape.js` | 조립 함수·민감 필드 부재·허용 판정 (unit) | T1 |
| `cia.js`, `mode3_rp.js`, `mode3_wallet_agent.js` | `GET /mode3/health` 라우트 | T1 |
| `tests/helpers/isolated_mode3_stack.mjs` | 지갑 포트 선할당 + CIA 에 `MODE3_WALLET_AGENT_ORIGIN` | T1 |
| `tests/test_mode3_health.mjs` | 실제 응답·CORS 헤더 (chain) | T1 |
| `mode3/common/demo.js` `Demo.stack` | 폴링·판정·점·패널 | T2 |
| `mode3/common/strings.js` `stack_*` | 패널 문구 | T2 |
| 네 페이지 | `Demo.stack({...})` 호출·주소 갱신 | T2 |
| `mode3/common/demo.js` `Demo.tour`, `strings.js` `tour_*`·`steps[k].tour/target` | 스위치·판정·잠금·오버레이 | T3 |
| `mode3/rp.html`, `mode3/wallet.html` | `Demo.tour.lock` 등록, `renderGuide` 위임, `?tour=` | T3 |
| `tests/test_mode3_tour.mjs`, `scripts/screenshot_mode3.mjs --tour`, `results/mode3_ux_20260925/`, `docs/MODE3_DEMO.md` | browser 테스트·캡처·문서·전체 검증 | T4 |

---

### Task 1: health 라이브러리 · 서버 라우트 · 격리 헬퍼 · 테스트

**Files:**
- Create: `lib/mode3_health.js`, `tests/test_mode3_health_shape.js`, `tests/test_mode3_health.mjs`
- Modify: `cia.js`(≈259 `/cia/public_keys` 근처), `mode3_rp.js`(≈287 `rp_info` 근처), `mode3_wallet_agent.js`(≈249 `/wallet/config` 근처), `tests/helpers/isolated_mode3_stack.mjs`(≈64–70), `scripts/run_tests.sh`(UNIT·CHAIN)

**Interfaces (Produces):**
```js
// lib/mode3_health.js
export const SENSITIVE_KEYS = ['uid', 'PPID', 'secret', 'sk_u', 'pk_u', 'pk_CIA', 'arid', 'r_s'];
export function shortRoot(rootStr)                       // 앞 12자리 + '…' (12자 이하면 그대로)
export function rootAge(head, lastPublished)             // bigint|string|number|null → number|null
export function allowOrigin(origin, list)                // 정확히 일치하는 항목이 있으면 true (list 의 빈/undefined 무시)
export function buildAaHealth({ now, chain, root, epoch, lastPublishedBlock, heartbeatBlocks, pendingLeaves, pendingRps, pendingOpenings, accounts, walletOrigin, rpOrigins })
export function buildRpHealth({ now, chain, status, active, inactiveReason, maxRootAge, rootAge, sessions, predicates, walletAgentOrigin, ciaUrl })
export function buildWalletHealth({ now, chain, secrets, registered, hasCred, sessions, ciaReachable, rpOrigin, ciaUrl })
// 세 함수 모두 { role, ok:true, now, chain: {id, head}|null, ...역할별 } 를 돌려주고 값은 string|boolean|number|null|string[] 뿐이다.
```
서버 라우트: `GET /mode3/health` (세 서버), 응답 헤더 `Cache-Control: no-store`, 허용 오리진이면 `Access-Control-Allow-Origin`·`Vary: Origin`.

- [ ] **Step 1: 실패하는 단위 테스트** — `tests/test_mode3_health_shape.js`

```js
// lib/mode3_health.js 의 순수 함수. node tests/test_mode3_health_shape.js
import assert from 'node:assert/strict';
import { SENSITIVE_KEYS, shortRoot, rootAge, allowOrigin, buildAaHealth, buildRpHealth, buildWalletHealth } from '../lib/mode3_health.js';
let fails = 0;
function t(name, fn) { try { fn(); console.log('ok   -', name); } catch (e) { fails++; console.log('FAIL -', name, '\n      ', e.message); } }
function deepKeys(o, acc = []) { if (o && typeof o === 'object') for (const [k, v] of Object.entries(o)) { acc.push(k); deepKeys(v, acc); } return acc; }
const now = '2026-09-25T00:00:00.000Z', chain = { id: '31337', head: '812' };

t('shortRoot: 12자리 + …, 짧으면 그대로', () => { assert.equal(shortRoot('1234567890123456'), '123456789012…'); assert.equal(shortRoot('123'), '123'); });
t('rootAge: head − lastPublished, 체인 없으면 null', () => { assert.equal(rootAge('812', 800n), 12); assert.equal(rootAge(null, 800n), null); assert.equal(rootAge('812', null), null); });
t('allowOrigin: 정확 일치만, 빈 항목 무시', () => {
  assert.equal(allowOrigin('http://a:1', ['http://a:1', '']), true);
  assert.equal(allowOrigin('http://a:1', ['http://a:10']), false);
  assert.equal(allowOrigin(undefined, ['http://a:1']), false);
  assert.equal(allowOrigin('http://a:1', [undefined, null]), false);
});
t('AA health: 역할별 필드와 민감 필드 부재', () => {
  const h = buildAaHealth({ now, chain, root: '9'.repeat(70), epoch: 3, lastPublishedBlock: '800', heartbeatBlocks: 50, pendingLeaves: 1, pendingRps: 0, pendingOpenings: 2, accounts: 4, walletOrigin: 'http://w', rpOrigins: ['http://r'] });
  assert.equal(h.role, 'aa'); assert.equal(h.ok, true); assert.equal(h.root, '999999999999…'); assert.equal(h.rootAge, 12);
  assert.deepEqual(h.rpOrigins, ['http://r']); assert.equal(h.chain.head, '812');
  for (const k of SENSITIVE_KEYS) assert.ok(!deepKeys(h).includes(k), k);
});
t('AA health: 체인 없음 → chain null, rootAge null', () => { const h = buildAaHealth({ now, chain: null, root: '1', epoch: 0, lastPublishedBlock: '0', heartbeatBlocks: 0, pendingLeaves: 0, pendingRps: 0, pendingOpenings: 0, accounts: 0, walletOrigin: '', rpOrigins: [] }); assert.equal(h.chain, null); assert.equal(h.rootAge, null); });
t('RP health', () => {
  const h = buildRpHealth({ now, chain, status: 'approved', active: true, inactiveReason: null, maxRootAge: 100, rootAge: 3, sessions: 2, predicates: { countries: 5, minAge: 19 }, walletAgentOrigin: 'http://w', ciaUrl: 'http://c' });
  assert.equal(h.role, 'rp'); assert.equal(h.active, true); assert.equal(h.predicates.minAge, 19);
  for (const k of SENSITIVE_KEYS) assert.ok(!deepKeys(h).includes(k), k);
});
t('wallet health', () => {
  const h = buildWalletHealth({ now, chain, secrets: 'file', registered: true, hasCred: true, sessions: 1, ciaReachable: false, rpOrigin: 'http://r', ciaUrl: 'http://c' });
  assert.equal(h.role, 'wallet'); assert.equal(h.ciaReachable, false);
  for (const k of SENSITIVE_KEYS) assert.ok(!deepKeys(h).includes(k), k);
});
t('값 형식: string|boolean|number|null|string[] 뿐', () => {
  const h = buildRpHealth({ now, chain, status: 'pending', active: false, inactiveReason: 'registration_pending', maxRootAge: 100, rootAge: null, sessions: 0, predicates: { countries: 0, minAge: 0 }, walletAgentOrigin: 'http://w', ciaUrl: 'http://c' });
  const ok = (v) => v === null || ['string', 'boolean', 'number'].includes(typeof v) || (Array.isArray(v) && v.every((x) => typeof x === 'string')) || (v && typeof v === 'object' && Object.values(v).every(ok));
  assert.ok(ok(h));
});
if (fails) { console.log(`\n${fails} FAIL`); process.exit(1); } else console.log('\nall ok');
```

- [ ] **Step 2: 실패 확인** — `node tests/test_mode3_health_shape.js` → 모듈 없음.

- [ ] **Step 3: `lib/mode3_health.js`**

```js
// Mode 3 데모 상태 엔드포인트(GET /mode3/health)의 응답 조립 — 설계 2026-09-25 §1. 순수 함수: 서버가 읽은 값을 넣으면 응답 객체.
// 여기 들어가는 값은 화면 상태 패널·체험 모드 판정용이다. uid·PPID·시크릿·키·arid·r_s 는 절대 넣지 않는다(SENSITIVE_KEYS, 단위 테스트).
export const SENSITIVE_KEYS = ['uid', 'PPID', 'secret', 'sk_u', 'pk_u', 'pk_CIA', 'arid', 'r_s'];
const num = (v) => (v === null || v === undefined ? null : Number(v));
export function shortRoot(rootStr) { const s = String(rootStr ?? ''); return s.length > 12 ? `${s.slice(0, 12)}…` : s; }
export function rootAge(head, lastPublished) { if (head === null || head === undefined || lastPublished === null || lastPublished === undefined) return null; return Number(BigInt(head) - BigInt(lastPublished)); }
/** 허용 목록과 정확히 같은 origin 만. 빈 문자열·undefined 항목은 무시(설정이 비어 있어도 "모두 허용"이 되지 않게). */
export function allowOrigin(origin, list) { if (typeof origin !== 'string' || !origin) return false; return (list ?? []).some((o) => typeof o === 'string' && o.length > 0 && o === origin); }
const chainOf = (chain) => (chain ? { id: String(chain.id), head: String(chain.head) } : null);
export function buildAaHealth({ now, chain, root, epoch, lastPublishedBlock, heartbeatBlocks, pendingLeaves, pendingRps, pendingOpenings, accounts, walletOrigin, rpOrigins }) {
  return { role: 'aa', ok: true, now, chain: chainOf(chain), root: shortRoot(root), epoch: num(epoch), lastPublishedBlock: lastPublishedBlock === null || lastPublishedBlock === undefined ? null : String(lastPublishedBlock),
    rootAge: chain ? rootAge(chain.head, lastPublishedBlock) : null, heartbeatBlocks: num(heartbeatBlocks), pendingLeaves: num(pendingLeaves), pendingRps: num(pendingRps), pendingOpenings: num(pendingOpenings), accounts: num(accounts),
    walletOrigin: String(walletOrigin ?? ''), rpOrigins: (rpOrigins ?? []).map(String) };
}
export function buildRpHealth({ now, chain, status, active, inactiveReason, maxRootAge, rootAge: ra, sessions, predicates, walletAgentOrigin, ciaUrl }) {
  return { role: 'rp', ok: true, now, chain: chainOf(chain), status: String(status), active: !!active, inactiveReason: inactiveReason ?? null, maxRootAge: num(maxRootAge), rootAge: num(ra), sessions: num(sessions),
    predicates: { countries: num(predicates?.countries ?? 0), minAge: num(predicates?.minAge ?? 0) }, walletAgentOrigin: String(walletAgentOrigin ?? ''), ciaUrl: String(ciaUrl ?? '') };
}
export function buildWalletHealth({ now, chain, secrets, registered, hasCred, sessions, ciaReachable, rpOrigin, ciaUrl }) {
  return { role: 'wallet', ok: true, now, chain: chainOf(chain), secrets: String(secrets), registered: !!registered, hasCred: !!hasCred, sessions: num(sessions), ciaReachable: !!ciaReachable, rpOrigin: String(rpOrigin ?? ''), ciaUrl: String(ciaUrl ?? '') };
}
/** 응답 헤더: 캐시 금지 + 허용 오리진에만 CORS. express res 를 받는다. */
export function applyHealthHeaders(req, res, allowList) {
  res.set('Cache-Control', 'no-store');
  const origin = req.get('Origin');
  if (allowOrigin(origin, allowList)) { res.set('Access-Control-Allow-Origin', origin); res.set('Vary', 'Origin'); }
}
```

- [ ] **Step 4: 통과 확인** — `node tests/test_mode3_health_shape.js` all ok. `scripts/run_tests.sh` UNIT 에 추가.

- [ ] **Step 5: 서버 라우트 3개**

`cia.js`(`/cia/public_keys` 아래; `headHeight`, `log.lastPublishedBlock()`, `tree`, `state`, `HEARTBEAT_BLOCKS`, `CHAIN_RPCS` 는 파일 안에 이미 있다):
```js
// 상태 엔드포인트(설계 2026-09-25 §1) — 민감정보 없음, 승인된 서비스·지갑 오리진에만 CORS.
const WALLET_AGENT_ORIGIN = process.env.MODE3_WALLET_AGENT_ORIGIN || 'http://127.0.0.1:5100';
app.get('/mode3/health', async (req, res) => {
  const rpOrigins = Object.values(state.rps).filter((r) => r.status === 'approved').map((r) => r.origin);
  applyHealthHeaders(req, res, [...rpOrigins, WALLET_AGENT_ORIGIN]);
  let chain = null, last = null;
  try { const head = await headHeight(); chain = { id: [...CHAIN_RPCS.keys()][0] ?? '', head: head.toString() }; } catch { /* 체인 없음 */ }
  try { if (chain && LOG_ADDRESS) last = (await log.lastPublishedBlock()).toString(); } catch { /* 로그 못 읽음 */ }
  res.json(buildAaHealth({ now: new Date().toISOString(), chain, root: tree.getRoot().toString(), epoch: state.epoch, lastPublishedBlock: last, heartbeatBlocks: Number(HEARTBEAT_BLOCKS),
    pendingLeaves: state.pending.length, pendingRps: Object.values(state.rps).filter((r) => r.status === 'pending').length, pendingOpenings: state.openings.filter((o) => o.status === 'pending').length,
    accounts: Object.keys(state.accounts).length, walletOrigin: WALLET_AGENT_ORIGIN, rpOrigins }));
});
```
(`log`·`LOG_ADDRESS`·`headHeight`·`state.openings[].status` 의 실제 이름은 파일에서 확인해 맞춘다 — 없는 이름을 지어내지 않는다.)

`mode3_rp.js`(`rp_info` 아래; `reg`, `verifier`, `inactiveReason()`, `EFFECTIVE_MAX_ROOT_AGE`, `sessions`, `WALLET_ORIGIN`, `CIA_URL`, `attrGatePolicy`/`rp_info.predicates` 소스 확인):
```js
let lastRootAge = null;   // 마지막 로그인·재검증·요청에서 본 head − lastPublishedBlock (health 표시용)
// … verifier.refreshChainView() 를 부르는 세 곳(login/revalidate/request)에서 view 를 얻은 직후: if (view) lastRootAge = Number(view.head - view.lastPublishedBlock);
app.get('/mode3/health', async (req, res) => {
  applyHealthHeaders(req, res, [WALLET_ORIGIN, CIA_URL]);
  let chain = null; try { chain = { id: (await provider.getNetwork()).chainId.toString(), head: (await provider.getBlockNumber()).toString() }; } catch { /* 체인 없음 */ }
  res.json(buildRpHealth({ now: new Date().toISOString(), chain, status: reg.status, active: !!verifier, inactiveReason: verifier ? null : inactiveReason(), maxRootAge: Number(EFFECTIVE_MAX_ROOT_AGE), rootAge: lastRootAge,
    sessions: sessions.size, predicates: { countries: (currentPredicates()?.allowedCountries ?? []).length, minAge: Number(currentPredicates()?.minAge ?? 0) }, walletAgentOrigin: WALLET_ORIGIN, ciaUrl: CIA_URL }));
});
```
(`currentPredicates()` 는 `rp_info` 가 `predicates` 를 만드는 식을 함수로 빼거나 같은 식을 쓴다.)

`mode3_wallet_agent.js`(`/wallet/config` 아래):
```js
let ciaSeenAt = 0;   // 마지막으로 CIA 가 200 을 준 시각(ms) — health 의 ciaReachable
async function pingCia() { try { const c = new AbortController(); const tm = setTimeout(() => c.abort(), 1500); const r = await fetch(`${CIA_URL}/cia/public_keys`, { signal: c.signal }); clearTimeout(tm); if (r.ok) ciaSeenAt = Date.now(); } catch { /* 못 닿음 */ } }
app.get('/mode3/health', async (req, res) => {
  applyHealthHeaders(req, res, [RP_ORIGIN, CIA_URL]);
  if (Date.now() - ciaSeenAt > 5000) await pingCia();
  let chain = null; try { chain = { id: (await chainId()).toString(), head: (await provider.getBlockNumber()).toString() }; } catch { /* 체인 없음 */ }
  res.json(buildWalletHealth({ now: new Date().toISOString(), chain, secrets: SECRETS, registered: !!state.registration, hasCred: !!state.registration?.userCred, sessions: Object.keys(state.sessions).length,
    ciaReachable: Date.now() - ciaSeenAt <= 5000, rpOrigin: RP_ORIGIN, ciaUrl: CIA_URL }));
});
```
세 파일에 `import { buildXHealth, applyHealthHeaders } from './lib/mode3_health.js';`.

- [ ] **Step 6: 격리 헬퍼** — `tests/helpers/isolated_mode3_stack.mjs`: `startIsolatedCia` 를 부르기 **전에** `walletPort = await freePort()` 와 `walletOrigin` 을 만들고 `startIsolatedCia({ env: { MODE3_WALLET_AGENT_ORIGIN: walletOrigin, ...ciaEnv } })` 로 넘긴다(이미 뒤에서 만드는 `walletPort` 선언을 앞으로 옮긴다 — 같은 값을 두 번 뽑지 않는다).

- [ ] **Step 7: chain 테스트** — `tests/test_mode3_health.mjs`(격리 스택, 서비스 승인 뒤):

```js
// GET /mode3/health 실제 응답·CORS. :8545 필요. node tests/test_mode3_health.mjs
import assert from 'node:assert/strict';
import { startIsolatedMode3Stack } from './helpers/isolated_mode3_stack.mjs';
const stack = await startIsolatedMode3Stack();
const { cia, rp, wallet } = stack;
let fails = 0; async function t(n, f) { try { await f(); console.log('ok   -', n); } catch (e) { fails++; console.log('FAIL -', n, '\n      ', e.message); } }
const get = (base, origin) => fetch(`${base}/mode3/health`, { headers: origin ? { Origin: origin } : {} });
await t('세 서버가 role·ok·chain 을 준다', async () => {
  for (const [b, role] of [[cia.base, 'aa'], [rp.base, 'rp'], [wallet.base, 'wallet']]) { const r = await get(b); const j = await r.json(); assert.equal(r.status, 200); assert.equal(j.role, role); assert.equal(j.ok, true); assert.ok(j.chain?.head, `${role} chain`); assert.equal(r.headers.get('cache-control'), 'no-store'); }
});
await t('민감 키 없음(전 깊이)', async () => {
  const bad = ['uid', 'PPID', 'secret', 'sk_u', 'pk_u', 'pk_CIA', 'arid', 'r_s'];
  for (const b of [cia.base, rp.base, wallet.base]) { const s = JSON.stringify(await (await get(b)).json()); for (const k of bad) assert.ok(!s.includes(`"${k}"`), `${b} has ${k}`); }
});
await t('CORS: 허용 오리진에만 헤더', async () => {
  assert.equal((await get(rp.base, wallet.origin)).headers.get('access-control-allow-origin'), wallet.origin);
  assert.equal((await get(rp.base, 'http://evil.example')).headers.get('access-control-allow-origin'), null);
  assert.equal((await get(wallet.base, rp.origin)).headers.get('access-control-allow-origin'), rp.origin);
  assert.equal((await get(cia.base, wallet.origin)).headers.get('access-control-allow-origin'), wallet.origin);   // MODE3_WALLET_AGENT_ORIGIN
  assert.equal((await get(cia.base, rp.origin)).headers.get('access-control-allow-origin'), rp.origin);           // 승인된 서비스
  assert.equal((await get(cia.base, 'http://evil.example')).headers.get('access-control-allow-origin'), null);
});
await t('RP: approved·active, 지갑: 미등록·ciaReachable', async () => {
  const r = await (await get(rp.base)).json(); assert.equal(r.status, 'approved'); assert.equal(r.active, true); assert.equal(typeof r.maxRootAge, 'number');
  const w = await (await get(wallet.base)).json(); assert.equal(w.registered, false); assert.equal(w.ciaReachable, true);
});
await stack.stop();
if (fails) { console.log(`\n${fails} FAIL`); process.exit(1); } console.log('\nall ok');
```
(`stack.stop()`·`wallet.origin`·`rp.origin` 의 실제 이름은 헬퍼에서 확인. 승인은 헬퍼가 대행한다 — 아니면 `cia.adminPost('/cia/rps/:arid/approve')` 로.) `scripts/run_tests.sh` CHAIN 에 추가.

- [ ] **Step 8: 검증** — 자기 hardhat 노드에서 `node tests/test_mode3_health.mjs`, `node tests/test_mode3_demo_stack.mjs`, `bash scripts/run_tests.sh unit`.
- [ ] **Step 9: 커밋** — `feat(mode3): GET /mode3/health — 역할별 상태(민감정보 없음)·허용 오리진 CORS, 순수 조립 lib·단위/체인 테스트`

---

### Task 2: `Demo.stack()` — 폴링·판정·상태 점·패널 + 페이지 연결

**Files:**
- Modify: `mode3/common/demo.js`, `mode3/common/demo.css`, `mode3/common/strings.js`, `tests/test_mode3_demo_strings.js`, 네 페이지

**Interfaces:**
- Consumes: T1 health 응답 형태.
- Produces:
```js
Demo.stack({ self: 'rp'|'wallet'|'aa', urls: { aa?: string, rp?: string, wallet?: string } })  // 시작/갱신(같은 인자로 다시 불러도 됨)
Demo.stack.last   // { at: ms, aa: obj|null, rp: obj|null, wallet: obj|null, errors: { aa?: 'timeout'|'error' ... } }
Demo.stack.judge(last) // { aa: {level:'ok'|'warn'|'bad'|'unknown', key, vars}, rp:{...}, wallet:{...}, chain:{...} }  — 순수, 단위 테스트 가능
Demo.stack.onChange(fn) // 폴링 결과가 바뀔 때 호출(체험 모드가 구독)
```

- [ ] **Step 1: 사전 테스트 확장** — `tests/test_mode3_demo_strings.js` 에 `for (const k of ['stack_aa','stack_rp','stack_wallet','stack_chain','stack_unknown','stack_no_response','stack_chain_none','stack_root_stale','stack_root_warn','stack_pending_leaves','stack_rp_pending','stack_rp_inactive','stack_wallet_unregistered','stack_wallet_cia_down','stack_ok','stack_panel_title','stack_head']) assert.ok(S.ui[k], k);` 케이스 추가 → 실패 확인.
- [ ] **Step 2: `strings.js`** — 위 키 ko·en(예: `stack_root_stale: {ko:'게시가 멈췄습니다 — 전원 root_too_old', en:'Publishing stalled — everyone gets root_too_old'}`, `stack_head: {ko:'블록 {head}', en:'block {head}'}`).
- [ ] **Step 3: `demo.js` `Demo.stack`** — 핵심:

```js
    stack(cfg) {
      const st = (D.stack.state ??= { urls: {}, last: { at: 0, aa: null, rp: null, wallet: null, errors: {} }, timer: null, subs: [] });
      Object.assign(st.urls, cfg.urls || {}); st.self = cfg.self;
      if (!st.timer) { const tick = () => D.stack.poll(); st.timer = setInterval(() => { if (!document.hidden) tick(); }, 5000); document.addEventListener('visibilitychange', () => { if (!document.hidden) tick(); }); tick(); }
      D.stack.renderDots();
    },
```
`D.stack.poll` 은 `urls` 의 각 항목에 `fetch(url + '/mode3/health', { signal: AbortSignal.timeout(2000) })`(구형이면 `AbortController`)를 병렬로 보내 `last` 를 갱신하고, JSON 이 바뀌었으면 `subs` 를 부른다. 자기 서버(`self`)는 상대 URL 없이 `'/mode3/health'` 로 부른다. `judge(last)`:
```js
      judge(last) {
        const lv = (level, key, vars = {}) => ({ level, key, vars });
        const anyChain = [last.aa, last.rp, last.wallet].find((h) => h?.chain);
        const chain = last.at === 0 ? lv('unknown', 'stack_unknown') : anyChain ? lv('ok', 'stack_head', { head: anyChain.chain.head }) : lv('bad', 'stack_chain_none');
        const maxAge = last.rp?.maxRootAge ?? (last.aa ? last.aa.heartbeatBlocks * 2 : null);
        const aa = !last.aa ? (last.errors.aa ? lv('bad', 'stack_no_response') : lv('unknown', 'stack_unknown'))
          : (maxAge && last.aa.rootAge !== null && last.aa.rootAge >= maxAge) ? lv('bad', 'stack_root_stale')
          : (maxAge && ((last.aa.rootAge !== null && last.aa.rootAge >= maxAge / 2) || last.aa.heartbeatBlocks >= maxAge)) ? lv('warn', 'stack_root_warn', { age: last.aa.rootAge })
          : last.aa.pendingLeaves > 0 ? lv('warn', 'stack_pending_leaves', { n: last.aa.pendingLeaves }) : lv('ok', 'stack_ok');
        const rp = !last.rp ? (last.errors.rp ? lv('bad', 'stack_no_response') : lv('unknown', 'stack_unknown')) : !last.rp.active ? lv('bad', 'stack_rp_inactive') : last.rp.status !== 'approved' ? lv('warn', 'stack_rp_pending') : lv('ok', 'stack_ok');
        const wallet = !last.wallet ? (last.errors.wallet ? lv('bad', 'stack_no_response') : lv('unknown', 'stack_unknown')) : !last.wallet.ciaReachable ? lv('warn', 'stack_wallet_cia_down') : !last.wallet.registered ? lv('unknown', 'stack_wallet_unregistered') : lv('ok', 'stack_ok');
        return { aa, rp, wallet, chain };
      },
```
`renderDots()` 는 `#demoBar .bar-tools` 앞에 `<div class="stack-dots">` 를 두고 점 4개(`button.dot.<role>.<level>` — 예 `dot aa ok`, role ∈ aa|rp|wallet|chain — + 라벨 `stack_aa` 등)를 그리며, 클릭 시 `#stackPanel`(바 아래, `.stack-panel`) 토글. 패널은 역할별 한 줄(판정 문구) + `bad/warn` 이면 `D.reason(코드)` 원인·조치(`stack_root_stale`→`root_too_old`, `stack_rp_inactive`→`last.rp.inactiveReason`, `stack_wallet_cia_down`→`cia_unavailable`, `stack_rp_pending`→`registration_pending`) + `.expert` 에 원본 JSON `<pre>`. 바깥 클릭·Esc 로 닫힘. 언어·전문가 전환 시 `renderDots()` 재호출(`setLang/setExpert` 에 한 줄).
- [ ] **Step 4: CSS** — `.stack-dots{display:flex;gap:6px}`, `.dot{display:inline-flex;align-items:center;gap:4px;padding:2px 8px;border-radius:999px;border:1px solid var(--line);font-size:12px;background:transparent;color:var(--ink)}`, `.dot::before{content:'';width:8px;height:8px;border-radius:50%;background:#9aa4b2}`, `.dot.ok::before{background:var(--ok)}`, `.dot.warn::before{background:var(--warn)}`, `.dot.bad::before{background:var(--bad)}`, `.stack-panel{grid-column:1 / -1;border-top:1px solid var(--line);padding-top:8px;display:grid;gap:6px}`, `.stack-panel .row{display:grid;grid-template-columns:auto 1fr;gap:10px}`.
- [ ] **Step 5: 페이지 연결** — 서비스: `loadInfo()` 뒤 `Demo.stack({ self:'rp', urls:{ wallet: info.walletAgentOrigin, aa: info.ciaUrl } })`; 지갑: `refresh()` 에서 status 를 받은 뒤 `Demo.stack({ self:'wallet', urls:{ aa: s.ciaUrl, rp: (Demo.stack.last?.wallet?.rpOrigin) || null } })`(첫 폴링 뒤 자기 health 의 `rpOrigin` 으로 갱신 — `onChange` 에서 한 번); 관리자·계정: `Demo.stack({ self:'aa', urls:{} })` 뒤 `onChange` 에서 `last.aa.walletOrigin`·`last.aa.rpOrigins[0]` 로 `urls` 갱신하고 1차 안내 바 링크(`links.wallet/rp`)도 채운다. `Demo.init` 직후 호출하되 승인 팝업(`IS_AUTHORIZE`)에서는 부르지 않는다.
- [ ] **Step 6: 검증** — `node tests/test_mode3_demo_strings.js`; 자기 노드에서 `node tests/test_mode3_browser.mjs`, `node tests/test_mode3_demo_stack.mjs`; 스크린샷으로 점·패널 확인(scratchpad).
- [ ] **Step 7: 커밋** — `feat(mode3-ui): 상태 패널 — Demo.stack 폴링·판정·상단 점 4개·펼침 패널, 네 페이지 연결`

---

### Task 3: `Demo.tour` — 스위치·판정·잠금·오버레이 + 페이지 연결

**Files:**
- Modify: `mode3/common/demo.js`, `demo.css`, `strings.js`, `tests/test_mode3_demo_strings.js`, `mode3/rp.html`, `mode3/wallet.html`, `mode3/cia_admin.html`, `mode3/cia_account.html`

**Interfaces:**
- Consumes: T2 `Demo.stack.last`, `Demo.stack.onChange`.
- Produces:
```js
Demo.tour.enabled            // boolean
Demo.tour.set(on)            // 저장 + 즉시 재평가
Demo.tour.lock({ id, cond, otherwise })  // cond: 'rp_approved'|'wallet_registered'|'has_session'; otherwise: () => boolean (원래 활성 규칙)
Demo.tour.evaluate({ progress })         // { done: [...], current } 계산 → Demo.guide 호출 + 잠금 적용 + 오버레이 렌더. 페이지의 renderGuide 가 이걸 부른다
strings.js: steps[k].target = { rp?: id, wallet?: id, admin?: id, account?: id }, steps[k].tour = { ko:{title, body}, en:{...} }
ui: tour_on, tour_off, tour_lock_login, tour_lock_register, tour_elsewhere, tour_done_title, tour_done_body, tour_next
```

- [ ] **Step 1: 사전 테스트 확장** — 7단계 모두 `tour.ko.title/body`·`tour.en.*` 와 `target` 이 객체이고 최소 한 페이지 id 를 가짐; `ui.tour_*` 8키 ko·en. 실패 확인.
- [ ] **Step 2: `strings.js`** — `steps` 각 항목에 `target`(approve: `{admin:'rpsBtn'}`, register: `{wallet:'registerBtn'}`, login: `{rp:'loginBtn'}`, use: `{rp:'revalidateBtn', wallet:'txBtn'}`, disclose: `{wallet:'discloseBox', rp:'requirePred'}`, revoke: `{wallet:'sessionActions', admin:'revokeBtn', account:'revokeBtn'}`, open: `{rp:'openBtn', admin:'openingsBtn'}`) 와 `tour` 문구, `ui.tour_*`.
- [ ] **Step 3: `demo.js` `Demo.tour`**

```js
    tour: {
      enabled: false, locks: [], lastEval: null,
      init() {
        const q = new URLSearchParams(location.search); const v = q.get('tour');
        if (v === '1' || v === '0') { store.set('mode3.tour', v === '1' ? '1' : ''); q.delete('tour'); history.replaceState(null, '', location.pathname + (q.toString() ? '?' + q : '') + location.hash); }
        D.tour.enabled = store.get('mode3.tour') === '1';
        // 안내 바 스위치
        const tools = document.querySelector('#demoBar .bar-tools'); if (tools && !tools.querySelector('#tourToggle')) { const l = document.createElement('label'); l.className = 'switch'; l.innerHTML = '<input type="checkbox" id="tourToggle"> <span data-i18n="tour_on"></span>'; tools.prepend(l); const cb = l.querySelector('input'); cb.checked = D.tour.enabled; cb.addEventListener('change', () => D.tour.set(cb.checked)); }
        D.stack.onChange(() => { if (D.tour.lastEval) D.tour.evaluate(D.tour.lastEval); });
      },
      set(on) { D.tour.enabled = !!on; store.set('mode3.tour', on ? '1' : ''); const cb = document.getElementById('tourToggle'); if (cb) cb.checked = D.tour.enabled; if (D.tour.lastEval) D.tour.evaluate(D.tour.lastEval); },
      lock(spec) { D.tour.locks.push(spec); },
      condMet(cond) {
        const l = D.stack.last; if (!l || l.at === 0) return null;   // 모르면 잠그지 않는다
        if (cond === 'rp_approved') return l.rp ? l.rp.status === 'approved' : null;
        if (cond === 'wallet_registered') return l.wallet ? !!l.wallet.registered : null;
        if (cond === 'has_session') return (l.wallet?.sessions ?? 0) > 0 || (l.rp?.sessions ?? 0) > 0;
        return null;
      },
      evaluate({ progress = {}, links } = {}) {
        D.tour.lastEval = { progress, links };
        const l = D.stack.last, done = [];
        if (D.tour.condMet('rp_approved')) done.push('approve');
        if (D.tour.condMet('wallet_registered')) done.push('register');
        if (D.tour.condMet('has_session') || progress.login) done.push('login');
        if (progress.used) done.push('use'); if (progress.disclosed) done.push('disclose');
        if (progress.revoked || (l?.aa?.pendingLeaves ?? 0) > 0 || D.tour.epochRose) done.push('revoke');
        if (progress.opened || D.tour.openingsDrained) done.push('open');
        const order = S.steps.map((s) => s.key); const current = order.find((k) => !done.includes(k)) ?? null;
        D.guide({ done, current, links: links || D.lastGuide?.links || {} });
        D.tour.applyLocks(); D.tour.renderOverlay(current, done.length === order.length, links);
      },
      applyLocks() {
        for (const { id, cond, otherwise } of D.tour.locks) { const el = document.getElementById(id); if (!el) continue; const met = D.tour.enabled ? D.tour.condMet(cond) : true;
          const locked = D.tour.enabled && met === false; el.disabled = locked ? true : !(otherwise ? otherwise() : true);
          let badge = el.nextElementSibling?.classList?.contains('tour-lock') ? el.nextElementSibling : null;
          if (locked) { if (!badge) { badge = document.createElement('span'); badge.className = 'tour-lock badge warn'; el.after(badge); } badge.textContent = D.t(cond === 'rp_approved' ? 'tour_lock_register' : 'tour_lock_login'); } else if (badge) badge.remove(); }
      },
      renderOverlay(current, allDone, links) { /* #tourBubble 하나를 body 에 두고, enabled 아니면 제거. allDone → tour_done_*; current 의 target[D.page] 가 있으면 getBoundingClientRect 로 그 아래(≤900px 면 전폭)에 title/body/next 링크(다른 당사자면 links[where] + '?tour=1'); 없으면 #demoBar 아래 .tour-elsewhere 카드(tour_elsewhere {where}). scroll/resize 에 위치 재계산. */ },
    },
```
`epochRose`·`openingsDrained` 는 `D.stack.onChange` 안에서 이전 값과 비교해 세운다(`prev.aa.epoch < cur.aa.epoch`, `prev.aa.pendingOpenings > 0 && cur.aa.pendingOpenings === 0`). `D.init` 끝에서 `D.tour.init()` 을 부르되 `IS_AUTHORIZE`(`?authorize=1`) 면 건너뛴다(페이지가 `Demo.init({page, tour:false})` 로 알린다).
- [ ] **Step 4: CSS** — `.tour-bubble{position:absolute;z-index:20;max-width:360px;background:#1d2433;color:#fff;border-radius:10px;padding:10px 12px;font-size:14px;box-shadow:0 6px 24px rgba(0,0,0,.25)}`, `.tour-bubble::before{content:'';position:absolute;top:-6px;left:16px;border:6px solid transparent;border-bottom-color:#1d2433;border-top:0}`, `.tour-bubble a{color:#cfe0ff}`, `.tour-lock{margin-left:6px}`, `.tour-elsewhere{grid-column:1 / -1}`, `@media (max-width:900px){.tour-bubble{left:16px!important;right:16px;max-width:none}}`.
- [ ] **Step 5: 페이지 연결** — 서비스: `Demo.tour.lock({ id:'loginBtn', cond:'wallet_registered', otherwise: () => info?.status === 'approved' })`(원래 `#loginBtn` 활성 규칙을 `otherwise` 로 옮긴다 — 파일에서 그 규칙이 어디서 정해지는지 확인); `renderGuide()` 본문을 `Demo.tour.evaluate({ progress: { login: !!currentSession, used: progress.used, disclosed: progress.disclosed, opened: progress.opened }, links })` 로 교체. 지갑: `Demo.tour.lock({ id:'registerBtn', cond:'rp_approved', otherwise: () => !state.registration })` 와 `renderGuide` 위임(`progress.txOk`→`used`). 관리자·계정: `renderGuide` → `Demo.tour.evaluate({ progress: {...} , links })`(잠금 없음). 링크에 `?tour=1` 붙이기는 `D.guide` 가 `D.tour.enabled` 일 때 자동으로 한다.
- [ ] **Step 6: 검증** — `node tests/test_mode3_demo_strings.js`; 자기 노드에서 `node tests/test_mode3_browser.mjs`(체험 모드 꺼짐 기본), `node tests/test_mode3_wallet_snap.mjs`; 수동: 서비스 `?tour=1` → 로그인 잠김 배지 → 지갑 등록 → 5초 안에 풀림 → 말풍선 이동(스크린샷 scratchpad).
- [ ] **Step 7: 커밋** — `feat(mode3-ui): 체험 모드 — 스위치·?tour 전파·서버 사실 판정·앞 3단계 잠금 배지·말풍선 오버레이, renderGuide 를 Demo.tour.evaluate 로`

---

### Task 4: 체험 모드 browser 테스트 · 스크린샷 · 문서 · 전체 검증

**Files:**
- Create: `tests/test_mode3_tour.mjs`, `results/mode3_ux_20260925/`(png + README)
- Modify: `scripts/run_tests.sh`(BROWSER), `scripts/screenshot_mode3.mjs`(`--tour`), `docs/MODE3_DEMO.md`

- [ ] **Step 1: `tests/test_mode3_tour.mjs`** — `tests/test_mode3_browser.mjs` 의 Chrome 기동·`waitText` 헬퍼를 그대로 따라(file 모드 스택):

```js
await t('체험 모드: 서비스 로그인은 지갑 등록 전 잠김', async () => {
  await rpPage.goto(`${rp.base}/?tour=1`);
  await rpPage.waitForFunction(() => document.querySelector('#loginBtn')?.disabled === true, undefined, { timeout: 20_000 });
  assert.ok(await rpPage.$('.tour-lock'));
  assert.equal(new URL(rpPage.url()).search, '');   // ?tour 는 지워진다
  assert.equal(await rpPage.evaluate(() => localStorage.getItem('mode3.tour')), '1');
});
await t('지갑에서 등록하면 서비스 잠금이 풀리고 말풍선이 로그인 버튼을 가리킨다', async () => {
  await walletPage.goto(`${wallet.base}/?tour=1`);
  await walletPage.waitForFunction(() => document.querySelector('#registerBtn') && !document.querySelector('#registerBtn').disabled, undefined, { timeout: 20_000 });   // 서비스는 이미 승인됨
  await walletPage.click('#registerBtn'); await waitText(walletPage, '#registerResult', '등록됨', 30_000);
  await rpPage.waitForFunction(() => document.querySelector('#loginBtn')?.disabled === false, undefined, { timeout: 20_000 });   // 5초 폴링
  await rpPage.waitForFunction(() => document.querySelector('.tour-bubble')?.textContent.includes('로그인'), undefined, { timeout: 20_000 });
});
await t('로그인 뒤 말풍선이 4단계로 옮겨가고 상태 점 셋이 초록', async () => {
  await rpPage.click('#loginBtn'); await waitText(rpPage, '#verdict', '로그인 성공', 180_000);
  await rpPage.waitForFunction(() => (document.querySelector('.tour-bubble')?.textContent ?? '').includes('재검증') , undefined, { timeout: 20_000 });
  const levels = await rpPage.evaluate(() => [...document.querySelectorAll('.stack-dots .dot')].map((d) => d.className));
  assert.ok(levels.filter((c) => c.includes('ok')).length >= 3, levels.join(','));
});
await t('CIA 를 죽이면 AA 점이 빨강·지갑 점이 노랑', async () => {
  await stack.cia.stop();   // isolated_cia 의 stop() — CIA 프로세스만 내린다(스택 stop 은 마지막에)
  await rpPage.waitForFunction(() => document.querySelector('.stack-dots .dot.aa')?.classList.contains('bad'), undefined, { timeout: 20_000 });
  await rpPage.waitForFunction(() => document.querySelector('.stack-dots .dot.wallet')?.classList.contains('warn'), undefined, { timeout: 20_000 });
});
```
(`.dot.aa`/`.dot.wallet` 클래스는 T2 의 `renderDots` 가 역할 클래스를 붙인다는 전제 — T2 브리프와 맞춘다: 점에 `dot <role> <level>` 클래스.) `run_tests.sh` BROWSER 에 추가.
- [ ] **Step 2: `scripts/screenshot_mode3.mjs --tour`** — 로그인 전에 서비스·지갑을 `?tour=1` 로 열어 `rp-tour-locked.png`(잠김 배지), 등록 뒤 `rp-tour-bubble.png`, `wallet-tour.png`, 점을 눌러 `rp-stack-panel.png`. 출력 기본 `results/mode3_ux_20260925/` + README(날짜·명령·관찰).
- [ ] **Step 3: 문서** — `docs/MODE3_DEMO.md`: "상태 패널"(점 4개·판정 표·`/mode3/health`·CORS 허용·env `MODE3_WALLET_AGENT_ORIGIN`), "체험 모드"(스위치·`?tour=1`·잠금 규칙 표·말풍선·완료), 각본에 "체험 모드로 한 번에" 절(순서대로 클릭하면 끝나는 경로), 프로세스·포트 표에 health 경로 한 줄.
- [ ] **Step 4: 전체 검증** — `npm test`, `bash scripts/run_tests.sh contract`, `chain`, `snap`, `browser`. 실패는 그대로 보고. 포트 정리.
- [ ] **Step 5: 커밋** — `test/docs(mode3-ui): 체험 모드 browser 테스트, 2차 스크린샷·문서(상태 패널·체험 모드·health)`

---

## Self-Review

**Spec coverage** — §1.1 필드·순수 조립·민감 필드 테스트: T1. §1.2 허용 목록·헤더 직접 부착·헬퍼 env: T1(Step 5·6·7). §1.3 타임아웃·실패 표현: T2 poll(2초)·judge. §2.1 점·패널·전문가 JSON: T2. §2.2 판정 표: T2 `judge`(빨강/노랑/초록/회색 전 행). §2.3 폴링·주소·`stack.last`: T2. §3.1 스위치·`?tour`·팝업 제외: T3 `init`. §3.2 판정 표: T3 `evaluate`(epochRose·openingsDrained 포함). §3.3 잠금 표: T3 `lock/applyLocks` + 페이지 등록(서비스 loginBtn, 지갑 registerBtn; 재검증·tx 는 기존 규칙 = `otherwise`). §3.4 오버레이·완료 카드·좁은 창: T3 `renderOverlay`·CSS. §3.5 문구·테스트: T3 Step 1·2. §4 테스트: unit(T1·T2·T3), chain(T1), browser(T4), 스크린샷(T4). §5 파일: 전부 배정.

**Placeholder scan** — T3 `renderOverlay` 본문은 주석으로 동작을 명세(요소 위치·전폭·elsewhere 카드·재계산) — 코드로 옮길 사항이 전부 적혀 있음. T1 서버 스니펫의 "실제 이름은 파일에서 확인"은 지어내지 말라는 지시이며 대상 값이 명시됨.

**Type consistency** — `Demo.stack.last` 형태(`{at, aa, rp, wallet, errors}`)를 T2 정의·T3 `condMet/evaluate`·T4 테스트가 같이 씀; `lock({id, cond, otherwise})` 시그니처와 조건 키 3종이 T3 정의·페이지 연결·스펙 §3.3 과 일치; 점 클래스 `dot <role> <level>` 을 T2 CSS/렌더·T4 테스트가 공유(T2 브리프에 명시 필요 — 본문에 적었음); health 필드 이름(`registered, sessions, status, active, rootAge, maxRootAge, heartbeatBlocks, pendingLeaves, pendingOpenings, epoch, walletOrigin, rpOrigins, rpOrigin, ciaUrl`)이 T1 조립·T2 judge·T3 condMet 에서 동일.
