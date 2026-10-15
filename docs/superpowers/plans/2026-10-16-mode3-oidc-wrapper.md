# Mode 3 OIDC 래퍼(Google 로그인으로 등록·자기 폐기) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Google ID 토큰으로 Mode 3 계정을 등록하고 자기 폐기할 수 있게 한다 — IdP 가 래퍼로서 토큰을 체인 밖에서 검증하고(uid = H(provider|sub)), 회로·토큰·증명 경로는 바꾸지 않는다.

**Architecture:** 순수 유도 함수(`lib/mode3_oidc_nonce.js`: uid·nonce — 브라우저 번들에도 들어감)와 Node 전용 검증기(`lib/mode3_oidc.js`: `jose` 로 RS256·iss·aud·exp·nonce 접두어)를 나눈다. IdP(`cia.js`)의 `/cia/register`·`/cia/account/self_revoke` 가 `{ id_token }` 경로를 더 받고 `/cia/public_keys` 가 `oidc` 설정을 공개한다. 사용자 코어는 등록 재료를 미리 만들어 nonce 를 내고(`prepareRegistration`) 토큰으로 등록을 끝낸다(`completeRegistration`). 페이지는 Google Identity Services 버튼을 `localhost` 오리진에서만 그린다. 테스트는 로컬 RS256 발급자 스텁으로 같은 코드 경로를 돈다.

**Tech Stack:** jose 5.10(이미 의존성), Google Identity Services(`https://accounts.google.com/gsi/client`, 브라우저), express, Playwright + Chrome. 새 의존성 없음.

**Spec:** `docs/superpowers/specs/2026-10-16-mode3-oidc-wrapper-design.md`(커밋 45a9646). 결정 D1~D7.

## Global Constraints

- 응답·문서·주석·커밋 메시지는 한글. 기존 파일의 문체·용어(IdP·RP·사용자)를 지킨다.
- **회로·토큰·컨트랙트·RP 검증기·증명 경로 불변.** `lib/mode3_wallet.js`·`lib/mode3_idp_proof.js`·`lib/mode3_credential.js`·`mode3_wallet_agent.js`·Snap 은 고치지 않는다.
- **uid 유도는 `uid = SHA-256(provider ‖ "|" ‖ sub) mod 2^250`(10진 문자열) — 토큰의 `iss` 를 쓰지 않는다**(Google `iss` 두 형태). 검증은 `iss ∈ { issuer, issuer 에서 "https://" 를 뗀 것 }` 를 허용한다.
- **등록 토큰 nonce = `"reg:" + SHA-256(pk_u.x ‖ "|" ‖ pk_u.y)`(소문자 hex 64자, 각 값은 10진 문자열 정규형; auid 는 넣지 않는다 — Task 1 R-A, 스펙 D4 수정)**; 폐기 토큰 nonce = `"revoke:" + 32바이트 임의 hex`. IdP 는 등록에서 nonce 를 다시 계산해 **정확 일치**를 요구하고, 폐기에서는 접두어 `revoke:` 와 hex 64자 형식만 본다. 접두어가 다른 토큰은 거절(400 `oidc_nonce_mismatch`).
- IdP 는 `sub`·이메일을 저장하지 않는다. `accounts[uid].provider` 만(`'google'` | `'demo'`). 데모 계정 경로(`{ uid, pwd }`)는 바뀌지 않는다.
- IdP env: `MODE3_OIDC_ISSUER`(기본 `https://accounts.google.com`), `MODE3_OIDC_JWKS_URL`(기본 `https://www.googleapis.com/oauth2/v3/certs`), `MODE3_OIDC_CLIENT_ID`(기본 `process.env.GOOGLE_CLIENT_ID`), `MODE3_OIDC_PROVIDER`(기본 `google`). 클라이언트 ID 가 없으면 `oidc.enabled=false` 이고 `id_token` 요청은 503 `oidc_disabled`.
- 새 사유(`strings.js` reasons + `tests/test_mode3_demo_strings.js` REASONS): `oidc_disabled`(503, where aa), `oidc_invalid`(401, aa), `oidc_nonce_mismatch`(400, aa), `oidc_unavailable`(502, aa), `gsi_unavailable`(wallet), `gsi_origin`(wallet). 새 ui 키는 `user_google_*`·`rp_google_*`·`account_google_*`.
- Google 버튼은 `location.hostname === 'localhost'` 이고 `oidc.enabled` 일 때만 그린다; 아니면 안내 문구(`gsi_origin`). GIS 는 `window.google?.accounts?.id` 가 이미 있으면 스크립트를 다시 로드하지 않는다(테스트 스텁 주입 지점).
- 비밀(`s_u`·`sk_u`·금고 비밀번호·ID 토큰)은 DOM·`localStorage`·로그에 남기지 않는다. ID 토큰은 코어 호출 뒤 참조를 버린다.
- 테스트는 격리 스택만(`tests/helpers/`); 라이브 포트(3100·3101·4100·5100·8545)·사용자의 Chrome 창은 건드리지 않는다. 새 테스트는 `scripts/run_tests.sh` 의 그룹에 넣는다(unit = 외부 의존 없음(localhost HTTP 스텁은 허용), chain = :8545, browser = chain + Chrome).
- 작업 트리에 **무관한 미커밋 데모 UI 배치**가 있다(`mode3/rp.html`·`mode3/common/strings.js`·`mode3/cia_account.html`·`docs/MODE3_DEMO.md`·`tests/test_mode3_demo_strings.js` 등). 공유 파일은 `git add -p` 로 자기 hunk 만 스테이징하고 `git diff --cached` 로 확인한다. `git add -A`/`.` 금지.
- `.env`·`cia_keys.json`·`idp_state.json`·저장소 루트의 `cia_state.json`·`mode3_wallet_state.json`·`mode3_rp_registration.json` 은 읽지도 고치지도 않는다.
- 커밋은 태스크마다 하나 이상, 메시지 끝에 `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>` 와 `Claude-Session: https://claude.ai/code/session_013qGSXZTftBJSB1M4XpPRHN`. push 금지.

## 파일 구조

| 파일 | 역할 | 태스크 |
|---|---|---|
| `lib/mode3_oidc_nonce.js` | 순수 함수: `uidOf(provider, sub)`, `regNonce(pk_u)`, `newRevokeNonce()`, `isRevokeNonce(s)`, `REG_PREFIX`·`REVOKE_PREFIX`. `node:crypto` 의 `createHash`·`randomBytes` 만(브라우저 번들은 shim) | 1 |
| `lib/mode3_oidc.js` | Node 전용 검증기 `createOidcVerifier({ issuer, jwksUrl, clientId, jwks })` → `verify(idToken, { noncePrefix })`, `GOOGLE_DEFAULTS` | 2 |
| `tests/helpers/oidc_issuer_stub.mjs` | RS256 발급자 스텁(`/.well-known/jwks.json`, `POST /mint`, CORS `*`) | 2 |
| `tests/helpers/isolated_cia.mjs` | 옵션 `oidc`(스텁 기동 + env 주입, `cia.oidc` 노출) | 3 |
| `lib/mode3_cia_state.js` | `accounts[uid].provider ??= 'demo'` | 3 |
| `cia.js` | `/cia/register`·`/cia/account/self_revoke` 의 `id_token` 분기, `/cia/public_keys.oidc`, env 4개 | 3 |
| `tests/helpers/isolated_mode3_stack.mjs` | 옵션 `oidc`(격리 IdP 로 전달), `walletHost`(`'127.0.0.1'` 기본, `'localhost'` 가능 — 사용자 오리진을 세 서버에 일관되게) | 4 |
| `mode3/user/core/user_core.js` | `prepareRegistration()`, `completeRegistration()`, `selfRevokeWithIdToken()`, `status().provider`, 내부 `registerWith()` 공통화 | 4 |
| `mode3/common/gsi.js` | GIS 로드·버튼 렌더·토큰 콜백(스텁 감지) — `/common` 으로 두 서버(정적·IdP)가 함께 낸다 | 5 |
| `mode3/user/index.html`·`ui.js`·`user.js`·`popup.js` | Google 등록·Google 자기 폐기·팝업 신원 줄·미등록 안내 | 5 |
| `mode3_rp.js`·`mode3/rp.html` | `rp_info.oidc` 중계, 모달 Google 버튼 → `startIdpLogin({ provider:'google' })` | 5 |
| `mode3/cia_account.html` | Google 로 자기 폐기 | 5 |
| `mode3/common/strings.js`·`tests/test_mode3_demo_strings.js` | 새 키·사유 | 5 |
| `tests/test_mode3_oidc_nonce.js`(unit), `tests/test_mode3_oidc_verifier.mjs`(unit, 스텁 HTTP), `tests/test_cia_oidc_register.mjs`(chain), `tests/test_mode3_user_core_oidc.mjs`(chain), `tests/test_mode3_user_web_oidc.mjs`(browser) | 테스트 | 1·2·3·4·5 |
| `docs/MODE3_DEMO.md`·스펙 상태 줄·`scripts/run_tests.sh` | 런북·그룹 | 6 |

---

### Task 1: uid·nonce 순수 함수 `lib/mode3_oidc_nonce.js`

**Files:**
- Create: `lib/mode3_oidc_nonce.js`
- Test: `tests/test_mode3_oidc_nonce.js` (unit)

**Interfaces:**
- Produces: `REG_PREFIX = 'reg:'`, `REVOKE_PREFIX = 'revoke:'`, `uidOf(provider: string, sub: string): string`(10진, `< 2^250`), `regNonce(pk_u: { x, y }): string`(`'reg:' + hex64`, `SHA-256(x|y)` — auid 는 넣지 않는다: 아래 R-A), `newRevokeNonce(): string`(`'revoke:' + hex64`), `isRevokeNonce(s): boolean`, `isRegNonce(s): boolean`. 모두 동기. 입력 검사: `provider`·`sub` 는 비어 있지 않은 문자열, `pk_u.x`·`pk_u.y` 는 10진 문자열 또는 bigint(`BigInt(...)` 로 정규화 뒤 `toString()`).
- **R-A(계획 작성 중 스펙 D4 수정, 스펙에 반영됨):** 등록 nonce 는 `"reg:" + SHA-256(pk_u.x|pk_u.y)` 다. auid = Poseidon(T, uid, s_u) 는 uid(= 토큰의 `sub` 로 정해짐)가 있어야 계산되는데 nonce 는 토큰 **발급 전에** 정해져야 하므로 auid 를 넣을 수 없다. pk_u 결속만으로 "가로챈 토큰으로 다른 키 등록" 은 막힌다 — 공격자는 pk_u 의 sk_u 를 몰라 `sig_reg`(uid·auid 위 서명)를 못 만들고, 같은 pk_u 로는 등록이 하나뿐이다. auid 는 `sig_reg` 가 결속한다.
- Consumes: `node:crypto` `createHash`·`randomBytes`(브라우저는 Task 4 의 esbuild shim 이 대체 — `lib/browser/node_crypto.js` 가 둘 다 제공한다).

- [ ] **Step 1: 실패하는 테스트**

```js
// tests/test_mode3_oidc_nonce.js — OIDC 래퍼의 순수 유도 함수(스펙 2026-10-16 D3·D4). 외부 의존 없음. (unit)  node tests/test_mode3_oidc_nonce.js
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { REG_PREFIX, REVOKE_PREFIX, uidOf, regNonce, newRevokeNonce, isRevokeNonce, isRegNonce } from '../lib/mode3_oidc_nonce.js';
import { SCALAR_MAX } from '../lib/mode3_credential.js';

let fails = 0;
function t(name, fn) { try { fn(); console.log('ok   -', name); } catch (e) { fails++; console.log('FAIL -', name, '\n      ', e.message); } }
const sha = (s) => createHash('sha256').update(s, 'utf8').digest('hex');

t('uidOf: SHA-256(provider|sub) mod 2^250, 10진, 결정적, provider·sub 가 다르면 다르다', () => {
  const u = uidOf('google', '1234567890');
  assert.match(u, /^(0|[1-9][0-9]*)$/); assert.ok(BigInt(u) < SCALAR_MAX);
  assert.equal(u, (BigInt('0x' + sha('google|1234567890')) & (SCALAR_MAX - 1n)).toString());
  assert.equal(uidOf('google', '1234567890'), u);
  assert.notEqual(uidOf('google', '1234567891'), u); assert.notEqual(uidOf('naver', '1234567890'), u);
  assert.throws(() => uidOf('', 'x'), /provider/); assert.throws(() => uidOf('google', ''), /sub/); assert.throws(() => uidOf('google', 5), /sub/);
});
t('regNonce: "reg:" + sha256(x|y) — 10진·bigint 입력이 같은 값, 비정규(앞자리 0)도 정규화된다', () => {
  const n = regNonce({ x: '45', y: '67' });
  assert.equal(n, REG_PREFIX + sha('45|67')); assert.match(n, /^reg:[0-9a-f]{64}$/);
  assert.equal(regNonce({ x: 45n, y: 67n }), n);
  assert.equal(regNonce({ x: '045', y: '67' }), n);
  assert.notEqual(regNonce({ x: '46', y: '67' }), n);
  assert.throws(() => regNonce({ x: 'abc', y: '2' })); assert.throws(() => regNonce({ x: '1' })); assert.throws(() => regNonce(null));
  assert.equal(isRegNonce(n), true); assert.equal(isRegNonce('revoke:' + 'a'.repeat(64)), false);
});
t('newRevokeNonce: "revoke:" + 64 hex, 매번 다르다; isRevokeNonce 는 형식만 본다', () => {
  const a = newRevokeNonce(), b = newRevokeNonce();
  assert.match(a, /^revoke:[0-9a-f]{64}$/); assert.notEqual(a, b);
  assert.equal(isRevokeNonce(a), true); assert.equal(isRevokeNonce('revoke:' + 'g'.repeat(64)), false); assert.equal(isRevokeNonce(REG_PREFIX + 'a'.repeat(64)), false); assert.equal(isRevokeNonce(REVOKE_PREFIX), false);
});
process.exit(fails ? 1 : 0);
```

- [ ] **Step 2: 실패 확인** — `node tests/test_mode3_oidc_nonce.js` → `ERR_MODULE_NOT_FOUND`.

- [ ] **Step 3: 구현**

```js
// lib/mode3_oidc_nonce.js — OIDC 래퍼의 순수 유도 함수(스펙 2026-10-16 D3·D4). IdP(cia.js)와 브라우저 사용자 페이지가 같이 쓴다(jose 를 import 하지 않는다 —
// 브라우저 번들은 node:crypto 를 lib/browser/node_crypto.js shim 으로 받는다).
//   uid        = SHA-256(provider|sub) mod 2^250 — 토큰의 iss 는 쓰지 않는다(Google 은 iss 를 두 형태로 낸다).
//   등록 nonce = "reg:" + SHA-256(pk_u.x|pk_u.y) — 토큰을 이 공개키에 묶는다(가로챈 토큰으로 다른 키를 등록하지 못하게; auid 는 sig_reg 가 결속).
//   폐기 nonce = "revoke:" + 32바이트 임의 hex — 등록 토큰과 목적이 섞이지 않게 접두어만 다르다(재사용 = 같은 계정 재폐기, 멱등).
import { createHash, randomBytes } from 'node:crypto';
import { SCALAR_MAX } from './mode3_credential.js';

export const REG_PREFIX = 'reg:';
export const REVOKE_PREFIX = 'revoke:';
const HEX64 = /^[0-9a-f]{64}$/;
const sha256Hex = (s) => createHash('sha256').update(s, 'utf8').digest('hex');
const dec = (v, name) => {
  if (typeof v === 'bigint') { if (v < 0n) throw new Error(`${name}: 음수`); return v.toString(); }
  if (typeof v === 'string' && /^[0-9]+$/.test(v)) return BigInt(v).toString();
  throw new Error(`${name}: 10진 문자열 또는 bigint 가 필요하다`);
};

export function uidOf(provider, sub) {
  if (typeof provider !== 'string' || !provider) throw new Error('uidOf: provider 문자열이 필요하다');
  if (typeof sub !== 'string' || !sub) throw new Error('uidOf: sub 문자열이 필요하다');
  return (BigInt('0x' + sha256Hex(`${provider}|${sub}`)) & (SCALAR_MAX - 1n)).toString();
}
/** 등록 토큰의 nonce — 토큰을 이 공개키에 묶는다(스펙 D4, R-A: auid 는 토큰 발급 전에 알 수 없어 넣지 않는다 — sig_reg 가 결속한다). */
export function regNonce(pk_u) {
  if (!pk_u || typeof pk_u !== 'object') throw new Error('regNonce: pk_u{x,y} 가 필요하다');
  return REG_PREFIX + sha256Hex(`${dec(pk_u.x, 'pk_u.x')}|${dec(pk_u.y, 'pk_u.y')}`);
}
export function newRevokeNonce() { return REVOKE_PREFIX + randomBytes(32).toString('hex'); }
export const isRegNonce = (s) => typeof s === 'string' && s.startsWith(REG_PREFIX) && HEX64.test(s.slice(REG_PREFIX.length));
export const isRevokeNonce = (s) => typeof s === 'string' && s.startsWith(REVOKE_PREFIX) && HEX64.test(s.slice(REVOKE_PREFIX.length));
```

- [ ] **Step 4: 통과 확인** — `node tests/test_mode3_oidc_nonce.js` 3개 ok.
- [ ] **Step 5: `scripts/run_tests.sh` UNIT 배열 끝(`tests/test_browser_node_shims.js` 다음)에 `tests/test_mode3_oidc_nonce.js` 추가. 커밋** — `feat(oidc): uid·nonce 순수 유도 함수(lib/mode3_oidc_nonce.js)`.

---

### Task 2: 검증기 `lib/mode3_oidc.js` 와 발급자 스텁

**Files:**
- Create: `lib/mode3_oidc.js`, `tests/helpers/oidc_issuer_stub.mjs`
- Test: `tests/test_mode3_oidc_verifier.mjs` (unit — localhost HTTP 스텁만 쓴다)

**Interfaces:**
- Produces(`lib/mode3_oidc.js`): `GOOGLE_DEFAULTS = { issuer: 'https://accounts.google.com', jwksUrl: 'https://www.googleapis.com/oauth2/v3/certs', provider: 'google' }`; `createOidcVerifier({ issuer, jwksUrl, clientId, jwks = null, clockToleranceSec = 60 })` → `{ issuer, clientId, verify(idToken, { noncePrefix }) }`. `verify` 는 `jose.jwtVerify(idToken, jwks ?? createRemoteJWKSet(new URL(jwksUrl)), { algorithms: ['RS256'], issuer: [issuer, issuer.replace(/^https:\/\//, '')], audience: clientId, clockTolerance: clockToleranceSec })` → `payload.sub` 가 비어 있지 않은 문자열이고 `payload.nonce` 가 문자열이며 `noncePrefix` 로 시작해야 한다 → `{ sub, nonce, iss: payload.iss }`. 실패는 `Error{ reason, detail }`: 형식(문자열 아님·JWT 세 조각 아님) → `oidc_invalid`(detail `'format'`); jose 의 `JWTExpired`·`JWSSignatureVerificationFailed`·`JWTClaimValidationFailed`·`JOSEAlgNotAllowed`·`JWSInvalid`·`JWTInvalid` → `oidc_invalid`(detail = `e.code`, 예 `ERR_JWT_EXPIRED`); nonce 접두어 불일치·nonce 없음 → `oidc_nonce_mismatch`; JWKS 를 못 받음(`JWKSTimeout`, `JWKSNoMatchingKey` 포함 `ERR_JWKS_*`, `TypeError`(fetch 실패)) → `oidc_unavailable`(detail 메시지).
- Produces(스텁): `startOidcIssuerStub({ clientId = 'mode3-test-client', provider = 'stub' } = {})` → `{ base, issuer: base, jwksUrl: `${base}/.well-known/jwks.json`, clientId, provider, mint({ sub, nonce, aud = clientId, iss = base, expSeconds = 300, extra = {} }) → Promise<string>, stop() }`. HTTP 서버(`node:http`, 127.0.0.1 임시 포트): `GET /.well-known/jwks.json` → `{ keys: [공개 JWK + kid + alg 'RS256' + use 'sig'] }`; `POST /mint`(JSON 본문 = mint 인자) → `{ id_token }`; 모든 응답에 `Access-Control-Allow-Origin: *`·`Access-Control-Allow-Headers: Content-Type`, `OPTIONS` 204 (Task 5 의 브라우저 스텁이 페이지에서 직접 부른다). 키는 `jose.generateKeyPair('RS256')` 로 기동마다 새로.
- Consumes: Task 1 의 `isRegNonce`/`isRevokeNonce` 는 쓰지 않는다(접두어 검사는 호출자가 넘기는 `noncePrefix` 로).

- [ ] **Step 1: 실패하는 테스트**

```js
// tests/test_mode3_oidc_verifier.mjs — OIDC 검증기(스펙 2026-10-16 §2 lib/mode3_oidc.js) + RS256 발급자 스텁. localhost HTTP 만 쓴다. (unit)
import assert from 'node:assert/strict';
import { SignJWT, generateKeyPair, exportJWK, createLocalJWKSet } from 'jose';
import { createOidcVerifier, GOOGLE_DEFAULTS } from '../lib/mode3_oidc.js';
import { startOidcIssuerStub } from './helpers/oidc_issuer_stub.mjs';

let fails = 0;
async function t(name, fn) { try { await fn(); console.log('ok   -', name); } catch (e) { fails++; console.log('FAIL -', name, '\n      ', e.stack ?? e.message); } }
const expectReason = async (p, reason, detailRe = null) => { try { await p; assert.fail(`${reason} 를 기대했는데 통과했다`); } catch (e) { assert.equal(e.reason, reason, `reason: ${e.reason} (${e.detail ?? e.message})`); if (detailRe) assert.match(String(e.detail), detailRe); } };

const stub = await startOidcIssuerStub({ clientId: 'cid-1' });
try {
  await t('GOOGLE_DEFAULTS 는 Google 의 iss·JWKS URL·provider 다', () => {
    assert.deepEqual(GOOGLE_DEFAULTS, { issuer: 'https://accounts.google.com', jwksUrl: 'https://www.googleapis.com/oauth2/v3/certs', provider: 'google' });
  });
  await t('스텁: JWKS 를 내고(CORS *), mint 한 토큰을 원격 JWKS 로 검증한다 — sub·nonce·iss 를 돌려준다', async () => {
    const r = await fetch(stub.jwksUrl); assert.equal(r.status, 200); assert.equal(r.headers.get('access-control-allow-origin'), '*');
    const jwks = await r.json(); assert.equal(jwks.keys.length, 1); assert.equal(jwks.keys[0].alg, 'RS256'); assert.ok(jwks.keys[0].kid);
    const v = createOidcVerifier({ issuer: stub.issuer, jwksUrl: stub.jwksUrl, clientId: 'cid-1' });
    const token = await stub.mint({ sub: 'user-1', nonce: 'reg:' + 'a'.repeat(64) });
    const out = await v.verify(token, { noncePrefix: 'reg:' });
    assert.deepEqual(out, { sub: 'user-1', nonce: 'reg:' + 'a'.repeat(64), iss: stub.issuer });
    const viaHttp = await (await fetch(`${stub.base}/mint`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ sub: 'user-2', nonce: 'revoke:' + 'b'.repeat(64) }) })).json();
    assert.deepEqual(await v.verify(viaHttp.id_token, { noncePrefix: 'revoke:' }), { sub: 'user-2', nonce: 'revoke:' + 'b'.repeat(64), iss: stub.issuer });
  });
  await t('iss 두 형태: https:// 를 뗀 iss 도 통과한다(Google 호환)', async () => {
    const v = createOidcVerifier({ issuer: 'https://accounts.example', jwksUrl: stub.jwksUrl, clientId: 'cid-1' });
    const ok1 = await stub.mint({ sub: 's', nonce: 'reg:' + 'c'.repeat(64), iss: 'https://accounts.example' });
    const ok2 = await stub.mint({ sub: 's', nonce: 'reg:' + 'c'.repeat(64), iss: 'accounts.example' });
    assert.equal((await v.verify(ok1, { noncePrefix: 'reg:' })).iss, 'https://accounts.example');
    assert.equal((await v.verify(ok2, { noncePrefix: 'reg:' })).iss, 'accounts.example');
    await expectReason(v.verify(await stub.mint({ sub: 's', nonce: 'reg:x', iss: 'https://other.example' }), { noncePrefix: 'reg:' }), 'oidc_invalid', /ERR_JWT_CLAIM_VALIDATION_FAILED/);
  });
  await t('거절: 다른 aud·만료·서명 위조·형식 → oidc_invalid(detail 에 jose 코드), nonce 접두어 불일치·nonce 없음 → oidc_nonce_mismatch', async () => {
    const v = createOidcVerifier({ issuer: stub.issuer, jwksUrl: stub.jwksUrl, clientId: 'cid-1' });
    await expectReason(v.verify(await stub.mint({ sub: 's', nonce: 'reg:n', aud: 'cid-2' }), { noncePrefix: 'reg:' }), 'oidc_invalid', /ERR_JWT_CLAIM_VALIDATION_FAILED/);
    await expectReason(v.verify(await stub.mint({ sub: 's', nonce: 'reg:n', expSeconds: -120 }), { noncePrefix: 'reg:' }), 'oidc_invalid', /ERR_JWT_EXPIRED/);
    const { privateKey } = await generateKeyPair('RS256');
    const forged = await new SignJWT({ sub: 's', nonce: 'reg:n' }).setProtectedHeader({ alg: 'RS256', kid: 'other' }).setIssuer(stub.issuer).setAudience('cid-1').setIssuedAt().setExpirationTime('5m').sign(privateKey);
    await expectReason(v.verify(forged, { noncePrefix: 'reg:' }), 'oidc_invalid');   // JWKS 에 그 kid 가 없다 — JWKSNoMatchingKey(jose 가 JWKS 를 한 번 다시 받아본 뒤다) = 발급자가 공개하지 않은 키로 서명된 토큰 → 무효(R2)
    await expectReason(v.verify('not-a-jwt', { noncePrefix: 'reg:' }), 'oidc_invalid', /format/);
    await expectReason(v.verify(12, { noncePrefix: 'reg:' }), 'oidc_invalid', /format/);
    await expectReason(v.verify(await stub.mint({ sub: 's', nonce: 'revoke:' + 'd'.repeat(64) }), { noncePrefix: 'reg:' }), 'oidc_nonce_mismatch');
    await expectReason(v.verify(await stub.mint({ sub: 's', nonce: undefined }), { noncePrefix: 'reg:' }), 'oidc_nonce_mismatch');
    await expectReason(v.verify(await stub.mint({ sub: '', nonce: 'reg:n' }), { noncePrefix: 'reg:' }), 'oidc_invalid', /sub/);
  });
  await t('로컬 JWKS 주입(jwks 인자)과 JWKS 서버 불가(oidc_unavailable)', async () => {
    const { publicKey, privateKey } = await generateKeyPair('RS256');
    const jwk = { ...(await exportJWK(publicKey)), kid: 'k1', alg: 'RS256', use: 'sig' };
    const v = createOidcVerifier({ issuer: 'https://accounts.google.com', jwksUrl: 'https://127.0.0.1:1/never', clientId: 'cid-1', jwks: createLocalJWKSet({ keys: [jwk] }) });
    const token = await new SignJWT({ sub: 'g-1', nonce: 'reg:' + 'e'.repeat(64) }).setProtectedHeader({ alg: 'RS256', kid: 'k1' }).setIssuer('accounts.google.com').setAudience('cid-1').setIssuedAt().setExpirationTime('5m').sign(privateKey);
    assert.equal((await v.verify(token, { noncePrefix: 'reg:' })).sub, 'g-1');
    const down = createOidcVerifier({ issuer: stub.issuer, jwksUrl: 'http://127.0.0.1:1/jwks', clientId: 'cid-1' });
    await expectReason(down.verify(await stub.mint({ sub: 's', nonce: 'reg:n' }), { noncePrefix: 'reg:' }), 'oidc_unavailable');
  });
} finally { await stub.stop(); }
process.exit(fails ? 1 : 0);
```

- [ ] **Step 2: 실패 확인** — `node tests/test_mode3_oidc_verifier.mjs` → `ERR_MODULE_NOT_FOUND`.

- [ ] **Step 3: 구현**

```js
// lib/mode3_oidc.js — OIDC 래퍼의 토큰 검증기(스펙 2026-10-16 §2). Node 전용(jose). IdP(cia.js)만 쓴다 — Google ID 토큰(RS256)을 체인 밖에서 검증하고
// sub·nonce 만 돌려준다. uid 유도·nonce 계산은 lib/mode3_oidc_nonce.js(브라우저도 쓰는 순수 함수)에 있다.
import { createRemoteJWKSet, jwtVerify, errors as joseErrors } from 'jose';

export const GOOGLE_DEFAULTS = Object.freeze({ issuer: 'https://accounts.google.com', jwksUrl: 'https://www.googleapis.com/oauth2/v3/certs', provider: 'google' });
const tagged = (reason, detail) => Object.assign(new Error(`${reason}: ${detail}`), { reason, detail });
const isJwtShape = (t) => typeof t === 'string' && /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(t);

export function createOidcVerifier({ issuer, jwksUrl, clientId, jwks = null, clockToleranceSec = 60 }) {
  if (typeof issuer !== 'string' || !issuer) throw new Error('createOidcVerifier: issuer 가 필요하다');
  if (typeof clientId !== 'string' || !clientId) throw new Error('createOidcVerifier: clientId 가 필요하다');
  if (!jwks && (typeof jwksUrl !== 'string' || !jwksUrl)) throw new Error('createOidcVerifier: jwksUrl 또는 jwks 가 필요하다');
  const keySet = jwks ?? createRemoteJWKSet(new URL(jwksUrl));
  // Google 은 iss 를 "https://accounts.google.com" 또는 "accounts.google.com" 으로 낸다 — 둘 다 받는다(uid 유도에는 iss 를 쓰지 않는다, D3).
  const issuers = [...new Set([issuer, issuer.replace(/^https:\/\//, '')])];
  return {
    issuer, clientId,
    async verify(idToken, { noncePrefix }) {
      if (typeof noncePrefix !== 'string' || !noncePrefix) throw new Error('verify: noncePrefix 가 필요하다');
      if (!isJwtShape(idToken)) throw tagged('oidc_invalid', 'format');
      let payload;
      try {
        ({ payload } = await jwtVerify(idToken, keySet, { algorithms: ['RS256'], issuer: issuers, audience: clientId, clockTolerance: clockToleranceSec }));
      } catch (e) {
        // 발급자에 닿지 못한 것(타임아웃·연결 거부·fetch TypeError)과 키 집합이 모호한 것만 '불가'. 모르는 kid 는 jose 가 JWKS 를 다시 받아본 뒤에도
        // 없는 것이므로 '무효'(R2 — 위조 토큰을 502 로 보고하면 재시도만 부른다). detail 은 코드명/클래스명만(e.message 는 쓰지 않는다).
        if (e instanceof joseErrors.JWKSTimeout || e instanceof joseErrors.JWKSMultipleMatchingKeys || e instanceof TypeError || e?.code === 'ECONNREFUSED' || e?.cause?.code === 'ECONNREFUSED') {
          throw tagged('oidc_unavailable', e.code ?? e.name ?? 'fetch_failed');
        }
        throw tagged('oidc_invalid', e.code ?? e.name);   // 만료·서명·aud·iss·alg·형식
      }
      if (typeof payload.sub !== 'string' || !payload.sub) throw tagged('oidc_invalid', 'sub 없음');
      if (typeof payload.nonce !== 'string' || !payload.nonce.startsWith(noncePrefix)) throw tagged('oidc_nonce_mismatch', `nonce 접두어 ${noncePrefix} 아님`);
      return { sub: payload.sub, nonce: payload.nonce, iss: payload.iss };
    },
  };
}
```

```js
// tests/helpers/oidc_issuer_stub.mjs — 테스트용 RS256 OIDC 발급자(스펙 2026-10-16 D7). JWKS 와 토큰 발행만 한다. 모든 응답에 CORS * —
// 브라우저 테스트의 GIS 스텁이 페이지에서 직접 /mint 를 부른다. 기동마다 새 키.
import http from 'node:http';
import { SignJWT, generateKeyPair, exportJWK } from 'jose';

export async function startOidcIssuerStub({ clientId = 'mode3-test-client', provider = 'stub' } = {}) {
  const { publicKey, privateKey } = await generateKeyPair('RS256');
  const kid = 'stub-' + Date.now().toString(36);
  const jwk = { ...(await exportJWK(publicKey)), kid, alg: 'RS256', use: 'sig' };
  let base = null;
  async function mint({ sub, nonce, aud = clientId, iss = base, expSeconds = 300, extra = {} }) {
    const now = Math.floor(Date.now() / 1000);
    const claims = { sub, ...(nonce === undefined ? {} : { nonce }), ...extra };
    return new SignJWT(claims).setProtectedHeader({ alg: 'RS256', kid }).setIssuer(iss).setAudience(aud).setIssuedAt(now).setExpirationTime(now + expSeconds).sign(privateKey);
  }
  const server = http.createServer(async (req, res) => {
    const cors = { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Content-Type', 'Access-Control-Allow-Methods': 'GET, POST, OPTIONS' };
    if (req.method === 'OPTIONS') { res.writeHead(204, cors); return res.end(); }
    if (req.method === 'GET' && req.url === '/.well-known/jwks.json') { res.writeHead(200, { ...cors, 'Content-Type': 'application/json' }); return res.end(JSON.stringify({ keys: [jwk] })); }
    if (req.method === 'POST' && req.url === '/mint') {
      let body = ''; for await (const c of req) body += c;
      try { const id_token = await mint(JSON.parse(body || '{}')); res.writeHead(200, { ...cors, 'Content-Type': 'application/json' }); return res.end(JSON.stringify({ id_token })); }
      catch (e) { res.writeHead(400, { ...cors, 'Content-Type': 'application/json' }); return res.end(JSON.stringify({ error: e.message })); }
    }
    res.writeHead(404, cors); res.end();
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${server.address().port}`;
  return { base, issuer: base, jwksUrl: `${base}/.well-known/jwks.json`, clientId, provider, mint, stop: () => new Promise((r) => server.close(() => r())) };
}
```

- [ ] **Step 4: 통과 확인** — `node tests/test_mode3_oidc_verifier.mjs` 5개 ok. jose 의 실제 오류 클래스·코드가 위 매핑과 다르면(예: 서명 위조가 `JWKSNoMatchingKey` 가 아니라 `JWSSignatureVerificationFailed` 로 오는 경우) **테스트의 기대 사유를 바꾸지 말고** 매핑을 jose 의 실제 동작에 맞춰 고치되, 원칙은 유지한다: "키를 찾지 못함/JWKS 못 받음 = `oidc_unavailable`, 그 밖 검증 실패 = `oidc_invalid`". 보고서에 실제 코드명을 적는다.
- [ ] **Step 5: UNIT 배열에 `tests/test_mode3_oidc_verifier.mjs` 추가(`tests/test_mode3_oidc_nonce.js` 다음). 커밋** — `feat(oidc): jose 검증기(lib/mode3_oidc.js)와 RS256 발급자 스텁`.

---
### Task 3: IdP — `id_token` 등록·자기 폐기, `public_keys.oidc`, 격리 IdP 의 `oidc` 옵션

**Files:**
- Modify: `cia.js` (env 4개·검증기 생성, `/cia/public_keys`, `/cia/register`, `/cia/account/self_revoke`)
- Modify: `lib/mode3_cia_state.js` (`a.provider ??= 'demo'`), `tests/test_mode3_cia_state.js` (케이스 1개 추가)
- Modify: `tests/helpers/isolated_cia.mjs` (옵션 `oidc`)
- Test: `tests/test_cia_oidc_register.mjs` (chain)

**Interfaces:**
- Produces(IdP):
  - env `MODE3_OIDC_ISSUER`·`MODE3_OIDC_JWKS_URL`·`MODE3_OIDC_CLIENT_ID`(기본 `process.env.GOOGLE_CLIENT_ID`)·`MODE3_OIDC_PROVIDER`. `const OIDC = clientId ? { enabled: true, provider, issuer, jwksUrl, clientId, verifier: createOidcVerifier({ issuer, jwksUrl, clientId }) } : { enabled: false, provider, issuer, jwksUrl, clientId: null, verifier: null }`.
  - `GET /cia/public_keys` 응답에 `oidc: { enabled, provider, clientId, issuer }`(clientId 는 공개 값).
  - `POST /cia/register` 본문 두 모양: `{ uid, pwd, auid, pk_u, sig_reg }`(기존, 불변) 또는 `{ id_token, auid, pk_u, sig_reg }`. `id_token` 경로: `!OIDC.enabled` → 503 `{ error:'oidc_disabled', reason:'oidc_disabled' }`; `verify(id_token, { noncePrefix: REG_PREFIX })` 실패 → `e.reason` 그대로(`oidc_invalid` 401, `oidc_nonce_mismatch` 400, `oidc_unavailable` 502; 본문 `{ error: reason, reason, detail }`); `nonce !== regNonce(pk_u)` → 400 `oidc_nonce_mismatch`; `uid = uidOf(OIDC.provider, sub)`; 이후 기존 검사(`already registered` 409, auid 범위, pk_u 점, `sig_reg` = `registerMessage(uid, auid)` 위 서명 — **지갑은 uid 를 아직 모르므로 어떻게 서명하나?** → 아래 "uid 선계산" 참조). 계정에 `provider: OIDC.provider`; 응답 201 `{ slot, schemaHash, uid, provider }`. 데모 경로의 응답에도 `uid`(요청값)·`provider:'demo'` 를 더한다(기존 키는 그대로).
  - **uid 선계산(설계 보완, 스펙 §3.1 4단계의 구현 세부).** `sig_reg` 는 `Poseidon(D_REGISTER_V2, uid, auid)` 위 서명이라 지갑이 uid 를 알아야 한다. 지갑은 ID 토큰을 받은 뒤 **토큰 payload 의 `sub` 를 디코드해(서명 검증 없이, base64url) `uidOf(provider, sub)` 를 스스로 계산**하고 그 uid 로 서명한다. IdP 는 자기가 검증한 `sub` 로 다시 uid 를 계산해 서명을 검증하므로, 지갑이 다른 uid 로 서명했으면 `bad_registration_signature` 다. 지갑이 쓸 `provider` 는 `/cia/public_keys.oidc.provider` 다.
  - `POST /cia/account/self_revoke` 본문 `{ uid, pwd }`(기존) 또는 `{ id_token }`: `verify(id_token, { noncePrefix: REVOKE_PREFIX })` → `isRevokeNonce(nonce)` 아니면 400 `oidc_nonce_mismatch` → `uid = uidOf(provider, sub)` → 계정 없음 404 → `revokeAccount(uid)`.
- Produces(헬퍼): `startIsolatedCia({ oidc: true | { clientId, provider } })` → 스텁을 먼저 띄우고 env `MODE3_OIDC_ISSUER=stub.issuer`, `MODE3_OIDC_JWKS_URL=stub.jwksUrl`, `MODE3_OIDC_CLIENT_ID=stub.clientId`, `MODE3_OIDC_PROVIDER=stub.provider` 를 넣는다; 반환 객체에 `oidc: stub`(`mint`·`stop` 포함); `stop()` 이 스텁도 내린다. 옵션이 없으면 env 를 **빈 문자열로 고정**(`MODE3_OIDC_CLIENT_ID: ''` 등 — `.env` 의 `GOOGLE_CLIENT_ID` 가 새어 들어와 테스트 IdP 가 Google 을 켜지 않게; cia.js 의 env 읽기는 빈 문자열을 "없음"으로 본다).
- Produces(상태): `lib/mode3_cia_state.js` `migrateCiaState` 가 `a.provider ??= 'demo'`(v12 유지, 이행 아님).
- Consumes: Task 1 `uidOf`·`regNonce`·`isRevokeNonce`·`REG_PREFIX`·`REVOKE_PREFIX`; Task 2 `createOidcVerifier`·`GOOGLE_DEFAULTS`·`startOidcIssuerStub`.

- [ ] **Step 1: 실패하는 테스트**

```js
// tests/test_cia_oidc_register.mjs — IdP 의 OIDC 래퍼 경로(스펙 2026-10-16 §3.1·§3.3). 격리 IdP + 발급자 스텁. :8545 필요(로그 배포). (chain)
import assert from 'node:assert/strict';
import { startIsolatedCia } from './helpers/isolated_cia.mjs';
import { createRegistration, signRegistration } from '../lib/mode3_wallet.js';
import { uidOf, regNonce, newRevokeNonce } from '../lib/mode3_oidc_nonce.js';

const cia = await startIsolatedCia({ oidc: true });
const stub = cia.oidc;
let fails = 0; async function t(n, f) { try { await f(); console.log('ok   -', n); } catch (e) { fails++; console.log('FAIL -', n, '\n      ', e.stack ?? e.message); } }
const j = (o) => JSON.stringify(o);
/** 지갑이 하는 일을 흉내: 재료 → sub 에서 uid 선계산 → 등록 토큰(nonce = regNonce) → 서명. */
async function makeReg(sub, { nonce = null, aud, iss, expSeconds } = {}) {
  const reg = await createRegistration(0n);   // s_u·sk_u·pk_u 만 쓴다 — auid 는 진짜 uid 로 다시 만든다
  const uid = uidOf(stub.provider, sub);
  const { auidOf } = await import('../lib/mode3_credential.js');
  const auid = await auidOf({ uid: BigInt(uid), s_u: reg.s_u });
  const pk_u = { x: reg.pk_u.x.toString(), y: reg.pk_u.y.toString() };
  const id_token = await stub.mint({ sub, nonce: nonce ?? regNonce(pk_u), ...(aud ? { aud } : {}), ...(iss ? { iss } : {}), ...(expSeconds ? { expSeconds } : {}) });
  return { uid, auid: auid.toString(), pk_u, sig_reg: await signRegistration(reg.sk_u, BigInt(uid), auid), id_token, sk_u: reg.sk_u };
}
try {
  await t('public_keys.oidc 가 스텁 발급자 설정을 공개한다(enabled·provider·clientId·issuer)', async () => {
    const k = (await cia.get('/cia/public_keys')).body;
    assert.deepEqual(k.oidc, { enabled: true, provider: stub.provider, clientId: stub.clientId, issuer: stub.issuer });
  });
  let first;
  await t('Google 경로 등록: 201, uid = uidOf(provider, sub), provider 기록, 데모 계정 경로와 같은 슬롯 배정', async () => {
    first = await makeReg('google-sub-1');
    const r = await cia.post('/cia/register', { id_token: first.id_token, auid: first.auid, pk_u: first.pk_u, sig_reg: first.sig_reg });
    assert.equal(r.status, 201, j(r.body)); assert.equal(r.body.uid, first.uid); assert.equal(r.body.provider, stub.provider); assert.equal(typeof r.body.slot, 'number'); assert.ok(r.body.schemaHash);
    const acc = (await cia.adminGet('/cia/accounts')).body;
    const mine = (acc.accounts ?? acc).find((a) => String(a.uid) === first.uid); assert.ok(mine, j(acc).slice(0, 200)); assert.equal(mine.provider, stub.provider);
  });
  await t('같은 sub 의 재등록은 409 already registered(토큰·키 재료가 새것이어도)', async () => {
    const again = await makeReg('google-sub-1');
    const r = await cia.post('/cia/register', { id_token: again.id_token, auid: again.auid, pk_u: again.pk_u, sig_reg: again.sig_reg });
    assert.equal(r.status, 409);
  });
  await t('nonce 가 요청의 pk_u 와 다르면 400 oidc_nonce_mismatch — 가로챈 토큰을 다른 키로 쓰는 재사용 차단', async () => {
    const a = await makeReg('google-sub-2');
    const b = await makeReg('google-sub-2');   // 다른 키 재료
    const r = await cia.post('/cia/register', { id_token: a.id_token, auid: b.auid, pk_u: b.pk_u, sig_reg: b.sig_reg });
    assert.equal(r.status, 400); assert.equal(r.body.reason, 'oidc_nonce_mismatch');
  });
  await t('폐기 토큰(revoke:)으로 등록 → 400 oidc_nonce_mismatch; 다른 aud → 401 oidc_invalid; 만료 → 401 oidc_invalid', async () => {
    const x = await makeReg('google-sub-3', { nonce: newRevokeNonce() });
    let r = await cia.post('/cia/register', { id_token: x.id_token, auid: x.auid, pk_u: x.pk_u, sig_reg: x.sig_reg }); assert.equal(r.status, 400); assert.equal(r.body.reason, 'oidc_nonce_mismatch');
    const y = await makeReg('google-sub-3', { aud: 'someone-else' });
    r = await cia.post('/cia/register', { id_token: y.id_token, auid: y.auid, pk_u: y.pk_u, sig_reg: y.sig_reg }); assert.equal(r.status, 401); assert.equal(r.body.reason, 'oidc_invalid');
    const z = await makeReg('google-sub-3', { expSeconds: -600 });
    r = await cia.post('/cia/register', { id_token: z.id_token, auid: z.auid, pk_u: z.pk_u, sig_reg: z.sig_reg }); assert.equal(r.status, 401); assert.equal(r.body.reason, 'oidc_invalid');
  });
  await t('지갑이 uid 를 잘못 선계산해 서명했으면 400 bad_registration_signature', async () => {
    const w = await makeReg('google-sub-4');
    const { signRegistration: sr } = await import('../lib/mode3_wallet.js');
    const wrongSig = await sr(w.sk_u, BigInt(w.uid) + 1n, BigInt(w.auid));
    const r = await cia.post('/cia/register', { id_token: w.id_token, auid: w.auid, pk_u: w.pk_u, sig_reg: wrongSig });
    assert.equal(r.status, 400); assert.equal(r.body.error, 'bad_registration_signature');
  });
  await t('자기 폐기(id_token): revoke 토큰 → 200, 계정 disabled; 등록 토큰으로 폐기 → 400; 모르는 sub → 404', async () => {
    const tok = await stub.mint({ sub: 'google-sub-1', nonce: newRevokeNonce() });
    const r = await cia.post('/cia/account/self_revoke', { id_token: tok }); assert.equal(r.status, 200, j(r.body));
    const acc = (await cia.adminGet('/cia/accounts')).body; const mine = (acc.accounts ?? acc).find((a) => String(a.uid) === first.uid); assert.equal(mine.disabled, true);
    const regTok = await stub.mint({ sub: 'google-sub-1', nonce: regNonce(first.pk_u) });
    assert.equal((await cia.post('/cia/account/self_revoke', { id_token: regTok })).status, 400);
    assert.equal((await cia.post('/cia/account/self_revoke', { id_token: await stub.mint({ sub: 'never-registered', nonce: newRevokeNonce() }) })).status, 404);
  });
  await t('데모 계정 경로는 그대로(uid·pwd 등록 201 + 응답에 uid·provider demo; 비밀번호 틀리면 401)', async () => {
    const reg = await createRegistration(12345n);
    const r = await cia.post('/cia/register', { uid: '12345', pwd: 'password123', auid: reg.auid.toString(), pk_u: { x: reg.pk_u.x.toString(), y: reg.pk_u.y.toString() }, sig_reg: await signRegistration(reg.sk_u, 12345n, reg.auid) });
    assert.equal(r.status, 201, j(r.body)); assert.equal(r.body.uid, '12345'); assert.equal(r.body.provider, 'demo');
    const reg2 = await createRegistration(67890n);
    assert.equal((await cia.post('/cia/register', { uid: '67890', pwd: 'wrong', auid: reg2.auid.toString(), pk_u: { x: reg2.pk_u.x.toString(), y: reg2.pk_u.y.toString() }, sig_reg: await signRegistration(reg2.sk_u, 67890n, reg2.auid) })).status, 401);
  });
  await t('형식: id_token 과 uid/pwd 가 둘 다 없으면 400; 둘 다 있으면 id_token 을 우선하지 않고 400(모호)', async () => {
    assert.equal((await cia.post('/cia/register', { auid: '1', pk_u: { x: '1', y: '1' }, sig_reg: { R8x: '1', R8y: '1', S: '1' } })).status, 400);
    const w = await makeReg('google-sub-5');
    assert.equal((await cia.post('/cia/register', { id_token: w.id_token, uid: '12345', pwd: 'password123', auid: w.auid, pk_u: w.pk_u, sig_reg: w.sig_reg })).status, 400);
  });
} finally { await cia.stop(); }
// oidc 를 끈 IdP: id_token 경로는 503 oidc_disabled, public_keys.oidc.enabled=false
const off = await startIsolatedCia();
try {
  await t('OIDC 설정이 없는 IdP: public_keys.oidc.enabled=false, id_token 등록·폐기는 503 oidc_disabled', async () => {
    const k = (await off.get('/cia/public_keys')).body; assert.equal(k.oidc.enabled, false); assert.equal(k.oidc.clientId, null);
    const r = await off.post('/cia/register', { id_token: 'a.b.c', auid: '1', pk_u: { x: '1', y: '1' }, sig_reg: { R8x: '1', R8y: '1', S: '1' } }); assert.equal(r.status, 503); assert.equal(r.body.reason, 'oidc_disabled');
    assert.equal((await off.post('/cia/account/self_revoke', { id_token: 'a.b.c' })).status, 503);
  });
} finally { await off.stop(); }
process.exit(fails ? 1 : 0);
```
(`/cia/accounts` 의 응답 모양은 `cia.js` 의 관리자 라우트를 읽어 맞춘다 — 배열인지 `{ accounts }` 인지에 따라 위 `acc.accounts ?? acc` 가 둘 다 받는다. 계정 항목에 `provider`·`disabled`·`uid` 가 실리도록 그 라우트의 뷰 함수에 `provider` 를 더한다.)

- [ ] **Step 2: 실패 확인** — `node tests/test_cia_oidc_register.mjs` → 헬퍼가 `oidc` 를 몰라 `cia.oidc` 가 undefined 로 첫 케이스에서 TypeError.

- [ ] **Step 3: 헬퍼** — `tests/helpers/isolated_cia.mjs`: `startIsolatedCia(opts)` 에서 `const { oidc = null } = opts;` → `let stub = null; if (oidc) { const { startOidcIssuerStub } = await import('./oidc_issuer_stub.mjs'); stub = await startOidcIssuerStub(typeof oidc === 'object' ? oidc : {}); }`; env 에 `MODE3_OIDC_ISSUER: stub?.issuer ?? ''`, `MODE3_OIDC_JWKS_URL: stub?.jwksUrl ?? ''`, `MODE3_OIDC_CLIENT_ID: stub?.clientId ?? ''`, `MODE3_OIDC_PROVIDER: stub?.provider ?? ''`(빈 문자열 = `.env` 의 값 차단); 반환에 `oidc: stub`; `stop()` 에 `if (stub) await stub.stop();`.

- [ ] **Step 4: IdP 구현** — `cia.js`:
  - import: `import { createOidcVerifier, GOOGLE_DEFAULTS } from './lib/mode3_oidc.js'; import { uidOf, regNonce, isRevokeNonce, REG_PREFIX, REVOKE_PREFIX } from './lib/mode3_oidc_nonce.js';`
  - `WALLET_AGENT_ORIGIN` 아래에:
    ```js
    // OIDC 래퍼(스펙 2026-10-16): Google ID 토큰을 체인 밖에서 검증해 계정을 만든다. 클라이언트 ID 가 없으면 꺼진다(데모 계정만).
    const envStr = (k, d) => (process.env[k] === undefined || process.env[k] === '' ? d : process.env[k]);
    const OIDC_PROVIDER = envStr('MODE3_OIDC_PROVIDER', GOOGLE_DEFAULTS.provider), OIDC_ISSUER = envStr('MODE3_OIDC_ISSUER', GOOGLE_DEFAULTS.issuer), OIDC_JWKS_URL = envStr('MODE3_OIDC_JWKS_URL', GOOGLE_DEFAULTS.jwksUrl), OIDC_CLIENT_ID = envStr('MODE3_OIDC_CLIENT_ID', envStr('GOOGLE_CLIENT_ID', null));
    const OIDC = { enabled: Boolean(OIDC_CLIENT_ID), provider: OIDC_PROVIDER, issuer: OIDC_ISSUER, jwksUrl: OIDC_JWKS_URL, clientId: OIDC_CLIENT_ID ?? null, verifier: OIDC_CLIENT_ID ? createOidcVerifier({ issuer: OIDC_ISSUER, jwksUrl: OIDC_JWKS_URL, clientId: OIDC_CLIENT_ID }) : null };
    const OIDC_STATUS = { oidc_invalid: 401, oidc_nonce_mismatch: 400, oidc_unavailable: 502 };
    /** id_token 을 검증해 { uid, sub, nonce } 를 돌려준다. 실패는 { status, body } 로(라우트가 그대로 낸다). */
    async function oidcUid(idToken, noncePrefix) {
      if (!OIDC.enabled) return { error: { status: 503, body: { error: 'oidc_disabled', reason: 'oidc_disabled' } } };
      try { const v = await OIDC.verifier.verify(idToken, { noncePrefix }); return { uid: uidOf(OIDC.provider, v.sub), sub: v.sub, nonce: v.nonce }; }
      catch (e) { const status = OIDC_STATUS[e.reason]; if (!status) throw e; return { error: { status, body: { error: e.reason, reason: e.reason, detail: e.detail } } }; }
    }
    ```
  - `/cia/public_keys`: 응답에 `oidc: { enabled: OIDC.enabled, provider: OIDC.provider, clientId: OIDC.clientId, issuer: OIDC.issuer }`.
  - `/cia/register` 앞부분을 바꾼다:
    ```js
    const { uid: uidIn, pwd, id_token, auid, pk_u, sig_reg } = req.body ?? {};
    if (!isDec(auid) || !isPt(pk_u) || !sig_reg) return res.status(400).json({ error: 'auid, pk_u{x,y}, sig_reg required' });
    const demoPath = uidIn !== undefined || pwd !== undefined, oidcPath = id_token !== undefined;
    if (demoPath === oidcPath) return res.status(400).json({ error: '{uid, pwd} 또는 {id_token} 중 하나만' });   // 둘 다 없거나 둘 다 있음
    let uid, provider;
    if (oidcPath) {
      if (typeof id_token !== 'string') return res.status(400).json({ error: 'id_token 은 문자열' });
      const o = await oidcUid(id_token, REG_PREFIX); if (o.error) return res.status(o.error.status).json(o.error.body);
      // 토큰은 이 pk_u 에 묶여 있어야 한다(D4) — 가로챈 토큰으로 다른 키를 등록하지 못하게. auid 는 sig_reg 가 결속한다.
      if (o.nonce !== regNonce(pk_u)) return res.status(400).json({ error: 'oidc_nonce_mismatch', reason: 'oidc_nonce_mismatch', detail: 'nonce 가 요청의 pk_u 와 다르다' });
      uid = o.uid; provider = OIDC.provider;
    } else {
      if (!isDec(uidIn) || typeof pwd !== 'string') return res.status(400).json({ error: 'uid, pwd, auid, pk_u{x,y}, sig_reg required' });
      const acct = Object.values(DEMO_ACCOUNTS).find((a) => a.uid === uidIn);
      if (!acct || acct.password !== pwd) return res.status(401).json({ error: 'invalid credentials' });
      uid = uidIn; provider = 'demo';
    }
    ```
    이후는 기존 코드 그대로(`state.accounts[uid]` 409 → auid 범위 → pk_u → `registerMessage(BigInt(uid), BigInt(auid))` 서명 → 경합 409 → 슬롯) 단, 계정 객체에 `provider` 를 넣고 응답을 `res.status(201).json({ slot, schemaHash: ATTR_SCHEMA_HASH, uid, provider })` 로.
  - `/cia/account/self_revoke`: 본문에 `id_token` 이 있으면 `oidcUid(id_token, REVOKE_PREFIX)` → `isRevokeNonce(o.nonce)` 아니면 400 `oidc_nonce_mismatch` → `uid = o.uid` → `state.accounts[uid]` 없으면 404 → `revokeAccount(uid)`. 없으면 기존 uid·pwd 경로 그대로.
  - 관리자 계정 목록 라우트(`/cia/accounts`)의 항목에 `provider: a.provider ?? 'demo'` 추가(모양은 기존 그대로).
  - `lib/mode3_cia_state.js` `migrateCiaState` 의 계정 루프에 `a.provider ??= 'demo';` + 주석 한 줄(2026-10-16 OIDC 래퍼 — 옛 계정은 데모 계정).
  - `tests/test_mode3_cia_state.js` 에 케이스 1개: `provider` 없는 v12 계정이 `migrateCiaState` 뒤 `'demo'` 가 되고, `'google'` 은 유지된다.

- [ ] **Step 5: 통과 확인** — `node tests/test_cia_oidc_register.mjs` 9개 ok(격리 IdP 두 번 기동, 1~2분). 회귀: `node tests/test_cia_register_issue.mjs`, `node tests/test_cia_cors.mjs`, `node tests/test_mode3_cia_state.js`, `node --check cia.js`.
- [ ] **Step 6: CHAIN 배열 `tests/test_cia_cors.mjs` 다음에 `tests/test_cia_oidc_register.mjs` 추가. 커밋** — `feat(cia): OIDC 래퍼 — id_token 으로 등록·자기 폐기(uid=H(provider|sub), nonce 결속), public_keys.oidc`.

---

### Task 4: 사용자 코어 — `prepareRegistration`·`completeRegistration`·`selfRevokeWithIdToken`, 격리 스택 옵션

**Files:**
- Modify: `mode3/user/core/user_core.js`
- Modify: `tests/helpers/isolated_mode3_stack.mjs` (옵션 `oidc`, `walletHost`)
- Test: `tests/test_mode3_user_core_oidc.mjs` (chain)

**Interfaces:**
- Produces(코어):
  - `prepareRegistration()`: 키 재료만 먼저 만든다(uid 는 토큰의 `sub` 로 정해지므로 아직 모른다 — auid 도 아직 없다): `s_u = randomScalar()`, `sk_u = randomBytes(32).toString('hex')`(브라우저는 shim), `pk_u = await eddsaPubOf(sk_u)`; `nonce = regNonce(pk_u)`(Task 1, R-A).
    - 반환 `{ nonce, pk_u: { x, y }, pending: true }`; 재료는 코어 메모리(`pendingReg`)에만 둔다(IndexedDB 에 쓰지 않는다 — 비밀번호 전이라 금고가 없을 수 있다). 다시 부르면 새 재료.
  - `completeRegistration({ idToken, profile = null, vaultPassword = null })`: `pendingReg` 없으면 409 `{ reason:'no_pending_registration' }`; `idToken` 문자열 아니면 400; **토큰 payload 를 base64url 디코드해 `sub`·`nonce` 를 읽고**(서명은 IdP 가 검증 — 여기서는 uid 선계산용) `nonce !== pendingReg.nonce` 면 400 `oidc_nonce_mismatch`; `provider = (await idp.publicKeys()).body.oidc?.provider`(없으면 503 `oidc_disabled`); `uid = uidOf(provider, sub)`; `auid = auidOf({ uid, s_u })`; 이후 **`register` 와 같은 금고·스키마·profile 규칙**(공통 함수 `registerWith({ uid, auth: { id_token } | { uid, pwd }, reg: { s_u, sk_u, pk_u, auid }, profileIn, vaultPassword, provider })` 로 뽑아 `register` 도 그것을 쓴다) → `POST /cia/register { id_token, auid, pk_u, sig_reg }` → 201 이면 응답의 `uid`·`provider` 로 `registration` 저장(`provider` 필드 추가), `pendingReg = null`. 실패 응답은 `{ status, body: { reason: 'register_failed', cia } }`(기존 규칙; 401·409 는 그대로, 그 밖 502) — 단 IdP 가 `oidc_*` 사유를 냈으면 `body.reason` 을 그 사유로(`{ reason: body.reason, cia }`), 상태는 IdP 의 것.
  - `selfRevokeWithIdToken({ idToken })`: 등록 없으면 409 `not_registered`; `registration.provider !== 'google'…` 는 보지 않는다(IdP 가 판단) → `POST /cia/account/self_revoke { id_token }` → `R(r.status, r.body)`; 네트워크 실패 502 `cia_unavailable`.
  - `status()` 응답에 `provider: reg?.provider ?? null`; `health()` 불변.
  - `register(...)`(데모 경로) 는 `registration.provider = 'demo'` 를 저장(응답의 `provider` 가 있으면 그것).
- Produces(헬퍼): `startIsolatedMode3Stack({ oidc, walletHost = '127.0.0.1' })` — `oidc` 를 `startIsolatedCia({ oidc })` 로 전달하고 `stack.oidc = cia.oidc`; `walletHost` 로 `walletOrigin = http://${walletHost}:${walletPort}` 를 만들어 IdP(`MODE3_WALLET_AGENT_ORIGIN`)·RP(`MODE3_WALLET_AGENT_ORIGIN`)·정적 서버/에이전트(`MODE3_WALLET_PUBLIC_ORIGIN`) 에 같은 값을 넣는다(서버는 127.0.0.1 에 listen 하므로 localhost 로도 닿는다). 기본값이면 지금과 완전히 같다.
- Consumes: Task 1(`uidOf`·`regNonce(pk_u)`·`newRevokeNonce` — `lib/mode3_oidc_nonce.js` 는 `node:crypto` 의 `createHash`·`randomBytes` 만 쓰므로 esbuild shim 으로 번들된다), Task 3 IdP 경로, `lib/mode3_wallet.js` 의 `eddsaPubOf`·`signRegistration`, `lib/mode3_credential.js` 의 `randomScalar`·`auidOf`.

- [ ] **Step 1: 실패하는 테스트**

```js
// tests/test_mode3_user_core_oidc.mjs — 사용자 코어의 Google(OIDC 래퍼) 등록·자기 폐기(스펙 2026-10-16 §3.1·§3.3). 격리 web 스택 + 발급자 스텁, Node 에서 메모리 kv. (chain)
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { startIsolatedMode3Stack } from './helpers/isolated_mode3_stack.mjs';
import { getProvider } from './helpers/mode3_chain.mjs';
import { createMemKv } from '../mode3/user/core/kv_mem.js';
import { createUserCore } from '../mode3/user/core/user_core.js';
import { uidOf, newRevokeNonce } from '../lib/mode3_oidc_nonce.js';
import * as snarkjs from 'snarkjs';

execFileSync('node', ['scripts/build_user_app.mjs'], { stdio: 'inherit' });
const stack = await startIsolatedMode3Stack({ userMode: 'web', autoRelay: true, oidc: true });
const { wallet, rp, oidc: stub } = stack;
const provider = getProvider();
let fails = 0; async function t(n, f) { try { await f(); console.log('ok   -', n); } catch (e) { fails++; console.log('FAIL -', n, '\n      ', e.stack ?? e.message); } }
const j = (o) => JSON.stringify(o, (k, v) => (typeof v === 'bigint' ? v.toString() : v));
try {
  const config = (await wallet.get('/user/config')).body;
  const kv = createMemKv();
  const fullProve = { idp: (i, w, z) => snarkjs.groth16.fullProve(i, w, z), cred: (i, w, z) => snarkjs.groth16.fullProve(i, w, z) };
  const core = createUserCore({ kv, config, provider, canonProvider: provider, fullProve });
  let info = (await rp.get('/api/mode3/rp_info')).body;
  for (let i = 0; i < 50 && !info.attrGateAddress; i++) { await new Promise((r) => setTimeout(r, 200)); info = (await rp.get('/api/mode3/rp_info')).body; }   // RP 등록 승인·팩토리 배포를 기다린다(test_mode3_user_core.mjs 와 같다)
  const PW = 'vault-oidc';
  const SUB = 'google-user-77';
  await t('prepareRegistration: nonce 가 "reg:"+hex64 이고 pk_u 를 돌려준다; 다시 부르면 새 재료', async () => {
    const a = await core.prepareRegistration(); assert.match(a.nonce, /^reg:[0-9a-f]{64}$/); assert.match(a.pk_u.x, /^[0-9]+$/);
    const b = await core.prepareRegistration(); assert.notEqual(a.nonce, b.nonce);
  });
  await t('completeRegistration: 스텁 토큰(nonce = prepare 의 것) → 201, uid = uidOf(provider, sub), registration.provider = 스텁 provider, 비밀은 금고에만', async () => {
    const p = await core.prepareRegistration();
    const idToken = await stub.mint({ sub: SUB, nonce: p.nonce });
    const r = await core.completeRegistration({ idToken, profile: { birthYear: '1990', country: 'KR' }, vaultPassword: PW });
    assert.equal(r.status, 201, j(r.body)); assert.equal(r.body.uid, uidOf(stub.provider, SUB)); assert.equal(r.body.provider, stub.provider);
    const reg = await kv.get('registration'); assert.equal(reg.provider, stub.provider); assert.equal(reg.uid, r.body.uid); assert.ok(!('s_u' in reg));
    assert.equal((await core.status()).body.provider, stub.provider);
  });
  await t('nonce 가 다른 토큰·pending 없음·토큰 형식 오류의 사유', async () => {
    assert.equal((await core.completeRegistration({ idToken: await stub.mint({ sub: 'x', nonce: 'reg:' + 'f'.repeat(64) }) })).body.reason, 'already_registered');   // 이미 등록됨이 먼저
    await core.wipe();
    assert.equal((await core.completeRegistration({ idToken: 'a.b.c', vaultPassword: PW })).body.reason, 'no_pending_registration');
    const p = await core.prepareRegistration();
    assert.equal((await core.completeRegistration({ idToken: await stub.mint({ sub: 'x', nonce: 'reg:' + 'f'.repeat(64) }), vaultPassword: PW })).body.reason, 'oidc_nonce_mismatch');
    assert.equal((await core.completeRegistration({ idToken: 'not-a-jwt', vaultPassword: PW })).status, 400);
    // 같은 sub 로 다시 등록(새 재료): IdP 가 409 → register_failed 가 아니라 IdP 의 409 그대로
    const again = await core.completeRegistration({ idToken: await stub.mint({ sub: SUB, nonce: p.nonce }), vaultPassword: PW });
    assert.equal(again.status, 409, j(again.body));
  });
  await t('Google 로 등록한 계정으로 RP 로그인이 된다(증명 경로 불변)', async () => {
    await core.wipe();
    const p = await core.prepareRegistration();
    const r = await core.completeRegistration({ idToken: await stub.mint({ sub: 'google-user-78', nonce: p.nonce }), profile: { birthYear: '1991', country: 'KR' }, vaultPassword: PW });
    assert.equal(r.status, 201, j(r.body));
    const ch = (await rp.post('/api/mode3/challenge')).body;
    const lg = await core.login({ arid: info.arid, origin: info.origin, cert_s: info.cert_s, pk_trace: info.pk_trace, r_s: ch.r_s, r_rp: ch.r_rp, allowAgent: '0', factoryAddress: info.factoryAddress, attrGateAddress: info.attrGateAddress }, { verifiedOrigin: info.origin });
    assert.equal(lg.status, 200, j(lg.body));
    assert.equal((await rp.post('/api/mode3/login', { proof: lg.body.proof, publicSignals: lg.body.publicSignals, sig: lg.body.sig, r_s: ch.r_s })).body.ok, true);
  });
  await t('selfRevokeWithIdToken: revoke 토큰 → 200, 그 뒤 로그인은 403 account_disabled; 등록 토큰으로는 400', async () => {
    const regTok = await stub.mint({ sub: 'google-user-78', nonce: (await core.prepareRegistration()).nonce });
    assert.equal((await core.selfRevokeWithIdToken({ idToken: regTok })).status, 400);
    const r = await core.selfRevokeWithIdToken({ idToken: await stub.mint({ sub: 'google-user-78', nonce: newRevokeNonce() }) });
    assert.equal(r.status, 200, j(r.body));
    const ch = (await rp.post('/api/mode3/challenge')).body;
    const lg = await core.login({ arid: info.arid, origin: info.origin, cert_s: info.cert_s, pk_trace: info.pk_trace, r_s: ch.r_s, r_rp: ch.r_rp, allowAgent: '0', factoryAddress: info.factoryAddress, attrGateAddress: info.attrGateAddress }, { verifiedOrigin: info.origin });
    assert.equal(lg.status, 403, j(lg.body)); assert.equal(lg.body.reason, 'account_disabled');
  });
  await t('데모 계정 register 는 그대로이고 provider demo 를 저장한다', async () => {
    await core.wipe();
    const r = await core.register({ uid: '12345', pwd: 'password123', vaultPassword: PW }); assert.equal(r.status, 201, j(r.body));
    assert.equal((await kv.get('registration')).provider, 'demo'); assert.equal((await core.status()).body.provider, 'demo');
  });
} finally { await stack.stop(); }
process.exit(fails ? 1 : 0);
```

- [ ] **Step 2: 실패 확인** — `node tests/test_mode3_user_core_oidc.mjs` → 헬퍼가 `oidc` 를 몰라 `stub` undefined → 첫 mint 에서 TypeError(또는 `prepareRegistration` 없음).

- [ ] **Step 3: 헬퍼** — `tests/helpers/isolated_mode3_stack.mjs`: 구조분해에 `oidc = null, walletHost = '127.0.0.1'`; `walletOrigin = `http://${walletHost}:${walletPort}``(이미 그 변수가 IdP·RP·지갑 env 로 흘러간다 — 정적 서버/에이전트 env 에 `MODE3_WALLET_PUBLIC_ORIGIN: walletOrigin` 을 **추가**한다. 지금은 넘기지 않아 서버가 `http://127.0.0.1:PORT` 를 스스로 만든다); `startIsolatedCia({ env: {...}, oidc, ... })`; 반환에 `oidc: cia.oidc`. 파일 머리 주석에 두 옵션 한 줄.

- [ ] **Step 4: 코어 구현** — 위 Interfaces 대로. 토큰 payload 디코드 헬퍼(코어 안): `const jwtPayload = (t) => { const parts = String(t).split('.'); if (parts.length !== 3) throw Object.assign(new Error('format'), { reason: 'oidc_invalid' }); const b = parts[1].replace(/-/g, '+').replace(/_/g, '/'); const pad = b + '='.repeat((4 - b.length % 4) % 4); return JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(pad), (c) => c.charCodeAt(0)))); }`(Node 22 에 `atob` 있음). `registerWith` 공통화: 금고 규칙(`needSetup`/`bad_password`/423) → 스키마·profile → (demo: `createRegistration(uid)`; oidc: `pendingReg` 재료 + `auidOf`) → 금고 setup → IdP POST → 비밀 저장 → registration 저장(`provider`) → 201. 주석에 "에이전트 /wallet/register 의 등가 + OIDC 분기(스펙 2026-10-16 §3.1)".

- [ ] **Step 5: 통과 확인** — `node tests/test_mode3_user_core_oidc.mjs` 6개 ok(실제 증명 2회, 1~2분). 회귀: `node tests/test_mode3_user_core.mjs`(18/18 — 기존 등록 경로 공통화가 깨지지 않았는지), `node tests/test_mode3_oidc_nonce.js`, `node tests/test_cia_oidc_register.mjs`, `node tests/test_mode3_user_static.mjs`(헬퍼 기본 동작), `node --check` 변경 파일.
- [ ] **Step 6: CHAIN 배열 `tests/test_mode3_user_core.mjs` 다음에 `tests/test_mode3_user_core_oidc.mjs` 추가. 커밋** — `feat(user-web): 코어 OIDC 등록(prepare/complete)·id_token 자기 폐기, 격리 스택 oidc·walletHost 옵션`.

---
### Task 5: 화면 — GIS 로더, 사용자 페이지 Google 등록·폐기, 팝업 신원 줄·미등록 안내, RP 모달 Google 버튼, 계정 페이지 Google 폐기, 문구

**Files:**
- Create: `mode3/common/gsi.js` (classic script, `window.Mode3Gsi`)
- Modify: `mode3/user/index.html`, `mode3/user/ui.js`, `mode3/user/user.js`, `mode3/user/popup.js`
- Modify: `mode3_rp.js`(`resolvePkCia`·`rp_info`), `mode3/rp.html`(`#googleLoginBtn`·`startIdpLogin`·`authorizeRequest`)
- Modify: `mode3/cia_account.html`
- Modify: `mode3/common/strings.js`(ui 키·reasons), `tests/test_mode3_demo_strings.js`(REASONS 6개 추가)
- Test: `tests/test_mode3_user_web_oidc.mjs` (browser)

**Interfaces:**
- Produces(`mode3/common/gsi.js`, 두 서버가 `/common` 으로 함께 낸다 — `cia.js`·`mode3_user_static.js` 모두 `express.static(mode3/common)`):
  ```js
  // mode3/common/gsi.js — Google Identity Services(GIS) 로더(스펙 2026-10-16 D5). classic script: 사용자 페이지(번들)와 계정 페이지(인라인 스크립트)가 같은 사본을 쓴다.
  // 테스트는 window.google.accounts.id 를 먼저 심어 두고(addInitScript) 이 로더가 스크립트 주입을 건너뛰게 한다.
  (function () {
    const GSI_SRC = 'https://accounts.google.com/gsi/client';
    let loading = null;
    /** Google 은 127.0.0.1 오리진을 승인 목록에 받지 않는다(D6) — localhost 로 열었을 때만 버튼을 그린다. */
    const originOk = () => location.hostname === 'localhost';
    /** window.google.accounts.id 를 돌려준다. 이미 있으면(스텁·재호출) 그대로, 없으면 스크립트를 한 번만 주입한다. 실패/8초 → Error{ reason:'gsi_unavailable' }. */
    function load({ timeoutMs = 8000 } = {}) {
      if (window.google?.accounts?.id) return Promise.resolve(window.google.accounts.id);
      if (loading) return loading;
      loading = new Promise((resolve, reject) => {
        const fail = (why) => { loading = null; reject(Object.assign(new Error(`GIS 스크립트를 불러오지 못했다: ${why}`), { reason: 'gsi_unavailable' })); };
        const s = document.createElement('script');
        s.src = GSI_SRC; s.async = true; s.defer = true;
        const timer = setTimeout(() => fail('timeout'), timeoutMs);
        s.onload = () => { clearTimeout(timer); window.google?.accounts?.id ? resolve(window.google.accounts.id) : fail('no google.accounts.id'); };
        s.onerror = () => { clearTimeout(timer); fail('error'); };
        document.head.appendChild(s);
      });
      return loading;
    }
    /** 버튼을 el 안에 그린다. 토큰(JWT 문자열)은 onToken 으로. nonce 는 호출마다 새로 넣는다(initialize 는 전역이라 마지막 호출이 이긴다 — 한 화면에 버튼 하나만 살아 있게 쓴다). */
    async function render({ el, clientId, nonce, onToken, text = 'signin_with', theme = 'outline', size = 'large' }) {
      const id = await load();
      id.initialize({ client_id: clientId, nonce, callback: (resp) => onToken(resp?.credential ?? null), auto_select: false, cancel_on_tap_outside: true, use_fedcm_for_prompt: false });
      el.replaceChildren();
      id.renderButton(el, { type: 'standard', theme, size, text, shape: 'rectangular', logo_alignment: 'left' });
    }
    window.Mode3Gsi = { originOk, load, render, GSI_SRC };
  })();
  ```
  브라우저 테스트의 스텁(`context.addInitScript`):
  ```js
  // 진짜 GIS 대신: initialize 가 준 nonce 로 발급자 스텁 /mint 에서 토큰을 받아 callback 을 부르는 버튼을 그린다. sub 는 window.__gsiSub 로 바꾼다.
  window.google = { accounts: { id: {
    _cfg: null,
    initialize(cfg) { this._cfg = cfg; },
    renderButton(el, opts) {
      const b = document.createElement('button'); b.type = 'button'; b.className = 'gsi-stub'; b.textContent = `Google(stub:${opts?.text ?? ''})`;
      b.addEventListener('click', async () => {
        const r = await fetch(window.__gsiMintUrl, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ sub: window.__gsiSub, nonce: this._cfg.nonce }) });
        const { id_token } = await r.json();
        this._cfg.callback({ credential: id_token });
      });
      el.replaceChildren(b);
    },
  } } };
  ```
  (스텁의 `POST /mint` 응답 모양은 Task 2 의 `oidc_issuer_stub.mjs` — `{ id_token }` — 를 따른다. 다르면 스텁 쪽 응답 키를 확인해 이 코드를 맞춘다.)
- Produces(사용자 페이지):
  - `index.html`: `<head>` 의 `/common/demo.js` 다음에 `<script src="/common/gsi.js"></script>`. `#identityCard` 의 `#fileRegFields` 바로 뒤에
    ```html
    <p id="googleRegRow" hidden><span data-i18n="user_google_register_or">또는 Google 계정으로 등록:</span> <span id="googleRegSlot" class="gsi-slot"></span></p>
    <p id="googleRegNote" class="muted" hidden></p>
    ```
    저장소 카드의 `#selfRevokeBtn` 바로 뒤에 `<span id="googleRevokeRow" hidden><span data-i18n="user_google_revoke_label">Google 로 계정 자기 폐기:</span> <span id="googleRevokeSlot" class="gsi-slot"></span></span>`. `#authorizeView` 의 `#authSummary` 뒤에 `<p id="authHint" class="auth-hint" hidden></p>`.
  - `user.js`: 코어를 만든 뒤 `let oidc = { enabled: false }; try { const k = await core.idp.publicKeys(); if (k?.oidc) oidc = k.oidc; } catch { /* IdP 가 죽어 있으면 Google 버튼만 숨는다 — 나머지 화면은 그대로 */ }` — **코어에 `idp` 가 노출돼 있지 않으면**(지금은 내부 변수) 코어가 `idp` 를 반환 객체에 넣는다(Task 4 에서 안 했으면 여기서 `return { …, idp }` 한 줄). `mountUi({ …, oidc })`, `runPopup({ …, oidc })`.
  - `ui.js` `mountUi({ core, prover, config, Demo, meta, oidc = { enabled: false } })`:
    - `readVaultPassword()` 를 뽑는다(지금 `registerBtn` 핸들러 안의 금고 비밀번호 규칙 — 두 칸 일치·8자 이상·금고 없을 때만 — 그대로; 실패 시 `{ error: 'user_vault_pw_mismatch' | 'user_vault_pw_short' }`, 성공 `{ vaultPassword }`). 등록 결과 카드도 `showRegisterResult({ status, body })` 로 뽑아 두 경로가 같이 쓴다(기존 문구·`profileDirty=false`·`refresh()` 그대로).
    - Google 등록: `async function mountGoogleRegister()`: `oidc.enabled` 아니면 두 요소 hidden 유지 후 return. `!window.Mode3Gsi` → 노트 `gsi_unavailable`. `!Mode3Gsi.originOk()` → `#googleRegNote` 에 `tt('user_gsi_origin_note', { url: `http://localhost:${location.port}/` })` + 그 URL 로 가는 링크(`<a>` 는 `document.createElement` 로 — innerHTML 금지) 보이고 return. 아니면 `#googleRegRow` 보이고 `armGoogleRegister()`: `const { nonce } = await core.prepareRegistration(); await Mode3Gsi.render({ el: $('googleRegSlot'), clientId: oidc.clientId, nonce, text: 'signup_with', onToken: onGoogleRegToken })`; 로드 실패는 `#googleRegNote` 에 `gsi_unavailable` 사유. `onGoogleRegToken(idToken)`: `pendingVerdict($('registerResult'), 'working')`; `readVaultPassword()`(실패 → 카드에 그 문구, **그리고 `armGoogleRegister()` 로 nonce 를 새로** — 토큰은 1회용); profile 은 `registerBtn` 과 같은 규칙; `withUnlock(() => core.completeRegistration({ idToken, profile, vaultPassword }))` → `showRegisterResult`; 성공이면 Google 행을 숨긴다(이미 등록); 실패면 다시 `armGoogleRegister()`.
    - Google 폐기: `renderVault()` 안에서(`lastStatus` 를 쓰는 곳) `const g = oidc.enabled && lastStatus?.registered && lastStatus.provider && lastStatus.provider !== 'demo' && window.Mode3Gsi?.originOk();` → `$('selfRevokeBtn').hidden = g; $('googleRevokeRow').hidden = !g;` g 이고 아직 안 그렸으면 `Mode3Gsi.render({ el: $('googleRevokeSlot'), clientId: oidc.clientId, nonce: newRevokeNonce(), text: 'continue_with', onToken: onGoogleRevokeToken })`(`newRevokeNonce` 는 `../../lib/mode3_oidc_nonce.js` 에서 import — 번들됨). `onGoogleRevokeToken(idToken)`: `Demo.confirmDanger('confirm_revoke')` 아니면 취소 문구; `pendingVerdict(storageVerdict(), 'working')`; `core.selfRevokeWithIdToken({ idToken })` → 200 이면 기존 `revoked_ok` 카드(`wallet_self_revoke_ok` 는 uid 를 받는다 — `lastStatus.uid`), 아니면 `wallet_self_revoke_failed` + `res.body.reason`; 끝에 `refresh()`. 실패 뒤에는 새 nonce 로 다시 그린다.
    - 등록 성공 후 `renderIdentity()` 의 등록 정보 줄(`#regInfo`)에 provider 를 덧붙인다: `lastStatus.provider && lastStatus.provider !== 'demo' ? ` · ${tt('user_identity_provider', { provider: lastStatus.provider })}` : ''`.
  - `popup.js` `runPopup({ core, config, Demo, meta, oidc = { enabled: false } })`: `mode3-authorize`(reauth 아님) 분기에서 precheck 통과 직후, `waitDecision()` 전에
    ```js
    const st = await core.status();
    if (!st.body?.registered) {
      // 미등록(스펙 §3.2): Google 로 들어온 요청이면 등록 안내 + 사용자 페이지 링크. 회신은 지금과 같은 not_registered(RP 쪽 표기는 불변).
      const hint = $('authHint'); hint.textContent = tt(req.provider === 'google' ? 'user_register_hint_google' : 'user_register_hint') || '먼저 사용자 페이지에서 등록하세요.';
      const a = document.createElement('a'); a.href = `${location.origin}/`; a.target = '_blank'; a.rel = 'noopener'; a.textContent = `${location.origin}/`; hint.append(' ', a); hint.hidden = false;
      step('등록 없음'); return reply({ ok: false, reason: 'not_registered' });
    }
    // 신원 줄(스펙 §3.2): 어느 계정으로 로그인하는지 — provider 만, 이메일·이름은 없다(범위 밖).
    renderAuthIdentity(st.body.provider ?? 'demo');
    ```
    `renderAuthIdentity(provider)` 는 `#authSummary` 에 `row('user_auth_identity', provider === 'demo' ? tt('user_auth_identity_demo') : tt('user_auth_identity_provider', { provider }))` 한 줄을 더한다(`row` 를 `renderAuthSummary` 밖으로 뽑는다). 실패 창은 3초 뒤 닫히므로(`reply` 의 setTimeout) 안내가 보이게 **미등록 회신은 닫기 지연을 15초로**: `reply(result, { closeMs })` 인자를 추가해 이 경우만 15_000.
  - `mode3_rp.js`: `resolvePkCia()` 가 응답의 `oidc` 도 보관 — env 경로(`MODE3_PK_CIA_X/Y`)면 IdP 를 안 부르므로 `oidc: { enabled: false }`; TOFU 경로면 `oidc: k.oidc ?? { enabled: false }`. `rp_info` 에 `oidc: pkCIA.oidc` 추가(`clientId` 는 공개 값이지만 RP 페이지는 쓰지 않는다 — `enabled`·`provider` 만 본다).
  - `rp.html`: `authorizeRequest(extra)` 는 그대로(`extra` 가 `provider` 를 싣는다). `startIdpLogin(opts = {})` → 팝업 요청에 `provider: opts.provider ?? null` 을 더해 `authorizeRequest({ r_s, r_rp, …, provider: opts.provider ?? null })`. `#googleLoginBtn` 핸들러: `info?.oidc?.enabled && WEB()` 이면 `closeLoginModal(); startIdpLogin({ provider: 'google' })`, 아니면 지금처럼 `showModalNote('rp_social_not_in_demo', …)`(Snap·에이전트 모드에서는 Google 등록이 없다 — 스펙 §8). `info` 가 아직 없으면 `await loadInfo()` 먼저. 모달을 열 때(`openLoginModal`) `#googleLoginBtn` 에 `data-oidc="1"` 속성을 `info?.oidc?.enabled && WEB()` 에 따라 토글한다(테스트가 활성 여부를 본다).
  - `cia_account.html`: `<head>` 에 `<script src="/common/gsi.js"></script>`; `#revokeBtn` 아래에 `<p id="googleRevokeRow" hidden><span data-i18n="account_google_revoke_label">Google 로 등록한 계정은 Google 로 폐기:</span> <span id="googleRevokeSlot" class="gsi-slot"></span></p><p id="googleRevokeNote" class="muted" hidden></p>`. 스크립트: 기존 클릭 핸들러의 fetch·결과 처리 부분을 `async function submitRevoke(body, uidLabel)` 로 뽑고(`$('out')` 표기·`revoked_ok`/실패 판정·`renderGuide()` 그대로; `uidLabel` 은 데모 경로 `uid`, Google 경로 `'(Google)'`), 기존 버튼은 `submitRevoke({ uid, pwd }, uid)`. 로드 시 `fetch('/cia/public_keys')` → `k.oidc?.enabled` 이고 `window.Mode3Gsi?.originOk()` 이면 행을 보이고 `Mode3Gsi.render({ el, clientId: k.oidc.clientId, nonce: 'revoke:' + hex64(), text: 'continue_with', onToken: (t) => submitRevoke({ id_token: t }, '(Google)') })`(`hex64 = () => Array.from(crypto.getRandomValues(new Uint8Array(32)), (b) => b.toString(16).padStart(2, '0')).join('')` — 인라인 페이지라 lib 를 import 할 수 없다, 한 줄 중복 허용); enabled 인데 origin 이 127.0.0.1 이면 `#googleRevokeNote` 에 `account_gsi_origin_note` + `http://localhost:${location.port}/account` 링크; 로드 실패는 `gsi_unavailable` 사유 문구. 완료·실패 뒤 새 nonce 로 다시 그린다.
  - `strings.js` `ui` 추가(ko/en 전부): `user_google_register_or`, `user_gsi_origin_note`(`{url}` — "Google 로그인은 http://localhost 주소에서만 됩니다 — {url} 로 여세요"), `user_google_revoke_label`, `user_register_hint_google`("Google 계정이 아직 zk-Delegation 에 등록되지 않았습니다. 사용자 페이지에서 Google 로 먼저 등록하세요:"), `user_register_hint`("이 브라우저에 등록이 없습니다. 사용자 페이지에서 먼저 등록하세요:"), `user_auth_identity`("신원"), `user_auth_identity_demo`("데모 계정"), `user_auth_identity_provider`(`{provider}` — "{provider} 계정으로 등록된 신원"), `user_identity_provider`(`{provider}`), `account_google_revoke_label`, `account_gsi_origin_note`(`{url}`), `rp_google_login_note`(모달 안내 — "Google 계정으로 등록한 사용자는 이 버튼으로 같은 zk 로그인을 합니다. IdP 는 Google 토큰을 등록 때만 봅니다."). `reasons` 추가(각 ko/en `title·cause·action`): `oidc_disabled`(where `aa`), `oidc_invalid`(`aa`), `oidc_nonce_mismatch`(`aa`), `oidc_unavailable`(`aa`), `gsi_unavailable`(`page`), `gsi_origin`(`page`). 문구는 스펙 §4 의 조건을 그대로 사람 말로(예: `oidc_invalid` cause "Google ID 토큰의 서명·발급자·대상·만료 중 하나가 맞지 않습니다", action "다시 Google 로 로그인해 새 토큰으로 시도하세요").
  - `tests/test_mode3_demo_strings.js` 의 `REASONS` 배열에 위 6개 추가.
- Consumes: Task 3 `/cia/public_keys.oidc`·`/cia/account/self_revoke { id_token }`; Task 4 `core.prepareRegistration()`·`completeRegistration()`·`selfRevokeWithIdToken()`·`status().provider`, 헬퍼 옵션 `oidc`·`walletHost`; Task 1 `newRevokeNonce`.

- [ ] **Step 1: 실패하는 테스트**

```js
// tests/test_mode3_user_web_oidc.mjs — Google(OIDC 래퍼) 경로를 실제 Chrome 에서(스펙 2026-10-16 §7). GIS 는 addInitScript 스텁(발급자 스텁에서 토큰), 사용자 오리진은 localhost(D6).
// hardhat :8545, build/mode3, Chrome 필요. 번들은 여기서 만든다. (browser)   node tests/test_mode3_user_web_oidc.mjs   MODE3_BROWSER_DEBUG=1 로 콘솔.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { chromium } from '@playwright/test';
import { startIsolatedMode3Stack } from './helpers/isolated_mode3_stack.mjs';
import { uidOf } from '../lib/mode3_oidc_nonce.js';

const DEBUG = process.env.MODE3_BROWSER_DEBUG === '1';
const j = (o) => JSON.stringify(o);
let failed = 0;
async function t(name, fn) { try { await fn(); console.log(`ok   ${name}`); } catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.stack ?? e.message}`); } }
async function launchBrowser() { const tried = []; for (const opts of [{ channel: 'chrome' }, {}]) { try { return await chromium.launch(opts); } catch (e) { tried.push(`${j(opts)}: ${e.message.split('\n')[0]}`); } } throw new Error(`BLOCKED: 브라우저를 띄우지 못했다.\n  ${tried.join('\n  ')}`); }
const GSI_STUB = (mintUrl) => `window.__gsiMintUrl = ${j(mintUrl)}; window.__gsiSub = window.__gsiSub ?? 'g-user-1';
window.google = { accounts: { id: { _cfg: null, initialize(cfg) { this._cfg = cfg; },
  renderButton(el, opts) { const b = document.createElement('button'); b.type = 'button'; b.className = 'gsi-stub'; b.textContent = 'Google(stub:' + (opts?.text ?? '') + ')';
    b.addEventListener('click', async () => { const r = await fetch(window.__gsiMintUrl, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ sub: window.__gsiSub, nonce: this._cfg.nonce }) }); const { id_token } = await r.json(); this._cfg.callback({ credential: id_token }); });
    el.replaceChildren(b); } } } };`;

execFileSync('node', ['scripts/build_user_app.mjs'], { stdio: 'inherit' });
const browser = await launchBrowser();
const stack = await startIsolatedMode3Stack({ userMode: 'web', autoRelay: true, oidc: true, walletHost: 'localhost' });
const { wallet, rp, cia, oidc: stub } = stack;
const PW = 'oidc-vault-pw';
const SUB1 = 'g-user-1', SUB2 = 'g-user-2';
try {
  const context = await browser.newContext();
  await context.addInitScript(GSI_STUB(`${stub.base}/mint`));
  if (DEBUG) context.on('page', (p) => { p.on('console', (m) => console.log(`    [${new URL(p.url()).host}] ${m.type()}: ${m.text()}`)); p.on('pageerror', (e) => console.log(`    [page error] ${e.message}`)); });
  const text = (page, sel) => page.$eval(sel, (el) => el.textContent ?? '');
  async function waitText(page, sel, needle, timeout = 60_000) {
    try { await page.waitForFunction(([s, n]) => (document.querySelector(s)?.textContent ?? '').includes(n), [sel, needle], { timeout }); }
    catch { throw new Error(`${sel} 에 "${needle}" 가 나오지 않았다 (${timeout}ms). 지금: ${j(await text(page, sel).catch(() => '?'))}`); }
  }
  const idbDump = (page) => page.evaluate(async () => { const open = indexedDB.open('mode3-user', 1); const db = await new Promise((r, x) => { open.onsuccess = () => r(open.result); open.onerror = () => x(open.error); }); const st = db.transaction('kv', 'readonly').objectStore('kv'); const keys = await new Promise((r) => { const q = st.getAllKeys(); q.onsuccess = () => r(q.result); }); const out = {}; for (const k of keys) out[k] = await new Promise((r) => { const q = st.get(k); q.onsuccess = () => r(q.result); }); return JSON.parse(JSON.stringify(out, (k, v) => (v instanceof CryptoKey ? '[CryptoKey]' : v))); });
  async function viaPopup(trigger, fn) { const [popup] = await Promise.all([context.waitForEvent('page'), trigger()]); await popup.waitForSelector('#authorizeView:not([hidden])'); await fn(popup); if (!popup.isClosed()) await popup.waitForEvent('close', { timeout: 120_000 }); }
  const approve = async (popup) => { await popup.waitForSelector('#authApproveBtn:not([hidden])', { timeout: 60_000 }); await popup.click('#authApproveBtn'); };
  const setSub = (page, sub) => page.evaluate((s) => { window.__gsiSub = s; }, sub);

  assert.match(wallet.base, /^http:\/\/localhost:/, 'walletHost 옵션으로 사용자 오리진이 localhost 다');
  const userPage = await context.newPage();
  await userPage.goto(`${wallet.base}/`);
  await userPage.waitForSelector('#mainView:not([hidden])');
  const rpPage = await context.newPage();
  await rpPage.goto(`${rp.base}/`);
  await waitText(rpPage, '#walletMode', '사용자 비밀=브라우저');

  await t('G1 미등록 + RP 모달 Google 버튼 → 팝업이 등록 안내와 사용자 페이지 링크를 보이고 not_registered 로 끝난다', async () => {
    await rpPage.click('#loginBtn');
    assert.equal(await rpPage.getAttribute('#googleLoginBtn', 'data-oidc'), '1', 'rp_info.oidc.enabled 로 Google 버튼이 활성');
    let hint = '', href = '';
    await viaPopup(() => rpPage.click('#googleLoginBtn'), async (popup) => { await popup.waitForSelector('#authHint:not([hidden])', { timeout: 60_000 }); hint = await text(popup, '#authHint'); href = await popup.getAttribute('#authHint a', 'href'); });
    assert.ok(hint.includes('Google'), hint); assert.equal(href, `${wallet.base}/`);
    await waitText(rpPage, '#verdict', 'not_registered', 30_000);
  });
  await t('G2 사용자 페이지: Google 행이 보이고(stub 버튼) 금고 비밀번호 + Google → 등록됨; registration.provider = 스텁 provider, uid = uidOf(provider, sub)', async () => {
    await userPage.waitForSelector('#googleRegRow:not([hidden])');
    await userPage.waitForSelector('#googleRegSlot .gsi-stub', { timeout: 30_000 });
    await setSub(userPage, SUB1);
    await userPage.fill('#vaultPw', PW); await userPage.fill('#vaultPw2', PW);
    await userPage.click('#googleRegSlot .gsi-stub');
    await waitText(userPage, '#registerResult', '등록됨', 90_000);
    const d = await idbDump(userPage);
    assert.equal(d.registration.provider, stub.provider); assert.equal(d.registration.uid, uidOf(stub.provider, SUB1)); assert.ok(!('s_u' in d.registration));
    await waitText(userPage, '#regInfo', stub.provider);
    assert.equal(await userPage.isHidden('#googleRegRow'), true, '등록 뒤 Google 등록 행은 숨는다');
  });
  await t('G3 RP 모달 Google 버튼 → 팝업 요약에 신원 줄(provider) → 승인 → 로그인 성공', async () => {
    await rpPage.click('#loginBtn');
    await viaPopup(() => rpPage.click('#googleLoginBtn'), async (popup) => { await waitText(popup, '#authSummary', stub.provider); await approve(popup); });
    await waitText(rpPage, '#verdict', '로그인 성공', 120_000);
  });
  await t('G4 계정 페이지(localhost): Google 폐기 행 → stub 버튼 → 200 revoked; 데모 uid/pwd 폼은 그대로 있다', async () => {
    const acct = await context.newPage();
    await acct.goto(`${cia.base.replace('127.0.0.1', 'localhost')}/account`);
    await acct.waitForSelector('#googleRevokeRow:not([hidden])'); await acct.waitForSelector('#googleRevokeSlot .gsi-stub', { timeout: 30_000 });
    assert.ok(await acct.$('#revokeBtn'), '데모 폼 유지');
    await setSub(acct, SUB1);
    acct.once('dialog', (d) => d.accept());
    await acct.click('#googleRevokeSlot .gsi-stub');
    await waitText(acct, '#out', '→ 200', 30_000);
    await acct.close();
  });
  await t('G5 폐기 뒤 RP Google 로그인은 account_disabled', async () => {
    await rpPage.click('#loginBtn');
    await viaPopup(() => rpPage.click('#googleLoginBtn'), async (popup) => { await approve(popup); });
    await waitText(rpPage, '#verdict', 'account_disabled', 120_000);
  });
  await t('G6 모두 지우기 → 두 번째 Google 계정으로 등록 → 사용자 페이지의 Google 폐기 행(폐기 버튼 대신)으로 자기 폐기 → revoked', async () => {
    userPage.once('dialog', (d) => d.accept());
    await userPage.click('#wipeBtn');
    await waitText(userPage, '#storageVerdict', '지웠습니다', 30_000);
    await userPage.waitForSelector('#googleRegSlot .gsi-stub', { timeout: 30_000 });
    await setSub(userPage, SUB2);
    await userPage.fill('#vaultPw', PW); await userPage.fill('#vaultPw2', PW);
    await userPage.click('#googleRegSlot .gsi-stub');
    await waitText(userPage, '#registerResult', '등록됨', 90_000);
    await userPage.waitForSelector('#googleRevokeRow:not([hidden])'); await userPage.waitForSelector('#googleRevokeSlot .gsi-stub', { timeout: 30_000 });
    assert.equal(await userPage.isHidden('#selfRevokeBtn'), true, 'Google 계정에는 비밀번호 폐기 버튼이 없다');
    userPage.once('dialog', (d) => d.accept());
    await userPage.click('#googleRevokeSlot .gsi-stub');
    await waitText(userPage, '#storageVerdict', '폐기', 60_000);
    const r = await cia.adminGet('/cia/accounts'); const acc = (r.body.accounts ?? r.body).find((a) => String(a.uid) === uidOf(stub.provider, SUB2)); assert.equal(acc?.disabled, true);
  });
  await t('G7 127.0.0.1 로 연 사용자 페이지: Google 행 대신 localhost 안내(gsi_origin)와 링크', async () => {
    const p = await context.newPage();
    await p.goto(`${wallet.base.replace('localhost', '127.0.0.1')}/`);
    await p.waitForSelector('#mainView:not([hidden])');
    await p.waitForSelector('#googleRegNote:not([hidden])');
    assert.ok((await text(p, '#googleRegNote')).includes('localhost')); assert.equal(await p.getAttribute('#googleRegNote a', 'href'), `${wallet.base}/`);
    assert.equal(await p.isHidden('#googleRegRow'), true);
    await p.close();
  });
  await t('G8 GIS 스크립트를 못 받으면(스텁 없음 + 네트워크 차단) gsi_unavailable 안내 — 데모 계정 등록 폼은 그대로', async () => {
    const ctx2 = await browser.newContext();
    await ctx2.route('https://accounts.google.com/**', (r) => r.abort());
    const p = await ctx2.newPage();
    await p.goto(`${wallet.base}/`); await p.waitForSelector('#mainView:not([hidden])');
    await p.waitForSelector('#googleRegNote:not([hidden])', { timeout: 20_000 });
    assert.ok((await text(p, '#googleRegNote')).includes('Google'), await text(p, '#googleRegNote'));
    assert.ok(await p.$('#registerBtn'));
    await ctx2.close();
  });
  await t('G9 사전: 새 사유 6개와 ui 키가 ko·en 으로 있다(strings.js 를 페이지가 아니라 파일로)', async () => {
    const src = readFileSync('mode3/common/strings.js', 'utf8');
    for (const k of ['oidc_disabled', 'oidc_invalid', 'oidc_nonce_mismatch', 'oidc_unavailable', 'gsi_unavailable', 'gsi_origin', 'user_register_hint_google', 'user_auth_identity', 'account_google_revoke_label', 'rp_google_login_note']) assert.ok(src.includes(`${k}:`), k);
  });
} finally { await browser.close(); await stack.stop(); }
process.exit(failed ? 1 : 0);
```
(`G4` 의 `'→ 200'` 바늘은 계정 페이지가 `$('out')` 에 쓰는 `POST /cia/account/self_revoke → ${r.status}` 형식에 맞춘 것이다. `cia.base` 가 이미 localhost 면 `replace` 는 무해하다.)

- [ ] **Step 2: 실패 확인** — `node tests/test_mode3_user_web_oidc.mjs` → G1 에서 `data-oidc` 가 null(또는 `#authHint` 없음)로 실패. Chrome 이 없으면 `BLOCKED:`.
- [ ] **Step 3: 구현** — 위 Interfaces 순서대로: `gsi.js` → `strings.js`·`test_mode3_demo_strings.js` → `index.html`·`ui.js`·`user.js`·`popup.js` → `mode3_rp.js`·`rp.html` → `cia_account.html`. `node scripts/build_user_app.mjs` 가 깨지지 않는지 중간중간 확인. `innerHTML` 금지(모든 동적 텍스트는 `textContent`, 링크는 `createElement`).
- [ ] **Step 4: 통과 확인** — `node tests/test_mode3_user_web_oidc.mjs` 9개 ok(약 3~5분). 회귀: `node tests/test_mode3_demo_strings.js`, `node tests/test_mode3_user_web.mjs`(14/14 — 등록 카드 리팩터·팝업 변경), `node tests/test_mode3_browser.mjs`·`node tests/test_mode3_tour.mjs`(rp.html 의 `startIdpLogin` 시그니처·Google 버튼 핸들러), `node tests/test_mode3_rp.mjs`(rp_info).
- [ ] **Step 5: `scripts/run_tests.sh` BROWSER 배열 `tests/test_mode3_user_web.mjs` 다음에 `tests/test_mode3_user_web_oidc.mjs` 추가. 커밋** — `feat(user-web): Google 로 등록·자기 폐기(GIS 로더·사용자 페이지·팝업 신원 줄·RP 모달 Google 버튼·계정 페이지), 사유·문구`.

---

### Task 6: 런북·스펙 상태·테스트 목록

**Files:**
- Modify: `docs/MODE3_DEMO.md`(§"브라우저 전용 사용자 페이지" 아래 새 소절, §"테스트" 두 줄, 기동 순서의 env)
- Modify: `docs/superpowers/specs/2026-10-16-mode3-oidc-wrapper-design.md`(상태 줄 1개)
- (`scripts/run_tests.sh` 는 Task 1·2·3·4·5 가 각각 넣었다 — 여기서는 네 그룹에 다 들어갔는지 확인만)

**Interfaces:** 없음(문서).

- [ ] **Step 1: 런북 소절** — `docs/MODE3_DEMO.md` 의 `### 다른 기계에서 web 모드로` 다음(= `## 엔드포인트` 앞)에 `### Google 로 등록·자기 폐기 (OIDC 래퍼, 2026-10-16)` 를 쓴다. 내용(기존 문체·용어 유지, 과장 없이):
  - 무엇이 바뀌고 무엇이 안 바뀌는지 한 문단: IdP 가 Google ID 토큰을 **체인 밖에서** 검증해 `uid = SHA-256("google|" + sub) mod 2^250` 으로 계정을 만든다; 회로·PS 토큰·로그인·폐기 트리 불변; Google 토큰은 등록·자기 폐기 때만 쓰고 저장하지 않는다; IdP 는 Google 계정과 uid 를 연결할 수 있다(데모 계정과 같은 신뢰 수준 — 스펙 §5).
  - 준비: Google 콘솔의 Mode 1 OAuth 클라이언트에 승인된 JavaScript 원본 `http://localhost:5100`·`http://localhost:4100` 추가(리다이렉트 URI 불필요). env: IdP `MODE3_OIDC_CLIENT_ID`(없으면 `GOOGLE_CLIENT_ID` 를 쓴다; 둘 다 없으면 꺼짐 — 버튼이 숨고 데모 계정만), 선택 `MODE3_OIDC_ISSUER`·`MODE3_OIDC_JWKS_URL`·`MODE3_OIDC_PROVIDER`(기본 Google). **사용자 오리진을 localhost 로**: 정적 서버 `MODE3_WALLET_PUBLIC_ORIGIN=http://localhost:5100`, IdP·RP 의 `MODE3_WALLET_AGENT_ORIGIN=http://localhost:5100`; 브라우저도 `http://localhost:5100/` 로 연다(127.0.0.1 로 열면 Google 행 대신 안내만 — Google 이 127.0.0.1 원본을 받지 않는다). 계정 페이지도 `http://localhost:4100/account`.
  - 수동 체크리스트(스펙 §6): Google 로 등록 → zkONE 로그인(모달 Google 버튼) → zkTWO 로그인 → 계정 페이지 Google 로 자기 폐기 → 재검증 `revoked`/다음 로그인 `account_disabled`. 재시연 세트에 "Google 로 등록한 브라우저의 모두 지우기" 추가.
  - 사유 표(짧게): `oidc_disabled` 503 / `oidc_invalid` 401 / `oidc_nonce_mismatch` 400 / `oidc_unavailable` 502 / `gsi_unavailable`·`gsi_origin`(페이지 전용).
  - 한계: Google 외 발급자 미확인, 이메일·이름 표시 없음, Snap·에이전트(file) 모드는 Google 등록 없음, 계정 연결 없음(스펙 §8).
- [ ] **Step 2: 테스트 목록** — §"테스트" 의 `unit` web 모드 셋 문단 끝에 `tests/test_mode3_oidc_nonce.js`(uid·nonce 유도)·`tests/test_mode3_oidc_verifier.mjs`(jose 검증, 발급자 스텁) 추가; `chain` 문단에 `tests/test_cia_oidc_register.mjs`(IdP 의 id_token 등록·폐기 9케이스)·`tests/test_mode3_user_core_oidc.mjs`(코어 prepare/complete·id_token 폐기, 격리 스택 `oidc`·`walletHost` 옵션) 추가; `browser` 문단에 `tests/test_mode3_user_web_oidc.mjs`(G1~G9, GIS 스텁·localhost 오리진) 추가.
- [ ] **Step 3: 스펙 상태 줄** — 스펙 파일 머리(제목 아래 첫 줄)에 `> 상태: 구현 완료 2026-10-16 — 계획 docs/superpowers/plans/2026-10-16-mode3-oidc-wrapper.md. D4 는 계획 중 pk_u 결속으로 수정(본문 참조).` (날짜는 `date` 실행값).
- [ ] **Step 4: 확인** — `grep -n oidc scripts/run_tests.sh` 에 5개 파일이 보이는지; `node tests/test_mode3_demo_strings.js`.
- [ ] **Step 5: 커밋** — `docs(mode3): OIDC 래퍼 런북(Google 콘솔·env·localhost 오리진·체크리스트·사유·한계), 테스트 목록, 스펙 상태`.

---

## 자기 검토

**1. 스펙 커버리지**
| 스펙 | 태스크 |
|---|---|
| D1 IdP 체인 밖 검증(jose RS256·iss·aud·exp) | Task 2·3 |
| D2 `uid = SHA-256(provider|sub) mod 2^250` | Task 1(`uidOf`), Task 3·4 사용 |
| D3 GIS 브라우저 직접 + 공개 클라이언트 ID | Task 5(`gsi.js`, `public_keys.oidc.clientId`) |
| D4 nonce 결속(수정: pk_u) | Task 1·3·4; 스펙 본문 수정 완료 |
| D5 GIS 로더·오프라인 사유 | Task 5(`gsi_unavailable`) |
| D6 localhost 오리진 통일 | Task 4(`walletHost`)·5(`originOk`, `gsi_origin`)·6(런북 env) |
| D7 `accounts[uid].provider`, 상태 이행 `??= 'demo'` | Task 3 |
| §3.1 등록 흐름 | Task 4(코어)·5(화면)·3(IdP) |
| §3.2 RP 모달 Google 버튼·미등록 안내·신원 줄 | Task 5 |
| §3.3 자기 폐기(사용자·계정 페이지) | Task 3(IdP)·4(코어)·5(화면) |
| §4 사유 6개 | Task 3(IdP 4개)·5(문구 6개) |
| §5 보안(토큰 비저장·nonce·결속) | Task 3(토큰은 검증만, 저장 안 함)·4 |
| §6 런북 | Task 6 |
| §7 테스트 unit/chain/browser | Task 1·2 / 3·4 / 5 |
| §8 범위 밖 | 어떤 태스크도 넘지 않음(이메일·이름 표시 없음, Snap 경로 불변) |

**2. 플레이스홀더 점검** — "TBD/TODO/적절히/나중에" 없음. Task 5 의 문구는 키와 의미를 적었고 정확한 한국어·영어 문장은 구현자가 사전 문체에 맞춰 쓴다(사전의 다른 항목처럼 `title·cause·action` 구조 — 플레이스홀더가 아니라 문체 위임).

**3. 타입·이름 일관성** — `regNonce(pk_u)`(Task 1·3·4), `verify(idToken, { noncePrefix })`(Task 2·3), `createOidcVerifier({ issuer, jwksUrl, clientId })`(2·3), `startOidcIssuerStub` 반환 `{ base, issuer, jwksUrl, clientId, provider, mint, stop }`(2·3·4·5 — Task 5 의 GIS 스텁이 부르는 `POST ${stub.base}/mint → { id_token }` 는 Task 2 스텁 코드에 CORS `*` 로 들어 있다, 확인함), `startIsolatedCia({ oidc })` → `.oidc`(3·4), `startIsolatedMode3Stack({ oidc, walletHost })` → `.oidc`(4·5), 코어 `prepareRegistration()`·`completeRegistration({ idToken, profile, vaultPassword })`·`selfRevokeWithIdToken({ idToken })`·`status().provider`(4·5), `core.idp.publicKeys()`(5 — Task 4 가 `idp` 를 노출하지 않으면 Task 5 가 한 줄 추가), 응답 `{ slot, schemaHash, uid, provider }`(3·4), 사유 이름 6개(3·5·6), `req.provider`(5 rp.html ↔ popup.js), 요소 id(`googleRegRow/Slot/Note`, `googleRevokeRow/Slot/Note`, `authHint`, `data-oidc`)(5 구현 ↔ 5 테스트).
