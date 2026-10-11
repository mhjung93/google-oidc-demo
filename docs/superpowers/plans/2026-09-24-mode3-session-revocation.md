# Mode 3 세션 폐기(V8) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 세션 하나만 폐기할 수 있게 한다 — RCL 에 세션 리프 `Poseidon(5, Cf_s)` 를 넣고 회로가 두 번째 비멤버십을 증명하며, 사용자(지갑, `sk_u` 서명)와 AA 운영자가 폐기할 수 있다.

**Architecture:** 같은 IMT 에 태그 5 리프를 추가한다(서비스·컨트랙트·공개 입력 불변, 검증자 컨트랙트만 재생성). AA 는 상태 v8 에 사용자별 세션 기록 `{Cf_s, max_height, chainid, allowAgent, issuedAt, revokedAt}` 을 두고 `/cia/revoke scope=session` 을 받는다. 지갑은 세션 리프 비멤버십 증인을 하나 더 만들고, 세션 리프가 트리에 있으면 그 세션만 `revoked_session` 으로 정리한다.

**Tech Stack:** circom 2.1.9 + circomlib(IMTNonMembershipV2 재사용), snarkjs Groth16(pot21), Node ESM(express, ethers v6, circomlibjs EdDSA-Poseidon), MetaMask Snap(snaps-sdk, Poseidon 없음), `t()` 러너 테스트.

**Spec:** `docs/superpowers/specs/2026-09-24-mode3-session-revocation-design.md`

## Global Constraints

- 세션 리프 = `leafValue(TAG_MODE3_SESSION = 5n, Cf_s)`(`lib/imt_v2.js` `leafValue` — 252비트 마스킹 포함), 사용자 리프 `leafValue(4n, Cf_u)` 와 같은 트리.
- 회로 공개 입력 25개·순서 불변; 비공개 입력 `s_lowValue, s_lowNextIndex, s_lowNextValue, s_pathElements[32], s_pathIndices[32]` 추가; `TAG_MODE3_SESSION = 5`.
- AA 상태 `CIA_STATE_VERSION = 8`, `accounts[uid].sessions[]`, v7→v8 이행은 `sessions = []`.
- `/cia/revoke` 본문 `{ uid, scope:'session', Cf_s, sig_u?, nonce? }`; 관리자 헤더(`X-CIA-Admin-Secret`) 없으면 `sig_u`·`nonce` 필수; 서명 메시지 `Poseidon(DOMAIN_MODE3_REVOKESESS, uid, Cf_s, nonce)`, `DOMAIN_MODE3_REVOKESESS = BigInt('0x' + Buffer.from('MODE3REVOKESESS').toString('hex'))`.
- 응답: 404 `unknown_session`, 409 `expired`(해당 체인 head ≥ max_height), 멱등 200 `{inserted:false}`, 성공 200 `{inserted:true, leaf, root, pending}`.
- 지갑 사유: 사용자 리프 → `revoked`, 세션 리프 → `revoked_session`(그 세션만 삭제). 서비스 페이지는 둘 다 세션 해제.
- Snap 에는 Poseidon 이 없다 → Snap RPC `consentRevokeSession` 은 **동의만** 하고, 서명은 에이전트가 한다(file 모드: 파일 `sk_u`, snap 모드: 세션 메모리 증인 `s.witness.sk_u`; 없으면 409 `needs_consent`).
- 산출물 재생성은 `bash scripts/build_mode3_circuit.sh pot21_final.ptau` 로만. `npm run zk:*` 금지. 새 테스트는 `scripts/run_tests.sh` 그룹에 등록.
- 커밋 메시지 한글 + 세션 트레일러 두 줄. `.env`·`*_keys.json`·`*_state.json` 은 읽지 않는다.

---

## 파일 구조

| 파일 | 책임 | 작업 |
|---|---|---|
| `lib/mode3_cia_state.js`, `lib/mode3_revocation.js`, `lib/mode3_issuance.js` | 상태 v8, 세션 리프, 폐기 서명 메시지 | T1 |
| `tests/test_mode3_cia_state.js`, `tests/test_mode3_revocation_tree.js` | 단위 테스트 | T1 |
| `circuits/pi_cred.circom`, `tests/helpers/mode3_fixture.mjs`, `tests/test_pi_cred_witness.mjs`, `contracts/PiCredVerifier.sol`(재생성) | 회로 V8 + 산출물 | T2 |
| `cia.js`, `mode3/cia_admin.html` | 세션 기록·폐기 API·관리자 UI | T3 |
| `tests/test_mode3_session_revoke.mjs` (신규, chain) | CIA 세션 폐기 분기 | T3 |
| `lib/mode3_wallet.js`, `mode3_wallet_agent.js`, `mode3/wallet.html`, `mode3/rp.html`, `snap-mode3/src/index.js`(+dist) | 증인·`revoked_session`·폐기 라우트·UI·동의 | T4 |
| `tests/test_mode3_wallet_agent.mjs`, `snap-mode3/test/rpc.test.mjs`, `tests/test_mode3_demo_stack.mjs` | 통합 테스트 | T4·T5 |
| `docs/MODE3_DEMO.md`, `results/mode3_session_revocation_20260924.md`, `scripts/run_tests.sh` | 문서·측정 | T5 |

---

### Task 1: 상태 v8 · 세션 리프 · 폐기 서명 메시지

**Files:**
- Modify: `lib/mode3_cia_state.js`, `lib/mode3_revocation.js`, `lib/mode3_issuance.js`
- Modify: `tests/test_mode3_cia_state.js`, `tests/test_mode3_revocation_tree.js`

**Interfaces:**
- Produces: `CIA_STATE_VERSION = 8`; `accounts[uid].sessions: []`; `TAG_MODE3_SESSION = 5n`, `sessionLeaf(Cf_s: bigint) → Promise<bigint>`; `DOMAIN_MODE3_REVOKESESS`, `revokeSessionMessage(uid: bigint, Cf_s: bigint, nonce: bigint) → Promise<bigint>`.

- [ ] **Step 1: 실패하는 테스트**

`tests/test_mode3_cia_state.js`: 기존 `기본 상태는 v7…`·`v7 는 그대로…` 케이스의 7 → 8(deepEqual 의 version 8), 그리고 추가:

```js
t('v7 → v8: 계정마다 sessions:[] 가 생기고 다른 필드는 그대로', () => {
  const s = { version: 7, accounts: { '1': { creds: [{ Cf_u: '9', leaf: '8', revoked: false }], attrs: ['1', '2', '3', '4'], disabled: false } }, rps: {}, openings: [], revoked: [], pending: [], epoch: 3 };
  const { state, notes } = migrateCiaState(s);
  assert.equal(state.version, 8);
  assert.deepEqual(state.accounts['1'].sessions, []);
  assert.deepEqual(state.accounts['1'].creds, [{ Cf_u: '9', leaf: '8', revoked: false }]);
  assert.equal(state.epoch, 3);
  assert.ok(notes.some((n) => n.startsWith('v7→v8')));
});
t('v8 는 그대로이고 sessions 가 빠진 계정은 채워진다', () => {
  const s = { version: 8, accounts: { '1': { creds: [] } }, rps: {}, openings: [], revoked: [], pending: [], epoch: 0 };
  const { state, notes } = migrateCiaState(s);
  assert.deepEqual(notes, []); assert.deepEqual(state.accounts['1'].sessions, []);
});
```

`tests/test_mode3_revocation_tree.js`(import 에 `TAG_MODE3_SESSION, sessionLeaf` 추가):

```js
await t('세션 리프 태그는 5 — 같은 Cf 라도 userLeaf 와 sessionLeaf 는 다르다', async () => {
  assert.equal(TAG_MODE3_SESSION, 5n);
  const a = await userLeaf(123n), b = await sessionLeaf(123n);
  assert.notEqual(a, b);
  assert.ok(b < (1n << 252n));
  assert.equal(b, await sessionLeaf(123n));
});
```

`tests/test_mode3_revocation_tree.js` 끝에(issuance 도메인):

```js
await t('revokeSessionMessage: 도메인은 ASCII MODE3REVOKESESS, 입력이 하나라도 다르면 값이 다르다', async () => {
  const { DOMAIN_MODE3_REVOKESESS, revokeSessionMessage } = await import('../lib/mode3_issuance.js');
  assert.equal(Buffer.from(DOMAIN_MODE3_REVOKESESS.toString(16), 'hex').toString(), 'MODE3REVOKESESS');
  const m = await revokeSessionMessage(1n, 2n, 3n);
  assert.notEqual(m, await revokeSessionMessage(1n, 2n, 4n));
  assert.notEqual(m, await revokeSessionMessage(1n, 5n, 3n));
});
```

- [ ] **Step 2: 실패 확인** — `node tests/test_mode3_cia_state.js; node tests/test_mode3_revocation_tree.js` → v8·sessionLeaf 없음으로 FAIL.

- [ ] **Step 3: 구현**

`lib/mode3_cia_state.js`: 머리 주석에 `// version 8 (2026-09-24): accounts[uid].sessions = [{ Cf_s, max_height, chainid, allowAgent, issuedAt, revokedAt }] — 세션 단위 폐기(설계 2026-09-24). 옛 세션은 기록이 없어 폐기 불가.` `CIA_STATE_VERSION = 8`. `if (state.version === 6) {…}` 블록 뒤:

```js
  if (state.version === 7) {
    for (const a of Object.values(state.accounts ?? {})) a.sessions ??= [];
    state.version = 8;
    notes.push('v7→v8: 계정마다 sessions:[] — 이전에 발급된 세션은 기록이 없어 세션 단위 폐기가 안 된다(만료로만 끝난다)');
  }
```

꼬리의 `for (const a of Object.values(state.accounts)) a.creds ??= [];` → `{ a.creds ??= []; a.sessions ??= []; }`.

`lib/mode3_revocation.js`(`TAG_MODE3_USER` 아래):

```js
/** 세션 리프 태그(2026-09-24 세션 폐기). 사용자 리프(4)와 같은 트리에 들어가므로 값을 가른다. */
export const TAG_MODE3_SESSION = 5n;
/** 세션 폐기 리프 = leafValue(5, Cf_s). Cf_s 는 회로가 공개 arid·pk_i 로 재계산하므로 다른 값을 들이밀 수 없다. */
export async function sessionLeaf(Cf_s) {
  return leafValue(TAG_MODE3_SESSION, Cf_s);
}
```

`lib/mode3_issuance.js`(도메인 상수 옆):

```js
export const DOMAIN_MODE3_REVOKESESS = BigInt('0x' + Buffer.from('MODE3REVOKESESS').toString('hex'));   // /cia/revoke scope=session 사용자 서명
/** 세션 폐기 요청의 사용자 서명 메시지 = Poseidon(D_REVOKESESS, uid, Cf_s, nonce). nonce 신선도는 검사하지 않는다(재생 = 같은 세션을 다시 폐기, 멱등). */
export async function revokeSessionMessage(uid, Cf_s, nonce) {
  const ps = await getPs();   // 파일의 기존 Poseidon 접근자(line 30)
  return ps.F.toObject(ps([DOMAIN_MODE3_REVOKESESS, uid, Cf_s, nonce]));
}
```

(`attrsRequestMessage` 가 Poseidon 을 얻는 방식을 그대로 따른다.)

- [ ] **Step 4: 통과 확인** — 두 파일 전부 ok. `bash scripts/run_tests.sh unit` 통과.
- [ ] **Step 5: Commit** — `feat(mode3): 세션 폐기 기반 — CIA 상태 v8(sessions), 세션 리프 태그 5, 폐기 요청 서명 메시지`

---

### Task 2: 회로 V8 + 산출물 재생성 + 컨트랙트 그룹

**Files:**
- Modify: `circuits/pi_cred.circom`, `tests/helpers/mode3_fixture.mjs`, `tests/test_pi_cred_witness.mjs`
- Regenerate: `build/mode3/*`(git 밖), `contracts/PiCredVerifier.sol`

**Interfaces:**
- Consumes: T1 `sessionLeaf`.
- Produces: 회로 입력 `s_lowValue, s_lowNextIndex, s_lowNextValue, s_pathElements[32], s_pathIndices[32]`; 픽스처 `buildValidInput({ revokedSessions = [] })` 가 `Cf_s` 를 돌려주고 입력에 `s_*` 를 채운다.

- [ ] **Step 1: 픽스처** — `import { userLeaf, sessionLeaf, createRevocationTree } from '../../lib/mode3_revocation.js';` 시그니처에 `revokedSessions = []`. `await tree.insert(await userLeaf(999n));` 뒤:

```js
  for (const c of revokedSessions) await tree.insert(await sessionLeaf(BigInt(c)));   // 남의 세션 폐기 리프 — 내 세션 비멤버십은 성립해야 한다
  const ws = await tree.getNonMembershipWitness(await sessionLeaf(Cf_s));
```

`input` 에 `s_lowValue: ws.lowValue.toString(), s_lowNextIndex: ws.lowNextIndex.toString(), s_lowNextValue: ws.lowNextValue.toString(), s_pathElements: ws.pathElements.map(String), s_pathIndices: ws.pathIndices.map(String),`. (`revRoot` 는 두 증인이 같은 트리에서 나오므로 그대로.) 반환에 `Cf_s` 는 이미 있다.

- [ ] **Step 2: 실패하는 witness 테스트** — 파일 끝(V7 케이스 뒤):

```js
await t('V8 양성: 남의 세션 폐기 리프가 있어도 내 세션 비멤버십은 성립', async () => {
  const fx = await buildValidInput({ revokedSessions: [777n, 778n] });
  await witness(fx.input);
});
await t('V8 음성: 내 세션 리프 Poseidon(5, Cf_s) 가 트리에 있으면 거부 — 사용자 리프는 그대로', async () => {
  const fx = await buildValidInput();
  await fx.tree.insert(await sessionLeaf(fx.Cf_s));
  await assert.rejects(() => witness({ ...fx.input, revRoot: fx.tree.getRoot().toString() }), /Assert Failed/);
});
await t('V8 음성: 세션 증인을 사용자 증인으로 바꿔치기하면 거부', async () => {
  const fx = await buildValidInput();
  await assert.rejects(() => witness({ ...fx.input, s_lowValue: fx.input.lowValue, s_lowNextIndex: fx.input.lowNextIndex, s_lowNextValue: fx.input.lowNextValue, s_pathElements: fx.input.pathElements, s_pathIndices: fx.input.pathIndices }), /Assert Failed/);
});
```

(`import { userLeaf, sessionLeaf, … }` 추가.) 세 번째 케이스: 사용자 증인은 `leaf(4, Cf_u)` 의 구간을 가리키므로 세션 리프 값이 그 구간에 있을 확률은 무시할 수 있다 — 거부되어야 한다.

- [ ] **Step 3: 실패 확인** — `node tests/test_pi_cred_witness.mjs 2>&1 | tail -5` → V8 케이스 FAIL(입력 없음).

- [ ] **Step 4: 회로** — Private 블록 `pathIndices[depth];` 뒤:

```
    // V8(2026-09-24) 세션 리프 비멤버십 증인
    signal input s_lowValue;
    signal input s_lowNextIndex;
    signal input s_lowNextValue;
    signal input s_pathElements[depth];
    signal input s_pathIndices[depth];
```

`var TAG_MODE3_USER = 4;` 아래 `var TAG_MODE3_SESSION = 5;  // 세션 리프(2026-09-24)`. ④ 블록 `nm.root <== revRoot;` 뒤:

```
    // ---- ④′ 세션 비멤버십 (2026-09-24 V8) ----
    // Cf_s 는 ② 에서 공개 arid·pk_i 로 재계산한 값 — 다른 세션의 Cf_s 를 들이밀 수 없다. 같은 트리, 같은 root.
    component sLeaf = Poseidon(2);
    sLeaf.inputs[0] <== TAG_MODE3_SESSION;
    sLeaf.inputs[1] <== Cf_s;
    component nmS = IMTNonMembershipV2(depth);
    nmS.target <== sLeaf.out;
    nmS.lowValue <== s_lowValue;
    nmS.lowNextIndex <== s_lowNextIndex;
    nmS.lowNextValue <== s_lowNextValue;
    for (var i = 0; i < depth; i++) {
        nmS.pathElements[i] <== s_pathElements[i];
        nmS.pathIndices[i] <== s_pathIndices[i];
    }
    nmS.root <== revRoot;
```

머리 주석에 `// V8(2026-09-24): 세션 리프 Poseidon(5, Cf_s) 비멤버십 추가 — 설계 2026-09-24-mode3-session-revocation-design.md §3`.

- [ ] **Step 5: 통과 확인** — witness 테스트 전부 ok, 제약 수 기록(≈34k).
- [ ] **Step 6: 재생성·컨트랙트** — `bash scripts/build_mode3_circuit.sh pot21_final.ptau`, `npx hardhat compile`, `bash scripts/run_tests.sh contract` → 94 passing(픽스처가 `s_*` 를 채우므로 기존 케이스가 그대로 돈다).
- [ ] **Step 7: Commit** — `git add circuits/pi_cred.circom tests/helpers/mode3_fixture.mjs tests/test_pi_cred_witness.mjs contracts/PiCredVerifier.sol` — `feat(mode3): 회로 V8 — 세션 리프 비멤버십(태그 5) 추가, 공개 입력 불변; 검증자 재생성`

---

### Task 3: CIA — 세션 기록, `/cia/revoke scope=session`, 관리자 세션 목록·정리

**Files:**
- Modify: `cia.js`, `mode3/cia_admin.html`
- Create: `tests/test_mode3_session_revoke.mjs` (chain 그룹, `scripts/run_tests.sh` CHAIN 배열에 추가)

**Interfaces:**
- Consumes: T1 `sessionLeaf`, `revokeSessionMessage`.
- Produces: `/cia/issue` 가 `accounts[uid].sessions` 에 push; `POST /cia/revoke {uid, scope:'session', Cf_s, sig_u?, nonce?}`; `GET /cia/admin/sessions?uid=`(requireAdmin) → `{ sessions: [{Cf_s, max_height, chainid, allowAgent, issuedAt, revokedAt, expired: bool}] }`; 하트비트 틱에서 만료 기록 삭제.

- [ ] **Step 1: 실패하는 테스트** — `tests/test_mode3_session_revoke.mjs`(격리 CIA만; `tests/helpers/isolated_cia.mjs` 와 `lib/mode3_wallet.js` 의 `createRegistration/buildUserCredRequest/buildIssueRequest/createSessionKey`, `tests/test_mode3_wallet.mjs` 의 등록→C_u→세션 발급 준비 코드를 그대로 따른다):

```js
// CIA 세션 폐기(2026-09-24 V8). 격리 CIA + :8545. node tests/test_mode3_session_revoke.mjs
import assert from 'node:assert/strict';
import { startIsolatedCia } from './helpers/isolated_cia.mjs';
import { createRegistration, createSessionKey, buildUserCredRequest, buildIssueRequest, signRevokeSession } from '../lib/mode3_wallet.js';
import { sessionLeaf } from '../lib/mode3_revocation.js';
// … t() 러너, cia 기동, testuser 등록(reg, sk_u), C_u 발급(uc), 세션 두 개 발급(issued1, issued2 — 각각 Cf_s) — test_mode3_wallet.mjs 의 준비 코드 복사
await t('발급이 세션 기록을 남긴다(관리자 조회)', async () => {
  const r = await cia.adminGet(`/cia/admin/sessions?uid=${UID}`);
  assert.equal(r.status, 200); assert.equal(r.body.sessions.length, 2);
  assert.ok(r.body.sessions.some((s) => s.Cf_s === issued1.body.Cf_s && s.revokedAt === null));
});
await t('사용자 서명으로 세션 하나 폐기 → 리프 pending, 다시 하면 멱등, 다른 세션은 그대로', async () => {
  const nonce = 12345n;
  const sig_u = await signRevokeSession(sk_u, UID, BigInt(issued1.body.Cf_s), nonce);
  const r = await cia.post('/cia/revoke', { uid: UID, scope: 'session', Cf_s: issued1.body.Cf_s, sig_u, nonce: nonce.toString() });
  assert.equal(r.status, 200, JSON.stringify(r.body)); assert.equal(r.body.inserted, true);
  assert.equal(BigInt(r.body.leaf), await sessionLeaf(BigInt(issued1.body.Cf_s)));
  const again = await cia.post('/cia/revoke', { uid: UID, scope: 'session', Cf_s: issued1.body.Cf_s, sig_u, nonce: nonce.toString() });
  assert.equal(again.status, 200); assert.equal(again.body.inserted, false);
  const list = (await cia.adminGet(`/cia/admin/sessions?uid=${UID}`)).body.sessions;
  assert.ok(list.find((s) => s.Cf_s === issued1.body.Cf_s).revokedAt);
  assert.equal(list.find((s) => s.Cf_s === issued2.body.Cf_s).revokedAt, null);
});
await t('서명이 다른 세션 것이면 400, 관리자 헤더 없이 서명도 없으면 401, 모르는 Cf_s 는 404', async () => {
  const bad = await signRevokeSession(sk_u, UID, BigInt(issued2.body.Cf_s), 1n);
  assert.equal((await cia.post('/cia/revoke', { uid: UID, scope: 'session', Cf_s: issued1.body.Cf_s, sig_u: bad, nonce: '1' })).status, 400);
  assert.equal((await cia.post('/cia/revoke', { uid: UID, scope: 'session', Cf_s: issued2.body.Cf_s })).status, 401);
  assert.equal((await cia.adminPost('/cia/revoke', { uid: UID, scope: 'session', Cf_s: '424242' })).status, 404);
});
await t('관리자 폐기(서명 없이) 200; 만료된 세션은 409 expired', async () => {
  const r = await cia.adminPost('/cia/revoke', { uid: UID, scope: 'session', Cf_s: issued2.body.Cf_s });
  assert.equal(r.status, 200); assert.equal(r.body.inserted, true);
  // 만료: max_height 를 현재 head 로 발급한 세션을 하나 더 만들고 블록을 진행시킨 뒤 폐기 → 409
  const expiring = await issueWith({ max_height: BigInt(await provider.getBlockNumber()) + 1n });
  await provider.send('evm_mine', []); await provider.send('evm_mine', []);
  const e = await cia.adminPost('/cia/revoke', { uid: UID, scope: 'session', Cf_s: expiring.body.Cf_s });
  assert.equal(e.status, 409); assert.equal(e.body.reason, 'expired');
});
```

(`issueWith`·`cia.adminGet` 은 파일 안에서 정의 — `isolated_cia.mjs` 가 `adminGet` 을 주지 않으면 `adminHeaders` 로 fetch 하는 두 줄 헬퍼를 쓴다. `signRevokeSession` 은 T4 의 함수지만 이 테스트가 먼저 필요하므로 **이 Task 에서 `lib/mode3_wallet.js` 에 추가한다**: `export async function signRevokeSession(sk_uHex, uid, Cf_s, nonce) { const eddsa = await getEddsa(); return sigStrings(eddsa.F, eddsa.signPoseidon(Buffer.from(sk_uHex, 'hex'), eddsa.F.e(await revokeSessionMessage(uid, Cf_s, nonce)))); }` — `signAttrsRequest` 와 같은 꼴.)

- [ ] **Step 2: 실패 확인** — :8545 노드(없으면 `npx hardhat node > /dev/null 2>&1 &`, 끝나면 종료) 후 `node tests/test_mode3_session_revoke.mjs` → 404/500 로 FAIL.

- [ ] **Step 3: 구현** (`cia.js`)

(a) `/cia/issue` 의 `res.json({...})` 직전:

```js
    acct.sessions ??= [];
    acct.sessions.push({ Cf_s: Cf_s.toString(), max_height: mh.toString(), chainid: chainStr, allowAgent: agent.toString(), issuedAt: new Date().toISOString(), revokedAt: null });
    persist();
```

(b) `/cia/revoke`: `requireAdmin` 미들웨어를 떼고 안에서 분기한다 —

```js
app.post('/cia/revoke', async (req, res) => {
  try {
    const { uid, scope, Cf_s, sig_u, nonce } = req.body ?? {};
    const isAdmin = req.get('X-CIA-Admin-Secret') && secretMatches(req.get('X-CIA-Admin-Secret'), ADMIN_SECRET);   // requireAdmin 이 쓰는 비교와 같은 함수
    if (scope !== 'session' && !isAdmin) return res.status(401).json({ error: 'admin secret required' });
    if (!isDec(uid) || !state.accounts[uid]) return res.status(404).json({ error: 'unknown account' });
    if (scope === 'account') return res.json(await revokeAccount(uid));
    if (scope === 'credential') { const inserted = await retireActiveCred(uid); persist(); return res.json({ inserted, root: tree.getRoot().toString(), pending: state.pending.length }); }
    if (scope !== 'session') return res.status(400).json({ error: "scope must be 'account', 'credential' or 'session'" });
    // V8 세션 폐기(설계 2026-09-24 §2.2): 사용자는 sk_u 서명, 운영자는 관리자 시크릿.
    if (!isDec(Cf_s)) return res.status(400).json({ error: 'Cf_s required' });
    const acct = state.accounts[uid];
    const rec = (acct.sessions ?? []).find((s) => s.Cf_s === BigInt(Cf_s).toString());
    if (!isAdmin) {
      if (!sig_u || !isDec(nonce)) return res.status(401).json({ error: 'sig_u and nonce required without admin secret' });
      let ok = false;
      try {
        const m = F.e(await revokeSessionMessage(BigInt(uid), BigInt(Cf_s), BigInt(nonce)));
        ok = eddsa.verifyPoseidon(m, { R8: [F.e(BigInt(sig_u.R8x)), F.e(BigInt(sig_u.R8y))], S: BigInt(sig_u.S) }, [F.e(BigInt(acct.pk_u.x)), F.e(BigInt(acct.pk_u.y))]);
      } catch { ok = false; }
      if (!ok) return res.status(400).json({ error: 'bad user signature' });
    }
    if (!rec) return res.status(404).json({ error: 'unknown session', reason: 'unknown_session' });
    if (rec.revokedAt) return res.json({ inserted: false, root: tree.getRoot().toString(), pending: state.pending.length });
    if ((await headOf(rec.chainid)) >= BigInt(rec.max_height)) return res.status(409).json({ error: 'session expired', reason: 'expired' });
    const leaf = (await sessionLeaf(BigInt(Cf_s))).toString();
    const inserted = await tree.insert(BigInt(leaf));
    if (inserted) { state.revoked.push(leaf); state.pending.push(leaf); }
    rec.revokedAt = new Date().toISOString();
    persist();
    res.json({ inserted, leaf, root: tree.getRoot().toString(), pending: state.pending.length });
  } catch (e) { res.status(e.status || 500).json({ error: e.message }); }
});
```

(`ADMIN_SECRET`·`secretMatches` 는 `requireAdmin` 이 쓰는 이름을 그대로; 서명 검증은 `/cia/issue` 의 코드와 같은 꼴. import: `sessionLeaf`, `revokeSessionMessage`.) **주의**: 관리자 헤더가 틀리게 온 경우도 `isAdmin=false` → scope=session 이면 서명 경로로 흘러간다; account/credential 은 401.

(c) `GET /cia/admin/sessions`:

```js
app.get('/cia/admin/sessions', requireAdmin, async (req, res) => {
  const uid = String(req.query.uid ?? '');
  if (!isDec(uid) || !state.accounts[uid]) return res.status(404).json({ error: 'unknown account' });
  const heads = {};
  const out = [];
  for (const s of state.accounts[uid].sessions ?? []) {
    if (heads[s.chainid] === undefined) { try { heads[s.chainid] = await headOf(s.chainid); } catch { heads[s.chainid] = null; } }
    out.push({ ...s, expired: heads[s.chainid] === null ? null : heads[s.chainid] >= BigInt(s.max_height) });
  }
  res.json({ sessions: out });
});
```

(d) `heartbeatTick` 시작부(`if (publishing || !LOG_ADDRESS) return;` 뒤)에 만료 정리:

```js
  await pruneExpiredSessions();
```

```js
/** V8: 만료된 세션 기록 삭제(리프는 남는다 — 설계 §6). 체인별 head 는 한 번만 읽는다. */
async function pruneExpiredSessions() {
  const heads = {};
  let dropped = 0;
  for (const acct of Object.values(state.accounts)) {
    if (!acct.sessions?.length) continue;
    const keep = [];
    for (const s of acct.sessions) {
      if (heads[s.chainid] === undefined) { try { heads[s.chainid] = await headOf(s.chainid); } catch { heads[s.chainid] = null; } }
      if (heads[s.chainid] !== null && heads[s.chainid] >= BigInt(s.max_height)) dropped++; else keep.push(s);
    }
    acct.sessions = keep;
  }
  if (dropped) persist();
}
```

(e) `mode3/cia_admin.html`: 계정 표 각 행에 "세션" 버튼 → `adminJson('GET', '/cia/admin/sessions?uid=…')` 결과를 그 행 아래 작은 표로(Cf_s 앞 10자리, chainid, max_height, allowAgent, issuedAt, 상태 = revokedAt ? '폐기됨' : expired ? '만료' : '활성') + 활성 행에 "폐기" 버튼 → `call('POST', '/cia/revoke', { uid, scope: 'session', Cf_s })`. 기존 `loadAccounts` 안에 붙인다.

- [ ] **Step 4: 통과 확인** — 새 테스트 전부 ok; `bash scripts/run_tests.sh chain` 의 기존 파일도 통과(발급 응답 형식 불변). `scripts/run_tests.sh` CHAIN 배열에 `tests/test_mode3_session_revoke.mjs` 추가.
- [ ] **Step 5: Commit** — `feat(mode3): CIA 세션 폐기 — 발급 세션 기록(v8), /cia/revoke scope=session(사용자 sk_u 서명·관리자), 관리자 세션 목록·폐기, 만료 기록 정리`

---

### Task 4: 지갑 — 세션 증인·`revoked_session`·`/wallet/session/revoke`·Snap 동의·페이지

**Files:**
- Modify: `lib/mode3_wallet.js`(`buildCredentialProof`), `mode3_wallet_agent.js`, `mode3/wallet.html`, `mode3/rp.html`, `snap-mode3/src/index.js`(+`dist`, `snap.manifest.json`), `snap-mode3/test/rpc.test.mjs`, `tests/test_mode3_wallet_agent.mjs`

**Interfaces:**
- Consumes: T1·T3(`signRevokeSession` 은 T3 에서 추가됨), 회로 V8.
- Produces: 지갑 사유 `revoked_session`; `POST /wallet/session/revoke { r_s }` → 200 `{ revoked: true, inserted, pending }` / 404 `no_session` / 409 `needs_consent`(snap 모드에 증인 없음) / CIA 오류 전달; Snap RPC `consentRevokeSession { arid, issuedAt, maxHeight }` → `{ok:true}|{denied:true}`.

- [ ] **Step 1: 실패하는 테스트**

`snap-mode3/test/rpc.test.mjs`:

```js
await t('consentRevokeSession: 대화상자에 arid·발급 시각이 보이고 승인/거절', async () => {
  answers.push(true);
  assert.deepEqual(await call('consentRevokeSession', { arid: '777', issuedAt: '2026-09-24T00:00:00Z', maxHeight: '1000' }), { ok: true });
  const d = lastDialogText();
  for (const part of ['777', '2026-09-24', '폐기']) assert.ok(d.includes(part), `대화상자에 ${part} 가 없다`);
  answers.push(false);
  assert.deepEqual(await call('consentRevokeSession', { arid: '777', issuedAt: 'x', maxHeight: '1' }), { denied: true });
});
```

`tests/test_mode3_wallet_agent.mjs`(기존 `동기화: 재검증 → 폐기 감지 …` 케이스 앞에; 헬퍼 `loginOnce`, `publishOnce`, `wallet.post`, `verify` 사용):

```js
  await t('V8 세션 폐기: 세션 둘 중 하나를 /wallet/session/revoke → 게시 → 그 세션만 403 revoked_session, 다른 세션은 재검증 성공, 새 로그인 정상', async () => {
    const a = await loginOnce(), b = await loginOnce();
    const r = await wallet.post('/wallet/session/revoke', { r_s: a.r_s });
    assert.equal(r.status, 200, j(r.body)); assert.equal(r.body.revoked, true);
    assert.equal((await wallet.get('/wallet/status')).body.sessions[a.r_s], undefined, '폐기 요청 뒤 지갑은 세션을 버린다');
    await publishOnce();
    const rb = await wallet.post('/wallet/revalidate', { r_s: b.r_s }, { Origin: stack.rpOriginForWallet });
    assert.equal(rb.status, 200, j(rb.body));
    const c = await loginOnce();   // 사용자 자격증명은 살아 있다
    assert.ok(c.r_s);
    const missing = await wallet.post('/wallet/session/revoke', { r_s: '999' });
    assert.equal(missing.status, 404); assert.equal(missing.body.reason, 'no_session');
  });
  await t('V8: 폐기된 세션의 π 를 재검증에 쓰면 revoked_session — 지갑이 세션을 지운 뒤라 404 no_session 로 끝난다(세션 하나가 지갑 밖에서 폐기된 경우는 관리자 폐기로 확인)', async () => {
    const a = await loginOnce();
    // 관리자가 이 세션만 폐기(지갑은 모른다)
    const cf = (await cia.adminGet(`/cia/admin/sessions?uid=${uid}`)).body.sessions.filter((s) => !s.revokedAt).at(-1).Cf_s;
    assert.equal((await cia.adminPost('/cia/revoke', { uid, scope: 'session', Cf_s: cf })).status, 200);
    await publishOnce();
    const r = await wallet.post('/wallet/revalidate', { r_s: a.r_s }, { Origin: stack.rpOriginForWallet });
    assert.equal(r.status, 403, j(r.body)); assert.equal(r.body.reason, 'revoked_session');
    assert.equal((await wallet.get('/wallet/status')).body.userCred?.revoked, false, '사용자 자격증명은 그대로');
  });
```

(`/wallet/revalidate` 의 실제 경로·Origin 규칙은 파일의 기존 재검증 케이스와 같게 맞춘다. `cia.adminGet` 이 없으면 T3 테스트처럼 헬퍼를 둔다.)

- [ ] **Step 2: 실패 확인** — Snap 테스트 FAIL(메서드 없음), 에이전트 테스트 FAIL(404 라우트 없음).

- [ ] **Step 3: 구현**

`lib/mode3_wallet.js` `buildCredentialProof`: `const w = …userLeaf…` 다음에

```js
  // V8: 세션 리프 비멤버십 — 세션이 폐기됐으면 여기서 "is a member" 로 던진다. 호출자(proveSession)가 사용자 리프와 구분한다.
  const ws = await tree.getNonMembershipWitness(await sessionLeaf(BigInt(credential.Cf_s)));
```

input 에 `s_lowValue: String(ws.lowValue), s_lowNextIndex: String(ws.lowNextIndex), s_lowNextValue: String(ws.lowNextValue), s_pathElements: ws.pathElements.map(String), s_pathIndices: ws.pathIndices.map(String),`. import `sessionLeaf`.

`mode3_wallet_agent.js` `proveSession`: `if (synced.tree.has(BigInt(uc.leaf))) throw … 'revoked'` 뒤에

```js
    if (synced.tree.has(await sessionLeaf(BigInt(s.credential.Cf_s)))) throw Object.assign(new Error('revoked_session'), { reason: 'revoked_session' });
```

catch 의 `/is a member/` 분기를: `if (/is a member/.test(e.message ?? '')) { const rs = synced.tree.has(await sessionLeaf(BigInt(s.credential.Cf_s))) ? 'revoked_session' : 'revoked'; throw Object.assign(new Error(rs), { reason: rs }); }`.
재검증(:524)·tx(:634) 의 `e.reason === 'revoked'` 분기 옆에 같은 처리로 `if (e.reason === 'revoked_session') { delete state.sessions[rsKey]; cache.deleteSession(rsKey); persist(); return …403 { reason: 'revoked_session', timings }; }`(`/wallet/tx/prepare` 도 `buildExecute` 를 타므로 함께).

라우트(`/wallet/self_revoke` 옆):

```js
// V8 세션 폐기(설계 2026-09-24 §4): 이 지갑의 세션 하나를 AA 에 폐기 요청한다. 서명은 sk_u — file 모드는 파일, snap 모드는 세션 메모리 증인.
app.post('/wallet/session/revoke', async (req, res) => {
  try {
    const { r_s } = req.body ?? {};
    if (!isDec(r_s)) return res.status(400).json({ error: 'r_s 필요' });
    const rsKey = BigInt(r_s).toString(); const s = state.sessions[rsKey];
    if (!s) return res.status(404).json({ reason: 'no_session' });
    const sk_u = SECRETS === 'snap' ? s.witness?.sk_u : state.registration?.sk_u;
    if (!sk_u) return res.status(409).json({ reason: 'needs_consent' });
    const nonce = randomScalar();   // lib/mode3_credential.js — 다른 요청과 같은 난수원
    const sig_u = await signRevokeSession(sk_u, BigInt(state.registration.uid), BigInt(s.credential.Cf_s), nonce);
    const r = await ciaPost('/cia/revoke', { uid: state.registration.uid, scope: 'session', Cf_s: s.credential.Cf_s, sig_u, nonce: nonce.toString() });
    if (r.status !== 200) return res.status(r.status).json(r.body ?? {});
    delete state.sessions[rsKey]; cache.deleteSession(rsKey); persist();   // 게시 전이라도 이 지갑은 더 쓰지 않는다
    res.json({ revoked: true, inserted: r.body.inserted, pending: r.body.pending });
  } catch (e) { res.status(502).json({ reason: 'cia_unavailable', detail: e.message }); }
});
```

(`signRevokeSession`·`randomScalar` import.)

`snap-mode3/src/index.js`(`selfRevoke` 옆):

```js
    // V8 세션 폐기 동의(설계 §4). Snap 에는 Poseidon 이 없어 서명은 에이전트가 세션 증인의 sk_u 로 한다 — 여기서는 동의만 받는다.
    case 'consentRevokeSession': {
      requireRegistered(state);
      const { arid, issuedAt, maxHeight } = params;
      const ok = await confirm('세션 폐기', [`서비스 arid: ${arid}`, `발급 시각: ${issuedAt}`, `만료 블록: ${maxHeight}`, null, '이 세션을 폐기합니다. 다음 게시부터 이 세션의 로그인·트랜잭션이 거부됩니다.']);
      return ok ? { ok: true } : { denied: true };
    }
```

빌드 `cd snap-mode3 && npm run build`.

`mode3/wallet.html`: 세션 목록의 각 항목에 "이 세션 폐기" 버튼: snap 모드면 먼저 `invokeSnap('consentRevokeSession', { arid: c.arid, issuedAt: c.issuedAt, maxHeight: c.max_height })` 로 동의(거절 시 중단), 그다음 `postJson('/wallet/session/revoke', { r_s })` → 결과를 세션 로그에 출력하고 `refresh()`.

`mode3/rp.html:286`: `if (wb.reason === 'revoked' || wb.reason === 'revoked_session') setSession(null);`.

- [ ] **Step 4: 통과 확인** — `cd snap-mode3 && npm test`; `node tests/test_mode3_wallet_agent.mjs`(:8545) 전부 ok.
- [ ] **Step 5: Commit** — `feat(mode3): 지갑 세션 폐기 — 세션 리프 증인·revoked_session, /wallet/session/revoke(sk_u 서명), Snap 동의 창, 페이지 버튼`

---

### Task 5: 데모 스택 시나리오 · 문서 · 측정 · 전체 검증

**Files:**
- Modify: `tests/test_mode3_demo_stack.mjs`, `docs/MODE3_DEMO.md`, `scripts/run_tests.sh`(T3 에서 추가 안 했으면)
- Create: `results/mode3_session_revocation_20260924.md`

- [ ] **Step 1: 데모 스택 케이스**(V7 케이스 뒤):

```js
  await t('V8 세션 폐기: 세션 둘 → 하나 폐기(지갑 버튼 경로) → 게시 → 그 세션 요청은 거부되고 다른 세션·재로그인은 정상; 계정 폐기는 여전히 전부 죽음', async () => {
    const s1 = await loginViaRp(), s2 = await loginViaRp();
    assert.equal((await wallet.post('/wallet/session/revoke', { r_s: s1.r_s })).status, 200);
    assert.equal((await cia.adminPost('/cia/publish')).status, 200);
    const req1 = await rp.post('/api/mode3/request', { r_s: s1.r_s, body: 'x', sig: 'y' });   // 서비스는 세션 테이블에 있어 revalidate_required 또는 지갑 재검증 404 — 서비스 관점에서는 해당 세션이 더 못 쓰인다
    assert.notEqual(req1.body.ok, true);
    const rv = await wallet.post('/wallet/revalidate', { r_s: s2.r_s }, { Origin: rp.origin });
    assert.equal(rv.status, 200, j(rv.body));
    const s3 = await loginViaRp(); assert.equal(s3.rp.ok, true, j(s3));
  });
```

(요청 경로의 정확한 본문·서명은 파일의 기존 세션 요청 케이스를 따른다 — 핵심 단언은 "s1 은 더 못 쓰고 s2·s3 은 된다".)

- [ ] **Step 2: 문서** — `docs/MODE3_DEMO.md`: `/cia/revoke scope=session`(사용자 서명·관리자), `GET /cia/admin/sessions`, `POST /wallet/session/revoke`, Snap `consentRevokeSession`, 오류 사유 `revoked_session`·`unknown_session`·`expired`·`needs_consent`, 상태 v8 이행 주의(옛 세션은 폐기 불가), 회로 V8 재빌드·팩토리 재배포 주의(0단계), 시나리오 표에 "세션 하나 폐기" 행, 한계(게시 뒤 효력, 리프 재기준화 후속).
- [ ] **Step 3: 측정** — `node scripts/bench_pi_cred.mjs pot21_final.ptau`(제약·증명/검증 ms), `node scripts/bench_mode3_onchain.mjs`(:8545) → `results/mode3_session_revocation_20260924.md`(형식은 `results/mode3_predicates_20260923.md`, V7 대비 표).
- [ ] **Step 4: 전체 검증** — `npm test`, `bash scripts/run_tests.sh contract`, `chain`, `snap`, `browser`(Chrome 있음). 실패는 그대로 보고.
- [ ] **Step 5: Commit** — `test/docs(mode3): 세션 폐기 데모 시나리오, 문서, V8 측정 결과`

---

## Self-Review

**Spec coverage** — §0/§1(리프·태그·공개 입력 불변): T1·T2. §2.1 상태 v8·발급 기록·만료 정리: T1·T3. §2.2 revoke 분기(관리자/서명, 404/409/멱등): T3. §2.3 관리자 페이지·조회 API: T3. §3 회로: T2. §4 지갑(증인, `revoked_session`, 라우트, Snap 동의, 페이지): T4 — Snap 서명 불가 → 동의만(Global Constraints 에 명시, spec §4 의 `signRevokeSession` RPC 를 `consentRevokeSession` 으로 갱신하는 것은 T5 문서 단계에서 spec 에 한 줄 정정). §5 RP 페이지: T4. §6·§7 한계·프라이버시: T5 문서. §8 빌드·측정: T2·T5. §9 테스트: unit(T1)·circuit(T2)·contract(T2)·chain(T3·T4·T5)·snap(T4).

**Placeholder scan** — 각 단계에 코드 있음; 파일 내 기존 헬퍼 이름(`loginOnce`, `publishOnce`, `loginViaRp`, `adminPost`) 은 실존 확인됨, `adminGet` 은 없으면 두 줄 헬퍼 지시.

**Type consistency** — `sessionLeaf(bigint)→bigint`(T1) 를 T2·T3·T4 가 같은 시그니처로 씀; `signRevokeSession(sk_uHex, uid: bigint, Cf_s: bigint, nonce: bigint)`(T3) 를 T4 가 같은 인자로; `/cia/revoke` 본문 필드 `sig_u`·`nonce`(문자열) 를 T3 라우트·T4 에이전트·T3 테스트가 동일하게 씀; 지갑 사유 문자열 `revoked_session` 을 T4 에이전트·rp.html·T4/T5 테스트가 공유.
