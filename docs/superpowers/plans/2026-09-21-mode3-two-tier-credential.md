# Mode 3 자격증명 이중 구조(C_u / C_s) 구현 계획

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 사용자 자격증명 C_u(사용자당 하나, 사용자 속성)와 세션 커밋 C_s(세션마다, arid·pk_i)로 자격증명을 나누고, 폐기 리프를 C_u 에서 뽑아 리프 하나로 그 사용자의 모든 세션을 무효화한다. 세션 속성은 AA 가 세션마다 서명한다.

**Architecture:** 회로 `pi_cred` V5 는 커밋 둘(C_u 7항, C_s 3항)을 열고 서명 `Sign(D_V5, Cf_u, Cf_s, max_height, chainid, allowAgent)` 을 검증하며 리프 `Poseidon(4, Cf_u)` 의 비멤버십을 보인다. 공개 입력 14개와 순서는 그대로라 서비스 검증기·Mode3Wallet·RevocationLog 컨트랙트 코드는 바뀌지 않는다. CIA 는 `/cia/user_cred`(π_u 시그마 + sig_u, 드묾)와 `/cia/issue` V5(sig_u + C_u 조회, ZKP 없음)를 제공하고 세션 기록을 갖지 않는다. 지갑은 userCred 를 등록에 보관하고 로그인마다 C_s 를 만든다.

**Tech Stack:** circom 2.1.9 + snarkjs 0.7.5(Groth16, BN254), circomlibjs(Baby Jubjub, Poseidon, EdDSA), Node 22 ESM, express, ethers 6, hardhat(in-process/:8545).

**Spec:** `docs/superpowers/specs/2026-09-21-mode3-two-tier-credential-design.md`

## Global Constraints

- 모든 주석·메시지·응답은 한글. 커밋 메시지 끝에 `Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>` 한 줄(세션 트레일러는 세션 리마인더가 주는 값).
- `npm run zk:*` 는 실행 금지. 회로 빌드는 **오직** `bash scripts/build_mode3_circuit.sh`(pot21_final.ptau). `build/`·`*.zkey`·`*.r1cs` 는 git 밖, `contracts/PiCredVerifier.sol` 은 추적됨.
- 테스트는 `scripts/run_tests.sh` 그룹으로: `npm test`(unit+circuit), `bash scripts/run_tests.sh contract`, chain 그룹은 :8545 hardhat 필요 — 떠 있지 않으면 `npx hardhat node` 를 백그라운드로 직접 띄우고 끝나면 종료·포트 확인. 이미 떠 있던 노드·:4100/:5100/:3100 프로세스는 건드리지 않는다.
- `.env`, `cia_keys.json`, `cia_state.json`, `mode3_wallet_state.json`, `idp_state.json` 등 비밀·상태 파일은 읽지도 수정하지도 않는다.
- Mode 1·Mode 2 파일(`custom_idp.js`, `wallet_agent.js`, `server.js`, `client.js`, `circuits/pi_*` Mode 2 회로, `lib/imt_v3.js` 등)은 건드리지 않는다.
- 공개 입력 14개의 순서 `[PPID, arid, pk_i, max_height, chainid, allowAgent, revRoot, pk_CIA_x, pk_CIA_y, pk_trace_x, pk_trace_y, tag_c1_x, tag_c1_y, tag_c2]` 는 불변.
- 상수(스펙 §3): `DOMAIN_MODE3_CRED_V5 = 93461614427473393731524149n`, `DOMAIN_MODE3_USERCRED = 6125100363120193649816638735684n`, `DOMAIN_MODE3_USERCREDREQ = 102762131813745922824802108462542767441n`, `DOMAIN_MODE3_ISSUEREQ_V4 = 401414577397388343646241740924474932n`, `TAG_MODE3_USER = 4n`. 스칼라 상한 `2^250`, max_height 상한 `2^64`, pk_i 160비트.
- 생성원: `PEDERSEN_GENERATORS` 의 기존 점을 그대로 쓴다. C_u 는 `uid, s_u, attr0..3, blind`, C_s 는 `arid, pk_i, blind`. 덧셈 순서는 JS 와 회로가 같게.
- V4 함수(`credCommit`, `credMessage`, `credLeaf`, `proveIssuance`, `verifyIssuance`, `issueRequestMessage`, `DOMAIN_MODE3_CRED_V4`, `DOMAIN_MODE3_ISSUEREQ_V3`)는 Task 8 에서 제거한다. 그전까지는 남겨 두어 각 Task 가 독립적으로 통과하게 한다.
- 새 테스트를 만들면 `scripts/run_tests.sh` 의 그룹에 넣는다.

---

## 파일 구조

| 파일 | 책임 |
|---|---|
| `lib/mode3_credential.js` | 커밋 두 종류(`userCommit`, `sessionCommit`), 서명 메시지 `credMessageV5`, 도메인 상수 |
| `lib/mode3_revocation.js` | `TAG_MODE3_USER`, `userLeaf(Cf_u)` |
| `lib/mode3_issuance.js` | π_u(`proveUserCred`/`verifyUserCred`), 요청 서명 메시지 둘, 직렬화 |
| `circuits/lib/mode3_commit.circom` | `CommitUser`, `CommitSession` 템플릿 |
| `circuits/pi_cred.circom` | V5 회로 |
| `tests/helpers/mode3_fixture.mjs` | V5 입력 생성기 |
| `lib/mode3_cia_state.js`, `cia.js` | 상태 v6, `/cia/user_cred`, `/cia/issue` V5, 폐기 단순화 |
| `lib/mode3_wallet.js` | 요청 빌더 둘, 서명 둘, `buildCredentialProof` V5 |
| `mode3_wallet_agent.js`, `mode3/wallet.html` | 상태 v6, userCred 확보, `/wallet/attrs` |
| `scripts/bench_zkp_inventory.mjs`, `scripts/bench_mode3_onchain.mjs` | 벤치 갱신 |

---

### Task 1: 커밋·서명 메시지·리프 라이브러리 (V5)

**Files:**
- Modify: `lib/mode3_credential.js`
- Modify: `lib/mode3_revocation.js`
- Create: `tests/test_mode3_credential_v5.js`
- Modify: `scripts/run_tests.sh` (unit 그룹에 새 테스트 추가)

**Interfaces:**
- Produces:
  - `export const DOMAIN_MODE3_CRED_V5 = 93461614427473393731524149n`
  - `export async function userCommit({ uid, s_u, blind_u, attrs }) → { Cx, Cy, Cf }` (bigint; 범위 밖이면 throw)
  - `export async function sessionCommit({ arid, pk_i, blind_s }) → { Cx, Cy, Cf }`
  - `export async function credMessageV5(Cf_u, Cf_s, max_height, chainid, allowAgent) → bigint`
  - `export const TAG_MODE3_USER = 4n`, `export async function userLeaf(Cf_u) → bigint` (lib/mode3_revocation.js)

- [ ] **Step 1: 실패하는 테스트 작성** — `tests/test_mode3_credential_v5.js`

```js
// V5 커밋 둘·서명 메시지·리프 (설계 2026-09-21 §3). 외부 의존 없음(unit).
//   node tests/test_mode3_credential_v5.js
import assert from 'node:assert/strict';
import { buildBabyjub, buildPoseidon } from 'circomlibjs';
import {
  userCommit, sessionCommit, credMessageV5, credCommit, compressPoint,
  PEDERSEN_GENERATORS, SCALAR_MAX, DOMAIN_MODE3_CRED_V5, DOMAIN_MODE3_CRED_V4, MAX_HEIGHT_MAX,
} from '../lib/mode3_credential.js';
import { userLeaf, TAG_MODE3_USER, TAG_MODE3_CRED } from '../lib/mode3_revocation.js';
import { TAG_SESSION, TAG_ACCOUNT, leafValue } from '../lib/imt_v2.js';

let failed = 0;
async function t(name, fn) {
  try { await fn(); console.log(`ok   ${name}`); }
  catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.message}`); }
}
const bj = await buildBabyjub();
const ps = await buildPoseidon();
const mul = (g, e) => bj.mulPointEscalar([bj.F.e(g[0]), bj.F.e(g[1])], e);
const uid = 11n, s_u = 22n, blind_u = 33n, attrs = [19n, 410n, 0n, 0n], arid = 44n, pk_i = 0x1234n, blind_s = 55n;

await t('userCommit = uid·G_UID + s_u·G_SU + Σattr·G_ATTR + blind_u·H (arid·pk_i 항 없음)', async () => {
  const { Cx, Cy, Cf } = await userCommit({ uid, s_u, blind_u, attrs });
  let acc = mul(PEDERSEN_GENERATORS.uid, uid);
  acc = bj.addPoint(acc, mul(PEDERSEN_GENERATORS.s_u, s_u));
  for (let i = 0; i < 4; i++) acc = bj.addPoint(acc, mul(PEDERSEN_GENERATORS[`attr${i}`], attrs[i]));
  acc = bj.addPoint(acc, mul(PEDERSEN_GENERATORS.blind, blind_u));
  assert.equal(Cx, bj.F.toObject(acc[0])); assert.equal(Cy, bj.F.toObject(acc[1]));
  assert.equal(Cf, ps.F.toObject(ps([Cx, Cy])));
  assert.equal(await compressPoint({ x: Cx, y: Cy }), Cf);
});

await t('sessionCommit = arid·G_ARID + pk_i·G_PKI + blind_s·H', async () => {
  const { Cx, Cy, Cf } = await sessionCommit({ arid, pk_i, blind_s });
  let acc = mul(PEDERSEN_GENERATORS.arid, arid);
  acc = bj.addPoint(acc, mul(PEDERSEN_GENERATORS.pk_i, pk_i));
  acc = bj.addPoint(acc, mul(PEDERSEN_GENERATORS.blind, blind_s));
  assert.equal(Cx, bj.F.toObject(acc[0])); assert.equal(Cy, bj.F.toObject(acc[1]));
  assert.equal(Cf, ps.F.toObject(ps([Cx, Cy])));
});

await t('userCommit + sessionCommit(같은 blind) 은 V4 credCommit 과 점이 같다 — 생성원 재사용의 정합', async () => {
  // V4: uid·G1 + arid·G2 + s_u·G3 + pk_i·G4 + Σattr + blind·H. V5 두 커밋의 합에서 H 항이 둘이므로 blind 를 나눠 비교한다.
  const u = await userCommit({ uid, s_u, blind_u: 10n, attrs });
  const s = await sessionCommit({ arid, pk_i, blind_s: 20n });
  const v4 = await credCommit({ uid, arid, s_u, pk_i, attrs, blind: 30n });
  const sum = bj.addPoint([bj.F.e(u.Cx), bj.F.e(u.Cy)], [bj.F.e(s.Cx), bj.F.e(s.Cy)]);
  assert.equal(bj.F.toObject(sum[0]), v4.Cx); assert.equal(bj.F.toObject(sum[1]), v4.Cy);
});

await t('blind_u 하나만 바꿔도 C_u 가 바뀐다; attrs 생략은 전부 0', async () => {
  const a = await userCommit({ uid, s_u, blind_u, attrs });
  const b = await userCommit({ uid, s_u, blind_u: blind_u + 1n, attrs });
  assert.notEqual(a.Cf, b.Cf);
  const c = await userCommit({ uid, s_u, blind_u });
  const d = await userCommit({ uid, s_u, blind_u, attrs: [0n, 0n, 0n, 0n] });
  assert.equal(c.Cf, d.Cf);
});

await t('범위: 스칼라가 2^250 이상이면 두 커밋 다 throw', async () => {
  await assert.rejects(() => userCommit({ uid, s_u: SCALAR_MAX, blind_u, attrs }), /2\^250/);
  await assert.rejects(() => sessionCommit({ arid, pk_i: SCALAR_MAX, blind_s }), /2\^250/);
  await assert.rejects(() => userCommit({ uid: 'x', s_u, blind_u, attrs }), /bigint/);
});

await t('credMessageV5 = Poseidon(D_V5, Cf_u, Cf_s, max_height, chainid, allowAgent); V4 와 다르다', async () => {
  const m = await credMessageV5(1n, 2n, 1000n, 31337n, 0n);
  assert.equal(m, ps.F.toObject(ps([DOMAIN_MODE3_CRED_V5, 1n, 2n, 1000n, 31337n, 0n])));
  assert.equal(DOMAIN_MODE3_CRED_V5, 93461614427473393731524149n);
  assert.equal(DOMAIN_MODE3_CRED_V5, DOMAIN_MODE3_CRED_V4 + 1n);
  assert.notEqual(m, await credMessageV5(2n, 1n, 1000n, 31337n, 0n), 'Cf_u 와 Cf_s 자리는 바뀌면 다른 메시지');
  assert.notEqual(m, await credMessageV5(1n, 2n, 1000n, 31337n, 1n));
  await assert.rejects(() => credMessageV5(1n, 2n, MAX_HEIGHT_MAX, 31337n, 0n), /2\^64/);
  await assert.rejects(() => credMessageV5(1n, 2n, 1000n, 31337n, 2n), /allowAgent/);
  await assert.rejects(() => credMessageV5(1n, 2n, 1000n, '31337', 0n), /bigint/);
});

await t('userLeaf = leafValue(4, Cf_u); 태그 4 는 1·2·3 과 다르다', async () => {
  const { Cf } = await userCommit({ uid, s_u, blind_u, attrs });
  assert.equal(TAG_MODE3_USER, 4n);
  assert.notEqual(TAG_MODE3_USER, TAG_SESSION); assert.notEqual(TAG_MODE3_USER, TAG_ACCOUNT); assert.notEqual(TAG_MODE3_USER, TAG_MODE3_CRED);
  assert.equal(await userLeaf(Cf), await leafValue(4n, Cf));
  assert.ok((await userLeaf(Cf)) < (1n << 252n));
  assert.notEqual(await userLeaf(Cf), await userLeaf(Cf + 1n));
});

process.exit(failed === 0 ? 0 : 1);
```

- [ ] **Step 2: 실패 확인**

Run: `node tests/test_mode3_credential_v5.js`
Expected: `SyntaxError: The requested module ... does not provide an export named 'userCommit'` (또는 import 실패로 종료 코드 1)

- [ ] **Step 3: 구현** — `lib/mode3_credential.js` 에 추가 (기존 `credCommit` 은 그대로 둔다)

`DOMAIN_MODE3_CRED_V4` 정의 아래에:

```js
// 2026-09-21 자격증명 이중 구조(설계 §3.3): Sign(D_V5, Cf_u, Cf_s, max_height, chainid, allowAgent). 인자 6개.
export const DOMAIN_MODE3_CRED_V5 = 93461614427473393731524149n; // ASCII "MODE3CREDV5" 빅엔디언
```

`credCommit` 정의 아래에:

```js
function checkScalars(fields) {
  for (const [k, v] of Object.entries(fields)) {
    if (typeof v !== 'bigint' || v < 0n || v >= SCALAR_MAX) {
      throw new Error(`${k} 는 [0, 2^250) 범위의 bigint 여야 한다 (회로 Num2Bits(250) 과 같은 상한): ${v}`);
    }
  }
}
async function finishCommit(acc) {
  const bj = await getBabyjub();
  const Cx = bj.F.toObject(acc[0]);
  const Cy = bj.F.toObject(acc[1]);
  const poseidon = await getPoseidon();
  return { Cx, Cy, Cf: poseidon.F.toObject(poseidon([Cx, Cy])) };
}

/**
 * 사용자 자격증명 커밋(설계 2026-09-21 §3.1). 사용자당 하나, 오래 산다.
 *   C_u = uid·G_UID + s_u·G_SU + attr₀·G_ATTR0 + … + attr₃·G_ATTR3 + blind_u·H
 * circuits/lib/mode3_commit.circom 의 CommitUser 와 생성원·덧셈 순서가 같다. arid·pk_i 항이 없다 — 그 둘은 sessionCommit 에.
 */
export async function userCommit({ uid, s_u, blind_u, attrs }) {
  checkScalars({ uid, s_u, blind_u });
  const a = normalizeAttrs(attrs);
  const bj = await getBabyjub();
  const mul = (g, e) => bj.mulPointEscalar([bj.F.e(g[0]), bj.F.e(g[1])], e);
  let acc = mul(PEDERSEN_GENERATORS.uid, uid);
  acc = bj.addPoint(acc, mul(PEDERSEN_GENERATORS.s_u, s_u));
  for (let i = 0; i < ATTR_SLOTS; i++) acc = bj.addPoint(acc, mul(PEDERSEN_GENERATORS[`attr${i}`], a[i]));
  acc = bj.addPoint(acc, mul(PEDERSEN_GENERATORS.blind, blind_u));
  return finishCommit(acc);
}

/**
 * 세션 커밋(설계 2026-09-21 §3.2). 로그인마다 새 blind_s.
 *   C_s = arid·G_ARID + pk_i·G_PKI + blind_s·H
 * arid 를 넣는 이유: 같은 세션키를 두 서비스에 쓰면 pk_i 로 이어지므로 세션 자격증명을 서비스에 묶는다(§2).
 * AA 는 이 커밋을 열지 못한다 — pk_i 를 평문으로 보면 온체인 pk_i 로 트랜잭션 ↔ uid 가 이어진다.
 */
export async function sessionCommit({ arid, pk_i, blind_s }) {
  checkScalars({ arid, pk_i, blind_s });
  const bj = await getBabyjub();
  const mul = (g, e) => bj.mulPointEscalar([bj.F.e(g[0]), bj.F.e(g[1])], e);
  let acc = mul(PEDERSEN_GENERATORS.arid, arid);
  acc = bj.addPoint(acc, mul(PEDERSEN_GENERATORS.pk_i, pk_i));
  acc = bj.addPoint(acc, mul(PEDERSEN_GENERATORS.blind, blind_s));
  return finishCommit(acc);
}
```

`credMessage` 정의 아래에:

```js
// circuits/pi_cred.circom V5 의 msgHasher(DOMAIN_MODE3_CRED_V5, Cf_u, Cf_s, max_height, chainid, allowAgent) 와 순서가 같아야 한다.
export async function credMessageV5(Cf_u, Cf_s, max_height, chainid, allowAgent) {
  for (const [k, v] of [['Cf_u', Cf_u], ['Cf_s', Cf_s], ['max_height', max_height], ['chainid', chainid], ['allowAgent', allowAgent]]) {
    if (typeof v !== 'bigint' || v < 0n) throw new Error(`credMessageV5: ${k} 는 음이 아닌 bigint 여야 한다`);
  }
  if (max_height >= MAX_HEIGHT_MAX) throw new Error('credMessageV5: max_height 는 2^64 미만이어야 한다 (회로 Num2Bits(64))');
  if (allowAgent > 1n) throw new Error('credMessageV5: allowAgent 는 0 또는 1 이어야 한다');
  const poseidon = await getPoseidon();
  return poseidon.F.toObject(poseidon([DOMAIN_MODE3_CRED_V5, Cf_u, Cf_s, max_height, chainid, allowAgent]));
}
```

`lib/mode3_revocation.js` 의 `credLeaf` 아래에:

```js
// 2026-09-21 자격증명 이중 구조(설계 §3.6): 리프는 세션이 아니라 **사용자 자격증명** Cf_u 에서 뽑는다. 사용자당 하나.
// 태그 4 — Mode 2 의 1·2, V4 세션 리프 3 과 값이 겹치지 않는다.
export const TAG_MODE3_USER = 4n;
export async function userLeaf(Cf_u) {
  return leafValue(TAG_MODE3_USER, Cf_u);
}
```

- [ ] **Step 4: 통과 확인**

Run: `node tests/test_mode3_credential_v5.js`
Expected: 7줄 `ok`, 종료 코드 0

- [ ] **Step 5: unit 그룹에 등록** — `scripts/run_tests.sh` 의 `tests/test_mode3_issuance.js` 줄 아래에 `  tests/test_mode3_credential_v5.js` 추가. `npm test` 의 unit 부분이 여전히 통과하는지 `bash scripts/run_tests.sh unit` 로 확인.

- [ ] **Step 6: 커밋**

```bash
git add lib/mode3_credential.js lib/mode3_revocation.js tests/test_mode3_credential_v5.js scripts/run_tests.sh
git commit -m "feat(mode3): 자격증명 이중 구조 1/8 — userCommit·sessionCommit·credMessageV5·userLeaf(TAG 4)"
```

---

### Task 2: 발급 증명 π_u 와 요청 서명 메시지

**Files:**
- Modify: `lib/mode3_issuance.js`
- Modify: `tests/test_mode3_issuance.js` (V4 π_issue 케이스는 Task 8 에서 지운다; 여기서는 V5 케이스를 **추가**)

**Interfaces:**
- Consumes: Task 1 의 `userCommit`(검증용 대조), `PEDERSEN_GENERATORS`, `SCALAR_MAX`, `normalizeAttrs`, `ATTR_SLOTS`
- Produces:
  - `export const DOMAIN_MODE3_USERCRED = 6125100363120193649816638735684n`, `DOMAIN_MODE3_USERCREDREQ = 102762131813745922824802108462542767441n`, `DOMAIN_MODE3_ISSUEREQ_V4 = 401414577397388343646241740924474932n`
  - `export async function proveUserCred({ uid, s_u, blind_u, r_u, attrs }) → { C_u_pt:{x,y}, cm_u:{x,y}, proof:{T1,T2,c,z_su,z_blind,z_ru,z_attr[4]} }`
  - `export async function verifyUserCred({ uid, C_u_pt, cm_u, proof }) → boolean`
  - `export async function userCredRequestMessage(C_u_pt) → bigint` = Poseidon(D_USERCREDREQ, x, y)
  - `export async function issueRequestMessageV4(Cf_u, C_s_pt, chainid, allowAgent, max_height) → bigint`
  - `export function serializeUserCredProof(p)`, `export function parseUserCredProof(o)`

- [ ] **Step 1: 실패하는 테스트 추가** — `tests/test_mode3_issuance.js` 맨 아래(`process.exit` 앞)에:

```js
// ---- V5 (2026-09-21): 사용자 자격증명 증명 π_u ----
const { proveUserCred, verifyUserCred, userCredRequestMessage, issueRequestMessageV4, serializeUserCredProof, parseUserCredProof,
        DOMAIN_MODE3_USERCRED, DOMAIN_MODE3_USERCREDREQ, DOMAIN_MODE3_ISSUEREQ_V4 } = await import('../lib/mode3_issuance.js');
const { userCommit, sessionCommit } = await import('../lib/mode3_credential.js');

await t('V5 도메인 세 개는 ASCII 빅엔디언이고 서로·옛 값과 다르다', () => {
  assert.equal(DOMAIN_MODE3_USERCRED, BigInt('0x' + Buffer.from('MODE3USERCRED').toString('hex')));
  assert.equal(DOMAIN_MODE3_USERCREDREQ, BigInt('0x' + Buffer.from('MODE3USERCREDREQ').toString('hex')));
  assert.equal(DOMAIN_MODE3_ISSUEREQ_V4, BigInt('0x' + Buffer.from('MODE3ISSUEREQV4').toString('hex')));
  assert.equal(new Set([DOMAIN_MODE3_USERCRED, DOMAIN_MODE3_USERCREDREQ, DOMAIN_MODE3_ISSUEREQ_V4, DOMAIN_MODE3_ISSUE, DOMAIN_MODE3_ISSUEREQ_V3]).size, 5);
});

await t('π_u 양성: 올바른 증인이면 검증되고 C_u_pt 는 userCommit 과 같은 점', async () => {
  const u = await freshUser();
  const { C_u_pt, cm_u, proof } = await proveUserCred({ uid, s_u: u.s_u, blind_u: u.blind, r_u: u.r_u, attrs: u.attrs });
  assert.equal(cm_u.x, u.cm_u.x); assert.equal(cm_u.y, u.cm_u.y);
  assert.equal(await verifyUserCred({ uid, C_u_pt, cm_u, proof }), true);
  const { Cx, Cy } = await userCommit({ uid, s_u: u.s_u, blind_u: u.blind, attrs: u.attrs });
  assert.equal(C_u_pt.x, Cx); assert.equal(C_u_pt.y, Cy);
});

await t('π_u 음성: cm_u 와 다른 s_u (Sybil), 다른 uid 재생, 응답 변조, 다른 attrs 의 C_u_pt, 곡선 밖 점', async () => {
  const u = await freshUser();
  const good = await proveUserCred({ uid, s_u: u.s_u, blind_u: u.blind, r_u: u.r_u, attrs: u.attrs });
  const other = await proveUserCred({ uid, s_u: u.s_u + 1n, blind_u: u.blind, r_u: u.r_u, attrs: u.attrs });
  assert.equal(await verifyUserCred({ uid, C_u_pt: other.C_u_pt, cm_u: u.cm_u, proof: other.proof }), false, 'cm_u 는 등록된 s_u 의 것');
  assert.equal(await verifyUserCred({ uid: uid + 1n, C_u_pt: good.C_u_pt, cm_u: good.cm_u, proof: good.proof }), false);
  assert.equal(await verifyUserCred({ uid, C_u_pt: good.C_u_pt, cm_u: good.cm_u, proof: { ...good.proof, z_su: good.proof.z_su + 1n } }), false);
  assert.equal(await verifyUserCred({ uid, C_u_pt: good.C_u_pt, cm_u: good.cm_u, proof: { ...good.proof, z_attr: [good.proof.z_attr[0] + 1n, ...good.proof.z_attr.slice(1)] } }), false);
  const { C_u_pt: C2 } = await proveUserCred({ uid, s_u: u.s_u, blind_u: u.blind, r_u: u.r_u, attrs: [1n, 0n, 0n, 0n] });
  assert.equal(await verifyUserCred({ uid, C_u_pt: C2, cm_u: good.cm_u, proof: good.proof }), false);
  assert.equal(await verifyUserCred({ uid, C_u_pt: { x: 1n, y: 1n }, cm_u: good.cm_u, proof: good.proof }), false);
  await assert.rejects(() => proveUserCred({ uid: SCALAR_MAX, s_u: u.s_u, blind_u: u.blind, r_u: u.r_u, attrs: u.attrs }), /2\^250/);
});

await t('π_u 직렬화 왕복', async () => {
  const u = await freshUser();
  const { C_u_pt, cm_u, proof } = await proveUserCred({ uid, s_u: u.s_u, blind_u: u.blind, r_u: u.r_u, attrs: u.attrs });
  const back = parseUserCredProof(JSON.parse(JSON.stringify(serializeUserCredProof(proof))));
  assert.deepEqual(back, proof);
  assert.equal(await verifyUserCred({ uid, C_u_pt, cm_u, proof: back }), true);
  assert.throws(() => parseUserCredProof({ ...serializeUserCredProof(proof), z_attr: ['1'] }), /z_attr/);
});

await t('요청 서명 메시지: userCredRequestMessage(C_u_pt), issueRequestMessageV4(Cf_u, C_s_pt, chainid, allowAgent, max_height)', async () => {
  const ps = await buildPoseidon();
  const P = { x: 5n, y: 6n };
  assert.equal(await userCredRequestMessage(P), ps.F.toObject(ps([DOMAIN_MODE3_USERCREDREQ, 5n, 6n])));
  const m = await issueRequestMessageV4(7n, P, 31337n, 0n, 1000n);
  assert.equal(m, ps.F.toObject(ps([DOMAIN_MODE3_ISSUEREQ_V4, 7n, 5n, 6n, 31337n, 0n, 1000n])));
  assert.notEqual(m, await issueRequestMessageV4(8n, P, 31337n, 0n, 1000n), 'Cf_u 를 덮는다 — 남의 C_u 에 내 C_s 를 못 붙인다');
  assert.notEqual(m, await issueRequestMessageV4(7n, P, 31337n, 0n, 1001n));
  await assert.rejects(() => issueRequestMessageV4(7n, P, 31337n, 2n, 1000n), /allowAgent/);
  await assert.rejects(() => issueRequestMessageV4(7n, P, 31337n, 0n, 1n << 64n), /max_height/);
  await assert.rejects(() => issueRequestMessageV4('7', P, 31337n, 0n, 1000n), /bigint/);
});
```

(`freshUser`, `uid`, `SCALAR_MAX`, `DOMAIN_MODE3_ISSUE`, `DOMAIN_MODE3_ISSUEREQ_V3`, `buildPoseidon` 은 이 파일 상단에 이미 import 되어 있다. `freshUser()` 는 `{ s_u, r_u, blind, attrs, cm_u }` 를 돌려준다 — 파일 상단 정의를 그대로 쓴다.)

- [ ] **Step 2: 실패 확인**

Run: `node tests/test_mode3_issuance.js`
Expected: 기존 케이스 ok, 새 케이스 5개 FAIL(`proveUserCred is not a function` 등)

- [ ] **Step 3: 구현** — `lib/mode3_issuance.js`

`DOMAIN_MODE3_ISSUEREQ_V3` 아래에 상수:

```js
// 2026-09-21 자격증명 이중 구조(설계 §3.4·§3.5). 세션 발급에는 ZKP 가 없고 사용자 자격증명 발급에만 π_u 가 있다.
export const DOMAIN_MODE3_USERCRED    = 6125100363120193649816638735684n;           // ASCII "MODE3USERCRED"   — π_u 의 FS 도메인
export const DOMAIN_MODE3_USERCREDREQ = 102762131813745922824802108462542767441n;   // ASCII "MODE3USERCREDREQ" — /cia/user_cred 요청 서명
export const DOMAIN_MODE3_ISSUEREQ_V4 = 401414577397388343646241740924474932n;      // ASCII "MODE3ISSUEREQV4" — /cia/issue V5 요청 서명(Cf_u 를 덮는다)
```

`verifyIssuance` 아래에:

```js
// ---- π_u: 사용자 자격증명 증명 (설계 2026-09-21 §3.5). proveIssuance 에서 arid·pk_i 항을 뺀 것 ----
async function challengeU(bj, uid, C_u_pt, cm_u, T1, T2) {
  const ps = await getPs();
  const h = ps.F.toObject(ps([DOMAIN_MODE3_USERCRED, uid, C_u_pt.x, C_u_pt.y, cm_u.x, cm_u.y, T1.x, T1.y, T2.x, T2.y]));
  return h & MASK_250;
}

/**
 * PoK{ (s_u, a₁..a₄, blind_u, r_u) : C_u = uid·G_UID + s_u·G_SU + Σaₖ·G_ATTR + blind_u·H  ∧  cm_u = s_u·G_SU + r_u·H }.
 * 공개 uid, C_u_pt, cm_u. CIA 는 s_u·속성·blind_u 를 모른 채 "C_u 가 내 uid 와 등록된 s_u 로 만들어졌다"만 안다.
 */
export async function proveUserCred({ uid, s_u, blind_u, r_u, attrs }) {
  if (typeof uid !== 'bigint' || uid < 0n || uid >= SCALAR_MAX) throw new Error(`uid 는 [0, 2^250) 이어야 한다: ${uid}`);
  const a4 = normalizeAttrs(attrs);
  const bj = await getBj();
  const r = bj.subOrder;
  const [G1, G3, H] = ['uid', 's_u', 'blind'].map((n) => G(bj, n));
  const GA = [0, 1, 2, 3].map((i) => G(bj, `attr${i}`));
  const C_u_pt = toObj(bj, msm(bj, [[uid, G1], [s_u, G3], ...a4.map((v, i) => [v, GA[i]]), [blind_u, H]]));
  const cm_u = toObj(bj, msm(bj, [[s_u, G3], [r_u, H]]));
  const a = { su: await randomZr(), blind: await randomZr(), ru: await randomZr() };
  const aAttr = [];
  for (let i = 0; i < ATTR_SLOTS; i++) aAttr.push(await randomZr());
  const T1 = toObj(bj, msm(bj, [[a.su, G3], ...aAttr.map((v, i) => [v, GA[i]]), [a.blind, H]]));
  const T2 = toObj(bj, msm(bj, [[a.su, G3], [a.ru, H]]));
  const c = await challengeU(bj, uid, C_u_pt, cm_u, T1, T2);
  const z = (ax, x) => (ax + c * x) % r;
  return {
    C_u_pt, cm_u,
    proof: { T1, T2, c, z_su: z(a.su, s_u), z_blind: z(a.blind, blind_u), z_ru: z(a.ru, r_u), z_attr: a4.map((v, i) => z(aAttr[i], v)) },
  };
}

export async function verifyUserCred({ uid, C_u_pt, cm_u, proof }) {
  if (typeof uid !== 'bigint' || uid < 0n || uid >= SCALAR_MAX) return false;
  const bj = await getBj();
  const r = bj.subOrder;
  const { T1, T2, c, z_su, z_blind, z_ru, z_attr } = proof ?? {};
  for (const P of [C_u_pt, cm_u, T1, T2]) if (!validPoint(bj, P)) return false;
  if (!Array.isArray(z_attr) || z_attr.length !== ATTR_SLOTS) return false;
  for (const z of [c, z_su, z_blind, z_ru, ...z_attr]) if (typeof z !== 'bigint' || z < 0n || z >= r) return false;
  if ((await challengeU(bj, uid, C_u_pt, cm_u, T1, T2)) !== c) return false;
  const [G1, G3, H] = ['uid', 's_u', 'blind'].map((n) => G(bj, n));
  const GA = [0, 1, 2, 3].map((i) => G(bj, `attr${i}`));
  const Y1 = bj.addPoint(fromObj(bj, C_u_pt), negPt(bj, bj.mulPointEscalar(G1, uid)));
  const lhs1 = msm(bj, [[z_su, G3], ...z_attr.map((z, i) => [z, GA[i]]), [z_blind, H]]);
  const rhs1 = bj.addPoint(fromObj(bj, T1), bj.mulPointEscalar(Y1, c));
  if (!eqPt(bj, lhs1, rhs1)) return false;
  const lhs2 = msm(bj, [[z_su, G3], [z_ru, H]]);
  const rhs2 = bj.addPoint(fromObj(bj, T2), bj.mulPointEscalar(fromObj(bj, cm_u), c));
  return eqPt(bj, lhs2, rhs2);
}

/** /cia/user_cred 요청의 사용자 서명 메시지 = Poseidon(D_USERCREDREQ, C_u_pt.x, C_u_pt.y). */
export async function userCredRequestMessage(C_u_pt) {
  if (typeof C_u_pt?.x !== 'bigint' || typeof C_u_pt?.y !== 'bigint') throw new Error('userCredRequestMessage: C_u_pt{x,y}(bigint) 가 필요하다');
  const ps = await getPs();
  return ps.F.toObject(ps([DOMAIN_MODE3_USERCREDREQ, C_u_pt.x, C_u_pt.y]));
}

/**
 * /cia/issue V5 요청의 사용자 서명 메시지 = Poseidon(D_ISSUEREQ_V4, Cf_u, C_s_pt.x, C_s_pt.y, chainid, allowAgent, max_height).
 * Cf_u 를 덮으므로 제3자가 남의 C_u 에 자기 C_s 를 붙여 달라고 할 수 없다(설계 §3.4).
 */
export async function issueRequestMessageV4(Cf_u, C_s_pt, chainid, allowAgent, max_height) {
  if (typeof Cf_u !== 'bigint' || Cf_u < 0n) throw new Error('issueRequestMessageV4: Cf_u 는 음이 아닌 bigint 여야 한다');
  if (typeof C_s_pt?.x !== 'bigint' || typeof C_s_pt?.y !== 'bigint') throw new Error('issueRequestMessageV4: C_s_pt{x,y}(bigint) 가 필요하다');
  for (const [k, v] of [['chainid', chainid], ['allowAgent', allowAgent], ['max_height', max_height]]) {
    if (typeof v !== 'bigint' || v < 0n) throw new Error(`issueRequestMessageV4: ${k} 는 음이 아닌 bigint 여야 한다`);
  }
  if (allowAgent > 1n) throw new Error('issueRequestMessageV4: allowAgent 는 0 또는 1 이어야 한다');
  if (max_height >= MAX_HEIGHT_MAX) throw new Error('issueRequestMessageV4: max_height 는 2^64 미만이어야 한다');
  const ps = await getPs();
  return ps.F.toObject(ps([DOMAIN_MODE3_ISSUEREQ_V4, Cf_u, C_s_pt.x, C_s_pt.y, chainid, allowAgent, max_height]));
}

export function serializeUserCredProof(p) {
  return {
    T1: pointToStrings(p.T1), T2: pointToStrings(p.T2), c: p.c.toString(),
    z_su: p.z_su.toString(), z_blind: p.z_blind.toString(), z_ru: p.z_ru.toString(), z_attr: p.z_attr.map((z) => z.toString()),
  };
}
export function parseUserCredProof(o) {
  const B = (v) => { if (typeof v !== 'string' || !/^[0-9]+$/.test(v)) throw new Error('bad scalar'); return BigInt(v); };
  if (!Array.isArray(o?.z_attr) || o.z_attr.length !== ATTR_SLOTS) throw new Error('bad z_attr');
  return { T1: pointFromStrings(o.T1), T2: pointFromStrings(o.T2), c: B(o.c), z_su: B(o.z_su), z_blind: B(o.z_blind), z_ru: B(o.z_ru), z_attr: o.z_attr.map(B) };
}
```

(`pointToStrings`/`pointFromStrings` 는 파일 아래쪽에 이미 있다 — 함수 선언이라 호이스팅되므로 위치는 상관없다.)

- [ ] **Step 4: 통과 확인**

Run: `node tests/test_mode3_issuance.js`
Expected: 전부 ok, 종료 코드 0

- [ ] **Step 5: 커밋**

```bash
git add lib/mode3_issuance.js tests/test_mode3_issuance.js
git commit -m "feat(mode3): 자격증명 이중 구조 2/8 — π_u(proveUserCred/verifyUserCred), 요청 서명 메시지 둘"
```

---

### Task 3: 회로 V5 + 픽스처 + 빌드

**Files:**
- Modify: `circuits/lib/mode3_commit.circom` (`CommitUser`, `CommitSession` 추가; `CommitPedersen` 은 Task 8 에서 제거)
- Modify: `circuits/pi_cred.circom`
- Modify: `tests/helpers/mode3_fixture.mjs`
- Modify: `tests/test_pi_cred_witness.mjs`
- Modify: `tests/test_mode3_commit_scheme.mjs`
- Generated: `contracts/PiCredVerifier.sol` (빌드 스크립트가 덮어씀), `build/mode3/*`

**Interfaces:**
- Consumes: Task 1 (`userCommit`, `sessionCommit`, `credMessageV5`, `userLeaf`)
- Produces: `buildValidInput(opts) → { input, Cf_u, Cf_s, pk_trace, shares, tag, ciaPub, arid, uid, tree }` — `input` 에 `blind_u`, `blind_s` (V4 의 `blind` 없음). 회로 공개 입력 14개 순서 불변.

- [ ] **Step 1: 픽스처를 V5 로** — `tests/helpers/mode3_fixture.mjs` 전체를 다음으로 교체

```js
// pi_cred 회로용 공유 입력 픽스처 (V5 — 설계 2026-09-21 §5).
// tests/test_pi_cred_witness.mjs, scripts/bench_pi_cred.mjs, test/Mode3Wallet.test.mjs 가 같은 입력 생성기를 쓴다.
import { buildPoseidon, buildEddsa, buildBabyjub } from 'circomlibjs';
import { userLeaf, createRevocationTree } from '../../lib/mode3_revocation.js';
import { userCommit, sessionCommit, credMessageV5, ppid as computePpid } from '../../lib/mode3_credential.js';
import { combinePublicKey, encryptTag } from '../../lib/mode3_trace.js';

// --- 정상 입력 하나를 만든다 -------------------------------------------------
// 옵션은 컨트랙트 테스트용이다: pk_i 는 실제 세션키의 주소, maxHeight 는 만료 케이스, allowAgent 는 플래그 케이스.
export async function buildValidInput({ pk_i: pkIOpt, maxHeight = 1789000000n, allowAgent = 0n, chainid = 31337n } = {}) {
  const poseidon = await buildPoseidon();
  const F = poseidon.F;
  const eddsa = await buildEddsa();

  const uid     = 11111111111111111111n;
  const arid    = 22222222222222222222n;
  const s_u     = 33333333333333333333n;
  const blind_u = 44444444444444444444n;
  const blind_s = 55555555555555555555n;
  const pk_i    = pkIOpt ?? 0x1234567890123456789012345678901234567890n; // 160비트
  const attrs   = [19n, 410n, 0n, 0n];
  const max_height = maxHeight;   // 블록 높이. 회로는 값만 통과시키고 검증자가 비교한다

  // 트레이스 태그(설계 2026-09-16 §4.1, 평문은 2026-09-18 §3.4). 조각은 테스트 고정값 — 실제 키가 아니다. r 도 고정.
  const bj = await buildBabyjub();
  const shareOf = (x) => ({ x, X: { x: bj.F.toObject(bj.mulPointEscalar(bj.Base8, x)[0]), y: bj.F.toObject(bj.mulPointEscalar(bj.Base8, x)[1]) } });
  const shares = { svc: shareOf(66666666666666666666n), aa: shareOf(77777777777777777777n) };
  const pk_trace = await combinePublicKey(shares.svc.X, shares.aa.X);
  const tag = await encryptTag(pk_trace, uid, arid, 88888888888888888888n);

  // 커밋 둘(2026-09-21 §3): 사용자 자격증명 C_u(사용자당 하나)와 세션 커밋 C_s(세션마다). 서명은 둘 다 덮는다.
  const { Cf: Cf_u } = await userCommit({ uid, s_u, blind_u, attrs });
  const { Cf: Cf_s } = await sessionCommit({ arid, pk_i, blind_s });
  const PPID = await computePpid({ uid, arid, s_u, chainid });
  const msg = await credMessageV5(Cf_u, Cf_s, max_height, chainid, allowAgent);

  // CIA 서명키. 테스트 고정값이며 실제 키가 아니다.
  const prv = Buffer.from('0001020304050607080900010203040506070809000102030405060708090001', 'hex');
  const pub = eddsa.prv2pub(prv);
  const sig = eddsa.signPoseidon(prv, F.e(msg));
  const ciaPub = { x: F.toObject(pub[0]), y: F.toObject(pub[1]) };

  // 폐기 트리에 남의 폐기를 하나 넣어 둔다 — 내 비멤버십은 여전히 성립해야 한다. 리프는 Cf_u 에서(§3.6).
  const tree = await createRevocationTree();
  await tree.insert(await userLeaf(999n));
  const w = await tree.getNonMembershipWitness(await userLeaf(Cf_u));

  const input = {
    uid: uid.toString(), s_u: s_u.toString(), blind_u: blind_u.toString(), blind_s: blind_s.toString(), attrs: attrs.map(String),
    S: sig.S.toString(), R8x: F.toObject(sig.R8[0]).toString(), R8y: F.toObject(sig.R8[1]).toString(),
    lowValue: w.lowValue.toString(), lowNextIndex: w.lowNextIndex.toString(), lowNextValue: w.lowNextValue.toString(),
    pathElements: w.pathElements.map(String), pathIndices: w.pathIndices.map(String),
    r: tag.r.toString(),
    PPID: PPID.toString(), arid: arid.toString(), pk_i: pk_i.toString(),
    max_height: max_height.toString(), chainid: chainid.toString(), allowAgent: allowAgent.toString(),
    revRoot: tree.getRoot().toString(),
    pk_CIA_x: ciaPub.x.toString(), pk_CIA_y: ciaPub.y.toString(),
    pk_trace_x: pk_trace.x.toString(), pk_trace_y: pk_trace.y.toString(),
    tag_c1_x: tag.c1.x.toString(), tag_c1_y: tag.c1.y.toString(), tag_c2: tag.c2.toString(),
  };

  return { input, Cf_u, Cf_s, pk_trace, shares, tag, ciaPub, arid, uid, tree };
}
```

- [ ] **Step 2: witness 테스트를 V5 로** — `tests/test_pi_cred_witness.mjs`
  - `const { input: valid, C: validC, ... } = await buildValidInput();` → `const { input: valid, Cf_u: validCfU, shares, tag, arid: validArid } = await buildValidInput();` (파일 안에서 `validC` 를 쓰는 곳은 `validCfU` 로).
  - "JS/회로 리프 일치" 케이스가 `credLeaf(validC)` 를 쓰면 `userLeaf(validCfU)` 로, import 도 `userLeaf` 로.
  - `'음성: pk_i를 바꾸면 거부된다 (C 바인딩이 깨진다)'` 는 그대로 두되 설명을 `(C_s 바인딩이 깨진다 — 서명이 Cf_s 를 덮는다)` 로.
  - 새 케이스 셋을 `⑤` 케이스들 앞에 추가:

```js
await t('V5 음성: blind_u 를 바꾸면 거부된다 (C_u 가 달라져 서명·리프가 안 맞는다)', async () => {
  await assert.rejects(() => witness({ ...valid, blind_u: (BigInt(valid.blind_u) + 1n).toString() }), /Assert Failed/);
});
await t('V5 음성: blind_s 를 바꾸면 거부된다 (C_s 가 달라져 서명이 안 맞는다)', async () => {
  await assert.rejects(() => witness({ ...valid, blind_s: (BigInt(valid.blind_s) + 1n).toString() }), /Assert Failed/);
});
await t('V5 음성: 폐기 트리에 내 userLeaf 가 들어 있으면 비멤버십이 거부된다', async () => {
  const { input, tree, Cf_u } = await buildValidInput();
  await tree.insert(await userLeaf(Cf_u));
  await assert.rejects(() => tree.getNonMembershipWitness(await userLeaf(Cf_u)), /member/);
  // 옛 witness 를 새 root 에 그대로 내밀면 회로가 거부한다
  await assert.rejects(() => witness({ ...input, revRoot: tree.getRoot().toString() }), /Assert Failed/);
});
await t('V5 음성: r = 0 은 회로가 거부한다 (2026-09-21 결정 — IsZero 제약)', async () => {
  await assert.rejects(() => witness({ ...valid, r: '0' }), /Assert Failed/);
});
```

- [ ] **Step 3: 실패 확인**

Run: `node tests/test_pi_cred_witness.mjs`
Expected: 컴파일은 되지만(회로가 아직 V4) `양성: 정상 credential의 witness가 계산된다` 가 FAIL — 입력에 `blind` 가 없어 witness 계산 실패.

- [ ] **Step 4: 회로 커밋 템플릿** — `circuits/lib/mode3_commit.circom` 의 `CommitPedersen` 아래에 추가 (생성원 상수는 `CommitPedersen` 의 것을 **글자 단위로 복사**한다)

```circom
// 2026-09-21 자격증명 이중 구조(설계 §3.1). 사용자 자격증명 커밋 — 사용자당 하나.
//   C_u = uid·G_UID + s_u·G_SU + attr₀·G_ATTR0 + … + attr₃·G_ATTR3 + blind_u·H
// CommitPedersen 에서 arid·pk_i 항을 뺀 것. 생성원·순서는 lib/mode3_credential.js userCommit 과 같다.
template CommitUser() {
    signal input uid;
    signal input s_u;
    signal input blind_u;
    signal input attrs[4];
    signal output Cx;
    signal output Cy;

    var N = 250;
    var G_UID[2]   = [10457101036533406547632367118273992217979173478358440826365724437999023779287,
                      19824078218392094440610104313265183977899662750282163392862422243483260492317];
    var G_SU[2]    = [5802099305472655231388284418920769829666717045250560929368476121199858275951,
                      5980429700218124965372158798884772646841287887664001482443826541541529227896];
    var G_ATTR[4][2] = [
        [1487999857809287756929114517587739322941449154962237464737694709326309567994,
         14017256862867289575056460215526364897734808720610101650676790868051368668003],
        [14618644331049802168996997831720384953259095788558646464435263343433563860015,
         13115243279999696210147231297848654998887864576952244320558158620692603342236],
        [6814338563135591367010655964669793483652536871717891893032616415581401894627,
         13660303521961041205824633772157003587453809761793065294055279768121314853695],
        [3571615583211663069428808372184817973703476260057504149923239576077102575715,
         11981351099832644138306422070127357074117642951423551606012551622164230222506]
    ];
    var H_BLIND[2] = [20265828622013100949498132415626198973119240347465898028410217039057588424236,
                      1160461593266035632937973507065134938065359936056410650153315956301179689506];

    component bUid   = Num2Bits(N);  bUid.in   <== uid;
    component bSu    = Num2Bits(N);  bSu.in    <== s_u;
    component bBlind = Num2Bits(N);  bBlind.in <== blind_u;
    component bAttr[4];
    for (var j = 0; j < 4; j++) { bAttr[j] = Num2Bits(N); bAttr[j].in <== attrs[j]; }
    component mUid   = EscalarMulFix(N, G_UID);
    component mSu    = EscalarMulFix(N, G_SU);
    component mBlind = EscalarMulFix(N, H_BLIND);
    component mAttr[4];
    for (var j = 0; j < 4; j++) mAttr[j] = EscalarMulFix(N, G_ATTR[j]);
    for (var i = 0; i < N; i++) {
        mUid.e[i]   <== bUid.out[i];
        mSu.e[i]    <== bSu.out[i];
        mBlind.e[i] <== bBlind.out[i];
        for (var j = 0; j < 4; j++) mAttr[j].e[i] <== bAttr[j].out[i];
    }
    // 덧셈 순서: uid + s_u + attr0..3 + blind_u (JS userCommit 과 같다).
    component a1 = BabyAdd();
    a1.x1 <== mUid.out[0];  a1.y1 <== mUid.out[1];
    a1.x2 <== mSu.out[0];   a1.y2 <== mSu.out[1];
    component aAttr[4];
    for (var j = 0; j < 4; j++) {
        aAttr[j] = BabyAdd();
        if (j == 0) { aAttr[j].x1 <== a1.xout; aAttr[j].y1 <== a1.yout; }
        else        { aAttr[j].x1 <== aAttr[j-1].xout; aAttr[j].y1 <== aAttr[j-1].yout; }
        aAttr[j].x2 <== mAttr[j].out[0]; aAttr[j].y2 <== mAttr[j].out[1];
    }
    component a2 = BabyAdd();
    a2.x1 <== aAttr[3].xout; a2.y1 <== aAttr[3].yout;
    a2.x2 <== mBlind.out[0]; a2.y2 <== mBlind.out[1];
    Cx <== a2.xout;
    Cy <== a2.yout;
}

// 세션 커밋(설계 §3.2) — 로그인마다.  C_s = arid·G_ARID + pk_i·G_PKI + blind_s·H
// pk_i 를 여기 두는 이유: AA 가 평문 pk_i 를 보면 온체인 pk_i 로 트랜잭션 ↔ uid 가 이어진다(§2).
// arid 를 두는 이유: 같은 세션키를 두 서비스에 쓰지 못하게 세션 자격증명을 서비스에 묶는다.
template CommitSession() {
    signal input arid;
    signal input pk_i;
    signal input blind_s;
    signal output Cx;
    signal output Cy;

    var N = 250;
    var G_ARID[2]  = [2671756056509184035029146175565761955751135805354291559563293617232983272177,
                      2663205510731142763556352975002641716101654201788071096152948830924149045094];
    var G_PKI[2]   = [7107336197374528537877327281242680114152313102022415488494307685842428166594,
                      2857869773864086953506483169737724679646433914307247183624878062391496185654];
    var H_BLIND[2] = [20265828622013100949498132415626198973119240347465898028410217039057588424236,
                      1160461593266035632937973507065134938065359936056410650153315956301179689506];

    component bArid  = Num2Bits(N);  bArid.in  <== arid;
    component bPki   = Num2Bits(N);  bPki.in   <== pk_i;
    component bBlind = Num2Bits(N);  bBlind.in <== blind_s;
    component mArid  = EscalarMulFix(N, G_ARID);
    component mPki   = EscalarMulFix(N, G_PKI);
    component mBlind = EscalarMulFix(N, H_BLIND);
    for (var i = 0; i < N; i++) {
        mArid.e[i]  <== bArid.out[i];
        mPki.e[i]   <== bPki.out[i];
        mBlind.e[i] <== bBlind.out[i];
    }
    // 덧셈 순서: arid + pk_i + blind_s (JS sessionCommit 과 같다).
    component a1 = BabyAdd();
    a1.x1 <== mArid.out[0]; a1.y1 <== mArid.out[1];
    a1.x2 <== mPki.out[0];  a1.y2 <== mPki.out[1];
    component a2 = BabyAdd();
    a2.x1 <== a1.xout;       a2.y1 <== a1.yout;
    a2.x2 <== mBlind.out[0]; a2.y2 <== mBlind.out[1];
    Cx <== a2.xout;
    Cy <== a2.yout;
}
```

- [ ] **Step 5: 회로 본체 V5** — `circuits/pi_cred.circom`
  - include 에 `include "lib/comparators.circom";` 추가(IsZero). (`circuits/lib/comparators.circom` 이 없으면 `-l node_modules/circomlib/circuits` 경로가 잡으므로 `include "comparators.circom";` 로 쓴다 — `imt_nonmembership_v2.circom` 과 같은 형식.)
  - 헤더 주석의 "네 가지를 함께 증명한다" 목록 위에 한 줄: `// V5(2026-09-21): 커밋 둘(C_u 사용자 자격증명, C_s 세션) — 서명은 둘을 덮고 리프는 C_u 에서만 뽑는다. 설계 docs/superpowers/specs/2026-09-21-mode3-two-tier-credential-design.md §5`
  - Private 입력: `signal input blind;` → `signal input blind_u;` 와 `signal input blind_s;` 둘.
  - 상수: `var DOMAIN_MODE3_CRED_V4 = ...;` → `var DOMAIN_MODE3_CRED_V5 = 93461614427473393731524149;  // ASCII "MODE3CREDV5"`, `var TAG_MODE3_CRED = 3;` → `var TAG_MODE3_USER = 4;  // 사용자 자격증명 리프. Mode 2 의 1·2, V4 의 3 과 갈라 둔다`.
  - "C 계산" 블록을 다음으로 교체:

```circom
    // ---- 커밋 둘 (2026-09-21 §3) ----
    // C_u: 사용자 속성(uid, s_u, attrs). 사용자당 하나. 서명·리프에는 Poseidon(Cx, Cy) 로 압축한 Cf_u.
    component cu = CommitUser();
    cu.uid <== uid;  cu.s_u <== s_u;  cu.blind_u <== blind_u;
    for (var j = 0; j < 4; j++) cu.attrs[j] <== attrs[j];
    component cfu = Poseidon(2);
    cfu.inputs[0] <== cu.Cx;  cfu.inputs[1] <== cu.Cy;
    signal Cf_u;
    Cf_u <== cfu.out;
    // C_s: 세션 속성(arid, pk_i). 공개 입력 arid·pk_i 로 직접 계산 — 다른 값을 넣으면 서명 검증이 깨진다.
    component cs = CommitSession();
    cs.arid <== arid;  cs.pk_i <== pk_i;  cs.blind_s <== blind_s;
    component cfs = Poseidon(2);
    cfs.inputs[0] <== cs.Cx;  cfs.inputs[1] <== cs.Cy;
    signal Cf_s;
    Cf_s <== cfs.out;
```

  - 서명 메시지: `component msgHasher = Poseidon(5);` → `Poseidon(6)`, 입력 `[DOMAIN_MODE3_CRED_V5, Cf_u, Cf_s, max_height, chainid, allowAgent]` 순서.
  - 리프: `leafHasher.inputs[0] <== TAG_MODE3_USER; leafHasher.inputs[1] <== Cf_u;`
  - 태그 블록 앞에 r ≠ 0:

```circom
    // r ≠ 0 (2026-09-21 결정): c1 = r·B8 가 항등원이면 c2 가 평문을 그대로 드러낸다. 컨트랙트·서비스의 c1 ≠ O 검사와 중복 방어.
    component rNZ = IsZero();
    rNZ.in <== r;
    rNZ.out === 0;
```

- [ ] **Step 6: 커밋 스킴 테스트 갱신** — `tests/test_mode3_commit_scheme.mjs`
  - "Pedersen 판: 회로의 (Cx, Cy) 가 JS credCommit 과 일치한다" 케이스 아래에 두 케이스 추가(이 파일의 기존 컴파일·witness 헬퍼를 그대로 쓴다 — `CommitPedersen` 을 감싸는 main 래퍼를 만드는 방식과 같게 `CommitUser`, `CommitSession` 래퍼 회로를 임시 디렉터리에 써서 컴파일):

이 파일의 기존 헬퍼는 `compile(name, src) → 제약 수`(래퍼 `.circom` 을 `OUT_DIR` 에 쓰고 circom 실행) 와 `witness(name, input) → witness 배열`(인덱스 1·2 가 main 의 첫 두 출력 = Cx, Cy) 이다. 파일 상단 `SRC` 객체(`poseidon`, `pedersen` 래퍼 소스)에 두 항목을 추가하고 케이스를 넣는다:

```js
// SRC 에 추가
  user: `pragma circom 2.0.0;
include "lib/mode3_commit.circom";
component main = CommitUser();`,
  session: `pragma circom 2.0.0;
include "lib/mode3_commit.circom";
component main = CommitSession();`,
```

```js
await t('V5: CommitUser 회로의 (Cx, Cy) 가 JS userCommit 과 일치한다', async () => {
  const { userCommit } = await import('../lib/mode3_credential.js');
  const n = compile('user', SRC.user);
  assert.ok(n > 0);
  const w = await witness('user', { uid: '11', s_u: '22', blind_u: '33', attrs: ['19', '410', '0', '0'] });
  const { Cx, Cy } = await userCommit({ uid: 11n, s_u: 22n, blind_u: 33n, attrs: [19n, 410n, 0n, 0n] });
  assert.equal(BigInt(w[1]), Cx); assert.equal(BigInt(w[2]), Cy);
});
await t('V5: CommitSession 회로의 (Cx, Cy) 가 JS sessionCommit 과 일치한다', async () => {
  const { sessionCommit } = await import('../lib/mode3_credential.js');
  compile('session', SRC.session);
  const w = await witness('session', { arid: '44', pk_i: '4660', blind_s: '55' });
  const { Cx, Cy } = await sessionCommit({ arid: 44n, pk_i: 4660n, blind_s: 55n });
  assert.equal(BigInt(w[1]), Cx); assert.equal(BigInt(w[2]), Cy);
});
```

(기존 "Pedersen 판: 회로의 (Cx, Cy) 가 JS credCommit 과 일치한다" 케이스가 witness 배열의 어느 인덱스를 Cx·Cy 로 읽는지 확인해 같은 인덱스를 쓴다.)

- [ ] **Step 7: 빌드**

Run: `bash scripts/build_mode3_circuit.sh pot21_final.ptau`
Expected: compile → setup → contribute → vkey → `contracts/PiCredVerifier.sol` 재생성, 에러 없음. `npx snarkjs r1cs info build/mode3/pi_cred.r1cs` 로 제약 수를 읽어 적어 둔다(예상 ≈ 27,200; Task 8 에서 스펙 §8 에 기록).

- [ ] **Step 8: circuit 그룹 통과 확인**

Run: `node tests/test_pi_cred_witness.mjs && node tests/test_mode3_commit_scheme.mjs`
Expected: 전부 ok. (`test_pi_cred_witness.mjs` 는 자체 컴파일을 `build/mode3/witness_test/` 에 하므로 빌드 산출물과 무관하게 돈다.)

- [ ] **Step 9: 커밋**

```bash
git add circuits/lib/mode3_commit.circom circuits/pi_cred.circom contracts/PiCredVerifier.sol tests/helpers/mode3_fixture.mjs tests/test_pi_cred_witness.mjs tests/test_mode3_commit_scheme.mjs
git commit -m "feat(mode3): 자격증명 이중 구조 3/8 — 회로 V5 (CommitUser·CommitSession, D_V5 서명, userLeaf, r≠0), 픽스처·PiCredVerifier 재생성"
```

---

### Task 4: CIA 상태 v6, `/cia/user_cred`, `/cia/issue` V5

**Files:**
- Modify: `lib/mode3_cia_state.js`
- Modify: `tests/test_mode3_cia_state.js`
- Modify: `cia.js` (`/cia/issue` 교체, `/cia/user_cred` 추가; 폐기는 Task 5)
- Modify: `tests/test_cia_register_issue.mjs` (발급 부분)
- Modify: `tests/test_cia_startup.mjs`
- Modify: `tests/helpers/isolated_cia.mjs` (`CIA_REVOKE_SKEW_BLOCKS: ''` 핀 제거 — env 는 이제 무시됨)

**Interfaces:**
- Consumes: Task 1·2 의 `userCommit`(안 씀), `compressPoint`, `credMessageV5`, `userLeaf`, `verifyUserCred`, `parseUserCredProof`, `userCredRequestMessage`, `issueRequestMessageV4`
- Produces:
  - 상태 v6: `accounts[uid] = { pk_u, cm_u, disabled, creds: [{ Cf_u, C_u_pt:{x,y}, leaf, issuedAt, revoked }] }`, `issued` 없음. `CIA_STATE_VERSION = 6`.
  - `POST /cia/user_cred {uid, C_u_pt, proof, sig_u}` → `201 {Cf_u, leaf}` (같은 Cf_u 재요청 200), 400 형식/서명/증명, 403 disabled, 404 unknown.
  - `POST /cia/issue {uid, Cf_u, C_s_pt, chainid, allowAgent, max_height, sig_u}` → `200 {Cf_u, Cf_s, max_height, chainid, allowAgent, sigma:{R8x,R8y,S}, pk_CIA}`; 403 `{error:'no active user credential'}` 를 `no_user_cred` 로 구분.
  - 내부 `activeCred(uid) → cred | null`.

- [ ] **Step 1: 상태 테스트** — `tests/test_mode3_cia_state.js` 의 v5 기대값을 v6 로 바꾸고 이행 케이스 추가

```js
await t('기본 상태는 v6 이고 issued 가 없다', () => {
  const s = defaultCiaState();
  assert.equal(s.version, 6); assert.equal(CIA_STATE_VERSION, 6);
  assert.deepEqual(s, { version: 6, accounts: {}, rps: {}, openings: [], revoked: [], pending: [], epoch: 0 });
});
await t('v5 → v6: issued 를 버리고 각 계정에 creds:[] 를 넣는다', () => {
  const v5 = { version: 5, accounts: { '12345': { pk_u: { x: '1', y: '2' }, cm_u: { x: '3', y: '4' }, disabled: false } },
    issued: { '12345': [{ leaf: '9', C: '8', max_height: '100', chainid: '31337' }] }, rps: {}, openings: [], revoked: [], pending: [], epoch: 0 };
  const { state, notes } = migrateCiaState(structuredClone(v5));
  assert.equal(state.version, 6); assert.equal(state.issued, undefined);
  assert.deepEqual(state.accounts['12345'].creds, []);
  assert.ok(notes.some((n) => n.includes('v5→v6') && n.includes('1개')));
});
```

기존 케이스 중 `assert.equal(s.version, 5)` 류는 6 으로, `issued: {}` 를 기대하는 deepEqual 은 제거. v4→v5 케이스는 최종 버전이 6 인지로 바꾼다(`state.version === 6`).

- [ ] **Step 2: 실패 확인** — `node tests/test_mode3_cia_state.js` → 새 케이스 FAIL.

- [ ] **Step 3: 상태 모듈 구현** — `lib/mode3_cia_state.js`

```js
// version 6 (2026-09-21): 자격증명 이중 구조. accounts[uid].creds = [{ Cf_u, C_u_pt, leaf, issuedAt, revoked }] (사용자당 활성 하나).
//   issued(세션 기록) 삭제 — 폐기 리프가 C_u 에서 나오므로 세션 기록이 필요 없다(설계 §4.2·§4.4).
export const CIA_STATE_VERSION = 6;
export function defaultCiaState() {
  return { version: CIA_STATE_VERSION, accounts: {}, rps: {}, openings: [], revoked: [], pending: [], epoch: 0 };
}
```

`migrateCiaState` 의 v4→v5 블록 뒤에:

```js
  if (state.version === 5) {
    const dropped = Object.values(state.issued ?? {}).reduce((n, l) => n + (Array.isArray(l) ? l.length : 0), 0);
    delete state.issued;
    for (const a of Object.values(state.accounts ?? {})) a.creds ??= [];
    state.version = 6;
    notes.push(`v5→v6: 세션 발급 기록 ${dropped}개 버림(V4 서명은 V5 회로에서 검증되지 않는다), 계정마다 creds:[] — 사용자 자격증명은 첫 로그인 때 다시 발급된다`);
  }
```

마지막 줄의 `state.issued ??= {};` 를 지우고 `for (const a of Object.values(state.accounts)) a.creds ??= [];` 를 넣는다.

- [ ] **Step 4: 통과 확인** — `node tests/test_mode3_cia_state.js` 전부 ok.

- [ ] **Step 5: CIA 엔드포인트 테스트** — `tests/test_cia_register_issue.mjs` 의 발급 헬퍼와 케이스를 V5 로. 파일 상단 헬퍼 `signUser`/`issueRequest` 를 다음으로 교체:

```js
import { userCommit, sessionCommit, compressPoint, randomScalar as rs250 } from '../lib/mode3_credential.js';
import { proveUserCred, serializeUserCredProof, userCredRequestMessage, issueRequestMessageV4, pointToStrings, registrationCommit } from '../lib/mode3_issuance.js';
import { userLeaf } from '../lib/mode3_revocation.js';

const signMsg = async (prvBuf, m) => { const s = eddsa.signPoseidon(prvBuf, F.e(m)); return { R8x: F.toObject(s.R8[0]).toString(), R8y: F.toObject(s.R8[1]).toString(), S: s.S.toString() }; };
const mhOf = async (ttl = 300n) => BigInt(await provider.getBlockNumber()) + ttl;

/** 사용자 자격증명 요청 본문. u 는 { s_u, r_u, sk_u(Buffer), attrs }. */
async function userCredRequest(u, overrides = {}) {
  const blind_u = rs250();
  const { C_u_pt, proof } = await proveUserCred({ uid, s_u: u.s_u, blind_u, r_u: u.r_u, attrs: u.attrs ?? [19n, 410n, 0n, 0n] });
  const Cf_u = await compressPoint(C_u_pt);
  return { body: { uid: uid.toString(), C_u_pt: pointToStrings(C_u_pt), proof: serializeUserCredProof(proof), sig_u: await signMsg(u.sk_u, await userCredRequestMessage(C_u_pt)), ...overrides }, C_u_pt, Cf_u, blind_u, leaf: await userLeaf(Cf_u) };
}
/** 세션 발급 요청 본문. cred 는 userCredRequest 의 반환값. */
async function issueRequest(u, cred, overrides = {}, { chainid = CHAIN_ID, allowAgent = 0n, max_height, pk_i = 0x1234n } = {}) {
  if (max_height === undefined) max_height = await mhOf();
  const blind_s = rs250();
  const { Cx, Cy } = await sessionCommit({ arid, pk_i, blind_s });
  const C_s_pt = { x: Cx, y: Cy };
  const sig_u = await signMsg(u.sk_u, await issueRequestMessageV4(cred.Cf_u, C_s_pt, chainid, allowAgent, max_height));
  return { body: { uid: uid.toString(), Cf_u: cred.Cf_u.toString(), C_s_pt: pointToStrings(C_s_pt), chainid: chainid.toString(), allowAgent: allowAgent.toString(), max_height: max_height.toString(), sig_u, ...overrides }, C_s_pt, blind_s, max_height };
}
```

기존 케이스의 `issueRequest(user)` 호출은 `issueRequest(user, cred)` 로 바꾸고, 각 블록 첫머리에 `const cred = await userCredRequest(user); assert.equal((await cia.post('/cia/user_cred', cred.body)).status, 201);` 를 둔다. `π_issue` 를 검사하던 케이스(`bad issuance proof`, "다른 s_u 로 만든 C_pt 는 400")는 `/cia/user_cred` 로 옮긴다. 새 케이스 (기존 "register" 케이스 뒤):

```js
await t('user_cred: 201 {Cf_u, leaf}; 같은 Cf_u 재요청은 200; 잘못된 증명·서명은 400; cm_u 와 다른 s_u 는 400', async () => {
  const c = await userCredRequest(user);
  const r = await cia.post('/cia/user_cred', c.body);
  assert.equal(r.status, 201, JSON.stringify(r.body));
  assert.equal(r.body.Cf_u, c.Cf_u.toString()); assert.equal(r.body.leaf, c.leaf.toString());
  assert.equal((await cia.post('/cia/user_cred', c.body)).status, 200);
  const bad = await userCredRequest(user); bad.body.proof.z_su = '1';
  assert.equal((await cia.post('/cia/user_cred', bad.body)).status, 400);
  const sybil = await userCredRequest({ ...user, s_u: user.s_u + 1n });
  assert.equal((await cia.post('/cia/user_cred', sybil.body)).status, 400);
  const badSig = await userCredRequest(user); badSig.body.sig_u = (await userCredRequest(user)).body.sig_u;
  assert.equal((await cia.post('/cia/user_cred', badSig.body)).status, 400);
  assert.equal((await cia.get(`/cia/state`)).body.accounts?.[uid.toString()]?.creds?.length ?? 1, 1, '활성 자격증명은 하나');
});

await t('user_cred: 새 자격증명을 받으면 옛 것은 revoked 되고 리프가 pending 에 들어간다 (속성 변경)', async () => {
  const a = await userCredRequest(user); assert.equal((await cia.post('/cia/user_cred', a.body)).status, 201);
  const before = (await cia.get('/cia/state')).body.pendingCount;
  const b = await userCredRequest({ ...user, attrs: [20n, 410n, 0n, 0n] }); assert.equal((await cia.post('/cia/user_cred', b.body)).status, 201);
  const st = (await cia.get('/cia/state')).body;
  assert.equal(st.pendingCount, before + 1);
  // 옛 Cf_u 로는 세션 발급이 안 된다
  const old = await issueRequest(user, a);
  const r = await cia.post('/cia/issue', old.body);
  assert.equal(r.status, 403); assert.equal(r.body.reason, 'no_user_cred');
});

await t('issue V5: 정상 200 — 응답에 Cf_u·Cf_s·서명, CIA 는 세션 기록을 남기지 않는다', async () => {
  const cred = await userCredRequest(user); assert.equal((await cia.post('/cia/user_cred', cred.body)).status, 201);
  const req = await issueRequest(user, cred);
  const r = await cia.post('/cia/issue', req.body);
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(r.body.Cf_u, cred.Cf_u.toString());
  assert.equal(r.body.Cf_s, (await compressPoint(req.C_s_pt)).toString());
  assert.equal(r.body.max_height, req.body.max_height);
  const m = await credMessageV5(BigInt(r.body.Cf_u), BigInt(r.body.Cf_s), BigInt(r.body.max_height), CHAIN_ID, 0n);
  assert.ok(eddsa.verifyPoseidon(F.e(m), { R8: [F.e(BigInt(r.body.sigma.R8x)), F.e(BigInt(r.body.sigma.R8y))], S: BigInt(r.body.sigma.S) }, [F.e(BigInt(r.body.pk_CIA.x)), F.e(BigInt(r.body.pk_CIA.y))]));
  assert.equal((await cia.get('/cia/state')).body.issuedCount, undefined, '세션 기록 없음');
});

await t('issue V5: 서명이 Cf_u·C_s·chainid·allowAgent·max_height 를 덮는다 — 하나라도 바꾸면 400; 등록 안 된 Cf_u 는 403 no_user_cred; C_s_pt 가 부분군 밖이면 400', async () => {
  const cred = await userCredRequest(user); assert.equal((await cia.post('/cia/user_cred', cred.body)).status, 201);
  for (const patch of [{ max_height: '1' }, { allowAgent: '1' }, { chainid: '1' }]) {
    const req = await issueRequest(user, cred, patch);
    assert.equal((await cia.post('/cia/issue', req.body)).status, 400, JSON.stringify(patch));
  }
  const other = await issueRequest(user, cred);
  const swapped = await issueRequest(user, cred);
  swapped.body.C_s_pt = other.body.C_s_pt;
  assert.equal((await cia.post('/cia/issue', swapped.body)).status, 400);
  const foreign = await issueRequest(user, { Cf_u: 12345n });
  const r = await cia.post('/cia/issue', foreign.body);
  assert.equal(r.status, 403); assert.equal(r.body.reason, 'no_user_cred');
  const badPt = await issueRequest(user, cred); badPt.body.C_s_pt = { x: '1', y: '1' };
  assert.equal((await cia.post('/cia/issue', badPt.body)).status, 400);
});
```

`credMessageV5` 를 import 에 추가. `/cia/state` 응답에 `accounts` 가 없으면 첫 케이스의 마지막 assert 는 `state.accounts` 대신 `(await cia.get('/cia/state')).body.credCount` 를 쓰도록 `/cia/state` 에 `credCount`(활성 자격증명 총수)를 추가한다(Step 6).

- [ ] **Step 6: CIA 구현** — `cia.js`
  - import 에 `verifyUserCred, parseUserCredProof, userCredRequestMessage, issueRequestMessageV4` 추가, `verifyIssuance, parseProof, issueRequestMessage` 는 제거. `credMessage, credLeaf` → `credMessageV5`, `userLeaf`.
  - `REVOKE_SKEW_BLOCKS`·`pruneExpired` 삭제; `CIA_REVOKE_SKEW_BLOCKS` 를 경고 목록(`CIA_TTL_SECONDS`, … 배열)에 추가.
  - 헬퍼:

```js
/** 사용자당 활성 자격증명 하나(설계 §3.1). 없으면 null. */
function activeCred(uid) {
  return (state.accounts[uid]?.creds ?? []).find((c) => !c.revoked) ?? null;
}
/** 활성 자격증명을 revoked 로 돌리고 리프를 트리·pending 에 넣는다. 돌려주는 값은 새로 들어간 리프 목록(멱등). */
async function retireActiveCred(uid) {
  const inserted = [];
  for (const c of state.accounts[uid]?.creds ?? []) {
    if (c.revoked) continue;
    c.revoked = true;
    if (await tree.insert(BigInt(c.leaf))) { state.revoked.push(c.leaf); state.pending.push(c.leaf); inserted.push(c.leaf); }
  }
  return inserted;
}
```

  - `/cia/user_cred`:

```js
// §4.1(2026-09-21) 사용자 자격증명 발급. 세션과 무관 — 속성이 바뀔 때만 다시 온다. AA 서명은 없다(세션 서명이 Cf_u 를 덮는다).
// 검사 순서: 형식 → 계정·disabled → C_u_pt 부분군 → sig_u → π_u → 기록. 이미 활성 자격증명이 있으면 그것을 물리고(리프 → pending) 새 것을 활성으로.
app.post('/cia/user_cred', async (req, res) => {
  try {
    const { uid, C_u_pt, proof, sig_u } = req.body ?? {};
    if (!isDec(uid) || !isPt(C_u_pt) || !proof || !sig_u) return res.status(400).json({ error: 'uid, C_u_pt, proof, sig_u required' });
    const acct = state.accounts[uid];
    if (!acct) return res.status(404).json({ error: 'unknown account' });
    if (acct.disabled) return res.status(403).json({ error: 'account disabled' });
    const cpt = pointFromStrings(C_u_pt);
    if (!(await isValidPoint(cpt))) return res.status(400).json({ error: 'C_u_pt is not a valid subgroup point' });
    let sigOk = false;
    try {
      const m = F.e(await userCredRequestMessage(cpt));
      sigOk = eddsa.verifyPoseidon(m, { R8: [F.e(BigInt(sig_u.R8x)), F.e(BigInt(sig_u.R8y))], S: BigInt(sig_u.S) }, [F.e(BigInt(acct.pk_u.x)), F.e(BigInt(acct.pk_u.y))]);
    } catch { sigOk = false; }
    if (!sigOk) return res.status(400).json({ error: 'bad user signature' });
    let proofOk = false;
    try { proofOk = await verifyUserCred({ uid: BigInt(uid), C_u_pt: cpt, cm_u: pointFromStrings(acct.cm_u), proof: parseUserCredProof(proof) }); }
    catch { proofOk = false; }
    if (!proofOk) return res.status(400).json({ error: 'bad user credential proof' });
    const Cf_u = (await compressPoint(cpt)).toString();
    const leaf = (await userLeaf(BigInt(Cf_u))).toString();
    if (acct.disabled) return res.status(403).json({ error: 'account disabled' });   // await 사이에 폐기가 끼어들 수 있다
    acct.creds ??= [];
    const existing = acct.creds.find((c) => c.Cf_u === Cf_u);
    if (existing && !existing.revoked) return res.json({ Cf_u, leaf });   // 멱등
    if (existing && existing.revoked) return res.status(409).json({ error: 'this user credential was revoked; make a new one' });
    await retireActiveCred(uid);
    acct.creds.push({ Cf_u, C_u_pt: { x: cpt.x.toString(), y: cpt.y.toString() }, leaf, issuedAt: new Date().toISOString(), revoked: false });
    persist();
    res.status(201).json({ Cf_u, leaf });
  } catch (e) { res.status(e.status || 500).json({ error: e.message }); }
});
```

  - `/cia/issue` 를 다음으로 교체:

```js
// §4.2(2026-09-21) 세션 발급 V5. ZKP 없음 — uid·s_u 는 사용자 자격증명 발급 때 π_u 로 이미 증명됐다.
// 검사 순서: 형식 → disabled → chainid 허용·체인 생존 → max_height 범위 → sig_u → 활성 Cf_u 조회 → C_s_pt 부분군 → 서명. 기록하지 않는다.
app.post('/cia/issue', async (req, res) => {
  try {
    const { uid, Cf_u, C_s_pt, sig_u, chainid, allowAgent, max_height } = req.body ?? {};
    if (!isDec(uid) || !isDec(Cf_u) || !isPt(C_s_pt) || !sig_u || !isDec(chainid) || (allowAgent !== '0' && allowAgent !== '1') || !isDec(max_height)) {
      return res.status(400).json({ error: 'uid, Cf_u, C_s_pt, sig_u, chainid, allowAgent("0"|"1"), max_height required' });
    }
    const mh = BigInt(max_height);
    if (mh >= (1n << 64n)) return res.status(400).json({ error: 'max_height must be < 2^64' });
    const acct = state.accounts[uid];
    if (!acct) return res.status(404).json({ error: 'unknown account' });
    if (acct.disabled) return res.status(403).json({ error: 'account disabled', reason: 'account_disabled' });
    const chainStr = BigInt(chainid).toString();
    if (CHAIN_RPCS.size === 0) return res.status(503).json({ error: 'chain id unknown: CIA_CHAIN_RPCS not configured and RPC unreachable at startup' });
    if (!CHAIN_RPCS.has(chainStr)) return res.status(400).json({ error: `bad chainid ${chainStr}: allowed ${[...CHAIN_RPCS.keys()].join(',')}` });
    const agent = BigInt(allowAgent);
    const cfu = BigInt(Cf_u);
    const cspt = pointFromStrings(C_s_pt);
    let sigOk = false;
    try {
      const m = F.e(await issueRequestMessageV4(cfu, cspt, BigInt(chainStr), agent, mh));
      sigOk = eddsa.verifyPoseidon(m, { R8: [F.e(BigInt(sig_u.R8x)), F.e(BigInt(sig_u.R8y))], S: BigInt(sig_u.S) }, [F.e(BigInt(acct.pk_u.x)), F.e(BigInt(acct.pk_u.y))]);
    } catch { sigOk = false; }
    if (!sigOk) return res.status(400).json({ error: 'bad user signature' });
    const cred = activeCred(uid);
    if (!cred || cred.Cf_u !== cfu.toString()) return res.status(403).json({ error: 'no active user credential for this Cf_u', reason: 'no_user_cred' });
    if (!(await isValidPoint(cspt))) return res.status(400).json({ error: 'C_s_pt is not a valid subgroup point' });
    const Cf_s = await compressPoint(cspt);
    await chainAlive(chainStr);   // fail-closed: 체인이 죽어 있으면 발급하지 않는다(게시도 불가하므로 폐기가 닿지 않는 세션이 된다)
    if (acct.disabled || activeCred(uid)?.Cf_u !== cfu.toString()) return res.status(403).json({ error: 'account disabled or credential retired', reason: 'no_user_cred' });   // await 사이의 폐기
    const s = eddsa.signPoseidon(ciaPrv, F.e(await credMessageV5(cfu, Cf_s, mh, BigInt(chainStr), agent)));
    res.json({
      Cf_u: cfu.toString(), Cf_s: Cf_s.toString(), max_height: mh.toString(), chainid: chainStr, allowAgent: agent.toString(),
      sigma: { R8x: F.toObject(s.R8[0]).toString(), R8y: F.toObject(s.R8[1]).toString(), S: s.S.toString() },
      pk_CIA: S(ciaPub),
    });
  } catch (e) { res.status(e.status || 500).json({ error: e.message }); }
});
```

  - `/cia/state` 응답에 `credCount: Object.values(state.accounts).reduce((n, a) => n + (a.creds ?? []).filter((c) => !c.revoked).length, 0)` 추가, `issuedCount` 가 있으면 제거.
  - 폐기 엔드포인트(`revokeAccount`, `/cia/revoke`)는 아직 `pruneExpired` 를 부르므로 이 Task 에서는 **임시로** `const targets = (await pruneExpired(uid))` 를 `const targets = []` 로 두지 말고, Task 5 를 바로 이어서 한다. Task 4 의 커밋 시점에 CIA 가 기동되려면 `pruneExpired` 참조가 없어야 하므로, Task 4 에서 `revokeAccount` 를 다음 최소형으로 바꿔 둔다(Task 5 가 테스트를 붙인다):

```js
async function revokeAccount(uid) {
  const acct = state.accounts[uid];
  if (!acct) throw Object.assign(new Error('unknown account'), { status: 404 });
  acct.disabled = true;
  const inserted = await retireActiveCred(uid);
  persist();
  return { inserted, root: tree.getRoot().toString(), pending: state.pending.length };
}
```

  그리고 `/cia/revoke` 의 `scope==='credential'` 분기는 `const inserted = await retireActiveCred(uid); persist(); return res.json({ inserted, root: tree.getRoot().toString(), pending: state.pending.length });` 로.

- [ ] **Step 7: startup·helper 갱신**
  - `tests/helpers/isolated_cia.mjs`: env 핀에서 `CIA_REVOKE_SKEW_BLOCKS: ''` 제거.
  - `tests/test_cia_startup.mjs`: 발급 스모크가 `signUserRequest(..., C_pt, ...)` + `/cia/issue` 를 쓰면, `/cia/user_cred` 먼저(위 `userCredRequest` 와 같은 구성) → `/cia/issue` V5 본문으로 바꾼다. 상태 파일 v5 → v6 이행 로그(`v5→v6`)를 확인하는 케이스가 있으면 문구를 맞춘다.

- [ ] **Step 8: 통과 확인** (hardhat :8545 필요)

Run: `node tests/test_cia_register_issue.mjs && node tests/test_cia_startup.mjs`
Expected: 전부 ok. (폐기 관련 케이스 중 `scope:'credential', C:` 를 쓰는 것들은 Task 5 에서 고치므로 이 시점엔 FAIL 이어도 된다 — Task 5 를 같은 세션에서 이어 간다. Task 4 단독으로 커밋할 때는 그 케이스들을 Task 5 로 옮기기 위해 `// Task 5` 주석으로 감싸 두지 말고, 그냥 이어서 진행한다.)

- [ ] **Step 9: 커밋**

```bash
git add lib/mode3_cia_state.js tests/test_mode3_cia_state.js cia.js tests/test_cia_register_issue.mjs tests/test_cia_startup.mjs tests/helpers/isolated_cia.mjs
git commit -m "feat(mode3): 자격증명 이중 구조 4/8 — CIA 상태 v6, /cia/user_cred(π_u), /cia/issue V5(ZKP 없음), 세션 기록 제거"
```

---

### Task 5: CIA 폐기 단순화와 폐기·경합·개봉 테스트

**Files:**
- Modify: `cia.js` (`/cia/revoke` 본문 정리, 주석)
- Modify: `tests/test_cia_register_issue.mjs` (폐기 케이스 전부)
- Modify: `tests/test_cia_issue_race.mjs`
- Modify: `tests/test_cia_opening.mjs`

**Interfaces:**
- Consumes: Task 4 의 `activeCred`, `retireActiveCred`, `/cia/user_cred`, `/cia/issue` V5
- Produces: `POST /cia/revoke {uid, scope:'account'|'credential'}` → `{inserted:[leaf...], root, pending}`; `leaf`/`C` 인자는 무시(있어도 400 아님).

- [ ] **Step 1: 폐기 케이스 재작성** — `tests/test_cia_register_issue.mjs`. 기존 `scope:'credential', C:`/`leaf:` 케이스, I1·I2·skew 케이스(`CIA_REVOKE_SKEW_BLOCKS`), "같은 C_pt 재요청은 200 — max_height 큰 쪽" 케이스, "미만료 리프 전부" 케이스를 지우고 다음으로 바꾼다:

```js
await t('revoke(account): 활성 자격증명 리프 하나가 트리에 들어가고 disabled; 재요청은 멱등(새 리프 없음); 이후 issue 403', async () => {
  const cred = await userCredRequest(user); assert.equal((await cia.post('/cia/user_cred', cred.body)).status, 201);
  const r = await cia.adminPost('/cia/revoke', { uid: uid.toString(), scope: 'account' });
  assert.equal(r.status, 200); assert.deepEqual(r.body.inserted, [cred.leaf.toString()]);
  const again = await cia.adminPost('/cia/revoke', { uid: uid.toString(), scope: 'account' });
  assert.deepEqual(again.body.inserted, []);
  const req = await issueRequest(user, cred);
  assert.equal((await cia.post('/cia/issue', req.body)).status, 403);
  assert.equal((await cia.post('/cia/user_cred', (await userCredRequest(user)).body)).status, 403, 'disabled 면 새 자격증명도 안 준다');
});

await t('revoke(credential): 리프만 넣고 계정은 살아 있다 — 새 user_cred 를 받으면 다시 발급된다', async () => {
  await cia.adminPost('/cia/set_disabled', { uid: uid.toString(), disabled: false });
  const cred = await userCredRequest(user); assert.equal((await cia.post('/cia/user_cred', cred.body)).status, 201);
  const r = await cia.adminPost('/cia/revoke', { uid: uid.toString(), scope: 'credential' });
  assert.deepEqual(r.body.inserted, [cred.leaf.toString()]);
  assert.equal((await cia.post('/cia/issue', (await issueRequest(user, cred)).body)).status, 403);
  const cred2 = await userCredRequest(user); assert.equal((await cia.post('/cia/user_cred', cred2.body)).status, 201);
  assert.equal((await cia.post('/cia/issue', (await issueRequest(user, cred2)).body)).status, 200);
});

await t('revoke: 활성 자격증명이 없는 계정의 account 폐기는 disabled 만 건다 (inserted 빈 배열)', async () => {
  // 등록만 하고 user_cred 를 받지 않은 새 계정
  const u2 = await freshRegistered('54321');
  const r = await cia.adminPost('/cia/revoke', { uid: '54321', scope: 'account' });
  assert.equal(r.status, 200); assert.deepEqual(r.body.inserted, []);
  assert.equal((await cia.post('/cia/user_cred', (await userCredRequest({ ...u2 }, { uid: '54321' })).body)).status, 403);
});

await t('self_revoke: 비밀번호만으로 계정 폐기 — 활성 자격증명 리프 하나 + disabled; 재요청은 새 리프 없이 200', async () => {
  await cia.adminPost('/cia/set_disabled', { uid: uid.toString(), disabled: false });
  const cred = await userCredRequest(user); assert.equal((await cia.post('/cia/user_cred', cred.body)).status, 201);
  const r = await cia.post('/cia/account/self_revoke', { uid: uid.toString(), pwd: 'password123' });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.deepEqual(r.body.inserted, [cred.leaf.toString()]); assert.equal(r.body.disabled, true);
  const again = await cia.post('/cia/account/self_revoke', { uid: uid.toString(), pwd: 'password123' });
  assert.equal(again.status, 200); assert.deepEqual(again.body.inserted, []);
  assert.equal((await cia.post('/cia/issue', (await issueRequest(user, cred)).body)).status, 403);
});
```

기존 self_revoke 케이스 중 "잘못된 비밀번호 401, 등록 안 된 계정 404, 형식 오류 400" 과 "체인이 죽어도 200 이고 disabled 가 걸리며 treeUpdated 필드가 없다" 는 본문을 유지하고, 후자의 발급 본문만 V5 형식으로 바꾼다(아래).

(`freshRegistered(uid)` 는 이 파일의 등록 헬퍼 이름에 맞춘다 — 파일에 `register` 류 헬퍼가 있으면 그것을 쓴다. `userCredRequest` 의 `uid` 는 파일 상단 상수 `uid` 를 쓰므로, 다른 uid 계정을 쓰는 케이스에서는 헬퍼에 `uidOverride` 인자를 하나 추가한다: `async function userCredRequest(u, overrides = {}, uidBig = uid)`.)

self_revoke 의 "체인이 죽어도 200" 케이스에서 하드코딩된 발급 본문 `{ uid:'12345', C_pt:{x:'1',y:'1'}, proof:{}, sig_u:{}, chainid:'31337', allowAgent:'0', max_height:'1' }` 는 V5 형식 `{ uid:'12345', Cf_u:'1', C_s_pt:{x:'1',y:'1'}, sig_u:{}, chainid:'31337', allowAgent:'0', max_height:'1' }` 로 바꾼다(disabled 검사가 먼저라 403).

- [ ] **Step 2: 경합 테스트** — `tests/test_cia_issue_race.mjs`. `issueBody()` 가 `proveIssuance` 로 본문을 만들면 다음으로: 먼저 `/cia/user_cred` 를 한 번 받아 `cred` 를 두고, `issueBody()` 는 Task 4 의 `issueRequest(user, cred)` 와 같은 구성(`sessionCommit` + `issueRequestMessageV4` 서명)으로 만든다. 기대는 그대로: 게이트 중 폐기되면 403 이고, 응답이 200 이면 안 된다. "기록도 남지 않는다" 검사는 `/cia/state` 의 `credCount` 가 폐기 뒤 0 인지로 바꾼다.

- [ ] **Step 3: 개봉 테스트** — `tests/test_cia_opening.mjs`. 로그인 트랜스크립트를 만드는 부분이 `buildIssueRequest`(V4) 를 쓰면 Task 6 의 지갑 라이브러리에 의존한다. 이 파일은 **Task 6 뒤에** 돌리는 것으로 하고 여기서는 손대지 않는다(Task 6 Step 5 에서 갱신).

- [ ] **Step 4: `/cia/revoke` 정리** — `cia.js`

```js
// §4.3(2026-09-21) 폐기. account = 활성 사용자 자격증명 리프 + disabled. credential = 리프만(계정은 살아 있어 새 user_cred 를 받아야 한다).
// 리프는 사용자당 하나라 leaf/C 인자를 받지 않는다. 트리 삽입은 멱등(이미 있으면 false).
app.post('/cia/revoke', requireAdmin, async (req, res) => {
  try {
    const { uid, scope } = req.body ?? {};
    if (!isDec(uid) || !state.accounts[uid]) return res.status(404).json({ error: 'unknown account' });
    if (scope === 'account') return res.json(await revokeAccount(uid));
    if (scope !== 'credential') return res.status(400).json({ error: "scope must be 'account' or 'credential'" });
    const inserted = await retireActiveCred(uid);
    persist();
    res.json({ inserted, root: tree.getRoot().toString(), pending: state.pending.length });
  } catch (e) { res.status(e.status || 500).json({ error: e.message }); }
});
```

`revokeAccount`·`/cia/account/self_revoke` 의 주석에서 "미만료 리프 전부" 를 "활성 자격증명 리프 하나" 로 고친다. 관리자 페이지(`mode3/admin.html` 또는 cia.js 안의 HTML)에서 `scope:'credential'` 에 `C`/`leaf` 입력란이 있으면 없앤다.

- [ ] **Step 5: 통과 확인**

Run: `node tests/test_cia_register_issue.mjs && node tests/test_cia_issue_race.mjs`
Expected: 전부 ok.

- [ ] **Step 6: 커밋**

```bash
git add cia.js tests/test_cia_register_issue.mjs tests/test_cia_issue_race.mjs mode3/admin.html
git commit -m "feat(mode3): 자격증명 이중 구조 5/8 — 폐기 = 사용자 자격증명 리프 하나, skew·세션 기록 제거, 폐기·경합 테스트"
```

(`mode3/admin.html` 이 바뀌지 않았으면 add 목록에서 뺀다.)

---

### Task 6: 지갑 라이브러리 V5 와 라이브러리 수준 테스트

**Files:**
- Modify: `lib/mode3_wallet.js`
- Modify: `tests/test_mode3_wallet.mjs`
- Modify: `tests/test_mode3_rp.mjs`
- Modify: `tests/test_mode3_e2e.mjs`
- Modify: `tests/test_cia_opening.mjs`

**Interfaces:**
- Consumes: Task 1·2 (`userCommit`, `sessionCommit`, `credMessageV5`, `userLeaf`, `proveUserCred`, `serializeUserCredProof`, `userCredRequestMessage`, `issueRequestMessageV4`)
- Produces (lib/mode3_wallet.js):
  - `export async function signUserCredRequest(sk_uHex, C_u_pt) → {R8x,R8y,S}(문자열)`
  - `export async function buildUserCredRequest({ uid, s_u, r_u, sk_u, attrs }) → { body:{uid, C_u_pt, proof, sig_u}, secrets:{blind_u}, C_u_pt, Cf_u, leaf }`
  - `export async function signIssueRequest(sk_uHex, Cf_u, C_s_pt, chainid, allowAgent, max_height) → {R8x,R8y,S}`
  - `export async function buildIssueRequest({ uid, Cf_u, arid, sk_u, session, chainid, allowAgent = 0n, max_height }) → { body:{uid, Cf_u, C_s_pt, chainid, allowAgent, max_height, sig_u}, secrets:{blind_s}, C_s_pt, Cf_s }`
  - `export async function buildCredentialProof({ uid, arid, s_u, blind_u, blind_s, pk_i, attrs, credential, pk_CIA, pk_trace, tree, wasmPath, zkeyPath })` — `credential = {Cf_u, Cf_s, max_height, chainid, allowAgent, sigma:{R8x,R8y,S}}`; 폐기됐으면 throw.
  - V4 `signUserRequest` 는 삭제(호출자 없음).

- [ ] **Step 1: 라이브러리 테스트 갱신** — `tests/test_mode3_wallet.mjs`
  - `localIssue` 를 V5 로:

```js
// 서버 없이 CIA 역할을 로컬에서 흉내낸다 (서명만). V5: Sign(D_V5, Cf_u, Cf_s, max_height, chainid, allowAgent). max_height 는 요청 값 그대로.
async function localIssue(Cf_u, C_s_pt, chainid, { max_height, allowAgent = 0n } = {}) {
  const Cf_s = await compressPoint(C_s_pt);
  if (max_height === undefined) max_height = await mh();
  const s = eddsa.signPoseidon(ciaPrv, F.e(await credMessageV5(Cf_u, Cf_s, max_height, chainid, allowAgent)));
  return { Cf_u: Cf_u.toString(), Cf_s: Cf_s.toString(), max_height: max_height.toString(), chainid: chainid.toString(), allowAgent: allowAgent.toString(), sigma: { R8x: F.toObject(s.R8[0]).toString(), R8y: F.toObject(s.R8[1]).toString(), S: s.S.toString() } };
}
```

  - 로그인 시나리오:

```js
  const uc = await buildUserCredRequest({ uid, arid, s_u: reg.s_u, r_u: reg.r_u, sk_u, attrs: [19n, 410n, 0n, 0n] });
  assert.equal(await verifyUserCred({ uid, C_u_pt: uc.C_u_pt, cm_u: reg.cm_u, proof: parseUserCredProof(uc.body.proof) }), true, 'CIA 가 하는 검증');
  req = await buildIssueRequest({ uid, Cf_u: uc.Cf_u, arid, sk_u, session, chainid: 31337n, max_height: await mh() });
  cred = await localIssue(uc.Cf_u, req.C_s_pt, 31337n, { max_height: BigInt(req.body.max_height) });
  ({ tree: tree0 } = await syncRevocationTree(provider, logAddress));
  const { proof, publicSignals, revRoot, tag } = await buildCredentialProof({
    uid, arid, s_u: reg.s_u, blind_u: uc.secrets.blind_u, blind_s: req.secrets.blind_s, pk_i: session.pk_i, attrs: [19n, 410n, 0n, 0n],
    credential: cred, pk_CIA, pk_trace, tree: tree0,
  });
```

  - "buildIssueRequest 는 allowAgent 를 싣고 …" 케이스: `body` 가 `Cf_u, C_s_pt, sig_u, chainid, allowAgent, max_height` 를 갖고 `proof`·`C_pt` 가 없는지, `max_height` 없으면 throw, `allowAgent: 2n` throw, `chooseMaxHeight` 단정은 그대로.
  - 폐기 케이스: `publish([await credLeaf(BigInt(cred.C))])` → `publish([await userLeaf(BigInt(cred.Cf_u))])`; 이후 `buildCredentialProof` 가 throw 하는지(`/member/`).
  - import: `credMessage, credLeaf, signUserRequest` → `credMessageV5, userLeaf, buildUserCredRequest, verifyUserCred, parseUserCredProof`.

- [ ] **Step 2: 실패 확인** — `node tests/test_mode3_wallet.mjs` → import 실패.

- [ ] **Step 3: 구현** — `lib/mode3_wallet.js`
  - import: `credCommit, credMessage` 계열 제거; `userCommit, sessionCommit, credMessageV5`(안 쓰면 생략), `compressPoint`; `userLeaf`; `proveUserCred, serializeUserCredProof, userCredRequestMessage, issueRequestMessageV4, pointToStrings`.
  - `signUserRequest`/`buildIssueRequest` 를 다음으로 교체:

```js
const sigStrings = (F, s) => ({ R8x: F.toObject(s.R8[0]).toString(), R8y: F.toObject(s.R8[1]).toString(), S: s.S.toString() });

/** /cia/user_cred 요청 서명 = Sign(sk_u, Poseidon(D_USERCREDREQ, C_u_pt.x, C_u_pt.y)). */
export async function signUserCredRequest(sk_uHex, C_u_pt) {
  const eddsa = await getEddsa();
  return sigStrings(eddsa.F, eddsa.signPoseidon(Buffer.from(sk_uHex, 'hex'), eddsa.F.e(await userCredRequestMessage(C_u_pt))));
}

/**
 * 사용자 자격증명 요청(설계 2026-09-21 §3.1·§3.5). 사용자당 하나 — 첫 로그인 또는 속성 변경 때. blind_u 는 여기서 뽑아 secrets 로 돌려준다.
 * 지갑은 (C_u_pt, blind_u, attrs, leaf) 를 등록 정보와 함께 보관한다(에이전트 상태 v6).
 */
export async function buildUserCredRequest({ uid, s_u, r_u, sk_u, attrs }) {
  const blind_u = randomScalar();
  const a4 = normalizeAttrs(attrs);
  const { C_u_pt, proof } = await proveUserCred({ uid, s_u, blind_u, r_u, attrs: a4 });
  const Cf_u = await compressPoint(C_u_pt);
  const body = { uid: uid.toString(), C_u_pt: pointToStrings(C_u_pt), proof: serializeUserCredProof(proof), sig_u: await signUserCredRequest(sk_u, C_u_pt) };
  return { body, secrets: { blind_u }, C_u_pt, Cf_u, leaf: await userLeaf(Cf_u) };
}

/** /cia/issue V5 요청 서명 = Sign(sk_u, Poseidon(D_ISSUEREQ_V4, Cf_u, C_s_pt.x, C_s_pt.y, chainid, allowAgent, max_height)). */
export async function signIssueRequest(sk_uHex, Cf_u, C_s_pt, chainid, allowAgent, max_height) {
  if (typeof chainid !== 'bigint' || typeof allowAgent !== 'bigint' || typeof max_height !== 'bigint') throw new Error('signIssueRequest: chainid·allowAgent·max_height(bigint) 가 필요하다');
  const eddsa = await getEddsa();
  return sigStrings(eddsa.F, eddsa.signPoseidon(Buffer.from(sk_uHex, 'hex'), eddsa.F.e(await issueRequestMessageV4(Cf_u, C_s_pt, chainid, allowAgent, max_height))));
}

/**
 * 세션 발급 요청(설계 §3.2·§4.2). ZKP 없음. blind_s 는 여기서 뽑아 secrets 로 돌려준다. max_height 는 지갑이 정한다(chooseMaxHeight).
 * C_s 는 (arid, pk_i) 를 담는다 — AA 는 pk_i 를 못 보고, 서명이 Cf_s 를 덮으므로 바꿔치기는 불가능하다.
 */
export async function buildIssueRequest({ uid, Cf_u, arid, sk_u, session, chainid, allowAgent = 0n, max_height }) {
  if (typeof Cf_u !== 'bigint') throw new Error('buildIssueRequest: Cf_u(bigint) 가 필요하다 — 먼저 사용자 자격증명을 받는다');
  if (typeof chainid !== 'bigint') throw new Error('buildIssueRequest: chainid(bigint) 가 필요하다');
  if (typeof allowAgent !== 'bigint' || (allowAgent !== 0n && allowAgent !== 1n)) throw new Error('buildIssueRequest: allowAgent 는 0n 또는 1n');
  if (typeof max_height !== 'bigint' || max_height < 0n || max_height >= MAX_HEIGHT_MAX) throw new Error('buildIssueRequest: max_height(bigint, < 2^64) 가 필요하다 — 지갑이 chooseMaxHeight 로 정한다');
  const blind_s = randomScalar();
  const { Cx, Cy, Cf } = await sessionCommit({ arid, pk_i: session.pk_i, blind_s });
  const C_s_pt = { x: Cx, y: Cy };
  const body = {
    uid: uid.toString(), Cf_u: Cf_u.toString(), C_s_pt: pointToStrings(C_s_pt),
    sig_u: await signIssueRequest(sk_u, Cf_u, C_s_pt, chainid, allowAgent, max_height),
    chainid: chainid.toString(), allowAgent: allowAgent.toString(), max_height: max_height.toString(),
  };
  return { body, secrets: { blind_s }, C_s_pt, Cf_s: Cf };
}
```

  - `buildCredentialProof`: 시그니처를 `({ uid, arid, s_u, blind_u, blind_s, pk_i, attrs, credential, pk_CIA, pk_trace, tree, wasmPath = WASM_PATH, zkeyPath = ZKEY_PATH })` 로. 본문에서 `const C = BigInt(credential.C); ... credLeaf(C)` → `const w = await tree.getNonMembershipWitness(await userLeaf(BigInt(credential.Cf_u)));`, `input` 의 `blind: blind.toString()` → `blind_u: blind_u.toString(), blind_s: blind_s.toString()`. 주석에 "리프는 사용자 자격증명 Cf_u 에서(2026-09-21 §3.6) — 폐기되면 모든 세션이 여기서 throw" 추가.

- [ ] **Step 4: 통과 확인** — `node tests/test_mode3_wallet.mjs` 전부 ok.

- [ ] **Step 5: 나머지 라이브러리 수준 테스트 갱신**
  - `tests/test_mode3_rp.mjs`: `issueWith(key, C_pt, …)` → `issueWith(key, Cf_u, C_s_pt, { max_height, chainid, allowAgent })` (V5 서명), `makeLogin` 이 `buildUserCredRequest` → `buildIssueRequest` → `issueWith` → `buildCredentialProof`(blind_u, blind_s) 순으로. 서비스 검증 기대(`ok`, `expired`, `bad_expiry`, `stale_root`, `revoked` 등)는 그대로. 폐기 케이스의 리프는 `userLeaf(Cf_u)`.
  - `tests/test_mode3_e2e.mjs`: 같은 방식. "계정 폐기 → 모든 세션 revoked" 를 보이는 케이스가 있으면 세션 둘(서비스 둘)을 만든 뒤 리프 하나 게시로 둘 다 `revoked` 가 되는 단정을 추가한다:

이 파일은 격리 CIA(`cia.post('/cia/issue')`)와 `rp.verifyLogin` 을 쓴다. 지갑 상태 변수 `blind` 를 `blind_u, userCred, blind_s` 로 나누고 `newSessionAndIssue` 를 V5 로:

```js
  async function ensureUserCred() {
    if (userCred) return;
    const uc = await buildUserCredRequest({ uid, s_u: reg.s_u, r_u: reg.r_u, sk_u, attrs: ATTRS });
    const r = await cia.post('/cia/user_cred', uc.body);
    assert.equal(r.status, 201, j(r.body));
    userCred = uc; blind_u = uc.secrets.blind_u;
  }
  async function newSessionAndIssue(aridFor = arid) {
    await ensureUserCred();
    session = createSessionKey();
    const max_height = BigInt(await provider.getBlockNumber()) + 300n;   // 지갑이 정한다
    const req = await buildIssueRequest({ uid, Cf_u: userCred.Cf_u, arid: aridFor, sk_u, session, chainid: 31337n, max_height });
    blind_s = req.secrets.blind_s;
    sessionRs = randomScalar();
    return cia.post('/cia/issue', req.body);
  }
```

`loginRound`·"폐기된 credential 로는 새 root 에 대한 π 도 만들 수 없다" 의 `buildCredentialProof` 호출에 `blind_u, blind_s` 를 넘긴다(`blind` 제거). "복구 → 재발급 → 로그인, PPID 유지" 케이스는 복구 뒤 `userCred = null` 로 두어 `ensureUserCred` 가 새 자격증명을 받게 한다. "disabled 계정은 재발급 거절" 은 `/cia/issue` 403 을 그대로 확인한다. 그리고 두 서비스 케이스를 "계정 폐기 + 게시" 케이스 **앞**에 추가한다:

```js
  await t('V5: 두 서비스(arid A·B)에 로그인한 뒤 사용자 자격증명 리프 하나가 게시되면 두 세션 모두 죽는다', async () => {
    const aridB = arid + 1n;
    const pk_traceB = await combinePublicKey((await createShare()).X, (await createShare()).X);
    const rpB = createRpVerifier({ provider, logAddress: cia.logAddress, vkey, pkCIA: pk_CIA, arid: aridB, chainId: 31337n, pkTrace: pk_traceB });
    // A: 현재 세션(앞 케이스에서 로그인 성공). B: 새 세션
    const sessA = session, rsA = sessionRs, blindA = blind_s, credA = cred;
    assert.equal((await newSessionAndIssue(aridB)).status, 200);
    // 격리 CIA 의 /cia/issue 는 마지막 응답을 cred 에 두는 기존 규약을 따른다 — 앞 케이스와 같은 방식으로 cred 를 갱신한다
    const { tree, root } = await syncRevocationTree(provider, cia.logAddress);
    const piB = await buildCredentialProof({ uid, arid: aridB, s_u: reg.s_u, blind_u, blind_s, pk_i: session.pk_i, attrs: ATTRS, credential: cred, pk_CIA, pk_trace: pk_traceB, tree });
    assert.equal((await rpB.verifyLogin({ proof: piB.proof, publicSignals: piB.publicSignals, sig: await signChallenge(session.wallet, sessionRs.toString()), r_s: sessionRs })).ok, true);
    // 폐기 리프 하나 게시
    const rv = await cia.adminPost('/cia/revoke', { uid: uid.toString(), scope: 'credential' });
    assert.equal(rv.body.inserted.length, 1);
    assert.equal((await cia.adminPost('/cia/publish')).body.published, true);
    const { tree: t2 } = await syncRevocationTree(provider, cia.logAddress);
    await assert.rejects(() => buildCredentialProof({ uid, arid, s_u: reg.s_u, blind_u, blind_s: blindA, pk_i: sessA.pk_i, attrs: ATTRS, credential: credA, pk_CIA, pk_trace, tree: t2 }), /is a member/);
    await assert.rejects(() => buildCredentialProof({ uid, arid: aridB, s_u: reg.s_u, blind_u, blind_s, pk_i: session.pk_i, attrs: ATTRS, credential: cred, pk_CIA, pk_trace: pk_traceB, tree: t2 }), /is a member/);
    // 계정은 살아 있으므로 새 사용자 자격증명을 받으면 다시 로그인된다
    userCred = null; session = sessA; sessionRs = rsA; blind_s = blindA; cred = credA;
    await cia.adminPost('/cia/set_disabled', { uid: uid.toString(), disabled: false });
    assert.equal((await newSessionAndIssue()).status, 200);
    assert.equal((await loginRound()).ok, true);
  });
```

(`cred` 를 `newSessionAndIssue` 의 응답 본문으로 갱신하는 줄이 기존 "발급 → 로그인 성공" 케이스에 있다 — 같은 줄을 위 케이스의 `newSessionAndIssue(aridB)` 뒤에도 둔다: `cred = r.body`. 이 파일에서 `cred` 는 `credential` 인자로 그대로 들어가는 CIA 응답 본문이다.)
  - `tests/test_cia_opening.mjs`: 트랜스크립트 생성이 `buildIssueRequest` 를 쓰면 `buildUserCredRequest` + `/cia/user_cred` 를 먼저 하고 V5 `buildIssueRequest`(`Cf_u` 인자) 로. 개봉 결과 단정(`uid`, `allowAgent`)은 그대로.

- [ ] **Step 6: 통과 확인**

Run: `node tests/test_mode3_rp.mjs && node tests/test_mode3_e2e.mjs && node tests/test_cia_opening.mjs`
Expected: 전부 ok.

- [ ] **Step 7: 커밋**

```bash
git add lib/mode3_wallet.js tests/test_mode3_wallet.mjs tests/test_mode3_rp.mjs tests/test_mode3_e2e.mjs tests/test_cia_opening.mjs
git commit -m "feat(mode3): 자격증명 이중 구조 6/8 — 지갑 라이브러리 V5(사용자 자격증명 요청·세션 요청·증명), rp/e2e/opening 테스트"
```

---

### Task 7: 지갑 에이전트 상태 v6, userCred 확보, `/wallet/attrs`, 데모 페이지·문서

**Files:**
- Modify: `mode3_wallet_agent.js`
- Modify: `mode3/wallet.html`
- Modify: `tests/test_mode3_wallet_agent.mjs`
- Modify: `tests/test_mode3_demo_stack.mjs`
- Modify: `docs/MODE3_DEMO.md`

**Interfaces:**
- Consumes: Task 6 의 `buildUserCredRequest`, `buildIssueRequest`, `buildCredentialProof`; Task 4 의 `/cia/user_cred`, `/cia/issue`
- Produces:
  - 상태 v6: `registration.userCred = { C_u_pt:{x,y}, Cf_u, blind_u, leaf, issuedAt } | null`; `sessions[r_s] = { arid, PPID, pk_trace, factoryAddress, allowAgent, C_s_pt, blind_s, credential, sessionPrivKey, pk_i, issuedAt }`.
  - `POST /wallet/attrs {attrs}` → `200 {Cf_u, leaf, sessionsDropped}`; 409 `not_registered`; 403 `account_disabled`.
  - `/wallet/status` 에 `userCred: {Cf_u, issuedAt, revoked}|null`.
  - 로그인 응답의 `issued:true` 는 그대로; `timings` 에 `userCredMs` 추가.

- [ ] **Step 1: 에이전트 테스트 갱신** — `tests/test_mode3_wallet_agent.mjs`
  - 첫 로그인 케이스 뒤에 status 로 `userCred` 가 생겼는지: `assert.ok(s.body.userCred?.Cf_u); assert.equal(s.body.userCred.revoked, false);`
  - 두 번째 로그인(새 r_s)의 `timings.userCredMs` 가 0 인지(재사용).
  - 폐기 케이스: "계정 폐기 + 게시 → skipSync 재검증은 옛 π → stale_root" 그대로. "동기화 재검증 → 403 revoked" 에서 **두 세션**(S1, S2 로그인해 둔 것)이 모두 403 이 되는지 단정 추가. `/wallet/status` 의 `userCred.revoked` 가 true.
  - 복구 케이스("set_disabled false → 로그인: 재발급, PPID 동일"): 로그인 응답 `timings.userCredMs > 0` 이고 status 의 `userCred.Cf_u` 가 바뀌었는지, PPID 는 같은지.
  - 새 케이스:

```js
await t('attrs: 속성을 바꾸면 새 사용자 자격증명, 기존 세션은 지워지고, 옛 리프는 다음 게시에 나간다', async () => {
  const S9 = newRs(); assert.equal((await login(S9)).status, 200);
  const before = (await wallet.get('/wallet/status')).body.userCred.Cf_u;
  const r = await wallet.post('/wallet/attrs', { attrs: ['20', '410', '0', '0'] });
  assert.equal(r.status, 200, j(r.body)); assert.notEqual(r.body.Cf_u, before); assert.ok(r.body.sessionsDropped >= 1);
  assert.equal((await wallet.get('/wallet/status')).body.sessions[S9], undefined);
  assert.equal((await cia.adminPost('/cia/publish')).body.published, true, '옛 리프가 pending 에 있었다');
  const S10 = newRs(); const l = await login(S10); assert.equal(l.status, 200); assert.equal(l.body.timings.userCredMs, 0);
});
```

  - `/wallet/tx` 케이스는 그대로(캐시 π 재사용). "계정 폐기 + 게시 뒤 tx 403 revoked" 그대로.

- [ ] **Step 2: 실패 확인** — `node tests/test_mode3_wallet_agent.mjs` → 로그인부터 FAIL(CIA 가 V5 본문을 요구).

- [ ] **Step 3: 에이전트 구현** — `mode3_wallet_agent.js`
  - 상태 주석·버전: `WALLET_STATE_VERSION = 6`; 주석을 v6 형식으로. 이행 로직은 그대로(세션 비움, 등록 유지). `state.registration.userCred ??= null`.
  - import: `buildIssueRequest, buildCredentialProof` 유지, `buildUserCredRequest` 추가; `credLeaf` → `userLeaf`.
  - `issueCredential` 을 둘로:

```js
/** 사용자 자격증명 확보(설계 2026-09-21 §6.2 3단계). 없거나 폐기됐으면 새로 받는다. 돌려주는 값은 { status, body, fresh }. */
async function ensureUserCred(tree) {
  const reg = state.registration;
  if (reg.userCred && !tree.has(BigInt(reg.userCred.leaf))) return { status: 200, fresh: false };
  const req = await buildUserCredRequest({ uid: BigInt(reg.uid), s_u: BigInt(reg.s_u), r_u: BigInt(reg.r_u), sk_u: reg.sk_u, attrs: (reg.attrs ?? []).map(BigInt) });
  const r = await ciaPost('/cia/user_cred', req.body);
  if (r.status === 201 || r.status === 200) {
    reg.userCred = { C_u_pt: { x: req.C_u_pt.x.toString(), y: req.C_u_pt.y.toString() }, Cf_u: req.Cf_u.toString(), blind_u: req.secrets.blind_u.toString(), leaf: req.leaf.toString(), issuedAt: new Date().toISOString() };
    // 옛 자격증명의 세션은 다음 게시에 죽는다 — 지금 지운다
    state.sessions = {}; cache.clear?.();
    persist();
    return { status: 200, body: r.body, fresh: true };
  }
  return { status: r.status, body: r.body, fresh: false };
}

async function issueSession(arid, r_s, pk_trace, allowAgent, factoryAddress, head) {
  const reg = state.registration;
  const session = createSessionKey();
  const chainid = await chainId();
  const req = await buildIssueRequest({
    uid: BigInt(reg.uid), Cf_u: BigInt(reg.userCred.Cf_u), arid: BigInt(arid), sk_u: reg.sk_u, session, chainid, allowAgent: BigInt(allowAgent),
    max_height: chooseMaxHeight(head, { ttlBlocks: TTL_BLOCKS, grid: HEIGHT_GRID }),
  });
  const r = await ciaPost('/cia/issue', req.body);
  if (r.status === 200) {
    const PPID = await ppid({ uid: BigInt(reg.uid), arid: BigInt(arid), s_u: BigInt(reg.s_u), chainid });
    state.sessions[r_s.toString()] = {
      arid, PPID: PPID.toString(), pk_trace: { x: pk_trace.x.toString(), y: pk_trace.y.toString() }, factoryAddress, allowAgent,
      C_s_pt: { x: req.C_s_pt.x.toString(), y: req.C_s_pt.y.toString() }, blind_s: req.secrets.blind_s.toString(),
      credential: r.body, sessionPrivKey: session.wallet.privateKey, pk_i: session.pk_i.toString(), issuedAt: new Date().toISOString(),
    };
    persist();
  }
  return r;
}
```

  (`ProofCache` 에 `clear()` 가 없으면 `lib/mode3_wallet.js` 에 `clear() { this.#m.clear(); }` 를 추가한다.)

  - `/wallet/login`: `timings = { syncMs:0, userCredMs:0, issueMs:0, proveMs:0 }`. 동기화·`pruneSessions` 뒤:

```js
    t = Date.now();
    const uc = await ensureUserCred(synced.tree);
    timings.userCredMs = uc.fresh ? Date.now() - t : 0;
    if (uc.status === 403) return res.status(403).json({ reason: 'account_disabled', timings });
    if (uc.status !== 200) return res.status(502).json({ reason: 'user_cred_failed', cia: uc.body, timings });
    t = Date.now();
    const r = await issueSession(arid, rs, { x: BigInt(pk_trace.x), y: BigInt(pk_trace.y) }, allowAgent, factoryAddress ? ethers.getAddress(factoryAddress) : null, synced.head);
    timings.issueMs = Date.now() - t;
    if (r.status === 403) return res.status(403).json({ reason: r.body?.reason === 'no_user_cred' ? 'user_cred_retired' : 'account_disabled', timings });
```

  - `proveSession`: 폐기 확인을 `if (synced.tree.has(BigInt(reg.userCred?.leaf ?? 0n))) throw Object.assign(new Error('revoked'), { reason: 'revoked' });` 로, `buildCredentialProof` 호출에 `blind_u: BigInt(reg.userCred.blind_u), blind_s: BigInt(s.blind_s)` (V4 `blind` 제거). `revoked` 로 throw 될 때 호출자는 `state.sessions` 전체가 아니라 그 세션만 지우던 것을 유지하되, `reg.userCred` 는 그대로 둔다(다음 로그인의 `ensureUserCred` 가 `tree.has` 로 알아채 새로 받는다).
  - `/wallet/status`: `userCred: state.registration?.userCred ? { Cf_u: ..., issuedAt: ..., revoked: lastSyncTree?.has(...) ?? null } : null`. 트리를 status 에서 다시 동기화하지 않기 위해 마지막 동기화의 `tree` 를 `lastSync.tree` 에 함께 보관하고 `revoked` 는 그 트리로 판정(없으면 null).
  - `/wallet/attrs`:

```js
// §6.3(2026-09-21) 속성 변경: 새 사용자 자격증명을 받는다. AA 가 옛 리프를 pending 에 넣으므로 옛 세션은 다음 게시에 죽는다 — 지금 지운다.
app.post('/wallet/attrs', async (req, res) => {
  try {
    if (!state.registration) return res.status(409).json({ reason: 'not_registered' });
    let attrs;
    try { attrs = normalizeAttrs(req.body?.attrs).map(String); } catch (e) { return res.status(400).json({ error: `attrs: ${e.message}` }); }
    if (!LOG_ADDRESS) return res.status(503).json({ reason: 'chain_unavailable' });
    let synced;
    try { synced = await syncRevocationTree(provider, LOG_ADDRESS); } catch (e) { return res.status(503).json({ reason: 'chain_unavailable', detail: e.message }); }
    const dropped = Object.keys(state.sessions).length;
    state.registration.attrs = attrs;
    state.registration.userCred = null;   // 강제 재발급
    const uc = await ensureUserCred(synced.tree);
    if (uc.status === 403) return res.status(403).json({ reason: 'account_disabled' });
    if (uc.status !== 200) return res.status(502).json({ reason: 'user_cred_failed', cia: uc.body });
    res.json({ Cf_u: state.registration.userCred.Cf_u, leaf: state.registration.userCred.leaf, sessionsDropped: dropped });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
```

- [ ] **Step 4: 데모 페이지** — `mode3/wallet.html`: 등록 폼의 attr 입력란 옆에 `속성 변경` 버튼(`attrsBtn`) 추가 → `POST /wallet/attrs` 로 현재 입력값 전송, 결과를 `registerResult` 에 표시. status 표시에 `userCred: 있음(Cf_u 앞 8자리)/없음/폐기됨` 한 줄 추가.

- [ ] **Step 5: 데모 스택 테스트** — `tests/test_mode3_demo_stack.mjs`: 로그인 트랜스크립트를 직접 만드는 곳(`buildIssueRequest`)이 있으면 Task 6 의 V5 방식(`buildUserCredRequest` + `/cia/user_cred` → `buildIssueRequest(Cf_u)`)으로. 시나리오 5·6(폐기 뒤 재검증 revoked → tx) 은 그대로.

- [ ] **Step 6: 문서** — `docs/MODE3_DEMO.md`: (1) env 목록에서 `CIA_REVOKE_SKEW_BLOCKS` 제거, (2) "폐기" 절에 "계정 폐기 = 사용자 자격증명 리프 하나, 그 사용자의 모든 세션이 다음 게시에 무효" 문장, (3) 지갑 페이지의 속성 변경 버튼 설명, (4) 회로 재빌드·팩토리 재배포·RevocationLog 재배포(리프 태그 4) 운영 주의, (5) `/cia/user_cred` 엔드포인트 한 줄.

- [ ] **Step 7: 통과 확인**

Run: `node tests/test_mode3_wallet_agent.mjs && node tests/test_mode3_demo_stack.mjs`
Expected: 전부 ok.

- [ ] **Step 8: 커밋**

```bash
git add mode3_wallet_agent.js mode3/wallet.html lib/mode3_wallet.js tests/test_mode3_wallet_agent.mjs tests/test_mode3_demo_stack.mjs docs/MODE3_DEMO.md
git commit -m "feat(mode3): 자격증명 이중 구조 7/8 — 지갑 상태 v6, 사용자 자격증명 확보, /wallet/attrs, 데모 페이지·문서"
```

---

### Task 8: V4 제거, 컨트랙트 테스트, 전 그룹 실행, 벤치·실측 기록

**Files:**
- Modify: `lib/mode3_credential.js` (V4 `credCommit`, `credMessage`, `DOMAIN_MODE3_CRED_V4` 삭제 — `DOMAIN_MODE3_CRED`·`_V2`·`_V3` 는 옛 테스트가 참조하면 함께 정리)
- Modify: `lib/mode3_issuance.js` (`proveIssuance`, `verifyIssuance`, `issueRequestMessage`, `serializeProof`, `parseProof`, `DOMAIN_MODE3_ISSUE`, `DOMAIN_MODE3_ISSUEREQ_V2/V3` 삭제)
- Modify: `lib/mode3_revocation.js` (`credLeaf`, `TAG_MODE3_CRED` 삭제)
- Modify: `circuits/lib/mode3_commit.circom` (`CommitPedersen`, `CommitPoseidon` 삭제)
- Modify: `tests/test_mode3_issuance.js`, `tests/test_mode3_commit_scheme.mjs`, `tests/test_mode3_revocation_tree.js`, `tests/test_mode3_credential_v5.js` (V4 대조 케이스 제거)
- Modify: `test/Mode3Wallet.test.mjs` (픽스처 반환값 `C` → `Cf_u` 를 쓰는 곳)
- Modify: `scripts/bench_zkp_inventory.mjs`, `scripts/bench_pi_cred.mjs`(픽스처만 쓰므로 무변경 확인), `results/zkp_inventory_20260918.md`(새 파일 `results/zkp_inventory_20260921.md` 로)
- Modify: 스펙 `docs/superpowers/specs/2026-09-21-mode3-two-tier-credential-design.md` §8 실측

**Interfaces:**
- Consumes: Task 1~7 전부.
- Produces: V4 심볼 없음. `grep -rn "credCommit\|credLeaf\|credMessage(\|proveIssuance\|DOMAIN_MODE3_CRED_V4\|TAG_MODE3_CRED\b" --include=*.js --include=*.mjs --include=*.circom . | grep -v node_modules | grep -v ^./build` 가 비어야 한다.

- [ ] **Step 1: V4 심볼 제거와 테스트 정리**
  - 위 grep 으로 남은 참조를 찾아 각 파일에서 제거·치환한다. `tests/test_mode3_issuance.js` 의 V4 `proveIssuance` 케이스(양성·Sybil·재생·변조·직렬화·`issueRequestMessage`·`credMessage`)는 지우고 V5 케이스만 남긴다(`freshUser` 는 유지). `tests/test_mode3_commit_scheme.mjs` 의 `CommitPedersen`·`CommitPoseidon` 케이스는 지우고 `CommitUser`·`CommitSession` 케이스와 "생성원 9개 부분군" 케이스를 남긴다. `tests/test_mode3_revocation_tree.js` 는 `credLeaf` → `userLeaf`, `TAG_MODE3_CRED` → `TAG_MODE3_USER`(=4 확인). `tests/test_mode3_credential_v5.js` 의 "V4 credCommit 과 점이 같다" 케이스 삭제.
  - `lib/mode3_credential.js` 상단 주석의 "DOMAIN_MODE3_CRED 계열" 이력 한 줄에 "V5(2026-09-21) 부터 커밋 둘" 을 적고 옛 상수는 지운다. `credCommitPoseidon` 도 참조가 없으면 지운다.

- [ ] **Step 2: unit + circuit**

Run: `npm test`
Expected: 통과 N/N, 실패 0.

- [ ] **Step 3: 컨트랙트 테스트**
  - `test/Mode3Wallet.test.mjs` 에서 픽스처의 `fx.C` 를 쓰는 곳(있다면 폐기 케이스의 `credLeaf(fx.C)`)을 `userLeaf(fx.Cf_u)` 로. `statement()`·`deployStack()` 은 그대로.

Run: `bash scripts/run_tests.sh contract`
Expected: passing(수는 기존 74 이상), `execute() gas:` 로그 값을 적어 둔다.

- [ ] **Step 4: chain 그룹 (Mode 3 파일)** — :8545 확인 후

Run:
```bash
for f in tests/test_cia_register_issue.mjs tests/test_cia_startup.mjs tests/test_cia_issue_race.mjs tests/test_cia_opening.mjs tests/test_mode3_wallet.mjs tests/test_mode3_rp.mjs tests/test_mode3_e2e.mjs tests/test_mode3_wallet_agent.mjs tests/test_mode3_demo_stack.mjs; do node $f || echo "FAIL $f"; done
```
Expected: `FAIL` 출력 없음.

- [ ] **Step 5: 벤치 갱신**
  - `scripts/bench_zkp_inventory.mjs`: π_issue 행을 `π_u (Σ, Mode 3 사용자 자격증명)` 로 바꾸고 `proveUserCred`/`verifyUserCred` 로 측정. pi_cred 행은 픽스처만 쓰므로 그대로. 실행해 `results/zkp_inventory_20260921.md` 를 새로 쓴다(2026-09-18 파일은 남긴다; 표 1 의 π_issue 행을 π_u 로, "세션 발급에 ZKP 없음" 한 줄).
  - `scripts/bench_mode3_onchain.mjs`: 로그인 timings 에 `userCredMs` 열 추가(첫 로그인만 > 0 이 정상). 실행해 `results/mode3_onchain_bench_20260921.md` 저장.
  - `npx snarkjs r1cs info build/mode3/pi_cred.r1cs` 의 제약·와이어·입력 수, zkey 크기.

- [ ] **Step 6: 스펙 §8 실측 기록** — 예상 표를 실측으로 교체(제약 수, prove/verify, 세션 발급 ms, 사용자 자격증명 발급 ms, 로그인 왕복, execute gas, 계정 폐기 게시 gas). §1 표의 "≈ 27k(추정)" 도 실측으로.

- [ ] **Step 7: 커밋**

```bash
git add -A lib tests test scripts/bench_zkp_inventory.mjs scripts/bench_mode3_onchain.mjs circuits/lib/mode3_commit.circom results/zkp_inventory_20260921.md results/mode3_onchain_bench_20260921.md docs/superpowers/specs/2026-09-21-mode3-two-tier-credential-design.md
git commit -m "refactor(mode3): 자격증명 이중 구조 8/8 — V4 심볼 제거, 전 그룹 통과, 실측 기록"
```

(`git add -A lib tests test` 는 그 디렉터리 안의 변경만 스테이징한다. `sui-repo/`·`build/` 는 포함되지 않는다. 스테이징 뒤 `git status` 로 의도치 않은 파일이 없는지 본다.)

---

## 계획 자체 점검

**스펙 커버리지**
- §3.1~3.3 커밋·서명 → Task 1·3. §3.4 요청 서명 → Task 2·6. §3.5 π_u → Task 2. §3.6 리프 → Task 1·3.
- §4.1 `/cia/user_cred` → Task 4. §4.2 `/cia/issue` V5·기록 없음·skew 제거 → Task 4. §4.3 폐기 → Task 5. §4.4 상태 v6 → Task 4. §4.5·4.6 변경 없음 → Task 6 opening 테스트로 확인.
- §5 회로(r≠0 포함) → Task 3. §6.1 상태 v6 → Task 7. §6.2 로그인 3~5단계 → Task 7. §6.3 `/wallet/attrs` → Task 7. §6.4 status → Task 7.
- §7 서비스·컨트랙트 무변경 → Task 6(rp 테스트)·Task 8(contract). §8 실측 → Task 8. §10 순서 → Task 1~8. §11 논문·형식 문서·슬라이드는 이 계획 밖(구현 뒤 별도).

**타입 일관성**
- `credential` 객체: CIA 응답 `{Cf_u, Cf_s, max_height, chainid, allowAgent, sigma, pk_CIA}` (Task 4) = 지갑 `buildCredentialProof` 의 `credential` (Task 6) = 에이전트 `sessions[r_s].credential` (Task 7) = 테스트 `localIssue` 반환값 (Task 6; `pk_CIA` 는 테스트에서 별도 인자).
- `userCred` 저장 형식 `{C_u_pt, Cf_u, blind_u, leaf, issuedAt}` (Task 7) 은 `buildUserCredRequest` 반환값 (Task 6) 에서 그대로 만든다.
- 리프 함수 이름 `userLeaf`, 태그 `TAG_MODE3_USER = 4n` — Task 1·3·4·6·7·8 동일.
- 서명 헬퍼 이름: `signUserCredRequest`, `signIssueRequest`(V4 `signUserRequest` 삭제). 기존 세션 요청 서명 `signSessionRequest`(r_s‖body) 는 별개이며 그대로.
- CIA 403 구분: `reason: 'no_user_cred'`(자격증명 없음/물림) vs `reason: 'account_disabled'` — Task 4 응답, Task 7 에이전트 매핑.
