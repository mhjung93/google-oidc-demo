# Mode 3 오프체인 전 구간 구현 계획 — 단계 (a)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 단계 (c)의 `pi_cred` 회로 위에 CIA·폐기 체인·지갑·RP를 올려, 등록 → 발급 → 로그인 → 폐기 → 거절 → 복구가 격리 환경에서 끝까지 도는 것을 테스트로 고정한다.

**Architecture:** 다섯 단위가 각각 하나의 책임을 갖는다 — 발급 PoK(시그마 프로토콜, 순수 JS), 폐기 체인 컨트랙트(`RevocationLog`, root + 리프 calldata), CIA 서버(`cia.js`, 등록·발급·폐기·게시), 지갑 라이브러리(`lib/mode3_wallet.js`, 트리 동기화·증명 생성), RP 검증기(`lib/mode3_rp.js`, §6.3의 7단계). 서버 프로세스는 CIA 하나뿐이고 지갑·RP는 라이브러리라 e2e 테스트가 한 프로세스에서 조립한다. 온체인 검증 경로는 없다(설계 §9.11).

**Tech Stack:** Node.js ESM, express 5, ethers 6, circomlibjs(baby jubjub·Poseidon·EdDSA-Poseidon), snarkjs(Groth16 오프체인 검증), hardhat 2.28 + solidity 0.8.24(폐기 체인 컨트랙트만), 단계 (c) 산출물 `build/mode3/pi_cred_final.zkey`·`pi_cred_vkey.json`·`pi_cred_js/pi_cred.wasm`

**설계 문서:** `docs/superpowers/specs/2026-09-09-mode3-cia-revocation-design.md` (2026-09-10 개정판, HEAD 9af558d 이후)

## Global Constraints

- **Mode 2를 건드리지 않는다.** `custom_idp.js`, `wallet_agent.js`, `server.js`, `client.js`, `lib/imt_v3.js`, `lib/idp_revocation_v3.js`, `lib/wallet_revocation_v3.js`, `contracts/PPIDWallet*.sol`, `contracts/RevocationRegistry*.sol`, `idp_state.json`, `idp_keys.json`은 읽기 전용이다.
- **실행 중인 데모(:3000/:4000/:5001)를 절대 건드리지 않는다.** CIA는 **:4100**(`CIA_PORT`)에 뜬다. 격리 테스트는 임시 포트·임시 디렉터리를 쓴다.
- **:8545 hardhat 노드는 사용자 프로세스다.** `chain` 그룹 테스트는 거기 컨트랙트를 새로 배포해 쓴다. 테스트가 `hardhat_mine`으로 블록을 진행시킬 수 있다(기존 `chain` 그룹과 같은 성질).
- **커밋 스킴은 교과서 Pedersen**(§4.1): `C_pt = uid·G₁ + arid·G₂ + s_u·G₃ + pk_i·G₄ + blind·H`, `C = Poseidon(C_pt.x, C_pt.y)`. 생성원은 `lib/mode3_credential.js`의 `PEDERSEN_GENERATORS`. **모든 커밋 스칼라 < 2^250**, 무작위 비밀은 `randomScalar()`로만 뽑는다.
- **서명 메시지** `Poseidon(DOMAIN_MODE3_CRED, C, max_height)`, **폐기 리프** `mask₂₅₂(Poseidon(3, C))` = `credLeaf(C)`. 이 둘은 `lib/mode3_credential.js`·`lib/mode3_revocation.js`에 이미 있고 회로와 일치가 테스트로 고정돼 있다. **다시 구현하지 말고 import한다.**
- **공개 입력 순서** `[PPID, arid, pk_i, max_height, revRoot, pk_CIA_x, pk_CIA_y]` (`publicSignals[0..6]`).
- **RP 검증 7단계**(§6.3): a. 헤드 신선도(10분) → b. root 일치 → c. `head ≤ max_height` → d. `pk_CIA` 고정 대조 → e. Groth16 → f. 챌린지 서명 → g. PPID. **d를 빠뜨리면 공격자가 자기 키로 서명한 credential이 통과한다** — 음성 테스트로 고정한다.
- **CIA는 `C`를 받지 않는다** — `π_issue`의 공개 입력 `C_pt`에서 스스로 계산한다(§6.2).
- **세션 서명은 secp256k1 ECDSA(EIP-191 personal sign)**, `pk_i` = 세션키의 이더리움 주소(160비트). 설계 §11이 재검토 대상으로 표시했지만, 회로가 160비트를 요구하고 ethers가 그대로 제공하므로 (a)에서는 이것을 쓴다. Schnorr로 바꾸려면 `lib/mode3_rp.js` f단계와 `lib/mode3_wallet.js` `signChallenge`만 바뀐다.
- **CIA는 키가 둘이다** — credential 서명용 EdDSA-Poseidon 키(baby jubjub)와 root 게시용 secp256k1 키(컨트랙트가 `ecrecover`로 검증). 둘 다 `cia_keys.json`(0600)에 저장한다.
- **root 서명은 리프 배열까지 덮는다** — `keccak(DOMAIN, root, epoch, keccak(leaves))`. 설계 §6.5는 `(root, epoch)`만 적었는데, 제출이 무허가라 릴레이어가 서명된 root에 엉뚱한 리프를 붙여 calldata를 오염시킬 수 있다(지갑이 잘못된 트리를 재구성해 root 불일치 → 전원 차단). 이 계획이 §6.5를 그렇게 보강한다.
- 상태 파일은 `cia_state.json`, 키 파일은 `cia_keys.json` — `.gitignore`에 추가한다. 쓰기는 임시 파일 + rename(원자적).
- 새 테스트는 `scripts/run_tests.sh`의 그룹에 등록한다: 외부 의존 없음 → `UNIT`, :8545 필요 → `CHAIN`, hardhat 인프로세스 → `contract`(`test/*.test.mjs`는 자동).
- 코드 주석은 한글. 커밋 메시지 한글 `feat(mode3): …`, 트레일러 2줄.
- **`.env`를 읽거나 수정하지 않는다.** 배포 주소는 스크립트가 출력만 하고 사람이 옮긴다.

## 이 계획이 다루지 않는 것

- 데모 UI(`client.js`, Snap) 연동 — 지갑은 라이브러리로 끝낸다.
- §9.12 계정 폐기 묶음 노출의 결정(감수/패딩/분산) — 사용자 결정. 이 계획은 "감수" 상태로 구현한다.
- 세션 서명을 Schnorr로 바꾸는 것.
- Poseidon 커밋 전환(설계 §12 "보류").

## File Structure

| 파일 | 책임 |
|---|---|
| `lib/mode3_credential.js` (수정) | `compressPoint({x,y}) → C` 추가 (CIA·검증기가 `C_pt`에서 `C`를 유도할 때) |
| `lib/mode3_issuance.js` (신규) | 발급 PoK 시그마 프로토콜 — `registrationCommit`, `proveIssuance`, `verifyIssuance`, `randomZr` |
| `contracts/RevocationLog.sol` (신규) | 폐기 체인 컨트랙트 — `publishRoot` (CIA 서명 검증, epoch 단조, 리프 이벤트) |
| `scripts/deploy_mode3_log.cjs` (신규) | `RevocationLog` 배포 (`--network localhost` 강제) |
| `tests/helpers/mode3_chain.mjs` (신규) | :8545 provider, 컨트랙트 배포, 자금 전송, 블록 진행 |
| `lib/mode3_state.js` (신규) | JSON 상태 파일 원자적 읽기/쓰기 |
| `cia.js` (신규) | CIA 서버 — 등록·발급·폐기·게시·상태 |
| `tests/helpers/isolated_cia.mjs` (신규) | 격리 CIA 기동(임시 포트·디렉터리·키·로그 컨트랙트) |
| `lib/mode3_wallet.js` (신규) | 지갑 측 — 등록값·세션키·발급 요청·트리 동기화·증명 생성·챌린지 서명 |
| `lib/mode3_rp.js` (신규) | RP 검증기 — §6.3 7단계 |
| `tests/test_mode3_issuance.js` (신규, UNIT) | 시그마 프로토콜 양성·음성 |
| `test/RevocationLog.test.mjs` (신규, contract) | 컨트랙트 |
| `tests/test_cia_register_issue.mjs` (신규, CHAIN) | CIA 엔드포인트 |
| `tests/test_mode3_wallet.mjs` (신규, CHAIN) | 트리 동기화·증명 생성·캐시 |
| `tests/test_mode3_rp.mjs` (신규, CHAIN) | RP 7단계 + 음성 6건 |
| `tests/test_mode3_e2e.mjs` (신규, CHAIN) | 전 구간 |
| `scripts/run_tests.sh` (수정) | 그룹 등록 |
| `.gitignore` (수정) | `cia_state.json`, `cia_keys.json` |
| 설계 문서 §6.5, §12 (수정) | root 서명 범위 보강, (a) 진행 표시 |

---

### Task 1: 발급 PoK — 시그마 프로토콜

**Files:**
- Modify: `lib/mode3_credential.js` (`compressPoint` 추가)
- Create: `lib/mode3_issuance.js`
- Create: `tests/test_mode3_issuance.js`
- Modify: `scripts/run_tests.sh` (`UNIT`)

**Interfaces:**
- Consumes: `PEDERSEN_GENERATORS`, `SCALAR_MAX`, `randomScalar` from `lib/mode3_credential.js`; circomlibjs `buildBabyjub` (`mulPointEscalar`, `addPoint`, `inCurve`, `inSubgroup`, `subOrder`, `F.neg`), `buildPoseidon`
- Produces:
  - `compressPoint({x, y}: {bigint, bigint}) → Promise<bigint>` = `Poseidon(x, y)` (`lib/mode3_credential.js`)
  - `DOMAIN_MODE3_ISSUE = 365084431357343731766597n` (ASCII `"MODE3ISSUE"` 빅엔디언)
  - `randomZr() → Promise<bigint>` — `Z_r` 균일 (512비트 mod r)
  - `registrationCommit(s_u, r_u) → Promise<{x, y}>` = `s_u·G₃ + r_u·H`
  - `proveIssuance({ uid, arid, s_u, blind, pk_i, r_u }) → Promise<{ C_pt, cm_u, proof }>` — `proof = { T1, T2, c, z_arid, z_su, z_pki, z_blind, z_ru }` (점은 `{x,y}` bigint, 스칼라는 bigint)
  - `verifyIssuance({ uid, C_pt, cm_u, proof }) → Promise<boolean>`
  - 직렬화: 점·스칼라를 **10진 문자열**로 주고받는 `serializeProof(proof)` / `parseProof(obj)`, `pointToStrings`, `pointFromStrings`

**프로토콜 (설계 §6.2).** 공개 `(uid, C_pt, cm_u)`, witness `(arid, s_u, blind, pk_i, r_u)`:

```
Y₁ = C_pt − uid·G₁                    (CIA 가 uid 를 아니까 뺀다)
증명할 것:  Y₁  = arid·G₂ + s_u·G₃ + pk_i·G₄ + blind·H
           cm_u = s_u·G₃ + r_u·H            (두 식의 s_u 가 같다)

Prover:  a_arid, a_su, a_pki, a_blind, a_ru ← Z_r
         T₁ = a_arid·G₂ + a_su·G₃ + a_pki·G₄ + a_blind·H
         T₂ = a_su·G₃ + a_ru·H
         c  = Poseidon(DOMAIN_MODE3_ISSUE, uid, C_pt.x, C_pt.y, cm_u.x, cm_u.y, T₁.x, T₁.y, T₂.x, T₂.y) 의 하위 250비트
         z_x = a_x + c·x  (mod r)   for x ∈ {arid, s_u, pk_i, blind, r_u}
Verifier: 모든 점이 곡선 위·부분군 안인지 확인
         c 재계산이 같은지
         z_arid·G₂ + z_su·G₃ + z_pki·G₄ + z_blind·H == T₁ + c·Y₁
         z_su·G₃ + z_ru·H                          == T₂ + c·cm_u
```

`c`를 250비트로 자르는 이유: Poseidon 출력은 `Z_p`(≈2²⁵⁴)에 균일한데 `mod r`로 줄이면 편향이 생긴다(`p/r ≈ 8.7`). 하위 250비트를 취하면 `[0, 2²⁵⁰) ⊂ Z_r`에서 균일하고 건전성 오차 2⁻²⁵⁰이다.

- [ ] **Step 1: 실패하는 테스트를 쓴다**

`tests/test_mode3_issuance.js`:

```js
// 발급 PoK 시그마 프로토콜 (설계 §6.2). 외부 의존 없음.
//   node tests/test_mode3_issuance.js
import assert from 'node:assert/strict';
import { buildBabyjub } from 'circomlibjs';
import { randomScalar, credCommit, PEDERSEN_GENERATORS, compressPoint } from '../lib/mode3_credential.js';
import {
  DOMAIN_MODE3_ISSUE, randomZr, registrationCommit, proveIssuance, verifyIssuance,
  serializeProof, parseProof, pointToStrings, pointFromStrings,
} from '../lib/mode3_issuance.js';

let failed = 0;
async function t(name, fn) {
  try { await fn(); console.log(`ok   ${name}`); }
  catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.message}`); }
}

const uid = 12345n;
const arid = 22222222222222222222n;
const pk_i = 0x1234567890123456789012345678901234567890n;

async function freshUser() {
  const s_u = randomScalar();
  const r_u = randomScalar();
  const blind = randomScalar();
  const cm_u = await registrationCommit(s_u, r_u);
  return { s_u, r_u, blind, cm_u };
}

await t('도메인 태그는 "MODE3ISSUE" 빅엔디언이다', () => {
  assert.equal(DOMAIN_MODE3_ISSUE, BigInt('0x' + Buffer.from('MODE3ISSUE').toString('hex')));
});

await t('randomZr 는 [0, r) 안이다', async () => {
  const bj = await buildBabyjub();
  for (let i = 0; i < 20; i++) {
    const z = await randomZr();
    assert.ok(z >= 0n && z < bj.subOrder);
  }
});

await t('양성: 올바른 witness 의 증명이 검증된다', async () => {
  const u = await freshUser();
  const { C_pt, cm_u, proof } = await proveIssuance({ uid, arid, s_u: u.s_u, blind: u.blind, pk_i, r_u: u.r_u });
  assert.equal(cm_u.x, u.cm_u.x); assert.equal(cm_u.y, u.cm_u.y);
  assert.equal(await verifyIssuance({ uid, C_pt, cm_u, proof }), true);
});

await t('C_pt 는 credCommit 과 같은 점이다 (회로가 여는 그 커밋)', async () => {
  const u = await freshUser();
  const { C_pt } = await proveIssuance({ uid, arid, s_u: u.s_u, blind: u.blind, pk_i, r_u: u.r_u });
  const { Cx, Cy, Cf } = await credCommit({ uid, arid, s_u: u.s_u, blind: u.blind, pk_i });
  assert.equal(C_pt.x, Cx); assert.equal(C_pt.y, Cy);
  assert.equal(await compressPoint(C_pt), Cf, 'CIA 가 C_pt 에서 유도하는 C 가 credCommit 의 Cf 와 같아야 한다');
});

await t('음성: 등록된 cm_u 와 다른 s_u 로 만든 C_pt 는 거절된다 (Sybil)', async () => {
  const u = await freshUser();
  const other_su = randomScalar();
  // 공격자: C_pt 는 other_su 로, cm_u 는 등록된 것(u.s_u)을 제시
  const forged = await proveIssuance({ uid, arid, s_u: other_su, blind: u.blind, pk_i, r_u: u.r_u });
  assert.equal(await verifyIssuance({ uid, C_pt: forged.C_pt, cm_u: u.cm_u, proof: forged.proof }), false);
});

await t('음성: 다른 uid 로 재생하면 거절된다 (Fiat-Shamir 가 uid 를 덮는다)', async () => {
  const u = await freshUser();
  const { C_pt, cm_u, proof } = await proveIssuance({ uid, arid, s_u: u.s_u, blind: u.blind, pk_i, r_u: u.r_u });
  assert.equal(await verifyIssuance({ uid: uid + 1n, C_pt, cm_u, proof }), false);
});

await t('음성: 응답 하나를 바꾸면 거절된다', async () => {
  const u = await freshUser();
  const { C_pt, cm_u, proof } = await proveIssuance({ uid, arid, s_u: u.s_u, blind: u.blind, pk_i, r_u: u.r_u });
  const bad = { ...proof, z_arid: (proof.z_arid + 1n) };
  assert.equal(await verifyIssuance({ uid, C_pt, cm_u, proof: bad }), false);
});

await t('음성: 곡선 밖의 점은 거절된다', async () => {
  const u = await freshUser();
  const { C_pt, cm_u, proof } = await proveIssuance({ uid, arid, s_u: u.s_u, blind: u.blind, pk_i, r_u: u.r_u });
  assert.equal(await verifyIssuance({ uid, C_pt: { x: 1n, y: 1n }, cm_u, proof }), false);
});

await t('직렬화 왕복이 값을 보존한다', async () => {
  const u = await freshUser();
  const { C_pt, cm_u, proof } = await proveIssuance({ uid, arid, s_u: u.s_u, blind: u.blind, pk_i, r_u: u.r_u });
  const wire = JSON.parse(JSON.stringify({ C_pt: pointToStrings(C_pt), cm_u: pointToStrings(cm_u), proof: serializeProof(proof) }));
  assert.equal(await verifyIssuance({ uid, C_pt: pointFromStrings(wire.C_pt), cm_u: pointFromStrings(wire.cm_u), proof: parseProof(wire.proof) }), true);
});

process.exit(failed === 0 ? 0 : 1);
```

- [ ] **Step 2: 실패를 확인한다**

```bash
node tests/test_mode3_issuance.js
```

Expected: `lib/mode3_issuance.js` 를 찾지 못해 실패

- [ ] **Step 3: `compressPoint` 를 추가한다**

`lib/mode3_credential.js` 끝에:

```js
/**
 * C = Poseidon(C_pt.x, C_pt.y). CIA 와 검증기가 π_issue 의 공개 입력 C_pt 에서 C 를
 * **스스로** 유도할 때 쓴다(설계 §6.2 — 사용자가 보낸 C 를 서명하면 증명된 C_pt 와
 * 무관한 값에 서명이 붙는다). credCommit 이 돌려주는 Cf 와 같은 계산이다.
 */
export async function compressPoint({ x, y }) {
  const poseidon = await getPoseidon();
  return poseidon.F.toObject(poseidon([x, y]));
}
```

- [ ] **Step 4: 시그마 프로토콜을 쓴다**

`lib/mode3_issuance.js`:

```js
// 발급 PoK — 시그마 프로토콜. 설계 §6.2.
//
// CIA 는 uid 를 알고 arid·pk_i·blind 를 몰라야 한다. C_pt 에서 uid·G₁ 을 빼고
// 나머지 네 항의 표현(representation)을 아는지, 그리고 그 s_u 가 등록 때 낸 cm_u 의
// s_u 와 같은지를 한 증명으로 보인다. SNARK 가 아니라 회로·셋업이 없다 — 이것이
// 커밋을 Pedersen 으로 둔 이유다(§11).
//
// 시그마 프로토콜은 Z_r 상의 표현 지식만 증명하고 범위는 증명하지 않는다. 2^250 상한을
// 실제로 강제하는 것은 show 회로의 Num2Bits(250) 이다(§6.1) — 여기서 s_u < 2^250 을
// 검사하지 않으며, 검사할 방법도 없다.
import { randomBytes } from 'node:crypto';
import { buildBabyjub, buildPoseidon } from 'circomlibjs';
import { PEDERSEN_GENERATORS } from './mode3_credential.js';

export const DOMAIN_MODE3_ISSUE = 365084431357343731766597n;   // ASCII "MODE3ISSUE"

const MASK_250 = (1n << 250n) - 1n;

let bjP = null, psP = null;
const getBj = () => (bjP ??= buildBabyjub());
const getPs = () => (psP ??= buildPoseidon());

function G(bj, name) {
  const g = PEDERSEN_GENERATORS[name];
  return [bj.F.e(g[0]), bj.F.e(g[1])];
}
const toObj = (bj, P) => ({ x: bj.F.toObject(P[0]), y: bj.F.toObject(P[1]) });
const fromObj = (bj, o) => [bj.F.e(o.x), bj.F.e(o.y)];
const eqPt = (bj, A, B) => bj.F.eq(A[0], B[0]) && bj.F.eq(A[1], B[1]);
const negPt = (bj, P) => [bj.F.neg(P[0]), P[1]];

/** Z_r 균일. 512비트를 뽑아 mod r — 편향 2^-260. 256비트 mod r 은 편향이 2^-5 라 못 쓴다. */
export async function randomZr() {
  const bj = await getBj();
  return BigInt('0x' + randomBytes(64).toString('hex')) % bj.subOrder;
}

function msm(bj, terms) {
  // terms: [[scalar, point], ...] — 곱해서 전부 더한다
  let acc = null;
  for (const [e, P] of terms) {
    const Q = bj.mulPointEscalar(P, e);
    acc = acc === null ? Q : bj.addPoint(acc, Q);
  }
  return acc;
}

/** cm_u = s_u·G₃ + r_u·H. 등록 시 사용자가 만들어 CIA 에 낸다(§6.1). */
export async function registrationCommit(s_u, r_u) {
  const bj = await getBj();
  return toObj(bj, msm(bj, [[s_u, G(bj, 's_u')], [r_u, G(bj, 'blind')]]));
}

async function challenge(bj, uid, C_pt, cm_u, T1, T2) {
  const ps = await getPs();
  const h = ps.F.toObject(ps([
    DOMAIN_MODE3_ISSUE, uid,
    C_pt.x, C_pt.y, cm_u.x, cm_u.y, T1.x, T1.y, T2.x, T2.y,
  ]));
  return h & MASK_250;
}

export async function proveIssuance({ uid, arid, s_u, blind, pk_i, r_u }) {
  const bj = await getBj();
  const r = bj.subOrder;
  const [G1, G2, G3, G4, H] = ['uid', 'arid', 's_u', 'pk_i', 'blind'].map((n) => G(bj, n));

  const C_ptP = msm(bj, [[uid, G1], [arid, G2], [s_u, G3], [pk_i, G4], [blind, H]]);
  const cm_uP = msm(bj, [[s_u, G3], [r_u, H]]);
  const C_pt = toObj(bj, C_ptP);
  const cm_u = toObj(bj, cm_uP);

  const a = {};
  for (const k of ['arid', 'su', 'pki', 'blind', 'ru']) a[k] = await randomZr();
  const T1 = toObj(bj, msm(bj, [[a.arid, G2], [a.su, G3], [a.pki, G4], [a.blind, H]]));
  const T2 = toObj(bj, msm(bj, [[a.su, G3], [a.ru, H]]));

  const c = await challenge(bj, uid, C_pt, cm_u, T1, T2);
  const z = (ax, x) => (ax + c * x) % r;
  const proof = {
    T1, T2, c,
    z_arid: z(a.arid, arid), z_su: z(a.su, s_u), z_pki: z(a.pki, pk_i),
    z_blind: z(a.blind, blind), z_ru: z(a.ru, r_u),
  };
  return { C_pt, cm_u, proof };
}

function validPoint(bj, o) {
  if (typeof o?.x !== 'bigint' || typeof o?.y !== 'bigint') return false;
  const P = fromObj(bj, o);
  return bj.inCurve(P) && bj.inSubgroup(P);
}

export async function verifyIssuance({ uid, C_pt, cm_u, proof }) {
  const bj = await getBj();
  const r = bj.subOrder;
  const { T1, T2, c, z_arid, z_su, z_pki, z_blind, z_ru } = proof ?? {};
  // 1) 형식·군 검사. 부분군 밖의 점은 작은 위수 성분으로 등식을 만족시킬 수 있어 거절한다.
  for (const P of [C_pt, cm_u, T1, T2]) if (!validPoint(bj, P)) return false;
  for (const z of [c, z_arid, z_su, z_pki, z_blind, z_ru]) {
    if (typeof z !== 'bigint' || z < 0n || z >= r) return false;
  }
  if (typeof uid !== 'bigint' || uid < 0n) return false;
  // 2) 챌린지 재계산
  if ((await challenge(bj, uid, C_pt, cm_u, T1, T2)) !== c) return false;
  // 3) 두 등식
  const [G1, G2, G3, G4, H] = ['uid', 'arid', 's_u', 'pk_i', 'blind'].map((n) => G(bj, n));
  const Y1 = bj.addPoint(fromObj(bj, C_pt), negPt(bj, bj.mulPointEscalar(G1, uid)));
  const lhs1 = msm(bj, [[z_arid, G2], [z_su, G3], [z_pki, G4], [z_blind, H]]);
  const rhs1 = bj.addPoint(fromObj(bj, T1), bj.mulPointEscalar(Y1, c));
  if (!eqPt(bj, lhs1, rhs1)) return false;
  const lhs2 = msm(bj, [[z_su, G3], [z_ru, H]]);
  const rhs2 = bj.addPoint(fromObj(bj, T2), bj.mulPointEscalar(fromObj(bj, cm_u), c));
  return eqPt(bj, lhs2, rhs2);
}

// ---- 직렬화 (HTTP 는 bigint 를 못 실으니 10진 문자열) ----
export const pointToStrings = (p) => ({ x: p.x.toString(), y: p.y.toString() });
export const pointFromStrings = (o) => ({ x: BigInt(o.x), y: BigInt(o.y) });
export function serializeProof(p) {
  return {
    T1: pointToStrings(p.T1), T2: pointToStrings(p.T2), c: p.c.toString(),
    z_arid: p.z_arid.toString(), z_su: p.z_su.toString(), z_pki: p.z_pki.toString(),
    z_blind: p.z_blind.toString(), z_ru: p.z_ru.toString(),
  };
}
export function parseProof(o) {
  const B = (v) => { if (typeof v !== 'string' || !/^[0-9]+$/.test(v)) throw new Error('bad scalar'); return BigInt(v); };
  return {
    T1: pointFromStrings(o.T1), T2: pointFromStrings(o.T2), c: B(o.c),
    z_arid: B(o.z_arid), z_su: B(o.z_su), z_pki: B(o.z_pki), z_blind: B(o.z_blind), z_ru: B(o.z_ru),
  };
}
```

- [ ] **Step 5: 통과를 확인한다**

```bash
node tests/test_mode3_issuance.js
```

Expected: 9줄 전부 `ok`

- [ ] **Step 6: `run_tests.sh` UNIT 에 등록하고 한 번 돌린다**

```bash
bash scripts/run_tests.sh unit
```

- [ ] **Step 7: 커밋**

```bash
git add lib/mode3_credential.js lib/mode3_issuance.js tests/test_mode3_issuance.js scripts/run_tests.sh
git commit -m "feat(mode3): 발급 PoK 시그마 프로토콜 — C_pt 표현 ∧ cm_u 표현, s_u 공유, Fiat-Shamir 가 uid·C_pt·cm_u 를 덮음"
```

---

### Task 2: `RevocationLog` 컨트랙트와 체인 헬퍼

**Files:**
- Create: `contracts/RevocationLog.sol`
- Create: `test/RevocationLog.test.mjs`
- Create: `scripts/deploy_mode3_log.cjs`
- Create: `tests/helpers/mode3_chain.mjs`

**Interfaces:**
- Consumes: `createRevocationTree()` from `lib/mode3_revocation.js` (빈 트리 root)
- Produces:
  - Solidity `RevocationLog(address cia, bytes32 emptyRoot)`, `root() → bytes32`, `epoch() → uint64`, `cia() → address`, `digestFor(bytes32 newRoot, uint64 newEpoch, bytes32[] leaves) → bytes32`, `publishRoot(bytes32 newRoot, uint64 newEpoch, bytes32[] leaves, bytes sig)`, `event Revoked(uint64 indexed epoch, bytes32 root, bytes32[] leaves)`, errors `EpochNotIncreasing(uint64 got, uint64 have)`, `BadSignature()`
  - JS helper `tests/helpers/mode3_chain.mjs`: `getProvider() → JsonRpcProvider(:8545)`, `getFunder() → Signer(계정0)`, `fundAddress(addr, eth='1')`, `deployRevocationLog(ciaAddress) → { address, contract }`, `mineBlocks(n)`, `logAbi`, `rootToBytes32(bigint) → hex`, `bytes32ToBigint(hex)`, `signRootPublication(wallet, { root, epoch, leaves }) → sig` (EIP-191, 컨트랙트와 같은 digest)

**서명 digest** (컨트랙트·JS 동일):
```
inner = keccak256(abi.encode(DOMAIN, newRoot, newEpoch, keccak256(abi.encodePacked(leaves))))
digest = keccak256("\x19Ethereum Signed Message:\n32" ‖ inner)        ← EIP-191. ethers Wallet.signMessage(getBytes(inner)) 가 이것을 만든다
DOMAIN = keccak256("MODE3_REVOCATION_ROOT_V1")
```

- [ ] **Step 1: 컨트랙트 테스트를 쓴다**

`test/RevocationLog.test.mjs`:

```js
// RevocationLog — 폐기 체인 컨트랙트. hardhat 인프로세스 체인. (contract 그룹)
import { expect } from 'chai';
import hre from 'hardhat';
import { createRevocationTree } from '../lib/mode3_revocation.js';

const { ethers } = hre;
const DOMAIN = ethers.keccak256(ethers.toUtf8Bytes('MODE3_REVOCATION_ROOT_V1'));
const b32 = (n) => ethers.zeroPadValue(ethers.toBeHex(n), 32);

async function signPub(wallet, root, epoch, leaves) {
  const leavesHash = ethers.keccak256(ethers.solidityPacked(leaves.map(() => 'bytes32'), leaves));
  const inner = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
    ['bytes32', 'bytes32', 'uint64', 'bytes32'], [DOMAIN, root, epoch, leavesHash]));
  return wallet.signMessage(ethers.getBytes(inner));
}

describe('RevocationLog', () => {
  let log, cia, relayer, stranger, emptyRoot;
  beforeEach(async () => {
    [, cia, relayer, stranger] = await ethers.getSigners();
    emptyRoot = b32((await createRevocationTree()).getRoot());
    const F = await ethers.getContractFactory('RevocationLog');
    log = await F.deploy(cia.address, emptyRoot);
  });

  it('초기 상태: 빈 트리 root, epoch 0', async () => {
    expect(await log.root()).to.equal(emptyRoot);
    expect(await log.epoch()).to.equal(0n);
    expect(await log.cia()).to.equal(cia.address);
  });

  it('CIA 서명 게시: root·epoch 갱신, 리프 이벤트', async () => {
    const leaves = [b32(111n), b32(222n)];
    const newRoot = b32(999n);
    const sig = await signPub(cia, newRoot, 1n, leaves);
    await expect(log.connect(relayer).publishRoot(newRoot, 1n, leaves, sig))
      .to.emit(log, 'Revoked').withArgs(1n, newRoot, leaves);
    expect(await log.root()).to.equal(newRoot);
    expect(await log.epoch()).to.equal(1n);
  });

  it('제출자는 아무나여도 된다 (권한은 서명에 있다)', async () => {
    const sig = await signPub(cia, b32(1n), 1n, []);
    await log.connect(stranger).publishRoot(b32(1n), 1n, [], sig);
    expect(await log.epoch()).to.equal(1n);
  });

  it('CIA 가 아닌 키의 서명은 거절된다', async () => {
    const sig = await signPub(stranger, b32(1n), 1n, []);
    await expect(log.publishRoot(b32(1n), 1n, [], sig)).to.be.revertedWithCustomError(log, 'BadSignature');
  });

  it('epoch 가 오르지 않으면 거절된다 (재생 방지)', async () => {
    await log.publishRoot(b32(1n), 1n, [], await signPub(cia, b32(1n), 1n, []));
    await expect(log.publishRoot(b32(2n), 1n, [], await signPub(cia, b32(2n), 1n, [])))
      .to.be.revertedWithCustomError(log, 'EpochNotIncreasing');
    await expect(log.publishRoot(b32(2n), 0n, [], await signPub(cia, b32(2n), 0n, [])))
      .to.be.revertedWithCustomError(log, 'EpochNotIncreasing');
  });

  it('서명된 것과 다른 리프 배열을 붙이면 거절된다 (calldata 오염 방지)', async () => {
    const sig = await signPub(cia, b32(5n), 1n, [b32(1n)]);
    await expect(log.publishRoot(b32(5n), 1n, [b32(2n)], sig)).to.be.revertedWithCustomError(log, 'BadSignature');
    await expect(log.publishRoot(b32(5n), 1n, [], sig)).to.be.revertedWithCustomError(log, 'BadSignature');
  });

  it('digestFor 가 JS 와 같은 digest 를 준다', async () => {
    const leaves = [b32(7n)];
    const leavesHash = ethers.keccak256(ethers.solidityPacked(['bytes32'], leaves));
    const inner = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
      ['bytes32', 'bytes32', 'uint64', 'bytes32'], [DOMAIN, b32(9n), 3n, leavesHash]));
    expect(await log.digestFor(b32(9n), 3n, leaves)).to.equal(inner);
  });
});
```

- [ ] **Step 2: 실패를 확인한다**

```bash
npx hardhat test test/RevocationLog.test.mjs
```

Expected: `RevocationLog` 아티팩트가 없어 `getContractFactory` 실패

- [ ] **Step 3: 컨트랙트를 쓴다**

`contracts/RevocationLog.sol`:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title Mode 3 폐기 체인 — CIA 서명 root + 리프 calldata
/// @notice 설계 §6.5, §7.2. 상태는 root 와 epoch 둘뿐이고 리프는 이벤트(calldata)로만 남긴다.
///   누구든 이벤트를 재생해 트리를 재구성할 수 있고(데이터 가용성), 재구성한 root 가 여기
///   저장된 root 와 다르면 그 자리에서 들통난다(사후 감사). 삽입을 온체인에서 검증하지 않는
///   이유는 CIA 를 신뢰하기로 했기 때문이다(§2.1) — 검증은 신뢰가 없을 때 필요한 것이다.
///
///   제출은 무허가다. 권한은 서명에 있으므로 릴레이어를 신뢰할 필요가 없다. 그래서 서명이
///   **리프 배열까지** 덮어야 한다 — 안 그러면 릴레이어가 서명된 root 에 엉뚱한 리프를 붙여
///   calldata 를 오염시키고, 지갑이 잘못된 트리를 재구성해 전원이 root 불일치로 막힌다.
contract RevocationLog {
    bytes32 public constant DOMAIN = keccak256("MODE3_REVOCATION_ROOT_V1");

    address public immutable cia;
    bytes32 public root;
    uint64 public epoch;

    event Revoked(uint64 indexed epoch, bytes32 root, bytes32[] leaves);

    error EpochNotIncreasing(uint64 got, uint64 have);
    error BadSignature();

    constructor(address cia_, bytes32 emptyRoot) {
        cia = cia_;
        root = emptyRoot;
    }

    /// @dev EIP-191 personal_sign 을 적용하기 **전의** 내부 digest. ethers 의
    ///   wallet.signMessage(getBytes(digestFor(...))) 가 이 컨트랙트가 기대하는 서명을 만든다.
    function digestFor(bytes32 newRoot, uint64 newEpoch, bytes32[] calldata leaves)
        public pure returns (bytes32)
    {
        return keccak256(abi.encode(DOMAIN, newRoot, newEpoch, keccak256(abi.encodePacked(leaves))));
    }

    function publishRoot(bytes32 newRoot, uint64 newEpoch, bytes32[] calldata leaves, bytes calldata sig)
        external
    {
        if (newEpoch <= epoch) revert EpochNotIncreasing(newEpoch, epoch);
        bytes32 inner = digestFor(newRoot, newEpoch, leaves);
        bytes32 ethDigest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", inner));
        if (_recover(ethDigest, sig) != cia) revert BadSignature();
        root = newRoot;
        epoch = newEpoch;
        emit Revoked(newEpoch, newRoot, leaves);
    }

    /// @dev OpenZeppelin 없이 ecrecover. s 의 상위 절반과 v ∉ {27,28} 을 거절해 가변성을 막는다.
    function _recover(bytes32 digest, bytes calldata sig) internal pure returns (address) {
        if (sig.length != 65) revert BadSignature();
        bytes32 r; bytes32 s; uint8 v;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) revert BadSignature();
        if (v != 27 && v != 28) revert BadSignature();
        address a = ecrecover(digest, v, r, s);
        if (a == address(0)) revert BadSignature();
        return a;
    }
}
```

- [ ] **Step 4: 통과를 확인한다**

```bash
npx hardhat test test/RevocationLog.test.mjs
```

Expected: 7 passing. 그리고 `bash scripts/run_tests.sh contract` 로 기존 컨트랙트 테스트도 그대로 통과하는지 한 번.

- [ ] **Step 5: 체인 헬퍼를 쓴다**

`tests/helpers/mode3_chain.mjs`:

```js
// :8545 hardhat 노드용 헬퍼 (chain 그룹). 컨트랙트 테스트(test/*.test.mjs)는 이걸 쓰지
// 않는다 — 그쪽은 hardhat 인프로세스 체인이다.
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { ethers } from 'ethers';
import { createRevocationTree } from '../../lib/mode3_revocation.js';

const ROOT_DIR = fileURLToPath(new URL('../..', import.meta.url));
const RPC_URL = process.env.CIA_RPC_URL || 'http://127.0.0.1:8545';
const ARTIFACT = path.join(ROOT_DIR, 'artifacts', 'contracts', 'RevocationLog.sol', 'RevocationLog.json');

export const DOMAIN = ethers.keccak256(ethers.toUtf8Bytes('MODE3_REVOCATION_ROOT_V1'));
export const rootToBytes32 = (n) => ethers.zeroPadValue(ethers.toBeHex(BigInt(n)), 32);
export const bytes32ToBigint = (h) => BigInt(h);

function artifact() {
  if (!fs.existsSync(ARTIFACT)) {
    execFileSync('npx', ['hardhat', 'compile', '--quiet'], { cwd: ROOT_DIR, stdio: 'inherit' });
  }
  return JSON.parse(fs.readFileSync(ARTIFACT, 'utf8'));
}
export const logAbi = () => artifact().abi;

export function getProvider() { return new ethers.JsonRpcProvider(RPC_URL); }
export async function getFunder(provider = getProvider()) { return provider.getSigner(0); }

export async function fundAddress(addr, eth = '1', provider = getProvider()) {
  const funder = await getFunder(provider);
  await (await funder.sendTransaction({ to: addr, value: ethers.parseEther(eth) })).wait();
}

export async function deployRevocationLog(ciaAddress, provider = getProvider()) {
  const { abi, bytecode } = artifact();
  const emptyRoot = rootToBytes32((await createRevocationTree()).getRoot());
  const factory = new ethers.ContractFactory(abi, bytecode, await getFunder(provider));
  const contract = await factory.deploy(ciaAddress, emptyRoot);
  await contract.waitForDeployment();
  return { address: await contract.getAddress(), contract };
}

export async function mineBlocks(n, provider = getProvider()) {
  await provider.send('hardhat_mine', ['0x' + n.toString(16)]);
}

/** 컨트랙트 digestFor 와 같은 내부 digest 에 EIP-191 서명. leaves 는 bytes32 hex 배열. */
export async function signRootPublication(wallet, { root, epoch, leaves }) {
  const leavesHash = ethers.keccak256(ethers.solidityPacked(leaves.map(() => 'bytes32'), leaves));
  const inner = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
    ['bytes32', 'bytes32', 'uint64', 'bytes32'], [DOMAIN, root, epoch, leavesHash]));
  return wallet.signMessage(ethers.getBytes(inner));
}
```

- [ ] **Step 6: 배포 스크립트를 쓴다**

`scripts/deploy_mode3_log.cjs`:

```js
// Mode 3 폐기 체인 컨트랙트 배포.
//   CIA_ETH_ADDRESS=0x... npx hardhat run scripts/deploy_mode3_log.cjs --network localhost
//
// 주소는 출력만 한다. .env 에 CIA_LOG_ADDRESS 로 옮기는 것은 사람이 한다.
const hre = require("hardhat");

async function main() {
  if (hre.network.name === "hardhat") {
    throw new Error("--network localhost 없이 실행되었습니다. 임시 인프로세스 체인에 배포하면 사라집니다.");
  }
  const raw = process.env.CIA_ETH_ADDRESS;
  if (!raw) throw new Error("CIA_ETH_ADDRESS 가 없습니다. cia.js 를 한 번 띄워 GET /cia/public_keys 의 ethAddress 를 쓰세요.");
  const cia = hre.ethers.getAddress(raw.trim());
  const { createRevocationTree } = await import("../lib/mode3_revocation.js");
  const emptyRoot = hre.ethers.zeroPadValue(hre.ethers.toBeHex((await createRevocationTree()).getRoot()), 32);
  const F = await hre.ethers.getContractFactory("RevocationLog");
  const log = await F.deploy(cia, emptyRoot);
  await log.waitForDeployment();
  console.log(`RevocationLog: ${await log.getAddress()}`);
  console.log(`  cia=${cia}  emptyRoot=${emptyRoot}`);
  console.log(`\n.env 에 추가:\n  CIA_LOG_ADDRESS=${await log.getAddress()}`);
}
main().then(() => process.exit(0)).catch((e) => { console.error(e); process.exit(1); });
```

- [ ] **Step 7: 커밋**

```bash
git add contracts/RevocationLog.sol test/RevocationLog.test.mjs scripts/deploy_mode3_log.cjs tests/helpers/mode3_chain.mjs
git commit -m "feat(mode3): RevocationLog 컨트랙트 — CIA 서명 root(리프 배열까지 덮음) + calldata 리프 이벤트, 체인 헬퍼"
```

---

### Task 3: `cia.js` 서버와 격리 하네스

**Files:**
- Create: `lib/mode3_state.js`
- Create: `cia.js`
- Create: `tests/helpers/isolated_cia.mjs`
- Create: `tests/test_cia_register_issue.mjs`
- Modify: `.gitignore`, `scripts/run_tests.sh` (`CHAIN`)

**Interfaces:**
- Consumes: Task 1 `verifyIssuance`, `pointFromStrings`, `parseProof`; Task 2 `signRootPublication`, `rootToBytes32`, `logAbi`; `credMessage`, `compressPoint` (`lib/mode3_credential.js`); `credLeaf`, `createRevocationTree` (`lib/mode3_revocation.js`)
- Produces (HTTP, JSON, 모든 bigint 는 10진 문자열, 점은 `{x,y}` 문자열):

| 메서드·경로 | 인증 | 요청 | 응답 |
|---|---|---|---|
| `GET /cia/public_keys` | — | | `{ pk_CIA:{x,y}, ethAddress, ttlBlocks, logAddress }` |
| `POST /cia/register` | — | `{ uid, pwd, cm_u:{x,y} }` | `201 { pk_u:{x,y}, sk_u }` (`sk_u` hex, 한 번만) / `409` 이미 등록 |
| `POST /cia/issue` | — | `{ uid, C_pt:{x,y}, proof, sig_u:{R8x,R8y,S} }` | `{ C, max_height, sigma:{R8x,R8y,S}, pk_CIA:{x,y} }` / `400` 증명·서명 불일치 / `403` disabled |
| `POST /cia/revoke` | admin | `{ uid, scope:'account'\|'credential', leaf? }` | `{ inserted:[hex], root, pending }` |
| `POST /cia/publish` | admin | | `{ published, epoch, root, txHash, leaves }` |
| `POST /cia/account/set_disabled` | admin | `{ uid, disabled }` | `{ uid, disabled }` |
| `GET /cia/state` | — | | `{ root, epoch, pendingCount, leafCount, head }` |

- 환경변수: `CIA_PORT`(4100), `CIA_STATE_FILE`(`cia_state.json`), `CIA_KEYS_FILE`(`cia_keys.json`), `CIA_ADMIN_SECRET`(없으면 admin 엔드포인트 503), `CIA_RPC_URL`(`http://127.0.0.1:8545`), `CIA_LOG_ADDRESS`(없으면 issue 가 503 — 헤드 높이를 못 읽으니 발급 불가, fail-closed), `CIA_TTL_BLOCKS`(300), `CIA_ETH_PRIVATE_KEY`(테스트 전용 override)
- admin 헤더: `X-CIA-Admin-Secret`
- 데모 계정(Mode 2 관례): `testuser / password123 → uid 12345`, `alice / alicepw → uid 67890`
- `tests/helpers/isolated_cia.mjs`: `startIsolatedCia({ env } = {}) → { base, port, dir, adminSecret, adminHeaders, ethAddress, logAddress, log, post(path, body), get(path), adminPost(path, body), stop() }` — ETH 키를 만들어 자금을 넣고 `RevocationLog` 를 먼저 배포한 뒤 CIA 를 띄운다

- [ ] **Step 1: 상태 파일 헬퍼를 쓴다**

`lib/mode3_state.js`:

```js
// JSON 상태 파일 원자적 읽기/쓰기. custom_idp.js 의 writeSecretFile 과 같은 방식이다 —
// 임시 파일에 쓰고 fsync 한 뒤 rename 으로 교체해 부분 상태가 관측되지 않게 한다.
// Mode 2 파일을 import 하지 않는 이유는 그쪽이 import 만으로 서버를 띄우기 때문이다.
import fs from 'node:fs';
import path from 'node:path';
import { randomBytes } from 'node:crypto';

export function readJson(file, fallback) {
  if (!fs.existsSync(file)) return fallback;
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

export function writeJsonAtomic(file, obj, mode = 0o600) {
  const dir = path.dirname(file);
  const tmp = path.join(dir, `.${path.basename(file)}.tmp-${process.pid}-${randomBytes(6).toString('hex')}`);
  const fd = fs.openSync(tmp, 'w', mode);
  try {
    fs.writeFileSync(fd, JSON.stringify(obj, null, 2));
    fs.fsyncSync(fd);
  } catch (err) {
    fs.closeSync(fd);
    try { fs.unlinkSync(tmp); } catch { /* best-effort */ }
    throw err;
  }
  fs.closeSync(fd);
  try {
    fs.renameSync(tmp, file);
  } catch (err) {
    try { fs.unlinkSync(tmp); } catch { /* best-effort */ }
    throw err;
  }
}
```

- [ ] **Step 2: 격리 하네스와 테스트를 먼저 쓴다 (실패 확인)**

`tests/helpers/isolated_cia.mjs`:

```js
// 격리 CIA 인스턴스. 임시 포트·임시 디렉터리·자체 키·자체 RevocationLog. :4100 개발용을 건드리지 않는다.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { ethers } from 'ethers';
import { getProvider, fundAddress, deployRevocationLog } from './mode3_chain.mjs';

const REPO_ROOT = fileURLToPath(new URL('../..', import.meta.url));

function freePort() {
  return new Promise((resolve, reject) => {
    const s = net.createServer();
    s.listen(0, '127.0.0.1', () => { const { port } = s.address(); s.close(() => resolve(port)); });
    s.on('error', reject);
  });
}

export async function startIsolatedCia(opts = {}) {
  const { env: extraEnv = {}, readyTimeoutMs = 30_000 } = opts;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mode3-cia-'));
  const port = await freePort();
  const adminSecret = randomBytes(16).toString('hex');
  const ethWallet = ethers.Wallet.createRandom();
  const provider = getProvider();
  await fundAddress(ethWallet.address, '1', provider);
  const { address: logAddress } = await deployRevocationLog(ethWallet.address, provider);

  const env = {
    ...process.env,
    CIA_PORT: String(port),
    CIA_STATE_FILE: path.join(dir, 'cia_state.json'),
    CIA_KEYS_FILE: path.join(dir, 'cia_keys.json'),
    CIA_ADMIN_SECRET: adminSecret,
    CIA_LOG_ADDRESS: logAddress,
    CIA_ETH_PRIVATE_KEY: ethWallet.privateKey,
    ...extraEnv,
  };
  const logFile = path.join(dir, 'cia.log');
  const out = fs.openSync(logFile, 'a');
  const child = spawn('node', ['cia.js'], { cwd: REPO_ROOT, env, stdio: ['ignore', out, out] });
  let spawnError = null;
  child.on('error', (e) => { spawnError = e; });

  const base = `http://127.0.0.1:${port}`;
  const deadline = Date.now() + readyTimeoutMs;
  let ready = false;
  while (Date.now() < deadline) {
    if (spawnError || child.exitCode !== null) break;
    try {
      const r = await fetch(`${base}/cia/public_keys`);
      if (r.ok) { ready = true; break; }
    } catch { /* not yet */ }
    await new Promise((r) => setTimeout(r, 200));
  }
  if (!ready) {
    const log = fs.existsSync(logFile) ? fs.readFileSync(logFile, 'utf8') : '';
    try { child.kill('SIGKILL'); } catch { /* */ }
    throw new Error(`격리 CIA 기동 실패(${port}).${spawnError ? ' spawn: ' + spawnError.message : ''}\n${log}`);
  }

  const adminHeaders = { 'Content-Type': 'application/json', 'X-CIA-Admin-Secret': adminSecret };
  const json = async (r) => ({ status: r.status, body: await r.json().catch(() => null) });
  return {
    base, port, dir, adminSecret, adminHeaders, ethAddress: ethWallet.address, logAddress,
    log: () => (fs.existsSync(logFile) ? fs.readFileSync(logFile, 'utf8') : ''),
    post: (p, body) => fetch(`${base}${p}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body ?? {}) }).then(json),
    adminPost: (p, body) => fetch(`${base}${p}`, { method: 'POST', headers: adminHeaders, body: JSON.stringify(body ?? {}) }).then(json),
    get: (p) => fetch(`${base}${p}`).then(json),
    async stop() {
      if (child.exitCode === null && child.signalCode === null) {
        child.kill('SIGTERM');
        await new Promise((resolve) => {
          const t = setTimeout(() => { try { child.kill('SIGKILL'); } catch { /* */ } resolve(); }, 3000);
          child.once('exit', () => { clearTimeout(t); resolve(); });
        });
      }
      fs.rmSync(dir, { recursive: true, force: true });
    },
  };
}
```

`tests/test_cia_register_issue.mjs`:

```js
// CIA 엔드포인트 — 격리 인스턴스 + :8545. (chain 그룹)
//   node tests/test_cia_register_issue.mjs
import assert from 'node:assert/strict';
import { buildEddsa, buildPoseidon } from 'circomlibjs';
import { ethers } from 'ethers';
import { startIsolatedCia } from './helpers/isolated_cia.mjs';
import { getProvider, logAbi } from './helpers/mode3_chain.mjs';
import { randomScalar, credMessage, compressPoint } from '../lib/mode3_credential.js';
import { credLeaf } from '../lib/mode3_revocation.js';
import { registrationCommit, proveIssuance, serializeProof, pointToStrings } from '../lib/mode3_issuance.js';

let failed = 0;
async function t(name, fn) {
  try { await fn(); console.log(`ok   ${name}`); }
  catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.message}`); }
}

const cia = await startIsolatedCia();
const eddsa = await buildEddsa();
const poseidon = await buildPoseidon();
const F = poseidon.F;
const uid = 12345n;
const arid = 22222222222222222222n;
const pk_i = BigInt(ethers.Wallet.createRandom().address);
let user;   // { s_u, r_u, cm_u, sk_u(Buffer), pk_u }

function signUser(prvBuf, C_pt) {
  const m = F.e(F.toObject(poseidon([C_pt.x, C_pt.y])));
  const s = eddsa.signPoseidon(prvBuf, m);
  return { R8x: F.toObject(s.R8[0]).toString(), R8y: F.toObject(s.R8[1]).toString(), S: s.S.toString() };
}

async function issueRequest(u, overrides = {}) {
  const blind = randomScalar();
  const { C_pt, proof } = await proveIssuance({ uid, arid, s_u: u.s_u, blind, pk_i, r_u: u.r_u });
  return { body: { uid: uid.toString(), C_pt: pointToStrings(C_pt), proof: serializeProof(proof), sig_u: signUser(u.sk_u, C_pt), ...overrides }, C_pt, blind };
}

try {
  await t('public_keys 가 CIA EdDSA 키·ETH 주소·TTL·로그 주소를 준다', async () => {
    const r = await cia.get('/cia/public_keys');
    assert.equal(r.status, 200);
    assert.equal(r.body.ethAddress.toLowerCase(), cia.ethAddress.toLowerCase());
    assert.equal(r.body.ttlBlocks, 300);
    assert.equal(r.body.logAddress.toLowerCase(), cia.logAddress.toLowerCase());
  });

  await t('register: cm_u 등록, 장기키 발급', async () => {
    const s_u = randomScalar(), r_u = randomScalar();
    const cm_u = await registrationCommit(s_u, r_u);
    const r = await cia.post('/cia/register', { uid: '12345', pwd: 'password123', cm_u: pointToStrings(cm_u) });
    assert.equal(r.status, 201, JSON.stringify(r.body));
    const sk_u = Buffer.from(r.body.sk_u, 'hex');
    const pub = eddsa.prv2pub(sk_u);
    assert.equal(F.toObject(pub[0]).toString(), r.body.pk_u.x, '돌려준 sk_u 가 pk_u 와 맞아야 한다');
    user = { s_u, r_u, cm_u, sk_u, pk_u: r.body.pk_u };
  });

  await t('register: 잘못된 비밀번호는 401, 재등록은 409', async () => {
    const cm = pointToStrings(await registrationCommit(1n, 2n));
    assert.equal((await cia.post('/cia/register', { uid: '12345', pwd: 'wrong', cm_u: cm })).status, 401);
    assert.equal((await cia.post('/cia/register', { uid: '12345', pwd: 'password123', cm_u: cm })).status, 409);
  });

  let cred;
  await t('issue: 올바른 π_issue + 사용자 서명 → CIA 서명 credential', async () => {
    const { body, C_pt } = await issueRequest(user);
    const r = await cia.post('/cia/issue', body);
    assert.equal(r.status, 200, JSON.stringify(r.body));
    cred = r.body;
    // C 는 CIA 가 C_pt 에서 유도한 값이어야 한다
    assert.equal(cred.C, (await compressPoint(C_pt)).toString());
    // σ_CIA 가 credMessage(C, max_height) 에 대한 pk_CIA 서명인지
    const msg = F.e(await credMessage(BigInt(cred.C), BigInt(cred.max_height)));
    const sig = { R8: [F.e(BigInt(cred.sigma.R8x)), F.e(BigInt(cred.sigma.R8y))], S: BigInt(cred.sigma.S) };
    const pub = [F.e(BigInt(cred.pk_CIA.x)), F.e(BigInt(cred.pk_CIA.y))];
    assert.ok(eddsa.verifyPoseidon(msg, sig, pub));
    // max_height = head + 300
    const head = await getProvider().getBlockNumber();
    assert.ok(BigInt(cred.max_height) >= BigInt(head) + 299n && BigInt(cred.max_height) <= BigInt(head) + 301n);
  });

  await t('issue: 다른 s_u 로 만든 C_pt 는 400 (cm_u 동일성)', async () => {
    const fake = { ...user, s_u: randomScalar() };
    const { body } = await issueRequest(fake);
    assert.equal((await cia.post('/cia/issue', body)).status, 400);
  });

  await t('issue: 사용자 서명이 다른 키면 400', async () => {
    const { body, C_pt } = await issueRequest(user);
    body.sig_u = signUser(Buffer.alloc(32, 7), C_pt);
    assert.equal((await cia.post('/cia/issue', body)).status, 400);
  });

  await t('revoke(account): 미만료 credential 리프가 트리에 들어가고 disabled 된다', async () => {
    const r = await cia.adminPost('/cia/revoke', { uid: '12345', scope: 'account' });
    assert.equal(r.status, 200, JSON.stringify(r.body));
    const leaf = await credLeaf(BigInt(cred.C));
    assert.ok(r.body.inserted.map((h) => BigInt(h)).includes(leaf), '발급했던 credential 의 리프가 있어야 한다');
    assert.equal(r.body.pending, r.body.inserted.length);
    const { body } = await issueRequest(user);
    assert.equal((await cia.post('/cia/issue', body)).status, 403, 'disabled 계정은 발급 거절');
  });

  await t('publish: 서명 root 가 RevocationLog 에 올라가고 epoch 1', async () => {
    const r = await cia.adminPost('/cia/publish');
    assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.equal(r.body.published, true);
    assert.equal(r.body.epoch, 1);
    const log = new ethers.Contract(cia.logAddress, logAbi(), getProvider());
    assert.equal(BigInt(await log.root()).toString(), BigInt(r.body.root).toString());
    assert.equal(await log.epoch(), 1n);
    const st = await cia.get('/cia/state');
    assert.equal(st.body.pendingCount, 0);
    assert.equal(st.body.epoch, 1);
  });

  await t('publish: 대기 리프가 없으면 published:false 이고 epoch 그대로', async () => {
    const r = await cia.adminPost('/cia/publish');
    assert.equal(r.status, 200);
    assert.equal(r.body.published, false);
    assert.equal((await cia.get('/cia/state')).body.epoch, 1);
  });

  await t('set_disabled false → 다시 발급된다 (복구, §6.6)', async () => {
    assert.equal((await cia.adminPost('/cia/account/set_disabled', { uid: '12345', disabled: false })).status, 200);
    const { body } = await issueRequest(user);
    assert.equal((await cia.post('/cia/issue', body)).status, 200);
  });

  await t('admin 엔드포인트는 시크릿 없이 401', async () => {
    assert.equal((await cia.post('/cia/revoke', { uid: '12345', scope: 'account' })).status, 401);
  });
} finally {
  await cia.stop();
}
process.exit(failed === 0 ? 0 : 1);
```

```bash
node tests/test_cia_register_issue.mjs
```

Expected: `cia.js` 가 없어 기동 실패로 throw

- [ ] **Step 3: `cia.js` 를 쓴다**

`cia.js`:

```js
// Mode 3 CIA (Credential Issuing Authority).
// 설계: docs/superpowers/specs/2026-09-09-mode3-cia-revocation-design.md §3, §6
//
// Mode 2 의 custom_idp.js 와 나란히 두는 별도 서버다(:4100). 그쪽 코드를 import 하지 않는다.
// 하는 일 넷: 등록(§6.1), 발급(§6.2), 폐기(§6.5), root 게시(§6.5). 로그인 검증은 하지 않는다 —
// 그것은 RP 의 일이고(§6.3) CIA 는 조회 경로에 있어서는 안 된다(§9.9).
import express from 'express';
import fs from 'node:fs';
import path from 'node:path';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { ethers } from 'ethers';
import { buildEddsa, buildPoseidon } from 'circomlibjs';
import { readJson, writeJsonAtomic } from './lib/mode3_state.js';
import { credMessage, compressPoint } from './lib/mode3_credential.js';
import { credLeaf, createRevocationTree } from './lib/mode3_revocation.js';
import { verifyIssuance, pointFromStrings, parseProof } from './lib/mode3_issuance.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.CIA_PORT) || 4100;
const STATE_FILE = process.env.CIA_STATE_FILE || path.join(__dirname, 'cia_state.json');
const KEYS_FILE = process.env.CIA_KEYS_FILE || path.join(__dirname, 'cia_keys.json');
const ADMIN_SECRET = process.env.CIA_ADMIN_SECRET;
const RPC_URL = process.env.CIA_RPC_URL || 'http://127.0.0.1:8545';
const LOG_ADDRESS = process.env.CIA_LOG_ADDRESS || null;
const TTL_BLOCKS = Number(process.env.CIA_TTL_BLOCKS) || 300;

const DOMAIN_ROOT = ethers.keccak256(ethers.toUtf8Bytes('MODE3_REVOCATION_ROOT_V1'));
const LOG_ABI = [
  'function root() view returns (bytes32)',
  'function epoch() view returns (uint64)',
  'function publishRoot(bytes32 newRoot, uint64 newEpoch, bytes32[] leaves, bytes sig)',
];

// 데모 계정. Mode 2 의 testuser 관례를 따른 프로토타입이다 — 실제 계정 체계가 아니다.
const DEMO_ACCOUNTS = {
  testuser: { password: 'password123', uid: '12345' },
  alice: { password: 'alicepw', uid: '67890' },
};

// ---- 키 ----
// EdDSA-Poseidon(credential 서명)과 secp256k1(root 게시) 둘. 파일은 0600.
let eddsa, poseidon, F;
let ciaPrv;        // Buffer 32 — signPoseidon 이 요구하는 형식
let ciaPub;        // [Ax, Ay]
let ethWallet;     // ethers.Wallet

function loadOrCreateKeys() {
  let keys = readJson(KEYS_FILE, null);
  if (!keys) {
    keys = { eddsaPrv: randomBytes(32).toString('hex'), ethPrv: ethers.Wallet.createRandom().privateKey };
    writeJsonAtomic(KEYS_FILE, keys, 0o600);
  }
  ciaPrv = Buffer.from(keys.eddsaPrv, 'hex');
  ciaPub = eddsa.prv2pub(ciaPrv);
  const ethPrv = process.env.CIA_ETH_PRIVATE_KEY || keys.ethPrv;   // 테스트는 배포한 로그와 맞는 키를 주입한다
  ethWallet = new ethers.Wallet(ethPrv, new ethers.JsonRpcProvider(RPC_URL));
}

// ---- 상태 ----
// accounts:  uid → { pk_u:{x,y}, cm_u:{x,y}, disabled }
// issued:    uid → [ { leaf(10진), max_height } ]      폐기 시 열거용. 만료되면 걷어낸다
// revoked:   [leaf(10진)]                              지금까지 트리에 넣은 전부 — 재기동 시 재구성
// pending:   [leaf(10진)]                              아직 게시 안 한 것
// epoch
let state;
let tree;
function defaultState() { return { version: 1, accounts: {}, issued: {}, revoked: [], pending: [], epoch: 0 }; }
function persist() { writeJsonAtomic(STATE_FILE, state, 0o600); }

async function loadState() {
  state = readJson(STATE_FILE, defaultState());
  tree = await createRevocationTree();
  for (const l of state.revoked) await tree.insert(BigInt(l));
}

// ---- 유틸 ----
const S = (o) => ({ x: F.toObject(o[0]).toString(), y: F.toObject(o[1]).toString() });
const isDec = (v) => typeof v === 'string' && /^[0-9]+$/.test(v);
const isPt = (p) => p && isDec(p.x) && isDec(p.y);
function secretMatches(a, b) {
  const A = Buffer.from(a), B = Buffer.from(b);
  return A.length === B.length && timingSafeEqual(A, B);
}
function requireAdmin(req, res, next) {
  if (!ADMIN_SECRET) return res.status(503).json({ error: 'admin endpoints disabled: CIA_ADMIN_SECRET is not configured' });
  const p = req.get('X-CIA-Admin-Secret');
  if (typeof p !== 'string' || !secretMatches(p, ADMIN_SECRET)) return res.status(401).json({ error: 'unauthorized' });
  next();
}
async function headHeight() {
  if (!LOG_ADDRESS) throw Object.assign(new Error('CIA_LOG_ADDRESS not configured'), { status: 503 });
  return BigInt(await ethWallet.provider.getBlockNumber());
}
function pruneExpired(uid, head) {
  const list = state.issued[uid] ?? [];
  state.issued[uid] = list.filter((e) => BigInt(e.max_height) >= head);
  return state.issued[uid];
}

// ---- 앱 ----
const app = express();
app.use(express.json({ limit: '256kb' }));

app.get('/cia/public_keys', (req, res) => {
  res.json({ pk_CIA: S(ciaPub), ethAddress: ethWallet.address, ttlBlocks: TTL_BLOCKS, logAddress: LOG_ADDRESS });
});

// §6.1 등록. CIA 가 장기키를 만들어 주고 sk_u 는 기억하지 않는다(응답에 한 번 실어 보내고 버린다).
app.post('/cia/register', (req, res) => {
  const { uid, pwd, cm_u } = req.body ?? {};
  if (!isDec(uid) || typeof pwd !== 'string' || !isPt(cm_u)) return res.status(400).json({ error: 'uid, pwd, cm_u{x,y} required' });
  const acct = Object.values(DEMO_ACCOUNTS).find((a) => a.uid === uid);
  if (!acct || acct.password !== pwd) return res.status(401).json({ error: 'invalid credentials' });
  if (state.accounts[uid]) return res.status(409).json({ error: 'already registered' });
  const prv = randomBytes(32);
  const pub = eddsa.prv2pub(prv);
  state.accounts[uid] = { pk_u: S(pub), cm_u: { x: cm_u.x, y: cm_u.y }, disabled: false };
  persist();
  res.status(201).json({ pk_u: S(pub), sk_u: prv.toString('hex') });
});

// §6.2 발급. C 는 받지 않는다 — C_pt 에서 스스로 유도한다.
app.post('/cia/issue', async (req, res) => {
  try {
    const { uid, C_pt, proof, sig_u } = req.body ?? {};
    if (!isDec(uid) || !isPt(C_pt) || !proof || !sig_u) return res.status(400).json({ error: 'uid, C_pt, proof, sig_u required' });
    const acct = state.accounts[uid];
    if (!acct) return res.status(404).json({ error: 'unknown account' });
    if (acct.disabled) return res.status(403).json({ error: 'account disabled' });

    const cpt = pointFromStrings(C_pt);
    // 사용자 인증: 등록된 pk_u 로 C_pt 에 대한 EdDSA-Poseidon 서명 검증
    let sigOk = false;
    try {
      const m = F.e(F.toObject(poseidon([cpt.x, cpt.y])));
      const sig = { R8: [F.e(BigInt(sig_u.R8x)), F.e(BigInt(sig_u.R8y))], S: BigInt(sig_u.S) };
      const pub = [F.e(BigInt(acct.pk_u.x)), F.e(BigInt(acct.pk_u.y))];
      sigOk = eddsa.verifyPoseidon(m, sig, pub);
    } catch { sigOk = false; }
    if (!sigOk) return res.status(400).json({ error: 'bad user signature' });

    // π_issue: 이 C_pt 가 내 uid 의 것이고 s_u 가 등록된 cm_u 와 같다
    let proofOk = false;
    try { proofOk = await verifyIssuance({ uid: BigInt(uid), C_pt: cpt, cm_u: pointFromStrings(acct.cm_u), proof: parseProof(proof) }); }
    catch { proofOk = false; }
    if (!proofOk) return res.status(400).json({ error: 'bad issuance proof' });

    const head = await headHeight();
    const C = await compressPoint(cpt);
    const max_height = head + BigInt(TTL_BLOCKS);
    const s = eddsa.signPoseidon(ciaPrv, F.e(await credMessage(C, max_height)));
    const leaf = await credLeaf(C);
    pruneExpired(uid, head).push({ leaf: leaf.toString(), max_height: max_height.toString() });
    persist();
    res.json({
      C: C.toString(), max_height: max_height.toString(),
      sigma: { R8x: F.toObject(s.R8[0]).toString(), R8y: F.toObject(s.R8[1]).toString(), S: s.S.toString() },
      pk_CIA: S(ciaPub),
    });
  } catch (e) {
    res.status(e.status || 500).json({ error: e.message });
  }
});

// §6.5 폐기. account = 그 uid 의 미만료 리프 전부 + disabled. credential = 리프 하나.
app.post('/cia/revoke', requireAdmin, async (req, res) => {
  try {
    const { uid, scope, leaf } = req.body ?? {};
    if (!isDec(uid) || !state.accounts[uid]) return res.status(404).json({ error: 'unknown account' });
    const head = await headHeight();
    let targets;
    if (scope === 'account') {
      targets = pruneExpired(uid, head).map((e) => e.leaf);
      state.accounts[uid].disabled = true;
    } else if (scope === 'credential') {
      if (!isDec(leaf)) return res.status(400).json({ error: 'leaf required' });
      targets = [leaf];
    } else return res.status(400).json({ error: "scope must be 'account' or 'credential'" });
    const inserted = [];
    for (const l of targets) {
      if (await tree.insert(BigInt(l))) { state.revoked.push(l); state.pending.push(l); inserted.push(l); }
    }
    persist();
    res.json({ inserted, root: tree.getRoot().toString(), pending: state.pending.length });
  } catch (e) { res.status(e.status || 500).json({ error: e.message }); }
});

// §6.5 게시. 서명이 리프 배열까지 덮는다 — 릴레이어의 calldata 오염 방지.
app.post('/cia/publish', requireAdmin, async (req, res) => {
  try {
    if (!LOG_ADDRESS) return res.status(503).json({ error: 'CIA_LOG_ADDRESS not configured' });
    if (state.pending.length === 0) return res.json({ published: false, epoch: state.epoch, root: tree.getRoot().toString() });
    const log = new ethers.Contract(LOG_ADDRESS, LOG_ABI, ethWallet);
    const leaves = state.pending.map((l) => ethers.zeroPadValue(ethers.toBeHex(BigInt(l)), 32));
    const root = ethers.zeroPadValue(ethers.toBeHex(tree.getRoot()), 32);
    const epoch = state.epoch + 1;
    const leavesHash = ethers.keccak256(ethers.solidityPacked(leaves.map(() => 'bytes32'), leaves));
    const inner = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
      ['bytes32', 'bytes32', 'uint64', 'bytes32'], [DOMAIN_ROOT, root, epoch, leavesHash]));
    const sig = await ethWallet.signMessage(ethers.getBytes(inner));
    const tx = await log.publishRoot(root, epoch, leaves, sig);
    await tx.wait();
    state.epoch = epoch;
    state.pending = [];
    persist();
    res.json({ published: true, epoch, root: tree.getRoot().toString(), txHash: tx.hash, leaves });
  } catch (e) { res.status(e.status || 500).json({ error: e.message }); }
});

app.post('/cia/account/set_disabled', requireAdmin, (req, res) => {
  const { uid, disabled } = req.body ?? {};
  if (!isDec(uid) || !state.accounts[uid]) return res.status(404).json({ error: 'unknown account' });
  state.accounts[uid].disabled = Boolean(disabled);
  persist();
  res.json({ uid, disabled: state.accounts[uid].disabled });
});

app.get('/cia/state', async (req, res) => {
  let head = null;
  try { head = (await headHeight()).toString(); } catch { /* 체인 없음 */ }
  res.json({ root: tree.getRoot().toString(), epoch: state.epoch, pendingCount: state.pending.length, leafCount: state.revoked.length, head });
});

// ---- 기동 ----
eddsa = await buildEddsa();
poseidon = await buildPoseidon();
F = poseidon.F;
loadOrCreateKeys();
await loadState();
app.listen(PORT, () => {
  console.log(`Mode 3 CIA running at http://localhost:${PORT} (log=${LOG_ADDRESS ?? 'none'}, ttl=${TTL_BLOCKS})`);
});
```

- [ ] **Step 4: 통과를 확인한다**

```bash
node tests/test_cia_register_issue.mjs
```

Expected: 11줄 `ok`. 종료 후 `ss -ltn | grep -c ":4100 "` 가 0 인지(격리 인스턴스는 임시 포트라 4100 을 쓰지 않는다), 사용자 포트 3000/4000/5001/8545 가 그대로인지 확인.

- [ ] **Step 5: `.gitignore` 와 `run_tests.sh`**

`.gitignore` 의 `idp_state.json` 줄 아래에 `cia_keys.json`, `cia_state.json` 추가. `run_tests.sh` 의 `CHAIN=(` 에 `tests/test_cia_register_issue.mjs` 추가.

- [ ] **Step 6: 커밋**

```bash
git add lib/mode3_state.js cia.js tests/helpers/isolated_cia.mjs tests/test_cia_register_issue.mjs .gitignore scripts/run_tests.sh
git commit -m "feat(mode3): cia.js — 등록·발급·폐기·root 게시, 격리 하네스"
```

---

### Task 4: 지갑 라이브러리 — 트리 동기화·증명 생성

**Files:**
- Create: `lib/mode3_wallet.js`
- Create: `tests/test_mode3_wallet.mjs`
- Modify: `scripts/run_tests.sh` (`CHAIN`)

**Interfaces:**
- Consumes: Task 1 (`registrationCommit`, `proveIssuance`, `serializeProof`, `pointToStrings`), Task 2 헬퍼, `lib/mode3_credential.js`, `lib/mode3_revocation.js`, `lib/imt_v2.js` `buildIMTv2`, snarkjs, `build/mode3/pi_cred_js/pi_cred.wasm`, `build/mode3/pi_cred_final.zkey`
- Produces:
  - `createRegistration() → { s_u, r_u, cm_u }`
  - `createSessionKey() → { wallet: ethers.Wallet, pk_i: bigint }`
  - `signUserRequest(sk_uHex, C_pt) → { R8x, R8y, S }` (문자열)
  - `buildIssueRequest({ uid, arid, s_u, r_u, sk_u, session }) → { body, secrets:{ blind } }` — `body` 는 `/cia/issue` 요청 그대로
  - `syncRevocationTree(provider, logAddress) → { tree, root, epoch, head }` — `Revoked` 이벤트 재생, `buildIMTv2(32, leaves)`, **컨트랙트 `root()` 와 다르면 throw**(데이터 가용성 깨짐)
  - `buildCredentialProof({ uid, arid, s_u, blind, pk_i, credential, pk_CIA, tree, wasmPath?, zkeyPath? }) → { proof, publicSignals, revRoot }`
  - `class ProofCache { get(root, sessionId) / set(root, sessionId, value) }` — root 일치 규칙(§8.4)
  - `signChallenge(wallet, challenge) → sig` (EIP-191)
  - `WASM_PATH`, `ZKEY_PATH` 기본값 (`build/mode3/…`)

- [ ] **Step 1: 실패하는 테스트를 쓴다**

`tests/test_mode3_wallet.mjs`:

```js
// 지갑 라이브러리 — 트리 동기화·증명 생성·캐시. :8545 + build/mode3 zkey 필요. (chain 그룹)
//   node tests/test_mode3_wallet.mjs
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { ethers } from 'ethers';
import { buildEddsa, buildPoseidon } from 'circomlibjs';
import * as snarkjs from 'snarkjs';
import { getProvider, fundAddress, deployRevocationLog, signRootPublication, rootToBytes32, logAbi } from './helpers/mode3_chain.mjs';
import { createRevocationTree, credLeaf } from '../lib/mode3_revocation.js';
import { credMessage, compressPoint } from '../lib/mode3_credential.js';
import {
  createRegistration, createSessionKey, buildIssueRequest, syncRevocationTree,
  buildCredentialProof, ProofCache, signChallenge, ZKEY_PATH, VKEY_PATH,
} from '../lib/mode3_wallet.js';
import { pointFromStrings } from '../lib/mode3_issuance.js';

let failed = 0;
async function t(name, fn) {
  try { await fn(); console.log(`ok   ${name}`); }
  catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.message}`); }
}
assert.ok(fs.existsSync(ZKEY_PATH), `zkey 가 없다: ${ZKEY_PATH} — 단계 (c) Task 6 의 bench 를 먼저 돌려야 한다`);

const provider = getProvider();
const ciaEth = ethers.Wallet.createRandom().connect(provider);
await fundAddress(ciaEth.address, '1', provider);
const { address: logAddress, contract: log } = await deployRevocationLog(ciaEth.address, provider);
const eddsa = await buildEddsa();
const poseidon = await buildPoseidon();
const F = poseidon.F;
const ciaPrv = Buffer.alloc(32, 9);
const ciaPub = eddsa.prv2pub(ciaPrv);
const pk_CIA = { x: F.toObject(ciaPub[0]), y: F.toObject(ciaPub[1]) };
const uid = 12345n, arid = 22222222222222222222n;

// 서버 없이 CIA 역할을 로컬에서 흉내낸다 (서명만)
async function localIssue(C_pt, head) {
  const C = await compressPoint(C_pt);
  const max_height = BigInt(head) + 300n;
  const s = eddsa.signPoseidon(ciaPrv, F.e(await credMessage(C, max_height)));
  return { C: C.toString(), max_height: max_height.toString(), sigma: { R8x: F.toObject(s.R8[0]).toString(), R8y: F.toObject(s.R8[1]).toString(), S: s.S.toString() } };
}
async function publish(leavesBig) {
  const tree = await createRevocationTree();
  const ev = await log.queryFilter(log.filters.Revoked());
  for (const e of ev) for (const l of e.args.leaves) await tree.insert(BigInt(l));
  for (const l of leavesBig) await tree.insert(l);
  const root = rootToBytes32(tree.getRoot());
  const epoch = (await log.epoch()) + 1n;
  const leaves = leavesBig.map(rootToBytes32);
  const sig = await signRootPublication(ciaEth, { root, epoch, leaves });
  await (await log.connect(ciaEth).publishRoot(root, epoch, leaves, sig)).wait();
}

await t('빈 로그를 동기화하면 빈 트리 root 와 같다', async () => {
  const { tree, root, epoch } = await syncRevocationTree(provider, logAddress);
  assert.equal(root, (await createRevocationTree()).getRoot());
  assert.equal(epoch, 0n);
  assert.equal(tree.size(), 1, 'anchor 만');
});

await t('게시된 리프가 동기화된 트리에 있고 root 가 컨트랙트와 같다', async () => {
  await publish([777n]);
  const { tree, root } = await syncRevocationTree(provider, logAddress);
  assert.ok(tree.has(777n));
  assert.equal(rootToBytes32(root), await log.root());
});

let reg, session, req, cred, tree0;
await t('발급 요청 → 로컬 CIA 서명 → 증명 생성 → vkey 로 검증된다', async () => {
  reg = await createRegistration();
  session = createSessionKey();
  const sk_u = Buffer.alloc(32, 3).toString('hex');
  req = await buildIssueRequest({ uid, arid, s_u: reg.s_u, r_u: reg.r_u, sk_u, session });
  const head = await provider.getBlockNumber();
  cred = await localIssue(pointFromStrings(req.body.C_pt), head);
  ({ tree: tree0 } = await syncRevocationTree(provider, logAddress));
  const { proof, publicSignals, revRoot } = await buildCredentialProof({
    uid, arid, s_u: reg.s_u, blind: req.secrets.blind, pk_i: session.pk_i, credential: cred, pk_CIA, tree: tree0,
  });
  assert.equal(revRoot, tree0.getRoot());
  assert.equal(publicSignals.length, 7);
  assert.equal(BigInt(publicSignals[2]), session.pk_i);
  assert.equal(BigInt(publicSignals[4]), tree0.getRoot());
  const vkey = JSON.parse(fs.readFileSync(VKEY_PATH, 'utf8'));
  assert.ok(await snarkjs.groth16.verify(vkey, publicSignals, proof));
});

await t('ProofCache 는 같은 root·세션이면 재사용, root 가 바뀌면 miss', async () => {
  const cache = new ProofCache();
  cache.set(tree0.getRoot(), 's1', { proof: 'p' });
  assert.deepEqual(cache.get(tree0.getRoot(), 's1'), { proof: 'p' });
  assert.equal(cache.get(tree0.getRoot() + 1n, 's1'), null);
  assert.equal(cache.get(tree0.getRoot(), 's2'), null);
});

await t('내 credential 이 폐기되면 동기화된 트리로는 witness 를 만들 수 없다', async () => {
  await publish([await credLeaf(BigInt(cred.C))]);
  const { tree } = await syncRevocationTree(provider, logAddress);
  await assert.rejects(
    () => buildCredentialProof({ uid, arid, s_u: reg.s_u, blind: req.secrets.blind, pk_i: session.pk_i, credential: cred, pk_CIA, tree }),
    /is a member/,
  );
});

await t('챌린지 서명은 세션키 주소로 복원된다', async () => {
  const sig = await signChallenge(session.wallet, 'challenge-123');
  assert.equal(BigInt(ethers.verifyMessage('challenge-123', sig)), session.pk_i);
});

process.exit(failed === 0 ? 0 : 1);
```

- [ ] **Step 2: 실패를 확인한다**

```bash
node tests/test_mode3_wallet.mjs
```

Expected: `lib/mode3_wallet.js` 없음

- [ ] **Step 3: 지갑 라이브러리를 쓴다**

`lib/mode3_wallet.js`:

```js
// Mode 3 지갑 측 라이브러리. 서버가 아니다 — 데모 UI 연동은 이 계획 밖이다.
// 설계 §6.1(등록값), §6.2(발급 요청), §7.1/§7.2(트리 동기화), §5(증명), §8.4(root 일치 규칙).
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ethers } from 'ethers';
import { buildEddsa, buildPoseidon } from 'circomlibjs';
import * as snarkjs from 'snarkjs';
import { randomScalar } from './mode3_credential.js';
import { credLeaf, createRevocationTree, MODE3_TREE_DEPTH } from './mode3_revocation.js';
import { buildIMTv2 } from './imt_v2.js';
import { registrationCommit, proveIssuance, serializeProof, pointToStrings } from './mode3_issuance.js';

const ROOT_DIR = fileURLToPath(new URL('..', import.meta.url));
export const WASM_PATH = path.join(ROOT_DIR, 'build', 'mode3', 'pi_cred_js', 'pi_cred.wasm');
export const ZKEY_PATH = path.join(ROOT_DIR, 'build', 'mode3', 'pi_cred_final.zkey');
export const VKEY_PATH = path.join(ROOT_DIR, 'build', 'mode3', 'pi_cred_vkey.json');

const LOG_ABI = [
  'function root() view returns (bytes32)',
  'function epoch() view returns (uint64)',
  'event Revoked(uint64 indexed epoch, bytes32 root, bytes32[] leaves)',
];

let eddsaP = null, psP = null;
const getEddsa = () => (eddsaP ??= buildEddsa());
const getPs = () => (psP ??= buildPoseidon());

/** §6.1 — s_u, r_u 는 randomScalar (2^250 미만). cm_u 를 CIA 에 낸다. */
export async function createRegistration() {
  const s_u = randomScalar(), r_u = randomScalar();
  return { s_u, r_u, cm_u: await registrationCommit(s_u, r_u) };
}

/** 세션키 = secp256k1. pk_i 는 주소(160비트) — 회로의 Num2Bits(160) 과 맞는다. */
export function createSessionKey() {
  const wallet = ethers.Wallet.createRandom();
  return { wallet, pk_i: BigInt(wallet.address) };
}

/** Sign(sk_u, C_pt): 등록된 장기키로 C_pt 에 서명 (§6.2 단계 2). 메시지 = Poseidon(C_pt.x, C_pt.y). */
export async function signUserRequest(sk_uHex, C_pt) {
  const eddsa = await getEddsa();
  const ps = await getPs();
  const F = ps.F;
  const s = eddsa.signPoseidon(Buffer.from(sk_uHex, 'hex'), F.e(F.toObject(ps([C_pt.x, C_pt.y]))));
  return { R8x: F.toObject(s.R8[0]).toString(), R8y: F.toObject(s.R8[1]).toString(), S: s.S.toString() };
}

/** §6.2 단계 1~2. blind 는 여기서 새로 뽑고 secrets 로 돌려준다 — 증명 생성 때 필요하다. */
export async function buildIssueRequest({ uid, arid, s_u, r_u, sk_u, session }) {
  const blind = randomScalar();
  const { C_pt, proof } = await proveIssuance({ uid, arid, s_u, blind, pk_i: session.pk_i, r_u });
  const body = { uid: uid.toString(), C_pt: pointToStrings(C_pt), proof: serializeProof(proof), sig_u: await signUserRequest(sk_u, C_pt) };
  return { body, secrets: { blind } };
}

/**
 * §7.2 — Revoked 이벤트를 처음부터 재생해 트리를 재구성한다. CIA 없이도 된다는 것이 요점이다.
 * 재구성한 root 가 컨트랙트 root 와 다르면 throw — 릴레이어가 calldata 를 오염시켰거나
 * (서명이 리프까지 덮으므로 이론상 불가) 이 라이브러리와 CIA 의 리프 규약이 어긋난 것이다.
 */
export async function syncRevocationTree(provider, logAddress) {
  const log = new ethers.Contract(logAddress, LOG_ABI, provider);
  const [events, onchainRoot, epoch, head] = await Promise.all([
    log.queryFilter(log.filters.Revoked(), 0), log.root(), log.epoch(), provider.getBlockNumber(),
  ]);
  const leaves = [];
  for (const e of events) for (const l of e.args.leaves) leaves.push(BigInt(l));
  const tree = leaves.length === 0 ? await createRevocationTree() : await buildIMTv2(MODE3_TREE_DEPTH, leaves);
  const root = tree.getRoot();
  if (root !== BigInt(onchainRoot)) {
    throw new Error(`재구성한 root(${root}) 가 컨트랙트 root(${BigInt(onchainRoot)}) 와 다르다 — 리프 규약 불일치 또는 calldata 오염`);
  }
  return { tree, root, epoch, head: BigInt(head) };
}

/** §5 — 공개 입력 순서 [PPID, arid, pk_i, max_height, revRoot, pk_CIA_x, pk_CIA_y] 는 회로가 정한다. */
export async function buildCredentialProof({ uid, arid, s_u, blind, pk_i, credential, pk_CIA, tree, wasmPath = WASM_PATH, zkeyPath = ZKEY_PATH }) {
  const ps = await getPs();
  const PPID = ps.F.toObject(ps([uid, arid, s_u]));
  const C = BigInt(credential.C);
  const w = await tree.getNonMembershipWitness(await credLeaf(C));   // 폐기됐으면 여기서 throw ("is a member")
  const input = {
    uid: uid.toString(), s_u: s_u.toString(), blind: blind.toString(),
    S: credential.sigma.S, R8x: credential.sigma.R8x, R8y: credential.sigma.R8y,
    lowValue: String(w.lowValue), lowNextIndex: String(w.lowNextIndex), lowNextValue: String(w.lowNextValue),
    pathElements: w.pathElements.map(String), pathIndices: w.pathIndices.map(String),
    PPID: PPID.toString(), arid: arid.toString(), pk_i: pk_i.toString(),
    max_height: credential.max_height.toString(), revRoot: tree.getRoot().toString(),
    pk_CIA_x: pk_CIA.x.toString(), pk_CIA_y: pk_CIA.y.toString(),
  };
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, wasmPath, zkeyPath);
  return { proof, publicSignals, revRoot: tree.getRoot() };
}

/** §8.4 — π 는 root 가 바뀔 때까지 재사용. 세션이 바뀌면 pk_i 가 달라 재사용 불가. */
export class ProofCache {
  #m = new Map();
  key(root, sessionId) { return `${root}:${sessionId}`; }
  get(root, sessionId) { return this.#m.get(this.key(root, sessionId)) ?? null; }
  set(root, sessionId, value) { this.#m.set(this.key(root, sessionId), value); }
}

/** 요청마다 새 σ. EIP-191 personal sign — RP 는 ethers.verifyMessage 로 주소를 복원해 pk_i 와 대조한다. */
export function signChallenge(wallet, challenge) {
  return wallet.signMessage(challenge);
}
```

- [ ] **Step 4: 통과를 확인한다**

```bash
node tests/test_mode3_wallet.mjs
```

Expected: 6줄 `ok` (증명 생성 1회 약 1초)

- [ ] **Step 5: `run_tests.sh` CHAIN 등록, 커밋**

```bash
git add lib/mode3_wallet.js tests/test_mode3_wallet.mjs scripts/run_tests.sh
git commit -m "feat(mode3): 지갑 라이브러리 — 등록값·발급 요청·이벤트 재생 트리 동기화·증명 생성·root 캐시"
```

---

### Task 5: RP 검증기 — §6.3 7단계

**Files:**
- Create: `lib/mode3_rp.js`
- Create: `tests/test_mode3_rp.mjs`
- Modify: `scripts/run_tests.sh` (`CHAIN`)

**Interfaces:**
- Consumes: Task 4 (증명 생성), Task 2 헬퍼, snarkjs
- Produces:
  - `createRpVerifier({ provider, logAddress, vkey, pkCIA:{x,y}, arid, headMaxAgeMs = 600_000, now = Date.now }) → { verifyLogin, refreshChainView }`
  - `verifyLogin({ proof, publicSignals, challenge, sig }) → { ok: true, PPID, pk_i } | { ok: false, reason }` — `reason ∈ { 'chain_unavailable', 'stale_root', 'expired', 'untrusted_cia', 'bad_proof', 'bad_signature', 'wrong_arid', 'malformed' }`
  - 검사 순서(§6.3): a 헤드 신선도 → b root 일치 → c 만료 → d `pk_CIA` 고정 → (arid 일치) → e Groth16 → f 서명 → g PPID

- [ ] **Step 1: 실패하는 테스트를 쓴다**

`tests/test_mode3_rp.mjs`:

```js
// RP 검증기 — §6.3 7단계와 음성 6건. :8545 + build/mode3 필요. (chain 그룹)
//   node tests/test_mode3_rp.mjs
// hardhat_mine 으로 :8545 블록을 진행시킨다 (기존 chain 그룹과 같은 성질).
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { ethers } from 'ethers';
import { buildEddsa, buildPoseidon } from 'circomlibjs';
import { getProvider, fundAddress, deployRevocationLog, signRootPublication, rootToBytes32, mineBlocks } from './helpers/mode3_chain.mjs';
import { credLeaf, createRevocationTree } from '../lib/mode3_revocation.js';
import { credMessage, compressPoint } from '../lib/mode3_credential.js';
import { pointFromStrings } from '../lib/mode3_issuance.js';
import { createRegistration, createSessionKey, buildIssueRequest, syncRevocationTree, buildCredentialProof, signChallenge, VKEY_PATH } from '../lib/mode3_wallet.js';
import { createRpVerifier } from '../lib/mode3_rp.js';

let failed = 0;
async function t(name, fn) {
  try { await fn(); console.log(`ok   ${name}`); }
  catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.message}`); }
}

const provider = getProvider();
const ciaEth = ethers.Wallet.createRandom().connect(provider);
await fundAddress(ciaEth.address, '1', provider);
const { address: logAddress, contract: log } = await deployRevocationLog(ciaEth.address, provider);
const eddsa = await buildEddsa();
const ps = await buildPoseidon();
const F = ps.F;
const vkey = JSON.parse(fs.readFileSync(VKEY_PATH, 'utf8'));
const keyOf = (prv) => { const p = eddsa.prv2pub(prv); return { prv, pub: { x: F.toObject(p[0]), y: F.toObject(p[1]) } }; };
const CIA = keyOf(Buffer.alloc(32, 9));
const ATTACKER = keyOf(Buffer.alloc(32, 66));
const uid = 12345n, arid = 22222222222222222222n, otherArid = 33333333333333333333n;

async function issueWith(key, C_pt, ttl = 300n) {
  const C = await compressPoint(C_pt);
  const max_height = BigInt(await provider.getBlockNumber()) + ttl;
  const s = eddsa.signPoseidon(key.prv, F.e(await credMessage(C, max_height)));
  return { C: C.toString(), max_height: max_height.toString(), sigma: { R8x: F.toObject(s.R8[0]).toString(), R8y: F.toObject(s.R8[1]).toString(), S: s.S.toString() } };
}
async function publish(leavesBig) {
  const { tree } = await syncRevocationTree(provider, logAddress);
  for (const l of leavesBig) await tree.insert(l);
  const root = rootToBytes32(tree.getRoot()), epoch = (await log.epoch()) + 1n, leaves = leavesBig.map(rootToBytes32);
  await (await log.connect(ciaEth).publishRoot(root, epoch, leaves, await signRootPublication(ciaEth, { root, epoch, leaves }))).wait();
}
async function makeLogin({ key = CIA, useArid = arid, ttl = 300n } = {}) {
  const reg = await createRegistration();
  const session = createSessionKey();
  const req = await buildIssueRequest({ uid, arid: useArid, s_u: reg.s_u, r_u: reg.r_u, sk_u: Buffer.alloc(32, 3).toString('hex'), session });
  const cred = await issueWith(key, pointFromStrings(req.body.C_pt), ttl);
  const { tree } = await syncRevocationTree(provider, logAddress);
  const { proof, publicSignals } = await buildCredentialProof({ uid, arid: useArid, s_u: reg.s_u, blind: req.secrets.blind, pk_i: session.pk_i, credential: cred, pk_CIA: key.pub, tree });
  const challenge = 'rp-challenge-' + Math.random();
  return { proof, publicSignals, challenge, sig: await signChallenge(session.wallet, challenge), session, cred, reg };
}

const rp = createRpVerifier({ provider, logAddress, vkey, pkCIA: CIA.pub, arid });

await t('양성: 7단계 전부 통과, PPID 와 pk_i 를 돌려준다', async () => {
  const L = await makeLogin();
  const r = await rp.verifyLogin(L);
  assert.equal(r.ok, true, JSON.stringify(r));
  assert.equal(r.PPID, BigInt(L.publicSignals[0]));
  assert.equal(r.pk_i, L.session.pk_i);
});

await t('음성 d: 공격자가 자기 CIA 키로 서명한 credential 은 untrusted_cia (유일한 위조 방어선)', async () => {
  const L = await makeLogin({ key: ATTACKER });
  const r = await rp.verifyLogin(L);
  assert.deepEqual(r, { ok: false, reason: 'untrusted_cia' });
});

await t('음성 f: 챌린지 서명이 다른 키면 bad_signature', async () => {
  const L = await makeLogin();
  L.sig = await signChallenge(ethers.Wallet.createRandom(), L.challenge);
  assert.deepEqual(await rp.verifyLogin(L), { ok: false, reason: 'bad_signature' });
});

await t('음성 f: 다른 챌린지에 대한 서명 재생은 bad_signature', async () => {
  const L = await makeLogin();
  assert.deepEqual(await rp.verifyLogin({ ...L, challenge: 'other' }), { ok: false, reason: 'bad_signature' });
});

await t('음성 arid: 다른 RP 용 credential 은 wrong_arid', async () => {
  const L = await makeLogin({ useArid: otherArid });
  assert.deepEqual(await rp.verifyLogin(L), { ok: false, reason: 'wrong_arid' });
});

await t('음성 c: max_height 를 지나면 expired', async () => {
  const L = await makeLogin({ ttl: 5n });
  await mineBlocks(10, provider);
  rp.refreshChainView && await rp.refreshChainView();
  assert.deepEqual(await rp.verifyLogin(L), { ok: false, reason: 'expired' });
});

await t('음성 b: 폐기 게시 후 옛 root 의 π 는 stale_root', async () => {
  const L = await makeLogin();
  assert.equal((await rp.verifyLogin(L)).ok, true);
  await publish([await credLeaf(BigInt(L.cred.C))]);
  assert.deepEqual(await rp.verifyLogin(L), { ok: false, reason: 'stale_root' });
});

await t('음성 e: 증명을 손대면 bad_proof', async () => {
  const L = await makeLogin();
  const bad = JSON.parse(JSON.stringify(L.proof));
  bad.pi_a[0] = (BigInt(bad.pi_a[0]) + 1n).toString();
  assert.deepEqual(await rp.verifyLogin({ ...L, proof: bad }), { ok: false, reason: 'bad_proof' });
});

await t('음성 a: 체인을 못 읽고 캐시가 10분보다 오래되면 chain_unavailable (fail-closed)', async () => {
  let now = Date.now();
  const broken = { getBlockNumber: async () => { throw new Error('rpc down'); } };
  const rp2 = createRpVerifier({ provider: broken, logAddress, vkey, pkCIA: CIA.pub, arid, now: () => now });
  const L = await makeLogin();
  assert.deepEqual(await rp2.verifyLogin(L), { ok: false, reason: 'chain_unavailable' });
});

await t('a: 캐시가 10분 안이면 RPC 가 죽어도 캐시로 검증한다', async () => {
  let now = Date.now();
  let alive = true;
  const flaky = new Proxy(provider, { get: (tgt, k) => (k === 'getBlockNumber' && !alive) ? async () => { throw new Error('rpc down'); } : tgt[k] });
  const rp2 = createRpVerifier({ provider: flaky, logAddress, vkey, pkCIA: CIA.pub, arid, now: () => now });
  const L = await makeLogin();
  assert.equal((await rp2.verifyLogin(L)).ok, true);
  alive = false; now += 5 * 60_000;
  assert.equal((await rp2.verifyLogin(L)).ok, true, '5분 된 캐시는 유효');
  now += 6 * 60_000;
  assert.deepEqual(await rp2.verifyLogin(L), { ok: false, reason: 'chain_unavailable' }, '11분이면 거절');
});

process.exit(failed === 0 ? 0 : 1);
```

- [ ] **Step 2: 실패를 확인한다**

```bash
node tests/test_mode3_rp.mjs
```

Expected: `lib/mode3_rp.js` 없음

- [ ] **Step 3: 검증기를 쓴다**

`lib/mode3_rp.js`:

```js
// RP 검증기 — 설계 §6.3 의 7단계를 그 순서대로. 오프체인 전용(§9.11).
//
//   a. 체인 뷰 신선도   ← fail-closed (§8.5). 헤드 높이로 판단하므로 하트비트가 필요 없다
//   b. root 일치        ← N=1 (§8.2). 최신 root 가 아니면 거절
//   c. 만료             ← head ≤ max_height. 온체인 §6.4 의 block.number 검사가 옮겨온 것
//   d. pk_CIA 고정      ← **유일한 위조 방어선** (§5). 회로는 "어떤 키에 대해" 만 증명한다
//      arid 일치        ← 다른 RP 용 credential 거절
//   e. Groth16
//   f. 챌린지 서명       ← 요청마다 새 σ (§8.4). pk_i 는 주소이므로 ethers.verifyMessage 로 복원
//   g. PPID
import { ethers } from 'ethers';
import * as snarkjs from 'snarkjs';

const LOG_ABI = ['function root() view returns (bytes32)'];

export function createRpVerifier({ provider, logAddress, vkey, pkCIA, arid, headMaxAgeMs = 10 * 60_000, now = Date.now }) {
  const log = new ethers.Contract(logAddress, LOG_ABI, provider);
  let view = null;   // { root, head, readAt }

  async function refreshChainView() {
    const [root, head] = await Promise.all([log.root(), provider.getBlockNumber()]);
    view = { root: BigInt(root), head: BigInt(head), readAt: now() };
    return view;
  }
  async function chainView() {
    try { return await refreshChainView(); }
    catch {
      // RPC 실패: 10분 안의 캐시만 인정한다. 그보다 오래됐으면 폐기가 무력화될 수 있으니 거절.
      if (view && now() - view.readAt <= headMaxAgeMs) return view;
      return null;
    }
  }

  async function verifyLogin({ proof, publicSignals, challenge, sig }) {
    if (!Array.isArray(publicSignals) || publicSignals.length !== 7 || !proof || typeof challenge !== 'string' || typeof sig !== 'string') {
      return { ok: false, reason: 'malformed' };
    }
    let ps;
    try { ps = publicSignals.map((s) => BigInt(s)); } catch { return { ok: false, reason: 'malformed' }; }
    const [PPID, aridIn, pk_i, max_height, revRoot, ciaX, ciaY] = ps;

    const v = await chainView();                                   // a
    if (!v) return { ok: false, reason: 'chain_unavailable' };
    if (revRoot !== v.root) return { ok: false, reason: 'stale_root' };       // b
    if (v.head > max_height) return { ok: false, reason: 'expired' };          // c
    if (ciaX !== BigInt(pkCIA.x) || ciaY !== BigInt(pkCIA.y)) return { ok: false, reason: 'untrusted_cia' };   // d
    if (aridIn !== BigInt(arid)) return { ok: false, reason: 'wrong_arid' };

    let proofOk = false;                                           // e
    try { proofOk = await snarkjs.groth16.verify(vkey, publicSignals, proof); } catch { proofOk = false; }
    if (!proofOk) return { ok: false, reason: 'bad_proof' };

    let signer;                                                    // f
    try { signer = BigInt(ethers.verifyMessage(challenge, sig)); } catch { return { ok: false, reason: 'bad_signature' }; }
    if (signer !== pk_i) return { ok: false, reason: 'bad_signature' };

    return { ok: true, PPID, pk_i };                               // g
  }

  return { verifyLogin, refreshChainView };
}
```

- [ ] **Step 4: 통과를 확인한다**

```bash
node tests/test_mode3_rp.mjs
```

Expected: 10줄 `ok`

- [ ] **Step 5: `run_tests.sh` CHAIN 등록, 커밋**

```bash
git add lib/mode3_rp.js tests/test_mode3_rp.mjs scripts/run_tests.sh
git commit -m "feat(mode3): RP 검증기 — §6.3 7단계, pk_CIA 고정·만료·stale root·fail-closed 음성 테스트"
```

---

### Task 6: 전 구간 e2e 와 문서 갱신

**Files:**
- Create: `tests/test_mode3_e2e.mjs`
- Modify: `scripts/run_tests.sh` (`CHAIN`)
- Modify: `docs/superpowers/specs/2026-09-09-mode3-cia-revocation-design.md` (§6.5 root 서명 범위, §12 (a))

**Interfaces:** Task 3 (격리 CIA), Task 4, Task 5 를 조립한다. 새 인터페이스 없음.

- [ ] **Step 1: e2e 테스트를 쓴다**

`tests/test_mode3_e2e.mjs`:

```js
// Mode 3 전 구간: 등록 → 발급 → 로그인 → 계정 폐기 → 게시 → 거절 → 복구 → 재발급 → 로그인.
// 격리 CIA + :8545 RevocationLog + 지갑 라이브러리 + RP 검증기. (chain 그룹)
//   node tests/test_mode3_e2e.mjs
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { startIsolatedCia } from './helpers/isolated_cia.mjs';
import { getProvider } from './helpers/mode3_chain.mjs';
import { createRegistration, createSessionKey, buildIssueRequest, syncRevocationTree, buildCredentialProof, signChallenge, ProofCache, VKEY_PATH } from '../lib/mode3_wallet.js';
import { pointToStrings } from '../lib/mode3_issuance.js';
import { createRpVerifier } from '../lib/mode3_rp.js';

let failed = 0;
async function t(name, fn) {
  try { await fn(); console.log(`ok   ${name}`); }
  catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.message}`); }
}

const provider = getProvider();
const cia = await startIsolatedCia();
const uid = 12345n, arid = 22222222222222222222n;
const vkey = JSON.parse(fs.readFileSync(VKEY_PATH, 'utf8'));

try {
  const keys = (await cia.get('/cia/public_keys')).body;
  const pk_CIA = { x: BigInt(keys.pk_CIA.x), y: BigInt(keys.pk_CIA.y) };
  const rp = createRpVerifier({ provider, logAddress: cia.logAddress, vkey, pkCIA: pk_CIA, arid });
  const cache = new ProofCache();

  // 지갑 상태
  const reg = await createRegistration();
  let sk_u, session, blind, cred;

  async function loginRound(label) {
    const { tree, root } = await syncRevocationTree(provider, cia.logAddress);
    let cached = cache.get(root, session.wallet.address);
    if (!cached) {
      cached = await buildCredentialProof({ uid, arid, s_u: reg.s_u, blind, pk_i: session.pk_i, credential: cred, pk_CIA, tree });
      cache.set(root, session.wallet.address, cached);
    }
    const challenge = `${label}-${Date.now()}`;
    return rp.verifyLogin({ proof: cached.proof, publicSignals: cached.publicSignals, challenge, sig: await signChallenge(session.wallet, challenge) });
  }
  async function newSessionAndIssue() {
    session = createSessionKey();
    const req = await buildIssueRequest({ uid, arid, s_u: reg.s_u, r_u: reg.r_u, sk_u, session });
    blind = req.secrets.blind;
    const r = await cia.post('/cia/issue', req.body);
    return r;
  }

  await t('등록', async () => {
    const r = await cia.post('/cia/register', { uid: uid.toString(), pwd: 'password123', cm_u: pointToStrings(reg.cm_u) });
    assert.equal(r.status, 201, JSON.stringify(r.body));
    sk_u = r.body.sk_u;
  });

  await t('발급 → 로그인 성공', async () => {
    const r = await newSessionAndIssue();
    assert.equal(r.status, 200, JSON.stringify(r.body));
    cred = r.body;
    const v = await loginRound('login1');
    assert.equal(v.ok, true, JSON.stringify(v));
  });

  let PPID1;
  await t('같은 root 면 두 번째 요청은 캐시된 π 로 통과 (σ 만 새로)', async () => {
    const v = await loginRound('login2');
    assert.equal(v.ok, true);
    PPID1 = v.PPID;
  });

  await t('계정 폐기 + 게시 → 옛 π 는 stale_root 로 거절', async () => {
    assert.equal((await cia.adminPost('/cia/revoke', { uid: uid.toString(), scope: 'account' })).status, 200);
    assert.equal((await cia.adminPost('/cia/publish')).body.published, true);
    const v = await loginRound('after-revoke');
    // 캐시된 π 는 옛 root — 검증기가 최신 root 와 비교해 거절해야 한다
    assert.equal(v.ok, false);
    assert.equal(v.reason, 'stale_root');
  });

  await t('폐기된 credential 로는 새 root 에 대한 π 도 만들 수 없다', async () => {
    const { tree } = await syncRevocationTree(provider, cia.logAddress);
    await assert.rejects(() => buildCredentialProof({ uid, arid, s_u: reg.s_u, blind, pk_i: session.pk_i, credential: cred, pk_CIA, tree }), /is a member/);
  });

  await t('disabled 계정은 재발급 거절 (403)', async () => {
    assert.equal((await newSessionAndIssue()).status, 403);
  });

  await t('복구(set_disabled false) → 재발급 → 로그인, PPID 유지 (§6.6)', async () => {
    assert.equal((await cia.adminPost('/cia/account/set_disabled', { uid: uid.toString(), disabled: false })).status, 200);
    const r = await newSessionAndIssue();
    assert.equal(r.status, 200, JSON.stringify(r.body));
    cred = r.body;
    const v = await loginRound('after-recover');
    assert.equal(v.ok, true, JSON.stringify(v));
    assert.equal(v.PPID, PPID1, 'PPID = H(uid, arid, s_u) 는 폐기·복구로 바뀌지 않는다');
  });
} finally {
  await cia.stop();
}
process.exit(failed === 0 ? 0 : 1);
```

- [ ] **Step 2: 실행한다**

```bash
node tests/test_mode3_e2e.mjs
```

Expected: 7줄 `ok`. (여기까지 Task 3~5 가 맞으면 새 코드 없이 통과해야 한다. 실패하면 그 자체가 통합 결함이므로 원인을 고친 뒤 해당 태스크의 테스트도 함께 보강한다.)

- [ ] **Step 3: `run_tests.sh` CHAIN 등록 후 chain 그룹 전체를 한 번 돌린다**

```bash
bash scripts/run_tests.sh chain
```

Expected: 기존 4개 + 신규 4개 통과. 끝나고 사용자 포트 4개(3000/4000/5001/8545)가 그대로이고 임시 CIA 프로세스가 남지 않았는지 `ss -ltn` 으로 확인.

- [ ] **Step 4: 설계 문서 갱신**

§6.5 `publishRoot` 블록의 `require(recover(H(DOMAIN, newRoot, epoch), sig) == CIA_KEY)` 를 `require(recover(H(DOMAIN, newRoot, epoch, keccak(newLeaves)), sig) == CIA_KEY)` 로 바꾸고 그 아래에 한 문단: **"서명이 리프 배열까지 덮는다(2026-09-10 구현에서 보강). 제출이 무허가이므로 릴레이어가 서명된 root 에 다른 리프를 붙여 calldata 를 오염시킬 수 있고, 그러면 지갑이 잘못된 트리를 재구성해 root 불일치로 전원이 막힌다. 리프를 서명에 넣으면 그 경로가 닫힌다."**

§12 (a) 목록의 각 항목 앞에 완료 표시(✅)를 붙이고, 항목 뒤에 파일명을 적는다: 발급 PoK → `lib/mode3_issuance.js`, `cia.js`, `RevocationLog` → `contracts/RevocationLog.sol`, RP 로그인 검증 → `lib/mode3_rp.js`, 지갑 → `lib/mode3_wallet.js`, `pk_CIA` 대조 → `lib/mode3_rp.js` d단계 + `tests/test_mode3_rp.mjs`. §9.12 결정 항목은 그대로 둔다(미결).

- [ ] **Step 5: 커밋**

```bash
git add tests/test_mode3_e2e.mjs scripts/run_tests.sh docs/superpowers/specs/2026-09-09-mode3-cia-revocation-design.md
git commit -m "feat(mode3): 전 구간 e2e — 등록·발급·로그인·폐기·거절·복구, 설계 §6.5 root 서명 범위 보강"
```

---

## 완료 기준

- [ ] `bash scripts/run_tests.sh unit` 통과 (기존 7 + `test_mode3_issuance.js`)
- [ ] `bash scripts/run_tests.sh contract` 통과 (기존 + `RevocationLog.test.mjs`)
- [ ] `bash scripts/run_tests.sh chain` 통과 (기존 4 + 신규 4)
- [ ] `bash scripts/run_tests.sh circuit` 여전히 통과 (이 계획은 회로를 건드리지 않는다)
- [ ] Mode 2 파일 무변경 (`git diff --stat <base>..HEAD -- custom_idp.js wallet_agent.js server.js client.js lib/imt_v3.js contracts/PPIDWallet*.sol contracts/RevocationRegistry*.sol` 가 비어 있음)
- [ ] 사용자 프로세스 4개 그대로, 임시 CIA 프로세스·디렉터리 잔존 없음
- [ ] `cia_state.json`/`cia_keys.json` 이 `.gitignore` 에 있고 커밋되지 않음
- [ ] 설계 §6.5 보강, §12 (a) 완료 표시

## 다음

- 데모 UI 연동(지갑 페이지·RP 로그인 버튼) — 별도 계획
- §9.12 결정
- 세션 서명 스킴 재검토(§11)
- Poseidon 전환(§12 보류)
