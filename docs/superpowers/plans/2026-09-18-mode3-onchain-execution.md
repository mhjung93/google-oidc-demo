# Mode 3 온체인 실행 구현 계획

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Mode 3 를 덱(260917_OVERALL)의 온체인 모델로 옮긴다 — 자격증명 V4(`max_height`, `allowAgent`, `r_s` 제거), 트레이스 태그 평문 `Poseidon(uid, arid)`, PPID 계정 컨트랙트(`Mode3Wallet`/`Mode3WalletFactory`/`PiCredVerifier`), `RevocationLog` 하트비트, CIA 상태 v5, 지갑 `POST /wallet/tx`, 서비스의 팩토리 배포·트랜잭션 해시 개봉.

**Architecture:** 회로 하나(`pi_cred` V4, 공개 입력 14개)로 오프체인 로그인과 온체인 실행을 모두 처리한다. 온체인 검증 규칙은 서비스 검증기(`lib/mode3_rp.js`)와 1:1 로 대응하며, 컨트랙트는 `PPIDWallet` 패턴을 따라 새로 둔다(Mode 2 불변). 온체인 유틸(서명·calldata·배포)은 `lib/mode3_onchain.js` 하나에 두고 지갑·서비스·테스트가 공유한다. CIA 는 체인 헤드로 `max_height` 를 양자화해 서명하고, 변화가 없어도 주기적으로 root 를 재게시한다(하트비트).

**Tech Stack:** circom 2.1.9 + circomlib, snarkjs 0.7.5 Groth16, circomlibjs(babyjub·EdDSA-Poseidon·Poseidon), Solidity 0.8.24 + hardhat(viaIR), ethers 6, Node.js ESM, express.

**Spec:** `docs/superpowers/specs/2026-09-18-mode3-onchain-execution-design.md` (이하 "스펙"). 기반: `2026-09-16-mode3-authorized-opening-design.md`, `2026-09-15-mode3-session-statement-design.md`, `2026-09-09-mode3-cia-revocation-design.md`.

## Global Constraints

- 모든 응답·주석·커밋 메시지는 한글(CLAUDE.md). 기존 파일의 주석 문체(한글 설명 + 설계 절 참조)를 유지한다.
- 공개 입력 순서(스펙 §3.5): `[PPID, arid, pk_i, max_height, chainid, allowAgent, revRoot, pk_CIA_x, pk_CIA_y, pk_trace_x, pk_trace_y, tag_c1_x, tag_c1_y, tag_c2]`. 14개. 인덱스 3=max_height, 5=allowAgent, 6=revRoot, 11..13=태그.
- 도메인 상수(스펙 §3.1·§3.3): `DOMAIN_MODE3_CRED_V4 = 93461614427473393731524148n`(ASCII "MODE3CREDV4"), `DOMAIN_MODE3_ISSUEREQ_V2 = 401414577397388343646241740924474930n`(ASCII "MODE3ISSUEREQV2").
- CIA 서명 메시지: `Poseidon(DOMAIN_MODE3_CRED_V4, C, max_height, chainid, allowAgent)`. 발급 요청 서명 메시지: `Poseidon(DOMAIN_MODE3_ISSUEREQ_V2, C_pt.x, C_pt.y, chainid, allowAgent)`.
- 태그(스펙 §3.4): `c1 = r·B8`, `c2 = Poseidon(uid, arid) + Poseidon(K.x, K.y)`, `K = r·pk_trace`, `r ∈ [1, 2^250)`.
- `max_height = ceil((head + CIA_TTL_BLOCKS) / CIA_HEIGHT_GRID) × CIA_HEIGHT_GRID`, 기본 TTL 300·GRID 100(스펙 §3.2). 검증: 컨트랙트 `block.number ≤ max_height`, 서비스 `head ≤ max_height`.
- 개봉 요청 메시지(스펙 §6.2): `mode3-open:${arid}:${PPID}:${c1.x}:${c1.y}:${D_svc.x}:${D_svc.y}:${ts}`. 중복 키 `(arid, c1.x, c1.y)`, pending·approved 만 중복.
- 컨트랙트 검사 순서(스펙 §5.3): nonce → ECDSA → PPID·arid·chainid → pk_CIA·pk_trace → allowAgent ≤ 1 → root == log.root() → root 나이 ≤ maxRootAge → block.number ≤ max_height → Groth16 → nonce++ → call → 이벤트.
- 서명 digest(스펙 §5.3 2): `keccak256(abi.encode(block.chainid, address(this), to, value, data, nonce))`, raw digest 위 secp256k1(EIP-191 없음), v ∈ {27, 28}.
- `.env`, `cia_keys.json`, `cia_state.json`, `mode3_wallet_state.json`, `mode3_rp_registration.json`, `mode3_rp_logins.jsonl` 은 읽거나 출력하거나 고치지 않는다. 테스트는 격리 인스턴스(`tests/helpers/isolated_cia.mjs`, `isolated_mode3_stack.mjs`)만 쓴다.
- 사용자 프로세스(:8545, :4100, :5100, :3100)는 건드리지 않는다. :8545 가 비어 있으면 `npx hardhat node` 를 직접 띄우고 끝나면 내린다.
- `npm run zk:*` 는 실행하지 않는다. Mode 3 회로 산출물은 `bash scripts/build_mode3_circuit.sh` 로만 만든다(`pot21_final.ptau` 존재, 2.4GB).
- Mode 1·Mode 2 파일(`PPIDWallet*.sol`, `RevocationRegistry*.sol`, `wallet_agent.js`, `server.js`, `custom_idp.js`, `test/PPIDWallet*.test.mjs`)은 수정하지 않는다.
- 새 테스트 파일은 `scripts/run_tests.sh` 의 해당 그룹에 넣는다(unit: 외부 의존 없음 / circuit: circom / chain: :8545 / contract: `test/*.test.mjs` 는 자동).
- 커밋은 태스크마다 하나. 메시지 끝에 `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>` 과 `Claude-Session: https://claude.ai/code/session_01LFKj24gQ9a9eWQ1cZFjhX8` 두 줄.

## 파일 구조

| 파일 | 책임 | 태스크 |
|---|---|---|
| `lib/mode3_credential.js` | `DOMAIN_MODE3_CRED_V4`, `credMessage(C, max_height, chainid, allowAgent)` | 1 |
| `lib/mode3_issuance.js` | `DOMAIN_MODE3_ISSUEREQ_V2`, `issueRequestMessage(C_pt, chainid, allowAgent)` | 1 |
| `lib/mode3_trace.js` | `tagPlaintext`, `encryptTag(pk_trace, uid, arid, r)`, `resolveTagPlaintext` | 1 |
| `lib/mode3_opening.js` | 개봉 메시지 V2(`c1` 기반) | 1 |
| `circuits/lib/mode3_trace_tag.circom`, `circuits/pi_cred.circom` | 회로 V4 | 2 |
| `tests/helpers/mode3_fixture.mjs` | V4 입력 픽스처(옵션: `pk_i, maxHeight, allowAgent, chainid`) | 2 |
| `scripts/build_mode3_circuit.sh`, `contracts/PiCredVerifier.sol` | zkey·vkey·검증자 생성 | 2 |
| `contracts/RevocationLog.sol`, `lib/mode3_log.js` | `lastPublishedBlock` | 3 |
| `contracts/Mode3Wallet.sol`, `contracts/Mode3WalletFactory.sol`, `hardhat.config.cjs` | PPID 계정 | 3 |
| `lib/mode3_onchain.js` | ABI·digest·서명·calldata·배포 — 지갑·서비스·테스트 공유 | 3 |
| `test/Mode3Wallet.test.mjs`, `test/RevocationLog.test.mjs` | 컨트랙트 테스트 | 3 |
| `lib/mode3_wallet.js`, `lib/mode3_rp.js` | 발급 요청·증명·검증기 V4 | 4 |
| `lib/mode3_cia_state.js` | CIA 상태 버전·이행(순수 함수) | 5 |
| `cia.js`, `tests/helpers/isolated_cia.mjs` | 발급 V4·체인 헤드·하트비트·개봉 V2 | 5 |
| `mode3_rp.js`, `mode3_wallet_agent.js`, `tests/helpers/isolated_mode3_stack.mjs` | 서버 V4·팩토리 배포·`/wallet/tx`·해시 개봉 | 6 |
| `mode3/wallet.html`, `mode3/rp.html`, `mode3/cia_admin.html`, `docs/MODE3_DEMO.md`, 기반 스펙 §9.11, `scripts/run_tests.sh` | UI·문서 | 7 |

---

### Task 1: 라이브러리 V4 — 서명 메시지·발급 요청 메시지·태그 평문·개봉 메시지

**Files:**
- Modify: `lib/mode3_credential.js:124-134` (`credMessage`), 상수 추가
- Modify: `lib/mode3_issuance.js:138-150` (`issueRequestMessage`), 상수 추가
- Modify: `lib/mode3_trace.js:65-73` (`encryptTag`), 함수 추가
- Modify: `lib/mode3_opening.js:8-10` (`openRequestMessage`)
- Test: `tests/test_mode3_issuance.js:185-191`, `tests/test_mode3_trace.js`, `tests/test_mode3_opening.js`

**Interfaces:**
- Produces: `credMessage(C: bigint, max_height: bigint, chainid: bigint, allowAgent: bigint) → Promise<bigint>`; `DOMAIN_MODE3_CRED_V4`; `MAX_HEIGHT_MAX = 1n << 64n`.
- Produces: `issueRequestMessage(C_pt: {x,y}, chainid: bigint, allowAgent: bigint) → Promise<bigint>`; `DOMAIN_MODE3_ISSUEREQ_V2`.
- Produces: `tagPlaintext(uid, arid) → Promise<bigint>`; `encryptTag(pk_trace, uid, arid, r?) → Promise<{c1, c2, r, h}>`; `resolveTagPlaintext(h: bigint, arid: bigint, uids: string[]) → Promise<string|null>`. `partialDecrypt`·`combineDecrypt` 는 그대로(복호 결과는 `h`).
- Produces: `openRequestMessage({ arid, PPID, c1:{x,y}, D_svc:{x,y}, ts }) → string`.

- [ ] **Step 1: 실패하는 테스트 — issuance**

`tests/test_mode3_issuance.js` 의 185~191행 케이스를 다음으로 바꾼다:

```js
await t('issueRequestMessage 는 (C_pt, chainid, allowAgent) 를 도메인과 함께 덮는다 — 하나라도 다르면 다른 메시지', async () => {
  const C_pt = { x: 1n, y: 2n };
  const m = await issueRequestMessage(C_pt, 31337n, 0n);
  assert.notEqual(m, await issueRequestMessage(C_pt, 1n, 0n));
  assert.notEqual(m, await issueRequestMessage(C_pt, 31337n, 1n));
  assert.notEqual(m, await issueRequestMessage({ x: 1n, y: 3n }, 31337n, 0n));
  // 도메인이 있다 — 옛 형식 Poseidon(C_pt.x, C_pt.y, chainid, x) 와 같은 값이 나오지 않는다
  const ps = await buildPoseidon();
  assert.notEqual(m, ps.F.toObject(ps([1n, 2n, 31337n, 0n])));
  assert.equal(DOMAIN_MODE3_ISSUEREQ_V2, 401414577397388343646241740924474930n);
  await assert.rejects(() => issueRequestMessage(C_pt, 31337n, 2n), /allowAgent/);
});
```

파일 상단 import 에 `DOMAIN_MODE3_ISSUEREQ_V2` 를 추가하고, `buildPoseidon` 이 import 되어 있지 않으면 `import { buildPoseidon } from 'circomlibjs';` 를 추가한다.

- [ ] **Step 2: 실패하는 테스트 — trace**

`tests/test_mode3_trace.js`: import 에 `tagPlaintext, resolveTagPlaintext` 를 추가하고, `const uid = 12345n;` 아래에 `const arid = 22222n;` 를 둔다. `encryptTag(pk, uid)` 호출을 전부 `encryptTag(pk, uid, arid)` 로, `encryptTag(pk, uid, a.r)` 를 `encryptTag(pk, uid, arid, a.r)` 로, `encryptTag(pk, uid, 0n)`/`SCALAR_MAX`/`encryptTag(pk, SCALAR_MAX, 5n)` 를 각각 `encryptTag(pk, uid, arid, 0n)`/`encryptTag(pk, uid, arid, SCALAR_MAX)`/`encryptTag(pk, SCALAR_MAX, arid, 5n)` 로 바꾼다. '양성' 케이스의 두 `assert.equal(await combineDecrypt(...), uid)` 를 다음으로 바꾼다:

```js
  const h = await combineDecrypt(tag.c2, D_svc, D_aa);
  assert.equal(h, tag.h);
  assert.equal(h, await tagPlaintext(uid, arid), '평문은 Poseidon(uid, arid)');
  assert.notEqual(h, uid, 'uid 원문이 아니다');
  assert.equal(await combineDecrypt(tag.c2, D_aa, D_svc), h, '순서 무관');
  assert.equal(await resolveTagPlaintext(h, arid, ['1', '12345', '67890']), '12345');
  assert.equal(await resolveTagPlaintext(h, arid, ['1', '67890']), null);
  assert.equal(await resolveTagPlaintext(h, arid + 1n, ['12345']), null, '다른 arid 의 평문은 같은 uid 로 풀리지 않는다');
```

'음성: 조각 하나' 케이스의 두 `assert.notEqual(..., uid)` 는 `assert.notEqual(..., tag.h)` 로 바꾼다.

- [ ] **Step 3: 실패하는 테스트 — opening**

`tests/test_mode3_opening.js` 의 `fields` 와 첫 케이스를 다음으로 바꾼다:

```js
const fields = { arid: '22222', PPID: '99999', c1: { x: '11', y: '22' }, D_svc: { x: '123', y: '456' }, ts: '1789000000' };

await t('메시지 형식은 스펙(2026-09-18 §6.2) 그대로 — r_s 가 아니라 c1 이 요청을 특정한다', () => {
  assert.equal(openRequestMessage(fields), 'mode3-open:22222:99999:11:22:123:456:1789000000');
  assert.equal(openResultMessage('abcd', '1789000001'), 'mode3-open-result:abcd:1789000001');
});
```

- [ ] **Step 4: 실패 확인**

Run: `node tests/test_mode3_issuance.js; node tests/test_mode3_trace.js; node tests/test_mode3_opening.js`
Expected: 세 파일 모두 FAIL 이 1건 이상(`DOMAIN_MODE3_ISSUEREQ_V2` undefined / `tagPlaintext is not a function` / 메시지 불일치).

- [ ] **Step 5: 구현 — credential**

`lib/mode3_credential.js` 의 `DOMAIN_MODE3_CRED_V3` 선언 아래에 추가:

```js
// 2026-09-18: max_height(블록 높이)·allowAgent 로 바뀐 V4. r_s 는 서명에서 빠졌다(설계 2026-09-18 §2 — 온체인 공개 입력은 AA 도 본다).
export const DOMAIN_MODE3_CRED_V4 = 93461614427473393731524148n; // ASCII "MODE3CREDV4" 빅엔디언
export const MAX_HEIGHT_MAX = 1n << 64n;   // 회로 Num2Bits(64) 와 같은 상한
```

`credMessage` 를 통째로 교체:

```js
// circuits/pi_cred.circom 의 msgHasher(DOMAIN_MODE3_CRED_V4, C, max_height, chainid, allowAgent 순서)와
// 일치해야 한다. max_height 는 블록 높이(설계 2026-09-18 §3.2), chainid 는 폐기 체인 id, allowAgent ∈ {0, 1}(§3.1).
export async function credMessage(C, max_height, chainid, allowAgent) {
  for (const [k, v] of [['max_height', max_height], ['chainid', chainid], ['allowAgent', allowAgent]]) {
    if (typeof v !== 'bigint' || v < 0n) throw new Error(`credMessage: ${k} 는 음이 아닌 bigint 여야 한다`);
  }
  if (max_height >= MAX_HEIGHT_MAX) throw new Error('credMessage: max_height 는 2^64 미만이어야 한다 (회로 Num2Bits(64))');
  if (allowAgent > 1n) throw new Error('credMessage: allowAgent 는 0 또는 1 이어야 한다');
  const poseidon = await getPoseidon();
  return poseidon.F.toObject(poseidon([DOMAIN_MODE3_CRED_V4, C, max_height, chainid, allowAgent]));
}
```

- [ ] **Step 6: 구현 — issuance**

`lib/mode3_issuance.js` 의 `DOMAIN_MODE3_ISSUE` 아래에:

```js
// 발급 요청 서명 메시지의 도메인(설계 2026-09-18 §3.3). 옛 메시지 Poseidon(C_pt.x, C_pt.y, chainid, r_s) 에는 도메인이 없었다.
export const DOMAIN_MODE3_ISSUEREQ_V2 = 401414577397388343646241740924474930n;   // ASCII "MODE3ISSUEREQV2"
```

`issueRequestMessage` 를 교체:

```js
/**
 * 발급 요청의 사용자 서명 메시지 = Poseidon(DOMAIN_MODE3_ISSUEREQ_V2, C_pt.x, C_pt.y, chainid, allowAgent)
 * (설계 2026-09-18 §3.3). r_s 는 빠졌다 — 재생으로 얻는 자격증명은 같은 C_pt 에 묶여 sk_i 없이는 쓸 수 없다.
 * 지갑의 signUserRequest 와 CIA 의 검증이 이 함수 하나를 공유한다 — 회로에는 들어가지 않는다.
 */
export async function issueRequestMessage(C_pt, chainid, allowAgent) {
  for (const [k, v] of [['chainid', chainid], ['allowAgent', allowAgent]]) {
    if (typeof v !== 'bigint' || v < 0n) throw new Error(`issueRequestMessage: ${k} 는 음이 아닌 bigint 여야 한다`);
  }
  if (allowAgent > 1n) throw new Error('issueRequestMessage: allowAgent 는 0 또는 1 이어야 한다');
  const ps = await getPs();
  return ps.F.toObject(ps([DOMAIN_MODE3_ISSUEREQ_V2, C_pt.x, C_pt.y, chainid, allowAgent]));
}
```

- [ ] **Step 7: 구현 — trace**

`lib/mode3_trace.js` 상단 주석의 `c2 = uid + Poseidon(K.x, K.y)` 를 `c2 = Poseidon(uid, arid) + Poseidon(K.x, K.y)  (평문 h — 2026-09-18 §3.4)` 로 고친다. `encryptTag` 를 교체하고 두 함수를 추가:

```js
/** 태그 평문 h = Poseidon(uid, arid) — 설계 2026-09-18 §3.4. 회로 TraceTag 와 같은 계산. 복호해도 uid 원문이 아니라 서비스별 값이 나온다. */
export async function tagPlaintext(uid, arid) {
  checkScalar(uid, 'uid'); checkScalar(arid, 'arid');
  const ps = await getPs();
  return ps.F.toObject(ps([uid, arid]));
}

export async function encryptTag(pk_trace, uid, arid, r = randomTraceScalar()) {
  const h = await tagPlaintext(uid, arid);
  if (typeof r !== 'bigint' || r <= 0n || r >= SCALAR_MAX) throw new Error('r 는 [1, 2^250) bigint');
  const bj = await getBj();
  const c1 = toObj(bj, bj.mulPointEscalar(bj.Base8, r));
  const K = toObj(bj, bj.mulPointEscalar(fromObj(bj, pk_trace), r));
  const c2 = (h + await maskOf(K)) % bj.F.p;
  return { c1, c2, r, h };
}

/** 복호 결과 h 를 등록부의 uid(10진 문자열 배열)로 되돌린다. 없으면 null. 데모 등록부는 작아 단순 반복한다 — 호출자가 arid 별로 캐시해도 된다. */
export async function resolveTagPlaintext(h, arid, uids) {
  for (const u of uids) if ((await tagPlaintext(BigInt(u), arid)) === h) return u;
  return null;
}
```

- [ ] **Step 8: 구현 — opening**

`lib/mode3_opening.js` 의 `openRequestMessage` 를 교체:

```js
/** 설계 2026-09-18 §6.2 — r_s 대신 태그의 c1 이 요청을 특정한다(온체인 트랜잭션에는 r_s 가 없다). */
export function openRequestMessage({ arid, PPID, c1, D_svc, ts }) {
  return `mode3-open:${arid}:${PPID}:${c1.x}:${c1.y}:${D_svc.x}:${D_svc.y}:${ts}`;
}
```

- [ ] **Step 9: 통과 확인**

Run: `node tests/test_mode3_issuance.js && node tests/test_mode3_trace.js && node tests/test_mode3_opening.js`
Expected: 세 파일 모두 `FAIL` 0. (다른 unit 테스트 `tests/test_mode3_rp_cert.js`, `tests/test_mode3_revocation_tree.js` 도 그대로 통과해야 한다: `bash scripts/run_tests.sh unit`.)

- [ ] **Step 10: 커밋**

```bash
git add lib/mode3_credential.js lib/mode3_issuance.js lib/mode3_trace.js lib/mode3_opening.js tests/test_mode3_issuance.js tests/test_mode3_trace.js tests/test_mode3_opening.js
git commit -m "feat(mode3): 라이브러리 V4 — 서명 메시지(max_height·allowAgent), 발급 요청 도메인, 태그 평문 Poseidon(uid, arid), 개봉 메시지 c1"
```

---

### Task 2: 회로 V4, 픽스처, zkey·vkey·검증자 컨트랙트 생성

**Files:**
- Modify: `circuits/lib/mode3_trace_tag.circom`
- Modify: `circuits/pi_cred.circom`
- Modify: `tests/helpers/mode3_fixture.mjs`
- Modify: `tests/test_pi_cred_witness.mjs`
- Modify: `scripts/build_mode3_circuit.sh`
- Create(생성물): `contracts/PiCredVerifier.sol`

**Interfaces:**
- Consumes: Task 1 의 `credMessage`, `encryptTag(pk_trace, uid, arid, r)`, `tagPlaintext`, `resolveTagPlaintext`.
- Produces: `buildValidInput({ pk_i?, maxHeight?, allowAgent?, chainid? } = {}) → { input, C, pk_trace, shares, tag, ciaPub:{x,y}, arid, uid }` — 컨트랙트 테스트(Task 3)와 witness 테스트가 쓴다. `input` 의 공개 입력 키: `PPID, arid, pk_i, max_height, chainid, allowAgent, revRoot, pk_CIA_x, pk_CIA_y, pk_trace_x, pk_trace_y, tag_c1_x, tag_c1_y, tag_c2`.
- Produces: `build/mode3/pi_cred_final.zkey`, `pi_cred_vkey.json`(nPublic 14), `pi_cred_js/pi_cred.wasm`, `contracts/PiCredVerifier.sol`(`contract PiCredVerifier`, `verifyProof(uint[2],uint[2][2],uint[2],uint[14]) view returns (bool)`).

- [ ] **Step 1: 픽스처를 V4 로**

`tests/helpers/mode3_fixture.mjs` 를 다음으로 교체:

```js
// pi_cred 회로용 공유 입력 픽스처 (V4 — 설계 2026-09-18 §3.5).
// tests/test_pi_cred_witness.mjs, scripts/bench_pi_cred.mjs, test/Mode3Wallet.test.mjs 가 같은 입력 생성기를 쓴다.
import { buildPoseidon, buildEddsa, buildBabyjub } from 'circomlibjs';
import { credLeaf, createRevocationTree } from '../../lib/mode3_revocation.js';
import { credCommit, credMessage, ppid as computePpid } from '../../lib/mode3_credential.js';
import { combinePublicKey, encryptTag } from '../../lib/mode3_trace.js';

// --- 정상 입력 하나를 만든다 -------------------------------------------------
// 옵션은 컨트랙트 테스트용이다: pk_i 는 실제 세션키의 주소, maxHeight 는 만료 케이스, allowAgent 는 플래그 케이스.
export async function buildValidInput({ pk_i: pkIOpt, maxHeight = 1789000000n, allowAgent = 0n, chainid = 31337n } = {}) {
  const poseidon = await buildPoseidon();
  const F = poseidon.F;
  const eddsa = await buildEddsa();

  const uid   = 11111111111111111111n;
  const arid  = 22222222222222222222n;
  const s_u   = 33333333333333333333n;
  const blind = 44444444444444444444n;
  const pk_i  = pkIOpt ?? 0x1234567890123456789012345678901234567890n; // 160비트
  const attrs = [19n, 410n, 0n, 0n];
  const max_height = maxHeight;   // 블록 높이. 회로는 값만 통과시키고 검증자가 비교한다(§3.2)

  // 트레이스 태그(설계 2026-09-16 §4.1, 평문은 2026-09-18 §3.4). 조각은 테스트 고정값 — 실제 키가 아니다. r 도 고정.
  const bj = await buildBabyjub();
  const shareOf = (x) => ({ x, X: { x: bj.F.toObject(bj.mulPointEscalar(bj.Base8, x)[0]), y: bj.F.toObject(bj.mulPointEscalar(bj.Base8, x)[1]) } });
  const shares = { svc: shareOf(66666666666666666666n), aa: shareOf(77777777777777777777n) };
  const pk_trace = await combinePublicKey(shares.svc.X, shares.aa.X);
  const tag = await encryptTag(pk_trace, uid, arid, 88888888888888888888n);

  // 스칼라는 2^250 미만이어야 한다(회로 Num2Bits(250), lib/mode3_credential.js 의 SCALAR_MAX).
  const { Cf: C } = await credCommit({ uid, arid, s_u, blind, pk_i, attrs });
  const PPID = await computePpid({ uid, arid, s_u, chainid });
  const msg = await credMessage(C, max_height, chainid, allowAgent);

  // CIA 서명키. 테스트 고정값이며 실제 키가 아니다.
  const prv = Buffer.from('0001020304050607080900010203040506070809000102030405060708090001', 'hex');
  const pub = eddsa.prv2pub(prv);
  const sig = eddsa.signPoseidon(prv, F.e(msg));
  const ciaPub = { x: F.toObject(pub[0]), y: F.toObject(pub[1]) };

  // 폐기 트리에 남의 폐기를 하나 넣어 둔다 — 내 비멤버십은 여전히 성립해야 한다.
  const tree = await createRevocationTree();
  await tree.insert(await credLeaf(999n));
  const w = await tree.getNonMembershipWitness(await credLeaf(C));

  const input = {
    uid: uid.toString(), s_u: s_u.toString(), blind: blind.toString(), attrs: attrs.map(String),
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

  return { input, C, pk_trace, shares, tag, ciaPub, arid, uid, tree };
}
```

- [ ] **Step 2: witness 테스트를 V4 로**

`tests/test_pi_cred_witness.mjs`:
- import 에 `import { partialDecrypt, combineDecrypt, resolveTagPlaintext } from '../lib/mode3_trace.js';` (기존 줄 교체).
- `const { input: valid, C: validC, shares, tag } = await buildValidInput();` 를 `const { input: valid, C: validC, shares, tag, arid: validArid } = await buildValidInput();` 로.
- '음성: exptime 을 바꾸면' 케이스를 교체:

```js
await t('음성: max_height 를 바꾸면 거부된다 (서명이 max_height 를 덮는다)', async () => {
  await assert.rejects(() => witness({ ...valid, max_height: (BigInt(valid.max_height) + 1n).toString() }), /Assert Failed/);
});
```

- '음성: r_s 를 바꾸면' 케이스를 교체:

```js
await t('음성: allowAgent 를 뒤집으면 거부된다 (서명이 allowAgent 를 덮는다), 2 는 불리언 제약에서 거부된다', async () => {
  await assert.rejects(() => witness({ ...valid, allowAgent: '1' }), /Assert Failed/);
  await assert.rejects(() => witness({ ...valid, allowAgent: '2' }), /Assert Failed/);
});

await t('양성: allowAgent = 1 로 서명한 자격증명은 통과한다', async () => {
  const { input } = await buildValidInput({ allowAgent: 1n });
  const w = await witness(input);
  assert.ok(w.length > 0);
});
```

- '⑤ 양성' 케이스의 마지막 단언을 교체:

```js
  const h = await combineDecrypt(tag.c2, D_svc, D_aa);
  assert.equal(h, tag.h, '복호 결과는 Poseidon(uid, arid)');
  assert.equal(await resolveTagPlaintext(h, validArid, ['1', valid.uid]), valid.uid);
```

- '⑤ 음성: c2' 케이스 이름 뒤에 "(평문이 커밋 안의 uid·공개 입력 arid 의 Poseidon 과 다르다)" 로 문구만 고친다.
- 마지막 `console.log` 의 참고값 줄 아래에 `console.log('   (V3 2026-09-16: 25,505)')` 를 추가한다.

- [ ] **Step 3: 실패 확인**

Run: `node tests/test_pi_cred_witness.mjs`
Expected: 컴파일은 되지만 `Signal not found: max_height`(또는 `allowAgent`) 로 양성 케이스 FAIL.

- [ ] **Step 4: 회로 — TraceTag 에 arid**

`circuits/lib/mode3_trace_tag.circom` 의 template 을 교체(파일 상단 주석의 `c2 = uid + Poseidon(K.x, K.y)` 는 `c2 = Poseidon(uid, arid) + Poseidon(K.x, K.y)` 로, "평문 uid 는" 문장은 "평문 h = Poseidon(uid, arid) 의 uid 는" 으로 고친다):

```circom
template TraceTag() {
    signal input r;
    signal input uid;
    signal input arid;
    signal input pk_trace_x;
    signal input pk_trace_y;
    signal output c1x;
    signal output c1y;
    signal output c2;

    var N = 250;
    var BASE8[2] = [
        5299619240641551281634865583518297030282874472190772894086521144482721001553,
        16950150798460657717958625567821834550301663161624707787222815936182638968203
    ];

    component bits = Num2Bits(N);
    bits.in <== r;

    component mFix = EscalarMulFix(N, BASE8);
    component mAny = EscalarMulAny(N);
    for (var i = 0; i < N; i++) {
        mFix.e[i] <== bits.out[i];
        mAny.e[i] <== bits.out[i];
    }
    mAny.p[0] <== pk_trace_x;
    mAny.p[1] <== pk_trace_y;

    c1x <== mFix.out[0];
    c1y <== mFix.out[1];

    // 평문 h = Poseidon(uid, arid) — 설계 2026-09-18 §3.4. JS 판은 lib/mode3_trace.js 의 tagPlaintext().
    component h = Poseidon(2);
    h.inputs[0] <== uid;
    h.inputs[1] <== arid;

    component mask = Poseidon(2);
    mask.inputs[0] <== mAny.out[0];
    mask.inputs[1] <== mAny.out[1];
    c2 <== h.out + mask.out;
}
```

- [ ] **Step 5: 회로 — pi_cred V4**

`circuits/pi_cred.circom` 에서:
- 상단 주석: `① CIA가 (C, exptime, chainid, r_s)에 서명했다` → `① CIA가 (C, max_height, chainid, allowAgent)에 서명했다`; `r_s 는 서비스가 …` 로 시작하는 두 줄을 다음으로 교체: `//   r_s 는 더 이상 서명·공개 입력에 없다(설계 2026-09-18 §2) — 온체인 공개 입력은 AA 도 보므로 AA 가 발급 때 본 값을 두지 않는다.` / `//   allowAgent ∈ {0,1} 은 AA 속성이다(2026-09-18 §3.1) — 서명이 덮고, 공개 입력으로 나가 온체인 이벤트·개봉 결과에 남는다.`
- 설계 참조 줄 아래에 `// V4(max_height·allowAgent, 태그 평문 Poseidon(uid, arid)): docs/superpowers/specs/2026-09-18-mode3-onchain-execution-design.md §3` 추가.
- 공개 입력 선언 `signal input exptime;` → `signal input max_height;`, `signal input r_s;` → `signal input allowAgent;`.
- `var DOMAIN_MODE3_CRED_V3 = …` → `var DOMAIN_MODE3_CRED_V4 = 93461614427473393731524148;  // ASCII "MODE3CREDV4"`.
- ① 블록을 교체:

```circom
    // ---- ① CIA 서명 검증 ----
    // max_height 는 2^64 미만(컨트랙트 uint64 비교와 맞춘다), allowAgent 는 불리언.
    component mhRange = Num2Bits(64);
    mhRange.in <== max_height;
    allowAgent * (allowAgent - 1) === 0;
    component msgHasher = Poseidon(5);
    msgHasher.inputs[0] <== DOMAIN_MODE3_CRED_V4;
    msgHasher.inputs[1] <== Cf;
    msgHasher.inputs[2] <== max_height;
    msgHasher.inputs[3] <== chainid;
    msgHasher.inputs[4] <== allowAgent;
```
  (그 아래 `sigVerifier` 블록은 그대로.)
- ⑤ 블록에 `tag.arid <== arid;` 를 `tag.uid <== uid;` 다음 줄에 추가. 주석 "uid 는 ② 의 커밋 개봉과 …" 뒤에 "평문은 Poseidon(uid, arid) 다 — 태그를 열면 이 성명의 (uid, arid) 값이 나오고 CIA 가 등록부로 uid 를 되찾는다(2026-09-18 §6.2)." 추가.
- `component main {public [...]}` 을 교체:

```circom
component main {public [
    PPID, arid, pk_i, max_height, chainid, allowAgent, revRoot, pk_CIA_x, pk_CIA_y,
    pk_trace_x, pk_trace_y, tag_c1_x, tag_c1_y, tag_c2
]} = PiCred(32);
```
- 그 위 주석의 "공개 입력의 순서는 …" 에 `contracts/Mode3Wallet.sol` 을 의존 목록에 추가.

- [ ] **Step 6: witness 테스트 통과 확인**

Run: `node tests/test_pi_cred_witness.mjs`
Expected: 전부 `ok`, 마지막에 `## pi_cred 비선형 제약: 25,7xx` 근처(25,505 + Poseidon(2) 하나 ≈ 240). 수치를 보고서에 적는다.

- [ ] **Step 7: 빌드 스크립트에 검증자 export 추가**

`scripts/build_mode3_circuit.sh` 의 `npx snarkjs zkey export verificationkey …` 줄 다음에:

```bash
echo "=== solidity verifier ==="
# snarkjs 0.7 템플릿의 컨트랙트 이름은 Groth16Verifier 다 — 저장소 관례(PiPkIVerifier)대로 회로 이름으로 바꾼다.
npx snarkjs zkey export solidityverifier "$OUT/pi_cred_final.zkey" contracts/PiCredVerifier.sol
sed -i -E 's/contract (Groth16Verifier|Verifier) /contract PiCredVerifier /' contracts/PiCredVerifier.sol
grep -q 'contract PiCredVerifier' contracts/PiCredVerifier.sol || { echo "PiCredVerifier 이름 치환 실패" >&2; exit 1; }
```

마지막 `echo "완료: …"` 에 `, contracts/PiCredVerifier.sol` 을 덧붙인다.

- [ ] **Step 8: zkey·vkey·검증자 생성**

Run: `bash scripts/build_mode3_circuit.sh` (수 분. `pot21_final.ptau` 2.4GB 를 읽는다.)
Expected: `완료: build/mode3/pi_cred_final.zkey, …, contracts/PiCredVerifier.sol`.
확인: `node -e "console.log(JSON.parse(require('fs').readFileSync('build/mode3/pi_cred_vkey.json','utf8')).nPublic)"` → `14`; `grep -c 'uint\[14\]' contracts/PiCredVerifier.sol` → 1 이상; `npx hardhat compile` 이 에러 없이 끝난다.

- [ ] **Step 9: 증명 생성·검증 실측(보고용)**

Run:
```bash
node --input-type=module -e "
import * as snarkjs from 'snarkjs'; import fs from 'node:fs'; import { buildValidInput } from './tests/helpers/mode3_fixture.mjs';
const { input } = await buildValidInput(); const vkey = JSON.parse(fs.readFileSync('build/mode3/pi_cred_vkey.json','utf8'));
const P=[],V=[]; for (let i=0;i<5;i++){ const a=performance.now(); const {proof,publicSignals}=await snarkjs.groth16.fullProve(input,'build/mode3/pi_cred_js/pi_cred.wasm','build/mode3/pi_cred_final.zkey'); const b=performance.now(); if(!(await snarkjs.groth16.verify(vkey,publicSignals,proof))) throw new Error('verify'); P.push(b-a); V.push(performance.now()-b); }
const med=(x)=>x.sort((a,b)=>a-b)[Math.floor(x.length/2)]; console.log('prove ms median', med(P).toFixed(0), 'verify ms median', med(V).toFixed(1), 'zkey bytes', fs.statSync('build/mode3/pi_cred_final.zkey').size); process.exit(0);"
```
Expected: 검증 통과, 수치 출력. 보고서에 적는다(스펙 §8 실측 자리).

- [ ] **Step 10: 커밋**

`build/` 는 gitignore 대상이다 — `git status` 에 `build/` 가 나오지 않는지 확인한 뒤:

```bash
git add circuits/lib/mode3_trace_tag.circom circuits/pi_cred.circom tests/helpers/mode3_fixture.mjs tests/test_pi_cred_witness.mjs scripts/build_mode3_circuit.sh contracts/PiCredVerifier.sol
git commit -m "feat(mode3): 회로 V4 — max_height·allowAgent 서명, 태그 평문 Poseidon(uid, arid), PiCredVerifier 생성"
```

---

### Task 3: 컨트랙트 — RevocationLog 하트비트 필드, Mode3Wallet, Mode3WalletFactory, lib/mode3_onchain.js

**Files:**
- Modify: `contracts/RevocationLog.sol` (필드·생성자·publishRoot)
- Modify: `lib/mode3_log.js:9-14` (`LOG_ABI`)
- Create: `contracts/Mode3Wallet.sol`, `contracts/Mode3WalletFactory.sol`
- Modify: `hardhat.config.cjs` (overrides 에 두 파일 추가)
- Create: `lib/mode3_onchain.js`
- Create: `test/Mode3Wallet.test.mjs`
- Modify: `test/RevocationLog.test.mjs` (케이스 1개 추가)

**Interfaces:**
- Consumes: Task 2 의 `buildValidInput(opts)`, `build/mode3/*`, `contracts/PiCredVerifier.sol`; `lib/mode3_log.js` 의 `signRootPublication`, `rootToBytes32`.
- Produces(Solidity): `Mode3Wallet.execute(Payload, bytes sig, uint[2] a, uint[2][2] b, uint[2] c, uint[14] pub) returns (bool)`, `nonce()`, 이벤트 `Executed`, `Mode3Auth`; `Mode3WalletFactory(address verifier, uint256 arid, uint256 pkCIAX, uint256 pkCIAY, uint256 pkTraceX, uint256 pkTraceY, address log, uint64 maxRootAge)`, `computeAddress(uint256)`, `deploy(uint256)`; `RevocationLog.lastPublishedBlock() → uint64`.
- Produces(JS, `lib/mode3_onchain.js`): `WALLET_ABI`, `FACTORY_ABI`, `walletInterface`, `MAX_ROOT_AGE_DEFAULT = 100n`, `payloadDigest({chainId, wallet, to, value, data, nonce}) → hex`, `signPayload(sessionWallet, fields) → hex(65B)`, `proofToCalldata(proof, publicSignals) → {a, b, c, pub}`, `decodeExecuteCalldata(data) → {payload, sig, a, b, c, pub: string[14]}|null`, `parseExecuteReceipt(receipt) → {executed, auth}`, `readArtifact(name)`, `deployVerifier(signer) → address`, `deployFactory(signer, {verifierAddress, arid, pkCIA, pkTrace, logAddress, maxRootAge}) → address`, `factoryAt(address, runner)`, `walletAt(address, runner)`.

- [ ] **Step 1: RevocationLog 테스트 추가(실패)**

`test/RevocationLog.test.mjs` 의 `'초기 상태'` 케이스 뒤에:

```js
  it('lastPublishedBlock: 배포 블록으로 시작하고 publishRoot 마다 그 블록으로 갱신된다 (하트비트 근거, 2026-09-18 §5.1)', async () => {
    const deployed = await log.lastPublishedBlock();
    expect(deployed).to.equal(BigInt(await ethers.provider.getBlockNumber()));
    await ethers.provider.send('hardhat_mine', ['0x5']);
    expect(await log.lastPublishedBlock()).to.equal(deployed, '게시 없이는 바뀌지 않는다');
    // 같은 root 를 새 epoch 로 다시 게시(하트비트) — 리프 없이도 갱신된다
    const sig = await signPub(cia, emptyRoot, 1n, []);
    await log.publishRoot(emptyRoot, 1n, [], sig);
    expect(await log.lastPublishedBlock()).to.equal(BigInt(await ethers.provider.getBlockNumber()));
    expect(await log.root()).to.equal(emptyRoot);
  });
```

- [ ] **Step 2: RevocationLog 구현**

`contracts/RevocationLog.sol`:
- `uint64 public epoch;` 아래에 `uint64 public lastPublishedBlock;   // publishRoot 가 성공한 마지막 블록. 지갑 컨트랙트가 root 의 나이를 잰다(2026-09-18 §5.1)`.
- 생성자 끝에 `lastPublishedBlock = uint64(block.number);`.
- `publishRoot` 의 `epoch = newEpoch;` 아래에 `lastPublishedBlock = uint64(block.number);`.
- 파일 상단 주석에 한 줄: `///   2026-09-18: lastPublishedBlock 추가. 같은 root 를 새 epoch 로 재게시하는 하트비트가 이 값을 갱신한다 — 컨트랙트 조건(epoch 증가)은 그대로다.`

`lib/mode3_log.js` 의 `LOG_ABI` 에 `'function lastPublishedBlock() view returns (uint64)',` 추가.

- [ ] **Step 3: RevocationLog 테스트 통과 확인**

Run: `npx hardhat test test/RevocationLog.test.mjs`
Expected: 전부 passing(새 케이스 포함).

- [ ] **Step 4: Mode3Wallet.sol**

`contracts/Mode3Wallet.sol` 생성:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./PiCredVerifier.sol";
import "./RevocationLog.sol";

/// @title Mode 3 PPID 계정 — 설계 2026-09-18 §5.3
/// @notice PPIDWallet(Mode 2)과 같은 구조다. 다른 점: 검증자가 pi_cred(공개 입력 14개), 폐기 근거가 RevocationLog(root + 게시 블록),
///   성명의 arid·pk_CIA·pk_trace 를 immutable 로 고정한다(서비스 검증기 lib/mode3_rp.js 의 d 단계와 같다), 트레이스 태그와
///   allowAgent 를 이벤트로 남긴다. 검사 순서는 싼 것부터다(§5.3).
contract Mode3Wallet {
    uint256 public immutable ppid;
    uint256 public immutable arid;
    uint256 public immutable pkCIAX;
    uint256 public immutable pkCIAY;
    uint256 public immutable pkTraceX;
    uint256 public immutable pkTraceY;
    PiCredVerifier public immutable verifier;
    RevocationLog public immutable log;
    uint64 public immutable maxRootAge;   // 블록. root 가 이보다 오래됐으면 CIA 가 죽었거나 withholding 이다 — fail-closed
    uint256 public nonce;

    struct Payload {
        address to;
        uint256 value;
        bytes data;
        uint256 nonce;
    }

    error NonceMismatch(uint256 expected, uint256 got);
    error BadSignature();
    error WrongWallet();
    error UntrustedKeys();
    error BadAllowAgent();
    error StaleRevocationRoot(bytes32 root);
    error RootTooOld(uint256 lastPublished, uint256 current);
    error Expired(uint256 currentBlock, uint256 maxHeight);
    error InvalidProof();

    /// @dev 내부 호출의 성공 여부는 영수증에 남지 않으므로 이벤트로 낸다(PPIDWallet 과 같은 이유).
    event Executed(uint256 indexed nonceUsed, address indexed to, uint256 value, bool success);
    /// @dev 서비스가 개봉 재료를 체인에서 바로 읽을 수 있게 태그·플래그를 남긴다. calldata 에도 있지만 이벤트가 조회하기 쉽다.
    event Mode3Auth(uint256 indexed nonceUsed, uint256 pk_i, uint256 maxHeight, uint256 allowAgent,
                    uint256 tagC1X, uint256 tagC1Y, uint256 tagC2);

    constructor(
        uint256 _ppid, uint256 _arid,
        uint256 _pkCIAX, uint256 _pkCIAY, uint256 _pkTraceX, uint256 _pkTraceY,
        address _verifier, address _log, uint64 _maxRootAge
    ) {
        ppid = _ppid; arid = _arid;
        pkCIAX = _pkCIAX; pkCIAY = _pkCIAY; pkTraceX = _pkTraceX; pkTraceY = _pkTraceY;
        verifier = PiCredVerifier(_verifier);
        log = RevocationLog(_log);
        maxRootAge = _maxRootAge;
    }

    /// @param pub 공개 입력 14개(circuits/pi_cred.circom 의 순서):
    ///   [0] PPID [1] arid [2] pk_i [3] max_height [4] chainid [5] allowAgent [6] revRoot
    ///   [7] pk_CIA_x [8] pk_CIA_y [9] pk_trace_x [10] pk_trace_y [11] tag_c1_x [12] tag_c1_y [13] tag_c2
    function execute(
        Payload calldata payload,
        bytes calldata sig,
        uint[2] calldata a,
        uint[2][2] calldata b,
        uint[2] calldata c,
        uint[14] calldata pub
    ) external returns (bool ok) {
        if (payload.nonce != nonce) revert NonceMismatch(nonce, payload.nonce);

        // 서명은 이 체인과 이 지갑에 묶인다(PPIDWallet 과 같은 도메인 분리). 같은 팩토리를 두 체인에 배포해도
        // PPID 가 chainid 를 포함해 주소가 다르지만, 서명까지 묶어 두는 편이 싸고 안전하다.
        bytes32 payloadHash = keccak256(
            abi.encode(block.chainid, address(this), payload.to, payload.value, payload.data, payload.nonce)
        );
        address recovered = _recover(payloadHash, sig);
        // ecrecover 는 잘못된 서명에 address(0) 을 돌려준다. 회로는 pk_i < 2^160 만 제약하므로 pk_i = 0 인
        // 성명이 있을 수 있고, 그때 비교가 공허하게 통과하지 않도록 0 을 먼저 거른다.
        if (recovered == address(0)) revert BadSignature();
        if (recovered != address(uint160(pub[2]))) revert BadSignature();

        _checkStatement(pub);
        if (!verifier.verifyProof(a, b, c, pub)) revert InvalidProof();

        // 검증 통과 후 실행 결과와 무관하게 nonce 를 올린다 — 실패한 payload 의 재생을 막는다.
        nonce += 1;
        (ok, ) = payload.to.call{value: payload.value}(payload.data);
        emit Executed(payload.nonce, payload.to, payload.value, ok);
        emit Mode3Auth(payload.nonce, pub[2], pub[3], pub[5], pub[11], pub[12], pub[13]);
    }

    /// @dev 성명의 공개 입력을 이 지갑의 고정값·체인 상태와 대조한다. 순서는 설계 §5.3 의 3~8.
    function _checkStatement(uint[14] calldata pub) internal view {
        if (pub[0] != ppid || pub[1] != arid || pub[4] != block.chainid) revert WrongWallet();
        if (pub[7] != pkCIAX || pub[8] != pkCIAY || pub[9] != pkTraceX || pub[10] != pkTraceY) revert UntrustedKeys();
        if (pub[5] > 1) revert BadAllowAgent();
        bytes32 root = bytes32(pub[6]);
        if (root != log.root()) revert StaleRevocationRoot(root);          // N=1: 최신 root 만
        uint256 last = log.lastPublishedBlock();
        if (block.number - last > maxRootAge) revert RootTooOld(last, block.number);
        if (block.number > pub[3]) revert Expired(block.number, pub[3]);
    }

    function _recover(bytes32 hash, bytes calldata sig) internal pure returns (address) {
        if (sig.length != 65) revert BadSignature();
        bytes32 r = bytes32(sig[0:32]);
        bytes32 s = bytes32(sig[32:64]);
        uint8 v = uint8(sig[64]);
        return ecrecover(hash, v, r, s);
    }

    receive() external payable {}
}
```

- [ ] **Step 5: Mode3WalletFactory.sol**

`contracts/Mode3WalletFactory.sol` 생성:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./Mode3Wallet.sol";

/// @title Mode 3 PPID 계정 팩토리 — 설계 2026-09-18 §5.4. 서비스마다 하나(arid·pk_trace 가 박힌다).
/// @notice 주소 = CREATE2(salt = PPID). PPID 가 chainid 를 포함하므로 같은 팩토리를 다른 체인에 배포해도 계정은 체인마다 다르다.
contract Mode3WalletFactory {
    address public immutable verifier;
    uint256 public immutable arid;
    uint256 public immutable pkCIAX;
    uint256 public immutable pkCIAY;
    uint256 public immutable pkTraceX;
    uint256 public immutable pkTraceY;
    address public immutable log;
    uint64 public immutable maxRootAge;

    constructor(
        address _verifier, uint256 _arid,
        uint256 _pkCIAX, uint256 _pkCIAY, uint256 _pkTraceX, uint256 _pkTraceY,
        address _log, uint64 _maxRootAge
    ) {
        verifier = _verifier; arid = _arid;
        pkCIAX = _pkCIAX; pkCIAY = _pkCIAY; pkTraceX = _pkTraceX; pkTraceY = _pkTraceY;
        log = _log; maxRootAge = _maxRootAge;
    }

    function _initCode(uint256 ppid) internal view returns (bytes memory) {
        return abi.encodePacked(
            type(Mode3Wallet).creationCode,
            abi.encode(ppid, arid, pkCIAX, pkCIAY, pkTraceX, pkTraceY, verifier, log, maxRootAge)
        );
    }

    function computeAddress(uint256 ppid) public view returns (address) {
        return address(uint160(uint256(keccak256(
            abi.encodePacked(bytes1(0xff), address(this), bytes32(ppid), keccak256(_initCode(ppid)))
        ))));
    }

    function deploy(uint256 ppid) external returns (address wallet) {
        wallet = computeAddress(ppid);
        if (wallet.code.length > 0) return wallet;
        Mode3Wallet deployed = new Mode3Wallet{salt: bytes32(ppid)}(
            ppid, arid, pkCIAX, pkCIAY, pkTraceX, pkTraceY, verifier, log, maxRootAge
        );
        require(address(deployed) == wallet, "CREATE2 address mismatch");
    }
}
```

- [ ] **Step 6: hardhat.config.cjs overrides**

`overrides` 객체의 `"contracts/PPIDWalletFactoryV3.sol"` 항목 뒤에(같은 이유 — execute 가 스택 한도를 넘고, 팩토리가 지갑을 import 하므로 같은 설정이어야 CREATE2 주소가 일치한다):

```js
      "contracts/Mode3Wallet.sol": {
        version: "0.8.24",
        settings: WALLET_IR_SETTINGS,
      },
      "contracts/Mode3WalletFactory.sol": {
        version: "0.8.24",
        settings: WALLET_IR_SETTINGS,
      },
```

Run: `npx hardhat compile`
Expected: `Compiled N Solidity files successfully`. "stack too deep" 가 나오면 `_checkStatement` 분리가 유지됐는지 확인한다.

- [ ] **Step 7: lib/mode3_onchain.js**

```js
// Mode 3 온체인 실행 유틸 — 설계 2026-09-18 §5·§6. 지갑 에이전트(서명·제출), 서비스(팩토리 배포·calldata 디코드),
// 컨트랙트 테스트가 전부 여기 하나를 쓴다. 컨트랙트와 바이트 단위로 맞아야 하는 것(payload digest, ABI)만 둔다.
// 테스트 헬퍼 tests/helpers/mode3_chain.mjs(:8545 노드용) 와는 별개다.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ethers } from 'ethers';
import * as snarkjs from 'snarkjs';

const ROOT_DIR = fileURLToPath(new URL('..', import.meta.url));

/** 스펙 §5.3: root 게시 뒤 이만큼 블록이 지나면 지갑이 RootTooOld 로 멈춘다. CIA 하트비트 간격(50)보다 넉넉히. */
export const MAX_ROOT_AGE_DEFAULT = 100n;

export const WALLET_ABI = [
  'function ppid() view returns (uint256)',
  'function arid() view returns (uint256)',
  'function nonce() view returns (uint256)',
  'function maxRootAge() view returns (uint64)',
  'function execute((address to,uint256 value,bytes data,uint256 nonce) payload, bytes sig, uint256[2] a, uint256[2][2] b, uint256[2] c, uint256[14] pub) returns (bool)',
  'event Executed(uint256 indexed nonceUsed, address indexed to, uint256 value, bool success)',
  'event Mode3Auth(uint256 indexed nonceUsed, uint256 pk_i, uint256 maxHeight, uint256 allowAgent, uint256 tagC1X, uint256 tagC1Y, uint256 tagC2)',
  'error NonceMismatch(uint256 expected, uint256 got)',
  'error BadSignature()',
  'error WrongWallet()',
  'error UntrustedKeys()',
  'error BadAllowAgent()',
  'error StaleRevocationRoot(bytes32 root)',
  'error RootTooOld(uint256 lastPublished, uint256 current)',
  'error Expired(uint256 currentBlock, uint256 maxHeight)',
  'error InvalidProof()',
];
export const FACTORY_ABI = [
  'function computeAddress(uint256 ppid) view returns (address)',
  'function deploy(uint256 ppid) returns (address)',
  'function arid() view returns (uint256)',
  'function verifier() view returns (address)',
  'function log() view returns (address)',
];
export const walletInterface = new ethers.Interface(WALLET_ABI);

/** Mode3Wallet.execute 의 서명 digest: keccak256(abi.encode(chainid, wallet, to, value, data, nonce)). */
export function payloadDigest({ chainId, wallet, to, value, data, nonce }) {
  return ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
    ['uint256', 'address', 'address', 'uint256', 'bytes', 'uint256'],
    [chainId, wallet, to, value, data, nonce],
  ));
}

/** 세션키(ethers.Wallet)로 raw digest 에 secp256k1 서명. EIP-191 없음 — 컨트랙트가 ecrecover(hash) 를 그대로 쓴다. v ∈ {27, 28}. */
export function signPayload(sessionWallet, fields) {
  return ethers.Signature.from(sessionWallet.signingKey.sign(payloadDigest(fields))).serialized;
}

/** snarkjs 증명을 execute 인자(a, b, c, pub) 로. pub 은 hex 문자열 14개 — ethers 가 uint256 으로 받는다. */
export async function proofToCalldata(proof, publicSignals) {
  const [a, b, c, pub] = JSON.parse('[' + (await snarkjs.groth16.exportSolidityCallData(proof, publicSignals)) + ']');
  return { a, b, c, pub };
}

/** execute 트랜잭션의 calldata 를 되돌린다. 서비스가 트랜잭션 해시로 개봉 재료를 꺼낼 때 쓴다(§6.2). execute 가 아니면 null. */
export function decodeExecuteCalldata(data) {
  let parsed;
  try { parsed = walletInterface.parseTransaction({ data }); } catch { return null; }
  if (!parsed || parsed.name !== 'execute') return null;
  const [payload, sig, a, b, c, pub] = parsed.args;
  return {
    payload: { to: payload.to, value: payload.value, data: payload.data, nonce: payload.nonce },
    sig,
    a: a.map((v) => BigInt(v).toString()),
    b: b.map((row) => row.map((v) => BigInt(v).toString())),
    c: c.map((v) => BigInt(v).toString()),
    pub: pub.map((v) => BigInt(v).toString()),
  };
}

/** 영수증에서 Executed·Mode3Auth 를 뽑는다. 없으면 각각 null. */
export function parseExecuteReceipt(receipt) {
  let executed = null, auth = null;
  for (const l of receipt.logs ?? []) {
    let p = null;
    try { p = walletInterface.parseLog({ topics: [...l.topics], data: l.data }); } catch { continue; }
    if (!p) continue;
    if (p.name === 'Executed') executed = { nonceUsed: p.args.nonceUsed, to: p.args.to, value: p.args.value, success: p.args.success };
    if (p.name === 'Mode3Auth') auth = { nonceUsed: p.args.nonceUsed, pk_i: p.args.pk_i, maxHeight: p.args.maxHeight, allowAgent: p.args.allowAgent, tag: { c1x: p.args.tagC1X, c1y: p.args.tagC1Y, c2: p.args.tagC2 } };
  }
  return { executed, auth };
}

/** hardhat 아티팩트. 없으면 컴파일부터 하라고 알린다 — 조용히 hardhat 을 부르지 않는다(서버 기동 중 컴파일은 느리고 놀랍다). */
export function readArtifact(name) {
  const p = path.join(ROOT_DIR, 'artifacts', 'contracts', `${name}.sol`, `${name}.json`);
  if (!fs.existsSync(p)) throw new Error(`${p} 가 없다 — 먼저 npx hardhat compile`);
  return JSON.parse(fs.readFileSync(p, 'utf8'));
}

export async function deployVerifier(signer) {
  const { abi, bytecode } = readArtifact('PiCredVerifier');
  const c = await new ethers.ContractFactory(abi, bytecode, signer).deploy();
  await c.waitForDeployment();
  return c.getAddress();
}

/** 서비스가 자기 팩토리를 배포한다(§6.1). pkCIA·pkTrace 는 {x, y} bigint. */
export async function deployFactory(signer, { verifierAddress, arid, pkCIA, pkTrace, logAddress, maxRootAge = MAX_ROOT_AGE_DEFAULT }) {
  const { abi, bytecode } = readArtifact('Mode3WalletFactory');
  const c = await new ethers.ContractFactory(abi, bytecode, signer).deploy(
    verifierAddress, BigInt(arid), BigInt(pkCIA.x), BigInt(pkCIA.y), BigInt(pkTrace.x), BigInt(pkTrace.y), logAddress, BigInt(maxRootAge),
  );
  await c.waitForDeployment();
  return c.getAddress();
}

export const factoryAt = (address, runner) => new ethers.Contract(address, FACTORY_ABI, runner);
export const walletAt = (address, runner) => new ethers.Contract(address, WALLET_ABI, runner);
```

- [ ] **Step 8: Mode3Wallet 테스트(실패 → 통과)**

`test/Mode3Wallet.test.mjs` 생성:

```js
// Mode3Wallet / Mode3WalletFactory — 설계 2026-09-18 §5. hardhat 인프로세스 체인(contract 그룹).
// 증명은 tests/helpers/mode3_fixture.mjs 의 픽스처로 실제로 만든다(build/mode3 산출물 필요).
import { expect } from 'chai';
import hre from 'hardhat';
import fs from 'node:fs';
import * as snarkjs from 'snarkjs';
import { buildValidInput } from '../tests/helpers/mode3_fixture.mjs';
import { signRootPublication, rootToBytes32 } from '../lib/mode3_log.js';
import { signPayload, proofToCalldata, decodeExecuteCalldata, parseExecuteReceipt, MAX_ROOT_AGE_DEFAULT } from '../lib/mode3_onchain.js';

const { ethers } = hre;
const WASM = 'build/mode3/pi_cred_js/pi_cred.wasm', ZKEY = 'build/mode3/pi_cred_final.zkey';

describe('Mode3Wallet', function () {
  this.timeout(180_000);
  before(() => { if (!fs.existsSync(ZKEY)) throw new Error(`${ZKEY} 없음 — bash scripts/build_mode3_circuit.sh`); });

  const chainId = () => ethers.provider.getNetwork().then((n) => n.chainId);

  /** 세션키 + 픽스처 증명. 옵션은 픽스처로 전달. */
  async function statement(opts = {}) {
    const session = ethers.Wallet.createRandom();
    const fx = await buildValidInput({ pk_i: BigInt(session.address), chainid: await chainId(), ...opts });
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(fx.input, WASM, ZKEY);
    const cd = await proofToCalldata(proof, publicSignals);
    return { session, fx, proof, publicSignals, ...cd };
  }

  /** 픽스처의 root 로 RevocationLog 를 배포하고(초기 root = 픽스처 트리), 검증자·팩토리·지갑까지. */
  async function deployStack(st, { arid = st.fx.arid, maxRootAge = MAX_ROOT_AGE_DEFAULT } = {}) {
    const [deployer, cia] = await ethers.getSigners();
    const Log = await ethers.getContractFactory('RevocationLog');
    const log = await Log.deploy(cia.address, rootToBytes32(BigInt(st.input().revRoot)));
    const Verifier = await ethers.getContractFactory('PiCredVerifier');
    const verifier = await Verifier.deploy();
    const Factory = await ethers.getContractFactory('Mode3WalletFactory');
    const factory = await Factory.deploy(await verifier.getAddress(), arid, st.fx.ciaPub.x, st.fx.ciaPub.y, st.fx.pk_trace.x, st.fx.pk_trace.y, await log.getAddress(), maxRootAge);
    const ppid = BigInt(st.input().PPID);
    const walletAddr = await factory.computeAddress(ppid);
    await (await deployer.sendTransaction({ to: walletAddr, value: ethers.parseEther('1') })).wait();
    await (await factory.deploy(ppid)).wait();
    const wallet = await ethers.getContractAt('Mode3Wallet', walletAddr);
    return { deployer, cia, log, verifier, factory, wallet, walletAddr, ppid };
  }
  const withInput = (st) => ({ ...st, input: () => st.fx.input });

  async function signedPayload(st, wallet, { to = ethers.Wallet.createRandom().address, value = 0n, data = '0x' } = {}) {
    const nonce = await wallet.nonce();
    const payload = { to, value, data, nonce };
    const sig = signPayload(st.session, { chainId: await chainId(), wallet: wallet.target, ...payload });
    return { payload, sig };
  }

  let ST;   // 공통 성명 — 증명 생성이 1초쯤이라 케이스 간 공유한다(체인은 케이스마다 새로 배포)
  before(async () => { ST = withInput(await statement()); });

  it('정상 실행: 값 전송, nonce 증가, Executed·Mode3Auth 이벤트, gas 기록', async () => {
    const { wallet } = await deployStack(ST);
    const recipient = ethers.Wallet.createRandom().address;
    const { payload, sig } = await signedPayload(ST, wallet, { to: recipient, value: ethers.parseEther('0.1') });
    const tx = await wallet.execute(payload, sig, ST.a, ST.b, ST.c, ST.pub);
    const receipt = await tx.wait();
    expect(await ethers.provider.getBalance(recipient)).to.equal(ethers.parseEther('0.1'));
    expect(await wallet.nonce()).to.equal(1n);
    const { executed, auth } = parseExecuteReceipt(receipt);
    expect(executed.success).to.equal(true);
    expect(auth.pk_i).to.equal(BigInt(ST.session.address));
    expect(auth.maxHeight).to.equal(BigInt(ST.fx.input.max_height));
    expect(auth.allowAgent).to.equal(0n);
    expect(auth.tag.c2).to.equal(ST.fx.tag.c2);
    console.log(`      execute() gas: ${receipt.gasUsed}`);
  });

  it('allowAgent = 1 성명은 이벤트에 1 로 남는다', async () => {
    const st = withInput(await statement({ allowAgent: 1n }));
    const { wallet } = await deployStack(st);
    const { payload, sig } = await signedPayload(st, wallet);
    const receipt = await (await wallet.execute(payload, sig, st.a, st.b, st.c, st.pub)).wait();
    expect(parseExecuteReceipt(receipt).auth.allowAgent).to.equal(1n);
  });

  it('같은 π 로 두 번째 트랜잭션도 된다(세션 안 재사용) — nonce 만 다르다', async () => {
    const { wallet } = await deployStack(ST);
    for (let i = 0; i < 2; i++) {
      const { payload, sig } = await signedPayload(ST, wallet);
      await (await wallet.execute(payload, sig, ST.a, ST.b, ST.c, ST.pub)).wait();
    }
    expect(await wallet.nonce()).to.equal(2n);
  });

  it('nonce 재사용은 NonceMismatch', async () => {
    const { wallet } = await deployStack(ST);
    const { payload, sig } = await signedPayload(ST, wallet);
    await (await wallet.execute(payload, sig, ST.a, ST.b, ST.c, ST.pub)).wait();
    await expect(wallet.execute(payload, sig, ST.a, ST.b, ST.c, ST.pub)).to.be.revertedWithCustomError(wallet, 'NonceMismatch');
  });

  it('다른 키의 서명·손상된 서명은 BadSignature', async () => {
    const { wallet } = await deployStack(ST);
    const { payload } = await signedPayload(ST, wallet);
    const other = ethers.Wallet.createRandom();
    const wrong = signPayload(other, { chainId: await chainId(), wallet: wallet.target, ...payload });
    await expect(wallet.execute(payload, wrong, ST.a, ST.b, ST.c, ST.pub)).to.be.revertedWithCustomError(wallet, 'BadSignature');
    await expect(wallet.execute(payload, '0x' + '11'.repeat(64) + '00', ST.a, ST.b, ST.c, ST.pub)).to.be.revertedWithCustomError(wallet, 'BadSignature');
  });

  it('다른 지갑 주소로 서명한 payload 는 BadSignature (도메인 분리)', async () => {
    const { wallet } = await deployStack(ST);
    const { payload } = await signedPayload(ST, wallet);
    const sig = signPayload(ST.session, { chainId: await chainId(), wallet: ethers.Wallet.createRandom().address, ...payload });
    await expect(wallet.execute(payload, sig, ST.a, ST.b, ST.c, ST.pub)).to.be.revertedWithCustomError(wallet, 'BadSignature');
  });

  it('공개 입력의 arid·chainid 가 지갑과 다르면 WrongWallet (다른 서비스·다른 체인의 성명 재생)', async () => {
    const { wallet } = await deployStack(ST);
    const { payload, sig } = await signedPayload(ST, wallet);
    const otherArid = [...ST.pub]; otherArid[1] = '0x1';
    await expect(wallet.execute(payload, sig, ST.a, ST.b, ST.c, otherArid)).to.be.revertedWithCustomError(wallet, 'WrongWallet');
    const otherChain = [...ST.pub]; otherChain[4] = '0x1';
    await expect(wallet.execute(payload, sig, ST.a, ST.b, ST.c, otherChain)).to.be.revertedWithCustomError(wallet, 'WrongWallet');
  });

  it('다른 arid 로 배포한 팩토리의 지갑에는 이 성명이 들어가지 않는다 (WrongWallet)', async () => {
    const { wallet } = await deployStack(ST, { arid: 5n });
    const { payload, sig } = await signedPayload(ST, wallet);
    await expect(wallet.execute(payload, sig, ST.a, ST.b, ST.c, ST.pub)).to.be.revertedWithCustomError(wallet, 'WrongWallet');
  });

  it('pk_CIA·pk_trace 가 다르면 UntrustedKeys', async () => {
    const { wallet } = await deployStack(ST);
    const { payload, sig } = await signedPayload(ST, wallet);
    const p = [...ST.pub]; p[9] = '0x1';
    await expect(wallet.execute(payload, sig, ST.a, ST.b, ST.c, p)).to.be.revertedWithCustomError(wallet, 'UntrustedKeys');
  });

  it('allowAgent = 2 는 BadAllowAgent (증명 검증 전에 걸린다)', async () => {
    const { wallet } = await deployStack(ST);
    const { payload, sig } = await signedPayload(ST, wallet);
    const p = [...ST.pub]; p[5] = '0x2';
    await expect(wallet.execute(payload, sig, ST.a, ST.b, ST.c, p)).to.be.revertedWithCustomError(wallet, 'BadAllowAgent');
  });

  it('root 가 게시로 바뀌면 옛 π 는 StaleRevocationRoot', async () => {
    const { wallet, log, cia } = await deployStack(ST);
    const newRoot = rootToBytes32(12345n);
    const sig = await signRootPublication(cia, { logAddress: await log.getAddress(), root: newRoot, epoch: 1n, leaves: [] });
    await (await log.publishRoot(newRoot, 1n, [], sig)).wait();
    const sp = await signedPayload(ST, wallet);
    await expect(wallet.execute(sp.payload, sp.sig, ST.a, ST.b, ST.c, ST.pub)).to.be.revertedWithCustomError(wallet, 'StaleRevocationRoot');
  });

  it('root 게시가 maxRootAge 블록보다 오래되면 RootTooOld, 하트비트(같은 root 재게시) 뒤엔 다시 된다', async () => {
    const { wallet, log, cia } = await deployStack(ST, { maxRootAge: 10n });
    await ethers.provider.send('hardhat_mine', ['0xb']);   // 11 블록
    const sp = await signedPayload(ST, wallet);
    await expect(wallet.execute(sp.payload, sp.sig, ST.a, ST.b, ST.c, ST.pub)).to.be.revertedWithCustomError(wallet, 'RootTooOld');
    const root = await log.root();
    const sig = await signRootPublication(cia, { logAddress: await log.getAddress(), root, epoch: 1n, leaves: [] });
    await (await log.publishRoot(root, 1n, [], sig)).wait();
    await expect(wallet.execute(sp.payload, sp.sig, ST.a, ST.b, ST.c, ST.pub)).to.not.be.reverted;
  });

  it('block.number > max_height 면 Expired', async () => {
    const st = withInput(await statement({ maxHeight: BigInt(await ethers.provider.getBlockNumber()) }));
    const { wallet } = await deployStack(st);   // 배포로 블록이 지나 이미 만료
    const { payload, sig } = await signedPayload(st, wallet);
    await expect(wallet.execute(payload, sig, st.a, st.b, st.c, st.pub)).to.be.revertedWithCustomError(wallet, 'Expired');
  });

  it('증명을 손상하면 InvalidProof', async () => {
    const { wallet } = await deployStack(ST);
    const { payload, sig } = await signedPayload(ST, wallet);
    const a = [ST.a[1], ST.a[0]];
    await expect(wallet.execute(payload, sig, a, ST.b, ST.c, ST.pub)).to.be.revertedWithCustomError(wallet, 'InvalidProof');
  });

  it('내부 호출이 실패해도 revert 하지 않고 nonce 를 소모하며 Executed(success=false)', async () => {
    const { wallet } = await deployStack(ST);
    const { payload, sig } = await signedPayload(ST, wallet, { value: ethers.parseEther('1000') });
    const receipt = await (await wallet.execute(payload, sig, ST.a, ST.b, ST.c, ST.pub)).wait();
    expect(parseExecuteReceipt(receipt).executed.success).to.equal(false);
    expect(await wallet.nonce()).to.equal(1n);
  });

  it('decodeExecuteCalldata 가 제출한 인자를 그대로 되돌린다 (서비스의 해시 기반 개봉 재료)', async () => {
    const { wallet } = await deployStack(ST);
    const { payload, sig } = await signedPayload(ST, wallet);
    const tx = await wallet.execute(payload, sig, ST.a, ST.b, ST.c, ST.pub);
    await tx.wait();
    const d = decodeExecuteCalldata((await ethers.provider.getTransaction(tx.hash)).data);
    expect(d.pub).to.deep.equal(ST.publicSignals);
    expect(d.payload.nonce).to.equal(payload.nonce);
    expect(d.sig).to.equal(sig);
  });

  it('computeAddress 는 배포 전후 같고, deploy 는 멱등이다', async () => {
    const { factory, walletAddr, ppid } = await deployStack(ST);
    expect(await factory.computeAddress(ppid)).to.equal(walletAddr);
    await (await factory.deploy(ppid)).wait();
    expect(await ethers.provider.getCode(walletAddr)).to.not.equal('0x');
  });
});
```

Run: `npx hardhat test test/Mode3Wallet.test.mjs`
Expected: 전부 passing. `execute() gas:` 줄의 수치를 보고서에 적는다(스펙 §8 실측).

주의: `decodeExecuteCalldata` 의 `pub` 은 10진 문자열이고 `ST.publicSignals` 도 10진 문자열이라 `deep.equal` 이 성립한다. `ST.pub`(hex) 과 비교하지 말 것.

- [ ] **Step 9: 전체 컨트랙트 그룹**

Run: `bash scripts/run_tests.sh contract`
Expected: Mode 2 컨트랙트 테스트 포함 전부 passing.

- [ ] **Step 10: 커밋**

```bash
git add contracts/RevocationLog.sol contracts/Mode3Wallet.sol contracts/Mode3WalletFactory.sol hardhat.config.cjs lib/mode3_log.js lib/mode3_onchain.js test/Mode3Wallet.test.mjs test/RevocationLog.test.mjs
git commit -m "feat(mode3): PPID 계정 컨트랙트 — Mode3Wallet·Mode3WalletFactory, RevocationLog.lastPublishedBlock, 온체인 유틸 lib/mode3_onchain.js"
```

---

### Task 4: 지갑·서비스 라이브러리 V4 — 발급 요청, 증명, 검증기

**Files:**
- Modify: `lib/mode3_wallet.js:36-57` (`signUserRequest`, `buildIssueRequest`), `:95-123` (`buildCredentialProof`)
- Modify: `lib/mode3_rp.js:43-71` (`verifyLogin`)
- Test: `tests/test_mode3_wallet.mjs`, `tests/test_mode3_rp.mjs`, `tests/test_mode3_e2e.mjs`

**Interfaces:**
- Consumes: Task 1 (`credMessage`, `issueRequestMessage`, `encryptTag`), Task 2 (zkey·wasm V4).
- Produces: `signUserRequest(sk_uHex, C_pt, chainid, allowAgent)`; `buildIssueRequest({ uid, arid, s_u, r_u, sk_u, session, chainid, attrs, allowAgent = 0n }) → { body: { uid, C_pt, proof, sig_u, chainid, allowAgent }, secrets: { blind } }`; `buildCredentialProof({ …, credential: { C, max_height, chainid, allowAgent, sigma }, … }) → { proof, publicSignals, revRoot, tag: { c1, c2, h } }`.
- Produces: `createRpVerifier(...).verifyLogin({ proof, publicSignals, sig, r_s }) → { ok, PPID, pk_i, max_height, allowAgent, root, tag } | { ok:false, reason }`. `r_s` 는 호출자(서버)가 준다 — 공개 입력에 없다. `reason` 에 `bad_allow_agent` 추가. `refreshChainView()` 그대로.

- [ ] **Step 1: 테스트 갱신 — wallet 라이브러리**

`tests/test_mode3_wallet.mjs`:
- `localIssue` 를 교체:

```js
// 서버 없이 CIA 역할을 로컬에서 흉내낸다 (서명만). max_height 는 현재 head + ttlBlocks — 그리드 양자화는 CIA 의 일이라 여기선 안 한다.
async function localIssue(C_pt, chainid, { ttlBlocks = 300n, allowAgent = 0n } = {}) {
  const C = await compressPoint(C_pt);
  const max_height = BigInt(await provider.getBlockNumber()) + ttlBlocks;
  const s = eddsa.signPoseidon(ciaPrv, F.e(await credMessage(C, max_height, chainid, allowAgent)));
  return { C: C.toString(), max_height: max_height.toString(), chainid: chainid.toString(), allowAgent: allowAgent.toString(), sigma: { R8x: F.toObject(s.R8[0]).toString(), R8y: F.toObject(s.R8[1]).toString(), S: s.S.toString() } };
}
```
- 79~81행: `const r_s = randomScalar();` 삭제, `buildIssueRequest({ …, r_s })` → `buildIssueRequest({ uid, arid, s_u: reg.s_u, r_u: reg.r_u, sk_u, session, chainid: 31337n, attrs: [19n, 410n, 0n, 0n] })`, `cred = await localIssue(pointFromStrings(req.body.C_pt), 31337n, r_s)` → `cred = await localIssue(pointFromStrings(req.body.C_pt), 31337n)`.
- 87~94행 단언을 교체:

```js
  assert.equal(publicSignals.length, 14);
  assert.equal(BigInt(publicSignals[2]), session.pk_i);
  assert.equal(BigInt(publicSignals[3]), BigInt(cred.max_height));
  assert.equal(BigInt(publicSignals[4]), 31337n);
  assert.equal(BigInt(publicSignals[5]), 0n, 'allowAgent');
  assert.equal(BigInt(publicSignals[6]), tree0.getRoot());
  assert.equal(BigInt(publicSignals[9]), pk_trace.x); assert.equal(BigInt(publicSignals[10]), pk_trace.y);
  assert.equal(BigInt(publicSignals[11]), tag.c1.x); assert.equal(BigInt(publicSignals[13]), tag.c2);
  assert.equal(tag.h, await tagPlaintext(uid, arid), '태그 평문은 Poseidon(uid, arid)');
```
  (import 에 `tagPlaintext` 를 `../lib/mode3_trace.js` 에서 추가.)
- 125~133행 케이스를 교체:

```js
await t('buildIssueRequest 는 allowAgent 를 싣고(기본 0) r_s 는 더 이상 받지 않는다', async () => {
  const session = createSessionKey();
  const a = await buildIssueRequest({ uid, arid, s_u: reg.s_u, r_u: reg.r_u, sk_u, session, chainid: 31337n });
  assert.equal(a.body.allowAgent, '0');
  assert.equal(a.body.r_s, undefined);
  const b = await buildIssueRequest({ uid, arid, s_u: reg.s_u, r_u: reg.r_u, sk_u, session, chainid: 31337n, allowAgent: 1n });
  assert.equal(b.body.allowAgent, '1');
  await assert.rejects(() => buildIssueRequest({ uid, arid, s_u: reg.s_u, r_u: reg.r_u, sk_u, session, chainid: 31337n, allowAgent: 2n }), /allowAgent/);
});
```
- 파일 안의 다른 `localIssue(…, r_s)` / `r_s` 인자 사용처가 있으면 같은 규칙으로 고친다(`grep -n r_s tests/test_mode3_wallet.mjs`). `signSessionRequest`/`verifySessionRequest` 케이스(135~140행)는 그대로다 — 세션 요청 서명은 여전히 `r_s` 위다.

- [ ] **Step 2: 테스트 갱신 — RP 검증기**

`tests/test_mode3_rp.mjs`:
- `issueWith` 를 교체:

```js
async function issueWith(key, C_pt, { ttlBlocks = 300n, chainid = 31337n, allowAgent = 0n } = {}) {
  const C = await compressPoint(C_pt);
  const max_height = BigInt(await provider.getBlockNumber()) + ttlBlocks;
  const s = eddsa.signPoseidon(key.prv, F.e(await credMessage(C, max_height, chainid, allowAgent)));
  return { C: C.toString(), max_height: max_height.toString(), chainid: chainid.toString(), allowAgent: allowAgent.toString(), sigma: { R8x: F.toObject(s.R8[0]).toString(), R8y: F.toObject(s.R8[1]).toString(), S: s.S.toString() } };
}
```
- `makeLogin` 을 교체:

```js
async function makeLogin({ key = CIA, useArid = arid, ttlBlocks = 300n, chainid = 31337n, useTrace = pk_trace, allowAgent = 0n } = {}) {
  const reg = await createRegistration();
  const session = createSessionKey();
  const attrs = [19n, 410n, 0n, 0n];
  const r_s = randomScalar();   // 서비스 챌린지 — σ 에만 쓴다(공개 입력엔 없다)
  const req = await buildIssueRequest({ uid, arid: useArid, s_u: reg.s_u, r_u: reg.r_u, sk_u: Buffer.alloc(32, 3).toString('hex'), session, chainid, attrs, allowAgent });
  const cred = await issueWith(key, pointFromStrings(req.body.C_pt), { ttlBlocks, chainid, allowAgent });
  const { tree } = await syncRevocationTree(provider, logAddress);
  const { proof, publicSignals } = await buildCredentialProof({ uid, arid: useArid, s_u: reg.s_u, blind: req.secrets.blind, pk_i: session.pk_i, attrs, credential: cred, pk_CIA: key.pub, pk_trace: useTrace, tree });
  return { proof, publicSignals, r_s, sig: await signChallenge(session.wallet, r_s.toString()), session, cred, reg };
}
```
- 모든 `rp.verifyLogin({ proof: L.proof, publicSignals: L.publicSignals, sig: L.sig })` 꼴 호출에 `r_s: L.r_s` 를 추가한다(`grep -n verifyLogin tests/test_mode3_rp.mjs` 로 전부 찾는다). 편의를 위해 파일 상단에 `const login = (L, extra = {}) => rp.verifyLogin({ proof: L.proof, publicSignals: L.publicSignals, sig: L.sig, r_s: L.r_s, ...extra });` 를 두고 호출을 바꿔도 된다.
- 91~97행('양성: verifyLogin 이 r_s·exptime·root 를 돌려준다') 를 교체:

```js
await t('양성: verifyLogin 이 max_height·allowAgent·root 를 돌려준다 (서버가 세션을 만들 재료)', async () => {
  const L = await makeLogin({ allowAgent: 1n });
  const r = await rp.verifyLogin({ proof: L.proof, publicSignals: L.publicSignals, sig: L.sig, r_s: L.r_s });
  assert.equal(r.ok, true, JSON.stringify(r, (k, v) => (typeof v === 'bigint' ? v.toString() : v)));
  assert.equal(r.max_height, BigInt(L.cred.max_height));
  assert.equal(r.allowAgent, 1n);
  assert.equal(r.root, BigInt(L.publicSignals[6]));
  assert.equal(r.r_s, undefined, 'r_s 는 검증기가 돌려주지 않는다 — 서버가 이미 안다');
});
```
- 128~130행('음성 c: exptime 이 지나면') 을 교체:

```js
await t('음성 c: head 가 max_height 를 넘으면 expired (블록 높이)', async () => {
  const L = await makeLogin({ ttlBlocks: 2n });
  await provider.send('hardhat_mine', ['0x3']);
  const r = await rp.verifyLogin({ proof: L.proof, publicSignals: L.publicSignals, sig: L.sig, r_s: L.r_s });
  assert.equal(r.ok, false); assert.equal(r.reason, 'expired');
});

await t('음성: allowAgent 가 1 을 넘는 공개 입력은 bad_allow_agent (증명 검증 전에 걸린다)', async () => {
  const L = await makeLogin();
  const ps = [...L.publicSignals]; ps[5] = '2';
  const r = await rp.verifyLogin({ proof: L.proof, publicSignals: ps, sig: L.sig, r_s: L.r_s });
  assert.equal(r.ok, false); assert.equal(r.reason, 'bad_allow_agent');
});
```
- 85~90행('음성 f: 다른 r_s 위의 서명') 은 `r_s: L.r_s` 를 넘긴 채 `sig` 만 `(L.r_s + 1n)` 위 서명으로 두면 그대로 성립한다. 추가로:

```js
await t('음성 f: 서버가 다른 r_s 를 넘기면 bad_signature (σ 는 서버가 준 챌린지 위여야 한다)', async () => {
  const L = await makeLogin();
  const r = await rp.verifyLogin({ proof: L.proof, publicSignals: L.publicSignals, sig: L.sig, r_s: L.r_s + 1n });
  assert.equal(r.ok, false); assert.equal(r.reason, 'bad_signature');
});
```
- 190~195행(체인별 PPID 케이스)의 `buildIssueRequest({ …, r_s })` → `r_s` 제거, `issueWith(CIA, …, r_s, 3600n, chainid)` → `issueWith(CIA, pointFromStrings(req.body.C_pt), { chainid })`.

- [ ] **Step 3: 테스트 갱신 — 라이브러리 e2e**

`tests/test_mode3_e2e.mjs`:
- `submit`: `rp.verifyLogin({ proof: cached.proof, publicSignals: cached.publicSignals, sig: await signChallenge(session.wallet, sessionRs.toString()), r_s: sessionRs })`.
- `newSessionAndIssue`: `buildIssueRequest({ uid, arid, s_u: reg.s_u, r_u: reg.r_u, sk_u, session, chainid: 31337n, attrs: ATTRS })` (r_s 제거), `sessionRs = randomScalar()` 는 유지(σ 용).
- 그 외 변경 없음. (CIA 서버는 Task 5 에서 V4 가 되므로 **이 파일의 실행은 Task 5 뒤에** 한다 — Task 4 의 실행 확인은 Step 5 의 두 파일로 한다.)

- [ ] **Step 4: 구현 — lib/mode3_wallet.js**

- 파일 상단 주석의 "로그인마다 발급된다(설계 2026-09-15 §5) — 성명은 세션(r_s) 단위" 를 "로그인마다 발급된다(2026-09-15 §5). 자격증명 V4 는 (C, max_height, chainid, allowAgent) 위 서명이다(2026-09-18 §3)" 로.
- `signUserRequest`·`buildIssueRequest` 를 교체:

```js
/** Sign(sk_u, (C_pt, chainid, allowAgent)): 등록된 장기키로 서명 (설계 2026-09-18 §3.3). 메시지는 issueRequestMessage(). */
export async function signUserRequest(sk_uHex, C_pt, chainid, allowAgent) {
  if (typeof chainid !== 'bigint' || typeof allowAgent !== 'bigint') throw new Error('signUserRequest: chainid·allowAgent(bigint) 가 필요하다');
  const eddsa = await getEddsa();
  const F = eddsa.F;
  const s = eddsa.signPoseidon(Buffer.from(sk_uHex, 'hex'), F.e(await issueRequestMessage(C_pt, chainid, allowAgent)));
  return { R8x: F.toObject(s.R8[0]).toString(), R8y: F.toObject(s.R8[1]).toString(), S: s.S.toString() };
}

/** §5 단계 1~2. blind 는 여기서 새로 뽑고 secrets 로 돌려준다. allowAgent 는 사용자의 선택(2026-09-18 §3.1), 기본 0. */
export async function buildIssueRequest({ uid, arid, s_u, r_u, sk_u, session, chainid, attrs, allowAgent = 0n }) {
  if (typeof chainid !== 'bigint') throw new Error('buildIssueRequest: chainid(bigint) 가 필요하다');
  if (typeof allowAgent !== 'bigint' || (allowAgent !== 0n && allowAgent !== 1n)) throw new Error('buildIssueRequest: allowAgent 는 0n 또는 1n');
  const blind = randomScalar();
  const a4 = normalizeAttrs(attrs);
  const { C_pt, proof } = await proveIssuance({ uid, arid, s_u, blind, pk_i: session.pk_i, r_u, attrs: a4 });
  const body = {
    uid: uid.toString(), C_pt: pointToStrings(C_pt), proof: serializeProof(proof),
    sig_u: await signUserRequest(sk_u, C_pt, chainid, allowAgent), chainid: chainid.toString(), allowAgent: allowAgent.toString(),
  };
  return { body, secrets: { blind } };
}
```
- `buildCredentialProof` 의 주석 첫 줄을 V4 순서로 고치고, 본문에서 `const tag = await encryptTag(pk_trace, uid);` → `const tag = await encryptTag(pk_trace, uid, arid);`, `input` 의 `exptime: …, chainid: …,` / `r_s: …, revRoot: …` 두 줄을 다음으로:

```js
    max_height: BigInt(credential.max_height).toString(), chainid: BigInt(credential.chainid).toString(),
    allowAgent: BigInt(credential.allowAgent).toString(), revRoot: tree.getRoot().toString(),
```
  반환값의 `tag` 를 `tag: { c1: tag.c1, c2: tag.c2, h: tag.h }` 로.

- [ ] **Step 5: 구현 — lib/mode3_rp.js**

- 파일 상단 주석: `c. 만료 ← now ≤ exptime …` 을 `c. 만료 ← head ≤ max_height (블록 높이, 2026-09-18 §3.2). 체인 뷰의 head 를 쓴다` 로; "r_s 대조는 서버가 한다" 줄을 "r_s 는 공개 입력에 없다(2026-09-18 §2) — 서버가 자기가 준 챌린지를 넘기고 검증기는 σ 를 그 위에서 확인한다(f)" 로; `d.` 목록에 `allowAgent ≤ 1 ← 회로도 막지만 이벤트·세션에 남는 값이라 한 번 더` 추가; 첫 줄 "오프체인 전용(§9.11)" 을 "오프체인 검증기. 온체인 판은 contracts/Mode3Wallet.sol — 같은 순서·같은 규칙(2026-09-18 §5.3)" 로.
- `verifyLogin` 을 교체:

```js
  async function verifyLogin({ proof, publicSignals, sig, r_s }) {
    if (!Array.isArray(publicSignals) || publicSignals.length !== 14 || !proof || typeof sig !== 'string' || typeof r_s !== 'bigint') {
      return { ok: false, reason: 'malformed' };
    }
    let ps;
    try { ps = publicSignals.map((s) => BigInt(s)); } catch { return { ok: false, reason: 'malformed' }; }
    const [PPID, aridIn, pk_i, max_height, chainIn, allowAgent, revRoot, ciaX, ciaY, traceX, traceY, c1x, c1y, c2] = ps;

    const v = await chainView();                                   // a
    if (!v) return { ok: false, reason: 'chain_unavailable' };
    if (revRoot !== v.root) return { ok: false, reason: 'stale_root' };       // b
    if (v.head > max_height) return { ok: false, reason: 'expired' };         // c — 블록 높이
    if (chainIn !== chainId) return { ok: false, reason: 'wrong_chain' };     // c'
    if (ciaX !== BigInt(pkCIA.x) || ciaY !== BigInt(pkCIA.y)) return { ok: false, reason: 'untrusted_cia' };   // d
    if (aridIn !== BigInt(arid)) return { ok: false, reason: 'wrong_arid' };  // d
    if (traceX !== pkTrace.x || traceY !== pkTrace.y) return { ok: false, reason: 'wrong_trace_key' };   // d'
    if (allowAgent > 1n) return { ok: false, reason: 'bad_allow_agent' };
    // r = 0 이면 c1 이 항등원이라 태그가 평문을 그대로 드러낸다 — 지갑 실수를 여기서 막는다.
    if (c1x === 0n && c1y === 1n) return { ok: false, reason: 'bad_tag' };

    let proofOk = false;                                           // e
    try { proofOk = await snarkjs.groth16.verify(vkey, publicSignals, proof); } catch { proofOk = false; }
    if (!proofOk) return { ok: false, reason: 'bad_proof' };

    let signer;                                                    // f — σ 는 서버가 준 r_s(10진) 위
    try { signer = BigInt(ethers.verifyMessage(r_s.toString(), sig)); } catch { return { ok: false, reason: 'bad_signature' }; }
    if (signer !== pk_i) return { ok: false, reason: 'bad_signature' };

    return { ok: true, PPID, pk_i, max_height, allowAgent, root: revRoot, tag: { c1x, c1y, c2 } };  // g — 서버가 세션을 만든다
  }
```

- [ ] **Step 6: 통과 확인**

:8545 hardhat 노드가 필요하다(없으면 `npx hardhat node` 를 백그라운드로 띄우고 끝나면 내린다).

Run: `node tests/test_mode3_wallet.mjs && node tests/test_mode3_rp.mjs`
Expected: 두 파일 모두 `FAIL` 0.

- [ ] **Step 7: 커밋**

```bash
git add lib/mode3_wallet.js lib/mode3_rp.js tests/test_mode3_wallet.mjs tests/test_mode3_rp.mjs tests/test_mode3_e2e.mjs
git commit -m "feat(mode3): 지갑·서비스 라이브러리 V4 — allowAgent 발급 요청, max_height 증명 입력, 검증기는 head≤max_height 와 서버 챌린지 σ"
```

---

### Task 5: CIA V4 — 발급(max_height·allowAgent·체인 헤드), 상태 v5, 하트비트, 개봉 V2

**Files:**
- Create: `lib/mode3_cia_state.js`
- Create: `tests/test_mode3_cia_state.js` (unit)
- Modify: `cia.js` (설정 33-47, 상태 77-92·137-177, 유틸 193-218, `/cia/public_keys`, `/cia/issue`, `revokeAccount`·`/cia/revoke` 의 `pruneExpired` 호출, `/cia/publish` → `publishNow`, 개봉 505-581, 기동 589-598)
- Modify: `tests/helpers/isolated_cia.mjs:31-44` (env 고정)
- Modify: `tests/test_cia_register_issue.mjs`, `tests/test_cia_opening.mjs`, `tests/test_cia_startup.mjs`, `tests/test_cia_issue_race.mjs`
- Modify: `scripts/run_tests.sh` (UNIT 에 `tests/test_mode3_cia_state.js`)

**Interfaces:**
- Consumes: Task 1 (`credMessage`, `issueRequestMessage`, `resolveTagPlaintext`, `openRequestMessage`), Task 3 (`LOG_ABI.lastPublishedBlock`), Task 4 (`buildIssueRequest` — 테스트에서).
- Produces(HTTP): `POST /cia/issue {uid, C_pt, proof, sig_u, chainid, allowAgent}` → `{C, max_height, chainid, allowAgent, sigma, pk_CIA}`; `GET /cia/public_keys` → `{pk_CIA, ethAddress, ttlBlocks, heightGrid, heartbeatBlocks, chainIds, logAddress}`; `POST /cia/open/request` 서명 메시지 V2, 중복 키 `(arid, c1)`; `GET /cia/open/:id` → `{id, status, uid|null, resolved, allowAgent, max_height, chainid, PPID, decidedAt}`; `POST /cia/publish` 응답에 `heartbeat: bool` 추가.
- Produces(JS): `lib/mode3_cia_state.js` — `CIA_STATE_VERSION = 5`, `defaultCiaState()`, `migrateCiaState(state) → { state, notes: string[] }` (v3→v4→v5, 그 외 throw).
- 환경변수: `CIA_TTL_BLOCKS`(300), `CIA_HEIGHT_GRID`(100), `CIA_REVOKE_SKEW_BLOCKS`(50), `CIA_HEARTBEAT_BLOCKS`(50, 0=끔), `CIA_HEARTBEAT_POLL_MS`(5000), `CIA_CHAIN_RPCS`("id=url,…"). `CIA_TTL_SECONDS`·`CIA_REVOKE_SKEW_SECONDS`·`CIA_CHAIN_IDS` 는 무시(경고).

**계획 판정(스펙과의 차이, 구현자가 따를 것):**
- 발급 검사 순서는 스펙 §4.1 의 "chainid 허용·헤드 조회 → sig_u" 대신 **chainid 허용(맵 키) → sig_u → π_issue → 같은 C → 헤드 조회 → disabled 재확인 → 서명·기록** 으로 한다. 헤드 조회가 옛 `chainAlive()` 자리를 그대로 대신해 "발급 직전 체인 가용성 확인(fail-closed)" 의미와 `tests/test_cia_issue_race.mjs` 의 게이트(eth_blockNumber)가 유지된다.
- 같은 `C_pt` 재요청은 옛 409 대신 **200** 이고 발급 기록의 `max_height` 를 큰 쪽으로 갱신한다(스펙 §3.3·§4.3). 기존 테스트 '같은 C_pt 로 재요청하면 409' 는 그에 맞게 뒤집는다.

- [ ] **Step 1: 상태 이행 라이브러리 + 단위 테스트(실패)**

`tests/test_mode3_cia_state.js`:

```js
// CIA 상태 파일 이행 (설계 2026-09-18 §4.4). 외부 의존 없음.
//   node tests/test_mode3_cia_state.js
import assert from 'node:assert/strict';
import { CIA_STATE_VERSION, defaultCiaState, migrateCiaState } from '../lib/mode3_cia_state.js';

let failed = 0;
function t(name, fn) { try { fn(); console.log(`ok   ${name}`); } catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.message}`); } }

t('기본 상태는 v5 이고 빈 컬렉션', () => {
  const s = defaultCiaState();
  assert.equal(s.version, 5); assert.equal(CIA_STATE_VERSION, 5);
  assert.deepEqual(s, { version: 5, accounts: {}, issued: {}, rps: {}, openings: [], revoked: [], pending: [], epoch: 0 });
});

t('v4 → v5: issued 를 비우고(V3 서명은 죽은 자격증명) openings 에 resolved·allowAgent·max_height·chainid 를 채운다, 나머지는 그대로', () => {
  const v4 = {
    version: 4,
    accounts: { '12345': { pk_u: { x: '1', y: '2' }, cm_u: { x: '3', y: '4' }, disabled: false } },
    issued: { '12345': [{ leaf: '9', C: '8', exptime: '1789000000' }] },
    rps: { '777': { name: 's', origin: 'http://127.0.0.1:3100', pk_service: '0x' + '11'.repeat(20), X_svc: { x: '1', y: '2' }, x_AA: '5', pk_trace: { x: '6', y: '7' }, status: 'approved', requestedAt: 'a', decidedAt: 'b' } },
    openings: [{ id: 'o1', arid: '777', r_s: '55', PPID: '99', c1: { x: '1', y: '2' }, c2: '3', D_svc: { x: '4', y: '5' }, status: 'approved', requestedAt: 'a', decidedAt: 'b', uid: '12345' },
               { id: 'o2', arid: '777', r_s: '56', PPID: '99', c1: { x: '1', y: '2' }, c2: '3', D_svc: { x: '4', y: '5' }, status: 'pending', requestedAt: 'a', decidedAt: null }],
    revoked: ['9'], pending: ['9'], epoch: 3,
  };
  const { state, notes } = migrateCiaState(structuredClone(v4));
  assert.equal(state.version, 5);
  assert.deepEqual(state.issued, {});
  assert.deepEqual(state.accounts, v4.accounts); assert.deepEqual(state.rps, v4.rps);
  assert.deepEqual(state.revoked, ['9']); assert.deepEqual(state.pending, ['9']); assert.equal(state.epoch, 3);
  assert.equal(state.openings[0].resolved, true); assert.equal(state.openings[0].uid, '12345');
  assert.equal(state.openings[1].resolved, null);
  for (const o of state.openings) { assert.equal(o.allowAgent, null); assert.equal(o.max_height, null); assert.equal(o.chainid, null); }
  assert.ok(notes.some((n) => /v4→v5/.test(n) && /1개/.test(n)), notes.join('|'));
});

t('v3 → v5: used_rs 버림, rps 는 approved·조각 없음, openings [] (v4 규칙을 거쳐 온다)', () => {
  const { state, notes } = migrateCiaState({ version: 3, accounts: {}, issued: {}, used_rs: { '12345': ['1'] }, rps: { '777': { name: 'old', origin: 'http://127.0.0.1:3100', at: '2026-09-15T00:00:00.000Z' } }, revoked: [], pending: [], epoch: 0 });
  assert.equal(state.version, 5); assert.equal(state.used_rs, undefined);
  const e = state.rps['777'];
  assert.equal(e.status, 'approved'); assert.equal(e.pk_service, null); assert.equal(e.X_svc, null); assert.equal(e.x_AA, null); assert.equal(e.pk_trace, null);
  assert.equal(e.requestedAt, '2026-09-15T00:00:00.000Z');
  assert.deepEqual(state.openings, []);
  assert.equal(notes.length, 2);
});

t('v5 는 그대로(notes 없음), v2 이하·미래 버전은 throw', () => {
  const { state, notes } = migrateCiaState(defaultCiaState());
  assert.equal(state.version, 5); assert.deepEqual(notes, []);
  assert.throws(() => migrateCiaState({ version: 2 }), /version 2/);
  assert.throws(() => migrateCiaState({ version: 6 }), /version 6/);
});

process.exit(failed === 0 ? 0 : 1);
```

Run: `node tests/test_mode3_cia_state.js` → Expected: `ERR_MODULE_NOT_FOUND`.

`lib/mode3_cia_state.js`:

```js
// CIA 상태 파일의 버전과 이행 — cia.js 에서 떼어 낸 순수 함수(설계 2026-09-18 §4.4). 체인·키 없이 테스트한다.
//
// version 4 (2026-09-16): used_rs 삭제, rps 에 키·상태, openings 추가.
// version 5 (2026-09-18): 발급 기록 형식 { leaf, C, max_height, chainid } — 옛 exptime 기록은 V3 서명 자격증명이라
//   새 회로·컨트랙트·서비스 검증기 어디서도 검증되지 않으므로 폐기 대상이 아니다 → 비운다. openings 에
//   resolved(역조회 성공 여부)·allowAgent·max_height·chainid 를 둔다(옛 항목은 null).
export const CIA_STATE_VERSION = 5;

export function defaultCiaState() {
  return { version: CIA_STATE_VERSION, accounts: {}, issued: {}, rps: {}, openings: [], revoked: [], pending: [], epoch: 0 };
}

/** 제자리 이행. 돌려주는 notes 는 기동 로그용 한 줄씩. v2 이하는 옛 서명 형식이라 읽지 않는다(throw). */
export function migrateCiaState(state) {
  const notes = [];
  if (state.version === 3) {
    delete state.used_rs;
    for (const e of Object.values(state.rps ?? {})) {
      e.pk_service ??= null; e.X_svc ??= null; e.x_AA ??= null; e.pk_trace ??= null;
      e.status ??= 'approved'; e.requestedAt ??= e.at ?? new Date().toISOString(); e.decidedAt ??= e.requestedAt;
    }
    state.openings ??= [];
    state.version = 4;
    notes.push('v3→v4: used_rs 버림, 기존 서비스 등록은 approved(조각 없음)');
  }
  if (state.version === 4) {
    const dropped = Object.values(state.issued ?? {}).reduce((n, l) => n + (Array.isArray(l) ? l.length : 0), 0);
    state.issued = {};
    for (const o of state.openings ?? []) {
      o.resolved ??= (o.status === 'approved' ? Boolean(o.uid) : null);
      o.allowAgent ??= null; o.max_height ??= null; o.chainid ??= null;
    }
    state.version = 5;
    notes.push(`v4→v5: 발급 기록 ${dropped}개 버림(V3 서명은 새 회로에서 검증되지 않는다), openings 에 resolved·allowAgent·max_height·chainid`);
  }
  if (state.version !== CIA_STATE_VERSION) throw new Error(`unsupported CIA state version ${state.version} (expected ${CIA_STATE_VERSION})`);
  state.accounts ??= {}; state.issued ??= {}; state.rps ??= {}; state.openings ??= []; state.revoked ??= []; state.pending ??= []; state.epoch ??= 0;
  return { state, notes };
}
```

Run: `node tests/test_mode3_cia_state.js` → Expected: 전부 ok. `scripts/run_tests.sh` 의 `UNIT` 배열 끝에 `tests/test_mode3_cia_state.js` 추가.

- [ ] **Step 2: 격리 CIA 의 env 고정**

`tests/helpers/isolated_cia.mjs` 31~44행의 주석과 env 를:

```js
  // 자식은 dotenv/config 로 .env 를 읽는다 — 개발용 값(TTL·그리드·체인 RPC·하트비트)이 새어 들어오지 않도록 테스트가
  // 기대하는 값으로 고정한다. dotenv 는 이미 있는 키(빈 문자열 포함)를 덮지 않으므로 빈 문자열이 "기본값 사용"이다
  // (TTL 300블록, 그리드 100, chainId 는 기동 시 RPC 에서 읽은 값 하나). 하트비트는 끈다 — 테스트가 기대하지 않은
  // epoch 증가·블록 소비를 막는다. 하트비트 테스트는 extraEnv 로 다시 켠다.
  const env = {
    ...process.env,
    CIA_RPC_URL: process.env.CIA_RPC_URL || 'http://127.0.0.1:8545',
    CIA_TTL_BLOCKS: '', CIA_HEIGHT_GRID: '', CIA_REVOKE_SKEW_BLOCKS: '', CIA_CHAIN_RPCS: '',
    CIA_HEARTBEAT_BLOCKS: '0',
    CIA_TTL_SECONDS: '', CIA_CHAIN_IDS: '',   // 옛 키 — 경고만 나오게 비운다
    CIA_PORT: String(port),
    …(나머지 그대로)
```

- [ ] **Step 3: 테스트 갱신 — register/issue**

`tests/test_cia_register_issue.mjs`:
- 33~43행을 교체:

```js
// 사용자 서명은 (C_pt, chainid, allowAgent) 를 덮는다(2026-09-18 §3.3). CIA 는 로그인당 기록이 없다 — 옛 본문 재생으로
// 얻는 것은 같은 C_pt 의 자격증명 하나뿐이고 sk_i 없이는 쓸 수 없다.
const CHAIN_ID = 31337n;
const signUser = (prvBuf, C_pt, chainid, allowAgent) => signUserRequest(prvBuf.toString('hex'), C_pt, chainid, allowAgent);

async function issueRequest(u, overrides = {}, { chainid = CHAIN_ID, allowAgent = 0n, attrs = [19n, 410n, 0n, 0n] } = {}) {
  const blind = randomScalar();
  const { C_pt, proof } = await proveIssuance({ uid, arid, s_u: u.s_u, blind, pk_i, r_u: u.r_u, attrs });
  return { body: { uid: uid.toString(), C_pt: pointToStrings(C_pt), proof: serializeProof(proof), sig_u: await signUser(u.sk_u, C_pt, chainid, allowAgent), chainid: chainid.toString(), allowAgent: allowAgent.toString(), ...overrides }, C_pt, blind };
}
```
- 'public_keys' 케이스의 `ttlSeconds` 단언을 `assert.equal(r.body.ttlBlocks, 300); assert.equal(r.body.heightGrid, 100); assert.equal(r.body.heartbeatBlocks, 0); assert.deepEqual(r.body.chainIds, ['31337']);` 로.
- 'issue: 올바른 π_issue' 케이스의 서명·만료 단언(134~143행)을 교체:

```js
    // σ_CIA 가 credMessage(C, max_height, chainid, allowAgent) 에 대한 pk_CIA 서명인지
    const msg = F.e(await credMessage(BigInt(cred.C), BigInt(cred.max_height), BigInt(cred.chainid), BigInt(cred.allowAgent)));
    const sig = { R8: [F.e(BigInt(cred.sigma.R8x)), F.e(BigInt(cred.sigma.R8y))], S: BigInt(cred.sigma.S) };
    const pub = [F.e(BigInt(cred.pk_CIA.x)), F.e(BigInt(cred.pk_CIA.y))];
    assert.ok(eddsa.verifyPoseidon(msg, sig, pub));
    // max_height = ceil((head + 300) / 100) × 100 — 그리드 배수이고 [head+300, head+400) 안(2026-09-18 §3.2)
    const head = BigInt(await provider.getBlockNumber());
    const mh = BigInt(cred.max_height);
    assert.equal(mh % 100n, 0n, cred.max_height);
    assert.ok(mh >= head + 300n && mh < head + 400n, `max_height ${mh} vs head ${head}`);
    assert.equal(cred.chainid, '31337');
    assert.equal(cred.allowAgent, '0');
    assert.equal(cred.exptime, undefined); assert.equal(cred.r_s, undefined);
```
  (파일 상단에 `provider` 가 없으면 `import { getProvider } from './helpers/mode3_chain.mjs'; const provider = getProvider();` 를 추가하고 `finally` 에서 `provider.destroy()` — 이미 있으면 그대로.)
- '사용자 서명이 다른 키면 400' 의 `signUser(Buffer.alloc(32, 7), C_pt, CHAIN_ID, BigInt(body.r_s))` → `signUser(Buffer.alloc(32, 7), C_pt, CHAIN_ID, 0n)`.
- '같은 r_s 로 다른 C_pt 는 200 …' 케이스를 교체:

```js
  await t('issue: allowAgent 는 서명이 덮는다 — 플래그만 바꾸면 400, 2 는 400, 없으면 400, 허용 목록 밖 chainid 는 400', async () => {
    const flipped = await issueRequest(user);
    flipped.body.allowAgent = '1';
    assert.equal((await cia.post('/cia/issue', flipped.body)).status, 400);
    const two = await issueRequest(user, { allowAgent: '2' });
    assert.equal((await cia.post('/cia/issue', two.body)).status, 400);
    const missing = await issueRequest(user);
    delete missing.body.allowAgent;
    assert.equal((await cia.post('/cia/issue', missing.body)).status, 400);
    const wrongChain = await issueRequest(user, {}, { chainid: 1n });
    const r2 = await cia.post('/cia/issue', wrongChain.body);
    assert.equal(r2.status, 400, JSON.stringify(r2.body));
    assert.match(r2.body.error, /chainid/);
  });

  await t('issue: allowAgent = 1 로 서명한 요청은 200 이고 응답의 allowAgent 도 1', async () => {
    const { body } = await issueRequest(user, {}, { allowAgent: 1n });
    const r = await cia.post('/cia/issue', body);
    assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.equal(r.body.allowAgent, '1');
  });
```
- '같은 C_pt 로 재요청하면 409' 케이스를 교체(본문 구조는 기존 것을 따르되 단언만):

```js
  await t('issue: 같은 C_pt 재요청은 200 — 같은 C 의 기록은 하나이고 max_height 는 큰 쪽(2026-09-18 §3.3·§4.3)', async () => {
    const { body } = await issueRequest(user);
    const a = await cia.post('/cia/issue', body);
    assert.equal(a.status, 200, JSON.stringify(a.body));
    await provider.send('hardhat_mine', ['0x64']);   // 100 블록 → 다음 그리드
    const b = await cia.post('/cia/issue', body);
    assert.equal(b.status, 200, JSON.stringify(b.body));
    assert.equal(b.body.C, a.body.C);
    assert.ok(BigInt(b.body.max_height) > BigInt(a.body.max_height));
    // 기록이 하나여야 한다: 리프로 폐기하면 inserted 가 정확히 1 개
    const r = await cia.adminPost('/cia/revoke', { uid: '12345', scope: 'credential', C: a.body.C });
    assert.equal(r.status, 200, JSON.stringify(r.body)); assert.equal(r.body.inserted.length, 1);
  });
```
- 289행 부근의 형식 오류 본문에서 `r_s: '1'` → `allowAgent: '0'`.
- I1/I3 을 교체:

```js
  await t('I1: max_height 가 지나도 CIA_REVOKE_SKEW_BLOCKS 안이면 계정 폐기 대상에 남는다', async () => {
    const skewCia = await startIsolatedCia({ env: { CIA_TTL_BLOCKS: '1', CIA_HEIGHT_GRID: '1', CIA_REVOKE_SKEW_BLOCKS: '600' } });
    try {
      const s_u = randomScalar(), r_u = randomScalar();
      const cm_u = await registrationCommit(s_u, r_u);
      const reg = await skewCia.post('/cia/register', { uid: '12345', pwd: 'password123', cm_u: pointToStrings(cm_u) });
      assert.equal(reg.status, 201, JSON.stringify(reg.body));
      const sk_u = Buffer.from(reg.body.sk_u, 'hex');
      const blind = randomScalar();
      const { C_pt, proof } = await proveIssuance({ uid, arid, s_u, blind, pk_i, r_u, attrs: [19n, 410n, 0n, 0n] });
      const body = { uid: uid.toString(), C_pt: pointToStrings(C_pt), proof: serializeProof(proof), sig_u: await signUser(sk_u, C_pt, CHAIN_ID, 0n), chainid: CHAIN_ID.toString(), allowAgent: '0' };
      const issued = await skewCia.post('/cia/issue', body);
      assert.equal(issued.status, 200, JSON.stringify(issued.body));
      await provider.send('hardhat_mine', ['0x5']);   // max_height(head+1) 는 지났지만 여유(600) 안
      const leaf = await credLeaf(BigInt(issued.body.C));
      const r = await skewCia.adminPost('/cia/revoke', { uid: '12345', scope: 'account' });
      assert.equal(r.status, 200, JSON.stringify(r.body));
      assert.ok(r.body.inserted.map((h) => BigInt(h)).includes(leaf), '만료됐지만 여유 안이라 폐기 대상에 남아야 한다');
    } finally { await skewCia.stop(); }
  });

  await t('I2: 여유까지 지난 기록은 걷어내져 계정 폐기 대상에서 빠진다', async () => {
    const ttlCia = await startIsolatedCia({ env: { CIA_TTL_BLOCKS: '1', CIA_HEIGHT_GRID: '1', CIA_REVOKE_SKEW_BLOCKS: '0' } });
    try {
      const s_u = randomScalar(), r_u = randomScalar();
      const cm_u = await registrationCommit(s_u, r_u);
      const reg = await ttlCia.post('/cia/register', { uid: '12345', pwd: 'password123', cm_u: pointToStrings(cm_u) });
      assert.equal(reg.status, 201, JSON.stringify(reg.body));
      const sk_u = Buffer.from(reg.body.sk_u, 'hex');
      const blind = randomScalar();
      const { C_pt, proof } = await proveIssuance({ uid, arid, s_u, blind, pk_i, r_u, attrs: [19n, 410n, 0n, 0n] });
      const body = { uid: uid.toString(), C_pt: pointToStrings(C_pt), proof: serializeProof(proof), sig_u: await signUser(sk_u, C_pt, CHAIN_ID, 0n), chainid: CHAIN_ID.toString(), allowAgent: '0' };
      const first = await ttlCia.post('/cia/issue', body);
      assert.equal(first.status, 200, JSON.stringify(first.body));
      await provider.send('hardhat_mine', ['0x5']);
      const r = await ttlCia.adminPost('/cia/revoke', { uid: '12345', scope: 'account' });
      assert.equal(r.status, 200, JSON.stringify(r.body));
      assert.deepEqual(r.body.inserted, [], '만료·여유 0 이면 리프가 걷어내져 있어야 한다');
    } finally { await ttlCia.stop(); }
  });

  await t('하트비트: CIA_HEARTBEAT_BLOCKS=2 면 게시 없이 블록이 지나도 같은 root 가 새 epoch 로 재게시되고 lastPublishedBlock 이 갱신된다', async () => {
    const hbCia = await startIsolatedCia({ env: { CIA_HEARTBEAT_BLOCKS: '2', CIA_HEARTBEAT_POLL_MS: '300' } });
    try {
      const log = new ethers.Contract(hbCia.logAddress, LOG_ABI, provider);
      const root0 = await log.root(), epoch0 = await log.epoch();
      await provider.send('hardhat_mine', ['0x3']);
      const deadline = Date.now() + 10_000;
      while (Date.now() < deadline && (await log.epoch()) === epoch0) await new Promise((r) => setTimeout(r, 200));
      assert.equal(await log.epoch(), epoch0 + 1n, hbCia.log());
      assert.equal(await log.root(), root0, '하트비트는 root 를 바꾸지 않는다');
      assert.ok(BigInt(await log.lastPublishedBlock()) > 0n);
      assert.equal((await hbCia.get('/cia/state')).body.epoch, Number(epoch0) + 1, 'CIA 상태의 epoch 도 따라간다');
    } finally { await hbCia.stop(); }
  });
```
  (import 에 `import { LOG_ABI } from '../lib/mode3_log.js';` 가 없으면 추가.)

- [ ] **Step 4: 테스트 갱신 — opening**

`tests/test_cia_opening.mjs`:
- `loginTranscript`: `const r_s = randomScalar();` 삭제, `buildIssueRequest({ …, attrs: [0n, 0n, 0n, 0n] })`(r_s 제거)에 `allowAgent` 인자를 받을 수 있게 `async function loginTranscript(svc, pk_trace = svc.pk_trace, allowAgent = 0n)` 으로 하고 `buildIssueRequest({ …, allowAgent })`; 반환 `{ proof, publicSignals, tag, PPID: publicSignals[0] }`.
- `openRequest`: `signOpenRequest(wallet, { arid, PPID: T.PPID, c1: { x: T.tag.c1.x.toString(), y: T.tag.c1.y.toString() }, D_svc, ts })`.
- '정상 경로' 케이스의 결과 단언(70행)을:

```js
    assert.equal(res.status, 200, j(res.body)); assert.equal(res.body.uid, '12345'); assert.equal(res.body.resolved, true);
    assert.equal(res.body.PPID, T1.PPID); assert.equal(res.body.r_s, undefined);
    assert.equal(res.body.allowAgent, '0'); assert.equal(res.body.max_height, T1.publicSignals[3]); assert.equal(res.body.chainid, '31337');
```
- 74행 케이스 이름을 `'같은 (arid, c1) 재요청은 새 id 를 만들지 않는다 (200, 같은 id)'` 로.
- 83행·175행의 `signOpenRequest(…, { arid: …, r_s: …, PPID: …, D_svc, ts })` 를 `c1` 형식으로(175행은 `c1: { x: tag.c1.x.toString(), y: tag.c1.y.toString() }`; 164~165행의 `r_s` 삭제).
- '정상 경로' 뒤에 추가:

```js
  await t('allowAgent = 1 로 로그인한 세션의 개봉 결과에는 allowAgent 1 이 남는다 (덱 22장의 용도)', async () => {
    const T = await loginTranscript(S1, S1.pk_trace, 1n);
    const { body: { id } } = await openRequest(S1, T);
    assert.equal((await cia.adminPost(`/cia/openings/${id}/approve`)).status, 200);
    const res = await fetchResult(S1, id);
    assert.equal(res.status, 200, j(res.body)); assert.equal(res.body.allowAgent, '1'); assert.equal(res.body.uid, '12345');
  });
```

- [ ] **Step 5: 테스트 갱신 — startup·race**

`tests/test_cia_startup.mjs`:
- `registerAndIssueLeaf`: `const blind = randomScalar();`, `signUserRequest(user.sk_u, C_pt, 31337n, 0n)`, 본문 `{ …, chainid: '31337', allowAgent: '0' }`.
- v3 이행 케이스: `assert.equal(saved.version, 4)` → `5`. 이름의 "v4 로" → "v5 로".
- 그 뒤에 추가:

```js
  await t('v4 상태 파일은 v5 로 이행된다 — 발급 기록은 비우고 계정·서비스·폐기·epoch 는 유지', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mode3-v4-'));
    const stateFile = path.join(dir, 'cia_state.json');
    fs.writeFileSync(stateFile, JSON.stringify({ version: 4, accounts: {}, issued: { '12345': [{ leaf: '9', C: '8', exptime: '1789000000' }] }, rps: {}, openings: [], revoked: [], pending: [], epoch: 0 }), { mode: 0o600 });
    const cia = await startIsolatedCia({ env: { CIA_STATE_FILE: stateFile } });
    try {
      const saved = JSON.parse(fs.readFileSync(stateFile, 'utf8'));
      assert.equal(saved.version, 5); assert.deepEqual(saved.issued, {});
      assert.match(cia.log(), /v4→v5/);
    } finally { await cia.stop(); fs.rmSync(dir, { recursive: true, force: true }); }
  });
```

`tests/test_cia_issue_race.mjs` 의 `issueBody`: `const blind = randomScalar();`, `signUserRequest(sk_u, C_pt, 31337n, 0n)`, 본문 `chainid: '31337', allowAgent: '0'`. 주석의 "chainAlive() 의 eth_blockNumber" 를 "headOf() 의 eth_blockNumber" 로.

- [ ] **Step 6: 실패 확인**

Run: `node tests/test_cia_register_issue.mjs` → Expected: 다수 FAIL(400 `r_s required` 등).

- [ ] **Step 7: 구현 — cia.js 설정·상태·유틸**

(1) import 에 추가: `import { CIA_STATE_VERSION, defaultCiaState, migrateCiaState } from './lib/mode3_cia_state.js';`, `mode3_trace.js` import 에 `resolveTagPlaintext` 추가. 파일 상단 주석에 `// V4(2026-09-18): 만료는 블록 높이(max_height), allowAgent, 체인 헤드 조회, 하트비트 게시, 개봉 평문 역조회 — 설계 2026-09-18-mode3-onchain-execution-design.md §4·§6.` 추가.

(2) 33~47행(`TTL_SECONDS` ~ `CHAIN_IDS`)을 교체:

```js
// 만료는 블록 높이다(설계 2026-09-18 §3.2). max_height = ceil((head + TTL) / GRID) × GRID — 같은 그리드 창에서 발급된
// 자격증명은 같은 값이라 AA 가 시각으로 특정하지 못한다(§2).
const TTL_BLOCKS = BigInt(process.env.CIA_TTL_BLOCKS || 300);
const HEIGHT_GRID = BigInt(process.env.CIA_HEIGHT_GRID || 100);
if (TTL_BLOCKS <= 0n || HEIGHT_GRID <= 0n) throw new Error(`CIA_TTL_BLOCKS(${TTL_BLOCKS})·CIA_HEIGHT_GRID(${HEIGHT_GRID}) 는 양수여야 한다`);
// 발급 기록을 만료 뒤에도 이만큼(블록) 더 들고 있다가 걷어낸다(설계 §4.3). 서비스의 체인 뷰가 CIA 보다 뒤처지면 그만큼 더
// 받아들이는데, 그때 기록을 이미 버렸으면 계정 폐기가 그 리프를 넣지 못한다 — 트리는 append-only 라 여분 리프는 무해하다.
const REVOKE_SKEW_BLOCKS = BigInt(process.env.CIA_REVOKE_SKEW_BLOCKS ?? 50);
if (REVOKE_SKEW_BLOCKS < 0n) throw new Error(`CIA_REVOKE_SKEW_BLOCKS(${REVOKE_SKEW_BLOCKS}) 는 0 이상이어야 한다`);
// 하트비트(설계 §4.5): 마지막 게시에서 이만큼 블록이 지나면 같은 root 를 새 epoch 로 재게시한다. 지갑 컨트랙트의
// MAX_ROOT_AGE(기본 100) 보다 작아야 한다. 0 이면 끈다(테스트).
const HEARTBEAT_BLOCKS = BigInt(process.env.CIA_HEARTBEAT_BLOCKS ?? 50);
const HEARTBEAT_POLL_MS = Number(process.env.CIA_HEARTBEAT_POLL_MS) || 5000;
for (const k of ['CIA_TTL_SECONDS', 'CIA_REVOKE_SKEW_SECONDS', 'CIA_CHAIN_IDS']) {
  if (process.env[k]) console.warn(`[cia] ${k} 는 더 이상 읽지 않는다(2026-09-18: 블록 높이·CIA_CHAIN_RPCS) — 무시`);
}
// 발급을 허용하는 체인과 그 헤드를 읽을 RPC(설계 §4.2). "chainid=url,chainid=url". 비어 있으면 기동 시 자기 provider 의
// chainId 하나를 RPC_URL 로 등록한다. 요청의 chainid 가 여기 없으면 400.
const CHAIN_RPCS = new Map();
for (const item of (process.env.CIA_CHAIN_RPCS || '').split(',').map((s) => s.trim()).filter(Boolean)) {
  const i = item.indexOf('=');
  if (i <= 0) throw new Error(`CIA_CHAIN_RPCS 항목 "${item}" 은 chainid=url 형식이어야 한다`);
  let id;
  try { id = BigInt(item.slice(0, i).trim()).toString(); } catch { throw new Error(`CIA_CHAIN_RPCS 의 chainid "${item.slice(0, i)}" 은 정수가 아니다`); }
  CHAIN_RPCS.set(id, item.slice(i + 1).trim());
}
const chainProviders = new Map();   // chainid → JsonRpcProvider (재사용)
```

(3) 77~92행의 상태 주석·상수를 교체:

```js
// ---- 상태 ----
// accounts:  uid → { pk_u:{x,y}, cm_u:{x,y}, disabled }
// issued:    uid → [ { leaf(10진), C(10진), max_height(10진 블록), chainid(10진) } ]   같은 leaf 는 하나(§4.3)
// rps:       arid → { name, origin, pk_service, X_svc, x_AA, pk_trace, status, requestedAt, decidedAt }   (2026-09-16 §3)
// openings:  [ { id, arid, PPID, c1:{x,y}, c2, D_svc:{x,y}, allowAgent, max_height, chainid, status, requestedAt, decidedAt,
//                uid|null, resolved } ]   영구 감사 기록(§6). uid·resolved 는 approved 에만 의미 있다
// revoked / pending / epoch
// 버전·이행은 lib/mode3_cia_state.js (v5, 2026-09-18).
const STATE_VERSION = CIA_STATE_VERSION;
let state;
let tree;            // 전체 폐기 트리(게시 여부 무관) — 서명해 올리는 root 의 출처
let publishedTree;   // 온체인에 이벤트로 나간 리프만 — 게시 직전 온체인 root 와 대조하는 기준
function defaultState() { return defaultCiaState(); }
```

(4) `loadState` 의 137~155행(`state = readJson…` 부터 `state.rps ??= {}; state.openings ??= [];` 까지)을 교체:

```js
  state = readJson(STATE_FILE, defaultState());
  let migrated;
  try { migrated = migrateCiaState(state); }
  catch (e) {
    console.error(`[cia] 기동 거부: ${e.message}. v2 이하는 옛 credential 형식이라 새 회로에서 검증되지 않으므로 마이그레이션하지 않는다 — ` +
      `재시연 세트(로그 재배포 → 상태 파일 삭제)로 새로 시작할 것.`);
    process.exit(1);
  }
  state = migrated.state;
  if (migrated.notes.length) { for (const n of migrated.notes) console.warn(`[cia] 상태 파일 이행 ${n}`); persist(); }
```
  173~176행(`CHAIN_IDS` 초기화)을 교체:

```js
  if (CHAIN_RPCS.size === 0) {
    try { CHAIN_RPCS.set((await ethWallet.provider.getNetwork()).chainId.toString(), RPC_URL); }
    catch (e) { console.warn(`[cia] 기동 시 chainId 를 읽지 못했다 — CIA_CHAIN_RPCS 가 없으면 발급은 503: ${e.message}`); }
  }
```

(5) 202~218행(`nowSec`, `pruneExpired`, `chainAlive`)을 교체(`headHeight` 는 그대로 둔다 — `/cia/state` 가 쓴다):

```js
function providerFor(chainStr) {
  if (!chainProviders.has(chainStr)) chainProviders.set(chainStr, new ethers.JsonRpcProvider(CHAIN_RPCS.get(chainStr), undefined, { cacheTimeout: -1 }));
  return chainProviders.get(chainStr);
}
/** 그 체인의 헤드. 발급 직전의 체인 가용성 확인(fail-closed, 기반 설계 §2.1)을 겸한다 — 못 읽으면 503. */
async function headOf(chainStr) {
  if (!LOG_ADDRESS) throw Object.assign(new Error('CIA_LOG_ADDRESS not configured'), { status: 503 });
  if (!CHAIN_RPCS.has(chainStr)) throw Object.assign(new Error(`bad chainid ${chainStr}: allowed ${[...CHAIN_RPCS.keys()].join(',')}`), { status: 400 });
  try { return BigInt(await providerFor(chainStr).getBlockNumber()); }
  catch { throw Object.assign(new Error('chain head unavailable'), { status: 503 }); }
}
/** 설계 §3.2: ceil((head + TTL) / GRID) × GRID. */
const quantizedMaxHeight = (head) => ((head + TTL_BLOCKS + HEIGHT_GRID - 1n) / HEIGHT_GRID) * HEIGHT_GRID;
/**
 * 만료(max_height + REVOKE_SKEW_BLOCKS < 그 체인의 head)된 발급 기록을 걷어내고 남은 것을 돌려준다. 체인별로 헤드를 읽는다.
 * 헤드를 못 읽은 체인의 항목은 남긴다(설계 §4.3) — 폐기 때 죽은 리프를 더 넣는 쪽이 산 리프를 빠뜨리는 쪽보다 낫다.
 */
async function pruneExpired(uid) {
  const list = state.issued[uid] ?? [];
  const heads = new Map();
  for (const e of list) {
    if (heads.has(e.chainid)) continue;
    try { heads.set(e.chainid, await headOf(e.chainid)); } catch { heads.set(e.chainid, null); }
  }
  state.issued[uid] = list.filter((e) => { const h = heads.get(e.chainid); return h === null || BigInt(e.max_height) + REVOKE_SKEW_BLOCKS >= h; });
  return state.issued[uid];
}
```

(6) `/cia/public_keys` 응답을 `{ pk_CIA: S(ciaPub), ethAddress: ethWallet.address, ttlBlocks: Number(TTL_BLOCKS), heightGrid: Number(HEIGHT_GRID), heartbeatBlocks: Number(HEARTBEAT_BLOCKS), chainIds: [...CHAIN_RPCS.keys()], logAddress: LOG_ADDRESS }` 로.

(7) `revokeAccount` 의 `pruneExpired(uid)` → `await pruneExpired(uid)`; `/cia/revoke` 의 `const issued = pruneExpired(uid);` → `const issued = await pruneExpired(uid);`. 기동 로그의 `ttl=${TTL_SECONDS}s, chains=${CHAIN_IDS.join(',') || 'none'}` → `ttl=${TTL_BLOCKS}blk/grid ${HEIGHT_GRID}, heartbeat=${HEARTBEAT_BLOCKS}, chains=${[...CHAIN_RPCS.keys()].join(',') || 'none'}`.

- [ ] **Step 8: 구현 — /cia/issue V4**

`app.post('/cia/issue', …)` 전체를 교체:

```js
// §4.1(2026-09-18) 발급. C 는 받지 않는다 — C_pt 에서 스스로 유도한다. 검사 순서: 형식 → disabled → chainid 허용 →
// 사용자 서명 → π_issue → 헤드 조회(체인 가용성, fail-closed) → disabled 재확인 → 서명·기록.
// 같은 C_pt 의 재요청은 200 이고 기록의 max_height 만 큰 쪽으로 갱신한다(§3.3·§4.3) — 재생으로 얻는 자격증명은
// 같은 C_pt 에 묶여 sk_i·증인 없이는 쓸 수 없다.
app.post('/cia/issue', async (req, res) => {
  try {
    const { uid, C_pt, proof, sig_u, chainid, allowAgent } = req.body ?? {};
    if (!isDec(uid) || !isPt(C_pt) || !proof || !sig_u || !isDec(chainid) || (allowAgent !== '0' && allowAgent !== '1')) {
      return res.status(400).json({ error: 'uid, C_pt, proof, sig_u, chainid, allowAgent("0"|"1") required' });
    }
    const acct = state.accounts[uid];
    if (!acct) return res.status(404).json({ error: 'unknown account' });
    if (acct.disabled) return res.status(403).json({ error: 'account disabled' });

    const chainStr = BigInt(chainid).toString();
    if (CHAIN_RPCS.size === 0) return res.status(503).json({ error: 'chain id unknown: CIA_CHAIN_RPCS not configured and RPC unreachable at startup' });
    if (!CHAIN_RPCS.has(chainStr)) return res.status(400).json({ error: `bad chainid ${chainStr}: allowed ${[...CHAIN_RPCS.keys()].join(',')}` });
    const agent = BigInt(allowAgent);

    const cpt = pointFromStrings(C_pt);
    // 사용자 인증: 등록된 pk_u 로 (C_pt, chainid, allowAgent) 에 대한 EdDSA-Poseidon 서명 검증
    let sigOk = false;
    try {
      const m = F.e(await issueRequestMessage(cpt, BigInt(chainStr), agent));
      const sig = { R8: [F.e(BigInt(sig_u.R8x)), F.e(BigInt(sig_u.R8y))], S: BigInt(sig_u.S) };
      const pub = [F.e(BigInt(acct.pk_u.x)), F.e(BigInt(acct.pk_u.y))];
      sigOk = eddsa.verifyPoseidon(m, sig, pub);
    } catch { sigOk = false; }
    if (!sigOk) return res.status(400).json({ error: 'bad user signature' });

    // π_issue: 이 C_pt 가 내 uid 의 것이고 s_u 가 등록된 cm_u 와 같다. 속성 슬롯은 검증하지 않는다(설계 §2).
    let proofOk = false;
    try { proofOk = await verifyIssuance({ uid: BigInt(uid), C_pt: cpt, cm_u: pointFromStrings(acct.cm_u), proof: parseProof(proof) }); }
    catch { proofOk = false; }
    if (!proofOk) return res.status(400).json({ error: 'bad issuance proof' });

    const C = await compressPoint(cpt);
    const Cstr = C.toString();

    const head = await headOf(chainStr);   // fail-closed: 체인이 죽어 있으면 발급하지 않는다(게시도 불가하므로 폐기가 닿지 않는 credential 이 된다)
    const max_height = quantizedMaxHeight(head);
    const s = eddsa.signPoseidon(ciaPrv, F.e(await credMessage(C, max_height, BigInt(chainStr), agent)));
    const leaf = await credLeaf(C);
    // 위 await 들 사이에 /cia/revoke·self_revoke 가 끼어들 수 있다 — 폐기 직후의 발급이 살아남으면 트리에 없는 새 credential 이
    // TTL 동안 유효하다. 마지막 await 뒤, 기록 직전에 disabled 를 다시 확인한다. 끼어든 revoke 의 pruneExpired 가 목록 배열을
    // 새로 만들었을 수 있어 state.issued[uid] 에 넣는다.
    if (acct.disabled) return res.status(403).json({ error: 'account disabled' });
    const list = (state.issued[uid] ??= []);
    const existing = list.find((e) => e.leaf === leaf.toString());
    if (existing) { if (BigInt(existing.max_height) < max_height) existing.max_height = max_height.toString(); existing.chainid = chainStr; }
    else list.push({ leaf: leaf.toString(), C: Cstr, max_height: max_height.toString(), chainid: chainStr });
    persist();
    res.json({
      C: Cstr, max_height: max_height.toString(), chainid: chainStr, allowAgent: agent.toString(),
      sigma: { R8x: F.toObject(s.R8[0]).toString(), R8y: F.toObject(s.R8[1]).toString(), S: s.S.toString() },
      pk_CIA: S(ciaPub),
    });
  } catch (e) {
    res.status(e.status || 500).json({ error: e.message });
  }
});
```

- [ ] **Step 9: 구현 — 게시 함수화 + 하트비트**

`let publishing = false;` 와 `app.post('/cia/publish', …)` 를 교체:

```js
let publishing = false;
/**
 * root 게시. heartbeat=true 면 pending 이 비어 있어도 같은 root 를 새 epoch 로 올린다(설계 §4.5) — 컨트랙트 조건은 epoch
 * 증가뿐이라 그대로다. 한 번에 하나만 돈다: 둘이 겹치면 각자 pending 을 자기 개수만큼 앞에서 잘라 그 사이 들어온 revoke 의
 * 리프가 pending 에서만 사라진다(트리·서명 root 에는 남아 지갑 재구성이 영구히 실패).
 */
async function publishNow({ heartbeat = false } = {}) {
  if (publishing) throw Object.assign(new Error('publish already in progress'), { status: 409 });
  publishing = true;
  try {
    if (!LOG_ADDRESS) throw Object.assign(new Error('CIA_LOG_ADDRESS not configured'), { status: 503 });
    // 게시 직전 대조(기동 시와 같은 규칙). 온체인 root 가 우리가 아는 어느 접두사와도 다르면 올리지 않는다.
    let chain;
    try { chain = await readChain(); }
    catch (e) { throw Object.assign(new Error(`chain unavailable: ${e.message}`), { status: 503 }); }
    if (!(await reconcileWithChain(chain))) {
      publishedTree = await buildPublishedTree();   // 걷다 만 트리를 되돌린다
      throw Object.assign(new Error(`onchain root ${chain.onchainRoot} 가 로컬 게시 기록의 어느 접두사와도 다르다 — ` +
        `로그를 재배포했거나 상태 파일이 유실·복원됐다. CIA_STATE_FILE 과 CIA_LOG_ADDRESS 를 확인할 것`), { status: 503 });
    }
    if (state.pending.length === 0 && !heartbeat) return { published: false, heartbeat: false, epoch: state.epoch, root: tree.getRoot().toString() };
    const log = new ethers.Contract(LOG_ADDRESS, LOG_ABI, ethWallet);
    const leaves = state.pending.map(rootToBytes32);
    const root = rootToBytes32(tree.getRoot());
    const epoch = state.epoch + 1;   // reconcileWithChain 이 state.epoch 를 온체인과 맞췄다
    const sig = await signRootPublication(ethWallet, { logAddress: LOG_ADDRESS, root, epoch, leaves });
    const tx = await log.publishRoot(root, epoch, leaves, sig);
    await tx.wait();
    state.epoch = epoch;
    // 위 await 들 사이에 pending 뒤에 붙은 리프는 이번 tx 에 실리지 않았다 — 이번에 실은 앞부분만 지운다.
    for (const l of state.pending.slice(0, leaves.length)) await publishedTree.insert(BigInt(l));
    state.pending = state.pending.slice(leaves.length);
    persist();
    return { published: true, heartbeat: leaves.length === 0, epoch, root: tree.getRoot().toString(), txHash: tx.hash, leaves };
  } finally { publishing = false; }
}
app.post('/cia/publish', requireAdmin, async (req, res) => {
  try { res.json(await publishNow()); }
  catch (e) { res.status(e.status || 500).json({ error: e.message }); }
});
/** 하트비트 틱(설계 §4.5): 마지막 게시에서 HEARTBEAT_BLOCKS 이상 지났으면 재게시. pending 이 있으면 그것도 같이 나간다. */
async function heartbeatTick() {
  if (publishing || !LOG_ADDRESS) return;
  try {
    const log = new ethers.Contract(LOG_ADDRESS, LOG_ABI, ethWallet);
    const [head, last] = await Promise.all([ethWallet.provider.getBlockNumber(), log.lastPublishedBlock()]);
    if (BigInt(head) - BigInt(last) < HEARTBEAT_BLOCKS) return;
    const r = await publishNow({ heartbeat: true });
    console.log(`[cia] 하트비트 게시: epoch ${r.epoch}, 리프 ${r.leaves.length}개, head ${head}`);
  } catch (e) { console.warn(`[cia] 하트비트 실패: ${e.message}`); }
}
```

기동부(`app.listen` 앞)에:

```js
if (HEARTBEAT_BLOCKS > 0n) {
  const hb = setInterval(heartbeatTick, HEARTBEAT_POLL_MS);
  hb.unref();
}
```

- [ ] **Step 10: 구현 — 개봉 V2**

`/cia/open/request` 안에서:
- 구조 분해 `const [PPID, aridIn, , , , r_s, , ciaX, …]` → `const [PPID, aridIn, , max_height, chainIn, allowAgent, , ciaX, ciaY, traceX, traceY, c1x, c1y, c2] = publicSignals;`
- 서명 검사: `recoverSigner(openRequestMessage({ arid, PPID, c1: { x: c1x, y: c1y }, D_svc, ts }), sig)`.
- `wrong_trace_key` 검사 뒤에 추가: `if (!CHAIN_RPCS.has(BigInt(chainIn).toString())) return res.status(403).json({ error: 'wrong_chain' });` 와 `if (BigInt(allowAgent) > 1n) return res.status(403).json({ error: 'bad_allow_agent' });`.
- 중복 판정: `state.openings.find((o) => o.arid === arid && o.c1.x === c1x && o.c1.y === c1y && (o.status === 'pending' || o.status === 'approved'))`.
- push 항목: `{ id, arid, PPID, c1: { x: c1x, y: c1y }, c2, D_svc: { x: D_svc.x, y: D_svc.y }, allowAgent, max_height, chainid: chainIn, status: 'pending', requestedAt: new Date().toISOString(), decidedAt: null, uid: null, resolved: null }`.
- 주석의 "arid 대조가 없으면 …" 뒤에 "복호 결과는 Poseidon(uid, arid) 라 등록부로 역조회한다(§6.2)." 추가.

`/cia/openings/:id/approve`:

```js
    const e = state.rps[o.arid];
    const D_aa = await partialDecrypt(BigInt(e.x_AA), pointFromStrings(o.c1));
    const h = await combineDecrypt(BigInt(o.c2), pointFromStrings(o.D_svc), D_aa);
    // 평문은 Poseidon(uid, arid)(2026-09-18 §3.4) — 등록부의 uid 마다 계산해 되찾는다. 못 찾으면 D_svc 가 틀렸거나(서비스 자신의
    // 요청만 망친다) 계정이 등록부에 없는 것이다. 어느 쪽이든 approved 로 기록하되 resolved=false 로 남긴다(§6.2).
    const uid = await resolveTagPlaintext(h, BigInt(o.arid), Object.keys(state.accounts));
    o.decidedAt = new Date().toISOString();
    o.status = 'approved'; o.uid = uid; o.resolved = uid !== null;
    persist();
    res.json({ id: o.id, status: o.status, resolved: o.resolved });
```

`GET /cia/open/:id` 의 마지막 응답: `res.json({ id: o.id, status: o.status, uid: o.uid, resolved: o.resolved, PPID: o.PPID, allowAgent: o.allowAgent, max_height: o.max_height, chainid: o.chainid, decidedAt: o.decidedAt });`.

- [ ] **Step 11: 통과 확인**

:8545 필요. Run:
```bash
node tests/test_mode3_cia_state.js && node tests/test_cia_register_issue.mjs && node tests/test_cia_opening.mjs && node tests/test_cia_startup.mjs && node tests/test_cia_issue_race.mjs && node tests/test_mode3_e2e.mjs
```
Expected: 전부 `FAIL` 0. (`test_cia_opening.mjs` 의 'failed' 관련 케이스가 있으면 — D_svc 가 틀린 요청은 이제 `approved`+`resolved:false` 다 — 그에 맞게 단언을 고친다: `res.body.status === 'approved' && res.body.resolved === false && res.body.uid === null`.)

- [ ] **Step 12: 커밋**

```bash
git add lib/mode3_cia_state.js tests/test_mode3_cia_state.js cia.js tests/helpers/isolated_cia.mjs tests/test_cia_register_issue.mjs tests/test_cia_opening.mjs tests/test_cia_startup.mjs tests/test_cia_issue_race.mjs tests/test_mode3_e2e.mjs scripts/run_tests.sh
git commit -m "feat(mode3): CIA V4 — max_height 양자화·allowAgent 발급, CIA_CHAIN_RPCS 헤드, 상태 v5, 하트비트 게시, 개봉 평문 역조회"
```

---

### Task 6: 서버 V4 — 지갑 에이전트(`allowAgent`, `/wallet/tx`), 서비스(팩토리 배포, 로그인 V4, 해시 개봉)

**Files:**
- Modify: `mode3_wallet_agent.js` (전체 흐름: 상태 v5, 로그인 필드, `/wallet/status`, `proveSession`, 신규 `/wallet/tx`)
- Modify: `mode3_rp.js` (등록 파일 v3, `ensureFactory`, `rp_info`/`challenge`, `login`/`revalidate`/`request` V4, `open` 의 `txHash`)
- Modify: `tests/helpers/isolated_mode3_stack.mjs` (env 고정, `ciaEnv` 옵션)
- Test: `tests/test_mode3_wallet_agent.mjs`, `tests/test_mode3_demo_stack.mjs`

**Interfaces:**
- Consumes: Task 3 `lib/mode3_onchain.js` 전부, Task 4 `buildIssueRequest({allowAgent})`·`verifyLogin({r_s})`, Task 5 CIA V4 응답.
- Produces(지갑 HTTP): `POST /wallet/login { arid, origin, cert_s, pk_trace, r_s, allowAgent?: "0"|"1", factoryAddress?: 0x… }` → 기존 필드 + `allowAgent`; `POST /wallet/tx { r_s, to, value?: wei 10진, data?: hex }` → `{ txHash, wallet, nonce, status, ok, gasUsed, deployed, cacheHit, root, timings }` / 409 `no_factory|session_expired|execute_reverted(detail=revert 이름)` / 403 `revoked`; `GET /wallet/status` 세션에 `max_height, allowAgent, factoryAddress, PPID`.
- Produces(서비스 HTTP): `GET /api/mode3/rp_info` + `factoryAddress, verifierAddress`; `POST /api/mode3/challenge` → `{ r_s, expiresAt, factoryAddress }`; `POST /api/mode3/login { proof, publicSignals, sig, r_s }` → `{ ok, PPID, pk_i, r_s, root, allowAgent }`; `POST /api/mode3/revalidate { …, r_s }`; `POST /api/mode3/open { PPID } | { txHash }`.
- 환경변수: 지갑 `MODE3_RELAYER_INDEX`(0); 서비스 `MODE3_RP_FACTORY_ADDRESS`, `MODE3_VERIFIER_ADDRESS`, `MODE3_MAX_ROOT_AGE`(100), `MODE3_RELAYER_INDEX`(0).

**계획 판정:** 스펙 §6.3 의 `POST /wallet/tx { arid, … }` 는 세션 식별을 `r_s` 로 한다(지갑의 다른 엔드포인트와 같은 키). 스펙 §6.2 의 `{loginId}` 는 현재 UI 가 쓰는 `{PPID}`(마지막 트랜스크립트)를 그대로 두고 `{txHash}` 를 더한다. `allowAgent` 체크박스는 로그인을 시작하는 서비스 페이지에 두고 지갑으로 전달한다(지갑 페이지는 표시만).

- [ ] **Step 1: 격리 스택 헬퍼**

`tests/helpers/isolated_mode3_stack.mjs`: `PINNED_ENV` 에 `MODE3_RP_FACTORY_ADDRESS: '', MODE3_VERIFIER_ADDRESS: '', MODE3_RELAYER_INDEX: '', MODE3_MAX_ROOT_AGE: ''` 추가. `startIsolatedMode3Stack(opts)` 의 구조 분해에 `ciaEnv = {}` 를 추가하고 `startIsolatedCia()` 를 `startIsolatedCia({ env: ciaEnv })` 로.

- [ ] **Step 2: 테스트 — 지갑 에이전트(실패)**

`tests/test_mode3_wallet_agent.mjs`:
- import 추가: `import { ethers } from 'ethers';`, `import { deployVerifier, deployFactory, walletAt } from '../lib/mode3_onchain.js';`, `import { LOG_ABI } from '../lib/mode3_log.js';`.
- 스택 기동을 `startIsolatedMode3Stack({ rp: false, ciaEnv: { CIA_HEARTBEAT_BLOCKS: '5', CIA_HEARTBEAT_POLL_MS: '300' } })` 로(하트비트 회복 케이스용. 5 블록마다 재게시되므로 stale_root 케이스는 게시 직후 바로 확인한다 — 아래 순서를 지킬 것).
- `verify` 를 `const verify = (body, r_s) => rp.verifyLogin({ proof: body.proof, publicSignals: body.publicSignals, sig: body.sig, r_s: BigInt(r_s) });` 로 바꾸고 모든 호출에 두 번째 인자(그 세션의 r_s: `rs`, `S1`, `S2`)를 넘긴다.
- '첫 로그인' 케이스에 `assert.equal(r.body.allowAgent, '0'); assert.equal(r.body.publicSignals[5], '0');` 추가.
- '입력 검증' 케이스에 `assert.equal((await login(newRs(), { allowAgent: '2' })).status, 400);` 추가.
- 'status' 케이스를 교체:

```js
  await t('status: 세션이 max_height(블록)·allowAgent·PPID 를 보여주고 exptime 은 없다', async () => {
    const s = await wallet.get('/wallet/status');
    const c = s.body.sessions[S2];
    assert.ok(c, 'S2 세션이 상태에 있어야 한다');
    assert.match(String(c.max_height), /^[0-9]+$/);
    assert.equal(c.exptime, undefined);
    assert.equal(c.allowAgent, '0');
    assert.match(String(c.PPID), /^[0-9]+$/);
    assert.ok(BigInt(c.max_height) > BigInt(await provider.getBlockNumber()));
  });
```
- 'request' 케이스 뒤에 추가:

```js
  await t('allowAgent=1 로그인: 공개 입력 [5] 가 1', async () => {
    const rs = newRs();
    const r = await login(rs, { allowAgent: '1' });
    assert.equal(r.status, 200, j(r.body));
    assert.equal(r.body.publicSignals[5], '1'); assert.equal(r.body.allowAgent, '1');
    assert.equal((await verify(r.body, rs)).ok, true);
  });

  let factoryAddress, S3, walletAddr;
  await t('tx: factoryAddress 없이 로그인한 세션은 409 no_factory', async () => {
    const r = await wallet.post('/wallet/tx', { r_s: S2, to: ethers.Wallet.createRandom().address }, { Origin: stack.rpOriginForWallet });
    assert.equal(r.status, 409, j(r.body)); assert.equal(r.body.reason, 'no_factory');
  });

  await t('tx: 팩토리를 준 세션 — 첫 트랜잭션은 지갑 배포 + 실행 ok, 두 번째는 캐시 π 재사용·nonce 1', async () => {
    const signer = await provider.getSigner(0);
    const verifierAddress = await deployVerifier(signer);
    factoryAddress = await deployFactory(signer, { verifierAddress, arid, pkCIA: pk_CIA, pkTrace: pk_trace, logAddress: cia.logAddress, maxRootAge: 10n });
    S3 = newRs();
    const l = await login(S3, { factoryAddress });
    assert.equal(l.status, 200, j(l.body));
    const to = ethers.Wallet.createRandom().address;
    const r1 = await wallet.post('/wallet/tx', { r_s: S3, to, value: '0' }, { Origin: stack.rpOriginForWallet });
    assert.equal(r1.status, 200, j(r1.body));
    assert.equal(r1.body.deployed, true); assert.equal(r1.body.ok, true); assert.equal(r1.body.nonce, '0'); assert.match(r1.body.txHash, /^0x[0-9a-f]{64}$/);
    walletAddr = r1.body.wallet;
    assert.notEqual(await provider.getCode(walletAddr), '0x');
    const r2 = await wallet.post('/wallet/tx', { r_s: S3, to }, { Origin: stack.rpOriginForWallet });
    assert.equal(r2.status, 200, j(r2.body));
    assert.equal(r2.body.deployed, false); assert.equal(r2.body.cacheHit, true); assert.equal(r2.body.nonce, '1');
    assert.equal(await walletAt(walletAddr, provider).nonce(), 2n);
    console.log(`     execute gas ${r1.body.gasUsed} (배포 포함 tx 아님 — execute 만)`);
  });

  await t('tx: 값 전송 — 릴레이어가 지갑에 입금한 뒤 value 를 보내면 수신자 잔액이 는다', async () => {
    const signer = await provider.getSigner(0);
    await (await signer.sendTransaction({ to: walletAddr, value: ethers.parseEther('0.5') })).wait();
    const to = ethers.Wallet.createRandom().address;
    const r = await wallet.post('/wallet/tx', { r_s: S3, to, value: ethers.parseEther('0.1').toString() }, { Origin: stack.rpOriginForWallet });
    assert.equal(r.status, 200, j(r.body)); assert.equal(r.body.ok, true);
    assert.equal(await provider.getBalance(to), ethers.parseEther('0.1'));
  });

  await t('tx: root 게시가 maxRootAge(10) 보다 오래되면 execute_reverted RootTooOld, CIA 하트비트 뒤 다시 ok', async () => {
    const log = new ethers.Contract(cia.logAddress, LOG_ABI, provider);
    const last0 = await log.lastPublishedBlock();
    await provider.send('hardhat_mine', ['0xb']);
    // 하트비트가 먼저 돌아 버리면 revert 를 못 본다 — 게시 뒤 11 블록 안에 제출한다(하트비트는 5 블록마다 300ms 폴링).
    const r = await wallet.post('/wallet/tx', { r_s: S3, to: ethers.Wallet.createRandom().address }, { Origin: stack.rpOriginForWallet });
    if (r.status === 409) assert.match(r.body.detail, /RootTooOld/, j(r.body));
    else assert.equal(r.status, 200, j(r.body));   // 하트비트가 이미 따라잡았으면 그대로 ok — 아래에서 lastPublishedBlock 전진만 확인
    const deadline = Date.now() + 10_000;
    while (Date.now() < deadline && (await log.lastPublishedBlock()) === last0) await new Promise((res) => setTimeout(res, 200));
    assert.ok((await log.lastPublishedBlock()) > last0, `하트비트가 게시했어야 한다\n${cia.log()}`);
    const ok = await wallet.post('/wallet/tx', { r_s: S3, to: ethers.Wallet.createRandom().address }, { Origin: stack.rpOriginForWallet });
    assert.equal(ok.status, 200, j(ok.body)); assert.equal(ok.body.ok, true);
  });

  await t('tx: 계정 폐기 + 게시 뒤에는 403 revoked (재증명 불가)', async () => {
    assert.equal((await cia.adminPost('/cia/revoke', { uid, scope: 'account' })).status, 200);
    assert.equal((await cia.adminPost('/cia/publish')).body.published, true);
    const r = await wallet.post('/wallet/tx', { r_s: S3, to: ethers.Wallet.createRandom().address }, { Origin: stack.rpOriginForWallet });
    assert.equal(r.status, 403, j(r.body)); assert.equal(r.body.reason, 'revoked');
    assert.equal((await cia.adminPost('/cia/account/set_disabled', { uid, disabled: false })).status, 200);
  });

  await t('tx 입력 검증: r_s 없음·주소 아님·모르는 세션', async () => {
    assert.equal((await wallet.post('/wallet/tx', { to: walletAddr }, { Origin: stack.rpOriginForWallet })).status, 400);
    assert.equal((await wallet.post('/wallet/tx', { r_s: S3, to: 'nope' }, { Origin: stack.rpOriginForWallet })).status, 400);
    assert.equal((await wallet.post('/wallet/tx', { r_s: newRs(), to: walletAddr }, { Origin: stack.rpOriginForWallet })).status, 404);
  });
```
  주의: 기존 '계정 폐기 + 게시 → skipSync 재검증 … stale_root' 케이스는 하트비트(5블록)가 게시하면 root 는 그대로라 여전히 stale 이 아니다 — 폐기 게시 직후 바로 검증하므로 영향 없다. 'CORS' 케이스에 `/wallet/tx` 의 OPTIONS 도 같은 단언으로 한 줄 추가한다.

- [ ] **Step 3: 테스트 — 데모 스택(실패)**

`tests/test_mode3_demo_stack.mjs`:
- `loginViaRp(allowAgent = '0')`: challenge 응답에서 `{ r_s, factoryAddress }` 를 받고 지갑 login 본문에 `allowAgent, factoryAddress` 를, RP login 본문에 `r_s` 를 넣는다. 반환에 `factoryAddress` 추가.
- `revalidateViaRp`: RP revalidate 본문에 `r_s` 추가.
- 'rp_info' 케이스에 `assert.match(r.body.factoryAddress, /^0x[0-9a-fA-F]{40}$/); assert.match(r.body.verifierAddress, /^0x[0-9a-fA-F]{40}$/);`.
- '2. 로그인' 케이스에 `assert.equal(r.rp.allowAgent, '0');`; `sessions`·`logins` 단언은 그대로.
- 'session_mismatch' 케이스의 `buildIssueRequest({ …, r_s: BigInt(mine.r_s) })` → `r_s` 제거; `rp.post('/api/mode3/revalidate', { proof, publicSignals, sig })` → `{ proof, publicSignals, sig, r_s: mine.r_s }`.
- '같은 r_s 로 /login 을 다시 내면' 케이스: RP login 본문에 `r_s: S1` 추가. 'r_s 음성' 케이스: 두 RP login 본문에 각각 `r_s: bogus`, `r_s` 추가. 'login 입력 검증': 그대로(400).
- "3''" 뒤에 추가:

```js
  let TX1;
  await t('2a. 온체인 트랜잭션: 지갑 배포 + execute ok, 두 번째는 같은 π 재사용(cacheHit)', async () => {
    const to = '0x000000000000000000000000000000000000dEaD';
    const r1 = await wallet.post('/wallet/tx', { r_s: S1, to }, { Origin: rp.origin });
    assert.equal(r1.status, 200, j(r1.body)); assert.equal(r1.body.ok, true); assert.equal(r1.body.deployed, true);
    const r2 = await wallet.post('/wallet/tx', { r_s: S1, to }, { Origin: rp.origin });
    assert.equal(r2.status, 200, j(r2.body)); assert.equal(r2.body.cacheHit, true); assert.equal(r2.body.nonce, '1');
    TX1 = r2.body.txHash;
  });

  await t('2b. 해시 기반 개봉: 서비스가 txHash 로 요청 → 승인 → uid·allowAgent(0)', async () => {
    const r = await rp.post('/api/mode3/open', { txHash: TX1 });
    assert.equal(r.status, 200, j(r.body));   // 같은 세션(같은 c1)의 개봉이 9 보다 먼저 여기서 생긴다 → 202. 이미 있으면 200
    const id = r.body.id;
    assert.equal((await cia.adminPost(`/cia/openings/${id}/approve`)).body.status, 'approved');
    const res = await rp.get(`/api/mode3/open/${id}`);
    assert.equal(res.status, 200, j(res.body)); assert.equal(res.body.uid, uid); assert.equal(res.body.allowAgent, '0'); assert.equal(res.body.PPID, PPID1);
    assert.equal((await rp.post('/api/mode3/open', { txHash: '0x' + '11'.repeat(32) })).status, 404);
  });
```
  ('2b' 의 첫 단언은 `[200, 202].includes(r.status)` 로 쓴다 — 어느 쪽이든 `id` 가 있다.)
- '5.' 케이스 끝에 추가: `const tx = await wallet.post('/wallet/tx', { r_s: S1, to: '0x000000000000000000000000000000000000dEaD' }, { Origin: rp.origin }); assert.equal(tx.status, 403, j(tx.body)); assert.equal(tx.body.reason, 'revoked');` (동기화하면 폐기를 본다).
- '9.' 케이스: 이름의 "같은 세션 재요청은 같은 id" 유지. `r2` 주석을 "같은 (arid, c1)" 로. 마지막 로그인 트랜스크립트가 8 의 세션이라 새 id 가 나온다 — 기존 단언 그대로 성립한다.
- 새 케이스(9 뒤): 

```js
  await t('9a. allowAgent=1 로그인 → PPID 개봉 결과에 allowAgent 1', async () => {
    const r = await loginViaRp('1');
    assert.equal(r.rp.ok, true, j(r)); assert.equal(r.rp.allowAgent, '1');
    const o = await rp.post('/api/mode3/open', { PPID: PPID1 });
    assert.equal(o.status, 202, j(o.body));
    assert.equal((await cia.adminPost(`/cia/openings/${o.body.id}/approve`)).status, 200);
    const res = await rp.get(`/api/mode3/open/${o.body.id}`);
    assert.equal(res.body.allowAgent, '1'); assert.equal(res.body.uid, uid);
  });
```

Run: `node tests/test_mode3_wallet_agent.mjs` → Expected: FAIL 다수(`allowAgent` 미지원, `/wallet/tx` 404).

- [ ] **Step 4: 구현 — mode3_wallet_agent.js**

(1) import 추가: `import { signPayload, proofToCalldata, parseExecuteReceipt, factoryAt, walletAt } from './lib/mode3_onchain.js';`, `lib/mode3_credential.js` import 에 `ppid`. 상단 주석에 `// V4(2026-09-18): 자격증명은 max_height·allowAgent, 세션은 서비스 팩토리 주소를 들고 /wallet/tx 로 온체인 실행(설계 §6.3).`

(2) 상태 블록(31~49행)을 교체:

```js
// ---- 상태 ----
// registration: { uid, s_u, r_u, cm_u:{x,y}, sk_u, attrs:[4개 10진] }   §6.1. 한 번
// sessions:     r_s → { arid, PPID, pk_trace:{x,y}, factoryAddress|null, allowAgent("0"|"1"),
//                       credential:{C,max_height,chainid,allowAgent,sigma,pk_CIA}, blind, sessionPrivKey, pk_i, issuedAt }
// version 5 (2026-09-18): 자격증명 V4·PPID·factoryAddress·allowAgent. 옛 파일은 등록만 살리고 세션은 비운다.
const WALLET_STATE_VERSION = 5;
let state = readJson(STATE_FILE, { version: WALLET_STATE_VERSION, registration: null, sessions: {} });
function persist() { writeJsonAtomic(STATE_FILE, state, 0o600); }
if (state.version !== WALLET_STATE_VERSION) {
  console.warn(`[wallet] 상태 파일 버전 ${state.version} → ${WALLET_STATE_VERSION}: 세션·credential 을 비운다(옛 형식). 등록은 유지.`);
  state = { version: WALLET_STATE_VERSION, registration: state.registration ?? null, sessions: {} };
  persist();
}
state.sessions ??= {};
/** 만료(head > max_height)된 세션을 걷어낸다(설계 §8). 동기화 뒤 head 를 알 때 부른다. */
function pruneSessions(head) {
  let changed = false;
  for (const [k, s] of Object.entries(state.sessions)) if (BigInt(s.credential.max_height) < head) { delete state.sessions[k]; changed = true; }
  if (changed) persist();
}
```
  (`nowSec` 는 더 쓰지 않으면 지운다.)

(3) `issueCredential` 을 교체:

```js
async function issueCredential(arid, r_s, pk_trace, allowAgent, factoryAddress) {
  const reg = state.registration;
  const session = createSessionKey();
  const chainid = await chainId();
  const req = await buildIssueRequest({
    uid: BigInt(reg.uid), arid: BigInt(arid), s_u: BigInt(reg.s_u), r_u: BigInt(reg.r_u), sk_u: reg.sk_u, session,
    chainid, attrs: (reg.attrs ?? []).map(BigInt), allowAgent: BigInt(allowAgent),
  });
  const r = await ciaPost('/cia/issue', req.body);
  if (r.status === 200) {
    const PPID = await ppid({ uid: BigInt(reg.uid), arid: BigInt(arid), s_u: BigInt(reg.s_u), chainid });
    state.sessions[r_s.toString()] = {
      arid, PPID: PPID.toString(), pk_trace: { x: pk_trace.x.toString(), y: pk_trace.y.toString() }, factoryAddress, allowAgent,
      credential: r.body, blind: req.secrets.blind.toString(),
      sessionPrivKey: session.wallet.privateKey, pk_i: session.pk_i.toString(),
      issuedAt: new Date().toISOString(),
    };
    persist();
  }
  return r;
}
```

(4) CORS 목록에 `app.options('/wallet/tx', loginCors);` 추가. `/wallet/status` 의 세션 뷰를 `{ arid: e.arid, PPID: e.PPID, max_height: e.credential.max_height, chainid: e.credential.chainid, allowAgent: e.allowAgent, factoryAddress: e.factoryAddress, sessionAddress: …, issuedAt: e.issuedAt, pk_trace: e.pk_trace }` 로.

(5) `/wallet/login`: 구조 분해를 `const { arid, origin, cert_s, pk_trace, r_s, allowAgent = '0', factoryAddress = null } = req.body ?? {};` 로, 형식 검사 뒤에 `if (allowAgent !== '0' && allowAgent !== '1') return res.status(400).json({ error: 'allowAgent 는 "0" 또는 "1"' }); if (factoryAddress !== null && !isAddr(factoryAddress)) return res.status(400).json({ error: 'factoryAddress 는 주소' });` (`const isAddr = (v) => typeof v === 'string' && /^0x[0-9a-fA-F]{40}$/.test(v);` 를 `isDec` 옆에). `pruneSessions();` → `pruneSessions(synced.head);` (동기화 뒤로 옮긴다). `issueCredential(arid, rs, {…})` → `issueCredential(arid, rs, { x: BigInt(pk_trace.x), y: BigInt(pk_trace.y) }, allowAgent, factoryAddress ? ethers.getAddress(factoryAddress) : null)`. 응답 `{ ...out, issued: true, allowAgent, timings }`.

(6) `proveSession` 반환에 `allowAgent: s.allowAgent, max_height: s.credential.max_height` 추가. `/wallet/revalidate` 의 동기화 뒤에 `pruneSessions(synced.head); if (!state.sessions[rsKey]) return res.status(410).json({ reason: 'session_expired', timings });` 를 넣는다.

(7) `/wallet/request` 뒤에 `/wallet/tx` 추가:

```js
// ---- 온체인 실행(설계 2026-09-18 §6.3) ----
// 세션의 성명(같은 π)을 트랜잭션마다 첨부한다 — 컨트랙트가 매번 검증한다(사용자 결정 2026-09-17). 지갑 주소는 서비스 팩토리의
// computeAddress(PPID). 릴레이어는 hardhat 언락 계정(후원 실행 설계 2026-07-20 과 같은 방식) — 데모용이며 실제 배포의 번들러 자리다.
const RELAYER_INDEX = Number(process.env.MODE3_RELAYER_INDEX ?? 0);
app.post('/wallet/tx', loginCors, async (req, res) => {
  try {
    const { r_s, to, value = '0', data = '0x' } = req.body ?? {};
    if (!isDec(r_s) || !isAddr(to) || !isDec(value) || typeof data !== 'string' || !/^0x([0-9a-fA-F]{2})*$/.test(data)) {
      return res.status(400).json({ error: 'r_s, to(주소), value(wei 10진, 선택), data(hex, 선택) 필요' });
    }
    const rsKey = BigInt(r_s).toString();
    const s = state.sessions[rsKey];
    if (!s) return res.status(404).json({ reason: 'no_session' });
    if (!s.factoryAddress) return res.status(409).json({ reason: 'no_factory', detail: '서비스가 로그인 때 factoryAddress 를 주지 않았다' });
    if (!LOG_ADDRESS) return res.status(503).json({ reason: 'chain_unavailable', detail: 'CIA_LOG_ADDRESS not configured' });
    const timings = { syncMs: 0, issueMs: 0, proveMs: 0, txMs: 0 };
    let t = Date.now();
    let synced;
    try { synced = await syncRevocationTree(provider, LOG_ADDRESS); }
    catch (e) { return res.status(503).json({ reason: 'chain_unavailable', detail: e.message }); }
    timings.syncMs = Date.now() - t;
    lastSync = { root: synced.root.toString(), head: synced.head.toString() };
    pruneSessions(synced.head);
    if (!state.sessions[rsKey]) return res.status(409).json({ reason: 'session_expired', timings });
    let proved;
    try { proved = await proveSession(rsKey, synced, timings); }   // root 가 같으면 캐시 π, 아니면 재증명
    catch (e) {
      if (e.reason === 'revoked') { delete state.sessions[rsKey]; persist(); return res.status(403).json({ reason: 'revoked', timings }); }
      throw e;
    }
    const relayer = await provider.getSigner(RELAYER_INDEX);
    const factory = factoryAt(s.factoryAddress, relayer);
    const walletAddr = await factory.computeAddress(BigInt(s.PPID));
    let deployed = false;
    if ((await provider.getCode(walletAddr)) === '0x') { await (await factory.deploy(BigInt(s.PPID))).wait(); deployed = true; }
    const walletC = walletAt(walletAddr, relayer);
    const nonce = await walletC.nonce();
    const payload = { to: ethers.getAddress(to), value: BigInt(value), data, nonce };
    const sig = signPayload(new ethers.Wallet(s.sessionPrivKey), { chainId: await chainId(), wallet: walletAddr, ...payload });
    const { a, b, c, pub } = await proofToCalldata(proved.proof, proved.publicSignals);
    t = Date.now();
    let receipt;
    try { receipt = await (await walletC.execute(payload, sig, a, b, c, pub)).wait(); }
    catch (e) {
      // revert 이름(NonceMismatch·StaleRevocationRoot·RootTooOld·Expired…)을 그대로 돌려준다 — 서비스 페이지가 보여준다.
      const name = e?.revert?.name ?? e?.reason ?? e?.shortMessage ?? e.message;
      return res.status(409).json({ reason: 'execute_reverted', detail: String(name), wallet: walletAddr, nonce: nonce.toString(), timings });
    }
    timings.txMs = Date.now() - t;
    const { executed } = parseExecuteReceipt(receipt);
    res.json({
      txHash: receipt.hash, wallet: walletAddr, nonce: nonce.toString(), status: receipt.status, ok: executed?.success ?? null,
      gasUsed: receipt.gasUsed.toString(), deployed, cacheHit: proved.cacheHit, root: synced.root.toString(), timings,
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
```

- [ ] **Step 5: 구현 — mode3_rp.js**

(1) import 추가: `import { deployVerifier, deployFactory, decodeExecuteCalldata, parseExecuteReceipt, MAX_ROOT_AGE_DEFAULT } from './lib/mode3_onchain.js';`. 상단 주석에 `// V4(2026-09-18): 팩토리 배포(§6.1), 로그인 V4(max_height·allowAgent, σ 는 서버 챌린지 위), 트랜잭션 해시 개봉(§6.2).`

(2) 등록 파일: `const REG_VERSION = 3;`. `let reg = readJson(REG_FILE, null);` 다음에:

```js
// v2 → v3(2026-09-18): 팩토리·검증자 주소 필드. 조각(x_svc)은 그대로 — 버리면 이전 로그인 로그의 태그를 열 수 없다.
if (reg && reg.version === 2) { reg = { ...reg, version: 3, factoryAddress: null, verifierAddress: null }; writeJsonAtomic(REG_FILE, reg, 0o600); }
```
  새 등록 객체에 `factoryAddress: null, verifierAddress: null` 추가. `registerOnce` 의 `reg = { ...reg, arid, status: 'approved', … }` 는 그대로(스프레드가 두 필드를 유지한다).

(3) `activate` 를 교체(비동기):

```js
// ---- 팩토리(설계 2026-09-18 §6.1): 승인 뒤 한 번 배포. env 가 있으면 그것. 배포자·가스는 hardhat 언락 계정(개인키 없음). ----
const RELAYER_INDEX = Number(process.env.MODE3_RELAYER_INDEX ?? 0);
const MAX_ROOT_AGE = BigInt(process.env.MODE3_MAX_ROOT_AGE ?? MAX_ROOT_AGE_DEFAULT);
async function ensureFactory() {
  if (process.env.MODE3_RP_FACTORY_ADDRESS) { reg.factoryAddress = ethers.getAddress(process.env.MODE3_RP_FACTORY_ADDRESS); return; }
  if (reg.factoryAddress) return;
  const signer = await provider.getSigner(RELAYER_INDEX);
  const verifierAddress = process.env.MODE3_VERIFIER_ADDRESS || reg.verifierAddress || await deployVerifier(signer);
  const factoryAddress = await deployFactory(signer, { verifierAddress, arid: reg.arid, pkCIA, pkTrace: { x: BigInt(reg.pk_trace.x), y: BigInt(reg.pk_trace.y) }, logAddress: LOG_ADDRESS, maxRootAge: MAX_ROOT_AGE });
  reg = { ...reg, verifierAddress, factoryAddress };
  writeJsonAtomic(REG_FILE, reg, 0o600);
  console.log(`[rp] 팩토리 배포: ${factoryAddress} (verifier ${verifierAddress}, maxRootAge ${MAX_ROOT_AGE}) → ${REG_FILE}`);
}
async function activate() {
  verifier = createRpVerifier({ provider, logAddress: LOG_ADDRESS, vkey, pkCIA, arid: BigInt(reg.arid), chainId, pkTrace: { x: BigInt(reg.pk_trace.x), y: BigInt(reg.pk_trace.y) } });
  // 팩토리가 없어도 오프체인 로그인은 된다 — 실패는 경고로 남기고 /wallet/tx 만 no_factory 가 된다.
  try { await ensureFactory(); } catch (e) { console.warn(`[rp] 팩토리 배포 실패(오프체인 로그인만 가능): ${e.message}`); }
}
```
  호출부: `activate();` → `await activate();`(두 곳), 타이머 안 `if (await registerOnce()) { await activate(); clearInterval(timer); }`.

(4) `sessions` 주석·형식: `r_s → { PPID, pk_i, max_height, allowAgent, root, at }`. `rp_info` 응답에 `factoryAddress: reg.factoryAddress ?? null, verifierAddress: reg.verifierAddress ?? null`. `challenge` 응답 `{ ...issueChallenge(), factoryAddress: reg.factoryAddress ?? null }`.

(5) `verifyBody(req, res, r_s)` 로 바꿔 `verifier.verifyLogin({ proof, publicSignals, sig, r_s })`. `rsFromSignals` 를 삭제하고 `login`/`revalidate` 는 본문의 `r_s` 를 쓴다:

```js
app.post('/api/mode3/login', async (req, res) => {
  try {
    if (!verifier) return res.status(503).json({ ok: false, reason: 'registration_pending' });
    const { r_s } = req.body ?? {};
    if (typeof r_s !== 'string' || !/^[0-9]+$/.test(r_s)) return res.status(400).json({ ok: false, reason: 'malformed' });
    const rsStr = BigInt(r_s).toString();
    if (!consumeChallenge(rsStr)) return res.status(401).json({ ok: false, reason: 'bad_challenge' });   // 검증 전에 소비
    const v = await verifyBody(req, res, BigInt(rsStr)); if (v === null) return;
    if (!v.ok) return res.json({ ok: false, reason: v.reason });
    const at = new Date().toISOString();
    sessions.set(rsStr, { PPID: v.PPID.toString(), pk_i: v.pk_i.toString(), max_height: v.max_height.toString(), allowAgent: v.allowAgent.toString(), root: v.root.toString(), at });
    logins.push({ PPID: v.PPID.toString(), at, root: v.root.toString(), r_s: rsShort(rsStr), allowAgent: v.allowAgent.toString() });
    // §5 로그인 로그 — 전체 r_s 와 트랜스크립트(태그 포함). 개봉 요청의 재료다. 조회 API 로는 내지 않는다.
    fs.appendFileSync(LOGIN_LOG, JSON.stringify({ at, PPID: v.PPID.toString(), r_s: rsStr, pk_i: v.pk_i.toString(), max_height: v.max_height.toString(), allowAgent: v.allowAgent.toString(), root: v.root.toString(), publicSignals: req.body.publicSignals, proof: req.body.proof }) + '\n', { mode: 0o600 });
    res.json({ ok: true, PPID: v.PPID.toString(), pk_i: v.pk_i.toString(), r_s: rsStr, root: v.root.toString(), allowAgent: v.allowAgent.toString() });
  } catch (e) { res.status(500).json({ ok: false, reason: 'internal', detail: e.message }); }
});
```
  `revalidate` 도 같은 방식으로 `r_s` 를 본문에서 받아 `sessions.get(rsStr)` 후 `verifyBody(req, res, BigInt(rsStr))`. `request` 의 만료 검사는 체인 뷰를 먼저 읽고 `if (view.head > BigInt(s.max_height)) { sessions.delete(r_s); return res.status(401).json({ ok: false, reason: 'expired' }); }` 를 root 비교 앞에 둔다. `/api/mode3/sessions` 의 `exptime` → `max_height, allowAgent`.

(6) 개봉: `lastTranscriptOf` 뒤에 추가하고 `/api/mode3/open` 을 교체:

```js
/** 트랜잭션 해시에서 개봉 재료(§6.2): calldata 의 (a, b, c, pub) 을 snarkjs 증명 형식으로 되돌린다. 성공한 execute 만 받는다. */
async function transcriptFromTx(txHash) {
  const tx = await provider.getTransaction(txHash);
  if (!tx) return { error: 'no_tx' };
  const d = decodeExecuteCalldata(tx.data);
  if (!d) return { error: 'not_execute' };
  const receipt = await provider.getTransactionReceipt(txHash);
  if (!receipt || receipt.status !== 1 || !parseExecuteReceipt(receipt).auth) return { error: 'tx_failed' };
  // exportSolidityCallData 는 b 의 각 행을 (y, x) 로 뒤집는다 — 되돌린다.
  const proof = {
    pi_a: [d.a[0], d.a[1], '1'],
    pi_b: [[d.b[0][1], d.b[0][0]], [d.b[1][1], d.b[1][0]], ['1', '0']],
    pi_c: [d.c[0], d.c[1], '1'],
    protocol: 'groth16', curve: 'bn128',
  };
  return { publicSignals: d.pub, proof, PPID: d.pub[0] };
}
app.post('/api/mode3/open', async (req, res) => {
  try {
    if (!verifier) return res.status(503).json({ ok: false, reason: 'registration_pending' });
    const { PPID, txHash } = req.body ?? {};
    let T;
    if (typeof txHash === 'string') {
      if (!/^0x[0-9a-fA-F]{64}$/.test(txHash)) return res.status(400).json({ ok: false, reason: 'malformed' });
      T = await transcriptFromTx(txHash);
      if (T.error) return res.status(404).json({ ok: false, reason: T.error });
    } else if (typeof PPID === 'string') {
      T = lastTranscriptOf(PPID);
      if (!T) return res.status(404).json({ ok: false, reason: 'no_transcript' });
    } else return res.status(400).json({ ok: false, reason: 'malformed' });
    const c1 = { x: BigInt(T.publicSignals[11]), y: BigInt(T.publicSignals[12]) };
    const D = await partialDecrypt(BigInt(reg.x_svc), c1);
    const D_svc = { x: D.x.toString(), y: D.y.toString() };
    const ts = Math.floor(Date.now() / 1000).toString();
    const sig = await signOpenRequest(serviceWallet, { arid: reg.arid, PPID: T.PPID, c1: { x: c1.x.toString(), y: c1.y.toString() }, D_svc, ts });
    const r = await fetch(`${CIA_URL}/cia/open/request`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ arid: reg.arid, publicSignals: T.publicSignals, proof: T.proof, D_svc, ts, sig }) });
    res.status(r.status).json(await r.json().catch(() => ({})));
  } catch (e) { res.status(500).json({ ok: false, reason: 'internal', detail: e.message }); }
});
```

- [ ] **Step 6: 통과 확인**

먼저 `npx hardhat compile` 로 `artifacts/contracts/PiCredVerifier.sol`·`Mode3WalletFactory.sol` 아티팩트가 있는지 확인한다(없으면 RP 가 "팩토리 배포 실패" 를 남기고 `/wallet/tx` 가 전부 `no_factory` 다).

Run: `node tests/test_mode3_wallet_agent.mjs && node tests/test_mode3_demo_stack.mjs`
Expected: 두 파일 모두 `FAIL` 0. 그 다음 `bash scripts/run_tests.sh chain` 전체(Mode 2 테스트 포함)가 통과.

- [ ] **Step 7: 커밋**

```bash
git add mode3_wallet_agent.js mode3_rp.js tests/helpers/isolated_mode3_stack.mjs tests/test_mode3_wallet_agent.mjs tests/test_mode3_demo_stack.mjs
git commit -m "feat(mode3): 서버 V4 — 지갑 /wallet/tx(PPID 계정 배포·execute·π 재사용), 서비스 팩토리 배포·로그인 V4·txHash 개봉"
```

---

### Task 7: 페이지, 문서, 테스트 그룹

**Files:**
- Modify: `mode3/wallet.html`, `mode3/rp.html`, `mode3/cia_admin.html`
- Modify: `docs/MODE3_DEMO.md`
- Modify: `docs/superpowers/specs/2026-09-09-mode3-cia-revocation-design.md` (§9.5·§9.11 에 추기 한 줄씩)
- Modify: `docs/superpowers/specs/2026-09-18-mode3-onchain-execution-design.md` (§8 실측값)
- Modify: `scripts/run_tests.sh` (Task 5 에서 UNIT 추가가 안 됐으면 여기서)

**Interfaces:** Consumes Task 6 의 HTTP 형식. 산출물은 사람이 보는 페이지·문서다.

- [ ] **Step 1: 서비스 페이지(`mode3/rp.html`)**

- 로그인 fieldset 의 버튼 앞에 `<label><input type="checkbox" id="allowAgent" /> 이번 세션에서 AI agent 동작 허용 (allowAgent, 덱 22장)</label><br />`.
- 로그인 스크립트: challenge 응답을 `const { r_s, factoryAddress } = …` 로 받고, 지갑 login 본문에 `allowAgent: $('allowAgent').checked ? '1' : '0', factoryAddress` 를, RP login 본문에 `r_s` 를 추가. 3단계 로그 뒤에 `allowAgent=${rb.allowAgent}` 표시. `currentFactory = factoryAddress` 를 전역에 보관.
- 재검증 스크립트: RP revalidate 본문에 `r_s: currentSession` 추가.
- 세션 fieldset 뒤에 새 fieldset:

```html
  <fieldset>
    <legend>온체인 트랜잭션 (설계 2026-09-18 §6.3 — sender = PPID 계정)</legend>
    <p class="muted">지갑이 같은 π 를 트랜잭션마다 첨부하고 컨트랙트가 매번 검증한다. 첫 트랜잭션은 CREATE2 로 계정을 배포한다. 가스는 릴레이어(hardhat 계정 0).</p>
    <label>to <input id="txTo" value="0x000000000000000000000000000000000000dEaD" size="44" /></label>
    <label>value(wei) <input id="txValue" value="0" size="10" /></label>
    <button id="txBtn" disabled>트랜잭션 보내기</button>
    <p id="txVerdict"></p>
    <pre id="txLog"></pre>
    <p class="muted">해시로 개봉: <input id="openTx" size="66" placeholder="0x…" /> <button id="openTxBtn">요청</button></p>
  </fieldset>
```
  스크립트: `setSession` 에서 `$('txBtn').disabled = !r_s;`. `txBtn` 클릭 → `post(`${info.walletAgentOrigin}/wallet/tx`, { r_s: currentSession, to: $('txTo').value.trim(), value: $('txValue').value.trim() || '0' })` → 200 이면 `txLog` 에 `txHash, wallet, nonce, ok, gasUsed, deployed, cacheHit, timings` 를 줄로 적고 `$('openTx').value = body.txHash`; 아니면 `reason/detail` 을 bad 로. `openTxBtn` → `post('/api/mode3/open', { txHash: $('openTx').value.trim() })` 를 기존 `openLog` 에 적고 `openingId` 갱신.
- 개봉 결과 표시: `openPollBtn` 결과에 `b.allowAgent` 가 있으면 `AI agent ${b.allowAgent === '1' ? '허용됨' : '허용 안 됨'}` 를 덧붙인다.
- 로그인 기록 표시에 `allowAgent=${l.allowAgent}` 추가. `rpInfo` 에 `팩토리=${info.factoryAddress ?? '(없음)'}` 추가.

- [ ] **Step 2: 지갑 페이지(`mode3/wallet.html`)**

상태 표시의 세션 줄을 `max_height=${c.max_height}  chainid=${c.chainid}  allowAgent=${c.allowAgent}  PPID=${String(c.PPID).slice(0, 12)}…\n    세션 주소=${c.sessionAddress}  팩토리=${c.factoryAddress ?? '-'}\n    발급=${c.issuedAt}` 로. 안내 문단에 "온체인 트랜잭션도 RP 페이지의 버튼이 시작한다(`/wallet/tx`)." 한 줄.

- [ ] **Step 3: 관리자 페이지(`mode3/cia_admin.html`)**

개봉 목록 행에 `o.allowAgent ?? ''` 열과 `o.resolved === false ? '(역조회 실패)' : ''` 를 추가: `table.appendChild(row([o.status, o.requestedAt, `arid ${…}`, `PPID ${…}`, o.uid ?? (o.resolved === false ? '(역조회 실패)' : ''), o.allowAgent == null ? '' : `agent=${o.allowAgent}`, last]));`. 안내 문단에 "복호 결과는 Poseidon(uid, arid) 라 등록부로 uid 를 되찾는다(2026-09-18 §6.2)." 추가. '조작' fieldset 의 게시 버튼 옆 설명에 "하트비트(CIA_HEARTBEAT_BLOCKS)가 켜져 있으면 변화가 없어도 주기적으로 재게시된다" 한 줄.

- [ ] **Step 4: 데모 문서(`docs/MODE3_DEMO.md`)**

- 상단 설계 링크에 `온체인 실행: docs/superpowers/specs/2026-09-18-mode3-onchain-execution-design.md`.
- "처음 한 번" 0 에 "회로 V4(2026-09-18)로 build/mode3 를 다시 만들었다 — 다른 기계의 build/mode3 도 다시 복사. 이 스크립트가 `contracts/PiCredVerifier.sol` 도 만든다." 3 뒤에 `3'. npx hardhat compile — RP 가 기동 시 PiCredVerifier·Mode3WalletFactory 를 아티팩트에서 읽어 배포한다(artifacts/ 가 없으면 RP 로그에 "팩토리 배포 실패", 오프체인 로그인만 된다).` 5 뒤에 `6. RP 는 승인 뒤 팩토리를 배포해 mode3_rp_registration.json 에 factoryAddress 를 둔다. 재배포하려면 그 필드를 지우거나 MODE3_RP_FACTORY_ADDRESS 로 덮어쓴다.`
- 선택 env 문단을 교체: `CIA_TTL_BLOCKS`(300)·`CIA_HEIGHT_GRID`(100)·`CIA_REVOKE_SKEW_BLOCKS`(50)·`CIA_HEARTBEAT_BLOCKS`(50, 0=끔)·`CIA_HEARTBEAT_POLL_MS`(5000)·`CIA_CHAIN_RPCS`("31337=http://127.0.0.1:8545", 비면 자기 RPC 하나)·`MODE3_MAX_ROOT_AGE`(100, 하트비트보다 커야 한다)·`MODE3_RELAYER_INDEX`(0)·`MODE3_RP_FACTORY_ADDRESS`·`MODE3_VERIFIER_ADDRESS`. 옛 `CIA_TTL_SECONDS`·`CIA_CHAIN_IDS` 는 무시된다고 적는다.
- 시연 각본 표에 행 추가: `2 | RP | 로그인 (AI agent 허용 체크 여부) | … allowAgent 표시`, `2a | RP | 트랜잭션 보내기 | 첫 번째 deployed=true·ok=true, 두 번째 캐시 히트·nonce 1`, `2b | RP → 관리자 → RP | 해시로 개봉 → 승인 → 결과 확인 | uid=12345, AI agent 허용 여부`, `5a | RP | (폐기·게시 뒤) 트랜잭션 보내기 | 지갑 revoked`. 표 아래 문단에 "온체인 실행은 트랜잭션마다 π 를 첨부하고 컨트랙트가 매번 검증한다(가스 실측 N — Task 3 값). root 게시가 MAX_ROOT_AGE 블록보다 오래되면 RootTooOld 로 멈추므로 CIA 하트비트를 켜 둔다." 를 넣고, "credential 은 발급 시각 + 1시간에 만료되며 … exptime" 문장을 "credential 은 발급 시점 head 기준 300~400 블록(그리드 양자화)에 만료되며 지갑 상태 페이지에 max_height 로 보인다" 로.
- "하지 말 것" 의 상태 파일 버전 문장: `cia_state.json` v3·v4 는 v5 로 이행(v4 의 발급 기록은 비워진다), `mode3_wallet_state.json` v4 이하는 세션이 비워진다, `mode3_rp_registration.json` v2 는 v3 로 이행(조각 유지). 재시연 세트에 `RevocationLog` 재배포와 `mode3_rp_registration.json` 의 `factoryAddress` 삭제(로그 주소가 바뀌면 팩토리도 새로 배포해야 한다 — 삭제하면 RP 가 다시 배포한다).
- 테스트 절에 `bash scripts/run_tests.sh contract` — `test/Mode3Wallet.test.mjs`(execute 검사 순서·가스), `unit` 에 `tests/test_mode3_cia_state.js`.

- [ ] **Step 5: 기반 스펙 추기**

`docs/superpowers/specs/2026-09-09-mode3-cia-revocation-design.md`:
- `### 9.11 온체인 검증 경로 (기각, 2026-09-10)` 바로 아래에: `> **2026-09-18 추기.** 덱(260917_OVERALL) 결정으로 온체인 실행을 되돌렸다 — \`2026-09-18-mode3-onchain-execution-design.md\`. 이 절이 최소 조건으로 꼽은 하트비트(RevocationLog.lastPublishedBlock + 지갑의 MAX_ROOT_AGE)를 넣었고, 나머지 대가(트랜잭션당 검증 가스, stale root 실패)는 그 문서 §8 에 감수 항목으로 적었다. 오프체인 로그인 경로는 그대로 남아 두 경로가 공존한다.`
- `### 9.5 \`max_height\` 양자화 (\`Q\`)` 아래에: `> **2026-09-18 추기.** 온체인 복귀와 함께 양자화를 도입했다 — 이유가 다르다: 온체인 공개 입력은 AA 도 보므로 발급 시각과의 상관을 끊기 위한 것이다(2026-09-18 설계 §2·§3.2). 여기서 기각한 논거(오프체인에서는 불필요)는 그대로 유효하다.`

- [ ] **Step 6: 새 스펙에 실측값**

`docs/superpowers/specs/2026-09-18-mode3-onchain-execution-design.md` §8 첫 항목의 "실측은 구현 뒤 `Mode3Wallet.test.mjs` 에서 기록한다" 를 Task 3 Step 8 과 Task 2 Step 6·9 에서 얻은 수치로 바꾼다: `execute() gas N(정상 실행, 배포 제외)`, `제약 N`, `증명 N ms 중앙값 / 검증 N ms / zkey N bytes`.

- [ ] **Step 7: 페이지 확인(수동 대체 — 자동)**

Run: `node tests/test_mode3_demo_stack.mjs` (페이지 서빙 케이스가 `Mode 3 로그인`·`Mode 3 지갑`·`CIA 관리자` 마커를 본다) 및 `bash scripts/run_tests.sh unit`.
Expected: 통과. 브라우저 확인은 사용자 프로세스(:3100 등)를 재시작해야 하므로 하지 않는다 — 보고서에 "페이지는 자동 서빙 검사만" 이라고 적는다.

- [ ] **Step 8: 커밋**

```bash
git add mode3/wallet.html mode3/rp.html mode3/cia_admin.html docs/MODE3_DEMO.md docs/superpowers/specs/2026-09-09-mode3-cia-revocation-design.md docs/superpowers/specs/2026-09-18-mode3-onchain-execution-design.md scripts/run_tests.sh
git commit -m "docs(mode3): 온체인 실행 데모 페이지(allowAgent·트랜잭션·해시 개봉), 데모 문서·기반 스펙 추기, 실측값"
```

---

## 자체 검토 기록

- **스펙 커버리지**: §2(공개 입력 선택) → Task 2 회로·Task 4 검증기; §3.1~3.5 → Task 1·2; §4.1~4.5 → Task 5; §5.1~5.4 → Task 3; §6.1~6.3 → Task 6; §7.1 → Task 2 Step 7~8; §7.2 → Task 2·3·5·6 의 테스트(스펙의 "다른 chainid 재생(체인을 바꾼 인프로세스 체인)" 은 공개 입력 `[4]` 를 바꾼 `WrongWallet` 케이스로 대신한다 — 컨트랙트는 `block.chainid` 와 비교하므로 같은 검사다); §7.3 → Task 7 문서(운영 절차); §8 실측 → Task 7 Step 6; §9·§11 → 코드 밖(논문 작업 별도).
- **계획 판정(스펙과 다른 점)**: Task 5 발급 검사 순서(헤드 조회 위치), 같은 `C_pt` 재요청 200; Task 6 `/wallet/tx` 의 세션 키 `r_s`, 개봉 `{PPID}|{txHash}`, `allowAgent` 체크박스 위치(서비스 페이지). 각 태스크 머리에 적었다.
- **타입 일관성**: `encryptTag(pk_trace, uid, arid, r)`(Task 1) ↔ 픽스처·`buildCredentialProof`(Task 2·4); `credMessage(C, max_height, chainid, allowAgent)` ↔ 회로 msgHasher 순서 ↔ CIA·테스트 `localIssue`; `verifyLogin({…, r_s: bigint})` ↔ `mode3_rp.js` `verifyBody(req, res, BigInt(rsStr))` ↔ 테스트 `verify(body, r_s)`; `signPayload(sessionWallet, { chainId, wallet, to, value, data, nonce })` ↔ 컨트랙트 `abi.encode(block.chainid, address(this), to, value, data, nonce)` ↔ 지갑 `/wallet/tx`; `decodeExecuteCalldata().pub`(10진) ↔ `publicSignals`(10진); 공개 입력 인덱스 3/5/6/11~13 을 회로·컨트랙트·검증기·CIA 개봉·서비스 개봉이 같이 쓴다.
