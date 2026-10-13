# Mode 3 V11 — 그림(261012) 프로토콜 구현 계획

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Mode 3 의 코드를 2026-10-12 그림(`documents/261012.pptx` Overall Flow, 덱 3~8장)에 맞춘다 — `auid`·`auid_s`·`arid_s` 도입, 세션마다 π_IdP(새 Groth16 회로 `pi_idp`), `pi_cred` V11(공개 입력 33), 토큰 재정의, `/cia/issue` 가 `/cia/user_cred` 를 흡수, 속성은 사용자가 지갑에 넣음(D15), RP 챌린지 `r_rp`.

**Architecture:** 라이브러리(`lib/mode3_credential.js`·`mode3_issuance.js`·`mode3_registry.js`)가 새 유도식을 정하고, 회로 둘(`circuits/pi_idp.circom` 신규, `circuits/pi_cred.circom` V11)이 그 식을 제약으로 옮긴다. 그 위에 지갑 라이브러리(`lib/mode3_wallet.js` + 새 `lib/mode3_idp_proof.js`), RP 검증기(`lib/mode3_rp.js`), 세 서버(`cia.js`·`mode3_rp.js`·`mode3_wallet_agent.js`), 컨트랙트(`Mode3Wallet.execute(uint[33])`), Snap·페이지·런북이 순서대로 바뀐다. CIA 상태는 v12 로 **새로 시작**(이행 없음), 지갑 상태는 v9.

**Tech Stack:** Node 20 ESM, circom 2.1.9 + snarkjs(Groth16, `pot21_final.ptau`), circomlibjs(Poseidon·Baby Jubjub·EdDSA), ethers v6 + hardhat, express, MetaMask Snap(`snap-mode3`).

**Spec:** `docs/superpowers/specs/2026-10-12-mode3-v11-figure-protocol-design.md` (결정 D1~D16, §2 표기, §3~§7 흐름·상태, §8 비용, §11 테스트). 작업자는 스펙을 함께 읽는다 — 계획은 스펙을 근거로 쓰였고, 충돌하면 스펙이 우선한다. 속성 매핑(스키마·`encodeProfile`)은 스펙 2 `docs/superpowers/specs/2026-10-07-mode3-attr-schema-design.md` 그대로다.

## Global Constraints

스펙에서 그대로 옮긴 전역 제약. 모든 작업의 요구사항에 암묵적으로 포함된다.

- **공개 입력 33개, 끝에 추가(D12)**: `[0] PPID [1] arid [2] pk_i [3] max_height [4] chainid [5] allowAgent [6] revRoot [7] regRoot [8,9] pk_CIA [10,11] pk_trace [12..14] tag [15] disc_mask [16..21] disc_lo [22..27] disc_hi [28] set_sel [29] set_root` + **`[30] auid_s [31] arid_s [32] r_s`**. 색인 0~29 는 바꾸지 않는다(`PUB_INDEX`·AttrGate 꼬리 15워드·σ_tx 다이제스트 불변).
- **유도식(H = Poseidon)**: `auid = Poseidon(T_AUID, uid, s_u)`; `auid_s = Poseidon(T_AUIDS, auid, arid, r_rp)`(D7 — rid 포함); `arid_s = Poseidon(T_ARIDS, arid, r_rp)`; `PPID = Poseidon(uid, s_u, arid, chainid)`(D13 — 순서 변경); 등록부 리프 `Poseidon(auid, Cf_u)`(D4); 세션 리프 `Poseidon(5, Cf_s)` 불변.
- **커밋먼트**: `C_u = uid·G_UID + s_u·G_SU + Σ attrs[k]·G_ATTR[k] + blind_u·H`(불변); **`C_s = pk_i·G_PK + max_height·G_EXP + r_s·G_RS + r_rp·H`**(D5). `pk_i` 160비트, `max_height` 64비트, `r_s`·`r_rp`·그 밖 스칼라 250비트. `G_PK = 기존 pk_i 생성원`, `G_EXP = getBasePoint('blake', 11)`, `G_RS = getBasePoint('blake', 12)`, `H = 기존 blind 생성원`. `G_arid` 는 남겨 두되 C_s 에서 빠진다.
- **토큰(D3)**: `sigma = EdDSA_IdP(Poseidon(D_V11, auid_s, arid_s, Cf_u, Cf_s, chainid, allowAgent))`, `Cf_x = Poseidon(C_x.x, C_x.y)`. max_height 는 토큰 메시지에 없다(C_s 안).
- **상수(ASCII 빅엔디언 정수, 기존 `DOMAIN_*` 관례)**: `T_AUID = "MODE3AUID" = 1426111059989489862980`, `T_AUIDS = "MODE3AUIDS" = 365084431357309404922963`, `T_ARIDS = "MODE3ARIDS" = 365084431357309354591315`, `D_V11 = "MODE3CREDV11" = 23926173293433188795270181169`, `D_ISSUEREQ_V11 = "MODE3ISSUEREQV11" = 102762131813731415973437885676665581873`, `D_REGISTER_V2 = "MODE3REGISTER2" = 1568025692958713225867644958495282`, `D_SLOTREQ = "MODE3SLOTREQ" = 23926173293437685841045636433`(계획이 추가 — `/cia/slot` 서명 도메인, 옛 `MODE3ATTRSREQ` 대체). 생성원 11·12 좌표는 Task 1 에 적혀 있다(2026-10-12 circomlibjs 로 계산·곡선·부분군 확인).
- **π_IdP(D10·§4)**: 비공개 `s_u, blind_u, attrs[6], arid, r_rp, pk_i, r_s`; 공개 **순서** `[0] uid [1] auid [2] auid_s [3] C_u_x [4] C_u_y [5] C_s_x [6] C_s_y [7] max_height`. 세션(토큰 발급)마다 제출(D2). IdP 는 공개 입력을 **스스로 조립**해 검증한다(uid 는 요청·계정, auid 는 DB 값).
- **`/cia/issue` V11(D11·§5.2)**: 본문 `{ uid, auid_s, arid_s, C_u_pt, C_s_pt, chainid, allowAgent, max_height, proof_idp, sig_u }`, `sig_u = EdDSA_{sk_u}(Poseidon(D_ISSUEREQ_V11, auid_s, arid_s, Cf_u, Cf_s, chainid, allowAgent, max_height))`. 검사 순서: 형식 → `max_height < 2^64` → 계정·disabled → chainid 허용 → sig_u → π_IdP → C_u·C_s 부분군 → 체인 생존 → disabled 재확인 → (C_u 가 활성과 다르면 은퇴·`setSlot`·persist·즉시 게시) → 서명 → 세션 기록 `{ Cf_s, max_height, chainid, allowAgent, issuedAt }`(**auid_s·arid_s 는 기록하지 않는다**, D1). `/cia/user_cred`·`/cia/attrs`·`/cia/accounts/:uid/attrs` 는 삭제, `/cia/slot` 은 유지.
- **등록(§3.1)**: `/cia/register` 본문 `{ uid, pwd, auid, pk_u, sig_reg }`, `sig_reg = EdDSA_{sk_u}(Poseidon(D_REGISTER_V2, uid, auid))`. 계정에 **attrs·profile 필드 없음**(D15). `DEMO_ACCOUNTS` 는 `{ password, uid }` 만.
- **속성(D15)**: 지갑이 `profile` 을 들고 스펙 2 의 `encodeProfile` 로 `attrs[6]` 을 만든다. IdP 는 값을 받지도 저장하지도 않는다. 스키마 공개(`GET /cia/attr_schema`)·RP 정책·AttrGate 는 그대로.
- **RP(§3.2·§5.3)**: `/api/mode3/challenge → { r_s, r_rp, expiresAt, factoryAddress, attrGateAddress }`(둘 다 250비트, r_s 1회 소비). `verifyLogin` 은 d 뒤에 `pub[32] === r_s`, `pub[31] === Poseidon(T_ARIDS, arid, r_rp)` 를 더한다(사유 `bad_r_s`·`bad_arid_s` — 계획이 정한 이름). 세션 기록에 `auid_s`·`arid_s`.
- **상태**: CIA 상태 **v12 — v11 이하는 이행하지 않고 기동 거부**("V11 은 새로 시작"). 지갑 상태 **v9**(등록만 유지, auid 는 s_u 로 재계산, 세션 비움). Snap `registration { uid, s_u, sk_u, attrs }`, 증인 `{ uid, s_u, sk_u, attrs, userCred }`.
- **컨트랙트(§6)**: `Mode3Wallet.execute(..., uint[33] pub)`, `_checkStatement` 는 0~29 만 본다. 꼬리 15워드·다이제스트 불변. `PiCredVerifier` 재생성. 팩토리·AttrGate 소스 불변(재배포는 런북).
- **작업 규칙(CLAUDE.md)**: 구현자는 커밋하지 않는다(커밋은 사용자 승인 뒤 컨트롤러만). `bash scripts/build_mode3_circuit.sh …`(zkey·vkey·wasm 재생성)은 **사용자의 명시적 승인이 있어야** 실행한다 — Task 4 Step 4 가 그 지점이고, 컨트롤러가 실행 전에 사용자에게 묻는다. 그 전 작업(1~3)은 `build/mode3/witness_test/`·`build/mode3/commit/` 에만 컴파일한다(배포용 산출물 불변). `:8545` hardhat 노드가 없으면 작업자가 `npx hardhat node` 를 백그라운드로 띄우고 끝나면 내린다(이미 떠 있던 노드는 건드리지 않는다). `.env`·키 파일은 읽지 않는다.
- **중간 상태에 관한 주의**: Task 1 이 `registrationCommit`·π_u 를 지우므로 `lib/mode3_wallet.js`·`lib/mode3_secret_source.js`·`cia.js`·픽스처는 **Task 5·7 전까지 import 가 깨진다**. 각 작업은 자기 테스트만 초록이면 된다(각 작업 끝의 "실행" 단계가 그 범위다). 전체 그룹은 Task 12 에서 돈다.

## 파일 구조

| 파일 | 책임 | 작업 |
|---|---|---|
| `lib/mode3_credential.js` | 유도식의 정본(C_u·C_s·토큰 메시지·auid·auid_s·arid_s·PPID·상수·생성원) | 1 |
| `lib/mode3_issuance.js` | 요청 서명 메시지(등록·발급·슬롯·세션 폐기)·점 검사·직렬화. σ-프로토콜 삭제 | 1 |
| `lib/mode3_registry.js` | 등록부 리프 `Poseidon(auid, Cf_u)` | 1 |
| `circuits/lib/mode3_commit.circom` | `CommitUser`(불변) + **`CommitSessionV11`**(신규). `CommitSession`·`RegistrationCommit` 삭제 | 2 |
| `circuits/pi_idp.circom` (신규) | π_IdP | 2 |
| `circuits/pi_cred.circom` | π_RP V11 | 3 |
| `tests/helpers/mode3_idp_fixture.mjs` (신규) · `tests/helpers/mode3_fixture.mjs` | 회로 입력 픽스처 | 2·3 |
| `scripts/build_mode3_circuit.sh` · `scripts/pack_mode3_build.sh` | 두 회로 빌드·묶음 | 4 |
| `contracts/Mode3Wallet.sol` · `contracts/test/AcceptAllPiCredVerifier.sol` · `lib/mode3_onchain.js` | `uint[33]`·`PUB_INDEX` | 4 |
| `lib/mode3_idp_proof.js` (신규) | π_IdP 증명·검증·공개 입력 조립 | 5 |
| `lib/mode3_wallet.js` · `lib/mode3_secret_source.js` | 지갑 라이브러리 V11·증인 검사(auid 바인딩) | 5 |
| `lib/mode3_rp.js` · `mode3_rp.js` | RP 검증기·서버(r_rp) | 6 |
| `cia.js` · `lib/mode3_cia_state.js` · `tests/helpers/isolated_cia.mjs` · `tests/helpers/mode3_flow.mjs` (신규) | IdP V11·상태 v12·테스트 헬퍼 | 7 |
| CIA 쪽 chain 테스트 6개 | 헬퍼로 이행 | 8 |
| `mode3_wallet_agent.js` · `mode3/rp.html`(r_rp 전달) · `mode3/wallet.html`(팝업 r_rp) | 지갑 에이전트 V11 | 9 |
| 데모 HTTP 테스트 4개 | V11 각본 | 10 |
| `snap-mode3/src/*` · `tests/helpers/snap_sim.mjs` · `mode3/wallet.html` · `mode3/cia_admin.html` · `mode3/common/strings.js` | Snap·화면·문구 | 11 |
| `docs/MODE3_DEMO.md` · `scripts/bench_pi_idp.mjs` (신규) · `results/mode3_v11_*.md` · `scripts/run_tests.sh` | 런북·벤치·전체 실행 | 12 |

---

### Task 1: 라이브러리 V11 유도식 — credential·issuance·registry

**Files:**
- Modify: `lib/mode3_credential.js`
- Modify (전면 교체): `lib/mode3_issuance.js`
- Modify: `lib/mode3_registry.js:1-20`
- Create: `tests/test_mode3_credential_v11.js` (대체: `tests/test_mode3_credential_v5.js` 삭제)
- Modify (전면 교체): `tests/test_mode3_issuance.js`
- Modify: `tests/test_mode3_registry.js:16-21`
- Delete: `tests/test_mode3_v9_lib.js` (생성원 단언은 새 credential 테스트로, 등록 메시지·ProofCache 단언은 Task 5 의 `tests/test_mode3_wallet_lib.js` 로 옮긴다)
- Modify: `scripts/run_tests.sh` UNIT 목록

**Interfaces:**
- Produces (`lib/mode3_credential.js`): `DOMAIN_MODE3_CRED_V11`, `DOMAIN_MODE3_AUID`, `DOMAIN_MODE3_AUIDS`, `DOMAIN_MODE3_ARIDS`, `PK_I_MAX = 1n << 160n`, `PEDERSEN_GENERATORS.exp`, `PEDERSEN_GENERATORS.rs`, `sessionCommit({ pk_i, max_height, r_s, r_rp }) → { Cx, Cy, Cf }`, `credMessageV11(auid_s, arid_s, Cf_u, Cf_s, chainid, allowAgent) → bigint`, `auidOf({ uid, s_u })`, `auidSOf({ auid, arid, r_rp })`, `aridSOf({ arid, r_rp })`, `ppid({ uid, s_u, arid, chainid })`. 삭제: `DOMAIN_MODE3_CRED_V5`, `credMessageV5`.
- Produces (`lib/mode3_issuance.js`): `DOMAIN_MODE3_ISSUEREQ_V11`, `DOMAIN_MODE3_REGISTER_V2`, `DOMAIN_MODE3_SLOTREQ`, `DOMAIN_MODE3_REVOKESESS`(불변), `issueRequestMessageV11(auid_s, arid_s, Cf_u, Cf_s, chainid, allowAgent, max_height)`, `registerMessage(uid, auid)`, `slotRequestMessage(uid, nonce)`, `revokeSessionMessage(uid, Cf_s, nonce)`(불변), `isValidPoint`, `pointToStrings`, `pointFromStrings`. 삭제: `registrationCommit`, `proveUserCred`, `verifyUserCred`, `serializeUserCredProof`, `parseUserCredProof`, `userCredRequestMessage`, `issueRequestMessageV4`, `attrsRequestMessage`, `randomZr`, `DOMAIN_MODE3_USERCRED_V2`, `DOMAIN_MODE3_ATTRSREQ`, `DOMAIN_MODE3_USERCREDREQ`, `DOMAIN_MODE3_ISSUEREQ_V4`, `DOMAIN_MODE3_REGISTER`.
- Produces (`lib/mode3_registry.js`): `registryLeaf(auid, Cf_u)` — 둘 다 bigint 또는 10진 문자열.

- [ ] **Step 1: 실패하는 단위 테스트 — `tests/test_mode3_credential_v11.js`**

```js
// V11(2026-10-12) 유도식 — C_s 재정의·토큰 메시지·auid/auid_s/arid_s·PPID 순서·생성원 13개. 외부 의존 없음(unit).
//   node tests/test_mode3_credential_v11.js
import assert from 'node:assert/strict';
import { buildBabyjub, buildPoseidon, buildPedersenHash } from 'circomlibjs';
import {
  userCommit, sessionCommit, credMessageV11, compressPoint, auidOf, auidSOf, aridSOf, ppid,
  PEDERSEN_GENERATORS, SCALAR_MAX, PK_I_MAX, MAX_HEIGHT_MAX, ATTR_SLOTS,
  DOMAIN_MODE3_CRED_V11, DOMAIN_MODE3_AUID, DOMAIN_MODE3_AUIDS, DOMAIN_MODE3_ARIDS,
} from '../lib/mode3_credential.js';
import { sessionLeaf, TAG_MODE3_SESSION } from '../lib/mode3_revocation.js';

let failed = 0;
async function t(name, fn) {
  try { await fn(); console.log(`ok   ${name}`); }
  catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.message}`); }
}
const be = (s) => BigInt('0x' + Buffer.from(s).toString('hex'));
const bj = await buildBabyjub();
const ps = await buildPoseidon();
const H = (arr) => ps.F.toObject(ps(arr));
const mul = (g, e) => bj.mulPointEscalar([bj.F.e(g[0]), bj.F.e(g[1])], e);
const uid = 11n, s_u = 22n, blind_u = 33n, attrs = [19n, 410n, 0n, 0n, 0n, 0n], arid = 44n, pk_i = 0x1234n, max_height = 1789000000n, r_s = 55n, r_rp = 66n;

await t('도메인 상수는 ASCII 빅엔디언이다', () => {
  assert.equal(DOMAIN_MODE3_CRED_V11, be('MODE3CREDV11'));
  assert.equal(DOMAIN_MODE3_AUID, be('MODE3AUID'));
  assert.equal(DOMAIN_MODE3_AUIDS, be('MODE3AUIDS'));
  assert.equal(DOMAIN_MODE3_ARIDS, be('MODE3ARIDS'));
  assert.equal(PK_I_MAX, 1n << 160n);
});

await t('생성원 13개 — uid,arid,s_u,pk_i,blind,attr0..3 = getBasePoint(0..8), attr4·attr5 = 9·10, exp = 11, rs = 12; 전부 곡선 위·부분군 안', async () => {
  const ph = await buildPedersenHash();
  const F = ph.babyJub.F;
  assert.equal(Object.keys(PEDERSEN_GENERATORS).length, 13);
  const idx = { uid: 0, arid: 1, s_u: 2, pk_i: 3, blind: 4, attr0: 5, attr1: 6, attr2: 7, attr3: 8, attr4: 9, attr5: 10, exp: 11, rs: 12 };
  for (const [name, i] of Object.entries(idx)) {
    const P = ph.getBasePoint('blake', i);
    assert.deepEqual([...PEDERSEN_GENERATORS[name]], [F.toObject(P[0]), F.toObject(P[1])], name);
    const Q = [bj.F.e(PEDERSEN_GENERATORS[name][0]), bj.F.e(PEDERSEN_GENERATORS[name][1])];
    assert.ok(bj.inCurve(Q) && bj.inSubgroup(Q), `${name} 곡선·부분군`);
  }
});

await t('userCommit 은 불변 — uid·G_UID + s_u·G_SU + Σattr·G_ATTR + blind_u·H', async () => {
  const { Cx, Cy, Cf } = await userCommit({ uid, s_u, blind_u, attrs });
  let acc = mul(PEDERSEN_GENERATORS.uid, uid);
  acc = bj.addPoint(acc, mul(PEDERSEN_GENERATORS.s_u, s_u));
  for (let i = 0; i < ATTR_SLOTS; i++) acc = bj.addPoint(acc, mul(PEDERSEN_GENERATORS[`attr${i}`], attrs[i]));
  acc = bj.addPoint(acc, mul(PEDERSEN_GENERATORS.blind, blind_u));
  assert.equal(Cx, bj.F.toObject(acc[0])); assert.equal(Cy, bj.F.toObject(acc[1]));
  assert.equal(Cf, H([Cx, Cy])); assert.equal(await compressPoint({ x: Cx, y: Cy }), Cf);
});

await t('V11 sessionCommit = pk_i·G_PK + max_height·G_EXP + r_s·G_RS + r_rp·H (arid 항 없음)', async () => {
  const { Cx, Cy, Cf } = await sessionCommit({ pk_i, max_height, r_s, r_rp });
  let acc = mul(PEDERSEN_GENERATORS.pk_i, pk_i);
  acc = bj.addPoint(acc, mul(PEDERSEN_GENERATORS.exp, max_height));
  acc = bj.addPoint(acc, mul(PEDERSEN_GENERATORS.rs, r_s));
  acc = bj.addPoint(acc, mul(PEDERSEN_GENERATORS.blind, r_rp));
  assert.equal(Cx, bj.F.toObject(acc[0])); assert.equal(Cy, bj.F.toObject(acc[1]));
  assert.equal(Cf, H([Cx, Cy]));
  const other = await sessionCommit({ pk_i, max_height: max_height + 1n, r_s, r_rp });
  assert.notEqual(other.Cf, Cf, 'max_height 가 커밋에 실린다');
  assert.notEqual((await sessionCommit({ pk_i, max_height, r_s: r_s + 1n, r_rp })).Cf, Cf, 'r_s 가 커밋에 실린다');
});

await t('sessionCommit 상한: pk_i ≥ 2^160, max_height ≥ 2^64, r_s·r_rp ≥ 2^250 은 거부', async () => {
  await assert.rejects(() => sessionCommit({ pk_i: PK_I_MAX, max_height, r_s, r_rp }), /2\^160/);
  await assert.rejects(() => sessionCommit({ pk_i, max_height: MAX_HEIGHT_MAX, r_s, r_rp }), /2\^64/);
  await assert.rejects(() => sessionCommit({ pk_i, max_height, r_s: SCALAR_MAX, r_rp }), /2\^250/);
  await assert.rejects(() => sessionCommit({ pk_i, max_height, r_s, r_rp: SCALAR_MAX }), /2\^250/);
  await assert.rejects(() => sessionCommit({ pk_i, max_height, r_s }), /r_rp/);
});

await t('credMessageV11 = Poseidon(D_V11, auid_s, arid_s, Cf_u, Cf_s, chainid, allowAgent); allowAgent 2 는 거부', async () => {
  const m = await credMessageV11(1n, 2n, 3n, 4n, 31337n, 1n);
  assert.equal(m, H([DOMAIN_MODE3_CRED_V11, 1n, 2n, 3n, 4n, 31337n, 1n]));
  await assert.rejects(() => credMessageV11(1n, 2n, 3n, 4n, 31337n, 2n), /allowAgent/);
  await assert.rejects(() => credMessageV11('1', 2n, 3n, 4n, 31337n, 0n), /bigint/);
});

await t('auidOf·auidSOf·aridSOf 는 태그가 붙은 Poseidon 이고, 같은 r_rp 라도 arid 가 다르면 auid_s 가 다르다(D7)', async () => {
  const a = await auidOf({ uid, s_u });
  assert.equal(a, H([DOMAIN_MODE3_AUID, uid, s_u]));
  assert.equal(await auidSOf({ auid: a, arid, r_rp }), H([DOMAIN_MODE3_AUIDS, a, arid, r_rp]));
  assert.equal(await aridSOf({ arid, r_rp }), H([DOMAIN_MODE3_ARIDS, arid, r_rp]));
  assert.notEqual(await auidSOf({ auid: a, arid, r_rp }), await auidSOf({ auid: a, arid: arid + 1n, r_rp }));
  assert.notEqual(await aridSOf({ arid, r_rp }), await aridSOf({ arid, r_rp: r_rp + 1n }));
  await assert.rejects(() => auidOf({ uid: SCALAR_MAX, s_u }), /2\^250/);
});

await t('PPID = Poseidon(uid, s_u, arid, chainid) — 옛 순서(uid, s_u, chainid, arid)와 다르다(D13)', async () => {
  const p = await ppid({ uid, s_u, arid, chainid: 31337n });
  assert.equal(p, H([uid, s_u, arid, 31337n]));
  assert.notEqual(p, H([uid, s_u, 31337n, arid]));
  await assert.rejects(() => ppid({ uid, s_u, arid }), /chainid/);
});

await t('세션 리프는 불변 — Poseidon(5, Cf_s)', async () => {
  assert.equal(TAG_MODE3_SESSION, 5n);
  assert.equal(await sessionLeaf(77n), H([5n, 77n]));
});

process.exit(failed === 0 ? 0 : 1);
```

- [ ] **Step 2: 실행해 실패 확인**

Run: `node tests/test_mode3_credential_v11.js`
Expected: FAIL — `SyntaxError: The requested module ... does not provide an export named 'auidOf'` (또는 PK_I_MAX 등).

- [ ] **Step 3: `lib/mode3_credential.js` 수정**

(a) 파일 머리 주석 바로 아래, 기존 `DOMAIN_MODE3_CRED_V5` 두 줄을 다음으로 **교체**:

```js
// 서명 도메인(MODE3CRED 계열) 이력: "MODE3CRED"(2026-09-09) → V2 속성 4슬롯(09-14) → V3 세션 성명(09-15) → V4 max_height·allowAgent(09-18)
// → V5(2026-09-21) 커밋 둘 → **V11(2026-10-12, 그림 261012)**: Sign(D_V11, auid_s, arid_s, Cf_u, Cf_s, chainid, allowAgent). 인자 7개.
// max_height 는 토큰 메시지에서 빠지고 C_s 안에 들어간다(D5). 옛 상수는 지웠다 — 도메인이 달라 옛 자격증명은 V11 회로에서 재생되지 않는다.
export const DOMAIN_MODE3_CRED_V11 = 23926173293433188795270181169n;   // ASCII "MODE3CREDV11" 빅엔디언
// 가명 유도 태그(스펙 2026-10-12 §2). 세 해시가 서로 다른 태그를 쓰므로 한 값이 다른 자리에서 재해석되지 않는다.
export const DOMAIN_MODE3_AUID  = 1426111059989489862980n;      // "MODE3AUID"  — auid   = Poseidon(T, uid, s_u)
export const DOMAIN_MODE3_AUIDS = 365084431357309404922963n;    // "MODE3AUIDS" — auid_s = Poseidon(T, auid, arid, r_rp)  (D7: arid 포함)
export const DOMAIN_MODE3_ARIDS = 365084431357309354591315n;    // "MODE3ARIDS" — arid_s = Poseidon(T, arid, r_rp)
export const MAX_HEIGHT_MAX = 1n << 64n;   // 회로 Num2Bits(64) 와 같은 상한
export const PK_I_MAX = 1n << 160n;        // pk_i 는 이더리움 주소 — 회로 Num2Bits(160)
export const ATTR_SLOTS = 6;
export const ATTR_MAX = 1n << 64n;   // 속성은 64비트 정수(스펙 2026-09-22 §4.1) — 회로 Num2Bits(64)·LessEqThan(64) 과 같은 상한
```
(기존 `MAX_HEIGHT_MAX`·`ATTR_SLOTS`·`ATTR_MAX` 줄은 위 블록으로 합쳐지므로 중복을 남기지 않는다.)

(b) `PEDERSEN_GENERATORS` 의 `blind:` 항목 뒤(닫는 `});` 앞)에 두 항목 추가, 주석 갱신:

```js
  // V11(2026-10-12 §2): C_s 의 max_height·r_s 항. circomlibjs getBasePoint('blake', 11)·(12) — attr5(10) 선례. 2026-10-12 inCurve·inSubgroup 확인.
  exp:   Object.freeze([15213743939064641260146023541489016041952046087348720940641996397552589095764n,
          12626463709848357735089296069583194130598330177778437327210365765201604869873n]),
  rs:    Object.freeze([3794846596710804728427490183747125272829051653079153052879417268450674798099n,
          21842435477255044883863745269531290629657425422620774125328061317110773122799n]),
```
머리 주석 "BASE[0..10]" → "BASE[0..12]" 로, "11개" 언급을 13개로 고친다.

(c) `sessionCommit` 함수(주석 포함)를 다음으로 **교체**:

```js
/**
 * 세션 커밋 V11(스펙 2026-10-12 D5·§3.2). 로그인마다.
 *   C_s = pk_i·G_PK + max_height·G_EXP + r_s·G_RS + r_rp·H
 * arid 는 빠졌다 — 서비스 바인딩은 토큰의 arid_s·auid_s(둘 다 r_rp 로 묶인다)가 맡는다. 블라인딩은 RP 가 준 r_rp 다:
 * RP 는 C_s 의 열림값을 모두 알고(심층 방어), IdP 는 r_rp 를 몰라 C_s 를 열지 못한다(pk_i 가 IdP 에 평문으로 가지 않는다).
 * circuits/lib/mode3_commit.circom 의 CommitSessionV11 과 생성원·덧셈 순서·비트 폭(pk_i 160, max_height 64, r_s·r_rp 250)이 같다.
 */
export async function sessionCommit({ pk_i, max_height, r_s, r_rp }) {
  if (typeof pk_i !== 'bigint' || pk_i < 0n || pk_i >= PK_I_MAX) throw new Error(`pk_i 는 [0, 2^160) 범위의 bigint 여야 한다 (회로 Num2Bits(160)): ${pk_i}`);
  if (typeof max_height !== 'bigint' || max_height < 0n || max_height >= MAX_HEIGHT_MAX) throw new Error(`max_height 는 [0, 2^64) 범위의 bigint 여야 한다 (회로 Num2Bits(64)): ${max_height}`);
  checkScalars({ r_s, r_rp });
  const bj = await getBabyjub();
  const mul = (g, e) => bj.mulPointEscalar([bj.F.e(g[0]), bj.F.e(g[1])], e);
  let acc = mul(PEDERSEN_GENERATORS.pk_i, pk_i);
  acc = bj.addPoint(acc, mul(PEDERSEN_GENERATORS.exp, max_height));
  acc = bj.addPoint(acc, mul(PEDERSEN_GENERATORS.rs, r_s));
  acc = bj.addPoint(acc, mul(PEDERSEN_GENERATORS.blind, r_rp));
  return finishCommit(acc);
}
```

(d) `credMessageV5` 를 다음으로 **교체**:

```js
// circuits/pi_cred.circom V11 의 msgHasher(DOMAIN_MODE3_CRED_V11, auid_s, arid_s, Cf_u, Cf_s, chainid, allowAgent) 와 순서가 같아야 한다.
// max_height 는 여기 없다 — C_s(Cf_s) 안에 있다(D5). IdP 는 auid_s·arid_s 를 서명하되 저장하지 않는다(D1·D3).
export async function credMessageV11(auid_s, arid_s, Cf_u, Cf_s, chainid, allowAgent) {
  for (const [k, v] of [['auid_s', auid_s], ['arid_s', arid_s], ['Cf_u', Cf_u], ['Cf_s', Cf_s], ['chainid', chainid], ['allowAgent', allowAgent]]) {
    if (typeof v !== 'bigint' || v < 0n) throw new Error(`credMessageV11: ${k} 는 음이 아닌 bigint 여야 한다`);
  }
  if (allowAgent > 1n) throw new Error('credMessageV11: allowAgent 는 0 또는 1 이어야 한다');
  const poseidon = await getPoseidon();
  return poseidon.F.toObject(poseidon([DOMAIN_MODE3_CRED_V11, auid_s, arid_s, Cf_u, Cf_s, chainid, allowAgent]));
}

/** auid = Poseidon(T_AUID, uid, s_u) — 등록 때 지갑이 IdP 에 내는 사용자 가명(D4). 등록부 리프 Poseidon(auid, Cf_u) 의 재료. */
export async function auidOf({ uid, s_u }) {
  checkScalars({ uid, s_u });
  const poseidon = await getPoseidon();
  return poseidon.F.toObject(poseidon([DOMAIN_MODE3_AUID, uid, s_u]));
}
/** auid_s = Poseidon(T_AUIDS, auid, arid, r_rp) — 세션 가명(D7: arid 가 들어가 두 RP 가 같은 r_rp 를 써도 RP 간에 다르다). */
export async function auidSOf({ auid, arid, r_rp }) {
  if (typeof auid !== 'bigint' || auid < 0n) throw new Error('auidSOf: auid(bigint) 가 필요하다');
  checkScalars({ arid, r_rp });
  const poseidon = await getPoseidon();
  return poseidon.F.toObject(poseidon([DOMAIN_MODE3_AUIDS, auid, arid, r_rp]));
}
/** arid_s = Poseidon(T_ARIDS, arid, r_rp) — 세션용 서비스 가명. RP 가 자기 r_rp 로 재계산해 토큰이 이 세션용인지 확인한다. */
export async function aridSOf({ arid, r_rp }) {
  checkScalars({ arid, r_rp });
  const poseidon = await getPoseidon();
  return poseidon.F.toObject(poseidon([DOMAIN_MODE3_ARIDS, arid, r_rp]));
}
```

(e) `ppid` 를 다음으로 **교체**:

```js
// circuits/pi_cred.circom V11 의 ppidHasher(uid, s_u, arid, chainid) 와 일치해야 한다 — 덱 3장 H(uid, salt, rid, chain_id) 순서(D13).
// V10 의 (uid, s_u, chainid, arid) 에서 순서만 바뀌었다 — 모든 계정 주소가 바뀐다(팩토리 재배포와 함께).
export async function ppid({ uid, s_u, arid, chainid }) {
  if (typeof chainid !== 'bigint') throw new Error('ppid: chainid(bigint) 가 필요하다');
  checkScalars({ uid, s_u, arid });
  const poseidon = await getPoseidon();
  return poseidon.F.toObject(poseidon([uid, s_u, arid, chainid]));
}
```

(f) 파일 맨 위 설명 주석의 "2026-09-14 …" 줄 아래에 한 줄 추가: `// 2026-10-12 V11: C_s 재정의(pk_i·max_height·r_s·r_rp), 토큰 7인자, auid·auid_s·arid_s, PPID 순서 — 스펙 2026-10-12 §2.`

- [ ] **Step 4: `lib/mode3_issuance.js` 전면 교체**

```js
// 발급·등록 요청의 서명 메시지와 점 검사 — V11(스펙 2026-10-12 §3.1·§5.2).
//
// V10 까지 여기 있던 π_u(시그마 프로토콜)·registrationCommit(cm_u) 는 지웠다: V11 은 등록 때 auid = Poseidon(T_AUID, uid, s_u) 를
// 내고(D4), 세션마다 Groth16 회로 π_IdP(circuits/pi_idp.circom, lib/mode3_idp_proof.js)로 uid·salt 관계와 세션 바인딩을 보인다(D10).
// 메시지 인자 **순서**는 회로·CIA·지갑이 공유하는 계약이다 — Poseidon 은 순서가 바뀌면 다른 해시다.
import { buildBabyjub, buildPoseidon } from 'circomlibjs';
import { SCALAR_MAX, MAX_HEIGHT_MAX } from './mode3_credential.js';

const be = (s) => BigInt('0x' + Buffer.from(s).toString('hex'));
export const DOMAIN_MODE3_ISSUEREQ_V11 = 102762131813731415973437885676665581873n;   // ASCII "MODE3ISSUEREQV11" — /cia/issue V11 요청 서명
export const DOMAIN_MODE3_REGISTER_V2 = 1568025692958713225867644958495282n;         // ASCII "MODE3REGISTER2" — /cia/register 소유 증명(uid, auid)
export const DOMAIN_MODE3_SLOTREQ = 23926173293437685841045636433n;                  // ASCII "MODE3SLOTREQ" — /cia/slot 요청 서명(옛 MODE3ATTRSREQ 대체)
export const DOMAIN_MODE3_REVOKESESS = be('MODE3REVOKESESS');                        // /cia/revoke scope=session 사용자 서명(불변)

let bjP = null, psP = null;
const getBj = () => (bjP ??= buildBabyjub());
const getPs = () => (psP ??= buildPoseidon());

const isScalar = (v) => typeof v === 'bigint' && v >= 0n && v < SCALAR_MAX;
const isField = (v) => typeof v === 'bigint' && v >= 0n;

/** 점이 정규 인코딩이고 곡선 위·소수 부분군 안인가. 등록·발급은 되돌릴 수 없어 여기서 걸러낸다(§6.1). */
export async function isValidPoint(o) {
  const bj = await getBj();
  if (typeof o?.x !== 'bigint' || typeof o?.y !== 'bigint') return false;
  const p = bj.F.p;
  if (o.x < 0n || o.x >= p || o.y < 0n || o.y >= p) return false;   // 비정규(non-canonical) 인코딩 거절
  const P = [bj.F.e(o.x), bj.F.e(o.y)];
  return bj.inCurve(P) && bj.inSubgroup(P);
}

/**
 * /cia/issue V11 요청의 사용자 서명 메시지 = Poseidon(D_ISSUEREQ_V11, auid_s, arid_s, Cf_u, Cf_s, chainid, allowAgent, max_height).
 * Cf_u·Cf_s 를 덮으므로 제3자가 남의 C_u 에 자기 C_s 를 붙여 달라고 할 수 없고, auid_s·arid_s 를 덮으므로 다른 세션의 바인딩으로 바꿔 끼울 수 없다.
 */
export async function issueRequestMessageV11(auid_s, arid_s, Cf_u, Cf_s, chainid, allowAgent, max_height) {
  for (const [k, v] of [['auid_s', auid_s], ['arid_s', arid_s], ['Cf_u', Cf_u], ['Cf_s', Cf_s], ['chainid', chainid], ['allowAgent', allowAgent], ['max_height', max_height]]) {
    if (!isField(v)) throw new Error(`issueRequestMessageV11: ${k} 는 음이 아닌 bigint 여야 한다`);
  }
  if (allowAgent > 1n) throw new Error('issueRequestMessageV11: allowAgent 는 0 또는 1 이어야 한다');
  if (max_height >= MAX_HEIGHT_MAX) throw new Error('issueRequestMessageV11: max_height 는 2^64 미만이어야 한다');
  const ps = await getPs();
  return ps.F.toObject(ps([DOMAIN_MODE3_ISSUEREQ_V11, auid_s, arid_s, Cf_u, Cf_s, chainid, allowAgent, max_height]));
}

/** /cia/register 의 소유 증명 메시지 = Poseidon(D_REGISTER_V2, uid, auid). 지갑이 만든 sk_u 로 서명한다 — CIA 는 sk_u 를 만들지 않는다. */
export async function registerMessage(uid, auid) {
  if (!isScalar(uid)) throw new Error('registerMessage: uid 는 [0, 2^250) bigint');
  if (!isField(auid)) throw new Error('registerMessage: auid(bigint) 가 필요하다');
  const ps = await getPs();
  return ps.F.toObject(ps([DOMAIN_MODE3_REGISTER_V2, uid, auid]));
}

/** /cia/slot 요청의 사용자 서명 메시지 = Poseidon(D_SLOTREQ, uid, nonce). nonce 는 지갑이 뽑는 난수 — CIA 는 신선도를 검사하지 않는다(응답은 공개 슬롯 번호). */
export async function slotRequestMessage(uid, nonce) {
  if (!isScalar(uid)) throw new Error('slotRequestMessage: uid 는 [0, 2^250) bigint');
  if (!isScalar(nonce)) throw new Error('slotRequestMessage: nonce 는 [0, 2^250) bigint');
  const ps = await getPs();
  return ps.F.toObject(ps([DOMAIN_MODE3_SLOTREQ, uid, nonce]));
}

/** 세션 폐기 요청의 사용자 서명 메시지 = Poseidon(D_REVOKESESS, uid, Cf_s, nonce). nonce 신선도는 검사하지 않는다(재생 = 같은 세션을 다시 폐기, 멱등). */
export async function revokeSessionMessage(uid, Cf_s, nonce) {
  const ps = await getPs();
  return ps.F.toObject(ps([DOMAIN_MODE3_REVOKESESS, uid, Cf_s, nonce]));
}

// ---- 직렬화 (HTTP 는 bigint 를 못 실으니 10진 문자열) ----
export const pointToStrings = (p) => ({ x: p.x.toString(), y: p.y.toString() });
export const pointFromStrings = (o) => ({ x: BigInt(o.x), y: BigInt(o.y) });
```

- [ ] **Step 5: `lib/mode3_registry.js` 리프 식 교체**

머리 주석 2행 "리프 = Poseidon(cm_u.x, cm_u.y, Cf_u)" → "리프 = Poseidon(auid, Cf_u) (V11, 스펙 2026-10-12 D4)" 로 고치고, `registryLeaf` 를 교체:

```js
/** L_reg(auid, Cf_u) = Poseidon(auid, Cf_u) — V11(D4). auid·Cf_u 는 bigint 또는 10진 문자열. 옛 Poseidon(cm_u.x, cm_u.y, Cf_u) 는 지웠다. */
export async function registryLeaf(auid, Cf_u) {
  const ps = await getPoseidon();
  return ps.F.toObject(ps([big(auid), big(Cf_u)]));
}
```

- [ ] **Step 6: 테스트 갱신 — issuance·registry**

`tests/test_mode3_issuance.js` 전면 교체:

```js
// V11 요청 서명 메시지·점 검사·직렬화 (스펙 2026-10-12 §3.1·§5.2). 외부 의존 없음(unit).
//   node tests/test_mode3_issuance.js
import assert from 'node:assert/strict';
import { buildBabyjub, buildPoseidon } from 'circomlibjs';
import * as issuance from '../lib/mode3_issuance.js';
import { SCALAR_MAX, MAX_HEIGHT_MAX } from '../lib/mode3_credential.js';
const { issueRequestMessageV11, registerMessage, slotRequestMessage, revokeSessionMessage, isValidPoint, pointToStrings, pointFromStrings,
  DOMAIN_MODE3_ISSUEREQ_V11, DOMAIN_MODE3_REGISTER_V2, DOMAIN_MODE3_SLOTREQ, DOMAIN_MODE3_REVOKESESS } = issuance;

let failed = 0;
async function t(name, fn) {
  try { await fn(); console.log(`ok   ${name}`); }
  catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.message}`); }
}
const be = (s) => BigInt('0x' + Buffer.from(s).toString('hex'));
const ps = await buildPoseidon();
const H = (arr) => ps.F.toObject(ps(arr));

await t('도메인 상수는 ASCII 빅엔디언이고 서로 다르다', () => {
  assert.equal(DOMAIN_MODE3_ISSUEREQ_V11, be('MODE3ISSUEREQV11'));
  assert.equal(DOMAIN_MODE3_REGISTER_V2, be('MODE3REGISTER2'));
  assert.equal(DOMAIN_MODE3_SLOTREQ, be('MODE3SLOTREQ'));
  assert.equal(DOMAIN_MODE3_REVOKESESS, be('MODE3REVOKESESS'));
  assert.equal(new Set([DOMAIN_MODE3_ISSUEREQ_V11, DOMAIN_MODE3_REGISTER_V2, DOMAIN_MODE3_SLOTREQ, DOMAIN_MODE3_REVOKESESS]).size, 4);
});
await t('V10 의 σ-프로토콜·등록 커밋 export 는 없다 (registrationCommit, proveUserCred, verifyUserCred, attrsRequestMessage, issueRequestMessageV4)', () => {
  for (const k of ['registrationCommit', 'proveUserCred', 'verifyUserCred', 'attrsRequestMessage', 'issueRequestMessageV4', 'userCredRequestMessage', 'randomZr']) assert.equal(issuance[k], undefined, k);
});
await t('issueRequestMessageV11 = Poseidon(D, auid_s, arid_s, Cf_u, Cf_s, chainid, allowAgent, max_height); allowAgent 2·max_height ≥ 2^64·비bigint 는 throw', async () => {
  assert.equal(await issueRequestMessageV11(1n, 2n, 3n, 4n, 31337n, 1n, 500n), H([DOMAIN_MODE3_ISSUEREQ_V11, 1n, 2n, 3n, 4n, 31337n, 1n, 500n]));
  await assert.rejects(() => issueRequestMessageV11(1n, 2n, 3n, 4n, 31337n, 2n, 500n), /allowAgent/);
  await assert.rejects(() => issueRequestMessageV11(1n, 2n, 3n, 4n, 31337n, 0n, MAX_HEIGHT_MAX), /2\^64/);
  await assert.rejects(() => issueRequestMessageV11('1', 2n, 3n, 4n, 31337n, 0n, 500n), /bigint/);
});
await t('registerMessage = Poseidon(D_REGISTER_V2, uid, auid); uid ≥ 2^250 은 throw', async () => {
  assert.equal(await registerMessage(12345n, 99n), H([DOMAIN_MODE3_REGISTER_V2, 12345n, 99n]));
  await assert.rejects(() => registerMessage(SCALAR_MAX, 99n), /2\^250/);
  await assert.rejects(() => registerMessage(12345n, '99'), /auid/);
});
await t('slotRequestMessage = Poseidon(D_SLOTREQ, uid, nonce); revokeSessionMessage = Poseidon(D_REVOKESESS, uid, Cf_s, nonce)', async () => {
  assert.equal(await slotRequestMessage(12345n, 7n), H([DOMAIN_MODE3_SLOTREQ, 12345n, 7n]));
  await assert.rejects(() => slotRequestMessage(12345n, SCALAR_MAX), /nonce/);
  assert.equal(await revokeSessionMessage(12345n, 8n, 9n), H([DOMAIN_MODE3_REVOKESESS, 12345n, 8n, 9n]));
});
await t('isValidPoint: Base8 은 참, 비정규 인코딩·곡선 밖·문자열은 거짓', async () => {
  const bj = await buildBabyjub();
  const G = { x: bj.F.toObject(bj.Base8[0]), y: bj.F.toObject(bj.Base8[1]) };
  assert.equal(await isValidPoint(G), true);
  assert.equal(await isValidPoint({ x: G.x + bj.F.p, y: G.y }), false);
  assert.equal(await isValidPoint({ x: 1n, y: 1n }), false);
  assert.equal(await isValidPoint({ x: '1', y: '2' }), false);
});
await t('pointToStrings ↔ pointFromStrings', () => {
  const p = { x: 123n, y: 456n };
  assert.deepEqual(pointToStrings(p), { x: '123', y: '456' });
  assert.deepEqual(pointFromStrings(pointToStrings(p)), p);
});
process.exit(failed === 0 ? 0 : 1);
```

`tests/test_mode3_registry.js:16-21` 의 리프 케이스를 다음으로 교체:

```js
await t('registryLeaf = Poseidon(auid, Cf_u) (V11); 문자열 입력도 같다; 옛 cm_u 3인자 식과 다르다', async () => {
  const ps = await buildPoseidon();
  const a = await registryLeaf(11n, 33n);
  assert.equal(a, ps.F.toObject(ps([11n, 33n])));
  assert.equal(await registryLeaf('11', '33'), a);
  assert.notEqual(a, ps.F.toObject(ps([11n, 22n, 33n])));
});
```
(파일 상단에 `import { buildPoseidon } from 'circomlibjs';` 가 없으면 추가. 그 밖의 케이스(트리 set/path/root)는 그대로.)

`tests/test_mode3_credential_v5.js`·`tests/test_mode3_v9_lib.js` 삭제(`git rm` 은 하지 않고 파일만 지운다 — 커밋은 컨트롤러).

`scripts/run_tests.sh` UNIT 배열: `tests/test_mode3_credential_v5.js` → `tests/test_mode3_credential_v11.js`, `tests/test_mode3_v9_lib.js` 줄 삭제.

- [ ] **Step 7: 실행해 통과 확인**

Run: `node tests/test_mode3_credential_v11.js && node tests/test_mode3_issuance.js && node tests/test_mode3_registry.js`
Expected: 세 파일 모두 전부 `ok`, 종료 코드 0.

- [ ] **Step 8: 보고**

커밋하지 않는다. 바뀐 파일 목록과 "Task 5·7 까지 `lib/mode3_wallet.js`·`lib/mode3_secret_source.js`·`cia.js`·`tests/helpers/mode3_fixture.mjs` 의 import 가 깨진 상태" 임을 보고에 적는다.

---

### Task 2: 회로 라이브러리 `CommitSessionV11` + 새 회로 `pi_idp`

**Files:**
- Modify: `circuits/lib/mode3_commit.circom` (`CommitSession`·`RegistrationCommit` 삭제, `CommitSessionV11` 추가)
- Create: `circuits/pi_idp.circom`
- Create: `tests/helpers/mode3_idp_fixture.mjs`
- Create: `tests/test_pi_idp_witness.mjs`
- Modify (전면 교체): `tests/test_mode3_commit_scheme.mjs`
- Modify: `scripts/run_tests.sh` CIRCUIT 목록(`tests/test_pi_idp_witness.mjs` 를 `tests/test_mode3_commit_scheme.mjs` 뒤에 추가)

**Interfaces:**
- Consumes: Task 1 의 `sessionCommit`, `userCommit`, `auidOf`, `auidSOf`, `aridSOf`, `PK_I_MAX`.
- Produces (circom): `template CommitSessionV11()` 입력 `pk_i, max_height, r_s, r_rp` 출력 `Cx, Cy`; `circuits/pi_idp.circom` 의 `component main {public [uid, auid, auid_s, C_u_x, C_u_y, C_s_x, C_s_y, max_height]} = PiIdp();` — 공개 입력 8개가 이 순서로 선언돼 있다(witness 색인 1..8).
- Produces (JS): `buildIdpInput({ attrs, maxHeight, pk_i, r_s, r_rp } = {})` → `{ input, uid, s_u, arid, r_rp, r_s, pk_i, auid, auid_s, arid_s, C_u, C_s, attrs }`.

- [ ] **Step 1: `circuits/lib/mode3_commit.circom` — 두 템플릿 삭제, 하나 추가**

`CommitSession` 과 `RegistrationCommit` 템플릿(각 주석 포함)을 지우고 파일 끝에 추가:

```circom
// V11(2026-10-12 §3.2·D5): 세션 커밋 — 로그인마다.  C_s = pk_i·G_PKI + max_height·G_EXP + r_s·G_RS + r_rp·H
//   pk_i 160비트(세션키 주소), max_height 64비트(만료 블록), r_s·r_rp 250비트(RP 챌린지·RP 난수). lib/mode3_credential.js sessionCommit 과 같다.
//   arid 는 빠졌다 — 서비스 바인딩은 토큰의 arid_s·auid_s(둘 다 r_rp 로 묶인다)가 맡는다. 블라인딩은 RP 가 준 r_rp:
//   RP 는 C_s 의 열림값을 모두 알고(심층 방어), IdP 는 r_rp 를 몰라 C_s 를 열지 못한다.
//   G_EXP·G_RS 는 circomlibjs getBasePoint('blake', 11)·(12) — 2026-10-12 inCurve·inSubgroup 확인(tests/test_mode3_credential_v11.js 가 글자 일치를 검사).
template CommitSessionV11() {
    signal input pk_i;
    signal input max_height;
    signal input r_s;
    signal input r_rp;
    signal output Cx;
    signal output Cy;

    var N = 250;
    var NP = 160;   // pk_i 는 이더리움 주소 — pi_cred 의 옛 Num2Bits(160) 을 여기로 옮겼다
    var NH = 64;    // max_height — 토큰 메시지에서 빠진 대신 여기서 범위가 잡힌다
    var G_PKI[2]   = [7107336197374528537877327281242680114152313102022415488494307685842428166594,
                      2857869773864086953506483169737724679646433914307247183624878062391496185654];
    var G_EXP[2]   = [15213743939064641260146023541489016041952046087348720940641996397552589095764,
                      12626463709848357735089296069583194130598330177778437327210365765201604869873];
    var G_RS[2]    = [3794846596710804728427490183747125272829051653079153052879417268450674798099,
                      21842435477255044883863745269531290629657425422620774125328061317110773122799];
    var H_BLIND[2] = [20265828622013100949498132415626198973119240347465898028410217039057588424236,
                      1160461593266035632937973507065134938065359936056410650153315956301179689506];

    component bPki = Num2Bits(NP);  bPki.in <== pk_i;
    component bMh  = Num2Bits(NH);  bMh.in  <== max_height;
    component bRs  = Num2Bits(N);   bRs.in  <== r_s;
    component bRrp = Num2Bits(N);   bRrp.in <== r_rp;
    component mPki = EscalarMulFix(NP, G_PKI);
    component mMh  = EscalarMulFix(NH, G_EXP);
    component mRs  = EscalarMulFix(N, G_RS);
    component mRrp = EscalarMulFix(N, H_BLIND);
    for (var i = 0; i < NP; i++) mPki.e[i] <== bPki.out[i];
    for (var i = 0; i < NH; i++) mMh.e[i]  <== bMh.out[i];
    for (var i = 0; i < N; i++) { mRs.e[i] <== bRs.out[i]; mRrp.e[i] <== bRrp.out[i]; }
    // 덧셈 순서: pk_i + max_height + r_s + r_rp (JS sessionCommit 과 같다).
    component a1 = BabyAdd();
    a1.x1 <== mPki.out[0]; a1.y1 <== mPki.out[1];
    a1.x2 <== mMh.out[0];  a1.y2 <== mMh.out[1];
    component a2 = BabyAdd();
    a2.x1 <== a1.xout;     a2.y1 <== a1.yout;
    a2.x2 <== mRs.out[0];  a2.y2 <== mRs.out[1];
    component a3 = BabyAdd();
    a3.x1 <== a2.xout;     a3.y1 <== a2.yout;
    a3.x2 <== mRrp.out[0]; a3.y2 <== mRrp.out[1];
    Cx <== a3.xout;
    Cy <== a3.yout;
}
```
파일 머리 주석의 `C_s = arid·G_ARID + pk_i·G_PKI + blind_s·H (세션마다)` 줄을 `C_s = pk_i·G_PKI + max_height·G_EXP + r_s·G_RS + r_rp·H (세션마다, V11)` 로, 생성원 설명을 "BASE[0..12]" 로 고친다.

- [ ] **Step 2: `circuits/pi_idp.circom` 생성**

```circom
pragma circom 2.0.0;

include "lib/poseidon.circom";
include "lib/mode3_commit.circom";

// π_IdP — V11(스펙 2026-10-12 §4, 덱 6장). 세션(토큰 발급)마다 지갑이 IdP 에 낸다(D2).
// IdP 는 서명하기 전에 **uid·salt 관계와 세션 바인딩**만 본다 — 속성 값은 보지 않는다(D15: attrs 는 64비트 범위만).
//   ① C_u = uid·G_UID + s_u·G_SU + Σ attrs·G_ATTR + blind_u·H     (CommitUser 재사용)
//   ② auid   = Poseidon(T_AUID, uid, s_u)                        — IdP DB 의 auid 와 같은가
//   ③ auid_s = Poseidon(T_AUIDS, auid, arid, r_rp)               — 토큰에 들어갈 세션 가명이 정형인가(D3·D7)
//   ④ C_s = pk_i·G_PK + max_height·G_EXP + r_s·G_RS + r_rp·H      — ③ 과 **같은 r_rp**(세션 가명과 세션 커밋의 결합)
// 비공개: s_u, blind_u, attrs[6], arid, r_rp, pk_i, r_s — arid·r_rp 가 비공개라 IdP 는 서비스를 알아보지 못한다(G4).
// 공개 입력 순서는 lib/mode3_idp_proof.js IDP_PUB_INDEX 와 cia.js 의 조립 순서가 의존한다. 바꾸지 말 것:
//   [0] uid [1] auid [2] auid_s [3] C_u_x [4] C_u_y [5] C_s_x [6] C_s_y [7] max_height
// 온체인에 가지 않는다(IdP 만 검증, §6).
template PiIdp() {
    // ---- Private ----
    signal input s_u;
    signal input blind_u;
    signal input attrs[6];
    signal input arid;
    signal input r_rp;
    signal input pk_i;
    signal input r_s;
    // ---- Public (선언 순서 = witness 순서) ----
    signal input uid;
    signal input auid;
    signal input auid_s;
    signal input C_u_x;
    signal input C_u_y;
    signal input C_s_x;
    signal input C_s_y;
    signal input max_height;

    var DOMAIN_MODE3_AUID  = 1426111059989489862980;     // ASCII "MODE3AUID"  — lib/mode3_credential.js DOMAIN_MODE3_AUID
    var DOMAIN_MODE3_AUIDS = 365084431357309404922963;   // ASCII "MODE3AUIDS" — DOMAIN_MODE3_AUIDS

    // ① C_u 재계산
    component cu = CommitUser();
    cu.uid <== uid;  cu.s_u <== s_u;  cu.blind_u <== blind_u;
    for (var j = 0; j < 6; j++) cu.attrs[j] <== attrs[j];
    C_u_x === cu.Cx;
    C_u_y === cu.Cy;

    // ② auid
    component ah = Poseidon(3);
    ah.inputs[0] <== DOMAIN_MODE3_AUID;  ah.inputs[1] <== uid;  ah.inputs[2] <== s_u;
    auid === ah.out;

    // ③ auid_s
    component ash = Poseidon(4);
    ash.inputs[0] <== DOMAIN_MODE3_AUIDS;  ash.inputs[1] <== auid;  ash.inputs[2] <== arid;  ash.inputs[3] <== r_rp;
    auid_s === ash.out;

    // ④ C_s 재계산 — 같은 r_rp
    component cs = CommitSessionV11();
    cs.pk_i <== pk_i;  cs.max_height <== max_height;  cs.r_s <== r_s;  cs.r_rp <== r_rp;
    C_s_x === cs.Cx;
    C_s_y === cs.Cy;
}

component main {public [uid, auid, auid_s, C_u_x, C_u_y, C_s_x, C_s_y, max_height]} = PiIdp();
```

- [ ] **Step 3: `tests/helpers/mode3_idp_fixture.mjs` 생성**

```js
// pi_idp 회로용 입력 픽스처(V11 §4). tests/test_pi_idp_witness.mjs·scripts/bench_pi_idp.mjs 가 쓴다.
// 상수는 tests/helpers/mode3_fixture.mjs(pi_cred)와 같은 값을 쓴다 — 두 회로가 같은 세션을 본다.
import { userCommit, sessionCommit, auidOf, auidSOf, aridSOf } from '../../lib/mode3_credential.js';

export const IDP_FIXTURE = Object.freeze({
  uid: 11111111111111111111n, s_u: 33333333333333333333n, blind_u: 44444444444444444444n,
  arid: 22222222222222222222n, r_rp: 12121212121212121212n, r_s: 13131313131313131313n,
  pk_i: 0x1234567890123456789012345678901234567890n, attrs: Object.freeze([1990n, 410n, 2n, 0n, 0n, 0n]), max_height: 1789000000n,
});

/** 정상 입력 하나. 옵션으로 attrs·maxHeight·pk_i·r_s·r_rp 를 바꿀 수 있다(값은 자유 — IdP 는 속성을 보지 않는다, D15). */
export async function buildIdpInput({ attrs = IDP_FIXTURE.attrs, maxHeight = IDP_FIXTURE.max_height, pk_i = IDP_FIXTURE.pk_i, r_s = IDP_FIXTURE.r_s, r_rp = IDP_FIXTURE.r_rp } = {}) {
  const { uid, s_u, blind_u, arid } = IDP_FIXTURE;
  const a = [...attrs];
  const cu = await userCommit({ uid, s_u, blind_u, attrs: a });
  const cs = await sessionCommit({ pk_i, max_height: maxHeight, r_s, r_rp });
  const auid = await auidOf({ uid, s_u });
  const auid_s = await auidSOf({ auid, arid, r_rp });
  const arid_s = await aridSOf({ arid, r_rp });
  const input = {
    s_u: s_u.toString(), blind_u: blind_u.toString(), attrs: a.map(String), arid: arid.toString(), r_rp: r_rp.toString(), pk_i: pk_i.toString(), r_s: r_s.toString(),
    uid: uid.toString(), auid: auid.toString(), auid_s: auid_s.toString(), C_u_x: cu.Cx.toString(), C_u_y: cu.Cy.toString(), C_s_x: cs.Cx.toString(), C_s_y: cs.Cy.toString(), max_height: maxHeight.toString(),
  };
  return { input, uid, s_u, arid, r_rp, r_s, pk_i, auid, auid_s, arid_s, C_u: { x: cu.Cx, y: cu.Cy, Cf: cu.Cf }, C_s: { x: cs.Cx, y: cs.Cy, Cf: cs.Cf }, attrs: a, max_height: maxHeight };
}
```

- [ ] **Step 4: 실패하는 회로 테스트 — `tests/test_pi_idp_witness.mjs`**

```js
// pi_idp 회로(V11 §4)의 witness 계산 — 양성·음성·공개 입력 순서·제약 수. (circuit 그룹)
//   node tests/test_pi_idp_witness.mjs
// zkey 는 만들지 않는다(Task 4 의 build_mode3_circuit.sh). build/mode3/witness_test/ 에만 컴파일한다 — 배포용 산출물은 건드리지 않는다.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { buildIdpInput } from './helpers/mode3_idp_fixture.mjs';
import { PK_I_MAX, MAX_HEIGHT_MAX } from '../lib/mode3_credential.js';

const ROOT_DIR = fileURLToPath(new URL('..', import.meta.url));
const OUT_DIR = path.join(ROOT_DIR, 'build', 'mode3', 'witness_test');
const NAME = 'pi_idp';

function compile() {
  fs.mkdirSync(OUT_DIR, { recursive: true });
  const out = execFileSync('circom', [
    path.join(ROOT_DIR, 'circuits', `${NAME}.circom`), '--r1cs', '--wasm', '--sym', '-o', OUT_DIR,
    '-l', path.join(ROOT_DIR, 'circuits'), '-l', path.join(ROOT_DIR, 'circuits', 'lib'), '-l', path.join(ROOT_DIR, 'node_modules', 'circomlib', 'circuits'),
  ], { cwd: ROOT_DIR, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  const m = /non-linear constraints:\s*(\d+)/.exec(out);
  console.log(`OK: 컴파일됨, 비선형 제약 ${m ? Number(m[1]).toLocaleString() : '?'}개`);
  return m ? Number(m[1]) : 0;
}
let calc = null;
async function witness(input) {
  if (!calc) {
    const jsDir = path.join(OUT_DIR, `${NAME}_js`);
    const cjsPath = path.join(jsDir, 'witness_calculator.cjs');
    if (!fs.existsSync(cjsPath)) fs.copyFileSync(path.join(jsDir, 'witness_calculator.js'), cjsPath);   // tests/test_pi_cred_witness.mjs 와 같은 CJS 우회
    const wc = await import(cjsPath).then((m) => m.default);
    calc = await wc(fs.readFileSync(path.join(jsDir, `${NAME}.wasm`)));
  }
  return calc.calculateWitness(input, true);
}
let failed = 0;
async function t(name, fn) { try { await fn(); console.log(`ok   ${name}`); } catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.message}`); } }

const constraints = compile();
const fx = await buildIdpInput();
const valid = fx.input;
const bump = (v) => (BigInt(v) + 1n).toString();

await t('양성: 정상 입력의 witness 가 계산된다', async () => { assert.ok((await witness(valid)).length > 0); });
await t('공개 입력 순서 = [uid, auid, auid_s, C_u_x, C_u_y, C_s_x, C_s_y, max_height] (witness 1..8, .sym)', async () => {
  const sym = fs.readFileSync(path.join(OUT_DIR, `${NAME}.sym`), 'utf8');
  const byIndex = new Map();
  for (const line of sym.split('\n')) { const f = line.split(','); if (f.length < 4) continue; const idx = Number(f[1]); if (idx >= 1 && idx <= 8 && /^main\.[^.]+$/.test(f[3]) && !byIndex.has(idx)) byIndex.set(idx, f[3].slice(5)); }
  assert.deepEqual(Array.from({ length: 8 }, (_, i) => byIndex.get(i + 1)), ['uid', 'auid', 'auid_s', 'C_u_x', 'C_u_y', 'C_s_x', 'C_s_y', 'max_height']);
  const w = await witness(valid);
  assert.equal(BigInt(w[2]).toString(), valid.auid); assert.equal(BigInt(w[8]).toString(), valid.max_height);
});
await t('D15: 속성 값은 자유 — 다른 attrs 로 만든 C_u 도 통과한다(IdP 는 값을 보지 않는다)', async () => {
  const other = await buildIdpInput({ attrs: [1n, 2n, 3n, 4n, 5n, 6n] });
  assert.ok((await witness(other.input)).length > 0);
});
await t('음성: s_u 를 바꾸면 거부 (C_u·auid 둘 다 어긋난다)', async () => { await assert.rejects(() => witness({ ...valid, s_u: bump(valid.s_u) }), /Assert Failed/); });
await t('음성: auid 를 바꾸면 거부 — IdP 가 DB 값을 넣으므로 다른 salt 의 지갑은 통과하지 못한다', async () => { await assert.rejects(() => witness({ ...valid, auid: bump(valid.auid) }), /Assert Failed/); });
await t('음성: auid_s 를 바꾸면 거부; arid 를 바꾸면 auid_s 가 어긋나 거부', async () => {
  await assert.rejects(() => witness({ ...valid, auid_s: bump(valid.auid_s) }), /Assert Failed/);
  await assert.rejects(() => witness({ ...valid, arid: bump(valid.arid) }), /Assert Failed/);
});
await t('음성: r_rp 를 바꾸면 거부 (auid_s 와 C_s 가 같은 r_rp 에 묶인다)', async () => { await assert.rejects(() => witness({ ...valid, r_rp: bump(valid.r_rp) }), /Assert Failed/); });
await t('음성: pk_i·r_s·max_height 를 바꾸면 C_s 가 어긋나 거부', async () => {
  await assert.rejects(() => witness({ ...valid, pk_i: bump(valid.pk_i) }), /Assert Failed/);
  await assert.rejects(() => witness({ ...valid, r_s: bump(valid.r_s) }), /Assert Failed/);
  await assert.rejects(() => witness({ ...valid, max_height: bump(valid.max_height) }), /Assert Failed/);
});
await t('음성: 범위 — attr ≥ 2^64, pk_i ≥ 2^160, max_height ≥ 2^64 는 거부', async () => {
  await assert.rejects(() => witness({ ...valid, attrs: [(1n << 64n).toString(), '410', '2', '0', '0', '0'] }), /Assert Failed/);
  await assert.rejects(() => witness({ ...valid, pk_i: PK_I_MAX.toString() }), /Assert Failed/);
  await assert.rejects(() => witness({ ...valid, max_height: MAX_HEIGHT_MAX.toString() }), /Assert Failed/);
});
await t('양성: 같은 r_rp 로 다른 세션키·만료의 C_s 를 만들면(픽스처 재생성) 통과한다', async () => {
  const other = await buildIdpInput({ pk_i: 0x9999n, maxHeight: 42n, r_s: 777n });
  assert.ok((await witness(other.input)).length > 0);
});

console.log('');
console.log(`## pi_idp 비선형 제약: ${constraints.toLocaleString()} (스펙 §4 추정 약 13,000)`);
process.exit(failed === 0 ? 0 : 1);
```

- [ ] **Step 5: 실행해 실패 확인**

Run: `node tests/test_pi_idp_witness.mjs`
Expected: Step 1·2 를 아직 안 했다면 컴파일 오류(`pi_idp.circom` 없음). Step 1·2 뒤에 다시 돌려 통과시킨다.

- [ ] **Step 6: `tests/test_mode3_commit_scheme.mjs` 전면 교체**

```js
// Mode 3 커밋 회로 둘(CommitUser·CommitSessionV11)이 JS 와 일치하는지와 제약 수. (circuit 그룹)
//   node tests/test_mode3_commit_scheme.mjs
// zkey 는 만들지 않는다. 산출물은 build/mode3/commit/ 에 만든다.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { buildBabyjub } from 'circomlibjs';
import { userCommit, sessionCommit, SCALAR_MAX, PK_I_MAX, PEDERSEN_GENERATORS } from '../lib/mode3_credential.js';

const ROOT_DIR = fileURLToPath(new URL('..', import.meta.url));
const OUT_DIR = path.join(ROOT_DIR, 'build', 'mode3', 'commit');
const SRC = {
  user: `pragma circom 2.0.0;\ninclude "lib/mode3_commit.circom";\ncomponent main = CommitUser();`,
  session: `pragma circom 2.0.0;\ninclude "lib/mode3_commit.circom";\ncomponent main = CommitSessionV11();`,
};
function compile(name, src) {
  fs.mkdirSync(OUT_DIR, { recursive: true });
  const wrapper = path.join(OUT_DIR, `${name}.circom`);
  fs.writeFileSync(wrapper, src);
  const out = execFileSync('circom', [wrapper, '--r1cs', '--wasm', '-o', OUT_DIR, '-l', path.join(ROOT_DIR, 'circuits'), '-l', path.join(ROOT_DIR, 'circuits', 'lib'), '-l', path.join(ROOT_DIR, 'node_modules', 'circomlib', 'circuits')], { cwd: ROOT_DIR, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  const m = /non-linear constraints:\s*(\d+)/.exec(out);
  assert.ok(m, `제약 수를 읽지 못했다:\n${out}`);
  return Number(m[1]);
}
async function witness(name, input) {
  const jsDir = path.join(OUT_DIR, `${name}_js`);
  const cjsPath = path.join(jsDir, 'witness_calculator.cjs');
  if (!fs.existsSync(cjsPath)) fs.copyFileSync(path.join(jsDir, 'witness_calculator.js'), cjsPath);
  const wc = await import(cjsPath).then((m) => m.default);
  const calc = await wc(fs.readFileSync(path.join(jsDir, `${name}.wasm`)));
  return calc.calculateWitness(input, true);
}
const USER_INPUT = { uid: '11111111111111111111', s_u: '33333333333333333333', blind_u: '44444444444444444444', attrs: ['19', '410', '0', '0', '0', '0'] };
const SESSION_INPUT = { pk_i: '1234567890123456789012345678901234567890', max_height: '1789000000', r_s: '13131313131313131313', r_rp: '12121212121212121212' };
let failed = 0;
async function t(name, fn) { try { await fn(); console.log(`ok   ${name}`); } catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.message}`); } }
const counts = {};

await t('CommitUser 회로의 (Cx, Cy) 가 JS userCommit 과 일치한다', async () => {
  counts.user = compile('user', SRC.user);
  const w = await witness('user', USER_INPUT);
  const { Cx, Cy } = await userCommit({ uid: BigInt(USER_INPUT.uid), s_u: BigInt(USER_INPUT.s_u), blind_u: BigInt(USER_INPUT.blind_u), attrs: USER_INPUT.attrs.map(BigInt) });
  assert.equal(BigInt(w[1]), Cx, 'Cx 불일치 — 생성원 순서나 스칼라 인코딩이 어긋났다'); assert.equal(BigInt(w[2]), Cy, 'Cy 불일치');
});
await t('CommitSessionV11 회로의 (Cx, Cy) 가 JS sessionCommit({pk_i, max_height, r_s, r_rp}) 과 일치한다', async () => {
  counts.session = compile('session', SRC.session);
  const w = await witness('session', SESSION_INPUT);
  const { Cx, Cy } = await sessionCommit({ pk_i: BigInt(SESSION_INPUT.pk_i), max_height: BigInt(SESSION_INPUT.max_height), r_s: BigInt(SESSION_INPUT.r_s), r_rp: BigInt(SESSION_INPUT.r_rp) });
  assert.equal(BigInt(w[1]), Cx); assert.equal(BigInt(w[2]), Cy);
});
await t('생성원 13개가 곡선 위·소수 부분군 안에 있다', async () => {
  const bj = await buildBabyjub();
  assert.equal(Object.keys(PEDERSEN_GENERATORS).length, 13, 'uid, arid, s_u, pk_i, attr0..5, blind, exp, rs');
  for (const [name, g] of Object.entries(PEDERSEN_GENERATORS)) { const P = [bj.F.e(g[0]), bj.F.e(g[1])]; assert.ok(bj.inCurve(P), `${name} 곡선`); assert.ok(bj.inSubgroup(P), `${name} 부분군 — binding 논증이 깨진다`); }
});
await t('JS 가 상한을 거부한다 (s_u·r_s 2^250, pk_i 2^160)', async () => {
  await assert.rejects(() => userCommit({ uid: 1n, s_u: SCALAR_MAX, blind_u: 4n }), /2\^250/);
  await assert.rejects(() => sessionCommit({ pk_i: 5n, max_height: 1n, r_s: SCALAR_MAX, r_rp: 2n }), /2\^250/);
  await assert.rejects(() => sessionCommit({ pk_i: PK_I_MAX, max_height: 1n, r_s: 1n, r_rp: 2n }), /2\^160/);
});
await t('회로도 상한을 거부한다 (s_u 2^250, pk_i 2^160, max_height 2^64)', async () => {
  await assert.rejects(() => witness('user', { ...USER_INPUT, s_u: SCALAR_MAX.toString() }), /Assert Failed/);
  await assert.rejects(() => witness('session', { ...SESSION_INPUT, pk_i: PK_I_MAX.toString() }), /Assert Failed/);
  await assert.rejects(() => witness('session', { ...SESSION_INPUT, max_height: (1n << 64n).toString() }), /Assert Failed/);
});
await t('attr·blind 하나만 바꿔도 C_u 가 바뀐다; max_height·r_s·r_rp 하나만 바꿔도 C_s 가 바뀐다', async () => {
  const a = await witness('user', USER_INPUT);
  assert.notEqual(a[1].toString(), (await witness('user', { ...USER_INPUT, attrs: ['20', '410', '0', '0', '0', '0'] }))[1].toString());
  assert.notEqual(a[1].toString(), (await witness('user', { ...USER_INPUT, blind_u: '66666666666666666666' }))[1].toString());
  const s = await witness('session', SESSION_INPUT);
  for (const [k, v] of [['max_height', '1789000001'], ['r_s', '1'], ['r_rp', '1']]) assert.notEqual(s[1].toString(), (await witness('session', { ...SESSION_INPUT, [k]: v }))[1].toString(), k);
});
await t('attrs 를 생략한 JS userCommit 은 전부 0 과 같다', async () => {
  assert.equal((await userCommit({ uid: 1n, s_u: 3n, blind_u: 4n, attrs: [0n, 0n, 0n, 0n, 0n, 0n] })).Cf, (await userCommit({ uid: 1n, s_u: 3n, blind_u: 4n })).Cf);
});
console.log('\n## 커밋 회로 제약 수\n\n| 회로 | 비선형 제약 |\n|---|--:|');
for (const [k, v] of Object.entries(counts)) console.log(`| ${k} | ${v.toLocaleString()} |`);
process.exit(failed === 0 ? 0 : 1);
```

- [ ] **Step 7: 실행해 통과 확인**

Run: `node tests/test_mode3_commit_scheme.mjs && node tests/test_pi_idp_witness.mjs`
Expected: 전부 `ok`; `pi_idp` 제약 수가 출력된다(스펙 추정 약 13,000 — 실측값을 보고에 적는다).

`scripts/run_tests.sh` CIRCUIT 배열의 `tests/test_mode3_commit_scheme.mjs` 다음 줄에 `tests/test_pi_idp_witness.mjs` 를 넣는다.

---

### Task 3: `pi_cred` V11 회로 — 공개 입력 33, 토큰·ID·등록부 제약

**Files:**
- Modify (전면 교체): `circuits/pi_cred.circom`
- Modify (전면 교체): `tests/helpers/mode3_fixture.mjs`
- Modify: `tests/test_pi_cred_witness.mjs` (V9 r_u·blind_s 케이스 교체, V11 케이스 추가)
- Modify (전면 교체): `tests/test_mode3_artifacts.mjs`

**Interfaces:**
- Consumes: Task 1 (`sessionCommit`, `credMessageV11`, `auidOf`, `auidSOf`, `aridSOf`, `ppid`, `registryLeaf`), Task 2 (`CommitSessionV11`).
- Produces: `circuits/pi_cred.circom` `component main {public [... 30개 ..., auid_s, arid_s, r_s]} = PiCred(32, 20);`; 비공개 입력 이름 `uid, s_u, blind_u, r_rp, attrs[6], r, S, R8x, R8y, s_lowValue, s_lowNextIndex, s_lowNextValue, s_pathElements[32], s_pathIndices[32], reg_pathElements[20], reg_pathIndices[20], set_index, set_path[8]`(r_u·blind_s 삭제). `buildValidInput(opts)` → `{ input, Cf_u, Cf_s, pk_trace, shares, tag, ciaPub, arid, uid, tree, registry, slot, auid, auid_s, arid_s, r_rp, r_s, attrs, disclosure, set }`.

- [ ] **Step 1: `circuits/pi_cred.circom` 전면 교체**

```circom
pragma circom 2.0.0;

include "lib/eddsaposeidon.circom";
include "lib/poseidon.circom";
include "lib/imt_nonmembership_v2.circom";
include "lib/merkle_inclusion.circom";
include "lib/bitify.circom";
include "lib/comparators.circom";
include "lib/mux1.circom";
include "lib/mode3_commit.circom";
include "lib/mode3_trace_tag.circom";

// Mode 3 credential 증명 π_RP — V11(2026-10-12, 그림 261012 · 덱 7장). 설계 docs/superpowers/specs/2026-10-12-mode3-v11-figure-protocol-design.md §5.3
// 이력: V5 커밋 둘(09-21) · V6 선택 공개(09-22) · V7 집합 소속(09-23) · V8 세션 비멤버십(09-24) · V9 등록부 멤버십(10-01) · V11 가명·세션 바인딩(10-12).
// 여덟 가지를 함께 증명한다. 하나라도 빠지면 뚫린다:
//   ① 토큰: IdP 가 (auid_s, arid_s, Cf_u, Cf_s, chainid, allowAgent) 에 서명했다 — 없으면 아무나 credential 을 만든다
//   ② ID 정확성: auid = Poseidon(T_AUID, uid, s_u), auid_s = Poseidon(T_AUIDS, auid, arid, r_rp), arid_s = Poseidon(T_ARIDS, arid, r_rp)
//      — 없으면 토큰의 세션 가명이 이 uid·arid 와 무관하다(남의 토큰을 자기 arid 로 쓴다)
//   ③ PPID = Poseidon(uid, s_u, arid, chainid) — 없으면 지갑 주소를 특정할 수 없다(D13 순서)
//   ④ 선택 공개·집합 소속(불변) — 사용자가 넣은 attrs 위에서(D15)
//   ⑤ 같은 r_rp: ② 의 두 해시와 ⑦ 의 C_s 블라인딩이 하나의 비공개 r_rp — 없으면 토큰(C_s)과 가명이 다른 세션 것일 수 있다
//   ⑥ 등록부: Poseidon(auid, Cf_u) ∈ Tree(regRoot)(깊이 20) · 폐기: Poseidon(5, Cf_s) ∉ Tree(revRoot)(IMT 32)
//      — 없으면 미등록·관리자 바꿔치기·은퇴한 자격증명, 폐기된 세션이 통과한다
//   ⑦ C_s = pk_i·G_PK + max_height·G_EXP + r_s·G_RS + r_rp·H — r_s(공개)·max_height(공개)·pk_i(공개) 가 토큰의 Cf_s 에 묶인다(재전송 방지: RP 가 r_s 를 1회 소비)
//   ⑧ tag = Enc(pk_trace, Poseidon(uid, arid); ρ), ρ ≠ 0 — 없으면 개봉이 엉뚱한 값을 연다
//
//   attrs[6] 는 C_u 에만 실린다 — IdP 는 값을 모른다(D15). 공개 입력은 AA(IdP)·RP·체인이 모두 보므로 uid·s_u·r_rp 는 어디에도 평문으로 없다.
//   auid_s·arid_s·r_s 는 공개 입력 끝(30·31·32)에 붙었다 — 색인 0~29 는 V9 와 같아 contracts/Mode3Wallet.sol 의 꼬리 15워드·다이제스트가 불변이다(D12).
template PiCred(depth, regDepth) {
    // ---- Private ----
    signal input uid;
    signal input s_u;
    signal input blind_u;
    signal input r_rp;       // V11: RP 난수 — auid_s·arid_s·C_s 블라인딩을 하나로 묶는다(⑤)
    signal input attrs[6];
    signal input r;

    signal input S;
    signal input R8x;
    signal input R8y;

    // V8 세션 리프 비멤버십 증인(폐기 트리)
    signal input s_lowValue;
    signal input s_lowNextIndex;
    signal input s_lowNextValue;
    signal input s_pathElements[depth];
    signal input s_pathIndices[depth];

    // V9 등록부 경로(비공개). 슬롯 번호는 pathIndices 비트에만 있다 — 공개되지 않는다.
    signal input reg_pathElements[regDepth];
    signal input reg_pathIndices[regDepth];

    // V7 집합 소속 경로(비공개)
    signal input set_index;
    signal input set_path[8];

    // ---- Public (순서 = lib/mode3_wallet.js·lib/mode3_rp.js·lib/mode3_onchain.js PUB_INDEX·contracts/Mode3Wallet.sol 의 계약) ----
    signal input PPID;
    signal input arid;
    signal input pk_i;
    signal input max_height;
    signal input chainid;
    signal input allowAgent;
    signal input revRoot;
    signal input regRoot;
    signal input pk_CIA_x;
    signal input pk_CIA_y;
    signal input pk_trace_x;
    signal input pk_trace_y;
    signal input tag_c1_x;
    signal input tag_c1_y;
    signal input tag_c2;
    signal input disc_mask;
    signal input disc_lo[6];
    signal input disc_hi[6];
    signal input set_sel;
    signal input set_root;
    signal input auid_s;     // V11 [30]
    signal input arid_s;     // V11 [31]
    signal input r_s;        // V11 [32]

    var DOMAIN_MODE3_CRED_V11 = 23926173293433188795270181169;   // ASCII "MODE3CREDV11" — lib/mode3_credential.js DOMAIN_MODE3_CRED_V11
    var DOMAIN_MODE3_AUID  = 1426111059989489862980;             // "MODE3AUID"
    var DOMAIN_MODE3_AUIDS = 365084431357309404922963;           // "MODE3AUIDS"
    var DOMAIN_MODE3_ARIDS = 365084431357309354591315;           // "MODE3ARIDS"
    var TAG_MODE3_SESSION = 5;

    // ---- 커밋 둘 ----
    component cu = CommitUser();
    cu.uid <== uid;  cu.s_u <== s_u;  cu.blind_u <== blind_u;
    for (var j = 0; j < 6; j++) cu.attrs[j] <== attrs[j];
    component cfu = Poseidon(2);
    cfu.inputs[0] <== cu.Cx;  cfu.inputs[1] <== cu.Cy;
    signal Cf_u;
    Cf_u <== cfu.out;
    // ⑦ C_s 는 공개 입력 pk_i·max_height·r_s 와 비공개 r_rp 로 **직접 계산**한다 — 다른 값을 넣으면 토큰 서명이 깨진다.
    //    pk_i 160비트·max_height 64비트 범위는 CommitSessionV11 안의 Num2Bits 가 잡는다(옛 pkIRange·mhRange 를 대신한다).
    component cs = CommitSessionV11();
    cs.pk_i <== pk_i;  cs.max_height <== max_height;  cs.r_s <== r_s;  cs.r_rp <== r_rp;
    component cfs = Poseidon(2);
    cfs.inputs[0] <== cs.Cx;  cfs.inputs[1] <== cs.Cy;
    signal Cf_s;
    Cf_s <== cfs.out;

    // ---- ② ID 정확성 (⑤: 같은 r_rp 신호) ----
    component ah = Poseidon(3);
    ah.inputs[0] <== DOMAIN_MODE3_AUID;  ah.inputs[1] <== uid;  ah.inputs[2] <== s_u;
    signal auid;
    auid <== ah.out;
    component ash = Poseidon(4);
    ash.inputs[0] <== DOMAIN_MODE3_AUIDS;  ash.inputs[1] <== auid;  ash.inputs[2] <== arid;  ash.inputs[3] <== r_rp;
    auid_s === ash.out;
    component arh = Poseidon(3);
    arh.inputs[0] <== DOMAIN_MODE3_ARIDS;  arh.inputs[1] <== arid;  arh.inputs[2] <== r_rp;
    arid_s === arh.out;

    // ---- ① 토큰 ----
    allowAgent * (allowAgent - 1) === 0;
    component msgHasher = Poseidon(7);
    msgHasher.inputs[0] <== DOMAIN_MODE3_CRED_V11;
    msgHasher.inputs[1] <== auid_s;
    msgHasher.inputs[2] <== arid_s;
    msgHasher.inputs[3] <== Cf_u;
    msgHasher.inputs[4] <== Cf_s;
    msgHasher.inputs[5] <== chainid;
    msgHasher.inputs[6] <== allowAgent;
    component sigVerifier = EdDSAPoseidonVerifier();
    sigVerifier.enabled <== 1;
    sigVerifier.Ax <== pk_CIA_x;
    sigVerifier.Ay <== pk_CIA_y;
    sigVerifier.S <== S;
    sigVerifier.R8x <== R8x;
    sigVerifier.R8y <== R8y;
    sigVerifier.M <== msgHasher.out;

    // ---- ③ PPID (D13 순서) ----
    // chainid 는 토큰 메시지에도 들어가는 같은 공개 입력이라, 토큰이 보증하는 체인과 가명의 체인이 어긋날 수 없다.
    component ppidHasher = Poseidon(4);
    ppidHasher.inputs[0] <== uid;
    ppidHasher.inputs[1] <== s_u;
    ppidHasher.inputs[2] <== arid;
    ppidHasher.inputs[3] <== chainid;
    PPID === ppidHasher.out;

    // ---- ⑥ 세션 비멤버십 (폐기 트리) ----
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

    // ---- ⑥ 등록부 멤버십 (V11 리프 Poseidon(auid, Cf_u)) ----
    // auid 는 ② 와 같은 신호 — 등록 때 낸 가명의 salt 와 지금 PPID 의 salt 가 같다는 뜻이다. 회로가 비공개 입력에서 리프를
    // 직접 계산하므로 증명자가 다른 리프를 제시할 수 없다.
    component regLeaf = Poseidon(2);
    regLeaf.inputs[0] <== auid;  regLeaf.inputs[1] <== Cf_u;
    component inc = MerkleInclusion(regDepth);
    inc.leaf <== regLeaf.out;
    for (var i = 0; i < regDepth; i++) {
        inc.pathElements[i] <== reg_pathElements[i];
        inc.pathIndices[i] <== reg_pathIndices[i];
    }
    inc.root === regRoot;

    // ---- ⑧ 트레이스 태그 ----
    // r ≠ 0 (2026-09-21 결정): c1 = r·B8 가 항등원이면 c2 가 평문을 그대로 드러낸다. 컨트랙트·서비스의 c1 ≠ O 검사와 중복 방어.
    component rNZ = IsZero();
    rNZ.in <== r;
    rNZ.out === 0;
    component tag = TraceTag();
    tag.r <== r;
    tag.uid <== uid;
    tag.arid <== arid;
    tag.pk_trace_x <== pk_trace_x;
    tag.pk_trace_y <== pk_trace_y;
    tag_c1_x === tag.c1x;
    tag_c1_y === tag.c1y;
    tag_c2 === tag.c2;

    // ---- ④ 선택 공개 (슬롯 6) ----
    // 속성은 CommitUser 에서 Num2Bits(64) 로 잘려 있다. lo·hi 도 64비트로 묶어야 LessEqThan(64) 이 성립한다.
    component maskBits = Num2Bits(6);
    maskBits.in <== disc_mask;
    component loBits[6]; component hiBits[6]; component ge[6]; component le[6];
    signal discOk[6];
    for (var k = 0; k < 6; k++) {
        loBits[k] = Num2Bits(64); loBits[k].in <== disc_lo[k];
        hiBits[k] = Num2Bits(64); hiBits[k].in <== disc_hi[k];
        ge[k] = LessEqThan(64); ge[k].in[0] <== disc_lo[k]; ge[k].in[1] <== attrs[k];
        le[k] = LessEqThan(64); le[k].in[0] <== attrs[k];   le[k].in[1] <== disc_hi[k];
        discOk[k] <== ge[k].out * le[k].out;
        maskBits.out[k] * (1 - discOk[k]) === 0;
    }

    // ---- ④ 집합 소속 (set_sel ∈ {0..6}) ----
    component selIs[7];
    var selSum = 0;
    for (var j = 0; j < 7; j++) {
        selIs[j] = IsEqual();
        selIs[j].in[0] <== set_sel;
        selIs[j].in[1] <== j;
        selSum += selIs[j].out;
    }
    selSum === 1;
    signal selTerm[6];
    for (var k = 0; k < 6; k++) selTerm[k] <== selIs[k + 1].out * attrs[k];
    signal setVal;
    setVal <== selTerm[0] + selTerm[1] + selTerm[2] + selTerm[3] + selTerm[4] + selTerm[5];
    component setInc = MerkleInclusion(8);
    setInc.leaf <== setVal;
    component setIdxBits = Num2Bits(8);
    setIdxBits.in <== set_index;
    for (var i = 0; i < 8; i++) {
        setInc.pathElements[i] <== set_path[i];
        setInc.pathIndices[i] <== setIdxBits.out[i];
    }
    (1 - selIs[0].out) * (setInc.root - set_root) === 0;
    selIs[0].out * set_root === 0;
}

// 공개 입력의 순서는 lib/mode3_wallet.js·lib/mode3_rp.js·lib/mode3_onchain.js(PUB_INDEX)·cia.js(개봉)·contracts/Mode3Wallet.sol 가 의존한다. 바꾸지 말 것.
// pk_CIA_x/y 와 pk_trace_x/y 는 공개 입력이다. 검증자는 반드시 전자를 고정된 CIA 키와, 후자를 자기 등록 파일의 조합 키와 비교해야 한다.
// [0] PPID [1] arid [2] pk_i [3] max_height [4] chainid [5] allowAgent [6] revRoot [7] regRoot [8,9] pk_CIA [10,11] pk_trace
// [12..14] tag [15] disc_mask [16..21] disc_lo [22..27] disc_hi [28] set_sel [29] set_root [30] auid_s [31] arid_s [32] r_s
component main {public [
    PPID, arid, pk_i, max_height, chainid, allowAgent, revRoot, regRoot, pk_CIA_x, pk_CIA_y,
    pk_trace_x, pk_trace_y, tag_c1_x, tag_c1_y, tag_c2,
    disc_mask, disc_lo, disc_hi, set_sel, set_root,
    auid_s, arid_s, r_s
]} = PiCred(32, 20);
```

- [ ] **Step 2: `tests/helpers/mode3_fixture.mjs` 전면 교체**

```js
// pi_cred 회로용 공유 입력 픽스처 (V11 — 스펙 2026-10-12 §5.3).
// tests/test_pi_cred_witness.mjs, scripts/bench_pi_cred.mjs, test/Mode3Wallet.test.mjs 가 같은 입력 생성기를 쓴다.
import { buildPoseidon, buildEddsa, buildBabyjub } from 'circomlibjs';
import { sessionLeaf, createRevocationTree } from '../../lib/mode3_revocation.js';
import { userCommit, sessionCommit, credMessageV11, ppid as computePpid, auidOf, auidSOf, aridSOf } from '../../lib/mode3_credential.js';
import { createRegistryTree, registryLeaf } from '../../lib/mode3_registry.js';
import { combinePublicKey, encryptTag } from '../../lib/mode3_trace.js';
import { setPath, NO_SET } from '../../lib/mode3_set_tree.js';

export const ZERO6 = Object.freeze([0n, 0n, 0n, 0n, 0n, 0n]);
export const FIXTURE_ATTRS = Object.freeze([1990n, 410n, 2n, 0n, 0n, 0n]);   // 회로 입력 벡터(스키마와 무관 — 스펙 2 §9). 값 2 는 옛 데모 등급이지만 회로·벤치 입력은 바꾸지 않는다(재현성).

/** 정상 입력 하나. 옵션: pk_i(실제 세션키 주소), maxHeight, allowAgent, chainid, disclosure{mask, lo[6], hi[6]}, set{slot 0..5, members},
 *  revokedSessions(남의 세션 리프), registrySlot(기본 7), registryLeafOverride(음성용), r_s·r_rp(V11 세션 난수 — 기본은 고정값). */
export async function buildValidInput({ pk_i: pkIOpt, maxHeight = 1789000000n, allowAgent = 0n, chainid = 31337n, disclosure = null, set = null, revokedSessions = [], registrySlot = 7, registryLeafOverride = null, r_s = 13131313131313131313n, r_rp = 12121212121212121212n } = {}) {
  const poseidon = await buildPoseidon();
  const F = poseidon.F;
  const eddsa = await buildEddsa();

  const uid     = 11111111111111111111n;
  const arid    = 22222222222222222222n;
  const s_u     = 33333333333333333333n;
  const blind_u = 44444444444444444444n;
  const pk_i    = pkIOpt ?? 0x1234567890123456789012345678901234567890n;
  const attrs   = [...FIXTURE_ATTRS];
  const max_height = maxHeight;

  const bj = await buildBabyjub();
  const shareOf = (x) => ({ x, X: { x: bj.F.toObject(bj.mulPointEscalar(bj.Base8, x)[0]), y: bj.F.toObject(bj.mulPointEscalar(bj.Base8, x)[1]) } });
  const shares = { svc: shareOf(66666666666666666666n), aa: shareOf(77777777777777777777n) };
  const pk_trace = await combinePublicKey(shares.svc.X, shares.aa.X);
  const tag = await encryptTag(pk_trace, uid, arid, 88888888888888888888n);

  const { Cf: Cf_u } = await userCommit({ uid, s_u, blind_u, attrs });
  const { Cf: Cf_s } = await sessionCommit({ pk_i, max_height, r_s, r_rp });
  const auid = await auidOf({ uid, s_u });
  const auid_s = await auidSOf({ auid, arid, r_rp });
  const arid_s = await aridSOf({ arid, r_rp });
  const PPID = await computePpid({ uid, s_u, arid, chainid });
  const msg = await credMessageV11(auid_s, arid_s, Cf_u, Cf_s, chainid, allowAgent);

  const prv = Buffer.from('0001020304050607080900010203040506070809000102030405060708090001', 'hex');
  const pub = eddsa.prv2pub(prv);
  const sig = eddsa.signPoseidon(prv, F.e(msg));
  const ciaPub = { x: F.toObject(pub[0]), y: F.toObject(pub[1]) };

  // 폐기 트리: 남의 세션 폐기 리프만. 내 세션 비멤버십은 성립해야 한다.
  const tree = await createRevocationTree();
  await tree.insert(await sessionLeaf(999n));
  for (const c of revokedSessions) await tree.insert(await sessionLeaf(BigInt(c)));
  const ws = await tree.getNonMembershipWitness(await sessionLeaf(Cf_s));

  // 등록부: 남의 슬롯 둘 + 내 슬롯(registrySlot). 리프 = Poseidon(auid, Cf_u).
  const registry = await createRegistryTree();
  if (registrySlot === 0 || registrySlot === 3) throw new Error('registrySlot 은 남의 슬롯(0, 3)과 겹칠 수 없다');
  registry.set(0, 12345n);
  registry.set(3, 67890n);
  const myLeaf = registryLeafOverride ?? await registryLeaf(auid, Cf_u);
  registry.set(registrySlot, myLeaf);
  const rp = registry.path(registrySlot);

  const disc = disclosure ?? { mask: 0n, lo: [...ZERO6], hi: [...ZERO6] };
  let st = NO_SET;
  if (set) {
    const { index, path, root } = await setPath(set.members, attrs[set.slot]);
    st = { sel: BigInt(set.slot) + 1n, root, index, path };
  }

  const input = {
    uid: uid.toString(), s_u: s_u.toString(), blind_u: blind_u.toString(), r_rp: r_rp.toString(), attrs: attrs.map(String),
    S: sig.S.toString(), R8x: F.toObject(sig.R8[0]).toString(), R8y: F.toObject(sig.R8[1]).toString(),
    s_lowValue: ws.lowValue.toString(), s_lowNextIndex: ws.lowNextIndex.toString(), s_lowNextValue: ws.lowNextValue.toString(),
    s_pathElements: ws.pathElements.map(String), s_pathIndices: ws.pathIndices.map(String),
    reg_pathElements: rp.pathElements.map(String), reg_pathIndices: rp.pathIndices.map(String),
    r: tag.r.toString(),
    PPID: PPID.toString(), arid: arid.toString(), pk_i: pk_i.toString(),
    max_height: max_height.toString(), chainid: chainid.toString(), allowAgent: allowAgent.toString(),
    revRoot: tree.getRoot().toString(), regRoot: registry.root().toString(),
    pk_CIA_x: ciaPub.x.toString(), pk_CIA_y: ciaPub.y.toString(),
    pk_trace_x: pk_trace.x.toString(), pk_trace_y: pk_trace.y.toString(),
    tag_c1_x: tag.c1.x.toString(), tag_c1_y: tag.c1.y.toString(), tag_c2: tag.c2.toString(),
    disc_mask: disc.mask.toString(), disc_lo: disc.lo.map(String), disc_hi: disc.hi.map(String),
    set_sel: st.sel.toString(), set_root: st.root.toString(), set_index: String(st.index), set_path: st.path.map(String),
    auid_s: auid_s.toString(), arid_s: arid_s.toString(), r_s: r_s.toString(),
  };

  return { input, Cf_u, Cf_s, pk_trace, shares, tag, ciaPub, arid, uid, tree, registry, slot: registrySlot, auid, auid_s, arid_s, r_rp, r_s, attrs, disclosure: disc, set: st };
}
```

- [ ] **Step 3: `tests/test_pi_cred_witness.mjs` 갱신**

(a) 머리 주석 "V9" → "V11"; import 에서 `ppid` 는 그대로 쓰고 `auidSOf` 를 추가(`import { ppid, auidSOf } from '../lib/mode3_credential.js';`).

(b) 'PPID 는 chainid 를 덮는다 …' 케이스의 `ppid({ uid, arid, s_u, chainid })` 호출 두 곳을 `ppid({ uid: BigInt(valid.uid), s_u: BigInt(valid.s_u), arid: BigInt(valid.arid), chainid: ... })` 로(인자 순서는 객체라 무관 — 함수 시그니처가 바뀐 것만 확인).

(c) 다음 두 케이스를 **삭제**: `'V5 음성: blind_s 를 바꾸면 거부된다 …'`, `'V9 음성: r_u 가 다르면 cm_u 가 달라 등록부 포함이 깨진다'`.

(d) `'음성: max_height 를 바꾸면 거부된다 (서명이 max_height 를 덮는다)'` 의 이름을 `'음성: max_height 를 바꾸면 거부된다 (V11: C_s 가 달라져 토큰 서명이 안 맞는다)'` 로.

(e) `'V9: JS registryLeaf 와 회로의 리프 계산이 일치한다 (main.inc.leaf)'` 안의 `registryLeaf(fx.cm_u, fx.Cf_u)` → `registryLeaf(fx.auid, fx.Cf_u)`; 이름 "V9" → "V11".

(f) 'V5 음성: r = 0 …' 케이스 **뒤**에 추가:

```js
await t('V11 음성: r_rp 를 바꾸면 거부 (auid_s·arid_s·C_s 가 모두 어긋난다 — ⑤ 같은 r_rp)', async () => {
  await assert.rejects(() => witness({ ...valid, r_rp: (BigInt(valid.r_rp) + 1n).toString() }), /Assert Failed/);
});
await t('V11 음성: 공개 입력 auid_s·arid_s·r_s 를 하나씩 바꾸면 거부', async () => {
  await assert.rejects(() => witness({ ...valid, auid_s: (BigInt(valid.auid_s) + 1n).toString() }), /Assert Failed/);
  await assert.rejects(() => witness({ ...valid, arid_s: (BigInt(valid.arid_s) + 1n).toString() }), /Assert Failed/);
  await assert.rejects(() => witness({ ...valid, r_s: (BigInt(valid.r_s) + 1n).toString() }), /Assert Failed/);
});
await t('V11 양성: 다른 r_s·r_rp 로 만든 세션(픽스처 재생성)은 통과 — 같은 r_rp 로 다른 arid 의 auid_s 는 다르다(D7)', async () => {
  const fx2 = await buildValidInput({ r_s: 1n, r_rp: 2n });
  await witness(fx2.input);
  assert.notEqual(await auidSOf({ auid: fx2.auid, arid: fx2.arid, r_rp: 2n }), await auidSOf({ auid: fx2.auid, arid: fx2.arid + 1n, r_rp: 2n }));
});
await t('V11 음성: PPID 를 옛 순서 Poseidon(uid, s_u, chainid, arid) 로 내면 거부(D13)', async () => {
  const { buildPoseidon } = await import('circomlibjs');
  const ps = await buildPoseidon();
  const old = ps.F.toObject(ps([BigInt(valid.uid), BigInt(valid.s_u), BigInt(valid.chainid), BigInt(valid.arid)])).toString();
  assert.notEqual(old, valid.PPID);
  await assert.rejects(() => witness({ ...valid, PPID: old }), /Assert Failed/);
});
await t('V11 음성: pk_i ≥ 2^160 은 CommitSessionV11 의 Num2Bits(160) 이 거부한다', async () => {
  await assert.rejects(() => witness({ ...valid, pk_i: (1n << 160n).toString() }), /Assert Failed/);
});
```

(g) 끝의 제약 수 출력에 `console.log('   (V10 2026-10-02: 34,934)');` 한 줄 추가.

- [ ] **Step 4: `tests/test_mode3_artifacts.mjs` 전면 교체**

```js
// 배포용 산출물(build/mode3)이 지금의 회로 소스에서 나온 것인가 — pi_cred(V11, 공개 33)·pi_idp(공개 8). (circuit 그룹)
//   node tests/test_mode3_artifacts.mjs
// 2026-09-25 리뷰 E-3: 회로를 고쳐도 `bash scripts/build_mode3_circuit.sh` 를 안 돌리면 zkey·vkey·wasm 은 옛 회로의 것으로 남는데,
// 테스트는 대부분 배포용 산출물로 증명을 만들어 검증하므로 전부 초록색이다. 여기서 둘을 잇는다.
// 컴파일 결과는 tests/test_pi_cred_witness.mjs·test_pi_idp_witness.mjs 가 build/mode3/witness_test/ 에 둔 것을 재사용하고, 없거나 소스보다 오래됐으면 여기서 컴파일한다.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT_DIR = fileURLToPath(new URL('..', import.meta.url));
const BUILD_DIR = path.join(ROOT_DIR, 'build', 'mode3');
const OUT_DIR = path.join(BUILD_DIR, 'witness_test');
const CIRCUITS_DIR = path.join(ROOT_DIR, 'circuits');
const REBUILD = '회로를 고치고 `bash scripts/build_mode3_circuit.sh` 를 안 돌렸다 — build/mode3 의 zkey·vkey·wasm 이 옛 회로의 것이다';

let failed = 0;
async function t(name, fn) { try { await fn(); console.log(`ok   ${name}`); } catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.message}`); } }

function newestCircuitMtime(dir = CIRCUITS_DIR) {
  let newest = 0;
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) newest = Math.max(newest, newestCircuitMtime(p));
    else if (e.name.endsWith('.circom')) newest = Math.max(newest, fs.statSync(p).mtimeMs);
  }
  return newest;
}
function compileFresh(name) {
  fs.mkdirSync(OUT_DIR, { recursive: true });
  execFileSync('circom', [path.join(CIRCUITS_DIR, `${name}.circom`), '--r1cs', '--wasm', '--sym', '-o', OUT_DIR, '-l', CIRCUITS_DIR, '-l', path.join(CIRCUITS_DIR, 'lib'), '-l', path.join(ROOT_DIR, 'node_modules', 'circomlib', 'circuits')], { cwd: ROOT_DIR, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
}
/** .r1cs 헤더(섹션 타입 1): n8·prime·nWires·nPubOut·nPubIn·nPrvIn·nLabels·nConstraints. snarkjs 의 nPublic = nPubOut + nPubIn. */
function r1csHeader(file) {
  const b = fs.readFileSync(file);
  assert.equal(b.toString('ascii', 0, 4), 'r1cs', `${file} 가 r1cs 가 아니다`);
  const nSections = b.readUInt32LE(8);
  let off = 12;
  for (let i = 0; i < nSections; i++) {
    const type = b.readUInt32LE(off), size = Number(b.readBigUInt64LE(off + 4)), data = off + 12;
    if (type === 1) {
      const n8 = b.readUInt32LE(data), p = data + 4 + n8;
      const nPubOut = b.readUInt32LE(p + 4), nPubIn = b.readUInt32LE(p + 8);
      return { nWires: b.readUInt32LE(p), nPubOut, nPubIn, nPrvIn: b.readUInt32LE(p + 12), nPublic: nPubOut + nPubIn, nConstraints: b.readUInt32LE(p + 24) };
    }
    off = data + size;
  }
  throw new Error(`${file} 에 r1cs 헤더 섹션이 없다`);
}
/** .sym 의 witness 인덱스 → 시그널 이름. 공개 입력은 1..nPublic(0 은 상수 1). main 의 직속 시그널만. */
function publicSignalNames(symFile, nPublic) {
  const byIndex = new Map();
  for (const line of fs.readFileSync(symFile, 'utf8').split('\n')) {
    const f = line.split(',');
    if (f.length < 4) continue;
    const idx = Number(f[1]);
    if (!Number.isInteger(idx) || idx < 1 || idx > nPublic || !/^main\.[^.]+$/.test(f[3])) continue;
    if (!byIndex.has(idx)) byIndex.set(idx, f[3].slice('main.'.length));
  }
  return Array.from({ length: nPublic }, (_, i) => byIndex.get(i + 1) ?? null);
}

// 회로가 정한 공개 입력 순서. contracts/Mode3Wallet.sol(pub[3]·pub[5]·pub[12..14]·pub[15..29]), lib/mode3_rp.js(구조분해·[30..32]),
// lib/mode3_onchain.js(PUB_INDEX), cia.js(개봉)가 이 자리를 번호로 읽는다.
const CIRCUITS = {
  pi_cred: {
    publicInputs: [
      'PPID', 'arid', 'pk_i', 'max_height', 'chainid', 'allowAgent', 'revRoot', 'regRoot',
      'pk_CIA_x', 'pk_CIA_y', 'pk_trace_x', 'pk_trace_y', 'tag_c1_x', 'tag_c1_y', 'tag_c2',
      'disc_mask', 'disc_lo[0]', 'disc_lo[1]', 'disc_lo[2]', 'disc_lo[3]', 'disc_lo[4]', 'disc_lo[5]',
      'disc_hi[0]', 'disc_hi[1]', 'disc_hi[2]', 'disc_hi[3]', 'disc_hi[4]', 'disc_hi[5]',
      'set_sel', 'set_root', 'auid_s', 'arid_s', 'r_s',
    ],
    indexNote: 'contracts/Mode3Wallet.sol·lib/mode3_rp.js·lib/mode3_onchain.js·cia.js',
  },
  // lib/mode3_idp_proof.js IDP_PUB_INDEX·cia.js 의 공개 입력 조립 순서
  pi_idp: { publicInputs: ['uid', 'auid', 'auid_s', 'C_u_x', 'C_u_y', 'C_s_x', 'C_s_y', 'max_height'], indexNote: 'lib/mode3_idp_proof.js·cia.js' },
};

for (const [name, spec] of Object.entries(CIRCUITS)) {
  const VKEY_FILE = path.join(BUILD_DIR, `${name}_vkey.json`);
  const DEPLOYED_R1CS = path.join(BUILD_DIR, `${name}.r1cs`);
  const FRESH_R1CS = path.join(OUT_DIR, `${name}.r1cs`);
  const FRESH_SYM = path.join(OUT_DIR, `${name}.sym`);
  assert.ok(fs.existsSync(VKEY_FILE), `배포용 vkey 가 없다: ${VKEY_FILE} — bash scripts/build_mode3_circuit.sh`);
  if (!fs.existsSync(FRESH_R1CS) || !fs.existsSync(FRESH_SYM) || fs.statSync(FRESH_R1CS).mtimeMs < newestCircuitMtime()) {
    console.log(`   (${name} 를 새로 컴파일한다 — witness_test/ 가 없거나 소스보다 오래됐다)`);
    compileFresh(name);
  }
  const fresh = r1csHeader(FRESH_R1CS);
  const vkey = JSON.parse(fs.readFileSync(VKEY_FILE, 'utf8'));

  await t(`E-3 ${name}: 회로 소스의 공개 입력 수(${spec.publicInputs.length})가 배포용 vkey 의 nPublic 과 같다`, () => {
    assert.equal(fresh.nPublic, spec.publicInputs.length, `회로 소스의 공개 입력이 ${fresh.nPublic}개 — 계획의 계약(${spec.publicInputs.length})과 다르다`);
    assert.equal(fresh.nPublic, vkey.nPublic, `회로는 공개 입력 ${fresh.nPublic}개인데 배포용 vkey 는 ${vkey.nPublic}개다 — ${REBUILD}`);
    assert.equal(vkey.IC.length, vkey.nPublic + 1, `vkey.IC 길이(${vkey.IC.length}) 가 nPublic + 1 이 아니다`);
  });
  await t(`E-3 ${name}: 배포용 .r1cs 도 같은 회로에서 나왔다(공개·비공개 입력 수)`, () => {
    assert.ok(fs.existsSync(DEPLOYED_R1CS), `배포용 r1cs 가 없다: ${DEPLOYED_R1CS} — ${REBUILD}`);
    const dep = r1csHeader(DEPLOYED_R1CS);
    assert.equal(dep.nPublic, fresh.nPublic, `배포용 r1cs 의 공개 입력 ${dep.nPublic}개 ≠ 소스 ${fresh.nPublic}개 — ${REBUILD}`);
    assert.equal(dep.nPrvIn, fresh.nPrvIn, `배포용 r1cs 의 비공개 입력 ${dep.nPrvIn}개 ≠ 소스 ${fresh.nPrvIn}개 — ${REBUILD}`);
  });
  await t(`E-3 ${name}: 공개 입력의 이름·순서가 ${spec.indexNote} 가 번호로 읽는 그 순서다`, () => {
    assert.deepEqual(publicSignalNames(FRESH_SYM, fresh.nPublic), spec.publicInputs, '공개 입력 순서가 바뀌었다 — 바꾸려면 그 파일들의 인덱스를 함께 고쳐야 한다');
  });
  await t(`E-3 ${name}: 배포용 증명자 산출물(zkey·wasm)이 제자리에 있다`, () => {
    for (const f of [path.join(BUILD_DIR, `${name}_final.zkey`), path.join(BUILD_DIR, `${name}_js`, `${name}.wasm`)]) assert.ok(fs.existsSync(f), `${f} 가 없다 — bash scripts/build_mode3_circuit.sh`);
  });
  console.log(`## ${name} 공개 입력 ${fresh.nPublic}개 / 비공개 입력 ${fresh.nPrvIn}개 / 비선형 제약 ${fresh.nConstraints.toLocaleString()}개(소스)`);
}
process.exit(failed === 0 ? 0 : 1);
```

- [ ] **Step 5: 실행**

Run: `node tests/test_pi_cred_witness.mjs`
Expected: 전부 `ok`(V11 케이스 포함), 제약 수 출력(스펙 §8 추정 35,000 ± 1,500 — 실측을 보고에 적는다).

Run: `node tests/test_mode3_artifacts.mjs`
Expected: **이 시점에는 실패가 정상이다** — 배포용 vkey(V10, nPublic 30)와 소스(33)가 다르고 `pi_idp_vkey.json` 이 없다. 메시지가 `REBUILD` 안내인지만 확인하고 보고에 "Task 4 의 재생성 뒤 초록" 이라고 적는다.

---

### Task 4: 빌드 스크립트·산출물 재생성(승인 지점)·컨트랙트 `uint[33]`

**Files:**
- Modify (전면 교체): `scripts/build_mode3_circuit.sh`
- Modify: `scripts/pack_mode3_build.sh` (FILES 배열)
- Modify: `contracts/Mode3Wallet.sol` (`uint[30]` → `uint[33]` 2곳 + 주석), `contracts/test/AcceptAllPiCredVerifier.sol`
- Regenerate: `contracts/PiCredVerifier.sol`, `build/mode3/pi_cred_*`, `build/mode3/pi_idp_*` (스크립트가 만든다)
- Modify: `lib/mode3_onchain.js` (`PUB_INDEX`, `WALLET_ABI`, 주석)
- Modify: `test/Mode3Wallet.test.mjs:335-340`

**Interfaces:**
- Produces: `PUB_INDEX = { …기존…, AUID_S: 30, ARID_S: 31, R_S: 32, COUNT: 33 }`; `WALLET_ABI` 의 `execute(..., uint256[33] pub)`; `Mode3Wallet.execute(Payload, bytes, uint[2], uint[2][2], uint[2], uint[33])`; `build/mode3/pi_idp_final.zkey`, `pi_idp_vkey.json`, `pi_idp_js/pi_idp.wasm`.
- Consumes: Task 3 의 픽스처(`buildValidInput`) — `test/Mode3Wallet.test.mjs` 가 실제 π 를 만든다.

- [ ] **Step 1: `scripts/build_mode3_circuit.sh` 전면 교체**

```bash
#!/usr/bin/env bash
# Mode 3 회로 둘(pi_cred·pi_idp) 컴파일 + Groth16 셋업. 산출물은 전부 build/mode3/ 아래.
#
#   bash scripts/build_mode3_circuit.sh [pot21_final.ptau]
#
# 회로를 바꾸면 반드시 이 스크립트로 zkey·vkey·wasm 을 **한 세트로** 다시 만든다 — 셋이 어긋나면 지갑의 로그인이 전부
# bad_proof 가 된다(tests/test_mode3_artifacts.mjs 가 소스와 산출물의 공개 입력 수·순서를 대조한다).
# V11(2026-10-12): pi_idp(세션마다 IdP 에 내는 π_IdP)가 추가됐다. 온체인에 가지 않으므로 solidity 검증기는 pi_cred 만 만든다.
#
# == 신뢰 설정에 관한 경고 ==
# contribute 는 고정 엔트로피 문자열을 쓴다(재현 가능한 데모 설정). 운영이라면 ceremony 가 필요하다.
set -euo pipefail
cd "$(dirname "$0")/.."

PTAU="${1:-pot21_final.ptau}"
if [ ! -f "$PTAU" ]; then
  echo "$PTAU 가 없습니다. pi_cred 는 2^14 를 넘어 pot21_final.ptau(2^21) 가 필요합니다." >&2
  exit 1
fi

OUT=build/mode3
mkdir -p "$OUT"

for NAME in pi_cred pi_idp; do
  rm -f "$OUT/${NAME}_0000.zkey" "$OUT/${NAME}_final.zkey" "$OUT/${NAME}_vkey.json"
  echo "=== compile $NAME ==="
  circom "circuits/${NAME}.circom" --r1cs --wasm --sym -o "$OUT" \
    -l circuits -l circuits/lib -l node_modules/circomlib/circuits
  echo "=== groth16 setup $NAME ==="
  npx snarkjs groth16 setup "$OUT/${NAME}.r1cs" "$PTAU" "$OUT/${NAME}_0000.zkey"
  npx snarkjs zkey contribute "$OUT/${NAME}_0000.zkey" "$OUT/${NAME}_final.zkey" --name=mode3 -v -e=mode3-bench
  npx snarkjs zkey export verificationkey "$OUT/${NAME}_final.zkey" "$OUT/${NAME}_vkey.json"
done

echo "=== solidity verifier (pi_cred) ==="
# snarkjs 0.7 템플릿의 컨트랙트 이름은 Groth16Verifier 다 — 저장소 관례(PiPkIVerifier)대로 회로 이름으로 바꾼다.
npx snarkjs zkey export solidityverifier "$OUT/pi_cred_final.zkey" contracts/PiCredVerifier.sol
sed -i -E 's/contract (Groth16Verifier|Verifier) /contract PiCredVerifier /' contracts/PiCredVerifier.sol
grep -q 'contract PiCredVerifier' contracts/PiCredVerifier.sol || { echo "PiCredVerifier 이름 치환 실패" >&2; exit 1; }
grep -q 'uint\[33\] calldata _pubSignals' contracts/PiCredVerifier.sol || { echo "PiCredVerifier 의 공개 입력이 33개가 아니다 — circuits/pi_cred.circom 을 확인" >&2; exit 1; }

echo "완료: $OUT/pi_cred_final.zkey, $OUT/pi_cred_vkey.json, $OUT/pi_cred_js/pi_cred.wasm, contracts/PiCredVerifier.sol"
echo "      $OUT/pi_idp_final.zkey, $OUT/pi_idp_vkey.json, $OUT/pi_idp_js/pi_idp.wasm"
echo "다음: npx hardhat compile (artifacts/ 의 PiCredVerifier 갱신) — 그 뒤 팩토리·AttrGate 재배포(docs/MODE3_DEMO.md '처음 한 번')"
```

- [ ] **Step 2: `scripts/pack_mode3_build.sh` — FILES 에 pi_idp 추가**

`FILES=(...)` 를 다음으로 교체하고 머리 주석의 "묶는 것" 목록에 `build/mode3/pi_idp_final.zkey 증명 키(지갑, π_IdP)`, `build/mode3/pi_idp_vkey.json 검증 키(CIA)`, `build/mode3/pi_idp_js/ pi_idp.wasm` 세 줄을 더한다:

```bash
FILES=(build/mode3/pi_cred_final.zkey build/mode3/pi_cred_vkey.json build/mode3/pi_cred_js/pi_cred.wasm build/mode3/pi_cred_js/generate_witness.js build/mode3/pi_cred_js/witness_calculator.js
       build/mode3/pi_idp_final.zkey build/mode3/pi_idp_vkey.json build/mode3/pi_idp_js/pi_idp.wasm build/mode3/pi_idp_js/generate_witness.js build/mode3/pi_idp_js/witness_calculator.js)
```

- [ ] **Step 3: 컨트랙트·온체인 라이브러리 편집**

`contracts/Mode3Wallet.sol`:
- 8행 주석 `pi_cred(공개 입력 30개)` → `pi_cred(공개 입력 33개 — V11 2026-10-12, [30..32] auid_s·arid_s·r_s 는 오프체인 검증기만 본다)`.
- 67~70행 `@param pub` 주석: `공개 입력 30개` → `공개 입력 33개`, 마지막 줄 끝에 ` [30] auid_s [31] arid_s [32] r_s (온체인에서는 보지 않는다 — RP 의 세션 바인딩 검사용, 설계 2026-10-12 §5.3)` 추가.
- 77행 `uint[30] calldata pub` → `uint[33] calldata pub`.
- 131행 `function _checkStatement(uint[30] calldata pub)` → `function _checkStatement(uint[33] calldata pub)`.
- `_checkStatement` 의 첫 주석 줄에 ` V11: 색인 30~32 는 검사하지 않는다(서비스가 r_s·arid_s 를 본다).` 를 덧붙인다.

`contracts/test/AcceptAllPiCredVerifier.sol`: `uint[30] calldata` → `uint[33] calldata`.

`lib/mode3_onchain.js`:
- `PUB_INDEX` 줄을 다음으로 교체:
```js
/** 공개 입력 색인(V11, circuits/pi_cred.circom) — 다른 파일은 숫자 대신 이것을 쓴다. 30~32 는 V11 에 붙은 세션 바인딩(온체인은 보지 않는다). */
export const PUB_INDEX = Object.freeze({ PPID: 0, ARID: 1, PK_I: 2, MAX_HEIGHT: 3, CHAINID: 4, ALLOW_AGENT: 5, REV_ROOT: 6, REG_ROOT: 7, PK_CIA_X: 8, PK_CIA_Y: 9, PK_TRACE_X: 10, PK_TRACE_Y: 11, TAG_C1_X: 12, TAG_C1_Y: 13, TAG_C2: 14, DISC_MASK: 15, DISC_LO: 16, DISC_HI: 22, SET_SEL: 28, SET_ROOT: 29, AUID_S: 30, ARID_S: 31, R_S: 32, COUNT: 33 });
```
- `WALLET_ABI` 의 `uint256[30] pub` → `uint256[33] pub`.
- 104행·116행 주석의 "30개" → "33개".

`test/Mode3Wallet.test.mjs:335-340`: 케이스 이름 `'V9: pub 은 30개이고 …'` → `'V11: pub 은 33개이고 …'`, `assert.equal(ST.pub.length, 30)` → `33`.

- [ ] **Step 4: ⚠ 산출물 재생성 — 사용자 승인 필요**

이 단계는 `build/mode3/` 의 zkey·vkey·wasm 과 `contracts/PiCredVerifier.sol` 을 덮어쓴다(CLAUDE.md: zk 산출물 재생성은 명시적 승인). **컨트롤러가 실행 전에 사용자에게 "V11 회로로 build/mode3 를 재생성할까요?" 를 묻고, 승인 뒤에만** 작업자가 실행한다:

Run: `bash scripts/build_mode3_circuit.sh pot21_final.ptau` (수 분. `pot21_final.ptau` 는 저장소 루트에 있다 — 없으면 멈추고 보고)
Expected: 마지막에 `완료: …` 두 줄과 "다음: npx hardhat compile" 안내. `contracts/PiCredVerifier.sol` 에 `uint[33] calldata _pubSignals` 가 있다.

Run: `npx hardhat compile`
Expected: `Compiled N Solidity files successfully`.

- [ ] **Step 5: 실행**

Run: `node tests/test_mode3_artifacts.mjs`
Expected: pi_cred(33)·pi_idp(8) 모두 `ok`.

Run: `bash scripts/run_tests.sh contract`
Expected: `npx hardhat test` 전부 통과(`Mode3Wallet` 의 gas 출력에 V11 값이 찍힌다 — 보고에 적는다. 스펙 §8 추정 ≈ 470,000).

Run: `bash scripts/run_tests.sh circuit`
Expected: 전부 PASS.

---

### Task 5: 지갑 라이브러리 V11 — `mode3_idp_proof.js`(신규)·`mode3_wallet.js`·`mode3_secret_source.js`

**Files:**
- Create: `lib/mode3_idp_proof.js`
- Modify: `lib/mode3_wallet.js` (import·`createRegistration`·`signRegistration`·`signSlotRequest`·`signIssueRequest`·`buildIssueRequest`·`buildCredentialProof`; `signUserCredRequest`·`signAttrsRequest`·`buildUserCredRequest` 삭제)
- Modify (전면 교체): `lib/mode3_secret_source.js`
- Create: `tests/test_mode3_wallet_lib.js` (unit)
- Modify (전면 교체): `tests/test_mode3_secret_source.js` (unit)
- Modify: `tests/test_mode3_wallet.mjs` (chain)
- Modify: `scripts/run_tests.sh` UNIT 에 `tests/test_mode3_wallet_lib.js` 추가(`tests/test_mode3_secret_source.js` 뒤)

**Interfaces:**
- Produces (`lib/mode3_idp_proof.js`): `IDP_WASM_PATH`, `IDP_ZKEY_PATH`, `IDP_VKEY_PATH`, `IDP_PUB_INDEX = { UID:0, AUID:1, AUID_S:2, C_U_X:3, C_U_Y:4, C_S_X:5, C_S_Y:6, MAX_HEIGHT:7, COUNT:8 }`, `idpPublicSignals({ uid, auid, auid_s, C_u_pt, C_s_pt, max_height }) → string[8]`, `proveIdp({ uid, s_u, blind_u, attrs, arid, r_rp, pk_i, r_s, auid, auid_s, C_u_pt, C_s_pt, max_height, wasmPath?, zkeyPath? }) → { proof, publicSignals }`, `verifyIdp(vkey, publicSignals, proof) → boolean`, `loadIdpVkey(path?) → Promise<vkey>`.
- Produces (`lib/mode3_wallet.js`): `createRegistration(uid: bigint) → { s_u, auid, sk_u, pk_u }`; `signRegistration(sk_uHex, uid, auid)`; `signSlotRequest(sk_uHex, uid, nonce)`; `signIssueRequest(sk_uHex, auid_s, arid_s, Cf_u, Cf_s, chainid, allowAgent, max_height)`; `buildIssueRequest({ uid, s_u, blind_u, attrs, arid, r_rp, r_s, sk_u, session, chainid, allowAgent = 0n, max_height, idpWasmPath?, idpZkeyPath? }) → { body, C_u_pt, Cf_u, C_s_pt, Cf_s, auid, auid_s, arid_s, idpPublicSignals }`; `buildCredentialProof({ uid, arid, s_u, auid, blind_u, r_rp, r_s, pk_i, attrs, credential, pk_CIA, pk_trace, tree, registry, slot, disclosure?, tagR?, wasmPath?, zkeyPath? }) → { proof, publicSignals, revRoot, regRoot, tag }` (credential = `{ Cf_u, Cf_s, max_height, chainid, allowAgent, sigma }`). 그 밖(`chooseMaxHeight`, `normalizeDisclosure`, `normalizeSet`, `syncRevocationTree`, `ProofCache`, `signChallenge`, `signSessionRequest`, `signRevokeSession`, `eddsaPubOf`, `createSessionKey`, `WASM_PATH`·`ZKEY_PATH`·`VKEY_PATH`, `syncRegistryTree`/`createRegistrySync` 재export)은 불변.
- Produces (`lib/mode3_secret_source.js`): `stripSecrets(reg) → { uid, auid, pk_u, slot, attrs, profile, userCred:{Cf_u, issuedAt}|null }`; `validateWitness(w, publicUid, publicAuid = null)` — 증인 `{ uid, s_u, sk_u, attrs[6], userCred|null }`, `publicAuid` 를 주면 `auidOf(uid, s_u) === publicAuid` 까지 본다; `createSecretSource({ mode, state, witness })` 의 `registration()` 은 `{ uid, s_u, sk_u, attrs, auid, slot, pk_u, profile }`.

- [ ] **Step 1: `lib/mode3_idp_proof.js` 생성**

```js
// π_IdP(스펙 2026-10-12 §4, D10) — 지갑이 세션마다 IdP 에 내는 Groth16. 회로 circuits/pi_idp.circom 과 공개 입력 순서를 공유한다.
// 지갑은 proveIdp 로 만들고, IdP(cia.js)는 **자기가 조립한** 공개 입력(uid 는 요청·계정, auid 는 DB, 나머지는 요청의 점·값)으로 verifyIdp 한다 —
// 지갑이 보낸 publicSignals 를 그대로 검증에 넣으면 아무 auid 에 대한 증명이 통과하므로 그 경로는 두지 않는다.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as snarkjs from 'snarkjs';
import { normalizeAttrs, SCALAR_MAX, MAX_HEIGHT_MAX, PK_I_MAX } from './mode3_credential.js';

const ROOT_DIR = fileURLToPath(new URL('..', import.meta.url));
export const IDP_WASM_PATH = path.join(ROOT_DIR, 'build', 'mode3', 'pi_idp_js', 'pi_idp.wasm');
export const IDP_ZKEY_PATH = path.join(ROOT_DIR, 'build', 'mode3', 'pi_idp_final.zkey');
export const IDP_VKEY_PATH = path.join(ROOT_DIR, 'build', 'mode3', 'pi_idp_vkey.json');

/** circuits/pi_idp.circom 의 component main 공개 입력 순서. tests/test_mode3_artifacts.mjs 가 .sym 과 대조한다. */
export const IDP_PUB_INDEX = Object.freeze({ UID: 0, AUID: 1, AUID_S: 2, C_U_X: 3, C_U_Y: 4, C_S_X: 5, C_S_Y: 6, MAX_HEIGHT: 7, COUNT: 8 });

const isScalar = (v) => typeof v === 'bigint' && v >= 0n && v < SCALAR_MAX;
const isField = (v) => typeof v === 'bigint' && v >= 0n;
const isPt = (p) => isField(p?.x) && isField(p?.y);

/** 공개 입력 8개를 10진 문자열로. IdP 는 여기 넣는 값을 스스로 정한다. */
export function idpPublicSignals({ uid, auid, auid_s, C_u_pt, C_s_pt, max_height }) {
  if (!isScalar(uid)) throw new Error('idpPublicSignals: uid 는 [0, 2^250) bigint');
  if (!isField(auid) || !isField(auid_s)) throw new Error('idpPublicSignals: auid·auid_s(bigint) 가 필요하다');
  if (!isPt(C_u_pt) || !isPt(C_s_pt)) throw new Error('idpPublicSignals: C_u_pt·C_s_pt{x,y}(bigint) 가 필요하다');
  if (typeof max_height !== 'bigint' || max_height < 0n || max_height >= MAX_HEIGHT_MAX) throw new Error('idpPublicSignals: max_height 는 [0, 2^64) bigint');
  return [uid, auid, auid_s, C_u_pt.x, C_u_pt.y, C_s_pt.x, C_s_pt.y, max_height].map(String);
}

/** 증명. 비공개 s_u·blind_u·attrs·arid·r_rp·pk_i·r_s 와 공개 8개. 공개값은 호출자가 같은 비밀로 미리 계산한 것이어야 한다(아니면 witness 실패). */
export async function proveIdp({ uid, s_u, blind_u, attrs, arid, r_rp, pk_i, r_s, auid, auid_s, C_u_pt, C_s_pt, max_height, wasmPath = IDP_WASM_PATH, zkeyPath = IDP_ZKEY_PATH }) {
  for (const [k, v] of [['s_u', s_u], ['blind_u', blind_u], ['arid', arid], ['r_rp', r_rp], ['r_s', r_s]]) if (!isScalar(v)) throw new Error(`proveIdp: ${k} 는 [0, 2^250) bigint`);
  if (typeof pk_i !== 'bigint' || pk_i < 0n || pk_i >= PK_I_MAX) throw new Error('proveIdp: pk_i 는 [0, 2^160) bigint');
  const pub = idpPublicSignals({ uid, auid, auid_s, C_u_pt, C_s_pt, max_height });
  const input = {
    s_u: s_u.toString(), blind_u: blind_u.toString(), attrs: normalizeAttrs(attrs).map(String), arid: arid.toString(), r_rp: r_rp.toString(), pk_i: pk_i.toString(), r_s: r_s.toString(),
    uid: pub[0], auid: pub[1], auid_s: pub[2], C_u_x: pub[3], C_u_y: pub[4], C_s_x: pub[5], C_s_y: pub[6], max_height: pub[7],
  };
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, wasmPath, zkeyPath);
  return { proof, publicSignals };
}

/** 검증. publicSignals 는 정규 10진 문자열 8개(lib/mode3_rp.js 의 C-1 과 같은 이유 — 앞자리 0·공백은 받지 않는다). 예외는 false. */
export async function verifyIdp(vkey, publicSignals, proof) {
  if (!Array.isArray(publicSignals) || publicSignals.length !== IDP_PUB_INDEX.COUNT || !publicSignals.every((v) => typeof v === 'string' && /^(0|[1-9][0-9]*)$/.test(v))) return false;
  if (!proof || typeof proof !== 'object') return false;
  try { return await snarkjs.groth16.verify(vkey, publicSignals, proof); } catch { return false; }
}

let vkeyCache = new Map();
/** vkey 파일을 읽어 캐시한다(경로별). 없으면 throw — 호출자(cia.js)가 503 으로 옮긴다. */
export async function loadIdpVkey(p = IDP_VKEY_PATH) {
  if (!vkeyCache.has(p)) vkeyCache.set(p, JSON.parse(await fs.promises.readFile(p, 'utf8')));
  return vkeyCache.get(p);
}
```

- [ ] **Step 2: `lib/mode3_wallet.js` 편집**

(a) import 블록을 다음으로 교체(파일 머리 주석의 "V9(2026-10-01 §3·§5)…" 문단 끝에 `// V11(2026-10-12): auid 등록, 세션마다 π_IdP(lib/mode3_idp_proof.js), C_s = (pk_i, max_height, r_s; r_rp), 토큰 7인자, 공개 입력 33 — 스펙 2026-10-12.` 한 줄 추가):

```js
import { randomScalar, ppid, normalizeAttrs, userCommit, sessionCommit, auidOf, auidSOf, aridSOf, MAX_HEIGHT_MAX, ATTR_MAX, ATTR_SLOTS } from './mode3_credential.js';
import { encryptTag } from './mode3_trace.js';
import { sessionLeaf, createRevocationTree, MODE3_TREE_DEPTH } from './mode3_revocation.js';
import { setPath, NO_SET } from './mode3_set_tree.js';
import { buildIMTv2 } from './imt_v2.js';
import { registryLeaf } from './mode3_registry.js';
import { issueRequestMessageV11, pointToStrings, slotRequestMessage, revokeSessionMessage, registerMessage } from './mode3_issuance.js';
import { proveIdp } from './mode3_idp_proof.js';
import { MODE3_LOG_ABI } from './mode3_log.js';
export { createRegistrySync, syncRegistryTree } from './mode3_registry_sync.js';
```

(b) `createRegistration` 을 교체:

```js
/** V11 §3.1 — s_u 는 randomScalar(2^250 미만), auid = Poseidon(T_AUID, uid, s_u) 를 CIA 에 낸다(cm_u·r_u 는 없어졌다). 등록 키 (sk_u, pk_u) 도 여기서 만든다 — CIA 는 pk_u 만 받는다. */
export async function createRegistration(uid) {
  if (typeof uid !== 'bigint') throw new Error('createRegistration(uid: bigint) — auid = Poseidon(T_AUID, uid, s_u) 를 계산하려면 uid 가 필요하다');
  const s_u = randomScalar();
  const sk_u = randomBytes(32).toString('hex');
  return { s_u, auid: await auidOf({ uid, s_u }), sk_u, pk_u: await eddsaPubOf(sk_u) };
}
```

(c) `signUserCredRequest`·`signAttrsRequest` 함수(주석 포함) 삭제, 그 자리에:

```js
/** /cia/slot 요청 서명 = Sign(sk_u, Poseidon(D_SLOTREQ, uid, nonce)) — 옛 상태 파일이 슬롯 번호를 되찾을 때(V9 §5). */
export async function signSlotRequest(sk_uHex, uid, nonce) {
  const eddsa = await getEddsa();
  return sigStrings(eddsa.F, eddsa.signPoseidon(Buffer.from(sk_uHex, 'hex'), eddsa.F.e(await slotRequestMessage(uid, nonce))));
}
```

(d) `signRegistration` 교체:

```js
/** /cia/register 소유 증명 = Sign(sk_u, Poseidon(D_REGISTER_V2, uid, auid)). */
export async function signRegistration(sk_uHex, uid, auid) {
  const eddsa = await getEddsa();
  return sigStrings(eddsa.F, eddsa.signPoseidon(Buffer.from(sk_uHex, 'hex'), eddsa.F.e(await registerMessage(uid, auid))));
}
```

(e) `buildUserCredRequest`·`signIssueRequest`·`buildIssueRequest`(주석 포함)를 다음으로 교체:

```js
/** /cia/issue V11 요청 서명 = Sign(sk_u, Poseidon(D_ISSUEREQ_V11, auid_s, arid_s, Cf_u, Cf_s, chainid, allowAgent, max_height)). */
export async function signIssueRequest(sk_uHex, auid_s, arid_s, Cf_u, Cf_s, chainid, allowAgent, max_height) {
  const eddsa = await getEddsa();
  return sigStrings(eddsa.F, eddsa.signPoseidon(Buffer.from(sk_uHex, 'hex'), eddsa.F.e(await issueRequestMessageV11(auid_s, arid_s, Cf_u, Cf_s, chainid, allowAgent, max_height))));
}

/**
 * 세션 발급 요청 V11(스펙 2026-10-12 §5.2, 그림 3 "DA request"). 한 요청에 (C_u, C_s, π_IdP, sig_u). 옛 /cia/user_cred 요청은 없어졌다 —
 * C_u 가 활성 자격증명과 다르면 CIA 가 등록부 슬롯을 갱신·게시한다(첫 로그인·속성 변경). blind_u 는 호출자가 정한다: 들고 있는
 * 사용자 자격증명을 재사용하면 그 blind_u, 새 C_u 가 필요하면 randomScalar(). auid 는 (uid, s_u) 에서 여기서 계산한다 — 시연
 * 덮어쓰기(가짜 s_u·uid)면 가짜 auid 로 증명돼 CIA 의 DB auid 와 어긋나 bad_idp_proof 가 된다(의도된 실패 경로).
 * r_rp·r_s 는 RP 챌린지의 값이다. max_height 는 지갑이 정한다(chooseMaxHeight).
 */
export async function buildIssueRequest({ uid, s_u, blind_u, attrs, arid, r_rp, r_s, sk_u, session, chainid, allowAgent = 0n, max_height, idpWasmPath, idpZkeyPath }) {
  for (const [k, v] of [['uid', uid], ['s_u', s_u], ['blind_u', blind_u], ['arid', arid], ['r_rp', r_rp], ['r_s', r_s], ['chainid', chainid]]) {
    if (typeof v !== 'bigint') throw new Error(`buildIssueRequest: ${k}(bigint) 가 필요하다`);
  }
  if (typeof allowAgent !== 'bigint' || (allowAgent !== 0n && allowAgent !== 1n)) throw new Error('buildIssueRequest: allowAgent 는 0n 또는 1n');
  if (typeof max_height !== 'bigint' || max_height < 0n || max_height >= MAX_HEIGHT_MAX) throw new Error('buildIssueRequest: max_height(bigint, < 2^64) 가 필요하다 — 지갑이 chooseMaxHeight 로 정한다');
  if (typeof session?.pk_i !== 'bigint') throw new Error('buildIssueRequest: session{pk_i} 가 필요하다(createSessionKey)');
  const a6 = normalizeAttrs(attrs);
  const cu = await userCommit({ uid, s_u, blind_u, attrs: a6 });
  const C_u_pt = { x: cu.Cx, y: cu.Cy };
  const cs = await sessionCommit({ pk_i: session.pk_i, max_height, r_s, r_rp });
  const C_s_pt = { x: cs.Cx, y: cs.Cy };
  const auid = await auidOf({ uid, s_u });
  const auid_s = await auidSOf({ auid, arid, r_rp });
  const arid_s = await aridSOf({ arid, r_rp });
  const idp = await proveIdp({ uid, s_u, blind_u, attrs: a6, arid, r_rp, pk_i: session.pk_i, r_s, auid, auid_s, C_u_pt, C_s_pt, max_height, ...(idpWasmPath ? { wasmPath: idpWasmPath } : {}), ...(idpZkeyPath ? { zkeyPath: idpZkeyPath } : {}) });
  const body = {
    uid: uid.toString(), auid_s: auid_s.toString(), arid_s: arid_s.toString(),
    C_u_pt: pointToStrings(C_u_pt), C_s_pt: pointToStrings(C_s_pt),
    chainid: chainid.toString(), allowAgent: allowAgent.toString(), max_height: max_height.toString(),
    proof_idp: idp.proof,
    sig_u: await signIssueRequest(sk_u, auid_s, arid_s, cu.Cf, cs.Cf, chainid, allowAgent, max_height),
  };
  return { body, C_u_pt, Cf_u: cu.Cf, C_s_pt, Cf_s: cs.Cf, auid, auid_s, arid_s, idpPublicSignals: idp.publicSignals };
}
```

(f) `buildCredentialProof`(주석 포함)를 교체:

```js
/**
 * §5 — 공개 입력 33개의 순서는 circuits/pi_cred.circom 의 component main 선언(스펙 2026-10-12 Global Constraints) 그대로다 —
 * 드리프트를 피하려고 여기서 다시 나열하지 않는다. pk_trace 는 인증서 cert_s 에 실린 서비스의 조합 키다 — 호출자는 검증된 인증서의
 * 값만 넘겨야 한다. 태그의 r 은 여기서 새로 뽑는다(재검증으로 새 π 를 만들면 태그도 바뀐다). disclosure 를 안 주면(null) mask 0.
 * V11: auid_s·arid_s 는 비밀 r_rp 에서 다시 계산해 공개 입력 [30]·[31] 로 내고, r_s 는 [32] 로 낸다 — 발급 때와 같은 r_rp·r_s 가 아니면
 * 토큰 서명이 맞지 않아 회로가 거절한다. auid 는 **등록 때 CIA 에 낸 값**(파일의 공개 부분)으로 받아 등록부 대조에 쓴다 — 회로는 (uid, s_u) 로
 * 다시 계산하므로, 시연 덮어쓰기(가짜 s_u)는 로컬 대조를 통과하고 회로에서 죽어 호출자가 demo_proof_failed 로 보여 준다.
 * registry 는 동기화된 등록부 트리(lib/mode3_registry_sync.js), slot 은 내 등록 슬롯. 리프 = Poseidon(auid, Cf_u).
 */
export async function buildCredentialProof({ uid, arid, s_u, auid, blind_u, r_rp, r_s, pk_i, attrs, credential, pk_CIA, pk_trace, tree, registry, slot, disclosure = null, tagR = undefined, wasmPath = WASM_PATH, zkeyPath = ZKEY_PATH }) {
  for (const [k, v] of [['uid', uid], ['arid', arid], ['s_u', s_u], ['auid', auid], ['blind_u', blind_u], ['r_rp', r_rp], ['r_s', r_s], ['pk_i', pk_i]]) {
    if (typeof v !== 'bigint') throw new Error(`buildCredentialProof: ${k}(bigint) 가 필요하다`);
  }
  if (typeof pk_trace?.x !== 'bigint' || typeof pk_trace?.y !== 'bigint') throw new Error('buildCredentialProof: pk_trace{x,y}(bigint) 가 필요하다 — cert_s 에 실린 서비스 조합 키');
  if (!registry || !Number.isInteger(slot)) throw new Error('buildCredentialProof: registry·slot 이 필요하다');
  const chainid = BigInt(credential.chainid);
  const PPID = await ppid({ uid, s_u, arid, chainid });
  const a6 = normalizeAttrs(attrs);
  const auid_s = await auidSOf({ auid, arid, r_rp });
  const arid_s = await aridSOf({ arid, r_rp });
  // 등록부 대조(V9 조건 9 → V11 리프) — 온체인에 내지 않고 여기서 먼저 "내 슬롯 = 내 자격증명" 을 확인한다(fail-closed).
  // 슬롯이 비어 있으면(0) 은퇴·아직 미게시, 다른 값이면 관리자 바꿔치기 등 — 호출자가 구분해 처리할 수 있도록 reason 을 싣는다.
  const expectedLeaf = await registryLeaf(auid, BigInt(credential.Cf_u));
  const onSlot = registry.leafAt(slot);
  if (onSlot !== expectedLeaf) throw Object.assign(new Error(onSlot === 0n ? 'registry_empty' : 'registry_mismatch'), { reason: onSlot === 0n ? 'registry_empty' : 'registry_mismatch', slot, expected: expectedLeaf.toString(), actual: onSlot.toString() });
  const regPath = registry.path(slot);
  const regRoot = registry.root();
  // 세션 리프 비멤버십 증인 — 세션이 폐기됐으면 여기서 "is a member" 로 던진다.
  const ws = await tree.getNonMembershipWitness(await sessionLeaf(BigInt(credential.Cf_s)));
  // 공개 입력 revRoot 는 이 증인이 계산된 root 로 고정한다(트리 객체를 여러 요청이 공유할 수 있다 — 스펙 2026-09-23 §5).
  const revRoot = BigInt(ws.root);
  // tagR 은 테스트 전용 — 태그 난수를 주입해 같은 c1 을 가진 트랜스크립트를 만든다(CIA 개봉 dup 키 회귀). 운영 경로는 넘기지 않는다.
  const tag = tagR === undefined ? await encryptTag(pk_trace, uid, arid) : await encryptTag(pk_trace, uid, arid, tagR);
  const disc = disclosure ?? { mask: 0n, lo: ZERO6, hi: ZERO6 };
  const st = { sel: disc.sel ?? NO_SET.sel, root: disc.root ?? NO_SET.root, index: disc.index ?? 0, path: disc.path ?? NO_SET.path };
  const input = {
    uid: uid.toString(), s_u: s_u.toString(), blind_u: blind_u.toString(), r_rp: r_rp.toString(),
    attrs: a6.map(String),
    S: credential.sigma.S, R8x: credential.sigma.R8x, R8y: credential.sigma.R8y,
    s_lowValue: String(ws.lowValue), s_lowNextIndex: String(ws.lowNextIndex), s_lowNextValue: String(ws.lowNextValue),
    s_pathElements: ws.pathElements.map(String), s_pathIndices: ws.pathIndices.map(String),
    reg_pathElements: regPath.pathElements.map(String), reg_pathIndices: regPath.pathIndices.map(String),
    r: tag.r.toString(),
    PPID: PPID.toString(), arid: arid.toString(), pk_i: pk_i.toString(),
    max_height: BigInt(credential.max_height).toString(), chainid: chainid.toString(),
    allowAgent: BigInt(credential.allowAgent).toString(), revRoot: revRoot.toString(), regRoot: regRoot.toString(),
    pk_CIA_x: pk_CIA.x.toString(), pk_CIA_y: pk_CIA.y.toString(),
    pk_trace_x: pk_trace.x.toString(), pk_trace_y: pk_trace.y.toString(),
    tag_c1_x: tag.c1.x.toString(), tag_c1_y: tag.c1.y.toString(), tag_c2: tag.c2.toString(),
    disc_mask: disc.mask.toString(), disc_lo: disc.lo.map(String), disc_hi: disc.hi.map(String),
    set_sel: st.sel.toString(), set_root: st.root.toString(), set_index: String(st.index), set_path: [...st.path].map(String),
    auid_s: auid_s.toString(), arid_s: arid_s.toString(), r_s: r_s.toString(),
  };
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, wasmPath, zkeyPath);
  return { proof, publicSignals, revRoot, regRoot, tag: { c1: tag.c1, c2: tag.c2, h: tag.h } };
}
```
(`compressPoint` 는 더 쓰지 않으면 import 에서 뺀다 — 위 (a) 가 이미 뺐다.)

- [ ] **Step 3: `lib/mode3_secret_source.js` 전면 교체**

```js
// 지갑 에이전트의 비밀 공급원 — 스펙 2026-09-22 metamask-snap §3.3, V11(2026-10-12) 갱신.
//   file: 상태 파일의 registration 이 비밀을 든다(자동 테스트·헤드리스 데모).
//   snap: 비밀은 요청에 첨부된 witness(Snap 이 동의 창 뒤에 내준 것)에서만 오고, 파일에는 공개 부분만 남는다. 에이전트는 Snap 을
//         부를 수 없으므로 새 C_u·attrs 는 pending 에 모아 응답에 실어 페이지가 Snap 에 저장하게 한다.
// V11: 등록 비밀은 { s_u, sk_u } 둘(r_u·cm_u 삭제). 증인과 등록의 바인딩은 auid = Poseidon(T_AUID, uid, s_u) 로 본다.
import { SCALAR_MAX, normalizeAttrs, auidOf } from './mode3_credential.js';

const isDec = (v) => typeof v === 'string' && /^[0-9]+$/.test(v);
const isHex64 = (v) => typeof v === 'string' && /^[0-9a-fA-F]{64}$/.test(v);
const isPt = (p) => p && isDec(p.x) && isDec(p.y);

export function stripSecrets(registration) {
  if (!registration) return null;
  const { uid, auid, pk_u, slot, attrs, profile = null, userCred } = registration;
  return { uid, auid, pk_u, slot, attrs, profile, userCred: userCred ? { Cf_u: userCred.Cf_u, issuedAt: userCred.issuedAt } : null };
}

/**
 * 증인 형식 검사. `publicAuid`(파일의 공개 `registration.auid`)를 주면 **증인이 그 등록에 실제로 묶였는지**까지 본다 —
 * Poseidon(T_AUID, uid, s_u) 가 등록 때 CIA 에 낸 auid 와 같아야 한다(2026-09-22 최종 리뷰 Minor 1 의 cm_u 바인딩을 V11 식으로).
 * 이 검사가 없으면 형식만 맞는 아무 s_u 나 받아 이 지갑의 등록과 무관한 증명 시도로 이어진다.
 */
export async function validateWitness(w, publicUid, publicAuid = null) {
  const fail = (msg) => { throw Object.assign(new Error(`bad_witness: ${msg}`), { reason: 'bad_witness' }); };
  if (!w || typeof w !== 'object') fail('witness 없음');
  if (!isDec(w.uid) || w.uid !== publicUid) fail('uid 가 등록과 다르다');
  if (!isDec(w.s_u) || BigInt(w.s_u) >= SCALAR_MAX) fail('s_u 범위');
  if (!isHex64(w.sk_u)) fail('sk_u 형식');
  try { normalizeAttrs(w.attrs); } catch (e) { fail(`attrs: ${e.message}`); }
  if (!Array.isArray(w.attrs) || w.attrs.length !== 6) fail('attrs 길이');
  if (w.userCred !== null && w.userCred !== undefined) {
    const u = w.userCred;
    if (!isPt(u.C_u_pt) || !isDec(u.Cf_u) || !isDec(u.blind_u) || BigInt(u.blind_u) >= SCALAR_MAX) fail('userCred 형식');
  }
  if (publicAuid !== null) {
    if (!isDec(publicAuid)) fail('등록의 auid 형식');
    const a = await auidOf({ uid: BigInt(w.uid), s_u: BigInt(w.s_u) });
    if (a.toString() !== publicAuid) fail('auid 가 등록과 다르다(s_u 불일치)');
  }
}

export function createSecretSource({ mode, state, witness = null }) {
  const pub = () => state.registration;
  if (mode === 'file') {
    return {
      mode, pending: {},
      registration: () => (pub() ? { uid: pub().uid, s_u: pub().s_u, sk_u: pub().sk_u, attrs: pub().attrs, auid: pub().auid, slot: pub().slot, pk_u: pub().pk_u, profile: pub().profile ?? null } : null),
      userCred: () => pub()?.userCred ?? null,
      setUserCred: (uc) => { state.registration.userCred = uc; },
      setAttrs: (attrs) => { state.registration.attrs = attrs; },
    };
  }
  if (mode !== 'snap') throw new Error(`unknown secret source mode: ${mode}`);
  const pending = {};
  return {
    mode, pending,
    registration: () => ((pub() && witness) ? { uid: pub().uid, s_u: witness.s_u, sk_u: witness.sk_u, attrs: witness.attrs, auid: pub().auid, slot: pub().slot, pk_u: pub().pk_u, profile: pub().profile ?? null } : null),
    userCred: () => witness?.userCred ?? null,
    setUserCred: (uc) => { pending.userCredIssued = uc; if (witness) witness.userCred = uc; state.registration.userCred = uc ? { Cf_u: uc.Cf_u, issuedAt: uc.issuedAt } : null; },
    setAttrs: (attrs) => { pending.attrsChanged = attrs; if (witness) witness.attrs = attrs; state.registration.attrs = attrs; },
  };
}
```

- [ ] **Step 4: 단위 테스트 — `tests/test_mode3_wallet_lib.js`(신규)·`tests/test_mode3_secret_source.js`(교체)**

`tests/test_mode3_wallet_lib.js`:

```js
// 지갑 라이브러리의 체인·zkey 없는 부분(V11) — 등록값·서명 메시지·ProofCache. (unit)  node tests/test_mode3_wallet_lib.js
import assert from 'node:assert/strict';
import { buildEddsa } from 'circomlibjs';
import { createRegistration, signRegistration, signSlotRequest, eddsaPubOf, ProofCache, chooseMaxHeight } from '../lib/mode3_wallet.js';
import { registerMessage, slotRequestMessage } from '../lib/mode3_issuance.js';
import { auidOf, SCALAR_MAX } from '../lib/mode3_credential.js';
import { IDP_PUB_INDEX, idpPublicSignals } from '../lib/mode3_idp_proof.js';

let fails = 0;
async function t(name, fn) { try { await fn(); console.log('ok   -', name); } catch (e) { fails++; console.log('FAIL -', name, '\n      ', e.message); } }
const eddsa = await buildEddsa(); const F = eddsa.F;
const verify = (m, sig, pub) => eddsa.verifyPoseidon(F.e(m), { R8: [F.e(BigInt(sig.R8x)), F.e(BigInt(sig.R8y))], S: BigInt(sig.S) }, [F.e(pub.x), F.e(pub.y)]);

await t('createRegistration(uid) = { s_u, auid = Poseidon(T_AUID, uid, s_u), sk_u(hex64), pk_u }; uid 없이는 throw', async () => {
  const reg = await createRegistration(12345n);
  assert.ok(reg.s_u < SCALAR_MAX); assert.match(reg.sk_u, /^[0-9a-f]{64}$/); assert.equal(typeof reg.pk_u.x, 'bigint');
  assert.equal(reg.auid, await auidOf({ uid: 12345n, s_u: reg.s_u }));
  assert.deepEqual(await eddsaPubOf(reg.sk_u), reg.pk_u);
  await assert.rejects(() => createRegistration(), /uid/);
  assert.notEqual((await createRegistration(12345n)).auid, reg.auid, 's_u 가 매번 다르다');
});
await t('signRegistration 은 registerMessage(uid, auid) 위 서명 — 다른 키·다른 auid 는 검증 실패', async () => {
  const reg = await createRegistration(12345n);
  const sig = await signRegistration(reg.sk_u, 12345n, reg.auid);
  assert.equal(verify(await registerMessage(12345n, reg.auid), sig, reg.pk_u), true);
  assert.equal(verify(await registerMessage(12345n, reg.auid + 1n), sig, reg.pk_u), false);
  assert.equal(verify(await registerMessage(12345n, reg.auid), sig, (await createRegistration(12345n)).pk_u), false);
});
await t('signSlotRequest 는 slotRequestMessage(uid, nonce) 위 서명', async () => {
  const reg = await createRegistration(12345n);
  const sig = await signSlotRequest(reg.sk_u, 12345n, 7n);
  assert.equal(verify(await slotRequestMessage(12345n, 7n), sig, reg.pk_u), true);
  assert.equal(verify(await slotRequestMessage(12345n, 8n), sig, reg.pk_u), false);
});
await t('idpPublicSignals: 8개 10진 문자열, 순서 = IDP_PUB_INDEX; 범위 밖은 throw', () => {
  const pub = idpPublicSignals({ uid: 1n, auid: 2n, auid_s: 3n, C_u_pt: { x: 4n, y: 5n }, C_s_pt: { x: 6n, y: 7n }, max_height: 8n });
  assert.deepEqual(pub, ['1', '2', '3', '4', '5', '6', '7', '8']); assert.equal(IDP_PUB_INDEX.COUNT, 8); assert.equal(pub[IDP_PUB_INDEX.MAX_HEIGHT], '8');
  assert.throws(() => idpPublicSignals({ uid: SCALAR_MAX, auid: 2n, auid_s: 3n, C_u_pt: { x: 4n, y: 5n }, C_s_pt: { x: 6n, y: 7n }, max_height: 8n }), /uid/);
  assert.throws(() => idpPublicSignals({ uid: 1n, auid: 2n, auid_s: 3n, C_u_pt: { x: 4n, y: 5n }, C_s_pt: { x: 6n, y: 7n }, max_height: 1n << 64n }), /max_height/);
});
await t('V10 ProofCache.rootKey(chainId, rev, reg) = "chainId:rev:reg", 2인자는 throw, deleteSession 은 세션만', () => {
  assert.equal(ProofCache.rootKey(31337n, 1n, 2n), '31337:1:2');
  assert.throws(() => ProofCache.rootKey(1n, 2n));
  assert.notEqual(ProofCache.rootKey(1n, 5n, 6n), ProofCache.rootKey(2n, 5n, 6n));
  const c = new ProofCache();
  c.set(ProofCache.rootKey(31337n, 1n, 2n), '77', 'a', '1:0,0:0,0:0:0'); c.set(ProofCache.rootKey(31337n, 1n, 2n), '88', 'b');
  c.deleteSession('77');
  assert.equal(c.get(ProofCache.rootKey(31337n, 1n, 2n), '77', '1:0,0:0,0:0:0'), null); assert.equal(c.get(ProofCache.rootKey(31337n, 1n, 2n), '88'), 'b');
});
await t('chooseMaxHeight 그리드', () => { assert.equal(chooseMaxHeight(1234n), 1600n); assert.equal(chooseMaxHeight(10n, { ttlBlocks: 5n, grid: 1n }), 15n); });
process.exit(fails ? 1 : 0);
```

`tests/test_mode3_secret_source.js` 전면 교체:

```js
// 비밀 공급원(file·snap)·증인 검사 — V11 auid 바인딩. (unit)  node tests/test_mode3_secret_source.js
import assert from 'node:assert/strict';
import { createSecretSource, stripSecrets, validateWitness } from '../lib/mode3_secret_source.js';
import { auidOf } from '../lib/mode3_credential.js';

let failed = 0;
async function t(name, fn) { try { await fn(); console.log(`ok   ${name}`); } catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.message}`); } }
const AUID = (await auidOf({ uid: 12345n, s_u: 11n })).toString();
const REG = { uid: '12345', s_u: '11', sk_u: 'ab'.repeat(32), attrs: ['1990', '410', '2', '0', '0', '0'], auid: AUID, pk_u: { x: '9', y: '10' }, slot: 0, profile: { birthYear: '1990', country: 'KR' },
  userCred: { C_u_pt: { x: '1', y: '2' }, Cf_u: '3', blind_u: '4', issuedAt: 't' } };

await t('file 모드: registration 은 파일의 비밀·auid·profile 을 그대로, setUserCred/setAttrs 는 파일을 바꾸고 pending 은 비어 있다', () => {
  const state = { registration: structuredClone(REG) };
  const src = createSecretSource({ mode: 'file', state });
  assert.equal(src.registration().s_u, '11'); assert.equal(src.registration().auid, AUID); assert.deepEqual(src.registration().profile, REG.profile);
  src.setAttrs(['1', '0', '0', '0', '0', '0']); src.setUserCred(null);
  assert.deepEqual(state.registration.attrs, ['1', '0', '0', '0', '0', '0']); assert.equal(state.registration.userCred, null); assert.deepEqual(src.pending, {});
});
await t('snap 모드: 비밀은 증인에서, auid·slot 은 파일에서; setUserCred 는 pending.userCredIssued + 파일에는 공개 부분만', () => {
  const state = { registration: stripSecrets(REG) };
  const witness = { uid: '12345', s_u: '11', sk_u: 'ab'.repeat(32), attrs: REG.attrs, userCred: REG.userCred };
  const src = createSecretSource({ mode: 'snap', state, witness });
  assert.equal(src.registration().s_u, '11'); assert.equal(src.registration().auid, AUID, 'auid 는 파일의 공개값');
  const uc = { C_u_pt: { x: '5', y: '6' }, Cf_u: '7', blind_u: '8', issuedAt: 'u' };
  src.setUserCred(uc);
  assert.deepEqual(src.pending.userCredIssued, uc); assert.deepEqual(state.registration.userCred, { Cf_u: '7', issuedAt: 'u' });
  src.setAttrs(['2', '0', '0', '0', '0', '0']);
  assert.deepEqual(src.pending.attrsChanged, ['2', '0', '0', '0', '0', '0']); assert.deepEqual(witness.attrs, ['2', '0', '0', '0', '0', '0']);
});
await t('stripSecrets 는 s_u·sk_u·blind_u 를 지우고 auid·profile 을 남긴다', () => {
  const s = stripSecrets(REG);
  assert.deepEqual(Object.keys(s).sort(), ['attrs', 'auid', 'pk_u', 'profile', 'slot', 'uid', 'userCred']);
  assert.deepEqual(s.userCred, { Cf_u: '3', issuedAt: 't' }); assert.equal(s.auid, AUID);
  assert.equal(stripSecrets({ ...REG, profile: undefined }).profile, null, 'profile 이 없으면 null');
  assert.equal(stripSecrets(null), null);
});
await t('validateWitness: uid 불일치·형식·범위 오류는 bad_witness; r_u 는 더 요구하지 않는다', async () => {
  const w = { uid: '12345', s_u: '11', sk_u: 'ab'.repeat(32), attrs: ['1', '2', '3', '4', '5', '6'], userCred: null };
  await validateWitness(w, '12345');
  for (const bad of [{ ...w, uid: '1' }, { ...w, s_u: 'x' }, { ...w, s_u: (1n << 250n).toString() }, { ...w, sk_u: 'zz' }, { ...w, attrs: ['1'] }, { ...w, attrs: [(1n << 64n).toString(), '0', '0', '0', '0', '0'] }, { ...w, userCred: { Cf_u: '1' } }, null]) {
    await assert.rejects(() => validateWitness(bad, '12345'), (e) => e.reason === 'bad_witness', JSON.stringify(bad));
  }
});
await t('validateWitness: auid 를 주면 s_u 가 등록과 묶였는지 본다', async () => {
  const w = { uid: '12345', s_u: '11', sk_u: 'ab'.repeat(32), attrs: ['1', '2', '3', '4', '5', '6'], userCred: null };
  await validateWitness(w, '12345', AUID);                              // 맞는 증인은 통과
  await validateWitness({ ...w, s_u: '12' }, '12345');                  // auid 를 안 주면 형식만 본다
  await assert.rejects(() => validateWitness({ ...w, s_u: '12' }, '12345', AUID), (e) => e.reason === 'bad_witness' && /auid/.test(e.message));
  await assert.rejects(() => validateWitness(w, '12345', 'zz'), (e) => e.reason === 'bad_witness', '등록 auid 형식 오류');
});
process.exit(failed === 0 ? 0 : 1);
```

- [ ] **Step 5: `tests/test_mode3_wallet.mjs`(chain) V11 이행**

(a) import 를 바꾼다: `credMessageV5` → `credMessageV11, auidSOf, aridSOf`; `buildUserCredRequest, signAttrsRequest` 삭제; `attrsRequestMessage, verifyUserCred, parseUserCredProof` import 삭제; `import { IDP_VKEY_PATH, loadIdpVkey, verifyIdp, idpPublicSignals } from '../lib/mode3_idp_proof.js';` 추가. `const { registryLeaf }` 는 그대로.

(b) `localIssue` 를 교체 — 요청(`req = buildIssueRequest(...)` 결과)을 받아 CIA 처럼 서명한다:

```js
// 서버 없이 CIA 역할을 로컬에서 흉내낸다 (서명만). V11: Sign(D_V11, auid_s, arid_s, Cf_u, Cf_s, chainid, allowAgent). max_height 는 C_s 안.
async function localIssue(req, chainid, { allowAgent = 0n } = {}) {
  const s = eddsa.signPoseidon(ciaPrv, F.e(await credMessageV11(req.auid_s, req.arid_s, req.Cf_u, req.Cf_s, chainid, allowAgent)));
  return { Cf_u: req.Cf_u.toString(), Cf_s: req.Cf_s.toString(), max_height: req.body.max_height, chainid: chainid.toString(), allowAgent: allowAgent.toString(), sigma: { R8x: F.toObject(s.R8[0]).toString(), R8y: F.toObject(s.R8[1]).toString(), S: s.S.toString() } };
}
```

(c) 전역 `let reg, session, uc, req, cred, tree0;` → `let reg, session, req, cred, tree0; const ATTRS = [19n, 410n, 0n, 0n, 0n, 0n]; let blind_u, r_rp, r_s;` 로 바꾸고 `proveWith` 를 교체(발급 때 뽑은 blind_u·r_rp·r_s 를 전역에 남겨 뒤 케이스가 다시 쓴다):

```js
async function proveWith(disclosure) {
  reg = await createRegistration(uid);
  session = createSessionKey();
  blind_u = randomScalar(); r_rp = randomScalar(); r_s = randomScalar();
  req = await buildIssueRequest({ uid, s_u: reg.s_u, blind_u, attrs: ATTRS, arid, r_rp, r_s, sk_u: reg.sk_u, session, chainid: 31337n, max_height: await mh() });
  cred = await localIssue(req, 31337n);
  ({ tree: tree0 } = await syncRevocationTree(provider, logAddress));
  registry.set(SLOT, await registryLeaf(reg.auid, req.Cf_u));
  await publishV3(log, ciaEth, { revRoot: tree0.getRoot(), regRoot: registry.root(), epoch: (await log.epoch()) + 1n, slotIdx: [SLOT], slotLeaves: [registry.leafAt(SLOT)] });
  return buildCredentialProof({ uid, arid, s_u: reg.s_u, auid: reg.auid, blind_u, r_rp, r_s, pk_i: session.pk_i, attrs: ATTRS, credential: cred, pk_CIA, pk_trace, tree: tree0, registry, slot: SLOT, disclosure });
}
```

(d) 첫 케이스 `'사용자 자격증명 요청(π_u) → …'` 를 다음으로 교체:

```js
await t('V11: 발급 요청(C_u·C_s·π_IdP·sig_u) → 로컬 CIA 서명 → 증명 생성 → vkey 로 검증; 공개 입력 33, [30..32] = auid_s·arid_s·r_s', async () => {
  const { proof, publicSignals, revRoot, tag } = await proveWith(null);
  assert.deepEqual(Object.keys(req.body).sort(), ['C_s_pt', 'C_u_pt', 'allowAgent', 'arid_s', 'auid_s', 'chainid', 'max_height', 'proof_idp', 'sig_u', 'uid']);
  const vkIdp = await loadIdpVkey(IDP_VKEY_PATH);
  const pubIdp = idpPublicSignals({ uid, auid: reg.auid, auid_s: req.auid_s, C_u_pt: req.C_u_pt, C_s_pt: req.C_s_pt, max_height: BigInt(req.body.max_height) });
  assert.deepEqual(pubIdp, req.idpPublicSignals, 'CIA 가 스스로 조립한 공개 입력이 지갑의 것과 같다');
  assert.equal(await verifyIdp(vkIdp, pubIdp, req.body.proof_idp), true, 'CIA 가 하는 π_IdP 검증');
  assert.equal(await verifyIdp(vkIdp, idpPublicSignals({ uid, auid: reg.auid + 1n, auid_s: req.auid_s, C_u_pt: req.C_u_pt, C_s_pt: req.C_s_pt, max_height: BigInt(req.body.max_height) }), req.body.proof_idp), false, '다른 auid 로는 통과하지 않는다');
  assert.equal(req.auid_s, await auidSOf({ auid: reg.auid, arid, r_rp })); assert.equal(req.arid_s, await aridSOf({ arid, r_rp }));
  assert.equal(cred.Cf_s, req.Cf_s.toString());
  assert.equal(revRoot, tree0.getRoot());
  assert.equal(publicSignals.length, 33, 'V11: V9 30 + auid_s·arid_s·r_s');
  assert.equal(BigInt(publicSignals[2]), session.pk_i);
  assert.equal(BigInt(publicSignals[3]), BigInt(cred.max_height));
  assert.equal(BigInt(publicSignals[4]), 31337n);
  assert.equal(BigInt(publicSignals[5]), 0n, 'allowAgent');
  assert.equal(BigInt(publicSignals[6]), tree0.getRoot());
  assert.equal(BigInt(publicSignals[7]), registry.root(), 'regRoot');
  assert.equal(BigInt(publicSignals[10]), pk_trace.x); assert.equal(BigInt(publicSignals[11]), pk_trace.y);
  assert.equal(BigInt(publicSignals[12]), tag.c1.x); assert.equal(BigInt(publicSignals[14]), tag.c2);
  assert.equal(BigInt(publicSignals[30]), req.auid_s); assert.equal(BigInt(publicSignals[31]), req.arid_s); assert.equal(BigInt(publicSignals[32]), r_s);
  assert.equal(tag.h, await tagPlaintext(uid, arid), '태그 평문은 Poseidon(uid, arid)');
  assert.equal(await combineDecrypt(tag.c2, await partialDecrypt(svcShare.x, tag.c1), await partialDecrypt(aaShare.x, tag.c1)), await tagPlaintext(uid, arid));
  const vkey = JSON.parse(fs.readFileSync(VKEY_PATH, 'utf8'));
  assert.ok(await snarkjs.groth16.verify(vkey, publicSignals, proof));
});
```

(e) 나머지 케이스는 기계적으로 바꾼다 — 바꾸는 규칙:
  - `buildCredentialProof({ uid, arid, s_u: reg.s_u, r_u: reg.r_u, blind_u: uc.secrets.blind_u, blind_s: req.secrets.blind_s, pk_i: session.pk_i, attrs: [...], credential: cred, pk_CIA, pk_trace, tree: X, registry: Y, slot: SLOT, cm_u: reg.cm_u, ... })` → `buildCredentialProof({ uid, arid, s_u: reg.s_u, auid: reg.auid, blind_u, r_rp, r_s, pk_i: session.pk_i, attrs: ATTRS, credential: cred, pk_CIA, pk_trace, tree: X, registry: Y, slot: SLOT, ... })`.
  - `'V9 buildCredentialProof: set …— 30개'` 의 `30` → `33`, 색인 `[28]`·`[29]` 단언은 그대로.
  - `'buildIssueRequest 는 allowAgent 를 싣고 …'` 케이스를 다음으로 교체:
```js
await t('V11 buildIssueRequest: 본문 10필드, allowAgent 기본 0, Cf_u·Cf_s·auid 를 돌려준다; 범위·누락은 throw', async () => {
  const session = createSessionKey();
  const h = await mh();
  const base = { uid, s_u: reg.s_u, blind_u: randomScalar(), attrs: ATTRS, arid, r_rp: randomScalar(), r_s: randomScalar(), sk_u: reg.sk_u, session, chainid: 31337n, max_height: h };
  const a = await buildIssueRequest(base);
  assert.equal(a.body.allowAgent, '0'); assert.equal(a.body.chainid, '31337'); assert.equal(a.body.max_height, h.toString());
  assert.equal(a.body.C_u_pt.x, a.C_u_pt.x.toString()); assert.equal(a.body.C_s_pt.x, a.C_s_pt.x.toString());
  assert.equal(a.Cf_u, await compressPoint(a.C_u_pt)); assert.equal(a.Cf_s, await compressPoint(a.C_s_pt));
  assert.equal(a.auid, reg.auid); assert.ok(a.body.proof_idp?.pi_a, 'π_IdP 가 실린다');
  assert.equal((await buildIssueRequest({ ...base, allowAgent: 1n })).body.allowAgent, '1');
  await assert.rejects(() => buildIssueRequest({ ...base, allowAgent: 2n }), /allowAgent/);
  await assert.rejects(() => buildIssueRequest({ ...base, max_height: undefined }), /max_height/);
  await assert.rejects(() => buildIssueRequest({ ...base, r_rp: undefined }), /r_rp/);
  assert.equal(chooseMaxHeight(1234n), 1600n); assert.equal(chooseMaxHeight(1299n), 1600n); assert.equal(chooseMaxHeight(1300n), 1600n); assert.equal(chooseMaxHeight(1301n), 1700n);
});
```
  (`compressPoint` 는 `lib/mode3_credential.js` 에 남아 있다 — import 에 추가.)
  - `'signAttrsRequest 는 attrsRequestMessage 위 EdDSA 서명이다'` 케이스 삭제(Task 5 unit 이 signSlotRequest 를 본다).
  - `'증인을 만든 뒤 트리가 바뀌어도 …'`·`'V9: 비멤버십 증인은 세션 리프 하나만 …'` 두 케이스의 준비 코드: `reg2 = await createRegistration(uid)`, `buildUserCredRequest(...)` 줄 삭제, `const b2 = randomScalar(), rp2 = randomScalar(), rs2 = randomScalar(); const req2 = await buildIssueRequest({ uid, s_u: reg2.s_u, blind_u: b2, attrs: ATTRS, arid, r_rp: rp2, r_s: rs2, sk_u: reg2.sk_u, session: session2, chainid: 31337n, max_height: await mh() }); const cred2 = await localIssue(req2, 31337n); registry2.set(SLOT, await registryLeaf(reg2.auid, req2.Cf_u));` 그리고 `buildCredentialProof({ uid, arid, s_u: reg2.s_u, auid: reg2.auid, blind_u: b2, r_rp: rp2, r_s: rs2, pk_i: session2.pk_i, attrs: ATTRS, credential: cred2, pk_CIA, pk_trace, tree, registry: registry2, slot: SLOT })` (reg3 도 같은 모양).
  - 'V10 syncRegistryTree …' 케이스는 불변.

- [ ] **Step 6: 실행**

Run: `node tests/test_mode3_wallet_lib.js && node tests/test_mode3_secret_source.js`
Expected: 전부 `ok`.

:8545 노드가 떠 있는지 확인(`curl -s -X POST 127.0.0.1:8545 -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}'`). 없으면 `npx hardhat node` 를 백그라운드로 띄운다(끝나면 내린다).
Run: `node tests/test_mode3_wallet.mjs`
Expected: 전부 `ok`(Task 4 의 산출물이 있어야 한다).

`scripts/run_tests.sh` UNIT 에 `tests/test_mode3_wallet_lib.js` 를 `tests/test_mode3_secret_source.js` 바로 뒤에 추가.

---

### Task 6: RP 검증기·서버 — `r_rp` 챌린지, `pub[30..32]` 검사

**Files:**
- Modify: `lib/mode3_rp.js` (`verifyLogin`)
- Modify: `mode3_rp.js` (`challenges`·`issueChallenge`·`consumeChallenge`·`verifyBody`·`/api/mode3/login`·`/api/mode3/revalidate`·`/api/mode3/sessions`·LOGIN_LOG)
- Modify: `tests/test_mode3_rp.mjs` (chain)

**Interfaces:**
- Consumes: Task 1 `aridSOf`, Task 5 `createRegistration(uid)`·`buildIssueRequest`·`buildCredentialProof`.
- Produces: `verifyLogin({ proof, publicSignals, sig, r_s, r_rp })` — `publicSignals.length === 33`, `r_s`·`r_rp` bigint 필수; 새 거절 사유 `bad_r_s`(pub[32] ≠ r_s), `bad_arid_s`(pub[31] ≠ Poseidon(T_ARIDS, arid, r_rp)); 성공 반환에 `auid_s`, `arid_s`(bigint) 추가. 서버: `POST /api/mode3/challenge → { ok, r_s, r_rp, expiresAt, factoryAddress, attrGateAddress }`; 세션 `{ PPID, pk_i, max_height, allowAgent, root, regRoot, disclosure, auid_s, arid_s, r_rp, at }`; `/api/mode3/sessions` 항목에 `auid_s`·`arid_s`(앞 8자리 축약).

- [ ] **Step 1: 실패하는 테스트 — `tests/test_mode3_rp.mjs` V11 이행**

(a) import: `credMessageV5` → `credMessageV11, aridSOf`; `buildUserCredRequest` 삭제.

(b) `issueWith`·`makeLogin` 교체:

```js
// 서버 없이 CIA 서명만 흉내낸다. V11: Sign(D_V11, auid_s, arid_s, Cf_u, Cf_s, chainid, allowAgent). 요청 객체(buildIssueRequest 결과)를 받는다.
async function issueWith(key, req, { chainid = 31337n, allowAgent = 0n } = {}) {
  const s = eddsa.signPoseidon(key.prv, F.e(await credMessageV11(req.auid_s, req.arid_s, req.Cf_u, req.Cf_s, chainid, allowAgent)));
  return { Cf_u: req.Cf_u.toString(), Cf_s: req.Cf_s.toString(), max_height: req.body.max_height, chainid: chainid.toString(), allowAgent: allowAgent.toString(), sigma: { R8x: F.toObject(s.R8[0]).toString(), R8y: F.toObject(s.R8[1]).toString(), S: s.S.toString() } };
}
/**
 * V9 조건 9: 증명을 만들기 전에 내 등록부 슬롯(SLOT=0)을 내 자격증명으로 채우고 게시해야 한다 … (기존 설명 유지)
 * V11: r_s·r_rp 는 RP 챌린지다 — 둘을 함께 돌려주고 verifyLogin 에 같이 넣는다. 토큰이 발급된 뒤에 슬롯을 게시하므로(C_u 는 발급 요청에 실려 간다)
 * max_height 는 게시 전 head 로 잰다 — 슬롯 게시 1블록을 ttl 에 더해 둔다(ttl 300 → head+301 이 상한 400 안이다).
 */
async function makeLogin({ key = CIA, useArid = arid, ttlBlocks = 300n, chainid = 31337n, useTrace = pk_trace, allowAgent = 0n, disclosure = null } = {}) {
  const reg = await createRegistration(uid);
  const attrs = [19n, 410n, 0n, 0n, 0n, 0n];
  const session = createSessionKey();
  const r_s = randomScalar(), r_rp = randomScalar(), blind_u = randomScalar();
  const max_height = BigInt(await provider.getBlockNumber()) + 1n + ttlBlocks;   // 아래 슬롯 게시가 블록 하나를 전진시킨다
  const req = await buildIssueRequest({ uid, s_u: reg.s_u, blind_u, attrs, arid: useArid, r_rp, r_s, sk_u: reg.sk_u, session, chainid, allowAgent, max_height });
  const cred = await issueWith(key, req, { chainid, allowAgent });
  const { tree } = await syncRevocationTree(provider, logAddress);
  registry.set(SLOT, await registryLeaf(reg.auid, req.Cf_u));
  await publishV3(log, ciaEth, { revRoot: tree.getRoot(), regRoot: registry.root(), epoch: (await log.epoch()) + 1n, slotIdx: [SLOT], slotLeaves: [registry.leafAt(SLOT)] });
  const { proof, publicSignals } = await buildCredentialProof({ uid, arid: useArid, s_u: reg.s_u, auid: reg.auid, blind_u, r_rp, r_s, pk_i: session.pk_i, attrs, credential: cred, pk_CIA: key.pub, pk_trace: useTrace, tree, registry, slot: SLOT, disclosure });
  return { proof, publicSignals, r_s, r_rp, sig: await signChallenge(session.wallet, r_s.toString()), session, cred, reg };
}
```

(c) `rp.verifyLogin({ proof: L.proof, publicSignals: L.publicSignals, sig: L.sig, r_s: L.r_s })` 모양의 호출(8곳)에 `r_rp: L.r_rp` 를 추가한다(`rp.verifyLogin(L)` 꼴은 L 에 r_rp 가 있어 그대로). `'음성 f: 서버가 다른 r_s 를 넘기면 bad_signature'` 는 V11 에서 **`bad_r_s`** 가 먼저 걸린다 — 이름을 `'음성 f→V11: 서버가 다른 r_s 를 넘기면 bad_r_s (pub[32] 검사가 σ 보다 앞)'` 로 바꾸고 기대 사유를 `bad_r_s` 로. `'V9: publicSignals 가 14개면 malformed, 30개면 …'` 의 `30` → `33`.

(d) 다음 케이스를 `'양성: verifyLogin 이 max_height·allowAgent·root 를 돌려준다'` 뒤에 추가:

```js
await t('V11: verifyLogin 은 auid_s·arid_s 를 돌려주고 arid_s = Poseidon(T_ARIDS, arid, r_rp) 다; r_rp 가 다르면 bad_arid_s; r_rp 없으면 malformed', async () => {
  const L = await makeLogin();
  const r = await rp.verifyLogin(L);
  assert.equal(r.ok, true, r.reason);
  assert.equal(r.arid_s, await aridSOf({ arid, r_rp: L.r_rp })); assert.equal(r.auid_s, BigInt(L.publicSignals[30]));
  assert.deepEqual(await rp.verifyLogin({ ...L, r_rp: L.r_rp + 1n }), { ok: false, reason: 'bad_arid_s' });
  assert.deepEqual(await rp.verifyLogin({ proof: L.proof, publicSignals: L.publicSignals, sig: L.sig, r_s: L.r_s }), { ok: false, reason: 'malformed' });
  const ps = [...L.publicSignals]; ps[32] = (BigInt(ps[32]) + 1n).toString();
  assert.deepEqual(await rp.verifyLogin({ ...L, publicSignals: ps }), { ok: false, reason: 'bad_r_s' }, '공개 입력의 r_s 를 손대면(증명은 어차피 깨진다) 정책 검사가 먼저 잡는다');
});
await t('V11 D7: 같은 r_rp 를 두 서비스가 쓰면 auid_s 가 서비스마다 다르다(RP 간 연결 불가), arid_s 도 다르다', async () => {
  const r_rp = randomScalar();
  const a = await makeLogin(); const b = await makeLogin({ useArid: otherArid });
  // 같은 사용자(uid·s_u 고정은 makeLogin 이 매번 새 등록을 만들므로 여기서는 라이브러리 수준으로 본다)
  const { auidOf, auidSOf } = await import('../lib/mode3_credential.js');
  const auid = await auidOf({ uid, s_u: a.reg.s_u });
  assert.notEqual(await auidSOf({ auid, arid, r_rp }), await auidSOf({ auid, arid: otherArid, r_rp }));
  assert.notEqual(await aridSOf({ arid, r_rp }), await aridSOf({ arid: otherArid, r_rp }));
  assert.equal((await rp.verifyLogin(b)).reason, 'wrong_arid', '다른 서비스의 π 는 arid 에서 걸린다(변함 없음)');
});
```

(e) `'같은 사용자·같은 RP 라도 chainid 가 다르면 PPID 가 다르다'` 케이스 안의 `ppid` 호출이 있으면 `ppid({ uid, s_u, arid, chainid })` 로(객체 인자라 이름만 맞으면 된다).

(f) 거울 케이스(422·464행 부근)에서 `buildCredentialProof(...)` 를 직접 부르는 곳은 (b) 의 `makeLogin` 과 같은 인자 모양으로 바꾼다(`r_u`·`blind_s`·`cm_u` → `auid`·`r_rp`·`r_s`).

- [ ] **Step 2: 실행해 실패 확인**

Run: `node tests/test_mode3_rp.mjs`
Expected: `malformed`(길이 33 거부) 로 대부분 FAIL.

- [ ] **Step 3: `lib/mode3_rp.js` 수정**

(a) 머리 주석 `//   r_s 는 공개 입력에 없다(2026-09-18 §2)…` 줄을 다음으로 교체:
```js
//   r_s·auid_s·arid_s 는 공개 입력 [32]·[30]·[31] 이다(V11 2026-10-12 §5.3). 서버가 자기가 준 챌린지 (r_s, r_rp) 를 넘기고 검증기는
//   d′. pub[32] === r_s (재전송 방지 — 토큰의 C_s 가 r_s 를 덮는다), pub[31] === Poseidon(T_ARIDS, arid, r_rp) (이 세션용 토큰인가) 를 본다.
//   σ 는 그대로 r_s 위에서 확인한다(f).
```
(b) import 에 `import { aridSOf } from './mode3_credential.js';` 추가.
(c) `verifyLogin` 시그니처·형식 검사·구조분해·검사·반환을 바꾼다:

```js
  async function verifyLogin({ proof, publicSignals, sig, r_s, r_rp }) {
    if (!Array.isArray(publicSignals) || publicSignals.length !== 33 || !proof || typeof sig !== 'string' || typeof r_s !== 'bigint' || typeof r_rp !== 'bigint') {
      return { ok: false, reason: 'malformed' };
    }
```
구조분해 줄 뒤에 `const auid_s = rest[14], arid_s = rest[15], rsIn = rest[16];` 를 추가(기존 `lo·hi·setSel·setRoot` 줄은 그대로). `wrong_trace_key` 검사 바로 뒤에:

```js
    // d′(V11): 세션 바인딩. r_s 는 서버가 1회 소비한 챌린지 — 토큰의 C_s 가 덮으므로 같은 토큰을 다른 세션에 재전송할 수 없다.
    if (rsIn !== r_s) return { ok: false, reason: 'bad_r_s' };
    // arid_s 는 서버만 아는 r_rp 로 재계산한다 — 다른 서비스(또는 다른 챌린지)용 토큰은 여기서 걸린다. IdP 는 r_rp 를 몰라 이 값을 못 만든다(G4).
    if (arid_s !== await aridSOf({ arid: BigInt(arid), r_rp })) return { ok: false, reason: 'bad_arid_s' };
```
반환 객체에 `auid_s, arid_s` 를 추가: `return { ok: true, PPID, pk_i, max_height, allowAgent, root: revRoot, regRoot, tag: { c1x, c1y, c2 }, disclosure, auid_s, arid_s, publicSignals: ps.map(String) };`.

- [ ] **Step 4: `mode3_rp.js` 수정**

```js
// ---- r_s·r_rp: 메모리, TTL, 로그인 때 1회 소비. 소비된 r_s 는 세션 식별자가 된다(설계 §7). r_rp 는 세션 가명·C_s 블라인딩의 재료(V11 §3.2) — IdP 에 보내지 않는다 ----
const challenges = new Map();   // r_s(10진) → { expiresAt(ms), r_rp(10진) }
const sessions = new Map();     // r_s(10진) → { PPID, pk_i, max_height, allowAgent, root, regRoot, disclosure, auid_s, arid_s, r_rp, at }
function sweepChallenges() { const now = Date.now(); for (const [c, e] of challenges) if (e.expiresAt < now) challenges.delete(c); }
function issueChallenge() {
  sweepChallenges();
  const r_s = randomScalar().toString(), r_rp = randomScalar().toString();
  const expiresAt = Date.now() + CHALLENGE_TTL_MS;
  challenges.set(r_s, { expiresAt, r_rp });
  return { r_s, r_rp, expiresAt };
}
/** 소비. 모르거나 만료면 null, 아니면 그 챌린지의 r_rp(10진). */
function consumeChallenge(r_s) {
  const e = challenges.get(r_s);
  if (e === undefined) return null;
  challenges.delete(r_s);
  return Date.now() <= e.expiresAt ? e.r_rp : null;
}
```
`verifyBody(req, res, r_s, r_rp)` 로 바꾸고 `verifier.verifyLogin({ proof, publicSignals, sig, r_s, r_rp })`. `/api/mode3/login`: `if (!consumeChallenge(rsStr)) …` → `const r_rp = consumeChallenge(rsStr); if (r_rp === null) return res.status(401).json({ ok: false, reason: 'bad_challenge' }); const v = await verifyBody(req, res, BigInt(rsStr), BigInt(r_rp)); if (v === null) return;`; `sessions.set(rsStr, { …기존…, auid_s: v.auid_s.toString(), arid_s: v.arid_s.toString(), r_rp, at })`; LOGIN_LOG JSON 에 `auid_s: v.auid_s.toString(), arid_s: v.arid_s.toString()` 추가. `/api/mode3/revalidate`: `verifyBody(req, res, BigInt(rsStr), BigInt(s.r_rp))`. `/api/mode3/sessions` 매핑에 `auid_s: rsShort(s.auid_s), arid_s: rsShort(s.arid_s)` 추가. 5행 머리 주석 `세션은 메모리 Map(r_s → PPID·pk_i·max_height·allowAgent·root)` 에 `·auid_s·arid_s·r_rp` 를 덧붙인다.

- [ ] **Step 5: 실행**

Run: `node tests/test_mode3_rp.mjs`
Expected: 전부 `ok`.

Run: `node -e "import('./mode3_rp.js').catch(e=>{console.error(e.message);process.exit(1)})"` 는 서버를 띄우므로 하지 않는다 — 대신 `node --check mode3_rp.js` 로 구문만 본다. Expected: 출력 없음.

---

### Task 7: `cia.js` V11 — 등록(auid)·발급(π_IdP, user_cred 흡수)·상태 v12·테스트 헬퍼

**Files:**
- Modify: `cia.js` (import·`DEMO_ACCOUNTS`·`loadState`·`/cia/register`·`/cia/issue`·`/cia/slot`·`/cia/accounts`·`/cia/admin/registry/{tamper,restore}`·`/cia/open/request` 길이; `/cia/user_cred`·`/cia/attrs`·`/cia/accounts/:uid/attrs` 삭제)
- Modify (전면 교체): `lib/mode3_cia_state.js`
- Modify (전면 교체): `tests/test_mode3_cia_state.js`; Delete: `tests/test_mode3_cia_state_v9.js`; `scripts/run_tests.sh` UNIT 에서 그 줄 삭제
- Modify: `tests/helpers/isolated_cia.mjs` (`registerUser`)
- Create: `tests/helpers/mode3_flow.mjs`
- Modify: `tests/test_cia_register_issue.mjs`, `tests/test_cia_startup.mjs` (chain)

**Interfaces:**
- Consumes: Task 1·5 (`credMessageV11`, `issueRequestMessageV11`, `registerMessage`, `slotRequestMessage`, `registryLeaf`, `auidOf`; `lib/mode3_idp_proof.js` 의 `loadIdpVkey`·`idpPublicSignals`·`verifyIdp`·`IDP_VKEY_PATH`).
- Produces (HTTP): `POST /cia/register { uid, pwd, auid, pk_u, sig_reg } → 201 { slot, schemaHash }`; `POST /cia/issue { uid, auid_s, arid_s, C_u_pt, C_s_pt, chainid, allowAgent, max_height, proof_idp, sig_u } → 200 { Cf_u, Cf_s, max_height, chainid, allowAgent, sigma, pk_CIA, slot, regRoot, epoch, published }`, 거절: 400 `{ error:'bad idp proof', reason:'bad_idp_proof' }`, 403 `{ reason:'account_disabled' }`, 409 `{ reason:'cred_revoked' }`(이미 물린 C_u 재사용), 404 `unknown account`; `POST /cia/slot { uid, nonce, sig_u }`(메시지 `slotRequestMessage`); `/cia/user_cred`·`/cia/attrs`·`/cia/accounts/:uid/attrs` → 404. `GET /cia/accounts` 항목 `{ uid, disabled, activeCf_u, slot, tampered, registryLeaf }`(attrs·profile 없음). `/cia/open/request` 는 `publicSignals.length === 33`.
- Produces (state): `CIA_STATE_VERSION = 12`; `accounts[uid] = { pk_u, auid, slot, tampered, disabled, creds, sessions, receipt, slotRetired }`; `migrateCiaState(state) → { state, notes: [] }` — 버전 ≠ 12 는 throw. 환경변수 `MODE3_IDP_VKEY_PATH`(기본 `build/mode3/pi_idp_vkey.json`).
- Produces (helpers): `cia.registerUser(uid, pwd) → { s_u, auid, sk_u, pk_u, slot, body }`; `tests/helpers/mode3_flow.mjs` 의 `TESTUSER_ATTRS`, `ALICE_ATTRS`, `userOf(reg, uid, attrs?)`, `issueV11(cia, user, opts)`, `proveV11(user, issued, opts)`.

- [ ] **Step 1: `lib/mode3_cia_state.js` 전면 교체**

```js
// CIA 상태 파일의 버전과 검사 — cia.js 에서 떼어 낸 순수 함수. 체인·키 없이 테스트한다.
//
// version 12 (2026-10-12, V11 그림 프로토콜): accounts[uid].auid(필수) 가 cm_u 를 대체하고 attrs·profile 이 없어졌다(D4·D15), 등록부 리프는 Poseidon(auid, Cf_u).
//   **v11 이하는 이행하지 않는다** — 옛 계정의 auid 는 IdP 가 알 수 없고(지갑만 s_u 로 계산한다) 리프·PPID 식이 바뀌어 체인도 새로 배포해야 하므로,
//   V5·V9 때와 같은 "로그 재배포 → 상태 파일 새로" 절차(docs/MODE3_DEMO.md 재시연 세트)로 새로 시작한다. v3~v11 의 이행 코드는 git 이력(78b2a1f)에 있다.
// 모양: accounts[uid] = { pk_u:{x,y}, auid(10진), slot, tampered, disabled, creds:[{ Cf_u, C_u_pt, issuedAt, revoked }], sessions:[{ Cf_s, max_height, chainid, allowAgent, issuedAt, revokedAt }], receipt, slotRetired }
//       rps / openings / revoked / pending / epoch / registry { depth, next, leaves, pendingSlots } / lastPublication / signedEpochMax / attrSchemaHash
export const CIA_STATE_VERSION = 12;

export function defaultCiaState() {
  return { version: CIA_STATE_VERSION, accounts: {}, rps: {}, openings: [], revoked: [], pending: [], epoch: 0, registry: { depth: 20, next: 0, leaves: {}, pendingSlots: [] }, lastPublication: null, signedEpochMax: 0, attrSchemaHash: null };
}

const isDec = (v) => typeof v === 'string' && /^[0-9]+$/.test(v);

/** 제자리 검사. notes 는 기동 로그용(지금은 늘 빈 배열 — 이행이 없다). 버전이 다르면 throw — cia.js 가 사유를 찍고 기동을 거부한다. */
export function migrateCiaState(state) {
  if (state?.version !== CIA_STATE_VERSION) {
    throw new Error(`unsupported CIA state version ${state?.version} (expected ${CIA_STATE_VERSION}) — V11(2026-10-12)은 옛 상태를 이행하지 않는다: 계정의 auid 는 지갑만 계산할 수 있고 등록부 리프·PPID 식이 바뀌어 체인도 새로 배포해야 한다. 재시연 세트(로그·거울 재배포 → 상태 파일 새로)로 시작할 것`);
  }
  state.accounts ??= {}; state.rps ??= {}; state.openings ??= []; state.revoked ??= []; state.pending ??= []; state.epoch ??= 0;
  state.registry ??= { depth: 20, next: 0, leaves: {}, pendingSlots: [] };
  // 손으로 적은(또는 깨진) 파일이 registry 는 있는데 하위 필드가 빠진 경우를 방어한다(2026-10-01 리뷰 Minor).
  state.registry.depth ??= 20; state.registry.next ??= 0; state.registry.leaves ??= {}; state.registry.pendingSlots ??= [];
  state.lastPublication ??= null; state.signedEpochMax ??= 0; state.attrSchemaHash ??= null;
  for (const [uid, a] of Object.entries(state.accounts)) {
    if (!isDec(a.auid)) throw new Error(`CIA state: account ${uid} has no auid — v12 계정은 auid(10진 문자열)가 필수다`);
    a.creds ??= []; a.sessions ??= []; a.tampered ??= false; a.receipt ??= null; a.slotRetired ??= false;
    if ('attrs' in a || 'profile' in a || 'cm_u' in a) throw new Error(`CIA state: account ${uid} has V10 fields (attrs/profile/cm_u) — v12 계정에는 없어야 한다(D15·D4)`);
  }
  return { state, notes: [] };
}
```

- [ ] **Step 2: `tests/test_mode3_cia_state.js` 전면 교체(`tests/test_mode3_cia_state_v9.js` 삭제)**

```js
// CIA 상태 v12(V11 2026-10-12) — 기본 상태·검사·옛 버전 거부. 외부 의존 없음(unit).  node tests/test_mode3_cia_state.js
import assert from 'node:assert/strict';
import { CIA_STATE_VERSION, defaultCiaState, migrateCiaState } from '../lib/mode3_cia_state.js';
let failed = 0;
function t(name, fn) { try { fn(); console.log(`ok   ${name}`); } catch (e) { failed++; console.error(`FAIL ${name}\n     ${e.message}`); } }

t('기본 상태는 v12 이고 attrs·profile·issued 가 없다', () => {
  const s = defaultCiaState();
  assert.equal(s.version, 12); assert.equal(CIA_STATE_VERSION, 12);
  assert.deepEqual(s, { version: 12, accounts: {}, rps: {}, openings: [], revoked: [], pending: [], epoch: 0, registry: { depth: 20, next: 0, leaves: {}, pendingSlots: [] }, lastPublication: null, signedEpochMax: 0, attrSchemaHash: null });
});
t('v12 는 그대로(notes 없음), 빠진 하위 필드는 채운다, 계정 기본값(creds·sessions·tampered·receipt·slotRetired)', () => {
  const { state, notes } = migrateCiaState({ version: 12, accounts: { '12345': { pk_u: { x: '1', y: '2' }, auid: '99', slot: 0, disabled: false } }, rps: {}, openings: [], revoked: [], pending: [], epoch: 3, registry: {} });
  assert.deepEqual(notes, []); assert.equal(state.epoch, 3);
  assert.deepEqual(state.registry, { depth: 20, next: 0, leaves: {}, pendingSlots: [] });
  assert.deepEqual(state.accounts['12345'], { pk_u: { x: '1', y: '2' }, auid: '99', slot: 0, disabled: false, creds: [], sessions: [], tampered: false, receipt: null, slotRetired: false });
  assert.equal(state.signedEpochMax, 0); assert.equal(state.attrSchemaHash, null, '스키마 해시는 cia.js 기동이 기록한다');
});
t('v11 이하(v2·v4·v8·v10·v11)와 미래 버전(13), 버전 없음은 전부 throw — 이행하지 않는다', () => {
  for (const v of [2, 4, 8, 10, 11, 13, undefined]) assert.throws(() => migrateCiaState({ version: v, accounts: {} }), /unsupported CIA state version/, String(v));
  assert.throws(() => migrateCiaState({ version: 11, accounts: {} }), /재시연 세트/);
});
t('v12 인데 auid 가 없거나 V10 필드(attrs·profile·cm_u)가 남은 계정은 throw', () => {
  const base = () => ({ ...defaultCiaState(), accounts: { '1': { pk_u: {}, auid: '5', slot: 0, disabled: false } } });
  migrateCiaState(base());
  const noAuid = base(); delete noAuid.accounts['1'].auid;
  assert.throws(() => migrateCiaState(noAuid), /auid/);
  for (const k of ['attrs', 'profile', 'cm_u']) { const s = base(); s.accounts['1'][k] = {}; assert.throws(() => migrateCiaState(s), /V10 fields/, k); }
});
process.exit(failed === 0 ? 0 : 1);
```
Run: `node tests/test_mode3_cia_state.js` → 전부 `ok`. `scripts/run_tests.sh` UNIT 에서 `tests/test_mode3_cia_state_v9.js` 줄을 지운다.

- [ ] **Step 3: `cia.js` 편집**

(a) import:
- 25행 `import { credMessageV5, compressPoint, randomScalar } from './lib/mode3_credential.js';` → `import { credMessageV11, compressPoint, randomScalar } from './lib/mode3_credential.js';`
- 26행 `encodeProfile, normalizeProfile` 은 더 쓰지 않으므로 `import { DEFAULT_ATTR_SCHEMA, loadSchema, schemaInfo } from './lib/mode3_attr_schema.js';`
- 28행 → `import { isValidPoint, pointFromStrings, issueRequestMessageV11, slotRequestMessage, revokeSessionMessage, registerMessage } from './lib/mode3_issuance.js';`
- 새 줄: `import { loadIdpVkey, idpPublicSignals, verifyIdp, IDP_VKEY_PATH } from './lib/mode3_idp_proof.js';`
- 41행 아래에 `const IDP_VKEY = process.env.MODE3_IDP_VKEY_PATH || IDP_VKEY_PATH;`

(b) `DEMO_ACCOUNTS`(104~108행)를 교체:
```js
// 데모 계정 — 비밀번호·uid 만(D15: 속성은 지갑이 들고 IdP 는 모른다. 옛 profile·attrs 필드는 2026-10-12 에 지웠다).
const DEMO_ACCOUNTS = {
  testuser: { password: 'password123', uid: '12345' },
  alice: { password: 'alicepw', uid: '67890' },
};
```

(c) 133행 상태 주석 `accounts:  uid → { pk_u:{x,y}, cm_u:{x,y}, …` → `accounts:  uid → { pk_u:{x,y}, auid(10진 — Poseidon(T_AUID, uid, s_u), V11 D4), disabled, slot, tampered, creds, sessions, receipt, slotRetired }   (attrs·profile 없음 — D15)`.

(d) `loadState()`:
- 첫 블록(`const named = ATTR_SCHEMA.slots.filter(...)` 부터 `a.profile = fitted; }` 까지, 데모 계정 인코딩 루프) **삭제**.
- `migrateCiaState(state, { demoAttrs: …, attrSchema: ATTR_SCHEMA })` → `migrateCiaState(state)`; catch 의 메시지 `v2 이하는 옛 credential 형식이라 …` → `V11(2026-10-12)은 옛 상태를 이행하지 않는다 — 재시연 세트(로그·거울 재배포 → 상태 파일 새로)로 새로 시작할 것.`
- `let retiredByMigration = 0; for (const uid of migrated.attrsChanged ?? []) …` 두 줄과 그 뒤 `if (retiredByMigration) console.warn(...)` 삭제; `if (migrated.notes.length || retiredByMigration || schemaHashRecorded) persist();` → `if (migrated.notes.length || schemaHashRecorded) persist();`
- 리프 채움 루프의 `registryLeaf(acct.cm_u, cur.Cf_u)` → `registryLeaf(BigInt(acct.auid), BigInt(cur.Cf_u))`.
- 스키마 해시 거부 블록은 **그대로 둔다**(스펙 §7 "attrSchemaHash 유지").

(e) `/cia/register` 전면 교체:
```js
// V11 §3.1 등록. 지갑이 auid = Poseidon(T_AUID, uid, s_u) 와 등록 키 pk_u 를 낸다 — CIA 는 소유 증명 서명만 보고 슬롯 번호를 배정한다. 속성은 받지 않는다(D15).
app.post('/cia/register', async (req, res) => {
  const { uid, pwd, auid, pk_u, sig_reg } = req.body ?? {};
  if (!isDec(uid) || typeof pwd !== 'string' || !isDec(auid) || !isPt(pk_u) || !sig_reg) return res.status(400).json({ error: 'uid, pwd, auid, pk_u{x,y}, sig_reg required' });
  const acct = Object.values(DEMO_ACCOUNTS).find((a) => a.uid === uid);
  if (!acct || acct.password !== pwd) return res.status(401).json({ error: 'invalid credentials' });
  if (state.accounts[uid]) return res.status(409).json({ error: 'already registered' });
  if (BigInt(auid) >= F.p) return res.status(400).json({ error: 'auid is not a field element' });   // Poseidon 출력 범위 — 비정규 값은 등록부 리프·π 와 어긋난다
  if (!(await isValidPoint(pointFromStrings(pk_u)))) return res.status(400).json({ error: 'pk_u is not a valid subgroup point' });
  let ok = false;
  try {
    const m = F.e(await registerMessage(BigInt(uid), BigInt(auid)));
    ok = eddsa.verifyPoseidon(m, { R8: [F.e(BigInt(sig_reg.R8x)), F.e(BigInt(sig_reg.R8y))], S: BigInt(sig_reg.S) }, [F.e(BigInt(pk_u.x)), F.e(BigInt(pk_u.y))]);
  } catch { ok = false; }
  if (!ok) return res.status(400).json({ error: 'bad_registration_signature' });
  if (state.accounts[uid]) return res.status(409).json({ error: 'already registered' });   // await 사이 경합
  const slot = state.registry.next++;
  state.accounts[uid] = { pk_u: { x: BigInt(pk_u.x).toString(), y: BigInt(pk_u.y).toString() }, auid: BigInt(auid).toString(), slot, tampered: false, disabled: false, creds: [], sessions: [], receipt: null, slotRetired: false };
  persist();
  res.status(201).json({ slot, schemaHash: ATTR_SCHEMA_HASH });
});
```

(f) `/cia/user_cred`·`/cia/attrs`·`/cia/accounts/:uid/attrs` 라우트(주석 포함) **삭제**. `/cia/slot` 의 `attrsRequestMessage` → `slotRequestMessage`, 주석 "메시지는 /cia/attrs 와 같은 Poseidon(D_ATTRSREQ, uid, nonce)" → "메시지는 Poseidon(D_SLOTREQ, uid, nonce)".

(g) `/cia/issue` 전면 교체:
```js
// V11(스펙 2026-10-12 §5.2, 그림 3 "DA request") 세션 발급 = (C_u, C_s, π_IdP, sig_u) 한 요청. 옛 /cia/user_cred 를 흡수했다 — 요청의 C_u 가
// 활성 자격증명과 다르면(첫 로그인·사용자의 속성 변경) 등록부 슬롯을 갱신·게시한 뒤 토큰을 낸다. 속성 값은 받지 않는다(D15).
// 검사 순서: 형식 → max_height 범위 → 계정·disabled → chainid 허용 → sig_u → π_IdP → C_u·C_s 부분군 → 체인 생존(fail-closed) → disabled 재확인 →
// (C_u 교체: 은퇴 → creds 추가 → setSlot → persist → 즉시 게시) → 토큰 서명 → 세션 기록. auid_s·arid_s 는 서명·토큰에만 쓰고 저장하지 않는다(D1).
app.post('/cia/issue', async (req, res) => {
  try {
    const { uid, auid_s, arid_s, C_u_pt, C_s_pt, chainid, allowAgent, max_height, proof_idp, sig_u } = req.body ?? {};
    if (!isDec(uid) || !isDec(auid_s) || !isDec(arid_s) || !isPt(C_u_pt) || !isPt(C_s_pt) || !isDec(chainid) || (allowAgent !== '0' && allowAgent !== '1') || !isDec(max_height) || !proof_idp || typeof proof_idp !== 'object' || !sig_u) {
      return res.status(400).json({ error: 'uid, auid_s, arid_s, C_u_pt{x,y}, C_s_pt{x,y}, chainid, allowAgent("0"|"1"), max_height, proof_idp, sig_u required' });
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
    const cupt = pointFromStrings(C_u_pt), cspt = pointFromStrings(C_s_pt);
    if (!(await isValidPoint(cupt))) return res.status(400).json({ error: 'C_u_pt is not a valid subgroup point' });
    if (!(await isValidPoint(cspt))) return res.status(400).json({ error: 'C_s_pt is not a valid subgroup point' });
    // Cf_u·Cf_s 는 CIA 가 점에서 스스로 유도한다(설계 §6.2) — 사용자가 보낸 Cf 를 서명하면 증명된 점과 무관한 값에 서명이 붙는다.
    const Cf_u = await compressPoint(cupt), Cf_s = await compressPoint(cspt);
    const auidS = BigInt(auid_s), aridS = BigInt(arid_s);
    let sigOk = false;
    try {
      const m = F.e(await issueRequestMessageV11(auidS, aridS, Cf_u, Cf_s, BigInt(chainStr), agent, mh));
      sigOk = eddsa.verifyPoseidon(m, { R8: [F.e(BigInt(sig_u.R8x)), F.e(BigInt(sig_u.R8y))], S: BigInt(sig_u.S) }, [F.e(BigInt(acct.pk_u.x)), F.e(BigInt(acct.pk_u.y))]);
    } catch { sigOk = false; }
    if (!sigOk) return res.status(400).json({ error: 'bad user signature' });
    // π_IdP — 공개 입력은 CIA 가 스스로 조립한다(uid 는 요청·계정, auid 는 DB 값): 지갑이 보낸 값을 그대로 넣으면 아무 auid 에 대한 증명이 통과한다.
    let vkIdp;
    try { vkIdp = await loadIdpVkey(IDP_VKEY); } catch (e) { return res.status(503).json({ error: `idp vkey unavailable: ${e.message}` }); }
    const pubIdp = idpPublicSignals({ uid: BigInt(uid), auid: BigInt(acct.auid), auid_s: auidS, C_u_pt: cupt, C_s_pt: cspt, max_height: mh });
    if (!(await verifyIdp(vkIdp, pubIdp, proof_idp))) return res.status(400).json({ error: 'bad idp proof', reason: 'bad_idp_proof' });
    const head = await headOf(chainStr);   // fail-closed: 체인이 죽어 있으면 발급하지 않는다(게시도 불가하므로 폐기가 닿지 않는 세션이 된다)
    const cfu = Cf_u.toString();
    // 이 await 를 끝으로 아래 물리기→push→setSlot→persist 구간은 동기다(2026-10-01 리뷰 Important 2 와 같은 이유).
    const newLeaf = await registryLeaf(BigInt(acct.auid), Cf_u);
    if (acct.disabled) return res.status(403).json({ error: 'account disabled', reason: 'account_disabled' });   // await 사이의 폐기
    acct.creds ??= [];
    const cur = activeCred(uid);
    let published = false;
    if (!cur || cur.Cf_u !== cfu) {
      // 물린 적 있는 C_u 는 다시 받지 않는다 — 은퇴·폐기의 되감기를 막는다.
      if (acct.creds.some((c) => c.Cf_u === cfu)) return res.status(409).json({ error: 'this user credential was revoked; make a new one', reason: 'cred_revoked' });
      retireActiveCred(uid);
      // V10(§4.5): 대기열로 영구 은퇴된 슬롯에는 0 아닌 리프를 쓸 수 없다(컨트랙트 SlotIsRetired) — 새 슬롯을 받는다. PPID 는 (uid, s_u, arid, chainid) 에만 걸려 있어 슬롯이 바뀌어도 그대로다.
      if (acct.slotRetired) { acct.slot = state.registry.next++; acct.slotRetired = false; }
      acct.creds.push({ Cf_u: cfu, C_u_pt: { x: cupt.x.toString(), y: cupt.y.toString() }, issuedAt: new Date().toISOString(), revoked: false });
      setSlot(uid, newLeaf);
      persist();
      published = Boolean((await publishSafely()).published);
      if (acct.disabled) return res.status(403).json({ error: 'account disabled', reason: 'account_disabled' });   // 게시 await 사이의 폐기
    }
    const s = eddsa.signPoseidon(ciaPrv, F.e(await credMessageV11(auidS, aridS, Cf_u, Cf_s, BigInt(chainStr), agent)));
    // V8(2026-09-24 §2.1): 세션 단위 폐기를 하려면 CIA 가 Cf_s 를 알아야 한다. 정리는 하트비트뿐 아니라 여기서도(최종 리뷰 F2). auid_s·arid_s 는 적지 않는다(D1).
    acct.sessions = (acct.sessions ?? []).filter((r) => r.chainid !== chainStr || BigInt(r.max_height) >= head);
    acct.sessions.push({ Cf_s: Cf_s.toString(), max_height: mh.toString(), chainid: chainStr, allowAgent: agent.toString(), issuedAt: new Date().toISOString(), revokedAt: null });
    persist();
    res.json({
      Cf_u: cfu, Cf_s: Cf_s.toString(), max_height: mh.toString(), chainid: chainStr, allowAgent: agent.toString(),
      sigma: { R8x: F.toObject(s.R8[0]).toString(), R8y: F.toObject(s.R8[1]).toString(), S: s.S.toString() },
      pk_CIA: S(ciaPub), slot: acct.slot, regRoot: registry.root().toString(), epoch: state.epoch, published,
    });
  } catch (e) { res.status(e.status || 500).json({ error: e.message }); }
});
```

(h) `/cia/accounts` 매핑에서 `attrs: a.attrs, profile: a.profile ?? {},` 제거. `/cia/admin/registry/tamper` 의 `registryLeaf(acct.cm_u, randomScalar())` → `registryLeaf(BigInt(acct.auid), randomScalar())`; `restore` 의 `registryLeaf(acct.cm_u, BigInt(cur.Cf_u))` → `registryLeaf(BigInt(acct.auid), BigInt(cur.Cf_u))`. `/cia/open/request` 의 `publicSignals.length !== 30` → `33`, 에러 문구 `publicSignals[33]`, 주석 "V9: 공개 입력 30 …" → "V11: 공개 입력 33 — 태그는 [12..14] 그대로". 기동 로그(`app.listen`)의 `vkey=` 뒤에 `idpVkey=${fs.existsSync(IDP_VKEY) ? 'ok' : 'missing'}` 추가.

(i) `node --check cia.js` 로 구문 확인.

- [ ] **Step 4: 테스트 헬퍼**

`tests/helpers/isolated_cia.mjs` 의 `registerUser` 교체(import 는 `createRegistration, signRegistration` 그대로):
```js
    /** V11 등록(스펙 2026-10-12 §3.1): 지갑 키·auid 를 만들어 /cia/register 를 부른다. { s_u, auid, sk_u, pk_u, slot, body } */
    async registerUser(uid, pwd) {
      const reg = await createRegistration(BigInt(uid));
      const r = await this.post('/cia/register', { uid, pwd, auid: reg.auid.toString(), pk_u: { x: reg.pk_u.x.toString(), y: reg.pk_u.y.toString() }, sig_reg: await signRegistration(reg.sk_u, BigInt(uid), reg.auid) });
      if (r.status !== 201) throw new Error(`register 실패(${r.status}): ${JSON.stringify(r.body)}`);
      return { ...reg, slot: r.body.slot, body: r.body };
    },
```
(`pointToStrings` import 가 더 안 쓰이면 지운다.)

`tests/helpers/mode3_flow.mjs` 생성:
```js
// V11 흐름 헬퍼(chain 테스트 공용) — 등록된 사용자로 (1) C_u 를 고르고 (2) /cia/issue(π_IdP 포함)를 부르고 (3) π_RP 를 만든다.
// 테스트마다 같은 코드를 적지 않게 한다. 속성은 사용자(테스트)가 정한다(D15) — IdP 는 값을 보지 않으므로 어떤 벡터든 발급된다.
import { randomScalar } from '../../lib/mode3_credential.js';
import { createSessionKey, buildIssueRequest, buildCredentialProof, syncRevocationTree, syncRegistryTree } from '../../lib/mode3_wallet.js';

export const TESTUSER_ATTRS = Object.freeze([1990n, 410n, 0n, 0n, 0n, 0n]);   // testuser(12345) — 지갑 기본 profile { birthYear 1990, country KR } 의 인코딩
export const ALICE_ATTRS = Object.freeze([2005n, 840n, 0n, 0n, 0n, 0n]);      // alice(67890) — { birthYear 2005, country US }

/** registerUser 결과 + attrs → 사용자 묶음 { uid(bigint), s_u, auid, sk_u(hex), slot, attrs(bigint[]) }. */
export function userOf(reg, uid, attrs = TESTUSER_ATTRS) {
  return { uid: BigInt(uid), s_u: reg.s_u, auid: reg.auid, sk_u: reg.sk_u, slot: reg.slot, attrs: [...attrs] };
}

/**
 * 세션 발급 한 번. 돌려주는 값 { r, req, session, r_s, r_rp, blind_u, cred } — r 은 CIA 응답, cred = r.body(토큰 묶음).
 * blind_u 를 같은 값으로 다시 주면 같은 C_u(재사용), 새 값이면 새 C_u(CIA 가 슬롯을 갱신·게시). max_height 가 없으면 provider 로 head+300.
 * uidInBody 는 본문의 uid 만 바꾼다(C_u 안의 uid 는 user.uid) — 시연 덮어쓰기 재현용. overrides 는 본문 필드를 덮는다(음성 케이스용).
 */
export async function issueV11(cia, user, { arid, chainid = 31337n, allowAgent = 0n, max_height, provider = null, blind_u = randomScalar(), r_s = randomScalar(), r_rp = randomScalar(), session = createSessionKey(), uidInBody = null, overrides = {}, post = (p, b) => cia.post(p, b) } = {}) {
  if (max_height === undefined) {
    if (!provider) throw new Error('issueV11: max_height 또는 provider 가 필요하다');
    max_height = BigInt(await provider.getBlockNumber()) + 300n;
  }
  const req = await buildIssueRequest({ uid: user.uid, s_u: user.s_u, blind_u, attrs: user.attrs, arid: BigInt(arid), r_rp, r_s, sk_u: user.sk_u, session, chainid, allowAgent, max_height });
  if (uidInBody !== null) req.body.uid = String(uidInBody);
  const r = await post('/cia/issue', { ...req.body, ...overrides });
  return { r, req, session, r_s, r_rp, blind_u, cred: r.body, user };
}

/** 발급 결과로 π_RP 를 만든다. tree·registry 를 안 주면 (provider, logAddress) 에서 동기화한다. slot 은 CIA 응답의 슬롯(재발급으로 바뀔 수 있다). */
export async function proveV11(issued, { arid, pk_CIA, pk_trace, provider, logAddress, tree, registry, slot = issued.cred?.slot ?? issued.user.slot, disclosure = null, tagR } = {}) {
  const u = issued.user;
  if (!tree) ({ tree } = await syncRevocationTree(provider, logAddress));
  if (!registry) ({ tree: registry } = await syncRegistryTree(provider, logAddress));
  return buildCredentialProof({ uid: u.uid, arid: BigInt(arid), s_u: u.s_u, auid: u.auid, blind_u: issued.blind_u, r_rp: issued.r_rp, r_s: issued.r_s, pk_i: issued.session.pk_i, attrs: u.attrs, credential: issued.cred, pk_CIA, pk_trace, tree, registry, slot, disclosure, ...(tagR !== undefined ? { tagR } : {}) });
}
```

- [ ] **Step 5: `tests/test_cia_register_issue.mjs` V11 이행**

(a) import: `sessionCommit, compressPoint, credMessageV5` → `compressPoint, credMessageV11, auidOf`; `registrationCommit, proveUserCred, serializeUserCredProof, userCredRequestMessage, issueRequestMessageV4, pointToStrings` → `issueRequestMessageV11, pointToStrings`; `buildUserCredRequest, signAttrsRequest` → `createRegistration, signRegistration, signSlotRequest, buildIssueRequest, createSessionKey`; `encodeSlotValue, DEFAULT_ATTR_SCHEMA` import 삭제; 추가 `import { issueV11, userOf, TESTUSER_ATTRS, ALICE_ATTRS } from './helpers/mode3_flow.mjs';`.

(b) 헬퍼 블록(`TESTUSER_ATTRS` 상수부터 `revokedLeaf` 끝까지)을 교체:
```js
let user;   // userOf(registerUser('12345'))
/** 데모 계정 하나를 등록만 한다. */
async function freshRegistered(uidStr, pwd, attrs = TESTUSER_ATTRS) { return userOf(await cia.registerUser(uidStr, pwd), uidStr, attrs); }
let _testuser = null;
/** uid 12345(testuser) 등록 — uid 는 한 번만 등록되므로 메모이즈한다. */
async function freshWallet() { return (_testuser ??= await freshRegistered('12345', 'password123')); }
/** 발급 한 번(기본값: 새 C_u, head+300). issueV11 의 얇은 포장 — 이 파일의 케이스가 자주 쓰는 모양. */
const issue = (u, opts = {}) => issueV11(cia, u, { arid, provider, ...opts });
/** 세션 하나 발급 → 그 자격증명 은퇴(scope=credential, 즉시 게시) → 그 세션 폐기(scope=session, pending 에만). 리프(10진)를 돌려준다. (설명은 V10 과 같다) */
async function revokedLeaf() {
  const iss = await issue(user);
  assert.equal(iss.r.status, 200, JSON.stringify(iss.r.body));
  const rc = await cia.adminPost('/cia/revoke', { uid: uid.toString(), scope: 'credential' });
  assert.equal(rc.status, 200, JSON.stringify(rc.body)); assert.equal(rc.body.retired, 1);
  const r = await cia.adminPost('/cia/revoke', { uid: uid.toString(), scope: 'session', Cf_s: iss.cred.Cf_s });
  assert.equal(r.status, 200, JSON.stringify(r.body)); assert.equal(r.body.inserted, true);
  return r.body.leaf;
}
```

(c) 케이스 교체·삭제·추가(이름으로 찾는다):
- `'register: 곡선 밖·부분군 밖의 cm_u 는 400 이고 uid 는 잠기지 않는다'` → 
```js
  await t('register: auid 가 10진이 아니거나 필드 밖이면 400 이고 uid 는 잠기지 않는다', async () => {
    const dummyPk = { x: '1', y: '1' }, dummySig = { R8x: '1', R8y: '1', S: '1' };
    assert.equal((await cia.post('/cia/register', { uid: '12345', pwd: 'password123', auid: 'zz', pk_u: dummyPk, sig_reg: dummySig })).status, 400);
    assert.equal((await cia.post('/cia/register', { uid: '12345', pwd: 'password123', auid: F.p.toString(), pk_u: dummyPk, sig_reg: dummySig })).status, 400, '필드 밖');
    assert.equal((await cia.post('/cia/register', { uid: '12345', pwd: 'password123', auid: '7', pk_u: dummyPk, sig_reg: dummySig })).status, 400, 'pk_u 가 곡선 밖');
  });
```
- `'register: cm_u 등록, 장기키 발급, 응답에 AA 기록 attrs'` → 
```js
  await t('register: auid 등록 → 201 { slot, schemaHash }, 속성·profile 은 없다(D15), 계정 상태에도 attrs 없음', async () => {
    user = await freshWallet();
    assert.equal(user.slot, 0); assert.equal(user.auid, await auidOf({ uid, s_u: user.s_u }));
    const acct = (await cia.adminGet('/cia/accounts')).body.accounts.find((a) => a.uid === '12345');
    assert.equal(acct.attrs, undefined); assert.equal(acct.profile, undefined); assert.equal(acct.activeCf_u, null); assert.equal(acct.slot, 0);
  });
```
- `'register: 잘못된 비밀번호는 401, 재등록은 409'` 의 본문 `cm_u: cm` → `auid: '1'`.
- `'user_cred: 201 …'`·`'user_cred: 새 자격증명을 받으면 …'`·`'register 응답에 AA 기록 attrs …/cia/attrs'`·`'user_cred: 지갑이 AA 기록과 다른 attrs …'`·`'관리자 속성 변경: …'`(2건) **삭제**.
- `'issue V5: 정상 200 …'` → 
```js
  await t('issue V11: 첫 발급 — 새 C_u 가 슬롯에 게시(published:true)되고 토큰·세션 기록; 같은 C_u 재발급은 published:false, 활성 자격증명은 하나', async () => {
    const a = await issue(user);
    assert.equal(a.r.status, 200, JSON.stringify(a.r.body));
    assert.deepEqual(Object.keys(a.cred).sort(), ['Cf_s', 'Cf_u', 'allowAgent', 'chainid', 'epoch', 'max_height', 'pk_CIA', 'published', 'regRoot', 'sigma', 'slot']);
    assert.equal(a.cred.Cf_u, a.req.Cf_u.toString()); assert.equal(a.cred.Cf_s, a.req.Cf_s.toString()); assert.equal(a.cred.published, true);
    const m = F.e(await credMessageV11(a.req.auid_s, a.req.arid_s, a.req.Cf_u, a.req.Cf_s, CHAIN_ID, 0n));
    const pk = (await cia.get('/cia/public_keys')).body.pk_CIA;
    assert.equal(eddsa.verifyPoseidon(m, { R8: [F.e(BigInt(a.cred.sigma.R8x)), F.e(BigInt(a.cred.sigma.R8y))], S: BigInt(a.cred.sigma.S) }, [F.e(BigInt(pk.x)), F.e(BigInt(pk.y))]), true, '토큰은 (auid_s, arid_s, Cf_u, Cf_s, chainid, allowAgent) 위 CIA 서명');
    const b = await issue(user, { blind_u: a.blind_u });   // 같은 C_u, 새 세션
    assert.equal(b.r.status, 200); assert.equal(b.cred.published, false); assert.equal(b.cred.Cf_u, a.cred.Cf_u); assert.notEqual(b.cred.Cf_s, a.cred.Cf_s);
    assert.equal((await cia.get('/cia/state')).body.credCount, 1);
    const sessions = (await cia.adminGet(`/cia/admin/sessions?uid=${uid}`)).body.sessions;
    assert.ok(sessions.some((s) => s.Cf_s === a.cred.Cf_s) && sessions.some((s) => s.Cf_s === b.cred.Cf_s), '세션 기록 둘');
    assert.ok(sessions.every((s) => s.auid_s === undefined && s.arid_s === undefined), 'D1: auid_s·arid_s 는 기록하지 않는다');
    const file = fs.readFileSync(path.join(cia.dir, 'cia_state.json'), 'utf8');
    for (const k of ['"attrs"', '"profile"', '"auid_s"', '"arid_s"', '"cm_u"']) assert.equal(file.includes(k), false, `${k} 가 상태 파일에 있다`);
  });
```
  (파일 상단에 `import fs from 'node:fs'; import path from 'node:path';` 추가.)
- 새 케이스(위 바로 뒤):
```js
  await t('issue V11: 다른 C_u(새 blind_u·같은 속성 또는 다른 속성)로 발급하면 옛 C_u 는 revoked·슬롯은 새 리프, 옛 C_u 재사용은 409 cred_revoked', async () => {
    const a = await issue(user);
    const b = await issue(user, { blind_u: randomScalar() });
    assert.equal(b.r.status, 200); assert.equal(b.cred.published, true); assert.notEqual(b.cred.Cf_u, a.cred.Cf_u);
    assert.equal((await cia.get('/cia/state')).body.credCount, 1);
    const again = await issue(user, { blind_u: a.blind_u });
    assert.equal(again.r.status, 409); assert.equal(again.r.body.reason, 'cred_revoked');
    const other = await issue({ ...user, attrs: [1991n, 392n, 0n, 0n, 0n, 0n] });   // D15: 속성은 사용자 몫 — 어떤 값이든 발급된다
    assert.equal(other.r.status, 200, JSON.stringify(other.r.body)); assert.equal(other.cred.published, true);
  });
  await t('issue V11: π_IdP 가 다른 auid(다른 salt 의 지갑)·다른 uid 면 400 bad_idp_proof; 증명 손상도 400; 없으면 400', async () => {
    const stranger = { ...user, s_u: randomScalar() };   // 같은 uid, 다른 salt → auid 가 DB 와 다르다
    const bad = await issue(stranger);
    assert.equal(bad.r.status, 400, JSON.stringify(bad.r.body)); assert.equal(bad.r.body.reason, 'bad_idp_proof');
    const fakeUid = await issue({ ...user, uid: 99999n }, { uidInBody: '12345' });   // C_u 안의 uid 만 바꾸고 본문 uid 는 진짜
    assert.equal(fakeUid.r.status, 400); assert.equal(fakeUid.r.body.reason, 'bad_idp_proof');
    const good = await issue(user);
    const broken = await issue(user, { overrides: { proof_idp: { ...good.req.body.proof_idp, pi_a: ['1', '2', '1'] } } });
    assert.equal(broken.r.status, 400); assert.equal(broken.r.body.reason, 'bad_idp_proof');
    assert.equal((await issue(user, { overrides: { proof_idp: undefined } })).r.status, 400);
  });
```
- `'issue V5: 서명이 Cf_u·C_s·chainid·allowAgent·max_height 를 덮는다 …'` → 
```js
  await t('issue V11: 서명이 auid_s·arid_s·C_u·C_s·chainid·allowAgent·max_height 를 덮는다 — 하나라도 바꾸면 400; 부분군 밖 점은 400', async () => {
    const g = await issue(user); assert.equal(g.r.status, 200);
    for (const patch of [{ auid_s: '1' }, { arid_s: '1' }, { allowAgent: '1' }, { chainid: '1' }, { max_height: (BigInt(g.req.body.max_height) + 1n).toString() }]) {
      assert.equal((await issue(user, { blind_u: g.blind_u, overrides: patch })).r.status, 400, JSON.stringify(patch));
    }
    const h = await issue(user, { blind_u: g.blind_u });   // 다른 요청의 C_s 로 바꿔치기 — 서명·π 모두 어긋난다
    assert.equal((await issue(user, { blind_u: g.blind_u, overrides: { C_s_pt: h.req.body.C_s_pt } })).r.status, 400);
    assert.equal((await issue(user, { overrides: { C_s_pt: { x: '1', y: '1' } } })).r.status, 400);
    assert.equal((await issue(user, { overrides: { C_u_pt: { x: '1', y: '1' } } })).r.status, 400);
  });
```
- `'issue V5: 사용자 서명이 다른 키면 400'` → `issue(user, { overrides: { sig_u: (await issue({ ...user, sk_u: (await createRegistration(uid)).sk_u })).req.body.sig_u } })` 가 400 (다른 키의 서명을 끼운다).
- `'issue V5: max_height …'`·`'issue V5: allowAgent …'`: 이름 "V5" → "V11"; 본문 조작은 `issue(user, { overrides: {...} })` 로, 정상 `allowAgent: 1n` 은 `issue(user, { allowAgent: 1n })` 로; `max_height` 없음은 `overrides: { max_height: undefined }`; `huge` 는 `issue(user, { max_height: 1n << 64n })` 가 **buildIssueRequest 에서 throw** 하므로 `assert.rejects` 로 바꾸고, 서버 쪽 범위 검사는 `overrides: { max_height: (1n << 64n).toString() }` 로 400 을 본다.
- `'revoke(account): …'`·`'revoke(credential): …'`·`'self_revoke: …'`(3건)·`'revoke: 활성 자격증명이 없는 계정 …'`·`'publish 도중 들어온 revoke …'`·`'self_revoke: 체인이 죽어도 …'`: `userCredRequest(x)` + `cia.post('/cia/user_cred', …)` 두 줄 → `const iss = await issue(x); assert.equal(iss.r.status, 200)`; `issueRequest(user, cred)` + `cia.post('/cia/issue', …)` → `issue(user, { blind_u: iss.blind_u })`; "새 user_cred 를 받으면 다시 발급된다" 류의 단언은 `issue(user)`(새 blind_u) 가 200 이고 `published:true` 인 것으로. `revoke(account)` 뒤 `issue(user)` 는 403 `account_disabled`; `u2`(alice) 는 `freshRegistered('67890', 'alicepw', ALICE_ATTRS)`.
  `'self_revoke: 체인이 죽어도 …'` 안의 `dead.post('/cia/issue', {...})` 직접 호출은 `issueV11(dead, user, { arid, max_height: 1000n, post: (p, b) => dead.post(p, b) })` 로.
- `'register_rp …'`·`'publish …'`·`'하트비트 …'`·`'admin 엔드포인트 …'` 는 불변.
- 파일 끝(try 안 마지막)에 추가:
```js
  await t('V11: 사라진 라우트는 404 — /cia/user_cred, /cia/attrs, /cia/accounts/:uid/attrs; /cia/slot 은 D_SLOTREQ 서명으로 슬롯을 준다', async () => {
    assert.equal((await cia.post('/cia/user_cred', {})).status, 404);
    assert.equal((await cia.post('/cia/attrs', {})).status, 404);
    assert.equal((await cia.adminPost('/cia/accounts/12345/attrs', { profile: {} })).status, 404);
    const nonce = randomScalar();
    const r = await cia.post('/cia/slot', { uid: '12345', nonce: nonce.toString(), sig_u: await signSlotRequest(user.sk_u, uid, nonce) });
    assert.equal(r.status, 200, JSON.stringify(r.body)); assert.equal(typeof r.body.slot, 'number');
    assert.equal((await cia.post('/cia/slot', { uid: '12345', nonce: '100', sig_u: await signSlotRequest(user.sk_u, uid, nonce) })).status, 400, '다른 nonce 의 서명은 거절');
  });
```

- [ ] **Step 6: `tests/test_cia_startup.mjs` V11 이행**

- import: `proveUserCred, serializeUserCredProof, userCredRequestMessage, issueRequestMessageV4, pointToStrings` 삭제; `import { issueV11, userOf } from './helpers/mode3_flow.mjs';` 추가; `sessionCommit, randomScalar` 는 쓰는 곳에 맞게 정리.
- `registerAndIssueLeaf(cia, user)` 교체:
```js
async function registerAndIssueLeaf(cia, user) {
  if (!user.sk_u) Object.assign(user, userOf(await cia.registerUser(uid.toString(), 'password123'), uid), { blind_u: randomScalar() });
  // 사용자 자격증명은 한 번만(매번 새 C_u 면 그 발급 자체가 등록부를 즉시 게시해 epoch 가 예측과 어긋난다) — 같은 blind_u 를 다시 준다.
  const iss = await issueV11(cia, user, { arid, provider: getProvider(), blind_u: user.blind_u });
  assert.equal(iss.r.status, 200, JSON.stringify(iss.r.body));
  const rv = await cia.adminPost('/cia/revoke', { uid: uid.toString(), scope: 'session', Cf_s: iss.cred.Cf_s });
  assert.equal(rv.status, 200, JSON.stringify(rv.body)); assert.equal(rv.body.inserted, true);
  return rv.body.leaf;
}
```
  (함수 끝의 기존 `return` 과 중간 `sessionCommit`·`issueRequestMessageV4` 코드는 전부 이 본문으로 바뀐다. 첫 발급은 등록부를 즉시 게시해 epoch 가 하나 오른다 — 뒤 케이스의 epoch 기대값(`pub1`·`pendingCount 2` 등)이 이 변화에 맞는지 실행으로 확인하고, 어긋나면 "첫 발급 게시 1회" 를 기대값에 반영한다.)
- 상태 파일 케이스 교체: `'v3 상태 파일은 v10 으로 마이그레이션된다 …'`·`'v4 상태 파일은 v10 으로 이행된다 …'`·`'v10 상태 파일은 v11 로 이행된다 …'`·`'v10→v11 이행의 온체인 효과 …'`·`'v6→v7 이행이 pending 리프를 남기면 …'`·`'자동 게시가 체인 RPC 를 못 읽으면 …'` 여섯을 **삭제**하고 다음 둘을 넣는다:
```js
  await t('V11: v11 이하 상태 파일(v4·v11)은 기동 거부 — 사유 한 줄에 "재시연 세트"', async () => {
    for (const v of [4, 11]) {
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), `mode3-old-v${v}-`));
      const stateFile = path.join(dir, 'cia_state.json');
      fs.writeFileSync(stateFile, JSON.stringify({ version: v, accounts: {}, rps: {}, openings: [], revoked: [], pending: [], epoch: 0 }), { mode: 0o600 });
      const msg = await expectStartupRefused({ env: { CIA_STATE_FILE: stateFile } });
      assert.match(msg, /unsupported CIA state version/); assert.match(msg, /재시연 세트/);
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
  await t('V11: 백로그(pendingSlots)가 남은 v12 파일은 기동이 자동 게시한다; 자동 게시가 RPC 를 못 읽으면 경고만 남기고 기동은 계속한다', async () => {
    const { createRegistration } = await import('../lib/mode3_wallet.js');
    const { userCommit } = await import('../lib/mode3_credential.js');
    const { registryLeaf } = await import('../lib/mode3_registry.js');
    const reg = await createRegistration(12345n);
    const { Cx, Cy, Cf } = await userCommit({ uid: 12345n, s_u: reg.s_u, blind_u: randomScalar(), attrs: [1990n, 410n, 0n, 0n, 0n, 0n] });
    const leaf = (await registryLeaf(reg.auid, Cf)).toString();
    const mk = () => ({ version: 12, accounts: { '12345': { pk_u: { x: reg.pk_u.x.toString(), y: reg.pk_u.y.toString() }, auid: reg.auid.toString(), slot: 0, tampered: false, disabled: false, creds: [{ Cf_u: Cf.toString(), C_u_pt: { x: Cx.toString(), y: Cy.toString() }, issuedAt: 'x', revoked: false }], sessions: [], receipt: null, slotRetired: false } },
      rps: {}, openings: [], revoked: [], pending: [], epoch: 0, registry: { depth: 20, next: 1, leaves: { '0': leaf }, pendingSlots: [{ index: 0, leaf }] }, lastPublication: null, signedEpochMax: 0, attrSchemaHash: null });
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mode3-v12-backlog-'));
    const stateFile = path.join(dir, 'cia_state.json');
    fs.writeFileSync(stateFile, JSON.stringify(mk()), { mode: 0o600 });
    const cia = await startIsolatedCia({ env: { CIA_STATE_FILE: stateFile } });
    try {
      const st = (await cia.get('/cia/state')).body;
      assert.equal(st.pendingSlots, 0, '기동이 백로그를 게시했어야 한다'); assert.equal(st.epoch, 1);
    } finally { await cia.stop(); }
    fs.writeFileSync(stateFile, JSON.stringify(mk()), { mode: 0o600 });
    const dead = await startIsolatedCia({ env: { CIA_STATE_FILE: stateFile, CIA_RPC_URL: 'http://127.0.0.1:1' } });
    try {
      assert.match(dead.log(), /\/cia\/publish/, '수동 게시 안내');
      assert.equal((await dead.get('/cia/state')).body.pendingSlots, 1, '게시가 실패했으므로 백로그는 그대로');
    } finally { await dead.stop(); fs.rmSync(dir, { recursive: true, force: true }); }
  });
```
- `'CIA_ATTR_SCHEMA_FILE 이 검증에 실패하면 기동하지 않는다'`·`'스키마 해시: …'` 는 유지하되 후자의 `version: 11` 픽스처를 `version: 12` 로(필드 모양은 defaultCiaState 와 같게 `attrSchemaHash` 만 뺀다).
- 나머지(크래시 복구·불일치 거부·하트비트)는 `registerAndIssueLeaf` 로 이미 덮인다.

- [ ] **Step 7: 실행**

Run: `node tests/test_mode3_cia_state.js && node --check cia.js`
Run: `node tests/test_cia_register_issue.mjs` → 전부 `ok`.
Run: `node tests/test_cia_startup.mjs` → 전부 `ok`(epoch 기대값은 Step 6 의 주의대로 맞춘다).

---

### Task 8: 나머지 CIA 쪽 chain 테스트를 V11 흐름으로

**Files:**
- Modify: `tests/test_cia_registry.mjs`, `tests/test_cia_issue_race.mjs`, `tests/test_cia_opening.mjs`, `tests/test_cia_mirror_relay.mjs`, `tests/test_mode3_session_revoke.mjs`, `tests/test_mode3_e2e.mjs`, `tests/test_mode3_health.mjs`

**Interfaces:**
- Consumes: Task 7 의 `cia.registerUser`·`issueV11`·`proveV11`·`userOf`·`TESTUSER_ATTRS`·`ALICE_ATTRS`; Task 5·6 의 라이브러리.

공통 치환 규칙(모든 파일에 적용):
| V10 코드 | V11 코드 |
|---|---|
| `const u = await cia.registerUser(uid, pwd)` 뒤에 `u.s_u, u.r_u, u.cm_u, u.sk_u, u.attrs` 를 쓰는 곳 | `const u = userOf(await cia.registerUser(uid, pwd), uid, ATTRS)` — `u.attrs` 는 테스트가 정한 벡터(testuser `TESTUSER_ATTRS`, alice `ALICE_ATTRS`) |
| `buildUserCredRequest({...})` + `cia.post('/cia/user_cred', uc.body)` | 삭제 — 첫 `issueV11` 이 C_u 를 게시한다. "C_u 만 받아 두는" 준비는 `const iss0 = await issueV11(cia, u, { arid, provider }); assert.equal(iss0.r.status, 200)` 로 하고 그 `iss0.blind_u` 를 이후 발급에 넘긴다(같은 C_u 재사용) |
| `buildIssueRequest({ uid, Cf_u: uc.Cf_u, arid, sk_u, session, chainid, max_height })` + `cia.post('/cia/issue', req.body)` | `const iss = await issueV11(cia, u, { arid, chainid, max_height, blind_u, session })` — 응답은 `iss.r`, 토큰은 `iss.cred` |
| `buildCredentialProof({ uid, arid, s_u, r_u, blind_u: uc.secrets.blind_u, blind_s: req.secrets.blind_s, pk_i: session.pk_i, attrs, credential: issued.body, pk_CIA, pk_trace, tree, registry, slot, cm_u, ... })` | `proveV11(iss, { arid, pk_CIA, pk_trace, provider, logAddress: cia.logAddress, tree?, registry?, disclosure?, tagR? })` |
| `registryLeaf(u.cm_u, Cf_u)` | `registryLeaf(u.auid, Cf_u)` |
| `/cia/issue` 가 403 `no_user_cred` 를 내던 단언 | V11 에는 그 경로가 없다(물린 C_u 재사용은 409 `cred_revoked`, 옛 C_u 와 다른 새 C_u 는 200 + 게시). 단언을 그에 맞게 바꾼다 |
| `/cia/user_cred` 가 201/200/403/409 를 내던 단언 | `issueV11(...).r` 의 200(새 C_u 는 `published:true`, 같은 C_u 는 `false`)/403 `account_disabled`/409 `cred_revoked` |
| `/cia/accounts/:uid/attrs` 로 속성을 바꿔 자격증명을 물리던 트리거 | `issueV11(cia, { ...u, attrs: 다른값 })` 또는 새 `blind_u` 로 발급 — 사용자가 C_u 를 바꾸면 CIA 가 슬롯을 갱신·게시한다 |

파일별 주의:
- `tests/test_cia_registry.mjs`: 첫 케이스의 `base` 본문은 `{ uid, pwd, auid: reg.auid.toString(), pk_u }`, `signRegistration(reg.sk_u, 12345n, reg.auid)`; `'발급: 201 {…published:true} …'` → `issueV11` 200 + `cred.published === true`, 이벤트 리프 `registryLeaf(u.auid, iss.req.Cf_u)`; `'교체: …403 no_user_cred'` → 새 blind_u 발급 뒤 옛 blind_u 로 다시 발급하면 **409 `cred_revoked`**; `'v8 상태 파일 → 기동 시 등록부 생성·게시'` 는 **v12 파일**로 바꿔 "리프가 비어 있는 슬롯을 기동이 채워 게시" 를 본다(`accounts['12345'] = { pk_u, auid: reg.auid, slot: 0, tampered:false, disabled:false, creds:[{Cf_u, C_u_pt, issuedAt, revoked:false}], sessions:[], receipt:null, slotRetired:false }`, `registry.leaves: {}`); `'재기동 백로그 자동 게시'`·`'대조(체인이 앞섬)'`·`'게시 직전 대조'`·`'게시 경합'`·`'은퇴 슬롯 방어'` 는 v12 모양(`auid`, `attrs` 없음)으로 픽스처만 고친다.
- `tests/test_cia_issue_race.mjs`: `userCredBody()`/`issueBody(Cf_u)` 를 지우고 `const issue = (opts) => issueV11(cia, u, { arid, provider, ...opts })` 하나로. `'user_cred 동시 요청 둘 …'` → `'issue 동시 요청 둘(같은 uid, 다른 blind_u): 둘 다 200, 활성 자격증명은 하나, 슬롯은 승자의 리프로 수렴; 패자의 blind_u 로 다시 발급하면 409 cred_revoked'`(패자 = `activeCf_u` 와 다른 쪽). `'user_cred 와 revoke(account) 동시 요청'` → `issue()` 와 `revoke(account)` 동시 — 불변식 `credCount 0` 뒤 `issue()` 는 403. 하트비트 경합 케이스의 `issueOne()` 은 `issueV11(hb, user, { arid, provider, blind_u: fixedBlind, post: (p, b) => hb.post(p, b) })`.
- `tests/test_cia_opening.mjs`: `loginTranscript(svc, pk_trace, allowAgent)` → `const iss = await issueV11(cia, user, { arid: svc.arid, provider, allowAgent, blind_u: user.blind_u }); const { proof, publicSignals, tag } = await proveV11(iss, { arid: svc.arid, pk_CIA, pk_trace, provider, logAddress: cia.logAddress });` (user 는 `userOf(reg, uid)` + 처음 발급에서 받은 `blind_u` 를 보관). `loginTranscriptFor(svc, who, tagR)` 도 같은 모양(+`tagR`). `cia2` 케이스의 재등록은 `cia2.post('/cia/register', { uid:'12345', pwd:'password123', auid: reg.auid.toString(), pk_u: pointToStrings(reg.pk_u), sig_reg: await signRegistration(reg.sk_u, 12345n, reg.auid) })`.
- `tests/test_cia_mirror_relay.mjs`: `buildUserCredRequest`+`/cia/user_cred` → `issueV11` 200(`published:true` 는 보지 않는다 — 기존 주석대로 판정은 SlotUpdated). 동시성 케이스의 `cia.post('/cia/user_cred', cred.body)` → `issueV11(cia, u, { arid, provider })` 를 Promise.all 안에 넣고 `iss.r.status === 200`, `want = registryLeaf(u.auid, iss.req.Cf_u)`, 슬롯은 `iss.cred.slot`.
- `tests/test_mode3_session_revoke.mjs`: `issueWith({ max_height })` → `issueV11(cia, user, { arid, provider, max_height, blind_u: user.blind_u })`(첫 호출 전에 `user.blind_u = randomScalar()`); alice 도 같은 모양(`ALICE_ATTRS`).
- `tests/test_mode3_e2e.mjs`: `ensureUserCred()` 삭제; `newSessionAndIssue()` → `blind_u ??= randomScalar(); const iss = await issueV11(cia, u, { arid, provider, blind_u, r_s: (sessionRs = randomScalar()), r_rp: (sessionRrp = randomScalar()) }); session = iss.session; lastIssued = iss; return iss.r;`; `loginRound()` 의 `buildCredentialProof(...)` → `proveV11(lastIssued, { arid, pk_CIA, pk_trace, tree, registry })`; `submit` 의 `rp.verifyLogin({ …, r_s: sessionRs, r_rp: sessionRrp })`; `'발급 → 슬롯 게시 → 로그인 성공 (공개 입력 30 …)'` → 33, `publicSignals[7]`·`[30..32]` 확인; `'은퇴(scope=credential): … registry_empty; 재발급 뒤 PPID 는 그대로'` → 은퇴 뒤 `blind_u = null`(새 C_u) 로 `newSessionAndIssue()`; `'계정 폐기 → disabled 재발급 거절(403, account_disabled) …'` 의 `/cia/user_cred` 403 단언은 삭제하고 `issueV11` 403 `account_disabled` 만 남긴다.
- `tests/test_mode3_health.mjs:56-75`: `buildUserCredRequest`+`/cia/user_cred` → `issueV11(cia, userOf(reg, uidB, ALICE_ATTRS), { arid, provider })`; 민감값 목록에서 `r_u`·`cm_u_x` 를 빼고 `s_u`·`sk_u`·`Cf_u`·`Cf_s` 는 그대로(+`blind_u`).

- [ ] **Step 1: 위 규칙으로 일곱 파일을 고친다**(각 파일을 열어 `cm_u`·`r_u`·`user_cred`·`buildUserCredRequest`·`issueRequestMessageV4`·`sessionCommit(` 가 남지 않게 한다: `grep -n "cm_u\|r_u\b\|user_cred\|buildUserCredRequest\|issueRequestMessageV4\|proveUserCred" tests/test_cia_*.mjs tests/test_mode3_session_revoke.mjs tests/test_mode3_e2e.mjs tests/test_mode3_health.mjs` 가 비어야 한다).

- [ ] **Step 2: 실행**

Run(:8545 필요): `for f in tests/test_cia_registry.mjs tests/test_cia_issue_race.mjs tests/test_cia_opening.mjs tests/test_cia_mirror_relay.mjs tests/test_mode3_session_revoke.mjs tests/test_mode3_e2e.mjs tests/test_mode3_health.mjs; do echo "== $f"; node "$f" || echo "FAIL $f"; done`
Expected: 일곱 파일 모두 `ok` 만, `FAIL` 줄 없음.

---

### Task 9: 지갑 에이전트 V11 — 상태 v9·`profile` 소유·`/wallet/login`(r_rp·π_IdP)·`PUT /wallet/profile`

**Files:**
- Modify: `mode3_wallet_agent.js`
- Modify: `mode3/rp.html:365-391`(챌린지의 `r_rp` 를 지갑 로그인 본문·팝업 요청에 싣는다), `mode3/wallet.html:401-404`(팝업 로그인 본문에 `r_rp: req.r_rp`)
- Modify: `tests/test_mode3_wallet_agent.mjs` (chain)

**Interfaces:**
- Consumes: Task 5 (`createRegistration(uid)`, `signRegistration`, `signSlotRequest`, `buildIssueRequest`, `buildCredentialProof`, `stripSecrets`, `validateWitness(w, uid, auid)`, `createSecretSource`), Task 7 (`/cia/register`·`/cia/issue` V11), Task 6 (`/api/mode3/challenge` 의 `r_rp`).
- Produces (HTTP): `POST /wallet/register { uid, pwd, profile?, s_u?(snap), sk_u?(snap) } → 201 { uid, slot, auid, attrs, profile }` — `profile` 생략 시 `DEFAULT_PROFILE = { birthYear: '1990', country: 'KR' }`; 인코딩 실패 400 `{ reason:'bad_attr', slot, field, detail }`; `PUT /wallet/profile { profile } → 200 { attrs, profile, changed, attrsChanged?(snap·changed) }`; `POST /wallet/login` 본문에 **`r_rp`(10진, 2^250 미만) 필수** — 없으면 400; 응답은 V10 과 같은 모양(`publicSignals` 33); `GET /wallet/status` 에 `auid` 추가; `POST /wallet/attrs/sync` → 404(삭제). 거절 사유: `user_cred_failed`(502, CIA 가 `bad_idp_proof` — 시연 덮어쓰기), `issue_failed`(502, 그 밖 CIA 오류), `account_disabled`(403), `registry_mismatch`·`registry_slot_unknown`(403), `registry_unpublished`(503).
- Produces (state): `WALLET_STATE_VERSION = 9`; `registration = { uid, s_u, sk_u, pk_u, auid, slot, profile, attrs, userCred }`(snap: `stripSecrets` 결과 — `s_u`·`sk_u` 없음); `sessions[r_s] = { arid, origin, PPID, pk_trace, factoryAddress, attrGateAddress, allowAgent, r_rp, auid_s, arid_s, credential, sessionPrivKey, pk_i, issuedAt, witness? }`; 세션 증인 `{ s_u, blind_u, attrs, sk_u }`.

- [ ] **Step 1: 실패하는 테스트 — `tests/test_mode3_wallet_agent.mjs` V11 이행**

(a) `loginNoRelay` 는 챌린지 두 값을 쓴다 — 헬퍼를 바꾼다:
```js
  const newCh = () => ({ r_s: randomScalar().toString(), r_rp: randomScalar().toString() });
  const loginNoRelay = (ch = newCh(), extra = {}) => wallet.post('/wallet/login', { arid, origin, cert_s, pk_trace: { x: pk_trace.x.toString(), y: pk_trace.y.toString() }, r_s: ch.r_s, r_rp: ch.r_rp, ...extra }, { Origin: stack.rpOriginForWallet });
  const login = (ch = newCh(), extra = {}) => stack.withRelay(() => loginNoRelay(ch, extra));
  const verify = (body, ch) => rp.verifyLogin({ proof: body.proof, publicSignals: body.publicSignals, sig: body.sig, r_s: BigInt(ch.r_s), r_rp: BigInt(ch.r_rp) });
```
  이후 `const rs = newRs(); const r = await login(rs); … verify(r.body, rs)` 꼴은 `const ch = newCh(); const r = await login(ch); … assert.equal(r.body.r_s, ch.r_s); verify(r.body, ch)` 로, 세션 식별자로 쓰던 `S1 = rs` 는 `S1 = ch.r_s`(재검증·request·tx 는 r_s 만 쓴다).
(b) `'등록: AA 속성을 저장하고 본문의 attrs 는 무시한다 …'` →
```js
  await t('등록: profile 없이 → 기본 { 1990, KR }(201, 슬롯 0, auid); profile 을 주면 그 값; 두 번째는 409; 잘못된 pwd 는 CIA 의 401; /wallet/status 에 auid·attrs·profile·slot', async () => {
    const r = await wallet.post('/wallet/register', { uid, pwd: 'password123' });
    assert.equal(r.status, 201, j(r.body));
    assert.deepEqual(Object.keys(r.body).sort(), ['attrs', 'auid', 'profile', 'slot', 'uid']);
    assert.equal(r.body.uid, uid); assert.equal(r.body.slot, 0); assert.match(r.body.auid, /^[0-9]+$/);
    assert.deepEqual(r.body.attrs, ['1990', '410', '0', '0', '0', '0']); assert.deepEqual(r.body.profile, { birthYear: '1990', country: 'KR' });
    assert.equal((await wallet.post('/wallet/register', { uid, pwd: 'password123' })).status, 409);
    assert.equal((await wallet.post('/wallet/register', { uid: '67890', pwd: 'wrong' })).status, 409, '지갑은 한 계정만 — 등록된 뒤에는 CIA 를 부르지 않는다');
    const s = await wallet.get('/wallet/status');
    assert.equal(s.body.registered, true); assert.equal(s.body.uid, uid); assert.equal(s.body.slot, 0); assert.equal(s.body.auid, r.body.auid);
    assert.deepEqual(s.body.attrs, ['1990', '410', '0', '0', '0', '0']); assert.deepEqual(s.body.profile, { birthYear: '1990', country: 'KR' });
    assert.equal(s.body.registry, null, '아직 동기화 전');
    const sch = (await cia.get('/cia/attr_schema')).body;
    assert.deepEqual(s.body.attrSchema, { id: 'zkd-attrs', version: 1, hash: sch.hash });
    assert.deepEqual(s.body.attrsView.map((v) => v.display), ['1990', 'KR', '', '', '', '']);
    const acct = (await cia.adminGet('/cia/accounts')).body.accounts.find((a) => a.uid === uid);
    assert.equal(acct.attrs, undefined, 'D15: IdP 는 속성을 받지 않는다'); assert.equal(acct.auid, undefined, '/cia/accounts 는 auid 를 내지 않아도 된다(계획: 공개 필드 아님)');
  });
```
  (마지막 `acct.auid` 단언은 `/cia/accounts` 가 auid 를 내지 않는 Task 7 구현에 맞춘 것이다 — 내기로 바꿨다면 단언을 `assert.ok(acct.auid)` 로.) 잘못된 pwd 케이스는 **등록 전** 인스턴스가 필요하므로, 이 케이스 앞의 `'미등록 상태: …'` 케이스 끝에 `assert.equal((await wallet.post('/wallet/register', { uid, pwd: 'wrong' })).status, 401, 'CIA 의 401 을 그대로');` 와 `const badAttr = await wallet.post('/wallet/register', { uid, pwd: 'password123', profile: { birthYear: '1800', country: 'KR' } }); assert.equal(badAttr.status, 400); assert.equal(badAttr.body.reason, 'bad_attr'); assert.equal((await wallet.get('/wallet/status')).body.registered, false, '인코딩 실패는 CIA 에 등록하지 않는다');` 를 넣는다.
(c) `'첫 로그인: 자동 발급 …'`: `publicSignals.length` 30 → 33 과 설명 `'V11: 30 + auid_s·arid_s·r_s'`; `assert.equal(r.body.publicSignals[32], ch.r_s)` 추가; 'r_rp 없으면 400' 단언 추가: `assert.equal((await wallet.post('/wallet/login', { arid, origin, cert_s, pk_trace: {...}, r_s: newCh().r_s }, { Origin: stack.rpOriginForWallet })).status, 400)`.
(d) `'관리자가 속성을 바꾸면 다음 로그인이 bad proof → /cia/attrs 재동기화 → …'` → 
```js
  await t('D15: 지갑에서 속성을 바꾸면(PUT /wallet/profile) 옛 C_u·세션이 버려지고 다음 로그인이 새 C_u 로 성공, PPID 동일, IdP 상태에는 속성이 없다', async () => {
    const first = await loginOnce();
    const same = await wallet.put('/wallet/profile', { profile: { birthYear: '1990', country: '410' } });   // 코드 표기 → 정규형 KR, attrs 불변
    assert.equal(same.status, 200, j(same.body)); assert.equal(same.body.changed, false); assert.deepEqual(same.body.profile, { birthYear: '1990', country: 'KR' });
    assert.ok(Object.keys((await wallet.get('/wallet/status')).body.sessions).length > 0, '속성이 그대로면 세션을 버리지 않는다');
    const chg = await wallet.put('/wallet/profile', { profile: { birthYear: '1990', country: 'KR', extra1: 'tier3' } });
    assert.equal(chg.status, 200, j(chg.body)); assert.equal(chg.body.changed, true);
    assert.deepEqual(chg.body.attrs, ['1990', '410', tier3, '0', '0', '0']);
    const st = (await wallet.get('/wallet/status')).body;
    assert.deepEqual(st.sessions, {}, '옛 C_u 위의 세션은 버린다'); assert.equal(st.userCred, null);
    assert.deepEqual(st.profile, { birthYear: '1990', country: 'KR', extra1: 'tier3' });
    const second = await loginOnce();
    assert.equal(second.PPID, first.PPID, 'PPID 는 (uid, s_u, arid, chainid) — 속성과 무관');
    assert.equal(second.timings.userCredMs > 0, true, '새 C_u');
    const bad = await wallet.put('/wallet/profile', { profile: { birthYear: '1800', country: 'KR' } });
    assert.equal(bad.status, 400); assert.equal(bad.body.reason, 'bad_attr');
    assert.equal((await wallet.put('/wallet/profile', { profile: { country: 'KR' } })).body.detail, 'missing_field');
    assert.equal((await wallet.put('/wallet/profile', {})).status, 400);
    const acct = (await cia.adminGet('/cia/accounts')).body.accounts.find((a) => a.uid === uid);
    assert.equal(acct.attrs, undefined); assert.equal(acct.profile, undefined);
  });
```
  (`wallet.put` 이 헬퍼에 없으면 `tests/helpers/isolated_mode3_stack.mjs` 의 wallet 객체에 `put: (p, body, headers = {}) => fetch(..., { method: 'PUT', ... })` 를 `post` 와 같은 모양으로 추가.) `loginOnce()` 는 이 파일의 기존 헬퍼(있으면 `ch` 를 쓰도록 고친다).
(e) `'/wallet/attrs 는 사라졨고(404) /wallet/attrs/sync 는 값을 다시 받는다'` → `'V11: /wallet/attrs·/wallet/attrs/sync 는 404'` (둘 다 404).
(f) `'시연 덮어쓰기(issue): salt 를 바꾸면 AA 가 bad user credential proof 로 거절 …'`: 전제의 `revoke scope=credential` 은 그대로(새 C_u 경로를 타게), 기대 `r.body.cia.error === 'bad idp proof'`, `r.body.cia.reason === 'bad_idp_proof'`, `r.body.reason === 'user_cred_failed'`, `r.body.demo === 'override:issue'`.
(g) `'attrs/sync: CIA 가 죽어 …'` 케이스 삭제.
(h) 마지막 `'지갑 상태 파일 7→8 이행 …'` → 
```js
await t('지갑 상태 파일 8→9 이행: file 모드 등록은 auid 를 s_u 로 재계산해 유지(r_u·cm_u 삭제, 세션 비움), snap 모드(비밀 없음) 등록은 비운다 (+ V10: 거울 주소가 없으면 체인 라우트는 503)', async () => {
  const { auidOf } = await import('../lib/mode3_credential.js');
  const reg = await createRegistration(424242n);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mode3-wallet-v8-'));
  const stateFile = path.join(dir, 'mode3_wallet_state.json');
  fs.writeFileSync(stateFile, JSON.stringify({ version: 8, registration: { uid: '424242', s_u: reg.s_u.toString(), r_u: '1', cm_u: { x: '1', y: '2' }, sk_u: reg.sk_u, pk_u: { x: reg.pk_u.x.toString(), y: reg.pk_u.y.toString() }, slot: 3, attrs: ['1990', '410', '2', '0', '0', '0'], profile: { birthYear: '1990', country: 'KR' }, userCred: { Cf_u: '9' } }, sessions: { '5': {} } }));
  const stack2 = await startIsolatedMode3Stack({ rp: false, walletEnv: { MODE3_WALLET_STATE_FILE: stateFile, MODE3_MIRROR_ADDRESS: '' } });
  try {
    const s = (await stack2.wallet.get('/wallet/status')).body;
    assert.equal(s.registered, true); assert.equal(s.uid, '424242'); assert.equal(s.slot, 3);
    assert.equal(s.auid, (await auidOf({ uid: 424242n, s_u: reg.s_u })).toString(), 'auid 는 s_u 로 재계산');
    assert.deepEqual(s.attrs, ['1990', '410', '2', '0', '0', '0']); assert.deepEqual(s.sessions, {}); assert.equal(s.userCred, null);
    const onDisk = JSON.parse(fs.readFileSync(stateFile, 'utf8'));
    assert.equal(onDisk.version, 9); assert.equal(onDisk.registration.r_u, undefined); assert.equal(onDisk.registration.cm_u, undefined); assert.ok(onDisk.registration.auid);
    const pre = await stack2.wallet.post('/wallet/authorize/precheck', { arid: '1', origin: 'http://x', cert_s: {}, pk_trace: { x: '1', y: '2' } });
    assert.equal(pre.status, 503, j(pre.body)); assert.equal(pre.body.detail, 'MODE3_MIRROR_ADDRESS not configured');
  } finally { await stack2.stop(); }
  fs.writeFileSync(stateFile, JSON.stringify({ version: 8, registration: { uid: '424242', cm_u: { x: '1', y: '2' }, pk_u: { x: '1', y: '2' }, slot: 0, attrs: ['1990', '410', '0', '0', '0', '0'], userCred: null }, sessions: {} }));
  const stack3 = await startIsolatedMode3Stack({ rp: false, walletEnv: { MODE3_WALLET_STATE_FILE: stateFile, MODE3_WALLET_SECRETS: 'snap', MODE3_MIRROR_ADDRESS: '' } });
  try { assert.equal((await stack3.wallet.get('/wallet/status')).body.registered, false, 'snap 모드 옛 등록은 auid 를 재계산할 수 없어 비운다'); }
  finally { await stack3.stop(); fs.rmSync(dir, { recursive: true, force: true }); }
});
```
(i) 그 밖 `no_user_cred`·`user_cred_retired` 를 기대하는 단언이 있으면 지운다(V11 경로 없음).

- [ ] **Step 2: `mode3_wallet_agent.js` 편집**

(a) import 를 바꾼다:
```js
import { createSecretSource, stripSecrets, validateWitness } from './lib/mode3_secret_source.js';
import { DEFAULT_ATTR_SCHEMA, loadSchema, assertPredicateTypes, decodeAttrs, schemaInfo, encodeProfile, normalizeProfile } from './lib/mode3_attr_schema.js';
import { createRegistration, createSessionKey, buildIssueRequest, buildCredentialProof, signChallenge, signSessionRequest, signSlotRequest, signRevokeSession, signRegistration, eddsaPubOf, normalizeDisclosure, normalizeSet, disclosureKey, hasPredicate, ProofCache, chooseMaxHeight, syncRegistryTree } from './lib/mode3_wallet.js';
import { normalizeAttrs, SCALAR_MAX, ppid, randomScalar, auidOf } from './lib/mode3_credential.js';
```
(`pointToStrings` import 는 `/wallet/register` 가 더 쓰지 않으면 지운다.) 머리 주석에 `// V11(2026-10-12): 속성은 사용자가 지갑에 넣는다(profile → attrs, D15), 발급마다 π_IdP, RP 챌린지 r_rp, 상태 v9.` 한 줄.

(b) 상태 블록(75~109행)을 교체:
```js
// ---- 상태 ----
// registration: { uid, s_u, sk_u, pk_u:{x,y}, auid(10진), slot, profile:{스키마 이름→값}, attrs:[6개 10진], userCred: { C_u_pt:{x,y}, Cf_u, blind_u, issuedAt } | null }
// sessions:     r_s → { arid, origin, PPID, pk_trace:{x,y}, factoryAddress|null, attrGateAddress|null, allowAgent("0"|"1"), r_rp, auid_s, arid_s,
//                       credential:{Cf_u,Cf_s,max_height,chainid,allowAgent,sigma,pk_CIA,slot,regRoot,epoch,published}, sessionPrivKey, pk_i, issuedAt,
//                       witness?: { s_u, blind_u, attrs, sk_u } }   ← snap 모드 전용, 메모리에만(persist 가 뺀다)
// snap 모드의 registration 은 stripSecrets 결과({ uid, auid, pk_u, slot, profile, attrs, userCred:{Cf_u,issuedAt} }) 다.
// version 9 (2026-10-12, V11): r_u·cm_u 삭제, auid(= Poseidon(T_AUID, uid, s_u))·profile(사용자 입력, D15) 추가; 세션에 r_rp·auid_s·arid_s.
//   옛 파일은 등록만 유지하고(file 모드 — auid 를 s_u 로 재계산; snap 모드는 비밀이 없어 재계산할 수 없으므로 등록을 비운다) 세션·userCred 를 비운다.
const WALLET_STATE_VERSION = 9;
const DEFAULT_PROFILE = Object.freeze({ birthYear: '1990', country: 'KR' });   // 데모 testuser 기본값(스펙 §7). 사용자가 등록 폼에서 바꿀 수 있다.
let state = readJson(STATE_FILE, { version: WALLET_STATE_VERSION, registration: null, sessions: {} });
function persist() { writeJsonAtomic(STATE_FILE, JSON.parse(JSON.stringify(state, (k, v) => (k === 'witness' ? undefined : v))), 0o600); }
function padAttrs6(attrs) { return [...(Array.isArray(attrs) ? attrs : []), '0', '0', '0', '0', '0', '0'].slice(0, 6).map(String); }
if (state.version !== WALLET_STATE_VERSION) {
  console.warn(`[wallet] 상태 파일 버전 ${state.version} → ${WALLET_STATE_VERSION}: 세션·credential 을 비운다(옛 형식). 등록은 file 모드에서만 유지(auid 재계산).`);
  const reg = state.registration ?? null;
  let kept = null;
  if (reg && typeof reg.s_u === 'string' && /^[0-9]+$/.test(reg.s_u) && typeof reg.uid === 'string') {
    kept = { uid: reg.uid, s_u: reg.s_u, sk_u: reg.sk_u, pk_u: reg.pk_u ?? null, auid: (await auidOf({ uid: BigInt(reg.uid), s_u: BigInt(reg.s_u) })).toString(), slot: reg.slot ?? null, profile: reg.profile ?? { ...DEFAULT_PROFILE }, attrs: padAttrs6(reg.attrs), userCred: null };
  } else if (reg) console.warn('[wallet] snap 모드 등록(파일에 비밀 없음)은 auid 를 재계산할 수 없어 등록을 비운다 — 다시 등록한다(Snap 쪽 "초기화" 도 함께)');
  state = { version: WALLET_STATE_VERSION, registration: kept, sessions: {} };
  persist();
}
```
(이어지는 `state.sessions ??= {}; if (state.registration) { … padAttrs6 … }` 블록은 그대로.)

(c) `syncAttrsFromCia` 함수 삭제. `registryCheck`·`mirrorLeafMatches` 의 `registryLeaf({ x: BigInt(reg.cm_u.x), y: BigInt(reg.cm_u.y) }, BigInt(uc.Cf_u))` → `registryLeaf(BigInt(reg.auid), BigInt(uc.Cf_u))`(두 곳). `ensureUserCred` 함수 삭제. `issueSession` 교체:
```js
/** 사용자 자격증명 선택(V11 — 옛 ensureUserCred). 들고 있는 C_u 가 등록부에서 내 슬롯에 살아 있으면 재사용(blind_u 그대로), 없거나 은퇴(슬롯 0)면 새 blind_u.
 *  남의 리프면 registry_mismatch — 신원 기관의 부정(또는 내가 모르는 재발급). 돌려주는 값: { blind_u, fresh } 또는 { status:403, reason, registry? }. */
async function chooseUserCred(synced, src) {
  const reg = src.registration();
  const uc = src.userCred();
  if (!uc) return { blind_u: randomScalar(), fresh: true };
  const chk = await registryCheck(canonicalView(synced), reg, uc);   // V10: 캐노니컬 최신 — 은퇴·바꿔치기를 거울보다 먼저 안다
  if (!chk) return { status: 403, reason: 'registry_slot_unknown' };
  if (chk.match) return { blind_u: BigInt(uc.blind_u), fresh: false };
  if (chk.leaf !== '0') return { status: 403, reason: 'registry_mismatch', registry: chk };
  return { blind_u: randomScalar(), fresh: true };   // 슬롯 0: 은퇴됐다 — 새로 받는다
}

/** 세션 발급(V11 §5.2): C_u(blind_u)·C_s·π_IdP 를 한 요청으로. 200 이면 세션을 저장하고, 새 C_u 였으면 사용자 자격증명도 바꿔 앉힌다(옛 세션은 함께 버린다). */
async function issueSession({ arid, r_s, r_rp, pk_trace, allowAgent, factoryAddress, attrGateAddress, head, src, blind_u }) {
  const reg = src.registration();
  const session = createSessionKey();
  const chainid = await chainId();
  const ov = takeOverride('issue');   // 시연(설계 §8.3): 이번 발급의 s_u·uid 를 한 번만 덮어쓴다 — 가짜 auid 로 증명돼 CIA 가 bad_idp_proof 를 낸다
  const req = await buildIssueRequest({
    uid: BigInt(ov?.uid ?? reg.uid), s_u: BigInt(ov?.s_u ?? reg.s_u), blind_u, attrs: (reg.attrs ?? []).map(BigInt), arid: BigInt(arid), r_rp, r_s,
    sk_u: reg.sk_u, session, chainid, allowAgent: BigInt(allowAgent), max_height: chooseMaxHeight(head, { ttlBlocks: TTL_BLOCKS, grid: HEIGHT_GRID }),
  });
  if (ov?.uid) req.body.uid = reg.uid;   // 요청 본문의 uid 는 진짜 — C_u·π_IdP 안의 uid 만 바뀐다(스펙 §8.3)
  const r = await ciaPost('/cia/issue', req.body);
  if (r.status !== 200) return { r, demo: ov ? 'override:issue' : undefined };
  // V10(§4.5): 계정 폐기로 슬롯이 은퇴된 뒤 되살아난 계정의 재발급은 새 슬롯을 받는다 — 응답의 슬롯을 따른다.
  if (Number.isInteger(r.body?.slot) && r.body.slot >= 0 && r.body.slot !== state.registration.slot) state.registration.slot = r.body.slot;
  const uc = src.userCred();
  if (!uc || uc.Cf_u !== req.Cf_u.toString()) replaceUserCred(src, { C_u_pt: { x: req.C_u_pt.x.toString(), y: req.C_u_pt.y.toString() }, Cf_u: req.Cf_u.toString(), blind_u: blind_u.toString(), issuedAt: new Date().toISOString() });
  const PPID = await ppid({ uid: BigInt(reg.uid), s_u: BigInt(reg.s_u), arid: BigInt(arid), chainid });
  state.sessions[r_s.toString()] = {
    arid, PPID: PPID.toString(), pk_trace: { x: pk_trace.x.toString(), y: pk_trace.y.toString() }, factoryAddress, attrGateAddress, allowAgent,
    r_rp: r_rp.toString(), auid_s: req.auid_s.toString(), arid_s: req.arid_s.toString(),
    credential: r.body, sessionPrivKey: session.wallet.privateKey, pk_i: session.pk_i.toString(), issuedAt: new Date().toISOString(),
  };
  persist();
  return { r, demo: ov ? 'override:issue' : undefined };
}
```
(`replaceUserCred` 는 그대로 — 세션·캐시를 비운 뒤 위에서 새 세션을 넣는다.)

(d) `secretSourceFor` 의 증인 재조립 `w = { uid: …, s_u: sw.s_u, r_u: sw.r_u, sk_u: sw.sk_u, attrs: sw.attrs, userCred: {...} }` → `r_u` 삭제; 주석의 r_u 문단 삭제. `setSessionWitness`: `s.witness = { s_u: reg.s_u, blind_u: uc?.blind_u ?? null, attrs: reg.attrs, sk_u: reg.sk_u };`. `validateWitness(witness, state.registration.uid, state.registration.cm_u)` 세 곳 → `validateWitness(witness, state.registration.uid, state.registration.auid)`.

(e) `/wallet/status` 응답에 `auid: reg?.auid ?? null,` 추가(`uid` 옆).

(f) `/wallet/register` 교체:
```js
// V11 §3.1·§3.3 — 등록 키(sk_u/pk_u)·salt(s_u) 는 지갑이 만들고 auid = Poseidon(T_AUID, uid, s_u) 를 CIA 에 낸다. 속성은 **사용자가 넣는다**(D15):
// 본문 profile(스키마 이름→값, 기본 DEFAULT_PROFILE)을 공개 스키마로 인코딩해 attrs 를 만든다 — IdP 는 받지 않는다.
// snap 모드(metamask-snap §4.1): s_u·sk_u 는 Snap 이 만들고 페이지가 한 번 넘긴다(로그인 증인과 같은 모델). 파일에는 stripSecrets 결과만 남는다.
app.post('/wallet/register', async (req, res) => {
  try {
    const { uid, pwd, profile: profileIn = null, s_u: suIn, sk_u: skIn } = req.body ?? {};
    if (!isDec(uid) || typeof pwd !== 'string') return res.status(400).json({ error: 'uid(10진 문자열), pwd 필요' });
    if (BigInt(uid) >= SCALAR_MAX) return res.status(400).json({ error: 'uid 는 2^250 미만' });
    if (SECRETS === 'snap' && !(isDec(suIn) && BigInt(suIn) < SCALAR_MAX && typeof skIn === 'string' && /^[0-9a-fA-F]{64}$/.test(skIn))) return res.status(400).json({ error: 'snap 모드는 s_u(10진, 2^250 미만)·sk_u(hex) 필요' });
    if (profileIn !== null && (typeof profileIn !== 'object' || Array.isArray(profileIn))) return res.status(400).json({ reason: 'bad_attr', detail: 'profile_required' });
    if (state.registration) return res.status(409).json({ reason: 'already_registered', uid: state.registration.uid });
    let schema;
    try { schema = (await schemaFor()).schema; } catch (e) { if (e.reason === 'schema_invalid') return res.status(503).json({ reason: 'schema_invalid', detail: e.message }); throw e; }
    const profile = profileIn ?? { ...DEFAULT_PROFILE };
    let attrs;
    try { attrs = await encodeProfile(schema, profile, { allowEmptyRequired: false }); }
    catch (e) { if (e.reason === 'bad_attr') return res.status(400).json({ reason: 'bad_attr', slot: e.slot, field: e.field, detail: e.detail, message: e.message }); throw e; }
    const normalized = normalizeProfile(schema, profile);
    const reg = SECRETS === 'snap' ? { s_u: BigInt(suIn), sk_u: skIn, auid: await auidOf({ uid: BigInt(uid), s_u: BigInt(suIn) }), pk_u: await eddsaPubOf(skIn) } : await createRegistration(BigInt(uid));
    const pub = { x: reg.pk_u.x.toString(), y: reg.pk_u.y.toString() };
    const r = await ciaPost('/cia/register', { uid, pwd, auid: reg.auid.toString(), pk_u: pub, sig_reg: await signRegistration(reg.sk_u, BigInt(uid), reg.auid) });
    if (r.status !== 201) {
      const status = r.status === 401 || r.status === 409 ? r.status : 502;
      return res.status(status).json({ reason: 'register_failed', cia: r.body });
    }
    await noteSchemaHint(r.body.schemaHash ?? null);
    const full = { uid, s_u: reg.s_u.toString(), sk_u: reg.sk_u, pk_u: pub, auid: reg.auid.toString(), slot: r.body.slot, profile: normalized, attrs, userCred: null };
    state.registration = SECRETS === 'snap' ? stripSecrets(full) : full;
    persist();
    res.status(201).json({ uid, slot: r.body.slot, auid: reg.auid.toString(), attrs, profile: normalized });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// V11 §3.3 — 사용자가 속성을 바꾼다. 스키마 검증 → attrs 재인코딩 → 바뀌었으면 옛 C_u·세션·π 캐시를 버린다(다음 로그인이 새 C_u 를 발급받는다 — PPID 는 그대로).
// snap 모드는 응답의 attrsChanged 를 페이지가 Snap 의 syncAttrs 에 전달한다(Snap 이 자기 userCred 를 버린다). 비밀이 필요 없어 증인은 받지 않는다.
app.put('/wallet/profile', async (req, res) => {
  try {
    if (!state.registration) return res.status(409).json({ reason: 'not_registered' });
    const profile = req.body?.profile;
    if (!profile || typeof profile !== 'object' || Array.isArray(profile)) return res.status(400).json({ reason: 'bad_attr', detail: 'profile_required' });
    let schema;
    try { schema = (await schemaFor()).schema; } catch (e) { if (e.reason === 'schema_invalid') return res.status(503).json({ reason: 'schema_invalid', detail: e.message }); throw e; }
    let attrs;
    try { attrs = await encodeProfile(schema, profile, { allowEmptyRequired: false }); }
    catch (e) { if (e.reason === 'bad_attr') return res.status(400).json({ reason: 'bad_attr', slot: e.slot, field: e.field, detail: e.detail, message: e.message }); throw e; }
    const normalized = normalizeProfile(schema, profile);
    const changed = JSON.stringify(attrs) !== JSON.stringify(state.registration.attrs ?? []);
    state.registration.profile = normalized;
    if (changed) { state.registration.attrs = attrs; state.registration.userCred = null; state.sessions = {}; cache.clear(); }
    persist();
    res.json({ attrs, profile: normalized, changed, ...(SECRETS === 'snap' && changed ? { attrsChanged: attrs } : {}) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
```

(g) `/wallet/login`:
- 본문 구조분해에 `r_rp` 추가, 형식 검사 `!isDec(r_s) || !isDec(r_rp)` → 400 `'arid, origin, cert_s, pk_trace{x,y}, r_s, r_rp 필요'`; `const rs = BigInt(r_s), rrp = BigInt(r_rp); if (rs >= SCALAR_MAX || rrp >= SCALAR_MAX) return res.status(400).json({ error: 'r_s·r_rp 는 2^250 미만' });`
- 슬롯 되찾기의 `signAttrsRequest` → `signSlotRequest`.
- `ensureUserCred` 호출부터 `issue()` 재시도 블록까지(`let uc = await ensureUserCred(...)` ~ `if (r.status !== 200) return 502 issue_failed`)를 교체:
```js
    pruneSessions(synced.head);
    // V11: 사용자 자격증명은 발급 요청에 함께 실려 간다 — 들고 있는 C_u 를 재사용할지(등록부에 살아 있음) 새로 만들지(없음·은퇴)를 먼저 정한다.
    const pick = await chooseUserCred(synced, src);
    if (pick.status === 403) return res.status(403).json({ reason: pick.reason, ...(pick.registry ? { registry: pick.registry } : {}), timings });
    t = Date.now();
    const issued = await issueSession({ arid, r_s: rs, r_rp: rrp, pk_trace: { x: BigInt(pk_trace.x), y: BigInt(pk_trace.y) }, allowAgent, factoryAddress: factoryAddress ? ethers.getAddress(factoryAddress) : null, attrGateAddress: attrGateAddress ? ethers.getAddress(attrGateAddress) : null, head: synced.head, src, blind_u: pick.blind_u });
    timings.issueMs = Date.now() - t;
    timings.userCredMs = pick.fresh ? timings.issueMs : 0;   // 새 C_u 를 받은 로그인만 0 이 아니다(옛 의미 유지 — 테스트·화면이 본다)
    const r = issued.r;
    if (r.status === 403) return res.status(403).json({ reason: 'account_disabled', timings });
    if (r.status === 400 && r.body?.reason === 'bad_idp_proof') return res.status(502).json({ reason: 'user_cred_failed', cia: r.body, demo: issued.demo, timings });
    if (r.status !== 200) return res.status(502).json({ reason: 'issue_failed', cia: r.body, demo: issued.demo, timings });
```
- 그 아래 `if (uc.fresh || !(await mirrorLeafMatches(...)))` → `if (pick.fresh || !(await mirrorLeafMatches(synced, src.registration(), src.userCred())))`.
- `timings` 초기값은 `{ syncMs: 0, userCredMs: 0, issueMs: 0, proveMs: 0 }` 그대로.

(h) `proveSession` 의 `buildCredentialProof({...})` 인자를 교체:
```js
        return await buildCredentialProof({
          uid: BigInt(ov?.uid ?? reg.uid), arid: BigInt(s.arid), s_u: BigInt(ov?.s_u ?? reg.s_u), auid: BigInt(reg.auid), blind_u: BigInt(uc.blind_u),
          r_rp: BigInt(s.r_rp), r_s: BigInt(rsKey), pk_i: BigInt(s.pk_i), attrs: (reg.attrs ?? []).map(BigInt),
          credential: s.credential, pk_CIA: { x: BigInt(s.credential.pk_CIA.x), y: BigInt(s.credential.pk_CIA.y) },
          pk_trace: { x: BigInt(s.pk_trace.x), y: BigInt(s.pk_trace.y) }, tree, registry, slot: reg.slot, disclosure,
        });
```

(i) `/wallet/attrs/sync` 라우트(주석 포함) 삭제. 머리 주석의 V6 문단(`/wallet/attrs/sync` 언급) 을 "V11: 속성은 지갑의 profile — PUT /wallet/profile" 로.

(j) 페이지 두 줄: `mode3/rp.html` 365행 `const { r_s, factoryAddress, attrGateAddress } = ch;` → `const { r_s, r_rp, factoryAddress, attrGateAddress } = ch;`; 376행 `authorizeRequest({ r_s, allowAgent, … })` 에 `r_rp,` 추가; 391행 `/wallet/login` 본문에 `r_rp,` 추가. `mode3/wallet.html` 402행 `r_s: req.r_s,` 뒤에 `r_rp: req.r_rp,` 추가.

(k) `node --check mode3_wallet_agent.js`.

- [ ] **Step 3: 실행**

Run(:8545 필요): `node tests/test_mode3_wallet_agent.mjs`
Expected: 전부 `ok`.

---

### Task 10: 데모 스택 HTTP 테스트 V11 각본

**Files:**
- Modify: `tests/test_mode3_demo_stack.mjs`, `tests/test_mode3_demo_full.mjs`, `tests/test_mode3_custom_schema.mjs`, `tests/helpers/isolated_mode3_stack.mjs`(wallet 객체에 `put`)

**Interfaces:**
- Consumes: Task 9 의 지갑 라우트(`/wallet/register { profile }`, `PUT /wallet/profile`, `/wallet/login { r_rp }`), Task 7·8 헬퍼(`issueV11`·`proveV11`·`userOf`·`ALICE_ATTRS`), Task 6 의 RP(`challenge → r_rp`).

- [ ] **Step 1: `tests/helpers/isolated_mode3_stack.mjs`** — `wallet` 객체(와 `rp`·`cia` 가 쓰는 같은 팩토리)에 `put: (p, body, headers = {}) => fetch(`${base}${p}`, { method: 'PUT', headers: { 'Content-Type': 'application/json', ...headers }, body: JSON.stringify(body ?? {}) }).then(json)` 를 `post` 옆에 추가(이미 Task 9 에서 넣었다면 생략).

- [ ] **Step 2: `tests/test_mode3_demo_stack.mjs`**

- `loginViaRp` / `revalidateViaRp`(34~47행): 챌린지에서 `r_rp` 도 받아 `/wallet/login` 본문에 싣는다(`const { r_s, r_rp, factoryAddress, attrGateAddress } = …; … r_s, r_rp, allowAgent: '0', …`). 반환에 `r_rp` 추가.
- `ensureAlice()`: `aliceReg = { user: userOf(reg, 67890n, ALICE_ATTRS), blind_u: randomScalar() }` 로(`sk_u`·`attrs` 는 user 안).
- `makeAliceAgent()`: `buildUserCredRequest`+`/cia/user_cred`+`buildIssueRequest`+`/cia/issue` → `const iss = await issueV11(cia, user, { arid, chainid: chainId, provider, blind_u: aliceReg.blind_u })`(세션키는 `iss.session`); `tx()`·`login()` 안의 `buildCredentialProof(...)` → `proveV11(iss, { arid, pk_CIA, pk_trace, tree, registry, disclosure })`; `login(rs, disclosure)` 는 **RP 챌린지의 r_s·r_rp 가 아니라 자기 발급의 r_s** 로만 통과하므로, 호출부(`'각본 12'`·`'13. 선택 공개(HTTP)'`)는 챌린지를 받은 뒤 그 `{ r_s, r_rp }` 로 **새 발급**을 하도록 `makeAliceAgent().loginWith(ch, disclosure)` 를 추가한다: `async function loginWith(ch, disclosure) { const i = await issueV11(cia, user, { arid, chainid: chainId, provider, blind_u: aliceReg.blind_u, r_s: BigInt(ch.r_s), r_rp: BigInt(ch.r_rp) }); assert.equal(i.r.status, 200, j(i.r.body)); await stack.relayIfBehind(); const built = await proveV11(i, { arid, pk_CIA, pk_trace, provider, logAddress: cia.logAddress, disclosure }); return { proof: built.proof, publicSignals: built.publicSignals, sig: await signChallenge(i.session.wallet, ch.r_s) }; }`. 기존 `login(rs, disclosure)` 는 지운다.
- `'1. 등록'`: `wallet.post('/wallet/register', { uid, pwd: 'password123', attrs: [...] })` → `{ uid, pwd: 'password123' }`(기본 profile).
- `'session_mismatch'` 케이스(205~232행): alice 발급을 `issueV11(cia, aliceUser, { arid: BigInt(info.arid), chainid: BigInt(info.chainId), provider, blind_u, r_s: BigInt(mine.r_s), r_rp: BigInt(mine.r_rp) })` 로 하고 `proveV11` 로 증명 — RP 가 세션의 r_rp 로 arid_s 를 검사하므로 **같은 챌린지의 r_rp** 를 써야 `session_mismatch` 까지 간다(다른 r_rp 면 `bad_arid_s` 가 먼저). 기대는 그대로 401 `session_mismatch`.
- `'12. 선택 공개: 관리자가 testuser a₂ 를 3 으로 → …'` → `'12. 속성 변경(D15): 지갑 PUT /wallet/profile 로 extra1 → 세션 비움 → 다음 로그인이 새 C_u·PPID 동일'`: `cia.adminPost('/cia/accounts/…/attrs', …)` 두 줄과 `published` 단언 → `const chg = await wallet.put('/wallet/profile', { profile: { birthYear: '1990', country: 'KR', extra1: 'tier3' } }); assert.equal(chg.status, 200, j(chg.body)); assert.equal(chg.body.changed, true);`; 뒤의 `/cia/publish` 단언 삭제(게시는 다음 로그인의 발급이 한다 — `after.wallet.timings.userCredMs > 0` 로 확인); `status.attrs` 단언은 그대로.
- `'C-4: 재검증이 …'`(455~500행): `issue(allowAgent, ttl)` → `issueV11(cia, aliceUser, { arid, chainid, provider, blind_u, allowAgent, max_height, r_s: BigInt(r_s), r_rp: BigInt(r_rp), session })`(같은 세션키 재사용 — `session` 옵션), `prove(c, rs)` → `proveV11(c, {...})` + `sig: signChallenge(session.wallet, rs)`; 챌린지 `{ r_s, r_rp }` 를 먼저 받아 두 발급 모두에 같은 값을 쓴다(로그인·재검증이 같은 세션).
- `'각본 11(V9): 시연 카드 …'`: 기대 `cia.error === 'bad idp proof'`, 이름 "(V11)".
- `'Ruling 1: 세션 요청도 root 나이로 …'`(781~810행): 나이를 0 으로 만드는 트리거 `cia.adminPost('/cia/accounts/…/attrs', …)` 두 곳 → `wallet.put('/wallet/profile', { profile: { birthYear: '1991', country: 'KR', extra1: 'tier3' } })`(두 번째는 `'1992'`) 뒤 `loginViaRp()` — 새 C_u 의 게시가 나이를 0 으로 되돌린다; `published`·`/cia/publish` 단언은 삭제.
- 그 밖 `/cia/user_cred`·`buildUserCredRequest`·`cm_u`·`r_u` 가 남지 않게 한다.

- [ ] **Step 3: `tests/test_mode3_demo_full.mjs`**

- `loginViaRp(rp, …)`(51~61행): 챌린지에서 `r_rp` 를 받아 `/wallet/login` 본문에 싣고 반환에 포함.
- `'막 8. 복구 — … (발급 덮어쓰기 시연: user_cred_failed) …'`: 기대 `badSalt.wallet.reason === 'user_cred_failed'` 그대로, `badSalt.wallet.cia?.reason === 'bad_idp_proof'` 추가.
- 등록 막(`wallet.post('/wallet/register', …)`)이 `attrs` 를 보내면 지운다.

- [ ] **Step 4: `tests/test_mode3_custom_schema.mjs`**

- `(가)`: `reg.body.attrs` 기대 `['1990', '0', '410', '0', '0', '0']` 는 **지갑이** 인코딩한 값이므로 그대로 성립(지갑이 IdP 스키마를 받아 `DEFAULT_PROFILE` 을 인코딩). `reg.body.profile` 기대도 그대로. `loginWithRequire(stack, …)` 헬퍼가 챌린지의 `r_rp` 를 지갑에 싣도록 고친다.
- `(나)`: `reg.body.profile` 기대 `{ birthYear: '1990' }` — 지갑의 `normalizeProfile` 이 스키마에 없는 `country` 를 버리는지 확인; 버리지 않고 400 `bad_attr`(unknown field) 를 내면 **지갑 `/wallet/register` 가 `DEFAULT_PROFILE` 을 스키마에 맞게 걸러 쓰도록**(`Object.fromEntries(Object.entries(profile).filter(([k]) => schema.slots.some((s) => s.type !== 'unused' && s.name === k)))` — 기본값일 때만) Task 9 의 코드를 보강한다(이 보강은 cia.js V10 의 "관대하게 맞춘다" 와 같은 뜻).
- 세 번째 케이스 `'데모 계정 profile 을 인코딩할 수 없는 스키마(US 없음 — alice)는 CIA 가 기동 거부'` → V11 에서 CIA 는 데모 계정 속성을 인코딩하지 않으므로 **기동한다**. 케이스를 `'(다) 데모 기본 profile 을 인코딩할 수 없는 스키마(KR 없음): CIA 는 뜨고, 지갑 등록이 400 bad_attr(지갑이 거절), profile 을 그 스키마에 맞게 주면 201'` 로 바꾼다 — `SCHEMA_C` 가 country 표에서 US 만 빼는 것이라면 KR 도 빼는 변형 `SCHEMA_D` 를 만들어 쓴다.

- [ ] **Step 5: 실행**

Run(:8545 필요, `tests/test_mode3_demo_full.mjs` 는 :8546 노드를 스스로 띄운다): `node tests/test_mode3_demo_stack.mjs && node tests/test_mode3_custom_schema.mjs && node tests/test_mode3_demo_full.mjs`
Expected: 전부 `ok`.

---

### Task 11: Snap·지갑/관리자 화면·문구 — 속성 편집, cm_u 제거, 새 사유

**Files:**
- Modify: `snap-mode3/src/crypto.js`(전면 교체), `snap-mode3/src/index.js`(`register`·`storeRegistration`·`getPublicInfo`·`buildWitness`·`reset` 문구), `snap-mode3/test/rpc.test.mjs`
- Modify: `tests/helpers/snap_sim.mjs`
- Modify: `mode3/wallet.html`(내 신원 카드: 속성 입력 가능 + "저장", "신원 기관에서 다시 받기" 삭제, 등록 본문 profile·snap s_u, Snap 상태 표시), `mode3/cia_admin.html`(속성 열·저장 삭제), `mode3/common/strings.js`
- Modify: `tests/test_mode3_wallet_snap.mjs`, `tests/test_mode3_browser.mjs`, `tests/test_mode3_tour.mjs`, `tests/test_mode3_demo_strings.js`
- Rebuild: `snap-mode3/dist/bundle.js`(`cd snap-mode3 && npm run build` — `snap-mode3/node_modules` 가 있어야 한다; 없으면 보고하고 넘긴다)

**Interfaces:**
- Produces (Snap RPC): `register → { uid, pwd, s_u, sk_u }`(cm_u 없음 — s_u 는 sk_u 와 같은 "한 번 넘기는" 모델); `storeRegistration({ attrs, slot, auid })`(auid 는 10진, 공개); `getPublicInfo → { registered, uid, auid, attrs, slot, hasUserCred, consents }`; 증인 `{ uid, s_u, sk_u, attrs, userCred }`; 상태 `registration { uid, s_u, sk_u, auid, slot, attrs, registeredAt }`. `syncAttrs`·`updateUserCred`·`consentLogin`·그 밖은 불변.
- Produces (strings.js): `reasons` 추가 `bad_idp_proof`(where `aa`), `bad_r_s`·`bad_arid_s`(where `rp`), `cred_revoked`(where `aa`); 삭제 `attrs_failed`, `use_profile`, `no_user_cred`, `user_cred_retired`; `bad_attr` 의 where → `wallet`; `user_cred_failed` 문구 → "신원 기관이 π_IdP 를 거절했습니다 …"; ui 추가 `wallet_profile_save_btn`(`속성 저장`/`Save attributes`), `wallet_profile_saved`, `wallet_profile_failed`, `wallet_profile_changed`(`속성을 바꿨습니다: {attrs}. 옛 자격증명과 세션은 버려졌고 다음 로그인이 새로 받습니다.`), `wallet_profile_same`; 삭제 `wallet_attrs_btn`, `wallet_attrs_ok`, `wallet_attrs_failed`, `wallet_attrs_changed`, `wallet_attrs_same`, `admin_accounts_attrs_note`, `admin_col_attrs`, `admin_attrs_title`, `admin_attrs_summary`, `admin_attrs_failed`; 문구 갱신 `wallet_identity_desc`(`신원 기관에 한 번 등록합니다. 속성은 내가 지갑에 넣고 기관은 모릅니다.`), `wallet_registered_summary`(`uid {uid} 로 등록했습니다. 내 속성: {attrs}`), `admin_accounts_desc`(`등록된 계정과 로그인 세션을 폐기합니다.`), `revoked` 의 cause 에서 "속성 변경 등" → "내가 지갑에서 속성을 바꾼 뒤 재발급 등".

- [ ] **Step 1: Snap**

`snap-mode3/src/crypto.js` 전면 교체:
```js
// 등록 비밀 생성 — lib/mode3_credential.js 의 randomScalar 를 Snap 번들에 맞게 옮겨 적은 것(스펙 2026-09-22 metamask-snap §3.1, V11 갱신).
// V11(2026-10-12): 등록 비밀은 { s_u, sk_u } 둘이다. 등록 커밋 cm_u(Baby Jubjub 스칼라곱)는 없어졌고, 등록 가명 auid = Poseidon(T_AUID, uid, s_u) 는
// Snap 에 Poseidon 이 없어(WASM 권한 없음) 에이전트가 계산한다 — 그래서 register 는 s_u 를 sk_u 와 함께 **한 번** 페이지로 넘긴다(로그인 증인과 같은 모델).
export const SCALAR_MAX = 1n << 250n;   // 회로 Num2Bits(250) 과 같은 상한

/** lib/mode3_credential.js 의 randomScalar — 32바이트를 250비트로 자른다. */
export function randomScalar() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  let v = 0n;
  for (const b of bytes) v = (v << 8n) | BigInt(b);
  return v & (SCALAR_MAX - 1n);
}

/** 등록 한 벌 — s_u·sk_u 는 Snap 상태에 남고 register 응답으로 한 번 나간다. sk_u 는 32바이트 16진(250비트로 자르지 않는다). */
export function createRegistrationSecrets() {
  const sk = new Uint8Array(32);
  crypto.getRandomValues(sk);
  return { s_u: randomScalar().toString(), sk_u: [...sk].map((b) => b.toString(16).padStart(2, '0')).join('') };
}
```
`snap-mode3/src/index.js`:
- 머리 주석 `(s_u·r_u·sk_u)` → `(s_u·sk_u)`.
- `buildWitness`: `!isDec(r.r_u)` 조건 삭제; 반환 `{ uid, s_u, sk_u, attrs, userCred }`.
- `register`: `state.registration = { uid, s_u: secrets.s_u, sk_u: secrets.sk_u, auid: null, slot: null, attrs: null, registeredAt }`; 반환 `{ uid, pwd, s_u: secrets.s_u, sk_u: secrets.sk_u }`; 두 번째 대화상자 문구 `'속성 기관(AA) 계정 비밀번호'` → `'신원 기관 계정 비밀번호'`.
- `storeRegistration`: `const { attrs, slot, auid } = params;` + `if (!isDec(String(auid ?? ''))) fail('bad_auid: auid 는 10진 문자열');` + `reg.auid = String(auid);`.
- `getPublicInfo`: `cm_u: clone(r?.cm_u)` → `auid: r?.auid ?? null`.
- `reset` 문구 `등록 비밀(s_u·r_u·sk_u)` → `등록 비밀(s_u·sk_u)`.

`tests/helpers/snap_sim.mjs`: `register` 는 `createRegistration(BigInt(uid))` 로 `{ s_u, sk_u }` 만 저장하고 `{ uid, pwd, s_u: reg.s_u.toString(), sk_u: reg.sk_u }` 반환(`cm_u`·`r_u` 삭제, `auid: null`); `storeRegistration({ attrs, slot, auid })` 가 `auid` 를 저장; `getPublicInfo` 에 `auid`; `consentLogin` 증인 `{ uid, s_u, sk_u, attrs, userCred }`. `pointToStrings` import 삭제.

`snap-mode3/test/rpc.test.mjs`: `registrationCommit` import 삭제, `auidOf` 를 `../../lib/mode3_credential.js` 에서 import. `'register: … { uid, pwd, cm_u, sk_u } …'` → `{ uid, pwd, s_u, sk_u }` 단언(`registered.s_u` 10진·2^250 미만, 상태의 `s_u === registered.s_u`, `r_u`·`cm_u` 없음). `'cm_u 는 루트 lib 의 registrationCommit …'` → `'auid 는 에이전트가 계산한다 — storeRegistration 이 받은 auid 가 getPublicInfo 에 보인다'`: `const auid = (await auidOf({ uid: 12345n, s_u: BigInt(registered.s_u) })).toString(); await call('storeRegistration', { attrs: ATTRS, slot: SLOT, auid }); assert.equal((await call('getPublicInfo', {})).auid, auid);` 그리고 `storeRegistration` 케이스들에 `auid` 인자 추가(없으면 `bad_auid`). `getPublicInfo` 키 목록 `['attrs', 'auid', 'consents', 'hasUserCred', 'registered', 'slot', 'uid']`. `validateWitness(w, '12345', registered.cm_u)` → `validateWitness(w, '12345', auid)`. 비밀 목록에서 `r_u` 삭제.

- [ ] **Step 2: 지갑 페이지 `mode3/wallet.html`**

- 내 신원 카드: `<p class="desc" data-i18n="wallet_identity_desc">` 문구를 strings 와 같게. `attrsView` 의 `<input id="attrN" readonly>` 에서 `readonly` 를 빼고, 스키마 타입에 따라 `renderIdentity()` 가 enum 슬롯을 `<select>` 로 바꿔 그린다(관리자 페이지 283~299행의 그리기 코드를 옮겨 온다: `attrSchema.slots` 순회, int → `<input size=6>`, enum → `<select>`(빈 옵션 + 이름들), string → `<input size=10>`, unused → 행 숨김). 값은 `s.profile?.[slot.name] ?? ''`.
- 버튼: `attrsBtn`("신원 기관에서 다시 받기") 을 `profileSaveBtn`(`data-i18n="wallet_profile_save_btn"`) 으로 바꾸고 핸들러를 교체:
```js
    // V11 §3.3 — 속성은 사용자가 넣는다. 저장 → PUT /wallet/profile → 바뀌었으면 옛 자격증명·세션이 지워지고 다음 로그인이 새 C_u 를 받는다. snap 모드는 attrsChanged 를 Snap 에 전달한다.
    $('profileSaveBtn').addEventListener('click', async () => {
      pendingVerdict($('registerResult'), 'working');
      try {
        const profile = readProfileForm();   // attrSchema.slots 의 unused 아닌 슬롯마다 { [slot.name]: 입력값.trim() }
        const { status, body: b } = await putJson('/wallet/profile', { profile });
        if (status !== 200) { setVerdict($('registerResult'), false, 'wallet_profile_failed', { reason: b.reason ?? `HTTP ${status}`, detail: safeDetail(b) }); return; }
        if (cfg.secrets === 'snap' && b.attrsChanged) await invokeSnap('syncAttrs', { attrs: b.attrsChanged });
        setVerdict($('registerResult'), true, 'wallet_profile_saved', () => ({ summary: tt(b.changed ? 'wallet_profile_changed' : 'wallet_profile_same', { attrs: profileText(b.profile) }) || profileText(b.profile), detail: safeDetail(b) }));
      } catch (e) { setVerdict($('registerResult'), false, 'wallet_profile_failed', { reason: isUserRejected(e) ? 'user_denied' : 'wallet_error', detail: e.message }); }
      refresh();
    });
```
  (`putJson` 은 `postJson` 과 같은 모양으로 `method: 'PUT'`.) 등록 전에는 폼 값이 등록 본문의 `profile` 이 된다: `body = { uid, pwd, profile: readProfileForm() }`(file), snap 은 `const reg = await invokeSnap('register'); body = { uid: reg.uid, pwd: reg.pwd, s_u: reg.s_u, sk_u: reg.sk_u, profile: readProfileForm() }` 그리고 성공 뒤 `invokeSnap('storeRegistration', { attrs: b.attrs, slot: b.slot, auid: b.auid })`. 등록 요약 `wallet_registered_summary` 의 `{attrs}` 는 `profileText(b.profile)`. `safeDetail` 의 제외 목록에 `s_u` 추가(`const { sk_u, s_u, pwd, witness, userCredIssued, attrsChanged, ...rest } = b`). `applyPendingToSnap` 은 불변. Snap 상태 표시(919행) `속성: …` 뒤에 `auid: ${i.auid}` 를 덧붙인다. `cfg`·`refresh` 등 기존 구조는 그대로.

- [ ] **Step 3: 관리자 페이지 `mode3/cia_admin.html`** — `admin_accounts_attrs_note` 문단 삭제; `renderAccounts()` 에서 `['admin_col_attrs']` 열과 속성 입력 그리기(283~300행), `admin_save_btn` 버튼 삭제; `saveAttrs` 함수 삭제. `attrSchema` 를 다른 데서 안 쓰면 그 fetch 도 지운다.

- [ ] **Step 4: `mode3/common/strings.js`** — Interfaces 의 추가·삭제·갱신 목록대로. 새 사유 문구:
```js
    bad_idp_proof: { where: 'aa', ko: { title: '신원 기관이 π_IdP 를 거절했습니다', cause: '지갑이 낸 증명이 등록된 가명(auid)·커밋먼트와 맞지 않습니다 — 시연 카드로 salt 나 uid 를 바꿨다면 그 때문입니다.', action: '"원래대로" 로 덮어쓰기를 풀고 다시 로그인하세요.' }, en: { title: 'The authority rejected π_IdP', cause: 'The proof does not match the registered pseudonym (auid) and commitments — if you changed the salt or uid in the demo card, that is why.', action: 'Clear the override ("Restore") and log in again.' } },
    cred_revoked: { where: 'aa', ko: { title: '물린 자격증명을 다시 쓸 수 없습니다', cause: '이 C_u 는 이미 은퇴·폐기됐습니다. 새 블라인딩으로 새 C_u 를 만들어야 합니다.', action: '다시 로그인하세요 — 지갑이 새 자격증명을 만듭니다.' }, en: { title: 'A retired credential cannot be reused', cause: 'This C_u was already retired or revoked. A fresh C_u with a new blinding is required.', action: 'Log in again — the wallet makes a fresh credential.' } },
    bad_r_s: { where: 'rp', ko: { title: '세션 난수가 맞지 않습니다', cause: '증명의 r_s(공개 입력 [32])가 서비스가 준 챌린지와 다릅니다 — 다른 세션용 증명을 재전송한 것입니다.', action: '서비스에서 다시 로그인하세요.' }, en: { title: 'Session nonce mismatch', cause: 'The proof’s r_s (public input [32]) differs from the challenge this service issued — a proof for another session was replayed.', action: 'Log in again at the service.' } },
    bad_arid_s: { where: 'rp', ko: { title: '이 세션용 토큰이 아닙니다', cause: 'arid_s(공개 입력 [31])가 서비스가 자기 r_RP 로 재계산한 값과 다릅니다 — 다른 서비스나 다른 챌린지용 토큰입니다.', action: '서비스에서 다시 로그인하세요.' }, en: { title: 'Token is not for this session', cause: 'arid_s (public input [31]) differs from what this service recomputes with its own r_RP — the token was issued for another service or challenge.', action: 'Log in again at the service.' } },
```
  `terms` 에 `auid: { ko: '사용자 가명', en: 'User pseudonym', expert: 'auid = Poseidon(T_AUID, uid, salt)' }`, `auid_s: { ko: '세션 가명', en: 'Session pseudonym', expert: 'auid_s = Poseidon(T_AUIDS, auid, arid, r_RP)' }`, `r_rp: { ko: '서비스 난수', en: 'Service nonce', expert: 'r_RP — RP 가 챌린지와 함께 주는 250비트 난수(IdP 비공개)' }` 추가. `steps` 의 register 힌트가 "기관이 준 속성" 을 말하면 "지갑에 넣은 속성" 으로.

- [ ] **Step 5: 테스트**

`tests/test_mode3_demo_strings.js`: `REASONS` 에서 `'no_user_cred', 'user_cred_retired'`·`'attrs_failed'`·`'use_profile'` 삭제, `'bad_idp_proof', 'cred_revoked', 'bad_r_s', 'bad_arid_s'` 추가; `terms` 필수 목록에 `'auid', 'auid_s', 'r_rp'` 추가; ui 키 검사에 `'wallet_profile_save_btn', 'wallet_profile_saved', 'wallet_profile_failed'` 추가. Run: `node tests/test_mode3_demo_strings.js`.

`tests/test_mode3_wallet_snap.mjs`: `'register: cm_u·sk_u 없으면 400 …'` → `'register: s_u·sk_u 없으면 400; 응답 { uid, slot, auid, attrs, profile }(sk_u·s_u 없음); 파일에 비밀 없음·auid 있음'`: 본문 `{ uid, pwd, s_u: r0.s_u, sk_u: r0.sk_u }`, 잘못된 `s_u: 'zz'` 400, 응답 `'s_u' in r.body === false`, `sim.storeRegistration({ attrs, slot, auid: r.body.auid })`, 파일 검사 `'"s_u"', '"sk_u"', '"blind_u"'` 없음 + `'"auid"'` 있음(`'"cm_u"'` 단언 삭제). `loginBase()` 에 `r_rp: ch.r_rp` 추가. `validateWitness(w, '12345', sim.state.registration.cm_u)` → `validateWitness(w, '12345', sim.state.registration.auid)`; `badCm` 기대 `/auid/`. `'시뮬레이터: …'` 의 `syncAttrs` 단언 그대로. `verify(body, r_s)` 는 `verify(body, ch)` 로 `r_rp` 를 함께 넘긴다.

`tests/test_mode3_browser.mjs`·`tests/test_mode3_tour.mjs`(Chrome 필요 — 없으면 `BLOCKED:` 로 끝나는 것이 정상): 비밀 목록에서 `r_u` 삭제; `'AA 속성 변경 뒤 로그인: …(syncAttrs → updateUserCred 순서)'` → `'지갑에서 속성 저장(extra1) → Snap 의 속성 갱신·C_u 폐기 → 다음 로그인이 새 C_u'`: `stack.cia.adminPost('/cia/accounts/12345/attrs', …)` → 지갑 페이지에서 extra1 입력 뒤 `#profileSaveBtn` 클릭(`await walletPage.fill('#attr2', 'tier3'); await walletPage.click('#profileSaveBtn'); await waitText(walletPage, '#registerResult', '속성', 15_000);`) 그리고 `snapState.userCred === null` 확인 뒤 로그인 → 새 C_u. 투어 테스트의 `'V9 시연 카드 … bad user credential proof'` 기대 문자열은 `strings.js` 의 `user_cred_failed.ko.title` 을 읽으므로 그대로 두되 제목 문구가 바뀌었음을 반영(이미 `DemoStrings.reasons.user_cred_failed.ko.title` 을 읽는다 — 변경 불필요).

Run: `bash scripts/run_tests.sh snap`(`snap-mode3/node_modules` 필요) → PASS. `cd snap-mode3 && npm run build` 로 `dist/bundle.js` 재생성. Run(:8545): `node tests/test_mode3_wallet_snap.mjs` → 전부 `ok`. Run: `bash scripts/run_tests.sh browser`(Chrome 없으면 BLOCKED 보고).

---

### Task 12: 런북·벤치·결과·전체 실행

**Files:**
- Modify: `docs/MODE3_DEMO.md`
- Create: `scripts/bench_pi_idp.mjs`; Modify: `scripts/bench_zkp_inventory.mjs`(π_u 절을 π_IdP 로), `scripts/bench_pi_cred.mjs`(주석 "V11")
- Create: `results/mode3_v11_figure_protocol_<YYYYMMDD>.md` (날짜는 `date +%Y%m%d` 실행값)
- Modify: `docs/superpowers/specs/2026-10-12-mode3-v11-figure-protocol-design.md` 머리 "상태" 와 §8 실측 열
- Modify: `scripts/run_tests.sh` 머리 주석(pi_idp 산출물 전제)

- [ ] **Step 1: `scripts/bench_pi_idp.mjs`**

```js
// pi_idp 회로의 증명·검증 시간 실측(스펙 2026-10-12 §8). zkey 는 scripts/build_mode3_circuit.sh 가 만든 것을 쓴다(없으면 안내 후 종료).
//   node scripts/bench_pi_idp.mjs
import fs from 'node:fs';
import * as snarkjs from 'snarkjs';
import { IDP_WASM_PATH, IDP_ZKEY_PATH, IDP_VKEY_PATH } from '../lib/mode3_idp_proof.js';
import { buildIdpInput } from '../tests/helpers/mode3_idp_fixture.mjs';

for (const f of [IDP_WASM_PATH, IDP_ZKEY_PATH, IDP_VKEY_PATH]) if (!fs.existsSync(f)) { console.error(`${f} 가 없다 — bash scripts/build_mode3_circuit.sh pot21_final.ptau`); process.exit(2); }
const { input } = await buildIdpInput();
const vkey = JSON.parse(fs.readFileSync(IDP_VKEY_PATH, 'utf8'));
const N = 10, proveMs = [], verifyMs = [];
let publicSignals;
for (let i = 0; i < N; i++) {
  const t0 = performance.now();
  const out = await snarkjs.groth16.fullProve(input, IDP_WASM_PATH, IDP_ZKEY_PATH);
  proveMs.push(performance.now() - t0);
  const t1 = performance.now();
  const ok = await snarkjs.groth16.verify(vkey, out.publicSignals, out.proof);
  verifyMs.push(performance.now() - t1);
  if (!ok) throw new Error('검증 실패');
  publicSignals = out.publicSignals;
}
const med = (a) => [...a].sort((x, y) => x - y)[Math.floor(a.length / 2)];
console.log('\n## pi_idp 실측\n\n| 항목 | 값 |\n|---|--:|');
console.log(`| 증명 시간 (중앙값, ${N}회) | ${med(proveMs).toFixed(1)} ms |`);
console.log(`| 검증 시간 (중앙값, ${N}회) | ${med(verifyMs).toFixed(1)} ms |`);
console.log(`| zkey 크기 | ${(fs.statSync(IDP_ZKEY_PATH).size / 1e6).toFixed(1)} MB |`);
console.log(`| 공개 입력 수 | ${publicSignals.length} |`);
```
`scripts/bench_zkp_inventory.mjs`: π_u(시그마) 절(54~70행 부근)을 지우고 `proveIdp`/`verifyIdp` 로 π_IdP 10회 중앙값을 재는 절로 바꾼다(import: `../lib/mode3_idp_proof.js`, `../tests/helpers/mode3_idp_fixture.mjs`). 머리 주석 2행 갱신.

- [ ] **Step 2: 벤치 실행·결과 파일**

Run: `node scripts/bench_pi_cred.mjs pot21_final.ptau`, `node scripts/bench_pi_idp.mjs`, `node scripts/bench_mode3_onchain.mjs`(:8545 필요; 이 스크립트가 `uint[33]`·픽스처로 돈다 — 깨지면 `buildValidInput`·`PUB_INDEX` 사용부를 고친다).
`results/mode3_v11_figure_protocol_<YYYYMMDD>.md` 에 스펙 §8 표의 V11 열(제약 수 둘·공개 입력·증명/검증·execute gas·zkey 크기·로그인 왕복은 `tests/test_mode3_wallet_agent.mjs` 의 `timings` 출력)을 실측으로 채우고, 측정 명령·`date` 실행값·커밋(작업 시작 커밋 `6ec83b7`)을 적는다. 스펙 머리의 "상태: 초안" 을 "구현 완료(결과 `results/…`)" 로, §8 에 "실측" 열을 더한다.

- [ ] **Step 3: `docs/MODE3_DEMO.md`**

- "처음 한 번" 0 번 항목 끝에 **V11 문단** 추가: 회로 둘(`pi_cred` 공개 33·`pi_idp`)이 바뀌었으니 (1) `bash scripts/build_mode3_circuit.sh pot21_final.ptau`(이제 `pi_idp_*` 도 만든다) (2) `npx hardhat compile` (3) **로그·거울 재배포 + `cia_state.json` 새로 시작**(v11 이하 상태 파일은 기동 거부 — 이행 없음, 이유: auid 는 지갑만 계산·리프/PPID 식 변경) (4) `mode3_rp_registration.json` 의 `verifierAddress`·`factoryAddress`·`attrGateAddress` 삭제(PPID 식이 바뀌어 **모든 계정 주소가 바뀐다**) (5) 지갑 상태는 v9 로 자동 이행(file 모드 등록 유지, snap 모드는 등록 비움 — Snap "초기화" 뒤 재등록) (6) 다른 기계는 `scripts/pack_mode3_build.sh` 로 `pi_idp` 포함 세트를 다시 복사 (7) `snap` 모드는 `cd snap-mode3 && npm run build` 뒤 Snap 재설치.
- "시연 각본" 표: 1 번 기대 `속성은 AA 기록값(…)` → `속성은 내가 등록 폼에 넣은 값(기본 출생연도 1990·국가 KR → [1990, 410, 0, 0, 0, 0]) — IdP 는 받지 않는다(D15)`; 11 번 `관리자 → 지갑(전문가 보기) | (계정) 속성을 바꿔 "저장"(활성 자격증명을 물린다) → …` → `지갑 → 지갑(전문가 보기) | (내 신원) 속성(예비 1)을 바꿔 "속성 저장" → "로그인"(새 C_u, 같은 PPID) → (시연: 비밀 바꾸기) salt … → "로그인"` 기대 `… user_cred_failed(신원 기관이 π_IdP 거절: bad_idp_proof) …`; 2 번 기대에 `공개 입력 33(끝의 auid_s·arid_s·r_s 는 서비스만 본다)` 한 구절.
- "실패 각본" F5: `관리자의 잘못된 속성 bad_attr / use_profile` → `지갑의 잘못된 속성 bad_attr — 지갑 (내 신원) 출생연도를 비우고 "속성 저장"; 1800 으로 "속성 저장"; 콘솔로 curl -X PUT 127.0.0.1:5100/wallet/profile -H 'Content-Type: application/json' -d '{"profile":{"birthYear":"1800","country":"KR"}}' | 400 bad_attr(reason empty / range), IdP 는 부르지 않는다`. 고정 테스트 `tests/test_mode3_wallet_agent.mjs`.
- "속성과 선택 공개" 절의 첫 두 문단(**속성 출처와 스키마**·**관리자 속성 변경**·**지갑의 재동기화**)을 D15 로 다시 쓴다: 속성은 지갑의 `profile`(사용자 입력, 기본 `{birthYear 1990, country KR}`), 스키마는 IdP 가 공개하는 공통 인코딩 규칙일 뿐 값은 받지 않음, 바꾸기는 `PUT /wallet/profile`(옛 C_u·세션 삭제 → 다음 로그인의 `/cia/issue` 가 새 C_u 를 게시, PPID 불변), **값의 보증은 없다 — 술어는 "사용자가 주장한 값" 위의 증명**(스펙 §3.3·§13, 후속 = 속성 발급자). 데모 계정 문장은 "지갑 기본값" 으로.
- "엔드포인트" 표: `/cia/user_cred`·`/cia/attrs`·`/cia/accounts/:uid/attrs`·`/wallet/attrs/sync` 행 삭제, `PUT /wallet/profile` 추가, `/cia/issue` 설명을 `(C_u, C_s, π_IdP, sig_u) — C_u 가 바뀌면 슬롯 갱신·게시`, `/api/mode3/challenge` 에 `r_rp`.
- "RP 거절 사유" 표에 `bad_r_s`·`bad_arid_s`(401/본문 `ok:false`), 지갑 사유 표의 `user_cred_failed` 설명을 `π_IdP 거절(bad_idp_proof)` 로; `no_user_cred`·`user_cred_retired`·`attrs_failed` 행 삭제.
- "수용한 한계": "uid 존재 열거" 항목의 `/cia/user_cred·/cia/attrs` → `/cia/issue·/cia/slot`; 항목 추가 `속성 값 보증 없음(V11 D15) — 거래소 데모의 "나이 ≥ 19" 는 메커니즘 시연이지 값의 진위 보증이 아니다. 후속: 속성 발급자(스펙 §10)`.
- "MetaMask / Snap 경로" 표: `등록 비밀 보관 … 공개 부분만(uid·cm_u·attrs·Cf_u·leaf)` → `(uid·auid·attrs·profile·Cf_u)`; `등록 | 에이전트가 s_u·r_u 를 만든다 | Snap 이 만들고 페이지는 cm_u 만 넘긴다` → `Snap 이 s_u·sk_u 를 만들고 페이지가 한 번 넘긴다(에이전트가 auid 계산)`; S2 기대 문구의 "속성은 AA 값" → "속성은 폼 값"; S8′ 를 지갑 속성 저장 경로로.
- "하지 말 것 / 재시연": "옛 상태 파일 … v2 이하" 문장을 `cia_state.json version 11 이하 → 기동 거부(V11 은 이행 없음)` 로, 재시연 세트 문단 끝에 `V11 부터는 cm_u 가 없으므로 'cm_u 가 달라진 만큼 409' 문장은 'uid 가 이미 등록돼 있어 409' 로 읽는다`.
- "테스트": chain 그룹 전제에 `build/mode3 의 pi_idp zkey·vkey·wasm` 추가.

- [ ] **Step 4: 전체 실행**

Run: `npm test`(unit + circuit) → 전부 PASS.
Run: `bash scripts/run_tests.sh contract` → PASS.
Run(:8545): `bash scripts/run_tests.sh chain` → PASS(느리다 — `run_in_background` 로 돌리고 끝나면 요약).
Run: `bash scripts/run_tests.sh snap`(node_modules 있으면), `bash scripts/run_tests.sh browser`(Chrome 있으면 — 없으면 BLOCKED 보고).
Expected: 실패 0. 실패가 남으면 파일·사유를 보고에 그대로 적는다(고치지 못한 것은 "미검증 위험" 으로).

- [ ] **Step 5: 보고**

바뀐 파일 목록, 실측 표, 남은 위험(Chrome/snap 미실행, 덱·그림 반영은 스펙 §12 — 코드 밖), 사용자 재배포 절차(런북 "처음 한 번" V11 문단)를 정리한다. 커밋은 하지 않는다.

---

## 자기 검토 메모(계획 작성자)

- **스펙 대조**: D1(세션 기록에 auid_s 없음 — Task 7 `/cia/issue`·테스트 단언) · D2·D10(π_IdP 세션마다 — Task 2·5·7) · D3(토큰 7인자 — Task 1·3·7) · D4(auid·리프 — Task 1·3·7) · D5(C_s — Task 1·2·3) · D6(r_s+r_rp — Task 6·9) · D7(auid_s 에 arid — Task 1·3·6 테스트) · D8·D9(cert_s·σ_{sk_s} 불변 — 바꾸지 않음) · D11(user_cred 흡수 — Task 7) · D12(33 — Task 3·4·6·7) · D13(PPID 순서 — Task 1·3) · D15(속성 사용자 — Task 7·9·11·12) · D16(max_height 공개 — Task 2 회로) · §7 상태(v12·v9·Snap — Task 7·9·11) · §11 테스트(단위·회로·컨트랙트·chain·browser·snap·벤치 — Task 1~12) · §12 덱 반영은 코드 밖(보고에 남긴다).
- **이름 일관성**: `auidOf/auidSOf/aridSOf`, `sessionCommit({pk_i,max_height,r_s,r_rp})`, `credMessageV11`, `issueRequestMessageV11`, `registerMessage(uid, auid)`, `slotRequestMessage`, `registryLeaf(auid, Cf_u)`, `createRegistration(uid)`, `signRegistration(sk,uid,auid)`, `signSlotRequest`, `buildIssueRequest({...r_rp,r_s...})`, `buildCredentialProof({...auid,r_rp,r_s...})`, `issueV11/proveV11/userOf`, `IDP_PUB_INDEX`, `PUB_INDEX.AUID_S/ARID_S/R_S`, 사유 `bad_idp_proof/cred_revoked/bad_r_s/bad_arid_s`, 지갑 `PUT /wallet/profile`·`DEFAULT_PROFILE` — 모든 작업이 같은 철자를 쓴다.
- **중간 상태**: Task 1 뒤 unit 그룹 일부(secret_source·wallet_lib)와 chain 전부가 Task 5·7 까지 빨갛다 — Global Constraints 에 적어 두었다. Task 4 의 산출물 재생성은 사용자 승인 지점이다.
