# Mode 3 속성 선택 공개(selective disclosure) 구현 계획

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** AA 가 보증하는 속성을 C_u 에 싣고, 트랜잭션(또는 로그인)의 π_rp 에 구간 술어 `lo ≤ a_k ≤ hi` 를 공개 입력으로 붙여 체인이 검증한 뒤 대상 컨트랙트(`AttrGate`)가 그 값으로 동작하게 한다.

**Architecture:** (1) 속성 출처를 AA 계정 기록으로 옮기고 π_u 를 "AA 가 uid·Σa_k 항을 빼고 (s_u, blind_u) 만 PoK" 로 바꾼다. (2) 회로 V6 는 공개 입력 23개(기존 14 + `disc_mask` + `disc_lo[4]` + `disc_hi[4]`)이고 속성은 64비트다. (3) `Mode3Wallet.execute` 가 `uint[23]` 을 받아 mask ≠ 0 이면 공개 값 9워드를 호출 데이터 꼬리에 붙여 대상에 전달하고, 세션키 서명 다이제스트가 공개 값 9워드(mask, lo[4], hi[4])를 덮는다. (4) 지갑 `/wallet/tx` 가 `disclose` 를 받아 새 π 를 만들고, 속성은 등록 응답·`/cia/attrs` 로 AA 에서 받는다.

**Tech Stack:** Node 22 ESM, circom 2.1.9 + snarkjs 0.7.5 (Groth16/BN254), circomlibjs (Baby Jubjub·Poseidon·EdDSA), Solidity 0.8.24 (hardhat), express, `node:assert` 테스트, `scripts/run_tests.sh` 그룹.

**Spec:** `docs/superpowers/specs/2026-09-22-mode3-selective-disclosure-design.md` (이하 "스펙"). 기반: `2026-09-21-mode3-two-tier-credential-design.md`.

## Global Constraints

- 속성 값 범위 `[0, 2^64)` — 회로 `Num2Bits(64)`, JS `ATTR_MAX = 1n << 64n` (스펙 §4.1). 다른 스칼라(uid, s_u, blind, arid, pk_i)는 `2^250` 그대로.
- π_rp 공개 입력 순서(스펙 §4.3): `[0] PPID [1] arid [2] pk_i [3] max_height [4] chainid [5] allowAgent [6] revRoot [7] pk_CIA_x [8] pk_CIA_y [9] pk_trace_x [10] pk_trace_y [11] tag_c1_x [12] tag_c1_y [13] tag_c2 [14] disc_mask [15..18] disc_lo[0..3] [19..22] disc_hi[0..3]`. 앞 14개는 V5 와 같다. 바꾸지 말 것.
- `disc_mask ∈ [0, 16)`, 비트 k = 슬롯 k 공개. 공개하지 않는 슬롯은 `lo = hi = 0`. 등식 공개 = `lo = hi`.
- 새 도메인 상수: `DOMAIN_MODE3_USERCRED_V2 = 1568025692958769574353059516335154n` (ASCII "MODE3USERCRED2"), `DOMAIN_MODE3_ATTRSREQ = 6125100363118752795903799739729n` (ASCII "MODE3ATTRSREQ"). 옛 `DOMAIN_MODE3_USERCRED` 는 삭제.
- σ_AA 메시지(`credMessageV5`)·C_s·PPID·리프·태그·`cert_s`·`share_pok` 는 바뀌지 않는다.
- 세션키 서명 다이제스트: `keccak256(abi.encode(chainid, wallet, to, value, data, nonce, pub[14], pub[15..18], pub[19..22]))`(공개 값
  9워드 전부 — mask 만 덮으면 같은 세션키·같은 mask 로 만든 다른 구간의 π 를 릴레이어가 바꿔 끼울 수 있다, 리뷰에서 발견,
  2026-09-22) — JS `payloadDigest` 와 컨트랙트가 같아야 한다.
- 데모 계정 속성(스펙 §3.1): `testuser` `['1990','410','2','0']`, `alice` `['2005','840','1','0']`. 슬롯 뜻: a₀ 출생연도, a₁ 국가 코드, a₂ 등급, a₃ 예비.
- `AttrGate` 정책: `countryEq = 410`, `birthYearMax = 2007`; `claim()` 은 mask 비트 0·1 필수, `lo[1] == hi[1] == 410`, `hi[0] ≤ 2007`.
- CIA 상태 v7: `accounts[uid].attrs` 추가, v6→v7 마이그레이션에서 활성 자격증명 전부 물림(리프 → pending). `idp_state.json`·`cia_state.json` 을 지우지 않는다.
- 회로 빌드는 `bash scripts/build_mode3_circuit.sh` 로만. `npm run zk:*` 금지. 이미 떠 있는 :8545 는 손대지 않고, 테스트용 hardhat 은 세션이 띄우고 내린다.
- 모든 응답·주석·커밋 메시지는 한글. 커밋 트레일러: `Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>` 와 `Claude-Session: https://claude.ai/code/session_013qGSXZTftBJSB1M4XpPRHN`.
- 기존 테스트 파일에 케이스를 더할 때 `scripts/run_tests.sh` 의 그룹은 그대로다(이미 등록됨). 새 테스트 파일은 없다.
- Mode 1/2 파일(`make_proof.js`, `custom_idp.js`, `contracts/PPIDWallet*.sol` 등)은 건드리지 않는다.

---

## 파일 구조

| 파일 | 책임 | Task |
|---|---|---|
| `lib/mode3_credential.js` | `ATTR_MAX`, `normalizeAttrs` 64비트 상한 | 1 |
| `lib/mode3_issuance.js` | π_u V2 (`proveUserCred`/`verifyUserCred` 에 공개 attrs), `DOMAIN_MODE3_USERCRED_V2`, `DOMAIN_MODE3_ATTRSREQ`, `attrsRequestMessage` | 1 |
| `circuits/lib/mode3_commit.circom` | `CommitUser` 속성 64비트 | 2 |
| `circuits/pi_cred.circom` | V6 공개 술어, 공개 입력 23개 | 2 |
| `tests/helpers/mode3_fixture.mjs` | `buildValidInput({ disclosure })` | 2 |
| `contracts/Mode3Wallet.sol` | `uint[23]`, mask 다이제스트, 꼬리 전달, `Disclosure` 이벤트, `BadDisclosure` | 3 |
| `contracts/Mode3WalletFactory.sol` | `isWallet` | 3 |
| `contracts/AttrGate.sol` | 데모 대상 | 3 |
| `lib/mode3_onchain.js` | ABI 갱신, `payloadDigest` 에 `discMask`, `deployAttrGate`, `attrGateAt`, `parseExecuteReceipt` 의 `disclosure` | 3 |
| `lib/mode3_cia_state.js` | v7 마이그레이션 | 4 |
| `cia.js` | `DEMO_ACCOUNTS.attrs`, register 응답 attrs, `/cia/attrs`, `/cia/accounts/:uid/attrs`, user_cred 의 π_u V2 | 4 |
| `mode3/cia_admin.html` | 계정 속성 편집 | 4 |
| `lib/mode3_wallet.js` | `buildCredentialProof({ disclosure })`, `ProofCache` 키, `signAttrsRequest`, `buildUserCredRequest` 그대로 | 5 |
| `mode3_wallet_agent.js` | register 가 AA attrs 저장, `ensureUserCred` bad_proof 재동기화, `/wallet/attrs` 삭제 → `/wallet/attrs/sync`, `/wallet/tx` disclose | 5 |
| `mode3/wallet.html` | 속성 읽기 전용, 공개 폼 | 5 |
| `lib/mode3_rp.js` | 23개, `bad_disclosure`, `disclosure` 반환 | 6 |
| `mode3_rp.js`, `mode3/rp.html` | `AttrGate` 배포·`rp_info.attrGateAddress`, 세션에 disclosure 기록 | 6 |
| `docs/MODE3_DEMO.md`, `scripts/bench_*`, `results/` | 절차·시나리오·실측 | 7 |

---

### Task 1: 속성 64비트 + π_u V2 (AA 가 속성 항을 빼고 PoK)

**Files:**
- Modify: `lib/mode3_credential.js` (`normalizeAttrs`, 새 `ATTR_MAX`)
- Modify: `lib/mode3_issuance.js` (`proveUserCred`, `verifyUserCred`, `challengeU`, 도메인 상수, `serializeUserCredProof`/`parseUserCredProof`, 새 `attrsRequestMessage`)
- Test: `tests/test_mode3_issuance.js`, `tests/test_mode3_credential_v5.js`

**Interfaces:**
- Consumes: `PEDERSEN_GENERATORS`, `SCALAR_MAX`, `normalizeAttrs` (기존).
- Produces:
  - `export const ATTR_MAX = 1n << 64n` (`lib/mode3_credential.js`). `normalizeAttrs` 가 `v >= ATTR_MAX` 를 throw.
  - `export const DOMAIN_MODE3_USERCRED_V2 = 1568025692958769574353059516335154n`, `export const DOMAIN_MODE3_ATTRSREQ = 6125100363118752795903799739729n`.
  - `proveUserCred({ uid, s_u, blind_u, r_u, attrs })` → `{ C_u_pt, cm_u, proof: { T1, T2, c, z_su, z_blind, z_ru } }` (z_attr 없음).
  - `verifyUserCred({ uid, attrs, C_u_pt, cm_u, proof })` → boolean. **attrs 는 검증자(AA) 의 기록값.**
  - `serializeUserCredProof(p)` / `parseUserCredProof(o)` — z_attr 필드 제거.
  - `attrsRequestMessage(uid, nonce)` → `Poseidon(DOMAIN_MODE3_ATTRSREQ, uid, nonce)` (bigint). Task 4·5 가 `/cia/attrs` 요청 서명에 쓴다.

- [ ] **Step 1: 실패하는 테스트 — 64비트 상한과 π_u V2**

`tests/test_mode3_credential_v5.js` 의 `normalizeAttrs` 케이스 옆에 추가:

```js
await t('normalizeAttrs: 2^64 이상은 throw, 2^64 − 1 은 통과 (스펙 2026-09-22 §4.1)', () => {
  assert.throws(() => normalizeAttrs([ATTR_MAX]), /attr0/);
  assert.deepEqual(normalizeAttrs([ATTR_MAX - 1n]), [ATTR_MAX - 1n, 0n, 0n, 0n]);
});
```

(import 에 `ATTR_MAX` 추가.)

`tests/test_mode3_issuance.js` — 기존 "π_u 양성"·"π_u 음성" 두 케이스를 아래로 **교체**하고, 도메인 케이스에 V2 값을 넣는다:

```js
await t('π_u V2 양성: AA 가 자기 기록 attrs 로 검증하면 통과하고 C_u_pt 는 userCommit 과 같은 점', async () => {
  const uid = 12345n, s_u = randomScalar(), r_u = randomScalar(), blind_u = randomScalar(), attrs = [1990n, 410n, 2n, 0n];
  const { C_u_pt, cm_u, proof } = await proveUserCred({ uid, s_u, blind_u, r_u, attrs });
  const c = await userCommit({ uid, s_u, blind_u, attrs });
  assert.equal(C_u_pt.x, c.Cx); assert.equal(C_u_pt.y, c.Cy);
  assert.equal(await verifyUserCred({ uid, attrs, C_u_pt, cm_u, proof }), true);
  assert.equal(Object.hasOwn(proof, 'z_attr'), false, 'V2 에는 z_attr 이 없다 — 속성은 공개값');
});

await t('π_u V2 음성: AA 기록과 다른 attrs, cm_u 와 다른 s_u(Sybil), 다른 uid, 응답 변조, 곡선 밖 점', async () => {
  const uid = 12345n, s_u = randomScalar(), r_u = randomScalar(), blind_u = randomScalar(), attrs = [1990n, 410n, 2n, 0n];
  const { C_u_pt, cm_u, proof } = await proveUserCred({ uid, s_u, blind_u, r_u, attrs });
  assert.equal(await verifyUserCred({ uid, attrs: [1991n, 410n, 2n, 0n], C_u_pt, cm_u, proof }), false, '지갑이 넣은 속성이 AA 기록과 다르면 실패');
  assert.equal(await verifyUserCred({ uid: 12346n, attrs, C_u_pt, cm_u, proof }), false);
  const other = await proveUserCred({ uid, s_u: randomScalar(), blind_u, r_u, attrs });
  assert.equal(await verifyUserCred({ uid, attrs, C_u_pt: other.C_u_pt, cm_u, proof: other.proof }), false, 'cm_u 의 s_u 와 다르면 실패');
  assert.equal(await verifyUserCred({ uid, attrs, C_u_pt, cm_u, proof: { ...proof, z_su: (proof.z_su + 1n) } }), false);
  assert.equal(await verifyUserCred({ uid, attrs, C_u_pt: { x: 1n, y: 1n }, cm_u, proof }), false);
  await assert.rejects(() => proveUserCred({ uid, s_u, blind_u, r_u, attrs: [1n << 64n, 0n, 0n, 0n] }), /attr0/);
});

await t('attrsRequestMessage = Poseidon(DOMAIN_MODE3_ATTRSREQ, uid, nonce)', async () => {
  const ps = await buildPoseidon();
  assert.equal(await attrsRequestMessage(12345n, 7n), ps.F.toObject(ps([DOMAIN_MODE3_ATTRSREQ, 12345n, 7n])));
  await assert.rejects(() => attrsRequestMessage('12345', 7n), /uid/);
});
```

도메인 케이스(기존 "V5 도메인 세 개…")를 아래로 교체한다(`DOMAIN_MODE3_USERCRED` 는 사라지므로 옛 값 목록으로 옮긴다):

```js
await t('도메인 상수는 ASCII 빅엔디언이고 서로·옛 값과 다르다 (2026-09-22: USERCRED_V2·ATTRSREQ 추가, USERCRED 는 옛 값)', () => {
  const be = (s) => BigInt('0x' + Buffer.from(s).toString('hex'));
  assert.equal(DOMAIN_MODE3_USERCRED_V2, be('MODE3USERCRED2'));
  assert.equal(DOMAIN_MODE3_ATTRSREQ, be('MODE3ATTRSREQ'));
  assert.equal(DOMAIN_MODE3_USERCREDREQ, be('MODE3USERCREDREQ'));
  assert.equal(DOMAIN_MODE3_ISSUEREQ_V4, be('MODE3ISSUEREQV4'));
  const old = [be('MODE3ISSUE'), be('MODE3ISSUEREQV3'), be('MODE3USERCRED')];
  assert.equal(new Set([DOMAIN_MODE3_USERCRED_V2, DOMAIN_MODE3_ATTRSREQ, DOMAIN_MODE3_USERCREDREQ, DOMAIN_MODE3_ISSUEREQ_V4, ...old]).size, 7);
});
```

(import 에 `DOMAIN_MODE3_USERCRED_V2, DOMAIN_MODE3_ATTRSREQ, attrsRequestMessage` 추가, `DOMAIN_MODE3_USERCRED` 제거. `buildPoseidon` 은 파일에 이미 import 돼 있는지 확인.)

- [ ] **Step 2: 실패 확인**

Run: `node tests/test_mode3_credential_v5.js && node tests/test_mode3_issuance.js`
Expected: FAIL — `ATTR_MAX`·`DOMAIN_MODE3_USERCRED_V2`·`attrsRequestMessage` import 실패(SyntaxError) 또는 attrs 불일치 케이스가 true.

- [ ] **Step 3: 구현**

`lib/mode3_credential.js`:

```js
export const ATTR_MAX = 1n << 64n;   // 속성은 64비트 정수(스펙 2026-09-22 §4.1) — 회로 Num2Bits(64)·LessEqThan(64) 과 같은 상한
```

`normalizeAttrs` 의 범위 검사를 `if (v < 0n || v >= ATTR_MAX) throw new Error(\`attr${i} 는 [0, 2^64) 범위여야 한다: ${v}\`);` 로.

`lib/mode3_issuance.js` — 상단 주석에 "2026-09-22: 속성은 AA 기록. AA 가 uid·G_UID + Σa_k·G_ATTR 을 빼고 (s_u, blind_u) 만 PoK" 한 줄. 상수 교체:

```js
export const DOMAIN_MODE3_USERCRED_V2 = 1568025692958769574353059516335154n;   // ASCII "MODE3USERCRED2" — π_u V2 FS 도메인(속성 공개)
export const DOMAIN_MODE3_ATTRSREQ    = 6125100363118752795903799739729n;      // ASCII "MODE3ATTRSREQ"  — /cia/attrs 요청 서명
```

`challengeU` 와 π_u:

```js
async function challengeU(bj, uid, attrs, C_u_pt, cm_u, T1, T2) {
  const ps = await getPs();
  const h = ps.F.toObject(ps([DOMAIN_MODE3_USERCRED_V2, uid, ...attrs, C_u_pt.x, C_u_pt.y, cm_u.x, cm_u.y, T1.x, T1.y, T2.x, T2.y]));
  return h & MASK_250;
}

/**
 * PoK{ (s_u, blind_u, r_u) : C_u − uid·G_UID − Σaₖ·G_ATTR = s_u·G_SU + blind_u·H  ∧  cm_u = s_u·G_SU + r_u·H }.
 * 공개 uid, a₀..a₃, C_u_pt, cm_u. 속성은 AA 기록이므로 AA 가 빼고 검증한다(스펙 2026-09-22 §3.4).
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
  const T1 = toObj(bj, msm(bj, [[a.su, G3], [a.blind, H]]));
  const T2 = toObj(bj, msm(bj, [[a.su, G3], [a.ru, H]]));
  const c = await challengeU(bj, uid, a4, C_u_pt, cm_u, T1, T2);
  const z = (ax, x) => (ax + c * x) % r;
  return { C_u_pt, cm_u, proof: { T1, T2, c, z_su: z(a.su, s_u), z_blind: z(a.blind, blind_u), z_ru: z(a.ru, r_u) } };
}

export async function verifyUserCred({ uid, attrs, C_u_pt, cm_u, proof }) {
  if (typeof uid !== 'bigint' || uid < 0n || uid >= SCALAR_MAX) return false;
  let a4; try { a4 = normalizeAttrs(attrs); } catch { return false; }
  const bj = await getBj();
  const r = bj.subOrder;
  const { T1, T2, c, z_su, z_blind, z_ru } = proof ?? {};
  for (const P of [C_u_pt, cm_u, T1, T2]) if (!validPoint(bj, P)) return false;
  for (const z of [c, z_su, z_blind, z_ru]) if (typeof z !== 'bigint' || z < 0n || z >= r) return false;
  if ((await challengeU(bj, uid, a4, C_u_pt, cm_u, T1, T2)) !== c) return false;
  const [G1, G3, H] = ['uid', 's_u', 'blind'].map((n) => G(bj, n));
  const GA = [0, 1, 2, 3].map((i) => G(bj, `attr${i}`));
  // Y1 = C_u − uid·G_UID − Σaₖ·G_ATTR — AA 가 아는 항을 전부 뺀다
  const known = msm(bj, [[uid, G1], ...a4.map((v, i) => [v, GA[i]])]);
  const Y1 = bj.addPoint(fromObj(bj, C_u_pt), negPt(bj, known));
  const lhs1 = msm(bj, [[z_su, G3], [z_blind, H]]);
  const rhs1 = bj.addPoint(fromObj(bj, T1), bj.mulPointEscalar(Y1, c));
  if (!eqPt(bj, lhs1, rhs1)) return false;
  const lhs2 = msm(bj, [[z_su, G3], [z_ru, H]]);
  const rhs2 = bj.addPoint(fromObj(bj, T2), bj.mulPointEscalar(fromObj(bj, cm_u), c));
  return eqPt(bj, lhs2, rhs2);
}

/** /cia/attrs 요청의 사용자 서명 메시지 = Poseidon(D_ATTRSREQ, uid, nonce). nonce 는 지갑이 뽑는 난수 — AA 는 신선도를 검사하지 않는다(스펙 §3.3). */
export async function attrsRequestMessage(uid, nonce) {
  if (typeof uid !== 'bigint' || uid < 0n || uid >= SCALAR_MAX) throw new Error('attrsRequestMessage: uid 는 [0, 2^250) bigint');
  if (typeof nonce !== 'bigint' || nonce < 0n || nonce >= SCALAR_MAX) throw new Error('attrsRequestMessage: nonce 는 [0, 2^250) bigint');
  const ps = await getPs();
  return ps.F.toObject(ps([DOMAIN_MODE3_ATTRSREQ, uid, nonce]));
}
```

`msm` 에서 `a4` 가 모두 0 이면 `[v, GA[i]]` 항이 0·G 가 되어 항등원을 더한다 — circomlibjs `mulPointEscalar(P, 0n)` 은 `[0, 1]` 을 돌려주므로 문제없다(기존 코드도 같은 경로였다). 직렬화:

```js
export function serializeUserCredProof(p) {
  return { T1: pointToStrings(p.T1), T2: pointToStrings(p.T2), c: p.c.toString(), z_su: p.z_su.toString(), z_blind: p.z_blind.toString(), z_ru: p.z_ru.toString() };
}
export function parseUserCredProof(o) {
  const B = (v) => { if (typeof v !== 'string' || !/^[0-9]+$/.test(v)) throw new Error('bad scalar'); return BigInt(v); };
  return { T1: pointFromStrings(o.T1), T2: pointFromStrings(o.T2), c: B(o.c), z_su: B(o.z_su), z_blind: B(o.z_blind), z_ru: B(o.z_ru) };
}
```

`ATTR_SLOTS` import 가 더 이상 쓰이지 않으면 제거한다. `tests/test_mode3_issuance.js` 의 "π_u 직렬화 왕복" 케이스에서 `z_attr` 을 비교하던 줄이 있으면 지운다.

- [ ] **Step 4: 통과 확인**

Run: `node tests/test_mode3_credential_v5.js && node tests/test_mode3_issuance.js`
Expected: 전부 `ok`. 이어서 `bash scripts/run_tests.sh unit` — `test_mode3_cia_state.js`·`test_mode3_trace.js` 등 다른 파일도 통과(π_u 를 직접 쓰는 곳은 `cia.js`·`lib/mode3_wallet.js` 뿐이며 unit 그룹에는 없다).

- [ ] **Step 5: 커밋**

```bash
git add lib/mode3_credential.js lib/mode3_issuance.js tests/test_mode3_credential_v5.js tests/test_mode3_issuance.js
git commit -m "feat(mode3): 선택 공개 1/7 — 속성 64비트, π_u V2(AA 가 속성 항을 빼고 PoK), attrsRequestMessage"
```

---

### Task 2: 회로 V6 — 속성 64비트, 공개 술어, 공개 입력 23개

**Files:**
- Modify: `circuits/lib/mode3_commit.circom` (`CommitUser` 의 attrs 비트 폭)
- Modify: `circuits/pi_cred.circom` (공개 술어 블록, `main` 의 public 목록)
- Modify: `tests/helpers/mode3_fixture.mjs` (`disclosure` 옵션, `disc_*` 입력)
- Test: `tests/test_pi_cred_witness.mjs`
- Regenerates: `build/mode3/*`, `contracts/PiCredVerifier.sol` (빌드 스크립트가 만든다)

**Interfaces:**
- Consumes: Task 1 의 `ATTR_MAX` (픽스처 값이 64비트 안이면 됨).
- Produces:
  - 회로 입력 `disc_mask`, `disc_lo[4]`, `disc_hi[4]` (public). 공개 입력 23개, 순서는 Global Constraints.
  - `buildValidInput({ pk_i, maxHeight, allowAgent, chainid, disclosure })` — `disclosure` 는 `{ mask: bigint, lo: bigint[4], hi: bigint[4] }` 또는 생략(mask 0). 반환 객체에 `disclosure` 필드 추가, `input` 에 `disc_mask`, `disc_lo`, `disc_hi`(10진 문자열) 포함. 픽스처의 `attrs` 는 `[1990n, 410n, 2n, 0n]` 으로 바꾼다.
  - `contracts/PiCredVerifier.sol` 의 `verifyProof(..., uint[23])`.

- [ ] **Step 1: 실패하는 증인 테스트**

`tests/test_pi_cred_witness.mjs` 에 추가(기존 케이스 뒤, `process.exit` 앞). 파일이 쓰는 헬퍼 이름(`calc`/`expectFail` 등)은 파일 안의 것을 그대로 쓴다:

```js
await t('V6 양성: mask = 0 이면 lo·hi 가 0 이어도 통과 (로그인 문장)', async () => {
  const fx = await buildValidInput();
  assert.equal(fx.input.disc_mask, '0');
  await calc(fx.input);
});
await t('V6 양성: 슬롯 0 구간 [0, 2007], 슬롯 1 등식 410 — 통과', async () => {
  const fx = await buildValidInput({ disclosure: { mask: 0b0011n, lo: [0n, 410n, 0n, 0n], hi: [2007n, 410n, 0n, 0n] } });
  await calc(fx.input);
});
await t('V6 음성: 구간 밖(a₀ = 1990 ∉ [0, 1980]) 은 거부', async () => {
  const fx = await buildValidInput({ disclosure: { mask: 0b0001n, lo: [0n, 0n, 0n, 0n], hi: [1980n, 0n, 0n, 0n] } });
  await expectFail(fx.input);
});
await t('V6 음성: 등식 불일치(a₁ = 410, lo = hi = 840) 는 거부', async () => {
  const fx = await buildValidInput({ disclosure: { mask: 0b0010n, lo: [0n, 840n, 0n, 0n], hi: [0n, 840n, 0n, 0n] } });
  await expectFail(fx.input);
});
await t('V6 양성: 공개하지 않는 슬롯의 lo·hi 는 무시된다 (mask 비트 0 인 슬롯 2 에 불가능한 구간)', async () => {
  const fx = await buildValidInput({ disclosure: { mask: 0b0001n, lo: [0n, 0n, 999n, 0n], hi: [2007n, 0n, 5n, 0n] } });
  await calc(fx.input);
});
await t('V6 음성: mask ≥ 16, lo ≥ 2^64, attr ≥ 2^64 는 거부', async () => {
  const ok = await buildValidInput({ disclosure: { mask: 0b0001n, lo: [0n, 0n, 0n, 0n], hi: [2007n, 0n, 0n, 0n] } });
  await expectFail({ ...ok.input, disc_mask: '16' });
  await expectFail({ ...ok.input, disc_lo: [(1n << 64n).toString(), '0', '0', '0'] });
  const big = await buildValidInput();
  await expectFail({ ...big.input, attrs: [(1n << 64n).toString(), '410', '2', '0'] });   // C_u 가 달라져 서명도 깨지지만 Num2Bits(64) 가 먼저 막는다
});
```

- [ ] **Step 2: 실패 확인**

Run: `node tests/test_pi_cred_witness.mjs`
Expected: FAIL — `disc_mask` 가 회로 입력에 없어 witness 계산이 "Too many values for input signal" 또는 픽스처에 `disclosure` 옵션이 없어 `disc_mask` undefined.

- [ ] **Step 3: 회로 수정**

`circuits/lib/mode3_commit.circom` `CommitUser`: 속성만 64비트로.

```circom
    var N = 250;
    var NA = 64;   // 속성은 64비트 정수(2026-09-22 선택 공개 §4.1) — pi_cred 의 LessEqThan(64) 전제. 다른 스칼라는 250비트 그대로
    ...
    component bAttr[4];
    for (var j = 0; j < 4; j++) { bAttr[j] = Num2Bits(NA); bAttr[j].in <== attrs[j]; }
    ...
    component mAttr[4];
    for (var j = 0; j < 4; j++) mAttr[j] = EscalarMulFix(NA, G_ATTR[j]);
    for (var i = 0; i < N; i++) {
        mUid.e[i]   <== bUid.out[i];
        mSu.e[i]    <== bSu.out[i];
        mBlind.e[i] <== bBlind.out[i];
    }
    for (var i = 0; i < NA; i++) for (var j = 0; j < 4; j++) mAttr[j].e[i] <== bAttr[j].out[i];
```

(EscalarMulFix(NA, BASE) 는 처음 NA 비트만 쓰는 고정 기저 곱이라 결과 점은 250비트 판과 같다 — 상위 비트가 0 이므로. JS `userCommit` 은 바꿀 필요 없다.)

`circuits/pi_cred.circom` — 헤더 주석에 "V6(2026-09-22): 공개 술어 disc_mask/lo/hi, 속성 64비트. 설계 2026-09-22-mode3-selective-disclosure-design.md §4" 추가. `// ---- Public ----` 끝에:

```circom
    // 선택 공개(2026-09-22 §4.2). 비트 k 가 1 이면 disc_lo[k] ≤ attrs[k] ≤ disc_hi[k]. 등식 공개는 lo = hi. 0 인 슬롯은 무시.
    signal input disc_mask;
    signal input disc_lo[4];
    signal input disc_hi[4];
```

`// ---- ⑤ 트레이스 태그 ----` 뒤(파일 끝 템플릿 안)에:

```circom
    // ---- ⑥ 선택 공개 술어 (2026-09-22) ----
    // 속성은 CommitUser 에서 Num2Bits(64) 로 잘려 있다. lo·hi 도 64비트로 묶어야 LessEqThan(64) 이 성립한다.
    component maskBits = Num2Bits(4);
    maskBits.in <== disc_mask;
    component loBits[4]; component hiBits[4]; component ge[4]; component le[4];
    signal discOk[4];
    for (var k = 0; k < 4; k++) {
        loBits[k] = Num2Bits(64); loBits[k].in <== disc_lo[k];
        hiBits[k] = Num2Bits(64); hiBits[k].in <== disc_hi[k];
        ge[k] = LessEqThan(64); ge[k].in[0] <== disc_lo[k]; ge[k].in[1] <== attrs[k];
        le[k] = LessEqThan(64); le[k].in[0] <== attrs[k];   le[k].in[1] <== disc_hi[k];
        discOk[k] <== ge[k].out * le[k].out;
        maskBits.out[k] * (1 - discOk[k]) === 0;
    }
```

`main`:

```circom
component main {public [
    PPID, arid, pk_i, max_height, chainid, allowAgent, revRoot, pk_CIA_x, pk_CIA_y,
    pk_trace_x, pk_trace_y, tag_c1_x, tag_c1_y, tag_c2,
    disc_mask, disc_lo, disc_hi
]} = PiCred(32);
```

주석의 "공개 입력의 순서는 … 바꾸지 말 것" 문장에 `[14] disc_mask [15..18] disc_lo [19..22] disc_hi` 를 덧붙인다.

- [ ] **Step 4: 픽스처**

`tests/helpers/mode3_fixture.mjs`:

```js
export async function buildValidInput({ pk_i: pkIOpt, maxHeight = 1789000000n, allowAgent = 0n, chainid = 31337n, disclosure = null } = {}) {
  ...
  const attrs   = [1990n, 410n, 2n, 0n];   // 데모 testuser 와 같은 값(스펙 2026-09-22 §3.1) — 64비트
  ...
  const disc = disclosure ?? { mask: 0n, lo: [0n, 0n, 0n, 0n], hi: [0n, 0n, 0n, 0n] };
  const input = {
    ... 기존 필드 ...,
    disc_mask: disc.mask.toString(), disc_lo: disc.lo.map(String), disc_hi: disc.hi.map(String),
  };
  return { ..., attrs, disclosure: disc, ... };
}
```

(반환 객체에 이미 `attrs` 가 있으면 값만 바뀐다. 다른 반환 필드는 그대로.)

- [ ] **Step 5: 빌드**

Run: `bash scripts/build_mode3_circuit.sh`
Expected: 컴파일 로그에 `non-linear constraints` 가 V5(26,601) 보다 **작다**(속성 4×186 비트 절감 > 술어 추가) — 값을 기록해 둔다. `contracts/PiCredVerifier.sol` 이 `uint[23] calldata _pubSignals` 로 재생성된다(`grep -n 'uint\[23\]' contracts/PiCredVerifier.sol`).

- [ ] **Step 6: 통과 확인**

Run: `node tests/test_pi_cred_witness.mjs`
Expected: 기존 케이스 + 새 6건 전부 `ok`. (기존 "attr 하나를 바꾸면 거부" 케이스는 그대로 통과해야 한다.)

- [ ] **Step 7: 커밋**

```bash
git add circuits/lib/mode3_commit.circom circuits/pi_cred.circom tests/helpers/mode3_fixture.mjs tests/test_pi_cred_witness.mjs contracts/PiCredVerifier.sol
git commit -m "feat(mode3): 선택 공개 2/7 — 회로 V6(속성 64비트, 공개 술어 mask/lo/hi, 공개 입력 23개), 검증자 재생성, 픽스처"
```

`build/mode3/` 는 git 밖(생성물)이다.

---

### Task 3: 컨트랙트 — `Mode3Wallet` 23개·꼬리 전달·mask 다이제스트, 팩토리 `isWallet`, `AttrGate`

**Files:**
- Modify: `contracts/Mode3Wallet.sol`
- Modify: `contracts/Mode3WalletFactory.sol`
- Create: `contracts/AttrGate.sol`
- Modify: `lib/mode3_onchain.js` (ABI, `payloadDigest`, `deployAttrGate`, `attrGateAt`, `parseExecuteReceipt`)
- Test: `test/Mode3Wallet.test.mjs`

**Interfaces:**
- Consumes: Task 2 의 `PiCredVerifier(uint[23])`, `buildValidInput({ disclosure })`.
- Produces:
  - `Mode3Wallet.execute(Payload, bytes sig, uint[2] a, uint[2][2] b, uint[2] c, uint[23] pub)`; 새 `error BadDisclosure()`; 새 `event Disclosure(uint256 indexed nonceUsed, uint256 mask, uint256[4] lo, uint256[4] hi)`.
  - 다이제스트 `keccak256(abi.encode(block.chainid, address(this), to, value, data, nonce, pub[14]))`.
  - `Mode3WalletFactory.isWallet(address) → bool`.
  - `AttrGate(address factory, uint64 countryEq, uint64 birthYearMax)`; `claim()`; `claimed(address) → bool`; `event Claimed(address indexed wallet, uint64 birthYearHi, uint64 country)`; revert 문자열 `"not a mode3 wallet"`, `"no disclosure"`, `"need slot0,1"`, `"country"`, `"age"`, `"already claimed"`.
  - `lib/mode3_onchain.js`: `payloadDigest({ chainId, wallet, to, value, data, nonce, discMask })`, `signPayload(sessionWallet, fields)` 같은 필드; `WALLET_ABI` 의 execute `uint256[23]` + Disclosure 이벤트 + BadDisclosure; `FACTORY_ABI` 에 `isWallet`; `export const ATTR_GATE_ABI`, `deployAttrGate(signer, { factoryAddress, countryEq = 410n, birthYearMax = 2007n })`, `attrGateAt(address, runner)`; `parseExecuteReceipt` 가 `disclosure: { mask, lo[4], hi[4] } | null` 을 더 돌려준다; `decodeExecuteCalldata` 는 `pub` 23개를 그대로 돌려준다.

- [ ] **Step 1: 실패하는 컨트랙트 테스트**

`test/Mode3Wallet.test.mjs` — `signedPayload` 에 `discMask` 인자를 더하고 케이스 추가:

```js
  async function signedPayload(st, wallet, { to = ethers.Wallet.createRandom().address, value = 0n, data = '0x', discMask = 0n } = {}) {
    const nonce = await wallet.nonce();
    const payload = { to, value, data, nonce };
    const sig = signPayload(st.session, { chainId: await chainId(), wallet: wallet.target, ...payload, discMask });
    return { payload, sig };
  }
```

케이스(기존 `it` 들 뒤):

```js
  it('V6: pub 은 23개이고 mask = 0 이면 꼬리 없이 실행, Disclosure 이벤트 없음', async () => {
    const { wallet } = await deployStack(ST);
    const { payload, sig } = await signedPayload(ST, wallet);
    const rc = await (await wallet.execute(payload, sig, ST.a, ST.b, ST.c, ST.pub)).wait();
    assert.equal(ST.pub.length, 23);
    const { disclosure } = parseExecuteReceipt(rc, wallet.target);
    assert.equal(disclosure, null);
  });

  it('V6: mask ≠ 0 이면 대상이 꼬리 9워드를 읽고 AttrGate.claim 이 통과한다; Disclosure 이벤트; 두 번째 claim 은 already claimed', async () => {
    const DS = withInput(await statement({ disclosure: { mask: 0b0011n, lo: [0n, 410n, 0n, 0n], hi: [2007n, 410n, 0n, 0n] } }));
    const { wallet, factory } = await deployStack(DS);
    const Gate = await ethers.getContractFactory('AttrGate');
    const gate = await Gate.deploy(await factory.getAddress(), 410n, 2007n);
    const data = gate.interface.encodeFunctionData('claim');
    const { payload, sig } = await signedPayload(DS, wallet, { to: await gate.getAddress(), data, discMask: 0b0011n });
    const rc = await (await wallet.execute(payload, sig, DS.a, DS.b, DS.c, DS.pub)).wait();
    const { executed, disclosure } = parseExecuteReceipt(rc, wallet.target);
    assert.equal(executed.success, true);
    assert.equal(disclosure.mask, 3n); assert.equal(disclosure.hi[0], 2007n); assert.equal(disclosure.lo[1], 410n);
    assert.equal(await gate.claimed(wallet.target), true);
    const again = await signedPayload(DS, wallet, { to: await gate.getAddress(), data, discMask: 0b0011n });
    const rc2 = await (await wallet.execute(again.payload, again.sig, DS.a, DS.b, DS.c, DS.pub)).wait();
    assert.equal(parseExecuteReceipt(rc2, wallet.target).executed.success, false, 'already claimed → 내부 호출 실패, nonce 는 소모');
  });

  it('V6: 국가가 다르면 claim 이 실패(success=false), 나이 상한을 넘겨도 실패', async () => {
    const bad = withInput(await statement({ disclosure: { mask: 0b0011n, lo: [0n, 840n, 0n, 0n], hi: [2007n, 840n, 0n, 0n] } }));
    // 픽스처 속성은 [1990, 410, 2, 0] 이라 a₁ = 840 등식은 증명 자체가 안 만들어진다 → 이 케이스는 alice 형 속성의 픽스처가 없으므로
    // 대신 "정책보다 넓은 구간" 으로 시험한다: hi[0] = 2010 (> birthYearMax 2007) 는 증명은 되지만 게이트가 거절한다.
    const wide = withInput(await statement({ disclosure: { mask: 0b0011n, lo: [0n, 410n, 0n, 0n], hi: [2010n, 410n, 0n, 0n] } }));
    const { wallet, factory } = await deployStack(wide);
    const Gate = await ethers.getContractFactory('AttrGate');
    const gate = await Gate.deploy(await factory.getAddress(), 410n, 2007n);
    const data = gate.interface.encodeFunctionData('claim');
    const { payload, sig } = await signedPayload(wide, wallet, { to: await gate.getAddress(), data, discMask: 0b0011n });
    const rc = await (await wallet.execute(payload, sig, wide.a, wide.b, wide.c, wide.pub)).wait();
    assert.equal(parseExecuteReceipt(rc, wallet.target).executed.success, false);
    assert.equal(await gate.claimed(wallet.target), false);
    void bad;
  });
```

위 세 번째 케이스에서 `bad` 는 증명 생성이 실패한다(회로가 거절) — `statement()` 가 throw 하므로 그 줄은 **지우고** `wide` 만 남긴다(주석은 왜 국가 불일치를 온체인에서 시험하지 않는지 설명으로 남긴다). 추가 케이스:

```js
  it('V6: EOA 가 꼬리를 흉내 내 AttrGate.claim 을 직접 부르면 not a mode3 wallet', async () => {
    const { factory } = await deployStack(ST);
    const Gate = await ethers.getContractFactory('AttrGate');
    const gate = await Gate.deploy(await factory.getAddress(), 410n, 2007n);
    const [eoa] = await ethers.getSigners();
    const tail = ethers.AbiCoder.defaultAbiCoder().encode(['uint256', 'uint256[4]', 'uint256[4]'], [3n, [0n, 410n, 0n, 0n], [2007n, 410n, 0n, 0n]]);
    await assert.rejects(eoa.sendTransaction({ to: await gate.getAddress(), data: gate.interface.encodeFunctionData('claim') + tail.slice(2) }), /not a mode3 wallet/);
  });

  it('V6: 다이제스트가 mask 를 덮는다 — mask 0 으로 서명한 σ 로 mask 3 의 π 를 붙이면 BadSignature', async () => {
    const DS = withInput(await statement({ disclosure: { mask: 0b0011n, lo: [0n, 410n, 0n, 0n], hi: [2007n, 410n, 0n, 0n] } }));
    const { wallet } = await deployStack(DS);
    const { payload, sig } = await signedPayload(DS, wallet, { discMask: 0n });
    await assert.rejects(wallet.execute(payload, sig, DS.a, DS.b, DS.c, DS.pub), /BadSignature/);
  });

  it('V6: pub[14] ≥ 16 은 BadDisclosure (증명 검증 전에 걸린다)', async () => {
    const { wallet } = await deployStack(ST);
    const { payload, sig } = await signedPayload(ST, wallet, { discMask: 16n });
    const pub = [...ST.pub]; pub[14] = 16n;
    await assert.rejects(wallet.execute(payload, sig, ST.a, ST.b, ST.c, pub), /BadDisclosure/);
  });

  it('V6: factory.isWallet 은 배포한 지갑만 true', async () => {
    const { factory, walletAddr } = await deployStack(ST);
    assert.equal(await factory.isWallet(walletAddr), true);
    assert.equal(await factory.isWallet(ethers.Wallet.createRandom().address), false);
  });
```

(`parseExecuteReceipt` import 가 없으면 `../lib/mode3_onchain.js` 에서 가져온다. `statement(opts)` 는 `buildValidInput` 에 `opts` 를 그대로 넘기므로 `disclosure` 가 전달된다.)

- [ ] **Step 2: 실패 확인**

Run: `npx hardhat test test/Mode3Wallet.test.mjs`
Expected: 컴파일 단계에서 `Mode3Wallet.sol` 이 `uint[14]` 로 `PiCredVerifier.verifyProof(uint[23])` 를 부르지 못해 컴파일 에러(또는 `AttrGate` 없음).

- [ ] **Step 3: 컨트랙트 구현**

`contracts/Mode3Wallet.sol`:

```solidity
    error BadDisclosure();
    /// @notice 공개한 속성 구간(2026-09-22 선택 공개 §5.1). 대상 컨트랙트가 읽은 값과 같은 것을 이벤트로 남긴다.
    event Disclosure(uint256 indexed nonceUsed, uint256 mask, uint256[4] lo, uint256[4] hi);

    /// @param pub 공개 입력 23개(circuits/pi_cred.circom 의 순서):
    ///   [0] PPID … [13] tag_c2 [14] disc_mask [15..18] disc_lo [19..22] disc_hi
    function execute(Payload calldata payload, bytes calldata sig,
                     uint[2] calldata a, uint[2][2] calldata b, uint[2] calldata c, uint[23] calldata pub)
        external returns (bool ok)
    {
        if (payload.nonce != nonce) revert NonceMismatch(nonce, payload.nonce);
        // 다이제스트가 disc_mask 를 덮는다 — 같은 세션키의 π 가 둘(mask 0·mask ≠ 0) 있어도 릴레이어가 고르지 못한다(§5.1).
        bytes32 payloadHash = keccak256(
            abi.encode(block.chainid, address(this), payload.to, payload.value, payload.data, payload.nonce, pub[14])
        );
        address recovered = _recover(payloadHash, sig);
        if (recovered == address(0)) revert BadSignature();
        if (recovered != address(uint160(pub[2]))) revert BadSignature();

        _checkStatement(pub);
        if (!verifier.verifyProof(a, b, c, pub)) revert InvalidProof();

        nonce += 1;
        bytes memory data = payload.data;
        if (pub[14] != 0) {
            // 꼬리 9워드(288바이트): mask, lo[4], hi[4]. 대상은 calldatasize 끝에서 읽는다(ERC-2771 방식). mask = 0 이면 붙이지 않아
            // 꼬리를 모르는 대상과 호환된다. Solidity ABI 디코더는 남는 calldata 를 무시한다.
            data = abi.encodePacked(payload.data, pub[14], pub[15], pub[16], pub[17], pub[18], pub[19], pub[20], pub[21], pub[22]);
        }
        (ok, ) = payload.to.call{value: payload.value}(data);
        emit Executed(payload.nonce, payload.to, payload.value, ok);
        emit Mode3Auth(payload.nonce, pub[2], pub[3], pub[5], pub[11], pub[12], pub[13]);
        if (pub[14] != 0) {
            emit Disclosure(payload.nonce, pub[14], [pub[15], pub[16], pub[17], pub[18]], [pub[19], pub[20], pub[21], pub[22]]);
        }
    }

    function _checkStatement(uint[23] calldata pub) internal view {
        ... 기존 검사 그대로 ...
        if (pub[14] >= 16) revert BadDisclosure();   // ⑤′ mask 는 4비트. 회로도 막지만 이벤트·꼬리에 남는 값이라 한 번 더
        ... root·만료 검사 그대로 ...
    }
```

(구현 시 리뷰 반영으로 lo/hi 까지 덮도록 확장됨 — Global Constraints 참조.)

(`BadAllowAgent` 검사 바로 뒤에 `BadDisclosure` 를 둔다 — 싼 검사부터.) `contracts/Mode3WalletFactory.sol`:

```solidity
    /// @notice 이 팩토리가 배포한 지갑. 대상 컨트랙트(AttrGate)가 msg.sender 를 확인하는 데 쓴다 — 꼬리 9워드는 π 를 검증한 지갑만 붙일 수 있다.
    mapping(address => bool) public isWallet;
    ...
    function deploy(uint256 ppid) external returns (address wallet) {
        wallet = computeAddress(ppid);
        if (wallet.code.length > 0) { isWallet[wallet] = true; return wallet; }   // 다른 경로로 이미 있어도 이 팩토리 코드로 만든 주소다
        Mode3Wallet deployed = new Mode3Wallet{salt: bytes32(ppid)}(...);
        require(address(deployed) == wallet, "CREATE2 address mismatch");
        isWallet[wallet] = true;
    }
```

`contracts/AttrGate.sol` (새 파일):

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./Mode3WalletFactory.sol";

/// @title 데모 대상 — 공개된 속성 구간으로 문을 연다 (선택 공개 설계 2026-09-22 §5.3)
/// @notice Mode3Wallet.execute 가 π 검증 뒤 호출 데이터 꼬리에 붙인 (mask, lo[4], hi[4]) 를 읽는다. 꼬리는 팩토리가 배포한
///   지갑만 붙일 수 있으므로 msg.sender 를 팩토리로 확인한다. 정책: 국가(a₁) = countryEq, 출생연도(a₀) ≤ birthYearMax.
contract AttrGate {
    Mode3WalletFactory public immutable factory;
    uint64 public immutable countryEq;
    uint64 public immutable birthYearMax;
    mapping(address => bool) public claimed;

    event Claimed(address indexed wallet, uint64 birthYearHi, uint64 country);

    uint256 private constant TAIL = 9 * 32;

    constructor(address _factory, uint64 _countryEq, uint64 _birthYearMax) {
        factory = Mode3WalletFactory(_factory); countryEq = _countryEq; birthYearMax = _birthYearMax;
    }

    /// @dev calldata 끝 288바이트 = mask, lo[0..3], hi[0..3] (각 32바이트 워드).
    function _disclosure() internal pure returns (uint256 mask, uint256[4] memory lo, uint256[4] memory hi) {
        require(msg.data.length >= 4 + TAIL, "no disclosure");
        uint256 base = msg.data.length - TAIL;
        assembly {
            mask := calldataload(base)
        }
        for (uint256 k = 0; k < 4; k++) {
            uint256 l; uint256 h;
            uint256 pl = base + 32 * (1 + k); uint256 ph = base + 32 * (5 + k);
            assembly { l := calldataload(pl) h := calldataload(ph) }
            lo[k] = l; hi[k] = h;
        }
    }

    function claim() external {
        require(factory.isWallet(msg.sender), "not a mode3 wallet");
        require(!claimed[msg.sender], "already claimed");
        (uint256 mask, uint256[4] memory lo, uint256[4] memory hi) = _disclosure();
        require(mask & 0x3 == 0x3, "need slot0,1");
        require(lo[1] == countryEq && hi[1] == countryEq, "country");
        require(hi[0] <= birthYearMax, "age");
        claimed[msg.sender] = true;
        emit Claimed(msg.sender, uint64(hi[0]), uint64(lo[1]));
    }
}
```

`claim()` 셀렉터 4바이트 뒤에 바로 꼬리가 오므로 `msg.data.length == 4 + 288` 이 정상 경로다. `>=` 로 두어 앞으로 인자가 있는 함수도 같은 헬퍼를 쓴다.

- [ ] **Step 4: `lib/mode3_onchain.js`**

```js
export const WALLET_ABI = [
  ...,
  'function execute((address to,uint256 value,bytes data,uint256 nonce) payload, bytes sig, uint256[2] a, uint256[2][2] b, uint256[2] c, uint256[23] pub) returns (bool)',
  ...,
  'event Disclosure(uint256 indexed nonceUsed, uint256 mask, uint256[4] lo, uint256[4] hi)',
  'error BadDisclosure()',
  ...,
];
export const FACTORY_ABI = [..., 'function isWallet(address) view returns (bool)'];
export const ATTR_GATE_ABI = [
  'function claim()',
  'function claimed(address) view returns (bool)',
  'function factory() view returns (address)',
  'function countryEq() view returns (uint64)',
  'function birthYearMax() view returns (uint64)',
  'event Claimed(address indexed wallet, uint64 birthYearHi, uint64 country)',
];

/** Mode3Wallet.execute 의 서명 digest: keccak256(abi.encode(chainid, wallet, to, value, data, nonce, discMask)). discMask 는 π 의 pub[14](2026-09-22 §5.1). */
export function payloadDigest({ chainId, wallet, to, value, data, nonce, discMask = 0n }) {
  return ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
    ['uint256', 'address', 'address', 'uint256', 'bytes', 'uint256', 'uint256'],
    [chainId, wallet, to, value, data, nonce, discMask],
  ));
}

export async function deployAttrGate(signer, { factoryAddress, countryEq = 410n, birthYearMax = 2007n }) {
  const { abi, bytecode } = readArtifact('AttrGate');
  const c = await new ethers.ContractFactory(abi, bytecode, signer).deploy(factoryAddress, countryEq, birthYearMax);
  await c.waitForDeployment();
  return c.getAddress();
}
export const attrGateAt = (address, runner) => new ethers.Contract(address, ATTR_GATE_ABI, runner);
```

(구현 시 리뷰 반영으로 `discLo`·`discHi` 까지 받도록 확장됨 — Global Constraints 참조.)

`parseExecuteReceipt` 루프에 `if (p.name === 'Disclosure') disclosure = { mask: p.args.mask, lo: [...p.args.lo], hi: [...p.args.hi] };` 를 더하고 `return { executed, auth, disclosure }` (초기값 `null`). `proofToCalldata` 주석의 "14개" 를 "23개" 로.

- [ ] **Step 5: 통과 확인**

Run: `npx hardhat test test/Mode3Wallet.test.mjs`
Expected: 기존 케이스(“정상 실행… gas 기록” 의 gas 값은 바뀐다 — 로그로만 남는다) + 새 7건 통과. 이어 `bash scripts/run_tests.sh contract` 전체 통과.

- [ ] **Step 6: 커밋**

```bash
git add contracts/Mode3Wallet.sol contracts/Mode3WalletFactory.sol contracts/AttrGate.sol lib/mode3_onchain.js test/Mode3Wallet.test.mjs
git commit -m "feat(mode3): 선택 공개 3/7 — Mode3Wallet 공개 입력 23개·mask 다이제스트·꼬리 전달·Disclosure 이벤트, 팩토리 isWallet, AttrGate"
```

---

### Task 4: CIA — 속성 기록(v7), 등록 응답·`/cia/attrs`·관리자 변경, π_u V2 검증

**Files:**
- Modify: `lib/mode3_cia_state.js` (v7)
- Modify: `cia.js` (`DEMO_ACCOUNTS`, `/cia/register`, `/cia/user_cred`, 새 `/cia/attrs`, 새 `/cia/accounts/:uid/attrs`)
- Modify: `mode3/cia_admin.html` (계정 속성 편집)
- Test: `tests/test_mode3_cia_state.js`, `tests/test_cia_register_issue.mjs`, `tests/test_cia_startup.mjs`(v7 기동만 확인)

**Interfaces:**
- Consumes: Task 1 의 `verifyUserCred({ uid, attrs, … })`, `attrsRequestMessage`, `normalizeAttrs`.
- Produces:
  - `CIA_STATE_VERSION = 7`; `accounts[uid].attrs: string[4]`(10진). `migrateCiaState` v6→v7: `attrs` 채우기(인자로 받은 `demoAttrs(uid)` 콜백, 없으면 `['0','0','0','0']`) + 모든 `creds` 의 `revoked = true`, 그 리프를 `revoked`·`pending` 에 push(트리는 cia.js 기동 시 `revoked` 배열로 재구성하므로 상태 배열만 갱신).
  - `POST /cia/register` 201 응답: `{ pk_u, sk_u, attrs }`.
  - `POST /cia/attrs` `{ uid, nonce, sig_u }` → 200 `{ attrs }`; 400 형식/서명, 404 계정 없음.
  - `POST /cia/accounts/:uid/attrs` (requireAdmin) `{ attrs }` → 200 `{ uid, attrs, inserted }`; 400 범위, 404.
  - `POST /cia/user_cred`: π_u 검증에 `attrs: acct.attrs` 사용; 실패는 기존과 같은 400 `'bad user credential proof'`.
  - `GET /cia/accounts` (requireAdmin, 이미 있으면 attrs 필드만 추가; 없으면 새로: `{ accounts: [{ uid, disabled, attrs, activeCf_u }] }`).

- [ ] **Step 1: 실패하는 테스트**

`tests/test_mode3_cia_state.js`:

```js
await t('v6 → v7: attrs 가 채워지고 활성 자격증명은 전부 물려 revoked·pending 에 리프가 들어간다', () => {
  const s = { version: 6, accounts: { '12345': { pk_u: {}, cm_u: {}, disabled: false, creds: [{ Cf_u: '1', C_u_pt: {}, leaf: '111', issuedAt: 'x', revoked: false }, { Cf_u: '2', C_u_pt: {}, leaf: '222', issuedAt: 'y', revoked: true }] } }, rps: {}, openings: [], revoked: ['222'], pending: [], epoch: 0 };
  const m = migrateCiaState(s, { demoAttrs: (uid) => (uid === '12345' ? ['1990', '410', '2', '0'] : null) });
  assert.equal(m.version, 7);
  assert.deepEqual(m.accounts['12345'].attrs, ['1990', '410', '2', '0']);
  assert.equal(m.accounts['12345'].creds[0].revoked, true);
  assert.deepEqual(m.revoked, ['222', '111']); assert.deepEqual(m.pending, ['111']);
});
await t('v7 기본 상태와 demoAttrs 없는 계정은 0 네 개', () => {
  assert.equal(defaultCiaState().version, 7);
  const m = migrateCiaState({ version: 6, accounts: { '1': { pk_u: {}, cm_u: {}, disabled: false, creds: [] } }, rps: {}, openings: [], revoked: [], pending: [], epoch: 0 });
  assert.deepEqual(m.accounts['1'].attrs, ['0', '0', '0', '0']);
});
```

`tests/test_cia_register_issue.mjs` — 등록·user_cred 케이스 근처에 추가(파일의 `cia.post`/`cia.adminPost`/`registerWallet` 류 헬퍼를 그대로 쓴다):

```js
await t('register 응답에 AA 기록 attrs 가 실린다; /cia/attrs 는 sk_u 서명으로 같은 값을 돌려준다', async () => {
  const w = await freshWallet();                                           // 파일의 등록 헬퍼(uid 12345 testuser)
  assert.deepEqual(w.registerBody.attrs, ['1990', '410', '2', '0']);
  const nonce = 99n;
  const sig_u = await signAttrsRequest(w.sk_u, 12345n, nonce);           // lib/mode3_wallet.js (Task 5 에서 추가) — 이 테스트에서는 eddsa 로 직접 서명해도 된다
  const r = await cia.post('/cia/attrs', { uid: '12345', nonce: nonce.toString(), sig_u });
  assert.equal(r.status, 200); assert.deepEqual(r.body.attrs, ['1990', '410', '2', '0']);
  assert.equal((await cia.post('/cia/attrs', { uid: '12345', nonce: '100', sig_u })).status, 400, '다른 nonce 의 서명은 거절');
});

await t('user_cred: 지갑이 AA 기록과 다른 attrs 로 만든 C_u 는 400 bad proof; 같은 값이면 201', async () => {
  const w = await freshWallet();
  const bad = await buildUserCredRequest({ uid: 12345n, s_u: w.s_u, r_u: w.r_u, sk_u: w.sk_u, attrs: [1991n, 410n, 2n, 0n] });
  assert.equal((await cia.post('/cia/user_cred', bad.body)).status, 400);
  const good = await buildUserCredRequest({ uid: 12345n, s_u: w.s_u, r_u: w.r_u, sk_u: w.sk_u, attrs: [1990n, 410n, 2n, 0n] });
  assert.equal((await cia.post('/cia/user_cred', good.body)).status, 201);
});

await t('관리자 속성 변경: 활성 C_u 가 물리고(inserted 1) 다음 user_cred 는 새 값으로만 통과', async () => {
  const w = await freshWallet();
  const good = await buildUserCredRequest({ uid: 12345n, s_u: w.s_u, r_u: w.r_u, sk_u: w.sk_u, attrs: [1990n, 410n, 2n, 0n] });
  assert.equal((await cia.post('/cia/user_cred', good.body)).status, 201);
  const r = await cia.adminPost('/cia/accounts/12345/attrs', { attrs: ['1990', '410', '3', '0'] });
  assert.equal(r.status, 200); assert.equal(r.body.inserted.length, 1);
  assert.equal((await cia.post('/cia/user_cred', good.body)).status, 400, '옛 속성의 C_u 는 더 이상 통과하지 않는다');
  const next = await buildUserCredRequest({ uid: 12345n, s_u: w.s_u, r_u: w.r_u, sk_u: w.sk_u, attrs: [1990n, 410n, 3n, 0n] });
  assert.equal((await cia.post('/cia/user_cred', next.body)).status, 201);
  assert.equal((await cia.adminPost('/cia/accounts/12345/attrs', { attrs: [(1n << 64n).toString(), '0', '0', '0'] })).status, 400);
  assert.equal((await cia.adminPost('/cia/accounts/424242/attrs', { attrs: ['1', '0', '0', '0'] })).status, 404);
});
```

`freshWallet()` 이 없으면 파일의 기존 등록 코드(createRegistration → `/cia/register` → sk_u)를 그 이름의 헬퍼로 뽑아 쓴다. 이 파일의 기존 user_cred 케이스들은 attrs 를 `[19n, 410n, 0n, 0n]` 등으로 넣고 있을 수 있다 — **testuser 는 `[1990n, 410n, 2n, 0n]`, alice 는 `[2005n, 840n, 1n, 0n]`** 으로 바꿔야 통과한다.

- [ ] **Step 2: 실패 확인**

Run: `node tests/test_mode3_cia_state.js`
Expected: FAIL — `migrateCiaState` 두 번째 인자 무시, version 6.

- [ ] **Step 3: `lib/mode3_cia_state.js`**

```js
// version 7 (2026-09-22): accounts[uid].attrs (AA 가 보증하는 속성 4슬롯, 10진 문자열). 기존 활성 자격증명은 사용자가 고른 속성이라
//   보증되지 않으므로 전부 물린다(리프 → revoked·pending). 지갑은 다음 세션 발급의 no_user_cred 로 새 C_u 를 받는다.
export const CIA_STATE_VERSION = 7;
...
export function migrateCiaState(state, { demoAttrs = () => null } = {}) {
  ...
  if (state.version === 6) {
    for (const [uid, acct] of Object.entries(state.accounts ?? {})) {
      acct.attrs = demoAttrs(uid) ?? ['0', '0', '0', '0'];
      for (const c of acct.creds ?? []) {
        if (c.revoked) continue;
        c.revoked = true;
        if (!state.revoked.includes(c.leaf)) state.revoked.push(c.leaf);
        if (!state.pending.includes(c.leaf)) state.pending.push(c.leaf);
      }
    }
    state.version = 7;
  }
  ...
}
```

`defaultCiaState()` 의 version 은 상수를 쓰므로 자동으로 7.

- [ ] **Step 4: `cia.js`**

`DEMO_ACCOUNTS`:

```js
const DEMO_ACCOUNTS = {
  testuser: { password: 'password123', uid: '12345', attrs: ['1990', '410', '2', '0'] },   // a₀ 출생연도, a₁ 국가(ISO 3166 numeric), a₂ 등급, a₃ 예비
  alice: { password: 'alicepw', uid: '67890', attrs: ['2005', '840', '1', '0'] },
};
```

`cia.js` 152행 부근의 `migrateCiaState(state)` 를 `migrateCiaState(state, { demoAttrs: (uid) => Object.values(DEMO_ACCOUNTS).find((a) => a.uid === uid)?.attrs ?? null })` 로 바꾼다(`DEMO_ACCOUNTS` 는 그보다 위 64행에 있다). 트리는 기동 시 `state.revoked` 로 재구성되므로 마이그레이션이 넣은 리프가 곧바로 트리에 들어간다 — 기동 로그에 "v7 마이그레이션: 물린 자격증명 N개" 한 줄.

`/cia/register`: 계정 생성 시 `attrs: [...acct.attrs]` 를 넣고 응답에 `attrs`:

```js
  state.accounts[uid] = { pk_u: S(pub), cm_u: { x: cm_u.x, y: cm_u.y }, disabled: false, creds: [], attrs: [...acct.attrs] };
  persist();
  res.status(201).json({ pk_u: S(pub), sk_u: prv.toString('hex'), attrs: state.accounts[uid].attrs });
```

`/cia/user_cred` 의 π_u 검증:

```js
    try { proofOk = await verifyUserCred({ uid: BigInt(uid), attrs: acct.attrs.map(BigInt), C_u_pt: cpt, cm_u: pointFromStrings(acct.cm_u), proof: parseUserCredProof(proof) }); }
```

(주석에 "속성은 AA 기록(acct.attrs) — 요청의 값은 받지 않는다(2026-09-22 §3.4)".) 새 엔드포인트(`/cia/user_cred` 뒤):

```js
// 2026-09-22 §3.3 지갑이 자기 속성을 다시 받는다 — user_cred 가 bad proof 로 거절됐을 때(AA 기록이 바뀜). sk_u 서명으로 인증.
app.post('/cia/attrs', async (req, res) => {
  try {
    const { uid, nonce, sig_u } = req.body ?? {};
    if (!isDec(uid) || !isDec(nonce) || !sig_u) return res.status(400).json({ error: 'uid, nonce, sig_u required' });
    const acct = state.accounts[uid];
    if (!acct) return res.status(404).json({ error: 'unknown account' });
    let ok = false;
    try {
      const m = F.e(await attrsRequestMessage(BigInt(uid), BigInt(nonce)));
      ok = eddsa.verifyPoseidon(m, { R8: [F.e(BigInt(sig_u.R8x)), F.e(BigInt(sig_u.R8y))], S: BigInt(sig_u.S) }, [F.e(BigInt(acct.pk_u.x)), F.e(BigInt(acct.pk_u.y))]);
    } catch { ok = false; }
    if (!ok) return res.status(400).json({ error: 'bad user signature' });
    res.json({ attrs: acct.attrs });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// 2026-09-22 §3.3 관리자가 속성을 바꾼다. 활성 자격증명은 옛 속성이라 물린다(리프 → 다음 게시). 지갑은 다음 발급에서 재동기화한다.
app.post('/cia/accounts/:uid/attrs', requireAdmin, async (req, res) => {
  try {
    const uid = req.params.uid;
    const acct = state.accounts[uid];
    if (!isDec(uid) || !acct) return res.status(404).json({ error: 'unknown account' });
    let attrs;
    try { attrs = normalizeAttrs(req.body?.attrs).map(String); } catch (e) { return res.status(400).json({ error: `attrs: ${e.message}` }); }
    acct.attrs = attrs;
    const inserted = await retireActiveCred(uid);
    persist();
    res.json({ uid, attrs, inserted });
  } catch (err) { res.status(500).json({ error: err.message }); }
});
```

import 에 `attrsRequestMessage`(`./lib/mode3_issuance.js`)·`normalizeAttrs`(`./lib/mode3_credential.js`) 추가. `isDec` 이 `req.params` 문자열에도 쓰인다. 관리자 계정 목록 엔드포인트는 아직 없다 — `app.get('/cia/accounts', requireAdmin, (req, res) => res.json({ accounts: Object.entries(state.accounts).map(([uid, a]) => ({ uid, disabled: a.disabled, attrs: a.attrs, activeCf_u: activeCred(uid)?.Cf_u ?? null })) }))` 를 `/cia/account/set_disabled` 옆에 둔다(`activeCred` 는 221행의 기존 헬퍼).

- [ ] **Step 5: 관리자 페이지**

`mode3/cia_admin.html` 에 "계정" 표(uid, disabled, 속성 4칸 입력, 저장 버튼)를 추가한다. 저장은 `POST /cia/accounts/:uid/attrs` 에 `{ attrs }` — 페이지가 이미 쓰는 관리자 시크릿 헤더 방식을 그대로 따른다(`grep -n "x-admin\|Authorization" mode3/cia_admin.html`). 목록은 `GET /cia/accounts`.

- [ ] **Step 6: 통과 확인**

Run: `node tests/test_mode3_cia_state.js` → 통과. 이어 :8545 hardhat 을 세션이 띄운 뒤 `node tests/test_cia_startup.mjs && node tests/test_cia_register_issue.mjs` → 통과. (`test_cia_register_issue.mjs` 의 `signAttrsRequest` 는 Task 5 에서 라이브러리에 들어가므로, 이 Task 에서는 테스트 파일 안에 아래 로컬 헬퍼를 두고 Task 5 에서 import 로 바꾼다:)

```js
async function signAttrsRequest(sk_uHex, uid, nonce) {
  const eddsa = await buildEddsa(); const F = eddsa.F;
  const s = eddsa.signPoseidon(Buffer.from(sk_uHex, 'hex'), F.e(await attrsRequestMessage(uid, nonce)));
  return { R8x: F.toObject(s.R8[0]).toString(), R8y: F.toObject(s.R8[1]).toString(), S: s.S.toString() };
}
```

- [ ] **Step 7: 커밋**

```bash
git add lib/mode3_cia_state.js cia.js mode3/cia_admin.html tests/test_mode3_cia_state.js tests/test_cia_register_issue.mjs tests/test_cia_startup.mjs
git commit -m "feat(mode3): 선택 공개 4/7 — CIA 상태 v7(속성 기록·활성 C_u 물림), register 응답 attrs, /cia/attrs, 관리자 속성 변경, π_u V2 검증"
```

---

### Task 5: 지갑 — AA 속성 저장·재동기화, `/wallet/tx` 공개, `/wallet/attrs` 삭제

**Files:**
- Modify: `lib/mode3_wallet.js` (`signAttrsRequest`, `buildCredentialProof({ disclosure })`, `ProofCache`)
- Modify: `mode3_wallet_agent.js` (register, `ensureUserCred`, `proveSession(rsKey, synced, timings, disclosure)`, `/wallet/tx`, `/wallet/attrs` → `/wallet/attrs/sync`, 상태 v7)
- Modify: `mode3/wallet.html`
- Test: `tests/test_mode3_wallet.mjs`, `tests/test_mode3_wallet_agent.mjs`, `tests/test_cia_register_issue.mjs`(로컬 헬퍼 → import)

**Interfaces:**
- Consumes: Task 1 `attrsRequestMessage`·`ATTR_MAX`; Task 3 `payloadDigest({ …, discMask })`, `parseExecuteReceipt().disclosure`; Task 4 `/cia/register` 의 `attrs`, `/cia/attrs`.
- Produces:
  - `signAttrsRequest(sk_uHex, uid, nonce)` → `{ R8x, R8y, S }`(문자열).
  - `buildCredentialProof({ …, disclosure = null })` — `disclosure = { mask: bigint, lo: bigint[4], hi: bigint[4] }`. 입력에 `disc_*` 를 넣는다. 반환값 그대로.
  - `normalizeDisclosure(disclose, attrs)` → `{ mask, lo, hi }` — `disclose` 는 `[{lo, hi} | null] × 4`(문자열/bigint), `attrs` 는 bigint[4]. 검사: lo ≤ hi < 2^64, `lo ≤ a_k ≤ hi`(아니면 `Error('disclosure_unsatisfiable')`, `.reason = 'disclosure_unsatisfiable'`). 전부 null 이면 mask 0.
  - `ProofCache.get(root, sessionId, discKey = '0')`/`set(root, sessionId, value, discKey = '0')` — `discKey = ${mask}:${lo.join(',')}:${hi.join(',')}`.
  - 지갑 상태 v7: `registration.attrs` 의 의미가 "AA 가 준 값". 마이그레이션 v6→v7 은 `userCred = null`(옛 C_u 는 사용자 속성이라 CIA 에서 물렸다), `sessions = {}`.
  - `POST /wallet/register { uid, pwd }` — `attrs` 본문 필드는 **무시**한다(있어도 400 이 아니다; AA 값을 쓴다). 응답 `{ uid, attrs }`.
  - `POST /wallet/attrs/sync` → 200 `{ attrs, changed }` (`/cia/attrs` 로 받아 저장, 값이 바뀌면 `userCred = null`·세션 삭제).
  - `POST /wallet/tx { r_s, to, value?, data?, disclose? }` → 기존 응답 + `disclosure: { mask, lo, hi } | null`, `receipt.disclosure`. 400 `disclosure_unsatisfiable`/`bad_disclosure`.
  - `ensureUserCred`: `/cia/user_cred` 400 `bad user credential proof` 면 `/cia/attrs` 로 재동기화 후 한 번 재시도.

- [ ] **Step 1: 실패하는 테스트**

`tests/test_mode3_wallet.mjs`(라이브러리 테스트) 에 추가:

```js
await t('normalizeDisclosure: null 넷 → mask 0; 구간·등식; 불만족은 disclosure_unsatisfiable; 64비트 밖·lo > hi 는 bad_disclosure', async () => {
  const attrs = [1990n, 410n, 2n, 0n];
  assert.deepEqual(normalizeDisclosure([null, null, null, null], attrs), { mask: 0n, lo: [0n, 0n, 0n, 0n], hi: [0n, 0n, 0n, 0n] });
  assert.deepEqual(normalizeDisclosure(undefined, attrs).mask, 0n);
  assert.deepEqual(normalizeDisclosure([{ lo: '0', hi: '2007' }, { lo: '410', hi: '410' }, null, null], attrs), { mask: 3n, lo: [0n, 410n, 0n, 0n], hi: [2007n, 410n, 0n, 0n] });
  assert.throws(() => normalizeDisclosure([{ lo: '0', hi: '1980' }, null, null, null], attrs), (e) => e.reason === 'disclosure_unsatisfiable');
  assert.throws(() => normalizeDisclosure([{ lo: '5', hi: '4' }, null, null, null], attrs), (e) => e.reason === 'bad_disclosure');
  assert.throws(() => normalizeDisclosure([null, null, null, { lo: '0', hi: (1n << 64n).toString() }], attrs), (e) => e.reason === 'bad_disclosure');
  assert.throws(() => normalizeDisclosure([null, null, null, null, null], attrs), (e) => e.reason === 'bad_disclosure');
});
await t('signAttrsRequest 는 attrsRequestMessage 위 EdDSA 서명이다', async () => {
  const eddsa = await buildEddsa(); const F = eddsa.F;
  const prv = Buffer.from('11'.repeat(32), 'hex'); const pub = eddsa.prv2pub(prv);
  const sig = await signAttrsRequest(prv.toString('hex'), 12345n, 7n);
  assert.equal(eddsa.verifyPoseidon(F.e(await attrsRequestMessage(12345n, 7n)), { R8: [F.e(BigInt(sig.R8x)), F.e(BigInt(sig.R8y))], S: BigInt(sig.S) }, pub), true);
});
await t('ProofCache 는 공개 키가 다르면 다른 항목이다', () => {
  const c = new ProofCache();
  c.set('r', 's', 'A'); c.set('r', 's', 'B', '3:0,410,0,0:2007,410,0,0');
  assert.equal(c.get('r', 's'), 'A'); assert.equal(c.get('r', 's', '3:0,410,0,0:2007,410,0,0'), 'B'); assert.equal(c.get('r', 's', '1:0,0,0,0:9,0,0,0'), null);
});
```

`tests/test_mode3_wallet_agent.mjs`(격리 스택 위 에이전트 테스트) 에 추가 — 파일의 스택 헬퍼(`startIsolatedMode3Stack` 등)와 `agent.post` 류를 그대로 쓴다:

```js
await t('register 는 AA 속성을 저장하고 본문의 attrs 는 무시한다; /wallet/status 에 attrs', async () => {
  const r = await agent.post('/wallet/register', { uid: '12345', pwd: 'password123', attrs: ['1', '2', '3', '4'] });
  assert.equal(r.status, 201); assert.deepEqual(r.body.attrs, ['1990', '410', '2', '0']);
  assert.deepEqual((await agent.get('/wallet/status')).body.attrs, ['1990', '410', '2', '0']);
});
await t('관리자가 속성을 바꾸면 다음 로그인이 bad proof → /cia/attrs 재동기화 → 새 C_u 로 성공, PPID 동일', async () => {
  const first = await loginOnce();                                          // 파일의 로그인 헬퍼: 등록 → 로그인, { PPID, ... }
  await cia.adminPost('/cia/accounts/12345/attrs', { attrs: ['1990', '410', '3', '0'] });
  await publishOnce();                                                       // 파일의 게시 헬퍼(리프가 트리에 오르게)
  const second = await loginOnce();
  assert.equal(second.PPID, first.PPID);
  assert.deepEqual((await agent.get('/wallet/status')).body.attrs, ['1990', '410', '3', '0']);
});
await t('/wallet/attrs 는 사라졌고(404) /wallet/attrs/sync 는 값을 다시 받는다', async () => {
  assert.equal((await agent.post('/wallet/attrs', { attrs: ['1', '0', '0', '0'] })).status, 404);
  const r = await agent.post('/wallet/attrs/sync', {});
  assert.equal(r.status, 200); assert.equal(Array.isArray(r.body.attrs), true);
});
await t('/wallet/tx disclose: 만족하는 구간은 새 π 로 실행되고 receipt.disclosure 가 있다; 불만족은 400 disclosure_unsatisfiable; mask 0 은 캐시 재사용', async () => {
  const s = await loginOnce();
  const gate = (await rp.get('/api/mode3/rp_info')).body.attrGateAddress;   // Task 6 이 제공. Task 5 단계에서는 to 를 아무 주소로 두고 receipt.disclosure 만 본다
  const ok = await agent.post('/wallet/tx', { r_s: s.r_s, to: gate ?? '0x000000000000000000000000000000000000dEaD', data: '0x4e71d92d', disclose: [{ lo: '0', hi: '2007' }, { lo: '410', hi: '410' }, null, null] });
  assert.equal(ok.status, 200); assert.equal(ok.body.disclosure.mask, '3'); assert.equal(ok.body.cacheHit, false);
  assert.equal(ok.body.receipt.disclosure.mask, '3');
  const bad = await agent.post('/wallet/tx', { r_s: s.r_s, to: '0x000000000000000000000000000000000000dEaD', disclose: [{ lo: '0', hi: '1980' }, null, null, null] });
  assert.equal(bad.status, 400); assert.equal(bad.body.reason, 'disclosure_unsatisfiable');
  const plain = await agent.post('/wallet/tx', { r_s: s.r_s, to: '0x000000000000000000000000000000000000dEaD' });
  assert.equal(plain.status, 200); assert.equal(plain.body.disclosure, null);
});
```

(`0x4e71d92d` 는 `claim()` 셀렉터 — Task 6 전에는 dEaD 주소로 가서 `success=false` 여도 `receipt.disclosure` 는 이벤트로 남는다.)

- [ ] **Step 2: 실패 확인**

Run: `node tests/test_mode3_wallet.mjs`
Expected: FAIL — `normalizeDisclosure`·`signAttrsRequest` import 실패.

- [ ] **Step 3: `lib/mode3_wallet.js`**

```js
import { attrsRequestMessage, ... } from './mode3_issuance.js';
import { ATTR_MAX, ... } from './mode3_credential.js';

/** /cia/attrs 요청 서명 = Sign(sk_u, Poseidon(D_ATTRSREQ, uid, nonce)) (스펙 2026-09-22 §3.3). */
export async function signAttrsRequest(sk_uHex, uid, nonce) {
  const eddsa = await getEddsa();
  return sigStrings(eddsa.F, eddsa.signPoseidon(Buffer.from(sk_uHex, 'hex'), eddsa.F.e(await attrsRequestMessage(uid, nonce))));
}

/**
 * /wallet/tx 의 disclose([{lo,hi}|null ×4]) 를 회로 입력 { mask, lo[4], hi[4] } 로. 지갑이 먼저 lo ≤ a_k ≤ hi 를 확인한다 —
 * 안 맞으면 증명이 어차피 안 만들어진다(reason 'disclosure_unsatisfiable'). 형식·범위 오류는 'bad_disclosure'.
 */
export function normalizeDisclosure(disclose, attrs) {
  const fail = (reason, msg) => Object.assign(new Error(msg ?? reason), { reason });
  if (disclose === undefined || disclose === null) return { mask: 0n, lo: [0n, 0n, 0n, 0n], hi: [0n, 0n, 0n, 0n] };
  if (!Array.isArray(disclose) || disclose.length !== 4) throw fail('bad_disclosure', 'disclose 는 길이 4 배열');
  let mask = 0n; const lo = [0n, 0n, 0n, 0n], hi = [0n, 0n, 0n, 0n];
  disclose.forEach((d, k) => {
    if (d === null || d === undefined) return;
    let l, h;
    try { l = BigInt(d.lo); h = BigInt(d.hi); } catch { throw fail('bad_disclosure', `슬롯 ${k}: lo·hi 는 10진`); }
    if (l < 0n || h < 0n || l >= ATTR_MAX || h >= ATTR_MAX || l > h) throw fail('bad_disclosure', `슬롯 ${k}: 0 ≤ lo ≤ hi < 2^64`);
    if (attrs[k] < l || attrs[k] > h) throw fail('disclosure_unsatisfiable', `슬롯 ${k}: 내 속성이 [${l}, ${h}] 밖`);
    mask |= 1n << BigInt(k); lo[k] = l; hi[k] = h;
  });
  return { mask, lo, hi };
}
export const disclosureKey = (d) => `${d.mask}:${d.lo.join(',')}:${d.hi.join(',')}`;
```

`buildCredentialProof` 시그니처에 `disclosure = null` 을 더하고 입력에:

```js
  const disc = disclosure ?? { mask: 0n, lo: [0n, 0n, 0n, 0n], hi: [0n, 0n, 0n, 0n] };
  const input = { ..., disc_mask: disc.mask.toString(), disc_lo: disc.lo.map(String), disc_hi: disc.hi.map(String) };
```

`ProofCache`:

```js
export class ProofCache {
  #m = new Map();
  #key(root, sessionId, discKey) { return `${root}:${sessionId}:${discKey}`; }
  get(root, sessionId, discKey = '0') { return this.#m.get(this.#key(root, sessionId, discKey)) ?? null; }
  set(root, sessionId, value, discKey = '0') { this.#m.set(this.#key(root, sessionId, discKey), value); }
  clear() { this.#m.clear(); }
}
```

(mask 0 의 키가 `'0'` 이 되도록 `disclosureKey({mask:0,…})` 대신 호출자가 mask 0 이면 `'0'` 을 넘긴다 — 아래 에이전트 코드 참고.)

- [ ] **Step 4: `mode3_wallet_agent.js`**

상태 버전: `mode3_wallet_agent.js` 상단 `WALLET_STATE_VERSION = 6` 을 7 로 올린다. 기존 마이그레이션 블록(버전이 다르면 등록만 살리고 세션을 비움)에 `registration.userCred = null` 을 더한다 — 옛 C_u 는 사용자가 고른 속성이라 CIA v7 이 물렸고 다음 로그인이 새로 받는다. 주석 줄 "version 7 (2026-09-22): 속성은 AA 기록 …" 추가.

`/wallet/register`: `attrs` 본문을 읽지 않는다. 응답의 `r.body.attrs` 를 저장:

```js
    state.registration = { uid, s_u: ..., r_u: ..., cm_u: ..., sk_u: r.body.sk_u, attrs: normalizeAttrs(r.body.attrs).map(String) };
    persist();
    res.status(201).json({ uid, attrs: state.registration.attrs });
```

`/wallet/status` 응답에 `attrs: state.registration?.attrs ?? null`.

`ensureUserCred(tree)` — bad proof 재동기화:

```js
async function syncAttrsFromCia() {
  const reg = state.registration;
  const nonce = randomScalar();
  const r = await ciaPost('/cia/attrs', { uid: reg.uid, nonce: nonce.toString(), sig_u: await signAttrsRequest(reg.sk_u, BigInt(reg.uid), nonce) });
  if (r.status !== 200) return { changed: false, status: r.status, body: r.body };
  const attrs = normalizeAttrs(r.body.attrs).map(String);
  const changed = JSON.stringify(attrs) !== JSON.stringify(reg.attrs);
  if (changed) { reg.attrs = attrs; replaceUserCred(null); } else persist();
  return { changed, status: 200, attrs };
}

async function ensureUserCred(tree, { resynced = false } = {}) {
  const reg = state.registration;
  if (reg.userCred && !tree.has(BigInt(reg.userCred.leaf))) return { status: 200, fresh: false };
  const req = await buildUserCredRequest({ uid: BigInt(reg.uid), s_u: BigInt(reg.s_u), r_u: BigInt(reg.r_u), sk_u: reg.sk_u, attrs: (reg.attrs ?? []).map(BigInt) });
  const r = await ciaPost('/cia/user_cred', req.body);
  if (r.status === 201 || r.status === 200) { replaceUserCred({ ... 기존 ... }); return { status: 200, body: r.body, fresh: true }; }
  // AA 기록이 바뀌어 π_u 가 깨진 경우(2026-09-22 §3.3): 속성을 다시 받아 한 번만 재시도한다
  if (r.status === 400 && !resynced && /proof/.test(r.body?.error ?? '')) {
    const s = await syncAttrsFromCia();
    if (s.status === 200) return ensureUserCred(tree, { resynced: true });
  }
  return { status: r.status, body: r.body, fresh: false };
}
```

`/wallet/attrs` 핸들러를 **삭제**하고 `/wallet/attrs/sync` 로 대체:

```js
// 2026-09-22 §3.3 — 속성은 AA 가 관리한다. 여기서는 값을 다시 받아 저장만 하고, 바뀌었으면 옛 C_u·세션을 버린다(재발급은 다음 로그인).
app.post('/wallet/attrs/sync', async (req, res) => {
  try {
    if (!state.registration) return res.status(409).json({ reason: 'not_registered' });
    const s = await syncAttrsFromCia();
    if (s.status !== 200) return res.status(502).json({ reason: 'attrs_failed', cia: s.body });
    res.json({ attrs: state.registration.attrs, changed: s.changed });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
```

`proveSession(rsKey, synced, timings, disclosure = null)`:

```js
  const discKey = disclosure && disclosure.mask !== 0n ? disclosureKey(disclosure) : '0';
  let cached = cache.get(synced.root, rsKey, discKey);
  ...
    cached = await buildCredentialProof({ ..., disclosure });
    cache.set(synced.root, rsKey, cached, discKey);
```

`/wallet/tx`:

```js
    const { r_s, to, value = '0', data = '0x', disclose } = req.body ?? {};
    ...
    let disclosure;
    try { disclosure = normalizeDisclosure(disclose, (state.registration.attrs ?? []).map(BigInt)); }
    catch (e) { if (e.reason) return res.status(400).json({ reason: e.reason, detail: e.message }); throw e; }
    ...
    try { proved = await proveSession(rsKey, synced, timings, disclosure); }
    ...
    const payload = { to: ethers.getAddress(to), value: BigInt(value), data, nonce };
    const sig = signPayload(new ethers.Wallet(s.sessionPrivKey), { chainId: await chainId(), wallet: walletAddr, ...payload, discMask: disclosure.mask });
    ...
    const parsed = parseExecuteReceipt(receipt, walletAddr);
    const discOut = disclosure.mask === 0n ? null : { mask: disclosure.mask.toString(), lo: disclosure.lo.map(String), hi: disclosure.hi.map(String) };
    res.json({ ...기존 응답, disclosure: discOut, receipt: { ...기존 receipt 필드, disclosure: parsed.disclosure && { mask: parsed.disclosure.mask.toString(), lo: parsed.disclosure.lo.map(String), hi: parsed.disclosure.hi.map(String) } } });
```

(기존 응답이 `receipt` 를 어떻게 구성하는지 파일에서 확인해 그 객체에 `disclosure` 필드를 더한다.) `cacheHit` 은 `proveSession` 이 돌려주는 값 그대로.

- [ ] **Step 5: 지갑 페이지**

`mode3/wallet.html`: 속성 4칸을 `readonly` 로 두고 `/wallet/status` 의 `attrs` 로 채운다(등록 전에는 비움). "속성 변경" 버튼 → "AA 에서 속성 다시 받기"(`POST /wallet/attrs/sync`, 결과 `changed` 표시). 트랜잭션 폼에 슬롯별 `<input type=checkbox id="dk">` + `lo`/`hi` 입력 4쌍, "정확히 공개" 버튼(체크된 슬롯의 lo=hi=내 속성). `data` 입력 칸(`txData`, 기본 `0x`)을 추가하고 `/wallet/tx` 본문에 `data`·`disclose` 를 싣는다. 결과에 `disclosure`·`receipt.disclosure`·`executed.success` 를 표시.

- [ ] **Step 6: 테스트 파일 정리와 통과 확인**

`tests/test_cia_register_issue.mjs` 의 로컬 `signAttrsRequest` 를 지우고 `import { signAttrsRequest } from '../lib/mode3_wallet.js'` 로. `tests/test_mode3_wallet_agent.mjs` 의 기존 "속성 변경(/wallet/attrs)" 케이스가 있으면 위 새 케이스로 대체한다.

Run: `node tests/test_mode3_wallet.mjs` → 통과. hardhat(:8545) 위에서 `node tests/test_cia_register_issue.mjs && node tests/test_mode3_wallet_agent.mjs` → 통과(`/wallet/tx disclose` 케이스는 `attrGateAddress` 가 아직 없어 dEaD 경로로 감).

- [ ] **Step 7: 커밋**

```bash
git add lib/mode3_wallet.js mode3_wallet_agent.js mode3/wallet.html tests/test_mode3_wallet.mjs tests/test_mode3_wallet_agent.mjs tests/test_cia_register_issue.mjs
git commit -m "feat(mode3): 선택 공개 5/7 — 지갑 AA 속성 저장·재동기화, /wallet/tx disclose(새 π·mask 서명), /wallet/attrs → /wallet/attrs/sync, 지갑 상태 v7"
```

---

### Task 6: 서비스 — 공개 입력 23개, `AttrGate` 배포·`rp_info`, 세션 기록, e2e·데모 시나리오

**Files:**
- Modify: `lib/mode3_rp.js` (`verifyLogin`)
- Modify: `mode3_rp.js` (`ensureFactory` 뒤 `AttrGate` 배포, `rp_info`, login/revalidate 세션 기록), `mode3/rp.html`(공개 값 표시)
- Test: `tests/test_mode3_rp.mjs`, `tests/test_mode3_e2e.mjs`, `tests/test_mode3_demo_stack.mjs`

**Interfaces:**
- Consumes: Task 3 `deployAttrGate`, `attrGateAt`; Task 5 `/wallet/tx` 의 `disclose`.
- Produces:
  - `verifyLogin` 은 `publicSignals.length === 23`, `ps[14] < 16`(아니면 `{ ok:false, reason:'bad_disclosure' }`), 반환에 `disclosure: { mask, lo[4], hi[4] }`(bigint).
  - 등록 파일 `reg.attrGateAddress`; `GET /api/mode3/rp_info` 에 `attrGateAddress`; `/api/mode3/challenge` 응답에도 `attrGateAddress`(지갑 페이지가 기본 대상으로 쓴다).
  - 세션 항목에 `disclosure: { mask, lo, hi }`(문자열).

- [ ] **Step 1: 실패하는 테스트**

`tests/test_mode3_rp.mjs` — 파일의 `verifyLogin` 호출 헬퍼를 써서:

```js
await t('V6: publicSignals 가 14개면 malformed, 23개면 통과하고 disclosure 를 돌려준다, [14] ≥ 16 은 bad_disclosure', async () => {
  const good = await makeLogin();                                            // 파일의 헬퍼: 픽스처 증명 + σ
  assert.equal(good.publicSignals.length, 23);
  const v = await verifier.verifyLogin(good);
  assert.equal(v.ok, true); assert.equal(v.disclosure.mask, 0n);
  assert.equal((await verifier.verifyLogin({ ...good, publicSignals: good.publicSignals.slice(0, 14) })).reason, 'malformed');
  const ps = [...good.publicSignals]; ps[14] = '16';
  assert.equal((await verifier.verifyLogin({ ...good, publicSignals: ps })).reason, 'bad_disclosure');
});
```

`tests/test_mode3_demo_stack.mjs` 에 §6.3 시나리오:

```js
await t('10. 선택 공개: testuser 가 [0,2007]·[410,410] 을 공개해 AttrGate.claim → Claimed; 두 번째는 already claimed(success=false)', async () => {
  const info = (await rp.get('/api/mode3/rp_info')).body;
  assert.ok(info.attrGateAddress);
  const s = await loginAs('testuser');
  const tx = await wallet.post('/wallet/tx', { r_s: s.r_s, to: info.attrGateAddress, data: '0x4e71d92d', disclose: [{ lo: '0', hi: '2007' }, { lo: '410', hi: '410' }, null, null] });
  assert.equal(tx.status, 200); assert.equal(tx.body.receipt.executed.success, true); assert.equal(tx.body.receipt.disclosure.mask, '3');
  const again = await wallet.post('/wallet/tx', { r_s: s.r_s, to: info.attrGateAddress, data: '0x4e71d92d', disclose: [{ lo: '0', hi: '2007' }, { lo: '410', hi: '410' }, null, null] });
  assert.equal(again.body.receipt.executed.success, false);
});
await t('11. 선택 공개: alice(2005, 840) 는 country 로 실패(success=false); 슬롯 0 을 [0,1980] 으로 공개하면 지갑이 disclosure_unsatisfiable', async () => {
  const info = (await rp.get('/api/mode3/rp_info')).body;
  const s = await loginAs('alice');
  const tx = await wallet.post('/wallet/tx', { r_s: s.r_s, to: info.attrGateAddress, data: '0x4e71d92d', disclose: [{ lo: '0', hi: '2007' }, { lo: '840', hi: '840' }, null, null] });
  assert.equal(tx.status, 200); assert.equal(tx.body.receipt.executed.success, false);
  const bad = await wallet.post('/wallet/tx', { r_s: s.r_s, to: info.attrGateAddress, data: '0x4e71d92d', disclose: [{ lo: '0', hi: '1980' }, null, null, null] });
  assert.equal(bad.status, 400); assert.equal(bad.body.reason, 'disclosure_unsatisfiable');
});
await t('12. 선택 공개: 관리자가 testuser a₂ 를 3 으로 → 게시 → 다음 로그인이 재동기화·새 C_u, PPID 동일', async () => {
  const before = await loginAs('testuser');
  await cia.adminPost('/cia/accounts/12345/attrs', { attrs: ['1990', '410', '3', '0'] });
  await publish();
  const after = await loginAs('testuser');
  assert.equal(after.PPID, before.PPID);
  assert.deepEqual((await wallet.get('/wallet/status')).body.attrs, ['1990', '410', '3', '0']);
});
```

(데모 스택 테스트는 지갑 에이전트 하나가 계정 하나를 들고 있다 — `loginAs('alice')` 가 파일에 없으면, 파일이 이미 쓰는 "두 번째 지갑 인스턴스" 헬퍼나 등록 초기화 방식(`isolated_mode3_stack.mjs` 의 두 번째 에이전트)을 따른다. 없으면 11번 케이스의 alice 부분은 `tests/test_mode3_e2e.mjs` 의 두 번째 지갑 상태 방식으로 옮긴다.)

`tests/test_mode3_e2e.mjs`: 기존 "V5: 두 서비스…" 케이스 뒤에 "V6: 공개 mask ≠ 0 인 로그인도 RP 가 받아 세션에 disclosure 를 기록한다" — RP 의 `/api/mode3/login` 을 `disclose` 가 있는 증명으로 부르고(지갑 라이브러리 `buildCredentialProof({ disclosure })` 직접 호출) 응답 200 과 서비스 세션 조회(파일이 쓰는 세션 확인 방법)에서 `disclosure.mask === '3'` 을 확인한다.

- [ ] **Step 2: 실패 확인**

Run: `node tests/test_mode3_rp.mjs`
Expected: FAIL — `publicSignals.length !== 14` 검사로 23개가 `malformed`.

- [ ] **Step 3: `lib/mode3_rp.js`**

```js
    if (!Array.isArray(publicSignals) || publicSignals.length !== 23 || ...) return { ok: false, reason: 'malformed' };
    ...
    const [PPID, aridIn, pk_i, max_height, chainIn, allowAgent, revRoot, ciaX, ciaY, traceX, traceY, c1x, c1y, c2, discMask, ...rest] = ps;
    const disclosure = { mask: discMask, lo: rest.slice(0, 4), hi: rest.slice(4, 8) };
    ...
    if (discMask >= 16n) return { ok: false, reason: 'bad_disclosure' };   // 회로도 막지만 세션·로그에 남는 값이라 한 번 더(2026-09-22 §6.2)
    ...
    return { ok: true, ..., disclosure, publicSignals: ps.map(String) };
```

헤더 주석의 검사 목록에 `bad_disclosure` 한 줄. 로그인 정책은 없다(기록만).

- [ ] **Step 4: `mode3_rp.js`·`mode3/rp.html`**

- `ensureFactory()` 뒤에 `ensureAttrGate()`: `reg.attrGateAddress` 가 없으면 `deployAttrGate(signer, { factoryAddress: reg.factoryAddress })` 로 배포해 등록 파일에 저장(팩토리 없으면 건너뜀·경고). `activate()` 에서 팩토리 다음에 호출.
- `rp_info`·`/api/mode3/challenge` 응답에 `attrGateAddress: reg.attrGateAddress ?? null`.
- login/revalidate 의 `sessions.set(...)` 항목과 `logins`·`LOGIN_LOG` 에 `disclosure: { mask: v.disclosure.mask.toString(), lo: v.disclosure.lo.map(String), hi: v.disclosure.hi.map(String) }`.
- `mode3/rp.html`: 로그인 결과·세션 표에 공개 값(mask ≠ 0 일 때만) 표시, 페이지 상단에 `AttrGate` 주소와 정책(국가 410, 출생연도 ≤ 2007) 표시.
- 재배포 절차: 등록 파일에 `attrGateAddress` 가 없으면 기동 시 자동 배포되므로 별도 삭제 항목은 없다. 단 팩토리를 재배포하면(`factoryAddress` 삭제) `AttrGate` 도 새 팩토리에 묶여야 하므로 **`factoryAddress` 를 지울 때 `attrGateAddress` 도 지운다** — 기동 코드에서 `reg.factoryAddress` 가 없으면 `reg.attrGateAddress = null` 로 맞춘다.

- [ ] **Step 5: 통과 확인**

hardhat(:8545) 위에서: `node tests/test_mode3_rp.mjs && node tests/test_mode3_e2e.mjs && node tests/test_mode3_demo_stack.mjs && node tests/test_mode3_wallet_agent.mjs`
Expected: 전부 통과(에이전트 테스트의 disclose 케이스가 이제 실제 `AttrGate` 로 간다).

- [ ] **Step 6: 커밋**

```bash
git add lib/mode3_rp.js mode3_rp.js mode3/rp.html tests/test_mode3_rp.mjs tests/test_mode3_e2e.mjs tests/test_mode3_demo_stack.mjs tests/test_mode3_wallet_agent.mjs
git commit -m "feat(mode3): 선택 공개 6/7 — 서비스 공개 입력 23개·bad_disclosure·세션 기록, AttrGate 배포·rp_info, e2e·데모 시나리오"
```

---

### Task 7: 문서·벤치·실측, 전 그룹 실행

**Files:**
- Modify: `docs/MODE3_DEMO.md` (재배포 절차, §6.3 시나리오, `/cia/attrs`·관리자 속성·`/wallet/attrs/sync`·`disclose`)
- Modify: `scripts/bench_zkp_inventory.mjs` (π_rp V6 행, π_u V2 행), `scripts/bench_mode3_onchain.mjs` (mask 0 / mask ≠ 0 + `AttrGate.claim` gas, 공개 트랜잭션 왕복)
- Create: `results/mode3_disclosure_bench_YYYYMMDD.md` (실행 날짜 — `date` 로)
- Modify: 스펙 `docs/superpowers/specs/2026-09-22-mode3-selective-disclosure-design.md` §8 에 실측 표, §11 에 남은 것; `docs/superpowers/specs/2026-09-21-mode3-two-tier-credential-design.md` §3.1·§3.5 머리에 "2026-09-22 선택 공개 설계가 대체" 한 줄.

**Interfaces:**
- Consumes: 전 Task.
- Produces: 실측 수치(제약 수, π_u V2 시간, 로그인, 공개 트랜잭션 왕복, gas), 문서.

- [ ] **Step 1: 벤치 스크립트**

`scripts/bench_zkp_inventory.mjs`: π_u 행이 `proveUserCred`/`verifyUserCred` 를 부르는 곳에 `attrs` 인자(`[1990n, 410n, 2n, 0n]`)를 맞추고 이름을 "π_u V2" 로. π_rp 행의 제약 수는 `build/mode3/pi_cred.r1cs` 에서 읽는 기존 방식 그대로.
`scripts/bench_mode3_onchain.mjs`: 기존 `execute` 측정 옆에 (a) mask = 0 캐시 π, (b) mask = 3 새 π + `AttrGate.claim` 의 gas·왕복 ms 를 N=10 중앙값으로. `AttrGate` 는 스크립트가 배포한다(`deployAttrGate`).

- [ ] **Step 2: 실행과 기록**

Run(세션이 :8545 를 띄운 뒤): `node scripts/bench_zkp_inventory.mjs` → `node scripts/bench_mode3_onchain.mjs`
`results/mode3_disclosure_bench_<date>.md` 에 표: 제약(V5 26,601 → V6), π_rp prove/verify, π_u V2 prove/verify(V5 121.9/140.5 대비), 로그인 왕복, 공개 트랜잭션 왕복(증명 포함), execute gas mask 0 / mask 3 + claim, 검증자 gas 차이. 스펙 §8 에 같은 표를 옮긴다.

- [ ] **Step 3: 문서**

`docs/MODE3_DEMO.md`:
- 재배포 절차에 "회로 V6: `bash scripts/build_mode3_circuit.sh` → `npx hardhat compile` → 서비스 등록 파일에서 `verifierAddress`·`factoryAddress`·`attrGateAddress` 삭제 → CIA 상태 v7 자동 마이그레이션(활성 C_u 물림, 다음 게시에 리프) → 지갑 상태 v7 자동(옛 C_u·세션 폐기) → 다음 로그인에서 자동 재발급".
- 새 절 "속성과 선택 공개": 데모 계정 속성, 관리자 속성 변경, `/wallet/attrs/sync`, 트랜잭션 폼의 공개 항목, `AttrGate` 정책, §6.3 시나리오 1~5.
- 엔드포인트 표에 `/cia/attrs`, `/cia/accounts/:uid/attrs`, `GET /cia/accounts`, `/wallet/attrs/sync`, `/wallet/tx.disclose`, `rp_info.attrGateAddress`.

스펙 §11: 남은 것(로그인 공개 정책, 리프 게시 여부 결정, 논문 반영 항목: V-B 속성 출처, Table 2·3 수치, IX 한계 — 공개 값에 의한 익명 집합 축소).

- [ ] **Step 4: 전 그룹 실행**

Run: `bash scripts/run_tests.sh contract` → `npm test`(unit + circuit) → `bash scripts/run_tests.sh chain`(세션 hardhat). 세 그룹 전부 통과를 확인하고 결과 수를 커밋 메시지에 적는다. 끝나면 세션이 띄운 hardhat 을 내리고 :8545 가 비었는지 확인.

- [ ] **Step 5: 커밋**

```bash
git add docs/MODE3_DEMO.md scripts/bench_zkp_inventory.mjs scripts/bench_mode3_onchain.mjs results/mode3_disclosure_bench_*.md docs/superpowers/specs/2026-09-22-mode3-selective-disclosure-design.md docs/superpowers/specs/2026-09-21-mode3-two-tier-credential-design.md
git commit -m "docs(mode3): 선택 공개 7/7 — 데모 절차·시나리오, 벤치 스크립트, 실측 기록, 스펙 §8·§11"
```

---

## 자체 점검 (작성 시)

- **스펙 커버리지.** §2 속성 출처·PoK → T1·T4. §3.1 데모 값 → T4. §3.2 v7·물림 → T4. §3.3 register 응답·`/cia/attrs`·관리자 변경·재동기화·`/wallet/attrs` 삭제 → T4·T5. §3.4 π_u V2 → T1. §4.1 64비트 → T1·T2. §4.2·§4.3 술어·순서 → T2. §5.1 execute·다이제스트·꼬리·이벤트 → T3. §5.2 `isWallet` → T3. §5.3 `AttrGate` → T3·T6. §6.1 `/wallet/tx` → T5. §6.2 로그인 23개·기록 → T6. §6.3 시나리오 → T6. §8 실측 → T7. §9 테스트 → T1~T6. §10 재배포 → T6·T7. §7 프라이버시 분석은 문서(스펙에 이미 있음) → T7 의 §11 갱신.
- **자리표시자.** 코드 블록에 TBD/TODO 없음. "파일의 헬퍼를 그대로 쓴다" 는 테스트 파일마다 다른 헬퍼 이름을 강제하지 않기 위한 것이며, 헬퍼가 없을 때 만들 코드(`signAttrsRequest` 로컬 판, `freshWallet`)를 적어 두었다.
- **타입 일관성.** `disclosure = { mask: bigint, lo: bigint[4], hi: bigint[4] }` 가 픽스처(T2)·`buildCredentialProof`(T5)·`verifyLogin` 반환(T6)에서 같다. HTTP 경계에서는 문자열(`/wallet/tx` 응답, 세션 기록). `payloadDigest` 의 `discMask` 는 bigint, 컨트랙트는 `pub[14]`. `verifyUserCred({ uid, attrs, C_u_pt, cm_u, proof })` 는 T1 정의를 T4 가 그대로 쓴다. `ProofCache.get/set` 의 4번째 인자 `discKey` 문자열은 T5 안에서만 쓰인다.
