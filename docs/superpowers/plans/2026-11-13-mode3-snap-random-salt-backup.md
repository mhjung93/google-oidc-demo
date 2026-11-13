# 스냅 기준 신원(무작위 salt · salt 만 든 백업) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 스냅이 무작위 salt 하나를 갖고 사용자는 salt 만 든 암호화 백업 파일로 지킨다. PPID·auid 에서 uid 를, C_attr 에서 blind 를 뺀다.

**Architecture:** 식 셋이 바뀐다 — `auid = Poseidon(T_AUID2, s_u)`, `PPID = Poseidon(s_u, arid, chainid)`, `C_attr = Poseidon(T_ATTRC4, s_u, attrs)`. 앞의 둘은 회로(`pi_idp`·`pi_cred`)와 JS 라이브러리가 같이 바뀌고 검증자 컨트랙트를 다시 만든다. 스냅은 `snap_getEntropy` 유도와 계정 번호를 버리고 `salt` 상태(무작위 생성·불러오기·백업 확인)를 갖는다. 백업 파일은 zk 스냅 화면(localhost:5100)이 설치 직후 한 번 만들고, 속성 도구의 백업 기능은 없앤다. IdP 는 같은 auid 의 두 번째 계정을 거절한다.

**Tech Stack:** circom 2 / snarkjs Groth16(`pi_idp`·`pi_cred` 재빌드), Solidity 검증자(hardhat), Node/Express(`cia.js`, `mode3_wallet_agent.js`), MetaMask Snap(`snap-mode3`, mm-snap build), 정적 HTML(`mode3/*.html`), esbuild 번들(`mode3/attr`, `mode3/user`), Playwright 브라우저 테스트.

**Spec:** `docs/superpowers/specs/2026-11-13-mode3-snap-random-salt-backup-design.md` (사용자 승인 2026-11-13, 커밋 `7c1eba8`)

## Global Constraints

- 식(스펙 R9·R10·R15):
  - `auid = Poseidon(T_AUID2, s_u)` — `T_AUID2` = ASCII `"MODE3AUID2"` 큰 끝 = `365084431357309404922930`. 입력 2개.
  - `PPID = Poseidon(s_u, arid, chainid)` — 입력 3개, 도메인 없음(지금 식에서 uid 만 뺀다).
  - `C_attr = Poseidon(T_ATTRC4, s_u, attrs[0..5])` — `T_ATTRC4` = ASCII `"MODE3ATTRC4"` = `93461614427471203550774068`. 입력 8개.
  - 그대로: `auid_s = Poseidon(T_AUIDS, auid, arid, r_rp)`, 등록부 리프 `Poseidon(auid, Cf_u)`, `C_u`, `pi_idp` 의 `tag = Poseidon(T_TAG, s_u, ctx)`, `pi_cred` ⑧ 추적 tag `Enc(pk_trace, Poseidon(uid, arid))`.
- 공개 입력의 개수·순서는 그대로다: `pi_idp` 10개(`[0] uid … [9] tag`), `pi_cred` 34개(`[0] PPID`). `contracts/Mode3Wallet.sol`·`Mode3WalletFactory.sol` 소스는 고치지 않는다.
- **회로 빌드는 `bash scripts/build_mode3_circuit.sh`(둘 다) 한 번뿐이고 실행 전에 사용자 승인을 받는다**(Task 2 Step 6). 기존 산출물은 먼저 스크래치패드에 백업한다. ptau 는 다시 만들지 않는다.
- 스냅 `0.4.0 → 0.5.0`(manifest·package.json). `snap_getEntropy` 권한을 뺀다. 스냅 상태 `version: 2`.
- IdP 상태 버전 `13 → 14`. 로더는 14 만 받는다(13 이하는 기동 거부 — 이행 없음, R14). **상태 파일은 지우지 않는다**(Mode 2 의 `idp_state.json` 은 건드리지 않는다).
- 백업: 봉인 형식 `zkd-attr-backup` v1 과 `lib/browser/attr_backup.js` 는 그대로, 평문은 `{ version: 4, s_u }`. `BACKUP_MIN_PASSWORD` 는 8 그대로.
- 옛 요청·상태·기록과 호환을 두지 않는다(데모 리셋). 예외 하나: 옛 백업 파일은 `s_u` 만 꺼내 받는다(스펙 §5.3).
- 계정 번호(`index`·`nextIndex`·`setNextIndex`)는 코드·화면·응답에서 모두 없앤다. 옛 기록에 남은 `index` 는 읽을 때 무시한다.
- 웹 모드(`mode3/user`, `lib/mode3_wallet.js`)는 식(`auidOf`·`ppid`)만 맞춘다 — 복구 코드 유도는 그대로(스펙 §8 후속).
- 새 의존성 금지. 모든 화면 문구·주석·커밋 메시지는 한글(기존 문체). 화면 이름은 "zk 스냅 화면(localhost:5100)", "속성 도구", "IdP 관리자 페이지".
- 커밋은 경로 지정 `git add -- <paths>`(`sui-repo/` 주의), 트레일러 두 줄(`Co-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>` / `Claude-Session: https://claude.ai/code/session_013qGSXZTftBJSB1M4XpPRHN`).
- 비밀 파일(`.env`, `*_state.json`, `*_keys.json`, `role.env`, `~/Downloads/zkd-attr-*.json` 등)은 읽지도 출력하지도 않는다. s_u·증명 값은 로그에 찍지 않는다.
- 사용자 프로세스(:5100 에이전트, :8082 스냅 서버)는 건드리지 않는다. hardhat 노드는 :8545 가 비어 있을 때만 `ETHERNAL_WORKSPACE= ETHERNAL_API_TOKEN= npx hardhat node` 로 직접 띄우고 끝나면 PID 로 끈다.
- 명령의 `$SCRATCH` 는 이 세션의 스크래치패드 디렉터리다. 긴 출력은 거기 파일로 보내고 끝만 읽는다.
- **이 계획은 배포를 하지 않는다.** VM rsync·데모 리셋·스냅 재설치는 구현이 끝난 뒤 따로 한다. 논문·덱 식 수정도 이 계획 밖이다(스펙 §9-2).

### 태스크 사이의 테스트 상태

Task 1 이 끝난 순간부터 Task 7 이 끝날 때까지 **그룹 전체는 붉다**(식이 바뀐 라이브러리와 옛 zkey, 옛 스냅 RPC 를 쓰는 화면이 섞여 있다). 각 태스크는 자기가 이름 붙인 테스트만 초록으로 만들고, 그룹 전체(unit·circuit·contract·snap·chain·browser)는 Task 8 에서 돌린다.

## Rulings (스펙이 정하지 않은 것 — 실행 전 사용자 검토 대상)

- **P1 스냅 상태 버전.** 스펙 §2.2 는 "최상위 `salt` 가 없으면 0.4.x 모양" 으로 구분한다고 했다. 상태 `version` 을 1 → 2 로 올려 구분한다 — `version !== 2` 면 빈 상태(`salt: null`)로 시작한다. 결과는 같고 판별이 한 줄이다.
- **P2 거절 순서.** salt 가 없으면 `no_salt`, 있는데 백업 전이면 `backup_required`. 둘 다 등록 여부 검사(`not_registered`·`already_registered`)보다 먼저다.
- **P3 `showSalt`·`getStoredState`.** 등록이 없어도 salt 가 있으면 답한다(스펙 표의 "backedUp 필요: 아니오"). salt 가 없으면 `showSalt` 는 `no_salt`.
- **P4 `importSalt` 거절.** 확인 창에서 거절하면 `{ denied: true }`(다른 RPC 와 같은 모양). 받은 값은 `source: 'import'`, `backedUp: true`.
- **P5 백업 도중 실패의 재시도.** `initSalt` 뒤 파일 저장에 실패하면 salt 는 남고 `backedUp` 은 거짓이다. 화면은 다음에 `exportSaltForBackup` 으로 같은 값을 받아 백업 절차만 다시 한다(`initSalt` 는 `salt_exists`).
- **P6 시뮬레이터.** `tests/helpers/snap_sim.mjs` 는 실제 스냅과 같은 거절을 한다. 테스트 편의로 `createReadySnapSim({ s_u })` 를 같이 내보낸다 — `s_u` 가 있으면 `importSalt`, 없으면 `initSalt` + `confirmBackup` 까지 끝낸 시뮬레이터.
- **P7 IdP `auid_taken` 의 범위.** 다른 uid 의 계정이 같은 auid 를 **지금 들고 있으면** 거절한다(폐기된 계정 포함). "지갑 연결 해제" 로 auid 가 비워진 계정은 막지 않는다. `/cia/issue` 의 암묵 등록(`verified: true`)에도 같은 검사를 한다.
- **P8 속성 도구 기록의 salt 대조.** 스냅 창이 등록 전에 기록의 `s_u` 를 스냅 `getSalt` 값과 맞춰 보는 검사는 남긴다. 사유는 `attr_record_salt_mismatch` 하나로 합친다(`attr_record_salt_not_derived` 삭제).
- **P9 `randomBlind` 삭제.** `lib/mode3_attr_commit.js` 의 `randomBlind` 와 번들 export 를 지운다(쓰는 곳이 속성 도구뿐이다).
- **P10 설정 카드의 위치.** zk 스냅 화면의 탭들 위, MetaMask 연결 상태 줄 바로 아래에 둔다. salt 가 없거나 백업 전이면 탭 내용 대신 이 카드만 보인다.
- **P12 salt 를 만드는 시점.** 스펙 §5.1 은 ① `initSalt` ② 비밀번호·파일 순서로 적었다. 화면은 **파일을 고른 뒤에** `initSalt` 를 부른다 — 비밀번호 오류나 파일 창 취소로 끝난 시도가 백업 없는 salt 를 남기지 않게. 그 뒤 쓰기가 실패한 경우만 P5 의 재시도 경로가 된다.
- **P11 "백업 다시 만들기".** "내 계정" 탭 아래쪽에 버튼 하나. `exportSaltForBackup` → 설정 카드와 같은 비밀번호·파일 절차 → `confirmBackup`.

## Review Focus

1. **백업 전 스냅으로 RP 로그인** — `backup_required` 로 멈추고 안내 문구가 보이며, 증인(s_u)은 팝업 밖으로 나가지 않는다. (Task 4 스냅 단위, Task 7 브라우저)
2. **백업 파일 저장이 도중에 실패**(파일 창 취소, 쓰기 오류, 비밀번호 불일치) — salt 는 남고 `backedUp` 은 거짓, 다시 시도하면 같은 salt 로 백업이 된다(새 salt 가 생기지 않는다). (Task 7)
3. **잘못된 불러오기** — 틀린 비밀번호, 다른 형식 파일, `s_u` 없는 기록, 이미 등록이 있는 스냅에 불러오기. 각각 사유가 보이고 상태가 바뀌지 않는다. (Task 4, Task 7)
4. **같은 스냅의 두 번째 IdP 계정** — 일반 등록·Google 등록·`/cia/issue` 암묵 등록 모두 `auid_taken`. 증명이 틀린 요청은 auid 존재 여부와 무관하게 `bad_idp_proof`. 연결 해제한 계정의 auid 는 다시 쓸 수 있다. (Task 5)
5. **옛 것을 만났을 때** — 0.4.x 스냅 상태(등록을 버리고 설정 화면), version 3 속성 기록("다시 만드세요"), 속성이 든 옛 백업 파일(salt 만 받음), IdP 상태 13(기동 거부). (Task 3·4·5·7)

---

### Task 1: 라이브러리 식 — `auidOf({ s_u })`, `ppid({ s_u, arid, chainid })`

**Files:**
- Modify: `lib/mode3_credential.js:17`(도메인), `:172-176`(auidOf), `:224-229`(ppid)
- Modify(호출부): `lib/mode3_secret_source.js:36`, `lib/mode3_wallet.js:50,152,179,255`, `mode3_wallet_agent.js:118,353,665,719,751`, `mode3/user/core/user_core.js:123,261,514,1010`, `mode3/attr.html`(auid 표시 1곳), `mode3/wallet.html:741`(등록 전 auid 대조)
- Modify(테스트·픽스처): `tests/helpers/mode3_fixture.mjs`, `tests/helpers/mode3_idp_fixture.mjs`, `tests/test_mode3_credential_v11.js`, `tests/test_mode3_secret_source.js`, `tests/test_mode3_wallet_lib.js`, 그 밖에 `grep -rn "auidOf(\|ppid({" tests snap-mode3/test test` 가 내는 모든 줄
- Test: `tests/test_mode3_credential_v11.js`

**Interfaces:**
- Produces: `DOMAIN_MODE3_AUID = 365084431357309404922930n`; `auidOf({ s_u: bigint }) → Promise<bigint>`; `ppid({ s_u: bigint, arid: bigint, chainid: bigint }) → Promise<bigint>`. `uid` 를 넘겨도 무시하지 않는다 — 인자에서 지운다.

- [ ] **Step 1: 실패하는 테스트** — `tests/test_mode3_credential_v11.js` 의 auid·PPID 케이스를 새 식으로 바꾸고 아래 둘을 더한다.

```js
await t('R10: auid = Poseidon(T_AUID2, s_u) — uid 가 달라도 같은 salt 면 같은 auid, 다른 salt 면 다르다', async () => {
  const poseidon = await getPoseidon();
  const want = poseidon.F.toObject(poseidon([365084431357309404922930n, 33n]));
  assert.equal(await auidOf({ s_u: 33n }), want);
  assert.equal(DOMAIN_MODE3_AUID, 365084431357309404922930n);
  assert.notEqual(await auidOf({ s_u: 34n }), want);
});
await t('R9: PPID = Poseidon(s_u, arid, chainid) — uid 가 식에 없다; arid·chainid 가 다르면 다르다', async () => {
  const poseidon = await getPoseidon();
  const want = poseidon.F.toObject(poseidon([33n, 22n, 31337n]));
  assert.equal(await ppid({ s_u: 33n, arid: 22n, chainid: 31337n }), want);
  assert.notEqual(await ppid({ s_u: 33n, arid: 23n, chainid: 31337n }), want);
  assert.notEqual(await ppid({ s_u: 33n, arid: 22n, chainid: 1n }), want);
});
```

- [ ] **Step 2: 붉은지 확인** — `node tests/test_mode3_credential_v11.js` → 새 두 케이스 FAIL(옛 식의 값).
- [ ] **Step 3: 구현** — `lib/mode3_credential.js`:

```js
export const DOMAIN_MODE3_AUID  = 365084431357309404922930n;    // "MODE3AUID2" — auid = Poseidon(T, s_u)  (2026-11-13 스펙 random-salt R10: uid 를 뺐다. 옛 "MODE3AUID"(uid 포함)의 값과 섞이지 않게 도메인을 바꿨다)

/** auid = Poseidon(T_AUID2, s_u) — 스냅(salt)의 가명. IdP 는 계정마다 이 값을 둔다(같은 IdP 에서 한 스냅의 계정은 하나, R11). */
export async function auidOf({ s_u }) {
  checkScalars({ s_u });
  const poseidon = await getPoseidon();
  return poseidon.F.toObject(poseidon([DOMAIN_MODE3_AUID, s_u]));
}

/** PPID = Poseidon(s_u, arid, chainid) — RP·체인마다 다른 가명(2026-11-13 R9: uid 를 뺐다 — RP 쪽 신원 단위는 스냅). auid 로 만들지 않는다(IdP 가 대입하지 못하게). */
export async function ppid({ s_u, arid, chainid }) {
  if (typeof chainid !== 'bigint') throw new Error('ppid: chainid(bigint) 가 필요하다');
  checkScalars({ s_u, arid });
  const poseidon = await getPoseidon();
  return poseidon.F.toObject(poseidon([s_u, arid, chainid]));
}
```

  호출부는 모두 `uid` 인자를 지운다(예: `auidOf({ uid: BigInt(reg.uid), s_u: BigInt(reg.s_u) })` → `auidOf({ s_u: BigInt(reg.s_u) })`, `ppid({ uid, s_u, arid, chainid })` → `ppid({ s_u, arid, chainid })`). 픽스처의 `auidOf({ uid, s_u })`·`ppid(...)` 도 같다. 식을 설명하는 주석(`Poseidon(T_AUID, uid, s_u)`, `Poseidon(uid, s_u, arid, chainid)`)을 같이 고친다 — `grep -rn "T_AUID, uid\|uid, s_u, arid\|H(uid, salt" lib mode3 mode3_wallet_agent.js cia.js mode3_rp.js` 로 찾는다.
- [ ] **Step 4: 초록 확인** — `node tests/test_mode3_credential_v11.js`, `node tests/test_mode3_secret_source.js`, `node tests/test_mode3_wallet_lib.js` → 모두 0 FAIL. `grep -rn "auidOf({ uid\|ppid({ uid" --include=*.js --include=*.mjs --include=*.html lib mode3 tests test snap-mode3/test mode3_wallet_agent.js` → 0줄.
- [ ] **Step 5: 커밋** — `feat(mode3): auid = H(T_AUID2, salt)·PPID = H(salt, arid, chainid) — 라이브러리 식에서 uid 제거(회로는 다음 커밋)`

### Task 2: 회로 `pi_idp`·`pi_cred` + 산출물 재빌드 + 검증자

**Files:**
- Modify: `circuits/pi_idp.circom`(머리 주석 ②, 상수, ② 블록), `circuits/pi_cred.circom`(머리 주석 ②③, 상수, ②·③ 블록), `circuits/lib/mode3_commit.circom:17`(uid 설명)
- Modify(빌드 산출물): `build/mode3/pi_{idp,cred}_*`, `contracts/PiCredVerifier.sol`
- Test: `tests/test_pi_idp_witness.mjs`, `tests/test_pi_cred_witness.mjs`, `tests/test_mode3_artifacts.mjs`, `bash scripts/run_tests.sh contract`

**Interfaces:**
- Consumes: Task 1 의 `auidOf`·`ppid`(픽스처가 쓴다).
- Produces: 새 zkey·vkey·wasm 한 세트, 새 `PiCredVerifier.sol`.

- [ ] **Step 1: 실패하는 테스트** — `tests/test_pi_idp_witness.mjs` 에 더한다(픽스처는 Task 1 에서 새 식이 됐다 — 지금 회로로는 양성 케이스부터 붉다).

```js
await t('R10: auid 는 uid 와 무관하다 — uid 만 바꾸면 C_u 가 어긋나 거부되지만, uid 를 바꿔 C_u 를 다시 만든 입력은 같은 auid 로 통과한다', async () => {
  await assert.rejects(() => witness({ ...valid, uid: bump(valid.uid) }), /Assert Failed/);
  const other = await buildIdpInput({ uid: 99999n });
  assert.equal(other.input.auid, valid.auid);
  assert.ok((await witness(other.input)).length > 0);
});
```

  `tests/helpers/mode3_idp_fixture.mjs` 의 `buildIdpInput` 에 `uid = IDP_FIXTURE.uid` 옵션을 더한다. `tests/test_pi_cred_witness.mjs` 에는 같은 뜻의 케이스 하나(uid 를 바꿔 C_u·토큰을 다시 만든 입력의 `PPID` 가 그대로)와, `PPID` 를 `bump` 하면 거부되는 기존 케이스가 남아 있는지 확인한다.
- [ ] **Step 2: 붉은지 확인** — `node tests/test_pi_idp_witness.mjs` → 양성 케이스들이 `Assert Failed`.
- [ ] **Step 3: 회로 수정** —

  `circuits/pi_idp.circom` ②:
```circom
    var DOMAIN_MODE3_AUID  = 365084431357309404922930;   // ASCII "MODE3AUID2" — lib/mode3_credential.js DOMAIN_MODE3_AUID (2026-11-13: uid 를 뺐다)

    // ② auid — 스냅(salt)의 가명. uid 와의 묶음은 ① C_u 와 IdP 의 계정 대조가 맡는다.
    component ah = Poseidon(2);
    ah.inputs[0] <== DOMAIN_MODE3_AUID;  ah.inputs[1] <== s_u;
    auid === ah.out;
```
  `circuits/pi_cred.circom` ②·③:
```circom
    component ah = Poseidon(2);
    ah.inputs[0] <== DOMAIN_MODE3_AUID;  ah.inputs[1] <== s_u;
    signal auid;
    auid <== ah.out;
    …
    // ---- ③ PPID (2026-11-13 R9: uid 를 뺐다 — 스냅별 가명) ----
    component ppidHasher = Poseidon(3);
    ppidHasher.inputs[0] <== s_u;
    ppidHasher.inputs[1] <== arid;
    ppidHasher.inputs[2] <== chainid;
    PPID === ppidHasher.out;
```
  `pi_cred.circom` 의 `DOMAIN_MODE3_AUID` 상수도 같은 값으로. 두 파일의 머리 주석 식과 `mode3_commit.circom:17` 의 "uid — 계정 식별자. PPID 유도에 쓰인다" 를 "uid — 계정 식별자. C_u 와 추적 tag 에 쓰인다(PPID·auid 에는 2026-11-13 부터 없다)" 로 고친다.
- [ ] **Step 4: witness 테스트 초록** — `node tests/test_pi_idp_witness.mjs`, `node tests/test_pi_cred_witness.mjs` → 0 FAIL. 출력의 제약 수를 적어 둔다(예상: `pi_idp` 는 Poseidon(3) → Poseidon(2) 로 조금 줄고, `pi_cred` 는 Poseidon(3)·Poseidon(4) 가 각각 한 칸씩 줄어든다).
- [ ] **Step 5: 기존 산출물 백업** — `mkdir -p "$SCRATCH/mode3_build_backup_20261113b" && cp -a build/mode3/pi_idp_final.zkey build/mode3/pi_idp_vkey.json build/mode3/pi_idp_js build/mode3/pi_cred_final.zkey build/mode3/pi_cred_vkey.json build/mode3/pi_cred_js contracts/PiCredVerifier.sol "$SCRATCH/mode3_build_backup_20261113b/"`
- [ ] **Step 6: 재빌드(사용자 승인 뒤)** — `bash scripts/build_mode3_circuit.sh > "$SCRATCH/build_circuits.log" 2>&1` (백그라운드, `pi_cred` 는 수 분). 끝나면 `tail -5`, 이어서 `npx hardhat compile > "$SCRATCH/hh_compile.log" 2>&1`.
- [ ] **Step 7: 산출물·컨트랙트 테스트** — `node tests/test_mode3_artifacts.mjs` → 0 FAIL. `bash scripts/run_tests.sh contract > "$SCRATCH/contract.log" 2>&1` → 전부 통과(`test/Mode3Wallet.test.mjs` 가 새 π 로 지갑을 통과).
- [ ] **Step 8: 커밋** — `circuits/*.circom`, `circuits/lib/mode3_commit.circom`, `contracts/PiCredVerifier.sol`, 테스트·픽스처. `feat(mode3): 회로 — pi_idp·pi_cred 의 auid = H(T_AUID2, salt), PPID = H(salt, arid, chainid); 검증자 재생성`

### Task 3: C_attr 에서 blind 제거 + 속성 도구에서 백업 기능 삭제

**Files:**
- Modify: `lib/mode3_attr_commit.js`, `mode3/attr/attr_core.js`(export), `mode3/attr.html`, `mode3/common/strings.js`, `mode3/wallet.html:704`(readAttrRecord)
- Modify(테스트): `tests/test_mode3_attr_commit.mjs`, `tests/test_attr_backup.mjs`(REC), `tests/test_cia_accounts.mjs`·`tests/test_mode3_demo_stack.mjs`(attrCommit 호출 1곳씩)
- Test: `tests/test_mode3_attr_commit.mjs`, `tests/test_attr_backup.mjs`, `tests/test_demo_strings.*`

**Interfaces:**
- Produces: `attrCommit({ s_u, attrs }) → Promise<string>`(10진), `DOMAIN_MODE3_ATTRC = 93461614427471203550774068n`. `randomBlind` 없음. 속성 도구 기록 `{ version: 4, schema, uid, s_u, profile, attrs, commit, createdAt }`.

- [ ] **Step 1: 실패하는 테스트** — `tests/test_mode3_attr_commit.mjs` 를 새 식으로:

```js
await t('R15: C_attr = Poseidon("MODE3ATTRC4", s_u, attrs[0..5]) — blind 가 없다', async () => {
  const poseidon = await getPoseidon();
  const attrs = ['1990', '410', '0', '0', '0', '0'];
  const want = poseidon.F.toObject(poseidon([93461614427471203550774068n, 77n, ...attrs.map(BigInt)])).toString();
  assert.equal(await attrCommit({ s_u: '77', attrs }), want);
  assert.equal(await attrCommit({ s_u: '77', attrs, blind: '5' }), want, 'blind 를 줘도 무시한다');
});
await t('같은 salt·같은 속성이면 같은 값, 속성이나 salt 가 다르면 다르다', async () => {
  const a = await attrCommit({ s_u: '77', attrs: ['1990', '410', '0', '0', '0', '0'] });
  assert.equal(a, await attrCommit({ s_u: '77', attrs: ['1990', '410', '0', '0', '0', '0'] }));
  assert.notEqual(a, await attrCommit({ s_u: '77', attrs: ['1991', '410', '0', '0', '0', '0'] }));
  assert.notEqual(a, await attrCommit({ s_u: '78', attrs: ['1990', '410', '0', '0', '0', '0'] }));
});
await t('randomBlind 는 없어졌다', async () => { assert.equal((await import('../lib/mode3_attr_commit.js')).randomBlind, undefined); });
```
  blind 범위·형식을 보던 기존 케이스는 지운다.
- [ ] **Step 2: 붉은지 확인** — `node tests/test_mode3_attr_commit.mjs` → 새 케이스 FAIL.
- [ ] **Step 3: 라이브러리** — `lib/mode3_attr_commit.js`: 도메인을 `'MODE3ATTRC4'` 로, `attrCommit({ s_u, attrs })` 는 `poseidon([DOMAIN_MODE3_ATTRC, su, ...a])`, `randomBlind` 삭제, 머리 주석의 식과 옛 도메인 이력(`MODE3ATTRC3` = 2026-11-13 오전, blind 포함)을 적는다. `mode3/attr/attr_core.js` export 에서 `randomBlind` 를 뺀다. `tests/test_attr_backup.mjs` 의 `REC` 를 `{ version: 4, s_u: '98765432109876543210' }` 로 바꾸고 평문 검사 목록을 `[REC.s_u, 's_u']` 로 줄인다.
- [ ] **Step 4: 속성 도구(`mode3/attr.html`)** —
  - `REC_VERSION = 4`. 만들기: `const commit = await A.attrCommit({ s_u, attrs }); save({ version: REC_VERSION, schema: {…}, uid, s_u, profile, attrs, commit, createdAt })`. `blind`·`index` 를 기록·화면에서 지운다("커밋먼트 재료" 표의 blind 줄 `#blindShown`·`#copyBlindBtn`, 식 표기).
  - 지울 요소·코드: `#exportBtn`, `#importFile` 과 그 `<label>`, `#importPwRow`·`#importVerdict`, "3. 자동 백업(암호화)" 절 전체(`#backupSetupBtn` 등), IndexedDB(`BK_DB`)·`showSaveFilePicker`·`writeAutoBackup`·`finishImport`·`openPendingImport`·`pendingImport` 관련 함수와 호출.
  - 문구: `attr_make_hint`("만들 때마다 새 blind 를 뽑습니다") 삭제, `attr_badge_offline` → "속성·salt 는 서버로 보내지 않음", `attr_old_record` 는 version 1~3 에 쓴다. `getSalt` 가 `no_salt`·`backup_required` 로 실패하면 새 문자열 `attr_snap_setup_required`("zk 스냅 화면(localhost:5100)에서 먼저 salt 를 만들고 백업하세요")를 보인다.
  - `mode3/common/strings.js` 에서 쓰이지 않게 된 `attr_export_*`·`attr_import_*`·`attr_backup_*`·`attr_blind_*`·`attr_make_hint` 키를 지운다(`grep -c` 로 페이지·테스트에 남은 참조가 0 인지 확인).
  - `mode3/wallet.html` `readAttrRecord`: `v.version === 4`, 반환에서 `index` 를 뺀다.
- [ ] **Step 5: 초록 확인** — `npm run attr:build`; `node tests/test_mode3_attr_commit.mjs`, `node tests/test_attr_backup.mjs`, 문자열 테스트(`bash scripts/run_tests.sh unit` 중 demo_strings) → 0 FAIL. `grep -n "blind\|importFile\|showSaveFilePicker\|indexedDB" mode3/attr.html` → 0줄.
- [ ] **Step 6: 커밋** — `feat(attr): C_attr = H("MODE3ATTRC4", salt, attrs) — blind 제거, 속성 도구에서 백업 내려받기·불러오기·자동 백업 삭제(기록 version 4)`

### Task 4: 스냅 0.5.0 — salt 상태·백업 강제·계정 번호 삭제

**Files:**
- Modify: `snap-mode3/src/crypto.js`, `snap-mode3/src/index.js`, `snap-mode3/snap.manifest.json`(버전·권한), `snap-mode3/package.json`(버전), `snap-mode3/README.md`
- Modify: `tests/helpers/snap_sim.mjs`, `tests/helpers/ethereum_stub.js`(`snap_getEntropy` 스텁 삭제, 버전 `0.5.0`)
- Test: `snap-mode3/test/rpc.test.mjs` (`bash scripts/run_tests.sh snap`)

**Interfaces:**
- Produces(스냅 RPC, 스펙 §2.3):
  - `initSalt({}) → { s_u }` | `salt_exists`
  - `importSalt({ s_u }) → { ok: true }` | `{ denied: true }` | `bad_salt` | `salt_exists`
  - `confirmBackup({ s_u }) → { ok: true, backedUpAt }` | `no_salt` | `backup_mismatch`
  - `exportSaltForBackup({}) → { s_u }` | `no_salt`
  - `getSalt({}) → { s_u }`, `prepareRegister({}) → { s_u }`, `register({ uid, s_u? }) → { uid, s_u }` — 셋 다 `no_salt` → `backup_required` 순으로 거절. `register` 의 `s_u` 가 다르면 `salt_mismatch`.
  - `consentLogin`·`consentDisclosure` 도 `no_salt`·`backup_required` 로 거절. 증인의 `s_u` 는 `state.salt.s_u`.
  - `getPublicInfo` 에 `hasSalt`·`backedUp`, `index`·`nextIndex` 없음. `getStoredState` 에 `salt`. `showSalt → { s_u }`(P3). `reset` 은 salt 를 남긴다(R8). `setNextIndex` 없음.
- Produces(시뮬레이터): `createSnapSim()` 같은 RPC·같은 사유, `createReadySnapSim({ s_u } = {})`(P6). `derivedSecrets`·`stubEntropy` 삭제.

- [ ] **Step 1: 실패하는 테스트** — `snap-mode3/test/rpc.test.mjs`: 시드 유도·계정 번호 케이스(`derivedSecrets`, `index`, `nextIndex`, `setNextIndex`, `salt_not_derived`, `snap_getEntropy` 를 쓰는 것)를 지우고 아래를 넣는다. 파일의 기존 하네스(`call(method, params)`, 대화상자 답 큐, `snap_manageState` 대역)를 그대로 쓴다.

```js
await t('salt: initSalt 는 한 번만 — [1, 2^250) 범위의 10진 문자열, 두 번째는 salt_exists; snap_getEntropy 를 부르지 않는다', async () => {
  fresh();
  const { s_u } = await call('initSalt', {});
  assert.match(s_u, /^[0-9]+$/); assert.ok(BigInt(s_u) >= 1n && BigInt(s_u) < (1n << 250n));
  await assert.rejects(() => call('initSalt', {}), /salt_exists/);
  assert.equal(snapCalls.filter((m) => m === 'snap_getEntropy').length, 0);
});
await t('백업 강제(R6): salt 없으면 no_salt, 백업 전이면 backup_required — getSalt·prepareRegister·register·consentLogin·consentDisclosure', async () => {
  fresh();
  for (const [m, p] of GATED) await assert.rejects(() => call(m, p), /no_salt/, m);
  await call('initSalt', {});
  for (const [m, p] of GATED) await assert.rejects(() => call(m, p), /backup_required/, m);
  const info = await call('getPublicInfo', {});
  assert.equal(info.hasSalt, true); assert.equal(info.backedUp, false);
  assert.equal('index' in info, false); assert.equal('nextIndex' in info, false);
});
await t('confirmBackup(R7): 다른 값이면 backup_mismatch 로 그대로, 같은 값이면 backedUp — 그 뒤 getSalt 가 같은 값을 준다', async () => {
  fresh();
  const { s_u } = await call('initSalt', {});
  await assert.rejects(() => call('confirmBackup', { s_u: (BigInt(s_u) + 1n).toString() }), /backup_mismatch/);
  assert.equal((await call('getPublicInfo', {})).backedUp, false);
  assert.equal((await call('confirmBackup', { s_u })).ok, true);
  assert.deepEqual(await call('getSalt', {}), { s_u });
});
await t('exportSaltForBackup(P5): 백업 전에도 같은 salt 를 준다; salt 없으면 no_salt', async () => {
  fresh();
  await assert.rejects(() => call('exportSaltForBackup', {}), /no_salt/);
  const { s_u } = await call('initSalt', {});
  assert.deepEqual(await call('exportSaltForBackup', {}), { s_u });
});
await t('importSalt: 빈 스냅은 받고(확인 창) backedUp 참; 거절하면 { denied }; 형식·범위 밖은 bad_salt', async () => {
  fresh(); dialogs.push(false);
  assert.deepEqual(await call('importSalt', { s_u: '12345' }), { denied: true });
  assert.equal((await call('getPublicInfo', {})).hasSalt, false);
  dialogs.push(true);
  assert.deepEqual(await call('importSalt', { s_u: '12345' }), { ok: true });
  assert.deepEqual(await call('getSalt', {}), { s_u: '12345' });
  for (const bad of ['0', 'abc', (1n << 250n).toString(), '']) { fresh(); await assert.rejects(() => call('importSalt', { s_u: bad }), /bad_salt/); }
});
await t('importSalt: 백업 전·등록 없는 salt 는 덮어쓸 수 있고, 백업했거나 등록이 있으면 salt_exists', async () => {
  fresh(); await call('initSalt', {}); dialogs.push(true);
  assert.deepEqual(await call('importSalt', { s_u: '777' }), { ok: true });
  await assert.rejects(() => call('importSalt', { s_u: '888' }), /salt_exists/);
});
await t('register: salt.s_u 를 쓴다 — s_u 를 실어 보내면 같을 때만(다르면 salt_mismatch); 등록 기록에는 s_u 를 두지 않는다', async () => {
  const s_u = await ready();
  await assert.rejects(() => call('register', { uid: '100001', s_u: (BigInt(s_u) + 1n).toString() }), /salt_mismatch/);
  assert.deepEqual(await call('register', { uid: '100001', s_u }), { uid: '100001', s_u });
  const st = await call('getStoredState', {});
  assert.equal('s_u' in st.registration, false); assert.equal(st.salt.s_u, s_u); assert.equal('nextIndex' in st, false);
});
await t('consentLogin: 증인의 s_u 는 salt.s_u', async () => {
  const s_u = await ready(); await registerFully('100001');
  assert.equal((await call('consentLogin', { origin: 'http://rp.test', arid: '1', allowAgent: false })).s_u, s_u);
});
await t('reset(R8): 등록·동의 기록·userCred 는 지우고 salt·backedUp 은 남는다 — 다시 등록하면 같은 salt', async () => {
  const s_u = await ready(); await registerFully('100001'); dialogs.push(true);
  assert.deepEqual(await call('reset', {}), { ok: true });
  const info = await call('getPublicInfo', {});
  assert.equal(info.registered, false); assert.equal(info.hasSalt, true); assert.equal(info.backedUp, true);
  assert.equal((await call('register', { uid: '100002' })).s_u, s_u);
});
await t('R14: 0.4.x 상태(version 1, 등록 있음)를 만나면 등록을 버리고 salt 없음으로 시작한다', async () => {
  stored = { version: 1, registration: { uid: '100001', index: 0, s_u: '55', auid: '9', slot: 0, attrs: ['0','0','0','0','0','0'] }, userCred: null, consents: {}, nextIndex: 1 };
  const info = await call('getPublicInfo', {});
  assert.equal(info.registered, false); assert.equal(info.hasSalt, false);
});
await t('없어진 것: setNextIndex 는 method_not_found; manifest 에 snap_getEntropy 권한이 없고 버전은 0.5.0', async () => {
  fresh(); await assert.rejects(() => call('setNextIndex', { index: 1 }), /method_not_found/);
  const mf = JSON.parse(fs.readFileSync(new URL('../snap.manifest.json', import.meta.url), 'utf8'));
  assert.equal('snap_getEntropy' in mf.initialPermissions, false); assert.equal(mf.version, '0.5.0');
});
```
  보조: `fresh()`(저장 상태·대화상자 큐 비움), `ready()`(`initSalt` + `confirmBackup`, s_u 반환), `registerFully(uid)`(`register` + `storeRegistration`), `GATED = [['getSalt', {}], ['prepareRegister', {}], ['register', { uid: '100001' }], ['consentLogin', { origin: 'http://rp.test' }], ['consentDisclosure', { relay: true, to: '0x0', value: '0' }]]`. 기존 케이스 가운데 등록을 전제로 하는 것은 앞에 `ready()` 를 넣는다.
- [ ] **Step 2: 붉은지 확인** — `bash scripts/run_tests.sh snap > "$SCRATCH/snap_red.log" 2>&1; tail -20` → 새 케이스 FAIL(`method_not_found: initSalt` 등).
- [ ] **Step 3: `snap-mode3/src/crypto.js`** — `ENTROPY_SALT_S_U`·`INDEX_MAX`·`isIndex`·`saltFromEntropy`·`deriveRegistrationSecrets` 를 지우고:

```js
/** salt(s_u) 를 스냅 안에서 무작위로 만든다 — [1, 2^250 − 1](10진 문자열). 2026-11-13(스펙 random-salt R2): snap_getEntropy 유도를 버렸다. */
export function randomSalt() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  let v = 0n;
  for (const b of bytes) v = (v << 8n) | BigInt(b);
  return (1n + (v % (SCALAR_MAX - 1n))).toString();
}
export const isSalt = (v) => typeof v === 'string' && /^[0-9]+$/.test(v) && BigInt(v) >= 1n && BigInt(v) < SCALAR_MAX;
```
  머리 주석에 2026-11-13 줄을 더한다.
- [ ] **Step 4: `snap-mode3/src/index.js`** —

```js
import { randomSalt, isSalt, ATTR_MAX } from './crypto.js';
const EMPTY_STATE = { version: 2, salt: null, registration: null, userCred: null, consents: {} };
async function getState() {
  const s = await snap.request({ method: 'snap_manageState', params: { operation: 'get' } });
  // 0.5.0(스펙 random-salt R14·P1): 옛 상태(version 1 — 시드 유도 등록·계정 번호)는 이어 쓰지 않는다. salt 없음으로 시작한다.
  if (!s || s.version !== 2) return { ...EMPTY_STATE, consents: {} };
  return { ...EMPTY_STATE, ...s, consents: s.consents ?? {} };
}
const requireSalt = (state) => (state.salt?.s_u ? state.salt : fail('no_salt: 이 스냅에 salt 가 없다 — zk 스냅 화면에서 새로 만들거나 백업에서 불러온다'));
/** 백업 강제(R6): salt 를 밖으로 내거나 가입·로그인으로 이어지는 RPC 가 먼저 부른다. */
const requireBackedUp = (state) => { const s = requireSalt(state); if (s.backedUp !== true) fail('backup_required: salt 백업을 확인한 뒤에 쓸 수 있다'); return s; };
```
  새 case:
```js
    case 'initSalt': {
      if (state.salt) fail('salt_exists: 이미 salt 가 있다');
      state.salt = { s_u: randomSalt(), createdAt: new Date().toISOString(), source: 'new', backedUp: false, backedUpAt: null };
      await setState(state);
      return { s_u: state.salt.s_u };
    }
    case 'importSalt': {
      const su = String(params.s_u ?? '').trim();
      if (!isSalt(su)) fail('bad_salt: salt 는 1 이상 2^250 미만의 10진 문자열');
      if (state.salt && (state.salt.backedUp === true || state.registration)) fail('salt_exists: 이미 쓰고 있는 salt 가 있다(바꾸려면 스냅을 제거한다)');
      const ok = await confirm('백업에서 salt 불러오기', ['백업 파일의 salt 를 이 스냅에 넣습니다.', '같은 salt 면 서비스마다 예전과 같은 주소로 로그인됩니다.']);
      if (!ok) return { denied: true };
      state.salt = { s_u: BigInt(su).toString(), createdAt: new Date().toISOString(), source: 'import', backedUp: true, backedUpAt: new Date().toISOString() };
      state.registration = null; state.userCred = null; await setState(state);
      return { ok: true };
    }
    case 'confirmBackup': {
      const salt = requireSalt(state);
      const su = String(params.s_u ?? '').trim();
      if (!isSalt(su) || BigInt(su).toString() !== salt.s_u) fail('backup_mismatch: 백업 파일의 값이 이 스냅의 salt 와 다르다');
      salt.backedUp = true; salt.backedUpAt = new Date().toISOString(); await setState(state);
      return { ok: true, backedUpAt: salt.backedUpAt };
    }
    case 'exportSaltForBackup': { return { s_u: requireSalt(state).s_u }; }
```
  고칠 case: `register`(맨 앞에 `const salt = requireBackedUp(state);`, 유도 대신 `salt.s_u`, `s_u` 불일치 사유 `salt_mismatch`, 기록 `{ uid, auid: null, slot: null, attrs: null, registeredAt }`, 반환 `{ uid, s_u: salt.s_u }`), `prepareRegister`(같은 방식, 보류가 있어도 `{ s_u: salt.s_u }`), `getSalt`(`{ s_u: requireBackedUp(state).s_u }`), `showSalt`(`{ s_u: requireSalt(state).s_u }`), `storeRegistration`(`nextIndex` 줄 삭제), `getPublicInfo`(`hasSalt: Boolean(state.salt)`, `backedUp: state.salt?.backedUp === true`, `index`·`nextIndex` 삭제), `getStoredState`(`{ ...clone(state), salt: clone(state.salt), … }`, `nextIndex` 삭제), `consentLogin`·`consentDisclosure`(맨 앞에 `requireBackedUp(state)`), `buildWitness`(`s_u: state.salt.s_u`, 완결성 검사에서 `r.s_u` 대신 `state.salt?.s_u`), `reset`(확인 문구 "이 스냅의 등록·동의 기록을 지웁니다. salt 는 남습니다 — 다시 등록하면 같은 주소입니다."; `await setState({ ...EMPTY_STATE, consents: {}, salt: state.salt })`), `setNextIndex` 삭제, `getState` 의 `sk_u` 정리 줄 삭제. 머리 주석의 "남은 대화상자" 목록에 "백업에서 salt 불러오기" 를 더한다.
- [ ] **Step 5: 버전·권한** — `snap.manifest.json`: `"version": "0.5.0"`, `initialPermissions` 에서 `snap_getEntropy` 삭제. `package.json`: `"version": "0.5.0"`. `README.md` 의 비밀 설명 한 줄(시드 유도 → 무작위 + 백업). `cd snap-mode3 && npm run build > "$SCRATCH/snap_build.log" 2>&1`(shasum 갱신), `grep -c snap_getEntropy snap-mode3/dist/bundle.js` → 0.
- [ ] **Step 6: 시뮬레이터·스텁** — `tests/helpers/snap_sim.mjs` 를 같은 RPC·같은 사유 문자열로 맞춘다(상태 `{ salt: null, registration: null, userCred: null, consents: {} }`, `initSalt`·`importSalt({ s_u }, decision = 'allow')`·`confirmBackup`·`exportSaltForBackup`, `register`/`prepareRegister`/`getSalt`/`consentLogin`/`consentDisclosure` 의 거절, `reset` 이 salt 유지). `createSnapSim({ srp })` 인자와 `derivedSecrets`·`stubEntropy` 를 지우고:

```js
/** 설정이 끝난 시뮬레이터(P6) — s_u 를 주면 불러오기, 없으면 새로 만들고 백업 확인까지. */
export function createReadySnapSim({ s_u } = {}) {
  const sim = createSnapSim();
  if (s_u !== undefined) sim.importSalt({ s_u: String(s_u) });
  else sim.confirmBackup({ s_u: sim.initSalt().s_u });
  return sim;
}
```
  `tests/helpers/ethereum_stub.js`: `snap_getEntropy` 분기와 SRP 주석을 지우고 버전 문자열을 `0.5.0` 으로.
- [ ] **Step 7: 초록 확인** — `bash scripts/run_tests.sh snap > "$SCRATCH/snap_green.log" 2>&1; tail -5` → `통과 1 / 실패 0`.
- [ ] **Step 8: 커밋** — `feat(snap): 0.5.0 — 무작위 salt 하나(initSalt·importSalt·confirmBackup·exportSaltForBackup), 백업 전에는 salt·가입·로그인 거절, 계정 번호·snap_getEntropy 삭제`

### Task 5: IdP — `auid_taken`, 상태 14

**Files:**
- Modify: `cia.js:1113-1141`(`registerAccount`), `lib/mode3_cia_state.js:28-43`, `mode3/common/strings.js`(`admin_auidmap_title` 등 문구), `mode3/cia_admin.html:105` 근처 설명
- Test: `tests/test_mode3_cia_state.js`, `tests/test_cia_register_issue.mjs`, `tests/test_cia_accounts.mjs`

**Interfaces:**
- Consumes: Task 1 `auidOf({ s_u })`, Task 2 의 `pi_idp` 산출물(체인 테스트가 실제 π_IdP 를 만든다).
- Produces: 등록 응답 `409 { error: 'auid taken', reason: 'auid_taken' }`; `CIA_STATE_VERSION = 14`.

- [ ] **Step 1: 실패하는 테스트** —
  `tests/test_mode3_cia_state.js`: "버전 14 는 그대로 통과", "13·12 는 `unsupported IdP state version` 으로 throw(메시지에 `데모 리셋`)", `defaultCiaState().version === 14`.
  `tests/test_cia_register_issue.mjs`(같은 salt 로 uid 둘을 등록하는 케이스를 새로):

```js
await t('R11: 같은 스냅(같은 auid)의 두 번째 계정은 409 auid_taken — 같은 uid 의 재등록은 restored, 증명이 틀리면 auid 와 무관하게 bad_idp_proof', async () => {
  const s_u = 4242424242n;
  const a = await registerWith({ uid: uidA, s_u });                 // 기존 헬퍼: π_IdP(등록 ctx) 를 만들어 POST /cia/register
  assert.equal(a.status, 201);
  const again = await registerWith({ uid: uidA, s_u });
  assert.equal(again.status, 201); assert.equal(again.body.restored, true);
  const b = await registerWith({ uid: uidB, s_u });
  assert.equal(b.status, 409); assert.equal(b.body.reason, 'auid_taken');
  const forged = await registerWith({ uid: uidB, s_u, tamperProof: true });
  assert.equal(forged.status, 400); assert.equal(forged.body.reason, 'bad_idp_proof');
});
await t('P7: 연결 해제로 auid 가 비워진 계정의 스냅은 다른 uid 로 다시 등록할 수 있다', async () => {
  const s_u = 5151515151n;
  assert.equal((await registerWith({ uid: uidC, s_u })).status, 201);
  await unlinkWallet(uidC);                                         // 기존 헬퍼(사용자 세션으로 POST /cia/user/unlink)
  assert.equal((await registerWith({ uid: uidD, s_u })).status, 201);
});
```
  헬퍼 이름은 그 파일의 기존 것에 맞춘다(없으면 같은 파일의 등록 호출 코드를 함수로 묶는다 — 테스트 파일 안에서만).
- [ ] **Step 2: 붉은지 확인** — `node tests/test_mode3_cia_state.js` FAIL; hardhat 노드를 띄운 뒤 `node tests/test_cia_register_issue.mjs > "$SCRATCH/t5_red.log" 2>&1` → 새 케이스 FAIL(두 번째 계정이 201).
- [ ] **Step 3: 구현** —
  `lib/mode3_cia_state.js`: `CIA_STATE_VERSION = 14`, `ACCEPTED_VERSIONS = new Set([14])`, 12 → 13 이행 줄 삭제, 오류 문구 `unsupported IdP state version ${v} (expected 14) — 2026-11-13(스펙 random-salt R14): auid·PPID 식이 바뀌어 옛 상태를 이행하지 않는다. 데모 리셋(상태 파일을 옮겨 두고 새로 시작)으로 시작할 것`, 머리 주석에 version 14 줄.
  `cia.js` `registerAccount` — `same` 계산 뒤, 증명 검증(`if (!verified) { … }`) **뒤**에:

```js
  // R11(2026-11-13 스펙 random-salt): 같은 IdP 에서 한 스냅(같은 auid)의 계정은 하나다. 증명을 본 뒤에 검사한다 — 틀린 요청에 auid 존재 여부를 알려 주지 않는다.
  const auidStr = BigInt(auid).toString();
  if (!same && Object.entries(state.accounts).some(([u, a]) => u !== uid && a?.auid === auidStr)) return fail(409, { error: 'auid taken', reason: 'auid_taken' });
```
  (`await` 사이 경합 검사 줄 `if (state.accounts[uid]?.auid) …` 바로 위에도 같은 조건을 한 번 더 둔다.) 관리자 표 문구: `admin_auidmap_title` 을 "uid ↔ auid(스냅 가명) 대응" 으로, 설명 문자열에 "계정 하나에 스냅 하나" 를 더한다.
- [ ] **Step 4: 초록 확인** — `node tests/test_mode3_cia_state.js`, `node tests/test_cia_register_issue.mjs`, `node tests/test_cia_accounts.mjs` → 0 FAIL.
- [ ] **Step 5: 커밋** — `feat(idp): 같은 스냅(auid)의 두 번째 계정은 auid_taken, 상태 버전 14(옛 상태는 기동 거부)`

### Task 6: 스냅 에이전트 — 계정 번호 삭제, 새 식

**Files:**
- Modify: `mode3_wallet_agent.js`(`:608` status 의 `index`, `/wallet/register`·`/wallet/register/resume`·Google 등록 경로의 `index` 처리, 등록 기록에 `index` 를 쓰는 곳), `lib/mode3_wallet_state.js`(있으면 `index` 검증)
- Test: `tests/test_mode3_wallet_agent.mjs`, `tests/test_mode3_wallet_snap.mjs`

**Interfaces:**
- Consumes: Task 4 `createReadySnapSim`, Task 5 `auid_taken`.
- Produces: `/wallet/status` 에 `index` 없음; `/wallet/register` 본문의 `index` 는 무시; IdP 의 `auid_taken` 은 `409 { reason: 'auid_taken' }` 로 그대로 전달.

- [ ] **Step 1: 실패하는 테스트** — `tests/test_mode3_wallet_snap.mjs`: `createSnapSim({ srp })`·`derivedSecrets`·`index` 를 쓰는 케이스를 `createReadySnapSim()` 으로 바꾸고 더한다:

```js
await t('복구: 스냅을 비우고 같은 salt 를 불러오면(importSalt) /wallet/register/resume 가 auid 를 맞춰 등록을 되살린다 — 다른 salt 면 secrets_mismatch', async () => {
  const first = createReadySnapSim();
  const { s_u } = await registerVia(first, uid);                    // 기존 등록 헬퍼
  const restored = createReadySnapSim({ s_u });
  assert.equal((await resumeVia(restored, uid)).status, 200);
  const other = createReadySnapSim();
  const r = await resumeVia(other, uid);
  assert.equal(r.status, 409); assert.equal(r.body.reason, 'secrets_mismatch');
});
await t('상태·응답에 계정 번호가 없다', async () => {
  const st = await (await fetch(`${agent}/wallet/status`)).json();
  assert.equal('index' in st, false);
});
```
- [ ] **Step 2: 붉은지 확인** — 두 테스트 파일 실행 → import 오류(`derivedSecrets` 없음) 또는 새 케이스 FAIL.
- [ ] **Step 3: 구현** — 에이전트에서 `index` 를 받는·저장하는·돌려주는 코드를 지운다(`grep -n "index" mode3_wallet_agent.js | grep -v "indexOf\|findIndex\|{ index: false }"` 로 전부 본다). 주석의 "시드에서 유도"·"계정 번호" 설명을 "스냅의 무작위 salt(백업에서 복구)" 로 고친다.
- [ ] **Step 4: 초록 확인** — `node tests/test_mode3_wallet_agent.mjs > "$SCRATCH/t6_agent.log" 2>&1`, `node tests/test_mode3_wallet_snap.mjs > "$SCRATCH/t6_snap.log" 2>&1` → 0 FAIL.
- [ ] **Step 5: 커밋** — `feat(agent): 계정 번호 삭제 — 스냅 salt 하나, 복구는 같은 salt 를 불러온 스냅으로`

### Task 7: zk 스냅 화면 — 설정 카드(새로 만들기·불러오기), 백업 다시 만들기, 계정 번호 UI 삭제

**Files:**
- Modify: `mode3/wallet.html`, `mode3/common/strings.js`
- Test: `tests/test_mode3_browser.mjs`, `tests/test_mode3_wallet_snap_oidc_browser.mjs`

**Interfaces:**
- Consumes: Task 4 RPC, `window.Mode3Attr.{backupKey, sealBackup, openBackup, isSealedBackup, BACKUP_MIN_PASSWORD}`(기존 `loadAttrBundle()`), Task 5 `auid_taken`.
- Produces(DOM id): `#setupCard`, `#setupNewBtn`, `#setupImportFile`, `#setupPw`, `#setupPw2`, `#setupSaveBtn`, `#setupImportPwRow`, `#setupImportPw`, `#setupImportOpenBtn`, `#setupImportCancelBtn`, `#setupVerdict`, `#rebackupBtn`.

- [ ] **Step 1: 실패하는 테스트** — `tests/test_mode3_browser.mjs`. 테스트 헬퍼 둘을 더한다: `snapReady(page)`(스텁 스냅에 `initSalt` + `confirmBackup` 을 직접 불러 설정을 끝낸다 — 기존 케이스들의 준비 단계), `stubSavePicker(page)`(929행의 `showSaveFilePicker` 대역 — OPFS 파일 핸들 — 을 함수로 옮긴 것). 기존 케이스는 등록·로그인 전에 `snapReady` 를 부르게 고치고, 계정 번호·시드 복구(I-3)·속성 도구 백업 케이스는 지운다. 새 케이스:

```js
await t('설정(R3·R4): 스냅을 연결하면 salt 가 없어 설정 카드가 먼저 보인다 — 새로 만들기 → 비밀번호 두 번 → 파일 저장 → 다시 읽어 확인 → 카드가 사라지고 백업 완료', async () => {
  const p = await openWallet(); await stubSavePicker(p);
  await p.click('#connectBtn');
  await p.waitForSelector('#setupCard:not([hidden])');
  await p.click('#setupNewBtn');
  await p.fill('#setupPw', 'backup-pass-1'); await p.fill('#setupPw2', 'backup-pass-1');
  await p.click('#setupSaveBtn');
  await p.waitForSelector('#setupCard', { state: 'hidden' });
  const info = await snapCall(p, 'getPublicInfo', {});
  assert.equal(info.hasSalt, true); assert.equal(info.backedUp, true);
  const text = await savedBackupText(p);                             // OPFS 파일 내용
  const sealed = JSON.parse(text);
  assert.equal(sealed.format, 'zkd-attr-backup'); assert.equal(text.includes((await snapCall(p, 'getSalt', {})).s_u), false, '파일에 salt 평문이 없다');
});
await t('Review 2: 비밀번호가 서로 다르거나 파일 창을 취소하면 salt 를 만들지 않는다; 쓰기가 실패하면 salt 는 남고 backedUp 은 거짓 — 다시 하면 같은 salt 로 백업된다', async () => {
  const p = await openWallet(); await p.click('#connectBtn'); await p.click('#setupNewBtn');
  await p.fill('#setupPw', 'backup-pass-1'); await p.fill('#setupPw2', 'different-1'); await p.click('#setupSaveBtn');
  await expectVerdict(p, '#setupVerdict', /비밀번호가 서로 다릅니다/);
  await p.evaluate(() => { window.showSaveFilePicker = async () => { throw new DOMException('abort', 'AbortError'); }; });
  await p.fill('#setupPw2', 'backup-pass-1'); await p.click('#setupSaveBtn');
  await expectVerdict(p, '#setupVerdict', /취소/);
  assert.equal((await snapCall(p, 'getPublicInfo', {})).hasSalt, false, '파일을 고르기 전에는 salt 를 만들지 않는다(P12)');
  await p.evaluate(() => { window.showSaveFilePicker = async () => ({ createWritable: async () => { throw new Error('disk full'); } }); });
  await p.click('#setupSaveBtn');
  await expectVerdict(p, '#setupVerdict', /저장하지 못했습니다/);
  const mid = await snapCall(p, 'getPublicInfo', {});
  assert.equal(mid.hasSalt, true); assert.equal(mid.backedUp, false);
  const before = (await snapCall(p, 'exportSaltForBackup', {})).s_u;
  await stubSavePicker(p, { now: true });                            // 이미 열린 페이지에 바로 심는다
  await p.fill('#setupPw', 'backup-pass-1'); await p.fill('#setupPw2', 'backup-pass-1'); await p.click('#setupSaveBtn');
  await p.waitForSelector('#setupCard', { state: 'hidden' });
  assert.equal((await snapCall(p, 'getSalt', {})).s_u, before);
});
await t('Review 1: 백업 전 스냅으로 RP 로그인하면 팝업이 설정 안내로 끝난다(snap_setup_required) — 증인은 나가지 않는다', async () => { /* RP 페이지에서 로그인 → 팝업 verdict 문구 "zk 스냅 화면에서 먼저 salt 를 만들고 백업", RP 는 로그인 실패 */ });
await t('불러오기 → 같은 PPID: 스냅 상태를 지우고 백업 파일을 불러오면 RP 로그인의 PPID 가 예전과 같고, 속성 도구에서 같은 속성을 넣으면 같은 C_attr', async () => { /* 로그인 PPID 기록 → clearSnapState → setInputFiles(#setupImportFile) → 비밀번호 → importSalt 확인 창 allow → 로그인 → PPID 같음 → attr.html 같은 속성 → commit 같음 */ });
await t('Review 3: 틀린 비밀번호(bad_password)·다른 형식 파일(bad_backup)·s_u 없는 기록은 사유를 보이고 스냅은 그대로 salt 없음; 속성이 든 옛 형식 백업은 salt 만 받는다', async () => { /* 네 파일을 차례로 */ });
await t('R16: 파일 change 직후 0.7초 안의 "취소" 클릭은 무시되고(비밀번호 칸이 남는다) 그 뒤 클릭은 듣는다', async () => {
  const p = await openWalletConnected();
  await p.setInputFiles('#setupImportFile', backupFilePath);
  await p.waitForSelector('#setupImportPwRow:not([hidden])');
  await p.click('#setupImportCancelBtn');                              // change 직후
  assert.equal(await p.isHidden('#setupImportPwRow'), false);
  await p.waitForTimeout(800);
  await p.click('#setupImportCancelBtn');
  assert.equal(await p.isHidden('#setupImportPwRow'), true);
});
await t('R11: 같은 스냅으로 두 번째 계정을 등록하면 "이 스냅은 이 IdP 에 이미 다른 계정으로 등록돼 있습니다"', async () => { /* 계정 A 등록 → 스냅 reset(동의) → 계정 B 로 로그인·등록 시도 → verdict 문구 */ });
await t('백업 다시 만들기(P11): "내 계정" 탭의 버튼 → 새 비밀번호·새 파일 → 새 파일을 새 비밀번호로 열면 같은 salt', async () => { /* … */ });
await t('계정 번호 UI 가 없다: #indexFold·#nextIndexBtn 없음', async () => { const p = await openWallet(); assert.equal(await p.locator('#indexFold, #nextIndexBtn').count(), 0); });
```
  주석으로 적은 케이스의 본문은 그 줄에 적힌 순서 그대로 쓴다(이 파일의 기존 헬퍼 `openWallet`·`snapCall`·`expectVerdict`·`idpLogin`·`completeIdpAuth` 를 쓴다 — 이름이 다르면 그 파일의 것에 맞춘다).
- [ ] **Step 2: 붉은지 확인** — hardhat 노드를 띄우고 `node tests/test_mode3_browser.mjs > "$SCRATCH/t7_red.log" 2>&1; grep -c "^FAIL"` → 새 케이스들이 FAIL(`#setupCard` 없음).
- [ ] **Step 3: 마크업** — MetaMask 연결 상태 줄 바로 아래(P10):

```html
<section class="card" id="setupCard" hidden>
  <h3 data-i18n="wallet_setup_title">스냅 설정 — salt 와 백업</h3>
  <p class="desc" id="setupDesc" data-i18n="wallet_setup_desc">이 스냅의 salt 가 서비스마다의 주소를 정합니다. 새로 만들면 암호화 백업 파일을 먼저 저장해야 쓸 수 있습니다. 백업 파일과 비밀번호를 잃으면 되찾을 수 없습니다.</p>
  <p class="row-actions" id="setupChoice">
    <button type="button" id="setupNewBtn" data-i18n="wallet_setup_new_btn">새로 만들기</button>
    <label class="btn btn-ghost"><span data-i18n="wallet_setup_import_btn">백업에서 불러오기</span> <input type="file" id="setupImportFile" accept="application/json" hidden /></label>
  </p>
  <div id="setupBackupRow" class="pw-form" hidden>
    <label><span data-i18n="wallet_setup_pw">백업 비밀번호(8자 이상)</span> <input id="setupPw" type="password" autocomplete="new-password" /></label>
    <label><span data-i18n="wallet_setup_pw2">한 번 더</span> <input id="setupPw2" type="password" autocomplete="new-password" /></label>
    <p class="row-actions"><button type="button" id="setupSaveBtn" data-i18n="wallet_setup_save_btn">백업 파일 저장</button></p>
  </div>
  <div id="setupImportPwRow" class="pw-form" hidden>
    <p class="muted" id="setupImportHint"></p>
    <label><span data-i18n="wallet_setup_import_pw">백업 비밀번호</span> <input id="setupImportPw" type="password" autocomplete="off" /></label>
    <p class="row-actions"><button type="button" id="setupImportOpenBtn" data-i18n="wallet_setup_import_open_btn">불러오기</button> <button type="button" id="setupImportCancelBtn" class="btn-ghost" data-i18n="wallet_setup_import_cancel_btn">취소</button></p>
  </div>
  <div id="setupVerdict"></div>
</section>
```
  "내 계정" 탭 끝에 `<p class="row-actions"><button type="button" id="rebackupBtn" class="btn-ghost" data-i18n="wallet_rebackup_btn">백업 다시 만들기</button></p>`. `#indexFold` 절(126-135행)을 지운다.
- [ ] **Step 4: 스크립트** —

```js
// ---- 스냅 설정(2026-11-13 스펙 random-salt R3~R7): salt 가 없거나 백업 전이면 이 카드가 탭보다 먼저다. ----
let setupMode = null;          // 'new'(initSalt 가 필요) | 'backup'(salt 는 있고 백업만) | 'rebackup'("내 계정" 의 다시 만들기)
let pendingImport = null;      // 비밀번호를 기다리는 봉인 백업
let importGuardUntil = 0;      // R16: 파일 선택 직후의 헛클릭을 무시할 시각
const setupGuarded = () => Date.now() < importGuardUntil;
async function refreshSetup() {
  const info = await invokeSnap('getPublicInfo', {});
  const need = !info.hasSalt || !info.backedUp;
  $('setupCard').hidden = !need && setupMode !== 'rebackup';
  document.querySelectorAll('[data-panel]').forEach((el) => { if (need) el.hidden = true; });   // 설정 전에는 탭 내용을 가린다(끝나면 showTab 이 다시 연다)
  $('setupChoice').hidden = info.hasSalt;                 // salt 가 있으면 새로 만들기·불러오기 대신 백업만
  $('setupBackupRow').hidden = !(info.hasSalt && !info.backedUp) && setupMode !== 'rebackup' && setupMode !== 'new';
  if (info.hasSalt && !info.backedUp) setupMode = 'backup';
  if (!need && setupMode !== 'rebackup') showTab(currentTab);
  return info;
}
$('setupNewBtn').addEventListener('click', () => { setupMode = 'new'; $('setupBackupRow').hidden = false; closeSetupImport(); clearVerdict($('setupVerdict')); });
$('rebackupBtn').addEventListener('click', () => { setupMode = 'rebackup'; $('setupCard').hidden = false; $('setupChoice').hidden = true; $('setupBackupRow').hidden = false; $('setupCard').scrollIntoView(); });
$('setupSaveBtn').addEventListener('click', async () => {
  const v = $('setupVerdict'); clearVerdict(v);
  try {
    if (!(await loadAttrBundle())) throw Object.assign(new Error('bundle_missing'), { reason: 'bundle_missing' });
    const A = window.Mode3Attr;
    const pw = $('setupPw').value;
    if (pw.length < A.BACKUP_MIN_PASSWORD) return setVerdict(v, false, 'wallet_setup_pw_short');
    if (pw !== $('setupPw2').value) return setVerdict(v, false, 'wallet_setup_pw_differ');
    if (typeof window.showSaveFilePicker !== 'function') return setVerdict(v, false, 'wallet_setup_unsupported');
    let handle;
    try { handle = await window.showSaveFilePicker({ suggestedName: 'zkd-salt-backup.json', types: [{ description: 'zkd salt 백업', accept: { 'application/json': ['.json'] } }] }); }
    catch { return setVerdict(v, false, 'wallet_setup_cancelled'); }
    // 파일을 고른 뒤에야 salt 를 만든다 — 취소로 끝난 시도가 백업 없는 salt 를 남기지 않게. 이미 있으면(P5) 그 값을 받는다.
    const info = await invokeSnap('getPublicInfo', {});
    const { s_u } = info.hasSalt ? await invokeSnap('exportSaltForBackup', {}) : await invokeSnap('initSalt', {});
    const { key, kdf } = await A.backupKey(pw);
    const w = await handle.createWritable(); await w.write(JSON.stringify(await A.sealBackup(key, kdf, { version: 4, s_u }))); await w.close();
    const back = await A.openBackup(pw, JSON.parse(await (await handle.getFile()).text()));   // R7: 저장한 파일을 다시 열어 본다
    await invokeSnap('confirmBackup', { s_u: String(back?.s_u ?? '') });
    $('setupPw').value = ''; $('setupPw2').value = ''; setupMode = null;
    setVerdict(v, true, 'wallet_setup_done'); await refreshSetup();
  } catch (e) { setVerdict(v, false, 'wallet_setup_failed', { reason: e?.reason ?? reasonOf(e), detail: e?.message }); }
});
function closeSetupImport() { pendingImport = null; $('setupImportPw').value = ''; $('setupImportPwRow').hidden = true; }
$('setupImportFile').addEventListener('change', async (ev) => {
  importGuardUntil = Date.now() + 700;   // R16(사용자 보고 2026-11-13): 파일 창에서 더블클릭하면 두 번째 클릭이 창이 닫힌 뒤 이 페이지에 떨어진다
  const f = ev.target.files?.[0]; ev.target.value = '';
  const v = $('setupVerdict'); clearVerdict(v); closeSetupImport();
  if (!f) return;
  let sealed = null;
  try { sealed = JSON.parse(await f.text()); } catch { return setVerdict(v, false, 'wallet_setup_import_failed', { reason: 'bad_backup' }); }
  if (!(await loadAttrBundle())) return setVerdict(v, false, 'wallet_setup_import_failed', { reason: 'bundle_missing' });
  if (!window.Mode3Attr.isSealedBackup(sealed)) return setVerdict(v, false, 'wallet_setup_import_failed', { reason: 'bad_backup' });
  pendingImport = sealed; $('setupImportHint').textContent = f.name; $('setupImportPwRow').hidden = false; $('setupBackupRow').hidden = true; $('setupImportPw').focus();
});
$('setupImportOpenBtn').addEventListener('click', async () => {
  if (setupGuarded() || !pendingImport) return;
  const v = $('setupVerdict'); clearVerdict(v);
  try {
    const rec = await window.Mode3Attr.openBackup($('setupImportPw').value, pendingImport);
    const su = typeof rec?.s_u === 'string' ? rec.s_u : '';
    if (!/^[0-9]+$/.test(su) || BigInt(su) < 1n || BigInt(su) >= (1n << 250n)) return setVerdict(v, false, 'wallet_setup_import_failed', { reason: 'bad_backup' });   // 옛 형식도 s_u 만 본다(스펙 §5.3)
    const r = await invokeSnap('importSalt', { s_u: su });
    if (r?.denied) return setVerdict(v, false, 'wallet_setup_import_failed', { reason: 'user_denied' });
    closeSetupImport(); setVerdict(v, true, 'wallet_setup_import_done'); await refreshSetup();
  } catch (e) { setVerdict(v, false, 'wallet_setup_import_failed', { reason: e?.reason ?? reasonOf(e), detail: e?.message }); }
});
$('setupImportCancelBtn').addEventListener('click', () => { if (setupGuarded()) return; closeSetupImport(); clearVerdict($('setupVerdict')); });
```
  `reasonOf(e)` 는 스냅 오류 문구의 앞 낱말(`no_salt`·`backup_required`·`salt_exists`·`backup_mismatch`·`bad_salt`)을 사유로 뽑는다 — 이 파일에 같은 일을 하는 함수가 있으면 그것을 쓴다. `connectMetaMask()` 성공 뒤와, 페이지를 열 때 스냅이 이미 설치돼 있으면(`snapInstalled`) `refreshSetup()` 을 부른다.
- [ ] **Step 5: 나머지 정리** —
  - `snapDerivedSalt(index)`(648-656행) → `async function snapSalt() { try { return { ok: true, s_u: String((await invokeSnap('getSalt', {})).s_u) }; } catch (e) { const r = reasonOf(e); if (r === 'no_salt' || r === 'backup_required') return { ok: false, reason: 'snap_setup_required' }; if (/method_not_found/.test(e?.message ?? '')) return { ok: false, reason: 'snap_outdated' }; throw e; } }`.
  - `restoreSnapIfEmpty`: `index` 를 지우고 `prepareRegister({})`. 스냅이 `snap_setup_required` 면 그 사유로 끝낸다.
  - 등록 흐름(738-757행): `rec.index` 검사 삭제, `snapSalt()` 값과 `rec.s_u` 가 다르면 `attr_record_salt_mismatch`(P8), `invokeSnap('register', { uid, s_u: rec.s_u })`, `/wallet/register` 본문에서 `index` 삭제. Google 등록(640행)도 `index` 삭제.
  - RP 로그인 팝업: `consentLogin`·`register`·`prepareRegister` 가 `no_salt`·`backup_required` 로 실패하면 사유 `snap_setup_required`, 문구 `wallet_err_snap_setup_required`("zk 스냅 화면(localhost:5100)에서 먼저 salt 를 만들고 백업하세요")와 그 화면 링크. 로그인은 실패로 끝낸다.
  - 등록 실패 사유 `auid_taken` → `wallet_err_auid_taken`("이 스냅은 이 IdP 에 이미 다른 계정으로 등록돼 있습니다").
  - "내 계정" 탭: `STORE_SECRETS` 에서 `sk_u` 삭제, `salt.s_u` 가 가려지는지 확인(키 이름 `s_u` 로 걸린다), `#meIndex`·`#meNextIndex`·`nextIndexBtn` 처리 코드(1237, 1582-1600행) 삭제.
  - `mode3/common/strings.js`: 위 새 키(`wallet_setup_*`, `wallet_rebackup_btn`, `wallet_err_snap_setup_required`, `wallet_err_auid_taken`)를 더하고 `wallet_index_*`·`wallet_next_index_*`·`attr_record_salt_not_derived`·`snap_restore_mismatch` 가운데 쓰이지 않게 된 것을 지운다.
- [ ] **Step 6: 초록 확인** — `node tests/test_mode3_browser.mjs > "$SCRATCH/t7_green.log" 2>&1; grep -c "^ok"; grep -c "^FAIL"` → FAIL 0. `node tests/test_mode3_wallet_snap_oidc_browser.mjs > "$SCRATCH/t7_oidc.log" 2>&1` → FAIL 0(준비 단계에 `snapReady` 를 넣는다).
- [ ] **Step 7: 커밋** — `feat(wallet): zk 스냅 화면 설정 카드 — salt 새로 만들기·백업에서 불러오기(파일 선택 직후 헛클릭 무시), 백업 다시 만들기, 계정 번호 UI 삭제`

### Task 8: 문서 + 전체 테스트

**Files:**
- Modify: `docs/MODE3_DEMO.md`, `docs/superpowers/specs/2026-11-12-mode3-snap-derived-secrets-design.md`(머리), `docs/superpowers/specs/2026-11-12-mode3-snap-account-index-design.md`(머리), `CLAUDE.md` 는 고치지 않는다
- Test: 그룹 전체

- [ ] **Step 1: 문서** — `docs/MODE3_DEMO.md` 에 2026-11-13 메모 블록: 스냅 0.5.0(권한이 줄어 재설치), 설치 직후 설정(새로 만들기 → 비밀번호 → 파일 저장 → 확인), 백업에는 salt 만, 복구 시연(스냅 제거 → 재설치 → 백업에서 불러오기 → RP 로그인 → 같은 PPID → 속성 도구에서 같은 속성 → 같은 C_attr), "백업 파일·비밀번호를 잃으면 복구할 수 없다", 식 셋(auid·PPID·C_attr), `auid_taken`, IdP 상태 14·데모 리셋 필요, 속성 도구에서 백업 기능 삭제. 11-12 의 "계정 번호"·"시드 복구 시연" 메모와 11-11 의 D20 자동 백업 메모에 "2026-11-13 대체" 한 줄. 경로 표의 스냅 RPC 목록이 있으면 맞춘다. 대체된 두 스펙의 머리에 `> 2026-11-13 대체: 2026-11-13-mode3-snap-random-salt-backup-design.md` 를 단다(S3 는 유효하다고 적는다).
- [ ] **Step 2: 전체 테스트** — hardhat 노드를 띄우고 차례로: `bash scripts/run_tests.sh unit`, `snap`, `circuit`, `contract`, `chain`, `browser` — 각 출력은 `$SCRATCH/t8_<그룹>.log`. 실패는 원인을 찾아 고치고 그 그룹을 다시 돌린다. 끝나면 노드를 PID 로 끄고 :8545 가 비었는지 확인한다.
- [ ] **Step 3: 남은 옛 흔적 확인** — `grep -rn "snap_getEntropy\|nextIndex\|setNextIndex\|derivedSecrets\|MODE3ATTRC3\|randomBlind" --include=*.js --include=*.mjs --include=*.html --include=*.json lib mode3 snap-mode3/src tests mode3_wallet_agent.js cia.js | grep -v "imt_v2\|dist/"` → 주석의 이력 설명 말고는 0줄.
- [ ] **Step 4: 커밋** — `docs(mode3): 스냅 기준 신원 — 런북(스냅 0.5.0·설치 직후 백업·복구 시연·식 셋·auid_taken·상태 14), 옛 스펙에 대체 표시`

---

## 구현 뒤(이 계획 밖 — 따로 승인)

- 배포: `SYNC=1 bash scripts/demo_split_snap_reset.sh`(사용자가 실행 — 로컬 :5100·:8082 를 내렸다 올린다). 새 `pi_idp`·`pi_cred` 산출물과 검증자 재배포가 같이 간다. 그 뒤 MetaMask 에서 스냅 제거 → 0.5.0 설치 → 설정 카드에서 새로 만들기.
- 논문·덱의 식 수정(PPID = H(salt, rid, chain_id), auid = H(salt)).
- 최종 브랜치 리뷰(Opus), 푸시.
