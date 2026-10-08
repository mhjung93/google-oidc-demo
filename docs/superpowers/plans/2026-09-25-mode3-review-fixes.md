# 2026-09-25 전체 코드 리뷰 지적 처리 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 2026-09-25 전체 코드 리뷰의 Important 7건과 고칠 값이 있는 Minor 를 모두 닫는다. Critical(C-1)은 이미 커밋 `25d56fe` 로 처리됐다.

**Architecture:** 영역별로 나눈다 — AA 서버(경합·지속성), RP 서버(정책 검사·세션 갱신·fail-closed), 지갑(팩토리 검증·동의 창·오리진), 컨트랙트(공개값 위생·다이제스트 범위), 테스트 공백, 문서. 회로와 zkey 는 건드리지 않는다(재빌드·재배포를 부르지 않기 위해, 같은 보장을 컨트랙트 쪽에서 얻는다).

**Tech Stack:** Node ESM(express, ethers v6, snarkjs), Solidity 0.8.24 + hardhat, `t()` 러너 테스트, 격리 스택(`tests/helpers/isolated_mode3_stack.mjs`), Playwright.

**리뷰 원본:** 세션 보고(2026-09-25). 근거 메모: `~/.claude/projects/.../memory/project_mode3_cia_branch_status.md` 의 "2026-09-25 전체 코드 리뷰" 항목.

## Global Constraints

- **회로(`circuits/`)와 `build/mode3/` 산출물은 바꾸지 않는다.** 바꾸면 zkey·검증자 재생성과 팩토리 재배포가 따라온다. 마스크 밖 슬롯 문제는 컨트랙트에서 막는다(T4).
- 기존 테스트는 **수정하지 않는다**. 단 T4 의 다이제스트 변경처럼 계약 자체가 바뀌는 곳은 그 테스트를 함께 고치되, 무엇을 왜 고쳤는지 보고한다.
- 모든 수정에는 **깨졌을 때 빨개지는 테스트**가 따라야 한다. 테스트 없는 수정은 미완성이다.
- `.env`·`*_keys.json`·`*_state.json` 은 읽지도 고치지도 않는다.
- hardhat 노드는 스스로 띄우고(`npx hardhat node > /dev/null 2>&1 &`) 끝나면 그 PID 만 종료, `pkill -f` 금지. 끝에 :8545·:3000·:4000·:5001·:3100·:4100·:5100 이 비었는지 확인한다.
- 커밋 메시지는 한글, 끝에 정확히 두 줄:
  `Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>`
  `Claude-Session: https://claude.ai/code/session_013qGSXZTftBJSB1M4XpPRHN`
- `git add` 는 자기가 고친 파일만. `git add -A` 금지. push 금지.

## 컨트롤러 결정(이미 내렸다 — 재논의하지 말 것)

1. **마스크 밖 슬롯은 컨트랙트가 "거절"한다**(0 으로 지우지 않는다). `_checkStatement` 에서 마스크 비트가 0 인 슬롯의 `lo`·`hi` 가 0 이 아니면 `BadDisclosure`. 정직한 지갑은 늘 0 을 보내므로(`normalizeDisclosure`) 깨질 것이 없고, 꼬리·이벤트를 읽는 대상은 "온체인에 올라온 마스크 밖 값은 항상 0" 을 믿을 수 있다.
2. **`set_root` 는 정책 root 와 다르면 거절한다.** 검사는 `createRpVerifier` 의 새 옵션 `policySetRoot`(기본 `null` = 검사 안 함)로 넣어 로그인·재검증 두 경로를 한 곳에서 덮는다. `mode3_rp.js` 가 `ALLOWED_COUNTRIES_ROOT` 를 넘긴다. 사유는 `bad_disclosure`.
3. **다이제스트를 넓힌다**(A-2). `pub[3] max_height`, `pub[5] allowAgent`, `pub[11..13] tag` 다섯을 추가한다. 이번 계획에서 가장 위험한 변경이니 T4 안에서 컨트랙트·JS·테스트를 한 커밋으로 맞춘다.
4. **고치지 않고 문서로 남기는 것**(T6): uid 존재 열거(다른 라우트도 같은 수준), 상태 무한 증가(데모 규모), RPC 장애 시 10분 캐시(이미 문서화된 설계 선택), 동의 창의 `data` 미표시(2차 UI), snap 증인 유휴 수명(타이머 설계 필요), 지갑 health 를 AA 오리진에 연 것(상태 패널을 위한 의도), `countedTxHashes` 증가(세션 수로 사실상 유계).

---

## 파일 구조

| 파일 | 책임 | 작업 |
|---|---|---|
| `cia.js` | prune 경합, user_cred 지속성, 승인 순서, 개봉 조각 파기 | T1 |
| `tests/test_cia_*.mjs` | 위 회귀 | T1 |
| `lib/mode3_rp.js`, `mode3_rp.js` | `policySetRoot`, 재검증 재바인딩, `/open/:id` fail-closed | T2 |
| `tests/test_mode3_rp.mjs`, `tests/test_mode3_e2e.mjs` | 위 회귀 | T2 |
| `lib/mode3_onchain.js`, `mode3_wallet_agent.js`, `snap-mode3/src/index.js` | 팩토리 상한 검증, `serviceName` 위생, 세션 라우트 arid 대조 | T3 |
| `tests/test_mode3_wallet_agent.mjs`, `snap-mode3/test/rpc.test.mjs` | 위 회귀 + E-2 공백 | T3 |
| `contracts/Mode3Wallet.sol`, `contracts/Mode3WalletFactory.sol`, `lib/mode3_onchain.js` | 마스크 위생, 다이제스트 확장, 낡은 주석 | T4 |
| `test/Mode3Wallet.test.mjs` | E-1 공백 + 위 회귀 | T4 |
| `tests/test_mode3_artifacts.mjs`(신규) 외 | E-3·E-6·E-7·E-8·부실 테스트 | T5 |
| `docs/MODE3_DEMO.md`, `docs/paper/zkd/security_formal.md` | 수용된 한계·바뀐 보장 | T6 |

---

### Task 1: AA 서버 — 정리 경합, 지속성, 승인 순서, 개봉 조각 파기

**Files:** Modify `cia.js`; Test `tests/test_cia_issue_race.mjs`, `tests/test_mode3_session_revoke.mjs`, `tests/test_cia_opening.mjs`

**Interfaces (Produces):** `pruneExpiredSessions()` 는 이제 `await` 를 계정 루프 **밖**에서만 한다. 외부 시그니처 변화 없음.

- [ ] **Step 1: 실패하는 테스트 — 정리 경합** (`tests/test_cia_issue_race.mjs` 에 추가)

경합을 결정적으로 재현한다. 하트비트를 기다리지 말고 `pruneExpiredSessions` 가 도는 동안 발급이 끼어들게 만든다. 격리 CIA 는 하트비트가 꺼져 있으므로(`CIA_HEARTBEAT_BLOCKS=0`) 정리는 `/cia/issue` 안에서만 돈다 — 그래서 **하트비트를 켠 격리 CIA**(`env: { CIA_HEARTBEAT_BLOCKS: '1' }`)로 띄우고, 하트비트 틱이 도는 동안 같은 계정으로 발급을 여러 번 보낸다.

```js
await t('경합: 하트비트 정리가 도는 동안 발급해도 세션 기록이 사라지지 않는다 (2026-09-25 리뷰 I-1)', async () => {
  // 하트비트를 켠 격리 CIA — 정리가 주기적으로 돈다. 발급을 여러 번 겹쳐 보낸다.
  const N = 12;
  const issued = [];
  for (let i = 0; i < N; i++) issued.push(await issueOne());        // 파일의 기존 발급 헬퍼를 쓴다
  const list = (await cia.adminGet(`/cia/admin/sessions?uid=${UID}`)).body.sessions;
  const have = new Set(list.map((s) => s.Cf_s));
  const missing = issued.map((r) => r.body.Cf_s).filter((c) => !have.has(c));
  assert.deepEqual(missing, [], `발급된 세션 기록이 정리에 덮여 사라졌다: ${missing.join(', ')}`);
});
```
발급 헬퍼·`adminGet` 이름은 파일의 기존 것을 그대로 쓴다. 없으면 `tests/test_mode3_session_revoke.mjs` 의 준비 코드를 옮겨 온다. 이 테스트는 확률적이라 수정 전에도 통과할 수 있다 — **그럴 때는 `await headOf` 앞에 인위적 지연을 넣어 재현되는 것을 한 번 확인한 뒤 지연을 빼고 커밋한다**(보고서에 재현 로그를 남길 것).

- [ ] **Step 2: 실패 확인** — 위 테스트(또는 지연을 넣은 판)가 빨개지는 것을 본다.

- [ ] **Step 3: 구현** — `cia.js` 의 `pruneExpiredSessions` 를 두 단계로 나눈다. 체인별 head 를 **먼저 전부** 읽고, 그 뒤 계정 순회는 `await` 없이 동기로 끝낸다.

```js
/** V8: 만료된 세션 기록 삭제(리프는 남는다 — 설계 §6).
 *  head 는 계정 순회 **전에** 모두 읽는다(2026-09-25 리뷰 I-1): 순회 안에서 await 하면 그 사이 /cia/issue 가
 *  acct.sessions 를 새 배열로 갈아끼우고, 재개한 정리가 옛 배열로 만든 keep 을 대입해 방금 발급된 기록을 덮어썼다.
 *  그러면 그 세션은 404 unknown_session 이라 개별 폐기가 영영 안 된다. 아래는 await 이 하나도 없어 원자적이다. */
async function pruneExpiredSessions() {
  const chainIds = new Set();
  for (const acct of Object.values(state.accounts)) for (const s of acct.sessions ?? []) chainIds.add(s.chainid);
  if (chainIds.size === 0) return;
  const heads = {};
  for (const id of chainIds) { try { heads[id] = await headOf(id); } catch { heads[id] = null; } }
  // ↓ 여기부터 await 없음 — 이벤트 루프가 끼어들지 못한다.
  let dropped = 0;
  for (const acct of Object.values(state.accounts)) {
    if (!acct.sessions?.length) continue;
    const keep = acct.sessions.filter((s) => { const h = heads[s.chainid]; const gone = h !== null && h !== undefined && h > BigInt(s.max_height); if (gone) dropped++; return !gone; });
    if (keep.length !== acct.sessions.length) acct.sessions = keep;
  }
  if (dropped) persist();
}
```

- [ ] **Step 4: Minor B-5 — `/cia/user_cred` 의 이른 반환이 `persist()` 를 건너뛴다.** `retireActiveCred()` 는 트리·`state.revoked`·`state.pending` 을 바꾸는데, 그 뒤 415/419/420 로 빠지면 파일에 안 쓴다. 프로세스가 죽으면 그 폐기가 되돌아간다. 고침: 루프에서 한 번이라도 `retireActiveCred` 를 불렀으면 이른 반환 **전에** `persist()` 한다.

```js
    let retired = false;
    for (;;) {
      const cur = activeCred(uid);
      if (cur && cur.Cf_u === Cf_u) { if (retired) persist(); return res.json({ Cf_u, leaf }); }
      if (!cur) break;
      await retireActiveCred(uid); retired = true;
    }
    if (acct.disabled) { if (retired) persist(); return res.status(403).json({ error: 'account disabled' }); }
    if (acct.creds.some((c) => c.Cf_u === Cf_u)) { if (retired) persist(); return res.status(409).json({ error: 'this user credential was revoked; make a new one' }); }
```
회귀 테스트: 속성을 두 번 바꿔 은퇴를 일으킨 뒤 409 로 빠지는 경로에서 `/cia/state` 의 `pendingCount` 가 파일 재기동 뒤에도 유지되는지 본다(`tests/test_cia_startup.mjs` 의 재기동 헬퍼 활용).

- [ ] **Step 5: Minor B-6 — 승인 순서.** `cia.js:343-353` 이 `e.status = 'approved'` 를 먼저 쓰고 `makeShare` 가 던지면 `pk_trace = null` 인 approved 로 굳어 재승인도 재등록도 막힌다. 고침: 조각 생성이 성공한 **뒤에** status 를 바꾼다. 회귀 테스트는 생략해도 되지만(주입이 번거롭다) 순서 이유를 주석에 남긴다.

- [ ] **Step 6: Minor B-4 — 결정 뒤 개봉 조각 파기.** `approve`·`deny` 가 결정된 항목에서 `D_svc`·`c1`·`c2` 를 지운다(`uid`·`resolved`·시각·`arid`·`PPID` 는 기록으로 남긴다). 거절된 요청의 복호 재료가 `x_AA` 와 같은 파일에 계속 남지 않게 한다. `tests/test_cia_opening.mjs` 에 "결정 뒤에는 D_svc·c1·c2 가 남지 않는다" 한 건을 더한다(관리자 `GET /cia/openings` 응답으로 확인).

- [ ] **Step 7: 검증** — 자기 hardhat 노드에서 `node tests/test_cia_issue_race.mjs`, `node tests/test_cia_opening.mjs`, `node tests/test_cia_startup.mjs`, `node tests/test_mode3_session_revoke.mjs`, 그리고 `bash scripts/run_tests.sh chain`.
- [ ] **Step 8: Commit** — `fix(mode3): AA — 세션 기록 정리를 원자적으로(발급과의 경합), 자격증명 은퇴 지속성, 서비스 승인 순서, 결정된 개봉의 복호 조각 파기`

---

### Task 2: RP — 정책 집합 대조, 재검증 재바인딩, 개봉 조회 fail-closed

**Files:** Modify `lib/mode3_rp.js`, `mode3_rp.js`; Test `tests/test_mode3_rp.mjs`

**Interfaces (Produces):** `createRpVerifier({ ..., policySetRoot = null })`. `policySetRoot` 가 bigint 면 `set_sel !== 0` 일 때 `set_root === policySetRoot` 를 강제하고 아니면 `{ ok:false, reason:'bad_disclosure' }`.

- [ ] **Step 1: 실패하는 테스트** (`tests/test_mode3_rp.mjs`)

```js
await t('I-2: 정책 집합이 아닌 set_root 는 bad_disclosure — 회로는 "어떤 트리에 속한다" 만 증명한다', async () => {
  const members = [410, 392, 840, 276, 250];
  const policyRoot = await setRoot(members);
  const rpPolicy = createRpVerifier({ provider, logAddress, vkey, pkCIA: CIA.pub, arid, chainId: 31337n, pkTrace: pk_trace, policySetRoot: policyRoot });
  // 자기 국가만 든 집합으로 "소속" 을 주장하는 유효한 π
  const mine = await setRoot([410]);
  const bad = await makeLogin({ disclosure: { mask: 0n, lo: [0n,0n,0n,0n], hi: [0n,0n,0n,0n], set: { sel: 2n, root: mine, index: 0, path: (await setPath([410], 410n)) } } });
  const r = await rpPolicy.verifyLogin(bad);
  assert.equal(r.ok, false); assert.equal(r.reason, 'bad_disclosure');
  // 정책 집합이면 통과한다
  const good = await makeLogin({ disclosure: { mask: 0n, lo: [0n,0n,0n,0n], hi: [0n,0n,0n,0n], set: { sel: 2n, root: policyRoot, index: <410 의 인덱스>, path: (await setPath(members, 410n)) } } });
  assert.equal((await rpPolicy.verifyLogin(good)).ok, true);
  // policySetRoot 를 안 주면 예전처럼 검사하지 않는다(일반 검증기 계약 유지)
  assert.equal((await rp.verifyLogin(bad)).ok, true);
});
```
`makeLogin` 이 집합을 어떻게 받는지는 파일의 기존 V7 케이스(`set_sel/set_root` 테스트)를 그대로 따른다. `lib/mode3_set_tree.js` 의 실제 API(`setRoot`, 경로 만드는 함수) 이름을 확인해 쓴다 — 지어내지 말 것.

- [ ] **Step 2: 실패 확인** — `node tests/test_mode3_rp.mjs`(:8545 필요).

- [ ] **Step 3: 구현** — `lib/mode3_rp.js`:
  - `createRpVerifier` 인자에 `policySetRoot = null` 추가. 타입 검사: `policySetRoot !== null && typeof policySetRoot !== 'bigint'` 면 throw.
  - `setSel > 4n || (setSel === 0n && setRoot !== 0n)` 줄 바로 뒤에:
```js
    // 회로는 "set_root 의 트리에 속한다" 만 증명한다 — **누구 트리인지는 모른다**(2026-09-25 리뷰 I-2).
    // 정책 집합을 아는 서비스는 여기서 못 박는다. 안 하면 자기 국가만 든 집합의 root 로 "허용 집합 소속" 을 주장할 수 있고
    // 세션·로그인 기록·화면이 그것을 보증처럼 싣는다. 온체인 AttrGate 는 이미 setRoot == allowedCountriesRoot 를 요구한다.
    if (policySetRoot !== null && setSel !== 0n && setRoot !== policySetRoot) return { ok: false, reason: 'bad_disclosure' };
```
  - `mode3_rp.js` 의 `createRpVerifier({...})` 호출에 `policySetRoot: ALLOWED_COUNTRIES_ROOT` 를 넘긴다(검증기를 만드는 곳이 한 군데인지 확인).

- [ ] **Step 4: Minor C-4 — 재검증이 세션을 다시 묶는다.** `mode3_rp.js:367-369` 은 `s.root`·`s.disclosure` 만 갱신한다. `s.max_height`·`s.allowAgent` 도 `v` 의 값으로 덮어 세션 상태가 마지막 증명과 어긋나지 않게 한다. 테스트: allowAgent=1 로 로그인한 뒤 allowAgent=0 인 credential 로 재검증하면 `/api/mode3/sessions` 의 그 세션이 0 으로 바뀐다(`tests/test_mode3_e2e.mjs` 또는 `test_mode3_rp.mjs` 중 세션 API 를 쓰는 쪽).

- [ ] **Step 5: Minor C-5 — `/api/mode3/open/:id` fail-closed.** 다른 라우트와 같게 맨 앞에 `if (!verifier) return res.status(503).json({ ok: false, reason: inactiveReason() });` 를 넣는다.

- [ ] **Step 6: 검증** — `node tests/test_mode3_rp.mjs`, `node tests/test_mode3_e2e.mjs`, `node tests/test_mode3_demo_stack.mjs`, `bash scripts/run_tests.sh chain`, `bash scripts/run_tests.sh browser`.
- [ ] **Step 7: Commit** — `fix(mode3): RP — 정책 집합 root 대조(policySetRoot), 재검증이 max_height·allowAgent 를 다시 묶는다, 개봉 조회 fail-closed`

---

### Task 3: 지갑 — 팩토리 상한 검증, 동의 창 위생, 세션 라우트 arid 대조

**Files:** Modify `lib/mode3_onchain.js`, `mode3_wallet_agent.js`, `snap-mode3/src/index.js`(+`dist`·`snap.manifest.json` 재빌드), `mode3/wallet.html`; Test `tests/test_mode3_wallet_agent.mjs`, `snap-mode3/test/rpc.test.mjs`

**Interfaces (Produces):**
```js
// lib/mode3_onchain.js
export const FACTORY_MAX_ROOT_AGE_BAND = { min: 1n, max: 2n * MAX_ROOT_AGE_DEFAULT };    // 1..200 블록
export const FACTORY_MAX_LIFETIME_BAND = { min: 1n, max: 4n * MAX_LIFETIME_DEFAULT };    // 1..1600 블록
```

- [ ] **Step 1: 실패하는 테스트** (`tests/test_mode3_wallet_agent.mjs`) — E-2 공백도 함께 메운다.

```js
await t('I-3/E-2: 팩토리의 log·pk_CIA·pk_trace·maxRootAge·maxLifetime 이 기대와 다르면 409 bad_factory', async () => {
  const signer = await provider.getSigner(0);
  const v = await deployVerifier(signer);
  const base = { verifierAddress: v, arid: BigInt(arid), pkCIA: pk_CIA, pkTrace: pk_trace, logAddress: cia.logAddress };
  const otherLog = (await deployRevocationLog(await signer.getAddress(), provider)).address;   // 서비스가 통제하는 로그
  const cases = [
    ['다른 폐기 로그', { ...base, logAddress: otherLog }],
    ['다른 pk_CIA', { ...base, pkCIA: { x: pk_CIA.x + 1n, y: pk_CIA.y } }],
    ['다른 pk_trace', { ...base, pkTrace: { x: BigInt(pk_trace.x) + 1n, y: BigInt(pk_trace.y) } }],
    ['maxRootAge 상한 밖', { ...base, maxRootAge: 2n ** 40n }],
    ['maxRootAge 0 (계정 영구 동결)', { ...base, maxRootAge: 0n }],
    ['maxLifetime 상한 밖', { ...base, maxLifetime: 2n ** 40n }],
  ];
  for (const [name, opts] of cases) {
    const f = await deployFactory(signer, opts);
    const r = await login(newRs(), { factoryAddress: f });
    assert.equal(r.status, 409, `${name}: ${j(r.body)}`);
    assert.equal(r.body.reason, 'bad_factory', name);
  }
});
```
`deployRevocationLog` import 와 `deployFactory` 의 `maxRootAge: 0n` 허용 여부를 먼저 확인한다(컨트랙트가 0 을 거부하면 그 케이스는 빼고 보고).

- [ ] **Step 2: 실패 확인.**
- [ ] **Step 3: 구현** — `lib/mode3_onchain.js` 에 두 밴드 상수를 추가하고, `mode3_wallet_agent.js` 의 `checkService` 에서:
```js
      const [fa, fl, fx, fy, tx, ty, fra, flt] = await Promise.all([f.arid(), f.log(), f.pkCIAX(), f.pkCIAY(), f.pkTraceX(), f.pkTraceY(), f.maxRootAge(), f.maxLifetime()]);
      if (fa !== BigInt(arid) || fl.toLowerCase() !== LOG_ADDRESS.toLowerCase() || fx !== pk.x || fy !== pk.y || tx !== BigInt(pk_trace.x) || ty !== BigInt(pk_trace.y)) {
        return { status: 409, body: { reason: 'bad_factory' } };
      }
      // 상한 두 개도 본다(2026-09-25 리뷰 I-3): 참조 코드 대조는 immutable 을 0 으로 지우고 비교하므로 이 둘을 못 잡는다.
      // 너무 크면 AA 가 게시를 멈춰도 온체인 실행이 계속되고(폐기 신선도 상실), 0 이면 그 계정의 모든 execute 가 revert 해
      // 이미 넣은 자산이 영구 동결된다(주소가 이 인자들로 결정돼 다른 값으로 재배포할 수 없다).
      if (BigInt(fra) < FACTORY_MAX_ROOT_AGE_BAND.min || BigInt(fra) > FACTORY_MAX_ROOT_AGE_BAND.max) return { status: 409, body: { reason: 'bad_factory', detail: 'maxRootAge out of band' } };
      if (BigInt(flt) < FACTORY_MAX_LIFETIME_BAND.min || BigInt(flt) > FACTORY_MAX_LIFETIME_BAND.max) return { status: 409, body: { reason: 'bad_factory', detail: 'maxLifetime out of band' } };
```

- [ ] **Step 4: Minor D-2 — 동의 창의 `serviceName` 위생.** `snap-mode3/src/index.js` 와 `mode3/wallet.html` 에서 표시 전에 한 줄·최대 48자로 자른다(개행·제어문자 제거). 인증서가 덮는 것은 `origin` 이라는 주석을 남긴다. `snap-mode3/test/rpc.test.mjs` 에 개행이 든 `serviceName` 이 한 줄로 잘리는 케이스를 더한다. Snap 소스를 고쳤으면 `cd snap-mode3 && npm run build` 후 `dist/bundle.js`·`snap.manifest.json` 도 커밋한다.

- [ ] **Step 5: Minor D-4 — 세션 라우트의 arid 대조.** `/wallet/revalidate`·`/wallet/request` 가 `precheck` 과 같은 규칙으로 요청 오리진과 세션의 서비스가 맞는지 본다. 지금은 `loginCors` 가 오리진 하나만 허용해 실현되지 않지만, 서비스를 둘 이상 허용하는 순간 교차 서비스 인증이 된다. 세션에 저장된 `arid`(`s.arid`)와 요청 본문/오리진이 가리키는 서비스가 다르면 404 `no_session`. 테스트 한 건.

- [ ] **Step 6: 검증** — `node tests/test_mode3_wallet_agent.mjs`, `node tests/test_mode3_wallet_snap.mjs`, `cd snap-mode3 && npm test`, `bash scripts/run_tests.sh chain`.
- [ ] **Step 7: Commit** — `fix(mode3): 지갑 — 팩토리 maxRootAge·maxLifetime 밴드 검증, 동의 창 서비스명 위생, 세션 라우트 arid 대조`

---

### Task 4: 컨트랙트 — 마스크 위생, 다이제스트 확장, 낡은 주석

**Files:** Modify `contracts/Mode3Wallet.sol`, `contracts/Mode3WalletFactory.sol`(주석), `lib/mode3_onchain.js`, `mode3_wallet_agent.js`(다이제스트 호출부); Test `test/Mode3Wallet.test.mjs`

**Interfaces (Produces):**
```js
// lib/mode3_onchain.js — 다섯 필드 추가(계약 변경)
payloadDigest({ chainId, wallet, to, value, data, nonce, discMask, discLo, discHi, setSel, setRoot,
                maxHeight, allowAgent, tagC1X, tagC1Y, tagC2 })
```

- [ ] **Step 1: 실패하는 테스트 — E-1(다이제스트가 payload 를 묶는다)** (`test/Mode3Wallet.test.mjs`)

```js
it('E-1: 서명한 payload 와 다른 payload 를 제출하면 BadSignature (다이제스트가 to·value·data 를 덮는다)', async () => {
  const { wallet } = await deployStack(ST);
  const { payload, sig } = await signedPayload(ST, wallet, { to: recipientA, value: 1n, data: '0x1234' });
  for (const tampered of [
    { ...payload, to: ethers.Wallet.createRandom().address },
    { ...payload, value: payload.value + 1n },
    { ...payload, data: payload.data + 'ff' },
  ]) {
    await expect(wallet.execute(tampered, sig, ST.a, ST.b, ST.c, ST.pub)).to.be.revertedWithCustomError(wallet, 'BadSignature');
  }
});
```
`signedPayload` 가 `to`·`value`·`data` 를 받는지 확인하고, 안 받으면 그 헬퍼를 넓힌다(기존 호출부는 기본값으로 그대로 돈다).

- [ ] **Step 2: 실패하는 테스트 — 마스크 위생·다이제스트 확장**

```js
it('I-4: 마스크 비트가 0 인 슬롯의 lo/hi 가 0 이 아니면 BadDisclosure', async () => {
  // mask = 0b0001 인데 슬롯 1 의 hi 에 값을 실은 **유효한** π
  const DS = withInput(await statement({ disclosure: { mask: 0b0001n, lo: [0n, 0n, 0n, 0n], hi: [2007n, 1990n, 0n, 0n] } }));
  const { wallet } = await deployStack(DS);
  const { payload, sig } = await signedPayload(DS, wallet, { discMask: 0b0001n, discLo: [0n,0n,0n,0n], discHi: [2007n, 1990n, 0n, 0n] });
  await expect(wallet.execute(payload, sig, DS.a, DS.b, DS.c, DS.pub)).to.be.revertedWithCustomError(wallet, 'BadDisclosure');
});

it('A-2: 다이제스트가 max_height·allowAgent·태그를 덮는다 — 다른 π 로 바꿔 끼우면 BadSignature', async () => {
  // 같은 지갑·같은 세션키·같은 공개 술어인데 allowAgent 만 다른 두 성명을 만든다.
  const S0 = withInput(await statement({ allowAgent: 0n }));
  const { wallet } = await deployStack(S0);
  const S1 = withInput(await statement({ allowAgent: 1n, session: S0.session }));   // 같은 pk_i
  const { payload, sig } = await signedPayload(S0, wallet);
  await expect(wallet.execute(payload, sig, S1.a, S1.b, S1.c, S1.pub)).to.be.revertedWithCustomError(wallet, 'BadSignature');
});
```
`statement()`·`withInput()`·`deployStack()` 이 `allowAgent` 와 세션키 재사용을 받는지 확인하고, 안 받으면 그 헬퍼를 넓힌다. A-2 케이스를 만들기 어려우면 **더 단순하게**: `signedPayload` 로 σ 를 만든 뒤 `pub` 의 `[5]`(allowAgent)만 바꿔 제출해 `BadSignature` 가 나는지 본다(회로 검증까지 가지 않고 서명에서 먼저 걸린다).

- [ ] **Step 3: 실패 확인** — `bash scripts/run_tests.sh contract`.

- [ ] **Step 4: 구현 — `Mode3Wallet.sol`**
  - `_checkStatement` 끝에 마스크 위생:
```solidity
        // 마스크 비트가 0 인 슬롯의 lo/hi 는 회로가 64비트 범위 말고 아무 제약도 걸지 않는다 — 증명자가 고른 값이다.
        // 꼬리·이벤트를 읽는 대상이 그것을 "AA 가 보증한 공개" 로 오인하지 않도록 여기서 거절한다(2026-09-25 리뷰 I-4).
        // 정직한 지갑은 늘 0 을 보낸다(lib/mode3_wallet.js normalizeDisclosure).
        for (uint256 k = 0; k < 4; k++) {
            if (((pub[14] >> k) & 1) == 0 && (pub[15 + k] != 0 || pub[19 + k] != 0)) revert BadDisclosure();
        }
```
  - 다이제스트에 다섯 필드 추가:
```solidity
        bytes32 payloadHash = keccak256(
            abi.encode(
                block.chainid, address(this), payload.to, payload.value, payload.data, payload.nonce,
                pub[14], [pub[15], pub[16], pub[17], pub[18]], [pub[19], pub[20], pub[21], pub[22]], pub[23], pub[24],
                // 2026-09-25 리뷰 A-2: 릴레이어가 같은 사용자·같은 세션키의 다른 π 로 바꿔 끼워
                // Mode3Auth 가 남기는 만료·에이전트 허용·태그를 어긋나게 하지 못하게 한다.
                pub[3], pub[5], pub[11], pub[12], pub[13]
            )
        );
```
  - 낡은 주석 둘: `Mode3Wallet.sol:8` "공개 입력 14개" → 25개, `Mode3WalletFactory.sol:19` "꼬리 9워드" → 11워드.

- [ ] **Step 5: 구현 — JS 쪽 다이제스트**
```js
export function payloadDigest({ chainId, wallet, to, value, data, nonce, discMask = 0n, discLo = [0n, 0n, 0n, 0n], discHi = [0n, 0n, 0n, 0n], setSel = 0n, setRoot = 0n, maxHeight = 0n, allowAgent = 0n, tagC1X = 0n, tagC1Y = 0n, tagC2 = 0n }) {
  return ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
    ['uint256', 'address', 'address', 'uint256', 'bytes', 'uint256', 'uint256', 'uint256[4]', 'uint256[4]', 'uint256', 'uint256', 'uint256', 'uint256', 'uint256', 'uint256', 'uint256'],
    [chainId, wallet, to, value, data, nonce, discMask, discLo, discHi, setSel, setRoot, maxHeight, allowAgent, tagC1X, tagC1Y, tagC2],
  ));
}
```
호출부(`mode3_wallet_agent.js` 의 tx·tx/prepare 경로, 테스트 헬퍼)가 `pub[3]`·`pub[5]`·`pub[11..13]` 을 넘기게 고친다. **기본값 0 을 두면 안 넘긴 호출부가 조용히 틀린 서명을 만든다** — 그래서 구현 뒤 `grep -n "payloadDigest\|signPayload"` 로 모든 호출부를 확인하고 전부 넘기는지 보고서에 적는다.

- [ ] **Step 6: 검증** — `bash scripts/run_tests.sh contract`, 자기 노드에서 `node tests/test_mode3_wallet_agent.mjs`, `node tests/test_mode3_e2e.mjs`, `node tests/test_mode3_demo_stack.mjs`, `bash scripts/run_tests.sh chain`, `bash scripts/run_tests.sh browser`.
- [ ] **Step 7: Commit** — `fix(mode3): 컨트랙트 — 마스크 밖 슬롯 거절(BadDisclosure), 다이제스트가 만료·에이전트 허용·태그까지 덮는다, 낡은 주석 정정`

---

### Task 5: 테스트 공백 메우기

**Files:** Create `tests/test_mode3_artifacts.mjs`; Modify `tests/test_mode3_session_revoke.mjs`, `tests/test_mode3_rp.mjs`, `test/Mode3Wallet.test.mjs`, `tests/test_mode3_wallet.mjs`, `tests/test_mode3_health.mjs`, `snap-mode3/test/rpc.test.mjs`, `scripts/run_tests.sh`

- [ ] **Step 1: E-3 — 산출물과 회로 소스를 잇는다.** `tests/test_mode3_artifacts.mjs`(CIRCUIT 그룹). `tests/test_pi_cred_witness.mjs` 가 이미 `build/mode3/witness_test/` 에 새로 컴파일하므로 그 `.r1cs` 를 읽어, 배포용 `build/mode3/pi_cred_vkey.json` 의 `nPublic` 과 같은지 본다. 다르면 "회로를 고치고 `bash scripts/build_mode3_circuit.sh` 를 안 돌렸다" 는 메시지로 실패시킨다. `npx snarkjs r1cs info` 를 execFile 로 부르거나 r1cs 헤더를 직접 읽는다(구현자가 고른다).
- [ ] **Step 2: E-6 — 만료 경계.** `head === max_height` 는 유효, `head === max_height + 1` 은 만료. 세 구현에 각각 한 건씩: `test/Mode3Wallet.test.mjs`(`Expired`), `tests/test_mode3_rp.mjs`(`expired`). CIA 쪽은 이미 있다.
- [ ] **Step 3: E-7 — 두 증인의 root 동일성 가드.** `lib/mode3_wallet.js` 의 `w.root !== ws.root` throw 를 덮는다. 트리를 스텁해 두 증인이 다른 root 를 내게 만들고 그 throw 가 나는지 본다(`tests/test_mode3_wallet.mjs`, 체인 불필요하면 unit).
- [ ] **Step 4: E-8 — 교차 계정 세션 폐기.** A 가 (uid=A, Cf_s=B 의 세션) 에 서명해 보내면 404 `unknown_session` 이고 B 의 세션은 그대로다(`tests/test_mode3_session_revoke.mjs`).
- [ ] **Step 5: 부실한 테스트 셋 손보기.**
  - `snap-mode3/test/rpc.test.mjs:54` — 제목이 "모든 RPC" 인데 `getPublicInfo` 하나만 본다. RPC 목록을 돌며 전부 거절되는지 확인하도록 고친다.
  - `tests/test_mode3_health.mjs:13-15` — 키 이름만 본다. 실제 비밀 **값**(등록된 계정의 `uid`, 세션의 `Cf_s` 등 테스트가 아는 값)이 응답 문자열에 없는지도 본다.
  - `tests/test_mode3_wallet_snap.mjs:70` — "팩토리 주소 오류" 가 getter throw 경로만 탄다. T3 가 값 대조 케이스를 추가했으므로 이 테스트의 제목을 실제로 덮는 것에 맞게 고친다.
- [ ] **Step 6: 검증** — `npm test`(unit+circuit), `bash scripts/run_tests.sh contract`·`chain`·`snap`.
- [ ] **Step 7: Commit** — `test(mode3): 리뷰가 짚은 공백 — 산출물·소스 연결, 만료 경계, 두 증인 root 가드, 교차 계정 세션 폐기, 부실 테스트 셋`

---

### Task 6: 문서 — 바뀐 보장과 수용한 한계

**Files:** Modify `docs/MODE3_DEMO.md`, `docs/paper/zkd/security_formal.md`

- [ ] **Step 1: 바뀐 보장.** `security_formal.md` 에 §11(2026-09-25) 을 더한다: (a) 서비스 검증기가 공개 입력을 정규 10진 문자열로만 받는다(C-1, 커밋 25d56fe) — 정책 검사와 Groth16 검증이 같은 값을 본다는 것이 이제 코드로 보장된다. (b) 온체인은 마스크 밖 슬롯이 0 이 아니면 거절한다 — §8(2) 의 "0 인 슬롯은 무제약·lo = hi = 0" 서술을 "회로는 무제약이나 컨트랙트가 0 을 강제한다" 로 정정. (c) σ_tx 다이제스트가 `max_height`·`allowAgent`·태그까지 덮는다(정리 8 의 튜플 갱신). (d) 서비스가 `set_root` 를 정책 집합 root 와 대조한다(§10.4 S11 이 이제 코드와 맞는다). (e) 지갑이 팩토리의 `maxRootAge`·`maxLifetime` 밴드를 검증한다(명제 21 의 W_ref 보완).
- [ ] **Step 2: 수용한 한계.** `MODE3_DEMO.md` 한계 절에 컨트롤러 결정 4 의 일곱 항목을 한 줄씩 적는다(uid 존재 열거, 상태 무한 증가, RPC 장애 10분 캐시, 동의 창의 `data` 미표시, snap 증인 유휴 수명, 지갑 health 를 AA 오리진에 연 것, `countedTxHashes`). 각 줄에 "왜 지금 안 고치는가" 를 함께 적는다.
- [ ] **Step 3: 전체 검증.** `npm test`, `bash scripts/run_tests.sh contract`·`chain`·`snap`·`browser` 를 한 번씩. 실패는 그대로 보고한다. 포트 정리 확인.
- [ ] **Step 4: Commit** — `docs(mode3): 2026-09-25 리뷰 반영 — 바뀐 보장(§11), 수용한 한계 목록`

---

## Self-Review

**리뷰 지적 대응** — Critical C-1: 이미 `25d56fe`. Important: I-1 → T1 Step 1-3, I-2 → T2 Step 1-3, I-3 → T3 Step 1-3, I-4 → T4 Step 2·4, E-1 → T4 Step 1, E-2 → T3 Step 1, E-3 → T5 Step 1. Minor 중 고치는 것: B-4/B-5/B-6 → T1 Step 4-6, C-4/C-5 → T2 Step 4-5, D-2/D-4 → T3 Step 4-5, A-2 → T4 Step 2·4·5, 낡은 주석 → T4 Step 4, E-6/E-7/E-8·부실 테스트 → T5. 문서로 남기는 일곱 → T6 Step 2.

**Placeholder scan** — T2 Step 1 의 `<410 의 인덱스>` 와 `setPath` 는 `lib/mode3_set_tree.js` 의 실제 API 를 확인해 채우라는 지시다(지어내지 말 것을 명시). T1 Step 1 은 확률적 재현이라 "지연을 넣어 한 번 확인" 절차를 명시했다. 그 밖에 TBD 없음.

**Type consistency** — `policySetRoot: bigint|null` 을 T2 정의·`mode3_rp.js` 호출·테스트가 공유. `FACTORY_MAX_ROOT_AGE_BAND`/`FACTORY_MAX_LIFETIME_BAND` 를 T3 정의·`checkService`·테스트가 공유. `payloadDigest` 의 다섯 새 필드 이름(`maxHeight, allowAgent, tagC1X, tagC1Y, tagC2`)을 T4 정의·호출부·컨트랙트 인코딩 순서(`pub[3], pub[5], pub[11], pub[12], pub[13]`)가 같은 순서로 쓴다. `bad_disclosure`·`bad_factory`·`unknown_session` 사유 문자열은 기존 값을 그대로 쓴다.
