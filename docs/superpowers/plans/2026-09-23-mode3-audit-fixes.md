# Mode 3 전체 점검 수정 묶음 구현 계획

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 2026-09-23 Mode 3 전체 코드 점검의 Important 8건 + 주목 Minor 3건 + RCL 증분 동기화 최종 리뷰 잔여 3건(N1·N2·N4)을 한 묶음으로 고친다.

**Architecture:** 서브시스템별로 4개 태스크(CIA / RP / 지갑 / 문서·테스트 인프라). 회로·컨트랙트는 바뀌지 않는다. 각 수정은 발견의 실패 시나리오를 그대로 재현하는 테스트를 먼저 붙이고 고친다.

**Tech Stack:** Node 22 ESM, express, ethers v6, snarkjs, circomlibjs, hardhat :8545(테스트), Playwright(browser 그룹).

**Spec:** `docs/audits/2026-09-23-mode3/SUMMARY.md` (Important 표·결정 절) — 상세 근거는 같은 디렉터리의 `A-cia.md`, `B-wallet.md`, `C-rp-circuit.md`, `D-contracts.md`. RCL 잔여 3건의 근거는 이미 지워진 SDD 원장 대신 이 계획 Task 3·4 본문에 적었다.

## Global Constraints

- 회로(`circuits/`)·컨트랙트(`contracts/`)·`snap-mode3/src/crypto.js` 는 바꾸지 않는다. `npm run zk:*` 금지.
- CIA 상태 파일(`cia_state.json`)·지갑 상태 파일(`mode3_wallet_state.json`)·RP 등록 파일의 **형식·버전은 그대로**. 상태·키 파일(`*_state.json`, `*_keys.json`, `.env`, `mode3_rp_registration.json`, `*.jsonl`)은 읽거나 지우지 않는다.
- **C-1 정책(결정)**: RP 오프체인 로그인은 `RevocationLog.lastPublishedBlock` 기준 root 나이가 `MODE3_MAX_ROOT_AGE`(기본 100블록, 컨트랙트 `maxRootAge` 와 같은 값)를 넘으면 `root_too_old` 로 거절한다(fail-closed). 검사 순서는 온체인 §5.3 과 같이 `stale_root`(b) 바로 뒤.
- 기존 오류 코드·응답 형식은 유지하고 새 사유만 추가한다: RP `root_too_old`, 지갑 `allow_agent_mismatch`(409), CIA `attrs 는 길이 4 배열` (400).
- 데모 계정(`testuser/password123` uid 12345 `[1990,410,2,0]`, `alice/alicepw` uid 67890 `[2005,840,1,0]`)·무인증 개봉 조회·릴레이어 등 문서에 "한계"로 적힌 데모 동작은 건드리지 않는다.
- 새 테스트는 기존 파일의 그룹을 따른다(`test_cia_*`·`test_mode3_rp/wallet/wallet_agent/rcl_sync` = chain, `test_mode3_browser` = browser, `test_mode3_*.js` 단위 = unit). 새 파일을 만들면 `scripts/run_tests.sh` 에 등록한다. hardhat :8545 는 세션이 띄운 것을 쓰고 끄지 않는다. 개발 서버(:4100/:5100/:3100)는 건드리지 않는다.
- 모든 주석·문서·커밋 메시지 한글. 커밋 트레일러 2줄: `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>`, `Claude-Session: https://claude.ai/code/session_013qGSXZTftBJSB1M4XpPRHN`.
- `CLAUDE.md` 는 사용자 파일이라 수정하지 않는다(D-I3 의 CLAUDE.md 쪽 문장은 보고서에 제안만).

---

## 파일 구조

| 파일 | 변경 | Task |
|---|---|---|
| `cia.js` | 개봉 dup 키에 `c2`·`PPID`(A-I1); `/cia/accounts/:uid/attrs` 길이 4 배열 필수(A-I2) | 1 |
| `lib/mode3_wallet.js` | `buildCredentialProof` 에 테스트용 `tagR` 옵션(태그 난수 주입, A-I1 음성 테스트용); `ProofCache.deleteSession(sessionId)` | 1, 3 |
| `tests/test_cia_opening.mjs`, `tests/test_cia_register_issue.mjs` | A-I1·A-I2 회귀 | 1 |
| `lib/mode3_rp.js` | `createRpVerifier({ …, maxRootAge })`, `chainView` 가 `lastPublishedBlock` 도 읽음, `root_too_old`(C-1); `maskDisclosure()` 내보내고 `verifyLogin` 이 적용(C-2) | 2 |
| `mode3_rp.js` | `MAX_ROOT_AGE` 를 검증기에 전달; `ensureFactory` 가 기존 팩토리의 `maxRootAge`·`maxLifetime` 을 읽어 env 와 대조 → 온체인 값을 채택하고 경고(D-I2) | 2 |
| `tests/test_mode3_rp.mjs` | C-1·C-2 회귀 | 2 |
| `mode3_wallet_agent.js` | precheck 가 재승인 시 세션의 `allowAgent` 반환, `/wallet/session/witness` 가 `allowAgent` 대조(B-I1); `pruneSessions` 가 캐시도 비움(M-1); 정규식 `/is a member/`(N1); `buildExecute` 반환의 `synced` 제거(N4) | 3 |
| `mode3/wallet.html` | 재승인 시 precheck 가 준 `sessionAllowAgent` 로 동의 창(B-I1); 등록 직후 Snap 저장 실패 안내(복구 창) | 3 |
| `tests/test_mode3_wallet_agent.mjs`, `tests/test_mode3_wallet.mjs`, `tests/test_mode3_browser.mjs` | B-I1·M-1 회귀 | 3 |
| `docs/MODE3_DEMO.md` | D-I1 주소 변경 경고, D-I3 contract 그룹 전제, publish 지침 모순, 등록 복구 창, `root_too_old` 운영 메모 | 4 |
| `scripts/run_tests.sh` | contract 그룹 주석에 zkey 전제 | 4 |
| `tests/test_mode3_rcl_sync.mjs` | 테스트 9 관측 단언 강화(N2) | 4 |
| `docs/audits/2026-09-23-mode3/SUMMARY.md` | 처리 결과 절 | 4 |

---

### Task 1: CIA — 개봉 중복 판정 키(A-I1)와 관리자 속성 변경 입력 검사(A-I2)

**Files:**
- Modify: `cia.js:633`(dup 판정), `cia.js:420-432`(`/cia/accounts/:uid/attrs`)
- Modify: `lib/mode3_wallet.js:160-190`(`buildCredentialProof` 에 `tagR` 옵션)
- Test: `tests/test_cia_opening.mjs`, `tests/test_cia_register_issue.mjs:553-559`

**Interfaces:**
- Consumes: `encryptTag(pk_trace, uid, arid, r = randomTraceScalar())` (`lib/mode3_trace.js:133`) — 이미 `r` 주입을 받는다.
- Produces: `buildCredentialProof({ …, tagR = undefined })` — `tagR` 이 있으면 `encryptTag(pk_trace, uid, arid, tagR)`. 기본 동작 불변. **테스트 전용 옵션**(주석으로 명시).

배경(A-I1): `cia.js:633` 의 dup 판정 `o.arid === arid && o.c1.x === c1x && o.c1.y === c1y` 는 `c2`·`PPID` 를 보지 않는다. 태그 `c1 = r·G` 는 사용자와 무관하므로, 두 사용자가 같은 `r` 을 쓰면(지갑 난수 재사용·버그) 같은 서비스의 두 트랜스크립트가 같은 키가 되고, 뒤 요청이 앞 사용자의 승인 항목 id 를 받아 `/cia/open/:id` 로 **다른 사용자의 uid** 를 얻는다.
배경(A-I2): `normalizeAttrs(undefined)` 는 `[0,0,0,0]` 을 돌려주므로 본문 없는 관리자 호출 한 번에 속성 4칸이 0 이 되고, `retireActiveCred` 가 옛 C_u 리프를 append-only 트리에 넣어 되돌릴 수 없다.

- [ ] **Step 1: 실패하는 테스트 — 같은 c1·다른 사용자는 새 개봉 항목**

`tests/test_cia_opening.mjs` 의 "같은 (arid, c1) 재요청은 새 id 를 만들지 않는다" 테스트(`:88`) 바로 뒤에 추가. 이 파일은 `uid=12345n`(testuser) 하나만 등록한다(`:13-20`). alice(uid 67890, pwd `alicepw`, attrs `[2005n, 840n, 1n, 0n]`)를 같은 방식으로 등록·C_u 발급·세션 발급하고, **같은 태그 난수** 로 두 트랜스크립트를 만든다. `loginTranscript`(`:22-30`) 를 복사해 `uid`·`reg`·`uc`·`attrs`·`tagR` 을 인자로 받는 `loginTranscriptFor` 를 만든다(기존 헬퍼는 손대지 않는다):

```js
  // A-I1 회귀: dup 키가 (arid, c1) 뿐이면 같은 r 로 만든 다른 사용자의 트랜스크립트가 앞 항목 id 를 받는다
  const regA = await createRegistration();
  const skA = ethers.Wallet.createRandom().privateKey;   // 파일이 sk_u 를 만드는 방식을 그대로 따른다(:11-13 참고)
  assert.equal((await cia.post('/cia/register', { uid: '67890', pwd: 'alicepw', cm_u: { x: regA.cm_u.x.toString(), y: regA.cm_u.y.toString() } })).status, 201);
  const ucA = await buildUserCredRequest({ uid: 67890n, s_u: regA.s_u, r_u: regA.r_u, sk_u: skA, attrs: [2005n, 840n, 1n, 0n] });
  assert.equal((await cia.post('/cia/user_cred', ucA.body)).status, 200);
  async function loginTranscriptFor(svc, who, tagR) {   // who = { uid, reg, uc, attrs, sk_u }
    const session = await createSessionKey();
    const max_height = BigInt(await provider.getBlockNumber()) + 300n;
    const req = await buildIssueRequest({ uid: who.uid, Cf_u: who.uc.Cf_u, arid: BigInt(svc.arid), sk_u: who.sk_u, session, chainid: 31337n, allowAgent: 0n, max_height });
    const issued = await cia.post('/cia/issue', req.body);
    assert.equal(issued.status, 200, JSON.stringify(issued.body));
    const { tree } = await syncRevocationTree(provider, cia.logAddress);
    const { proof, publicSignals, tag } = await buildCredentialProof({ uid: who.uid, arid: BigInt(svc.arid), s_u: who.reg.s_u, blind_u: who.uc.secrets.blind_u, blind_s: req.secrets.blind_s, pk_i: session.pk_i, attrs: who.attrs, credential: issued.body, pk_CIA, pk_trace: svc.pk_trace, tree, tagR });
    return { proof, publicSignals, tag, PPID: publicSignals[0] };
  }
  await t('A-I1: 같은 c1(같은 태그 난수)·다른 사용자의 개봉 요청은 앞 항목 id 를 받지 않는다', async () => {
    const r = 123456789n;
    const T1 = await loginTranscriptFor(S1, { uid, reg, uc, attrs: [1990n, 410n, 2n, 0n], sk_u }, r);
    const T2 = await loginTranscriptFor(S1, { uid: 67890n, reg: regA, uc: ucA, attrs: [2005n, 840n, 1n, 0n], sk_u: skA }, r);
    assert.equal(T1.tag.c1.x, T2.tag.c1.x, '같은 r → 같은 c1');
    assert.notEqual(T1.PPID, T2.PPID);
    const o1 = await openRequest(S1, T1); assert.equal(o1.status, 202);
    const o2 = await openRequest(S1, T2); assert.equal(o2.status, 202, JSON.stringify(o2.body));
    assert.notEqual(o1.body.id, o2.body.id, '다른 사용자의 트랜스크립트는 새 항목이어야 한다');
  });
```

`loginTranscript` 의 `max_height` 계산·`sk_u` 생성 방식은 파일의 기존 코드(`:11-13`, `:22-30`)를 읽고 그대로 맞춘다(위 코드의 해당 줄은 그 형태를 가정한 것이다 — 이름이 다르면 파일 쪽을 따른다).

- [ ] **Step 2: 실패 확인**

Run: `node tests/test_cia_opening.mjs 2>&1 | grep -A3 "A-I1"`
Expected: `FAIL … 다른 사용자의 트랜스크립트는 새 항목이어야 한다`(o2 가 200 + o1.id 를 돌려준다). 그 전에 `buildCredentialProof` 가 `tagR` 을 모르면 두 트랜스크립트의 c1 이 달라 첫 단언에서 FAIL — Step 3 의 `tagR` 옵션을 먼저 넣고 다시 확인한다.

- [ ] **Step 3: 구현**

`lib/mode3_wallet.js` `buildCredentialProof` 시그니처에 `tagR = undefined` 를 추가하고 `:176` 을:

```js
  // tagR 은 테스트 전용 — 태그 난수를 주입해 같은 c1 을 가진 트랜스크립트를 만든다(CIA 개봉 dup 키 회귀). 운영 경로는 넘기지 않는다.
  const tag = tagR === undefined ? await encryptTag(pk_trace, uid, arid) : await encryptTag(pk_trace, uid, arid, tagR);
```

`cia.js:633` dup 판정을:

```js
    // dup 키는 (arid, c1, c2, PPID) — c1 = r·G 는 사용자와 무관해 두 사용자가 같은 r 을 쓰면 겹친다(2026-09-23 점검 A-I1).
    // c2·PPID 까지 같아야 "같은 트랜스크립트"다.
    const dup = state.openings.find((o) => o.arid === arid && o.c1.x === c1x && o.c1.y === c1y && o.c2 === c2 && o.PPID === PPID
      && (o.status === 'pending' || (o.status === 'approved' && o.resolved !== false)));
```

`c2`·`PPID` 가 이 스코프에서 정규화된 10진 문자열인지(`:636` 의 push 에 쓰는 것과 같은 변수) 확인해 같은 값을 비교한다.

- [ ] **Step 4: 통과 확인**

Run: `node tests/test_cia_opening.mjs`
Expected: 새 케이스 포함 전부 `ok`(기존 "같은 (arid, c1) 재요청 → 같은 id" 도 그대로 — 같은 트랜스크립트는 c2·PPID 도 같다).

- [ ] **Step 5: 실패하는 테스트 — 본문 없는 속성 변경은 400**

`tests/test_cia_register_issue.mjs:553-559` 의 속성 변경 테스트에 추가:

```js
    // A-I2: 본문이 없거나 짧으면 0 패딩으로 속성이 지워지고 옛 C_u 리프가 되돌릴 수 없게 게시된다 → 길이 4 배열만 받는다
    assert.equal((await cia.adminPost('/cia/accounts/12345/attrs', {})).status, 400);
    assert.equal((await cia.adminPost('/cia/accounts/12345/attrs', { attrs: ['1990', '410'] })).status, 400);
    assert.equal((await cia.adminPost('/cia/accounts/12345/attrs', { attrs: 'x' })).status, 400);
```

Run: `node tests/test_cia_register_issue.mjs 2>&1 | grep -B1 -A3 "attrs"` → Expected: 첫 단언 FAIL(200).

- [ ] **Step 6: 구현**

`cia.js` `/cia/accounts/:uid/attrs`:

```js
    // 관리자 변경은 길이 4 배열만 받는다 — normalizeAttrs 의 0 패딩(발급 경로엔 필요)이 여기서는 "본문 없는 호출 한 번에
    // 속성 4칸이 0" 이 되고 옛 C_u 리프가 append-only 트리에 들어가 되돌릴 수 없다(2026-09-23 점검 A-I2).
    const raw = req.body?.attrs;
    if (!Array.isArray(raw) || raw.length !== ATTR_SLOTS) return res.status(400).json({ error: `attrs 는 길이 ${ATTR_SLOTS} 배열이어야 한다` });
    let attrs;
    try { attrs = normalizeAttrs(raw).map(String); } catch (e) { return res.status(400).json({ error: `attrs: ${e.message}` }); }
```

`ATTR_SLOTS` 가 `lib/mode3_credential.js` 에서 export 되는지 확인하고 import 에 추가(안 되면 `4` 리터럴 대신 export 를 추가한다 — 시그니처 변경 아님).

- [ ] **Step 7: 통과 확인·기존 회귀**

Run: `node tests/test_cia_register_issue.mjs && node tests/test_mode3_demo_stack.mjs`
Expected: 전부 통과(데모 스택 시나리오 12 는 길이 4 배열을 보낸다 — `:333`).

- [ ] **Step 8: 커밋**

```bash
git add cia.js lib/mode3_wallet.js tests/test_cia_opening.mjs tests/test_cia_register_issue.mjs
git commit -m "fix(cia): 개봉 dup 키에 c2·PPID(같은 r 의 다른 사용자 오귀속 차단), 관리자 속성 변경은 길이 4 배열만 (점검 A-I1·A-I2)"
```

---

### Task 2: RP — root 나이 fail-closed(C-1), 공개값 mask 필터(C-2), 팩토리 상수 대조(D-I2)

**Files:**
- Modify: `lib/mode3_rp.js:19-60`(`createRpVerifier` 옵션·`refreshChainView`·`verifyLogin` 검사 b′), `lib/mode3_rp.js` 끝(`maskDisclosure` export)
- Modify: `mode3_rp.js:119-131`(`ensureFactory`), `:140-146`(`activate`), `:240`(`discOf` 가 마스킹된 값을 받도록)
- Test: `tests/test_mode3_rp.mjs`

**Interfaces:**
- Produces: `createRpVerifier({ …, maxRootAge = 100n })` — bigint. `verifyLogin` 새 거절 사유 `root_too_old`. `verifyLogin` 이 돌려주는 `disclosure` 는 **mask 비트가 0 인 슬롯의 lo/hi 가 0n** 으로 정규화됨. `export function maskDisclosure({ mask, lo, hi })` → `{ mask, lo: bigint[4], hi: bigint[4] }`.
- Consumes: `LOG_ABI` 의 `lastPublishedBlock() view returns (uint64)` (`lib/mode3_log.js`), `FACTORY_ABI` 의 `maxRootAge()`·`maxLifetime()` (`lib/mode3_onchain.js:50-51`).

배경(C-1): 온체인 `Mode3Wallet.execute` 는 `head - log.lastPublishedBlock() > maxRootAge` 면 `RootTooOld` 로 멈추는데(하트비트가 생존 신호), 오프체인 `verifyLogin` 은 `lastPublishedBlock` 을 읽지 않아 CIA 게시가 멈춘 뒤에도 무한히 통과한다. 결정: 같은 상한으로 fail-closed.
배경(C-2): 회로는 mask 비트 0 인 슬롯의 `disc_lo/hi` 에 64비트 범위 말고 제약을 두지 않는다. RP 가 9워드를 그대로 세션·로그·`/api/mode3/sessions`·화면에 실으면 "검증 안 된 슬롯이 공개된 것"처럼 보인다.
배경(D-I2): `ensureFactory` 는 `factoryAddress` 가 있으면 조기 리턴하므로 팩토리 배포 뒤 `MODE3_MAX_LIFETIME_BLOCKS`/`MODE3_MAX_ROOT_AGE` 를 바꾸면 온체인 immutable 과 오프체인 검증기가 갈라진다.

- [ ] **Step 1: 실패하는 테스트 — 게시가 멈추면 root_too_old**

`tests/test_mode3_rp.mjs` 의 "음성 b: 폐기 게시 후 옛 root 의 π 는 stale_root"(`:183`) 뒤에 추가. 이 파일은 `deployRevocationLog` 로 자기 로그를 배포하고 `createRpVerifier` 를 직접 만든다(`:8, :12`). `mineBlocks(n, provider)` 는 `tests/helpers/mode3_chain.mjs:43` 에 있다(이 파일은 아직 import 하지 않으므로 `:8` 의 import 에 추가).

```js
await t('음성 b′(C-1): 마지막 게시가 maxRootAge 블록보다 오래되면 root_too_old (온체인 RootTooOld 와 같은 상한, fail-closed)', async () => {
  const short = createRpVerifier({ provider, logAddress, vkey, pkCIA, arid, chainId: 31337n, pkTrace, maxLifetimeBlocks: 400n, maxRootAge: 5n });
  const T = await freshLogin();                    // 파일의 기존 "양성" 케이스가 쓰는 트랜스크립트 생성 헬퍼 이름으로 맞춘다
  const ok = await short.verifyLogin(T);
  assert.equal(ok.ok, true, JSON.stringify(ok));
  await mineBlocks(6, provider);                   // 게시 없이 6블록 → 나이 > 5
  const r = await short.verifyLogin({ ...T, sig: await signChallenge(T.sessionWallet, T.r_s) });   // 새 σ(파일 관례대로)
  assert.equal(r.ok, false); assert.equal(r.reason, 'root_too_old');
  // 하트비트(같은 root, 새 epoch)를 게시하면 다시 통과한다
  await publishHeartbeat();                        // 파일의 게시 헬퍼로 leaves=[] 게시
  const again = await short.verifyLogin({ ...T, sig: await signChallenge(T.sessionWallet, T.r_s) });
  assert.equal(again.ok, true, JSON.stringify(again));
});
```

`freshLogin`·`publishHeartbeat`·`signChallenge` 사용법은 파일의 기존 케이스(`:67, :156, :183`)가 트랜스크립트와 게시를 만드는 코드를 읽고 그 이름·형태에 맞춘다(같은 `r_s` 로 σ 를 다시 만드는 방식은 `:98-110` 케이스 참고). 기존 검증기(`maxRootAge` 미지정, 기본 100)로 돌아가는 케이스들은 이 테스트 뒤에도 그대로 통과해야 한다 — 파일의 앞 케이스들이 100블록 넘게 채굴하지 않는지 확인하고, 넘는다면 그 케이스 앞에 하트비트 게시를 넣는다.

- [ ] **Step 2: 실패 확인**

Run: `node tests/test_mode3_rp.mjs 2>&1 | grep -A3 "C-1"`
Expected: `FAIL`(`r.ok === true` — 지금은 나이를 안 본다).

- [ ] **Step 3: 구현 (C-1)**

`lib/mode3_rp.js`:

```js
export function createRpVerifier({ provider, logAddress, vkey, pkCIA, arid, chainId, pkTrace, headMaxAgeMs = 10 * 60_000, maxLifetimeBlocks = 400n, maxRootAge = 100n, now = Date.now }) {
  if (typeof maxRootAge !== 'bigint' || maxRootAge <= 0n) throw new Error('createRpVerifier: maxRootAge(bigint > 0) 가 필요하다 — 컨트랙트 maxRootAge 와 같은 값(2026-09-23 점검 C-1)');
  …
  let view = null;   // { root, head, lastPublishedBlock, readAt }
  async function refreshChainView() {
    const head = BigInt(await provider.getBlockNumber());
    const blockTag = Number(head);
    const [root, lastPublishedBlock] = await Promise.all([log.root({ blockTag }), log.lastPublishedBlock({ blockTag })]);
    view = { root: BigInt(root), head, lastPublishedBlock: BigInt(lastPublishedBlock), readAt: now() };
    return view;
  }
```

`verifyLogin` 의 b 뒤에:

```js
    if (revRoot !== v.root) return { ok: false, reason: 'stale_root' };       // b
    // b′ — root 게시 나이(2026-09-23 점검 C-1). 온체인 execute 의 RootTooOld 와 같은 상한. CIA 가 게시(하트비트)를
    // 멈추면 오프체인 로그인도 같이 멈춘다 — 폐기가 체인에 못 오르는 동안 로그인이 계속되는 것을 막는다.
    if (v.head - v.lastPublishedBlock > maxRootAge) return { ok: false, reason: 'root_too_old' };
```

파일 머리 주석의 검사 목록(`:3-16`)에 `b′` 한 줄을 넣는다. `mode3_rp.js:140` `activate()` 의 `createRpVerifier(...)` 에 `maxRootAge: MAX_ROOT_AGE` 를 넘긴다.

- [ ] **Step 4: 통과 확인**

Run: `node tests/test_mode3_rp.mjs`
Expected: 전부 `ok`.

- [ ] **Step 5: 실패하는 테스트 — maskDisclosure**

같은 파일 끝쪽(단위 케이스 자리)에:

```js
await t('C-2: maskDisclosure 는 mask 비트가 0 인 슬롯의 lo/hi 를 0 으로 지운다 (회로가 그 슬롯을 검증하지 않으므로 기록·표시하면 안 된다)', () => {
  const d = maskDisclosure({ mask: 1n, lo: [0n, 410n, 7n, 0n], hi: [2007n, 410n, 9n, 0n] });
  assert.deepEqual(d.lo, [0n, 0n, 0n, 0n]); assert.deepEqual(d.hi, [2007n, 0n, 0n, 0n]); assert.equal(d.mask, 1n);
  const e = maskDisclosure({ mask: 10n, lo: [1n, 2n, 3n, 4n], hi: [5n, 6n, 7n, 8n] });   // 비트 1·3
  assert.deepEqual(e.lo, [0n, 2n, 0n, 4n]); assert.deepEqual(e.hi, [0n, 6n, 0n, 8n]);
});
```

import 에 `maskDisclosure` 추가. Run → Expected: import 오류로 FAIL.

- [ ] **Step 6: 구현 (C-2)**

`lib/mode3_rp.js`:

```js
/** mask 비트가 0 인 슬롯의 lo/hi 를 0 으로 지운다. 회로는 그 슬롯의 disc_lo/hi 에 64비트 범위 말고 아무 제약도 걸지 않으므로
 *  (2026-09-22 §4.3), 그 값을 세션·로그·화면에 실으면 "AA 가 보증한 공개"처럼 읽힌다(2026-09-23 점검 C-2). */
export function maskDisclosure({ mask, lo, hi }) {
  const m = BigInt(mask);
  const keep = (arr) => arr.map((v, k) => ((m >> BigInt(k)) & 1n) === 1n ? BigInt(v) : 0n);
  return { mask: m, lo: keep(lo), hi: keep(hi) };
}
```

`verifyLogin` 의 `const disclosure = { mask: discMask, lo: …, hi: … }` 를 `const disclosure = maskDisclosure({ mask: discMask, lo: rest.slice(0, 4), hi: rest.slice(4, 8) });` 로. `mode3_rp.js` 는 `v.disclosure` 를 그대로 쓰므로(`:240 discOf(v.disclosure)`) 세션·로그·API·화면이 함께 정리된다. 로그인 로그의 `publicSignals` 는 원문 그대로 남긴다(개봉 재료 — 정규형 문자열이어야 한다, `:60-62` 주석).

- [ ] **Step 7: D-I2 — 기존 팩토리의 상수 대조**

`mode3_rp.js` `ensureFactory`:

```js
async function ensureFactory() {
  if (process.env.MODE3_RP_FACTORY_ADDRESS) { reg.factoryAddress = ethers.getAddress(process.env.MODE3_RP_FACTORY_ADDRESS); return adoptFactoryConstants(); }
  if (reg.factoryAddress) return adoptFactoryConstants();
  …(기존 배포 코드)…
}
// 팩토리가 이미 있으면 그 immutable(maxRootAge·maxLifetime)이 진실이다 — env 를 나중에 바꿔도 온체인은 안 바뀌므로
// 오프체인 검증기는 온체인 값을 채택하고 경고한다(2026-09-23 점검 D-I2). 바꾸려면 팩토리를 재배포한다(문서 "처음 한 번" 6).
let EFFECTIVE_MAX_ROOT_AGE = MAX_ROOT_AGE, EFFECTIVE_MAX_LIFETIME = MAX_LIFETIME;
async function adoptFactoryConstants() {
  const f = new ethers.Contract(reg.factoryAddress, FACTORY_ABI, provider);
  const [ra, ml] = await Promise.all([f.maxRootAge(), f.maxLifetime()]);
  EFFECTIVE_MAX_ROOT_AGE = BigInt(ra); EFFECTIVE_MAX_LIFETIME = BigInt(ml);
  if (EFFECTIVE_MAX_ROOT_AGE !== MAX_ROOT_AGE || EFFECTIVE_MAX_LIFETIME !== MAX_LIFETIME) {
    console.warn(`[rp] 팩토리 ${reg.factoryAddress} 의 maxRootAge=${EFFECTIVE_MAX_ROOT_AGE}·maxLifetime=${EFFECTIVE_MAX_LIFETIME} 가 env(${MAX_ROOT_AGE}·${MAX_LIFETIME})와 다르다 — 온체인 값을 쓴다. 바꾸려면 팩토리를 재배포한다`);
  }
}
```

`activate()` 에서 `ensureFactory()` 를 **먼저** 돌린 뒤 `createRpVerifier({ …, maxLifetimeBlocks: EFFECTIVE_MAX_LIFETIME, maxRootAge: EFFECTIVE_MAX_ROOT_AGE })` 를 만든다(지금은 검증기를 먼저 만든다 — 순서를 바꾼다. 팩토리 배포 실패 시엔 env 값으로 검증기를 만들고 경고는 그대로). `FACTORY_ABI` import 를 `lib/mode3_onchain.js` 에서 추가.

테스트(`tests/test_mode3_wallet_agent.mjs` 나 `test_mode3_demo_stack.mjs` 중 RP 를 띄우는 쪽, 격리 스택 `rpEnv` 로 팩토리 배포 → `stack.restartRp` 가 없으면 이 케이스는 **RP 로그 문자열 검사**로 대신한다): 팩토리가 이미 있는 등록 파일로 RP 를 `MODE3_MAX_LIFETIME_BLOCKS=399` 로 띄우면 로그에 `온체인 값을 쓴다` 가 찍히고 `/api/mode3/rp_info`(또는 검증 동작)가 400 기준으로 동작한다. 격리 스택 헬퍼에 RP 재시작이 없으면 `startIsolatedMode3Stack` 을 두 번(같은 `dir` 의 등록 파일을 `rpEnv.MODE3_RP_REGISTRATION_FILE` 로 넘겨) 띄우는 방식으로 한다 — 어렵다면 그 사실을 보고서에 적고 로그 검사 없이 `adoptFactoryConstants` 를 `node -e` 로 직접 불러 확인한 결과를 남긴다.

- [ ] **Step 8: 통과 확인·회귀**

Run: `node tests/test_mode3_rp.mjs && node tests/test_mode3_e2e.mjs && node tests/test_mode3_demo_stack.mjs`
Expected: 전부 통과. 데모 스택의 선택 공개 시나리오(mask=3)는 마스킹 뒤에도 같은 값(두 슬롯 모두 켜져 있음).

- [ ] **Step 9: 커밋**

```bash
git add lib/mode3_rp.js mode3_rp.js tests/test_mode3_rp.mjs tests/test_mode3_demo_stack.mjs tests/test_mode3_wallet_agent.mjs
git commit -m "fix(rp): root 게시 나이 fail-closed(root_too_old, 점검 C-1), 공개값 mask 필터(C-2), 기존 팩토리의 maxRootAge·maxLifetime 채택(D-I2)"
```

---

### Task 3: 지갑 — 재승인 allowAgent 바인딩(B-I1), 세션 정리 시 캐시(M-1), 잔여 N1·N4, 등록 복구 안내

**Files:**
- Modify: `mode3_wallet_agent.js`(`/wallet/authorize/precheck`, `/wallet/session/witness:398-420`, `pruneSessions:78-82`, `:451` 정규식, `:615` 반환)
- Modify: `lib/mode3_wallet.js:196-204`(`ProofCache.deleteSession`)
- Modify: `mode3/wallet.html:185-205`(재승인 분기), `:300-320`(등록 실패 안내)
- Test: `tests/test_mode3_wallet_agent.mjs`, `tests/test_mode3_wallet.mjs`(ProofCache), `tests/test_mode3_browser.mjs`

**Interfaces:**
- Produces: `POST /wallet/authorize/precheck` 본문에 선택 `r_s` — 있으면 그 세션의 `allowAgent`('0'|'1') 를 `sessionAllowAgent` 로 돌려주고, 세션이 없으면 `404 { reason: 'no_session' }`. `POST /wallet/session/witness` 본문에 선택 `allowAgent` — 있고 세션 값과 다르면 `409 { reason: 'allow_agent_mismatch' }`. `ProofCache.deleteSession(sessionId)`.

배경(B-I1): 재승인 팝업의 Snap 동의 창 문구 `AI 에이전트 허용: 예/아니오` 는 RP 가 보낸 `req.allowAgent` 로 만들어지고, 지갑은 그 값이 `r_s` 세션의 실제 `allowAgent` 와 같은지 확인하지 않는다. RP 쪽은 지난 SDD 에서 세션 값을 기억해 보내도록 고쳤지만, 지갑이 RP 를 믿는 구조 자체가 남아 있다(악의적·버그 있는 RP 가 '0' 으로 재승인시키면 사용자는 "아니오"를 읽고 승인, 세션은 '1' 그대로).
배경(M-1): `pruneSessions` 가 만료 세션을 지우면서 `ProofCache` 항목은 두므로, 같은 `r_s` 로 다시 로그인하면 옛 π 가 히트한다(폐기 우회는 아님 — root 가 바뀌면 미스).

- [ ] **Step 1: 실패하는 테스트 — 지갑이 세션 allowAgent 를 돌려주고 불일치를 거절**

`tests/test_mode3_wallet_agent.mjs` 의 snap 모드 케이스가 있는 `tests/test_mode3_wallet_snap.mjs` 쪽이 `/wallet/session/witness` 를 부른다(재시작 뒤 needs_consent 시나리오). 그 파일에서 `allowAgent:'1'` 로 만든 세션에 대해:

```js
await t('B-I1: precheck(r_s) 가 세션의 allowAgent 를 돌려주고, session/witness 는 다른 allowAgent 를 409 로 거절한다', async () => {
  const pre = await wallet.post('/wallet/authorize/precheck', { arid, origin, cert_s, pk_trace, r_s: rs1 });     // rs1: allowAgent '1' 세션
  assert.equal(pre.status, 200, j(pre.body)); assert.equal(pre.body.sessionAllowAgent, '1');
  const bad = await wallet.post('/wallet/session/witness', { r_s: rs1, witness, allowAgent: '0' });
  assert.equal(bad.status, 409); assert.equal(bad.body.reason, 'allow_agent_mismatch');
  const good = await wallet.post('/wallet/session/witness', { r_s: rs1, witness, allowAgent: '1' });
  assert.equal(good.status, 200, j(good.body));
  const none = await wallet.post('/wallet/authorize/precheck', { arid, origin, cert_s, pk_trace, r_s: '424242' });
  assert.equal(none.status, 404); assert.equal(none.body.reason, 'no_session');
});
```

`arid/origin/cert_s/pk_trace/witness/rs1` 은 그 파일이 이미 쓰는 변수 이름에 맞춘다(재시작 뒤 needs_consent 케이스 근처).

- [ ] **Step 2: 실패 확인**

Run: `node tests/test_mode3_wallet_snap.mjs 2>&1 | grep -A3 "B-I1"` → Expected: `sessionAllowAgent` undefined 로 FAIL.

- [ ] **Step 3: 구현 (에이전트)**

precheck:

```js
    const { arid, origin, cert_s, pk_trace, factoryAddress = null, r_s = null } = req.body ?? {};
    …
    const bad = await checkService(...); if (bad) return res.status(bad.status).json(bad.body);
    // 재승인(r_s 있음): 동의 창의 "AI 에이전트 허용" 은 RP 가 보낸 값이 아니라 **이 세션의 실제 값**이어야 한다(2026-09-23 점검 B-I1).
    if (r_s !== null) {
      if (!isDec(r_s)) return res.status(400).json({ error: 'r_s 는 10진 문자열' });
      const s = state.sessions[BigInt(r_s).toString()];
      if (!s) return res.status(404).json({ reason: 'no_session' });
      return res.json({ ok: true, sessionAllowAgent: String(s.allowAgent) });
    }
    res.json({ ok: true });
```

`/wallet/session/witness`: `const { r_s, witness, allowAgent = null } = req.body ?? {};` 그리고 세션을 찾은 뒤 `if (allowAgent !== null && String(allowAgent) !== String(s.allowAgent)) return res.status(409).json({ reason: 'allow_agent_mismatch' });`.

- [ ] **Step 4: 페이지**

`mode3/wallet.html` 재승인 분기: precheck 본문에 `r_s: req.reauth === true ? req.r_s : undefined` 를 넣고, 재승인이면 `const witness = await consentLogin({ ...req, allowAgent: pre.body.sessionAllowAgent });` 로 동의 창을 띄우고 `/wallet/session/witness` 본문에 `allowAgent: pre.body.sessionAllowAgent` 를 실어 보낸다. precheck 404 `no_session` 은 `reply({ ok:false, reason:'no_session' })`.

브라우저 회귀(`tests/test_mode3_browser.mjs`, 재시작 뒤 재승인 케이스 `:261` 근처): RP 가 `allowAgent:'0'` 을 실어 재승인 요청을 보내도 Snap 동의 창 문구(`dialogs` 의 마지막 항목, `snap-mode3/src/index.js:125` 의 `AI 에이전트 허용: 예`)가 세션의 실제 값 `예` 인지 단언한다. 기존 재승인 케이스가 `allowAgent:'1'` 세션이 아니면 그 케이스의 로그인을 `allowAgent` 체크박스를 켜고 하게 바꾸거나, 위조 요청을 보내는 형태(`forgeAuthorize` 계열 헬퍼가 있음)로 `reauth:true, allowAgent:'0'` 을 보내 문구를 검사한다.

- [ ] **Step 5: M-1 — ProofCache.deleteSession**

`lib/mode3_wallet.js` `ProofCache`:

```js
  /** 한 세션(r_s)의 캐시 항목을 전부 지운다 — 세션 만료 정리에서 부른다. 키는 `${root}:${sessionId}:${discKey}` 이고 root·sessionId 는 10진 문자열이라 ':' 을 포함하지 않는다. */
  deleteSession(sessionId) { for (const k of [...this.#m.keys()]) if (k.split(':')[1] === String(sessionId)) this.#m.delete(k); }
```

`tests/test_mode3_wallet.mjs` 의 ProofCache 케이스에 `c.deleteSession('s'); assert.equal(c.get('r','s'), null); assert.equal(c.get('r','s','3:0,410,0,0:2007,410,0,0'), null); assert.notEqual(c.get('r','other'), null)`(다른 세션 항목 하나를 미리 넣어 둔다). 에이전트 `pruneSessions`:

```js
function pruneSessions(head) {
  let changed = false;
  for (const [k, s] of Object.entries(state.sessions)) if (BigInt(s.credential.max_height) < head) { delete state.sessions[k]; cache.deleteSession(k); changed = true; }
  if (changed) persist();
}
```

(`cache` 가 `pruneSessions` 보다 아래 `:84` 에 선언돼 있다 — `const` TDZ 는 호출 시점엔 문제 없지만, 읽기 쉽게 `cache` 선언을 `pruneSessions` 위로 옮긴다.) `/wallet/revalidate`·`/wallet/tx` 의 `session_expired` 경로, 그리고 `delete state.sessions[rsKey]` 를 하는 `revoked` 경로(`:571` 부근)에도 `cache.deleteSession(rsKey)` 를 넣는다.

- [ ] **Step 6: N1·N4·등록 안내**

- `mode3_wallet_agent.js:451` 정규식을 `/is a member/` 로(imt_v2 테스트가 고정한 계약은 부분 문구다).
- `:615` `return { s, rsKey, disclosure, synced, … }` 에서 `synced` 제거(읽는 곳 없음 — `grep -n "\.synced" mode3_wallet_agent.js` 로 확인).
- `mode3/wallet.html:300-320` 등록 흐름: 에이전트 `/wallet/register` 가 201 을 준 뒤 `invokeSnap('storeRegistration', …)` 이 실패하면(throw), 사용자에게 "에이전트에는 등록됐지만 Snap 저장에 실패했다 — Snap 은 `registration_incomplete` 상태다. 복구: 'Snap 초기화' → 에이전트 상태 파일 삭제 → 다시 등록(재시연 세트, 문서 '하지 말 것 / 재시연')" 을 `step()`/`log()` 로 보여 준다(지금은 일반 오류 문구뿐).

- [ ] **Step 7: 통과 확인·회귀**

Run: `node tests/test_mode3_wallet.mjs && node tests/test_mode3_wallet_snap.mjs && node tests/test_mode3_wallet_agent.mjs && bash scripts/run_tests.sh browser`
Expected: 전부 통과(browser 는 Chrome 필요 — 없으면 보고).

- [ ] **Step 8: 커밋**

```bash
git add mode3_wallet_agent.js lib/mode3_wallet.js mode3/wallet.html tests/test_mode3_wallet.mjs tests/test_mode3_wallet_snap.mjs tests/test_mode3_wallet_agent.mjs tests/test_mode3_browser.mjs
git commit -m "fix(wallet): 재승인 동의 창의 allowAgent 를 세션 값에 묶음(점검 B-I1), 세션 정리 시 π 캐시 삭제(M-1), 정규식·죽은 반환값(N1·N4), 등록 실패 복구 안내"
```

---

### Task 4: 문서·테스트 인프라 — D-I1·D-I3·publish 지침 모순·N2·점검 결과 기록

**Files:**
- Modify: `docs/MODE3_DEMO.md:62`(주소 변경 경고), `:146-147`·`:226`(publish 지침), `:307`(contract 그룹), 운영 메모(`root_too_old`, 등록 복구 창, `allow_agent_mismatch`)
- Modify: `scripts/run_tests.sh:13`(contract 주석)
- Modify: `tests/test_mode3_rcl_sync.mjs:255`(N2)
- Modify: `docs/audits/2026-09-23-mode3/SUMMARY.md`(처리 결과 절)

- [ ] **Step 1: 문서**

`docs/MODE3_DEMO.md`:
- `:62` 경고를 "팩토리를 다시 배포하거나 **팩토리 생성자 인자 중 하나라도**(`MODE3_MAX_ROOT_AGE`, `MODE3_MAX_LIFETIME_BLOCKS`, 검증기 주소, 로그 주소, CIA 키, 서비스 조합 키) 바꾸면 모든 PPID 계정 주소가 바뀐다" 로. 그리고 "팩토리가 이미 있으면 RP 는 env 대신 **팩토리의 값**을 쓰고 경고한다(2026-09-23) — env 를 바꿨는데 안 먹는다면 그 경고를 보라" 한 줄.
- `:146-147`("속성 변경 직후 `/cia/publish` 를 따로 부르지 말고 하트비트에 묶는다") 과 `:226` S8′("`/cia/publish` →") 의 모순: S8′ 을 "`/cia/publish`(시연 편의로 즉시 게시 — 운영에선 위 '관리자 속성 변경' 의 이유로 하트비트에 묶는다)" 로 고쳐 둘이 서로를 가리키게 한다.
- `:307` contract 항목: "hardhat 인프로세스 체인이라 :8545 가 필요 없다. 단 `build/mode3/` 의 `pi_cred` zkey·wasm 은 필요하다(`test/Mode3Wallet.test.mjs` 가 실제 π 를 만든다) — 깨끗한 체크아웃에서 그룹 전체가 실패하면 그 이유다."
- 엔드포인트/운영 메모: RP 로그인 거절 사유에 `root_too_old`(CIA 하트비트가 `MODE3_MAX_ROOT_AGE` 블록 넘게 멈추면 온체인 `RootTooOld` 와 함께 오프체인 로그인도 막힌다 — CIA 를 살리고 `/cia/publish` 또는 하트비트를 기다린다), 지갑 `/wallet/session/witness` 의 `allow_agent_mismatch`, 등록 직후 Snap 저장 실패 복구 절차(Task 3 Step 6 의 문구와 같은 내용).
- `scripts/run_tests.sh:13` 주석에 `# build/mode3 zkey·wasm 필요` 추가.

- [ ] **Step 2: N2**

`tests/test_mode3_rcl_sync.mjs:255` 의 `assert.ok(observed.length > 0, …)` 를 `assert.ok(observed.includes(a.root) && observed.includes(b.root), '관측 창이 델타 전후 root 를 모두 봤어야 한다(삽입 구간을 덮었다는 증거)');` 로.

Run: `node tests/test_mode3_rcl_sync.mjs` → 14/14.

- [ ] **Step 3: 점검 결과 기록**

`docs/audits/2026-09-23-mode3/SUMMARY.md` 끝에 "## 처리 결과 (2026-09-23)" 절: Important 8건·주목 Minor 3건·N1/N2/N4 각각 커밋 해시와 한 줄. 처리하지 않은 Minor 는 "기록으로 남김" 으로.

- [ ] **Step 4: 전 그룹 실행**

Run: `bash scripts/run_tests.sh chain && bash scripts/run_tests.sh contract && npm test` (+ Chrome 있으면 `browser`, `snap`).
Expected: 전부 통과.

- [ ] **Step 5: 커밋**

```bash
git add docs/MODE3_DEMO.md scripts/run_tests.sh tests/test_mode3_rcl_sync.mjs docs/audits/2026-09-23-mode3/SUMMARY.md
git commit -m "docs(mode3): 점검 반영 — 주소 변경 경고 전체 인자, contract 그룹 전제, publish 지침 정리, root_too_old·복구 절차, N2 단언 강화"
```

---

## 자체 점검

- **스펙 커버리지**: A-I1·A-I2 → T1; B-I1 → T3; C-1·C-2 → T2; D-I1 → T4; D-I2 → T2 Step 7; D-I3 → T4; 주목 Minor(ProofCache → T3 Step 5, 등록 복구 창 → T3 Step 6 + T4, publish 지침 모순 → T4); N1·N4 → T3 Step 6; N2 → T4 Step 2. 결정(C-1 fail-closed)은 Global Constraints 와 T2 Step 3 에.
- **자리표시자**: T1 Step 1 의 alice 등록·헬퍼는 파일의 기존 코드 형태에 맞추라고 적었다(변수 이름이 파일마다 달라 복제하면 드리프트). T2 Step 1 의 `freshLogin`/`publishHeartbeat` 도 같은 이유. T2 Step 7 의 D-I2 테스트는 헬퍼 유무에 따른 두 경로를 적었다.
- **타입 일관성**: `sessionAllowAgent`·`allowAgent` 는 문자열 '0'|'1'(세션이 `String(s.allowAgent)` 로 저장, RP 도 문자열) — T3 에이전트·페이지·테스트 모두 문자열 비교. `maskDisclosure` 입출력 bigint — `verifyLogin` 은 `discOf` 가 `.toString()` 하므로 무관. `maxRootAge` bigint — `mode3_rp.js` 의 `MAX_ROOT_AGE` 도 `BigInt(...)`.
- **한계**: D-I2 의 자동 테스트는 격리 스택의 RP 재시작 지원에 달렸다 — 없으면 구현자가 보고서에 적고 `node -e` 확인으로 대신한다.
