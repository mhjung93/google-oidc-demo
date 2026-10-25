# Mode 3 root 유효 창 + 거울 세션별 counter 구현 계획

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 타 사용자의 세션 폐기·신규 등록으로 응용 체인 root 가 바뀌어도, 그 직전 root 로 만든 내 진행 중 거래가 `StaleRevocationRoot`/`StaleRegistryRoot` 로 튕기지 않게 하고(레이스 (1) 제거), 그 대신 폐기된 세션의 `nonce ≥ c` 거래는 거울에 공개된 세션별 counter 가 즉시 막게 한다.

**Architecture:** 캐노니컬 `Mode3Log` 와 거울 `Mode3Mirror` 가 공통 베이스 `Mode3RootHistory` 를 상속해 (a) 대체된 root 의 블록 높이를 최근 16개까지 기억하고 `isAcceptableRevRoot/RegRoot(root, G)` 로 "최신 또는 대체된 지 G 블록 이내" 를 답하며 (b) 게시 페이로드에 추가된 `(boundKeys[], boundValues[])` 를 `sessionBoundOf[pk_i] = c + 1` 로 낮추기만 적용한다. `Mode3Wallet` 은 생성자 `rootWindow`(G) 로 두 root 를 창 검사하고, 세션 상한은 자기 호출 값과 거울 값 중 낮은 쪽을 쓴다. IdP `cia.js` 는 세션 폐기 때 지갑이 세션키 서명으로 묶어 보낸 `pk_i` 를 받아 `pendingBounds` 대기열에 넣고 다음 게시 페이로드(·거울 중계)에 싣는다. 회로·검증기·RCL 리프 형식·RP 로그인 경로·Snap 은 바꾸지 않는다.

**Tech Stack:** Solidity 0.8.24(hardhat, viaIR), ethers v6, Node 테스트(`test/*.test.mjs` = hardhat 인프로세스, `tests/*.mjs` = :8545 + 격리 IdP), circom 산출물은 그대로(`build/mode3/` 재생성 없음).

**Spec:** `docs/superpowers/specs/2026-10-25-mode3-root-window-session-counter-design.md` (Task 1 이 §2·§3·§4·§5·§6 을 아래 "스펙 보정" 대로 고친다 — 고친 스펙이 이후 태스크의 정본이다). 선행 스펙: `docs/superpowers/specs/2026-10-22-mode3-revocation-counter-bound-design.md`.

## Global Constraints

- 회로 `pi_cred`·검증 컨트랙트 `PiCredVerifier`·공개 입력 34개·RCL 리프 `H′·2^32 + c`·`LOGIN_COUNTER = 2^32−1` 은 바꾸지 않는다. `npm run zk:*`·`scripts/build_mode3_circuit.sh` 를 실행하지 않는다.
- Snap(`snap-mode3/`)·지갑 페이지(`mode3/wallet.html`)·RP 오프체인 검증기(`lib/mode3_rp.js`, 최신 root 요구)는 바꾸지 않는다. 지갑 에이전트 변경은 `/wallet/session/revoke` 본문에 `pk_i`·`sig_i` 를 얹는 것과 팩토리 `rootWindow` 범위 검사 두 곳만이다.
- 새 의존성 추가 없음. `.env`·`cia_state.json`·`cia_keys.json`·`*_keys.json`·`mode3_wallet_state.json`·`mode3_rp_registration*.json`·`idp_state.json` 은 읽거나 출력하거나 커밋하지 않는다(테스트가 `os.tmpdir()` 아래 만든 격리 상태 파일은 예외).
- 게시 다이제스트 도메인은 `MODE3_LOG_V4`(기존 `MODE3_LOG_V3` 서명과 구분). JS 함수 이름(`publicationDigestV3`, `signPublicationV3`, `entryHashes`)은 그대로 두고 값만 바꾼다.
- `sessionBoundOf`·`Mode3Wallet.sessionBound`·`effectiveSessionBound` 의 저장 인코딩은 모두 **c + 1**(0 = 미설정), 타입 `uint256`.
- `Mode3Log.publish(bytes32 newRev, bytes32 newReg, uint64 newEpoch, bytes32[] revLeaves, uint32[] slotIdx, bytes32[] slotLeaves, uint256[] boundKeys, uint32[] boundValues, bytes sig)`; `Mode3Mirror.publish(bytes32 newRev, bytes32 newReg, uint64 newEpoch, bytes32 hLeaves, bytes32 hIdx, bytes32 hSlots, uint256[] boundKeys, uint32[] boundValues, bytes sig)`.
- 상수: `ROOT_HISTORY = 16`(컨트랙트 상수), `ROOT_WINDOW_DEFAULT = 20n`(`lib/mode3_onchain.js`), `FACTORY_ROOT_WINDOW_BAND = { min: 0n, max: 200n }`, RP env `MODE3_ROOT_WINDOW`.
- 커밋은 pathspec 으로만(`git add <files>`; `git add -A` 금지 — 루트에 추적되지 않는 민감 파일이 있다). 커밋 메시지 끝에 `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>` 과 `Claude-Session: https://claude.ai/code/session_013qGSXZTftBJSB1M4XpPRHN` 두 줄. 푸시·PR 은 하지 않는다.
- 테스트는 `bash scripts/run_tests.sh contract`(hardhat 인프로세스, `build/mode3/` 산출물 필요)·`bash scripts/run_tests.sh chain`(:8545 hardhat 노드 — 비어 있으면 스스로 띄우고 끝나면 끈다, 떠 있던 노드는 건드리지 않는다)·`npm test`(unit). 사용자 데모 프로세스(:5100/:8082/:8547/:8548, VM)는 건드리지 않는다. 시각은 `date` 실행값만 적는다.

## Review Focus

스펙이 암시하지만 어느 태스크의 테스트도 원래는 다루지 않던 입력 다섯 가지 — 각 줄의 테스트를 해당 태스크에 넣었다.

1. `rootWindow = 0` 으로 배포한 팩토리 — 예전처럼 "최신 root 만" 으로 동작해야 한다(대체 직후 다음 블록부터 `StaleRevocationRoot`). → Task 3 테스트 "rootWindow = 0".
2. 하트비트(같은 root 재게시) — root 가 바뀌지 않았으므로 이력에 들어가면 안 되고 현재 root 의 `supersededAt` 은 0 그대로, `lastPublishedBlock` 만 바뀐다. → Task 2 테스트 "하트비트는 이력을 건드리지 않는다".
3. 상한 최댓값 `c = 2^32 − 1` 게시 — `c + 1` 이 `uint32` 를 넘치므로 `uint256` 으로 저장돼 `2^32` 가 돼야 한다(0 으로 되돌아가 "미설정" 이 되면 안 된다). → Task 2 테스트 "최댓값".
4. 같은 게시 calldata 에 같은 `pk_i` 가 두 번(`[5, 3]`·`[3, 5]`) — 순서와 무관하게 최솟값 + 1 이 남아야 한다. → Task 2 테스트 "중복 pk_i".
5. 거울 중계가 epoch 을 건너뛸 때(IdP 가 두 번 게시한 뒤 한 번만 중계) — 건너뛴 게시의 `(pk_i, c)` 가 거울에 유실되면 안 된다(IdP 가 모든 거울이 받을 때까지 누적 재전송). → Task 4 테스트 "건너뛴 epoch".

## 스펙 보정(Task 1 에서 스펙 파일에 반영)

코드를 읽어 보니 스펙 §4 의 전제("발급 때 요청의 `pk_i` 를 레코드에 저장")가 성립하지 않는다 — `/cia/issue` 요청에는 `pk_i` 가 없고(세션키는 `C_s` 안에만 있다, D1 비연결성) IdP 가 발급 때 `pk_i` 를 알면 거래(`pub[2]`)와 세션을 연결할 수 있어 알면 안 된다. 다음으로 바꾼다.

- **§2 공통 베이스**: `Mode3Log`·`Mode3Mirror` 가 `abstract contract Mode3RootHistory`(`contracts/Mode3RootHistory.sol`)를 상속한다. `sessionBoundOf` 는 `uint256`(c + 1). 도메인 `MODE3_LOG_V4`. 거울 `publish` 도 bound **배열** 을 받는다(해시만 받으면 저장할 수 없다). 거울 중계가 최신 epoch 만 옮기므로 IdP 는 `pendingBounds` 항목을 **모든 거울이 그 항목을 실은 epoch 이상을 받을 때까지** 매 게시에 다시 싣는다(컨트랙트는 같은 값·올리기를 무시하므로 무해).
- **§3**: `effectiveSessionBound(pk_i) view` 추가(자기 호출·거울 값 중 0 이 아닌 더 낮은 쪽). 생성자 인자 `rootWindow` 는 팩토리·지갑 모두 마지막에 붙고 `_initCode` 에도 들어간다(CREATE2 주소가 바뀐다 → 재배포). 지갑이 받아들이는 범위 0..200.
- **§4**: `pk_i` 는 **폐기 때** 지갑이 `/cia/revoke` 본문에 `pk_i` 와 `sig_i` 로 보낸다. `sig_i` = 세션키(secp256k1, `sk_i`) 의 EIP-191 서명, 메시지 `MODE3_REVOKE_BIND_V1|uid|Cf_s|bound|nonce`(sk_u 서명과 같은 값, 10진). 둘 중 하나만 오거나 서명이 틀리면 `400 bad_session_signature`(리프도 넣지 않음). 레코드에 `pk_i` 를 적고 `pendingBounds` 에 `(pk_i, bound)` 를 넣는다. 관리자 폐기·옛 지갑(web 코어)의 폐기처럼 `pk_i` 가 없으면 지금처럼 RCL 리프만(거울 counter 없음, 응답 `mirrorBound:false`). 이 결속이 없으면 `sig_u` 만 가진 사용자가 남의 `pk_i` 를 넣어 그 세션을 막을 수 있다.
- **§5**: 지갑 에이전트 변경은 `/wallet/session/revoke` 본문(`pk_i`, `sig_i`)과 팩토리 `rootWindow` 범위 검사. Snap·페이지·RP 검증기는 그대로. RP 는 env `MODE3_ROOT_WINDOW` 를 팩토리 배포에 넘긴다.
- **§6**: 데모 기본 G = 20(`ROOT_WINDOW_DEFAULT`), K = 16(`ROOT_HISTORY`).

## 파일 구조

| 파일 | 역할 |
|---|---|
| `contracts/Mode3RootHistory.sol` (신설) | root 이력(링 버퍼 16)·`isAcceptable*Root`·`sessionBoundOf`·`_setRoots`·`_applyBounds` — 캐노니컬·거울 공통 |
| `contracts/IMode3Roots.sol` | `isAcceptableRevRoot`·`isAcceptableRegRoot`·`sessionBoundOf` 추가 |
| `contracts/Mode3Log.sol`, `contracts/Mode3Mirror.sol` | 베이스 상속, `publish`/`digestFor` 에 bound 배열, 도메인 V4 |
| `contracts/Mode3Wallet.sol`, `contracts/Mode3WalletFactory.sol` | `rootWindow`, 창 검사, `effectiveSessionBound` |
| `hardhat.config.cjs` | 위 세 로그 계열 파일 viaIR override(스택 한도) |
| `lib/mode3_log.js` | 도메인 값·ABI·`entryHashes`/`publicationDigestV3*` 에 bound 두 해시 |
| `lib/mode3_onchain.js` | `ROOT_WINDOW_DEFAULT`·`FACTORY_ROOT_WINDOW_BAND`·ABI·`deployFactory(rootWindow)` |
| `lib/mode3_revocation.js` | `revokeBindMessage`·`signRevokeBind`·`verifyRevokeBind` |
| `lib/mode3_cia_state.js` | `pendingBounds` 기본값 |
| `cia.js` | `/cia/revoke` pk_i·sig_i, `pendingBounds`, 게시 페이로드·거울 중계·누적 재전송·정리 |
| `mode3_wallet_agent.js` | revoke 본문 두 필드, 팩토리 `rootWindow` 검사 |
| `mode3_rp.js` | `MODE3_ROOT_WINDOW` → `deployFactory` |
| `scripts/bench_baselines.cjs` | 팩토리 생성자 10번째 인자 |
| `tests/helpers/mode3_chain.mjs` | `publishV3`/`relayToMirror` 에 bound 배열 |
| 테스트 | `test/Mode3Log.test.mjs`, `test/Mode3Mirror.test.mjs`, `test/Mode3Wallet.test.mjs`, `tests/test_cia_revoke_bound.mjs`, `tests/test_mode3_wallet_agent.mjs`, `tests/test_mode3_revocation_tree.js`, `tests/test_mode3_cia_state.js` |
| 문서 | 스펙(Task 1), `docs/MODE3_DEMO.md`(Task 6) |

태스크 의존: 1 → 2 → {3, 4}(파일이 겹치지 않아 병렬 가능 — 단 둘이 같은 :8545 를 쓰지 않도록 Task 4 의 chain 테스트는 Task 3 의 contract 테스트와 병렬이어도 무관하다: contract 그룹은 인프로세스 체인이다) → 5 → 6.

---

### Task 1: 스펙 보정

**Files:**
- Modify: `docs/superpowers/specs/2026-10-25-mode3-root-window-session-counter-design.md` (§2, §3, §4, §5, §6)

**Interfaces:**
- Produces: 이후 태스크가 따르는 정본 문구(위 "스펙 보정" 다섯 항목).

- [ ] **Step 1: §2 제목·본문 고치기**

§2 제목을 `## 2. 캐노니컬·거울 공통 베이스 \`Mode3RootHistory\`(Mode3Log·Mode3Mirror 가 상속)` 로 바꾸고, §2.1 첫 줄 뒤에 다음 단락을 넣는다.

```markdown
- 구현 위치(2026-10-25 계획 보정): `contracts/Mode3RootHistory.sol`(abstract). `Mode3Log`·`Mode3Mirror` 가 상속해 root 이력·세션 counter 코드가 하나다 — 검증자가 어느 쪽을 읽어도 같은 답이어야 한다. 다이제스트 도메인은 `MODE3_LOG_V4`(bound 두 해시가 추가돼 옛 서명과 구분).
```

§2.2 의 `mapping(uint256 pk_i => uint32) sessionBoundOf — **c + 1** 저장` 을 `mapping(uint256 pk_i => uint256) sessionBoundOf — **c + 1** 저장(c = 2^32−1 일 때 +1 이 uint32 를 넘치므로 uint256; Mode3Wallet.sessionBound 와 같은 인코딩)` 으로 바꾼다. §2.2 마지막 줄("거울 중계(Mode3Mirror)는 같은 페이로드를 그대로 옮긴다") 뒤에 다음을 덧붙인다.

```markdown
  거울 `publish` 는 리프·슬롯은 해시로 받되 bound 는 **배열 그대로** 받는다(저장해야 하므로) — 다이제스트에는 두 배열의 `keccak256(abi.encodePacked(...))` 가 들어가 캐노니컬과 바이트 단위로 같다. 거울 중계는 최신 epoch 만 옮기므로, IdP 는 `pendingBounds` 항목을 **모든 거울이 그 항목이 실린 epoch 이상을 받을 때까지** 매 게시에 다시 싣는다(컨트랙트는 같은 값·올리기를 무시하므로 중복은 무해). 거울이 없으면 캐노니컬 게시 직후 비운다.
```

- [ ] **Step 2: §3 고치기**

§3 첫 항목을 `- 생성자 파라미터 \`uint64 rootWindow\`(G, 블록) — 팩토리·지갑 생성자의 **마지막** 인자이고 팩토리 \`_initCode\` 에도 들어간다(CREATE2 주소가 바뀌므로 스택 재배포). 데모 20(\`ROOT_WINDOW_DEFAULT\`). 지갑 에이전트는 팩토리의 \`rootWindow()\` 를 0..200 범위로 받아들인다(\`FACTORY_ROOT_WINDOW_BAND\`).` 로 바꾼다. 세 번째 항목(거울 값과 자기 호출 값) 끝에 ` 이 값을 \`effectiveSessionBound(pk_i) view\` 로도 노출한다(저장 인코딩 c + 1).` 를 덧붙인다.

- [ ] **Step 3: §4 교체**

§4 전체를 다음으로 교체한다.

```markdown
## 4. IdP `cia.js` 와 게시

- IdP 는 발급 때 세션키 `pk_i` 를 **모른다**(`/cia/issue` 요청에 없고 `C_s` 안에만 있다 — D1 비연결성: 알면 거래 `pub[2]` 와 세션을 연결할 수 있다). 그래서 `pk_i` 는 **폐기 때** 지갑이 알려 준다: `/cia/revoke scope=session` 본문에 `pk_i`(10진, < 2^160) 와 `sig_i` 를 함께 싣는다. `sig_i` = 세션키(secp256k1 `sk_i`) 의 EIP-191 서명, 메시지 `MODE3_REVOKE_BIND_V1|uid|Cf_s|bound|nonce`(sk_u 서명 `revokeSessionMessage` 와 같은 값, 10진 문자열, `lib/mode3_revocation.js` `revokeBindMessage`). IdP 는 `ethers.verifyMessage` 로 복원한 주소가 `pk_i` 와 같은지 본다 — 이 결속이 없으면 `sig_u` 만 가진 사용자가 **남의** `pk_i` 를 넣어 그 세션을 막을 수 있다(낮추기만이라 되돌릴 수 없다).
- 둘 중 하나만 오거나 서명이 틀리면 `400 { reason: 'bad_session_signature' }`(리프도 넣지 않음). 둘 다 없으면 지금처럼 RCL 리프만 넣는다(관리자 폐기, 옛 지갑·web 코어) — 응답 `mirrorBound: false`. 받아들이면 세션 레코드에 `pk_i` 를 적고 `state.pendingBounds` 에 `{ pk_i, bound, epoch: null }` 을 넣는다(같은 pk_i 는 더 낮은 bound 로만 갈아끼움). 응답 `mirrorBound: true`.
- `publishNow` 는 대기열 전부를 `(boundKeys, boundValues)` 로 싣고(서명이 덮는다) 성공하면 각 항목에 그 epoch 를 적는다. 아직 어느 게시에도 실리지 않은 항목이 있으면 리프·슬롯이 없어도 게시한다. `lastPublication` 에 두 배열을 남겨 거울 중계가 그대로 옮긴다. 모든 거울이 받은 epoch(거울이 없으면 캐노니컬 epoch) 이하에 실린 항목은 버린다(§2.2). 상태 스키마는 v12 유지(`pendingBounds ??= []`).
- 관리자 폐기(기본 bound 0)는 레코드에 이미 `pk_i` 가 있을 때만(앞선 사용자 폐기로) 거울 counter 를 게시한다 — 없으면 RCL 리프만.
```

- [ ] **Step 4: §5·§6 고치기**

§5 첫 항목 `- 변경 없음.` 을 `- 지갑 에이전트(\`mode3_wallet_agent.js\`): \`/wallet/session/revoke\` 가 본문에 \`pk_i\`·\`sig_i\`(세션키로 서명) 를 얹고, 팩토리 검사에 \`rootWindow\` 범위(0..200) 를 더한다. Snap·지갑 페이지·RP 오프체인 검증기(최신 root 요구)는 변경 없음. RP(\`mode3_rp.js\`) 는 env \`MODE3_ROOT_WINDOW\`(기본 20) 를 팩토리 배포에 넘긴다.` 로 바꾼다. §6 첫 항목 끝에 ` 코드 상수 \`ROOT_WINDOW_DEFAULT = 20n\`(\`lib/mode3_onchain.js\`), RP env \`MODE3_ROOT_WINDOW\`.` 를, 둘째 항목 끝에 ` 컨트랙트 상수 \`ROOT_HISTORY = 16\`.` 를 덧붙인다.

- [ ] **Step 5: 커밋**

```bash
git add docs/superpowers/specs/2026-10-25-mode3-root-window-session-counter-design.md docs/superpowers/plans/2026-10-25-mode3-root-window-session-counter.md
git commit -m "docs(mode3): root 창 스펙 보정(공통 베이스·pk_i 는 폐기 때 세션키 서명으로·누적 재전송) + 구현 계획" -m "Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>" -m "Claude-Session: https://claude.ai/code/session_013qGSXZTftBJSB1M4XpPRHN" -- docs/superpowers/specs/2026-10-25-mode3-root-window-session-counter-design.md docs/superpowers/plans/2026-10-25-mode3-root-window-session-counter.md
```

---

### Task 2: 공통 베이스 `Mode3RootHistory` + 로그·거울 게시 페이로드

**Files:**
- Create: `contracts/Mode3RootHistory.sol`
- Modify: `contracts/IMode3Roots.sol`, `contracts/Mode3Log.sol`, `contracts/Mode3Mirror.sol`, `hardhat.config.cjs:46-60`(overrides), `lib/mode3_log.js:40-95`, `tests/helpers/mode3_chain.mjs:92-105`
- Test: `test/Mode3Log.test.mjs`, `test/Mode3Mirror.test.mjs`

**Interfaces:**
- Consumes: 없음(Task 1 의 스펙 문구만).
- Produces(Task 3·4·5 가 쓴다):
  - Solidity: `IMode3Roots.isAcceptableRevRoot(bytes32,uint64) view returns (bool)`, `isAcceptableRegRoot(bytes32,uint64)`, `sessionBoundOf(uint256) view returns (uint256)`; `Mode3RootHistory.ROOT_HISTORY() = 16`, `revSupersededAt(bytes32)`, `regSupersededAt(bytes32)`, 이벤트 `SessionBoundPublished(uint256 indexed pk_i, uint32 bound, uint64 epoch)`, 에러 `LengthMismatch()`(베이스로 이동).
  - `Mode3Log.publish(newRev, newReg, newEpoch, revLeaves, slotIdx, slotLeaves, boundKeys, boundValues, sig)`, `Mode3Log.digestFor(newRev, newReg, newEpoch, revLeaves, slotIdx, slotLeaves, boundKeys, boundValues)`.
  - `Mode3Mirror.publish(newRev, newReg, newEpoch, hLeaves, hIdx, hSlots, boundKeys, boundValues, sig)`, `Mode3Mirror.digestFor(newRev, newReg, newEpoch, hLeaves, hIdx, hSlots, hBoundKeys, hBoundValues)`.
  - JS(`lib/mode3_log.js`): `DOMAIN_LOG_V3` 값 = keccak("MODE3_LOG_V4"); `entryHashes({ revLeaves, slotIdx, slotLeaves, boundKeys = [], boundValues = [] }) → { hLeaves, hIdx, hSlots, hBoundKeys, hBoundValues }`; `publicationDigestV3({ canonicalChainId, canonicalLogAddress, revRoot, regRoot, epoch, revLeaves, slotIdx, slotLeaves, boundKeys = [], boundValues = [] })`; `signPublicationV3(wallet, 같은 인자)`; `MODE3_ROOTS_ABI` 에 `isAcceptableRevRoot`·`isAcceptableRegRoot`·`sessionBoundOf`·`revSupersededAt`·`regSupersededAt`·이벤트 `SessionBoundPublished`; `MODE3_LOG_ABI`·`MODE3_MIRROR_ABI` 의 `publish`/`digestFor` 새 시그니처.
  - 테스트 헬퍼: `publishV3(log, ciaWallet, { revRoot, regRoot, epoch, revLeaves = [], slotIdx = [], slotLeaves = [], boundKeys = [], boundValues = [] })` 가 `p` 에 `boundKeys`(bigint[])·`boundValues`(number[]) 를 포함해 돌려주고, `relayToMirror(mirror, signer, { p, sig })` 가 그 둘을 거울에 넘긴다.

- [ ] **Step 1: 베이스 컨트랙트 작성**

`contracts/Mode3RootHistory.sol`:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./IMode3Roots.sol";

/// @title Mode 3 root 이력 + 세션별 counter — 캐노니컬 Mode3Log 와 거울 Mode3Mirror 의 공통 베이스
///   (설계 2026-10-25 root 유효 창 §2). 둘이 같은 코드를 공유해야 검증자(Mode3Wallet)가 어느 쪽을 읽어도 같은 답을 얻는다.
/// @notice 최신 root 외에 "대체된 블록" 을 최근 ROOT_HISTORY 개까지 기억한다. isAcceptable*Root(root, G) 는 최신이거나
///   대체된 지 G 블록 이내인 root 만 참이다. sessionBoundOf[pk_i] 는 IdP 가 게시 페이로드에 실어 보낸 세션별 허용
///   거래 수 c 를 **c + 1** 로 저장한다(0 = 미설정; Mode3Wallet.sessionBound 와 같은 인코딩. uint32 c 가 2^32−1 일 때
///   +1 이 넘치지 않게 uint256 으로 둔다).
abstract contract Mode3RootHistory is IMode3Roots {
    uint256 public constant ROOT_HISTORY = 16;

    bytes32 public revRoot;
    bytes32 public regRoot;
    uint64 public epoch;
    uint64 public lastPublishedBlock;

    /// @dev root → 그 root 가 대체된 블록 높이. 최신 root 와 이력 밖으로 밀린 root 는 0.
    mapping(bytes32 => uint64) public revSupersededAt;
    mapping(bytes32 => uint64) public regSupersededAt;
    bytes32[ROOT_HISTORY] private revHist;
    bytes32[ROOT_HISTORY] private regHist;
    uint256 private revPos;
    uint256 private regPos;

    /// @notice 세션키별 공개 상한: 저장값 = c + 1 (0 = 없음). 낮추기만 된다.
    mapping(uint256 => uint256) public sessionBoundOf;

    event SessionBoundPublished(uint256 indexed pk_i, uint32 bound, uint64 epoch);
    error LengthMismatch();

    constructor(bytes32 emptyRevRoot, bytes32 emptyRegRoot) {
        revRoot = emptyRevRoot;
        regRoot = emptyRegRoot;
        lastPublishedBlock = uint64(block.number);
    }

    function isAcceptableRevRoot(bytes32 root, uint64 window) public view returns (bool) {
        if (root == revRoot) return true;
        uint64 at = revSupersededAt[root];
        return at != 0 && block.number <= uint256(at) + uint256(window);
    }

    function isAcceptableRegRoot(bytes32 root, uint64 window) public view returns (bool) {
        if (root == regRoot) return true;
        uint64 at = regSupersededAt[root];
        return at != 0 && block.number <= uint256(at) + uint256(window);
    }

    /// @dev 링 버퍼에 옛 root 를 넣고 밀려난 root 의 기록을 지운다. 같은 root 가 다시 대체되면(등록부가 옛 값으로 돌아온 뒤
    ///   또 바뀜) 시각을 덮어쓴다 — 먼저 들어간 항목이 밀려날 때 새 기록까지 지워 liveness 만 조금 깎인다(안전과 무관).
    function _supersede(bytes32[ROOT_HISTORY] storage hist, uint256 pos, mapping(bytes32 => uint64) storage at, bytes32 old) private returns (uint256) {
        bytes32 evicted = hist[pos];
        if (evicted != bytes32(0)) delete at[evicted];
        hist[pos] = old;
        at[old] = uint64(block.number);
        return (pos + 1) % ROOT_HISTORY;
    }

    /// @dev 두 root·epoch·게시 블록을 갱신한다. 값이 바뀐 root 만 이력에 넣는다(하트비트 재게시는 이력을 건드리지 않는다).
    function _setRoots(bytes32 newRev, bytes32 newReg, uint64 newEpoch) internal {
        if (newRev != revRoot) revPos = _supersede(revHist, revPos, revSupersededAt, revRoot);
        if (newReg != regRoot) regPos = _supersede(regHist, regPos, regSupersededAt, regRoot);
        revRoot = newRev;
        regRoot = newReg;
        epoch = newEpoch;
        lastPublishedBlock = uint64(block.number);
    }

    /// @dev 세션별 상한 적용 — 낮추기만, 아니면 조용히 무시(게시 전체가 막히지 않게). 같은 pk_i 가 여러 번 실리면
    ///   순서대로 적용돼 최솟값이 남는다.
    function _applyBounds(uint256[] calldata boundKeys, uint32[] calldata boundValues, uint64 newEpoch) internal {
        if (boundKeys.length != boundValues.length) revert LengthMismatch();
        for (uint256 i = 0; i < boundKeys.length; i++) {
            uint256 cur = sessionBoundOf[boundKeys[i]];
            uint256 next = uint256(boundValues[i]) + 1;
            if (cur == 0 || next < cur) {
                sessionBoundOf[boundKeys[i]] = next;
                emit SessionBoundPublished(boundKeys[i], boundValues[i], newEpoch);
            }
        }
    }
}
```

- [ ] **Step 2: 인터페이스 확장**

`contracts/IMode3Roots.sol` 의 `lastPublishedBlock()` 줄 뒤에 추가:

```solidity
    /// @notice 2026-10-25 root 유효 창: root 가 최신이거나 대체된 지 window 블록 이내인가.
    function isAcceptableRevRoot(bytes32 root, uint64 window) external view returns (bool);
    function isAcceptableRegRoot(bytes32 root, uint64 window) external view returns (bool);
    /// @notice 거울에 공개된 세션별 상한(저장값 c + 1, 0 = 없음).
    function sessionBoundOf(uint256 pk_i) external view returns (uint256);
```

- [ ] **Step 3: Mode3Log 를 베이스 위로**

`contracts/Mode3Log.sol`:
- `import "./IMode3Roots.sol";` → `import "./Mode3RootHistory.sol";`, `contract Mode3Log is IMode3Roots` → `contract Mode3Log is Mode3RootHistory`.
- `DOMAIN = keccak256("MODE3_LOG_V3")` → `keccak256("MODE3_LOG_V4")`.
- 상태 변수 `revRoot`, `regRoot`, `epoch`, `lastPublishedBlock` 네 줄과 `error LengthMismatch();` 를 삭제(베이스에 있다).
- 생성자:

```solidity
    constructor(address cia_, bytes32 emptyRevRoot, bytes32 emptyRegRoot) Mode3RootHistory(emptyRevRoot, emptyRegRoot) {
        cia = cia_;
    }
```
- `digestFor`·`publish` 교체(주석의 "V3" 설명은 유지하고 아래를 덧붙인다):

```solidity
    /// @dev 2026-10-25 root 유효 창 §2.2: bound 두 배열의 해시가 뒤에 붙는다(도메인 V4). lib/mode3_log.js publicationDigestV3 와 바이트 단위로 같다.
    function digestFor(
        bytes32 newRev, bytes32 newReg, uint64 newEpoch,
        bytes32[] calldata revLeaves, uint32[] calldata slotIdx, bytes32[] calldata slotLeaves,
        uint256[] calldata boundKeys, uint32[] calldata boundValues
    ) public view returns (bytes32) {
        return keccak256(abi.encode(
            DOMAIN, block.chainid, address(this), newRev, newReg, newEpoch,
            keccak256(abi.encodePacked(revLeaves)), keccak256(abi.encodePacked(slotIdx)), keccak256(abi.encodePacked(slotLeaves)),
            keccak256(abi.encodePacked(boundKeys)), keccak256(abi.encodePacked(boundValues))
        ));
    }

    function publish(
        bytes32 newRev, bytes32 newReg, uint64 newEpoch,
        bytes32[] calldata revLeaves, uint32[] calldata slotIdx, bytes32[] calldata slotLeaves,
        uint256[] calldata boundKeys, uint32[] calldata boundValues, bytes calldata sig
    ) external {
        if (newEpoch <= epoch) revert EpochNotIncreasing(newEpoch, epoch);
        if (slotIdx.length != slotLeaves.length) revert LengthMismatch();
        bytes32 inner = digestFor(newRev, newReg, newEpoch, revLeaves, slotIdx, slotLeaves, boundKeys, boundValues);
        bytes32 ethDigest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", inner));
        if (_recover(ethDigest, sig) != cia) revert BadSignature();

        _enforceRevocationQueue(slotIdx, slotLeaves, newEpoch);
        _applyBounds(boundKeys, boundValues, newEpoch);   // 2026-10-25 §2.2: 세션별 counter(낮추기만)
        _setRoots(newRev, newReg, newEpoch);              // 2026-10-25 §2.1: 바뀐 root 는 이력에
        emit Revoked(newEpoch, newRev, revLeaves);
        for (uint256 i = 0; i < slotIdx.length; i++) emit SlotUpdated(newEpoch, slotIdx[i], slotLeaves[i]);
    }
```

- [ ] **Step 4: Mode3Mirror 를 베이스 위로**

`contracts/Mode3Mirror.sol`:
- `import "./IMode3Roots.sol";` → `import "./Mode3RootHistory.sol";`, `contract Mode3Mirror is IMode3Roots` → `is Mode3RootHistory`.
- `DOMAIN` → `keccak256("MODE3_LOG_V4")`. 상태 변수 `revRoot; regRoot; epoch; lastPublishedBlock;` 한 줄 삭제.
- 생성자:

```solidity
    constructor(address cia_, uint256 canonicalChainId_, address canonicalLog_, bytes32 emptyRevRoot, bytes32 emptyRegRoot) Mode3RootHistory(emptyRevRoot, emptyRegRoot) {
        cia = cia_; canonicalChainId = canonicalChainId_; canonicalLog = canonicalLog_;
    }
```
- `digestFor`·`publish` 교체:

```solidity
    /// @dev 캐노니컬 Mode3Log.digestFor 와 바이트 단위로 같다 — block.chainid/address(this) 대신 생성자로 받은
    ///   canonicalChainId/canonicalLog 를 넣는다. 2026-10-25: bound 두 배열의 해시가 뒤에 붙는다.
    function digestFor(bytes32 newRev, bytes32 newReg, uint64 newEpoch, bytes32 hLeaves, bytes32 hIdx, bytes32 hSlots, bytes32 hBoundKeys, bytes32 hBoundValues) public view returns (bytes32) {
        return keccak256(abi.encode(DOMAIN, canonicalChainId, canonicalLog, newRev, newReg, newEpoch, hLeaves, hIdx, hSlots, hBoundKeys, hBoundValues));
    }
    /// @notice 제출자는 아무나(릴레이어) — 신뢰 근거는 CIA 서명뿐이다. 리프·슬롯은 해시 세 개로 받지만 bound 는 저장해야 하므로
    ///   배열 그대로 받는다(2026-10-25 §2.2). epoch 은 건너뛸 수 있다(거울은 뒤처질 수 있다, V10 §3) — 건너뛴 게시의 bound 는
    ///   IdP 가 다음 게시에 다시 실어 보낸다(같은 값·올리기는 _applyBounds 가 무시한다).
    function publish(bytes32 newRev, bytes32 newReg, uint64 newEpoch, bytes32 hLeaves, bytes32 hIdx, bytes32 hSlots, uint256[] calldata boundKeys, uint32[] calldata boundValues, bytes calldata sig) external {
        if (newEpoch <= epoch) revert EpochNotIncreasing(newEpoch, epoch);
        bytes32 inner = digestFor(newRev, newReg, newEpoch, hLeaves, hIdx, hSlots, keccak256(abi.encodePacked(boundKeys)), keccak256(abi.encodePacked(boundValues)));
        bytes32 ethDigest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", inner));
        if (_recover(ethDigest, sig) != cia) revert BadSignature();
        _applyBounds(boundKeys, boundValues, newEpoch);
        _setRoots(newRev, newReg, newEpoch);
        emit Mirrored(newEpoch, newRev, newReg);
    }
```

- [ ] **Step 5: hardhat override(스택 한도)**

`hardhat.config.cjs` 의 `overrides` 에 `AttrGate.sol` 항목 뒤 추가. `publish` 의 calldata 배열 인자가 다섯(10 슬롯)이라 비-IR 로는 "stack too deep" 이 난다. 이 세 파일은 CREATE2 주소와 무관하다.

```js
      // 2026-10-25 root 유효 창: publish() 의 calldata 배열 인자가 5개(10 스택 슬롯)라 비-IR 로는 stack too deep. 세 파일 모두
      // (베이스·캐노니컬·거울) 같은 설정으로 — 이 셋은 CREATE2 주소 계산과 무관하다.
      "contracts/Mode3RootHistory.sol": { version: "0.8.24", settings: WALLET_IR_SETTINGS },
      "contracts/Mode3Log.sol": { version: "0.8.24", settings: WALLET_IR_SETTINGS },
      "contracts/Mode3Mirror.sol": { version: "0.8.24", settings: WALLET_IR_SETTINGS },
```

- [ ] **Step 6: 컴파일**

Run: `npx hardhat compile`
Expected: 오류 없이 끝남(`Mode3RootHistory`·`Mode3Log`·`Mode3Mirror` 아티팩트 생성). `Mode3Wallet.sol` 은 아직 옛 인터페이스를 쓰지만 `IMode3Roots` 에 함수가 **추가**만 돼 컴파일된다.

- [ ] **Step 7: JS 다이제스트·ABI**

`lib/mode3_log.js`:

```js
// 2026-10-25 root 유효 창 §2.2: 이름은 V3 API 그대로 두고 도메인 값만 V4 — 다이제스트에 bound 배열 두 해시가 추가돼 옛 서명과 구분한다.
export const DOMAIN_LOG_V3 = ethers.keccak256(ethers.toUtf8Bytes('MODE3_LOG_V4'));
export const MODE3_ROOTS_ABI = [
  'function revRoot() view returns (bytes32)',
  'function regRoot() view returns (bytes32)',
  'function epoch() view returns (uint64)',
  'function lastPublishedBlock() view returns (uint64)',
  // 2026-10-25 root 유효 창(Mode3RootHistory)
  'function isAcceptableRevRoot(bytes32 root, uint64 window) view returns (bool)',
  'function isAcceptableRegRoot(bytes32 root, uint64 window) view returns (bool)',
  'function revSupersededAt(bytes32 root) view returns (uint64)',
  'function regSupersededAt(bytes32 root) view returns (uint64)',
  'function sessionBoundOf(uint256 pk_i) view returns (uint256)',
  'function ROOT_HISTORY() view returns (uint256)',
  'event SessionBoundPublished(uint256 indexed pk_i, uint32 bound, uint64 epoch)',
];
```
`MODE3_LOG_ABI` 의 두 줄을:

```js
  'function digestFor(bytes32 newRev, bytes32 newReg, uint64 newEpoch, bytes32[] revLeaves, uint32[] slotIdx, bytes32[] slotLeaves, uint256[] boundKeys, uint32[] boundValues) view returns (bytes32)',
  'function publish(bytes32 newRev, bytes32 newReg, uint64 newEpoch, bytes32[] revLeaves, uint32[] slotIdx, bytes32[] slotLeaves, uint256[] boundKeys, uint32[] boundValues, bytes sig)',
```
`MODE3_MIRROR_ABI` 의 두 줄을:

```js
  'function digestFor(bytes32 newRev, bytes32 newReg, uint64 newEpoch, bytes32 hLeaves, bytes32 hIdx, bytes32 hSlots, bytes32 hBoundKeys, bytes32 hBoundValues) view returns (bytes32)',
  'function publish(bytes32 newRev, bytes32 newReg, uint64 newEpoch, bytes32 hLeaves, bytes32 hIdx, bytes32 hSlots, uint256[] boundKeys, uint32[] boundValues, bytes sig)',
```
해시·다이제스트 함수:

```js
/** 컨트랙트가 서명 안에서 쓰는 다섯 배열의 해시. slotIdx·boundValues(uint32[])·boundKeys(uint256[]) 는 32바이트 패딩 패킹(Solidity encodePacked 의 배열 규칙). */
export function entryHashes({ revLeaves, slotIdx, slotLeaves, boundKeys = [], boundValues = [] }) {
  if (slotIdx.length !== slotLeaves.length) throw new Error('entryHashes: slotIdx 와 slotLeaves 길이가 다르다');
  if (boundKeys.length !== boundValues.length) throw new Error('entryHashes: boundKeys 와 boundValues 길이가 다르다');
  return {
    hLeaves: packedHash(revLeaves.map(() => 'bytes32'), revLeaves), hIdx: packedHash(slotIdx.map(() => 'uint256'), slotIdx), hSlots: packedHash(slotLeaves.map(() => 'bytes32'), slotLeaves),
    hBoundKeys: packedHash(boundKeys.map(() => 'uint256'), boundKeys), hBoundValues: packedHash(boundValues.map(() => 'uint256'), boundValues),
  };
}
export function publicationDigestV3Hashed({ canonicalChainId, canonicalLogAddress, revRoot, regRoot, epoch, hLeaves, hIdx, hSlots, hBoundKeys, hBoundValues }) {
  if (canonicalChainId === undefined || canonicalChainId === null || !canonicalLogAddress) throw new Error('publicationDigestV3: canonicalChainId·canonicalLogAddress 가 필요하다');
  if (!hBoundKeys || !hBoundValues) throw new Error('publicationDigestV3: hBoundKeys·hBoundValues 가 필요하다(entryHashes)');
  return ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
    ['bytes32', 'uint256', 'address', 'bytes32', 'bytes32', 'uint64', 'bytes32', 'bytes32', 'bytes32', 'bytes32', 'bytes32'],
    [DOMAIN_LOG_V3, BigInt(canonicalChainId), canonicalLogAddress, revRoot, regRoot, epoch, hLeaves, hIdx, hSlots, hBoundKeys, hBoundValues]));
}
export function publicationDigestV3({ revLeaves, slotIdx, slotLeaves, boundKeys = [], boundValues = [], ...rest }) {
  return publicationDigestV3Hashed({ ...rest, ...entryHashes({ revLeaves, slotIdx, slotLeaves, boundKeys, boundValues }) });
}
```
(`signPublicationV3` 는 그대로 — `publicationDigestV3` 를 부른다.)

- [ ] **Step 8: 테스트 헬퍼**

`tests/helpers/mode3_chain.mjs` 의 `publishV3`·`relayToMirror` 를 교체:

```js
/** V10 게시 헬퍼 — 테스트가 CIA 없이 캐노니컬 Mode3Log 에 두 root 를 올린다. 인자는 bigint, 서명은 ciaWallet.
 *  2026-10-25: boundKeys(bigint[])·boundValues(number[]) — 거울 공개 세션 counter. 돌려주는 p 에 그대로 들어 relayToMirror 가 넘긴다. */
export async function publishV3(log, ciaWallet, { revRoot, regRoot, epoch, revLeaves = [], slotIdx = [], slotLeaves = [], boundKeys = [], boundValues = [] }) {
  const b = rootToBytes32;
  const p = { revRoot: b(revRoot), regRoot: b(regRoot), epoch, revLeaves: revLeaves.map(b), slotIdx, slotLeaves: slotLeaves.map(b), boundKeys: boundKeys.map(BigInt), boundValues: boundValues.map(Number) };
  const sig = await signPublicationV3(ciaWallet, { ...(await canonOf(log, ciaWallet.provider)), ...p });
  await (await log.connect(ciaWallet).publish(p.revRoot, p.regRoot, epoch, p.revLeaves, slotIdx, p.slotLeaves, p.boundKeys, p.boundValues, sig)).wait();
  return { sig, p };
}

/** V10: 캐노니컬에 이미 올라간 게시(p, sig)를 거울에 중계한다 — 같은 서명이 거울에도 그대로 유효하다. bound 배열은 그대로 넘긴다. */
export async function relayToMirror(mirror, signer, { p, sig }) {
  const h = entryHashes(p);
  await (await mirror.connect(signer).publish(p.revRoot, p.regRoot, p.epoch, h.hLeaves, h.hIdx, h.hSlots, p.boundKeys ?? [], p.boundValues ?? [], sig)).wait();
}
```

- [ ] **Step 9: 기존 publish 호출 전부 찾기**

Run: `grep -rn "\.publish(" test tests lib cia.js scripts --include=*.mjs --include=*.js --include=*.cjs | grep -v node_modules`
Expected: 목록이 나온다. `test/Mode3Log.test.mjs`·`test/Mode3Mirror.test.mjs` 는 이 태스크에서, `test/Mode3Wallet.test.mjs`·`scripts/bench_baselines.cjs` 는 Task 3, `cia.js` 는 Task 4 에서 고친다. `tests/helpers/mode3_chain.mjs` 는 Step 8 에서 고쳤다. 그 밖의 파일(예: `lib/mode3_registry_sync.js`·`lib/mode3_rcl_sync.js` 는 이벤트만 읽어 해당 없음)이 `publish` 를 **호출** 하면 이 태스크에서 같은 방식으로 `boundKeys, boundValues` 두 인자를 `sig` 앞에 넣는다.

- [ ] **Step 10: Mode3Log 테스트 갱신·추가**

`test/Mode3Log.test.mjs`: 기존 모든 `log.publish(a, b, c, d, e, f, sig)` 호출을 `log.publish(a, b, c, d, e, f, [], [], sig)` 로, `log.digestFor(…6개)` 를 `log.digestFor(…6개, [], [])` 로, `DOMAIN` 단언을 `'MODE3_LOG_V4'` 로 바꾼다(`other.publish` 도 같다). 파일 끝(`describe` 닫기 전)에 추가:

```js
  // ── 2026-10-25 root 유효 창 §2.1: root 이력 ──
  const P = (over) => ({ revRoot: emptyRev, regRoot: emptyReg, revLeaves: [], slotIdx: [], slotLeaves: [], boundKeys: [], boundValues: [], ...over });
  const pub = async (p) => log.publish(p.revRoot, p.regRoot, p.epoch, p.revLeaves, p.slotIdx, p.slotLeaves, p.boundKeys, p.boundValues, await sign(cia, p));
  const boundEvents = (rc) => rc.logs.map((l) => { try { return log.interface.parseLog(l); } catch { return null; } }).filter((e) => e?.name === 'SessionBoundPublished');

  it('root 이력: 대체된 root 는 대체 블록을 기억하고 isAcceptableRevRoot(root, G) 가 G 블록 동안 참, 최신 root 는 늘 참, 모르는 root 는 거짓', async () => {
    await (await pub(P({ revRoot: b32(1n), epoch: 1n }))).wait();
    const h = BigInt(await ethers.provider.getBlockNumber());
    expect(await log.revSupersededAt(emptyRev)).to.equal(h);
    expect(await log.revSupersededAt(b32(1n))).to.equal(0n);                 // 최신은 0
    expect(await log.isAcceptableRevRoot(b32(1n), 0)).to.equal(true);
    expect(await log.isAcceptableRevRoot(emptyRev, 3)).to.equal(true);        // 같은 블록
    await ethers.provider.send('hardhat_mine', ['0x3']);                      // h + 3 == 경계 — 포함
    expect(await log.isAcceptableRevRoot(emptyRev, 3)).to.equal(true);
    await ethers.provider.send('hardhat_mine', ['0x1']);                      // h + 4 — 창 밖
    expect(await log.isAcceptableRevRoot(emptyRev, 3)).to.equal(false);
    expect(await log.isAcceptableRevRoot(emptyRev, 0)).to.equal(false);
    expect(await log.isAcceptableRevRoot(b32(999n), 1000)).to.equal(false);
    // 등록부 root 는 바뀌지 않았다 — 이력에 들어가지 않는다
    expect(await log.regSupersededAt(emptyReg)).to.equal(0n);
    expect(await log.isAcceptableRegRoot(emptyReg, 0)).to.equal(true);
  });
  it('등록부 root 도 같은 규칙(isAcceptableRegRoot)', async () => {
    await (await pub(P({ regRoot: b32(7n), epoch: 1n }))).wait();
    const h = BigInt(await ethers.provider.getBlockNumber());
    expect(await log.regSupersededAt(emptyReg)).to.equal(h);
    expect(await log.isAcceptableRegRoot(emptyReg, 2)).to.equal(true);
    await ethers.provider.send('hardhat_mine', ['0x3']);
    expect(await log.isAcceptableRegRoot(emptyReg, 2)).to.equal(false);
    expect(await log.isAcceptableRegRoot(b32(7n), 0)).to.equal(true);
    expect(await log.revSupersededAt(emptyRev)).to.equal(0n);
  });
  it('하트비트(같은 root 재게시)는 이력을 건드리지 않는다 — 현재 root 의 supersededAt 은 0 그대로, lastPublishedBlock 만 바뀐다', async () => {
    await (await pub(P({ epoch: 1n }))).wait();
    await ethers.provider.send('hardhat_mine', ['0x2']);
    await (await pub(P({ epoch: 2n }))).wait();
    expect(await log.revSupersededAt(emptyRev)).to.equal(0n);
    expect(await log.regSupersededAt(emptyReg)).to.equal(0n);
    expect(await log.isAcceptableRevRoot(emptyRev, 0)).to.equal(true);
    expect(await log.lastPublishedBlock()).to.equal(BigInt(await ethers.provider.getBlockNumber()));
  });
  it('링 버퍼: 옛 root 는 최근 ROOT_HISTORY(16)개만 — 17번째 대체에서 가장 오래된 root 가 밀려나 창 안이라도 거절', async () => {
    expect(await log.ROOT_HISTORY()).to.equal(16n);
    for (let i = 1n; i <= 17n; i++) await (await pub(P({ revRoot: b32(i), epoch: i }))).wait();
    // 대체된 순서: emptyRev, 1, 2, …, 16 (17 은 최신). 17개 중 가장 오래된 emptyRev 가 밀려났다.
    expect(await log.revSupersededAt(emptyRev)).to.equal(0n);
    expect(await log.isAcceptableRevRoot(emptyRev, 1000)).to.equal(false);
    expect(await log.isAcceptableRevRoot(b32(1n), 1000)).to.equal(true);
    expect(await log.isAcceptableRevRoot(b32(16n), 1000)).to.equal(true);
    expect(await log.isAcceptableRevRoot(b32(17n), 0)).to.equal(true);
  });

  // ── §2.2 세션별 counter ──
  it('세션별 counter: (pk_i, c) 를 c+1 로 저장·이벤트; 낮추기만(올리기·같은 값은 revert 없이 무시); 중복 pk_i 는 순서와 무관하게 최솟값', async () => {
    const k1 = 0xabcn, k2 = 0xdefn, k3 = 0x123n;
    const tx1 = await pub(P({ epoch: 1n, boundKeys: [k1, k2, k3, k3], boundValues: [5, 0, 5, 3] }));
    await expect(tx1).to.emit(log, 'SessionBoundPublished').withArgs(k1, 5, 1n);
    await expect(tx1).to.emit(log, 'SessionBoundPublished').withArgs(k2, 0, 1n);
    expect(await log.sessionBoundOf(k1)).to.equal(6n); expect(await log.sessionBoundOf(k2)).to.equal(1n);
    expect(await log.sessionBoundOf(k3)).to.equal(4n, '[5, 3] → 3 + 1');
    const rc2 = await (await pub(P({ epoch: 2n, boundKeys: [k1, k1, k2, k3, k3], boundValues: [7, 3, 0, 1, 2] }))).wait();   // k1: 7 무시·3 적용, k2: 같은 값 무시, k3: [1, 2] → 1
    const evs = boundEvents(rc2);
    expect(evs.map((e) => [e.args.pk_i, e.args.bound])).to.deep.equal([[k1, 3n], [k3, 1n]]);
    expect(await log.sessionBoundOf(k1)).to.equal(4n); expect(await log.sessionBoundOf(k2)).to.equal(1n); expect(await log.sessionBoundOf(k3)).to.equal(2n);
    expect(await log.sessionBoundOf(0x111n)).to.equal(0n);
  });
  it('최댓값 c = 2^32−1 은 2^32 로 저장된다(uint32 넘침으로 0 이 되지 않는다)', async () => {
    await (await pub(P({ epoch: 1n, boundKeys: [1n], boundValues: [4294967295] }))).wait();
    expect(await log.sessionBoundOf(1n)).to.equal(4294967296n);
  });
  it('bound 배열 길이 불일치는 LengthMismatch, 서명 뒤 bound 를 바꾸면 BadSignature, digestFor 가 JS 와 같다', async () => {
    const bad = P({ epoch: 1n, boundKeys: [1n], boundValues: [] });
    await expect(log.publish(bad.revRoot, bad.regRoot, 1n, [], [], [], [1n], [], await sign(cia, { ...bad, boundKeys: [], boundValues: [] }))).to.be.revertedWithCustomError(log, 'BadSignature');   // JS entryHashes 는 길이 불일치를 던지므로 빈 배열로 서명 → 서명 불일치가 먼저
    const p = P({ epoch: 1n, boundKeys: [1n, 2n], boundValues: [4, 5] });
    const sig = await sign(cia, p);
    await expect(log.publish(p.revRoot, p.regRoot, 1n, [], [], [], [1n, 2n], [4, 6], sig)).to.be.revertedWithCustomError(log, 'BadSignature');
    await expect(log.publish(p.revRoot, p.regRoot, 1n, [], [], [], [1n, 3n], [4, 5], sig)).to.be.revertedWithCustomError(log, 'BadSignature');
    expect(await log.digestFor(p.revRoot, p.regRoot, 1n, [], [], [], [1n, 2n], [4, 5])).to.equal(publicationDigestV3({ ...(await canon()), ...p }));
    await expect(log.publish(p.revRoot, p.regRoot, 1n, [], [], [], [1n, 2n], [4, 5], sig)).to.not.be.reverted;
  });
  it('LengthMismatch: 서명이 맞아도 bound 두 배열 길이가 다르면 거절(컨트랙트가 직접 확인한다)', async () => {
    // JS 쪽은 길이 불일치를 던지므로 다이제스트를 손으로 만든다 — 컨트랙트 digestFor 로 받아 서명한다.
    const inner = await log.digestFor(emptyRev, emptyReg, 1n, [], [], [], [1n], []);
    const sig = await cia.signMessage(ethers.getBytes(inner));
    await expect(log.publish(emptyRev, emptyReg, 1n, [], [], [], [1n], [], sig)).to.be.revertedWithCustomError(log, 'LengthMismatch');
  });
```

- [ ] **Step 11: Mode3Mirror 테스트 갱신·추가**

`test/Mode3Mirror.test.mjs`: 기존 `mirror.publish(…, h.hSlots, sig)` 를 `mirror.publish(…, h.hSlots, [], [], sig)` 로, `log.publish(…6개, sig)` 를 `log.publish(…6개, [], [], sig)` 로, `mirror.digestFor(…6개)` 를 `mirror.digestFor(…6개, h.hBoundKeys, h.hBoundValues)` 로, `log.digestFor(…6개)` 를 `log.digestFor(…6개, [], [])` 로 바꾼다. 추가:

```js
  it('bound 배열은 거울도 그대로 받아 sessionBoundOf 에 적고(c+1), 다이제스트가 캐노니컬과 같다; 서명 뒤 바꾸면 BadSignature', async () => {
    const p = { revRoot: b32(9n), regRoot: b32(8n), epoch: 1n, revLeaves: [], slotIdx: [], slotLeaves: [], boundKeys: [0xaaan, 0xbbbn], boundValues: [2, 0] };
    const sig = await signPublicationV3(cia, { ...canon, ...p });
    const h = entryHashes(p);
    expect(await mirror.digestFor(p.revRoot, p.regRoot, p.epoch, h.hLeaves, h.hIdx, h.hSlots, h.hBoundKeys, h.hBoundValues)).to.equal(await log.digestFor(p.revRoot, p.regRoot, p.epoch, [], [], [], p.boundKeys, p.boundValues));
    await expect(mirror.publish(p.revRoot, p.regRoot, 1n, h.hLeaves, h.hIdx, h.hSlots, p.boundKeys, [2, 1], sig)).to.be.revertedWithCustomError(mirror, 'BadSignature');
    const tx = mirror.connect(relayer).publish(p.revRoot, p.regRoot, 1n, h.hLeaves, h.hIdx, h.hSlots, p.boundKeys, p.boundValues, sig);
    await expect(tx).to.emit(mirror, 'SessionBoundPublished').withArgs(0xaaan, 2, 1n);
    expect(await mirror.sessionBoundOf(0xaaan)).to.equal(3n); expect(await mirror.sessionBoundOf(0xbbbn)).to.equal(1n);
    expect(await mirror.revSupersededAt(emptyRev)).to.equal(BigInt(await ethers.provider.getBlockNumber()));
    expect(await mirror.isAcceptableRevRoot(emptyRev, 5)).to.equal(true);
  });
  it('epoch 을 건너뛴 중계에도 그 페이로드의 bound 가 실린다(IdP 가 누적해 다시 보낸다 — 건너뛴 게시의 값은 여기서 유실되지 않는다)', async () => {
    const p = { revRoot: b32(1n), regRoot: b32(2n), epoch: 5n, revLeaves: [], slotIdx: [], slotLeaves: [], boundKeys: [7n], boundValues: [4] };
    const h = entryHashes(p);
    await mirror.publish(p.revRoot, p.regRoot, 5n, h.hLeaves, h.hIdx, h.hSlots, p.boundKeys, p.boundValues, await signPublicationV3(cia, { ...canon, ...p }));
    expect(await mirror.epoch()).to.equal(5n);
    expect(await mirror.sessionBoundOf(7n)).to.equal(5n);
  });
```

- [ ] **Step 12: 두 테스트 파일 실행**

Run: `npx hardhat test test/Mode3Log.test.mjs test/Mode3Mirror.test.mjs`
Expected: 모두 PASS. (`test/Mode3Wallet.test.mjs` 는 아직 옛 `publish` 호출이라 깨져 있다 — Task 3 가 고친다. 이 단계에서 전체 `npx hardhat test` 는 돌리지 않는다.)

- [ ] **Step 13: 커밋**

```bash
git add contracts/Mode3RootHistory.sol contracts/IMode3Roots.sol contracts/Mode3Log.sol contracts/Mode3Mirror.sol hardhat.config.cjs lib/mode3_log.js tests/helpers/mode3_chain.mjs test/Mode3Log.test.mjs test/Mode3Mirror.test.mjs
git commit -m "feat(mode3-log): Mode3RootHistory 공통 베이스 — root 유효 창(이력 16)·세션별 counter(sessionBoundOf) 게시, 도메인 V4" -m "Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>" -m "Claude-Session: https://claude.ai/code/session_013qGSXZTftBJSB1M4XpPRHN" -- contracts/Mode3RootHistory.sol contracts/IMode3Roots.sol contracts/Mode3Log.sol contracts/Mode3Mirror.sol hardhat.config.cjs lib/mode3_log.js tests/helpers/mode3_chain.mjs test/Mode3Log.test.mjs test/Mode3Mirror.test.mjs
```

---

### Task 3: `Mode3Wallet` 창 검사 + 거울 상한 + 팩토리 `rootWindow`

**Files:**
- Modify: `contracts/Mode3Wallet.sol`, `contracts/Mode3WalletFactory.sol`, `lib/mode3_onchain.js:20-80, 236-243`, `scripts/bench_baselines.cjs:32, 104-106`
- Test: `test/Mode3Wallet.test.mjs`

**Interfaces:**
- Consumes(Task 2): `IMode3Roots.isAcceptableRevRoot/RegRoot(bytes32, uint64)`, `sessionBoundOf(uint256) → uint256`; `Mode3Log.publish(…, boundKeys, boundValues, sig)`.
- Produces(Task 5 가 쓴다): `Mode3Wallet.rootWindow() view returns (uint64)`, `Mode3Wallet.effectiveSessionBound(uint256 pk_i) view returns (uint256)`, `Mode3WalletFactory.rootWindow() view returns (uint64)`; 생성자 인자는 둘 다 기존 인자 **뒤에** `uint64 _rootWindow`; JS `ROOT_WINDOW_DEFAULT = 20n`, `FACTORY_ROOT_WINDOW_BAND = { min: 0n, max: 200n }`, `deployFactory(signer, { …, rootWindow = ROOT_WINDOW_DEFAULT })`, `WALLET_ABI`/`FACTORY_ABI` 에 `rootWindow()`·`effectiveSessionBound(uint256)`.

- [ ] **Step 1: 지갑 컨트랙트**

`contracts/Mode3Wallet.sol`:
- `uint64 public immutable maxLifetime;` 줄 뒤에:

```solidity
    uint64 public immutable rootWindow;   // 블록. 대체된 root 를 이만큼 더 받는다(2026-10-25 root 유효 창 §3) — 타 사용자의 폐기·등록이 내 진행 중 거래를 튕기지 않게. 0 = 최신만
```
- 생성자 시그니처 끝에 `, uint64 _rootWindow` 를 더하고 본문에 `rootWindow = _rootWindow;`.
- `execute` 의 `uint256 bnd = sessionBound[pub[2]];` 를 `uint256 bnd = effectiveSessionBound(pub[2]);` 로 바꾸고 그 위 주석에 `거울 공개 값(log.sessionBoundOf)과 자기 호출 값 중 낮은 쪽(2026-10-25 §3)` 를 덧붙인다.
- `setSessionBound` 함수 뒤에 추가:

```solidity
    /// @notice 거래 경로에 적용되는 세션 상한(저장 인코딩 c + 1, 0 = 없음, 2026-10-25 root 유효 창 §3): 자기 호출 값(sessionBound)과
    ///   거울이 공개한 값(log.sessionBoundOf) 중 0 이 아닌 더 낮은 쪽. 거울 값이 정본이고 자기 호출은 선택 기능이다(결정 1).
    function effectiveSessionBound(uint256 pk_i) public view returns (uint256) {
        uint256 self = sessionBound[pk_i];
        uint256 mirror = log.sessionBoundOf(pk_i);
        if (self == 0) return mirror;
        if (mirror == 0) return self;
        return self < mirror ? self : mirror;
    }
```
- `_checkStatement` 의 두 root 검사를 교체:

```solidity
        // 2026-10-25 root 유효 창 §3: 최신 root 또는 대체된 지 rootWindow 블록 이내의 root. 폐기된 세션은 창 안에서도 거울의
        // sessionBoundOf(위 execute 의 effectiveSessionBound)가 막고, 창이 닫힌 뒤에는 회로의 구간 비멤버십이 막는다.
        bytes32 root = bytes32(pub[6]);
        if (!log.isAcceptableRevRoot(root, rootWindow)) revert StaleRevocationRoot(root);
        bytes32 reg = bytes32(pub[7]);
        if (!log.isAcceptableRegRoot(reg, rootWindow)) revert StaleRegistryRoot(reg);
```

- [ ] **Step 2: 팩토리**

`contracts/Mode3WalletFactory.sol`: `uint64 public immutable maxLifetime;` 뒤에 `uint64 public immutable rootWindow;   // 2026-10-25 root 유효 창 §3 — 지갑 생성자 마지막 인자`. 생성자 끝에 `, uint64 _rootWindow` 와 `rootWindow = _rootWindow;`. `_initCode` 의 `abi.encode(…, maxRootAge, maxLifetime)` 와 `deploy` 의 `new Mode3Wallet{salt: …}(…, maxRootAge, maxLifetime)` 둘 다 끝에 `, rootWindow` 를 더한다.

- [ ] **Step 3: 컴파일**

Run: `npx hardhat compile`
Expected: 성공.

- [ ] **Step 4: JS 상수·ABI·배포 헬퍼**

`lib/mode3_onchain.js`: `MAX_LIFETIME_DEFAULT` 줄 뒤에

```js
/** 2026-10-25 root 유효 창 §6: 대체된 root 를 이만큼의 블록 동안 더 받는다(타 사용자의 폐기·등록이 내 진행 중 거래를 튕기지 않게). 데모(automine) 기본 20. */
export const ROOT_WINDOW_DEFAULT = 20n;
```
`FACTORY_MAX_LIFETIME_BAND` 줄 뒤에

```js
/** 지갑이 받아들이는 rootWindow 범위 — 0(옛 동작: 최신만) 부터 maxRootAge 상한과 같은 200 까지. 너무 크면 은퇴한 자격증명의 옛 π 가 그만큼
 *  오래 통과한다(2026-10-25 설계 §7 한계 2). 세션 폐기는 창과 무관하게 거울 counter 가 막으므로 아래쪽은 0 도 허용한다. */
export const FACTORY_ROOT_WINDOW_BAND = Object.freeze({ min: 0n, max: 2n * MAX_ROOT_AGE_DEFAULT });     // 0..200 블록
```
`WALLET_ABI` 의 `'function maxLifetime() view returns (uint64)',` 뒤에 `'function rootWindow() view returns (uint64)',` 와 `'function effectiveSessionBound(uint256 pk_i) view returns (uint256)',`. `FACTORY_ABI` 의 `maxLifetime()` 뒤에 `'function rootWindow() view returns (uint64)',`. `deployFactory`:

```js
export async function deployFactory(signer, { verifierAddress, arid, pkCIA, pkTrace, logAddress, maxRootAge = MAX_ROOT_AGE_DEFAULT, maxLifetime = MAX_LIFETIME_DEFAULT, rootWindow = ROOT_WINDOW_DEFAULT }) {
  const { abi, bytecode } = readArtifact('Mode3WalletFactory');
  const c = await new ethers.ContractFactory(abi, bytecode, signer).deploy(
    verifierAddress, BigInt(arid), BigInt(pkCIA.x), BigInt(pkCIA.y), BigInt(pkTrace.x), BigInt(pkTrace.y), logAddress, BigInt(maxRootAge), BigInt(maxLifetime), BigInt(rootWindow),
  );
  await c.waitForDeployment();
  return c.getAddress();
}
```
`scripts/bench_baselines.cjs`: 32행을 `const MAX_ROOT_AGE = 100n, MAX_LIFETIME = 400n, ROOT_WINDOW = 20n;` 로, 팩토리 `deploy(…, MAX_ROOT_AGE, MAX_LIFETIME,` 를 `…, MAX_ROOT_AGE, MAX_LIFETIME, ROOT_WINDOW,` 로. `Mode3Log` 생성자는 그대로다.

- [ ] **Step 5: 지갑 테스트 — 공통 부분 갱신**

`test/Mode3Wallet.test.mjs`:
- import 에 `ROOT_WINDOW_DEFAULT` 추가(`lib/mode3_onchain.js` 에서).
- `deployStack(st, { arid = st.fx.arid, maxRootAge = MAX_ROOT_AGE_DEFAULT, maxLifetime = MAX_LIFETIME_DEFAULT, rootWindow = ROOT_WINDOW_DEFAULT } = {})`, `Factory.deploy(…, maxRootAge, maxLifetime, rootWindow)`.
- `withInput` 정의 뒤에 헬퍼:

```js
  /** 테스트용 게시 — 두 root 와 bound 배열을 cia 서명으로 올린다(2026-10-25: publish 에 boundKeys/boundValues 가 추가됐다). 리프·슬롯은 비운다. */
  async function publishRoots(log, cia, { revRoot, regRoot, epoch, slotIdx = [], slotLeaves = [], boundKeys = [], boundValues = [] }) {
    const p = { revRoot, regRoot, epoch, revLeaves: [], slotIdx, slotLeaves, boundKeys, boundValues };
    const sig = await signPublicationV3(cia, { canonicalChainId: await chainId(), canonicalLogAddress: await log.getAddress(), ...p });
    await (await log.publish(revRoot, regRoot, epoch, [], slotIdx, slotLeaves, boundKeys, boundValues, sig)).wait();
  }
```
- 'root 게시가 maxRootAge 블록보다 오래되면 RootTooOld…' 케이스의 서명·`log.publish(revRoot, regRoot, 1n, [], [], [], sig)` 를 `await publishRoots(log, cia, { revRoot, regRoot, epoch: 1n });` 로.
- V10 거울 케이스: `log.publish(newRoot, initReg, 1n, [], [], [], sigCanon)` → `log.publish(newRoot, initReg, 1n, [], [], [], [], [], sigCanon)`; `mirror.publish(newRoot, initReg, 1n, h.hLeaves, h.hIdx, h.hSlots, sigCanon)` → `mirror.publish(newRoot, initReg, 1n, h.hLeaves, h.hIdx, h.hSlots, [], [], sigCanon)`; 팩토리 `deploy(…, MAX_ROOT_AGE_DEFAULT, MAX_LIFETIME_DEFAULT)` → `…, MAX_ROOT_AGE_DEFAULT, MAX_LIFETIME_DEFAULT, 0n)` (**rootWindow 0** — 이 케이스는 "거울이 전진하면 옛 π 는 바로 거절" 을 보는 것이므로 창을 끈다) 그리고 케이스 제목 끝에 `(rootWindow 0)` 을 덧붙인다.
- Step 6 의 `grep` 결과에 남는 다른 `.publish(` 호출도 같은 방식(`[], []` 를 `sig` 앞에)으로 고친다.

- [ ] **Step 6: 지갑 테스트 — 두 stale 케이스를 창 버전으로 교체**

'root 가 게시로 바뀌면 옛 π 는 StaleRevocationRoot' 케이스를 다음으로 교체:

```js
  it('root 유효 창(2026-10-25 §3): 폐기 root 가 게시로 바뀌어도(타 사용자의 폐기) rootWindow 블록 안이면 옛 π 가 통과, 창이 닫히면 StaleRevocationRoot', async () => {
    const { wallet, log, cia } = await deployStack(ST, { rootWindow: 5n });
    await publishRoots(log, cia, { revRoot: rootToBytes32(12345n), regRoot: await log.regRoot(), epoch: 1n });   // ST 의 root 는 이제 "대체된 root"
    const sp = await signedPayload(ST, wallet);
    await expect(wallet.execute(sp.payload, sp.sig, ST.a, ST.b, ST.c, ST.pub)).to.not.be.reverted;   // 대체 다음 블록 — 창 안
    // nonce 1 의 새 π — 픽스처 트리는 그대로라 revRoot 는 여전히 옛 root 다. 창(5블록)을 넘긴다.
    const st1 = withInput(await statement({ session: ST.session, counter: 1n }));
    await ethers.provider.send('hardhat_mine', ['0x6']);
    const sp1 = await signedPayload(st1, wallet);
    await expect(wallet.execute(sp1.payload, sp1.sig, st1.a, st1.b, st1.c, st1.pub)).to.be.revertedWithCustomError(wallet, 'StaleRevocationRoot');
  });
  it('rootWindow = 0 이면 예전처럼 최신 root 만 받는다(대체 다음 블록부터 StaleRevocationRoot)', async () => {
    const { wallet, log, cia } = await deployStack(ST, { rootWindow: 0n });
    await publishRoots(log, cia, { revRoot: rootToBytes32(12345n), regRoot: await log.regRoot(), epoch: 1n });
    const sp = await signedPayload(ST, wallet);
    await expect(wallet.execute(sp.payload, sp.sig, ST.a, ST.b, ST.c, ST.pub)).to.be.revertedWithCustomError(wallet, 'StaleRevocationRoot');
  });
```
'V9: 등록부 root 가 바뀌면(슬롯 바꿔치기·은퇴) 옛 π 는 StaleRegistryRoot' 케이스를 다음으로 교체:

```js
  it('V9 + 창: 등록부 root 가 바뀌어도(다른 사용자의 등록·은퇴) 창 안이면 통과, 창이 닫히면 StaleRegistryRoot', async () => {
    const { wallet, log, cia } = await deployStack(ST, { rootWindow: 5n });
    await publishRoots(log, cia, { revRoot: await log.revRoot(), regRoot: rootToBytes32(777n), epoch: 1n, slotIdx: [7], slotLeaves: [rootToBytes32(424242n)] });
    const sp = await signedPayload(ST, wallet);
    await expect(wallet.execute(sp.payload, sp.sig, ST.a, ST.b, ST.c, ST.pub)).to.not.be.reverted;
    const st1 = withInput(await statement({ session: ST.session, counter: 1n }));
    await ethers.provider.send('hardhat_mine', ['0x6']);
    const sp1 = await signedPayload(st1, wallet);
    await expect(wallet.execute(sp1.payload, sp1.sig, st1.a, st1.b, st1.c, st1.pub)).to.be.revertedWithCustomError(wallet, 'StaleRegistryRoot');
  });
```

- [ ] **Step 7: 지갑 테스트 — 거울 상한·min·getter 추가**

`describe` 끝(마지막 `it` 뒤)에 추가:

```js
  // ── 2026-10-25 root 유효 창 §3: 거울 공개 상한(sessionBoundOf) ──
  it('거울 공개 상한: 게시 페이로드의 (pk_i, c) 만으로 nonce ≥ c 가 SessionBounded — 자기 호출 없이, root 창과 무관하게', async () => {
    const { wallet, log, cia } = await deployStack(ST);
    const pk = BigInt(ST.session.address);
    await publishRoots(log, cia, { revRoot: await log.revRoot(), regRoot: await log.regRoot(), epoch: 1n, boundKeys: [pk], boundValues: [1] });   // c = 1: nonce 0 만 허용
    expect(await log.sessionBoundOf(pk)).to.equal(2n);
    expect(await wallet.effectiveSessionBound(pk)).to.equal(2n);
    const p0 = await signedPayload(ST, wallet);
    await (await wallet.execute(p0.payload, p0.sig, ST.a, ST.b, ST.c, ST.pub)).wait();   // nonce 0 < 1
    const st1 = withInput(await statement({ session: ST.session, counter: 1n }));
    const p1 = await signedPayload(st1, wallet);
    await expect(wallet.execute(p1.payload, p1.sig, st1.a, st1.b, st1.c, st1.pub)).to.be.revertedWithCustomError(wallet, 'SessionBounded').withArgs(pk, 1n);
  });
  it('자기 호출 상한과 거울 상한 중 더 낮은 값이 적용된다(effectiveSessionBound)', async () => {
    const s1 = ethers.Wallet.createRandom(), s2 = ethers.Wallet.createRandom();
    const A0 = withInput(await statement({ session: s1, counter: 0n }));
    const { wallet, walletAddr, log, cia } = await deployStack(A0);
    const pk1 = BigInt(s1.address);
    expect(await wallet.effectiveSessionBound(pk1)).to.equal(0n);
    await publishRoots(log, cia, { revRoot: await log.revRoot(), regRoot: await log.regRoot(), epoch: 1n, boundKeys: [pk1], boundValues: [3] });   // 거울 3 → 4
    expect(await wallet.effectiveSessionBound(pk1)).to.equal(4n);
    const B0 = withInput(await statement({ session: s2, counter: 0n }));   // s2 가 자기 호출로 s1 의 상한 1 → min(2, 4) = 2
    let p = await signedPayload(B0, wallet, { to: walletAddr, data: wallet.interface.encodeFunctionData('setSessionBound', [pk1, 1]) });
    await (await wallet.execute(p.payload, p.sig, B0.a, B0.b, B0.c, B0.pub)).wait();
    expect(await wallet.sessionBound(pk1)).to.equal(2n);
    expect(await wallet.effectiveSessionBound(pk1)).to.equal(2n);
    await publishRoots(log, cia, { revRoot: await log.revRoot(), regRoot: await log.regRoot(), epoch: 2n, boundKeys: [pk1], boundValues: [0] });   // 거울이 0 으로 더 낮추면 → 1
    expect(await wallet.effectiveSessionBound(pk1)).to.equal(1n);
    const A1 = withInput(await statement({ session: s1, counter: 1n }));
    p = await signedPayload(A1, wallet);
    await expect(wallet.execute(p.payload, p.sig, A1.a, A1.b, A1.c, A1.pub)).to.be.revertedWithCustomError(wallet, 'SessionBounded').withArgs(pk1, 0n);
  });
  it('rootWindow 는 팩토리 생성자 인자 그대로 팩토리·지갑에 박힌다', async () => {
    const { wallet, factory } = await deployStack(ST, { rootWindow: 7n });
    expect(await factory.rootWindow()).to.equal(7n);
    expect(await wallet.rootWindow()).to.equal(7n);
  });
```

- [ ] **Step 8: contract 그룹 전체 실행**

Run: `bash scripts/run_tests.sh contract`
Expected: 모두 PASS(`test/Mode3Wallet.test.mjs` 의 다른 케이스는 `publishRoots` 외 변경이 없어 그대로 통과해야 한다; `test/AttrGate.test.mjs`·`test/Mode3ReferenceCode.test.mjs` 가 팩토리를 직접 배포하면 10번째 인자 누락으로 실패한다 — 그때는 `deployFactory` 또는 `…, ROOT_WINDOW_DEFAULT)` 로 고치고 이 커밋에 포함한다).

- [ ] **Step 9: 커밋**

```bash
git add contracts/Mode3Wallet.sol contracts/Mode3WalletFactory.sol lib/mode3_onchain.js scripts/bench_baselines.cjs test/Mode3Wallet.test.mjs
git commit -m "feat(mode3-wallet): rootWindow 창 검사(isAcceptable*Root) + 거울 세션 상한(effectiveSessionBound = min(자기 호출, 거울))" -m "Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>" -m "Claude-Session: https://claude.ai/code/session_013qGSXZTftBJSB1M4XpPRHN" -- contracts/Mode3Wallet.sol contracts/Mode3WalletFactory.sol lib/mode3_onchain.js scripts/bench_baselines.cjs test/Mode3Wallet.test.mjs
```
(Step 8 에서 다른 test/ 파일을 고쳤으면 pathspec 에 함께 넣는다.)

---

### Task 4: IdP — 폐기 때 `pk_i` 결속, `pendingBounds`, 게시·중계 페이로드

**Files:**
- Modify: `lib/mode3_revocation.js`, `lib/mode3_cia_state.js:14-22, 33-39`, `cia.js`(`/cia/revoke` ~1009-1072, `publishNow` ~1129-1206, `initMirrors`/`sendMirrorTx`/`relayMirror`/`relayAll` ~1249-1346, `/cia/admin/revoked_sessions` ~1428-1437)
- Test: `tests/test_mode3_revocation_tree.js`(unit), `tests/test_mode3_cia_state.js`(unit), `tests/test_cia_revoke_bound.mjs`(chain)

**Interfaces:**
- Consumes(Task 2): `MODE3_LOG_ABI`/`MODE3_MIRROR_ABI` 새 `publish`, `signPublicationV3({ …, boundKeys, boundValues })`, `entryHashes` 의 `hBoundKeys/hBoundValues`, 컨트랙트 `sessionBoundOf(uint256)`.
- Produces(Task 5 가 쓴다): `lib/mode3_revocation.js` 의 `revokeBindMessage({ uid, Cf_s, bound, nonce }) → string`, `signRevokeBind(sessionPrivKeyHex, fields) → Promise<string>`, `verifyRevokeBind(pk_iDec, fields, sig_i) → boolean`, `REVOKE_BIND_PREFIX = 'MODE3_REVOKE_BIND_V1'`; `/cia/revoke scope=session` 본문 선택 필드 `pk_i`(10진 < 2^160)·`sig_i`(둘 다 또는 둘 다 없음), 응답 `mirrorBound: boolean`, 오류 `400 { reason: 'bad_session_signature' }`; `/cia/publish` 응답 `bounds: number`; `/cia/admin/revoked_sessions` 항목에 `pk_i: string|null`; 상태 `state.pendingBounds: [{ pk_i, bound, epoch: string|null }]`.

- [ ] **Step 1: 결속 서명 헬퍼 + 단위 테스트(실패 확인)**

`tests/test_mode3_revocation_tree.js` 의 import 에 `revokeBindMessage, signRevokeBind, verifyRevokeBind` 를 더하고(`'../lib/mode3_revocation.js'` 에서) `import { ethers } from 'ethers';` 를 추가, 파일 끝에:

```js
// 2026-10-25 root 유효 창 §4: 세션키 결속 서명 — 폐기 요청의 pk_i 가 그 요청(uid·Cf_s·bound·nonce)의 것임을 sk_i 로 묶는다.
{
  const w = ethers.Wallet.createRandom();
  const f = { uid: 12345n, Cf_s: 777n, bound: 2n, nonce: 999n };
  assert.equal(revokeBindMessage(f), 'MODE3_REVOKE_BIND_V1|12345|777|2|999');
  assert.equal(revokeBindMessage({ uid: '12345', Cf_s: '777', bound: '2', nonce: '999' }), revokeBindMessage(f), '10진 문자열도 같은 메시지');
  const sig = await signRevokeBind(w.privateKey, f);
  const pk_i = BigInt(w.address).toString();
  assert.equal(verifyRevokeBind(pk_i, f, sig), true);
  assert.equal(verifyRevokeBind(BigInt(ethers.Wallet.createRandom().address).toString(), f, sig), false, '다른 pk_i');
  assert.equal(verifyRevokeBind(pk_i, { ...f, bound: 3n }, sig), false, '다른 bound');
  assert.equal(verifyRevokeBind(pk_i, { ...f, nonce: 1n }, sig), false, '다른 nonce');
  assert.equal(verifyRevokeBind(pk_i, f, '0xdead'), false, '깨진 서명은 false(throw 아님)');
  assert.equal(verifyRevokeBind('not-a-number', f, sig), false, '깨진 pk_i 도 false');
  console.log('ok   revokeBind 결속 서명');
}
```
Run: `node tests/test_mode3_revocation_tree.js`
Expected: FAIL — `revokeBindMessage` export 없음.

- [ ] **Step 2: 헬퍼 구현**

`lib/mode3_revocation.js` 상단 import 에 `import { ethers } from 'ethers';` 를 더하고 파일 끝에:

```js
// ---- 2026-10-25 root 유효 창 §4: 세션키 결속 서명 ----
// IdP 는 발급 때 pk_i 를 모른다(C_s 안에만 있다, D1). 폐기 때 지갑이 pk_i 를 알려 주되, 그 pk_i 가 **이 요청의** 것임을 세션키
// (secp256k1 sk_i) 서명으로 묶는다 — 묶지 않으면 sig_u 만 가진 사용자가 남의 pk_i 를 넣어 그 세션의 거울 counter 를 낮출 수 있다
// (낮추기만이라 되돌릴 수 없다). 메시지는 EIP-191 personal_sign 문자열, 값은 sk_u 서명(revokeSessionMessage)과 같은 것을 10진으로.
export const REVOKE_BIND_PREFIX = 'MODE3_REVOKE_BIND_V1';
export function revokeBindMessage({ uid, Cf_s, bound, nonce }) {
  return `${REVOKE_BIND_PREFIX}|${BigInt(uid)}|${BigInt(Cf_s)}|${BigInt(bound)}|${BigInt(nonce)}`;
}
/** 세션키(0x 개인키)로 결속 서명. */
export function signRevokeBind(sessionPrivKey, fields) {
  return new ethers.Wallet(sessionPrivKey).signMessage(revokeBindMessage(fields));
}
/** pk_i(10진, 160비트 주소) 가 sig_i 의 서명자인가. 형식이 깨졌으면 false(throw 하지 않는다). */
export function verifyRevokeBind(pk_i, fields, sig_i) {
  try {
    const addr = ethers.getAddress(ethers.toBeHex(BigInt(pk_i), 20));
    return ethers.verifyMessage(revokeBindMessage(fields), sig_i).toLowerCase() === addr.toLowerCase();
  } catch { return false; }
}
```
Run: `node tests/test_mode3_revocation_tree.js`
Expected: PASS(기존 단언 포함).

- [ ] **Step 3: 상태 스키마 `pendingBounds`**

`lib/mode3_cia_state.js`: 헤더 주석의 `sessions:[{ Cf_s, max_height, chainid, allowAgent, issuedAt, revokedAt, bound }]` 를 `sessions:[{ Cf_s, max_height, chainid, allowAgent, issuedAt, revokedAt, bound, pk_i? }]` 로 바꾸고 `/ lastPublication / signedEpochMax` 앞에 `/ pendingBounds [{ pk_i(10진), bound(10진), epoch(마지막으로 실린 게시 epoch, 10진)|null }] (2026-10-25 root 창 §4 — 거울 공개 세션 counter 대기열)` 를 넣는다. `defaultCiaState()` 의 `lastPublication: null,` 앞에 `pendingBounds: [],`. `migrateCiaState` 의 `state.lastPublication ??= null;` 줄 앞에 `state.pendingBounds ??= [];`. `lastPublication` 설명 줄(cia.js 196행 주석)에 `boundKeys, boundValues(10진 문자열 배열, 2026-10-25)` 를 덧붙인다.

`tests/test_mode3_cia_state.js` 끝에(파일의 기존 import 방식 그대로 `defaultCiaState`·`migrateCiaState`·`CIA_STATE_VERSION` 을 쓴다):

```js
// 2026-10-25 root 유효 창 §4: pendingBounds 는 v12 확장 — 기본값 [] 이고 옛 파일에는 ??= 로 채운다.
{
  assert.deepEqual(defaultCiaState().pendingBounds, []);
  const old = defaultCiaState(); delete old.pendingBounds;
  migrateCiaState(old);
  assert.deepEqual(old.pendingBounds, []);
  const kept = { ...defaultCiaState(), pendingBounds: [{ pk_i: '1', bound: '2', epoch: null }] };
  migrateCiaState(kept);
  assert.deepEqual(kept.pendingBounds, [{ pk_i: '1', bound: '2', epoch: null }], '있는 대기열은 보존');
  console.log('ok   pendingBounds 기본값·보존');
}
```
Run: `node tests/test_mode3_cia_state.js`
Expected: PASS.

- [ ] **Step 4: chain 테스트 먼저 작성(실패 확인)**

`tests/test_cia_revoke_bound.mjs` import 에 추가: `import fs from 'node:fs'; import path from 'node:path'; import { ethers } from 'ethers'; import { MODE3_LOG_ABI, MODE3_MIRROR_ABI } from '../lib/mode3_log.js'; import { signRevokeBind } from '../lib/mode3_revocation.js';`. 마지막 `await t(…)` 뒤(`try` 블록 안)에:

```js
  // ── 2026-10-25 root 유효 창 §4: pk_i + sig_i → 거울 공개 counter ──
  const logC = new ethers.Contract(cia.logAddress, MODE3_LOG_ABI, provider);
  const mirrorC = new ethers.Contract(cia.mirrorAddress, MODE3_MIRROR_ABI, provider);
  const stateJson = () => JSON.parse(fs.readFileSync(path.join(cia.dir, 'cia_state.json'), 'utf8'));   // 격리 인스턴스의 임시 상태 파일(테스트 소유)
  /** 사용자 폐기 요청 본문(sk_u 서명 + 선택 pk_i/sig_i). */
  async function revokeBody(iss, bound, { withBind = true, bindKey = iss.session.wallet.privateKey, bindBound = bound } = {}) {
    const Cf_s = iss.cred.Cf_s, nonce = randomScalar();
    const body = { uid: uid.toString(), scope: 'session', Cf_s, bound: bound.toString(), nonce: nonce.toString(), sig_u: await signRevokeSession(user.sk_u, uid, BigInt(Cf_s), bound, nonce) };
    if (withBind) { body.pk_i = iss.session.pk_i.toString(); body.sig_i = await signRevokeBind(bindKey, { uid, Cf_s, bound: bindBound, nonce }); }
    return body;
  }
  const fresh = async () => { const iss = await issueV11(cia, user, { arid, provider }); assert.equal(iss.r.status, 200, j(iss.r.body)); return iss; };

  await t('pk_i+sig_i 를 실은 사용자 폐기: 대기열(pendingBounds, 영속)에 들어가고 게시 → 캐노니컬 sessionBoundOf = bound+1 → 중계 → 거울도 같다 → 대기열에서 빠진다; 레코드·관리자 목록에 pk_i', async () => {
    const iss = await fresh(); const pk_i = iss.session.pk_i.toString();
    const r = await cia.post('/cia/revoke', await revokeBody(iss, 2n));
    assert.equal(r.status, 200, j(r.body)); assert.equal(r.body.inserted, true); assert.equal(r.body.mirrorBound, true);
    assert.deepEqual(stateJson().pendingBounds.find((e) => e.pk_i === pk_i), { pk_i, bound: '2', epoch: null });
    const list = (await cia.adminGet(`/cia/admin/sessions?uid=${uid}`)).body.sessions;
    assert.equal(list.find((s) => s.Cf_s === iss.cred.Cf_s).pk_i, pk_i, '레코드에 pk_i');
    const revoked = (await cia.adminGet('/cia/admin/revoked_sessions')).body.sessions;
    assert.equal(revoked.find((s) => s.Cf_s === iss.cred.Cf_s).pk_i, pk_i, '관리자 폐기 목록에 pk_i');
    assert.equal(await logC.sessionBoundOf(BigInt(pk_i)), 0n, '게시 전');
    const pub = await cia.adminPost('/cia/publish', {});
    assert.equal(pub.status, 200, j(pub.body)); assert.equal(pub.body.published, true); assert.ok(pub.body.bounds >= 1, j(pub.body));
    assert.equal(await logC.sessionBoundOf(BigInt(pk_i)), 3n, '캐노니컬: c + 1');
    assert.equal(stateJson().pendingBounds.find((e) => e.pk_i === pk_i).epoch, String(pub.body.epoch), '실린 epoch 기록 — 거울이 받을 때까지 유지');
    assert.equal(await mirrorC.sessionBoundOf(BigInt(pk_i)), 0n, '중계 전 거울은 비어 있다');
    const rl = await cia.adminPost('/cia/admin/relay', {}); assert.equal(rl.status, 200, j(rl.body));
    assert.equal(await mirrorC.sessionBoundOf(BigInt(pk_i)), 3n, '거울: c + 1');
    assert.equal(stateJson().pendingBounds.some((e) => e.pk_i === pk_i), false, '모든 거울이 받았으니 대기열에서 빠진다');
  });
  await t('pk_i 만·sig_i 만·다른 키·다른 bound 위의 sig_i·범위 밖 pk_i 는 400 bad_session_signature 이고 리프를 넣지 않는다', async () => {
    const iss = await fresh();
    const good = await revokeBody(iss, 1n);
    const other = ethers.Wallet.createRandom();
    const cases = [
      ['pk_i 만', { ...good, sig_i: undefined }],
      ['sig_i 만', { ...good, pk_i: undefined }],
      ['다른 키의 sig_i', { ...good, sig_i: await signRevokeBind(other.privateKey, { uid, Cf_s: iss.cred.Cf_s, bound: 1n, nonce: good.nonce }) }],
      ['다른 bound 위의 sig_i', { ...good, sig_i: await signRevokeBind(iss.session.wallet.privateKey, { uid, Cf_s: iss.cred.Cf_s, bound: 0n, nonce: good.nonce }) }],
      ['pk_i 범위 밖(2^160)', { ...good, pk_i: (1n << 160n).toString() }],
    ];
    for (const [name, body] of cases) {
      const r = await cia.post('/cia/revoke', JSON.parse(JSON.stringify(body)));   // undefined 필드 제거
      assert.equal(r.status, 400, `${name}: ${j(r.body)}`); assert.equal(r.body.reason, 'bad_session_signature', name);
    }
    const ok = await cia.post('/cia/revoke', good);
    assert.equal(ok.status, 200, j(ok.body)); assert.equal(ok.body.inserted, true, '위 400 들은 리프를 넣지 않았다');
  });
  await t('pk_i 없는 폐기(관리자·옛 지갑)는 그대로 받되 거울 counter 는 게시하지 않는다(mirrorBound=false, sessionBoundOf=0)', async () => {
    const iss = await fresh(); const pk = BigInt(iss.session.pk_i);
    const r = await cia.post('/cia/revoke', await revokeBody(iss, 0n, { withBind: false }));
    assert.equal(r.status, 200, j(r.body)); assert.equal(r.body.inserted, true); assert.equal(r.body.mirrorBound, false);
    const iss2 = await fresh();
    const rA = await cia.adminPost('/cia/revoke', { uid: uid.toString(), scope: 'session', Cf_s: iss2.cred.Cf_s });
    assert.equal(rA.status, 200, j(rA.body)); assert.equal(rA.body.mirrorBound, false);
    assert.equal((await cia.adminPost('/cia/publish', {})).body.published, true);
    await cia.adminPost('/cia/admin/relay', {});
    assert.equal(await logC.sessionBoundOf(pk), 0n); assert.equal(await mirrorC.sessionBoundOf(pk), 0n);
    assert.equal(await mirrorC.sessionBoundOf(BigInt(iss2.session.pk_i)), 0n);
  });
  await t('낮추기만: 같은 세션을 bound 3 → 1 로 재폐기하면 거울 2(=1+1); 그 뒤 5 는 멱등 응답(inserted:false)이고 거울 그대로', async () => {
    const iss = await fresh(); const pk = BigInt(iss.session.pk_i);
    assert.equal((await cia.post('/cia/revoke', await revokeBody(iss, 3n))).body.inserted, true);
    const lower = await cia.post('/cia/revoke', await revokeBody(iss, 1n));
    assert.equal(lower.status, 200, j(lower.body)); assert.equal(lower.body.inserted, true); assert.equal(lower.body.bound, '1');
    assert.equal(stateJson().pendingBounds.find((e) => e.pk_i === pk.toString()).bound, '1', '대기열은 더 낮은 값으로 갈아끼운다');
    assert.equal((await cia.adminPost('/cia/publish', {})).body.published, true);
    await cia.adminPost('/cia/admin/relay', {});
    assert.equal(await mirrorC.sessionBoundOf(pk), 2n);
    const raise = await cia.post('/cia/revoke', await revokeBody(iss, 5n));
    assert.equal(raise.status, 200, j(raise.body)); assert.equal(raise.body.inserted, false);
    assert.equal((await cia.adminPost('/cia/publish', {})).body.published, false, '새로 실을 것이 없다');
    assert.equal(await mirrorC.sessionBoundOf(pk), 2n);
  });
  await t('건너뛴 epoch: 두 번 게시(각각 pk_i 하나) 뒤 한 번만 중계해도 거울에 둘 다 실린다(누적 재전송), 그 뒤 대기열이 비워진다', async () => {
    const a = await fresh(), b = await fresh();
    assert.equal((await cia.post('/cia/revoke', await revokeBody(a, 1n))).status, 200);
    const p1 = await cia.adminPost('/cia/publish', {}); assert.equal(p1.body.published, true);
    assert.equal((await cia.post('/cia/revoke', await revokeBody(b, 2n))).status, 200);
    const p2 = await cia.adminPost('/cia/publish', {}); assert.equal(p2.body.published, true); assert.ok(p2.body.bounds >= 2, '앞 게시의 항목도 다시 실린다: ' + j(p2.body));
    assert.ok((await mirrorC.epoch()) < BigInt(p1.body.epoch), '전제: 거울은 두 게시 모두 아직 못 받았다');
    await cia.adminPost('/cia/admin/relay', {});
    assert.equal(await mirrorC.epoch(), BigInt(p2.body.epoch), '중계는 최신 epoch 만 옮긴다');
    assert.equal(await mirrorC.sessionBoundOf(BigInt(a.session.pk_i)), 2n, '건너뛴 게시(p1)의 bound 도 실렸다');
    assert.equal(await mirrorC.sessionBoundOf(BigInt(b.session.pk_i)), 3n);
    const pend = stateJson().pendingBounds.map((e) => e.pk_i);
    assert.equal(pend.includes(a.session.pk_i.toString()) || pend.includes(b.session.pk_i.toString()), false, '거울이 받았으니 비운다');
  });
```
Run: `bash scripts/run_tests.sh chain 2>&1 | tail -40` 대신 단일 파일: `node tests/test_cia_revoke_bound.mjs`(:8545 hardhat 노드가 필요하다 — 비어 있으면 `npx hardhat node` 를 백그라운드로 띄우고 끝나면 끈다)
Expected: 새 케이스 5개 FAIL(기존 3개 PASS).

- [ ] **Step 5: `/cia/revoke` 에 pk_i·sig_i**

`cia.js` import 36행을 `import { sessionLeaf, createRevocationTree, SESSION_BOUND_MAX, verifyRevokeBind } from './lib/mode3_revocation.js';` 로. `/cia/revoke` 의 `if (!isAdmin) { … }` 블록 **뒤**, `if (!rec) return …unknown_session` **앞** 에:

```js
    // 2026-10-25 root 유효 창 §4: 지갑이 세션키 pk_i 를 세션키 서명 sig_i 로 묶어 함께 내면 거울 공개 counter 게시 대기열에 넣는다.
    // 둘 중 하나만 오거나 서명이 틀리면 400 — 묶지 않으면 sig_u 만 있는 사용자가 남의 pk_i 를 넣어 그 세션을 막을 수 있다(낮추기만이라 못 되돌린다).
    const { pk_i: pkIn, sig_i } = req.body ?? {};
    let boundKey = null;
    if (pkIn !== undefined || sig_i !== undefined) {
      if (!isDec(pkIn) || BigInt(pkIn) >= (1n << 160n) || typeof sig_i !== 'string' || !isDec(nonce)) {
        return res.status(400).json({ error: 'pk_i(10진, < 2^160)·sig_i·nonce 가 함께 필요하다', reason: 'bad_session_signature' });
      }
      if (!verifyRevokeBind(pkIn, { uid, Cf_s, bound, nonce }, sig_i)) return res.status(400).json({ error: 'bad session key signature', reason: 'bad_session_signature' });
      boundKey = BigInt(pkIn).toString();
    }
```
멱등 분기의 응답에 `mirrorBound: Boolean(rec.pk_i)` 를 더한다:

```js
      return res.json({ inserted: false, bound: rec.bound ?? '0', root: tree.getRoot().toString(), pending: state.pending.length, mirrorBound: Boolean(rec.pk_i) });
```
`cur.bound = BigInt(bound).toString();` 뒤를:

```js
    cur.bound = BigInt(bound).toString();
    if (boundKey) cur.pk_i = boundKey;            // 거울 공개용 — 발급 때는 모르는 값(D1)이라 폐기 때 지갑이 알려 준다
    if (cur.pk_i) queueBound(cur.pk_i, cur.bound);   // 관리자 폐기도 레코드에 pk_i 가 있으면(앞선 사용자 폐기) 같이 게시한다
    persist();
    res.json({ inserted, leaf, bound: cur.bound, root: tree.getRoot().toString(), pending: state.pending.length, mirrorBound: Boolean(cur.pk_i) });
```

- [ ] **Step 6: 대기열 헬퍼 세 개**

`publishNow` 정의 바로 위에:

```js
// 2026-10-25 root 유효 창 §4: 거울 공개 세션 counter 대기열.
/** 같은 pk_i 는 더 낮은 bound 로만 갈아끼운다(컨트랙트도 낮추기만 받는다). epoch:null = 아직 어느 게시에도 실리지 않음. 호출자가 persist 한다. */
function queueBound(pk_i, bound) {
  const cur = state.pendingBounds.find((e) => e.pk_i === pk_i);
  if (!cur) { state.pendingBounds.push({ pk_i, bound, epoch: null }); return; }
  if (BigInt(bound) < BigInt(cur.bound)) { cur.bound = bound; cur.epoch = null; }
}
/** 게시에 실을 (pk_i, bound) — 대기열 **전부**. 이미 실린 항목도 모든 거울이 그 epoch 를 받을 때까지 다시 싣는다: 거울 중계는 최신 epoch 만
 *  옮기므로 건너뛴 epoch 의 bound 가 유실되지 않게. 컨트랙트는 같은 값·올리기를 무시한다. */
function boundsPayload() {
  return { boundKeys: state.pendingBounds.map((e) => BigInt(e.pk_i)), boundValues: state.pendingBounds.map((e) => Number(e.bound)) };
}
/** 모든 거울이 받은 epoch(거울이 없으면 캐노니컬 epoch) 이하에 실린 항목을 버린다. 아직 한 번도 읽지 못한 거울이 있으면 보수적으로 둔다. */
function pruneMirroredBounds() {
  let floor;
  if (MIRRORS.length === 0) floor = BigInt(state.epoch);
  else {
    if (MIRRORS.some((m) => m.mirroredEpoch === undefined)) return;
    floor = MIRRORS.reduce((acc, m) => (m.mirroredEpoch < acc ? m.mirroredEpoch : acc), MIRRORS[0].mirroredEpoch);
  }
  const before = state.pendingBounds.length;
  state.pendingBounds = state.pendingBounds.filter((e) => e.epoch === null || BigInt(e.epoch) > floor);
  if (state.pendingBounds.length !== before) persist();
}
```

- [ ] **Step 7: `publishNow` 페이로드**

`publishNow` 안에서:
- `const noRev = …, noSlots = …;` 줄 뒤에 `const noNewBounds = !state.pendingBounds.some((e) => e.epoch === null);   // 2026-10-25 §4: 아직 안 실린 거울 counter 가 있으면 게시한다` 를 넣고, 바로 다음 `if (noRev && noSlots && !heartbeat)` 를 `if (noRev && noSlots && noNewBounds && !heartbeat)` 로.
- `const revRoot = …, regRoot = …;` 줄 뒤에:

```js
    const { boundKeys, boundValues } = boundsPayload();
    const boundsSnapshot = state.pendingBounds.map((e) => ({ pk_i: e.pk_i, bound: e.bound }));   // 이번 게시에 실린 (pk_i, bound) — 게시 중 더 낮아진 항목은 epoch 를 받지 않는다
```
- `signPublicationV3(ethWallet, { …, slotIdx, slotLeaves })` 끝에 `, boundKeys, boundValues`; `log.publish(revRoot, regRoot, epoch, leaves, slotIdx, slotLeaves, sig)` → `log.publish(revRoot, regRoot, epoch, leaves, slotIdx, slotLeaves, boundKeys, boundValues, sig)`.
- `state.lastPublication = { … }` 를:

```js
    state.lastPublication = { revRoot, regRoot, epoch: String(epoch), ...entryHashes({ revLeaves: leaves, slotIdx, slotLeaves, boundKeys, boundValues }), boundKeys: boundKeys.map(String), boundValues: boundValues.map(String), sig, txHash: tx.hash };
    for (const e of state.pendingBounds) if (boundsSnapshot.some((s) => s.pk_i === e.pk_i && s.bound === e.bound)) e.epoch = String(epoch);
```
- 마지막 `persist();` 뒤, `return { published: true, … }` 앞에 `if (MIRRORS.length === 0) pruneMirroredBounds();`. 그 `return` 객체에 `bounds: boundKeys.length` 를 더한다.

- [ ] **Step 8: 거울 중계**

- `sendMirrorTx` 의 `m.contract.publish(lp.revRoot, lp.regRoot, lp.epoch, lp.hLeaves, lp.hIdx, lp.hSlots, lp.sig)` → `m.contract.publish(lp.revRoot, lp.regRoot, lp.epoch, lp.hLeaves, lp.hIdx, lp.hSlots, (lp.boundKeys ?? []).map(BigInt), (lp.boundValues ?? []).map(Number), lp.sig)` (옛 상태 파일의 `lastPublication` 은 두 배열이 없다 — 빈 배열).
- `relayMirror` 에서 `const behind = mv.epoch < canon.epoch;` 바로 앞에 `m.mirroredEpoch = mv.epoch;   // 2026-10-25 §4: 거울이 지금 가진 epoch — pendingBounds 정리 기준`, 그리고 `const txHash = await sendMirrorTx(m, lp);` 바로 뒤에 `m.mirroredEpoch = BigInt(lp.epoch);`.
- `relayAll` 의 `for (const m of MIRRORS) { … }` 루프가 끝난 뒤(결과 배열을 돌려주기 전)에 `pruneMirroredBounds();`.

- [ ] **Step 9: 관리자 목록**

`/cia/admin/revoked_sessions` 의 `out.push({ uid, Cf_s: s.Cf_s, … pending: pendingLeaves.has(leaf) })` 에 `pk_i: s.pk_i ?? null,` 를 더한다. (`/cia/admin/sessions` 는 `{ ...s }` 를 그대로 내므로 `pk_i` 가 자동으로 실린다.)

- [ ] **Step 10: chain 테스트 통과 확인**

Run: `node tests/test_cia_revoke_bound.mjs`
Expected: 전부 PASS(8개). 이어서 영향 받는 격리 IdP 테스트: `node tests/test_cia_mirror_relay.mjs && node tests/test_mode3_session_revoke.mjs && node tests/test_cia_registry.mjs`
Expected: PASS(게시·중계 호출 모양만 바뀌었고 동작은 같다).

- [ ] **Step 11: 커밋**

```bash
git add lib/mode3_revocation.js lib/mode3_cia_state.js cia.js tests/test_mode3_revocation_tree.js tests/test_mode3_cia_state.js tests/test_cia_revoke_bound.mjs
git commit -m "feat(cia): 세션 폐기 때 pk_i 를 세션키 서명으로 묶어 받고 pendingBounds 를 게시·거울 중계 페이로드에 누적 재전송" -m "Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>" -m "Claude-Session: https://claude.ai/code/session_013qGSXZTftBJSB1M4XpPRHN" -- lib/mode3_revocation.js lib/mode3_cia_state.js cia.js tests/test_mode3_revocation_tree.js tests/test_mode3_cia_state.js tests/test_cia_revoke_bound.mjs
```

---

### Task 5: 지갑 에이전트·RP — 폐기 결속, 팩토리 `rootWindow`, 종단 테스트

**Files:**
- Modify: `mode3_wallet_agent.js:24-27`(import), `~369-378`(checkService), `~1051-1055`(`/wallet/session/revoke`); `mode3_rp.js:21, 156-158, 173-182`
- Test: `tests/test_mode3_wallet_agent.mjs`

**Interfaces:**
- Consumes: Task 3 `FACTORY_ROOT_WINDOW_BAND`·`ROOT_WINDOW_DEFAULT`·`deployFactory({ rootWindow })`·`FACTORY_ABI.rootWindow()`; Task 4 `signRevokeBind`, `/cia/revoke` 의 `pk_i`·`sig_i`·`mirrorBound`.
- Produces: `/wallet/session/revoke` 응답에 `mirrorBound: boolean`; `bad_factory` detail `'rootWindow out of band'`; RP env `MODE3_ROOT_WINDOW`.

- [ ] **Step 1: 에이전트 테스트 추가(실패 확인)**

`tests/test_mode3_wallet_agent.mjs`:
- import 갱신: 10행을 `import { getProvider, deployRevocationLog, mineBlocks } from './helpers/mode3_chain.mjs';` 로, 끝에 `import { issueV11, userOf, TESTUSER_ATTRS } from './helpers/mode3_flow.mjs';`.
- 'I-3/E-2: 팩토리의 …' 케이스의 `cases` 에 `['rootWindow 상한 밖(201)', { ...base, rootWindow: 201n }],` 를 더한다.
- 'F-14: /wallet/tx/record …' 케이스 뒤에:

```js
  // ── 2026-10-25 root 유효 창 ──
  await t('거울 counter: /wallet/session/revoke 가 pk_i·sig_i 를 실어(mirrorBound) IdP 게시 → 중계 뒤 거울 sessionBoundOf(pk_i) = bound+1', async () => {
    const ch = newCh(); const l = await login(ch, { factoryAddress }); assert.equal(l.status, 200, j(l.body));
    const req = await wallet.post('/wallet/request', { r_s: ch.r_s, body: 'x' }, { Origin: stack.rpOriginForWallet }); assert.equal(req.status, 200, j(req.body));
    const pk_i = BigInt(req.body.pk_i);
    const rv = await wallet.post('/wallet/session/revoke', { r_s: ch.r_s, bound: '4' });
    assert.equal(rv.status, 200, j(rv.body)); assert.equal(rv.body.mirrorBound, true);
    assert.equal((await cia.adminPost('/cia/publish', {})).body.published, true);
    await relay();
    assert.equal(await mirrorC.sessionBoundOf(pk_i), 5n);
  });
  await t('root 창(G=5): 다른 사용자의 등록·세션 폐기로 거울의 두 root 가 바뀌어도 창 안이면 옛 root 로 준비한 거래가 통과, 창이 닫히면 StaleRevocationRoot', async () => {
    const signer = await provider.getSigner(0);
    const f = await deployFactory(signer, { verifierAddress: await deployVerifier(signer), arid: BigInt(arid), pkCIA: pk_CIA, pkTrace: pk_trace, logAddress: cia.mirrorAddress, rootWindow: 5n });
    const A = newCh(); assert.equal((await login(A, { factoryAddress: f })).status, 200);
    assert.equal((await wallet.post('/wallet/tx', { r_s: A.r_s, to: ethers.ZeroAddress, value: '0' })).status, 200, '첫 거래로 지갑 배포');
    // 다른 사용자(alice/67890): 발급 → 그 세션을 관리자 폐기 → 게시 → 중계 = 거울 revRoot 가 바뀐다
    const alice = userOf(await cia.registerUser('67890', 'password123'), '67890', TESTUSER_ATTRS);
    // alice 의 **첫** 발급은 등록부 슬롯도 채워 regRoot 까지 바꾼다(스펙 §8 "신규 등록 뒤 옛 등록부 root 증명 통과" 도 (1) 에서 함께 지나간다).
    const bumpRoot = async ({ expectRegChange = false } = {}) => {
      const before = await mirrorC.revRoot(), beforeReg = await mirrorC.regRoot();
      const iss = await issueV11(cia, alice, { arid, provider }); assert.equal(iss.r.status, 200, j(iss.r.body));
      assert.equal((await cia.adminPost('/cia/revoke', { uid: '67890', scope: 'session', Cf_s: iss.cred.Cf_s, bound: '0' })).status, 200);
      assert.equal((await cia.adminPost('/cia/publish', {})).body.published, true);
      await relay();
      assert.notEqual(await mirrorC.revRoot(), before, '전제: 거울 revRoot 가 바뀌었다');
      if (expectRegChange) assert.notEqual(await mirrorC.regRoot(), beforeReg, '전제: 첫 발급으로 거울 regRoot 도 바뀌었다');
    };
    const eoa = await provider.getSigner(1);
    // (1) 옛 root 로 준비 → 타인 폐기 반영 → 바로 보내면 창 안이라 통과
    const pre1 = await wallet.post('/wallet/tx/prepare', { r_s: A.r_s, to: ethers.ZeroAddress, value: '0' });
    assert.equal(pre1.status, 200, j(pre1.body)); assert.equal(pre1.body.deployNeeded, false);
    await bumpRoot({ expectRegChange: true });
    const rc1 = await (await eoa.sendTransaction({ to: pre1.body.walletAddr, data: pre1.body.calldata })).wait();
    assert.equal(rc1.status, 1);
    assert.equal(await walletAt(pre1.body.walletAddr, provider).nonce(), 2n);
    // (2) 다시 준비(새 root) → 타인 폐기 반영 → 6블록 뒤 보내면 창 밖 — StaleRevocationRoot
    const pre2 = await wallet.post('/wallet/tx/prepare', { r_s: A.r_s, to: ethers.ZeroAddress, value: '0' });
    assert.equal(pre2.status, 200, j(pre2.body)); assert.equal(pre2.body.nonce, '2');
    await bumpRoot();
    await mineBlocks(6, provider);
    let err = null;
    try { await provider.call({ to: pre2.body.walletAddr, data: pre2.body.calldata, from: await eoa.getAddress() }); } catch (e) { err = e; }
    assert.ok(err, '창 밖이면 revert');
    assert.equal(walletInterface.parseError(err.data)?.name, 'StaleRevocationRoot', String(err.message));
  });
```
Run: `node tests/test_mode3_wallet_agent.mjs 2>&1 | grep -E "^(ok|FAIL)" | tail -12`
Expected: 새 케이스 둘과 `rootWindow 상한 밖` 포함 I-3/E-2 가 FAIL.

- [ ] **Step 2: 에이전트 — 결속 서명·팩토리 검사**

`mode3_wallet_agent.js`:
- 24행 import 를 `import { sessionLeafRange, SESSION_BOUND_MAX, signRevokeBind } from './lib/mode3_revocation.js';` 로, 27행 import 목록에 `FACTORY_ROOT_WINDOW_BAND` 를 더한다.
- `checkService` 의 `Promise.all([…, f.maxRootAge(), f.maxLifetime()])` 를 `const [fa, fl, fx, fy, tx, ty, fra, flt, frw] = await Promise.all([…, f.maxRootAge(), f.maxLifetime(), f.rootWindow()]);` 로 하고 `maxLifetime out of band` 줄 뒤에:

```js
      // 2026-10-25 root 유효 창 §3: 창이 너무 크면 은퇴한 자격증명의 옛 π 가 그만큼 오래 통과한다(§7 한계 2). 0 은 옛 동작(최신만)이라 허용.
      // rootWindow() 가 없는 옛 팩토리는 호출이 revert 해 아래 catch 의 bad_factory 로 떨어진다 — 재배포가 필요하다.
      if (BigInt(frw) < FACTORY_ROOT_WINDOW_BAND.min || BigInt(frw) > FACTORY_ROOT_WINDOW_BAND.max) return { status: 409, body: { reason: 'bad_factory', detail: 'rootWindow out of band' } };
```
- `/wallet/session/revoke` 의 `const sig_u = await signRevokeSession(…)` 줄 뒤에:

```js
    // 2026-10-25 root 유효 창 §4: 세션키 pk_i 를 세션키 서명으로 묶어 함께 낸다 — IdP 가 다음 게시에 (pk_i, bound) 를 실어 거울이 창 안에서도 즉시 막는다.
    const sig_i = await signRevokeBind(s.sessionPrivKey, { uid: state.registration.uid, Cf_s: s.credential.Cf_s, bound, nonce });
```
`ciaPost('/cia/revoke', { uid: …, scope: 'session', Cf_s: …, bound: bound.toString(), sig_u, nonce: nonce.toString() })` 에 `, pk_i: s.pk_i, sig_i` 를 더하고, 응답 `res.json({ revoked: true, inserted: …, pending: …, bound: appliedBound, pendingBoundId })` 에 `, mirrorBound: r.body.mirrorBound === true` 를 더한다.

- [ ] **Step 3: RP env**

`mode3_rp.js`: 21행 import 목록에 `ROOT_WINDOW_DEFAULT` 추가. `const MAX_LIFETIME = …;` 줄 뒤에:

```js
// 2026-10-25 root 유효 창 §6: 계정 컨트랙트가 대체된 root 를 더 받는 블록 수 G. 팩토리 immutable 이라 바꾸려면 팩토리를 재배포한다.
const ROOT_WINDOW = BigInt(process.env.MODE3_ROOT_WINDOW || ROOT_WINDOW_DEFAULT);
```
`ensureFactory` 의 `deployFactory(signer, { …, maxLifetime: MAX_LIFETIME })` 에 `, rootWindow: ROOT_WINDOW` 를 더하고 로그 줄을 `` `[rp] 팩토리 배포: ${factoryAddress} (verifier ${verifierAddress}, maxRootAge ${MAX_ROOT_AGE}, maxLifetime ${MAX_LIFETIME}, rootWindow ${ROOT_WINDOW}) → ${REG_FILE}` `` 로.

- [ ] **Step 4: 에이전트 테스트 통과 확인**

Run: `node tests/test_mode3_wallet_agent.mjs 2>&1 | grep -E "^(ok|FAIL)|failed" | tail -15`
Expected: 전부 `ok`.

- [ ] **Step 5: chain 그룹 전체**

Run: `bash scripts/run_tests.sh chain`
Expected: 전부 PASS. 특히 `tests/test_mode3_demo_stack.mjs`·`tests/test_mode3_demo_full.mjs`(RP 가 `deployFactory` 로 배포 → 기본 rootWindow 20)·`tests/test_mode3_e2e.mjs`·`tests/test_mode3_rp.mjs`(RP 오프체인 검증기는 최신 root 요구 그대로 — `stale_root`/`stale_registry_root` 기대 유지)·`tests/test_mode3_wallet_snap.mjs`. 실패가 있으면 원인을 적고 고친 뒤 이 커밋에 넣는다(기대값 자체를 바꿔야 하면 그 이유를 커밋 메시지에 적는다).

- [ ] **Step 6: 커밋**

```bash
git add mode3_wallet_agent.js mode3_rp.js tests/test_mode3_wallet_agent.mjs
git commit -m "feat(wallet-agent,rp): 세션 폐기에 pk_i 결속 서명 동봉, 팩토리 rootWindow 검사·MODE3_ROOT_WINDOW; 타인 폐기 뒤 옛 root 거래 통과 종단 테스트" -m "Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>" -m "Claude-Session: https://claude.ai/code/session_013qGSXZTftBJSB1M4XpPRHN" -- mode3_wallet_agent.js mode3_rp.js tests/test_mode3_wallet_agent.mjs
```

---

### Task 6: 런북·전체 검증

**Files:**
- Modify: `docs/MODE3_DEMO.md`(폐기 상한 절 ~860-866, 한계 절 ~873, 환경 변수 절 ~855-858, 재시연 세트 언급)
- Test: 전 그룹 실행(코드 변경 없음)

**Interfaces:**
- Consumes: 앞 태스크 전부.
- Produces: 운영자가 읽는 문서.

- [ ] **Step 1: 런북 — 새 절**

`docs/MODE3_DEMO.md` 의 "### 폐기 상한(카운터, 세션 폐기)" 절 끝(전파 지연 단락 뒤)에 새 절을 넣는다.

```markdown
### root 유효 창 + 거울 세션 counter (2026-10-25)

설계 `docs/superpowers/specs/2026-10-25-mode3-root-window-session-counter-design.md`. 그전에는 계정 컨트랙트가 두 root(폐기·등록부) 모두 **최신**만 받아, 내가 증명을 만든 뒤 MetaMask 승인 사이에 **다른 사용자**의 세션 폐기·신규 등록이 거울에 실리면 내 거래가 `StaleRevocationRoot`/`StaleRegistryRoot` 로 튕겼다(미팅 덱 "Race Condition (1)"). 이제:

- 로그·거울(`Mode3Log`·`Mode3Mirror`, 공통 베이스 `Mode3RootHistory`)이 **대체된 root 의 블록**을 최근 16개까지 기억하고, 계정 컨트랙트는 팩토리 생성자 `rootWindow`(G 블록, 기본 **20**, RP env `MODE3_ROOT_WINDOW`) 안의 옛 root 도 받는다. 창 안에서는 타인의 폐기·등록이 내 거래를 튕기지 않는다.
- 그 대신 **폐기된 세션**은 창과 무관하게 막힌다: 지갑이 세션을 폐기할 때 세션키 `pk_i` 를 세션키 서명으로 묶어 IdP 에 알리고, IdP 는 다음 게시 페이로드에 `(pk_i, 허용 거래 수 c)` 를 실어 거울이 `sessionBoundOf[pk_i]` 로 공개한다(낮추기만). 계정 컨트랙트는 자기 호출 상한(`setSessionBound`, 선택 기능)과 거울 값 중 **낮은 쪽**을 적용해 `nonce ≥ c` 를 `SessionBounded` 로 거절한다. 거울이 받기 전까지의 거래는 채굴 순서 문제(Race (2))로 남는다 — 지연 실행 큐가 별도 후속이다.
- 관리자 폐기(지갑을 거치지 않음)·옛 지갑의 폐기는 `pk_i` 가 없어 거울 counter 없이 RCL 리프만 — 창이 닫힌 뒤 회로의 구간 검사로 막힌다.
- **재시연 세트가 필요하다**: 로그·거울 컨트랙트가 바뀌고(게시 다이제스트 도메인 `MODE3_LOG_V4`) 팩토리·계정 생성자 인자가 늘어 CREATE2 주소가 바뀐다 — 로그·거울 재배포(`scripts/deploy_mode3_log.cjs`), IdP 상태 파일 새로, RP 등록 파일의 `factoryAddress`·`verifierAddress` 삭제(RP 가 다시 배포한다). 옛 팩토리로 로그인하면 지갑이 `bad_factory`(rootWindow 조회 실패)로 거절한다.
- 지갑이 받아들이는 `rootWindow` 범위는 0..200 블록이다(0 = 옛 동작, 최신만). 창이 클수록 **은퇴한 자격증명**의 옛 π 가 그만큼 더 통과하므로(세션 폐기는 counter 가 막아 무관) 데모 외에는 블록 시간에 맞춰 줄인다(12 s 체인 ≈ 10).
```

- [ ] **Step 2: 런북 — 기존 문구 갱신**

- "### 환경 변수" 절에 항목 추가: `- \`MODE3_ROOT_WINDOW\`(RP, 기본 20): 계정 컨트랙트가 대체된 root 를 더 받는 블록 수(위 "root 유효 창" 절). 팩토리 immutable 이라 바꾸면 팩토리 재배포.`
- "### 한계" 의 `- **전파 지연**: …` 항목을 `- **전파 지연**: 거울이 \`(pk_i, c)\` 를 받기 전까지는 폐기한 세션키의 거래가 통과할 수 있다(Race (2), 채굴 순서) — 타 사용자의 폐기·등록이 내 거래를 튕기는 쪽(Race (1))은 root 유효 창으로 없앴다(위 절).` 로 바꾼다.
- "### 시연 순서(2026-10-22)" 8번 끝에 ` 거울 중계 뒤 거울의 \`sessionBoundOf(pk_i)\`(관리자 "폐기 세션 목록"의 pk_i 로 조회) 가 c+1 인지로도 확인할 수 있다.` 를 덧붙인다.

- [ ] **Step 3: 전 그룹 실행**

Run(순서대로, 각각 결과를 기록): `npm test` → `bash scripts/run_tests.sh contract` → `bash scripts/run_tests.sh chain` → (Chrome 이 있으면) `bash scripts/run_tests.sh browser` → (`snap-mode3/node_modules` 가 있으면) `bash scripts/run_tests.sh snap`
Expected: 모두 PASS. browser·snap 은 전제가 없으면 `BLOCKED:` 로 건너뛰고 그 사실을 보고한다. 자기가 띄운 :8545 노드는 끝나면 끄고 포트가 비었는지 확인한다.

- [ ] **Step 4: 커밋**

```bash
git add docs/MODE3_DEMO.md
git commit -m "docs(mode3): 런북 — root 유효 창·거울 세션 counter 절, MODE3_ROOT_WINDOW, 재시연 세트·한계 갱신" -m "Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>" -m "Claude-Session: https://claude.ai/code/session_013qGSXZTftBJSB1M4XpPRHN" -- docs/MODE3_DEMO.md
```

---

## 범위 밖(후속)

- 레이스 (2) 지연 실행 큐(별도 스펙).
- 지갑 페이지의 "체인 반영 대기" 카드 기본 숨김(`MODE3_ONCHAIN_BOUND` 옵션)·`/wallet/config.onchainBound` — 거울 값이 정본이 됐으므로 자기 호출 상한은 선택 기능으로 남는다(현 UI 유지, 후속에서 옵션화).
- 분리 데모(VM 3대)·Snap 재시연: 스택 재배포가 필요하므로 사용자 승인 뒤 `scripts/demo_split_snap_reset.sh` 로 진행(이 계획에 넣지 않음).
- Snap 모드 OIDC 래퍼(2026-10-25 사용자 지시 "다음 과제").
