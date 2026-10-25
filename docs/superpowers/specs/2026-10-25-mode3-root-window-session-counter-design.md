# Mode 3 — root 유효 창 + 세션별 counter 공개 (타 사용자 레이스 제거) 설계

작성 2026-10-25. 선행 스펙: `2026-10-22-mode3-revocation-counter-bound-design.md`(폐기 상한 c·counter), `2026-10-22-mode3-idp-pages-design.md`.

## 1. 목표

- **없앨 것(레이스 (1))**: 타 사용자의 세션 폐기·신규 등록으로 응용 체인의 폐기 root/등록부 root 가 바뀌면, 그 직전 root 로 만든 내 진행 중 거래가 `StaleRevocationRoot`/`StaleRegistryRoot` 로 튕기는 liveness 문제. 지금은 컨트랙트가 두 root 모두 "최신" 만 받는다(`Mode3Wallet._checkStatement`).
- **유지할 것(안전)**: 폐기된 세션의 거래는 `nonce ≥ c` 이면 막힌다. 창이 열린 동안은 **거울에 공개된 세션별 counter** 가, 창이 닫힌 뒤에는 지금처럼 RCL 리프(회로 구간 비멤버십)가 막는다.
- **바꾸지 않을 것**: 회로 `pi_cred`·검증기·IdP 리프 형식(`H′·2^32 + c`)·RP 로그인 경로(미러 직접 읽기, 최신 root 요구)·지갑 증명 흐름. 재빌드 없음.
- **범위 밖(레이스 (2))**: 폐기된 세션키를 쥔 공격자의 거래가 폐기 반영보다 **먼저 채굴**되는 경우. 어떤 counter 설계로도 제거되지 않으며(채굴된 거래는 되돌릴 수 없음) 지연 실행 큐만이 완전 해법이다 — 미팅 덱 9장·§7 한계에 기술.

### 세 counter 의 대응(2026-10-24 논의)

| 논의 용어 | 구현 |
|---|---|
| PPID(tx) counter | 계정 컨트랙트 `nonce` = 증명 공개 입력 `counter` |
| fetched | 폐기 시점에 지갑이 읽은 `nonce`(세션 발급 시점으로 고정해 보아도 결과 동일) |
| next (내 폐기 때만 `fetched + 1`, 아니면 `fetched` 그대로) | RCL 리프의 `c` + **거울의 `sessionBoundOf[pk_i]`**; 폐기가 없으면 둘 다 없음 = 제한 없음 |
| 검사 | `nonce < c` — 창 안에서는 거울 counter 로, 창 밖에서는 회로 구간 검사로 |

기본 `c` 는 지갑이 읽은 현재 `nonce`(결정 이후 전부 금지). 진행 중 거래 1건을 살리려면 사용자가 입력칸에서 `+1`.

## 2. 캐노니컬·거울 공통 베이스 `Mode3RootHistory`(Mode3Log·Mode3Mirror 가 상속)

### 2.1 root 이력(유효 창)
- 구현 위치(2026-10-25 계획 보정): `contracts/Mode3RootHistory.sol`(abstract). `Mode3Log`·`Mode3Mirror` 가 상속해 root 이력·세션 counter 코드가 하나다 — 검증자가 어느 쪽을 읽어도 같은 답이어야 한다. 다이제스트 도메인은 `MODE3_LOG_V4`(bound 두 해시가 추가돼 옛 서명과 구분).
- 상태: `mapping(bytes32 => uint64) revSupersededAt`, `mapping(bytes32 => uint64) regSupersededAt` — 그 root 가 **대체된 블록 높이**. 최신 root 는 항목 없음(0).
- 링 버퍼: 최근 K = 16 개 옛 root 만 유지(`bytes32[16]` 순환 + 삭제). K 는 생성자 상수. 버퍼 밖으로 밀린 root 는 "창 밖" 으로 취급(liveness 만 영향).
- `publish(newRev, newReg, …)`: 기존 동작 뒤에 `if (newRev != revRoot) { _supersede(rev, revRoot) } ; if (newReg != regRoot) { _supersede(reg, regRoot) }` 를 수행(현재 높이 기록, 버퍼 밀기).
- 조회: `isAcceptableRevRoot(bytes32 root, uint64 G) view returns (bool)` = `root == revRoot || (revSupersededAt[root] != 0 && block.number <= revSupersededAt[root] + G)`. 등록부도 동일(`isAcceptableRegRoot`). `IMode3Roots` 인터페이스에 추가.

### 2.2 세션별 counter 공개
- 상태: `mapping(uint256 pk_i => uint256) sessionBoundOf` — **c + 1** 저장(c = 2^32−1 일 때 +1 이 uint32 를 넘치므로 uint256; Mode3Wallet.sessionBound 와 같은 인코딩).
- `publish(...)` 인자에 `uint256[] boundKeys, uint32[] boundValues` 추가(길이 동일). 각 항목: `cur == 0 || value + 1 < cur` 일 때만 갱신(낮추기만), 아니면 무시(revert 아님 — 게시 전체가 막히지 않게). 이벤트 `SessionBoundPublished(uint256 indexed pk_i, uint32 bound, uint64 epoch)`.
- 다이제스트(`digestFor`)에 두 배열을 포함해 IdP 서명이 보호한다. 거울 중계(`Mode3Mirror`)는 같은 페이로드를 그대로 옮긴다.
  거울 `publish` 는 리프·슬롯은 해시로 받되 bound 는 **배열 그대로** 받는다(저장해야 하므로) — 다이제스트에는 두 배열의 `keccak256(abi.encodePacked(...))` 가 들어가 캐노니컬과 바이트 단위로 같다. 거울 중계는 최신 epoch 만 옮기므로, IdP 는 `pendingBounds` 항목을 **모든 거울이 그 항목이 실린 epoch 이상을 받을 때까지** 매 게시에 다시 싣는다(컨트랙트는 같은 값·올리기를 무시하므로 중복은 무해). 거울이 없으면 캐노니컬 게시 직후 비운다.
- 공개 노출: 폐기된 세션의 `pk_i` 가 거울에 보인다. `pk_i` 는 거래 때 `pub[2]` 로 이미 공개되고, 거래하지 않은 세션키는 무작위 값이라 누구와도 연결되지 않는다(D1·PPID 비연결성 불변).

## 3. 계정 컨트랙트 `Mode3Wallet`
- 생성자 파라미터 `uint64 rootWindow`(G, 블록) — 팩토리·지갑 생성자의 **마지막** 인자이고 팩토리 `_initCode` 에도 들어간다(CREATE2 주소가 바뀌므로 스택 재배포). 데모 20(`ROOT_WINDOW_DEFAULT`). 지갑 에이전트는 팩토리의 `rootWindow()` 를 0..200 범위로 받아들인다(`FACTORY_ROOT_WINDOW_BAND`).
- `_checkStatement`: `root != log.revRoot()` → `!log.isAcceptableRevRoot(root, rootWindow)` 이면 `StaleRevocationRoot`; 등록부도 `isAcceptableRegRoot`. 오류 이름·`RootTooOld`(하트비트 liveness) 는 그대로.
- 거래 경로의 세션 상한 검사(현재 `sessionBound[pk_i]`): 거울 값 `log.sessionBoundOf(pk_i)` 와 자기 호출 값 중 **0 이 아닌 것 중 더 낮은 값** 을 적용. `nonce + 1 >= bound` 이면 `SessionBounded(pk_i, bound - 1)`. 이 값을 `effectiveSessionBound(pk_i) view` 로도 노출한다(저장 인코딩 c + 1).
- `setSessionBound`(자기 호출) 는 선택 기능으로 유지(2026-10-25 결정 1: 기본 꺼짐, 거울 값이 정본).

## 4. IdP `cia.js` 와 게시

- IdP 는 발급 때 세션키 `pk_i` 를 **모른다**(`/cia/issue` 요청에 없고 `C_s` 안에만 있다 — D1 비연결성: 알면 거래 `pub[2]` 와 세션을 연결할 수 있다). 그래서 `pk_i` 는 **폐기 때** 지갑이 알려 준다: `/cia/revoke scope=session` 본문에 `pk_i`(10진, < 2^160) 와 `sig_i` 를 함께 싣는다. `sig_i` = 세션키(secp256k1 `sk_i`) 의 EIP-191 서명, 메시지 `MODE3_REVOKE_BIND_V1|uid|Cf_s|bound|nonce`(sk_u 서명 `revokeSessionMessage` 와 같은 값, 10진 문자열, `lib/mode3_revocation.js` `revokeBindMessage`). IdP 는 `ethers.verifyMessage` 로 복원한 주소가 `pk_i` 와 같은지 본다 — 이 결속이 없으면 `sig_u` 만 가진 사용자가 **남의** `pk_i` 를 넣어 그 세션을 막을 수 있다(낮추기만이라 되돌릴 수 없다).
- 둘 중 하나만 오거나 서명이 틀리면 `400 { reason: 'bad_session_signature' }`(리프도 넣지 않음). 둘 다 없으면 지금처럼 RCL 리프만 넣는다(관리자 폐기, 옛 지갑·web 코어) — 응답 `mirrorBound: false`. 받아들이면 세션 레코드에 `pk_i` 를 적고 `state.pendingBounds` 에 `{ pk_i, bound, epoch: null }` 을 넣는다(같은 pk_i 는 더 낮은 bound 로만 갈아끼움). 응답 `mirrorBound: true`.
- `publishNow` 는 대기열 전부를 `(boundKeys, boundValues)` 로 싣고(서명이 덮는다) 성공하면 각 항목에 그 epoch 를 적는다. 아직 어느 게시에도 실리지 않은 항목이 있으면 리프·슬롯이 없어도 게시한다. `lastPublication` 에 두 배열을 남겨 거울 중계가 그대로 옮긴다. 모든 거울이 받은 epoch(거울이 없으면 캐노니컬 epoch) 이하에 실린 항목은 버린다(§2.2). 상태 스키마는 v12 유지(`pendingBounds ??= []`).
- 관리자 폐기(기본 bound 0)는 레코드에 이미 `pk_i` 가 있을 때만(앞선 사용자 폐기로) 거울 counter 를 게시한다 — 없으면 RCL 리프만.

## 5. 지갑·RP·릴레이
- 지갑 에이전트(`mode3_wallet_agent.js`): `/wallet/session/revoke` 가 본문에 `pk_i`·`sig_i`(세션키로 서명) 를 얹고, 팩토리 검사에 `rootWindow` 범위(0..200) 를 더한다. Snap·지갑 페이지·RP 오프체인 검증기(최신 root 요구)는 변경 없음. RP(`mode3_rp.js`) 는 env `MODE3_ROOT_WINDOW`(기본 20) 를 팩토리 배포에 넘긴다.
- RP 로그인 검증·릴레이 길이 검사 변경 없음.

## 6. 파라미터
- G(블록): 창이 덮어야 할 지연 L = root 동기화(0.3 s) + π_RP(1~3 s) + MetaMask 승인(수십 초) + 포함. 데모(automine + 50블록 하트비트) 기본 **20**; 공개 체인은 블록 시간에 맞춰(12 s 체인 ≈ 10). 생성자 파라미터로 바꾼다. 코드 상수 `ROOT_WINDOW_DEFAULT = 20n`(`lib/mode3_onchain.js`), RP env `MODE3_ROOT_WINDOW`.
- K(링 버퍼): 16. G 블록 안에 일어날 root 갱신 수보다 크게. 모자라면 liveness 만 깎인다. 컨트랙트 상수 `ROOT_HISTORY = 16`.

## 7. 보장과 한계
- 보장(liveness): 창 안 root 로 만든 거래는 타 사용자의 폐기·등록과 무관하게 통과한다.
- 보장(safety): 폐기된 세션 S 의 거래 중 `nonce ≥ c` 는 (i) 거울에 `(pk_S, c)` 가 반영된 뒤 즉시, (ii) 창이 닫힌 뒤에는 회로 구간 검사로 막힌다. `nonce < c` 는 정의상 허용.
- 한계 1(창 안, 폐기 직후): `(pk_S, c)` 가 거울에 반영되기 전까지의 거래는 레이스 (2) 와 같은 성격(채굴 순서). 거울 반영은 root 게시와 같은 트랜잭션이라 창 자체가 추가 노출을 만들지는 않는다.
- 한계 2(등록부 창): 자격증명 교체·은퇴 직후 G 블록 동안 옛 자격증명으로 증명이 통과할 수 있다(세션 폐기는 counter 로 막힘).
- 한계 3(레이스 (2)): 그대로. 지연 실행 큐(execute 적재 → G 뒤 finalize 에서 `nonce < c` 재확인)만이 제거 수단 — 후속 설계.
- 한계 4(공개): 폐기된 세션키 목록이 거울에 남는다(위 §2.2 평가).

## 8. 테스트
- 컨트랙트(`test/Mode3Log.test.mjs` 신설 또는 기존 확장, `test/Mode3Wallet.test.mjs`): 최신 root 수락; 대체된 root 가 `G` 안이면 수락·`G+1` 이면 `StaleRevocationRoot`; 등록부 동일; 링 버퍼 밀림; `sessionBoundOf` 낮추기만·게시 다이제스트에 포함; 거울 counter 만으로 `SessionBounded`; 자기 호출 값과 거울 값 중 낮은 쪽 적용.
- 체인(`tests/test_mode3_rp.mjs`, `tests/test_mode3_wallet_agent.mjs`, `tests/test_cia_registry.mjs`): "다른 사용자 폐기 뒤 옛 root 증명이 통과"(현재 stale 기대 케이스 역전), "신규 등록 뒤 옛 등록부 root 증명 통과", "폐기 뒤 거울 counter 로 `nonce ≥ c` 즉시 차단(root 창 안에서도)", IdP 게시 페이로드에 `(pk_i, bound)` 포함·다이제스트 검증.
- 벤치 영향 없음(회로 불변). 데모 스택 재배포 필요(팩토리·로그 컨트랙트 변경) — `scripts/deploy_*`·`demo_*` 의 생성자 인자(G) 반영.

## 9. 미결·후속
- 레이스 (2) 지연 큐 설계(별도 스펙).
- 기본 G 의 실측 보정: 데모에서 "증명→포함" 지연 분포를 기록해 p99 기준으로 조정.
