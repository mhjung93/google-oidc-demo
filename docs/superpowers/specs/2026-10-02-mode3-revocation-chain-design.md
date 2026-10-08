# Mode 3 V10 설계 — 폐기 전용 블록체인(revocation chain)과 체인별 거울

작성 2026-10-02. 상태: **초안(사용자 검토 대기)**. 근거가 된 논의: 2026-10-02 대화(결정 1·2·3), V9 스펙 `2026-10-01-mode3-v9-registry-design.md`, 현행 코드 `contracts/Mode3Log.sol`(V2), `cia.js`, `lib/mode3_rp.js`, `lib/mode3_rcl_sync.js`, `lib/mode3_registry_sync.js`, `mode3_wallet_agent.js`.

## 0. 한 줄 요약

폐기 상태(세션 폐기 트리 root, 사용자 자격증명 등록부 root)의 **정본은 폐기 전용 체인 하나**에 둔다. 응용 체인마다 **거울(mirror) 컨트랙트**가 그 root 를 하트비트 주기로 받아 적고, 그 체인의 검증자(RP·PPID 계정)는 **자기 거울 값만** 본다. 사용자의 폐기 요청은 지금처럼 uid/비밀번호로 IdP 에 내되, IdP 가 **서명한 접수증**을 돌려주고, 접수증을 폐기 체인에 올리면 IdP 의 다음 게시가 그 슬롯을 0 으로 만들도록 **강제**된다. 회로·증명·검증 논리는 바뀌지 않는다.

## 1. 왜

- 지금(V9)은 체인마다 `Mode3Log` 가 하나씩 있고 IdP 가 체인마다 따로 게시한다. 체인이 늘수록 게시 비용과 상태 불일치 가능성이 선형으로 는다. 폐기 상태는 체인과 무관한 IdP 의 상태이므로 **한 곳에 두고 나머지는 그 값을 참조**하는 편이 chain-agnostic 하다.
- 폐기 체인이 "IdP 가 낸 모든 폐기·등록부 변경의 순서 있는 공개 기록"이 되면, 사용자가 자기 요청의 반영 여부를 한 곳에서 확인할 수 있고(책임성), 응용 체인은 그 기록만 믿으면 된다.

## 2. 구성 요소

| 구성 요소 | 어디 | 역할 |
|---|---|---|
| **폐기 체인**(revocation chain) | 별도 체인(데모: 두 번째 hardhat 노드) | 정본. `Mode3Log` V3(캐노니컬 로그) + 폐기 요청 대기열 |
| **`Mode3Log` V3**(캐노니컬) | 폐기 체인 | V2 와 같은 `publish`(두 root·리프·슬롯·IdP 서명) + 대기열 강제 + 은퇴 슬롯 잠금 |
| **`Mode3Mirror`** | 응용 체인마다 하나 | (revRoot, regRoot, epoch, lastPublishedBlock) 만 보관. IdP 서명 검증, epoch 단조 증가. **`revRoot()`·`regRoot()`·`lastPublishedBlock()` 의 ABI 는 V2 로그와 같게** 두어 `Mode3Wallet`·RP 코드가 읽는 주소만 바꾸면 되게 한다 |
| **IdP(CIA)** | 오프체인 | 폐기 체인에 게시, 접수증 서명, 기본 릴레이어(하트비트로 거울 갱신) |
| **릴레이어** | 누구나 | 캐노니컬 게시(서명 포함)를 거울에 옮긴다. 권한은 서명에 있으므로 신뢰 불필요 |
| **지갑** | 오프체인 | 트리 재구성은 **폐기 체인 이벤트**로, 증명에 쓸 root 는 **대상 체인 거울**에서 |
| **RP** | 오프체인 | 자기 chainid 의 거울을 읽는다(폐기 체인이 아니라) |
| **`Mode3Wallet`(PPID 계정)** | 응용 체인 | 자기 체인 거울의 두 root·나이와 π 를 대조(현행 그대로) |

## 3. 결정 1 — 거울의 신뢰 근거: IdP 서명 재생 (A)

- 거울은 **IdP 서명만** 검증한다. 폐기 체인은 정본·감사 기록이지 신뢰의 원천이 아니다(신뢰 원천은 여전히 IdP 키 — 현행 모델과 같다). 브리지/라이트 클라이언트(B)·오라클(C)은 채택하지 않는다. 다만 거울 메시지에 폐기 체인의 epoch 를 넣어 두므로 나중에 (B)로 올릴 수 있다.
- **서명 메시지(V3 다이제스트)**: `keccak(DOMAIN="MODE3_LOG_V3", canonicalChainId, canonicalLogAddress, newRev, newReg, newEpoch, keccak(revLeaves), keccak(slotIdx), keccak(slotLeaves))`.
  - V2 의 `address(this)` 자리에 **캐노니컬 로그의 (chainid, 주소)** 를 넣는다. 그래서 같은 서명이 캐노니컬 로그와 모든 거울에서 유효하고(의도), 다른 배포(다른 캐노니컬 로그)로의 재생은 막힌다.
  - 거울은 리프·슬롯 배열이 필요 없으므로 **세 해시만 calldata 로** 받는다: `mirror.publish(newRev, newReg, newEpoch, hLeaves, hIdx, hSlots, sig)`. 서명 하나가 캐노니컬·거울 양쪽에 쓰인다.
- **재생 방지**: 캐노니컬·거울 모두 `newEpoch > lastEpoch` 만 요구(V2 와 같음, 건너뜀 허용). 거울은 캐노니컬보다 뒤처질 수는 있어도 앞설 수는 없다(캐노니컬에 없는 epoch 의 서명은 IdP 가 만들지 않는다 — IdP 는 캐노니컬 게시가 확정된 뒤에만 그 서명을 거울로 보낸다)(IdP 는 서명한 epoch 를 재사용하지 않는다 — §9).

## 4. 결정 2 — 사용자 폐기 요청: uid/비밀번호 → IdP, 접수증으로 강제

채택: **주 경로는 현행대로** `POST /cia/account/self_revoke { uid, pwd }`. 폐기 전용 키(sk_rev)는 두지 않는다. 이유: (1) IdP 가 요청을 묵살하는 것은 honest-but-curious 모델 밖의 능동 공격이라, 그걸 막자고 모든 사용자에게 비밀 하나를 더 보관시키는 비용이 맞지 않는다. (2) 장치를 잃은 사용자에게 남는 인증 수단은 비밀번호뿐이다. (3) IdP 가 꺼져 있으면 공격자도 새 세션을 못 받으므로 피해가 max_height 창에 묶인다.

그래도 "요청을 받고도 반영하지 않는 것"은 사용자 부담 없이 막을 수 있다.

1. IdP 는 자기 폐기(및 관리자 폐기)를 처리하면서 **접수증** `receipt = Sign_IdP(keccak(D_RECEIPT="MODE3_REVOKE_RECEIPT_V1", canonicalChainId, canonicalLogAddress, slot, epochAtRequest, requestedAt))` 를 응답에 함께 돌려준다. uid 는 넣지 않는다(슬롯은 SlotUpdated 로 어차피 공개되는 값).
2. 평소: IdP 가 다음 게시에 `slot := 0` 을 넣는다(현행 즉시 게시). 접수증은 쓰이지 않는다.
3. IdP 가 미적대면 **사용자든 누구든** 접수증을 폐기 체인의 대기열에 올린다: `Mode3Log.requestRevocation(slot, epochAtRequest, requestedAt, sig)`. 컨트랙트는 IdP 서명만 확인하고 `pending[slot] = true` 로 적는다.
4. **강제**: `publish` 는 pending 인 모든 슬롯이 이번 `slotIdx` 에 리프 0 으로 들어 있지 않으면 revert 한다(`PendingRevocationNotApplied(slot)`). 하트비트도 `publish` 이므로 막힌다 → root 가 늙어 전원 Stale → IdP 는 따를 수밖에 없다. 처리된 슬롯은 pending 에서 지운다.
5. **영구 은퇴**: 대기열을 거쳐 0 이 된 슬롯은 `retired[slot] = true` 로 잠그고, 이후 그 슬롯에 0 아닌 리프를 쓰는 `publish` 는 revert 한다(`SlotRetired`). 재발급은 새 슬롯으로 받는다(IdP 가 새 슬롯을 배정). PPID 는 uid·s_u 에만 걸려 있어 슬롯이 바뀌어도 그대로다. (IdP 가 자발적으로 0 으로 만든 슬롯은 현행대로 재사용 가능 — 속성 변경에 따른 은퇴·재발급이 같은 슬롯을 다시 채운다.)
6. IdP 가 접수증 자체를 안 주면 강제는 못 하지만 사용자가 그 자리에서 알아챈다(지금은 그것도 모른다).
7. **세션 폐기**(Cf_s + sk_u 서명)는 현행대로 IdP 만 처리한다. 컨트랙트는 Cf_s 가 누구 것인지 알 수 없고, 이번 논의 범위 밖이다.

기각한 대안과 이유: sk_rev(보관 부담, 모델 밖 위협), 비밀번호 파생 키를 등록부에 공개(pk 로 비밀번호 오프라인 사전 공격 → IdP 로그인·재발급까지 뚫림), 컨트랙트가 Merkle 경로를 받아 root 를 직접 갱신(깊이 20 Poseidon ×2 온체인, 가스 과다).

## 5. 결정 3 — 거울 갱신: 하트비트 주기, 거울 값만 기준

- 체인 X 의 거울은 **주기 H_X 블록**(체인 X 기준)마다 릴레이어가 **캐노니컬의 최신 게시(서명 포함)** 를 올려 갱신한다. 캐노니컬에 변화가 없어도 올린다(하트비트) — IdP 는 캐노니컬에 하트비트 게시(현행 50블록)를 계속 내므로 거울에 올릴 새 epoch 가 항상 있다.
- 체인 X 의 RP 와 `Mode3Wallet` 은 **거울 X 의 (revRoot, regRoot, lastPublishedBlock) 만** 본다. 검사는 현행 그대로: π 의 두 root = 거울 root, `head − lastPublished ≤ MAX_ROOT_AGE_X`.
- **지연**: 체인 X 에서 폐기가 효력을 갖는 시점은 캐노니컬 게시 뒤 **다음 거울 갱신**이다(등록부 "즉시 게시"도 X 기준으로는 다음 하트비트). 첫 로그인 대기도 그만큼 는다. `MAX_ROOT_AGE_X ≥ 2–3·H_X` 로 두어 하트비트 한두 번을 놓쳐도 바로 멈추지 않게 한다.
- **거울이 저장할 값**: root 두 개 + **epoch** + lastPublishedBlock. 지갑은 폐기 체인 이벤트로 트리를 재구성하므로 "거울 X 의 root 가 어느 epoch 까지 반영한 것인지" 가 있어야 그 시점의 트리로 Merkle 경로를 만들 수 있다. 체인마다 epoch 가 다를 수 있다.
- **지갑**: 동기화 소스는 폐기 체인(이벤트 `Revoked`·`SlotUpdated` 는 epoch 가 indexed 라 "epoch ≤ E 까지" 로 자를 수 있다). 증명 캐시 키는 `(chainid, revRoot, regRoot, r_s)`. 로그인 전 "내 슬롯 확인"은 캐노니컬 최신 상태로 한다(은퇴·대체 탐지는 빠를수록 좋다).
- **RP**: 자기 chainid 의 거울을 읽는다. 로그인 증명과 그 세션의 트랜잭션 증명이 같은 root 를 써야 증명 하나로 둘 다 쓰므로, 폐기 체인을 직접 읽으면 안 된다.
- **릴레이어 생존성 = 체인 가용성**: 거울이 비면 그 체인은 전원 Stale 로 멈춘다. IdP 가 기본 릴레이어를 돌리고(체인마다 `H_X` 폴링), 누구든 대신 올릴 수 있다. 거울은 epoch 단조 증가만 보므로 둘이 동시에 올려도 안전하다(뒤처진 쪽은 `EpochNotIncreasing` 로 revert — 릴레이어는 그 revert 를 "이미 갱신됨" 으로 처리).

## 6. 바뀌는 범위 (V9 → V10)

| 영역 | 변경 |
|---|---|
| `contracts/Mode3Log.sol` | V3: 다이제스트에 `(canonicalChainId, canonicalLogAddress)`; `requestRevocation`; `publish` 의 pending 강제·retired 잠금; `error PendingRevocationNotApplied(uint32)`, `SlotRetired(uint32)`; `event RevocationRequested(uint32 slot, uint64 epochAtRequest)` |
| `contracts/Mode3Mirror.sol` | 신규: `publish(newRev, newReg, newEpoch, hLeaves, hIdx, hSlots, sig)`, getters `revRoot/regRoot/lastEpoch/lastPublishedBlock` (V2 로그와 같은 이름) |
| `contracts/Mode3Wallet.sol`·Factory | 생성자 인자의 로그 주소가 **거울 주소**가 된다. 읽기 ABI 가 같으므로 코드 변경 없음(배포 인자만) |
| 회로·`PiCredVerifier` | **변경 없음** |
| `cia.js` | 게시 대상 = 폐기 체인 RPC(`CIA_REV_CHAIN_RPC`, `CIA_LOG_ADDRESS`); 거울 목록 `CIA_MIRRORS=chainid=url=mirrorAddress,…`; 체인별 릴레이 루프(`H_X`); `self_revoke`·`/cia/revoke scope=account|credential` 응답에 `receipt`; 재기동 대조는 캐노니컬 기준 |
| `lib/mode3_log.js` | V3 다이제스트, 접수증 서명·검증, 거울 호출 |
| `lib/mode3_rp.js` | 읽는 주소를 `mirrorAddress`(chainid 별)로. 로직 동일 |
| `lib/mode3_rcl_sync.js`·`mode3_registry_sync.js` | 소스 = 폐기 체인 provider; "epoch ≤ E 까지" 재구성 옵션 |
| `mode3_wallet_agent.js` | 두 provider(폐기 체인, 대상 체인); 거울 읽기; 캐시 키에 chainid; `registry_unpublished` 대기는 "거울 X 에 반영될 때까지" |
| `scripts/deploy_v4_stack.cjs` 류·데모 스택·`run_tests.sh chain` | 두 hardhat 노드(폐기 체인 :8546 가칭) + 거울 배포; 격리 테스트 헬퍼도 두 노드 |
| 문서 | `docs/MODE3_DEMO.md` 런북, 논문 §VI(게시·검증), Fig. 1·2, 폐기 슬라이드 2·3장 |
| 비용 | 거울 갱신 가스(해시 3개 + 서명 검증, 추정 ~50k)·체인 수만큼; 캐노니컬 게시는 V2 와 같음 + pending 검사 |

## 7. 별도 제안(이 설계와 독립, 채택 여부 따로)

- **sk_u 제거**: 지갑→IdP 요청 인증을 EdDSA 키 대신 cm_u 의 열림 (s_u, r_u) 에 대한 Fiat–Shamir 증명(Okamoto 서명)으로. IdP 가 저장하는 값이 cm_u 하나로 줄고 sig_reg·pk_u 가 사라진다. 회로 무관.
- **s_u·r_u 시드 파생**: 지금 Snap 은 등록 비밀을 난수로 만들어 Snap 저장소에만 둔다(`snap-mode3/src/crypto.js`). 장치를 잃으면 s_u 와 함께 PPID 를 잃는다. `snap_getEntropy` 파생으로 바꾸면 시드 백업으로 복구된다. 이때 "폐기가 필요한 상황"은 분실이 아니라 시드 유출이 된다.

## 8. 남는 질문

1. 폐기 체인은 무엇으로? 데모는 hardhat 두 번째 노드. 실제로는 저렴한 L2 나 전용 체인 — 거울 갱신 가스가 체인 수에 비례하므로 응용 체인 쪽 비용이 결정 요인.
2. `H_X`·`MAX_ROOT_AGE_X` 기본값(데모: H=50, MAX=100 을 두 체인에 같이 두고 시작).
3. 접수증을 어디에 보관하나 — 지갑 상태 파일·브라우저 다운로드·IdP 계정 페이지 재발급(IdP 가 안 주면 그게 신호) 중 택.
4. 오프체인 전용 RP(체인 없는 서비스)는 어느 거울을 읽나 — chainid 가 공개 입력이므로 그 chainid 의 거울. chainid 없는 RP 는 없다(현행도 같음).

## 9. 구현 중 확정한 룰링 (2026-10-02, SDD 실행 원장에서 옮김)

구현·리뷰 과정에서 §3~§5 를 다음과 같이 구체화하거나 고쳤다. 코드가 정본이며, 아래는 그 요약이다.

- **접수증은 계정 폐기에만** 낸다(`/cia/account/self_revoke`, `/cia/revoke scope=account`). `scope=credential`(속성 변경에 따른 은퇴)은 IdP 가 결정하는 것이라 사용자가 강제할 요청이 없고, 접수증을 내면 다시 채운 슬롯을 누구든 나중에 은퇴시킬 수 있어서다. 접수증은 만료가 없으므로 §4.5 의 "영구 은퇴" 를 **로컬에서도** 적용한다: 계정 폐기는 `slotRetired = true` 로 그 슬롯을 영구히 비우고, 관리자가 되살린 계정의 재발급은 **새 슬롯**을 받는다. 그래서 옛 접수증은 이미 영원히 빈 슬롯만 가리킨다. 접수증은 응답에 실리고 `accounts[uid].receipt` 에 저장되며 같은 요청을 다시 보내면 같은 것을 돌려준다(멱등).
- **게시 강제 규칙(컨트랙트)**: pending 슬롯의 `slotIdx` 항목은 **모두** 리프 0 이어야 하고 하나는 있어야 한다. "하나만 0" 으로 두면 `[0, 42]` 처럼 미끼 항목으로 우회된다(지갑은 이벤트를 순서대로 재생해 마지막 값이 이긴다). 오류 이름은 이벤트 `SlotRetired` 와 겹쳐 `SlotIsRetired` 다.
- **IdP 의 대기열 따르기**: `publishNow` 는 빈 게시의 조기 반환보다 먼저 `pendingSlots()` 를 읽고, 그 슬롯의 백로그 항목을 모두 걷어낸 뒤 `(slot, 0)` 하나만 싣는다(계정이 없는 슬롯도 로컬 트리를 0 으로 맞춘다). 게시 직전에 이번 배치의 슬롯 중 온체인 `isRetired` 인 것이 0 이 아니면 0 으로 강제한다 — 옛 백업을 복원한 IdP 가 `SlotIsRetired` 로 영구히 막히는 것을 막는다.
- **게시 락**: 거울 트랜잭션은 같은 키의 nonce 경합 때문에 캐노니컬 게시와 같은 `publishing` 락을 쓴다. 락 획득은 원자적이어야 한다(대기 루프와 대입이 같은 동기 구간, 소유자만 해제) — 아니면 게시·거울 tx 가 겹치거나 `publishSafely` 가 409 로 게시를 잃는다.
- **릴레이**: 거울 갱신은 거울 체인 head 기준 주기(`CIA_MIRROR_HEARTBEAT_BLOCKS`)로만; 캐노니컬에 새 epoch 가 없으면 캐노니컬 하트비트를 먼저 올린다. `POST /cia/admin/relay` 는 주기를 무시하고 캐노니컬 하트비트 하나를 더 쓴다(데모·관리용). 건강 정보는 `/mode3/health` 의 `mirrors[]`.
- **릴레이 개정(2026-10-05, 전체 코드 리뷰 3·9번)**: 위 "새 epoch 가 없으면 하트비트를 먼저 올린다" 는 §5 원문("IdP 는 캐노니컬에 하트비트를 계속 내므로 거울에 올릴 새 epoch 가 항상 있다")과 어긋났고, 캐노니컬 게시가 거울 수·짧은 H 에 비례해 늘었다(데모에서 15초마다 epoch +1). 이제 (1) 캐노니컬 게시가 성공하면 곧바로 뒤처진 거울에 중계한다(`CIA_MIRROR_RELAY_ON_PUBLISH`, 기본 켬 — 첫 로그인이 30초 대기를 넘기던 문제와 폐기 반영의 시간 상한 부재를 함께 고친다), (2) 주기 틱은 안전망(뒤처진 거울의 behindSince·lastPublished 상한, 불일치 복구)이고 따라잡은 거울에는 아무것도 하지 않는다. 하트비트를 새로 만드는 것은 불일치 복구·관리자 강제·게시 기록 없음일 때뿐이다. 따라서 거울 신선도 = 캐노니컬 정규 하트비트 주기 + 중계 지연이고, `CIA_HEARTBEAT_BLOCKS` 의 시간은 각 응용 체인 `MAX_ROOT_AGE` 시간보다 짧아야 한다.
- **지갑**: 증명의 root 는 거울 뷰, "내 슬롯"·세션 리프 확인은 캐노니컬 최신(캐시 히트에서도) — 거울이 뒤처진 동안 폐기된 계정이 트랜잭션을 내지 못하게. 공유 rcl 트리에 동시 sync 가 끼어들어 π 의 root 가 거울과 달라지면 격리 트리로 한 번 재증명하고, 그래도 다르면 `sync_unstable`(503). 거울 뷰에 내 리프가 없으면 `registry_unpublished` 로 기다린다(첫 로그인·비-fresh 모두).
- **최종 리뷰 I-3 — 옛 접수증과 복구된 계정**: 대기열 따르기에서 pending 슬롯의 계정이 이미 `slotRetired` 면(계정 폐기 뒤 관리자가 되살렸지만 아직 재발급 전이라 `acct.slot` 이 옛 슬롯) 계정은 건드리지 않는다(`disabled`·활성 자격증명 은퇴 생략). 로컬 트리를 0 으로 맞추고 `(slot, 0)` 을 싣는 것은 그대로다 — 재발급은 어차피 새 슬롯을 받는다.
- **최종 리뷰 I-1 — 거울 갱신 트리거**: `lastPublishedBlock` 은 누구나(캐노니컬에 공개된 중간 epoch 서명을 올려) 갱신할 수 있으므로 그것만으로는 갱신 지연의 상한이 없다. 거울마다 `behindSince`(거울이 캐노니컬보다 뒤처진 것을 처음 관측한 거울 체인 블록, IdP 메모리)를 두고, 뒤처져 있으면 `head_X − behindSince ≥ H` 일 때 중계한다(따라잡으면 null). 뒤처지지 않았으면 기존대로 `head_X − lastPublishedBlock ≥ H` 일 때 하트비트(둘은 OR — 기동 직후 오래 뒤처진 거울은 뒤쪽이 먼저 걸린다).
- **최종 리뷰 I-2 — 서명한 epoch 는 소비된다, 거울 대조**: `pendingSlots()` 를 읽은 뒤 채굴 전에 접수증이 끼면 게시가 revert 되고 그 epoch 의 서명이 calldata 로 공개된다. IdP 는 서명 **전에** `signedEpochMax` 를 저장하고 `max(epoch, signedEpochMax) + 1` 을 쓴다(상태 파일 필드, 버전 10 유지·기본 0). 릴레이는 거울의 `(epoch, revRoot, regRoot)` 를 캐노니컬(체인에서 읽은 값)·`lastPublication` 과 대조해, 거울이 앞서거나 같은 epoch 에 다른 root 면 주기와 무관하게 즉시 그보다 큰 epoch 의 하트비트로 덮는다(거울 epoch 는 IdP 서명으로만 오르므로 그 epoch 까지 `signedEpochMax` 를 끌어올린다). 건강 정보 `mirrors[]` 에 `mismatch` 를 낸다. 거울이 캐노니컬보다 뒤인데 root 가 다른 경우(건너뛴 epoch 의 서명)는 기록이 없어 대조하지 못하고, I-1 의 뒤처짐 트리거가 H 안에 덮는다.
- **테스트·데모**: chain 그룹은 :8545 하나에 로그와 거울을 둔다. 두 노드 구성(폐기 체인 :8546)은 런북의 선택 절이며 코드 읽기로 작성됐고 전체 실행은 하지 않았다(2026-10-02).
