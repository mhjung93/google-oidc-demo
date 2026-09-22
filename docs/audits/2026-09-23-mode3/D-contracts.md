# 점검자 D — 컨트랙트·온체인 인코딩·테스트 커버리지

대상 HEAD `64cf579`(`feat/mode3-cia`). 읽기 전용 점검. 서버·테스트는 돌리지 않았고, 순수 함수(`ethers` ABI 인코딩)만 `node -e` 로 확인했다.

## 1. 판정 요약

- Mode 3 컨트랙트 4종(`Mode3Wallet`·`Mode3WalletFactory`·`RevocationLog`·`AttrGate`)은 스펙 2026-09-18 §5.3 의 검사 10단계와 2026-09-22 선택 공개 §5.1 을 **순서까지 그대로** 구현하고 있고, 재진입·서명 가변성·꼬리 위조·교차 로그 재생 같은 고전적 함정은 모두 막혀 있다. Critical 없음.
- JS(`lib/mode3_onchain.js`·`lib/mode3_log.js`)와 Solidity 의 다이제스트 인코딩은 **독립 구현끼리 대조**되고 있어(헬퍼가 컨트랙트 view 를 부르지 않는다) "테스트가 통과한다"가 실제 증거로 성립한다. `uint256[4]` 고정 배열이 인라인된다는 점도 별도로 확인했다.
- 남은 것은 운영 문서와 코드가 어긋나는 두 건(팩토리 initcode 인자 경고 누락, `contract` 그룹의 숨은 의존성)과, 검사 순서 §5.3 중 **다이제스트가 덮는 필드(chainid·to·value·data) 변조**·`recovered == address(0)` 경로가 테스트에 없다는 커버리지 구멍이다.

---

## 2. 발견 목록

### Critical
없음.

### Important

**I-1. `MODE3_MAX_LIFETIME_BLOCKS`·`MODE3_VERIFIER_ADDRESS` 도 PPID 계정 주소를 바꾸는데 문서 경고에는 `MODE3_MAX_ROOT_AGE` 만 적혀 있다 — 확인**
`docs/MODE3_DEMO.md:62-63` / `contracts/Mode3WalletFactory.sol:32-37`
`_initCode()` 가 `abi.encode(ppid, arid, pkCIAX, pkCIAY, pkTraceX, pkTraceY, verifier, log, maxRootAge, maxLifetime)` 를 creationCode 뒤에 붙이므로 **아홉 인자 중 어느 하나라도** 바뀌면 initcode hash → CREATE2 주소가 전부 바뀐다. 문서 경고는 "팩토리를 다시 배포하거나 `MODE3_MAX_ROOT_AGE` 를 바꾸면" 만 적는다.
실패 시나리오: 잔액이 있는 데모 도중 `mode3_rp_registration.json` 의 `factoryAddress` 를 지우고(로그 재배포 절차, 문서 271-274 줄이 권하는 동작) `MODE3_MAX_LIFETIME_BLOCKS=600` 으로 RP 를 재기동하면 — 문서가 경고한 `MAX_ROOT_AGE` 는 건드리지 않았는데도 — 모든 PPID 지갑 주소가 달라지고 옛 주소의 잔액에 접근할 방법이 없어진다.
고치는 방향: 경고 문장을 "팩토리 생성자 9인자(verifier·arid·pk_CIA·pk_trace·log·maxRootAge·maxLifetime) 중 하나라도 바뀌면" 으로 일반화.

**I-2. 팩토리 배포 후 `MODE3_MAX_LIFETIME_BLOCKS` 를 바꾸면 온체인 상한과 오프체인 상한이 갈라진다 — 확인**
`mode3_rp.js:121-128, 146` / `contracts/Mode3Wallet.sol:21,135`
`ensureFactory()` 는 `reg.factoryAddress` 가 이미 있으면 바로 리턴하므로 팩토리의 `maxLifetime`(immutable)은 옛 값 그대로인데, 같은 기동에서 `createRpVerifier({ maxLifetimeBlocks: MAX_LIFETIME })` 는 **새 env 값**을 쓴다.
실패 시나리오: 운영자가 세션을 더 길게 쓰려고 `MODE3_MAX_LIFETIME_BLOCKS` 를 400 → 800 으로 올리고 RP 만 재기동한다. 지갑이 `max_height = head + 700` 인 성명을 받으면 RP 오프체인 로그인은 통과하지만(`bad_expiry` 안 남), 모든 `execute` 는 `TooFarExpiry` 로 revert 한다 — "로그인은 되는데 트랜잭션만 전부 실패" 라는 진단하기 어려운 상태가 된다. 반대로 내리면 체인은 받는데 로그인이 `bad_expiry` 로 막힌다.
고치는 방향: 기동 시 `factory.maxLifetime()`/`maxRootAge()` 를 읽어 env 와 다르면 경고(또는 팩토리 값을 정본으로 채택).

**I-3. `contract` 그룹이 `build/mode3/pi_cred_final.zkey`·wasm 을 전제하는데 문서에는 "외부 의존 없음" 처럼 적혀 있다 — 확인**
`test/Mode3Wallet.test.mjs:13,17` / `scripts/run_tests.sh:13` / `CLAUDE.md`(테스트 그룹 설명)
`before(() => { if (!fs.existsSync(ZKEY)) throw ... })` 라 zkey 가 없으면 mocha 훅 실패로 **그룹 전체**가 깨진다. `run_tests.sh` 의 주석은 build/mode3 산출물 요건을 `chain` 그룹에만 적어 두었고(12줄), `contract` 는 "hardhat 인프로세스 체인" 만 적는다(13줄).
실패 시나리오: clean checkout 에서 `bash scripts/run_tests.sh contract` 를 돌리면 회로 산출물이 없어 Mode3Wallet 22 케이스가 통째로 실패하고, 원인이 컨트랙트 회귀처럼 보인다.
고치는 방향: 13줄 주석과 CLAUDE.md 에 "build/mode3 의 pi_cred zkey·wasm 필요" 를 명시.

### Minor

**M-1. `mask ≠ 0` + 빈 `payload.data` 는 꼬리가 붙어 `receive()`-only 대상 송금이 조용히 실패한다 — 확인(의도된 경계, 테스트 없음)**
`contracts/Mode3Wallet.sol:110-113`
예외는 `payload.data.length == 0 && pub[14] == 0` 에만 걸리므로, 선택 공개를 켠 채 단순 송금하면 288바이트 꼬리가 붙어 `receive()` 가 실행되지 않고 `Executed(success=false)` 로 nonce 만 소모된다. 스펙 §5.1(191줄)의 예외 정의와 **정확히 일치**하므로 결함은 아니지만, 사용자 관점에선 "공개 체크박스를 켰더니 송금이 실패" 로 보인다. 테스트는 `mask=0`+빈 data(성공)와 `mask=0`+data 있음(실패) 두 경우만 고정하고 이 세 번째 조합은 없다.
고치는 방향: 지갑(`/wallet/tx`)에서 `data === '0x' && mask != 0` 을 미리 거절하거나 문서에 한 줄.

**M-2. 릴레이어의 가스 그리핑 — 내부 호출만 OOG 로 죽이고 nonce 를 태울 수 있다 — 확인(코드), 영향은 추측**
`contracts/Mode3Wallet.sol:113`
`payload.to.call{value:}(data)` 에 가스 상한이 없고 호출 실패를 전파하지 않으므로, 릴레이어가 `verifyProof`(~340k) 는 통과하되 내부 호출이 63/64 규칙으로 OOG 나도록 가스를 맞춰 제출하면 `nonce` 만 올라가고 아무 일도 일어나지 않는다. 사용자는 그 π·서명을 다시 못 쓴다(nonce 가 올랐다). 데모에선 릴레이어 = 사용자 자신의 에이전트라 실害는 없다.
고치는 방향: payload 에 `gasLimit` 을 넣어 다이제스트로 덮고 `require(gasleft() > gasLimit * 64/63 + …)`.

**M-3. `transcriptFromTx` 의 "성공한 execute 만 받는다" 는 주석이 사실과 다르다 — 확인**
`mode3_rp.js:293,300` (스펙 §6.2 문구도 같다)
`Mode3Auth` 는 내부 호출 성공 여부와 무관하게 emit 되므로(`Mode3Wallet.sol:116`), `Executed(success=false)` 인 트랜잭션도 개봉 재료로 통과한다. 보안 경계는 아니다(π 자체는 온체인에서 검증됐고 CIA 가 Groth16 을 다시 본다). 주석/스펙 문구를 "revert 하지 않은 execute" 로 고치는 편이 맞다.

**M-4. `publishRoot` 의 `leaves` 길이가 무제한이고 CIA 가 pending 전부를 한 트랜잭션에 싣는다 — 확인**
`contracts/RevocationLog.sol:102-112` / `cia.js:530`
`const leaves = state.pending.map(rootToBytes32);` — 청크가 없다. pending 이 블록 가스 한도를 넘을 만큼 쌓이면 게시가 영구히 실패하고, `maxRootAge` 가 지나면 **전원**이 `RootTooOld` 로 막힌다(fail-closed). 권한이 CIA 서명에 있으므로 외부 공격자의 DoS 는 아니다.
고치는 방향: 게시 배치 크기 상한(예: 리프 N개씩 여러 epoch).

**M-5. `epoch` 가 단조 증가만 되고 CIA 주소가 immutable 이라 복구 경로가 재배포뿐 — 확인(한계)**
`contracts/RevocationLog.sol:78,105`
`cia` 에 setter 가 없고 `newEpoch <= epoch` 는 무조건 거절이므로, CIA 상태의 epoch 가 체인보다 뒤처지거나 CIA 이더 키를 잃으면 게시가 영구히 막히고 로그 재배포 → 팩토리 재배포 → 모든 지갑 주소 변경으로만 복구된다(I-1 과 같은 연쇄). 문서 271-274 줄이 절차는 적고 있다.

**M-6. `factory.deploy()` 의 "다른 경로로 이미 있어도 이 팩토리 코드로 만든 주소다" 주장 — 확인(성립하지만 근거는 좁다)**
`contracts/Mode3WalletFactory.sol:47`
그 주소에 코드가 있을 수 있는 경로는 이 팩토리의 CREATE2(같은 initcode)뿐이고 `Mode3Wallet` 에 `selfdestruct` 가 없어 주장은 성립한다. 다만 무조건 `isWallet[wallet] = true` 로 표시하므로, 근거가 "CREATE2 주소 유일성" 이라는 점을 주석에 명시해 두는 편이 안전하다(`AttrGate` 의 유일한 신뢰 근거가 이 매핑이다).

**M-7. `AttrGate` 가 `hardhat.config.cjs` 의 viaIR override 목록에 없다 — 확인, 무해**
`hardhat.config.cjs:26-55`
`AttrGate.sol` 이 `Mode3WalletFactory.sol → Mode3Wallet.sol` 을 import 하지만, Hardhat 은 override 가 걸린 파일의 아티팩트를 그 파일 자신의 컴파일 job 에서만 emit 하므로 `Mode3Wallet` 바이트코드(=CREATE2 주소)는 드리프트하지 않는다. 주석에 적힌 "팩토리가 지갑을 import 하므로 같은 설정" 논리를 따르면 `AttrGate.sol` 도 목록에 넣는 게 일관적이다(기능상 필요는 없다).

---

## 3. 바이트 일치 검증 결과 (점검 포인트 3)

- `Mode3Wallet.sol:83-88` 은 `abi.encode(chainid, address(this), to, value, data, nonce, pub[14], [pub[15..18]], [pub[19..22]])`. 두 배열 리터럴은 Solidity 에서 `uint256[4] memory`(정적)이고, `lib/mode3_onchain.js:70-75` 는 `['uint256','address','address','uint256','bytes','uint256','uint256','uint256[4]','uint256[4]']` 을 쓴다.
  `node -e` 로 `uint256[4]` 인코딩이 4워드 인라인(=동적 오프셋 없음)임을 확인했다 → 타입·순서·배열 인코딩 일치. **확인**
- **독립 검증인가**: 그렇다. `test/Mode3Wallet.test.mjs:53` 은 JS `signPayload` 로만 서명하고 컨트랙트의 어떤 view 도 부르지 않는다. 즉 execute 가 통과한다는 사실 자체가 JS↔Solidity 인코딩 일치의 증거다.
- `RevocationLog.digestFor` ↔ `lib/mode3_log.js:publicationDigest` 는 `test/RevocationLog.test.mjs:92-96` 이 **두 독립 구현의 값을 직접 비교**한다(과거 사본 3벌 드리프트 사고의 대응). 빈 `leaves` 의 `keccak256(abi.encodePacked([]))` = `keccak256("")` 도 JS `solidityPacked([],[])` → `'0x'` 로 같음을 확인했다. **확인**
- `PiCredVerifier.verifyProof(uint[2],uint[2][2],uint[2],uint[23])`(125줄), `checkField` 23회(268~312줄), IC0~IC23 — 공개 입력 23개와 시그니처 일치. **확인**

## 4. 검사 순서 §5.3 ↔ 테스트 커버리지 표

| # | §5.3 검사 | 코드 | `test/Mode3Wallet.test.mjs` |
|---|---|---|---|
| 1 | `payload.nonce == nonce` | `Mode3Wallet.sol:77` | ✅ `nonce 재사용은 NonceMismatch`(101) |
| 2a | digest 의 `block.chainid` | :85 | ❌ **없음** — 어느 테스트도 다이제스트의 chainId 를 바꾸지 않는다 |
| 2b | digest 의 `address(this)` (도메인 분리) | :85 | ✅ `다른 지갑 주소로 서명한 payload`(130) |
| 2c | digest 의 `to`·`value`·`data` | :85 | ❌ **없음** — 서명 후 `to`/`data`/`value` 를 바꿔 넣는 케이스가 없다 |
| 2d | digest 의 공개 9워드(mask·lo·hi) | :86 | ✅ mask(340), hi[0](347) |
| 2e | `sig.length != 65`, high‑s, `v ∉ {27,28}` | :143-148 | ✅ malleability(117), 손상 서명(114, v=0 경로) / ❌ 길이 ≠ 65 단독 케이스 없음 |
| 2f | `recovered == address(0)` 거르기 | :92 | ❌ **없음** — 114줄 케이스는 `v=0` 검사에서 먼저 걸려 이 분기에 닿지 않는다 |
| 2g | `recovered != pub[2]` | :93 | ✅ `다른 키의 서명`(108) |
| 3 | `pub[0]/[1]/[4]` → `WrongWallet` | :124 | ✅ 세 필드 각각(137) + 다른 arid 팩토리(148) |
| 4 | `pub[7..10]` → `UntrustedKeys` | :125 | ⚠️ `pub[9]`(pk_trace.x) 하나만(154). pkCIA x/y·pk_trace.y 는 미검증 |
| 5 | `pub[5] <= 1` → `BadAllowAgent` | :126 | ✅ (161) + allowAgent=1 정상 경로(84) |
| 5′ | `pub[11..12] != (0,1)` → `BadTag` | :127 | ✅ (168) |
| 5″ | `pub[14] < 16` → `BadDisclosure` | :128 | ✅ (355) |
| 6 | `pub[6] == log.root()` → `StaleRevocationRoot` | :129-130 | ✅ (175) |
| 7 | root 나이 ≤ `maxRootAge` → `RootTooOld` | :131-132 | ✅ + 하트비트 복구까지(184) |
| 8 | `block.number <= pub[3]` → `Expired` | :133 | ✅ (202) |
| 8′ | `pub[3] <= block.number + maxLifetime` → `TooFarExpiry` | :135 | ✅ (195) |
| 9 | `verifyProof` → `InvalidProof` | :96 | ✅ (209) |
| 10a | `nonce += 1` 이 외부 호출 **앞** | :99 vs :113 | ⚠️ 간접 확인만(실패 호출도 nonce 소모, 216). 재진입 시나리오 테스트는 없음 |
| 10b | 꼬리 9워드 항상 부착(위조 방어) | :110-112 | ✅ 회귀 PoC(256) |
| 10c | 예외: 빈 data + mask=0 → 꼬리 없음 | :110 | ✅ 양쪽 경계(283) / ❌ `mask≠0` + 빈 data 조합 없음(M‑1) |
| 10d | 내부 호출 실패 시 revert 없이 `Executed(false)` | :113-115 | ✅ (216) |
| 10e | `Mode3Auth` 이벤트 | :116 | ✅ (60, 84) |
| 10f | `Disclosure` 는 `mask != 0` 일 때만 | :117-119 | ✅ 양방향(243, 299) |
| — | `receive()` | :152 | ✅ 간접(283, 다른 Mode3Wallet 수신) |

**팩토리**: `computeAddress` 멱등·`isWallet`(235, 362) ✅ / **재배포 시 주소 변화는 테스트 없음** ❌(생성자 9인자 중 `arid` 만 간접 확인, 148줄) / 팩토리 밖 배포 계정 거절은 `isWallet(random)==false` 로만 확인.

**`RevocationLog`**(`test/RevocationLog.test.mjs`): 초기 상태 ✅ / `lastPublishedBlock` 초기값·게시 갱신 ✅ / 같은 root 새 epoch(하트비트) ✅ / epoch 비증가·감소 거절 ✅ / 무허가 제출 ✅ / 비‑CIA 서명 거절 ✅ / leaves 오염 거절 ✅ / 다른 로그 주소 재생 거절 ✅ / JS digest 일치 ✅ / 빈 leaves ✅(간접) — **없는 것**: `sig.length != 65`, high‑s·`v∉{27,28}` 거절(지갑 쪽만 있다), `cia` 변경 불가(setter 부재)의 명시적 고정.

**`AttrGate`**: `isWallet` 거절(331) ✅ / 꼬리 파싱 정상(299) ✅ / 정책 실패(316) ✅ / 중복 claim(299) ✅ — **없는 것**: `msg.data.length < 4 + 288` 인 `no disclosure` 경로, 다른 팩토리의 지갑에서 온 호출.

**온체인을 치는 chain 그룹**: `tests/test_mode3_wallet_agent.mjs:275`(RootTooOld → 하트비트 복구, 실 노드), `tests/test_mode3_demo_stack.mjs:172, 297, 318`(지갑 배포 + execute, π 캐시 재사용, `AttrGate.claim` 성공/국가 불일치 실패)이 데모 스택 수준에서 같은 경로를 한 번 더 덮는다.

## 5. 강점 (다음 점검자가 다시 볼 필요 없는 것)

- 검사 순서·에러 이름·이벤트 시그니처가 스펙 §5.3 과 1:1 로 맞고, 싼 검사 → `verifyProof` → 상태 변경 → 외부 호출 순서가 지켜진다. `nonce += 1` 이 외부 호출보다 앞이라 재진입으로 같은 payload 를 되쓸 수 없다.
- 꼬리 9워드가 **항상** `pub[14..22]` 에서 나오고 `payload.data` 를 신뢰하지 않는다. 2026-09-22 Critical(PoC)이 회귀 테스트로 고정돼 있고, `AttrGate` 는 `isWallet(msg.sender)` → `claimed` → 꼬리 파싱 순서라 EOA 위조가 파싱 전에 걸린다.
- 서명 가변성 방어(high‑s·`v` 제한·`address(0)` 거르기)가 `Mode3Wallet`·`RevocationLog` 양쪽에 같은 기준으로 들어 있다.
- `RevocationLog` digest 가 `address(this)` 와 `keccak(leaves)` 를 덮어 교차 로그 재생·릴레이어 calldata 오염을 막고, 그 두 성질 각각에 전용 테스트가 있다.
- digest 계산 코드가 `lib/mode3_log.js`·`lib/mode3_onchain.js` 각각 한 벌뿐이고(과거 3벌 드리프트 사고의 수정), 테스트가 그 한 벌을 쓰면서도 컨트랙트 view 에 의존하지 않아 독립 검증이 성립한다.

## 6. 점검하지 못한 것

- **테스트를 실행하지 않았다**(읽기 전용 지침). 위 커버리지 표는 소스 독해 기준이며, 실제 통과/실패는 미검증이다.
- `PiCredVerifier.sol` 은 snarkjs 산출물이라 지시대로 **공개 입력 개수(23)와 시그니처 일치만** 봤고, 페어링 어셈블리·IC 상수가 `pi_cred_final.zkey` 와 맞는지는 보지 않았다(증명이 통과한다는 것으로만 간접 확인 가능).
- 가스 실측(스펙 §8 의 402,130 / 444,509)은 재현하지 않았다 — `scripts/bench_mode3_onchain.mjs` 실행이 필요하다.
- 회로(`circuits/pi_cred.circom`)가 `disc_lo[k] ≤ a_k ≤ disc_hi[k]`·`mask < 16`·`pk_i < 2^160` 을 실제로 강제하는지는 점검자 A/C 의 범위로 두고 보지 않았다. 컨트랙트의 `BadDisclosure`·`BadAllowAgent`·`BadTag` 는 그 가정 위에 있는 2차 방어다.
- `lib/mode3_rcl_sync.js`·`tests/test_mode3_rcl_sync.mjs` 는 공통 지침대로 제외했다.
- 상태·키 파일(`mode3_rp_registration.json` 등)은 열지 않았으므로 I-2 의 "실제 배포된 팩토리의 maxLifetime 값" 은 확인하지 못했다(코드 경로만 확인).
