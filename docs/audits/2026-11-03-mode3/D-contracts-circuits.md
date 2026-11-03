# 점검 D — Mode 3 온체인·회로 계층 (contracts/Mode3*.sol · AttrGate · PiCredVerifier · circuits/pi_cred.circom + lib 가젯)

- 대상: 브랜치 `feat/mode3-v11`, HEAD `7e9eb25` (점검 시각 2026-11-03 19:19 KST, `date` 실행값). 읽기 전용 — 컴파일·실행·테스트 수행 없음, 키·상태 파일 열지 않음.
- 선행 점검(`docs/audits/2026-09-23-mode3/SUMMARY.md`, D-contracts.md)의 Important D-I1~I3 는 처리 완료로 확인했고(코드·문서 모두 반영 — `mode3_rp.js:187-195` 가 팩토리 immutable 을 읽어 env 와 대조, `scripts/build_mode3_circuit.sh` 가 공개 입력 34 를 검사) 다시 보고하지 않는다. 그때 "기록으로 남긴" Minor 중 아직 열린 것은 §2 Minor 에 이월 표시로만 적는다.
- `circuits/mode3/` 디렉터리는 없다 — 메인 회로는 `circuits/pi_cred.circom`, 가젯은 `circuits/lib/`(`imt_range_nonmembership_v2`·`merkle_inclusion`·`mode3_commit`·`mode3_trace_tag` + circomlib 사본). circomlib 사본 12개 파일을 `node_modules/circomlib@2.0.5` 와 diff 했다 — 차이는 `pragma circom 2.0.0;` 머리글(와 montgomery.circom 의 공백 1자)뿐이다.

## 1. 한 줄 총평

execute()·publish()·회로의 핵심 보안 목표(계정·체인·nonce·root 창·세션키·세션 상한·공개값 바인딩, 서명 가변성, 비제약 신호 없음)는 모두 코드로 확인됐고 Critical 은 없다. 남은 것은 Mode3Log 접수증 대기열의 O(P·S) 중첩 루프가 외부 제출만으로 publish 를 **영구히** 막을 수 있는 liveness 결함(Important 1건)과, 설계 문서가 이미 "한계"로 적은 것 외의 Minor 몇 건·테스트 구멍이다.

## 2. 발견 목록 (순위순)

### Critical — 없음

### Important

**D3-I1. `Mode3Log._enforceRevocationQueue` 의 `pendingList.length × slotIdx.length` 중첩 루프 + 무제한 `pendingList` → 접수증을 한 번에 많이 올리면 publish 가 가스 한도를 넘어 영구히 불가능해진다(복구 경로 = 로그 재배포 → 팩토리 재배포 → 모든 계정 주소 변경)**
- 위치: `contracts/Mode3Log.sol:86-106` (`_enforceRevocationQueue`), `:116-123` (`requestRevocation` — `pendingList.push` 상한 없음).
- 무엇이 문제인가: 로그는 pending 슬롯 **전부**가 다음 publish 한 건의 `slotIdx` 에 0 으로 실려야 통과시킨다(`:100 PendingRevocationNotApplied`). 그래서 P 개가 쌓이면 publish 의 `slotIdx` 도 ≥ P 개가 되어 `:91-99` 가 P² 번 돈다. 이 함수는 "두 배열 다 소규모 … 프로토타입 단계에서는 허용(2026-10-02)" 주석으로 수용됐지만, `pendingList` 를 늘리는 쪽은 IdP 가 아니라 **IdP 서명 접수증을 가진 누구나**(`requestRevocation` 은 무허가)이고, 한 번 넘치면 되돌릴 방법이 없다(`pendingList` 는 publish 로만 비워진다).
- 공격/실패 시나리오: 공격자가 IdP 에 계정 N 개를 만들고(`/user` 가입은 공개) 각각 등록 뒤 계정 폐기(`cia.js:1024 receiptFor` 가 계정 폐기마다 접수증 1장을 돌려준다)로 접수증 N 장을 모은다. IdP 는 폐기 직후 publish 로 그 슬롯을 이미 0 으로 실었지만 `isRetired` 는 접수증 경로를 지나야만 true 가 되므로(`:102`), 접수증은 아직 유효하다. 공격자가 N 장을 한 블록 안에 올리면(`pending[s]=true` N 개) IdP 의 다음 publish 는 `pendingSlots()` 를 읽어 N 개 (slot,0) 을 싣고(`cia.js:1216-1226`) 컨트랙트는 N² 번 비교한다 — N≈800 이면 ~1M 반복 ≈ 30–40M gas 로 hardhat/메인넷 블록 한도를 넘어 **모든 publish(하트비트 포함)가 실패**한다. `maxRootAge`(100블록) 뒤 그 로그를 보는 지갑 전원이 `RootTooOld`, 거울도 새 epoch 를 못 받아 응용 체인 전원이 멈춘다. 비용은 접수증 트랜잭션 N 건의 가스 + IdP 계정 N 개.
- 최소 수정: 중첩 루프를 `slotIdx` 한 번 순회로 바꾼다 — `s = slotIdx[i]`; `if (isRetired[s] && leaf != 0) revert SlotIsRetired`; `if (pending[s]) { if (leaf != 0) revert PendingRevocationNotApplied(s); pending[s] = false; isRetired[s] = true; pendingCount--; emit SlotRetired; }` 순회 뒤 `require(pendingCount == 0)`(어느 pending 슬롯이 빠졌는지는 이벤트/`pendingSlots` 로 알 수 있다). 미끼 순서 `[7→0, 7→42]` 는 두 번째 항목이 `isRetired && ≠0` 로, `[7→42, 7→0]` 은 첫 항목이 `pending && ≠0` 로 각각 거절되므로 2026-10-02 수정의 의미가 유지된다. 추가로 `requestRevocation` 에 `pendingList.length < MAX_PENDING`(예 256) 상한을 두면 publish 한 건의 calldata 도 유계가 된다.
- 테스트: `test/Mode3Log.test.mjs` 는 pending 1~2개만 다룬다(`:79-101`). 수정 뒤 "pending 300개를 한 publish 로 전부 은퇴, gas 가 선형" 과 미끼 두 순서 모두 거절을 추가해야 한다. 2026-09-23 D M-4(leaves 무제한) 와 같은 계열이지만 그쪽은 IdP 가 쪼갤 수 있고 이쪽은 쪼갤 수 없다는 점이 다르다.

### Minor

**D3-M1. 거울의 root 나이(`lastPublishedBlock`)는 "캐노니컬이 게시한 시각"이 아니라 "누가 중계한 시각"이다 — 중계 백로그를 가진 제3자가 옛 epoch 를 하나씩 올려 `RootTooOld` 를 무기한 미루며 거울을 뒤처진 채로 둘 수 있다**
- 위치: `contracts/Mode3Mirror.sol:162-170`, `contracts/Mode3RootHistory.sol:139`, 소비자 `contracts/Mode3Wallet.sol:193-194`.
- 시나리오: 캐노니컬 epoch 100(공격자 세션 폐기 포함), 거울 50, IdP 의 중계 프로세스가 죽어 있을 때, 캐노니컬 체인 calldata 에 공개된 서명 페이로드 51…99 를 누구든 `maxRootAge` 미만 간격으로 하나씩 올리면 거울은 늘 "신선"하지만 폐기는 49 epoch 뒤의 일이 된다. 설계가 허용한 "거울은 뒤처질 수 있다" 와 겹치지만, `maxRootAge` 가 약속하는 "withholding 이면 fail-closed" 가 거울에서는 중계자 하나의 정직성에 걸려 있다는 점이 문서에 없다. 전제(IdP 의 자기 중계가 멈춤)가 좁아 Minor.
- 방향: 게시 페이로드(다이제스트)에 캐노니컬 `block.timestamp`(또는 블록 높이) 를 넣고 거울이 `block.timestamp − publishedAt ≤ X` 를 요구하거나, 문서 §7 한계에 "거울의 root 나이는 중계 시각 기준" 을 명시.
- 테스트: 없음(건너뛴 epoch 수락만 있다 `test/Mode3Mirror.test.mjs:233-238`).

**D3-M2. 폐기 접수증에 만료·epoch 결속이 없다 — `epochAtRequest`·`requestedAt` 은 다이제스트에만 들어가고 컨트랙트가 검사하지 않는다**
- 위치: `contracts/Mode3Log.sol:110-123`.
- 시나리오: 사용자가 계정을 폐기해 접수증을 받고(IdP 는 즉시 (slot,0) 게시) 올리지 않는다. 뒤에 관리자가 계정을 되살리고 **같은 슬롯**에 재발급하면(`cia.js:983` 은 `slotRetired` 일 때만 새 슬롯) 그 접수증은 여전히 유효해 누구든(응답으로 받은 사용자, 또는 그 JSON 을 손에 넣은 자) 올려 다음 publish 가 그 슬롯을 0 으로 강제·영구 은퇴시키게 만들 수 있다. 피해자는 그 사용자 자신(자기 슬롯)이라 경계 침범은 아니다 — "확인 필요": 관리자 되살림 뒤 같은 슬롯 재발급이 실제 경로인지는 cia.js(점검 A 범위)의 몫.
- 방향: `requestRevocation` 에 `epochAtRequest + K ≥ epoch`(접수증 유효 epoch 창) 또는 `isRetired`/`pending` 외에 "슬롯의 현재 리프가 0 이면 no-op" 류의 검사.

**D3-M3. 거래 counter 가 32비트라 계정 nonce 가 2^32−1 에 닿으면 그 계정은 더 이상 어떤 거래도 증명할 수 없고(`Num2Bits(32)`), nonce = 2^32−1 자체는 로그인 counter 값과 겹친다**
- 위치: `circuits/pi_cred.circom:150-151`, `contracts/Mode3Wallet.sol:114`, `lib/mode3_onchain.js:17`.
- 실질 영향 없음(43억 거래). 다만 `LOGIN_COUNTER = 2^32−1` 이 "유효한 nonce 값" 공간과 분리돼 있지 않다는 점은 문서에 적어 두는 편이 낫다(RP 의 `bad_counter` 가 거래 π 를 거르는 근거가 "그 값은 nonce 로 쓰이지 않는다" 라서).

**D3-M4. `rootWindow` 허용 범위(0..200, `FACTORY_ROOT_WINDOW_BAND`)가 `maxRootAge` 기본(100) 보다 크다 — 창이 100 을 넘으면 "대체된 지 100블록 넘은 root" 가 하트비트만 살아 있으면 통과한다**
- 위치: `lib/mode3_onchain.js:37`, `contracts/Mode3Wallet.sol:189-194`.
- 영향: 2026-10-25 설계 §7 한계 1·2(pk_i 없는 폐기·자격증명 은퇴의 G 블록 노출)가 G 만큼 늘어난다 — 설계가 받아들인 노출의 상한을 운영 파라미터가 더 늘릴 수 있다는 뜻. 정책 문제. 방향: 밴드 상한을 `maxRootAge` 이하로 두거나 지갑 쪽 검사에 `rootWindow ≤ maxRootAge` 를 추가.

**D3-M5. 이월(2026-09-23 D M-2, 미수정): `payload.to.call{value:}` 에 가스 상한이 없어 릴레이어가 내부 호출만 OOG 로 죽이고 nonce 를 태울 수 있다**
- 위치: `contracts/Mode3Wallet.sol:161`. Snap 모드는 사용자가 직접 보내므로 영향이 더 작아졌다. 수정 방향은 그때와 같다(payload 에 `gasLimit` 을 넣어 다이제스트로 덮기).

**D3-M6. 이월(2026-09-23 D M-3·M-5): `Mode3Auth`/`Executed` 는 내부 호출 실패에도 emit 되고, `cia` 주소·`epoch` 단조성 때문에 IdP 키 분실 시 복구 경로가 재배포뿐이다** — 코드 변경 없음, 기록만.

**D3-M7. 회로 `TraceTag` 의 `EscalarMulAny(250)` 는 `pk_trace` 가 소수 부분군 점이라는 전제를 회로 안에서 검사하지 않는다(주석 `mode3_trace_tag.circom:102-103` 이 명시)**
- 전제가 깨지면(저차수 성분을 가진 점) `MontgomeryAdd` 의 `lamda` 가 두 입력이 같은 경우 자유 변수가 되어 K 를 공격자가 고를 수 있고 c2 가 아무 값이나 돼 개봉이 깨진다. 지금은 `cia.js:581` 이 등록 때 `isTracePoint(X_svc)`(inCurve·inSubgroup) 를 검사하고 `pk_trace = X_svc + x_AA·B8` 이라 부분군 점이며, 팩토리가 그 값을 immutable 로 박고 `_checkStatement` 가 대조하므로 **성립한다**. 다만 보증이 회로가 아닌 IdP 의 등록 검사에 있다는 점을 문서화해 두는 편이 안전하다(팩토리 배포 스크립트에서 `inSubgroup` 재검사 한 줄도 싸다).

## 3. 확인하고 건전하다고 본 것 (검사 지점을 명시)

### Mode3Wallet.execute (`contracts/Mode3Wallet.sol`)
- nonce 일치 `:110`; `pub[33] == payload.nonce` `:114`(증명자가 counter 를 낮춰 고르지 못함 — 회로가 counter 를 공개 입력으로 묶고 체인이 고정).
- 세션 상한 `:118-119`: `effectiveSessionBound = min(자기 호출, 거울)`(둘 다 c+1 인코딩, 0 = 없음) 로 `nonce + 1 >= c + 1 ⇔ nonce ≥ c` 거절. `setSessionBound :56-62` 는 `msg.sender == address(this)` 만, `bound + 1 >= cur` 면 `BoundNotLowered`(엄격히 낮추기만), uint32 → uint256 승격으로 +1 넘침 없음.
- 다이제스트 `:129-135`: `chainid, address(this), to, value, data, nonce, pub[15], lo[6], hi[6], pub[28], pub[29], pub[3], pub[5], pub[12..14]` — JS `payloadDigest`(`lib/mode3_onchain.js:111-119`)의 타입 열 `uint256,address,address,uint256,bytes,uint256,uint256,uint256[6],uint256[6],uint256×7` 과 순서·타입이 같다(정적 배열은 인라인). 릴레이어가 바꿀 수 있는 공개 입력은 `pub[6],[7],[30..32]` 뿐이고 이들은 π 가 묶는다(`test/Mode3Wallet.test.mjs:360-367` 이 [30..32] 변조 → InvalidProof 확인).
- 서명 `:204-212`: 길이 65, `s ≤ n/2`(상수 `7FFF…1B20A0` = secp256k1 n/2 정확), `v ∈ {27,28}`, `ecrecover == 0` 거절(`:139`), `recovered == address(uint160(pub[2]))`(회로가 pk_i < 2^160 을 `CommitSessionV11` `Num2Bits(160)` 으로 보장하므로 절단 안전).
- `_checkStatement :172-198`: `pub[0]==ppid, [1]==arid, [4]==chainid`; `[8..11]` 키 4개 immutable 대조; `[5] ≤ 1`; `[12]==0&&[13]==1` 거절; `[15] < 64`; `[28] ≤ 6`, `sel=0 ⇒ root=0`; 마스크 밖 lo/hi = 0; 두 root 각각 `isAcceptable*Root(root, rootWindow)`; `block.number − lastPublishedBlock ≤ maxRootAge`; `block.number ≤ max_height ≤ block.number + maxLifetime`.
- 순서: 모든 검사 → `verifyProof :143` → `nonce += 1 :146` → 외부 호출 `:161` → 이벤트. 재진입으로 같은 payload 재사용 불가(nonce 선증가). 자기 호출(`to == address(this)`)로 들어오는 `setSessionBound` 는 꼬리 480바이트가 붙어도 Solidity ABI 디코더가 남는 calldata 를 무시하므로 동작한다(테스트 `:630-681` 이 실제로 execute 경유로 통과).
- 꼬리 `:158-160`: `payload.data` 가 비고 mask=0·set_sel=0 인 단순 송금만 예외, 그 외엔 항상 `pub[15..29]` 15워드가 끝에 붙는다 → `AttrGate._disclosure` 가 끝에서 읽으므로 `payload.data` 안의 위조 꼬리는 묻힌다(회귀 테스트 `:411`).

### Mode3WalletFactory
- `_initCode :34-39` 와 `new Mode3Wallet{salt}(…) :50-52` 의 인자 11개(uint256×6, address×2, uint64×3)가 생성자 시그니처 `:82-85` 와 순서·타입 일치 → `computeAddress` 가 실제 배포 주소와 같다(`:53` require 로 재확인). `deploy` 가 코드 있는 주소를 `isWallet=true` 로 표시하는 것은 CREATE2 주소가 (이 팩토리, salt, 이 initcode) 로만 나오고 `Mode3Wallet` 에 `selfdestruct` 가 없어 안전.

### Mode3RootHistory / Mode3Log / Mode3Mirror
- `isAcceptable*Root :110-120`: 최신 root 는 항상 참; 대체된 root 는 `supersededAt != 0 && block.number ≤ at + window`. uint64 → uint256 승격으로 넘침 없음. 링 버퍼 16(`_supersede :124-130`) 밀림은 liveness 만 깎고 안전과 무관(주석과 일치) — 같은 root 가 두 번 들어간 뒤 먼저 것이 밀리면 새 기록까지 지워지는 것도 liveness 쪽.
- `_setRoots :133-140`: 값이 바뀐 root 만 이력에 넣는다(하트비트는 이력 불변) — `test/Mode3Log.test.mjs:143-151`.
- `_applyBounds :144-154`: 길이 일치 검사, `cur == 0 || next < cur` 일 때만(낮추기만, 조용히 무시), `c = 2^32−1 → 2^32` 넘침 없음(`:177-180` 테스트).
- `Mode3Log.publish :56-72`: epoch 엄격 증가 → 길이 → 다이제스트(`DOMAIN, chainid, address(this), rev, reg, epoch, keccak(revLeaves), keccak(slotIdx), keccak(slotLeaves), keccak(boundKeys), keccak(boundValues)`) → EIP-191 → `_recover == cia` → 대기열 → bound → root. JS `publicationDigestV3`(`lib/mode3_log.js:74-92`)는 `uint32[]` 를 원소별 32바이트 패딩(`uint256`)으로 패킹해 Solidity `abi.encodePacked(uint32[])` 규칙과 같다; `test/Mode3Log.test.mjs:61-65,188` 이 두 독립 구현을 직접 비교.
- 거울 `digestFor :156-158` 는 `block.chainid/address(this)` 자리에 생성자 `canonicalChainId/canonicalLog` 를 넣어 캐노니컬과 바이트 일치(`test/Mode3Mirror.test.mjs:224,243`). 도메인 분리: 다른 로그 주소의 서명은 `address(this)`/`canonicalLog` 가 달라 거절(`Mode3Log.test:54-60`, `Mirror.test:231`), 같은 거울에 재생은 epoch 로 거절, 다른 체인의 캐노니컬 서명은 `canonicalChainId` 가 달라 거절. 거울이 epoch 를 건너뛰어도 그 페이로드의 bound 는 그대로 실린다(`Mirror.test:251-257`).
- 두 컨트랙트 `_recover` 본문이 지갑과 같은 기준(길이·low-s·v·address(0)).

### AttrGate
- `claim :236-245`: `factory.isWallet(msg.sender)` → `claimed` → 꼬리 15워드 파싱(`msg.data.length ≥ 4 + 480`, 끝에서 읽음) → `mask & 1 == 1`(Solidity 에서 `&` 가 `==` 보다 우선순위가 높아 의도대로 `(mask & 1) == 1`) → `setSel == 2 && setRoot == allowedCountriesRoot` → `hi[0] + minAge ≤ yearOf(now)`. 회로가 `attr0 ≤ hi[0]` 를 보장하므로 증명자가 hi[0] 를 내리는 쪽으로는 유리해질 수 없다(최솟값 = 출생연도). `yearOf` 윤년 규칙 테스트 있음.

### PiCredVerifier
- `verifyProof(uint[2], uint[2][2], uint[2], uint[34] calldata)` `:158`, `IC0…IC34`(35개 = 1 + 34) `:46-148`, `checkField` 34회 `:323-389`, `g1_mulAccC` 가 `pubSignals + 0 … + 1056`(= 33×32) 로 34개 전부 누산 `:202-268`. 공개 입력 수가 회로 `main {public […]}`(24개 항목 = 30 스칼라 + `disc_lo[6]` + `disc_hi[6]` → 34)·`PUB_INDEX.COUNT = 34`·`WALLET_ABI` 의 `uint256[34]`·`Mode3Wallet.execute(uint[34])` 와 일치. 배선: `test/Mode3Wallet.test.mjs:38-41` 과 `lib/mode3_onchain.js:229`(`deployVerifier`) 가 아티팩트 `PiCredVerifier` 를 배포하고, `verifyReferenceCode`(`:193-`) 가 온체인 코드를 그 아티팩트와 바이트 대조한다. **확인 필요**: IC 상수가 현재 `build/mode3/pi_cred_final.zkey` 와 짝인지는 실행 없이 알 수 없다(`tests/test_mode3_artifacts.mjs` 가 vkey nPublic 을, 컨트랙트 테스트의 실제 π 통과가 간접 증거).

### 회로 `circuits/pi_cred.circom` (PiCred(32, 20))
- ① 토큰: `EdDSAPoseidonVerifier(enabled=1)` over `Poseidon(7)(D_V11, auid_s, arid_s, Cf_u, Cf_s, chainid, allowAgent)` `:120-136`; `allowAgent` 불리언 `:120`. A = pk_CIA 는 공개 입력(컨트랙트가 immutable 과 대조), 검증기가 8배 후 영점 검사·`S < 부분군 위수`(CompConstant) 를 한다.
- ② `auid = Poseidon(T, uid, s_u)`, `auid_s === Poseidon(T, auid, arid, r_rp)`, `arid_s === Poseidon(T, arid, r_rp)` `:108-117` — 같은 비공개 `r_rp` 신호가 `CommitSessionV11.r_rp` 에도 들어가(⑤) 토큰·가명·C_s 가 하나의 세션으로 묶인다.
- ③ `PPID === Poseidon(uid, s_u, arid, chainid)` `:140-145`; `chainid` 는 토큰 메시지와 같은 신호.
- ⑥ 등록부: `Poseidon(auid, Cf_u)` 를 비공개 입력에서 직접 계산해 `MerkleInclusion(20)` → `inc.root === regRoot` `:179-187`; 경로 비트 불리언 제약(`merkle_inclusion.circom:78`).
- ⑥ 폐기 구간: `sLeaf = Poseidon(5, Cf_s)` → `Num2Bits_strict`(AliasCheck 로 정규 분해 강제 — 비정규 254비트 표현으로 하위 220비트를 바꾸는 길을 막는다) → 하위 220비트 선형합 `hp` → `sLo <== hp·2^32`, `sHi <== sLo + counter`(`counter` 는 `Num2Bits(32)`) `:150-163`. `hp ≤ 2^220−1` 이라 `sHi ≤ 2^252−1` 로 가젯의 `Num2Bits(252)` 범위 안, `lo ≤ hi` 구조적. JS `sessionLeaf`(`lib/mode3_revocation.js:24-30`)·`sessionLeafRange` 와 같은 식.
- `IMTRangeNonMembershipV2(32)`: 리프 `Poseidon(lowValue, lowNextIndex, lowNextValue)`, Merkle 경로·비트 제약, `lo·hi·lowValue·lowNextValue` 모두 `Num2Bits(252)`, `LessThan(252)(lowValue, lo) === 1`, `(hi < lowNextValue) ∨ (lowNextValue == 0)` 를 `Mux1`+`IsZero` 로 `=== 1`. 입력이 전부 252비트로 묶여 `in[0] + 2^252 − in[1]` 이 253비트 안이다(비교자 넘침 없음). 빈 슬롯 = 리터럴 0(`lib/imt_v2.js:61`) 이라 anchor `(0,0,0)` 모양의 가짜 low 리프를 제시할 수 없고, 값 0 삽입은 라이브러리가 막아 sentinel `nextValue=0` 은 마지막 리프에만 나타난다.
- ⑦ `CommitSessionV11`: `pk_i` 160·`max_height` 64·`r_s`·`r_rp` 250비트 `Num2Bits` + `EscalarMulFix` + `BabyAdd`(완전 덧셈), 생성원 NUMS(`G_PKI, G_EXP, G_RS, H`), 스칼라 < 2^250 < 부분군 위수 → `e` 와 `e + r` 별칭 없음(binding). `CommitUser` 도 같은 구조(uid·s_u·blind 250비트, attrs 64비트).
- ⑧ `TraceTag`: `r` 250비트, `r ≠ 0`(`IsZero.out === 0` `:191-193`), `c1 = r·B8`(Fix), `K = r·pk_trace`(Any), `c2 = Poseidon(uid, arid) + Poseidon(K)`, 세 출력 모두 `===` 로 공개 입력에 고정 `:200-202`. `r < 2^250 < 위수` 라 `c1 ≠ O`.
- ④ 선택 공개: `disc_mask` `Num2Bits(6)`, `disc_lo/hi[k]` `Num2Bits(64)`, `attrs[k]` 는 `CommitUser` 의 `Num2Bits(64)` → `LessEqThan(64)` 두 개(내부 `in[1]+1 ≤ 2^64`, `in[0] + 2^64 − in[1] − 1 ∈ [0, 2^65)` 로 넘침·음수 없음), `maskBits[k]·(1 − ge·le) === 0` `:206-217`.
- ④ 집합: `IsEqual(set_sel, j)` 7개의 합 `=== 1` 로 `set_sel ∈ {0..6}`; `setVal = Σ selIs[k+1]·attrs[k]`; `MerkleInclusion(8)` 의 경로 비트는 `Num2Bits(8)(set_index)`; `(1 − sel0)·(root − set_root) === 0`, `sel0·set_root === 0` `:220-242`. 리프가 원시 속성값(64비트)이고 내부 노드는 ~254비트 해시라 "내부 노드를 리프로" 혼동 공격이 성립하지 않으며(깊이 고정 8), 패딩 `2^64` 은 `Num2Bits(64)` 가 막는다(`lib/mode3_set_tree.js:3-9`).
- `<--` 로만 대입되고 `===` 짝이 없는 신호: **pi_cred.circom 및 프로젝트 가젯 4개 안에는 없다**(전부 `<==`/`===`). circomlib 사본 안의 `<--` 는 모두 짝 제약이 있다 — `IsZero.inv`(`out` 정의 + `in·out === 0`), `Num2Bits.out[i]`(비트 + 합), `BabyAdd.xout/yout`, `MontgomeryAdd/Double.lamda·out`, `Edwards2Montgomery/Montgomery2Edwards.out`. 뒤 셋은 "두 입력이 같은 점/x=0/v=0" 일 때 `lamda`·`out` 이 자유가 되는 circomlib 의 알려진 조건부 전제가 있는데, EscalarMulFix 는 2^247·B 오프셋 설계로, EscalarMulAny 는 "p 가 영이 아닌 부분군 점" 전제로 그 경우를 피한다 — pi_cred 에서 Any 의 p 는 `pk_trace`(D3-M7 참조) 와 EdDSA 의 `8·A`(pk_CIA, immutable 대조) 둘뿐이다.
- 비트 폭이 넘칠 수 있는 비교자: 없음(위 LessThan(252)·LessEqThan(64) 모두 입력이 같은 폭으로 range-check 됨; `IsEqual`/`IsZero` 는 폭 무관).
- 제약에 쓰이지 않는 공개 입력: **없음** — 34개 전부가 `===` 또는 해시·커밋·비교자의 입력으로 들어간다(`PPID, arid, pk_i, max_height, chainid, allowAgent, revRoot, regRoot, pk_CIA_x/y, pk_trace_x/y, tag_c1_x/y, tag_c2, disc_mask, disc_lo[6], disc_hi[6], set_sel, set_root, auid_s, arid_s, r_s, counter`).

### 설계 문서가 이미 "한계"로 적은 것(재보고하지 않음, 코드로 확인만)
- 2026-10-25 §7 한계 1·2: `pk_i` 없는 세션 폐기(관리자 경로)와 자격증명 은퇴·교체는 거울 반영 뒤에도 `rootWindow` 블록 동안 옛 root 의 π 가 통과한다 — `isAcceptable*Root` 의 창이 두 root 에 독립적으로 적용되는 코드와 일치.
- 2026-10-22 §7: 상한은 계정 공용 nonce 기준이라 다른 세션의 거래(자기 호출 상한 거래 포함)가 S1 의 허용 구간을 소모한다; 레이스 (2)(폐기 반영 전 채굴) 는 어떤 counter 설계로도 제거되지 않는다.
- IdP 가 서명한 root 와 리프/슬롯 배열의 **내용 정합성**(리프 집합이 정말 그 root 를 만드는지) 은 컨트랙트가 검증하지 않는다 — IdP 신뢰 모델(V10 결정 1-A)과 일치.

## 4. 테스트 구멍

컨트랙트(`test/Mode3Wallet.test.mjs`·`Mode3Log.test.mjs`·`Mode3Mirror.test.mjs`·`AttrGate.test.mjs`):
1. `_recover` 의 `sig.length != 65` 단독 경로와 `recovered == address(0)`(예: `s = 0, v = 27` 처럼 low-s·v 검사는 통과하고 ecrecover 만 0 을 돌려주는 서명) — 2026-09-23 이후에도 없음(`:153-160` 의 손상 서명은 65바이트·v=0 이라 v 검사에서 먼저 걸린다).
2. 다이제스트의 `block.chainid` 변조(다른 chainId 로 서명한 σ → BadSignature) — E-1(`:548`) 은 to·value·data 만.
3. `UntrustedKeys` 는 `pub[10]`(pk_trace.x) 하나만(`:199-204`); `[8],[9],[11]` 미검증.
4. Mode3Log 접수증 대기열의 규모 테스트(D3-I1) — pending 수백 개에서 publish 가스가 선형인지; `requestRevocation` 상한.
5. `Mode3RootHistory._supersede` 의 "같은 root 가 두 번 대체돼 먼저 항목이 밀릴 때 새 기록이 지워진다" 경계; 거울 쪽 링 버퍼 밀림(로그 쪽만 `:152-161`).
6. 거울 `LengthMismatch`(bound 배열 길이 불일치, 서명은 맞음) — 로그에만 있음(`Mode3Log.test:191-196`).
7. `setSessionBound(pk_i, 2^32−1)` 의 지갑 쪽 저장값(로그 쪽만 `:177-180`); 자기 호출 상한 거래에 `mask ≠ 0` 꼬리가 붙은 경우(지금은 mask=0·data 비어 있지 않음 경로만 — 디코더가 남는 calldata 를 무시한다는 사실 자체는 이 경로가 간접 확인).
8. `AttrGate`: `msg.data.length < 4 + 480` 인 `no disclosure` 경로, 다른 팩토리로 배포한 지갑에서의 `claim`(isWallet 거절), 나이 미달(`age`) 실패 — `AttrGate.test.mjs` 는 yearOf·immutable·EOA 거절만, 정책 실패는 `Mode3Wallet.test:457-476`(통과·중복)에 있고 `country`/`age` 실패는 **확인 필요**(이번 독해 범위에서 못 찾았다).
9. 재진입 시나리오(payload.to 가 지갑을 되부르는 컨트랙트)와 릴레이어 OOG 그리핑(D3-M5) — 없음.
10. 혼합 epoch root(revRoot 는 창 안 옛 것, regRoot 는 최신)가 통과하는 설계 사실의 고정 테스트 — 없음(의도된 동작이라도 회귀 방지용으로 둘 만하다).

회로(`tests/test_pi_cred_witness.mjs` 50건, `tests/test_imt_v2_range_circuit.mjs`):
11. `counter ≥ 2^32` 거부(`Num2Bits(32)`) — 없음.
12. `s_pathIndices` 비불리언 거부 — 등록부 경로(`reg_pathIndices`)만 있음(`:300-305`).
13. `disc_hi[k] ≥ 2^64` — `disc_lo` 만(`:233`); `set_index ≥ 256`; `r ≥ 2^250`·`uid/s_u/blind_u ≥ 2^250` 범위 거부 — 없음(`pk_i ≥ 2^160` 만 있음).
14. `pk_CIA` 를 바꾼 서명 거부 — 회로 수준 테스트 없음(컨트랙트 `UntrustedKeys` 가 앞단에서 막지만 회로 자체의 음성 케이스는 없다).
15. 구간 가젯의 sentinel·anchor 위조는 가젯 단독 테스트(`test_imt_v2_range_circuit.mjs:119-127`)에만 있고 pi_cred 전체 입력으로는 없다(가젯이 같은 코드라 위험은 낮다).

## 5. 점검하지 못한 것
- 컴파일·테스트·가스 실측을 하지 않았다(지시). 위 커버리지 표는 소스 독해 기준.
- `PiCredVerifier.sol` 의 IC 상수와 `pi_cred_final.zkey` 의 짝 여부(위 "확인 필요").
- cia.js 의 접수증 발급·슬롯 재사용 경로(D3-I1·D3-M2 의 전제)는 공격 전제 확인에 필요한 만큼만 읽었다 — 점검 A 범위.
