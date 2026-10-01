# Mode 3 V9 — 사용자 자격증명 등록부·등록 키 지갑 생성·속성 6슬롯·시연용 비밀 바꾸기

작성 2026-10-01. 브랜치 `feat/mode3-cia` HEAD d22b2ff 기준. 근거 메모: `2026-10-01-mode3-credential-registry-memo.md`(O2 권고).
2026-09-30 회의 피드백(`documents/260930_meeting_MHJ(with feedback).pptx` 2·6장)에 대한 구현 설계다.
속성 **매핑 계층**(이름·타입·인코딩·화면)은 별도 스펙(스펙 2)이며, 이 문서는 그 경계(§5.4)만 정한다.

## 0. 한 줄 요약

사용자 자격증명의 활성 여부를 **공개 등록부(사용자별 슬롯)** 로 옮긴다. 슬롯 키는 등록 커밋먼트 cm_u, 값은 활성 H(C_u) 이고,
π_RP 가 "내 슬롯에 내 자격증명이 있다"를 증명하므로 AA 가 공개하지 않은 자격증명은 어디서도 쓸 수 없고, 공개한 교체는 사용자가 본다.
폐기 트리는 세션 리프만 남긴다(교수님의 "두 종류" = 등록부 + 폐기 트리). 같은 회로 판에 속성 슬롯을 4 → 6 으로 늘리고,
등록 키 sk_u 를 AA 가 아니라 지갑이 만들며, 시연용으로 salt·uid 를 바꿔 거절 장면을 보일 수 있게 한다.

## 1. 요구와 결정 (근거: 메모 §1–§6, 회의 2026-10-01 결정)

| # | 요구 | 결정 |
|---|---|---|
| R1 | 사용자가 AA 의 발급 장부를 스스로 확인(책임성) | 등록부 O2: 키 cm_u → 활성 H(C_u) 슬롯, π_RP 멤버십 + salt 등식 |
| R2 | RCL 두 종류 | 등록부(멤버십, 갱신형) + 폐기 트리(비멤버십, append-only, 세션 리프만) |
| R3 | latest active | 슬롯 자체. 폐기해서 확인할 필요 없음 |
| R4 | 등록 키 | 지갑이 (sk_u, pk_u) 생성, pk_u 만 제출, 소유 증명 서명 |
| R5 | 속성 attribute1~6 | 슬롯 6개, 64비트 정수 도메인(인코딩은 스펙 2) |
| R6 | 데모 | 지갑의 등록부 확인 표시 + 관리자 "슬롯 바꿔치기" 시연 + 지갑의 "salt·uid 바꾸기" 시연 |
| R7 | 한계 수용 | 내 uid 의 두 번째 등록은 못 잡음(VRF 키는 후속). 새 배포(계정 주소 변경) 수용 |

접근 비교(인덱스 슬롯 트리 vs 키드 SMT vs IMT 버전 리프)는 회의에서 A(인덱스 슬롯 트리)로 결정했다 — SMT 는 경로 160~254단으로 제약 4~6만, IMT 는 "최신" 의미를 비멤버십으로 표현할 수 없다.

## 2. 표기

- `C_u = uid·G_UID + s_u·G_SU + Σ_{k<6} a_k·G_ATTR[k] + blind_u·H`, `Cf_u = Poseidon(C_u.x, C_u.y)`.
- `cm_u = s_u·G_SU + r_u·H` — 등록 커밋먼트(현행, `lib/mode3_issuance.js registrationCommit`).
- `C_s = arid·G_ARID + pk_i·G_PKI + blind_s·H`, `Cf_s = Poseidon(C_s.x, C_s.y)`.
- 등록부 리프 `L_reg(cm_u, Cf_u) = Poseidon(cm_u.x, cm_u.y, Cf_u)`; 빈 칸·은퇴 = 0.
- 세션 폐기 리프 `Poseidon(5, Cf_s)`(현행 `sessionLeaf`). 사용자 리프 `Poseidon(4, Cf_u)` 는 V9 에서 **쓰지 않는다**.
- 슬라이드 용어 대응: salt = s_u, Token = σ_AA, auid_i 자리 = Cf_s, PPID = Poseidon(uid, s_u, chainid, arid).

## 3. 등록부

### 3.1 트리
- 깊이 `REG_DEPTH = 20`(슬롯 2²⁰ = 1,048,576). 내부 노드 `Poseidon(left, right)`, 빈 리프 0, 영해시 체인은 깊이별로 미리 계산.
- 새 모듈 `lib/mode3_registry.js`: `createRegistryTree(depth = 20)` → `{ set(index, leaf), leafAt(index), path(index) → {pathElements[depth], pathIndices[depth]}, root(), size }`. 리프 배열은 희소(Map). root 는 갱신마다 경로 20개만 다시 계산.
- CIA 상태 `state.registry = { depth: 20, next: <다음 슬롯 번호>, leaves: { "<index>": "<leaf 10진>" }, pendingSlots: [{index, leaf}] }` — `cia_state.json` 에 저장. 기동 때 `leaves` 로 트리를 다시 만든다.

### 3.2 슬롯과 상태
- 등록 때 `slot = state.registry.next++` 를 배정해 `accounts[uid].slot` 에 적고 응답으로 돌려준다. 리프는 0 인 채다.
- 사용자 자격증명 발급·교체: `registry.set(slot, L_reg(cm_u, Cf_u))`. 은퇴(credential 폐기)·계정 폐기·자기 폐기: `registry.set(slot, 0)`. 계정 복구(`/cia/accounts/:uid/restore`)는 슬롯을 건드리지 않는다 — 지갑이 새 자격증명을 받을 때 다시 채워진다(현행 "복구 뒤 새 발급" 흐름 그대로). 시연용 `registry/restore`(§9)는 별개다.
- 활성 자격증명은 사용자당 하나(현행 §3.1)이므로 슬롯 값도 하나다. 등록부가 그 사실을 구조로 강제한다.

### 3.3 게시
- 등록부가 바뀌면 **즉시** `publish`(§4)한다 — 발급·교체·은퇴·폐기·시연 tamper/restore. 폐기 트리의 pending 리프가 있으면 같은 트랜잭션에 실린다. 하트비트는 두 root 를 그대로 재게시한다(epoch 증가, `lastPublishedBlock` 갱신).
- 게시 실패(체인 다운·서명 실패): 상태 변경은 유지하고 `pendingSlots` 에 남겨 다음 하트비트가 재시도한다. 발급 응답은 201 에 `published:false` 를 싣는다(§10).

### 3.4 마이그레이션 (기존 `cia_state.json`)
- 기동 때 `state.registry` 가 없으면 만든다: `slot` 이 없는 계정에 **uid 오름차순**(결정적)으로 번호를 주고, 활성 자격증명이 있으면 `L_reg(cm_u, Cf_u)` 를, 없으면 0 을 둔다. 전부 `pendingSlots` 에 넣고 첫 하트비트(또는 첫 변경)에서 게시한다.
- 폐기 트리·revoked·pending 은 그대로 둔다. 옛 사용자 리프(태그 4)는 트리에 남지만 V9 회로가 그 비멤버십을 보지 않으므로 효력이 없다 — 상태 파일은 지우지 않는다(CLAUDE.md 규칙).
- 상태 파일 버전은 올리지 않는다(필드 추가뿐). V9 CIA 가 V8 파일을 읽을 수 있고, V8 CIA 가 V9 파일을 읽으면 `registry` 를 무시한다.

## 4. 로그 컨트랙트 V2 — `contracts/Mode3Log.sol` (새 파일, `RevocationLog.sol` 은 그대로 둔다)

```
contract Mode3Log {
  bytes32 public constant DOMAIN = keccak256("MODE3_LOG_V2");
  address public immutable cia;
  bytes32 public revRoot;  bytes32 public regRoot;
  uint64  public epoch;    uint64  public lastPublishedBlock;
  event Revoked(uint64 indexed epoch, bytes32 root, bytes32[] leaves);          // 현행과 같은 모양
  event SlotUpdated(uint64 indexed epoch, uint32 index, bytes32 leaf);           // 슬롯 갱신마다 하나
  error EpochNotIncreasing(uint64 got, uint64 have); error BadSignature(); error LengthMismatch();
  constructor(address cia_, bytes32 emptyRevRoot, bytes32 emptyRegRoot);
  function digestFor(bytes32 newRev, bytes32 newReg, uint64 newEpoch, bytes32[] calldata revLeaves,
                     uint32[] calldata slotIdx, bytes32[] calldata slotLeaves) public view returns (bytes32)
    = keccak256(abi.encode(DOMAIN, address(this), newRev, newReg, newEpoch,
                keccak256(abi.encodePacked(revLeaves)), keccak256(abi.encodePacked(slotIdx)), keccak256(abi.encodePacked(slotLeaves))));
  function publish(bytes32 newRev, bytes32 newReg, uint64 newEpoch, bytes32[] calldata revLeaves,
                   uint32[] calldata slotIdx, bytes32[] calldata slotLeaves, bytes calldata sig) external;
}
```
- `publish`: epoch 증가 검사 → `slotIdx.length == slotLeaves.length` → EIP-191 서명이 `cia` 인지(low-s·v 검사 현행) → 저장 → `Revoked` 1건 + `SlotUpdated` n건.
- `Mode3Wallet` 과 지갑·RP 는 `revRoot()`, `regRoot()`, `lastPublishedBlock()` 을 읽는다. root 나이 검사는 하나다(둘이 같은 트랜잭션에 게시).
- JS: `lib/mode3_log.js` 에 V2 ABI·`digestFor` 와 같은 계산·`publish` 호출 보조. CIA `publishNow()` 는 `(revRoot, regRoot, epoch+1, pending, pendingSlots)` 로 부른다.
- 배포: `scripts/deploy_mode3_log.cjs` 가 `Mode3Log` 를 배포(두 빈 root 를 JS 로 계산해 넘김). `.env` 키 `CIA_LOG_ADDRESS` 는 그대로 쓴다. `tests/helpers/mode3_chain.mjs` 의 `deployRevocationLog` → `deployMode3Log`.

## 5. 회로 V9 — `circuits/pi_cred.circom`

### 5.1 입력
비공개: `uid, s_u, r_u(새), blind_u, blind_s, attrs[6], r, S, R8x, R8y, s_lowValue, s_lowNextIndex, s_lowNextValue, s_pathElements[32], s_pathIndices[32], reg_pathElements[20](새), reg_pathIndices[20](새), set_index, set_path[8]`.
빠진 것: 사용자 리프 비멤버십의 `lowValue, lowNextIndex, lowNextValue, pathElements[32], pathIndices[32]`.

공개 30개(순서가 컨트랙트·RP·지갑의 계약이다):
```
[0] PPID [1] arid [2] pk_i [3] max_height [4] chainid [5] allowAgent [6] revRoot [7] regRoot
[8] pk_CIA_x [9] pk_CIA_y [10] pk_trace_x [11] pk_trace_y [12] tag_c1_x [13] tag_c1_y [14] tag_c2
[15] disc_mask [16..21] disc_lo[6] [22..27] disc_hi[6] [28] set_sel [29] set_root
```

### 5.2 조건 (형식 문서 조건 번호와 대응)
1. `EdDSA.Verify(pk_CIA, Poseidon(D_cred, Cf_u, Cf_s, max_height, chainid, allowAgent), σ)` — 현행.
2. `Cf_u = Poseidon(CommitUser(uid, s_u, attrs[6], blind_u))`, `Cf_s = Poseidon(CommitSession(arid, pk_i, blind_s))` — 슬롯 6.
3. `PPID = Poseidon(uid, s_u, chainid, arid)` — 현행.
4′. 세션 리프 `Poseidon(5, Cf_s) ∉ Tree(revRoot)` — 현행(IMTNonMembershipV2(32)). **사용자 리프 비멤버십은 삭제.**
5. 태그 `c1 = r·B8, c2 = Poseidon(uid, arid) + Poseidon(r·pk_trace)` — 현행.
6. 범위: `uid, s_u, r_u, blind_u, blind_s, r < 2^250`, `attrs[k] < 2^64`, `pk_i < 2^160`, `max_height < 2^64` — `r_u` 추가.
7. 선택 공개: 비트 k 가 1 이면 `disc_lo[k] ≤ attrs[k] ≤ disc_hi[k]`(LessEqThan(64)), k < 6; `disc_mask < 64`.
8. 집합: `set_sel ∈ {0..6}`, sel = k+1 이면 `Poseidon(attrs[k])` 가 `set_root` 의 깊이 8 트리에 포함, sel = 0 이면 `set_root = 0` — 현행을 6 으로.
9. **등록부(새)**: `cm = s_u·G_SU + r_u·H`(EscalarMulFix 2개 + 덧셈), `leaf = Poseidon(cm.x, cm.y, Cf_u)`, `MerkleInclusion(20)(leaf, reg_pathElements, reg_pathIndices) == regRoot`. 포함 가젯은 집합 술어의 경로 템플릿을 깊이 매개변수로 일반화한 `circuits/lib/merkle_inclusion.circom`(Poseidon(2), pathIndices 는 비트 검사).

### 5.3 제너레이터
`circuits/lib/mode3_commit.circom` 의 `G_ATTR` 를 6개로. 추가 두 점은 circomlibjs `pedersenHash.getBasePoint(9)`, `getBasePoint(10)` 의 좌표를 회로 상수와 `lib/mode3_credential.js PEDERSEN_GENERATORS.attr4/attr5` 에 같은 글자로 넣고, 현행 생성원 단위 테스트가 두 쪽 일치를 확인한다. `ATTR_SLOTS = 6`, `normalizeAttrs` 는 길이 6·64비트.

### 5.4 속성 값의 도메인 (스펙 2 와의 경계)
슬롯 값은 **64비트 정수**다. 문자열·날짜·열거형·구조체는 스펙 2 의 인코딩(사전 코드, epoch 일수, Poseidon 하위 64비트, 필드 펼치기)으로 정수가 되어 들어온다. CIA·지갑·RP 의 `attrs` 인터페이스는 "10진 문자열 6개"로 두고, 스펙 2 가 그 앞에 스키마·인코더를 얹는다. 범위 술어는 순서가 있는 인코딩에서만 뜻이 있다(스펙 2 가 슬롯별로 허용 술어를 표시).

### 5.5 비용 추정과 산출물
V8 37,130 − 사용자 비멤버십 ≈ 9.5천 + 포함 20단 ≈ 4.9천 + 곱셈 2 ≈ 2.2천 + Poseidon(3) ≈ 0.3천 + 속성 항 2 ≈ 2.2천 + 범위 술어 2 ≈ 0.6천 ≈ **V8 ± 1천**. 실측으로 확정(§12).
산출물 재생성: `scripts/build_mode3_circuit.sh` → `build/mode3/pi_cred.r1cs`, `pi_cred_final.zkey`, `pi_cred_vkey.json`, `pi_cred_js/`, `contracts/PiCredVerifier.sol`(snarkjs export). 기존 ptau 재사용. 이 재생성은 본 스펙 승인으로 허가된 것으로 본다.

## 6. 컨트랙트 변경

- `Mode3Wallet.sol`: `uint[30] pub`; 로그 타입 `Mode3Log`; `_checkStatement`: `pub[6] == log.revRoot()`(StaleRevocationRoot), `pub[7] == log.regRoot()`(**새 `StaleRegistryRoot(bytes32)`**), 키 대조 인덱스 `[8..11]`, 태그 `[12..14]`, `pub[15] >= 64 → BadDisclosure`, `pub[28] > 6 || (pub[28] == 0 && pub[29] != 0) → BadDisclosure`, 마스크 밖 슬롯 검사 `k < 6` on `pub[16+k], pub[22+k]`, root 나이·만료·수명 현행. 꼬리 = `pub[15..29]` 15워드(480바이트). σ_tx 다이제스트 = 꼬리 15 + `(max_height, allowAgent, c1.x, c1.y, c2)` = 20워드. `Mode3Auth` 이벤트 인자 `pub[2], pub[3], pub[5], pub[12], pub[13], pub[14]`; `Disclosure` 이벤트 배열 `[6]`.
- `Mode3WalletFactory.sol`: 로그 타입만.
- `AttrGate.sol`: `_disclosure()` 가 꼬리 15워드를 읽어 `(mask, lo[6], hi[6], setSel, setRoot)`; 정책(국가 집합·나이)은 슬롯 번호를 상수로 둔다(현행 0 = 출생연도, 1 = 국가).
- `PiCredVerifier.sol`: 재생성(공개 입력 30).
- `lib/mode3_onchain.js`: ABI(`uint[30]`), 참조 바이트코드 해시 갱신, `deployMode3Log`, 꼬리 디코드 15워드, `decodeExecuteCalldata`/`parseExecuteReceipt` 배열 6.

## 7. 프로토콜 흐름

### 7.1 등록 (R4)
- 지갑 `createRegistration()`(`lib/mode3_wallet.js`): `s_u, r_u, cm_u` + EdDSA-Poseidon 키 `(sk_u, pk_u)`(circomlibjs `eddsa.prv2pub`). Snap 은 `createRegistrationSecrets()` 가 같은 일을 하고 sk_u 는 Snap 밖으로 나가지 않는다(`storeRegistration` 은 `slot, attrs` 만 받음).
- `sig_reg = EdDSA.Sign_sk_u(Poseidon(D_REG, uid, cm_u.x, cm_u.y))`, `D_REG = ASCII("MODE3REGISTER")` 를 bigint 로(현행 도메인 상수 관례, `lib/mode3_issuance.js registerMessage`).
- `POST /cia/register { uid, pwd, cm_u:{x,y}, pk_u:{x,y}, sig_reg:{R8x,R8y,S} }` → CIA: 형식 → 비밀번호 → `cm_u`·`pk_u` 부분군 점 → `sig_reg` 검증(`bad_registration_signature`) → 이미 등록이면 409 → `accounts[uid] = { pk_u, cm_u, slot, disabled:false, creds:[], attrs }`, `persist` → **201 `{ slot, attrs }`**. `sk_u` 는 더 이상 내려주지 않는다.
- V9 이전 계정(CIA 가 키를 만들어 준 계정)은 그대로 쓴다 — 지갑에 sk_u 가 있고 CIA 는 pk_u 만 쓴다. `slot` 은 마이그레이션(§3.4)이 준다.

### 7.2 사용자 자격증명 발급·교체 (`POST /cia/user_cred`)
현행 검사(형식 → 계정·disabled → 부분군 → sig_u → π_IdP(attrs 6) → 기록) 뒤에: 활성 자격증명 은퇴(폐기 트리 리프 **삽입 없이** 기록만 `revoked:true`) → `registry.set(slot, L_reg(cm_u, Cf_u))` → `pendingSlots.push` → `persist` → `publishNow()` → 201 `{ Cf_u, slot, regRoot, epoch, published }`. 같은 Cf_u 재요청은 멱등(현행). 폐기된 Cf_u 재사용 409 현행.

### 7.3 세션 발급·로그인·트랜잭션
- 세션 발급(`/cia/issue`) 불변. 지갑은 로그인 전에 폐기 트리와 **등록부**를 체인 이벤트에서 복원(§8.1)하고, 증인에 `r_u`·`reg_pathElements/Indices` 를 넣어 π_RP 를 만든다. 공개 입력에 `regRoot`.
- RP 검증기(`lib/mode3_rp.js`): `regRoot == log.regRoot()` 아니면 `stale_registry_root`(순서: revRoot 검사 바로 뒤). 컨트랙트 §6.
- 트랜잭션: 꼬리 15워드, σ_tx 20워드. 캐시 재사용 조건은 현행(두 root 가 최신이고 만료 전).

### 7.4 폐기·복구
- 세션: 현행(`/cia/revoke scope=session` → `Poseidon(5, Cf_s)` 삽입 → pending).
- 자격증명 은퇴(`scope=credential`)·계정 폐기(`scope=account`)·자기 폐기(`/cia/account/self_revoke`): `revoked:true` + (계정이면 `disabled:true`) + `registry.set(slot, 0)` + 게시. **폐기 트리에는 아무것도 넣지 않는다.**
- 복구(`/cia/accounts/:uid/restore`): `disabled:false` 만. 지갑이 다음 로그인에서 `user_cred` 를 새로 받으면 슬롯이 채워진다.
- 효력: 등록부 root 가 바뀌면 캐시된 증명은 `stale_registry_root` 로 떨어지고(폐기와 같은 재검증 시점), `maxRootAge` 안에서 새 root 가 강제된다.

### 7.5 속성 변경 (`/cia/accounts/:uid/attrs`, `/cia/attrs`)
현행과 같되 슬롯 6. 관리자가 바꾸면 활성 자격증명 은퇴 + 슬롯 0 + 게시(현행 "다음 게시까지 대기" 가 "즉시 0" 으로 바뀜); 지갑이 다음 발급에서 다시 받는다.

## 8. 지갑

### 8.1 등록부 동기화 — `lib/mode3_registry_sync.js`
`createRegistrySync({provider, logAddress})` → `sync()`: head 블록을 읽고 창세기부터 `SlotUpdated` 이벤트를 순서대로 `set` 해 트리를 만든 뒤 `root() == log.regRoot()`(같은 head 기준) 가 아니면 throw(fail-closed). 캐시·증분은 두지 않는다(데모 규모; 후속). 폐기 트리 동기화(`mode3_rcl_sync.js`)와 같은 호출 자리(로그인·재검증·상태)에서 함께 돈다.

### 8.2 확인 (R1 의 사용자 쪽, G12)
동기화 뒤 `registry = { slot, leaf: tree.leafAt(slot), expected: L_reg(cm_u, Cf_u), match, regRoot, epoch, checkedAt }` 를 계산해 `/wallet/status` 에 싣고, 지갑 페이지 신원 카드에 한 줄로 보인다.
- `match === true`: "등록부의 내 자격증명이 내 것입니다 (슬롯 N, epoch E)".
- 리프 0: "등록부 게시 대기" — 자격증명 발급 직후 게시 전. 로그인은 게시될 때까지 짧게 재시도(최대 30 s, 2 s 간격)하고 안 되면 `registry_unpublished`.
- 그 외 불일치: "등록부의 내 자격증명이 바뀌었습니다 — 내가 요청한 재발급이 아니면 신원 기관의 부정입니다" (`registry_mismatch`). 로그인·트랜잭션은 시도하지 않는다(증명이 성립하지 않으므로).
- 사용자 자격증명이 없는 상태(첫 로그인 전·은퇴 뒤)는 "자격증명 없음" 으로 현행 표시.

### 8.3 시연: salt·uid 바꾸기 (R6)
- `POST /wallet/demo/override { s_u?: <10진>, uid?: <10진>, scope: "issue" | "prove" }`, `POST /wallet/demo/override { clear: true }`. 메모리에만 두고 재시작하면 사라진다. `/wallet/status` 에 `demoOverride: {scope, fields}` 를 싣는다.
- `scope: "issue"`: 다음 `user_cred` 요청을 만들 때 s_u 또는 C_u 안의 uid 를 덮어쓴다(요청 본문의 uid 는 진짜). 지갑 자체의 증인 정합성 검사(`mode3_secret_source.js` 의 cm_u 대조)는 시연 경로에서 건너뛴다. 기대: AA 400 `bad user credential proof`. 결과 카드에 "시연 모드(salt 바꿈)" 표시.
- `scope: "prove"`: 다음 π_RP 증인의 s_u 또는 uid 를 덮어쓴다. 기대: witness 계산 실패 → 지갑 "증명 생성 실패: 서명된 자격증명과 증인이 다름(C_u 재계산·등록부 리프 불일치)". 한 번 쓰면 자동 해제.
- UI: 지갑 페이지 **전문가 보기**에만 보이는 "시연: 비밀 바꾸기" 카드 — salt "새 난수" 버튼, uid 입력, 범위 선택, "적용"/"원래대로". Snap 모드도 같은 경로(덮어쓰기는 에이전트 메모리).

## 9. 관리자 (R6 의 AA 쪽)
- `POST /cia/admin/registry/tamper { uid }`(requireAdmin): 활성 자격증명이 있는 계정의 슬롯에 `Poseidon(cm_u.x, cm_u.y, 난수)` 를 쓰고 `acct.tampered = true`, 게시. CIA 기록(creds)은 바꾸지 않는다 — "장부를 속이는 AA" 시연. 없으면 409 `no_active_credential`.
- `POST /cia/admin/registry/restore { uid }`: 활성 자격증명의 진짜 리프(없으면 0)를 다시 쓰고 `tampered` 해제, 게시.
- 관리자 페이지 계정 카드에 "슬롯 바꿔치기(시연)" / "되돌리기" 버튼, 표에 `tampered` 표시. `GET /cia/admin/registry` 가 `{ depth, next, regRoot, epoch, slots: [{index, uid, leaf, tampered}] }` 를 준다(관리자용; 공개 아님).

## 10. 오류 처리

| 곳 | 사유 | 동작 |
|---|---|---|
| CIA register | `bad_registration_signature`, `pk_u is not a valid subgroup point` | 400 |
| CIA user_cred | 게시 실패 | 201 `published:false`; `pendingSlots` 유지; 하트비트 재시도; 지갑 "게시 대기" |
| CIA tamper/restore | 슬롯·활성 자격증명 없음 | 409 `no_active_credential` |
| RP 검증기 | `regRoot` ≠ 체인 | `stale_registry_root` |
| 컨트랙트 | `pub[7]` ≠ `log.regRoot()` | `StaleRegistryRoot(bytes32)` |
| 지갑 동기화 | 재생 root ≠ 체인 regRoot | throw(fail-closed), 상태 점 "지갑 노랑: 등록부 불일치" |
| 지갑 로그인 | 리프 0 | `registry_unpublished`(재시도 뒤) |
| 지갑 로그인 | 리프 ≠ 기대 | `registry_mismatch`, 시도 안 함 |
| 지갑 시연 | 덮어쓰기 중 | 결과 카드 "시연 모드" + 실제 거절 사유 그대로 |

## 11. 보안·프라이버시 노트
- **G12 발급 책임성(새 목표, 비형식 진술)**: AA 가 사용자 uid 의 등록(cm_u)에 대해 사용자가 요청하지 않은 자격증명 C′ 을 어떤 검증자에게든 통과시키려면 등록부의 그 슬롯을 L_reg(cm_u, Cf′) 로 바꿔 게시해야 하고, 그러면 사용자의 다음 확인(§8.2)이 불일치를 보인다. 바꾸지 않으면 조건 9 가 실패한다(Pedersen 결합성 + Poseidon 충돌 저항 + Groth16 건전성). 형식화는 `security_formal.md` 후속.
- 못 잡는 것(R7): AA 가 같은 uid 로 등록을 하나 더(cm_u′) 만드는 것. 키가 uid 와 무관해서다. 논문 한계에 적는다.
- 새로 보이는 것: 등록 수(슬롯 수)와 슬롯 갱신 시각. cm_u 는 은닉 커밋먼트라 리프에서 사용자를 알 수 없고 RP 는 cm_u 를 본 적이 없다(비공개 증인). 갱신 시각과 첫 로그인의 상관은 폐기 리프 시각과 같은 부류(형식 문서 §8 (c)).
- 등록 키를 지갑이 만들므로 (A10) 의 "AA 가 사용자 키를 안다" 가 사라진다. sig_u·sig_reg·폐기 요청 서명의 증거력이 생긴다.
- 시연 덮어쓰기는 지갑 자체 보호를 끄는 기능이므로 전문가 보기에만 두고 메모리에만 둔다.

## 12. 테스트·벤치

| 그룹 | 파일 | 내용 |
|---|---|---|
| unit | `tests/test_mode3_registry.js`(새) | 트리 set/path/root, 빈 트리 root, 깊이 20 경로 검증 |
| unit | `tests/test_mode3_issuance.js`, `tests/test_mode3_credential_v5.js`(수정) | attrs 6, 제너레이터 두 쪽 일치, `registerMessage`·sig_reg, 등록부 리프 |
| unit | `tests/test_mode3_health_shape.js` | status 의 `registry`·`demoOverride` 모양 |
| circuit | `tests/test_pi_cred_witness.mjs`(수정) | 양성; 음성 — 틀린 r_u, 틀린 경로, 리프 0, 6번 슬롯 범위·집합, salt 바꾼 증인 |
| contract | `test/Mode3Log.test.mjs`(새), `test/Mode3Wallet.test.mjs`·`test/AttrGate.test.mjs`·`test/Mode3ReferenceCode.test.mjs`(수정) | 게시·다이제스트·epoch·길이 불일치; regRoot stale; 입력 30; 마스크 6; 꼬리 15; AttrGate 6 |
| chain | `tests/test_mode3_e2e.mjs`, `tests/test_mode3_demo_stack.mjs`(수정), `tests/test_cia_registry.mjs`(새) | 등록(지갑 키) → 발급 → 게시 → 로그인 → tx; 은퇴 → 슬롯 0 → 거절; tamper → ✗·거절 → restore; 옛 상태 파일 마이그레이션; 시연 덮어쓰기 3경로 |
| browser | `tests/test_mode3_browser.mjs`·`test_mode3_tour.mjs`(수정) | 등록부 줄 ✓/✗, 관리자 버튼, 속성 6행, 시연 카드 |
| bench | `scripts/bench_pi_cred.mjs`, `scripts/bench_mode3_onchain.mjs` → `results/mode3_v9_registry_<날짜>.md` | 제약, 증명/검증 ms, execute gas(mask 0·범위·집합), 게시 gas(리프·슬롯), 로그인 지연 |

`scripts/run_tests.sh` 의 해당 그룹에 새 파일을 넣는다.

## 13. 비범위·후속
- 스펙 2: 속성 매핑 계층(스키마 `GET /cia/attr_schema`, 인코더 `lib/mode3_attr_schema.js`, 화면의 이름값, RP 정책의 디코드 표현).
- VRF 키 슬롯(두 번째 등록 탐지), 등록부 증분 동기화 캐시, 형식 문서 G12·(A10) 갱신, 논문 §V·§VII, 그림 Fig. 1 갱신, 폐기 트리의 옛 사용자 리프 정리.
