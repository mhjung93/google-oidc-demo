# Mode 3 세션 폐기 상한(카운터) — RCL 리프에 nonce 상한을 실어 폐기 레이스를 없앤다 (설계)

작성 2026-10-22. 브랜치 `feat/mode3-v11`. 같은 날의 "IdP 페이지" 설계(`2026-10-22-mode3-idp-pages-design.md`)와 한 계획으로 묶어 구현한다(Snap 재빌드·재설치를 한 번으로). Snap 모드 기준, web 모드는 손대지 않는다.

## 0. 한 줄 요약

세션 폐기 요청에 **허용 상한 c**(계정 컨트랙트 nonce 기준)를 넣고, 폐기 트리(RCL) 리프를 `H'·2^32 + c` 로 만들어 트리에서 같은 세션의 리프가 연속 구간에 놓이게 한다. 거래 증명 π_RP 는 "상한이 이번 nonce 이하인 리프가 없다"(구간 비멤버십)를 증명하고 계정 컨트랙트가 증명의 카운터와 거래 nonce 가 같음을 확인한다. 그러면 폐기 시점과 거래 전파 순서에 관계없이 **nonce < c 인 거래만 유효**(c = 허용하는 거래 수)가 확정된다. 로그인·재검증은 상한과 무관하게 "폐기 리프가 하나라도 있으면 불가"다. 전파 지연 동안의 거래까지 즉시 막기 위해 **같은 상한을 응용 체인의 계정 컨트랙트에도 올린다**(세션키별, 새 세션의 거래로, §6.5) — 두 곳의 상한은 같은 값이다.

## 1. 결정 (2026-10-22 대화)

| # | 결정 | 근거 |
|---|---|---|
| C1 | 카운터 = 계정 컨트랙트(`Mode3Wallet`)의 `nonce` | 이미 체인에 있고 단조 증가하며 세션키 서명이 덮는다. 새 상태 없음 |
| C2 | 로그인·재검증 증명은 상한과 무관하게 폐기 여부만 본다(카운터 자리에 최댓값) | 폐기된 세션은 상한이 남아 있어도 로그인하면 안 된다 |
| C3 | 회로·zkey·검증 컨트랙트 재생성, 전 데모 리셋, 논문 V11 수치·벤치마크 재측정을 감수한다 | 사용자 결정 |
| C4 | IdP 페이지 작업과 한 계획으로 묶는다 | Snap 재빌드·MetaMask 재설치를 한 번으로 |
| C5 | RCL 상한과 **응용 체인 계정 컨트랙트의 세션키별 상한** 둘 다 넣는다 | RCL 상한은 리프 반영 뒤의 유효 집합을 확정하고, 체인 상한은 전파 지연 동안의 거래를 즉시 막는다(2026-10-22, root 검사 정정 뒤 재확인) |

## 2. 문제

폐기 요청(IdP 삽입) → 캐노니컬 게시 → 거울 중계 → RP·컨트랙트의 최신 root 갱신 사이에 **전파 지연**이 있다. 계정 컨트랙트·RP 는 증명의 root 가 **최신 root 와 같아야** 받으므로(`StaleRevocationRoot`, `stale_root` — 옛 root 를 받아 주는 창은 없다), 그 지연 동안만 세션키로 낸 거래가 통과한다. `maxRootAge`(100블록)는 이와 별개의 **생존 검사**다(최신 root 가 그보다 오래됐으면 fail-closed — IdP 가 죽었거나 게시를 숨길 때). 지금은 "어느 거래까지가 유효한가"가 전파 순서에 달려 있어 사용자가 예측할 수 없다. 상한 c(= 허용하는 거래 수)를 두면 리프가 반영된 뒤의 유효 집합이 `nonce < c` 로 확정된다. `c = 0` 은 "전부 차단"이다. 전파 지연 자체는 §7.

## 3. 리프와 트리

- 세션 폐기 리프 값: `V = H' · 2^32 + c`, `H' = Poseidon(5, Cf_s) mod 2^220`, `c ∈ [0, 2^32)`. `V < 2^252` 이므로 기존 `leafValue` 의 252비트 마스크·회로의 `LessThan(252)` 범위 안이다.
- 같은 세션의 리프는 `[H'·2^32, H'·2^32 + 2^32 − 1]` 구간에만 놓인다. 다른 세션과 겹칠 확률은 2^-220 수준(무시).
- 한 세션에 상한이 다른 리프가 여럿 있을 수 있다(상한을 낮추는 재폐기). 검사는 "구간 안에 리프가 하나라도 있는가"라 가장 낮은 상한이 효력을 갖는다. 상한을 **올리는** 재폐기는 효력이 없다(append-only 와 맞다).
- 사용자 리프(`Poseidon(4, Cf_u)`, V9 이후 미사용)·등록부는 그대로.
- `lib/mode3_revocation.js`: `sessionLeaf(Cf_s, bound)` → `V`. `sessionLeafRange(Cf_s, k)` → `[H'·2^32, H'·2^32 + k]`(상한 `≤ k` 인 리프 전부 — nonce k 의 거래가 걸리는 리프). `TAG_MODE3_SESSION` 그대로.
- `lib/imt_v2.js`: `getNonMembershipWitness(value)` 외에 `getRangeNonMembershipWitness(lo, hi)` — low 리프 = `value < lo` 인 가장 큰 리프, `low.nextValue > hi` 또는 `low.nextValue == 0`(끝) 이어야 한다. 없으면(구간 안에 리프) "is a member" 류 오류.

## 4. 회로 (`circuits/pi_cred.circom`, `circuits/lib/imt_nonmembership_v2.circom`)

- 공개 입력 추가: `counter`(34번째, `PUB_INDEX.COUNTER = 33`, `COUNT = 34`). `Num2Bits(32)` 로 범위 제약.
- ⑥ 세션 비멤버십을 구간 버전으로: `IMTRangeNonMembershipV2(depth)` — 입력 `lo, hi, lowValue, lowNextIndex, lowNextValue, path…, root`. 검사: `lowValue < lo`, `(lowNextValue > hi) OR (lowNextValue == 0)`, Merkle 경로. 기존 가젯은 그대로 두고(등록부·다른 용처 없음이면 삭제 가능) 새 템플릿을 더한다.
- `lo`·`hi` 계산: `sLeaf = Poseidon(5, Cf_s)` → `Num2Bits(254)` → 하위 220비트로 `H'` → `lo = H'·2^32`, `hi = lo + counter`. 구간 `[lo, hi]` 는 상한 `c ≤ counter` 인 리프 전부를 덮는다. 거래는 `counter = nonce`(상한 c ≤ nonce 인 리프가 있으면 실패 = `nonce < c` 만 통과), 로그인은 `counter = 2^32 − 1`(그 세션의 리프가 하나라도 있으면 실패)(§6). 언더플로 없음.
- 비용 추정: `Num2Bits(254)` ~254 + 비교 2개 ~500 + `Num2Bits(32)` 32 → 제약 **약 +800**(33,909 → ~34,700). 실측은 빌드 뒤 기록.
- 메인의 `public [...]` 끝에 `counter`(auid_s·arid_s·r_s 뒤). 검증 컨트랙트는 `uint[34]`.

## 5. 컨트랙트

- `contracts/PiCredVerifier.sol`: 빌드 스크립트가 다시 뽑는다(`uint[34] calldata _pubSignals` 검사로 스크립트의 33 검사를 34 로).
- `contracts/Mode3Wallet.sol`: `execute(..., uint[34] pub)`; `if (pub[33] != payload.nonce) revert CounterMismatch(payload.nonce, pub[33]);` (nonce 검사 바로 뒤). 다이제스트에 `pub[33]` 을 더하지는 않는다(`payload.nonce` 가 이미 서명에 들어 있고 같음을 강제한다). 이벤트 변경 없음.
- `contracts/Mode3WalletFactory.sol`·`AttrGate.sol`: `pub` 길이 상수만 34 로(있다면).
- 배포 스크립트·`lib/mode3_onchain.js`(`PUB_INDEX`·`proofToCalldata`·`decodeExecuteCalldata`·ABI): 34 로.

## 6. 지갑·RP·IdP

### 6.1 증명 생성 (`lib/mode3_wallet.js buildCredentialProof`, 에이전트, web 코어는 범위 밖)
- 입력 `counter` 추가. 거래(`prepareTx`): `counter = payload.nonce`(계정 미배포면 0 — 상한 `c = 0` 으로 폐기된 세션은 첫 거래도 거절된다). 로그인·재검증·세션 요청: `counter = LOGIN_COUNTER = 2^32 − 1`.
- 증명 캐시(`proofCache`): 키에 `counter` 를 넣는다. 로그인 π(LOGIN_COUNTER)는 지금처럼 root·disclosure 가 같으면 재사용; 거래 π 는 nonce 마다 새로 만든다(캐시 없음 — 거래마다 증명 비용).
- 비멤버십 증인: 거래는 `getRangeNonMembershipWitness(lo, lo + nonce)`, 로그인은 `getRangeNonMembershipWitness(lo, lo + 2^32 − 1)`(= 그 세션의 리프가 하나도 없음).

### 6.2 RP 검증 (`lib/mode3_rp.js verifyLogin`, `mode3_rp.js`)
- 로그인·재검증·세션 요청의 π 는 `pub[COUNTER] == LOGIN_COUNTER` 여야 한다(아니면 `bad_counter`). 거래 경로(릴레이)는 컨트랙트가 본다.

### 6.3 폐기 요청 (`cia.js /cia/revoke`, `lib/mode3_issuance.js revokeSessionMessage`, Snap)
- 본문 `{ uid, scope:'session', Cf_s, bound, nonce, sig_u }`. 서명 메시지 `Poseidon(D_REVOKESESS, uid, Cf_s, bound, nonce)`(도메인 태그 값은 그대로, 인자 하나 추가 — 옛 서명과 호환되지 않는다; 같은 날 전부 재배포하므로 수용). 관리자 폐기(시크릿)는 `bound` 를 관리자가 준다(기본 `0` = 전부 차단). `bound` 는 `[0, 2^32)`.
- IdP 는 `sessionLeaf(Cf_s, bound)` 로 리프를 넣고 세션 레코드에 `bound` 를 남긴다. 관리자 페이지의 세션 폐기 표에 `bound` 열.
- Snap: `mode3_revoke_session` 동의 창에 "허용 거래 수 c(nonce < c 만 유효)" 를 보이고 서명에 `bound` 를 넣는다(재빌드).

### 6.4 폐기 UI (`mode3/wallet.html`, 에이전트 `/wallet/revoke_session`)
- 세션 카드에 계정 `nonce`(= 지금까지 보낸 거래 수, 체인에서 읽음, 미배포면 0)를 보인다. 폐기 버튼 → 허용 거래 수 입력(기본 `nonce`, 즉 "지금까지 보낸 것까지만"; 진행 중 거래 하나를 살리려면 `nonce + 1`; 전부 차단은 `0`).
- 폐기 뒤 세션 카드는 지금처럼 사라지고(폐기 요청 접수), 그 세션의 `{ account, pk_i, bound }` 가 에이전트 상태의 **체인 반영 대기 목록**(`pendingBounds`)에 남는다(§6.5).

### 6.5 응용 체인 계정 컨트랙트의 세션키별 상한 (즉시 차단, C5)
- `Mode3Wallet.sol`: `mapping(uint256 pk_i => uint256 boundPlusOne) public sessionBound;`(0 = 없음, 저장값 = c + 1 — c = 0 도 표현). `execute` 는 증명 검증 뒤 `uint256 b = sessionBound[pub[2]]; if (b != 0 && payload.nonce + 1 >= b) revert SessionBounded(pub[2], b - 1);` — 즉 그 세션키로는 `nonce < c` 만 통과(RCL 과 같은 의미).
- 설정 함수 `setSessionBound(uint256 pk_i, uint32 c)`: `msg.sender == address(this)` 만(계정이 **자기 자신을 부르는 거래**로만 설정) — 새 진입점·새 증명 종류 없이, 다른 세션(S2)이 보내는 **보통의 execute**(`payload.to = address(this)`, `payload.data = setSessionBound(pk_i_S1, c)`)로 설정한다. 계정 소유 증명은 S2 의 π_RP 가 이미 한다. 상한은 **낮추기만** 된다(`b != 0 && c + 1 >= b` 면 revert `BoundNotLowered`) — RCL 의 "가장 낮은 상한이 효력" 과 같다. 이벤트 `SessionBound(pk_i, c)`.
- 지갑(Snap 모드 에이전트·`wallet.html`): 세션 카드 아래 **"체인 반영 대기"** 목록 — 폐기한 세션마다 `account`·`pk_i` 앞자리·`c` 를 보이고, 같은 계정(같은 RP·같은 체인)의 **살아 있는 다른 세션**이 있으면 "지금 반영" 버튼이 활성이다(없으면 "이 RP 에 다시 로그인하면 반영할 수 있습니다"). 누르면 에이전트 `POST /wallet/apply_bound { pending_id, r_s(S2) }` → `prepareTx` 와 같은 경로로 `to = account, data = setSessionBound(pk_i_S1, c)` 인 execute 를 만들어 RP 릴레이로 보낸다(릴레이의 검사 — execute 셀렉터·`to == computeAddress(PPID)` — 를 그대로 통과한다). 영수증이 오면 대기 목록에서 지운다.
- 폐기 흐름은 그대로 두 단계다: ① IdP 폐기(RCL 상한) ② 새 세션으로 체인 상한. ②는 선택이지만 데모의 폐기 단계는 ①②를 이어서 보인다(폐기 → 같은 RP 재로그인 → "지금 반영").
- 에이전트 상태에 `pendingBounds: [{ id, account, chainid, arid, pk_i, bound, revokedAt, txHash? }]`. 지갑 재시작을 넘어 남는다(파일).
- 릴레이·RP·IdP 는 변경 없음(RP 관리자 거래 기록에는 `kind: 'bound'` 로 보인다 — `payload.to == account` 이고 셀렉터가 `setSessionBound`).

## 7. 보장과 한계

- 보장(RCL): 체인 root 에 리프가 반영된 뒤에는 `nonce ≥ c` 인 거래는 어떤 π 로도 통과하지 못하고, `nonce < c` 인 거래는 영향을 받지 않는다. RP 로그인·재검증은 폐기 리프가 있으면 불가.
- 보장(체인 상한): `setSessionBound` 거래가 채굴된 뒤에는 IdP 게시·중계와 무관하게 그 세션키의 `nonce ≥ c` 거래가 즉시 거절된다. 전파 지연 동안의 거래는 이 거래가 채굴되기 전까지만 가능하다.
- 한계: 리프가 응용 체인의 최신 root 에 반영되기 전(IdP 삽입 → 캐노니컬 게시 → 거울 중계)에는 세션키로 낸 거래가 통과한다 — 데모는 게시 즉시 중계라 몇 초, 실제 체인은 두 체인의 블록 시간 + 중계기 지연. 체인 상한(§6.5)은 이 지연을 "새 세션 로그인 + 거래 한 건" 시간으로 바꾼다. `maxRootAge` 는 이 지연과 무관한 생존 검사다.
- 체인 상한은 그 계정(그 RP·그 체인)에서만 효력이 있다. 같은 세션키가 다른 계정에 쓰일 일은 없다(세션은 RP·체인에 묶인다).
- 상한은 세션(Cf_s)마다다. 같은 계정의 다른 세션(재발급 뒤)은 별개 Cf_s 라 별개 리프다.

## 8. 테스트

| 묶음 | 파일 | 내용 |
|---|---|---|
| circuit | `tests/test_imt_v2_nonmembership_circuit.mjs`(확장) | 구간 비멤버십: 구간 밖 리프만 있으면 통과, 구간 안 리프(경계 포함)가 있으면 실패, `lowNextValue=0` 끝 처리 |
| unit | `tests/test_mode3_revocation*.js`, `tests/test_imt_v2*.mjs` | `sessionLeaf(Cf_s, c)` 값·범위, `getRangeNonMembershipWitness` |
| contract | `test/Mode3Wallet.test.mjs` | `pub[33] != nonce` → `CounterMismatch`; 실제 π 로 nonce 0·1 실행; `setSessionBound` 는 자기 호출(execute 경유)로만(외부 호출 revert), 낮추기만, 설정 뒤 그 pk_i 의 `nonce ≥ c` execute 는 `SessionBounded`, 다른 pk_i 는 무관 |
| chain | `tests/test_mode3_wallet_agent.mjs`, `tests/test_mode3_rp.mjs`, `tests/test_cia_register_issue.mjs` | 폐기(bound) 서명·리프; RP 가 `bad_counter` 거절; **레이스 시나리오**: 세션으로 거래 2건(nonce 0·1) → 허용 수 3 으로 폐기·게시·중계 → nonce 2 거래는 성공, nonce 3 거래는 거절(회로 증인 실패 → `revoked_session`/컨트랙트 거절), 로그인·재검증은 `revoked_session`; 허용 수 0 으로 폐기한 다른 세션은 첫 거래(nonce 0)도 거절. **즉시 차단**: 중계를 끈 채(거울 root 그대로) S1 을 허용 수 2 로 폐기 → S2 로 로그인 → `/wallet/apply_bound` → S1 의 nonce 2 거래는 `SessionBounded`(거울 root 가 아직 옛것이어도), nonce 1 은 성공 |
| browser | `tests/test_mode3_browser.mjs` | 세션 카드 nonce 표시, 폐기 상한 입력 → Snap 동의 창에 상한 표시; 폐기 뒤 "체인 반영 대기" 행, 재로그인 뒤 "지금 반영" → 거래 성공·행 사라짐 |
| bench | `scripts/bench_pi_cred.mjs` | 제약 수·증명 시간 재측정 → `results/` 에 날짜 파일 |

## 9. 빌드·배포 순서

1. 회로·가젯 수정 → `bash scripts/build_mode3_circuit.sh pot21_final.ptau`(사용자 승인 C3; pi_cred·pi_idp 둘 다 다시 만든다 — pi_idp 는 바뀌지 않지만 스크립트가 묶어 돈다) → `contracts/PiCredVerifier.sol` 갱신 → `scripts/pack_mode3_build.sh`(MANIFEST).
2. 컨트랙트 컴파일·`test/*.test.mjs`.
3. 라이브러리·에이전트·RP·IdP·Snap(재빌드) → chain·browser·snap 테스트.
4. 데모 리셋 네 스크립트로 재배포(검증기·팩토리 주소가 바뀐다). 분리 데모는 VM 에 코드·`build/mode3` 재전송(`SYNC=1`).
5. 벤치마크 재측정·논문 수치 메모.

## 10. 수용 기준

1. 제약 수·zkey·검증기가 새로 생성되고 `PUB_INDEX.COUNT == 34` 로 전 묶음 테스트가 통과한다.
2. 레이스 시나리오(§8 chain)가 통과한다: 허용 수 c 로 폐기한 뒤 `nonce < c` 거래는 성공, `nonce ≥ c` 거래는 거절, 로그인·재검증은 거절.
3. 데모에서 세션 폐기 때 상한을 고를 수 있고, 관리자 페이지에 상한이 보인다. 폐기 뒤 재로그인해 "지금 반영" 을 누르면 체인 상한 거래가 성공하고, 그 뒤 옛 세션키의 거래는 중계 전에도 거절된다.
4. `results/` 에 새 제약 수·증명 시간이 기록된다.
