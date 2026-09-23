# BAAR 기반 PairCT Revocation — 설계 문서

## 1. 배경

PairCT는 현재 revocation을 구현하지 않았다. 있는 것은 `max_height` 만료뿐이며, SSI revocation 분류(`documents/260818_related_work_hybrid_auth_revocation.md` 3.0절) 기준으로 **③번 단기 크레덴셜**에 해당한다 — 네 범주 중 가장 약한 쪽이다. 세션 중 폐기가 불가능하고, `pi_pk_i`를 매 트랜잭션 재생성해도 상태 조회가 없어 폐기에 기여하지 못한다.

관련 연구 조사에서 세 가지 방향(Option A/B/C)을 검토했고, **Option C(폐기를 온체인 상태로 이전)**를 권고안으로 정했다. 그 설계 원본이 BAAR(Ahmed 외, *"BAAR: A framework for blockchain-based anonymous and revocable user authentication scheme"*, PLOS ONE 21(3): e0343696, 2026-03-31)이다. BAAR는 Pedersen vector commitment + Schnorr ZKP + Merkle 동적 accumulator로 구성되며, **오프체인 증명 + 온체인 컴팩트 root**라는 구조를 취한다.

본 문서는 BAAR의 구조를 PairCT에 맞게 재설계한다. BAAR가 Schnorr Σ-protocol을 쓰는 반면 PairCT는 Groth16을 쓰므로, Merkle 경로 검증을 circom 회로 안에 넣어야 한다는 점이 가장 큰 차이다.

## 2. 목표 / 비목표

**목표**
- 세션 단위(`r_token`)와 계정 단위(`auid`) 폐기를 지원한다.
- 폐기 권한은 IdP 단독으로 한다 — conditional privacy가 이미 IdP를 신뢰 주체로 두므로 새 신뢰 가정을 추가하지 않는다.
- grace window(최근 K개 root 허용)로 증명 캐싱을 유지한다.
- **cross-service unlinkability를 보존한다.** 같은 계정의 서로 다른 PPID 지갑이 온체인에서 연결되어서는 안 된다.
- 논문의 설계·비용 분석 절에 쓸 수 있는 수준까지 정리한다.

**비목표**
- 구현. 회로·zkey 재생성, verifier·factory 재배포는 이번 범위가 아니다.
- PPID 단위 폐기. 3.1절에서 설명하듯 IdP가 `ppid`를 구조적으로 알 수 없어 IdP 단독 권한과 양립하지 않는다.
- 폐기 권한의 탈중앙화(다중서명·거버넌스). 중앙화 우려는 5.3절에 한계로 기록만 한다.
- 형식 보안 증명. 5절의 논증은 정성적 수준이다.

## 3. 설계 제약 (코드 확인 결과)

### 3.1 IdP가 아는 식별자는 제한적이다

| IdP가 아는 것 | IdP가 모르는 것 |
|---|---|
| `uid`, `auid`, `auid_i`, `r_token`, `token_nonce` | `ppid`, `pk_i`, `rp_nonce`, `salt`, `rid` |

`custom_idp.js:633`에 근거가 명시돼 있다.

> `rp_nonce` is never sent to the IdP (it would let the IdP recover `rid` via `arid_i / rp_nonce`)

`auid_i = ppid × rp_nonce`이므로 `rp_nonce`를 알면 나눗셈으로 `ppid`를 복원할 수 있다. 이를 막기 위해 `rp_nonce`를 IdP에 보내지 않는 것이 현 설계의 의도이며, 그 결과 **IdP는 `ppid`를 계산할 수 없다.** 따라서 "IdP가 사용자의 PPID를 열거해 폐기한다"는 방식은 성립하지 않는다.

### 3.2 `auid`는 계정 고정값이고 IdP가 항상 안다

`auid = Poseidon(uid, salt)`는 `rid`도 세션 nonce도 포함하지 않는 계정 고정값이다. `pi_arid_i`의 public input이므로 IdP가 로그인 때마다 관측하며, `custom_idp.js:618`에서 `user.lastAuid`로 저장한다.

더불어 `custom_idp.js:615-617`이 **salt 교체를 능동적으로 거부**한다.

> `Wallet binding mismatch: this account is using a different salt than its last successful login`

따라서 `auid`는 계정마다 안정적이고, 폐기된 사용자가 salt를 바꿔 회피할 수 없다.

### 3.3 `r_token`은 이미 회로 안에 있다

`circuits/pi_pk_i.circom:31-37`이 `r_token === Poseidon(pk_i, max_height, rp_nonce)`를 이미 제약한다. 세션 폐기를 위해 회로에 새 입력을 추가할 필요가 없다.

### 3.4 `r_token`을 public으로 올려서는 안 된다

세션 폐기를 온체인 매핑 조회로 처리하면 Merkle 경로 하나를 아낄 수 있으나, **채택해서는 안 된다.** IdP는 `issuanceLog`로 `r_token → uid`를 알고 있다. `r_token`이 온체인에 공개되면 IdP 로그와 온체인 지갑을 잇는 다리가 생겨, IdP나 그 로그를 얻은 자가 모든 지갑을 계정에 매핑할 수 있다. `pk_i`·`ppid`가 이미 공개지만 IdP는 그 둘을 모르기 때문에 현재는 다리가 없다.

**세션 폐기를 지원하려면 `r_token`은 비공개로 두고 ZK 비멤버십을 써야 한다.**

## 4. 아키텍처

### 4.1 핵심 구조

IdP가 폐기 항목을 **하나의 indexed Merkle tree(IMT)**에 넣고 root만 온체인에 게시한다. 지갑은 증명 안에서 자기 세션과 계정이 그 트리에 없음을 보인다. 폐기 대상은 회로 밖으로 나오지 않는다.

두 종류를 한 트리에 담되 도메인 태그로 분리한다.

```
세션 리프 = Poseidon(TAG_SESSION, r_token)
계정 리프 = Poseidon(TAG_ACCOUNT, auid)
```

root가 하나뿐이라 grace window의 K개 root도 한 벌만 관리한다.

**IMT를 쓰는 이유:** 비멤버십 증명이 필요한데, sparse Merkle tree는 깊이가 필드 비트수(254)라 Poseidon 254회가 든다. IMT는 정렬된 리프에서 `low < target < next`를 보이는 방식이라 경로 하나와 비교 몇 개로 끝난다.

**폐기 집합(비멤버십)을 쓰는 이유:** zk-creds형 발급 집합 멤버십은 발급 때마다 root가 바뀌어 모든 사용자의 witness가 상시 갱신 대상이 된다. 폐기는 드물고 발급은 잦으므로, 폐기 집합 쪽이 root 변경 빈도가 훨씬 낮아 grace window와 궁합이 맞는다.

### 4.2 신설: `RevocationRegistry` 컨트랙트

| 항목 | 내용 |
|---|---|
| 상태 | `bytes32[K] roots` 순환 버퍼, `uint256 head`, `mapping(bytes32 => uint256) rootIndex` |
| 권한 | IdP 주소만 갱신 (`onlyIdP`) |
| `pushRoot(bytes32)` | 새 root 추가, 가장 오래된 것 축출 |
| `isRecentRoot(bytes32) view returns (bool)` | grace window 포함 여부를 O(1) 조회 |

온체인 상태는 32바이트 × K다. K=8이면 8 slot.

### 4.3 변경: `circuits/pi_pk_i.circom`

**새 public input** — `revocationRoot` 1개

**새 private input** — `uid`, `rid`, `salt`, 그리고 두 비멤버십 witness(low leaf 값, 경로, 인덱스)

**새 제약**

```
PPID === Poseidon(uid, rid, salt)
auid === Poseidon(uid, salt)
NonMembership(Poseidon(TAG_SESSION, r_token), revocationRoot)
NonMembership(Poseidon(TAG_ACCOUNT, auid),    revocationRoot)
```

**바인딩 제약이 필수인 이유:** `auid`만 private으로 받으면 사용자가 폐기되지 않은 아무 계정의 `auid`를 가져다 쓸 수 있다. `PPID`(이미 public이고 CREATE2로 지갑 주소에 묶여 있음)를 통해 같은 `uid`·`salt`에 묶어야 위조가 막힌다.

### 4.4 변경: `PPIDWallet.execute()`

`revocationRoot`를 인자로 받아 `registry.isRecentRoot(root)`를 확인하고, `pubSignals`를 6개로 확장한다.

```
[pk_i, pk_IdP_x, pk_IdP_y, ppid, max_height, revocationRoot]
```

### 4.5 변경: `custom_idp.js`

폐기 API(`POST /idp/revoke`)와 IMT를 유지하고, root 갱신 후 `pushRoot`를 호출한다. **기존 `issuanceLog`(r_token → uid)와 `user.lastAuid`를 그대로 재사용**해 폐기 대상을 식별하므로 새로 만들 로그가 없다.

### 4.6 변경: `wallet_agent.js`

로그인 시 현재 root와 두 비멤버십 witness를 확보하고, 캐시된 증명의 root가 grace window 안이면 재사용한다.

## 5. 데이터 흐름

### 5.1 폐기 흐름 (IdP)

```
① 폐기 트리거 — 관리자 판단 또는 conditional privacy 추적 결과
② 대상 식별
     계정 → users[username].lastAuid          (이미 존재)
     세션 → issuanceLog 역조회로 r_token       (이미 존재)
③ IMT에 리프 삽입
     Poseidon(TAG_ACCOUNT, auid) 또는 Poseidon(TAG_SESSION, r_token)
④ 새 root 계산 → registry.pushRoot(newRoot)   [온체인 tx]
⑤ 갱신된 폐기 목록 공개
```

### 5.2 검증 흐름 (트랜잭션 제출)

```
① wallet_agent: 캐시된 증명의 root가 아직 grace window 안인가?
     예   → 증명 재사용 (비용 0)
     아니오 → 최신 root로 pi_pk_i 재생성
② execute() 호출
③ 컨트랙트: registry.isRecentRoot(root) 확인
④ Groth16 검증 → ecrecover 서명 검증 → max_height 확인
```

### 5.3 witness 갱신

폐기 목록 전체를 공개하고 지갑이 로컬에서 IMT를 재구성해 자기 witness를 계산한다.

리프가 `Poseidon(TAG, ·)` 해시라 preimage가 드러나지 않고, "내 `auid`가 목록에 있는가"는 자기 preimage를 아는 본인만 판정할 수 있다. 제3자가 특정인의 포함 여부를 확인하려면 그 사람의 `uid`와 `salt`가 필요하므로 불가능하다. 따라서 **폐기 목록 공개는 프라이버시를 해치지 않는다.**

zk-creds가 쓰는 로그 크기 증분 갱신도 가능하지만, 폐기 집합은 작아서(수천~수만) 전체 다운로드가 수백 KB 수준이므로 초기 설계에서는 단순화를 택한다.

### 5.4 설계 제약: `K × T < max_height`

grace window가 K개, IdP의 root 갱신 주기가 T라면 **폐기 반영 최대 지연은 K × T**다. 이 값이 `max_height`(현재 1시간)보다 커지면 만료를 기다리는 것보다 느린 폐기가 되어 무의미하다.

예: K = 8, T = 5분 → 최대 40분. 1시간보다 짧아 유효하다.

### 5.5 주요 실패 모드

| 상황 | 처리 |
|---|---|
| root가 grace window를 벗어남 | `execute()` revert → wallet_agent가 재증명 후 재시도 |
| IdP가 root 갱신을 멈춤 | 기존 root가 유지되는 동안 정상 동작, 이후 전면 중단 |
| 폐기 직후~root 게시 전 tx | 통과됨 (최대 T만큼의 창) |
| 지갑이 폐기 목록을 못 받음 | witness 계산 불가 → 재증명 실패. 목록 미러링 필요 |

IdP 갱신 중단이 전면 중단으로 이어지는 점이 가장 큰 가용성 약점이며, 이는 "발급자 세션 개입형"이 가용성을 신선도와 맞바꾼 구조적 특성이 폐기에도 그대로 나타나는 것이다.

## 6. 보안·프라이버시 논증

### 6.1 유지되는 것

**온체인 관찰자는 폐기 여부 외 아무것도 얻지 못한다.** 추가되는 public input은 `revocationRoot` 하나이고, 전역값이라 사용자별 정보를 담지 않는다.

**cross-service unlinkability가 보존된다.** `auid`가 private input으로만 들어가므로 같은 계정의 서로 다른 PPID 지갑이 온체인에서 연결되지 않는다. 3.4절에서 `r_token` public화를 기각한 이유와 같은 원리다.

**IdP는 새로운 정보를 얻지 못한다.** 폐기 트리에 넣는 `auid`·`r_token`은 IdP가 이미 알던 값이다. IdP가 온체인에서 보는 것은 root와 기존 public signals뿐이라, 여전히 `ppid`·`pk_i`를 계정에 매핑할 수 없다.

**위조가 막힌다.** 4.3절의 바인딩 제약으로 `auid`를 임의로 고를 수 없다. `r_token`도 회로가 `Poseidon(pk_i, max_height, rp_nonce)`로 이미 제약한다.

### 6.2 새로 생기는 누출 — grace window의 익명 집합 분할

**이 설계가 도입하는 유일한 프라이버시 비용이다.** K개 root 중 어느 것을 쓰느냐가 "마지막으로 재증명한 시점"을 드러내, 익명 집합이 최대 K개로 쪼개진다.

K를 키우면 캐싱 효율은 오르지만 분할이 심해지고, K=1이면 분할이 없는 대신 매 갱신마다 전원 재증명이다. **K가 신선도·성능뿐 아니라 익명성까지 조절하는 파라미터**임을 논문에 명시해야 한다.

### 6.3 남는 위험

| 위험 | 성격 |
|---|---|
| IdP의 폐기 권한 남용 | 이번 범위 밖. conditional privacy가 이미 IdP를 신뢰하므로 신뢰 가정 자체는 추가되지 않음 |
| IdP 갱신 중단 시 전면 마비 | 가용성을 신선도와 맞바꾼 구조적 결과 |
| 폐기 규모·타이밍 공개 | 경미한 부수 채널 |
| salt 교체 차단으로 salt 유출 시 복구 불가 | **기존 한계**, 이 설계가 만든 것이 아님 |

## 7. 비용

### 7.1 회로

| 항목 | constraints | 근거 |
|---|---|---|
| 현재 `pi_pk_i` | 4,820 | 실측 |
| 계정 바인딩 (`Poseidon(3)` + `Poseidon(2)`) | +501 | 실측 |
| IMT 비멤버십 × 2 | (아래 실측값에 포함) | **실측으로 대체** |
| 합계 (Task 8 재배포 후 실측) | **19,049** | **실측** |

당초 추정(약 15,041)보다 IMT 비멤버십 비용이 커서 최종 constraints는 19,049다. 다만 아래 증명 시간 실측치는 원래 추정 구간(779~922ms) 안에 들어왔다 — 대형 회로 처리량이 추정보다 좋았던 것으로 보인다.

Task 8에서 warm-state 벤치마크로 재측정(`pi_pk_i.wasm`/`pi_pk_i_final.zkey`, 5회 워밍업 폐기 후 10회 측정):

| | 추정 (참고용, superseded) | **실측 (Task 8)** |
|---|---|---|
| 증명 시간 | 779~922 ms | **799.61 ms (±85.69 ms, n=10)** |
| 세션 고정비용 (로그인 363.89 + 증명) | 1,143~1,286 ms | **약 1,163 ms** |
| 손익분기 (zkAA 121.10 ms/tx 대비) | N ≥ 10~11 | **N ≥ 10** (재계산 불필요 — 실측치가 추정 구간 내) |

1시간 세션 기준 **평균 5~6분에 1건** 이상이면 세션 방식이 여전히 유리하다는 결론은 유지된다.

비교: 현재(폐기 없음)는 4,820 constraints, 295.50 ms, 세션 고정비용 659 ms, 손익분기 N ≥ 6.

### 7.2 온체인

| 연산 | gas |
|---|---|
| `pushRoot` (갱신 주기당 1회) | ~30K (BAAR 참조값) |
| `isRecentRoot` (tx당) | ~2,100 (콜드 SLOAD) |
| Groth16 검증 증가분 | public input 1개 추가분 |

`execute()`가 이미 200K 이상을 쓰므로 한계 증가분은 미미하다.

## 8. 검증 계획

논문용 설계이므로 구현 검증이 아니라 **수치 확정**이 목표다.

1. **IMT 비멤버십 회로를 실제로 작성해 컴파일한다.** 9,720은 깊이 20 멤버십 경로 실측치(4,860)를 2배 한 추정이며, `low < target < next` 비교 로직 비용이 빠져 있어 실제로는 더 클 수 있다.
2. 확정된 constraint 수로 증명 시간·세션 고정비용·손익분기를 재계산한다.
3. `RevocationRegistry` 스켈레톤을 작성해 `pushRoot`·`isRecentRoot` gas를 실측한다.
4. 보안 논증은 정성적 수준으로 두고, 형식 증명은 별도 과제로 남긴다.

**가장 불확실한 수치는 IMT 비멤버십 비용**이며, 이것만 확정하면 나머지는 따라온다.

## 9. 기각한 대안

| 대안 | 기각 이유 |
|---|---|
| PPID 단위 폐기 | IdP가 `ppid`를 구조적으로 알 수 없다(3.1절). RP 신고 경로를 열면 IdP-side RP hiding이 깨진다 |
| `r_token`을 public input으로 승격 | IdP 로그와 온체인 지갑을 잇는 다리가 생겨 cross-service unlinkability가 무너진다(3.4절) |
| 계정 단위만 지원(세션 제외) | 탈취된 세션키에 대응할 수단이 없어 `max_height` 만료를 기다리는 현 상태와 다르지 않다 |
| zk-creds형 발급 집합 멤버십 | 발급 때마다 root가 바뀌어 모든 사용자의 witness가 상시 갱신 대상이 된다 |
| sparse Merkle tree 비멤버십 | 깊이가 필드 비트수(254)라 IMT 대비 비용이 과도하다 |
| 온체인에 `auid` 커밋먼트 저장 | 같은 계정의 지갑들이 연결돼 unlinkability가 깨진다. 지갑별 블라인딩을 넣으면 대조가 불가능해진다 |

## 10. 참고

- 관련 연구 정리: `documents/260818_related_work_hybrid_auth_revocation.md` (3.0절 폐기 분류, 3.1절 zk-creds, 3.3절 BAAR, 4.6절 Option 권고, 4.8절 BAAR 적용 추정)
- BAAR 원논문: Ahmed, Ahmad, Zeshan, Akram, PLOS ONE 21(3): e0343696 (2026-03-31), DOI 10.1371/journal.pone.0343696
