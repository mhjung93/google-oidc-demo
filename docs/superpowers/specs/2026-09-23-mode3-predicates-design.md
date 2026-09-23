# Mode 3 — 속성 술어 확장(V7) 설계: 집합 소속 + 시각 상대 술어

2026-09-23. 선택 공개 설계(`2026-09-22-mode3-selective-disclosure-design.md`, V6)를 잇는다. 목적은 두 가지다 — 논문 VIII·IX 에 "π_rp 의
술어는 범위에 그치지 않는다"를 실측으로 뒷받침하고, 데모에서 보여 줄 술어 종류를 늘린다. 술어 DSL·임의 술어 조립은 범위 밖이다.

## 0. 결정 요약

| 결정 | 내용 | 이유 |
|---|---|---|
| 시각 상대 술어("나이 ≥ N") | **회로 불변.** 지갑이 `hi[0] = 올해 − N` 로 범위 공개하고, 검증자가 고정 상수 대신 **자기 시계**로 상한을 계산한다(AttrGate: `block.timestamp`, RP: `Date.getUTCFullYear()`) | 이미 V6 범위 술어로 표현된다. 회로에 시각을 넣으면 증명자가 넣는 값이라 어차피 검증자가 다시 비교해야 한다 |
| 집합 소속 `a_k ∈ S` | **집합 Merkle root 하나**를 공개 입력으로(A안). 한 증명에 집합 술어는 슬롯 하나 | 국가 집합처럼 수십 개짜리가 자연스럽고 공개 입력이 가장 적다(+2). 원소를 공개 입력으로 두면(B안) |S| ≤ 8 에 +9, 비트맵(C안)은 값 < 256 슬롯에만 |
| 슬롯 간 비교 `a_i ≥ a_j` | **제외** | 데모 슬롯(출생연도·국가·등급·예비)에 비교할 의미 있는 쌍이 없다. 논문에는 "같은 방식으로 한 줄"로 적는다 |
| 정밀도 | 나이는 **연 단위**("올해 − 출생연도 ≥ N", 만 나이 아님) | a₀ 가 출생연도이기 때문. 문서·UI 에 그렇게 쓴다 |

## 1. 무엇이 달라지는가 (V6 → V7)

| | V6 | V7 |
|---|---|---|
| 술어 | 슬롯별 범위 `disc_lo[k] ≤ a_k ≤ disc_hi[k]` | 범위 **+** 집합 소속 `a_{set_sel−1} ∈ S` (root 로 표현) |
| π_rp 공개 입력 | 23 | **25** = 23 + `set_sel` [23] + `set_root` [24] |
| 회로 추가 | — | 4→1 mux + Poseidon(2) 경로 깊이 8 + 두 조건식 ≈ 2.0k 제약(V6 25,369 → ≈27.4k 예상, 실측으로 갱신) |
| `execute` 꼬리 | 9워드(288 B) | **11워드(352 B)**: mask, lo[4], hi[4], set_sel, set_root |
| σ 다이제스트 | 공개 9워드 | 공개 11워드 |
| AttrGate 정책 | `a₁ = countryEq`, `a₀ ≤ 2007`(상수) | `a₁ ∈ S(allowedCountriesRoot)`, `올해(block.timestamp) − a₀ ≥ minAge` |
| CIA | — | **변경 없음**(속성·π_u·발급·개봉 그대로) |

호환: V7 검증자는 V6 증명을 받지 않는다(공개 입력 수). 팩토리·AttrGate 재배포, 데모 스택 재기동.

## 2. 집합 트리 (한 정의를 회로·지갑·RP·테스트가 공유)

- 원소는 정수 `0 ≤ s < 2^64`. **오름차순 정렬·중복 제거**. 원소 수 `1 ≤ |S| ≤ 256`.
- 깊이 **8**, 리프 256개. 리프 = 원소 값 그대로. 빈 자리 = **`PAD = 2^64`**. 속성은 `CommitUser` 에서 `Num2Bits(64)` 로 64비트임이 강제되므로
  어떤 `a_k` 도 PAD 와 같을 수 없다 — 패딩 리프로는 소속을 증명할 수 없다.
- 노드 = `Poseidon(2)(left, right)`. `root = MerkleRoot(S)`.
- `lib/mode3_set_tree.js`(신규): `setRoot(members) → bigint`, `setPath(members, value) → { index, path[8] }`(value 가 없으면 throw),
  `normalizeMembers(members) → bigint[]`(형식 검사·정렬·중복 제거; 오류는 `bad_disclosure`). `SET_DEPTH = 8`, `SET_PAD = 1n << 64n` 을 export.
  Poseidon 은 `lib/imt.js` 가 쓰는 것과 같은 circomlibjs 인스턴스.

## 3. 회로 V7 (`circuits/pi_cred.circom`)

### 3.1 입력

```
// 공개 (V6 [0..22] 뒤에)
signal input set_sel;        // [23]  0 = 집합 술어 없음, k ∈ {1,2,3,4} = 슬롯 k−1
signal input set_root;       // [24]  sel = 0 이면 0 이어야 한다
// 비공개
signal input set_index;      // 리프 인덱스 0..255 (8비트)
signal input set_path[8];    // 형제 노드, 리프에서 root 쪽으로
```

### 3.2 제약

```
// sel ∈ {0..4}: 5진 원핫으로 분해
component selBits = Num2Bits(3); selBits.in <== set_sel;          // < 8
signal selIs[5];  // selIs[j] = (set_sel == j), IsEqual 5개
sum(selIs) === 1;                                                    // 0..4 밖이면 실패
// v = attrs[sel−1] (sel = 0 이면 0)
signal v <== Σ_{k=0..3} selIs[k+1] * attrs[k];
// 경로: index 비트로 좌우 선택, 8단 Poseidon(2)
component idxBits = Num2Bits(8); idxBits.in <== set_index;
cur[0] <== v;
for i in 0..7: cur[i+1] <== Poseidon(2)( idxBits.out[i] ? (set_path[i], cur[i]) : (cur[i], set_path[i]) )   // Mux1 두 개
// 조건식
(1 − selIs[0]) * (cur[8] − set_root) === 0;     // sel ≠ 0 → root 일치
selIs[0] * set_root === 0;                       // sel = 0 → root = 0
```

sel = 0 일 때 `set_index`·`set_path` 는 임의(지갑은 0 을 넣는다). 회로는 S 가 무엇인지 모른다 — root 만 안다.

### 3.3 공개 입력 순서(불변 목록 갱신)

```
[0] PPID [1] arid [2] pk_i [3] max_height [4] chainid [5] allowAgent [6] rev_root [7,8] pk_CIA [9,10] pk_trace
[11,12] tag_c1 [13] tag_c2 [14] disc_mask [15..18] disc_lo [19..22] disc_hi [23] set_sel [24] set_root
```

`component main {public [..., disc_mask, disc_lo, disc_hi, set_sel, set_root]}`.

## 4. 온체인

### 4.1 `Mode3Wallet.execute`
- 시그니처 `execute(Payload payload, bytes sig, uint[2] a, uint[2][2] b, uint[2] c, uint[25] pub)`.
- 다이제스트: `abi.encode(chainid, this, to, value, data, nonce, pub[14], [pub[15..18]], [pub[19..22]], pub[23], pub[24])`.
- 꼬리: `abi.encodePacked(payload.data, pub[14], …, pub[24])` — 11워드, mask·sel 값과 무관하게 항상 붙인다(V6 §5.1 의 위조 꼬리 매장 논리 그대로).
  단순 송금(data 비고 mask = 0 **이고 sel = 0**)만 꼬리 없음.
- `Disclosure(nonceUsed, mask, lo, hi)` 이벤트를 `Disclosure(nonceUsed, mask, lo, hi, setSel, setRoot)` 로.
- `_checkStatement` 는 그대로(새 두 입력은 verifier 가 π 로 묶는다).

### 4.2 `AttrGate` v2
```solidity
constructor(address _factory, uint256 _allowedCountriesRoot, uint64 _minAge)
uint256 private constant TAIL = 11 * 32;
function claim() external {
    require(msg.sender 가 factory 배포 지갑);
    (mask, lo, hi, setSel, setRoot) = _disclosure();          // calldata 끝 352 B
    require(mask & 1 == 1, "need slot0");                     // a₀ 범위 공개
    require(setSel == 2 && setRoot == allowedCountriesRoot, "country");   // a₁ ∈ S
    require(hi[0] + minAge <= _year(block.timestamp), "age");            // 올해 − 출생연도 ≥ minAge
    claimed[msg.sender] = true; emit Claimed(msg.sender, uint64(hi[0]), setRoot);
}
function _year(uint256 ts) internal pure returns (uint256)   // days-from-civil 역산(UTC, 윤년 포함)
```
`_year`: `z = ts / 86400 + 719468; era = z / 146097; doe = z − era·146097; yoe = (doe − doe/1460 + doe/36524 − doe/146096) / 365;
y = yoe + era·400; doy = doe − (365·yoe + yoe/4 − yoe/100); mp = (5·doy + 2)/153; return y + (mp < 10 ? 0 : 1)`.
(Howard Hinnant 의 civil_from_days. 단위 테스트로 1970-01-01, 2000-02-29, 2026-12-31 23:59:59 UTC, 2027-01-01 00:00:00 UTC 경계를 고정한다.)

### 4.3 배포
AttrGate 는 RP 가 기동 때 배포한다(`mode3_rp.js` `ensureAttrGate` → `lib/mode3_onchain.js` `deployAttrGate`). `deployAttrGate(signer, { factoryAddress, allowedCountries = [410n, 392n, 840n, 276n, 250n], minAge = 19n })` 로 바꾸고
안에서 `setRoot(allowedCountries)` 를 계산해 생성자에 넘긴다 — KR·JP·US·DE·FR(ISO 3166 numeric). root 하드코딩 금지. RP 는 같은 목록을
env `MODE3_ALLOWED_COUNTRIES`(쉼표 구분, 기본 위 5개)·`MODE3_MIN_AGE`(기본 19)로 받아 오프체인 정책(§6)과 AttrGate 배포에 같이 쓴다.
`ensureAttrGate` 의 재배포 판정(팩토리 주소 비교)에 root·minAge 도 넣는다 — 값이 바뀌면 다시 배포.

## 5. 지갑

### 5.1 요청 형식 (`/wallet/tx`, `/wallet/login` 의 `disclose` 옆)
```json
"set": { "slot": 1, "members": [410, 392, 840, 276, 250] }     // 선택. slot 0..3
```
- `normalizeDisclosure(disclose, attrs, set)` → `{ mask, lo, hi, sel, root, index, path }`. set 이 없으면 `sel = 0n, root = 0n, index = 0, path = [0n×8]`.
  - `slot ∉ 0..3`, members 형식 오류(배열 아님·256 초과·비정수·≥ 2^64·빈 배열) → `bad_disclosure`.
  - `attrs[slot] ∉ members` → `disclosure_unsatisfiable`.
- `disclosureKey` 에 `:${sel}:${root}` 추가(π 캐시 키).
- `buildCredentialProof` 가 `set_sel, set_root, set_index, set_path` 를 회로 입력에 넣는다. `pub` 25개.
- `signPayload` 다이제스트에 `setSel, setRoot` 추가(컨트랙트 4.1 과 같은 순서).
- 응답의 `disclosure` 에 `set: { sel, root }`, `onchainDisclosure` 도 이벤트에서 읽어 채운다.

### 5.2 Snap 동의 창 (`snap-mode3/src/index.js` `consentDisclosure`)
- params 에 `set: { slot, members }` 추가. 표시: `국가 ∈ {410, 392, 840, 276, 250} (5개)`. members 가 32개를 넘으면 앞 8개 + "… 외 N개".
- Snap 은 Poseidon 이 없으므로 root 를 검산하지 않는다 — 에이전트가 members 에서 root 를 **스스로 계산**해 공개 입력에 넣으므로
  "동의 창의 members" 와 "증명의 root" 는 같은 에이전트 코드 경로에서 나온다(에이전트는 이미 증명을 만드는 신뢰 경계 안).

### 5.3 지갑 페이지 (`mode3/wallet.html`)
- 공개 폼: 슬롯별 "집합" 라디오(하나만 선택 가능) + members 입력(쉼표 구분). "나이 ≥ N 증명" 버튼: a₀ 체크 + `lo = 0`, `hi = 현재 UTC 연도 − N`.
- 결과 표시에 `set` 반영. 데모 기본값: 국가 집합 = 4.3 의 5개, N = 19.

## 6. 서비스(RP)

- `verifyLogin`(`lib/mode3_rp.js`): 25개 파싱. `disclosure = maskDisclosure({mask, lo, hi, sel, root})` — sel = 0 이면 root 를 0 으로 지운다
  (회로도 강제하지만 세션·로그에 남는 값이라 한 번 더). `sel > 4` 또는 (sel = 0 ∧ root ≠ 0) → `bad_disclosure`.
- 로그인 요청(`/api/mode3/login`)에도 `set` 을 실을 수 있다(지갑 페이지 팝업 경로에서 RP 가 요구하는 술어를 지갑에 전달). 데모 RP 페이지에
  "국가 ∈ 허용 집합 요구" 체크박스 하나. RP 오프체인 정책 검사는 `hi[0] + minAge ≤ getUTCFullYear()` 와 `root == setRoot(allowedCountries)`.
- 세션·로그인 로그·`/api/mode3/sessions` 표시에 `set` 필드.

## 7. 빌드·측정

1. `bash scripts/build_mode3_circuit.sh pot21_final.ptau` — zkey·vkey·wasm·`contracts/Mode3Verifier.sol` 재생성(수 분).
2. 스택 재배포(팩토리·AttrGate v2), `.env` 주소 갱신, 데모 스택 재기동. `docs/MODE3_DEMO.md` 의 재배포 절차에 V7 주의 추가.
3. 재측정 → `results/mode3_predicates_20260923.md`: 제약 수, π_rp 증명/검증 ms(N=10), execute gas 4가지(공개 0 / 범위만 / 집합만 / 범위+집합),
   AttrGate.claim gas. 논문 Table 2·3·VII-D·VIII 반영과 슬라이드 갱신은 **별도 후속**(이 spec 의 범위 밖).

## 8. 보안·프라이버시 메모

- **익명 집합**(V6 §7·논문 VII-D 연장): 집합 소속 공개는 "S 안의 값을 가진 사용자"로 익명 집합을 줄인다 — 정확 값 공개(lo = hi)보다 덜, 범위보다
  많거나 적을 수 있다(|S| 에 따라). AA 는 S 를 모른다(root 만 온체인) — 다만 AttrGate 상수·서비스 페이지에서 S 는 공개 정보다.
- **root 의 의미**: 검증자는 "이 root 가 내가 허용한 집합의 root 인가"만 본다. 서비스가 지갑에 다른 S 를 보내면 트랜잭션이 revert 될 뿐,
  지갑이 속아 다른 사실을 증명하지는 않는다(증명하는 사실은 항상 "내 속성 ∈ 내가 받은 members").
- **sel = 0 → root = 0 강제**: 검증자가 무시하는 값에 임의 워드가 실려 다이제스트·이벤트·로그에 남는 일을 막는다.
- **패딩**: PAD = 2^64 은 속성 정의역 밖 — 빈 리프로 소속을 만들 수 없다(3.2 의 `Num2Bits(64)` 전제).
- **시각**: 검증자 시계(block.timestamp / RP UTC 시각)를 쓰므로 증명자가 시각을 고를 수 없다. 연 단위 정밀도는 문서화된 한계.
- V6 §5.1 의 꼬리 매장 논리(항상 붙이는 꼬리, 위조 꼬리는 그 앞에 묻힘)는 11워드로 그대로 성립.

## 9. 테스트

| 그룹 | 파일 | 내용 |
|---|---|---|
| unit | `tests/test_mode3_set_tree.mjs`(신규) | 정렬·중복 제거·패딩·root 결정성(순서 무관), `setPath` 가 root 를 재구성, 없는 값 throw, 257개·≥2^64 거절 |
| unit | `tests/test_mode3_wallet.mjs`(기존 확장) | `normalizeDisclosure` 의 set 분기: 없음→sel 0, 소속 ok, 비소속 `disclosure_unsatisfiable`, 형식 `bad_disclosure`, 캐시 키 |
| circuit | `tests/test_pi_cred_witness.mjs`(확장) | 원소 통과 / 비원소 실패 / sel=0∧root≠0 실패 / sel=5 실패 / PAD 값을 속성으로 넣을 수 없음(64비트) / 공개 입력 25개 순서 |
| contract | `test/AttrGate.test.mjs`(신규) + `test/Mode3Wallet.test.mjs`(확장) — contract 그룹은 `build/mode3/` 의 V7 zkey·wasm 이 필요 | `_year` 경계 4건(`evm_setNextBlockTimestamp`), 연도 경계에서 claim 성공↔실패, root 불일치 revert, 11워드 꼬리, payload.data 안 위조 꼬리 매장(기존 시험 유지), 다이제스트에 sel·root 포함(바꿔치기 revert) |
| chain E2E | `tests/test_mode3_e2e.mjs`·`tests/test_mode3_demo_stack.mjs`(확장) | "국가 ∈ S ∧ 나이 ≥ 19" 트랜잭션 성공 + `Disclosure`/`Claimed` 이벤트, S 에서 내 국가를 뺀 요청은 `disclosure_unsatisfiable`, 로그인에 set 요구 |
| browser/snap | `snap-mode3/test/rpc.test.mjs`·browser 그룹(확장) | 동의 창에 슬롯 이름과 members 가 보인다, 33개 이상이면 축약 |

`scripts/run_tests.sh` 의 해당 그룹에 새 파일을 넣는다.

## 10. 범위 밖

술어 DSL·복수 집합 술어·슬롯 간 비교·만 나이(월·일) 정밀도·논문/슬라이드 갱신(후속 작업).
